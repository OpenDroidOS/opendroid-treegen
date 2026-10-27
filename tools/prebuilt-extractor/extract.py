#!/usr/bin/env python3
# Copyright 2026 OpenDroidOS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""OpenDroidOS: extract local kernel/device-tree/module evidence offline."""

import argparse
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import resource
import runpy
import shutil
import stat
import struct
import subprocess
import sys
import time
import types
import zlib


sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parent
REFERENCE = PROJECT / "third_party/aosp"
REFERENCE_SHA256 = "06b54dd9a07c5281778e29e234e76f6e3faee8bf0c904a5ef88fdee30eeed12e"
REFERENCE_REVISION = "954bc3ead5e679005fddf3484d247f2557b3c2c9"
CHUNK = 1024 * 1024
KINDS = ("boot", "init_boot", "vendor_boot", "dtbo", "dtb", "vendor", "system_dlkm", "vendor_dlkm")
OUTPUT_KINDS = ("kernel", "config", "dtb", "dtbo", "modules", "headers")
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
DT_TABLE_MAGIC = b"\xd7\xb7\xab\x1e"
SPARSE_MAGIC = b"\x3a\xff\x26\xed"
MODULE_RE = re.compile(r".+\.ko(?:\.(?:gz|xz|zst|lz4))?$")
SAFE_LABEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
DISCOVERY_WRAPPERS = {"images", "image", "partitions", "firmware", "extracted", "unpacked", "raw", "dump", "dumps",
                      "headers", "kernel_headers", "kernel-headers", "modules", "lib", "usr", "include",
                      "trees", "device-trees", "device_trees", "dtbs", "dtbos"}
COLLECTION_FOLDERS = {"headers", "kernel_headers", "kernel-headers", "modules", "lib", "usr", "include",
                      "trees", "device-trees", "device_trees", "dtbs", "dtbos"}
UNRELATED_PARTITION_ROOTS = {"system_root", "system", "system_ext", "product", "odm", "rootfs"}


class ExtractionError(ValueError):
    pass


class Unsupported(ExtractionError):
    pass


class SelectionRequired(ExtractionError):
    def __init__(self, message, alternatives):
        super().__init__(message)
        self.alternatives = alternatives


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(CHUNK), b""):
            digest.update(data)
    return digest.hexdigest()


def identity(path):
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def regular(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ExtractionError(f"Input must be a regular file without a symlink: {path}")


def bounded_range(offset, size, total, name):
    if offset < 0 or size < 0 or offset > total or size > total - offset:
        raise ExtractionError(f"{name} range is outside the input")


def read_exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise ExtractionError("Truncated input")
    return data


def align(value, page):
    return (value + page - 1) // page * page


def safe_relative(name):
    if "\0" in name or "\\" in name or any(ord(c) < 32 for c in name):
        raise ExtractionError("Unsafe archive/directory filename")
    while name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return None
    value = PurePosixPath(name)
    if value.is_absolute() or ".." in value.parts:
        raise ExtractionError("Absolute or traversing archive/directory path")
    return str(value)


def selected_kind(name):
    base = PurePosixPath(name).name
    if MODULE_RE.fullmatch(base):
        return "kernel-module"
    if base.startswith("modules.") or base in ("Module.symvers", "System.map"):
        return "kernel-module-metadata"
    if base in (".config", "config.gz") or re.fullmatch(r"config-[0-9].*", base):
        return "kernel-config-candidate"
    if base.endswith(".h"):
        return "header-file-candidate"
    if re.fullmatch(r"(?:kernel[-_]headers|kheaders|kernel[-_]devel).*\.(?:tar|tar\.gz|tar\.xz|tar\.zst|tgz)", base):
        return "header-archive-candidate"
    return None


def load_inspector():
    path = PROJECT / "inspect_inputs.py"
    spec = importlib.util.spec_from_file_location("opendroid_input_inspector", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def directory_role(name):
    name = name.lower().replace("-", "_")
    for prefix in ("extracted_", "unpacked_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    while True:
        original = name
        for suffix in ("_extracted", "_unpacked", ".img", "_a", "_b"):
            if name.endswith(suffix):
                name = name[:-len(suffix)]
        if name == original:
            break
    return name if name in KINDS else None


def capture_slot(name):
    match = re.search(r"_([ab])(?=\.|_(?:extracted|unpacked)(?:_|$)|$)", name.lower().replace("-", "_"))
    return match[1] if match else None


def image_role(name):
    normalized = name.lower().replace("-", "_")
    if normalized in KINDS:
        return normalized
    for role in sorted(KINDS, key=len, reverse=True):
        if re.fullmatch(re.escape(role) + r"(?:_[ab])?\.(?:img|bin|dtb|dtbo)", normalized):
            return role
    return None


def component_type(relative, role):
    path = PurePosixPath(relative)
    name = path.name.lower()
    name = re.sub(r"^.*\.img[-_]", "", name)
    shallow = len(path.parts) <= 2
    boot_role = role in ("boot", "init_boot", "vendor_boot")
    if boot_role and shallow and re.fullmatch(r"(?:kernel|image|zimage|bzimage)(?:\.(?:gz|xz|lz4|zst))?(?:[-_]dtb)?", name):
        return "kernel"
    if boot_role and shallow and re.fullmatch(r"(?:vendor_)?ramdisk[0-9]*(?:\.(?:img|cpio))?(?:\.(?:gz|xz|lz4|zst))?", name):
        return "ramdisk"
    if name in ("dtb", "dtb.img") or name.endswith((".dtb", ".fdt")):
        return "dtb"
    if name in ("dtbo", "dtbo.img", "recovery_dtbo") or name.endswith(".dtbo"):
        return "dtbo"
    if boot_role and shallow and name in ("bootconfig", "second", "boot_signature"):
        return "other"
    return None


def discover(folder, explicit=None, max_entries=20000, max_depth=3):
    """Select one capture per role. Discovery never enters extracted role trees."""
    explicit = explicit or {}
    if folder.is_symlink() or not folder.is_dir():
        raise ExtractionError("Input folder must be an ordinary directory without a symlink")
    candidates = {role: [] for role in KINDS}
    skipped = []
    scanned = 0
    generic = False
    generic_cohorts = set()
    queue = [(folder, 0)]
    root_role = directory_role(folder.name)
    if root_role:
        candidates[root_role].append({"path": str(folder), "type": "directory", "cohort": "", "slot": capture_slot(folder.name)})
    while queue:
        current, depth = queue.pop(0)
        children = []
        with os.scandir(current) as listing:
            for item in listing:
                scanned += 1
                if scanned > max_entries:
                    raise ExtractionError("Discovery entry limit exceeded; select a narrower input folder")
                children.append(item)
        for entry in sorted(children, key=lambda item: item.name):
            path = Path(entry.path)
            if entry.is_symlink():
                skipped.append({"path": str(path), "reason": "symlink-not-followed"})
                continue
            is_directory = entry.is_dir(follow_symlinks=False)
            role = directory_role(entry.name) if is_directory else image_role(entry.name)
            if role and (is_directory or entry.is_file(follow_symlinks=False)):
                parents = path.parent.relative_to(folder).parts
                cohort = "/".join(part for part in parents if part.lower() not in DISCOVERY_WRAPPERS)
                candidates[role].append({"path": str(path), "type": "directory" if is_directory else "image",
                                         "cohort": cohort, "slot": capture_slot(entry.name)})
                continue
            if is_directory:
                if entry.name.lower() in UNRELATED_PARTITION_ROOTS:
                    skipped.append({"path": str(path), "reason": "unrelated-extracted-partition-root"})
                    continue
                if depth < max_depth:
                    queue.append((path, depth + 1))
                else:
                    skipped.append({"path": str(path), "reason": "discovery-depth-limit"})
            elif entry.is_file(follow_symlinks=False) and (selected_kind(entry.name) or component_type(entry.name, "files")):
                generic = True
                cohort_parts = []
                for part in path.parent.relative_to(folder).parts:
                    if part.lower() in COLLECTION_FOLDERS:
                        break
                    if part.lower() not in DISCOVERY_WRAPPERS:
                        cohort_parts.append(part)
                generic_cohorts.add("/".join(cohort_parts))
    selected = []
    automatic = []
    for role in KINDS:
        choices = sorted(candidates[role], key=lambda item: item["path"])
        if role in explicit:
            path = explicit[role]
            selected.append({"label": role, "path": path, "directory": path.is_dir(), "selection": "explicit"})
            skipped.extend({**item, "role": role, "reason": "explicit-selection"} for item in choices if item["path"] != str(path))
            continue
        images = [item for item in choices if item["type"] == "image"]
        preferred = images or choices
        if len(preferred) > 1:
            raise SelectionRequired(f"Multiple {role} inputs found; choose --{role.replace('_', '-')} PATH or a narrower folder", choices)
        if preferred:
            choice = preferred[0]
            selected.append({"label": role, "path": Path(choice["path"]), "directory": choice["type"] == "directory",
                             "selection": "image-preferred" if images else "extracted-directory"})
            automatic.append(choice)
            skipped.extend({**item, "role": role, "reason": "image-preferred"} for item in choices if item != choice)
    root_selected = any(item["path"] == folder and item["directory"] for item in selected)
    cohorts = {item["cohort"] for item in automatic} | (set() if root_selected else generic_cohorts)
    slots = {item["slot"] for item in automatic if item["slot"]}
    if len(cohorts) > 1 or len(slots) > 1:
        raise SelectionRequired("Inputs span different build/slot containers; choose one folder or select each role explicitly", automatic)
    excluded = [Path(item["path"]) for choices in candidates.values() for item in choices]
    excluded += [Path(item["path"]) for item in skipped if item["reason"] == "unrelated-extracted-partition-root"]
    if generic and not root_selected:
        selected.append({"label": "files", "path": folder, "directory": True, "selection": "ordinary-directory",
                         "excluded": excluded})
    if not selected:
        raise ExtractionError("No supported image, extracted role directory, module, header or device-tree input found")
    report = {"root": str(folder), "max_depth": max_depth, "max_entries": max_entries,
              "entries_scanned": scanned,
              "selected": [{"label": item["label"], "path": str(item["path"]), "selection": item["selection"]} for item in selected],
              "skipped": skipped,
              "scope": "Filename/layout selection only; common build identity and hardware compatibility are not established"}
    return selected, report


def preflight_directory(root, label, max_entries=20000):
    """Reject competing shallow boot captures before output is created."""
    if label not in ("boot", "init_boot", "vendor_boot"):
        return
    queue = [(root, 0)]
    components = {"kernel": [], "ramdisk": []}
    count = 0
    while queue:
        base, depth = queue.pop()
        with os.scandir(base) as listing:
            for entry in listing:
                count += 1
                if count > max_entries:
                    raise ExtractionError("Extracted boot preflight entry limit exceeded; select a narrower folder")
                if entry.is_symlink():
                    continue
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False) and depth == 0:
                    queue.append((path, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    kind = component_type(str(path.relative_to(root)), label)
                    if kind in components:
                        components[kind].append(str(path))
    for kind, paths in components.items():
        if len(paths) > 1 and (kind == "kernel" or label != "vendor_boot"):
            raise SelectionRequired(f"Multiple extracted {kind} files; select one capture directory", sorted(paths))


class Extractor:
    def __init__(self, output, max_file_bytes=512 * CHUNK, max_total_bytes=2 * 1024 * CHUNK,
                 max_expanded_bytes=8 * 1024 * CHUNK, max_entries=200000, only=None):
        self.output = Path(output).absolute()
        if self.output.exists() or self.output.is_symlink():
            raise ExtractionError("Output must be a new, nonexistent directory")
        if not self.output.parent.is_dir() or self.output.parent.resolve() != self.output.parent:
            raise ExtractionError("Output parent must already exist, without symlink or '..' components")
        self.output.mkdir(mode=0o700)
        self.max_file = max_file_bytes
        self.max_total = max_total_bytes
        self.max_expanded = max_expanded_bytes
        self.max_entries = max_entries
        self.selection_explicit = only is not None
        self.only = set(only or OUTPUT_KINDS)
        self.total = 0
        self.tools = {}
        self.command_number = 0
        self.artifacts = []
        self.inspector = load_inspector()
        self.report = {
            "report_format_version": 1,
            "kind": "opendroid-prebuilt-extraction-evidence",
            "project": "OpenDroidOS",
            "copyright": "Copyright 2026 OpenDroidOS",
            "created_unix_seconds": int(time.time()),
            "extractor_sha256": sha256_file(Path(__file__)),
            "inspector_sha256": sha256_file(PROJECT / "inspect_inputs.py"),
            "limits": {"file_bytes": self.max_file, "total_artifact_bytes": self.max_total,
                       "expanded_image_bytes": self.max_expanded, "entries": self.max_entries},
            "inputs": [], "artifacts": self.artifacts, "tools": self.tools,
            "requested_output_kinds": sorted(self.only),
            "validation": {
                "inputs": "Read only; no mount, flash, repair, module load or execution of extracted files.",
                "signatures_avb": "not-verified",
                "bootloader_image_partition_contract": "not-established",
                "module_symbols_crcs_signatures_namespaces": "not-verified",
                "headers": "Only actual candidate files/archives are extracted; a complete matching kernel build tree is not reconstructed.",
                "device_trees": "DTB/DTBO bytes and table identity are retained; overlays are not applied or chosen for hardware.",
                "openharmony_compatibility": "not-established-by-extraction",
                "build_and_device_runtime": "not-tested",
            },
        }

    def tool(self, name):
        if name in self.tools:
            return self.tools[name]["path"]
        executable = shutil.which(name)
        if not executable:
            raise Unsupported(f"Required installed tool is unavailable: {name}")
        path = Path(executable).resolve()
        self.tools[name] = {"path": str(path), "sha256": sha256_file(path)}
        return str(path)

    def target(self, relative):
        name = safe_relative(relative)
        if not name:
            raise ExtractionError("Empty output path")
        path = self.output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise ExtractionError(f"Duplicate output path: {name}")
        return path

    def reserve(self, size):
        if size > self.max_file or size > self.max_total - self.total:
            raise ExtractionError("Artifact size limit exceeded; raise explicit limits for larger local inputs")

    def record(self, path, kind, source, details=None):
        size = path.stat().st_size
        self.reserve(size)
        path.chmod(0o600)
        item = {"kind": kind, "path": str(path.relative_to(self.output)), "bytes": size,
                "sha256": sha256_file(path), "source": source}
        if details:
            item["details"] = details
        self.artifacts.append(item)
        self.total += size
        return item

    def wants(self, kind):
        if kind in OUTPUT_KINDS:
            return kind in self.only
        if kind in ("kernel-payload", "kernel-decoded-payload"):
            return bool(self.only & {"kernel", "config", "dtb"})
        if kind == "embedded-kernel-config":
            return "config" in self.only
        if kind == "kernel-config-candidate":
            return "config" in self.only
        if kind in ("dtb-container", "dtb-candidate"):
            return "dtb" in self.only
        if kind in ("dtbo-container", "dtbo-entry", "recovery-dtbo-container"):
            return "dtbo" in self.only
        if kind.startswith("kernel-module"):
            return "modules" in self.only
        if kind.startswith("header-"):
            return "headers" in self.only
        # Unclassified boot components (bootconfig, second-stage payloads,
        # signatures, and future parser components) belong only to legacy
        # full extraction. Explicit selections must never publish them.
        if kind == "boot-component":
            return not self.selection_explicit
        return not self.selection_explicit

    def wants_candidate(self, kind):
        return self.wants(kind)

    def copy_range(self, source_path, offset, size, relative, kind, source, details=None):
        self.reserve(size)
        bounded_range(offset, size, source_path.stat().st_size, kind)
        target = self.target(relative)
        try:
            with source_path.open("rb") as input_file, target.open("xb") as output_file:
                input_file.seek(offset)
                left = size
                while left:
                    data = read_exact(input_file, min(left, CHUNK))
                    output_file.write(data)
                    left -= len(data)
            return self.record(target, kind, source, details)
        except Exception:
            target.unlink(missing_ok=True)
            raise

    def stage_range(self, source_path, offset, size, label, name):
        """Copy a bounded input range to disposable work space without publishing it."""
        bounded_range(offset, size, source_path.stat().st_size, "Temporary component")
        if size > self.max_file:
            raise ExtractionError("Temporary component exceeds file limit")
        target = self.scratch(label, name)
        with source_path.open("rb") as input_file, target.open("xb") as output_file:
            input_file.seek(offset)
            left = size
            while left:
                data = read_exact(input_file, min(left, CHUNK))
                output_file.write(data)
                left -= len(data)
        return {"path": str(target.relative_to(self.output)), "sha256": sha256_file(target),
                "bytes": size, "temporary": True}

    def write_bytes(self, data, relative, kind, source, details=None):
        self.reserve(len(data))
        target = self.target(relative)
        target.write_bytes(data)
        return self.record(target, kind, source, details)

    def scratch(self, label, name):
        path = self.output / ".work" / label / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    def issue(self, input_info, message):
        input_info.setdefault("limitations", []).append(message)
        if input_info.get("state") not in ("failed", "unsupported"):
            input_info["state"] = "partial"

    def decode(self, path, label, name):
        with path.open("rb") as stream:
            magic = stream.read(8)
        if magic.startswith((b"070701", b"070702")):
            return path, "uncompressed-newc"
        if magic.startswith(b"\x1f\x8b"):
            codec = "gzip"
        elif magic.startswith(b"\xfd7zXZ\0"):
            codec = "xz"
        elif magic.startswith((b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18")):
            codec = "lz4"
        elif magic.startswith(b"\x28\xb5\x2f\xfd"):
            codec = "zstd"
        else:
            raise Unsupported("No supported gzip/xz/LZ4/Zstandard stream or raw newc archive detected")
        target = self.scratch(label, name + ".decoded")
        try:
            if codec == "gzip":
                with gzip.open(path, "rb") as source, target.open("xb") as output:
                    count = 0
                    while True:
                        data = source.read(min(CHUNK, self.max_file - count + 1))
                        if not data:
                            break
                        count += len(data)
                        if count > self.max_file:
                            raise ExtractionError("Decompressed stream exceeds file limit")
                        output.write(data)
            elif codec == "xz":
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * CHUNK)
                count = 0
                with path.open("rb") as source, target.open("xb") as output:
                    while not decoder.eof:
                        data = source.read(CHUNK) if decoder.needs_input else b""
                        if not data and decoder.needs_input:
                            raise ExtractionError("Truncated XZ stream")
                        decoded = decoder.decompress(data, max_length=min(CHUNK, self.max_file - count + 1))
                        count += len(decoded)
                        if count > self.max_file:
                            raise ExtractionError("Decompressed stream exceeds file limit")
                        output.write(decoded)
                    if decoder.unused_data.strip(b"\0") or source.read().strip(b"\0"):
                        raise Unsupported("Concatenated/trailing nonzero XZ members are not supported")
            else:
                executable = self.tool(codec)
                def limit_output():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (self.max_file, self.max_file))
                with target.open("xb") as output:
                    result = subprocess.run([executable, "-d", "-c", str(path)], stdout=output,
                                            stderr=subprocess.PIPE, timeout=120, preexec_fn=limit_output,
                                            env={**os.environ, "LC_ALL": "C"})
                if result.returncode:
                    raise ExtractionError(f"{codec} decompression failed: " + result.stderr[:300].decode("utf-8", "replace"))
            return target, codec
        except Exception:
            target.unlink(missing_ok=True)
            raise

    def cpio(self, path, label, tag, source, input_info):
        size = path.stat().st_size
        count = 0
        archive = 0
        links = {}
        selected = []
        skipped = 0
        archive_open = False

        def flush():
            nonlocal links, selected
            for entry in selected:
                payload = entry
                if entry["nlink"] > 1 and not entry["size"]:
                    payload = links.get(entry["link_key"])
                    if payload is None:
                        self.issue(input_info, "A selected CPIO hardlink has no captured data-bearing member: " + entry["name"])
                        continue
                self.copy_range(path, payload["offset"], payload["size"],
                                f"{label}/ramdisk-files/{tag}/archive-{archive:03}/{entry['name']}",
                                entry["kind"], {**source, "archive": archive, "entry": entry["name"],
                                                "data_entry": payload["name"], "offset_in_decoded_archive": payload["offset"]})
            links, selected = {}, []

        with path.open("rb") as stream:
            cursor = 0
            while cursor < size:
                stream.seek(cursor)
                first = stream.read(1)
                if first == b"\0":
                    cursor += 1
                    continue
                stream.seek(cursor)
                header = read_exact(stream, 110)
                if header[:6] not in (b"070701", b"070702"):
                    raise Unsupported("Mixed/compressed/legacy CPIO member is not supported by the selective newc parser")
                try:
                    fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
                except ValueError as error:
                    raise ExtractionError("Invalid newc hexadecimal field") from error
                inode, mode, _, _, nlink, _, length, major, minor, _, _, namesize, checksum = fields
                if not 1 <= namesize <= 4096:
                    raise ExtractionError("Invalid newc filename size")
                raw_name = read_exact(stream, namesize)
                if not raw_name.endswith(b"\0"):
                    raise ExtractionError("CPIO filename is not NUL-terminated")
                raw_name = raw_name.rstrip(b"\0")
                name = raw_name.decode("utf-8", "strict")
                data_offset = align(cursor + 110 + namesize, 4)
                bounded_range(data_offset, length, size, "CPIO payload")
                count += 1
                if count > self.max_entries:
                    raise ExtractionError("Archive entry count exceeds limit")
                if name == "TRAILER!!!":
                    if length:
                        raise ExtractionError("CPIO trailer has payload")
                    flush()
                    archive += 1
                    archive_open = False
                else:
                    archive_open = True
                    name = safe_relative(name)
                    if header[:6] == b"070702":
                        stream.seek(data_offset)
                        total = 0
                        left = length
                        while left:
                            data = read_exact(stream, min(left, CHUNK))
                            total = (total + sum(data)) & 0xffffffff
                            left -= len(data)
                        if total != checksum:
                            raise ExtractionError("CPIO crc-format byte-sum does not match")
                    if name and stat.S_ISREG(mode):
                        entry = {"name": name, "size": length, "offset": data_offset,
                                 "nlink": nlink, "link_key": (major, minor, inode), "kind": selected_kind(name)}
                        if nlink > 1 and length:
                            links[entry["link_key"]] = entry
                        if entry["kind"] and self.wants_candidate(entry["kind"]):
                            selected.append(entry)
                    elif name:
                        skipped += 1
                cursor = align(data_offset + length, 4)
                if cursor > size:
                    raise ExtractionError("Truncated CPIO record alignment padding")
            if archive_open:
                # Linux permits a missing trailer, but extraction cannot claim
                # a positively observed archive closure in that case.
                self.issue(input_info, "CPIO TRAILER!!! absent: recovered entries retained, archive closure unverified")
            flush()
        input_info.setdefault("ramdisks", []).append({"component": tag, "entries_scanned": count,
                                                      "nonregular_entries_not_materialized": skipped,
                                                      "archive_members": archive or 1})

    def ramdisk(self, artifact, label, input_info):
        path = self.output / artifact["path"]
        tag = path.name
        try:
            decoded, codec = self.decode(path, label, tag)
            self.cpio(decoded, label, tag, {"input": label, "component": tag,
                                           "component_sha256": artifact["sha256"], "compression": codec}, input_info)
        except (ExtractionError, OSError, EOFError, lzma.LZMAError, zlib.error) as error:
            self.issue(input_info, f"{tag}: raw component retained; selective archive extraction incomplete: {error}")

    def kernel(self, artifact, label, input_info):
        path = self.output / artifact["path"]
        component_ref = "temporary extraction input" if artifact.get("temporary") else artifact["path"]
        with path.open("rb") as stream:
            prefix = stream.read(64)
        raw = path
        codec = "none"
        if prefix[56:60] != b"ARMd" and prefix.startswith((b"\x1f\x8b", b"\xfd7zXZ\0", b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18", b"\x28\xb5\x2f\xfd")):
            try:
                decoded, codec = self.decode(path, label, "kernel")
                if not self.selection_explicit:
                    item = self.copy_range(decoded, 0, decoded.stat().st_size, f"{label}/kernel-decoded",
                                           "kernel-decoded-payload", {"input": label, "component": path.name,
                                                                      "component_sha256": artifact["sha256"], "compression": codec})
                    raw = self.output / item["path"]
                else:
                    raw = decoded
            except (ExtractionError, OSError, EOFError, lzma.LZMAError, zlib.error) as error:
                self.issue(input_info, f"Compressed kernel retained but not decoded: {error}")
        data = raw.read_bytes()
        observation = self.inspector.inspect_embedded_config(data)
        input_info["kernel_observations"] = {
            "format": "arm64-Image-header-observed" if data[56:60] == b"ARMd" else "unidentified-or-compressed-payload",
            "release_strings": sorted({x.decode("ascii") for x in re.findall(rb"Linux version ([A-Za-z0-9_.+\-]{1,200})(?=\s)", data)}),
            "embedded_config": observation,
            "scope": "Static observations only; release equality, config and extracted modules do not establish ABI/runtime support.",
        }
        if observation["state"] == "observed" and "config" in self.only:
            candidate = observation["candidates"][0]
            start = candidate["offset_in_kernel"] + 8
            decoder = zlib.decompressobj(31)
            config = decoder.decompress(data[start:], self.inspector.MAX_CONFIG_BYTES + 1)
            self.write_bytes(config, f"{label}/kernel.config", "embedded-kernel-config",
                             {"input": label, "component": component_ref,
                              "offset_in_kernel": candidate["offset_in_kernel"]})
        if "dtb" in self.only:
            self.scan_dtbs(raw, label, "kernel", {"input": label, "component": component_ref}, input_info)
        if input_info["kernel_observations"]["format"] != "arm64-Image-header-observed":
            self.issue(input_info, "Kernel format/architecture not established; raw payload retained. Other compression/wrappers may be unsupported.")

    @staticmethod
    def fdt_size(data, offset=0):
        if len(data) - offset < 40 or data[offset:offset + 4] != FDT_MAGIC:
            raise ExtractionError("FDT header is absent or truncated")
        _, total, structure, strings, reserve, version, compatible, _, strings_size, structure_size = struct.unpack_from(">10I", data, offset)
        if version != 17 or compatible > 17 or total < 40 or total > 16 * CHUNK:
            raise Unsupported("Only bounded FDT v17 headers are supported")
        bounded_range(offset, total, len(data), "FDT")
        for start, length in ((structure, structure_size), (strings, strings_size), (reserve, 16)):
            if start < 40:
                raise ExtractionError("FDT block overlaps header")
            bounded_range(start, length, total, "FDT block")
        if structure_size < 8 or struct.unpack_from(">I", data, offset + structure)[0] != 1:
            raise ExtractionError("FDT structure has no root begin-node token")
        return total

    def scan_dtbs(self, path, label, tag, source, input_info):
        if not self.wants("dtb"):
            return []
        if path.stat().st_size > self.max_file:
            raise ExtractionError("DTB scan payload exceeds file limit")
        data = path.read_bytes()
        found = []
        end = 0
        for match in re.finditer(re.escape(FDT_MAGIC), data):
            offset = match.start()
            if offset < end:
                continue
            try:
                length = self.fdt_size(data, offset)
            except ExtractionError:
                continue
            if not self.wants("dtb"):
                continue
            if len(found) >= 4096:
                raise ExtractionError("Too many FDT candidates")
            self.copy_range(path, offset, length, f"{label}/device-trees/{tag}-{len(found):03}.dtb", "dtb-candidate",
                            {**source, "offset_in_component": offset}, {"validation": "FDT v17 header/block bounds only; no board selection, overlay application or hardware validation"})
            found.append({"offset": offset, "bytes": length})
            end = offset + length
        input_info.setdefault("device_tree_scans", []).append({"component": tag, "candidates": found,
                                                               "scope": "Header-bounded FDT candidates; absence is not proof of no DTB in another container/compression."})
        return found

    def dtbo(self, path, label, input_info, output_prefix=None, source=None):
        size = path.stat().st_size
        with path.open("rb") as stream:
            header = read_exact(stream, 32)
            magic, total, header_size, entry_size, count, entry_offset, page, version = struct.unpack(">8I", header)
            if magic != 0xd7b7ab1e:
                raise Unsupported("Expected Android DT table magic; use --dtb for raw FDT")
            if version != 0:
                raise Unsupported(f"DT table version {version} is unsupported; compressed/version1 entries are not decoded")
            if not 32 <= header_size <= entry_offset or entry_size < 32 or count > 4096:
                raise ExtractionError("Invalid DT table header/entry count")
            bounded_range(0, total, size, "DT table")
            bounded_range(entry_offset, entry_size * count, total, "DT entries")
            entries = []
            payload_min = entry_offset + entry_size * count
            for i in range(count):
                stream.seek(entry_offset + i * entry_size)
                length, offset, board_id, revision, *custom = struct.unpack(">8I", read_exact(stream, 32))
                if offset < payload_min or length > self.max_file:
                    raise ExtractionError("DT payload overlaps table or exceeds limit")
                bounded_range(offset, length, total, "DT payload")
                stream.seek(offset)
                payload = read_exact(stream, length)
                self.fdt_size(payload)
                if self.wants("dtbo"):
                    self.write_bytes(payload, f"{output_prefix or label}/entries/entry-{i:03}.dtbo", "dtbo-entry",
                                 {"input": label, **(source or {}), "offset": offset, "entry": i},
                                 {"id": board_id, "revision": revision, "custom": custom,
                                  "validation": "FDT header bounds only; entry not selected or applied"})
                entries.append({"index": i, "offset": offset, "bytes": length, "id": board_id,
                                "revision": revision, "custom": custom})
        table = {"version": version, "total_bytes": total, "page_bytes": page, "entries": entries}
        if not entries:
            self.issue(input_info, "Required content not found in DTBO table: at least one device-tree entry")
        if output_prefix:
            input_info.setdefault("dt_tables", []).append({"source": source, **table})
        else:
            input_info["dt_table"] = table

    def boot(self, path, label, input_info):
        if sys.byteorder != "little":
            raise Unsupported("Pinned AOSP parser uses native-endian fields; this wrapper requires little-endian host")
        reference = REFERENCE / "unpack_bootimg.py"
        if sha256_file(reference) != REFERENCE_SHA256:
            raise ExtractionError("Pinned AOSP reference hash mismatch")
        size = path.stat().st_size
        with path.open("rb") as stream:
            header = stream.read(65536)
        if label == "vendor_boot":
            if len(header) < 2112 or header[:8] != b"VNDRBOOT":
                raise Unsupported("Expected vendor_boot magic/header")
            version, page = struct.unpack_from("<2I", header, 8)
            if version not in (3, 4):
                raise Unsupported("Only vendor_boot header3/4 are supported")
            header_size, dtb_size = struct.unpack_from("<2I", header, 2096)
            expected = 2128 if version == 4 else 2112
            if header_size != expected or len(header) < expected:
                raise ExtractionError("Unexpected/truncated vendor_boot header size")
            ramdisk_size = struct.unpack_from("<I", header, 24)[0]
            if version == 4:
                table_size, entries, entry_size, bootconfig = struct.unpack_from("<4I", header, 2112)
                if entries > 4096 or entry_size < 108 or entries * entry_size > table_size:
                    raise ExtractionError("Invalid vendor ramdisk table")
                table_start = align(header_size, page) + align(ramdisk_size, page) + align(dtb_size, page) if page else 0
                bounded_range(table_start, table_size, size, "Vendor ramdisk table")
                bounded_range(table_start + align(table_size, page) if page else 0, bootconfig, size, "Vendor bootconfig")
                with path.open("rb") as table:
                    for i in range(entries):
                        table.seek(table_start + i * entry_size)
                        length, offset = struct.unpack("<2I", read_exact(table, 8))
                        bounded_range(offset, length, ramdisk_size, "Vendor ramdisk fragment")
        else:
            if len(header) < 44 or header[:8] != b"ANDROID!":
                raise Unsupported("Expected Android boot magic/header")
            version = struct.unpack_from("<I", header, 40)[0]
            if version not in (0, 1, 2, 3, 4):
                raise Unsupported(f"Boot header version {version} is unsupported")
            if label == "init_boot" and (version != 4 or struct.unpack_from("<I", header, 8)[0] != 0):
                raise Unsupported("init_boot extraction expects a kernel-free Android boot header4 image")
            if version >= 3:
                self.inspector.parse_boot_header(header[:4096], size)
                page = 4096
            else:
                page = struct.unpack_from("<I", header, 36)[0]
                expected = {0: 1632, 1: 1648, 2: 1660}[version]
                if len(header) < expected or page < expected:
                    raise ExtractionError("Truncated legacy boot header/page")
                if version and struct.unpack_from("<I", header, 1644)[0] != expected:
                    raise ExtractionError("Unexpected legacy boot header size")
        if page < 512 or page > 65536 or page & (page - 1):
            raise ExtractionError("Invalid boot page size")
        namespace = runpy.run_path(str(reference))
        unpacker = namespace["unpack_vendor_boot_image" if label == "vendor_boot" else "unpack_boot_image"]
        captures = []
        def capture(offset, length, stream, name):
            bounded_range(offset, length, size, "Boot component")
            base = Path(name).name
            if not re.fullmatch(r"kernel|ramdisk|second|recovery_dtbo|dtb|boot_signature|bootconfig|vendor_ramdisk[0-9]*", base):
                raise ExtractionError("Unexpected AOSP component name")
            if not length:
                return
            if base == "kernel" and not self.only & {"kernel", "config", "dtb"}:
                return
            if base.startswith("vendor_ramdisk") or base == "ramdisk":
                if not self.only & {"modules", "headers"}:
                    return
            if base == "dtb" and "dtb" not in self.only:
                return
            if base == "recovery_dtbo" and "dtbo" not in self.only:
                return
            if self.selection_explicit and base in ("second", "boot_signature", "bootconfig"):
                return
            kind = {"kernel": "kernel-payload", "dtb": "dtb-container", "recovery_dtbo": "recovery-dtbo-container"}.get(base, "boot-component")
            temporary = self.selection_explicit and (
                kind in ("boot-component", "dtb-container", "recovery-dtbo-container") or
                (kind == "kernel-payload" and "kernel" not in self.only))
            if temporary:
                artifact = self.stage_range(path, offset, length, label, f"component-{base}")
                artifact["kind"] = kind
            else:
                artifact = self.copy_range(path, offset, length, f"{label}/components/{base}", kind,
                                           {"input": label, "offset": offset, "parser_revision": REFERENCE_REVISION})
            artifact["component_name"] = base
            captures.append(artifact)
        # In-memory adapters retain AOSP parsing. All names/table symlinks are data;
        # our bounded writer owns outputs, and the reference never writes files.
        unpacker.__globals__["create_out_dir"] = lambda _: None
        unpacker.__globals__["extract_image"] = capture
        unpacker.__globals__["os"] = types.SimpleNamespace(
            path=types.SimpleNamespace(join=os.path.join, lexists=lambda _: False),
            symlink=lambda *_: None)
        with path.open("rb") as stream:
            info = unpacker(stream, "reference-output-intercepted")
        input_info["boot_layout"] = {"header_version": info.header_version, "page_bytes": info.page_size,
                                      "parser_revision": REFERENCE_REVISION, "parser_sha256": REFERENCE_SHA256,
                                      "cmdline_contents_emitted": False,
                                      "vendor_ramdisk_names_used_as_paths": False}
        required = "kernel" if label == "boot" else "ramdisk"
        present = any(item.get("component_name", Path(item["path"]).name) == "kernel" if required == "kernel"
                      else "ramdisk" in item.get("component_name", Path(item["path"]).name) for item in captures)
        required_by_selection = ((required == "kernel" and bool(self.only & {"kernel", "config", "dtb"})) or
                                 (required == "ramdisk" and bool(self.only & {"modules", "headers"})))
        input_info["boot_layout"]["required_content"] = ([{"component": required, "state": "observed" if present else "missing"}]
                                                            if required_by_selection else [])
        if required_by_selection and not present:
            self.issue(input_info, f"Required content not found in {label} image: {required}")
        for artifact in captures:
            tag = artifact.get("component_name", Path(artifact["path"]).name)
            component = self.output / artifact["path"]
            if tag == "kernel":
                self.kernel(artifact, label, input_info)
            elif "ramdisk" in tag:
                self.ramdisk(artifact, label, input_info)
            elif tag == "dtb":
                self.scan_dtbs(component, label, "dtb", {"input": label, "component": tag}, input_info)
            elif tag == "recovery_dtbo":
                try:
                    self.dtbo(component, label + "-recovery-dtbo", input_info)
                except ExtractionError as error:
                    self.issue(input_info, f"Recovery DTBO container retained; {error}")

    def expand_sparse(self, path, label):
        target = self.scratch(label, "expanded.raw")
        size = path.stat().st_size
        checksum = 0
        with path.open("rb") as source, target.open("xb") as output:
            magic, major, minor, file_header, chunk_header, block, blocks, chunks, expected_crc = struct.unpack(
                "<I4H4I", read_exact(source, 28))
            if magic != 0xed26ff3a or major != 1 or file_header < 28 or chunk_header < 12:
                raise Unsupported("Unsupported Android sparse header")
            if not block or block % 4 or block > CHUNK or blocks * block > self.max_expanded or chunks > self.max_entries:
                raise ExtractionError("Sparse image limits/size are invalid")
            bounded_range(0, file_header, size, "Sparse header")
            source.seek(file_header)
            emitted = 0
            for _ in range(chunks):
                kind, _, count, total = struct.unpack("<2H2I", read_exact(source, 12))
                if total < chunk_header or chunk_header > 65536:
                    raise ExtractionError("Invalid sparse chunk size")
                read_exact(source, chunk_header - 12)
                payload = total - chunk_header
                length = count * block
                if emitted + length > blocks * block:
                    raise ExtractionError("Sparse chunks exceed declared output")
                if kind == 0xcac1:
                    if payload != length:
                        raise ExtractionError("Sparse RAW length mismatch")
                    left = length
                    while left:
                        data = read_exact(source, min(left, CHUNK))
                        output.write(data)
                        checksum = zlib.crc32(data, checksum)
                        left -= len(data)
                elif kind in (0xcac2, 0xcac3):
                    if payload != (4 if kind == 0xcac2 else 0):
                        raise ExtractionError("Sparse fill/hole size mismatch")
                    fill = read_exact(source, 4) if kind == 0xcac2 else b"\0" * 4
                    left = length
                    while left:
                        data = (fill * (min(left, CHUNK) // 4))
                        if kind == 0xcac3:
                            output.seek(len(data), os.SEEK_CUR)
                        else:
                            output.write(data)
                        checksum = zlib.crc32(data, checksum)
                        left -= len(data)
                elif kind == 0xcac4:
                    if count or payload != 4 or struct.unpack("<I", read_exact(source, 4))[0] != checksum:
                        raise ExtractionError("Sparse CRC32 mismatch")
                else:
                    raise Unsupported(f"Unsupported sparse chunk type: {kind:#x}")
                emitted += length
            if emitted != blocks * block:
                raise ExtractionError("Sparse output length does not match header")
            output.truncate(emitted)
            if expected_crc and expected_crc != checksum:
                raise ExtractionError("Sparse image checksum mismatch")
            if source.read(1):
                raise Unsupported("Trailing data after sparse chunks is unsupported")
        return target, {"major": major, "minor": minor, "expanded_bytes": emitted,
                        "expanded_sha256": sha256_file(target), "crc32": f"{checksum:08x}"}

    def debugfs(self, image, request, max_output=4 * CHUNK):
        executable = self.tool("debugfs")
        self.command_number += 1
        output = self.scratch("debugfs", f"{self.command_number}.stdout")
        error = self.scratch("debugfs", f"{self.command_number}.stderr")
        def limit_output():
            maximum = min(max_output + 1, self.max_file) if request.startswith("ls ") else self.max_file
            resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
        try:
            with output.open("xb") as stdout, error.open("xb") as stderr:
                result = subprocess.run([executable, "-R", request, str(image)], stdout=stdout, stderr=stderr,
                                        timeout=120, env={**os.environ, "LC_ALL": "C"}, preexec_fn=limit_output)
            if result.returncode or output.stat().st_size > max_output or error.stat().st_size > 16384:
                raise ExtractionError("debugfs command failed or bounded listing/diagnostics exceeded limit")
            stderr = error.read_text(errors="replace")
            # debugfs sometimes exits zero on errors. Only its version banner
            # is normal on this read-only path; warnings/errors are not success.
            errors = [line for line in stderr.splitlines() if line and not line.startswith("debugfs ")]
            if errors:
                raise ExtractionError("debugfs reported: " + " | ".join(errors)[:500])
            return output.read_text(encoding="utf-8", errors="strict")
        finally:
            output.unlink(missing_ok=True)
            error.unlink(missing_ok=True)

    def filesystem(self, path, label, input_info):
        with path.open("rb") as stream:
            magic = stream.read(4)
        image = path
        if magic == SPARSE_MAGIC:
            image, sparse = self.expand_sparse(path, label)
            input_info["sparse"] = sparse
        with image.open("rb") as stream:
            stream.seek(1024)
            superblock = stream.read(64)
        if superblock[:4] == b"\xe2\xe1\xf5\xe0":
            raise Unsupported("OpenHarmony supports EROFS; bounded selective EROFS reading is not implemented. Supply a trusted separately extracted directory with --directory")
        if len(superblock) < 58 or superblock[56:58] != b"\x53\xef":
            raise Unsupported("Only raw/sparse ext2/3/4 filesystems are supported here; payload, super, encrypted and other images are not unpacked")
        queue = [(2, "")]
        seen = set()
        entries = 0
        skipped = 0
        while queue:
            inode, directory = queue.pop()
            if inode in seen:
                continue
            seen.add(inode)
            listing = self.debugfs(image, f"ls -p <{inode}>")
            for line in listing.splitlines():
                if not line:
                    continue
                fields = line.split("/")
                if len(fields) != 8 or fields[0] or fields[-1]:
                    raise ExtractionError("Unsupported debugfs listing filename/format")
                _, number, mode_text, _, _, name, length_text, _ = fields
                if name in (".", ".."):
                    continue
                if not number.isdigit() or not re.fullmatch(r"[0-7]+", mode_text):
                    raise ExtractionError("Invalid debugfs listing metadata")
                if int(number) == 0:
                    continue
                relative = safe_relative(f"{directory}/{name}".lstrip("/"))
                if not relative:
                    continue
                entries += 1
                if entries > self.max_entries:
                    raise ExtractionError("Filesystem entry limit exceeded")
                mode = int(mode_text, 8)
                if stat.S_ISDIR(mode):
                    queue.append((int(number), relative))
                elif stat.S_ISREG(mode):
                    kind = selected_kind(relative)
                    if not kind or not self.wants_candidate(kind):
                        continue
                    if not length_text.isdigit():
                        raise ExtractionError("Invalid debugfs regular file size")
                    self.reserve(int(length_text))
                    target = self.target(f"{label}/filesystem-files/{relative}")
                    # Destination is controlled by us. Inode syntax avoids
                    # interpolating untrusted image filenames into commands.
                    if any(c in str(target) for c in ('"', '\\', '\n', '\r')):
                        raise ExtractionError("Output root contains characters unsupported by debugfs quoting")
                    self.debugfs(image, f'dump <{number}> "{target}"')
                    if not target.is_file() or target.stat().st_size != int(length_text):
                        target.unlink(missing_ok=True)
                        raise ExtractionError("debugfs extracted size differs from directory metadata")
                    self.record(target, kind, {"input": label, "filesystem_path": "/" + relative,
                                              "inode": int(number), "filesystem": "ext2/3/4"})
                else:
                    skipped += 1
        input_info["filesystem"] = {"format": "ext2/3/4", "entries_scanned": entries,
                                     "nonregular_entries_not_materialized": skipped,
                                     "journal_replayed_or_image_repaired": False}

    def directory(self, root, label, input_info, excluded=()):
        before = identity(root)
        start = len(self.artifacts)
        count = 0
        skipped = 0
        records = []
        queue = [root]
        excluded = set(excluded)
        while queue:
            base = queue.pop()
            children = []
            with os.scandir(base) as listing:
                for entry in listing:
                    count += 1
                    if count > self.max_entries:
                        raise ExtractionError("Directory entry count limit exceeded")
                    children.append(entry)
            for entry in sorted(children, key=lambda item: item.name):
                path = Path(entry.path)
                if path in excluded:
                    continue
                if entry.is_symlink():
                    skipped += 1
                elif entry.is_dir(follow_symlinks=False):
                    queue.append(path)
                elif entry.is_file(follow_symlinks=False):
                    relative = safe_relative(str(path.relative_to(root)))
                    records.append((path, relative, identity(path), component_type(relative, label)))
                else:
                    skipped += 1
        kernels = [record for record in records if record[3] == "kernel"]
        if len(kernels) > 1:
            raise SelectionRequired("Multiple extracted kernel files; select a directory containing one capture", [str(record[0]) for record in kernels])
        archives = [record for record in records if record[3] == "ramdisk"]
        if label in ("boot", "init_boot") and len(archives) > 1:
            raise SelectionRequired("Multiple extracted ramdisk archives; select one capture directory", [str(record[0]) for record in archives])
        components = []
        for index, (path, relative, old, component) in enumerate(records):
            kind = selected_kind(relative)
            if kind and not self.wants_candidate(kind):
                kind = None
            if not component and not kind:
                continue
            if component == "kernel" and not self.only & {"kernel", "config", "dtb"}:
                continue
            if component == "ramdisk" and not self.only & {"modules", "headers"}:
                continue
            if component == "other" and self.selection_explicit:
                continue
            self.reserve(old[2])
            source = {"input": label, "directory_path": relative, "file_sha256": sha256_file(path)}
            if component in ("kernel", "ramdisk", "other"):
                tag = "kernel" if component == "kernel" else f"{component}-{index:06}"
                artifact_kind = "kernel-payload" if component == "kernel" else "boot-component"
                temporary = self.selection_explicit and (
                    component != "kernel" or "kernel" not in self.only)
                if temporary:
                    artifact = self.stage_range(path, 0, old[2], label, f"component-{tag}")
                    artifact["kind"] = artifact_kind
                else:
                    artifact = self.copy_range(path, 0, old[2], f"{label}/components/{tag}", artifact_kind, source)
                components.append({"type": component, "directory_path": relative, "bytes": old[2], "sha256": artifact["sha256"]})
                if component == "kernel":
                    self.kernel(artifact, label, input_info)
                elif component == "ramdisk":
                    self.ramdisk(artifact, label, input_info)
            elif component in ("dtb", "dtbo"):
                tag = f"{component}-{index:06}"
                artifact_kind = f"{component}-container"
                if self.selection_explicit:
                    artifact = self.stage_range(path, 0, old[2], label, f"component-{tag}")
                    artifact["kind"] = artifact_kind
                else:
                    artifact = self.copy_range(path, 0, old[2], f"{label}/components/{tag}", artifact_kind, source)
                payload = self.output / artifact["path"]
                with payload.open("rb") as stream:
                    magic = stream.read(4)
                if component == "dtbo" and magic == DT_TABLE_MAGIC:
                    self.dtbo(payload, label, input_info, f"{label}/device-tree-tables/{tag}", source)
                elif not self.scan_dtbs(payload, label, tag, source, input_info):
                    self.issue(input_info, f"No supported FDT found in {relative}; original bytes retained")
                components.append({"type": component, "directory_path": relative, "bytes": old[2], "sha256": artifact["sha256"]})
            elif kind:
                self.copy_range(path, 0, old[2], f"{label}/directory-files/{relative}", kind, source)
            if (component or kind) and identity(path) != old:
                raise ExtractionError("Directory candidate changed during extraction")
        tree_present = any(any(part.startswith(("ramdisk", "vendor_ramdisk")) for part in PurePosixPath(record[1]).parts[:-1])
                           for record in records)
        tree_present = tree_present or any(record[1] == "init" for record in records)
        required = []
        if label == "boot" and self.only & {"kernel", "config", "dtb"}:
            required.append(("kernel", any(record[2][2] for record in kernels)))
        elif label in ("init_boot", "vendor_boot") and self.only & {"modules", "headers"}:
            required.append(("ramdisk-archive-or-unpacked-tree", any(record[2][2] for record in archives) or tree_present))
        elif label in ("dtb", "dtbo"):
            required.append(("valid-device-tree-candidate", any(item["kind"] in ("dtb-candidate", "dtbo-entry") for item in self.artifacts[start:])))
        else:
            required.append(("supported-component-module-header-or-config", len(self.artifacts) > start))
        for component, present in required:
            if not present:
                self.issue(input_info, f"Required content not found in extracted {label} directory: {component}")
        if identity(root) != before:
            raise ExtractionError("Input directory changed during extraction")
        input_info["directory"] = {"files_scanned": count, "nonregular_entries_not_materialized": skipped,
                                    "components": components, "unpacked_ramdisk_tree_observed": tree_present,
                                    "required_content": [{"component": component, "state": "observed" if present else "missing"} for component, present in required],
                                    "original_image_header_layout": "not-available-from-directory",
                                    "identity": "Individual extracted-file hashes; no full directory snapshot hash or concurrent-subtree guarantee"}

    def process(self, label, path, directory=False, excluded=()):
        info = {"label": label, "path": str(path), "state": "extracted"}
        self.report["inputs"].append(info)
        start = len(self.artifacts)
        applicable = {
            "kernel": {"boot"}, "config": {"boot"},
            "dtb": {"boot", "vendor_boot", "dtb"},
            "dtbo": {"boot", "vendor_boot", "dtbo"},
            "modules": {"boot", "init_boot", "vendor_boot", "vendor", "system_dlkm", "vendor_dlkm"},
            "headers": {"boot", "init_boot", "vendor_boot", "vendor", "system_dlkm", "vendor_dlkm"},
        }
        if self.selection_explicit and not directory and not any(label in applicable[kind] for kind in self.only):
            info.update(state="skipped-selection", reason="Input role cannot contain a requested output kind")
            info["artifacts_extracted"] = 0
            return
        try:
            if directory or path.is_dir():
                if path.is_symlink() or not path.is_dir():
                    raise ExtractionError("Directory input must be an ordinary directory without a symlink")
                self.directory(path, label, info, excluded)
            else:
                regular(path)
                before = identity(path)
                info.update(bytes=before[2], sha256=sha256_file(path))
                if label in ("boot", "init_boot", "vendor_boot"):
                    self.boot(path, label, info)
                elif label == "dtbo":
                    self.dtbo(path, label, info)
                elif label == "dtb":
                    if self.selection_explicit:
                        container = path
                    else:
                        self.copy_range(path, 0, before[2], f"{label}/dtb-container", "dtb-container", {"input": label, "offset": 0})
                        container = path
                    if not self.scan_dtbs(container, label, "dtb", {"input": label, "offset": 0}, info):
                        self.issue(info, "No supported FDT candidate found; container bytes retained")
                else:
                    self.filesystem(path, label, info)
                if identity(path) != before or sha256_file(path) != info["sha256"]:
                    raise ExtractionError("Input changed during extraction; output is not a consistent snapshot")
        except Unsupported as error:
            info.update(state="unsupported", error=str(error))
        except (ExtractionError, self.inspector.InspectionError, OSError, EOFError, UnicodeError, struct.error,
                lzma.LZMAError, zlib.error, subprocess.SubprocessError) as error:
            info.update(state="failed", error=str(error))
        info["artifacts_extracted"] = len(self.artifacts) - start

    def finish(self):
        work = self.output / ".work"
        if work.exists():
            shutil.rmtree(work)
        modules = [x for x in self.artifacts if x["kind"] == "kernel-module"]
        if modules:
            try:
                self.report["module_observations"] = self.inspector.inspect_modules(
                    [("extracted", self.output)])
            except (self.inspector.InspectionError, OSError, subprocess.SubprocessError) as error:
                self.report["module_observations"] = {"state": "not-inspected", "error": str(error)}
        found = {
            "kernel": any(x["kind"] == "kernel-payload" for x in self.artifacts),
            "config": any(x["kind"] == "embedded-kernel-config" for x in self.artifacts),
            "dtb": any(x["kind"] == "dtb-candidate" for x in self.artifacts),
            "dtbo": any(x["kind"] == "dtbo-entry" for x in self.artifacts),
            "modules": any(x["kind"] == "kernel-module" for x in self.artifacts),
            "headers": any(x["kind"] in ("header-file-candidate", "header-archive-candidate") for x in self.artifacts),
        }
        missing = sorted(kind for kind in self.only if not found[kind]) if self.selection_explicit else []
        self.report["selection"] = {"found": sorted(kind for kind in self.only if found[kind]), "missing": missing}
        self.report["summary"] = {"artifacts": len(self.artifacts), "artifact_bytes": self.total,
                                   "kinds": {kind: sum(x["kind"] == kind for x in self.artifacts)
                                             for kind in sorted({x["kind"] for x in self.artifacts})},
                                   "all_requested_inputs_extracted": all(x["state"] in ("extracted", "skipped-selection") for x in self.report["inputs"]),
                                   "all_requested_output_kinds_found": not missing}
        report = self.output / "extraction-report.json"
        report.write_text(json.dumps(self.report, indent=2) + "\n")
        report.chmod(0o600)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog="opendroid-extract", description=__doc__)
    parser.add_argument("input_folder", nargs="?", type=Path,
                        help="Discover images, extracted role directories, modules, headers and device trees")
    for kind in KINDS:
        parser.add_argument("--" + kind.replace("_", "-"), type=Path)
    parser.add_argument("--directory", nargs=2, action="append", default=[], metavar=("LABEL", "PATH"),
                        help="Selectively copy modules/metadata/header candidates from an already extracted directory")
    parser.add_argument("--only", choices=OUTPUT_KINDS, action="append",
                        help="Output kind to extract; repeat for multiple kinds (default: all kinds)")
    parser.add_argument("--output", required=True, type=Path, help="New nonexistent output directory; parent must exist")
    parser.add_argument("--max-file-mib", type=int, default=512)
    parser.add_argument("--max-total-mib", type=int, default=2048)
    parser.add_argument("--max-expanded-mib", type=int, default=8192)
    args = parser.parse_args(argv)
    explicit = {kind: getattr(args, kind).absolute() for kind in KINDS if getattr(args, kind)}
    discovery = None
    try:
        if args.input_folder:
            inputs, discovery = discover(args.input_folder.absolute(), explicit)
        else:
            inputs = [{"label": kind, "path": path, "directory": path.is_dir(), "selection": "explicit"}
                      for kind, path in explicit.items()]
    except SelectionRequired as error:
        print(json.dumps({"state": "selection-required", "error": str(error), "alternatives": error.alternatives}), file=sys.stderr)
        return 2
    except (ExtractionError, OSError) as error:
        parser.error(str(error))
    inputs += [{"label": label, "path": Path(path).absolute(), "directory": True, "selection": "explicit"}
               for label, path in args.directory]
    if not inputs:
        parser.error("Supply INPUT_FOLDER or at least one explicit input")
    labels = [item["label"] for item in inputs]
    if len(set(labels)) != len(labels) or any(not SAFE_LABEL.fullmatch(x) for x in labels):
        parser.error("Labels must be unique, with letters, digits, underscores or hyphens")
    if min(args.max_file_mib, args.max_total_mib, args.max_expanded_mib) <= 0:
        parser.error("Size limits must be positive")
    output = args.output.absolute()
    if args.input_folder and output.resolve().is_relative_to(args.input_folder.resolve()):
        parser.error("Output must be outside the input folder")
    for item in inputs:
        path, directory = item["path"], item["directory"]
        if output.resolve() == path.resolve() or (directory and output.resolve().is_relative_to(path.resolve())):
            parser.error("Output must be outside every input and input directory")
    try:
        for item in inputs:
            if item["directory"]:
                preflight_directory(item["path"], item["label"])
        extractor = Extractor(output, args.max_file_mib * CHUNK, args.max_total_mib * CHUNK,
                              args.max_expanded_mib * CHUNK, only=args.only)
        if discovery is not None:
            extractor.report["discovery"] = discovery
        for item in inputs:
            extractor.process(item["label"], item["path"], item["directory"], item.get("excluded", ()))
        report = extractor.finish()
        print(json.dumps({"report": str(report), **extractor.report["summary"]}))
        if any(x["state"] == "failed" for x in extractor.report["inputs"]):
            return 2
        return 0 if (extractor.report["summary"]["all_requested_inputs_extracted"] and
                     extractor.report["summary"]["all_requested_output_kinds_found"]) else 1
    except SelectionRequired as error:
        print(json.dumps({"state": "selection-required", "error": str(error), "alternatives": error.alternatives}), file=sys.stderr)
        return 2
    except (ExtractionError, OSError) as error:
        print(json.dumps({"state": "extraction-failed", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
