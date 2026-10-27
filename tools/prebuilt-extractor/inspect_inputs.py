#!/usr/bin/env python3
# Copyright 2026 OpenDroidOS
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

"""Inspect supplied boot/module files without executing or modifying them."""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zlib


PAGE = 4096
MAX_KERNEL_BYTES = 512 * 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024
CONFIG_KEYS = (
    "IKCONFIG", "IKCONFIG_PROC", "MODULES", "MODVERSIONS", "MODULE_SIG",
    "MODULE_SIG_FORCE", "ANDROID_BINDER_IPC", "ANDROID_BINDERFS",
    "ANDROID_BINDER_DEVICES", "HDF", "DEVTMPFS", "TMPFS", "NAMESPACES",
    "PID_NS", "USER_NS", "NET_NS", "SECCOMP", "SECCOMP_FILTER",
    "SECURITY_SELINUX", "CGROUPS", "CGROUP_BPF", "MEMCG", "DM_VERITY",
    "DM_CRYPT", "F2FS_FS", "EXT4_FS", "EROFS_FS", "ARM64_4K_PAGES",
    "COMPAT", "BPF_SYSCALL", "PM", "SUSPEND",
)


class InspectionError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def require_regular(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise InspectionError(f"Expected an ordinary file, without a symlink: {path}")


def hash_stream(stream, length):
    digest = hashlib.sha256()
    while length:
        chunk = stream.read(min(length, 1024 * 1024))
        if not chunk:
            raise InspectionError("Truncated input while hashing")
        digest.update(chunk)
        length -= len(chunk)
    return digest.hexdigest()


def parse_boot_header(header, file_size):
    if len(header) < 44 or header[:8] != b"ANDROID!":
        raise InspectionError("Expected Android boot magic and a complete version field")
    version = struct.unpack_from("<I", header, 40)[0]
    if version not in (3, 4):
        raise InspectionError(f"Boot header version {version} is not supported; only3/4 are inspected")
    expected = {3: 1580, 4: 1584}[version]
    if len(header) < expected or file_size < PAGE:
        raise InspectionError("Truncated boot header/page")
    kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from("<4I", header, 8)
    if header_size != expected:
        raise InspectionError(f"Unexpected v{version} header size {header_size}; expected {expected}")
    signature_size = struct.unpack_from("<I", header, 1580)[0] if version == 4 else 0
    sections = []
    cursor = PAGE
    for name, size in (("kernel", kernel_size), ("ramdisk", ramdisk_size),
                       ("boot_signature", signature_size)):
        if size and (cursor > file_size or size > file_size - cursor):
            raise InspectionError(f"Declared {name} is outside the input file")
        sections.append({"name": name, "offset": cursor, "bytes": size})
        cursor += ((size + PAGE - 1) // PAGE) * PAGE
    cmdline = header[44:1580].split(b"\0", 1)[0]
    return {
        "magic": "ANDROID!", "header_version": version, "header_bytes": header_size,
        "page_bytes": PAGE, "os_version_field": os_version,
        "reserved_words": list(struct.unpack_from("<4I", header, 24)),
        "cmdline": {"bytes": len(cmdline), "sha256": sha256(cmdline), "contents_emitted": False},
        "sections": sections,
    }


def inspect_embedded_config(kernel, max_bytes=MAX_CONFIG_BYTES):
    offsets = [match.start() for match in re.finditer(b"IKCFG_ST", kernel)]
    candidates = []
    failures = []
    for offset in offsets:
        start = offset + 8
        try:
            decoder = zlib.decompressobj(31)
            config = decoder.decompress(kernel[start:], max_bytes + 1)
            if len(config) > max_bytes or not decoder.eof:
                raise InspectionError("Incomplete or oversized embedded configuration")
            end = len(kernel) - len(decoder.unused_data)
            if kernel[end:end + 8] != b"IKCFG_ED":
                raise InspectionError("Embedded configuration end marker is absent")
            text = config.decode("utf-8")
            values = {}
            for line in text.splitlines():
                if re.fullmatch(r"CONFIG_[A-Za-z0-9_]+=.*", line):
                    key, value = line.split("=", 1)
                    if key in values:
                        raise InspectionError(f"Duplicate configuration option: {key}")
                    values[key] = value
                else:
                    unset = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_]+) is not set", line)
                    if unset:
                        key = unset.group(1)
                        if key in values:
                            raise InspectionError(f"Duplicate configuration option: {key}")
                        values[key] = "n"
            if not values:
                raise InspectionError("Embedded data has no recognized kernel options")
            candidates.append({
                "offset_in_kernel": offset, "bytes": len(config), "sha256": sha256(config),
                "option_count": len(values),
                "selected_options": {"CONFIG_" + key: values.get(
                    "CONFIG_" + key, "not-recorded") for key in CONFIG_KEYS},
            })
        except (zlib.error, UnicodeError, InspectionError) as error:
            failures.append({"offset_in_kernel": offset, "error": str(error)})
    return {"state": "observed" if len(candidates) == 1 else
            "ambiguous" if candidates else "not-found-or-not-decodable",
            "candidates": candidates, "rejected_markers": failures,
            "scope": "Selected build options, not a list of mandatory OpenHarmony requirements or runtime proof."}


def inspect_boot(path):
    require_regular(path)
    before = path.stat()
    with path.open("rb") as stream:
        image_hash = hash_stream(stream, before.st_size)
        stream.seek(0)
        report = parse_boot_header(stream.read(PAGE), before.st_size)
        for section in report["sections"]:
            stream.seek(section["offset"])
            section["sha256"] = hash_stream(stream, section["bytes"])
        kernel_section = report["sections"][0]
        if kernel_section["bytes"] > MAX_KERNEL_BYTES:
            report["kernel_analysis"] = {"state": "not-inspected-size-limit"}
        elif kernel_section["bytes"]:
            stream.seek(kernel_section["offset"])
            kernel = stream.read(kernel_section["bytes"])
            report["kernel_analysis"] = {
                "format": "uncompressed-arm64-image" if kernel[56:60] == b"ARMd" else "unidentified-payload",
                "embedded_release_strings": sorted({match.decode("ascii") for match in re.findall(
                    rb"Linux version ([A-Za-z0-9_.+\-]{1,200})(?=\s)", kernel)}),
                "embedded_config": inspect_embedded_config(kernel),
                "scope": "Static payload observations; compressed kernel expansion and runtime validation are not performed.",
            }
        else:
            report["kernel_analysis"] = {"state": "no-kernel-section"}
    if file_identity(before) != file_identity(path.stat()):
        raise InspectionError("Boot image changed during inspection")
    return {"report_format_version": 1, "kind": "boot-input-observations", "input": {
        "path": str(path), "bytes": before.st_size, "sha256": image_hash}, **report,
        "validation": {"signature_or_avb": "not-verified", "partition_layout": "not-established",
                       "matching_module_set": "not-established", "device_runtime": "not-tested"}}


def parse_modinfo(data):
    fields = defaultdict(list)
    for item in data.decode("utf-8", "replace").split("\0"):
        # kmod --null emits .modinfo key=value records; filename uses a colon.
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", item, re.DOTALL)
        if match:
            fields[match.group(1)].append(match.group(2))
    if len(fields["name"]) != 1 or len(fields["vermagic"]) != 1:
        raise InspectionError("Module metadata has no unique name/vermagic")
    return {key: fields[key] for key in
            ("name", "vermagic", "depends", "softdep", "license", "sig_id") if fields[key]}


def inspect_module(path, root, label, modinfo):
    result = {"root": label, "path": str(path.relative_to(root))}
    try:
        require_regular(path)
        before = path.stat()
        with path.open("rb") as stream:
            result.update(bytes=before.st_size, sha256=hash_stream(stream, before.st_size))
        process = subprocess.run([modinfo, "-0", str(path)], capture_output=True,
                                 timeout=15, check=False)
        if process.returncode:
            raise InspectionError(process.stderr.decode("utf-8", "replace").strip())
        result["metadata"] = parse_modinfo(process.stdout)
        if file_identity(before) != file_identity(path.stat()):
            raise InspectionError("Module file changed during inspection")
        result["state"] = "observed"
    except (OSError, subprocess.TimeoutExpired, InspectionError) as error:
        result.update(state="inspection-failed", error=str(error))
    return result


def inspect_modules(roots, kernel_release=None):
    modinfo = shutil.which("modinfo")
    if not modinfo:
        raise InspectionError("modinfo from kmod is required for module metadata inspection")
    labels = [label for label, _ in roots]
    if len(labels) != len(set(labels)):
        raise InspectionError("Module root labels must be unique")
    work = []
    for label, root in roots:
        if not root.is_dir():
            raise InspectionError(f"Module root is absent: {root}")
        for path in sorted(root.rglob("*")):
            if any(path.name.endswith(suffix) for suffix in (".ko", ".ko.xz", ".ko.gz", ".ko.zst")):
                work.append((path, root, label))
    if not work:
        raise InspectionError("No supported module files found in the supplied roots")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda task: inspect_module(*task, modinfo), work))
    releases = Counter()
    providers = defaultdict(list)
    for result in results:
        if result["state"] == "observed":
            metadata = result["metadata"]
            releases[metadata["vermagic"][0].split()[0]] += 1
            providers[metadata["name"][0].replace("-", "_")].append(result)
    unresolved = Counter()
    for result in results:
        if result["state"] != "observed":
            continue
        dependencies = [name for value in result["metadata"].get("depends", [])
                        for name in value.split(",") if name]
        result["declared_dependencies_without_captured_provider"] = [
            name for name in dependencies if name.replace("-", "_") not in providers]
        unresolved.update(result["declared_dependencies_without_captured_provider"])
    duplicates = {name: {
        "files": [item["root"] + ":" + item["path"] for item in copies],
        "content_hashes": sorted({item["sha256"] for item in copies}),
        "classification": ("byte-identical-copies" if len({item["sha256"] for item in copies}) == 1
                           else "different-captured-file-bytes"),
    } for name, copies in providers.items() if len(copies) > 1}
    return {
        "report_format_version": 1, "kind": "module-input-observations",
        "roots": [{"label": label, "path": str(root)} for label, root in roots],
        "modules_found": len(results),
        "modules_observed": sum(item["state"] == "observed" for item in results),
        "unique_observed_module_names": len(providers),
        "unique_observed_file_hashes": len({item["sha256"] for item in results
                                           if item["state"] == "observed"}),
        "release_string_populations": dict(sorted(releases.items())),
        "comparison_kernel_release": kernel_release,
        "different_release_string_count": sum(count for release, count in releases.items()
                                               if kernel_release and release != kernel_release),
        "duplicate_provider_names": duplicates,
        "declared_dependencies_without_captured_provider": dict(sorted(unresolved.items())),
        "modules": results,
        "metadata_tool": {"path": modinfo, "version": subprocess.check_output(
            [modinfo, "--version"], text=True, timeout=15).strip()},
        "validation": {
            "scope": "Captured-file hashes and kmod metadata; no module loading or code execution.",
            "release_strings": "Different labels do not prove ABI incompatibility; equal labels do not prove compatibility.",
            "dependencies": "Only hard depends metadata is matched to captured names. A missing captured provider is a coverage gap, not proof of an absent built-in. Softdep order, ELF symbols and full closure are unverified.",
            "symbol_crcs_signatures_namespaces_and_runtime": "not-verified",
        },
    }


def write_report(path, encoded):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".input-report-", delete=False) as output:
            temporary = Path(output.name)
            output.write(encoded)
        # Replacing the directory entry avoids truncating a captured input
        # reached through an existing hard link at the report destination.
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("boot", help="Inspect Android boot header3/4 and a raw embedded kernel")
    boot.add_argument("image", type=Path)
    boot.add_argument("--output", type=Path)
    modules = sub.add_parser("modules", help="Inspect captured module files with kmod modinfo")
    modules.add_argument("--root", nargs=2, action="append", metavar=("LABEL", "DIRECTORY"), required=True)
    modules.add_argument("--kernel-release")
    modules.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "boot":
            image = args.image.absolute()
            if args.output and args.output.resolve() == image.resolve():
                raise InspectionError("Report output must not overwrite the input image")
            report = inspect_boot(image)
        else:
            roots = [(label, Path(directory).absolute()) for label, directory in args.root]
            if args.output and any(args.output.resolve().is_relative_to(root.resolve()) for _, root in roots):
                raise InspectionError("Report output must be outside all module input directories")
            report = inspect_modules(roots, args.kernel_release)
        report["inspector_source_sha256"] = sha256(Path(__file__).read_bytes())
        encoded = json.dumps(report, indent=2) + "\n"
        if args.output:
            write_report(args.output, encoded)
        else:
            sys.stdout.write(encoded)
        if args.command == "modules" and report["modules_observed"] != report["modules_found"]:
            return 1
        return 0
    except (OSError, subprocess.SubprocessError, InspectionError) as error:
        print(json.dumps({"state": "inspection-failed", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
