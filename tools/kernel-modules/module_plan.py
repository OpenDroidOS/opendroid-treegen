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

"""Check a selected kernel/module set and generate native init load order."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import zlib


NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*\Z")
PATH = re.compile(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*\Z")
PHASES = ("post-fs", "post-fs-data", "boot")


class PlanError(ValueError):
    pass


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PlanError(f"duplicate JSON field: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise PlanError(f"{label} requires exactly {sorted(expected)}")


def regular(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise PlanError(f"expected a regular input without a symlink: {path}")
    return path


def digest(path):
    with regular(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def normalized(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise PlanError(f"invalid module name: {name}")
    return name.replace("-", "_")


def relative(value):
    if (not isinstance(value, str) or not PATH.fullmatch(value)
            or any(part in (".", "..") for part in value.split("/"))):
        raise PlanError("destination must be a safe relative path")
    return value


def module_metadata(path, modinfo):
    header = regular(path).read_bytes()[:64]
    if (header[:6] != b"\x7fELF\x02\x01" or len(header) < 64
            or struct.unpack_from("<HH", header, 16) != (1, 183)):
        raise PlanError(f"expected an uncompressed ARM64 ELF relocatable module: {path.name}")
    process = subprocess.run([modinfo, "-0", str(path)], capture_output=True,
                             check=False, timeout=20)
    if process.returncode:
        raise PlanError(f"modinfo failed for {path.name}")
    info = defaultdict(list)
    for item in process.stdout.decode("utf-8", "strict").split("\0"):
        match = re.fullmatch(r"([A-Za-z0-9_]+)=(.*)", item, re.DOTALL)
        if match:
            info[match[1]].append(match[2])
    if len(info["name"]) != 1 or len(info["vermagic"]) != 1:
        raise PlanError(f"module lacks unique name/vermagic: {path.name}")
    return dict(info)


def load_plan(path, modinfo):
    data = read_json(path)
    fields(data, {"format_version", "kernel", "config", "builtins", "modules", "firmware"}, "plan")
    if type(data["format_version"]) is not int or data["format_version"] != 1:
        raise PlanError("unsupported module plan format")
    base = path.parent

    def source(value):
        if not isinstance(value, str) or not value:
            raise PlanError("input paths must be nonempty strings")
        return regular((base / value).absolute())

    kernel, config = source(data["kernel"]), source(data["config"])
    config_bytes = config.read_bytes()
    options = dict(re.findall(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", config_bytes.decode(), re.MULTILINE))
    if options.get("CONFIG_MODULES") != "y":
        raise PlanError("selected kernel configuration does not enable modules")
    # Compare the full string. A different release may be KMI-compatible, but
    # that needs symbol/version/signature evidence beyond this deployment tool.
    raw = kernel.read_bytes()
    if raw[56:60] != b"ARMd":
        raise PlanError("expected a raw ARM64 kernel Image")
    configs = []
    for marker in re.finditer(b"IKCFG_ST", raw):
        try:
            decoder = zlib.decompressobj(31)
            embedded = decoder.decompress(raw[marker.end():], 16 * 1024 * 1024 + 1)
            if (decoder.eof and decoder.unused_data.startswith(b"IKCFG_ED")
                    and len(embedded) <= 16 * 1024 * 1024):
                configs.append(embedded)
        except zlib.error:
            pass
    if configs != [config_bytes]:
        raise PlanError("configuration does not match one unique embedded kernel config")
    magics = {value.decode() for value in re.findall(
        rb"[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9_.+/-]+ SMP [^\x00\n]{1,160}aarch64(?=\x00)", raw)}
    if len(magics) != 1:
        raise PlanError("kernel has no unique embedded ARM64 vermagic")
    kernel_magic = magics.pop()
    builtins = set()
    if data["builtins"] is not None:
        for line in source(data["builtins"]).read_text().splitlines():
            if not line.endswith(".ko"):
                raise PlanError("invalid modules.builtin entry")
            builtins.add(normalized(Path(line).stem))
    firmware = {}
    if not isinstance(data["firmware"], list) or not isinstance(data["modules"], list):
        raise PlanError("modules and firmware must be arrays")
    for item in data["firmware"]:
        fields(item, {"name", "source"}, "firmware item")
        name = relative(item["name"])
        if name in firmware:
            raise PlanError(f"duplicate firmware: {name}")
        firmware[name] = {"source": source(item["source"]), "sha256": digest(source(item["source"]))}
    modules, destinations, issues = {}, set(), []
    for item in data["modules"]:
        fields(item, {"source", "destination", "phase"}, "module item")
        destination = relative(item["destination"])
        if not destination.endswith(".ko") or destination in destinations:
            raise PlanError("module destinations must be unique .ko paths")
        destinations.add(destination)
        if item["phase"] not in PHASES:
            raise PlanError("module phase must be post-fs, post-fs-data or boot; early-root modules need ramdisk integration")
        file = source(item["source"])
        before = file.stat()
        metadata = module_metadata(file, modinfo)
        name = normalized(metadata["name"][0])
        if name in modules or name in builtins:
            raise PlanError(f"duplicate or built-in module selection: {name}")
        dependencies = [normalized(dep) for value in metadata.get("depends", [])
                        for dep in value.split(",") if dep]
        before_soft, after_soft = [], []
        for value in metadata.get("softdep", []):
            target = None
            for token in value.split():
                if token in ("pre:", "post:"):
                    target = before_soft if token == "pre:" else after_soft
                elif target is None:
                    raise PlanError(f"invalid softdep for {name}")
                else:
                    target.append(normalized(token))
        entry = {"name": name, "source": str(file), "sha256": digest(file),
                 "destination": destination, "phase": item["phase"],
                 "vermagic": metadata["vermagic"][0], "depends": dependencies,
                 "soft_pre": before_soft, "soft_post": after_soft,
                 "firmware": metadata.get("firmware", []),
                 "signer": metadata.get("signer", [])}
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                file.stat().st_ino, file.stat().st_size, file.stat().st_mtime_ns, file.stat().st_ctime_ns):
            raise PlanError(f"input changed during inspection: {file.name}")
        if entry["vermagic"] != kernel_magic:
            issues.append({"module": name, "kind": "vermagic-difference", "observed": entry["vermagic"]})
        for firmware_name in entry["firmware"]:
            if firmware_name not in firmware:
                issues.append({"module": name, "kind": "firmware-not-selected", "name": firmware_name})
        modules[name] = entry
    if modules and options.get("CONFIG_MODULE_SIG_FORCE") == "y":
        issues.append({"kind": "signature-enforcement-needs-trusted-key-validation"})
    return {"kernel": str(kernel), "kernel_sha256": digest(kernel),
            "config_sha256": digest(config), "kernel_vermagic": kernel_magic,
            "modules": modules, "builtins": sorted(builtins), "issues": issues,
            "firmware": {name: {"source": str(item["source"]), "sha256": item["sha256"]}
                         for name, item in firmware.items()}}


def order_modules(modules, builtins):
    predecessors = {name: set(item["depends"] + item["soft_pre"]) for name, item in modules.items()}
    for name, item in modules.items():
        for post in item["soft_post"]:
            if post not in modules and post not in builtins:
                raise PlanError(f"missing soft dependency: {name} -> {post}")
            if post in modules:
                predecessors[post].add(name)
    order, visiting = [], []

    def visit(name):
        if name in builtins or name in order:
            return
        if name not in modules:
            raise PlanError(f"missing module dependency: {name}")
        if name in visiting:
            raise PlanError("module dependency cycle: " + " -> ".join(visiting + [name]))
        visiting.append(name)
        for dependency in sorted(predecessors[name]):
            if dependency in modules and PHASES.index(modules[dependency]["phase"]) > PHASES.index(modules[name]["phase"]):
                raise PlanError(f"dependency loads in a later phase: {name} -> {dependency}")
            visit(dependency)
        visiting.pop()
        order.append(name)
    for name in sorted(modules, key=lambda name: PHASES.index(modules[name]["phase"])):
        visit(name)
    return order


def build_plan(manifest, output, modinfo):
    if output.exists() or output.is_symlink():
        raise PlanError("output already exists")
    report = load_plan(manifest, modinfo)
    try:
        order = order_modules(report["modules"], set(report["builtins"]))
    except PlanError as exc:
        order = []
        report["issues"].append({"kind": "dependency-order", "error": str(exc)})
    report["order"] = order
    report["metadata_checks_passed"] = not report["issues"]
    report["validation"] = {
        "scope": "Static input identity, metadata, dependency and phase checks only",
        "symbol_crcs_relocations_namespaces_trust": "not-verified",
        "firmware_installation_mounts_policy_and_runtime": "not-verified",
        "early_storage_loading": "requires a separate first-stage ramdisk integration"}
    output.mkdir(parents=False)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["issues"]:
        return False
    modules = report["modules"]
    jobs = [{"name": phase, "cmds": ["insmod /vendor/lib/opendroid/" + modules[name]["destination"]
             for name in order if modules[name]["phase"] == phase]} for phase in PHASES]
    (output / "init.modules.cfg").write_text(json.dumps({"jobs": [job for job in jobs if job["cmds"]]}, indent=2) + "\n")
    (output / "module-order.json").write_text(json.dumps({"format_version": 1,
        "modules": [modules[name]["destination"] for name in order]}, indent=2) + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        modinfo = shutil.which("modinfo")
        if not modinfo:
            raise PlanError("kmod modinfo is required")
        ready = build_plan(args.manifest.absolute(), args.output.absolute(), modinfo)
    except (PlanError, OSError, UnicodeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        parser.exit(2, f"module-plan: {exc}\n")
    if not ready:
        parser.exit(1, "module-plan: unresolved input checks; see report.json; no load configuration emitted\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
