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

"""Verify extractor outputs and describe candidates without choosing a port's inputs."""

from collections import Counter, defaultdict
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct


MAX_REPORT = 32 * 1024 * 1024
MAX_ARTIFACTS = 20000
MAX_TREE = 16 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")
STATES = {"extracted", "partial", "failed", "unsupported"}


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def object_value(value, name):
    require(isinstance(value, dict), f"{name} must be an object")
    return value


def integer(value, name):
    require(type(value) is int and value >= 0, f"{name} must be a nonnegative integer")
    return value


def strings(value, name):
    require(isinstance(value, list) and all(isinstance(x, str) for x in value),
            f"{name} must be a list of strings")
    return value


def hash_value(value):
    require(isinstance(value, str) and HASH.fullmatch(value), "Invalid evidence SHA256")
    return value


def relative_path(value):
    require(isinstance(value, str) and value and "\\" not in value
            and not any(ord(c) < 32 for c in value), "Unsafe evidence path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and path.parts
            and str(path) == value, f"Unsafe or noncanonical evidence path: {value}")
    return value


def ordinary_path(path, directory=False):
    path = Path(os.path.abspath(path))
    for parent in [*reversed(path.parents), path]:
        require(not parent.is_symlink(), f"Symbolic link in evidence path: {parent}")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            f"Evidence must be an ordinary {'directory' if directory else 'file'}: {path}")
    return path


def fingerprint(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def ordinary_file(path):
    path = Path(os.path.abspath(path))
    parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        # Resolve every component relative to an open directory, so a directory
        # substituted after preflight cannot redirect reads through a symlink.
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            yield stream, parent, path.name
    except OSError as error:
        raise EvidenceError(f"Cannot read ordinary evidence file {path}: {error}") from error
    finally:
        os.close(parent)


def read_file(path, expected_size=None, expected_hash=None, retain_limit=0):
    with ordinary_file(path) as (stream, parent, name):
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), f"Not a regular evidence file: {path}")
        if expected_size is not None:
            require(before.st_size == expected_size, f"Evidence size differs: {path}")
        digest = hashlib.sha256()
        content = bytearray()
        size = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if retain_limit:
                require(size <= retain_limit, f"Evidence file exceeds read limit: {path}")
                content.extend(chunk)
        require(fingerprint(before) == fingerprint(os.fstat(stream.fileno()))
                == fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                f"Evidence changed during reading: {path}")
    actual = digest.hexdigest()
    require(expected_hash is None or actual == expected_hash, f"Evidence hash differs: {path}")
    return bytes(content), actual


def read_report(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate evidence JSON key: {key}")
            result[key] = value
        return result

    raw, digest = read_file(path, retain_limit=MAX_REPORT)
    report = json.loads(raw, object_pairs_hook=unique,
                        parse_constant=lambda value: require(False, f"Invalid JSON constant: {value}"))
    return object_value(report, "Extraction report"), digest


def inspect_tree(data):
    """Observe a bounded v17 FDT body; do not apply overlays or choose hardware."""
    try:
        require(len(data) >= 40, "truncated FDT header")
        magic, total, off, names, reserve, version, compat, _, names_len, body_len = struct.unpack_from(">10I", data)
        require(magic == 0xD00DFEED and version == 17 and compat <= 17, "unsupported FDT header")
        require(40 <= total <= len(data) <= MAX_TREE, "FDT size outside bounds")
        require(40 <= off <= total - body_len and 40 <= names <= total - names_len
                and 40 <= reserve <= total - 16, "FDT blocks outside bounds")
        end, pos, depth, nodes, properties = off + body_len, off, 0, 0, 0
        root = {}
        ended = False
        while pos < end:
            require(pos + 4 <= end, "truncated FDT token")
            token = struct.unpack_from(">I", data, pos)[0]
            pos += 4
            if token == 1:
                zero = data.find(b"\0", pos, end)
                require(zero >= pos and (depth > 0 or nodes == 0 and zero == pos), "invalid FDT node")
                pos = (zero + 4) & ~3
                depth += 1
                nodes += 1
            elif token == 2:
                require(depth > 0, "unbalanced FDT node")
                depth -= 1
            elif token == 3:
                require(depth > 0 and pos + 8 <= end, "invalid FDT property")
                length, name_offset = struct.unpack_from(">2I", data, pos)
                pos += 8
                require(length <= end - pos and name_offset < names_len, "FDT property outside bounds")
                name_end = data.find(b"\0", names + name_offset, names + names_len)
                require(name_end >= 0, "unterminated FDT property name")
                name = data[names + name_offset:name_end]
                if depth == 1 and name in (b"model", b"compatible"):
                    value = data[pos:pos + length]
                    require(value.endswith(b"\0") and length <= 65536, "invalid root identity strings")
                    root[name.decode()] = value[:-1].decode("utf-8").split("\0")
                pos = (pos + length + 3) & ~3
                properties += 1
            elif token == 4:
                continue
            elif token == 9:
                require(depth == 0 and nodes > 0, "unclosed FDT root")
                ended = True
                break
            else:
                raise EvidenceError("unknown FDT token")
        require(ended and pos <= end, "missing FDT end")
        return {"state": "empty-root" if nodes == 1 and properties == 0 else "structure-observed",
                "nodes": nodes, "properties": properties, "root_identity": root}
    except (EvidenceError, UnicodeError, struct.error) as error:
        return {"state": "not-established", "reason": str(error)}


def portable_source(value, labels):
    source = object_value(value, "Artifact source")
    require(isinstance(source.get("input"), str) and source["input"] in labels,
            "Artifact source does not reference a reported input")
    result = {"input": source["input"]}
    for key in ("component", "directory_path", "archive_path", "data_entry"):
        if key in source:
            result[key] = relative_path(source[key])
    if "filesystem_path" in source:
        name = source["filesystem_path"]
        require(isinstance(name, str) and name.startswith("/"), "Invalid in-image filesystem path")
        result["filesystem_path"] = "/" + relative_path(name[1:])
    for key in ("offset", "offset_in_component", "offset_in_kernel", "offset_in_decoded_archive", "archive", "inode"):
        if key in source:
            result[key] = integer(source[key], key)
    for key in ("file_sha256", "component_sha256"):
        if key in source:
            result[key] = hash_value(source[key])
    if "entry" in source:
        result["entry"] = (relative_path(source["entry"]) if isinstance(source["entry"], str)
                           else integer(source["entry"], "Entry index"))
    for key in ("compression", "parser_revision", "filesystem"):
        if key in source:
            require(isinstance(source[key], str), f"Invalid provenance {key}")
            result[key] = source[key]
    return result


def load_report(supplied):
    supplied = ordinary_path(supplied, directory=Path(supplied).is_dir())
    path = supplied / "extraction-report.json" if supplied.is_dir() else supplied
    report, report_hash = read_report(path)
    require(type(report.get("report_format_version")) is int and report["report_format_version"] == 1
            and report.get("kind") == "opendroid-prebuilt-extraction-evidence", "Unsupported extraction report")
    extractor = hash_value(report.get("extractor_sha256"))
    inspector = hash_value(report.get("inspector_sha256"))
    inputs = report.get("inputs")
    require(isinstance(inputs, list) and 0 < len(inputs) <= MAX_ARTIFACTS, "Invalid extraction input list")
    labels, normalized_inputs = set(), []
    for item in inputs:
        item = object_value(item, "Extraction input")
        label = item.get("label")
        require(isinstance(label, str) and LABEL.fullmatch(label) and label not in labels,
                "Invalid or duplicate extraction input label")
        require(isinstance(item.get("state"), str) and item["state"] in STATES, "Invalid extraction input state")
        labels.add(label)
        normalized = {"label": label, "state": item["state"], "source_identity": "individual-artifact-hashes"}
        if "sha256" in item:
            normalized.update(sha256=hash_value(item["sha256"]), bytes=integer(item.get("bytes"), "Input size"),
                              source_identity="reported-original-file-hash-not-rechecked")
        required = []
        for key in ("boot_layout", "directory"):
            if key in item:
                layout = object_value(item[key], key)
                content = layout.get("required_content", [])
                require(isinstance(content, list), "required_content must be a list")
                for field in content:
                    field = object_value(field, "Required content")
                    require(isinstance(field.get("component"), str) and field.get("state") in ("observed", "missing"),
                            "Invalid required-content observation")
                    required.append({"component": field["component"], "state": field["state"]})
        normalized["required_content"] = required
        if "boot_layout" in item:
            layout = item["boot_layout"]
            normalized["reported_boot_layout"] = {
                key: integer(layout[key], key) for key in ("header_version", "page_bytes") if key in layout}
            if "parser_sha256" in layout:
                normalized["reported_boot_layout"]["parser_sha256"] = hash_value(layout["parser_sha256"])
        normalized["reported_limitation_count"] = len(strings(item.get("limitations", []), "Input limitations"))
        normalized["reported_error_present"] = "error" in item
        normalized_inputs.append(normalized)

    artifacts = report.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) <= MAX_ARTIFACTS, "Invalid artifact list")
    checked = {}
    trees = []
    for item in artifacts:
        item = object_value(item, "Artifact")
        name = relative_path(item.get("path"))
        require(name not in checked, f"Duplicate artifact path: {name}")
        kind = item.get("kind")
        require(isinstance(kind, str) and LABEL.fullmatch(kind), "Invalid artifact kind")
        size, digest = integer(item.get("bytes"), "Artifact size"), hash_value(item.get("sha256"))
        source = portable_source(item.get("source"), labels)
        is_tree = kind in ("dtb-candidate", "dtbo-entry")
        require(not is_tree or size <= MAX_TREE, "Device-tree artifact exceeds read limit")
        content, _ = read_file(path.parent / name, size, digest, MAX_TREE if is_tree else 0)
        entry = {"kind": kind, "path": name, "bytes": size, "sha256": digest, "source": source}
        if kind == "dtbo-entry":
            details = object_value(item.get("details"), "DTBO entry identity")
            custom = details.get("custom")
            require(isinstance(custom, list) and len(custom) == 4, "Invalid DTBO custom identity")
            entry["table_identity"] = {"id": integer(details.get("id"), "DTBO id"),
                                       "revision": integer(details.get("revision"), "DTBO revision"),
                                       "custom": [integer(x, "DTBO custom") for x in custom]}
        checked[name] = entry
        if is_tree:
            trees.append({"path": name, **inspect_tree(content)})

    kernels = []
    for item in inputs:
        if "kernel_observations" not in item:
            continue
        observed = object_value(item["kernel_observations"], "Kernel observations")
        candidates = [x["path"] for x in checked.values() if x["source"]["input"] == item["label"]
                      and x["kind"] in ("kernel-payload", "kernel-decoded-payload")]
        require(candidates, "Kernel observations have no captured kernel artifact")
        kernels.append({"input": item["label"], "artifacts": candidates,
                        "config_artifacts": [x["path"] for x in checked.values()
                                             if x["source"]["input"] == item["label"]
                                             and x["kind"] in ("embedded-kernel-config", "kernel-config-candidate")],
                        "reported_release_strings": strings(observed.get("release_strings", []), "Kernel releases"),
                        "metadata_source": "extractor-report-not-reinspected"})

    modules = []
    observations = object_value(report.get("module_observations", {}), "Module observations")
    records = observations.get("modules", [])
    require(isinstance(records, list) and len(records) <= MAX_ARTIFACTS, "Invalid module observation list")
    seen = set()
    for item in records:
        item = object_value(item, "Module observation")
        name = relative_path(item.get("path"))
        require(item.get("root") == "extracted" and name not in seen and name in checked,
                "Module observation has a duplicate or unknown artifact")
        artifact = checked[name]
        state = item.get("state")
        require(isinstance(state, str) and state in ("observed", "inspection-failed"), "Unsupported module observation state")
        require(artifact["kind"] == "kernel-module", "Module observation references a non-module artifact")
        if state == "observed" or "sha256" in item or "bytes" in item:
            require(item.get("sha256") == artifact["sha256"] and type(item.get("bytes")) is int
                    and item["bytes"] == artifact["bytes"], "Module observation does not match captured module identity")
        seen.add(name)
        module = {"path": name, "state": state, "metadata_source": "extractor-report-not-reinspected"}
        if state == "observed":
            metadata = object_value(item.get("metadata"), "Module metadata")
            names = strings(metadata.get("name"), "Module names")
            vermagic = strings(metadata.get("vermagic"), "Module vermagic")
            require(len(names) == len(vermagic) == 1 and names[0] and vermagic[0].split(),
                    "Observed module needs one name and vermagic")
            module.update(name=names[0], vermagic=vermagic[0], release_string=vermagic[0].split()[0],
                          depends=[x for value in strings(metadata.get("depends", []), "Module depends")
                                   for x in value.split(",") if x])
        modules.append(module)
    observed = [m for m in modules if m["state"] == "observed"]
    providers = defaultdict(list)
    for module in observed:
        providers[module["name"].replace("-", "_")].append(module["path"])
    duplicates = []
    for name, paths in sorted(providers.items()):
        if len(paths) > 1:
            hashes = sorted({checked[p]["sha256"] for p in paths})
            duplicates.append({"name": name, "paths": paths, "sha256": hashes,
                               "state": "byte-identical-copies" if len(hashes) == 1 else "different-captured-bytes"})
    missing = Counter(dependency for m in observed for dependency in m["depends"]
                      if dependency.replace("-", "_") not in providers)
    module_count = sum(x["kind"] == "kernel-module" for x in checked.values())
    populations = dict(sorted(Counter(m["release_string"] for m in observed).items()))
    kernel_releases = sorted({release for k in kernels for release in k["reported_release_strings"]})
    return {
        "report_sha256": report_hash, "extractor_sha256": extractor, "inspector_sha256": inspector,
        "inputs": normalized_inputs, "artifacts": list(checked.values()),
        "counts": dict(sorted(Counter(x["kind"] for x in checked.values()).items())),
        "kernel_candidates": kernels, "device_trees": trees,
        "modules": {"captured": module_count, "metadata_observed": len(observed),
                    "metadata_unknown": module_count - len(observed), "records": modules,
                    "release_string_populations": populations, "duplicate_providers": duplicates,
                    "hard_dependencies_without_captured_provider": dict(sorted(missing.items())),
                    "release_strings_outside_kernel_candidates": sorted(set(populations) - set(kernel_releases))},
        "all_requested_inputs_extracted": all(x["state"] == "extracted" for x in normalized_inputs),
    }


def load_extractions(paths):
    reports, seen = [], set()
    for path in paths:
        report = load_report(path)
        require(report["report_sha256"] not in seen, "The same extraction report was supplied twice")
        seen.add(report["report_sha256"])
        reports.append(report)
    reports.sort(key=lambda report: report["report_sha256"])
    kinds = Counter()
    populations = Counter()
    kernels = set()
    warnings = []
    for report in reports:
        identity = report["report_sha256"]
        kinds.update(report["counts"])
        populations.update(report["modules"]["release_string_populations"])
        kernels.update(r for k in report["kernel_candidates"] for r in k["reported_release_strings"])
        for item in report["inputs"]:
            if item["state"] != "extracted":
                warnings.append({"id": "incomplete-extraction", "report_sha256": identity,
                                 "input": item["label"], "state": item["state"]})
        if report["modules"]["metadata_unknown"]:
            warnings.append({"id": "module-metadata-unknown", "report_sha256": identity})
        report_populations = report["modules"]["release_string_populations"]
        if report_populations:
            if not any(k["reported_release_strings"] for k in report["kernel_candidates"]):
                warnings.append({"id": "kernel-release-unavailable", "report_sha256": identity})
            elif report["modules"]["release_strings_outside_kernel_candidates"]:
                warnings.append({"id": "module-kernel-release-label-difference", "report_sha256": identity,
                                 "values": report["modules"]["release_strings_outside_kernel_candidates"]})
        empty = [x["path"] for x in report["device_trees"] if x["state"] == "empty-root"]
        if empty:
            warnings.append({"id": "empty-device-tree", "report_sha256": identity, "paths": empty})
        invalid = [x["path"] for x in report["device_trees"] if x["state"] == "not-established"]
        if invalid:
            warnings.append({"id": "device-tree-structure-unestablished", "report_sha256": identity, "paths": invalid})
        if any(x["state"] == "different-captured-bytes" for x in report["modules"]["duplicate_providers"]):
            warnings.append({"id": "conflicting-module-providers", "report_sha256": identity})
    if len(populations) > 1:
        warnings.append({"id": "multiple-module-release-strings", "values": sorted(populations)})
    if len(kernels) > 1:
        warnings.append({"id": "multiple-kernel-release-strings", "values": sorted(kernels)})
    if len(reports) > 1:
        warnings.append({"id": "separate-captures-unbound", "required": "Keep report identities separate until a compatible set is explicitly selected."})
    return {
        "evidence_version": 1, "state": "verified-artifact-identities" if reports else "not-supplied",
        "reports": reports, "summary": {
            "reports": len(reports), "artifacts": sum(kinds.values()), "kinds": dict(sorted(kinds.items())),
            "kernel_release_strings": sorted(kernels), "module_release_string_populations": dict(sorted(populations.items())),
            "empty_device_trees": sum(x["state"] == "empty-root" for r in reports for x in r["device_trees"]),
        },
        "warnings": warnings, "selection": {"state": "unselected", "kernel": None, "modules": [], "device_trees": [], "firmware": []},
        "validation": {
            "artifact_identity": "Every listed ordinary file size/SHA256 rechecked; no input or tool paths from the report opened.",
            "metadata": "Release/name/dependency observations originate in the identified extractor report, not a fresh ABI inspection.",
            "provenance": "Original absolute input/tool paths and free-form errors omitted; report hash, input labels/hashes and artifact origin fields retained. Original input hashes not rechecked.",
            "release_strings": "Matching labels do not prove ABI compatibility; different labels require review, not an automatic incompatibility verdict.",
            "dependencies": "Coverage is computed separately within each report; missing providers can be built into the kernel. Symbols, CRCs, signatures, namespaces and softdeps unverified.",
            "device_trees": "Bounded FDT structure/root identity observations only; no overlay selection/application or hardware association.",
            "headers_firmware": "Captured header/config candidates do not establish a matching build tree; firmware requirements remain unaudited.",
            "authentication": "Hashes establish content identity, not trusted authorship or device suitability.",
        },
    }
