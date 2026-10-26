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

"""Validate and stage an explicitly selected kernel set; never execute its files."""

import argparse
from contextlib import contextmanager
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile


class StageError(ValueError):
    """The selected files cannot safely satisfy the staging contract."""


ROLES = {"kernel", "config", "module", "dtb", "dtbo"}
HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
OPTION = re.compile(r"CONFIG_[A-Za-z0-9_]+\Z")
REPORT_NAME = "stage-report.json"


def _relative(value, label):
    if not isinstance(value, str) or not value or "\\" in value:
        raise StageError(f"{label} must be a safe relative POSIX path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise StageError(f"{label} contains a control character")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise StageError(f"{label} must not be absolute or contain empty/dot/traversal components")
    return value


def _absolute(value):
    return Path(os.path.abspath(os.fspath(value)))


@contextmanager
def _open_regular(path):
    """Open every path component without following a symlink (Linux host)."""
    path = _absolute(path)
    parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    file_fd = None
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise StageError(f"Expected an ordinary file: {path}")
        with os.fdopen(file_fd, "rb") as stream:
            file_fd = None
            yield stream
    except OSError as error:
        raise StageError(f"Cannot read ordinary file {path}: {error.strerror}") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def _json_file(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise StageError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    with _open_regular(path) as stream:
        raw = stream.read()
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise StageError(f"Invalid JSON in {path}: {error}") from error
    if not isinstance(data, dict):
        raise StageError(f"Expected a JSON object: {path}")
    return data, hashlib.sha256(raw).hexdigest()


def _manifest(data):
    if set(data) != {"format_version", "state", "files"}:
        raise StageError("Manifest requires exactly format_version, state and files")
    if type(data["format_version"]) is not int or data["format_version"] != 1:
        raise StageError("Manifest format_version must be integer 1")
    if data["state"] != "selected":
        raise StageError("Prebuilt set is unselected; explicitly select a matching kernel/config set first")
    if not isinstance(data["files"], list) or not data["files"]:
        raise StageError("Selected manifest files must be a nonempty list")
    destinations = set()
    sources = set()
    result = []
    for index, item in enumerate(data["files"]):
        if not isinstance(item, dict) or set(item) != {"role", "path", "sha256", "destination"}:
            raise StageError(f"files[{index}] requires exactly role, path, sha256 and destination")
        if not isinstance(item["role"], str) or item["role"] not in ROLES:
            raise StageError(f"Unknown role in files[{index}]")
        source = _relative(item["path"], f"files[{index}].path")
        destination = _relative(item["destination"], f"files[{index}].destination")
        if not isinstance(item["sha256"], str) or not HASH.fullmatch(item["sha256"]):
            raise StageError(f"files[{index}].sha256 must be a SHA256 hex digest")
        if source in sources:
            raise StageError(f"Duplicate source path: {source}")
        sources.add(source)
        if destination == REPORT_NAME or destination.startswith(REPORT_NAME + "/"):
            raise StageError(f"Reserved report destination: {destination}")
        if any(destination == other or destination.startswith(other + "/") or
               other.startswith(destination + "/") for other in destinations):
            raise StageError(f"Duplicate or overlapping destination: {destination}")
        destinations.add(destination)
        result.append(dict(item, sha256=item["sha256"].lower()))
    for role in ("kernel", "config"):
        if sum(item["role"] == role for item in result) != 1:
            raise StageError(f"Selected set requires exactly one {role} file")
    return result


def _requirements(data):
    if not isinstance(data, dict):
        raise StageError("Kernel requirements must be an object")
    if set(data) - {"format_version", "required_options", "scope", "module_values"}:
        raise StageError("Unknown kernel requirements fields")
    if type(data.get("format_version")) is not int or data["format_version"] != 1:
        raise StageError("Requirements format_version must be integer 1")
    options = data.get("required_options")
    if not isinstance(options, dict) or not options:
        raise StageError("required_options must be a nonempty object")
    for name, values in options.items():
        if not OPTION.fullmatch(name):
            raise StageError(f"Invalid required kernel option: {name}")
        if (not isinstance(values, list) or not values or
                any(not isinstance(value, str) or value not in ("y", "m", "n") for value in values) or
                len(values) != len(set(values))):
            raise StageError(f"{name} requires a nonempty list of distinct y/m/n values")
    for name in ("scope", "module_values"):
        if name in data and not isinstance(data[name], str):
            raise StageError(f"Requirements {name} must be text")
    return options


def load_requirements(primary, additional=()):
    """Intersect shared and board requirements; a board cannot weaken the SoC."""
    paths = [_absolute(primary)] + [_absolute(path) for path in additional]
    if len(paths) != len(set(paths)):
        raise StageError("Duplicate kernel requirements descriptor")
    merged = {}
    descriptors = []
    for path in paths:
        data, descriptor_hash = _json_file(path)
        for name, values in _requirements(data).items():
            allowed = [value for value in merged.get(name, values) if value in values]
            if not allowed:
                raise StageError(f"Conflicting kernel requirements for {name}")
            merged[name] = allowed
        descriptors.append((path, descriptor_hash))
    return merged, descriptors


def _configuration(raw, requirements):
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise StageError("Selected config is not a UTF-8 kernel .config") from error
    options = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        disabled = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_]+) is not set", line)
        if disabled:
            name, value = disabled[1], "n"
        elif not line or line.startswith("#"):
            continue
        else:
            assignment = re.fullmatch(r"(CONFIG_[A-Za-z0-9_]+)=(.+)", line)
            if not assignment:
                raise StageError(f"Malformed kernel .config line {number}")
            name, value = assignment.groups()
        if name in options:
            raise StageError(f"Duplicate kernel configuration option: {name}")
        options[name] = value
    missing = [f"{name}: expected {' or '.join(allowed)}, observed {options.get(name, 'missing')}"
               for name, allowed in sorted(requirements.items()) if options.get(name) not in allowed]
    if missing:
        raise StageError("Kernel configuration requirements failed:\n" + "\n".join(missing))
    return {name: options[name] for name in sorted(requirements)}


def _hash_file(path, copy_to=None):
    digest = hashlib.sha256()
    count = 0
    with _open_regular(path) as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            count += len(block)
            if copy_to is not None:
                copy_to.write(block)
    return digest.hexdigest(), count


def _directory(path, create=False):
    """Reject symlinks in existing ancestors, optionally creating directories."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if not create:
                raise StageError(f"Directory does not exist: {current}")
            current.mkdir()
            mode = current.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise StageError(f"Expected an ordinary directory, without symlinks: {current}")


def _existing(output, expected):
    _directory(output)
    allowed_directories = set()
    for name in expected:
        allowed_directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
    found = set()
    for root, directories, files in os.walk(output, followlinks=False):
        for name in directories:
            entry = Path(root) / name
            relative = entry.relative_to(output).as_posix()
            if not stat.S_ISDIR(entry.lstat().st_mode) or relative not in allowed_directories:
                raise StageError(f"Unmanaged or unsafe output directory: {relative}")
        for name in files:
            entry = Path(root) / name
            relative = entry.relative_to(output).as_posix()
            if relative not in expected:
                raise StageError(f"Unmanaged output file: {relative}")
            observed, size = _hash_file(entry)
            if (observed, size) != expected[relative]:
                raise StageError(f"Existing output was changed or belongs to another selection: {relative}")
            found.add(relative)
    if found != set(expected):
        raise StageError(f"Existing output is incomplete: missing {sorted(set(expected) - found)}")


def _empty_hierarchy(output, expected):
    """Describe a build-created empty hierarchy, or return None if files exist."""
    _directory(output)
    allowed = set()
    for name in expected:
        allowed.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
    directories = []
    contains_files = False
    for root, names, files in os.walk(output, followlinks=False):
        contains_files = contains_files or bool(files)
        for name in names:
            entry = Path(root) / name
            relative = entry.relative_to(output).as_posix()
            if not stat.S_ISDIR(entry.lstat().st_mode) or relative not in allowed:
                raise StageError(f"Unmanaged or unsafe output directory: {relative}")
            directories.append(relative)
    if contains_files:
        return None
    return sorted(directories, key=lambda value: (len(PurePosixPath(value).parts), value))


def _restore_empty_hierarchy(output, directories):
    """Best effort restoration; never remove or replace any concurrent content."""
    try:
        _directory(output, create=True)
        for relative in directories:
            _directory(output / relative, create=True)
    except (StageError, OSError):
        # Concurrently changed paths belong to their writer. Leave them intact.
        pass


def _publish(temporary, output):
    """Linux atomic directory publication with no replacement, even in a race."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as error:
        raise StageError("Atomic staging requires Linux libc renameat2 support") from error
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    # AT_FDCWD=-100, RENAME_NOREPLACE=1. No selected input is executed here.
    if rename(-100, os.fsencode(temporary), -100, os.fsencode(output), 1) != 0:
        code = ctypes.get_errno()
        if code in (errno.EEXIST, errno.ENOTEMPTY):
            raise StageError(f"Output appeared during staging; preserved without replacement: {output}")
        raise StageError(f"Cannot atomically publish output: {os.strerror(code)}")


def describe(manifest_path, requirements_path, module_order_path=None, additional_requirements=()):
    """Validate descriptors without reading payloads or writing any files."""
    manifest, manifest_hash = _json_file(_absolute(manifest_path))
    _, descriptors = load_requirements(requirements_path, additional_requirements)
    files = _manifest(manifest)
    identity = hashlib.sha256((manifest_hash + "".join(item[1] for item in descriptors)).encode("ascii")).hexdigest()
    result = {"id": identity, "files": files}
    if module_order_path is not None:
        order, _ = _json_file(_absolute(module_order_path))
        if (not isinstance(order, dict) or set(order) != {"format_version", "modules"}
                or type(order["format_version"]) is not int or order["format_version"] != 1
                or not isinstance(order["modules"], list)):
            raise StageError("Module order requires format_version 1 and modules list")
        available = {item["destination"] for item in files if item["role"] == "module"}
        seen = set()
        for destination in order["modules"]:
            _relative(destination, "module order destination")
            if destination in seen or destination not in available:
                raise StageError(f"Module load destination is duplicate or not a selected module: {destination}")
            seen.add(destination)
        result["module_load_order"] = order["modules"]
    return result


def stage(manifest_path, requirements_path, output, allow_empty_output=False, additional_requirements=()):
    """Return provenance after validating and atomically staging a selected set."""
    manifest_path = _absolute(manifest_path)
    requirements_path = _absolute(requirements_path)
    output = _absolute(output)
    if output == manifest_path.parent or manifest_path.parent in output.parents:
        raise StageError("Output must be outside the manifest input directory")
    descriptor_paths = [requirements_path] + [_absolute(path) for path in additional_requirements]
    if output in manifest_path.parents or any(output in path.parents for path in descriptor_paths):
        raise StageError("Output must not contain an input descriptor")
    manifest, manifest_hash = _json_file(manifest_path)
    entries = _manifest(manifest)
    required_options, descriptors = load_requirements(requirements_path, additional_requirements)
    requirements_hash = descriptors[0][1]
    files = []
    config_observations = None
    for entry in entries:
        source = manifest_path.parent / entry["path"]
        observed, size = _hash_file(source)
        if observed != entry["sha256"]:
            raise StageError(f"SHA256 mismatch for selected {entry['role']}: {entry['path']}")
        if not size:
            raise StageError(f"Selected file is empty: {entry['path']}")
        if entry["role"] == "config":
            with _open_regular(source) as stream:
                config_data = stream.read()
            if hashlib.sha256(config_data).hexdigest() != observed:
                raise StageError("Selected kernel config changed during validation")
            config_observations = _configuration(config_data, required_options)
        files.append(dict(entry, bytes=size))
    report = {
        "format_version": 1,
        "state": "staged",
        "manifest_sha256": manifest_hash,
        "requirements_sha256": requirements_hash,
        "files": files,
        "configuration": {"required_options": required_options, "observed_options": config_observations},
        "limits": ["File hashes and declared kernel options were checked; module ABI, firmware closure and hardware compatibility were not established.",
                   "No boot images were generated and no selected file was executed or loaded."],
    }
    if len(descriptors) > 1:
        report["additional_requirements_sha256"] = [item[1] for item in descriptors[1:]]
    report_bytes = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    expected = {item["destination"]: (item["sha256"], item["bytes"]) for item in files}
    expected[REPORT_NAME] = (hashlib.sha256(report_bytes).hexdigest(), len(report_bytes))
    empty_directories = None
    if output.exists() or output.is_symlink():
        _directory(output)
        if allow_empty_output:
            empty_directories = _empty_hierarchy(output, expected)
        if empty_directories is None:
            _existing(output, expected)
            return report
    _directory(output.parent, create=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        for item in files:
            destination = temporary / item["destination"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                observed, size = _hash_file(manifest_path.parent / item["path"], copy_to=stream)
            if (observed, size) != (item["sha256"], item["bytes"]):
                raise StageError(f"Selected source changed during staging: {item['path']}")
        (temporary / REPORT_NAME).write_bytes(report_bytes)
        # Recheck descriptors before publishing, including their no-symlink rule.
        if (_json_file(manifest_path)[1] != manifest_hash or
                any(_json_file(path)[1] != expected_hash for path, expected_hash in descriptors)):
            raise StageError("An input descriptor changed during staging")
        if empty_directories is not None:
            # GN may precreate the expected output parents. Accept only their
            # original empty hierarchy; rmdir cannot remove files or links.
            if _empty_hierarchy(output, expected) != empty_directories:
                raise StageError(f"Precreated output no longer empty or was changed; preserved: {output}")
            try:
                for relative in reversed(empty_directories):
                    _directory(output / relative)
                    os.rmdir(output / relative)
                os.rmdir(output)
                _publish(temporary, output)
            except OSError as error:
                _restore_empty_hierarchy(output, empty_directories)
                raise StageError(f"Precreated output no longer empty; preserved: {output}") from error
            except BaseException:
                _restore_empty_hierarchy(output, empty_directories)
                raise
        elif output.exists() or output.is_symlink():
            _existing(output, expected)
        else:
            _publish(temporary, output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--additional-requirements", action="append", type=Path, default=[],
                        help="Intersect additional board requirements; may be repeated")
    parser.add_argument("--describe", action="store_true", help="Validate descriptors only; print their identity and file list")
    parser.add_argument("--module-order", type=Path, help="Validate explicit load destinations with --describe")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-empty-output", action="store_true", help="Accept the expected empty output-parent hierarchy precreated by the build tool")
    args = parser.parse_args(argv)
    if not args.describe and args.output is None:
        parser.error("--output is required when staging")
    if args.module_order is not None and not args.describe:
        parser.error("--module-order is only supported with --describe")
    try:
        if args.describe:
            report = describe(args.manifest, args.requirements, args.module_order, args.additional_requirements)
        else:
            report = stage(args.manifest, args.requirements, args.output,
                           allow_empty_output=args.allow_empty_output,
                           additional_requirements=args.additional_requirements)
    except (StageError, OSError) as error:
        print(f"stage_kernel: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
