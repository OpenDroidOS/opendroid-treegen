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

"""Inspect source interfaces without importing or executing checkout code."""

import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


BASE_PRODUCT = "productdefine/common/base/standard_system.json"


class ContractError(ValueError):
    """The checkout lacks a source interface used by the generated files."""


def _json(text, label):
    try:
        # Match the checkout loader's last-key-wins JSON semantics.
        return json.loads(text)
    except (ValueError, TypeError) as error:
        raise ContractError(f"Invalid JSON in {label}: {error}") from error


def _code(text):
    # Preserve quoted strings while removing GN/C comments. Comment edits do
    # not change the symbols inspected below.
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*'
    return re.sub(pattern, lambda match: "" if match[0].startswith(("#", "//", "/*")) else match[0], text)


def inspect(root, data, common_selections):
    root = root.resolve()
    observed, checks, selected = {}, [], {}

    def read(relative):
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
            raise ContractError(f"Unsafe source interface path: {relative}")
        source = root / relative
        if not source.resolve().is_relative_to(root) or not source.is_file():
            raise ContractError(f"Required source interface is absent or outside the checkout: {relative}")
        raw = source.read_bytes()
        observed[relative] = hashlib.sha256(raw).hexdigest()
        try:
            return raw.decode("utf-8-sig")
        except UnicodeError as error:
            raise ContractError(f"Source interface is not UTF-8: {relative}") from error

    def python_api(relative, names):
        try:
            tree = ast.parse(read(relative), filename=relative)
        except SyntaxError as error:
            raise ContractError(f"Invalid Python interface in {relative}:{error.lineno}") from error
        for dotted, parameters in names.items():
            scope = tree
            for name in dotted.split("."):
                scope = next((node for node in scope.body
                              if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name), None)
                if scope is None:
                    raise ContractError(f"Required Python interface is absent: {relative}: {dotted}")
            if not isinstance(scope, ast.FunctionDef):
                raise ContractError(f"Expected a Python function: {relative}: {dotted}")
            actual = {arg.arg for arg in scope.args.posonlyargs + scope.args.args + scope.args.kwonlyargs}
            if not set(parameters).issubset(actual):
                raise ContractError(f"Required parameters changed: {relative}: {dotted}")
            positional = scope.args.posonlyargs + scope.args.args
            mandatory = {arg.arg for arg in positional[:len(positional) - len(scope.args.defaults)]}
            mandatory.update(arg.arg for arg, default in zip(scope.args.kwonlyargs, scope.args.kw_defaults)
                             if default is None)
            if mandatory - set(parameters) - {"self", "cls"}:
                raise ContractError(f"New required parameters: {relative}: {dotted}")
        checks.append({"interface": relative, "checked": "Python declarations and parameter names"})
        return tree

    def selection(value, label):
        if not isinstance(value, dict) or not isinstance(value.get("subsystems"), list):
            raise ContractError(f"Expected a product subsystems list: {label}")
        for subsystem in value["subsystems"]:
            if not isinstance(subsystem, dict) or not isinstance(subsystem.get("subsystem"), str):
                raise ContractError(f"Invalid subsystem declaration: {label}")
            if not isinstance(subsystem.get("components"), list):
                raise ContractError(f"Expected a components list: {label}")
            for component in subsystem["components"]:
                if not isinstance(component, dict) or not isinstance(component.get("component"), str):
                    raise ContractError(f"Invalid component declaration: {label}")
                identity = (subsystem["subsystem"], component["component"])
                if component.get("exclude") == "true":
                    selected.pop(identity, None)
                else:
                    selected[identity] = component

    def product(relative, stack=()):
        if relative in stack:
            raise ContractError(f"Product inheritance cycle: {relative}")
        value = _json(read(relative), relative)
        if not isinstance(value, dict) or not isinstance(value.get("inherit", []), list):
            raise ContractError(f"Invalid product inheritance: {relative}")
        for inherited in value.get("inherit", []):
            if not isinstance(inherited, str):
                raise ContractError(f"Invalid inherited product path: {relative}")
            product(inherited, stack + (relative,))
        selection(value, relative)

    product(data["base_product"])
    if data.get("system_profile") == "tablet":
        product("productdefine/common/inherit/tablet.json")
    for value in common_selections:
        selection(value, "generated common configuration")
    checks.append({"interface": "product JSON", "checked": "inheritance, subsystem/component lists and exclusions"})

    python_api("build/hb/util/product_util.py", {
        "ProductUtil.get_products": (), "ProductUtil.get_device_info": ("product_json",),
        "ProductUtil.get_compiler": ("config_path",),
    })
    python_api("build/hb/util/preloader/preloader_process_data.py", {
        "Product._get_device_specific_subsystem": (), "Product._get_product_specific_subsystem": (),
    })
    python_api("build/hb/util/loader/load_bundle_file.py", {"BundlePartObj.to_ohos_build": ()})
    python_api("build/templates/metadata/gen_module_info.py", {
        "gen_install_dests": tuple(name + "_base_dir" for name in (
            "system", "ramdisk", "vendor", "updater", "updater_vendor", "sys_prod", "chip_prod",
            "eng_system", "eng_chipset", "cloud_rom")) + (
                "install_images", "source_file_name", "module_install_dir", "relative_install_dir", "module_type"),
    })

    for relative, template in (("build/templates/cxx/prebuilt.gni", "ohos_prebuilt_etc"),
                               ("build/templates/common/copy.gni", "ohos_copy")):
        if not re.search(r'\btemplate\s*\(\s*"' + template + r'"\s*\)', _code(read(relative))):
            raise ContractError(f"Required GN template is absent: {relative}: {template}")
        checks.append({"interface": relative, "checked": f"GN template {template}"})
    for relative in (".gn", "build/ohos.gni", "build/config/BUILDCONFIG.gn"):
        read(relative)
    if data.get("native_config", {}).get("images"):
        for relative in ("build/ohos/build_var.gni", "build/ohos/images/mkimage/mkextimage.py"):
            read(relative)
    if data.get("native_config", {}).get("firmware_directory"):
        relative = "base/startup/init/services/init/init_common_cmds.c"
        if not re.search(r'\{\s*"write\s+"\s*,', _code(read(relative))):
            raise ContractError(f"Native init write command is absent: {relative}")
        checks.append({"interface": relative, "checked": "registered init write command"})
    if data.get("module_load_order"):
        relative = "base/startup/init/services/init/standard/init_cmds.c"
        if not re.search(r'\{\s*"insmod\s+"\s*,', _code(read(relative))):
            raise ContractError(f"Native init insmod command is absent: {relative}")
        checks.append({"interface": relative, "checked": "registered init insmod command"})
    mounts = data.get("native_config", {}).get("mounts", [])
    if mounts:
        relative = "base/startup/init/interfaces/innerkits/fs_manager/fstab.c"
        flags = _code(read(relative))
        for flag in {flag for mount in mounts for flag in mount["manager_flags"]}:
            if not re.search(r'\{\s*"' + re.escape(flag) + r'"\s*,', flags):
                raise ContractError(f"Native fstab flag is absent: {relative}: {flag}")
        checks.append({"interface": relative, "checked": "requested fstab manager flag declarations"})

    config_path = "build/subsystem_config.json"
    config = _json(read(config_path), config_path)
    if not isinstance(config, dict):
        raise ContractError("Expected a subsystem registry object")
    scanner_path = "build/hb/util/loader/subsystem_scan.py"
    try:
        scanner = ast.parse(read(scanner_path))
        defaults = next(ast.literal_eval(node.value) for node in scanner.body
                        if isinstance(node, ast.Assign) and any(
                            isinstance(target, ast.Name) and target.id == "_default_subsystem" for target in node.targets))
    except (SyntaxError, ValueError, TypeError, StopIteration) as error:
        raise ContractError(f"Cannot inspect native default subsystem paths: {scanner_path}") from error
    if not isinstance(defaults, dict):
        raise ContractError("Default subsystem paths must be an object")
    roots = {}
    required_subsystems = {subsystem for subsystem, name in selected if subsystem != name or subsystem in config}
    for subsystem in sorted(set(config) | set(defaults) | required_subsystems):
        entry = config.get(subsystem, {})
        if not isinstance(entry, dict):
            raise ContractError(f"Invalid subsystem registry entry: {subsystem}")
        value = defaults.get(subsystem, entry.get("path"))
        paths = value if isinstance(value, list) else [value]
        if any(not isinstance(path, str) for path in paths):
            raise ContractError(f"Source subsystem path is absent: {subsystem}")
        roots[subsystem] = paths
    candidates = {}
    ignored = []
    unavailable = []
    seen = set()
    for subsystem, paths in roots.items():
        for relative in paths:
            # Validate registry paths before walking; symlink directories are not followed.
            base = root / relative
            if not base.resolve().is_relative_to(root) or not base.is_dir():
                if subsystem in required_subsystems:
                    raise ContractError(f"Source subsystem directory is absent or outside the checkout: {relative}")
                unavailable.append(relative)
                continue
            for directory, children, files in os.walk(base, followlinks=False):
                children[:] = sorted(name for name in children if name not in {
                    ".git", ".repo", ".gitee", ".github", "doc", "docs", "node_modules", "out", "prebuilts"})
                if "bundle.json" not in files:
                    continue
                relative_bundle = str((Path(directory) / "bundle.json").relative_to(root))
                if relative_bundle in seen:
                    continue
                seen.add(relative_bundle)
                try:
                    text = read(relative_bundle)
                    bundle = _json(text, relative_bundle)
                except ContractError as error:
                    ignored.append({"file": relative_bundle, "error": str(error)})
                    continue
                component = bundle.get("component") if isinstance(bundle, dict) else None
                if not isinstance(component, dict):
                    continue
                identity = (component.get("subsystem"), component.get("name"))
                if not all(isinstance(value, str) for value in identity):
                    ignored.append({"file": relative_bundle, "error": "Invalid component identity"})
                    continue
                candidates.setdefault(identity[1], []).append((relative_bundle, component))
    components = []
    for identity, selection_value in selected.items():
        # The native loader resolves component names globally and separately
        # checks the product's subsystem name. Preserve both names as evidence.
        found = candidates.get(identity[1], [])
        if len(found) != 1:
            state = "absent" if not found else "ambiguous"
            raise ContractError(f"Source component is {state}: {identity[0]}:{identity[1]}")
        path, component = found[0]
        features = component.get("features", [])
        requested = selection_value.get("features", [])
        if not isinstance(features, list) or not isinstance(requested, list):
            raise ContractError(f"Invalid component feature declaration: {path}")
        declared = {value.split("=", 1)[0].strip() for value in features if isinstance(value, str)}
        for value in requested:
            name = value.split("=", 1)[0].strip() if isinstance(value, str) else None
            if name not in declared:
                raise ContractError(f"Source component feature is absent: {path}: {name}")
        components.append({"subsystem": identity[0], "component": identity[1], "bundle": path,
                           "declared_subsystem": component["subsystem"]})
    checks.append({"interface": "component registry", "checked": "selected component names and feature declarations"})
    return {
        "format_version": 1, "checks": checks, "components": components,
        "files_sha256": dict(sorted(observed.items())), "unreadable_registry_entries": ignored,
        "unavailable_unselected_paths": sorted(set(unavailable)),
        "limits": ["Source declarations were inspected without executing checkout code.",
                   "Declaration checks do not establish implementation semantics, GN dependency closure, compilation or hardware compatibility."],
    }
