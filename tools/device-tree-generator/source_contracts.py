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


def _select_product_file(relative, read, selection):
    """Apply one directly inherited product file without following its inherit list."""
    value = _json(read(relative), relative)
    if not isinstance(value, dict):
        raise ContractError(f"Invalid product config: {relative}")
    selection(value, relative)


def _product_feature_components(upstream_selected, feature_catalog, choices, common_selected=None,
                                bootstrap_common=False):
    components = []
    unknown = set(choices) - set(feature_catalog)
    if unknown:
        raise ContractError(f"Unknown product feature: {sorted(unknown)}")
    catalog_groups = {}
    for option, item in feature_catalog.items():
        identity = (item["subsystem"], item["component"])
        catalog_groups.setdefault(identity, []).append((option, item))
    for identity, options in sorted(catalog_groups.items()):
        inherited = upstream_selected.get(identity)
        if inherited is None:
            raise ContractError(
                f"Product feature component is not selected by the upstream profile: {identity[0]}:{identity[1]}")
        selected = [(option, item) for option, item in options if option in choices]
        default_entry = (common_selected or {}).get(identity, inherited)
        # In bootstrap mode the generated common fragment replaces the whole
        # native component entry. Do not silently lose native fields when no
        # product choice causes us to emit a preserving override.
        if bootstrap_common and not selected:
            lost_keys = set(inherited) - set(default_entry)
            managed = {item["feature"] for _, item in options}

            def unmanaged_features(component):
                parsed = {}
                for assignment in component.get("features", []):
                    if not isinstance(assignment, str) or "=" not in assignment:
                        raise ContractError(
                            f"Invalid inherited feature assignment: {identity[0]}:{identity[1]}")
                    name, value = (part.strip() for part in assignment.split("=", 1))
                    if name not in managed:
                        parsed[name] = value
                return parsed

            original_features = unmanaged_features(inherited)
            default_features = unmanaged_features(default_entry)
            lost_features = {name for name, value in original_features.items()
                             if default_features.get(name) != value}
            if lost_keys or lost_features:
                details = ", ".join(sorted(lost_keys | ({"features"} if lost_features else set())))
                raise ContractError(
                    f"Generated common defaults would discard inherited {identity[0]}:{identity[1]} "
                    f"fields ({details}); add an explicit product_features choice to preserve them")
        if not selected:
            continue
        # For bootstrap choices, copy the effective upstream entry so its
        # unrelated native features and metadata survive the product override.
        original = inherited if bootstrap_common else default_entry
        assignments = {}
        for assignment in original.get("features", []):
            if not isinstance(assignment, str) or "=" not in assignment:
                raise ContractError(f"Invalid inherited feature assignment: {identity[0]}:{identity[1]}")
            name, value = (part.strip() for part in assignment.split("=", 1))
            if name in assignments and assignments[name] != value:
                raise ContractError(f"Conflicting inherited feature assignment: {identity[0]}:{identity[1]}:{name}")
            assignments[name] = value
        for _, item in options:
            assignments[item["feature"]] = str(item["default"]).lower()
        for option, item in selected:
            assignments[item["feature"]] = str(choices[option]).lower()
        if selected:
            entry = {key: value for key, value in original.items() if key not in ("component", "features")}
            entry["component"] = identity[1]
            entry["features"] = [f"{name} = {value}" for name, value in sorted(assignments.items())]
            components.append({"subsystem": identity[0], "components": [entry]})
    return components


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


def inspect(root, data, common_selections=None, feature_catalog=None, feature_choices=None,
            bootstrap_common=False):
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

    if common_selections is None and feature_catalog is not None:
        base_path = "vendor/opendroid/common/base.json"
        catalog_path = "vendor/opendroid/common/product-features.json"
        common_selections = [_json(read(base_path), base_path)]
        actual_catalog = _json(read(catalog_path), catalog_path)
        if not isinstance(actual_catalog, list):
            raise ContractError(f"Invalid product feature catalog: {catalog_path}")
        actual_catalog = {item.get("id"): item for item in actual_catalog if isinstance(item, dict)}
        if set(actual_catalog) != set(feature_catalog or {}):
            raise ContractError(f"Product feature catalog IDs differ from generator contract: {catalog_path}")
        for option, expected in (feature_catalog or {}).items():
            item = actual_catalog[option]
            fields = ("subsystem", "component", "feature", "default")
            if any(item.get(field) != expected.get(field) for field in fields) or type(item.get("default")) is not bool:
                raise ContractError(f"Product feature catalog differs from generator contract: {catalog_path}: {option}")
        if data.get("system_profile") == "tablet":
            tablet_path = "vendor/opendroid/common/tablet.json"
            common_selections.append(_json(read(tablet_path), tablet_path))
    elif common_selections is None:
        common_selections = []

    # hb reads direct product inherit files only; it does not recursively
    # traverse inherit entries found inside those files.
    _select_product_file(data["base_product"], read, selection)
    if data.get("system_profile") == "tablet":
        _select_product_file("productdefine/common/inherit/tablet.json", read, selection)
    upstream_selected = dict(selected)
    for value in common_selections:
        selection(value, "source common configuration")
    common_selected = dict(selected)
    product_feature_components = _product_feature_components(
        upstream_selected, feature_catalog or {}, feature_choices or {}, common_selected, bootstrap_common)
    if product_feature_components:
        selection({"subsystems": product_feature_components}, "generated product feature overrides")
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
    feature_defaults = {}
    for option, item in (feature_catalog or {}).items():
        selected_component = common_selected.get((item["subsystem"], item["component"]))
        assignments = selected_component.get("features", []) if selected_component else []
        expected_assignment = None
        for assignment in assignments:
            if isinstance(assignment, str) and "=" in assignment:
                name, value = (part.strip() for part in assignment.split("=", 1))
                if name == item["feature"]:
                    expected_assignment = value
        if expected_assignment not in ("true", "false"):
            raise ContractError(
                f"Source common feature assignment is absent or non-Boolean: "
                f"{item['subsystem']}:{item['component']}:{item['feature']}")
        if expected_assignment != str(item["default"]).lower():
            raise ContractError(
                f"Source common feature default differs from catalog: "
                f"{item['subsystem']}:{item['component']}:{item['feature']}")
        feature_defaults[option] = expected_assignment == "true"
    return {
        "format_version": 1, "checks": checks, "components": components,
        "product_feature_components": product_feature_components,
        "product_feature_defaults": feature_defaults,
        "files_sha256": dict(sorted(observed.items())), "unreadable_registry_entries": ignored,
        "unavailable_unselected_paths": sorted(set(unavailable)),
        "limits": ["Source declarations were inspected without executing checkout code.",
                   "Declaration checks do not establish implementation semantics, GN dependency closure, compilation or hardware compatibility."],
    }
