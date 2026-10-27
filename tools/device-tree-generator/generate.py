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

"""Generate native OpenHarmony board, SoC, kernel and product configuration."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

import evidence
import native_layout
import native_config
import source_contracts
import product_features


FEATURES = (
    "display_gpu", "input", "audio", "camera_media", "wifi_bluetooth",
    "power_battery_thermal", "sensors", "usb", "storage",
)
IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
HEADER = """# Copyright 2026 OpenDroidOS
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

"""


class InputError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_text(value):
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InputError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def validate_input(data):
    if not isinstance(data, dict):
        raise InputError("Input must be a JSON object")
    allowed = {"schema_version", "source_profile", "company", "board", "product",
               "target_cpu", "base_product", "kernel_strategy", "providers", "notes", "soc", "soc_company",
               "system_profile", "native_config", "module_load_order", "init_mode"}
    allowed.add("product_features")
    required = allowed - {"providers", "notes", "system_profile", "native_config", "module_load_order", "source_profile", "product_features"}
    if set(data) - allowed:
        raise InputError(f"Unknown input fields: {sorted(set(data) - allowed)}")
    if required - set(data):
        raise InputError(f"Missing input fields: {sorted(required - set(data))}")
    if type(data["schema_version"]) is not int or data["schema_version"] != 3:
        raise InputError("schema_version must be integer 3; specify init_mode explicitly")
    for key in ("company", "board", "product", "soc_company", "soc"):
        if not isinstance(data[key], str) or not IDENTIFIER.fullmatch(data[key]):
            raise InputError(f"{key} must use lowercase letters, digits and underscores; start with a letter")
    if data["product"] == "common":
        raise InputError("product common is reserved for shared distribution configuration")
    if "source_profile" in data and not isinstance(data["source_profile"], str):
        raise InputError("Legacy source_profile must be a string; it is no longer used")
    if data["target_cpu"] not in ("arm", "arm64"):
        raise InputError("target_cpu must be arm or arm64")
    if data["base_product"] != source_contracts.BASE_PRODUCT:
        raise InputError("This template requires the standard_system base product")
    if data["kernel_strategy"] != "prebuilt":
        raise InputError("kernel_strategy must be prebuilt")
    if data.get("system_profile", "base") not in ("base", "tablet"):
        raise InputError("system_profile must be base or tablet")
    if data["init_mode"] not in ("single-stage", "two-stage"):
        raise InputError("init_mode must be single-stage or two-stage")
    try:
        product_features.validate(data.get("product_features", {}))
    except ValueError as error:
        raise InputError(str(error)) from error
    order = data.get("module_load_order", [])
    if not isinstance(order, list) or any(
        not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_+./-]+\.ko", name)
        or any(part in ("", ".", "..") for part in name.split("/"))
        for name in order
    ) or len(order) != len(set(order)):
        raise InputError("module_load_order must contain unique safe relative .ko destinations")
    if order and "native_config" not in data:
        raise InputError("module_load_order requires native_config.hardware")
    try:
        native_config.validate(data)
    except ValueError as error:
        raise InputError(str(error)) from error
    providers = data.get("providers", {})
    if not isinstance(providers, dict) or set(providers) - set(FEATURES):
        raise InputError(f"providers must be an object with keys from {', '.join(FEATURES)}")
    for name, state in providers.items():
        if not isinstance(state, str) or state not in ("unknown", "planned", "missing"):
            raise InputError(f"{name}: supported provider states are unknown, planned, missing")
    notes = data.get("notes", [])
    if not isinstance(notes, list) or not all(isinstance(n, str) for n in notes):
        raise InputError("notes must be a list of strings")


def _source_json(root, relative):
    path = root / relative
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise InputError(f"Required source-provided interface is absent: {relative}")
    try:
        return read_json(path)
    except (OSError, ValueError) as error:
        raise InputError(f"Invalid source-provided JSON {relative}: {error}") from error


def _requirements_match(actual_data, expected_options, path, description):
    if (not isinstance(actual_data, dict) or
            set(actual_data) - {"format_version", "required_options", "scope", "module_values"} or
            type(actual_data.get("format_version")) is not int or actual_data["format_version"] != 1 or
            any(name in actual_data and not isinstance(actual_data[name], str)
                for name in ("scope", "module_values"))):
        raise InputError(f"Invalid source {description} requirements: {path}")
    actual_options = actual_data.get("required_options") if isinstance(actual_data, dict) else None
    if not isinstance(actual_options, dict):
        raise InputError(f"Invalid source {description} requirements: {path}:required_options")
    for option, allowed_values in actual_options.items():
        if (not isinstance(option, str) or not re.fullmatch(r"CONFIG_[A-Za-z0-9_]+", option) or
                not isinstance(allowed_values, list) or not allowed_values or
                any(not isinstance(value, str) or value not in ("y", "m", "n") for value in allowed_values) or
                len(allowed_values) != len(set(allowed_values))):
            raise InputError(f"Invalid source {description} requirement: {path}:{option}")
    for option, allowed in expected_options.items():
        actual = actual_options.get(option)
        if not isinstance(actual, list) or not actual or not set(actual).issubset(set(allowed)):
            raise InputError(f"Source {description} requirement {path}:{option} conflicts with requested contract")


def verify_source(root, data, bootstrap_platform=False):
    root = root.resolve()
    kernel_path = f"kernel/{data['company']}/{data['board']}"
    bootstrap = native_layout.render(data, "", "", "")
    try:
        if bootstrap_platform:
            common_path = "vendor/opendroid/common/base.json"
            common_selections = [json.loads(bootstrap[common_path])]
            if data.get("system_profile") == "tablet":
                common_selections.append(json.loads(bootstrap["vendor/opendroid/common/tablet.json"]))
            platform = {"kernel_scaffold": "bootstrap-template", "kernel_path": kernel_path}
            result = source_contracts.inspect(root, data, common_selections, product_features.CATALOG,
                                              data.get("product_features", {}), bootstrap_common=True)
            result["source_platform"] = platform
            return result
        for relative in ("device/soc/%s/%s/config.gni" % (data["soc_company"], data["soc"]),
                         "device/soc/%s/%s/kernel/requirements.json" % (data["soc_company"], data["soc"]),
                         "vendor/opendroid/common/BUILD.gn", "vendor/opendroid/common/base.json",
                         "vendor/opendroid/common/opendroid.para",
                         "vendor/opendroid/common/product-features.json",
                         "vendor/opendroid/common/scripts/stage_kernel.py"):
            path = root / relative
            if not path.resolve().is_relative_to(root) or not path.is_file():
                raise InputError(f"Required source-provided interface is absent: {relative}")
        kernel_dir = root / kernel_path
        platform = {"kernel_scaffold": "present" if (kernel_dir / "BUILD.gn").is_file() else "missing",
                    "kernel_path": kernel_path}
        requirements_path = kernel_dir / "requirements.json"
        order_path = kernel_dir / "module-order.json"
        shared_path = f"device/soc/{data['soc_company']}/{data['soc']}/kernel/requirements.json"
        expected_shared = json.loads(bootstrap[shared_path])["required_options"]
        _requirements_match(_source_json(root, shared_path), expected_shared, shared_path, "SoC")
        if requirements_path.is_file():
            expected_board_path = f"{kernel_path}/requirements.json"
            expected_board = json.loads(bootstrap[expected_board_path]).get("required_options", {})
            _requirements_match(_source_json(root, expected_board_path), expected_board,
                                expected_board_path, "board")
            platform["board_requirements"] = "present-and-compatible"
        else:
            platform["board_requirements"] = "missing" if data["init_mode"] == "two-stage" else "not-required-by-input"
        if data.get("module_load_order"):
            if not order_path.is_file():
                platform["module_order"] = "missing"
            else:
                actual_order = _source_json(root, f"{kernel_path}/module-order.json")
                requested_order = {"format_version": 1, "modules": data["module_load_order"]}
                if actual_order != requested_order:
                    raise InputError(f"Source module order {kernel_path}/module-order.json conflicts with input module_load_order")
                platform["module_order"] = "present-and-matching"
        result = source_contracts.inspect(root, data, None, product_features.CATALOG,
                                          data.get("product_features", {}))
        result["source_platform"] = platform
        return result
    except source_contracts.ContractError as error:
        raise InputError(str(error)) from error


def component(identity, path, target):
    return {
        "name": f"@opendroid/{identity}", "license": "Apache-2.0",
        "component": {
            "name": identity, "subsystem": identity,
            "build": {"sub_component": [f"//{path}:{target}"]},
        },
    }


def support_markdown(report, prebuilts):
    summary = prebuilts["summary"]
    lines = ["# Porting gaps", "", "State: scaffold only. Build, images and hardware remain unverified.", "",
             f"Verified {summary['artifacts']} artifact identities from {summary['reports']} extraction reports.",
             "No kernel, module set, device tree or firmware was selected.", ""]
    if summary["reports"]:
        lines += ["See `prebuilt-evidence.json` for report hashes, input states and per-file origins.",
                  "Release labels and dependency metadata come from those reports; matching labels do not prove ABI compatibility.", ""]
        for item in prebuilts["reports"]:
            lines += [f"Capture `{item['report_sha256']}`:", ""]
            lines += [f"- `{x['label']}`: {x['state']}" for x in item["inputs"]]
            lines += [""]
        if summary["kernel_release_strings"]:
            lines += ["Kernel release labels: " + ", ".join(f"`{x}`" for x in summary["kernel_release_strings"]) + ".", ""]
        if summary["module_release_string_populations"]:
            lines += ["Module release labels:", ""]
            lines += [f"- `{name}`: {count} files" for name, count in summary["module_release_string_populations"].items()]
            lines += [""]
        descriptions = {
            "incomplete-extraction": "An input is partial, failed or unsupported; inspect its required-content gaps and original report.",
            "module-metadata-unknown": "Some captured modules lack observed metadata.",
            "empty-device-tree": "An empty FDT root supplies no board description.",
            "device-tree-structure-unestablished": "A captured tree's structure was not established.",
            "conflicting-module-providers": "A capture contains modules with the same normalized name and different bytes.",
            "multiple-module-release-strings": "Multiple module release labels require explicit selection of a matching set.",
            "multiple-kernel-release-strings": "Multiple kernel release labels require explicit selection.",
            "kernel-release-unavailable": "Module labels have no observed kernel release to compare.",
            "module-kernel-release-label-difference": "Some module release labels differ from all kernel candidates; review their origin and ABI.",
            "separate-captures-unbound": "Separate captures remain separate evidence; they are not a compatible combined set.",
        }
        lines += ["Evidence requiring review:", ""]
        ids = sorted({warning["id"] for warning in prebuilts["warnings"]})
        lines += [f"- {descriptions[name]}" for name in ids] or ["- No additional observation warnings; compatibility remains unverified."]
        lines += ["", "Missing captured module dependencies may be built into the kernel. Headers/config candidates do not establish a matching build tree. Firmware requirements remain unaudited.", ""]
    lines += ["Required integration:", ""]
    lines += [f"- **{gap['id']}** ({gap['state']}): {gap['required']}" for gap in report["gaps"]]
    return "\n".join(lines) + "\n"


def render(data, contracts, prebuilts, output_scope="bootstrap-platform"):
    company, board, product = (data[k] for k in ("company", "board", "product"))
    board_path = f"device/board/{company}/{board}"
    product_path = f"vendor/{company}/{product}"
    config = {
        "product_name": product, "product_company": company,
        "device_company": company, "device_build_path": board_path, "board_path": board_path,
        "product_build_path": product_path, "board": board,
        "version": "3.0", "type": "standard", "target_os": "ohos",
        "target_cpu": data["target_cpu"], "kernel_type": "linux",
        "build_selinux": True, "enable_ramdisk": data["init_mode"] == "two-stage",
        "inherit": [data["base_product"], "vendor/opendroid/common/base.json"],
        "subsystems": [{"subsystem": f"product_{product}",
                        "components": [{"component": f"product_{product}"}]}],
    }
    product_overrides = contracts.get("product_feature_components", [])
    if product_overrides:
        config["subsystems"].extend(product_overrides)
    if data.get("system_profile") == "tablet":
        config["inherit"].insert(1, "productdefine/common/inherit/tablet.json")
        config["inherit"].append("vendor/opendroid/common/tablet.json")
    platform = contracts.get("source_platform", {})
    kernel_required = "Bind a compatible kernel/config/module/tree manifest; image/runtime integration remains open."
    if platform.get("kernel_scaffold") == "missing":
        kernel_required = (f"Source kernel integration `{platform.get('kernel_path', '')}` is absent. "
                           "Add device-specific kernel integration separately or use --bootstrap-platform for a starter template.")
    if platform.get("board_requirements") == "missing":
        kernel_required += " Two-stage init also needs compatible board kernel requirements; the source file was not present."
    if platform.get("module_order") == "missing":
        kernel_required += " Requested module_load_order needs a source-provided module-order.json matching the input."
    gaps = [
        {"id": "kernel", "state": "unresolved", "required": kernel_required},
        {"id": "boot_packaging", "state": "unresolved", "required": "Implement the actual bootloader image/header/ramdisk/DTB/DTBO contract."},
        {"id": "partitions", "state": "unresolved", "required": "Supply evidenced partitions, filesystems, mount/init configuration, slots and verified-boot chain."},
        {"id": "recovery_updates", "state": "unresolved", "required": "Integrate updater/recovery, update metadata and rollback for this device."},
        {"id": "security", "state": "unresolved", "required": "Select SELinux components and supply device policy, labels, service permissions and kernel support."},
    ]
    required_mounts = [mount for mount in data.get("native_config", {}).get("mounts", [])
                       if "required" in mount["manager_flags"]]
    if data["init_mode"] == "two-stage":
        root_declared = any(mount["mount_point"] == "/usr" for mount in required_mounts)
        gaps.append({"id": "first_stage", "state": "declared-unvalidated" if root_declared else "unresolved",
                     "required": "Declare the evidenced required /usr root mount before other early mounts. Supply built-in storage/controller/dm/filesystem prerequisites and any early firmware; vendor-installed modules/init jobs run too late. Check ohos.required_mount cmdline overrides, mount/root-switch error propagation and ramdisk runtime libraries/size; nofail alone does not guarantee abort."})
    gaps += [{"id": name, "state": data.get("providers", {}).get(name, "unknown"),
              "required": "Trace native interface/provider, kernel interface, build, installation, startup, policy and hardware validation."}
             for name in FEATURES]
    report = {
        "report_version": 1, "source_inspection": "source-inspection.json",
        "project": "opendroid", "organization": "OpenDroidOS",
        "direction": "native-open-source-providers", "state": "scaffold-only",
        "build_ready": False, "flashable": False, "hardware_support": "unverified",
        "gaps": gaps,
        "layout": {"board": board_path, "soc": f"device/soc/{data['soc_company']}/{data['soc']}",
                   "kernel": f"kernel/{company}/{board}", "product": product_path,
                   "common": "vendor/opendroid/common"},
        "integration": {"board_soc_config_import": "generated", "kernel_prebuilt_staging": "implemented-unbound",
                        "product_parameter_installation": "generated", "native_hardware_providers": "not-selected-or-validated",
                        "system_profile": data.get("system_profile", "base"),
                        "init_mode": data["init_mode"],
                        "required_mounts_declared": len(required_mounts),
                        "native_config": data.get("native_config", {}),
                        "module_load_order": data.get("module_load_order", [])},
        "prebuilt_evidence": {"state": prebuilts["state"], "summary": prebuilts["summary"],
                             "warnings": prebuilts["warnings"], "selection": prebuilts["selection"],
                             "details": "prebuilt-evidence.json" if prebuilts["reports"] else None},
        "output_scope": output_scope,
        "validation": {"json": "generated", "upstream_parsers": "not-run-by-generator",
                       "gn": "not-run", "build": "not-run", "device": "not-tested"},
    }
    license_text = (Path(__file__).resolve().parents[2] / "LICENSE").read_text(encoding="utf-8")
    notice = (
            "OpenDroidOS configuration for OpenHarmony\nCopyright 2026 OpenDroidOS\n"
            "Apache-2.0; see LICENSE.\n\n"
            "Uses OpenHarmony build interfaces.\n"
            "https://github.com/openharmony/build\n"
        )
    files = native_layout.render(data, HEADER, license_text, notice)
    files.update(native_config.render(data, HEADER))
    files.update({
        f"{board_path}/bundle.json": json_text(component(f"device_{board}", board_path, "board")),
        f"{product_path}/bundle.json": json_text(component(f"product_{product}", product_path, "product")),
        f"{product_path}/config.json": json_text(config),
    })
    reports = {
        "porting-input.json": json_text(data),
        "support-report.json": json_text(report),
        "PORTING.md": support_markdown(report, prebuilts),
        "source-inspection.json": json_text(contracts),
    }
    if prebuilts["reports"]:
        reports["prebuilt-evidence.json"] = json_text(prebuilts)
    manifest = {
        "manifest_version": 2,
        "generator_sha256": digest(Path(__file__).read_bytes()),
        "layout_sha256": digest(Path(native_layout.__file__).read_bytes()),
        "native_config_sha256": digest(Path(native_config.__file__).read_bytes()),
        "product_features_sha256": digest(Path(product_features.__file__).read_bytes()),
        "evidence_reader_sha256": digest(Path(evidence.__file__).read_bytes()),
        "extraction_report_sha256": [r["report_sha256"] for r in prebuilts["reports"]],
        "source_inspector_sha256": digest(Path(source_contracts.__file__).read_bytes()),
        "input_sha256": digest(json_text(data).encode()),
        "files": {name: digest(value.encode()) for name, value in sorted(files.items())},
        "executable_files": ["vendor/opendroid/common/scripts/stage_kernel.py"],
        "report_files": {name: digest(value.encode()) for name, value in sorted(reports.items())},
    }
    reports["generation-manifest.json"] = json_text(manifest)
    return files, reports


def report_root(output, reports=None):
    if reports is not None:
        return reports
    if (output / "generation-manifest.json").exists():
        return output
    return output.with_name(output.name + "-reports")


def generate(input_path, output, source_root, extracted=(), reports=None, bootstrap_platform=False):
    data = read_json(input_path)
    validate_input(data)
    data.pop("source_profile", None)
    source_root = source_root.resolve()
    contracts = verify_source(source_root, data, bootstrap_platform)
    output = output.absolute()
    reports = report_root(output, reports).absolute()
    if output.resolve().is_relative_to(reports.resolve()) or reports.resolve().is_relative_to(output.resolve()):
        raise InputError("Source tree and reports must be separate, non-nested directories")
    for destination in (output, reports):
        if destination.exists() or destination.is_symlink():
            raise InputError("Output already exists; choose new tree/report directories to preserve edits")
        if destination.resolve().is_relative_to(source_root):
            raise InputError("Generate outside the source checkout; this tool creates reviewable artifacts")
        for supplied in extracted:
            root = supplied if supplied.is_dir() else supplied.parent
            if destination.resolve().is_relative_to(root.resolve()):
                raise InputError("Generate outside extraction directories to preserve evidence inputs")
    prebuilts = evidence.load_extractions(extracted)
    output_scope = "bootstrap-platform" if bootstrap_platform else "board-product"
    files, report_files = render(data, contracts, prebuilts, output_scope)
    if not bootstrap_platform:
        board_prefix = f"device/board/{data['company']}/{data['board']}/"
        product_prefix = f"vendor/{data['company']}/{data['product']}/"
        files = {name: content for name, content in files.items()
                 if name.startswith(board_prefix) or name.startswith(product_prefix)}
    manifest = read_json_from_text(report_files["generation-manifest.json"])
    manifest["output_scope"] = output_scope
    manifest["files"] = {name: digest(value.encode()) for name, value in sorted(files.items())}
    manifest["executable_files"] = [name for name in manifest.get("executable_files", []) if name in files]
    report_files["generation-manifest.json"] = json_text(manifest)
    for destination, content_files in ((output, files), (reports, report_files)):
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".oh-treegen-", dir=destination.parent) as temporary:
            stage = Path(temporary) / "tree"
            stage.mkdir()
            for relative, content in content_files.items():
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                if destination == output and relative == "vendor/opendroid/common/scripts/stage_kernel.py":
                    target.chmod(0o755)
            destination.mkdir()
            for child in stage.iterdir():
                os.rename(child, destination / child.name)
    return len(files) + len(report_files)


def read_json_from_text(text):
    return json.loads(text)


def check(output, reports=None):
    reports = report_root(output, reports)
    if output.is_symlink() or reports.is_symlink():
        raise InputError("Tree and reports must not be symbolic links")
    manifest_path = reports / "generation-manifest.json"
    if manifest_path.is_symlink():
        raise InputError("Manifest must not be a symbolic link")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or type(manifest.get("manifest_version")) is not int or manifest["manifest_version"] not in (1, 2):
        raise InputError("Unsupported generation manifest")
    output_scope = manifest.get("output_scope", "bootstrap-platform")
    if output_scope not in ("bootstrap-platform", "board-product"):
        raise InputError("Unsupported output scope in generation manifest")
    count = check_entries(output, manifest.get("files"))
    executables = manifest.get("executable_files", [])
    if (not isinstance(executables, list) or
            any(not isinstance(name, str) or name not in manifest["files"] for name in executables)):
        raise InputError("Invalid executable file list in generation manifest")
    for name in executables:
        if (output / name).stat().st_mode & 0o111 != 0o111:
            raise InputError(f"Managed build script is not executable: {name}")
    if manifest["manifest_version"] == 2:
        count += check_entries(reports, manifest.get("report_files"))
    return count


def check_entries(output, entries):
    if not isinstance(entries, dict) or not entries:
        raise InputError("Generation manifest has no files")
    for name, expected in entries.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or not relative.parts:
            raise InputError(f"Unsafe manifest path: {name}")
        path = output
        for part in relative.parts:
            path /= part
            if path.is_symlink():
                raise InputError(f"Symbolic link in managed path: {name}")
        if not path.is_file() or digest(path.read_bytes()) != expected:
            raise InputError(f"Managed file is missing or changed: {name}")
    return len(entries)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="opendroid-treegen", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("generate", help="Create device configuration outside the source checkout")
    make.add_argument("--input", required=True, type=Path)
    make.add_argument("--output", required=True, type=Path)
    make.add_argument("--source-root", required=True, type=Path)
    make.add_argument("--reports", type=Path, help="Separate report directory; default <output>-reports")
    make.add_argument("--bootstrap-platform", action="store_true",
                      help="also generate the existing SoC, kernel and shared-common starter templates")
    make.add_argument("--extracted", action="append", default=[], type=Path,
                      help="Extraction directory or report file; repeat for separate captures")
    verify = commands.add_parser("check", help="Check managed hashes and executable modes")
    verify.add_argument("output", type=Path)
    verify.add_argument("--reports", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            count = generate(args.input, args.output, args.source_root, args.extracted, args.reports,
                             args.bootstrap_platform)
            print(f"Generated {count} files. Tree: {args.output}; reports: {report_root(args.output, args.reports)}. Build/hardware unverified.")
        else:
            count = check(args.output, args.reports)
            print(f"Matched {count} managed file hashes. Build and hardware unverified.")
    except (InputError, OSError, ValueError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
