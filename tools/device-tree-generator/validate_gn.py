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

"""Exercise generated GN and kernel staging with synthetic files in an isolated fixture."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import generate
from runtime import stage_kernel


def validate(output, reports, gn, source_root=None):
    generate.check(output, reports)
    data = generate.read_json(reports / "porting-input.json")
    layout = generate.read_json(reports / "support-report.json")["layout"]
    manifest = generate.read_json(reports / "generation-manifest.json")
    output_scope = manifest.get("output_scope", "bootstrap-platform")
    if output_scope == "board-product" and source_root is None:
        raise generate.InputError(
            "Board/product GN validation needs --source-root to supply existing common, SoC and kernel interfaces")
    commands = []
    with tempfile.TemporaryDirectory(prefix=".gn-fixture-", dir=output.parent) as temporary:
        root = Path(temporary)
        for directory in ("device", "vendor", "kernel"):
            if (output / directory).is_dir():
                shutil.copytree(output / directory, root / directory)
        if output_scope == "board-product":
            kernel = f"kernel/{data['company']}/{data['board']}"
            required = [
                f"device/soc/{data['soc_company']}/{data['soc']}/config.gni",
                f"device/soc/{data['soc_company']}/{data['soc']}/kernel/requirements.json",
                f"{kernel}/BUILD.gn",
                "vendor/opendroid/common/BUILD.gn",
                "vendor/opendroid/common/opendroid.para",
                "vendor/opendroid/common/scripts/stage_kernel.py",
            ]
            for relative in required:
                candidate = source_root / relative
                if not candidate.is_file():
                    raise generate.InputError(
                        f"Board/product GN validation requires source-provided {relative}; "
                        "add the kernel integration or use --bootstrap-platform to validate a starter")
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, destination)
            for relative in (f"{kernel}/requirements.json", f"{kernel}/module-order.json"):
                candidate = source_root / relative
                if candidate.is_file():
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(candidate, destination)
        (root / "build").mkdir()
        (root / "toolchain").mkdir()
        (root / ".gn").write_text(
            'buildconfig = "//build/BUILDCONFIG.gn"\n'
            'exec_script_allowlist = []\n'
            'script_executable = "/usr/bin/env"\n')
        (root / "build/BUILDCONFIG.gn").write_text(
            'set_default_toolchain("//toolchain:host")\n'
            f'target_cpu = {json.dumps(data["target_cpu"])}\n'
            f'product_name = {json.dumps(data["product"])}\n'
            f'opendroid_fixture_board = {json.dumps(data["board"])}\n'
            'sys_prod_base_dir = "sys_prod"\n'
            'vendor_base_dir = "vendor"\n'
            'ramdisk_base_dir = "ramdisk"\n'
            f'import("//{layout["board"]}/config.gni")\n')
        (root / "build/ohos").mkdir()
        (root / "build/ohos/build_var.gni").write_text(
            'product_output_dir = "$root_build_dir/packages"\n')
        (root / "toolchain/BUILD.gn").write_text('''toolchain("host") {
  tool("stamp") {
    command = "touch {{output}}"
    description = "STAMP {{output}}"
  }
  tool("copy") {
    command = "cp -f {{source}} {{output}}"
    description = "COPY {{source}}"
  }
}
''')
        # This stand-in checks generated template arguments, dependencies and
        # copied bytes. It does not execute upstream installation/image code.
        (root / "build/ohos.gni").write_text('''template("ohos_prebuilt_etc") {
  assert(invoker.install_enable)
  assert(invoker.install_images == [ "sys_prod" ] ||
         invoker.install_images == [ "vendor" ] ||
         invoker.install_images == [ "ramdisk" ])
  _images = invoker.install_images
  _image = _images[0]
  _install_dir = "etc"
  if (_image == "sys_prod") {
    assert(invoker.relative_install_dir == "param")
    assert(invoker.part_name == "product_${product_name}")
  } else {
    assert(invoker.part_name == "device_${opendroid_fixture_board}")
    assert(invoker.subsystem_name == "device_${opendroid_fixture_board}")
  }
  if (defined(invoker.module_install_dir)) {
    assert(_image == "vendor")
    assert(defined(invoker.output))
    assert(get_path_info(invoker.output, "file") ==
           get_path_info(invoker.source, "file"))
    _install_dir = invoker.module_install_dir
  } else if (defined(invoker.relative_install_dir)) {
    _install_dir += "/${invoker.relative_install_dir}"
  }
  _prebuilt_target = "${target_name}_fixture_prebuilt"
  _copy_output = "$target_out_dir/$target_name/" +
                 get_path_info(invoker.source, "file")
  if (defined(invoker.output)) {
    _copy_output = "$target_out_dir/${invoker.output}"
  }
  copy(_prebuilt_target) {
    forward_variables_from(invoker, [ "deps" ])
    sources = [ invoker.source ]
    outputs = [ _copy_output ]
  }
  copy(target_name) {
    sources = [ _copy_output ]
    outputs = [ "$root_build_dir/install/$_image/$_install_dir/{{source_file_part}}" ]
    deps = [ ":$_prebuilt_target" ]
  }
}

template("ohos_copy") {
  copy(target_name) {
    forward_variables_from(invoker, [ "sources", "outputs", "deps" ])
  }
}
''')
        (root / "BUILD.gn").write_text(
            'group("all") {\n  deps = [\n'
            f'    "//{layout["board"]}:board",\n'
            f'    "//{layout["product"]}:product",\n  ]\n}}\n')

        def run(args, success=True):
            result = subprocess.run(args, cwd=root, text=True, capture_output=True, timeout=60)
            commands.append({"command": [str(a).replace(str(root), "<fixture>") for a in args],
                             "exit_code": result.returncode,
                             "output": (result.stdout + result.stderr).replace(str(root), "<fixture>")})
            if success and result.returncode:
                raise generate.InputError(json.dumps(commands[-1], indent=2))
            return result

        unselected = run([str(gn), "gen", "out"], success=False)
        if not unselected.returncode or "unselected" not in (unselected.stdout + unselected.stderr):
            raise generate.InputError("Default unselected kernel manifest did not stop GN generation: "
                                      + json.dumps(commands[-1], indent=2))
        private = root / "private"
        private.mkdir()
        board_requirements = root / layout["kernel"] / "requirements.json"
        additional = [board_requirements] if board_requirements.exists() else []
        requirements, _ = stage_kernel.load_requirements(root / layout["soc"] / "kernel/requirements.json", additional)
        config = ("".join(f"# {name} is not set\n" if allowed[0] == "n" else f"{name}={allowed[0]}\n"
                          for name, allowed in requirements.items())
                  + "CONFIG_FONT_8x16=y\n").encode()
        entries = []
        for name, role, payload in (("Image", "kernel", b"synthetic kernel bytes; never executed\n"),
                                    ("kernel.config", "config", config),
                                    ("fixture.ko", "module", b"synthetic module; never loaded\n"),
                                    ("fixture.dtb", "dtb", b"synthetic dtb; never applied\n")):
            (private / name).write_bytes(payload)
            destination = {"module": "modules/fixture.ko", "dtb": "device-trees/fixture.dtb"}.get(role, name)
            entries.append({"role": role, "path": name, "sha256": generate.digest(payload), "destination": destination})
        for index, destination in enumerate(data.get("module_load_order", [])):
            if any(item["role"] == "module" and item["destination"] == destination for item in entries):
                continue
            name = f"ordered-module-{index}.ko"
            payload = f"synthetic ordered module {index}; never loaded\n".encode()
            (private / name).write_bytes(payload)
            entries.append({"role": "module", "path": name, "sha256": generate.digest(payload),
                            "destination": destination})
        manifest = private / "selection.json"
        module_order = root / layout["kernel"] / "module-order.json"
        requirements_path = root / layout["soc"] / "kernel/requirements.json"
        selection_index = 0

        def select():
            nonlocal selection_index
            manifest.write_text(generate.json_text({"format_version": 1, "state": "selected", "files": entries}))
            description = private / f"gn-selection-{selection_index}.json"
            selection_index += 1
            stage_kernel.prepare(manifest, requirements_path, module_order, description, additional)
            run([str(gn), "gen", "out", "--args=opendroid_kernel_selection=" + json.dumps(str(description))])
            return description

        select()
        run(["ninja", "-C", "out", "all"])
        staged = list((root / "out/opendroid-prebuilts" / data["board"]).glob("*/stage-report.json"))
        if len(staged) != 1 or (staged[0].parent / "Image").read_bytes() != (private / "Image").read_bytes():
            raise generate.InputError("Ninja did not stage exactly the synthetic selected kernel")
        for entry in entries:
            if (staged[0].parent / entry["destination"]).read_bytes() != (private / entry["path"]).read_bytes():
                raise generate.InputError("Ninja staged bytes differ from the selected synthetic payload")
        original = {str(p.relative_to(staged[0].parent)): p.read_bytes() for p in staged[0].parent.rglob("*") if p.is_file()}
        changed = b"second synthetic kernel selection\n"
        (private / "Image").write_bytes(changed)
        entries[0]["sha256"] = generate.digest(changed)
        manifest.write_text(generate.json_text({"format_version": 1, "state": "selected", "files": entries}))
        stale = run(["ninja", "-C", "out", "all"], success=False)
        if not stale.returncode or "stale or invalid" not in stale.stdout + stale.stderr:
            raise generate.InputError("Changed manifest was not rejected before explicit preparation")
        select()
        run(["ninja", "-C", "out", "all"])
        stages = list((root / "out/opendroid-prebuilts" / data["board"]).glob("*/stage-report.json"))
        if len(stages) != 2 or original != {str(p.relative_to(staged[0].parent)): p.read_bytes()
                                          for p in staged[0].parent.rglob("*") if p.is_file()}:
            raise generate.InputError("Changed selection failed to create a new stage while preserving the old one")
        if additional:
            previous = {str(p.relative_to(root / "out/opendroid-prebuilts")): p.read_bytes()
                        for p in (root / "out/opendroid-prebuilts").rglob("*") if p.is_file()}
            board_requirements.write_text(board_requirements.read_text() + "\n")
            stale = run(["ninja", "-C", "out", "all"], success=False)
            if not stale.returncode or "stale or invalid" not in stale.stdout + stale.stderr:
                raise generate.InputError("Changed board requirements did not invalidate the prepared selection")
            select()
            run(["ninja", "-C", "out", "all"])
            stages = list((root / "out/opendroid-prebuilts" / data["board"]).glob("*/stage-report.json"))
            if len(stages) != 3 or any((root / "out/opendroid-prebuilts" / name).read_bytes() != contents
                                      for name, contents in previous.items()):
                raise generate.InputError("Board requirement change did not create a new stage and preserve previous bytes")
        previous = {str(p.relative_to(root / "out/opendroid-prebuilts")): p.read_bytes()
                    for p in (root / "out/opendroid-prebuilts").rglob("*") if p.is_file()}
        module_order.write_text(module_order.read_text() + "\n")
        stale = run(["ninja", "-C", "out", "all"], success=False)
        if not stale.returncode or "stale or invalid" not in stale.stdout + stale.stderr:
            raise generate.InputError("Changed module order did not invalidate the prepared selection")
        select()
        run(["ninja", "-C", "out", "all"])
        if any((root / "out/opendroid-prebuilts" / name).read_bytes() != contents
               for name, contents in previous.items()):
            raise generate.InputError("Module order preparation changed a previous stage")
        params = root / "out/install/sys_prod/etc/param"
        if (params / "product.para").read_bytes() != (root / layout["product"] / "product.para").read_bytes():
            raise generate.InputError("Product parameter copy differs")
        if (params / "opendroid.para").read_bytes() != (root / layout["common"] / "opendroid.para").read_bytes():
            raise generate.InputError("Shared parameter copy differs")
        native_validation = check_native_installation(root, data, layout, private, entries)
        entries = [item for item in entries if item["role"] in ("kernel", "config")]
        module_order.write_text(generate.json_text({"format_version": 1, "modules": []}))
        description = select()
        run(["ninja", "-C", "out", "kernel", "modules"])
        stage = root / "out/opendroid-prebuilts" / data["board"] / generate.read_json(description)["id"]
        for entry in entries:
            if (stage / entry["destination"]).read_bytes() != (private / entry["path"]).read_bytes():
                raise generate.InputError("Kernel/config-only staging differs from the selected payloads")
        targets = run([str(gn), "ls", "out", f"//{layout['kernel']}:*"]).stdout.splitlines()
        if set(targets) != {f"//{layout['kernel']}:kernel", f"//{layout['kernel']}:modules"}:
            raise generate.InputError("Kernel/config-only graph retained module install targets")
    return {
        "result": "pass", "gn_version": subprocess.check_output([str(gn), "--version"], text=True).strip(),
        "gn_sha256": hashlib.sha256(gn.read_bytes()).hexdigest(), "scope": "Isolated generated GN/Ninja host fixture",
        "board_soc_imports": "pass", "unselected_manifest": "rejected", "selected_kernel_staging": "pass",
        "changed_selection": "new content-addressed output; previous stage preserved",
        "board_requirement_dependency": "Stale selection rejected; explicit preparation creates a new stage" if additional else "no board descriptor",
        "module_order_dependency": "Stale selection rejected; explicit preparation creates a new stage",
        "kernel_config_only": "GN/Ninja pass without module install targets",
        "exec_script_allowlist": "Empty; no GN-time scripts permitted",
        "parameter_targets": "invocations checked with stand-in ohos_prebuilt_etc; copied bytes verified",
        "native_configuration": native_validation,
        "real_upstream_prebuilt_template": "not-executed", "os_build": "not-run", "device": "not-tested",
        "commands": commands,
    }


def check_native_installation(root, data, layout, private, entries):
    """Check fixture install destinations against explicitly supplied inputs."""
    native = data.get("native_config", {})
    vendor = root / "out/install/vendor"
    cfg = root / layout["board"] / "cfg"

    def config_copy(filename, image="vendor"):
        installed = root / "out/install" / image / "etc" / filename
        if installed.read_bytes() != (cfg / filename).read_bytes():
            raise generate.InputError(f"Configuration copy differs in {image}: {filename}")
        return installed

    counts = {"mounts": 0, "required_mounts": 0, "device_permissions": 0, "images": 0, "modules": 0, "ordered_module_loads": 0}
    if native.get("mounts"):
        path = config_copy("fstab." + native["hardware"])
        observed = [line.split() for line in path.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        expected = [[mount["device"], mount["mount_point"], mount["fs_type"],
                     ",".join(mount["mount_options"]), ",".join(mount["manager_flags"])]
                    for mount in native["mounts"]]
        if observed != expected:
            raise generate.InputError("Installed fstab differs from the declared synthetic mounts")
        counts["mounts"] = len(expected)
    elif native and (vendor / "etc" / ("fstab." + native["hardware"])).exists():
        raise generate.InputError("A fstab was installed without declared mounts")
    required = [mount for mount in native.get("mounts", []) if "required" in mount["manager_flags"]]
    if required:
        path = config_copy("fstab.required", image="ramdisk")
        observed = [line.split() for line in path.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        expected = [[mount["device"], mount["mount_point"], mount["fs_type"],
                     ",".join(mount["mount_options"]), ",".join(mount["manager_flags"])] for mount in required]
        if observed != expected:
            raise generate.InputError("Ramdisk fstab differs from declared required mounts")
        counts["required_mounts"] = len(required)
    elif (root / "out/install/ramdisk/etc/fstab.required").exists():
        raise generate.InputError("First-stage fstab installed without declared required mounts")
    if native.get("device_permissions"):
        path = config_copy("ueventd.config")
        observed = [line.split() for line in path.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        expected = [["[device]"]] + [[item["path"], item["mode"], str(item["uid"]), str(item["gid"])]
                                      for item in native["device_permissions"]]
        if observed != expected:
            raise generate.InputError("Installed ueventd rules differ from declared synthetic permissions")
        counts["device_permissions"] = len(native["device_permissions"])
    elif (vendor / "etc/ueventd.config").exists():
        raise generate.InputError("Device permissions were installed without declared rules")

    selected_modules = {entry["destination"]: entry for entry in entries if entry["role"] == "module"}
    for destination, entry in selected_modules.items():
        installed = vendor / "lib/opendroid" / destination
        if installed.read_bytes() != (private / entry["path"]).read_bytes():
            raise generate.InputError(f"Installed selected module bytes differ: {destination}")
    counts["modules"] = len(selected_modules)
    expected_commands = []
    if native.get("firmware_directory"):
        expected_commands.append("write /sys/module/firmware_class/parameters/path " + native["firmware_directory"])
    for destination in data.get("module_load_order", []):
        if destination not in selected_modules:
            raise generate.InputError("Declared module load order does not name a selected module")
        expected_commands.append("insmod /vendor/lib/opendroid/" + destination)
    if expected_commands:
        path = config_copy("init." + native["hardware"] + ".cfg")
        observed = generate.read_json(path)
        expected = {"jobs": [{"name": "init", "cmds": expected_commands}]}
        if observed != expected:
            raise generate.InputError("Installed init commands differ from declared firmware path/module order")
    elif native and (vendor / "etc" / ("init." + native["hardware"] + ".cfg")).exists():
        raise generate.InputError("Board init commands were installed without declared inputs")
    counts["ordered_module_loads"] = len(data.get("module_load_order", []))

    for name, image in native.get("images", {}).items():
        filename = name + "_image_conf.txt"
        source = root / layout["board"] / "image_conf" / filename
        installed = root / "out/packages/imagesconf" / filename
        if installed.read_bytes() != source.read_bytes():
            raise generate.InputError(f"Copied ext4 image configuration differs: {filename}")
        observed = [line for line in installed.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        expected = [image["mount_point"], str(image["size_bytes"]), "--fs_type=ext4",
                    "--dac_config ../../build/ohos/images/mkimage/dac.txt",
                    "--file_context obj/base/security/selinux_adapter/file_contexts.bin"]
        if observed != expected:
            raise generate.InputError(f"Image configuration differs from declared ext4 inputs: {name}")
        counts["images"] += 1
    actual_images = {path.name for path in (root / "out/packages/imagesconf").glob("*")}
    expected_images = {name + "_image_conf.txt" for name in native.get("images", {})}
    if actual_images != expected_images:
        raise generate.InputError("Installed image configurations do not match declared images")
    return {"result": "pass", "scope": "Generated declarations and copied fixture bytes only",
            "checked": counts, "firmware_path_command": bool(native.get("firmware_directory")),
            "init_or_modules_executed": False, "filesystem_images_created": False,
            "upstream_init_fstab_uevent_parsers": "not-executed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--gn", required=True, type=Path)
    parser.add_argument("--source-root", type=Path,
                        help="Checkout providing common, SoC and kernel interfaces for board-product output")
    args = parser.parse_args()
    try:
        print(generate.json_text(validate(args.output.resolve(), generate.report_root(args.output, args.reports).resolve(),
                                          args.gn.resolve(), args.source_root.resolve() if args.source_root else None)), end="")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
