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

"""Original OpenDroid board, common SoC and prebuilt integration templates."""

import json
from pathlib import Path

import native_config


def render(data, header, license_text, notice):
    company, board, product = (data[k] for k in ("company", "board", "product"))
    soc_company, soc = data["soc_company"], data["soc"]
    board_path = f"device/board/{company}/{board}"
    soc_path = f"device/soc/{soc_company}/{soc}"
    kernel_path = f"kernel/{company}/{board}"
    product_path = f"vendor/{company}/{product}"
    common_path = "vendor/opendroid/common"
    encoded = lambda value: json.dumps(value, indent=2) + "\n"
    arch = "armv8-a" if data["target_cpu"] == "arm64" else "armv7-a"
    options = {
        "CONFIG_ANDROID_BINDER_IPC": ["y", "m"], "CONFIG_SECURITY": ["y"],
        "CONFIG_SECURITY_SELINUX": ["y"], "CONFIG_EXT4_FS": ["y", "m"],
        "CONFIG_TMPFS": ["y"], "CONFIG_PROC_FS": ["y"], "CONFIG_SYSFS": ["y"],
    }
    if data["target_cpu"] == "arm64":
        options.update(CONFIG_ARM64=["y"], CONFIG_64BIT=["y"])
    else:
        options["CONFIG_ARM"] = ["y"]
    if data.get("native_config", {}).get("firmware_directory"):
        options["CONFIG_FW_LOADER"] = ["y"]
    configuration = native_config.render(data, header)
    board_options = {}
    if data["init_mode"] == "two-stage":
        board_options.update(CONFIG_BLK_DEV_INITRD=["y"], CONFIG_RD_GZIP=["y"],
                             CONFIG_INITRAMFS_FORCE=["n"])
        if any("required" in mount["manager_flags"]
               for mount in data.get("native_config", {}).get("mounts", [])):
            board_options["CONFIG_EXT4_FS"] = ["y"]
    additional_requirements = '[ "requirements.json" ]' if board_options else '[]'
    board_dependencies = [f"//{kernel_path}:kernel", f"//{kernel_path}:modules"]
    if f"{board_path}/cfg/BUILD.gn" in configuration:
        board_dependencies.append("cfg:native_configs")
    if f"{board_path}/image_conf/BUILD.gn" in configuration:
        board_dependencies.append("image_conf:image_configs")
    deps = "\n".join(f'    "{label}",' for label in board_dependencies)
    files = {
        f"{board_path}/config.gni": header + f'''import("//{soc_path}/config.gni")

# hb scans this file before evaluating GN imports.
board_toolchain_type = "clang"
''',
        f"{board_path}/BUILD.gn": header + f'''group("board") {{
  deps = [
{deps}
  ]
}}
''',
        f"{soc_path}/config.gni": header + f'''assert(target_cpu == "{data['target_cpu']}", "SoC userspace ABI differs")

board_arch = "{arch}"
board_cpu = ""
board_toolchain_type = "clang"
board_fpu = "{'neon-fp-armv8' if data['target_cpu'] == 'arm64' else 'neon'}"
''',
        f"{soc_path}/kernel/requirements.json": encoded({
            "format_version": 1, "required_options": options,
        }),
        f"{kernel_path}/prebuilts.json": encoded({"format_version": 1, "state": "unselected", "files": []}),
        f"{kernel_path}/module-order.json": encoded({"format_version": 1, "modules": data.get("module_load_order", [])}),
        f"{kernel_path}/BUILD.gn": header + f'''import("//build/ohos.gni")

declare_args() {{
  opendroid_kernel_selection = ""
}}

_requirements = "//{soc_path}/kernel/requirements.json"
_additional_requirements = {additional_requirements}
_module_order = "module-order.json"
_stager = "//{common_path}/scripts/stage_kernel.py"
assert(opendroid_kernel_selection != "",
       "Kernel prebuilt set is unselected; run stage_kernel.py --prepare and set opendroid_kernel_selection")
_selection = read_file(opendroid_kernel_selection, "json")
assert(_selection.format_version == 1, "Unsupported kernel selection description")
_id_check = _selection.id
foreach(digit, [ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" ]) {{
  _id_check = string_replace(_id_check, digit, "")
}}
assert(_selection.id != "" && _id_check == "", "Invalid kernel selection identity")
foreach(item, _selection.files) {{
  foreach(path, [ item.path, item.destination ]) {{
    assert(string_replace(path, "\\\\", "") == path, "Kernel file paths must use POSIX separators")
    foreach(component, string_split(path, "/")) {{
      assert(component != "" && component != "." && component != "..",
             "Kernel file paths must be relative without traversal")
    }}
  }}
}}
_manifest_dir = get_path_info(_selection.manifest_path, "dir")
_stage_dir = "$root_build_dir/opendroid-prebuilts/{board}/${{_selection.id}}"

action("kernel") {{
  script = _stager
  inputs = [
    opendroid_kernel_selection,
    _selection.manifest_path,
    _requirements,
    _module_order,
  ] + _additional_requirements
  outputs = [ "$_stage_dir/stage-report.json" ]
  foreach(item, _selection.files) {{
    inputs += [ "$_manifest_dir/${{item.path}}" ]
    outputs += [ "$_stage_dir/${{item.destination}}" ]
  }}
  args = [
    "--allow-empty-output",
    "--selection",
    rebase_path(opendroid_kernel_selection, root_build_dir),
    "--manifest",
    rebase_path(_selection.manifest_path, root_build_dir),
    "--requirements",
    rebase_path(_requirements, root_build_dir),
    "--module-order",
    rebase_path(_module_order, root_build_dir),
    "--output",
    rebase_path(_stage_dir, root_build_dir),
  ]
  foreach(requirement, _additional_requirements) {{
    args += [ "--additional-requirements", rebase_path(requirement, root_build_dir) ]
  }}
}}

_module_targets = []
_module_index = 0
foreach(item, _selection.files) {{
  if (item.role == "module") {{
    _name = "module_${{_module_index}}"
    _module_targets += [ ":$_name" ]
    _module_index += 1
    ohos_prebuilt_etc(_name) {{
      source = "$_stage_dir/${{item.destination}}"
      output = "$_name/" + get_path_info(item.destination, "file")
      module_install_dir = "lib/opendroid/" + get_path_info(item.destination, "dir")
      install_images = [ vendor_base_dir ]
      install_enable = true
      part_name = "device_{board}"
      subsystem_name = "device_{board}"
      deps = [ ":kernel" ]
    }}
  }}
}}

group("modules") {{
  deps = _module_targets
}}
''',
        f"{product_path}/BUILD.gn": header + f'''import("//build/ohos.gni")

ohos_prebuilt_etc("product_parameters") {{
  source = "product.para"
  relative_install_dir = "param"
  install_images = [ sys_prod_base_dir ]
  install_enable = true
  part_name = "product_{product}"
}}

group("product") {{
  deps = [
    ":product_parameters",
    "//{common_path}:common",
  ]
}}
''',
        f"{product_path}/product.para": header + f"const.build.product={product}\n",
        f"{common_path}/BUILD.gn": header + '''import("//build/ohos.gni")

ohos_prebuilt_etc("distribution_parameters") {
  source = "opendroid.para"
  relative_install_dir = "param"
  install_images = [ sys_prod_base_dir ]
  install_enable = true
  part_name = "product_${product_name}"
}

group("common") {
  deps = [ ":distribution_parameters" ]
}
''',
        f"{common_path}/opendroid.para": header + "const.product.brand=OpenDroidOS\n",
        f"{common_path}/base.json": encoded({"subsystems": [{"subsystem": "security", "components": [
            {"component": "selinux_adapter"}]}]}),
    }
    if data.get("system_profile") == "tablet":
        files[f"{common_path}/tablet.json"] = encoded({"subsystems": [
            {"subsystem": "ability", "components": [{"component": "idl_tool"}]},
            {"subsystem": "arkcompiler", "components": [{"component": "taihe_ffi_gen"}]},
            {"subsystem": "developtools", "components": [{"component": name} for name in (
                "ace_js2bundle", "ace_ets2bundle", "global_resource_tool", "packing_tool"
            )]},
            {"subsystem": "sdk", "components": [{"component": "sdk"}]},
            {"subsystem": "hdf", "components": [{"component": name} for name in (
                "drivers_interface_memorytracker", "drivers_interface_partitionslot",
                "drivers_peripheral_partitionslot", "drivers_interface_bluetooth",
                "drivers_interface_distributed_audio", "drivers_tools"
            )]},
            {"subsystem": "multimedia", "components": [{"component": "ringtone_library"}]},
            {"subsystem": "graphic", "components": [{"component": "graphics_effect"}]},
            {"subsystem": "telephony", "components": [{"component": name} for name in (
                "telephony_data", "core_service", "cellular_data", "call_manager", "state_registry"
            )]},
            {"subsystem": "tee", "components": [{"component": "tee_client"}]},
            {"subsystem": "thirdparty", "components": [{"component": name} for name in (
                "parse5", "weex-loader", "xmp_toolkit_sdk", "expat", "libdrm",
                "typescript", "astc-encoder", "rust_libc", "optimized_routines",
                "lzma", "vulkan-loader", "abseil-cpp", "vma", "FreeBSD", "dav1d",
                "elfio", "freetype", "grpc", "harfbuzz", "iptables", "jerryscript",
                "lame", "libexif", "libinput", "libphonenumber", "libvpx",
                "meshoptimizer", "mtdev", "opencore-amr", "openmax", "opus", "re2",
                "rust_cxx", "rust_bindgen", "vulkan-headers", "flatbuffers",
                "vixl", "css-what", "opencl-headers"
            )] + [
                {"component": name, "exclude": "true"} for name in ("eudev", "libsnd")
            ]},
            {"subsystem": "security", "components": [{
                "component": "access_token", "features": ["access_token_enhance_capability = false"]
            }, {"component": "security_guard"}, {"component": "asset"},
                {"component": "security_component_manager"}]},
        ]})
    if board_options:
        files[f"{kernel_path}/requirements.json"] = encoded({
            "format_version": 1, "required_options": board_options,
        })
    board_requirement_argument = (f"  --additional-requirements {kernel_path}/requirements.json \\\n"
                                  if board_options else "")
    descriptions = {
        board_path: f"# {board}\n\nOpenHarmony board configuration. Imports `{soc_path}` and uses `{kernel_path}` for prebuilt kernel and module integration.\n",
        soc_path: f"# {soc}\n\nShared {data['target_cpu']} build settings and Linux kernel requirements for OpenHarmony.\n",
        kernel_path: f'''# {board} kernel integration

Prepare a private GN selection from the source root:

```sh
python3 vendor/opendroid/common/scripts/stage_kernel.py --prepare \\
  --manifest /path/to/private/prebuilts.json \\
  --requirements {soc_path}/kernel/requirements.json \\
{board_requirement_argument}  --module-order {kernel_path}/module-order.json \\
  --output /path/to/private/selection.json
```

Set `opendroid_kernel_selection` to the prepared file. Use a new output path
when the manifest, requirements, module order or source paths change.

The input manifest has `format_version: 1`, `state: selected`, and `files`
entries with `role`, `path`, `sha256`, `destination`. Paths are relative to the
manifest. Include one `kernel` and one `config`; optional roles are `module`,
`dtb`, `dtbo`.

Staging rechecks the prepared description, payload hashes and kernel options.
Modules install at `/vendor/lib/opendroid/<destination>`. `module-order.json`
lists their init load order; module dependencies and ABI need a matching set.
''',
        product_path: f"# {product}\n\nOpenHarmony {data.get('system_profile', 'base')} product configuration for `{board_path}`. Inherits `vendor/opendroid/common` and installs product parameters.\n",
        common_path: "# OpenDroid common configuration\n\nShared OpenHarmony product components, distribution parameters and prebuilt staging tools.\n\n`scripts/stage_kernel.py --prepare` writes a private GN selection description. Set\n`opendroid_kernel_selection` to that file. Staging rechecks descriptors, selected\nfile hashes and kernel configuration before publishing outputs.\n",
    }
    if data.get("native_config"):
        native = data["native_config"]
        descriptions[board_path] += f"\nInit hardware key: `{native['hardware']}`.\n"
        if native.get("firmware_directory"):
            descriptions[board_path] += f"Firmware search path: `{native['firmware_directory']}`.\n"
    if data.get("system_profile") == "tablet":
        descriptions[common_path] += "\nTablet products inherit `tablet.json` after `productdefine/common/inherit/tablet.json`.\n"
    descriptions[board_path] += f"\nInit mode: `{data['init_mode']}`.\n"
    if board_options:
        descriptions[kernel_path] += "\n`requirements.json` adds the board's built-in ramdisk and first-stage filesystem requirements to the shared SoC requirements.\n"
    for path, readme in descriptions.items():
        files[f"{path}/README.md"] = readme
        files[f"{path}/LICENSE"] = license_text
        files[f"{path}/NOTICE"] = notice
    runtime = Path(__file__).parent / "runtime/stage_kernel.py"
    files[f"{common_path}/scripts/stage_kernel.py"] = runtime.read_text(encoding="utf-8")
    return files
