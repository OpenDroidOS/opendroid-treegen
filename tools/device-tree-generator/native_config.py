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

"""Render only explicitly supplied native board mounts, permissions and images.

ueventd uses the first matching permission rule. A vendor rule does not override
an earlier system match; callers must inspect that native ordering separately.
No board paths, firmware locations or filesystem sizes are inferred here.
"""

import json
import re


IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
PATH_COMPONENT = re.compile(r"[A-Za-z0-9_.@+-]+\Z")
DEVICE_COMPONENT = re.compile(r"[A-Za-z0-9_.@+*-]+\Z")
ACCOUNT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,62}\Z")
MOUNT_POINTS = {"/usr", "/vendor", "/sys_prod", "/chip_prod", "/data", "/metadata", "/mnt/vendor/persist"}
MOUNT_OPTIONS = {"ro", "rw", "noatime", "nosuid", "nodev", "barrier=1", "discard"}
MANAGER_FLAGS = {"wait", "check", "required", "nofail"}
IMAGE_MOUNTS = {"system": "/", "vendor": "/vendor", "sys_prod": "/sys_prod",
                "chip_prod": "/chip_prod", "userdata": "/data"}


def _object(value, allowed, required, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    if set(value) - set(allowed):
        raise ValueError(f"{label} has unknown fields: {sorted(set(value) - set(allowed))}")
    if set(required) - set(value):
        raise ValueError(f"{label} is missing fields: {sorted(set(required) - set(value))}")


def _identifier(value, label):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase identifier starting with a letter")


def _path(value, label, wildcard=False):
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{label} must be an absolute safe path")
    matcher = DEVICE_COMPONENT if wildcard else PATH_COMPONENT
    if any(part in ("", ".", "..") or not matcher.fullmatch(part)
           for part in value.split("/")[1:]):
        raise ValueError(f"{label} contains an unsafe path component")


def _flags(value, allowed, label):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a nonempty list")
    if any(not isinstance(flag, str) or flag not in allowed for flag in value):
        raise ValueError(f"{label} contains an unsupported flag")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicate flags")


def _account(value, label):
    if type(value) is int:
        if 0 <= value <= 2 ** 32 - 2:
            return
    elif isinstance(value, str):
        if ACCOUNT.fullmatch(value):
            return
        if re.fullmatch(r"[0-9]{1,10}", value) and int(value) <= 2 ** 32 - 2:
            return
    raise ValueError(f"{label} must be a safe account name or nonnegative numeric ID")


def validate(data):
    """Validate optional native_config and the source identities used by render."""
    if not isinstance(data, dict):
        raise ValueError("Generator data must be an object")
    module_order = data.get("module_load_order", [])
    if not isinstance(module_order, list):
        raise ValueError("module_load_order must be a list")
    seen_modules = set()
    for destination in module_order:
        if not isinstance(destination, str) or not destination.endswith(".ko") or destination.startswith("/"):
            raise ValueError("module_load_order entries must be safe relative .ko destinations")
        _path("/" + destination, "module_load_order destination")
        if destination in seen_modules:
            raise ValueError(f"Duplicate module load destination: {destination}")
        seen_modules.add(destination)
    if "native_config" not in data:
        if module_order:
            raise ValueError("module_load_order requires native_config.hardware")
        return
    for name in ("company", "board"):
        _identifier(data.get(name), name)
    native = data["native_config"]
    _object(native, {"hardware", "mounts", "device_permissions", "firmware_directory", "images"},
            {"hardware"}, "native_config")
    _identifier(native["hardware"], "native_config.hardware")
    mounts = native.get("mounts", [])
    if not isinstance(mounts, list):
        raise ValueError("native_config.mounts must be a list")
    seen_mounts = set()
    for index, mount in enumerate(mounts):
        label = f"native_config.mounts[{index}]"
        fields = {"device", "mount_point", "fs_type", "mount_options", "manager_flags"}
        _object(mount, fields, fields, label)
        _path(mount["device"], f"{label}.device")
        if not mount["device"].startswith("/dev/block/"):
            raise ValueError(f"{label}.device must be below /dev/block")
        if not isinstance(mount["mount_point"], str) or mount["mount_point"] not in MOUNT_POINTS:
            raise ValueError(f"{label}.mount_point is unsupported")
        if mount["mount_point"] in seen_mounts:
            raise ValueError(f"Duplicate mount point: {mount['mount_point']}")
        seen_mounts.add(mount["mount_point"])
        if mount["fs_type"] != "ext4":
            raise ValueError(f"{label}.fs_type must be ext4")
        _flags(mount["mount_options"], MOUNT_OPTIONS, f"{label}.mount_options")
        if "ro" in mount["mount_options"] and "rw" in mount["mount_options"]:
            raise ValueError(f"{label}.mount_options cannot contain both ro and rw")
        _flags(mount["manager_flags"], MANAGER_FLAGS, f"{label}.manager_flags")
        if "required" in mount["manager_flags"] and data.get("init_mode") != "two-stage":
            raise ValueError("required mounts need explicit init_mode two-stage")
        if "required" in mount["manager_flags"] and "nofail" not in mount["manager_flags"]:
            raise ValueError("A required mount needs nofail so native mount errors propagate")
    required = [mount for mount in mounts if "required" in mount["manager_flags"]]
    root_indices = [index for index, mount in enumerate(required) if mount["mount_point"] == "/usr"]
    if root_indices and root_indices[0] != 0:
        raise ValueError("The required /usr root mount must precede other required mounts")
    permissions = native.get("device_permissions", [])
    if not isinstance(permissions, list):
        raise ValueError("native_config.device_permissions must be a list")
    seen_devices = set()
    for index, item in enumerate(permissions):
        label = f"native_config.device_permissions[{index}]"
        fields = {"path", "mode", "uid", "gid"}
        _object(item, fields, fields, label)
        _path(item["path"], f"{label}.path", wildcard=True)
        if not item["path"].startswith("/dev/"):
            raise ValueError(f"{label}.path must be below /dev")
        if item["path"] in seen_devices:
            raise ValueError(f"Duplicate device permission path: {item['path']}")
        seen_devices.add(item["path"])
        if not isinstance(item["mode"], str) or not re.fullmatch(r"0[0-7]{3}", item["mode"]):
            raise ValueError(f"{label}.mode must contain four octal digits, at most 0777")
        _account(item["uid"], f"{label}.uid")
        _account(item["gid"], f"{label}.gid")
    if "firmware_directory" in native:
        value = native["firmware_directory"]
        _path(value, "native_config.firmware_directory")
        if len(value.encode("utf-8")) > 255:
            raise ValueError("firmware_directory must fit the Linux 256-byte firmware path buffer")
        if not any(value == root or value.startswith(root + "/") for root in ("/vendor/firmware", "/lib/firmware")):
            raise ValueError("firmware_directory must be /vendor/firmware or /lib/firmware, or below either")
    images = native.get("images", {})
    _object(images, IMAGE_MOUNTS, set(), "native_config.images")
    for name, image in images.items():
        label = f"native_config.images.{name}"
        _object(image, {"size_bytes", "mount_point"}, {"size_bytes", "mount_point"}, label)
        size = image["size_bytes"]
        if type(size) is not int or not 0 < size <= 2 ** 45 or size % 4096:
            raise ValueError(f"{label}.size_bytes must be a positive 4096-aligned integer at most 2**45")
        if image["mount_point"] != IMAGE_MOUNTS[name]:
            raise ValueError(f"{label}.mount_point must be {IMAGE_MOUNTS[name]}")


def render(data, header):
    """Return namespaced source files for explicit native_config, with no writes."""
    validate(data)
    if "native_config" not in data:
        return {}
    native = data["native_config"]
    board = data["board"]
    hardware = native["hardware"]
    board_path = f"device/board/{data['company']}/{board}"
    cfg_path = f"{board_path}/cfg"
    files = {}
    targets = []
    if native.get("mounts"):
        filename = f"fstab.{hardware}"
        lines = [" ".join((mount["device"], mount["mount_point"], "ext4",
                           ",".join(mount["mount_options"]), ",".join(mount["manager_flags"])))
                 for mount in native["mounts"]]
        files[f"{cfg_path}/{filename}"] = header + "\n".join(lines) + "\n"
        targets.append(("fstab", filename, "vendor_base_dir"))
        required = [line for mount, line in zip(native["mounts"], lines)
                    if "required" in mount["manager_flags"]]
        if required:
            files[f"{cfg_path}/fstab.required"] = header + "\n".join(required) + "\n"
            targets.append(("first_stage_fstab", "fstab.required", "ramdisk_base_dir"))
    if native.get("device_permissions"):
        lines = ["[device]"]
        lines += [f"{item['path']} {item['mode']} {item['uid']} {item['gid']}" for item in native["device_permissions"]]
        files[f"{cfg_path}/ueventd.config"] = header + "\n".join(lines) + "\n"
        targets.append(("device_permissions", "ueventd.config", "vendor_base_dir"))
    commands = []
    if "firmware_directory" in native:
        commands.append(f"write /sys/module/firmware_class/parameters/path {native['firmware_directory']}")
    commands += [f"insmod /vendor/lib/opendroid/{destination}" for destination in data.get("module_load_order", [])]
    if commands:
        filename = f"init.{hardware}.cfg"
        contents = {"jobs": [{"name": "init", "cmds": commands}]}
        # Native init cfg is JSON; comments and copyright headers are not valid JSON.
        files[f"{cfg_path}/{filename}"] = json.dumps(contents, indent=2) + "\n"
        targets.append(("board_init", filename, "vendor_base_dir"))
    if targets:
        blocks = [header + 'import("//build/ohos.gni")\n']
        for target, filename, image in targets:
            blocks.append(f'''ohos_prebuilt_etc("{target}") {{
  source = "{filename}"
  install_images = [ {image} ]
  install_enable = true
  part_name = "device_{board}"
  subsystem_name = "device_{board}"
}}
''')
        blocks.append('group("native_configs") {\n  deps = [\n' +
                      "".join(f'    ":{target}",\n' for target, _, _ in targets) + '  ]\n}\n')
        files[f"{cfg_path}/BUILD.gn"] = "\n".join(blocks)
    if native.get("images"):
        image_path = f"{board_path}/image_conf"
        names = sorted(native["images"])
        for name in names:
            image = native["images"][name]
            files[f"{image_path}/{name}_image_conf.txt"] = header + (
                f"{image['mount_point']}\n{image['size_bytes']}\n--fs_type=ext4\n"
                "--dac_config ../../build/ohos/images/mkimage/dac.txt\n"
                "--file_context obj/base/security/selinux_adapter/file_contexts.bin\n")
        files[f"{image_path}/BUILD.gn"] = header + '''import("//build/ohos.gni")
import("//build/ohos/build_var.gni")

ohos_copy("image_config_files") {
  sources = [
''' + "".join(f'    "{name}_image_conf.txt",\n' for name in names) + '''  ]
  outputs = [ "${product_output_dir}/imagesconf/{{source_file_part}}" ]
}

group("image_configs") {
  deps = [ ":image_config_files" ]
}
'''
    return files
