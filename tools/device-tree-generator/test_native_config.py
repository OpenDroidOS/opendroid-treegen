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

import copy
import json
import unittest

import native_config


class NativeConfigTests(unittest.TestCase):
    def setUp(self):
        self.data = {"company": "opendroid", "board": "demo_board", "init_mode": "two-stage", "native_config": {
            "hardware": "demo_hw",
            "mounts": [{"device": "/dev/block/by-name/vendor", "mount_point": "/vendor", "fs_type": "ext4",
                        "mount_options": ["ro", "noatime", "barrier=1"], "manager_flags": ["wait", "required", "nofail"]}],
            "device_permissions": [{"path": "/dev/example*", "mode": "0660", "uid": "system", "gid": 1000}],
            "firmware_directory": "/vendor/firmware/demo",
            "images": {"vendor": {"size_bytes": 256 * 1024 * 1024, "mount_point": "/vendor"}},
        }}
        self.header = "# Copyright 2026 OpenDroidOS\n"
        self.board_path = "device/board/opendroid/demo_board"

    def test_absent_or_explicit_empty_configuration_generates_nothing(self):
        self.assertEqual(native_config.render({}, self.header), {})
        for value in ({"hardware": "demo_hw"}, {"hardware": "demo_hw", "mounts": [], "device_permissions": [], "images": {}}):
            self.data["native_config"] = value
            self.assertEqual(native_config.render(self.data, self.header), {})

    def test_installed_native_files_contain_only_declared_work(self):
        original = copy.deepcopy(self.data)
        files = native_config.render(self.data, self.header)
        self.assertEqual(self.data, original)
        cfg = f"{self.board_path}/cfg"
        self.assertEqual(files[f"{cfg}/fstab.demo_hw"], self.header + "/dev/block/by-name/vendor /vendor ext4 ro,noatime,barrier=1 wait,required,nofail\n")
        self.assertEqual(files[f"{cfg}/ueventd.config"], self.header + "[device]\n/dev/example* 0660 system 1000\n")
        self.assertEqual(json.loads(files[f"{cfg}/init.demo_hw.cfg"]), {"jobs": [{"name": "init", "cmds": [
            "write /sys/module/firmware_class/parameters/path /vendor/firmware/demo"]}]})
        build = files[f"{cfg}/BUILD.gn"]
        for target in ("fstab", "device_permissions", "board_init"):
            self.assertIn(f'ohos_prebuilt_etc("{target}")', build)
            self.assertIn(f'":{target}"', build)
        self.assertEqual(build.count("install_images = [ vendor_base_dir ]"), 3)
        self.assertEqual(build.count('part_name = "device_demo_board"'), 4)
        self.assertEqual(build.count('subsystem_name = "device_demo_board"'), 4)
        self.assertEqual(build.count("install_images = [ ramdisk_base_dir ]"), 1)
        self.assertIn('group("native_configs")', build)
        self.assertNotIn("uevent firmware", "\n".join(files.values()))

    def test_each_optional_work_item_generates_only_its_own_file(self):
        for key, filename in (("mounts", "fstab.demo_hw"), ("device_permissions", "ueventd.config"),
                              ("firmware_directory", "init.demo_hw.cfg")):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data["native_config"] = {"hardware": "demo_hw", key: data["native_config"][key]}
                files = native_config.render(data, self.header)
                expected = {f"{self.board_path}/cfg/{filename}", f"{self.board_path}/cfg/BUILD.gn"}
                if key == "mounts":
                    expected.add(f"{self.board_path}/cfg/fstab.required")
                self.assertEqual(set(files), expected)

    def test_first_stage_fstab_excludes_late_mounts(self):
        mounts = self.data["native_config"]["mounts"]
        mounts.append({"device": "/dev/block/by-name/userdata", "mount_point": "/data",
                       "fs_type": "ext4", "mount_options": ["rw"], "manager_flags": ["wait"]})
        files = native_config.render(self.data, self.header)
        cfg = f"{self.board_path}/cfg"
        self.assertEqual(files[f"{cfg}/fstab.required"], self.header +
                         "/dev/block/by-name/vendor /vendor ext4 ro,noatime,barrier=1 wait,required,nofail\n")
        self.assertIn("/data", files[f"{cfg}/fstab.demo_hw"])
        mounts[0]["manager_flags"] = ["wait"]
        self.data["init_mode"] = "single-stage"
        files = native_config.render(self.data, self.header)
        self.assertNotIn(f"{cfg}/fstab.required", files)
        self.assertNotIn("ramdisk_base_dir", files[f"{cfg}/BUILD.gn"])

    def test_required_mounts_need_explicit_two_stage_init_and_error_preservation(self):
        for mode in (None, "single-stage"):
            self.data["init_mode"] = mode
            with self.assertRaisesRegex(ValueError, "two-stage"):
                native_config.validate(self.data)
        self.data["init_mode"] = "two-stage"
        self.data["native_config"]["mounts"][0]["manager_flags"] = ["wait", "required"]
        with self.assertRaisesRegex(ValueError, "nofail"):
            native_config.validate(self.data)
        self.data["native_config"]["mounts"][0]["manager_flags"] = ["wait", "required", "nofail"]
        native_config.validate(self.data)
        self.data["native_config"]["mounts"][0]["manager_flags"] = ["wait", "check", "required", "nofail"]
        native_config.validate(self.data)

    def test_required_root_precedes_other_required_mounts(self):
        mounts = self.data["native_config"]["mounts"]
        root = {"device": "/dev/block/by-name/system", "mount_point": "/usr", "fs_type": "ext4",
                "mount_options": ["ro"], "manager_flags": ["wait", "required", "nofail"]}
        mounts.append(root)
        with self.assertRaisesRegex(ValueError, "precede"):
            native_config.validate(self.data)
        mounts.reverse()
        files = native_config.render(self.data, self.header)
        lines = files[f"{self.board_path}/cfg/fstab.required"].splitlines()
        self.assertIn(" /usr ", lines[1])
        self.assertIn(" /vendor ", lines[2])

    def test_image_configs_use_explicit_native_mounts_sizes_and_copy_destination(self):
        self.data["native_config"] = {"hardware": "demo_hw", "images": {
            name: {"size_bytes": 4096 * (index + 1), "mount_point": mount}
            for index, (name, mount) in enumerate(native_config.IMAGE_MOUNTS.items())}}
        files = native_config.render(self.data, self.header)
        for name, image in self.data["native_config"]["images"].items():
            contents = files[f"{self.board_path}/image_conf/{name}_image_conf.txt"]
            lines = [line for line in contents.splitlines() if line and not line.startswith("#")]
            self.assertEqual(lines[:3], [image["mount_point"], str(image["size_bytes"]), "--fs_type=ext4"])
            self.assertIn("--dac_config ../../build/ohos/images/mkimage/dac.txt", lines)
            self.assertIn("--file_context obj/base/security/selinux_adapter/file_contexts.bin", lines)
        build = files[f"{self.board_path}/image_conf/BUILD.gn"]
        self.assertIn('import("//build/ohos/build_var.gni")', build)
        self.assertIn('${product_output_dir}/imagesconf/{{source_file_part}}', build)
        self.assertIn('ohos_copy("image_config_files")', build)
        self.assertIn('group("image_configs")', build)
        self.assertIn('deps = [ ":image_config_files" ]', build)
        self.assertFalse(any("/cfg/" in name for name in files))

    def test_rejects_unknown_fields_and_missing_hardware(self):
        for change in ({}, {"hardware": "demo_hw", "guess_drivers": True}, {"hardware": "demo_hw", "mounts": [{}]},
                       {"hardware": "demo_hw", "images": {"boot": {"size_bytes": 4096, "mount_point": "/"}}}):
            with self.subTest(change=change):
                self.data["native_config"] = change
                with self.assertRaises(ValueError):
                    native_config.validate(self.data)

    def test_rejects_unsafe_identifiers_paths_and_injection(self):
        for key in ("company", "board"):
            for value in ("../escape", "bad/name", "quote\"", "name\n", True):
                with self.subTest(key=key, value=value):
                    data = copy.deepcopy(self.data)
                    data[key] = value
                    with self.assertRaises(ValueError):
                        native_config.validate(data)
        for value in ("../escape", "bad/name", "bad\"", "name\n", "${exec}", True):
            data = copy.deepcopy(self.data)
            data["native_config"]["hardware"] = value
            with self.assertRaises(ValueError):
                native_config.validate(data)
        for value in ("/dev/block/../escape", "/dev/block/a b", "/dev/block/a\nb", "/dev/block/a\\b",
                      "/dev/block/a//b", "/dev/block/*", "/dev/block/$(execute)", "/tmp/vendor", True):
            with self.subTest(device=value):
                data = copy.deepcopy(self.data)
                data["native_config"]["mounts"][0]["device"] = value
                with self.assertRaises(ValueError):
                    native_config.validate(data)

    def test_mount_flags_require_native_allowlist(self):
        for key, values in (("mount_options", ["ro", "rw"]), ("mount_options", ["ro", "ro"]),
                            ("mount_options", []), ("mount_options", ["rw;exec"]), ("mount_options", [True]),
                            ("manager_flags", ["slotselect"]), ("manager_flags", ["logical"]),
                            ("manager_flags", ["avb"]), ("manager_flags", []), ("manager_flags", ["wait", "wait"])):
            with self.subTest(key=key, values=values):
                data = copy.deepcopy(self.data)
                data["native_config"]["mounts"][0][key] = values
                with self.assertRaises(ValueError):
                    native_config.validate(data)
        for key, value in (("mount_point", "/system"), ("fs_type", "erofs"), ("mount_point", True)):
            data = copy.deepcopy(self.data)
            data["native_config"]["mounts"][0][key] = value
            with self.assertRaises(ValueError):
                native_config.validate(data)

    def test_permissions_reject_unsafe_paths_modes_and_accounts(self):
        for key, values in (("path", ["/sys/example", "/dev/a?", "/dev/a[0]", "/dev/../a", "/dev/a b", "/dev/${bad}"]),
                            ("mode", ["660", "1660", "0888", "07777", 0o660, True]),
                            ("uid", ["root\nexec", "root;exec", "${user}", -1, True, 2 ** 32]),
                            ("gid", ["bad group", "/root", "1000\n", -1, True])):
            for value in values:
                with self.subTest(key=key, value=value):
                    data = copy.deepcopy(self.data)
                    data["native_config"]["device_permissions"][0][key] = value
                    with self.assertRaises(ValueError):
                        native_config.validate(data)

    def test_duplicate_mounts_and_permissions_rejected(self):
        for key in ("mounts", "device_permissions"):
            data = copy.deepcopy(self.data)
            data["native_config"][key].append(copy.deepcopy(data["native_config"][key][0]))
            with self.assertRaises(ValueError):
                native_config.validate(data)

    def test_firmware_paths_are_explicit_and_safe(self):
        for value in ("/vendor/firmware", "/lib/firmware", "/lib/firmware/qcom/sm8735"):
            self.data["native_config"]["firmware_directory"] = value
            native_config.validate(self.data)
        for value in ("/vendor/firmware-bad", "/data/firmware", "/lib/firmware/../other", "/vendor/firmware/a b", True):
            self.data["native_config"]["firmware_directory"] = value
            with self.assertRaises(ValueError):
                native_config.validate(self.data)

    def test_image_size_and_mount_validation_rejects_bool_and_guesses(self):
        for size in (True, False, 0, -4096, 4097, 2 ** 45 + 4096, "4096", 4096.0):
            with self.subTest(size=size):
                data = copy.deepcopy(self.data)
                data["native_config"]["images"]["vendor"]["size_bytes"] = size
                with self.assertRaises(ValueError):
                    native_config.validate(data)
        for mount in ("/system", "/vendor/", "/vendor\nexec", True):
            data = copy.deepcopy(self.data)
            data["native_config"]["images"]["vendor"]["mount_point"] = mount
            with self.assertRaises(ValueError):
                native_config.validate(data)

    def test_module_load_order_is_explicit_and_follows_firmware_path(self):
        self.data["module_load_order"] = ["modules/dependency.ko", "modules/device.ko"]
        files = native_config.render(self.data, self.header)
        commands = json.loads(files[f"{self.board_path}/cfg/init.demo_hw.cfg"])["jobs"][0]["cmds"]
        self.assertEqual(commands, ["write /sys/module/firmware_class/parameters/path /vendor/firmware/demo",
                                    "insmod /vendor/lib/opendroid/modules/dependency.ko",
                                    "insmod /vendor/lib/opendroid/modules/device.ko"])
        self.data["native_config"] = {"hardware": "demo_hw"}
        files = native_config.render(self.data, self.header)
        commands = json.loads(files[f"{self.board_path}/cfg/init.demo_hw.cfg"])["jobs"][0]["cmds"]
        self.assertEqual(commands, ["insmod /vendor/lib/opendroid/modules/dependency.ko",
                                    "insmod /vendor/lib/opendroid/modules/device.ko"])
        self.assertEqual(set(files), {f"{self.board_path}/cfg/init.demo_hw.cfg", f"{self.board_path}/cfg/BUILD.gn"})

    def test_module_load_order_rejects_unsafe_paths_and_requires_hardware(self):
        for order in ("a.ko", ["../a.ko"], ["/absolute.ko"], ["a//b.ko"], ["a\\b.ko"],
                      ["bad name.ko"], ["a.ko\n"], ["a.ko.gz"], [True], ["a.ko", "a.ko"]):
            with self.subTest(order=order):
                data = copy.deepcopy(self.data)
                data["module_load_order"] = order
                with self.assertRaises(ValueError):
                    native_config.validate(data)
        with self.assertRaises(ValueError):
            native_config.validate({"module_load_order": ["a.ko"]})


if __name__ == "__main__":
    unittest.main()
