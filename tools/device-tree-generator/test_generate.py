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
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.data = generate.read_json(Path(__file__).parent / "examples/native-arm64.json")
        generate.validate_input(self.data)

    def test_path_injection_and_unsupported_claims(self):
        for key, value in (("company", "../escape"), ("board", 'bad"name'),
                           ("product", "../../out"), ("schema_version", True),
                           ("product", "common"), ("soc", "../bad"), ("soc_company", "qcom/bad"),
                           ("source_profile", True), ("target_cpu", "auto"),
                           ("providers", {"display_gpu": "supported"}),
                           ("system_profile", "android"),
                           ("init_mode", "android"), ("init_mode", True),
                           ("module_load_order", ["../bad.ko"]),
                           ("module_load_order", ["modules/a.ko", "modules/a.ko"]),
                           ("native_config", {"hardware": "bad/name"}),
                           ("providers", {"typo": "unknown"})):
            with self.subTest(key=key, value=value):
                data = copy.deepcopy(self.data)
                data[key] = value
                with self.assertRaises(generate.InputError):
                    generate.validate_input(data)

    def test_product_feature_choices_are_typed_and_unknown_ids_fail(self):
        for value in ({"safwk_run_on_demand_qos": True},
                      {"hitrace_executable": False}, {}):
            data = copy.deepcopy(self.data)
            data["product_features"] = value
            generate.validate_input(data)
        for value in ({"safwk_run_on_demand_qos": 1}, {"typo": True}, [], None):
            data = copy.deepcopy(self.data)
            data["product_features"] = value
            with self.subTest(value=value), self.assertRaises(generate.InputError):
                generate.validate_input(data)

    def test_product_feature_overrides_preserve_inherited_assignment_lists(self):
        contracts = {"product_feature_components": [{"subsystem": "hiviewdfx", "components": [{
            "component": "hitrace", "features": ["hitrace_support_executable_file = true",
                                                        "hitrace_custom_assignment = false"]}]}]}
        files, _ = generate.render(self.data, contracts, generate.evidence.load_extractions([]))
        config = generate.json.loads(files["vendor/opendroid/opendroid_demo/config.json"])
        parts = [part for subsystem in config["subsystems"] for part in subsystem["components"]]
        self.assertIn({"component": "product_opendroid_demo"}, parts)
        self.assertEqual(next(part["features"] for part in parts if part["component"] == "hitrace"),
                         ["hitrace_support_executable_file = true", "hitrace_custom_assignment = false"])

    def test_init_modes_control_ramdisk_and_keep_board_requirements_out_of_common_soc(self):
        data = copy.deepcopy(self.data)
        files, reports = generate.render(data, {}, generate.evidence.load_extractions([]))
        config = generate.json.loads(files["vendor/opendroid/opendroid_demo/config.json"])
        self.assertIs(config["enable_ramdisk"], True)
        board = generate.json.loads(files["kernel/opendroid/demo_board/requirements.json"])["required_options"]
        shared = generate.json.loads(files["device/soc/generic/generic_arm64/kernel/requirements.json"])["required_options"]
        self.assertEqual(board["CONFIG_EXT4_FS"], ["y"])
        self.assertEqual(board["CONFIG_INITRAMFS_FORCE"], ["n"])
        self.assertEqual(shared["CONFIG_EXT4_FS"], ["y", "m"])
        self.assertNotIn("CONFIG_BLK_DEV_INITRD", shared)
        report = generate.json.loads(reports["support-report.json"])
        self.assertEqual(next(g for g in report["gaps"] if g["id"] == "first_stage")["state"], "declared-unvalidated")
        data["native_config"].pop("mounts")
        files, reports = generate.render(data, {}, generate.evidence.load_extractions([]))
        self.assertNotIn("CONFIG_EXT4_FS", generate.json.loads(files["kernel/opendroid/demo_board/requirements.json"])["required_options"])
        report = generate.json.loads(reports["support-report.json"])
        self.assertEqual(next(g for g in report["gaps"] if g["id"] == "first_stage")["state"], "unresolved")
        data["init_mode"] = "single-stage"
        files, _ = generate.render(data, {}, generate.evidence.load_extractions([]))
        self.assertIs(generate.json.loads(files["vendor/opendroid/opendroid_demo/config.json"])["enable_ramdisk"], False)
        self.assertNotIn("kernel/opendroid/demo_board/requirements.json", files)

    def test_source_requirement_values_cannot_weaken_requested_values(self):
        expected = {"CONFIG_EXT4_FS": ["y"]}
        for actual in (
                {"format_version": 1, "required_options": {"CONFIG_EXT4_FS": ["y", "m"]}},
                {"format_version": 1, "required_options": {"CONFIG_EXT4_FS": [True]}},
                {"format_version": 1, "required_options": {"CONFIG_EXT4_FS": []}},
                {"format_version": 1, "required_options": {"CONFIG_EXTRA": ["unknown"]}}):
            with self.subTest(actual=actual), self.assertRaises(generate.InputError):
                generate._requirements_match(actual, expected, "kernel/board/requirements.json", "board")
        generate._requirements_match({"format_version": 1, "required_options": {"CONFIG_EXT4_FS": ["y"]}},
                                     expected, "kernel/board/requirements.json", "board")

    def test_init_mode_and_schema_migration_are_explicit(self):
        data = copy.deepcopy(self.data)
        del data["init_mode"]
        with self.assertRaisesRegex(generate.InputError, "init_mode"):
            generate.validate_input(data)
        data = copy.deepcopy(self.data)
        data["schema_version"] = 2
        with self.assertRaisesRegex(generate.InputError, "schema_version"):
            generate.validate_input(data)

    def test_generated_source_has_only_build_configuration_and_legal_metadata(self):
        files, _ = generate.render(self.data, {}, generate.evidence.load_extractions([]))
        for path, text in files.items():
            with self.subTest(path=path):
                self.assertNotIn("Inspected source profile", text)
                self.assertNotIn("opendroid-openharmony-weekly_", text)
                self.assertNotIn("integration-v", text)
                if path.endswith("bundle.json"):
                    bundle = generate.json.loads(text)
                    self.assertNotIn("version", bundle)
                    self.assertEqual(bundle["license"], "Apache-2.0")
                if path.endswith("requirements.json"):
                    self.assertEqual(set(generate.json.loads(text)), {"format_version", "required_options"})

    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text('{"board":"a","board":"b"}')
            with self.assertRaises(generate.InputError):
                generate.read_json(path)

    def test_oem_paths_do_not_move_distribution_common_code(self):
        data = copy.deepcopy(self.data)
        data.update(company="lenovo", board="malbec", product="malbec")
        generate.validate_input(data)
        files, reports = generate.render(data, {}, generate.evidence.load_extractions([]))
        self.assertIn("device/board/lenovo/malbec/BUILD.gn", files)
        self.assertIn("kernel/lenovo/malbec/BUILD.gn", files)
        config = generate.json.loads(files["vendor/lenovo/malbec/config.json"])
        self.assertIn("vendor/opendroid/common/base.json", config["inherit"])
        self.assertIn("vendor/opendroid/common/scripts/stage_kernel.py", files)
        self.assertFalse(any(name.startswith("vendor/lenovo/common/") for name in files))

    def test_legacy_profile_is_optional_and_removed_from_reports(self):
        for legacy in (None, "other-weekly"):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / "source"
                source.mkdir()
                data = copy.deepcopy(self.data)
                if legacy is not None:
                    data["source_profile"] = legacy
                path = root / "input.json"
                path.write_text(generate.json_text(data))
                with patch.object(generate, "verify_source", return_value={"checks": []}):
                    generate.generate(path, root / "tree", source, reports=root / "reports")
                normalized = generate.read_json(root / "reports/porting-input.json")
                self.assertNotIn("source_profile", normalized)
                report = generate.read_json(root / "reports/support-report.json")
                self.assertNotIn("source_profile", report)
                self.assertEqual(report["source_inspection"], "source-inspection.json")
                manifest = generate.read_json(root / "reports/generation-manifest.json")
                self.assertNotIn("profile_sha256", manifest)
                self.assertIn("source_inspector_sha256", manifest)
                generate.check(root / "tree", root / "reports")

    def test_output_preservation_and_edit_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            input_path = root / "input.json"
            input_path.write_text(generate.json_text(self.data))
            output = root / "output"
            with patch.object(generate, "verify_source", return_value={}):
                generate.generate(input_path, output, source)
                generate.check(output)
                edited = output / "vendor/opendroid/opendroid_demo/BUILD.gn"
                edited.write_text("user edit")
                with self.assertRaises(generate.InputError):
                    generate.check(output)
                with self.assertRaises(generate.InputError):
                    generate.generate(input_path, output, source)
                self.assertEqual(edited.read_text(), "user edit")

    def test_native_build_helper_requires_executable_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            input_path = root / "input.json"
            input_path.write_text(generate.json_text(self.data))
            with patch.object(generate, "verify_source", return_value={}):
                generate.generate(input_path, root / "tree", source, bootstrap_platform=True)
            helper = root / "tree/vendor/opendroid/common/scripts/stage_kernel.py"
            self.assertEqual(helper.stat().st_mode & 0o777, 0o755)
            helper.chmod(0o644)
            with self.assertRaisesRegex(generate.InputError, "not executable"):
                generate.check(root / "tree")

    def test_no_source_checkout_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            input_path = root / "input.json"
            input_path.write_text(generate.json_text(self.data))
            with patch.object(generate, "verify_source", return_value={}):
                with self.assertRaises(generate.InputError):
                    generate.generate(input_path, source / "new-tree", source)
            self.assertEqual(list(source.iterdir()), [])

    def test_native_layout_and_separate_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            output, reports = root / "tree", root / "reports"
            input_path = root / "input.json"
            input_path.write_text(generate.json_text(self.data))
            with patch.object(generate, "verify_source", return_value={}):
                generate.generate(input_path, output, source, reports=reports)
                generate.check(output, reports)
                self.assertEqual({p.name for p in output.iterdir()}, {"device", "vendor"})
                self.assertTrue((reports / "PORTING.md").is_file())
                self.assertTrue((output / "device/board/opendroid/demo_board/config.gni").is_file())
                self.assertFalse((output / "device/soc").exists())
                self.assertFalse((output / "kernel").exists())
                self.assertIn('cfg:native_configs', (output / "device/board/opendroid/demo_board/BUILD.gn").read_text())
                self.assertIn('image_conf:image_configs', (output / "device/board/opendroid/demo_board/BUILD.gn").read_text())
                manifest = generate.read_json(reports / "generation-manifest.json")
                self.assertEqual(manifest["output_scope"], "board-product")
                self.assertTrue(all(path.startswith(("device/board/", "vendor/opendroid/opendroid_demo/"))
                                    for path in manifest["files"]))
                with patch.object(generate, "verify_source", return_value={}):
                    generate.generate(input_path, root / "bootstrap", source, bootstrap_platform=True)
                self.assertEqual({p.name for p in (root / "bootstrap").iterdir()},
                                 {"device", "vendor", "kernel"})
                self.assertTrue((root / "bootstrap/device/soc/generic/generic_arm64/kernel/requirements.json").is_file())
                self.assertTrue((root / "bootstrap/kernel/opendroid/demo_board/BUILD.gn").is_file())
                config = generate.read_json(output / "vendor/opendroid/opendroid_demo/config.json")
                self.assertIn("productdefine/common/inherit/tablet.json", config["inherit"])
                self.assertGreater(config["inherit"].index("vendor/opendroid/common/tablet.json"),
                                   config["inherit"].index("productdefine/common/inherit/tablet.json"))
                self.assertTrue((output / "device/board/opendroid/demo_board/cfg/init.demo_hw.cfg").is_file())
                self.assertFalse((output / "device/board/opendroid/demo_board/BUILD.gn").read_text().endswith("deps = []\n}\n"))
                (reports / "PORTING.md").write_text("owner report edit")
                with self.assertRaises(generate.InputError):
                    generate.check(output, reports)
                with self.assertRaises(generate.InputError):
                    generate.generate(input_path, root / "new-tree", source, reports=reports)
                self.assertEqual((reports / "PORTING.md").read_text(), "owner report edit")

    def test_report_destinations_cannot_nest_or_write_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            output = root / "tree"
            input_path = root / "input.json"
            input_path.write_text(generate.json_text(self.data))
            with patch.object(generate, "verify_source", return_value={}):
                for reports in (output, output / "reports", root, source / "reports"):
                    with self.subTest(reports=reports), self.assertRaises(generate.InputError):
                        generate.generate(input_path, output, source, reports=reports)
            self.assertFalse(output.exists())
            self.assertEqual(list(source.iterdir()), [])

    def test_manifest_cannot_escape_or_follow_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.write_text("content")
            output = root / "output"
            output.mkdir()
            manifest = output / "generation-manifest.json"
            for name in ("../outside", str(outside), "a\\b"):
                manifest.write_text(generate.json_text({"manifest_version": 1, "files": {name: generate.digest(b"content")}}))
                with self.assertRaises(generate.InputError):
                    generate.check(output)
            (output / "link").symlink_to(outside)
            manifest.write_text(generate.json_text({"manifest_version": 1, "files": {"link": generate.digest(b"content")}}))
            with self.assertRaises(generate.InputError):
                generate.check(output)


if __name__ == "__main__":
    unittest.main()
