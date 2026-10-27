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
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate
import source_contracts


class SourceContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        self.data = generate.read_json(Path(__file__).parent / "examples/native-arm64.json")
        self.data["system_profile"] = "base"
        self.selections = [{"subsystems": [{"subsystem": "security", "components": [
            {"component": "selinux_adapter", "features": ["selinux_enabled = true"]}]}]}]
        self.write(self.data["base_product"], {"subsystems": []})
        self.write("build/hb/util/product_util.py", '''
raise RuntimeError("Source code must never execute during inspection")
class ProductUtil:
    def get_products(): pass
    def get_device_info(product_json): pass
    def get_compiler(config_path): pass
''')
        self.write("build/hb/util/preloader/preloader_process_data.py", '''
class Product:
    def _get_device_specific_subsystem(self): pass
    def _get_product_specific_subsystem(self): pass
''')
        self.write("build/hb/util/loader/load_bundle_file.py", '''
class BundlePartObj:
    def to_ohos_build(self): pass
''')
        self.write("build/templates/metadata/gen_module_info.py", '''
def gen_install_dests(system_base_dir, ramdisk_base_dir, vendor_base_dir, updater_base_dir,
                      updater_vendor_base_dir, sys_prod_base_dir, chip_prod_base_dir,
                      eng_system_base_dir, eng_chipset_base_dir, cloud_rom_base_dir,
                      install_images, source_file_name, module_install_dir,
                      relative_install_dir, module_type): pass
''')
        self.write("build/templates/cxx/prebuilt.gni", 'template("ohos_prebuilt_etc") {}\n')
        self.write("build/templates/common/copy.gni", 'template("ohos_copy") {}\n')
        for name in (".gn", "build/ohos.gni", "build/config/BUILDCONFIG.gn",
                     "build/ohos/build_var.gni", "build/ohos/images/mkimage/mkextimage.py"):
            self.write(name, "# fixture\n")
        self.write("base/startup/init/services/init/init_common_cmds.c", '{ "write ", 2, 2, DoWrite },\n')
        self.write("base/startup/init/services/init/standard/init_cmds.c", '{ "insmod ", 1, 2, DoInsmod },\n')
        self.write("base/startup/init/interfaces/innerkits/fs_manager/fstab.c", '''
{ "wait", FS_MANAGER_WAIT }, { "required", FS_MANAGER_REQUIRED }, { "nofail", FS_MANAGER_NOFAIL },
''')
        self.write("build/subsystem_config.json", {"security": {"path": "base/security"}})
        self.write("build/hb/util/loader/subsystem_scan.py", '_default_subsystem = {"build": "build"}\n')
        self.bundle = "base/security/selinux_adapter/bundle.json"
        self.write(self.bundle, {"component": {"subsystem": "security", "name": "selinux_adapter",
                                             "features": ["selinux_enabled"]}})

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)

    def inspect(self):
        return source_contracts.inspect(self.root, self.data, self.selections)

    def test_direct_product_file_does_not_follow_nested_inherit(self):
        files = {
            "base.json": {"inherit": ["nested.json"], "subsystems": [{"subsystem": "a", "components": [{"component": "direct"}]}]},
            "nested.json": {"subsystems": [{"subsystem": "a", "components": [{"component": "nested"}]}]},
        }
        reads, selected = [], {}

        def read(path):
            reads.append(path)
            return json.dumps(files[path])

        def selection(value, label):
            for subsystem in value["subsystems"]:
                for component in subsystem["components"]:
                    selected[(subsystem["subsystem"], component["component"])] = component

        source_contracts._select_product_file("base.json", read, selection)
        self.assertEqual(reads, ["base.json"])
        self.assertIn(("a", "direct"), selected)
        self.assertNotIn(("a", "nested"), selected)

    def test_common_default_rejects_unmanaged_assignment_but_explicit_choice_preserves_it(self):
        catalog = {"trace": {"subsystem": "hiviewdfx", "component": "hitrace",
                             "feature": "trace_enabled", "default": False}}
        upstream = {("hiviewdfx", "hitrace"): {
            "component": "hitrace", "features": ["trace_enabled = false", "local_diagnostic = true",
                                                    "local_count = 7", 'local_name = "native"']}}
        with self.assertRaisesRegex(source_contracts.ContractError, "local_diagnostic.*explicit product_features"):
            source_contracts._product_feature_components(upstream, catalog, {})
        result = source_contracts._product_feature_components(upstream, catalog, {"trace": True})
        self.assertEqual(result[0]["components"][0]["features"],
                         ['local_count = 7', 'local_diagnostic = true', 'local_name = "native"',
                          "trace_enabled = true"])

    def test_common_default_rejects_inherited_metadata_but_explicit_choice_preserves_it(self):
        catalog = {"trace": {"subsystem": "hiviewdfx", "component": "hitrace",
                             "feature": "trace_enabled", "default": False}}
        upstream = {("hiviewdfx", "hitrace"): {
            "component": "hitrace", "features": ["trace_enabled = false"],
            "syscap": ["SystemCapability.HiviewDFX.HiTrace"],
            "exclusions": ["module = diagnostic_stub"],
        }}
        with self.assertRaisesRegex(source_contracts.ContractError, "exclusions.*syscap.*explicit product_features"):
            source_contracts._product_feature_components(upstream, catalog, {})
        component = source_contracts._product_feature_components(
            upstream, catalog, {"trace": True})[0]["components"][0]
        self.assertEqual(component["syscap"], upstream[("hiviewdfx", "hitrace")]["syscap"])
        self.assertEqual(component["exclusions"], upstream[("hiviewdfx", "hitrace")]["exclusions"])

    def test_catalog_component_must_exist_before_common_defaults(self):
        catalog = {"trace": {"subsystem": "hiviewdfx", "component": "hitrace",
                             "feature": "trace_enabled", "default": False}}
        with self.assertRaisesRegex(source_contracts.ContractError, "not selected by the upstream profile"):
            source_contracts._product_feature_components({}, catalog, {"trace": True})

    def test_comments_and_unrelated_edits_change_evidence_without_blocking_generation(self):
        before = self.inspect()
        path = "build/templates/cxx/prebuilt.gni"
        self.write(path, '# an upstream comment\n\ntemplate ( "ohos_prebuilt_etc" ) { unrelated = true }\n')
        after = self.inspect()
        self.assertNotEqual(before["files_sha256"][path], after["files_sha256"][path])
        self.assertEqual(before["components"], after["components"])

    def test_missing_template_fails_before_creating_output(self):
        self.write("build/templates/cxx/prebuilt.gni", '# template("ohos_prebuilt_etc") {}\n')
        input_path = Path(self.temporary.name) / "input.json"
        input_path.write_text(generate.json_text(self.data))
        output = Path(self.temporary.name) / "tree"
        with patch.dict(generate.product_features.CATALOG, {}, clear=True):
            with self.assertRaisesRegex(generate.InputError, "GN template is absent"):
                generate.generate(input_path, output, self.root)
        self.assertFalse(output.exists())
        self.assertFalse(output.with_name("tree-reports").exists())

    def test_python_interface_rename_and_parameter_change_are_rejected(self):
        path = "build/hb/util/product_util.py"
        original = (self.root / path).read_text()
        for old, new in (("get_device_info", "get_board_info"), ("product_json", "product_path")):
            with self.subTest(new=new):
                self.write(path, original.replace(old, new))
                with self.assertRaisesRegex(source_contracts.ContractError, "interface is absent|parameters changed"):
                    self.inspect()

    def test_selected_component_and_feature_changes_fail(self):
        original = json.loads((self.root / self.bundle).read_text())
        for key, value in (("name", "other_component"), ("features", [])):
            with self.subTest(key=key):
                altered = copy.deepcopy(original)
                altered["component"][key] = value
                self.write(self.bundle, altered)
                with self.assertRaisesRegex(source_contracts.ContractError, "component is absent|feature is absent"):
                    self.inspect()

    def test_new_required_python_argument_fails_but_optional_argument_is_allowed(self):
        path = "build/hb/util/product_util.py"
        original = (self.root / path).read_text()
        self.write(path, original.replace("get_products()", "get_products(extra=None)"))
        self.inspect()
        self.write(path, original.replace("get_products()", "get_products(extra)"))
        with self.assertRaisesRegex(source_contracts.ContractError, "New required parameters"):
            self.inspect()

    def test_duplicate_selected_component_is_ambiguous(self):
        self.write("base/security/duplicate/bundle.json", json.loads((self.root / self.bundle).read_text()))
        with self.assertRaisesRegex(source_contracts.ContractError, "component is ambiguous"):
            self.inspect()

    def test_upstream_duplicate_feature_keys_use_native_json_semantics(self):
        self.write(self.bundle, '{"component":{"subsystem":"security", "name":"selinux_adapter",'
                               '"features":[], "features":["selinux_enabled"]}}')
        self.assertEqual(self.inspect()["components"][0]["component"], "selinux_adapter")

    def test_native_component_alias_records_actual_subsystem(self):
        self.selections[0]["subsystems"].append({"subsystem": "wukong", "components": [{"component": "wukong"}]})
        self.write("build/subsystem_config.json", {"security": {"path": "base/security"},
                                                   "ostest": {"path": "test/ostest"}})
        self.write("test/ostest/wukong/bundle.json", {"component": {"subsystem": "ostest", "name": "wukong"}})
        result = next(item for item in self.inspect()["components"] if item["component"] == "wukong")
        self.assertEqual(result["subsystem"], "wukong")
        self.assertEqual(result["declared_subsystem"], "ostest")

    def test_nested_source_inherit_entries_are_not_recursed(self):
        self.write("productdefine/common/nested.json", {"subsystems": [{
            "subsystem": "security", "components": [{"component": "nested_only"}]}]})
        self.write(self.data["base_product"], {"inherit": ["productdefine/common/nested.json"], "subsystems": []})
        self.assertEqual([entry["component"] for entry in self.inspect()["components"]], ["selinux_adapter"])

    def test_excluded_component_is_not_required(self):
        self.write(self.data["base_product"], {"subsystems": [{"subsystem": "security", "components": [
            {"component": "absent_component"}]}]})
        self.selections[0]["subsystems"][0]["components"].append({"component": "absent_component", "exclude": "true"})
        self.assertEqual([entry["component"] for entry in self.inspect()["components"]], ["selinux_adapter"])

    def test_source_links_cannot_read_outside_checkout(self):
        path = self.root / "build/templates/cxx/prebuilt.gni"
        outside = Path(self.temporary.name) / "outside.gni"
        outside.write_text(path.read_text())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(source_contracts.ContractError, "outside the checkout"):
            self.inspect()

    def test_native_configuration_requires_registered_commands_and_flags(self):
        for path in ("base/startup/init/services/init/init_common_cmds.c",
                     "base/startup/init/services/init/standard/init_cmds.c",
                     "base/startup/init/interfaces/innerkits/fs_manager/fstab.c"):
            with self.subTest(path=path):
                original = (self.root / path).read_text()
                self.write(path, "/* " + original + " */")
                with self.assertRaisesRegex(source_contracts.ContractError, "command is absent|flag is absent"):
                    self.inspect()
                self.write(path, original)

    def test_malformed_unselected_bundle_is_reported(self):
        self.write("base/security/unrelated/bundle.json", {"component": {"name": []}})
        result = self.inspect()
        self.assertEqual(result["unreadable_registry_entries"][0]["error"], "Invalid component identity")


if __name__ == "__main__":
    unittest.main()
