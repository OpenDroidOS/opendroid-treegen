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
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runtime import stage_kernel


class KernelStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "private"
        self.inputs.mkdir()
        self.output = self.root / "out/kernel"
        self.manifest_path = self.inputs / "selection.json"
        self.requirements_path = self.root / "requirements.json"
        self.data = {"format_version": 1, "state": "selected", "files": []}
        payloads = {"Image": ("kernel", b"host fixture, never executed\n", "kernel/Image"),
                    "kernel.config": ("config", b"CONFIG_ARM64=y\nCONFIG_EXT4_FS=m\n# CONFIG_OTHER is not set\n", "config/kernel.config"),
                    "test.ko": ("module", b"fixture module", "modules/test.ko"),
                    "test.dtb": ("dtb", b"fixture dtb", "dtbs/test.dtb"),
                    "test.dtbo": ("dtbo", b"fixture dtbo", "dtbo/test.dtbo")}
        for name, (role, content, destination) in payloads.items():
            (self.inputs / name).write_bytes(content)
            self.data["files"].append({"role": role, "path": name,
                                       "sha256": hashlib.sha256(content).hexdigest(),
                                       "destination": destination})
        self.requirements = {"format_version": 1, "required_options": {
            "CONFIG_ARM64": ["y"], "CONFIG_EXT4_FS": ["y", "m"]},
            "scope": "host fixture", "module_values": "ABI still requires validation"}
        self.write_inputs()

    def write_inputs(self):
        self.manifest_path.write_text(json.dumps(self.data))
        self.requirements_path.write_text(json.dumps(self.requirements))

    def stage(self):
        return stage_kernel.stage(self.manifest_path, self.requirements_path, self.output)

    def assert_failure(self, message=None):
        with self.assertRaises(stage_kernel.StageError) as error:
            self.stage()
        if message:
            self.assertIn(message, str(error.exception))
        self.assertFalse(self.output.exists())

    def test_selected_files_stage_and_repeat_without_changes(self):
        originals = {p.name: p.read_bytes() for p in self.inputs.iterdir()}
        report = self.stage()
        report_path = self.output / "stage-report.json"
        self.assertEqual(report, json.loads(report_path.read_text()))
        self.assertEqual(report["configuration"]["observed_options"]["CONFIG_EXT4_FS"], "m")
        before = {p.relative_to(self.output).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(self.stage(), report)
        after = {p.relative_to(self.output).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
                 for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(originals, {p.name: p.read_bytes() for p in self.inputs.iterdir()})
        self.assertEqual((self.output / "kernel/Image").read_bytes(), (self.inputs / "Image").read_bytes())

    def test_unselected_empty_and_missing_required_roles(self):
        original = copy.deepcopy(self.data)
        for state, entries in (("unselected", []), ("selected", []),
                               ("selected", [item for item in original["files"] if item["role"] != "config"]),
                               ("selected", [item for item in original["files"] if item["role"] != "kernel"])):
            with self.subTest(state=state, count=len(entries)):
                self.data.update(state=state, files=entries)
                self.write_inputs()
                self.assert_failure()

    def test_changed_hash_and_empty_file(self):
        (self.inputs / "Image").write_bytes(b"changed")
        self.assert_failure("SHA256 mismatch")
        (self.inputs / "Image").write_bytes(b"")
        self.data["files"][0]["sha256"] = hashlib.sha256(b"").hexdigest()
        self.write_inputs()
        self.assert_failure("empty")

    def test_missing_and_disabled_configuration_requirements(self):
        self.requirements["required_options"].update(CONFIG_MISSING=["y"], CONFIG_OTHER=["y"])
        self.write_inputs()
        with self.assertRaises(stage_kernel.StageError) as error:
            self.stage()
        self.assertIn("CONFIG_MISSING: expected y, observed missing", str(error.exception))
        self.assertIn("CONFIG_OTHER: expected y, observed n", str(error.exception))
        self.assertFalse(self.output.exists())

    def test_invalid_requirements(self):
        invalid = ({}, {"ARM64": ["y"]}, {"CONFIG_ARM64": "y"},
                   {"CONFIG_ARM64": ["yes"]}, {"CONFIG_ARM64": ["y", "y"]},
                   {"CONFIG_ARM64": [True]}, {"CONFIG_ARM64": []})
        for options in invalid:
            with self.subTest(options=options):
                self.requirements["required_options"] = options
                self.write_inputs()
                self.assert_failure()

    def test_board_requirements_narrow_shared_values_and_stage_disabled_options(self):
        overlay = self.root / "board.json"
        overlay.write_text(json.dumps({"format_version": 1, "required_options": {
            "CONFIG_EXT4_FS": ["y"], "CONFIG_OTHER": ["n"], "CONFIG_ARM64": ["y", "m"]}}))
        merged, descriptors = stage_kernel.load_requirements(self.requirements_path, [overlay])
        self.assertEqual(merged["CONFIG_ARM64"], ["y"])
        self.assertEqual(merged["CONFIG_EXT4_FS"], ["y"])
        with self.assertRaisesRegex(stage_kernel.StageError, "CONFIG_EXT4_FS: expected y, observed m"):
            stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                               additional_requirements=[overlay])
        self.assertFalse(self.output.exists())
        config = self.inputs / "kernel.config"
        config.write_bytes(config.read_bytes().replace(b"CONFIG_EXT4_FS=m", b"CONFIG_EXT4_FS=y"))
        self.data["files"][1]["sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
        self.write_inputs()
        report = stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                    additional_requirements=[overlay])
        self.assertEqual(report["configuration"]["observed_options"]["CONFIG_OTHER"], "n")
        self.assertEqual(report["additional_requirements_sha256"], [descriptors[1][1]])

    def test_board_descriptor_changes_identity_and_cannot_reuse_prior_stage(self):
        overlay = self.root / "board.json"
        requirements = {"format_version": 1, "required_options": {"CONFIG_OTHER": ["n"]}}
        overlay.write_text(json.dumps(requirements))
        first = stage_kernel.describe(self.manifest_path, self.requirements_path,
                                      additional_requirements=[overlay])
        stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                           additional_requirements=[overlay])
        before = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob("*") if p.is_file()}
        requirements["scope"] = "same constraints, new descriptor identity"
        overlay.write_text(json.dumps(requirements))
        second = stage_kernel.describe(self.manifest_path, self.requirements_path,
                                       additional_requirements=[overlay])
        self.assertNotEqual(first["id"], second["id"])
        with self.assertRaisesRegex(stage_kernel.StageError, "another selection"):
            stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                               additional_requirements=[overlay])
        self.assertEqual(before, {str(p.relative_to(self.output)): p.read_bytes()
                                  for p in self.output.rglob("*") if p.is_file()})

    def test_board_requirements_reject_conflicts_duplicates_links_and_bad_shapes(self):
        overlay = self.root / "board.json"
        overlay.write_text(json.dumps({"format_version": 1, "required_options": {"CONFIG_ARM64": ["m"]}}))
        with self.assertRaisesRegex(stage_kernel.StageError, "Conflicting"):
            stage_kernel.load_requirements(self.requirements_path, [overlay])
        with self.assertRaisesRegex(stage_kernel.StageError, "Duplicate"):
            stage_kernel.load_requirements(self.requirements_path, [self.requirements_path])
        link = self.root / "link.json"
        link.symlink_to(overlay)
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.load_requirements(self.requirements_path, [link])
        for value in ([], None, {"format_version": 1, "required_options": {"CONFIG_ARM64": [False]}}):
            overlay.write_text(json.dumps(value))
            with self.assertRaises(stage_kernel.StageError):
                stage_kernel.load_requirements(self.requirements_path, [overlay])
        self.assertFalse(self.output.exists())

    def test_disabled_requirement_needs_explicit_disabled_config_line(self):
        for raw in (b"CONFIG_OTHER=y\n", b"CONFIG_ARM64=y\n"):
            with self.assertRaises(stage_kernel.StageError):
                stage_kernel._configuration(raw, {"CONFIG_OTHER": ["n"]})
        self.assertEqual(stage_kernel._configuration(b"# CONFIG_OTHER is not set\n", {"CONFIG_OTHER": ["n"]}),
                         {"CONFIG_OTHER": "n"})

    def test_additional_requirements_cli_applies_to_describe_and_staging(self):
        overlay = self.root / "board.json"
        overlay.write_text(json.dumps({"format_version": 1, "required_options": {"CONFIG_OTHER": ["n"]}}))
        args = ["--manifest", str(self.manifest_path), "--requirements", str(self.requirements_path),
                "--additional-requirements", str(overlay)]
        with patch("sys.stdout", io.StringIO()) as captured:
            self.assertEqual(stage_kernel.main(args + ["--describe"]), 0)
        expected = stage_kernel.describe(self.manifest_path, self.requirements_path,
                                          additional_requirements=[overlay])
        self.assertEqual(json.loads(captured.getvalue()), expected)
        with patch("sys.stdout", io.StringIO()) as captured:
            self.assertEqual(stage_kernel.main(args + ["--output", str(self.output)]), 0)
        self.assertEqual(json.loads(captured.getvalue())["configuration"]["observed_options"]["CONFIG_OTHER"], "n")

    def test_board_descriptor_race_stops_before_publication(self):
        overlay = self.root / "board.json"
        overlay.write_text(json.dumps({"format_version": 1, "required_options": {"CONFIG_OTHER": ["n"]}}))
        original = stage_kernel._hash_file
        def change_after_copy(path, copy_to=None):
            result = original(path, copy_to)
            if copy_to is not None:
                overlay.write_text(json.dumps({"format_version": 1, "required_options": {"CONFIG_OTHER": ["y"]}}))
            return result
        with patch.object(stage_kernel, "_hash_file", side_effect=change_after_copy):
            with self.assertRaisesRegex(stage_kernel.StageError, "descriptor changed"):
                stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                   additional_requirements=[overlay])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.iterdir()), [])

    def test_lowercase_kconfig_symbols_are_valid_but_malformed_keys_are_rejected(self):
        config = self.inputs / "kernel.config"
        config.write_bytes(config.read_bytes() + b"CONFIG_FONT_8x16=y\n# CONFIG_lowercase_disabled is not set\n")
        self.data["files"][1]["sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
        self.requirements["required_options"]["CONFIG_FONT_8x16"] = ["y"]
        self.write_inputs()
        report = self.stage()
        self.assertEqual(report["configuration"]["observed_options"]["CONFIG_FONT_8x16"], "y")
        with self.assertRaises(stage_kernel.StageError) as error:
            stage_kernel._configuration(config.read_bytes(), {"CONFIG_lowercase_disabled": ["y"]})
        self.assertIn("observed n", str(error.exception))
        for malformed in ("CONFIG_BAD-NAME", "CONFIG_bad name", "CONFIG_", "badCONFIG_name"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(stage_kernel.StageError):
                    stage_kernel._requirements({"format_version": 1, "required_options": {malformed: ["y"]}})
                with self.assertRaises(stage_kernel.StageError):
                    stage_kernel._configuration((malformed + "=y\n").encode(), {"CONFIG_ARM64": ["y"]})

    def test_unsafe_source_and_destination_paths(self):
        for field in ("path", "destination"):
            for value in ("../escape", "/absolute", "a/../b", "a//b", "./Image", "a\\b", "a\nb"):
                with self.subTest(field=field, value=value):
                    original = self.data["files"][0][field]
                    self.data["files"][0][field] = value
                    self.write_inputs()
                    self.assert_failure()
                    self.data["files"][0][field] = original

    def test_destination_collisions_and_reserved_report(self):
        for destination in ("kernel/Image", "kernel", "kernel/Image/subfile", "stage-report.json", "stage-report.json/x"):
            with self.subTest(destination=destination):
                self.data["files"][1]["destination"] = destination
                self.write_inputs()
                self.assert_failure()

    def test_symlink_source_descriptor_and_parent_are_rejected(self):
        original = self.inputs / "Image"
        outside = self.root / "original"
        original.rename(outside)
        original.symlink_to(outside)
        self.assert_failure()
        original.unlink()
        outside.rename(original)
        link = self.root / "link-private"
        link.symlink_to(self.inputs, target_is_directory=True)
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.stage(link / "selection.json", self.requirements_path, self.output)
        descriptor = self.inputs / "descriptor.json"
        self.manifest_path.rename(descriptor)
        self.manifest_path.symlink_to(descriptor)
        self.assert_failure()

    def test_source_directory_and_fifo_are_not_regular_files(self):
        original = self.inputs / "Image"
        original.unlink()
        original.mkdir()
        self.assert_failure("ordinary file")
        original.rmdir()
        import os
        os.mkfifo(original)
        self.assert_failure("ordinary file")

    def test_output_cannot_be_inside_inputs_or_use_symlink_parent(self):
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.stage(self.manifest_path, self.requirements_path, self.inputs / "staged")
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.stage(self.manifest_path, self.requirements_path, link / "staged")
        self.assertEqual(list(real.iterdir()), [])

    def test_existing_edits_extra_files_and_empty_outputs_preserved(self):
        self.output.mkdir(parents=True)
        with self.assertRaises(stage_kernel.StageError):
            self.stage()
        self.assertEqual(list(self.output.iterdir()), [])
        self.output.rmdir()
        self.stage()
        image = self.output / "kernel/Image"
        image.write_bytes(b"user edit")
        with self.assertRaises(stage_kernel.StageError):
            self.stage()
        self.assertEqual(image.read_bytes(), b"user edit")
        image.write_bytes((self.inputs / "Image").read_bytes())
        extra = self.output / "user.txt"
        extra.write_text("preserve me")
        with self.assertRaises(stage_kernel.StageError):
            self.stage()
        self.assertEqual(extra.read_text(), "preserve me")

    def test_duplicate_json_keys_and_strict_versions(self):
        self.manifest_path.write_text('{"format_version":1,"format_version":1}')
        self.assert_failure("Duplicate JSON key")
        self.data["format_version"] = True
        self.write_inputs()
        self.assert_failure("integer 1")

    def test_source_change_during_copy_cleans_temporary_output(self):
        original = stage_kernel._hash_file
        def change_before_copy(path, copy_to=None):
            if copy_to is not None and path.name == "Image":
                path.write_bytes(b"changed after initial verification")
            return original(path, copy_to)
        with patch.object(stage_kernel, "_hash_file", side_effect=change_before_copy):
            self.assert_failure("changed during staging")
        self.assertEqual(list(self.output.parent.iterdir()), [])

    def test_publication_race_never_replaces_existing_directory(self):
        original = stage_kernel._publish
        def concurrent_directory(temporary, output):
            output.mkdir()
            (output / "concurrent.txt").write_text("preserve concurrent work")
            original(temporary, output)
        with patch.object(stage_kernel, "_publish", side_effect=concurrent_directory):
            with self.assertRaises(stage_kernel.StageError) as error:
                self.stage()
        self.assertIn("without replacement", str(error.exception))
        self.assertEqual((self.output / "concurrent.txt").read_text(), "preserve concurrent work")
        self.assertEqual(sorted(p.name for p in self.output.parent.iterdir()), ["kernel"])

    def test_describe_is_deterministic_descriptor_only_and_tracks_both_hashes(self):
        for payload in self.inputs.iterdir():
            if payload != self.manifest_path:
                payload.unlink()
        before = {p.relative_to(self.root).as_posix(): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file()}
        first = stage_kernel.describe(self.manifest_path, self.requirements_path)
        self.assertEqual(first, stage_kernel.describe(self.manifest_path, self.requirements_path))
        manifest_hash = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        requirements_hash = hashlib.sha256(self.requirements_path.read_bytes()).hexdigest()
        self.assertEqual(first["id"], hashlib.sha256((manifest_hash + requirements_hash).encode("ascii")).hexdigest())
        self.assertEqual(first["files"], self.data["files"])
        self.assertEqual(before, {p.relative_to(self.root).as_posix(): p.read_bytes()
                                  for p in self.root.rglob("*") if p.is_file()})
        self.assertFalse(self.output.parent.exists())
        self.requirements["scope"] = "changed descriptor"
        self.write_inputs()
        second = stage_kernel.describe(self.manifest_path, self.requirements_path)
        self.assertNotEqual(first["id"], second["id"])
        self.data["files"][0]["destination"] = "kernel/other-Image"
        self.write_inputs()
        third = stage_kernel.describe(self.manifest_path, self.requirements_path)
        self.assertNotEqual(second["id"], third["id"])

    def test_describe_rejects_unselected_unsafe_and_bad_requirements_without_writes(self):
        self.data["state"] = "unselected"
        self.write_inputs()
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.describe(self.manifest_path, self.requirements_path)
        self.data["state"] = "selected"
        self.data["files"][0]["path"] = "../escape"
        self.write_inputs()
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.describe(self.manifest_path, self.requirements_path)
        self.data["files"][0]["path"] = "Image"
        self.requirements["required_options"] = {"CONFIG_ARM64": ["invalid"]}
        self.write_inputs()
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.describe(self.manifest_path, self.requirements_path)
        self.assertFalse(self.output.parent.exists())

    def test_describe_cli_needs_no_output_and_prints_json(self):
        capture = io.StringIO()
        with patch("sys.stdout", capture):
            status = stage_kernel.main(["--manifest", str(self.manifest_path),
                                        "--requirements", str(self.requirements_path), "--describe"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(capture.getvalue()), stage_kernel.describe(self.manifest_path, self.requirements_path))
        self.assertFalse(self.output.parent.exists())

    def test_load_order_must_bind_only_selected_modules_and_preserve_order(self):
        order_path = self.root / "module-order.json"
        destination = next(item["destination"] for item in self.data["files"] if item["role"] == "module")
        for order in ([destination], []):
            order_path.write_text(json.dumps({"format_version": 1, "modules": order}))
            result = stage_kernel.describe(self.manifest_path, self.requirements_path, order_path)
            self.assertEqual(result["module_load_order"], order)
        kernel = next(item["destination"] for item in self.data["files"] if item["role"] == "kernel")
        for order in ([kernel], ["missing.ko"], [destination, destination], ["../escape.ko"], [True]):
            order_path.write_text(json.dumps({"format_version": 1, "modules": order}))
            with self.subTest(order=order), self.assertRaises(stage_kernel.StageError):
                stage_kernel.describe(self.manifest_path, self.requirements_path, order_path)
        self.assertFalse(self.output.parent.exists())

    def test_opt_in_build_precreated_empty_output_stages_and_repeats(self):
        self.output.mkdir(parents=True)
        report = stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                    allow_empty_output=True)
        self.assertEqual(report, json.loads((self.output / "stage-report.json").read_text()))
        self.assertEqual(report, stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                                   allow_empty_output=True))

    def test_opt_in_nested_expected_empty_parents_stage_successfully(self):
        self.data["files"][2]["destination"] = "modules/vendor/subdir/test.ko"
        self.write_inputs()
        for item in self.data["files"]:
            (self.output / item["destination"]).parent.mkdir(parents=True, exist_ok=True)
        stage_kernel.stage(self.manifest_path, self.requirements_path, self.output, allow_empty_output=True)
        self.assertEqual((self.output / "modules/vendor/subdir/test.ko").read_bytes(), b"fixture module")
        self.assertTrue((self.output / "stage-report.json").is_file())

    def test_opt_in_racing_contents_or_subdirectories_are_preserved(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                self.output.mkdir(parents=True, exist_ok=True)
                original = stage_kernel._hash_file
                def populate_during_copy(path, copy_to=None):
                    if copy_to is not None and path.name == "Image":
                        if kind == "file":
                            (self.output / "user.txt").write_text("preserve user content")
                        else:
                            (self.output / "empty-user-directory").mkdir()
                    return original(path, copy_to)
                with patch.object(stage_kernel, "_hash_file", side_effect=populate_during_copy):
                    with self.assertRaises(stage_kernel.StageError) as error:
                        stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                           allow_empty_output=True)
                self.assertIn("no longer empty" if kind == "file" else "Unmanaged", str(error.exception))
                self.assertFalse((self.output / "stage-report.json").exists())
                if kind == "file":
                    self.assertEqual((self.output / "user.txt").read_text(), "preserve user content")
                    (self.output / "user.txt").unlink()
                else:
                    self.assertTrue((self.output / "empty-user-directory").is_dir())
                    (self.output / "empty-user-directory").rmdir()

    def test_opt_in_publish_failure_restores_original_empty_directory(self):
        self.output.mkdir(parents=True)
        with patch.object(stage_kernel, "_publish", side_effect=stage_kernel.StageError("fixture publication failure")):
            with self.assertRaises(stage_kernel.StageError):
                stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                   allow_empty_output=True)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])

    def test_opt_in_nested_empty_hierarchy_restored_after_publish_failure(self):
        for item in self.data["files"]:
            (self.output / item["destination"]).parent.mkdir(parents=True, exist_ok=True)
        before = sorted(p.relative_to(self.output).as_posix() for p in self.output.rglob("*"))
        with patch.object(stage_kernel, "_publish", side_effect=stage_kernel.StageError("fixture publication failure")):
            with self.assertRaises(stage_kernel.StageError):
                stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                   allow_empty_output=True)
        self.assertEqual(before, sorted(p.relative_to(self.output).as_posix() for p in self.output.rglob("*")))
        self.assertTrue(all(p.is_dir() for p in self.output.rglob("*")))

    def test_opt_in_content_added_during_directory_removal_is_preserved(self):
        for item in self.data["files"]:
            (self.output / item["destination"]).parent.mkdir(parents=True, exist_ok=True)
        original = stage_kernel.os.rmdir
        def populate_before_removal(path, *args, **kwargs):
            if Path(path) == self.output / "kernel":
                (self.output / "config/user.txt").write_text("concurrent content")
            return original(path, *args, **kwargs)
        with patch.object(stage_kernel.os, "rmdir", side_effect=populate_before_removal):
            with self.assertRaises(stage_kernel.StageError):
                stage_kernel.stage(self.manifest_path, self.requirements_path, self.output,
                                   allow_empty_output=True)
        self.assertEqual((self.output / "config/user.txt").read_text(), "concurrent content")
        self.assertFalse((self.output / "stage-report.json").exists())
        for item in self.data["files"]:
            self.assertTrue((self.output / item["destination"]).parent.is_dir())

    def test_opt_in_rejects_nonempty_and_symlink_output(self):
        self.output.mkdir(parents=True)
        (self.output / "empty-directory").mkdir()
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.stage(self.manifest_path, self.requirements_path, self.output, allow_empty_output=True)
        self.assertTrue((self.output / "empty-directory").is_dir())
        (self.output / "empty-directory").rmdir()
        self.output.rmdir()
        real = self.root / "real-empty"
        real.mkdir()
        self.output.symlink_to(real, target_is_directory=True)
        with self.assertRaises(stage_kernel.StageError):
            stage_kernel.stage(self.manifest_path, self.requirements_path, self.output, allow_empty_output=True)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(list(real.iterdir()), [])

    def test_opt_in_cli_stages_precreated_empty_directory(self):
        self.output.mkdir(parents=True)
        with patch("sys.stdout", io.StringIO()):
            status = stage_kernel.main(["--manifest", str(self.manifest_path),
                                        "--requirements", str(self.requirements_path),
                                        "--output", str(self.output), "--allow-empty-output"])
        self.assertEqual(status, 0)
        self.assertTrue((self.output / "stage-report.json").is_file())


if __name__ == "__main__":
    unittest.main()
