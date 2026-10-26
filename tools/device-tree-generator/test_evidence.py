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
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

import evidence
import generate


def fdt(identity=False):
    body = struct.pack(">I", 1) + b"\0" * 4
    names = b"compatible\0"
    if identity:
        value = b"test,board\0"
        body += struct.pack(">3I", 3, len(value), 0) + value
        body += b"\0" * (-len(body) % 4)
    body += struct.pack(">2I", 2, 9)
    total = 56 + len(body) + len(names)
    return struct.pack(">10I", 0xD00DFEED, total, 56, 56 + len(body), 40, 17, 16,
                       0, len(names), len(body)) + b"\0" * 16 + body + names


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.capture = self.root / "capture"
        self.capture.mkdir()
        self.report = {
            "report_format_version": 1, "kind": "opendroid-prebuilt-extraction-evidence",
            "extractor_sha256": "a" * 64, "inspector_sha256": "b" * 64,
            "inputs": [{"label": "boot", "state": "extracted", "path": "/private/original/boot.img",
                        "sha256": "c" * 64, "bytes": 123}],
            "artifacts": [], "summary": {"artifacts": 999999, "all_requested_inputs_extracted": True},
        }

    def write(self):
        path = self.capture / "extraction-report.json"
        path.write_text(json.dumps(self.report))
        return path

    def add_artifact(self, name="boot/kernel", kind="kernel-payload", content=b"kernel", source=None):
        path = self.capture / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        item = {"path": name, "kind": kind, "bytes": len(content), "sha256": generate.digest(content),
                "source": source or {"input": "boot", "offset": 4096}}
        self.report["artifacts"].append(item)
        return item

    def add_module(self, name="modules/test.ko", provider="test", release="6.6.test", content=b"module", depends=""):
        artifact = self.add_artifact(name, "kernel-module", content)
        module = {**{k: artifact[k] for k in ("path", "sha256", "bytes")}, "root": "extracted", "state": "observed",
                  "metadata": {"name": [provider], "vermagic": [release + " SMP aarch64"], "depends": [depends]}}
        self.report.setdefault("module_observations", {"modules": []})["modules"].append(module)
        return module

    def load(self):
        self.write()
        return evidence.load_extractions([self.capture])

    def test_report_identity_and_recomputed_counts(self):
        self.add_artifact()
        result = self.load()
        self.assertEqual(result["summary"]["artifacts"], 1)
        self.assertEqual(result["reports"][0]["report_sha256"], generate.digest(self.write().read_bytes()))
        self.assertEqual(result["selection"]["state"], "unselected")
        self.assertNotIn("/private/", json.dumps(result))
        self.assertEqual(result, evidence.load_extractions([self.write()]))

    def test_artifact_bytes_and_size_must_match(self):
        artifact = self.add_artifact()
        original = copy.deepcopy(artifact)
        for key, value in (("sha256", "0" * 64), ("bytes", 99), ("bytes", True)):
            artifact.update(original)
            artifact[key] = value
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError):
                self.load()

    def test_paths_cannot_escape_or_use_aliases(self):
        artifact = self.add_artifact()
        for name in ("../outside", "/etc/passwd", "boot/../kernel", "boot//kernel", "./boot/kernel", "a\\b", "a\0b", "."):
            artifact["path"] = name
            with self.subTest(name=name), self.assertRaises(evidence.EvidenceError):
                self.load()

    def test_symlink_artifact_and_parent_rejected(self):
        artifact = self.add_artifact()
        path = self.capture / artifact["path"]
        outside = self.root / "outside"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(evidence.EvidenceError):
            self.load()
        path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(evidence.EvidenceError):
            self.load()

    def test_symlink_report_and_capture_rejected(self):
        path = self.write()
        alias = self.root / "alias.json"
        alias.symlink_to(path)
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_extractions([alias])
        alias_dir = self.root / "alias"
        alias_dir.symlink_to(self.capture, target_is_directory=True)
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_extractions([alias_dir])

    def test_directory_substitution_cannot_redirect_artifact_read(self):
        self.add_artifact()
        self.write()
        external = self.root / "external"
        external.mkdir()
        (external / "kernel").write_bytes(b"kernel")
        original_open = os.open

        def substitute(name, flags, *args, **kwargs):
            if name == "boot":
                (self.capture / "boot").rename(self.capture / "saved")
                (self.capture / "boot").symlink_to(external, target_is_directory=True)
            return original_open(name, flags, *args, **kwargs)

        with patch.object(evidence.os, "open", side_effect=substitute), self.assertRaises(evidence.EvidenceError):
            evidence.load_extractions([self.capture])

    def test_special_file_rejected(self):
        artifact = self.add_artifact()
        path = self.capture / artifact["path"]
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(evidence.EvidenceError):
            self.load()

    def test_schema_duplicate_json_and_read_limit(self):
        path = self.write()
        for content in ('{"a":1,"a":2}', '{"a":NaN}', '[]', '{"report_format_version":true}'):
            path.write_text(content)
            with self.subTest(content=content), self.assertRaises(evidence.EvidenceError):
                evidence.load_extractions([path])
        self.write()
        with patch.object(evidence, "MAX_REPORT", 10), self.assertRaises(evidence.EvidenceError):
            evidence.load_extractions([path])

    def test_unsupported_report_and_duplicate_records(self):
        self.add_artifact()
        original = copy.deepcopy(self.report)
        mutations = (
            lambda d: d.update(report_format_version=2),
            lambda d: d.update(kind="other"),
            lambda d: d["inputs"].append(copy.deepcopy(d["inputs"][0])),
            lambda d: d["artifacts"].append(copy.deepcopy(d["artifacts"][0])),
            lambda d: d["artifacts"][0]["source"].update(input="unknown"),
        )
        for mutate in mutations:
            self.report = copy.deepcopy(original)
            mutate(self.report)
            with self.subTest(mutate=mutate), self.assertRaises(evidence.EvidenceError):
                self.load()

    def test_partial_evidence_preserves_required_content(self):
        self.report["inputs"][0].update(state="partial", limitations=["missing kernel at /private/path"],
            directory={"required_content": [{"component": "kernel", "state": "missing"}]},
            boot_layout={"header_version": 4, "page_bytes": 4096})
        result = self.load()
        record = result["reports"][0]
        self.assertFalse(record["all_requested_inputs_extracted"])
        self.assertEqual(record["inputs"][0]["required_content"][0]["state"], "missing")
        self.assertEqual(record["inputs"][0]["reported_boot_layout"], {"header_version": 4, "page_bytes": 4096})
        self.assertIn("incomplete-extraction", {w["id"] for w in result["warnings"]})
        self.assertNotIn("/private/", json.dumps(result))

    def test_module_observations_must_link_exact_artifact(self):
        module = self.add_module()
        original = copy.deepcopy(module)
        for key, value in (("root", "other"), ("path", "unknown.ko"), ("sha256", "0" * 64), ("bytes", 1)):
            module.update(original)
            module[key] = value
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError):
                self.load()

    def test_failed_or_missing_module_metadata_stays_unknown(self):
        module = self.add_module()
        module.update(state="inspection-failed")
        module.pop("metadata")
        self.add_artifact("modules/other.ko", "kernel-module", b"other")
        result = self.load()
        self.assertEqual(result["reports"][0]["modules"]["metadata_unknown"], 2)
        self.assertEqual(result["summary"]["module_release_string_populations"], {})

    def test_mixed_releases_do_not_select_or_claim_abi(self):
        self.add_artifact()
        self.report["inputs"][0]["kernel_observations"] = {"release_strings": ["6.6.one"]}
        self.add_module("modules/one.ko", release="6.6.one")
        self.add_module("modules/two.ko", release="6.6.two")
        self.report["module_observations"]["different_release_string_count"] = 0
        result = self.load()
        self.assertEqual(result["summary"]["module_release_string_populations"], {"6.6.one": 1, "6.6.two": 1})
        ids = {w["id"] for w in result["warnings"]}
        self.assertIn("multiple-module-release-strings", ids)
        self.assertIn("module-kernel-release-label-difference", ids)
        self.assertIsNone(result["selection"]["kernel"])

    def test_equal_release_still_unselected(self):
        self.add_artifact()
        self.report["inputs"][0]["kernel_observations"] = {"release_strings": ["6.6.test"]}
        self.add_module()
        result = self.load()
        self.assertEqual(result["selection"]["modules"], [])
        self.assertIn("do not prove ABI", result["validation"]["release_strings"])

    def test_duplicate_providers_and_dependency_coverage(self):
        self.add_module("modules/a.ko", "provider", depends="builtin_or_missing")
        self.add_module("modules/b.ko", "provider")
        self.add_module("modules/c.ko", "conflict", content=b"one")
        self.add_module("modules/d.ko", "conflict", content=b"two")
        result = self.load()["reports"][0]["modules"]
        self.assertEqual({x["state"] for x in result["duplicate_providers"]},
                         {"byte-identical-copies", "different-captured-bytes"})
        self.assertEqual(result["hard_dependencies_without_captured_provider"], {"builtin_or_missing": 1})

    def test_fdt_empty_and_board_identity_are_only_observations(self):
        self.add_artifact("trees/empty.dtb", "dtb-candidate", fdt())
        self.add_artifact("trees/board.dtb", "dtb-candidate", fdt(True))
        result = self.load()
        trees = {x["path"]: x for x in result["reports"][0]["device_trees"]}
        self.assertEqual(trees["trees/empty.dtb"]["state"], "empty-root")
        self.assertEqual(trees["trees/board.dtb"]["root_identity"]["compatible"], ["test,board"])
        self.assertEqual(result["selection"]["device_trees"], [])

    def test_bad_fdt_body_does_not_silently_claim_valid_tree(self):
        data = bytearray(fdt())
        data[64:68] = struct.pack(">I", 99)
        self.add_artifact("trees/bad.dtb", "dtb-candidate", bytes(data))
        result = self.load()
        self.assertIn("device-tree-structure-unestablished", {w["id"] for w in result["warnings"]})

    def test_dtbo_table_and_archive_filesystem_origins_preserved(self):
        item = self.add_artifact("trees/one.dtbo", "dtbo-entry", fdt(True),
                                 {"input": "boot", "offset": 8192, "entry": 2})
        item["details"] = {"id": 17, "revision": 3, "custom": [1, 2, 3, 4]}
        self.add_artifact("headers/a.h", "header-candidate", b"header",
            {"input": "boot", "component": "boot/ramdisk", "archive": 1, "entry": "include/a.h",
             "data_entry": "include/b.h", "offset_in_decoded_archive": 512})
        self.add_artifact("headers/b.h", "header-candidate", b"header2",
            {"input": "boot", "filesystem_path": "/include/b.h", "inode": 11, "filesystem": "ext2/3/4"})
        artifacts = self.load()["reports"][0]["artifacts"]
        self.assertEqual(artifacts[0]["table_identity"], item["details"])
        self.assertEqual(artifacts[1]["source"]["data_entry"], "include/b.h")
        self.assertEqual(artifacts[2]["source"]["inode"], 11)

    def test_multiple_reports_remain_separate_and_duplicates_rejected(self):
        self.add_module()
        self.write()
        other = self.root / "other"
        other.mkdir()
        report = copy.deepcopy(self.report)
        report.update(artifacts=[], inputs=[{"label": "other", "state": "unsupported"}])
        report.pop("module_observations")
        (other / "extraction-report.json").write_text(json.dumps(report))
        result = evidence.load_extractions([self.capture, other])
        self.assertEqual(result["summary"]["reports"], 2)
        self.assertEqual(result["selection"]["modules"], [])
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_extractions([self.capture, self.capture / "extraction-report.json"])

    def test_other_capture_cannot_supply_matching_kernel_or_dependency(self):
        self.add_artifact()
        self.report["inputs"][0]["kernel_observations"] = {"release_strings": ["6.6.a"]}
        self.add_module(provider="a", release="6.6.b", depends="b")
        self.write()
        other = self.root / "other"
        shutil.copytree(self.capture, other)
        report = copy.deepcopy(self.report)
        report["inputs"][0]["kernel_observations"]["release_strings"] = ["6.6.b"]
        module = report["module_observations"]["modules"][0]
        module["metadata"].update(name=["b"], vermagic=["6.6.a SMP"], depends=["a"])
        (other / "extraction-report.json").write_text(json.dumps(report))
        result = evidence.load_extractions([self.capture, other])
        mismatches = [w for w in result["warnings"] if w["id"] == "module-kernel-release-label-difference"]
        self.assertEqual(len(mismatches), 2)
        self.assertEqual(len({w["report_sha256"] for w in mismatches}), 2)
        self.assertTrue(all(r["modules"]["hard_dependencies_without_captured_provider"] for r in result["reports"]))

    def test_generator_integration_preserves_evidence_and_existing_edits(self):
        self.add_artifact()
        self.write()
        source = self.root / "source"
        source.mkdir()
        input_path = Path(__file__).parent / "examples/native-arm64.json"
        output = self.root / "output"
        with patch.object(generate, "verify_source", return_value={}):
            generate.generate(input_path, output, source, [self.capture])
            generate.check(output)
            reports = generate.report_root(output)
            report = generate.read_json(reports / "support-report.json")
            self.assertFalse(report["build_ready"])
            self.assertFalse(report["flashable"])
            self.assertEqual(report["prebuilt_evidence"]["summary"]["artifacts"], 1)
            (reports / "PORTING.md").write_text("owner edit")
            with self.assertRaises(generate.InputError):
                generate.generate(input_path, output, source, [self.capture])
            with self.assertRaises(generate.InputError):
                generate.generate(input_path, self.capture / "output", source, [self.capture])
        self.assertEqual((reports / "PORTING.md").read_text(), "owner edit")
        self.assertEqual(list(source.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
