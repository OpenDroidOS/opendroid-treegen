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

import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import module_plan as plan


def module(deps=(), pre=(), post=(), phase="post-fs"):
    return {"depends": list(deps), "soft_pre": list(pre), "soft_post": list(post), "phase": phase}


class DependencyTests(unittest.TestCase):
    def test_pre_post_and_builtin_dependencies(self):
        modules = {"gpu": module(("iommu",), ("heap",), ("monitor",)),
                   "heap": module(), "monitor": module()}
        self.assertEqual(plan.order_modules(modules, {"iommu"}), ["heap", "gpu", "monitor"])

    def test_missing_provider_is_not_a_builtin(self):
        with self.assertRaisesRegex(plan.PlanError, "missing module dependency"):
            plan.order_modules({"ufs": module(("clock",))}, set())

    def test_missing_post_dependency(self):
        with self.assertRaisesRegex(plan.PlanError, "missing soft dependency"):
            plan.order_modules({"wifi": module(post=("radio",))}, set())

    def test_mixed_dependency_cycle(self):
        with self.assertRaisesRegex(plan.PlanError, "cycle"):
            plan.order_modules({"a": module(("b",)), "b": module(pre=("a",))}, set())

    def test_provider_cannot_load_after_its_consumer(self):
        with self.assertRaisesRegex(plan.PlanError, "later phase"):
            plan.order_modules({"display": module(("heap",)), "heap": module(phase="boot")}, set())


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = b"CONFIG_MODULES=y\nCONFIG_MODVERSIONS=y\n"
        (self.root / "config").write_bytes(self.config)
        raw = bytearray(64)
        raw[56:60] = b"ARMd"
        self.magic = "6.6.1-test SMP preempt mod_unload modversions aarch64"
        raw += self.magic.encode() + b"\0IKCFG_ST" + gzip.compress(self.config) + b"IKCFG_ED"
        (self.root / "Image").write_bytes(raw)
        (self.root / "display.ko").write_bytes(b"fixture")
        self.data = {"format_version": 1, "kernel": "Image", "config": "config", "builtins": None,
                     "modules": [{"source": "display.ko", "destination": "modules/display.ko", "phase": "post-fs"}],
                     "firmware": []}
        self.manifest = self.root / "modules.json"

    def build(self, magic=None, **extra):
        self.manifest.write_text(json.dumps(self.data))
        metadata = {"name": ["display"], "vermagic": [magic or self.magic], **extra}
        with patch.object(plan, "module_metadata", return_value=metadata):
            return plan.build_plan(self.manifest, self.root / "result", "modinfo")

    def test_order_and_commands_match_existing_install_contract(self):
        self.assertTrue(self.build())
        cfg = json.loads((self.root / "result/init.modules.cfg").read_text())
        self.assertEqual(cfg["jobs"], [{"name": "post-fs", "cmds": [
            "insmod /vendor/lib/opendroid/modules/display.ko"]}])

    def test_wrong_kernel_emits_report_but_no_load_commands(self):
        self.assertFalse(self.build(magic=self.magic.replace("6.6.1", "6.6.2")))
        self.assertFalse((self.root / "result/init.modules.cfg").exists())

    def test_firmware_gap_blocks_load_config(self):
        self.assertFalse(self.build(firmware=["qcom/gpu.bin"]))

    def test_config_must_come_from_selected_image(self):
        (self.root / "config").write_bytes(self.config + b"CONFIG_FOO=y\n")
        with self.assertRaisesRegex(plan.PlanError, "embedded kernel config"):
            self.build()

    def test_early_phase_is_not_misrepresented_by_late_init(self):
        self.data["modules"][0]["phase"] = "pre-init"
        with self.assertRaisesRegex(plan.PlanError, "early-root"):
            self.build()

    def test_destination_cannot_inject_init_commands(self):
        self.data["modules"][0]["destination"] = "a.ko -f"
        with self.assertRaisesRegex(plan.PlanError, "safe relative"):
            self.build()


if __name__ == "__main__":
    unittest.main()
