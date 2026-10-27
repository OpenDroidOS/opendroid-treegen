# Copyright 2026 OpenDroidOS
#
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
"""Boundary, provenance and real offline extraction checks for OpenDroidOS."""

import gzip
import hashlib
import json
import lzma
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

import extract


def pad(data, page=4096):
    return data + b"\0" * (-len(data) % page)


def fdt():
    structure = struct.pack(">I", 1) + b"\0" * 4 + struct.pack(">2I", 2, 9)
    return struct.pack(">10I", 0xd00dfeed, 72, 56, 72, 40, 17, 16, 0, 0, 16) + b"\0" * 16 + structure


def cpio(entries):
    data = bytearray()
    for inode, (name, payload, mode, links) in enumerate(entries + [("TRAILER!!!", b"", stat.S_IFREG, 1)], 1):
        name = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, links, 0, len(payload), 0, 0, 0, 0, len(name), 0]
        data += b"070701" + b"".join(f"{v:08x}".encode() for v in fields) + name
        data += b"\0" * (-len(data) % 4)
        data += payload
        data += b"\0" * (-len(data) % 4)
    return bytes(data)


def boot(version=4, kernel=None, ramdisk=b""):
    if kernel is None:
        kernel = b"\0" * 56 + b"ARMd" + b"x" * 20
    header = bytearray(4096)
    header[:8] = b"ANDROID!"
    struct.pack_into("<4I", header, 8, len(kernel), len(ramdisk), 0, 1584 if version == 4 else 1580)
    struct.pack_into("<I", header, 40, version)
    return bytes(header) + pad(kernel) + pad(ramdisk)


def vendor_boot(version=4, ramdisk=b"", name=b"../../must-not-write", dtb=None):
    dtb = fdt() if dtb is None else dtb
    header = bytearray(4096)
    header[:8] = b"VNDRBOOT"
    struct.pack_into("<5I", header, 8, version, 4096, 0, 0, len(ramdisk))
    struct.pack_into("<2I", header, 2096, 2128 if version == 4 else 2112, len(dtb))
    if version == 3:
        return bytes(header) + pad(ramdisk) + pad(dtb)
    struct.pack_into("<4I", header, 2112, 108, 1, 108, 0)
    entry = struct.pack("<3I", len(ramdisk), 0, 1) + name.ljust(32, b"\0")[:32] + b"\0" * 64
    return bytes(header) + pad(ramdisk) + pad(dtb) + pad(entry)


def legacy_boot(version):
    page = 2048
    kernel, ramdisk, dtb = b"\0" * 56 + b"ARMd", b"", fdt()
    header = bytearray(page)
    header[:8] = b"ANDROID!"
    struct.pack_into("<9I", header, 8, len(kernel), 0, len(ramdisk), 0, 0, 0, 0, page, version)
    if version:
        struct.pack_into("<IQI", header, 1632, 0, 0, 1648 if version == 1 else 1660)
    if version == 2:
        struct.pack_into("<IQ", header, 1648, len(dtb), 0)
    result = bytes(header) + pad(kernel, page)
    if version == 2:
        result += pad(dtb, page)
    return result


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="opendroid-extract-test-")
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def extractor(self, **kwargs):
        return extract.Extractor(self.root / "output", **kwargs)

    def test_boot_extracts_exact_kernel_config_ramdisk_modules_and_appended_dtb(self):
        config = b"CONFIG_MODULES=y\n# CONFIG_PID_NS is not set\n"
        kernel = (b"\0" * 56 + b"ARMd" + b"Linux version 6.6-test test\n"
                  + b"IKCFG_ST" + gzip.compress(config) + b"IKCFG_ED" + fdt())
        ramdisk = gzip.compress(cpio([("lib/modules/test.ko", b"module bytes", stat.S_IFREG | 0o755, 1),
                                     ("usr/include/test.h", b"#define TEST 1\n", stat.S_IFREG | 0o644, 1),
                                     ("lib/modules/escape.ko", b"/tmp/outside", stat.S_IFLNK | 0o777, 1)]))
        path = self.root / "boot.img"
        path.write_bytes(boot(kernel=kernel, ramdisk=ramdisk))
        original = path.read_bytes()
        engine = self.extractor()
        engine.process("boot", path)
        report = json.loads(engine.finish().read_text())
        self.assertEqual(report["inputs"][0]["state"], "extracted")
        self.assertEqual(path.read_bytes(), original)
        by_kind = {x["kind"]: engine.output / x["path"] for x in report["artifacts"]}
        self.assertEqual(by_kind["kernel-payload"].read_bytes(), kernel)
        self.assertEqual(by_kind["embedded-kernel-config"].read_bytes(), config)
        self.assertEqual(by_kind["kernel-module"].read_bytes(), b"module bytes")
        self.assertEqual(by_kind["dtb-candidate"].read_bytes(), fdt())
        self.assertEqual(by_kind["header-file-candidate"].read_bytes(), b"#define TEST 1\n")
        self.assertEqual(report["inputs"][0]["kernel_observations"]["embedded_config"]["state"], "observed")
        self.assertFalse(any(x.is_symlink() for x in engine.output.rglob("*")))
        for item in report["artifacts"]:
            self.assertEqual(hashlib.sha256((engine.output / item["path"]).read_bytes()).hexdigest(), item["sha256"])
            self.assertFalse((engine.output / item["path"]).stat().st_mode & 0o111)

    def test_only_modules_skips_kernel_and_device_tree_payloads(self):
        archive = gzip.compress(cpio([("lib/modules/storage.ko", b"module bytes", stat.S_IFREG | 0o755, 1)]))
        path = self.root / "boot.img"
        path.write_bytes(boot(kernel=b"kernel payload", ramdisk=archive))
        engine = extract.Extractor(self.root / "modules-only", only=("modules",))
        engine.process("boot", path)
        report = json.loads(engine.finish().read_text())
        self.assertEqual(report["selection"], {"found": ["modules"], "missing": []})
        self.assertEqual([item["kind"] for item in report["artifacts"]], ["kernel-module"])
        module = next(item for item in report["artifacts"] if item["kind"] == "kernel-module")
        self.assertEqual((engine.output / module["path"]).read_bytes(), b"module bytes")

    def test_only_config_uses_kernel_as_temporary_input(self):
        config = b"CONFIG_MODULES=y\n"
        kernel = b"\0" * 56 + b"ARMd" + b"Linux version test\nIKCFG_ST" + gzip.compress(config) + b"IKCFG_ED" + fdt()
        archive = gzip.compress(cpio([("lib/modules/not-selected.ko", b"module", stat.S_IFREG | 0o755, 1)]))
        path = self.root / "config-only-boot.img"
        path.write_bytes(boot(kernel=kernel, ramdisk=archive))
        engine = extract.Extractor(self.root / "config-only", only=("config",))
        engine.process("boot", path)
        report = json.loads(engine.finish().read_text())
        self.assertEqual([item["kind"] for item in report["artifacts"]], ["embedded-kernel-config"])
        self.assertEqual((engine.output / "boot/kernel.config").read_bytes(), config)
        self.assertFalse((engine.output / "boot/components/kernel").exists())
        self.assertFalse((engine.output / ".work").exists())

    def test_only_kernel_does_not_emit_observed_config_modules_or_dtb(self):
        config = b"CONFIG_MODULES=y\n"
        kernel = b"\0" * 56 + b"ARMd" + b"Linux version test\nIKCFG_ST" + gzip.compress(config) + b"IKCFG_ED" + fdt()
        archive = gzip.compress(cpio([("lib/modules/not-selected.ko", b"module", stat.S_IFREG | 0o755, 1)]))
        path = self.root / "kernel-only-boot.img"
        path.write_bytes(boot(kernel=kernel, ramdisk=archive))
        engine = extract.Extractor(self.root / "kernel-only", only=("kernel",))
        engine.process("boot", path)
        report = json.loads(engine.finish().read_text())
        self.assertEqual([item["kind"] for item in report["artifacts"]], ["kernel-payload"])
        self.assertFalse((engine.output / "boot/kernel.config").exists())
        self.assertFalse((engine.output / "boot/ramdisk-files").exists())
        self.assertFalse((engine.output / "boot/device-trees").exists())

    def test_raw_fdt_named_dtbo_respects_requested_output_family(self):
        capture = self.root / "dtbo-directory"
        capture.mkdir()
        (capture / "dtbo").write_bytes(fdt())

        dtbo_only = extract.Extractor(self.root / "dtbo-only", only=("dtbo",))
        dtbo_only.process("files", capture, directory=True)
        dtbo_report = json.loads(dtbo_only.finish().read_text())
        self.assertEqual(dtbo_report["selection"]["missing"], ["dtbo"])
        self.assertFalse(any(item["kind"] == "dtb-candidate" for item in dtbo_report["artifacts"]))

        dtb_only = extract.Extractor(self.root / "dtb-only", only=("dtb",))
        dtb_only.process("files", capture, directory=True)
        dtb_report = json.loads(dtb_only.finish().read_text())
        self.assertEqual(dtb_report["selection"], {"found": ["dtb"], "missing": []})
        self.assertEqual([item["kind"] for item in dtb_report["artifacts"]], ["dtb-candidate"])

    def test_explicit_families_filter_loose_candidates_and_boot_other_components(self):
        capture = self.root / "mixed-boot"
        (capture / "headers").mkdir(parents=True)
        (capture / "lib/modules").mkdir(parents=True)
        (capture / ".config").write_text("CONFIG_MODULES=y\n")
        (capture / "headers/test.h").write_text("#define TEST 1\n")
        (capture / "lib/modules/test.ko").write_bytes(b"module")
        (capture / "kernel").write_bytes(b"kernel payload")
        (capture / "board.dtb").write_bytes(fdt())
        dt = fdt()
        table = struct.pack(">8I", 0xd7b7ab1e, 64 + len(dt), 32, 32, 1, 32, 4096, 0)
        (capture / "overlay.dtbo").write_bytes(
            table + struct.pack(">8I", len(dt), 64, 123, 7, 1, 2, 3, 4) + dt)
        (capture / "bootconfig").write_bytes(b"bootconfig data")
        (capture / "second").write_bytes(b"second-stage data")

        expected = {
            "kernel": {"kernel-payload"},
            "config": {"kernel-config-candidate"},
            "dtb": {"dtb-candidate"},
            "dtbo": {"dtbo-entry"},
            "modules": {"kernel-module"},
            "headers": {"header-file-candidate"},
        }
        for selected, selected_kinds in expected.items():
            with self.subTest(selected=selected):
                output = self.root / f"only-{selected}"
                engine = extract.Extractor(output, only=(selected,))
                engine.process("boot", capture, directory=True)
                report = json.loads(engine.finish().read_text())
                observed = {item["kind"] for item in report["artifacts"]}
                self.assertEqual(observed, selected_kinds)
                self.assertFalse(any("bootconfig" in item["path"] or "second" in item["path"]
                                     for item in report["artifacts"]))
                if selected == "config":
                    self.assertEqual(report["selection"], {"found": [], "missing": ["config"]})
                else:
                    self.assertEqual(report["selection"], {"found": [selected], "missing": []})

    def test_root_cli_rejects_missing_and_ambiguous_capture_selection(self):
        cli = Path(__file__).resolve().parents[2] / "opendroid-treegen"
        output = self.root / "missing-output"
        result = subprocess.run([sys.executable, "-B", str(cli), "extract", "--output", str(output)],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

        capture = self.root / "ambiguous"
        capture.mkdir()
        (capture / "boot_a.img").write_bytes(boot())
        (capture / "boot_b.img").write_bytes(boot())
        output = self.root / "ambiguous-output"
        result = subprocess.run([sys.executable, "-B", str(cli), "extract", str(capture),
                                 "--output", str(output)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("selection-required", result.stderr)
        self.assertFalse(output.exists())

        capture = self.root / "boot-only"
        capture.mkdir()
        (capture / "boot.img").write_bytes(boot())
        output = self.root / "missing-dtbo-output"
        result = subprocess.run([sys.executable, "-B", str(cli), "extract", str(capture),
                                 "--only", "dtbo", "--output", str(output)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads((output / "extraction-report.json").read_text())
        self.assertEqual(report["selection"]["missing"], ["dtbo"])

    def test_vendor_ramdisk_names_are_never_used_as_output_paths(self):
        archive = cpio([("lib/modules/modules.load", b"a.ko\n", stat.S_IFREG, 1)])
        path = self.root / "vendor_boot.img"
        path.write_bytes(vendor_boot(ramdisk=archive))
        engine = self.extractor()
        engine.process("vendor_boot", path)
        info = engine.report["inputs"][0]
        self.assertEqual(info["state"], "extracted", info)
        self.assertTrue((engine.output / "vendor_boot/components/vendor_ramdisk00").is_file())
        self.assertFalse((self.root / "must-not-write").exists())
        self.assertFalse(any(p.is_symlink() for p in engine.output.rglob("*")))
        self.assertTrue(any(x["kind"] == "dtb-candidate" for x in engine.artifacts))

    def test_boot_versions_zero_through_four_and_vendor_three_are_usable(self):
        for version in range(5):
            path = self.root / f"boot-{version}.img"
            path.write_bytes(legacy_boot(version) if version < 3 else boot(version))
            engine = extract.Extractor(self.root / f"out-{version}")
            engine.process("boot", path)
            info = engine.report["inputs"][0]
            self.assertEqual(info["state"], "extracted", info)
            self.assertEqual(info["boot_layout"]["header_version"], version)
        path = self.root / "vendor-v3.img"
        path.write_bytes(vendor_boot(3, cpio([])))
        engine = self.extractor()
        engine.process("vendor_boot", path)
        self.assertEqual(engine.report["inputs"][0]["state"], "extracted")

    def test_gzip_and_xz_kernel_decode_keep_original_bytes(self):
        kernel = b"\0" * 56 + b"ARMd" + b"Linux version 6.6-test test\n"
        for codec, encoded in (("gzip", gzip.compress(kernel)), ("xz", lzma.compress(kernel))):
            path = self.root / (codec + ".img")
            path.write_bytes(boot(kernel=encoded))
            engine = extract.Extractor(self.root / codec)
            engine.process("boot", path)
            self.assertEqual(engine.report["inputs"][0]["state"], "extracted")
            self.assertEqual((engine.output / "boot/components/kernel").read_bytes(), encoded)
            self.assertEqual((engine.output / "boot/kernel-decoded").read_bytes(), kernel)

    @unittest.skipUnless(shutil.which("lz4") and shutil.which("zstd"), "installed stream tools unavailable")
    def test_installed_lz4_and_zstd_decoders_extract_real_archives(self):
        archive = cpio([("lib/modules/a.ko", b"payload", stat.S_IFREG, 1)])
        for codec in ("lz4", "zstd"):
            encoded = subprocess.check_output([shutil.which(codec), "-c"], input=archive, stderr=subprocess.DEVNULL)
            path = self.root / (codec + ".img")
            path.write_bytes(boot(ramdisk=encoded))
            engine = extract.Extractor(self.root / codec)
            engine.process("boot", path)
            info = engine.report["inputs"][0]
            self.assertEqual(info["state"], "extracted", info)
            artifact = next(x for x in engine.artifacts if x["kind"] == "kernel-module")
            self.assertEqual((engine.output / artifact["path"]).read_bytes(), b"payload")

    def test_truncated_boot_and_invalid_vendor_fragments_fail(self):
        for label, data in (("boot", boot()[:4097]), ("vendor_boot", vendor_boot(ramdisk=b"abc")[:-4090])):
            with self.subTest(label=label):
                path = self.root / (label + ".img")
                path.write_bytes(data)
                engine = extract.Extractor(self.root / (label + "-out"))
                engine.process(label, path)
                self.assertEqual(engine.report["inputs"][0]["state"], "failed")

    def test_cpio_traversal_is_rejected_without_creating_external_files(self):
        path = self.root / "archive"
        path.write_bytes(cpio([("../../outside.h", b"bad", stat.S_IFREG, 1)]))
        engine = self.extractor()
        with self.assertRaises(extract.ExtractionError):
            engine.cpio(path, "boot", "ramdisk", {"input": "boot"}, {})
        self.assertFalse((self.root / "outside.h").exists())

    def test_missing_cpio_trailer_is_partial_and_alignment_truncation_fails(self):
        archive = cpio([("a.h", b"x", stat.S_IFREG, 1)])
        end = archive.find(b"070701", 6)
        path = self.root / "archive"
        path.write_bytes(archive[:end])
        engine = self.extractor()
        info = {"state": "extracted"}
        engine.cpio(path, "boot", "ramdisk", {"input": "boot"}, info)
        self.assertEqual(info["state"], "partial")
        self.assertIn("closure unverified", info["limitations"][0])
        path.write_bytes(archive[:end - 1])
        other = extract.Extractor(self.root / "truncated")
        with self.assertRaises(extract.ExtractionError):
            other.cpio(path, "boot", "ramdisk", {"input": "boot"}, {})

    def test_init_boot_has_ramdisk_and_no_invented_kernel(self):
        path = self.root / "init_boot.img"
        path.write_bytes(boot(kernel=b"", ramdisk=gzip.compress(cpio([]))))
        engine = self.extractor()
        engine.process("init_boot", path)
        self.assertEqual(engine.report["inputs"][0]["state"], "extracted")
        self.assertFalse(any(x["kind"] == "kernel-payload" for x in engine.artifacts))
        self.assertTrue((engine.output / "init_boot/components/ramdisk").is_file())

    def test_cpio_concatenated_archives_and_hardlink_data(self):
        # Same inode, data-bearing member last, represented with an explicit header edit.
        archive = bytearray(cpio([("lib/modules/alias.ko", b"", stat.S_IFREG, 2),
                                  ("lib/modules/real.ko", b"real payload", stat.S_IFREG, 2)]))
        second = archive.find(b"070701", 6)
        archive[second + 6:second + 14] = b"00000001"
        archive += cpio([("usr/include/a.h", b"header", stat.S_IFREG, 1)])
        path = self.root / "archive"
        path.write_bytes(archive)
        engine = self.extractor()
        engine.cpio(path, "boot", "ramdisk", {"input": "boot"}, {})
        modules = [engine.output / x["path"] for x in engine.artifacts if x["kind"] == "kernel-module"]
        self.assertEqual([p.read_bytes() for p in modules], [b"real payload", b"real payload"])
        self.assertEqual(len(engine.artifacts), 3)

    def test_dtbo_table_preserves_entries_and_rejects_overlap_or_version(self):
        dt = fdt()
        image = struct.pack(">8I", 0xd7b7ab1e, 64 + len(dt), 32, 32, 1, 32, 4096, 0)
        image += struct.pack(">8I", len(dt), 64, 123, 7, 1, 2, 3, 4) + dt
        path = self.root / "dtbo.img"
        path.write_bytes(image)
        engine = self.extractor()
        engine.process("dtbo", path)
        self.assertEqual(engine.report["inputs"][0]["dt_table"]["entries"][0]["id"], 123)
        self.assertEqual((engine.output / "dtbo/entries/entry-000.dtbo").read_bytes(), dt)
        for name, offset, value in (("overlap", 36, 32), ("version", 28, 1)):
            changed = bytearray(image)
            struct.pack_into(">I", changed, offset, value)
            path.write_bytes(changed)
            other = extract.Extractor(self.root / name)
            other.process("dtbo", path)
            self.assertIn(other.report["inputs"][0]["state"], ("failed", "unsupported"))

    def test_fresh_output_and_input_alias_protection(self):
        output = self.root / "existing"
        output.mkdir()
        marker = output / "keep"
        marker.write_text("keep")
        with self.assertRaises(extract.ExtractionError):
            extract.Extractor(output)
        self.assertEqual(marker.read_text(), "keep")
        source = self.root / "inputs"
        source.mkdir()
        (source / "real.ko").write_bytes(b"data")
        (source / "link.ko").symlink_to(source / "real.ko")
        engine = self.extractor()
        engine.process("captured", source, True)
        self.assertEqual(len(engine.artifacts), 1)
        self.assertEqual(engine.report["inputs"][0]["directory"]["nonregular_entries_not_materialized"], 1)

    def test_gzip_size_limit_retains_component_and_marks_partial(self):
        path = self.root / "boot.img"
        path.write_bytes(boot(ramdisk=gzip.compress(b"x" * 20000)))
        engine = self.extractor(max_file_bytes=8192)
        engine.process("boot", path)
        self.assertEqual(engine.report["inputs"][0]["state"], "partial")
        self.assertTrue((engine.output / "boot/components/ramdisk").is_file())
        self.assertFalse(any(p.name.endswith(".decoded") for p in (engine.output / ".work").rglob("*")))

    def test_sparse_raw_fill_hole_crc_and_truncation(self):
        block = 4
        raw = b"abcd" + b"ABCD" * 2 + b"\0" * 4
        crc = zlib.crc32(raw)
        image = struct.pack("<I4H4I", 0xed26ff3a, 1, 0, 28, 12, block, 4, 4, crc)
        image += struct.pack("<2H2I", 0xcac1, 0, 1, 16) + b"abcd"
        image += struct.pack("<2H2I", 0xcac2, 0, 2, 16) + b"ABCD"
        image += struct.pack("<2H2I", 0xcac3, 0, 1, 12)
        image += struct.pack("<2H2I", 0xcac4, 0, 0, 16) + struct.pack("<I", crc)
        path = self.root / "sparse.img"
        path.write_bytes(image)
        engine = self.extractor()
        expanded, _ = engine.expand_sparse(path, "vendor")
        self.assertEqual(expanded.read_bytes(), raw)
        changed = bytearray(image)
        changed[-1] ^= 1
        path.write_bytes(changed)
        with self.assertRaises(extract.ExtractionError):
            engine.expand_sparse(path, "bad-crc")
        path.write_bytes(image[:-3])
        with self.assertRaises(extract.ExtractionError):
            engine.expand_sparse(path, "truncated")

    def test_sparse_expansion_limit_and_fdt_block_bounds_are_enforced(self):
        path = self.root / "oversized.sparse"
        path.write_bytes(struct.pack("<I4H4I", 0xed26ff3a, 1, 0, 28, 12, 4096, 10000, 0, 0))
        engine = self.extractor(max_expanded_bytes=8192)
        with self.assertRaises(extract.ExtractionError):
            engine.expand_sparse(path, "large")
        malformed = bytearray(fdt())
        struct.pack_into(">I", malformed, 12, 1024)
        with self.assertRaises(extract.ExtractionError):
            engine.fdt_size(malformed)

    def test_crc_cpio_corruption_is_not_accepted(self):
        raw = bytearray(cpio([("a.h", b"bad-checksum", stat.S_IFREG, 1)]))
        raw[:6] = b"070702"
        path = self.root / "archive"
        path.write_bytes(raw)
        engine = self.extractor()
        with self.assertRaises(extract.ExtractionError):
            engine.cpio(path, "boot", "ramdisk", {"input": "boot"}, {})

    def test_command_exit_status_and_provenance_contract(self):
        path = self.root / "boot.img"
        path.write_bytes(boot())
        command = Path(__file__).with_name("opendroid-extract")
        result = subprocess.run(["python3", "-B", str(command), "--boot", str(path),
                                 "--output", str(self.root / "cli-output")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        report = json.loads(Path(summary["report"]).read_text())
        self.assertEqual(report["kind"], "opendroid-prebuilt-extraction-evidence")
        self.assertEqual(report["inputs"][0]["sha256"], extract.sha256_file(path))
        self.assertEqual(report["validation"]["openharmony_compatibility"], "not-established-by-extraction")
        again = subprocess.run(["python3", "-B", str(command), "--boot", str(path),
                                "--output", str(self.root / "cli-output")], capture_output=True, text=True)
        self.assertEqual(again.returncode, 2)

    @unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "installed ext tools unavailable")
    def test_real_ext4_inode_extraction_is_selective_and_read_only(self):
        tree = self.root / "fs-root"
        modules = tree / "lib/modules"
        modules.mkdir(parents=True)
        (modules / "real.ko").write_bytes(b"module-data")
        (modules / "modules.dep").write_bytes(b"real.ko:\n")
        (modules / "link.ko").symlink_to("/outside.ko")
        (tree / "secret.txt").write_bytes(b"not selected")
        headers = tree / "usr/include"
        headers.mkdir(parents=True)
        (headers / "a.h").write_bytes(b"#define A 1\n")
        image = self.root / "vendor.img"
        with image.open("wb") as stream:
            stream.truncate(16 * extract.CHUNK)
        subprocess.run([shutil.which("mke2fs"), "-q", "-F", "-t", "ext4", "-d", str(tree), str(image)],
                       check=True, capture_output=True, timeout=60)
        before = extract.sha256_file(image)
        engine = self.extractor()
        engine.process("vendor", image)
        info = engine.report["inputs"][0]
        self.assertEqual(info["state"], "extracted", info)
        self.assertEqual(extract.sha256_file(image), before)
        self.assertEqual(len(engine.artifacts), 3)
        self.assertEqual((engine.output / "vendor/filesystem-files/lib/modules/real.ko").read_bytes(), b"module-data")
        self.assertFalse(any(p.name in ("secret.txt", "link.ko") for p in engine.output.rglob("*")))

    def test_unsupported_erofs_and_payload_are_explicit(self):
        for label, data in (("vendor", b"\0" * 1024 + b"\xe2\xe1\xf5\xe0" + b"\0" * 60),
                            ("vendor_dlkm", b"CrAU" + b"\0" * 2048)):
            path = self.root / (label + ".img")
            path.write_bytes(data)
            engine = extract.Extractor(self.root / (label + "-output"))
            engine.process(label, path)
            self.assertEqual(engine.report["inputs"][0]["state"], "unsupported")

    def run_folder(self, folder, name="folder-output", extra=()):
        return subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("opendroid-extract")),
                               str(folder), *extra, "--output", str(self.root / name)],
                              capture_output=True, text=True)

    def test_folder_discovers_images_and_prefers_image_over_extracted_alternative(self):
        folder = self.root / "capture"
        folder.mkdir()
        (folder / "boot.img").write_bytes(boot())
        unpacked = folder / "boot"
        unpacked.mkdir()
        (unpacked / "kernel").write_bytes(b"unused extracted alternative")
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual([item["label"] for item in report["inputs"]], ["boot"])
        self.assertEqual(report["discovery"]["selected"][0]["selection"], "image-preferred")
        self.assertEqual(report["discovery"]["skipped"][0]["reason"], "image-preferred")

    def test_extracted_boot_is_usable_without_inventing_original_header(self):
        folder = self.root / "capture/boot"
        folder.mkdir(parents=True)
        kernel = b"\0" * 56 + b"ARMd" + fdt()
        (folder / "boot.img-kernel").write_bytes(kernel)
        (folder / "boot.img-ramdisk.gz").write_bytes(gzip.compress(cpio([])))
        result = self.run_folder(folder.parent)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        info = report["inputs"][0]
        self.assertNotIn("boot_layout", info)
        self.assertEqual(info["directory"]["original_image_header_layout"], "not-available-from-directory")
        self.assertEqual((self.root / "folder-output/boot/components/kernel").read_bytes(), kernel)
        candidate = next(item for item in report["artifacts"] if item["kind"] == "kernel-payload")
        self.assertEqual(candidate["source"]["file_sha256"], hashlib.sha256(kernel).hexdigest())

    def test_direct_extracted_boot_with_unpacked_ramdisk_is_one_capture(self):
        folder = self.root / "boot"
        modules = folder / "ramdisk/lib/modules"
        modules.mkdir(parents=True)
        (folder / "kernel").write_bytes(b"\0" * 56 + b"ARMd")
        (modules / "a.ko").write_bytes(b"module")
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual(len(report["inputs"]), 1)
        self.assertEqual(report["summary"]["kinds"]["kernel-module"], 1)

    def test_extracted_boot_missing_kernel_is_explicitly_partial(self):
        folder = self.root / "boot"
        folder.mkdir()
        (folder / "config").write_text("not a kernel")
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual(report["inputs"][0]["directory"]["required_content"],
                         [{"component": "kernel", "state": "missing"}])

    def test_loose_trees_next_to_image_are_collected_once_with_source_identity(self):
        folder = self.root / "capture"
        folder.mkdir()
        dt = fdt()
        table = struct.pack(">8I", 0xd7b7ab1e, 64 + len(dt), 32, 32, 1, 32, 4096, 0)
        table += struct.pack(">8I", len(dt), 64, 123, 7, 1, 2, 3, 4) + dt
        (folder / "dtbo.img").write_bytes(table)
        for name in ("board.dtb", "overlay.dtbo", "live-effective.fdt"):
            (folder / name).write_bytes(dt)
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual(report["summary"]["kinds"]["dtbo-entry"], 1)
        files = [item for item in report["artifacts"] if item["source"]["input"] == "files"]
        self.assertEqual({item["source"]["directory_path"] for item in files},
                         {"board.dtb", "overlay.dtbo", "live-effective.fdt"})
        self.assertEqual(sum(item["kind"] == "dtb-candidate" for item in files), 3)

    def test_folder_collects_modules_headers_and_deep_tree_candidates(self):
        folder = self.root / "capture"
        headers = folder / "headers/linux"
        headers.mkdir(parents=True)
        (headers / "a.h").write_text("#define A 1\n")
        modules = folder / "lib/modules/6.6"
        modules.mkdir(parents=True)
        (modules / "a.ko").write_bytes(b"module")
        trees = folder / "trees/nested/more"
        trees.mkdir(parents=True)
        (trees / "board.dtb").write_bytes(fdt())
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual(report["summary"]["kinds"]["kernel-module"], 1)
        self.assertEqual(report["summary"]["kinds"]["header-file-candidate"], 1)
        self.assertEqual(report["summary"]["kinds"]["dtb-candidate"], 1)

    def test_ambiguous_images_slots_and_build_folders_fail_before_output(self):
        for scenario in ("duplicate", "slot", "build"):
            folder = self.root / scenario
            folder.mkdir()
            if scenario == "duplicate":
                (folder / "boot_a.img").write_bytes(boot())
                (folder / "boot_b.img").write_bytes(boot())
            elif scenario == "slot":
                (folder / "boot_a.img").write_bytes(boot())
                (folder / "vendor_boot_b.img").write_bytes(vendor_boot())
            else:
                (folder / "build1").mkdir()
                (folder / "build2").mkdir()
                (folder / "build1/boot.img").write_bytes(boot())
                (folder / "build2/vendor_boot.img").write_bytes(vendor_boot())
            result = self.run_folder(folder, scenario + "-output")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stderr)["state"], "selection-required")
            self.assertFalse((self.root / (scenario + "-output")).exists())

    def test_explicit_role_can_resolve_automatic_image_ambiguity(self):
        folder = self.root / "capture"
        folder.mkdir()
        for name in ("boot_a.img", "boot_b.img"):
            (folder / name).write_bytes(boot())
        result = self.run_folder(folder, extra=("--boot", str(folder / "boot_a.img")))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual(report["inputs"][0]["path"], str(folder / "boot_a.img"))

    def test_competing_extracted_kernels_fail_before_output(self):
        folder = self.root / "boot"
        folder.mkdir()
        for name in ("kernel", "Image"):
            (folder / name).write_bytes(b"different capture")
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "folder-output").exists())

    def test_image_only_folder_output_must_still_be_outside_input(self):
        folder = self.root / "capture"
        folder.mkdir()
        (folder / "boot.img").write_bytes(boot())
        result = self.run_folder(folder, "capture/output")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((folder / "output").exists())

    def test_discovery_limits_symlinks_empty_and_mixed_loose_builds(self):
        folder = self.root / "capture"
        folder.mkdir()
        with self.assertRaises(extract.ExtractionError):
            extract.discover(folder)
        (folder / "boot.img").symlink_to(self.root / "outside.img")
        with self.assertRaises(extract.ExtractionError):
            extract.discover(folder)
        for name in ("build1", "build2"):
            (folder / name).mkdir()
            (folder / name / "board.dtb").write_bytes(fdt())
        with self.assertRaises(extract.SelectionRequired):
            extract.discover(folder)
        with self.assertRaises(extract.ExtractionError):
            extract.discover(folder, max_entries=1)

    def test_extracted_slot_suffixes_are_not_mixed(self):
        folder = self.root / "capture"
        folder.mkdir()
        (folder / "boot_a_extracted").mkdir()
        (folder / "vendor_boot_b_extracted").mkdir()
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "folder-output").exists())
        self.assertEqual(extract.directory_role("boot_extracted_a"), "boot")

    def test_role_named_folder_containing_image_prefers_its_image(self):
        folder = self.root / "boot"
        folder.mkdir()
        (folder / "boot.img").write_bytes(boot())
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertIn("boot_layout", report["inputs"][0])

    def test_unrelated_extracted_system_vendor_is_not_a_second_capture(self):
        folder = self.root / "capture"
        folder.mkdir()
        (folder / "boot.img").write_bytes(boot())
        for role in ("vendor", "system_dlkm", "vendor_dlkm"):
            (folder / role).mkdir()
            (folder / role / "a.ko").write_bytes(b"module")
        unrelated = folder / "system_root/vendor"
        unrelated.mkdir(parents=True)
        (unrelated / "a.ko").write_bytes(b"unrelated module")
        (folder / "board.dtb").write_bytes(fdt())
        result = self.run_folder(folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "folder-output/extraction-report.json").read_text())
        self.assertEqual(report["summary"]["kinds"]["kernel-module"], 3)
        self.assertTrue(any(item["reason"] == "unrelated-extracted-partition-root" for item in report["discovery"]["skipped"]))
        self.assertFalse(any("system_root" in item["source"].get("directory_path", "") for item in report["artifacts"]))

    def test_empty_boot_init_boot_and_dtbo_payloads_are_partial(self):
        table = struct.pack(">8I", 0xd7b7ab1e, 32, 32, 32, 0, 32, 4096, 0)
        for label, data in (("boot", boot(kernel=b"")), ("init_boot", boot(kernel=b"")), ("dtbo", table)):
            path = self.root / (label + ".img")
            path.write_bytes(data)
            engine = extract.Extractor(self.root / (label + "-output"))
            engine.process(label, path)
            self.assertEqual(engine.report["inputs"][0]["state"], "partial", engine.report["inputs"][0])


if __name__ == "__main__":
    unittest.main()
