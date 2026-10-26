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

"""OpenDroidOS: check scaffold identities with pinned upstream parsers in a fixture."""

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace

import generate


def required_fstab_destination(source, data):
    """Resolve first-stage installation with the actual upstream metadata helper."""
    if not any("required" in mount["manager_flags"]
               for mount in data.get("native_config", {}).get("mounts", [])):
        return []
    path = source / "build/templates/metadata/gen_module_info.py"
    spec = importlib.util.spec_from_file_location("opendroid_upstream_module_info", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bases = {name + "_base_dir": name for name in (
        "system", "ramdisk", "vendor", "updater", "updater_vendor", "sys_prod", "chip_prod",
        "eng_system", "eng_chipset", "cloud_rom")}
    destinations = module.gen_install_dests(
        **bases, source_file_name="fstab.required", install_images=["ramdisk"],
        module_install_dir="", relative_install_dir="", module_type="etc")
    if destinations != ["ramdisk/etc/fstab.required"]:
        raise generate.InputError("Upstream metadata no longer installs the required fstab at the early-init path")
    return destinations


def validate(source, output, reports=None):
    sys.dont_write_bytecode = True
    reports = generate.report_root(output, reports)
    data = generate.read_json(reports / "porting-input.json")
    profile = generate.validate_input(data)
    generate.verify_source(source, profile)
    generate.check(output, reports)

    # Fail if an imported parser attempts to write the owner's source tree.
    def audit(event, args):
        if event == "open":
            path, mode, flags = args
            writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            if writing and isinstance(path, (str, bytes)):
                if Path(os.fsdecode(path)).resolve().is_relative_to(source):
                    raise PermissionError("Parser attempted a source-checkout write")

    sys.addaudithook(audit)
    sys.path[:0] = [str(source / "build"), str(source / "build/hb")]
    import containers.status as status
    # Its stock exception decorator writes failure logs. Keep parser exceptions
    # visible without running that unrelated build-session logging path.
    status.throw_exception = lambda function: function
    import resources.config as config_module
    from util.log_util import LogUtil
    warnings = []
    LogUtil.hb_warning = lambda message, *args, **kwargs: warnings.append(str(message))

    with tempfile.TemporaryDirectory(prefix=".parser-fixture-", dir=output.parent) as temporary:
        root = Path(temporary)
        for name in ("device", "vendor", "kernel"):
            shutil.copytree(output / name, root / name)
        base = root / data["base_product"]
        base.parent.mkdir(parents=True)
        shutil.copyfile(source / data["base_product"], base)
        if data.get("system_profile") == "tablet":
            inherit = Path("productdefine/common/inherit/tablet.json")
            (root / inherit).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / inherit, root / inherit)
        company, product = data["company"], data["product"]
        product_path = f"vendor/{company}/{product}"
        fixture_config = SimpleNamespace(
            product=product, product_json=str(root / product_path / "config.json"),
            target_cpu="", target_os="", compile_config="",
            gn_product_path="//" + product_path, product_config_path="//" + product_path,
            config_json=str(root / "fixture-config.json"), compile_mode="cross", os_level="standard",
            root_path=str(root), vendor_path=str(root / "vendor"),
            built_in_product_path=str(root / "productdefine/common/products"),
            built_in_product_path_for_llvm=str(root / "productdefine/common/llvm-products"),
        )
        Path(fixture_config.config_json).write_text("{}")
        # Never instantiate the real Config: its constructor/setters write out/.
        config_module.Config = lambda: fixture_config
        from util.preloader.preloader_process_data import Product
        from util.loader.load_bundle_file import BundlePartObj
        import util.product_util as product_util
        product_util.Config = lambda: fixture_config
        (root / "productdefine/common/products").mkdir(parents=True)
        discovered = [p for p in product_util.ProductUtil.get_products() if p["name"] == product]
        if len(discovered) != 1 or discovered[0]["company"] != company:
            raise generate.InputError("Native hb product discovery did not find the namespaced product")
        device_info = product_util.ProductUtil.get_device_info(discovered[0]["config"])
        expected_board = str(root / f"device/board/{company}/{data['board']}")
        if device_info["board_path"] != expected_board:
            raise generate.InputError("Native hb resolved an unexpected board path")
        compiler = product_util.ProductUtil.get_compiler(expected_board)
        if compiler != "clang":
            raise generate.InputError("Native hb did not discover the board's clang toolchain")
        dirs = SimpleNamespace(
            source_root_dir=str(root), built_in_product_dir=str(root / "productdefine/common/products"),
            built_in_base_dir=str(base.parent), vendor_dir=str(root / "vendor"), device_dir=str(root / "device"),
        )
        parsed = Product(dirs, fixture_config)
        identities = [f"device_{data['board']}", f"product_{product}"]
        subsystems = {**parsed._get_device_specific_subsystem(), **parsed._get_product_specific_subsystem()}
        empty = root / "empty.json"
        empty.write_text("{}")
        results = []
        for identity in identities:
            if f"{identity}:{identity}" not in parsed._parts:
                raise generate.InputError(f"Upstream did not select expected part {identity}")
            path = subsystems[identity]["path"]
            bundle = root / path / "bundle.json"
            converted = BundlePartObj(str(bundle), str(empty), str(empty), False).to_ohos_build()
            if converted["subsystem"] != identity or identity not in converted["parts"]:
                raise generate.InputError(f"Upstream bundle identity mismatch: {identity}")
            labels = converted["parts"][identity]["module_list"]
            expected = "board" if identity.startswith("device_") else "product"
            if labels != [f"//{path}:{expected}"]:
                raise generate.InputError(f"Upstream entry target differs: {identity}")
            results.append({"identity": identity, "module_list": labels})
        if parsed._build_vars["target_cpu"] != data["target_cpu"]:
            raise generate.InputError("Upstream userspace architecture differs")
        if parsed._build_vars["build_selinux"] is not True:
            raise generate.InputError("SELinux build selection was lost")
        if parsed._build_vars.get("enable_ramdisk") != (data["init_mode"] == "two-stage"):
            raise generate.InputError("Native preloader lost the declared init/ramdisk mode")
        if data.get("system_profile") == "tablet":
            for part in ("multimodalinput:input", "arkui:ace_engine", "graphic:graphic_surface",
                         "ability:idl_tool", "arkcompiler:taihe_ffi_gen", "sdk:sdk"):
                if part not in parsed._parts:
                    raise generate.InputError(f"Tablet inheritance lost required userspace part {part}")
            for part in ("thirdparty:eudev", "thirdparty:libsnd"):
                if part in parsed._parts:
                    raise generate.InputError(f"Tablet inheritance retained an unavailable component: {part}")
            features = parsed._parts["security:access_token"].get("features", {})
            if features != {"access_token_enhance_capability": False}:
                raise generate.InputError("Tablet access-token feature differs from the native component declaration")
        return {
            "result": "pass", "scope": "Actual Product and BundlePartObj parsing in isolated fixture",
            "source_profile": profile["id"], "parts_selected": len(parsed._parts),
            "native_product_discovery": "pass", "native_board_resolution": device_info["board_path"].replace(str(root) + "/", ""),
            "native_board_compiler": compiler,
            "enable_ramdisk": parsed._build_vars["enable_ramdisk"],
            "required_fstab_install_destinations": required_fstab_destination(source, data),
            "components": results, "warnings": warnings,
            "config_singleton": "replaced by in-memory fixture to avoid source writes",
            "exception_logging": "disabled; exceptions propagate",
            "gn": "not-run", "build": "not-run", "device": "not-tested",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reports", type=Path)
    args = parser.parse_args()
    try:
        print(generate.json_text(validate(args.source_root.resolve(), args.output.resolve(), args.reports)), end="")
    except (OSError, ValueError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
