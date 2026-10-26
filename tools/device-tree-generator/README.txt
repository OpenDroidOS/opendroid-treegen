OPENDROIDOS TREE GENERATOR
=========================
Generate OpenHarmony board, SoC, kernel and product configuration.
Requires Linux and Python3.9+.

USAGE
-----
Run from the repository root:

python3 -B tools/device-tree-generator/generate.py generate \
  --input tools/device-tree-generator/examples/native-arm64.json \
  --source-root /path/to/openharmony \
  --output /path/to/new-tree --reports /path/to/new-reports

Replace example values with device inputs. Add --extracted /path/to/extractor-output
for each capture. An extraction-report.json path is also accepted.

INPUT
-----
schema_version: 3.
company,board,product: OEM namespace, board and product identifiers.
soc_company,soc: shared SoC namespace and family.
target_cpu: arm or arm64.
source_profile: weekly_20261026.
system_profile: base or tablet component selection.
Tablet products inherit vendor/opendroid/common/tablet.json after the upstream
tablet list. It selects IDL, Taihe, SDK and HAP build components, excludes the
unavailable eudev/libsnd entries and corrects access_token_enhance_capability.
init_mode: single-stage or two-stage; controls enable_ramdisk in the product.
native_config: hardware key, firmware directory, mounts, device permissions
and ext4 image budgets. Fields and types are shown in the example.
module_load_order: ordered module destinations from the private selection.

Names use lowercase letters, digits and underscores, starting with a letter.
Android logical/slotselect/avb fstab flags are rejected. Image sizes are byte
budgets; partition mappings and verified boot are separate configurations.
Mounts marked required need two-stage init. They also install in ramdisk at
/etc/fstab.required; other mounts stay in the vendor fstab. Kernel cmdline
ohos.required_mount entries take precedence over the required-fstab file.
Required mounts also need nofail: this native flag preserves mount errors.
The pinned early-init code checks negative returns; positive errno paths still
need error-handling integration before mount failures reliably abort startup.
Two-stage root switching needs a required system mount at /usr. Its storage
drivers, filesystem support and early firmware must be available before vendor
modules or second-stage init jobs run.
When declared, the required /usr entry must precede other required mounts.
The native check flag does not guarantee fsck; wait is a bounded device wait.

OUTPUT
------
device/board/<company>/<board>: board configuration and native install targets.
device/soc/<soc_company>/<soc>: shared build settings and kernel requirements.
kernel/<company>/<board>: private prebuilt selection and staging targets.
vendor/<company>/<product>: product component selection and parameters.
vendor/opendroid/common: shared configuration and staging helper.

Reports are written separately. Output directories must be new and outside
the source checkout and extraction directories. Existing files are preserved.

PREBUILT SELECTION
-----------------
Create a private JSON manifest:
format_version1, state=selected, files with role,path,sha256,destination.
Include one kernel and one config. Optional roles: module,dtb,dtbo.
Paths are relative to the manifest directory.

Prepare a GN selection with vendor/opendroid/common/scripts/stage_kernel.py:

python3 vendor/opendroid/common/scripts/stage_kernel.py --prepare \
  --manifest /path/to/private/prebuilts.json \
  --requirements device/soc/generic/generic_arm64/kernel/requirements.json \
  --additional-requirements kernel/opendroid/demo_board/requirements.json \
  --module-order kernel/opendroid/demo_board/module-order.json \
  --output /path/to/private/selection.json

Use the paths from the generated kernel README for another board. Set GN
argument opendroid_kernel_selection to the prepared JSON file. GN reads it
without executing scripts. Staging revalidates its descriptors and payloads.
Prepare a new output file when inputs or source paths change; existing
descriptions are preserved.

The staging helper checks hashes and kernel options. Modules install under
/vendor/lib/opendroid/<destination>; module_load_order generates native insmod
commands. Module dependencies and ABI require a matching selected set.
Two-stage boards add requirements.json for built-in initramfs/gzip support;
required ext4 mounts also require built-in ext4. Board requirements intersect
the shared SoC requirements and cannot weaken them. The helper accepts repeated
--additional-requirements paths for the same intersection outside GN.
Required values can be y, m or n. Disabled options must appear explicitly in
the config, for example "# CONFIG_NAME is not set". Two-stage boards require
INITRAMFS_FORCE disabled.

CHECKS
------
python3 -B tools/device-tree-generator/generate.py check /path/to/tree \
  --reports /path/to/reports

python3 -B tools/device-tree-generator/validate_upstream.py \
  --source-root /path/to/openharmony --output /path/to/tree --reports /path/to/reports

python3 -B tools/device-tree-generator/validate_gn.py \
  --gn /path/to/gn --output /path/to/tree --reports /path/to/reports

python3 -B -m unittest discover -s tools/device-tree-generator

validate_upstream uses OpenHarmony product parsers. validate_gn uses an
isolated GN/Ninja fixture with synthetic inputs and stand-in install templates.

Copyright2026OpenDroidOS. Apache-2.0; see LICENSE and NOTICE.
Build and native configuration contracts follow OpenHarmony.
