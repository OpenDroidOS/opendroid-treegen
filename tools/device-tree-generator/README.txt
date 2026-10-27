OPENDROIDOS TREE GENERATOR
=========================
Generate OpenHarmony board and product configuration by default.
Requires Linux and Python3.9+.

USAGE
-----
Run from the repository root:

python3 -B tools/device-tree-generator/generate.py generate \
  --input /path/to/device-input.json \
  --source-root /path/to/openharmony \
  --output /path/to/new-tree --reports /path/to/new-reports

Copy examples/native-arm64.json and replace its values with device inputs.
Add --extracted /path/to/extractor-output
for each capture. An extraction-report.json path is also accepted.
Default output contains only the board and product. It uses common and SoC
configuration already present in --source-root; missing device kernel
integration is reported for separate completion. Add --bootstrap-platform to
also emit the existing SoC, kernel and shared-common starter templates.

INPUT
-----
schema_version: 3.
company,board,product: OEM namespace, board and product identifiers.
soc_company,soc: shared SoC namespace and family.
target_cpu: arm or arm64.
base_product: OpenHarmony component list for the device product.
system_profile: base uses that list and shared common settings; tablet also
adds the upstream tablet list and vendor/opendroid/common/tablet.json.
Phone and tablet products keep device-specific selections in their vendor
product configuration. See vendor/opendroid/common/docs/configuration.md for
the shared feature and kernel options.
init_mode: single-stage or two-stage; controls enable_ramdisk in the product.
native_config: hardware key, firmware directory, mounts, device permissions
and ext4 image budgets. Fields and types are shown in the example.
module_load_order: ordered module destinations from the private selection.
product_features: optional object mapping IDs in
`vendor/opendroid/common/product-features.json` to JSON Booleans. Omitted IDs
use shared defaults. `safwk_run_on_demand_qos` defaults to false; true enables
SAFWK's run-on-demand start QoS priority adjustment. `hitrace_executable`
defaults to true; true builds Hitrace executable tools when `support_jsapi` is
enabled. False disables those specific build behaviors. Choices require their
native component to be selected and do not establish device provider support.
If a shared default would replace additional inherited feature assignments or
component metadata, generation requires an explicit choice for that component;
the override preserves that data.

Names use lowercase letters, digits and underscores, starting with a letter.
Android logical/slotselect/avb fstab flags are rejected. Image sizes are byte
budgets; partition mappings and verified boot are separate configurations.
Mounts marked required need two-stage init. They also install in ramdisk at
/etc/fstab.required; other mounts stay in the vendor fstab. Kernel cmdline
ohos.required_mount entries take precedence over the required-fstab file.
Required mounts also need nofail: this native flag preserves mount errors.
Verify that the selected startup implementation propagates mount and root-switch
failures before relying on two-stage boot.
Two-stage root switching needs a required system mount at /usr. Its storage
drivers, filesystem support and early firmware must be available before vendor
modules or second-stage init jobs run.
When declared, the required /usr entry must precede other required mounts.
The native check flag does not guarantee fsck; wait is a bounded device wait.

OUTPUT
------
device/board/<company>/<board>: board configuration and native install targets.
vendor/<company>/<product>: product component selection and parameters.

With --bootstrap-platform, also emit:

device/soc/<soc_company>/<soc>: shared build settings and kernel requirements.
kernel/<company>/<board>: prebuilt manifest and staging targets. Payloads may
be tracked under prebuilt/ when their redistribution terms allow it and their
license/source attribution is included. The generated private/ ignore rule is
for local workspace data; it does not classify all kernel payloads as private.
Restricted inputs, local manifests and prepared machine-specific selections
belong outside the source checkout.
vendor/opendroid/common: shared configuration and staging helper.

Reports are written separately. Output directories must be new and outside
the source checkout and extraction directories. Existing files are preserved.
source-inspection.json records inspected source declarations and observed hashes.
Those hashes identify the inputs; they do not restrict generation to a snapshot.

PREBUILT SELECTION
-----------------
Create a JSON manifest with:
format_version1, state=selected, files with role,path,sha256,destination.
Include one kernel and one config. Optional roles: module,dtb,dtbo.
Paths are relative to the manifest directory. Use a checked-in manifest for
tracked payloads or a work-area manifest for local/restricted inputs.

Prepare a GN selection with vendor/opendroid/common/scripts/stage_kernel.py:

python3 vendor/opendroid/common/scripts/stage_kernel.py --prepare \
  --manifest kernel/opendroid/demo_board/prebuilts.json \
  --requirements device/soc/generic/generic_arm64/kernel/requirements.json \
  --additional-requirements kernel/opendroid/demo_board/requirements.json \
  --module-order kernel/opendroid/demo_board/module-order.json \
  --output /path/to/work/kernel-selection.json

For local inputs, replace the manifest argument with a work-area manifest.
Use the paths from the generated kernel README for another board. Set GN
argument opendroid_kernel_selection to the prepared JSON file. Keep
machine-specific origin and selection records outside the source checkout. GN
reads the selection without executing scripts. Staging revalidates its
descriptors and payloads. Prepare a new output file when inputs or source
paths change; existing descriptions are preserved.

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
Generation inspects product inheritance, selected component and feature names,
Python API declarations, GN templates and requested native init/fstab commands.
It reads the checkout without importing or executing its code. Missing required
interfaces fail before output is created. Declaration checks do not establish
GN dependency closure, compilation or hardware compatibility.

Legacy inputs may retain source_profile as a string. It is ignored and omitted
from normalized reports. No weekly profile is required.

python3 -B tools/device-tree-generator/generate.py check /path/to/tree \
  --reports /path/to/reports

python3 -B tools/device-tree-generator/validate_upstream.py \
  --source-root /path/to/openharmony --output /path/to/tree --reports /path/to/reports

python3 -B tools/device-tree-generator/validate_gn.py \
  --gn /path/to/gn --source-root /path/to/openharmony \
  --output /path/to/tree --reports /path/to/reports

python3 -B -m unittest discover -s tools/device-tree-generator

validate_upstream explicitly executes OpenHarmony product parsers from the
selected checkout in a fixture. validate_gn uses an
isolated GN/Ninja fixture with synthetic inputs and stand-in install templates.

Copyright2026OpenDroidOS. Apache-2.0; see LICENSE and NOTICE.
Build and native configuration contracts follow OpenHarmony.
