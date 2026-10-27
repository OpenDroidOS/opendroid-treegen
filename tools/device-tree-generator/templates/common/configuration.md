# Common product configuration

## Product inheritance

Phone and tablet products select their OpenHarmony component set through the
device product's `base_product` input. The generator then adds `base.json` for
shared OpenDroidOS settings. Device-specific selections stay in the product's
`vendor/<company>/<product>/config.json`.

`system_profile: "base"` uses that component set directly. The optional `tablet`
profile also inherits OpenHarmony's `productdefine/common/inherit/tablet.json`,
followed by this repository's `tablet.json` for its build dependencies and
component overrides. This profile controls component selection; it does not
describe hardware compatibility.

## Feature options

Set `product_features` in the tree generator's device input. Omitted options use
the defaults in [product-features.json](../product-features.json).

| Option | Default | Effect when enabled |
| --- | --- | --- |
| `safwk_run_on_demand_qos` | `false` | Enable SAFWK's run-on-demand start QoS priority adjustment. |
| `hitrace_executable` | `true` | Build Hitrace command-line tools when `support_jsapi` is enabled. |

For example:

```json
{
  "product_features": {
    "safwk_run_on_demand_qos": true,
    "hitrace_executable": false
  }
}
```

Each option requires its native component to be selected. If applying a shared
default would replace additional inherited feature assignments or component
metadata, the generator requires an explicit choice and preserves that data
in the generated override.

## Prebuilt kernel setup

The device kernel repository supplies its prebuilt manifest, kernel requirements
and optional module load order. Its README provides the preparation command.

Run [scripts/stage_kernel.py](../scripts/stage_kernel.py) with `--prepare` to
validate those inputs and write a selection file outside the source checkout.
Pass its path to the build as the GN argument `opendroid_kernel_selection`.
Prepare a new selection after changing inputs or their paths. The build's
staging step revalidates the selected files and kernel requirements before
copying outputs. Run the script with `--help` for its arguments.
