# OpenDroidOS tree generator

Extract device inputs and generate OpenHarmony board and product configuration.

```sh
./opendroid-treegen extract /path/to/capture --only kernel --only config \
  --output /path/to/new-extraction

./opendroid-treegen generate \
  --input /path/to/device-input.json \
  --source-root /path/to/openharmony \
  --output artifacts/example-tree --reports artifacts/example-reports
```

Use the supplied JSON example as the input format. Normal generation writes only
`device/board/<company>/<board>` and `vendor/<company>/<product>`, using shared
SoC/common configuration already installed in the source checkout. Add
`--bootstrap-platform` to create starter SoC, kernel and common integration too.

Extraction accepts images such as `boot.img`, `vendor_boot.img`, `dtbo.img`,
`vendor.img`, `system_dlkm.img` and `vendor_dlkm.img`, corresponding extracted
folders, or loose module/header/device-tree files. Supply the inputs needed for
the requested outputs; every image is not required. Repeat `--only` for
`kernel`, `config`, `dtb`, `dtbo`, `modules` or `headers`; omit it to extract all.
An extracted config comes from the kernel; the tool does not invent a defconfig.

Add `--extracted /path/to/new-extraction` to generation to inspect the extraction
report. Keep reports and machine-specific selections in the work area outside
source repositories. Output directories must be new; existing files are preserved.

`./opendroid-treegen check /path/to/tree --reports /path/to/reports` checks the
managed output files and executable modes. Driver integration, kernel/module
compatibility, image packaging and device validation remain separate steps.

Linux; Python 3.10+ for extraction, 3.9+ for generation. Details:
[generation](tools/device-tree-generator/README.txt) and
[extraction](tools/prebuilt-extractor/README.md).

Copyright 2026 OpenDroidOS. Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Built for [OpenHarmony](https://github.com/openharmony).
