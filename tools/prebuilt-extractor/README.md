# Prebuilt capture extractor

Extract kernel payloads, embedded configs, DTB/DTBO entries, modules and
available header candidates from local device captures. The unified command is
available at the repository root:

```sh
./opendroid-treegen extract /path/to/capture --output /path/to/new-output
./opendroid-treegen extract /path/to/capture --only modules --only headers \
  --output /path/to/new-output
```

`--only` accepts `kernel`, `config`, `dtb`, `dtbo`, `modules` and `headers`;
repeat it to select multiple kinds. Full extraction is the default. Inputs that
cannot contain a selected kind are skipped, and selected kinds with no observed
candidate are reported as missing. Carrier bytes are temporarily read when
needed to derive a selected result; only selected artifact families are
written to the output directory. Loose `.config` and `config.gz` files are
emitted as config candidates, but do not satisfy the config selection status;
that status requires a configuration observed inside the kernel payload.

The input can be a folder containing `boot.img`, `init_boot.img`,
`vendor_boot.img`, `dtbo.img`, `dtb.img`, `vendor.img`, `system_dlkm.img` or
`vendor_dlkm.img`; correspondingly named extracted folders; or a directory with
loose modules, headers and device trees. Explicit role paths are available as
`--boot`, `--vendor-boot`, `--vendor`, and related options. Captures with
ambiguous slots or competing candidates require a narrower folder or explicit
role selection. Do not combine unrelated captures.

The output directory must be new, outside input folders, and have an existing
parent. `extraction-report.json` records local input paths, hashes and
limitations; keep this report with local working data rather than generated
source. Inputs are read without mounting or executing extracted files. This
does not establish module ABI compatibility or OpenHarmony runtime support.

Requires Linux and Python 3.10+. Ext4 images need `debugfs`; LZ4/Zstandard
streams need `lz4`/`zstd`. `modinfo` adds module metadata. EROFS, OTA packages
and super images are not unpacked. Header candidates do not reconstruct a
matching kernel build tree.

Run tests from this directory with `python3 -B -m unittest -v test_extract.py`.

Copyright 2026 OpenDroidOS. Apache-2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Built for [OpenHarmony](https://github.com/openharmony/docs)
porting.
