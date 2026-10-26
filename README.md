# OpenDroidOS tree generator

Generate OpenHarmony board, SoC, kernel and product configuration.

```sh
python3 -B tools/device-tree-generator/generate.py generate \
  --input tools/device-tree-generator/examples/native-arm64.json \
  --source-root /path/to/openharmony \
  --output artifacts/example-tree --reports artifacts/example-reports
```

Replace the example values with device inputs. Add
`--extracted /path/to/extractor-output` to read extractor results.
Output directories must be new. Kernel staging requires a prepared private selection.

Linux and Python 3.9+. Details: [generator README](tools/device-tree-generator/README.txt).

Copyright 2026 OpenDroidOS. Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Built for [OpenHarmony](https://github.com/openharmony).
