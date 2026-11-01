# Kernel module plans

Check selected modules before adding their native init jobs. The tool is shared
by boards; it contains no Qualcomm model names, module lists or device paths.

```sh
./opendroid-treegen module-plan --manifest inputs/modules.json --output reports/modules
```

The JSON input has these fields:

```json
{
  "format_version": 1,
  "kernel": "Image",
  "config": "kernel.config",
  "builtins": "modules.builtin",
  "modules": [
    {"source": "display.ko", "destination": "modules/display.ko", "phase": "post-fs"}
  ],
  "firmware": [
    {"name": "qcom/display.bin", "source": "firmware/display.bin"}
  ]
}
```

Paths are relative to the input JSON, or absolute. Inputs remain in place.
Use `null` for `builtins` when no matching `modules.builtin` is supplied; a
missing dependency is then an error, not an inferred built-in. Requires kmod
`modinfo` and uncompressed ARM64 `.ko` files.

The configuration must exactly match the one embedded in the selected raw
ARM64 Image. Metadata checks compare full vermagic strings, resolve hard and
soft dependencies, reject cycles and providers scheduled after their consumers,
and require explicit files for firmware names declared by modules. A different
release can share a compatible KMI, but proving that requires symbol/version and
trust evidence outside this tool. It never requests forced module loading.

`report.json` records observations and gaps. Successful checks additionally emit
`module-order.json` for the kernel stager and `init.modules.cfg`. Install the
configuration through the board's native GN target. Module paths match the
existing `/vendor/lib/opendroid/<destination>` installation contract. Keep these
phase-specific jobs separate from the generator's legacy single `init` job.

Supported phases are `post-fs`, `post-fs-data` and `boot`. Storage drivers needed
to mount the root or vendor filesystem must instead be available in the first
stage ramdisk. A later init job cannot supply those prerequisites. The tool does
not install modules or firmware. Native `insmod` logs load failures; generated
commands do not establish successful initialization or stop later init jobs.

Matching metadata does not validate relocations, symbol CRCs, namespaces, trusted
module signatures, firmware completeness, probing, mount availability, permissions
or runtime behavior. Signature-enforcing kernels require a separate trusted-key
validation before this tool emits load commands.
