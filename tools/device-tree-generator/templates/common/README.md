# OpenDroid common configuration

Shared OpenHarmony product settings, distribution parameters and kernel staging
for OpenDroidOS. Each device product selects its components and feature overrides.

Source synchronization is configured by
[OpenDroidOS/manifest](https://github.com/OpenDroidOS/manifest), using the
`opendroid-7.0` branch. Board, kernel and device vendor repositories are cloned
or created separately by the porter.

See the [configuration reference](docs/configuration.md) for product inheritance,
feature options and prebuilt kernel setup.
