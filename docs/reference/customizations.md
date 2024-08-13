(customizations)=
# Customizations

Images that are generated using `encrypt-cloud-image` subcommands, contain
the following additional customizations:

## Disabling of secureboot-db.service

systemd's `secureboot-db.service` is disabled on images produced by the tool.

## manifest.json

Images produced by the tool which use the `integrity-protect` subcommand, will contain
a manifest in the ESP partition under `EFI/ubuntu/manifest.json`. This file contains
information about which partitions should be mounted on boot. Please refer to
[](../reference/integrity-protect.md) for more information.
