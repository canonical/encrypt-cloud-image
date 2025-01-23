(command-integrity-protect)=
# `integrity-protect`

Basic usage:
```bash
encrypt-cloud-image integrity-protect input.vhd
```

This command expects an input vhd file which contains the following 3 partitions:
```
$ sgdisk input.vhd --print

Disk input.vhd: 62916609 sectors, 30.0 GiB

...<snip>...

Number  Start (sector)    End (sector)  Size       Code  Name
   1         2107392         8388574   3.0 GiB     8300
  14            2048           10239   4.0 MiB     EF02
  15           10240         2107391   1024.0 MiB  EF00
```
`integrity-protect` will:
- apply some customizations to the rootfs. See section [Customizations](customizations.md).
- shrink the filesystem of the rootfs (partition 1).
- re-create the root partition to fit the shrunk filesystem.
- create dm-verity data for the rootfs partition.
- append a new partition for the dm-verity data physically located after the rootfs.
- create a manifest file which will be used on boot in order to mount the partitions.
- place the manifest in the ESP partition next to the kernel UKI.

This is the resulting image:
```
$ sgdisk input.vhd --print
Disk input.vhd: 62916609 sectors, 30.0 GiB

...<snip>...

Number  Start (sector)    End (sector)  Size       Code  Name
   1         2107392         6182911   1.9 GiB     8300  cloudimg-rootfs
   2         6182912         6215023   15.7 MiB    830C  cloudimg-rootfs-verity
  14            2048           10239   4.0 MiB     EF02
  15           10240         2107391   1024.0 MiB  EF00
```
and an example manifest:
```bash
$ cat esp/EFI/ubuntu/manifest.json | jq
```
```json
{
  "partitions": [
    {
      "label": "cloudimg-rootfs",
      "root_hash": "11c983ad490fdcd57e554a73926ae0038510f5bc6945acda487c1f14df30e139",
      "overlay": "lowerdir"
    }
  ]
}
```

An image that is integrity protected is meant to be booted using an overlayfs mount for
the rootfs which uses a read-only dm-verity protected partition as the lower filesystem
and a tmpfs-based writable partition for the upper. See [](../reference/architecture.md)
for more information.

## Using a writable partition

Example usage:
```bash
encrypt-cloud-image integrity-protect --writable input.vhd
```

The `integrity-protect` command supports an optional `--writable` argument which will also
create a fixed size 1GB writable partition, physically located after the verity one:
```
$ sgdisk input.vhd --print
Disk input.vhd: 62916609 sectors, 30.0 GiB

...<snip>...

Number  Start (sector)    End (sector)  Size       Code  Name
   1         2107392         6178815   1.9 GiB     8300  cloudimg-rootfs
   2         6178816         6210895   15.7 MiB    830C  cloudimg-rootfs-verity
   3         6211584         8308735   1024.0 MiB  8300  writable
  14            2048           10239   4.0 MiB     EF02
  15           10240         2107391   1024.0 MiB  EF00
```

with the following manifest file:
```bash
$ cat esp/EFI/ubuntu/manifest.json | jq
```
```json
{
  "partitions": [
    {
      "label": "cloudimg-rootfs",
      "root_hash": "af98ebd232aec8b99e8830429decb752aec4629cf3de2d2618f5cce1d1facd25",
      "overlay": "lowerdir"
    },
    {
      "label": "writable",
      "root_hash": "",
      "overlay": "upperdir"
    }
  ]
}
```

This will instruct the booting process to use the writable partition from the disk instead of
an ephemeral tmpfs one. See [](../reference/architecture.md) for more information.

```{important}
For the confidential computing model, the writable partition must also be encrypted. This is WIP.
```

## Options

### Override cloud-init datasources
It may be desirable to override an image's enabled cloud-init datasources to facilitate debugging the final image in QEMU.
To enable only the NoCloud datasource so that an image can be initialized with user data from a separate seed image:
```bash
$ sudo encrypt-cloud-image integrity-protect \
                                    --override-datasources "NoCloud" \
                                    <input_image>
```
The `--override-datasources` option takes a comma-delimited list of datasources.
