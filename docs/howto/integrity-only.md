# Provision an image with OS disk integrity for ephemeral VMs

The workflow describes the image provisioning process for an image with a dm-verity
protected rootfs. The resulting image is an image which mounts the rootfs using an overlayfs
with 2 layers. An unencrypted but dm-verity protected read-only partition as the lower layer
and an tmpfs-based writable partition as the upper one.

To produce such an image from a source image the following steps are required:

1. invoke `integrity-protect` to create a verity partition:
```bash
sudo encrypt-cloud-image integrity-protect input.vhd

# This is the final image
mv input.vhd final.vhd
```

For more information about each command and their arguments please refer to their respective
[reference pages](../reference/index).

For more information about the booting process, see [](../reference/architecture.md).
