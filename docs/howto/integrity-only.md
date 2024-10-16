# Provision an image with OS disk integrity for ephemeral VMs

The workflow describes the image provisioning process for an image with a dm-verity
protected rootfs. The resulting image is an image which mounts the rootfs using an overlayfs
with 2 layers. An unencrypted but dm-verity protected read-only partition as the lower layer
and an tmpfs-based writable partition as the upper one.

To produce such an image from a source image the following steps are required:

1. invoke `integrity-protect` to create a verity partition:
```bash
# needs sudo for mount permissions
sudo encrypt-cloud-image integrity-protect input.vhd -o final.vhd

# ensure the image is owned by your user
sudo chown `whoami` final.vhd
```

For more information about each command and their arguments please refer to their respective
[reference pages](../reference/index).

For more information about the booting process, see [](../reference/architecture.md).

````{note}
Although setting up a vTPM is not a requirement for the provisioning process of an integrity-protected only image,
an image like this is booted using a manifest to retrieve partition information and the dm-verity root hash of the
root partition. This manifest will also be measured to a vTPM if one is available.

You can run a vTPM such as swtpm:

```bash
mkdir /tmp/mytpm0
swtpm socket --server type=unixio,path=/tmp/mytpm0/swtpm-sock \
             --ctrl type=unixio,path=/tmp/mytpm0/swtpm-sock.ctrl,mode=0600 \
             --tpmstate dir=/tmp/mytpm0 \
             --tpm2 \
             --flags not-need-init,startup-clear
```

A primary key also needs to be initialized:

```bash
export TPM2TOOLS_TCTI="swtpm:path=/tmp/mytpm0/swtpm-sock"
tpm2_createprimary
```

````
