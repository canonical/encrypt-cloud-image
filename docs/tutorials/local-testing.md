(local-testing)=
# Local provisioning and booting with QEMU tutorial

This tutorial describes how to provision an Ubuntu image with the
`encrypt-cloud-image` tool for various different scenarios.

## Runtime prerequisites
- Ubuntu environment
- root privileges (required to create NBD devices, use /dev/mapper/control and mount block devices)
- cryptsetup (>= 2.2.0)
   - Available from Ubuntu archive on 20.04 LTS and later
   - For Ubuntu 18.04 LTS backport is available from
        ```
        sudo add-apt-repository ppa:canonical-kernel-team/azure-test
        sudo apt-get update
        sudo apt install cryptsetup
        ```
- qemu-utils
- cloud-guest-utils (for growpart)

## Installing dependencies
First install dependencies that are needed:
- `golang`, necessary for the `encrypt-cloud-image` tool
- `swtpm`, provides a vTPM implementation
- `tpm2-tools`, client library used to communicate with the vTPM
- `efitools`, provides the `cert-to-efi-sig-list` tool
- `virt-firmware`, provides the `virt-fw-vars` tool

```bash
sudo apt install -y tpm2-tools golang swtpm efitools
```

```bash
pipx install virt-firmware
```

```bash
go install github.com/canonical/encrypt-cloud-image/create-uefi-config@latest
go install github.com/canonical/encrypt-cloud-image@latest
```

## Getting a source image

The type of image that is used as a source in the `encrypt-cloud-image` tool
is an image which boots the kernel directly as a UKI with special logic in the
initramfs to handle the mounting and TPM measurement operations
(See [](../reference/architecture.md) for more details. You can ask
CPC to provide an initial image to you or build one yourself using the instructions
in [](../explanation/building.md).

## Provision the image

```{important}
If you are building a custom image you need to modify the instructions below using
the instructions from [](custom-cert)
```

````{tabs}

:::{group-tab} CVM with FDE
```{include} ../howto/encrypt-only.md
```
:::

:::{group-tab} Ephemeral VM with rootfs integrity
```{include} ../howto/integrity-only.md
```
:::

````

## Create cloud-init metadata
To create the cloud-init seed partition (replace your launchpad user):
```bash
cat << EOF > user-data.yaml
#cloud-config
ssh_import_id: [<YOUR USERNAME>]
EOF

cloud-localds seed.img user-data.yaml
```

## Boot the image in QEMU

Finally the customized image can be booted in QEMU with something like:

```bash
format="${FORMAT:-$(qemu-img info --output=json input.vhd | jq -r .format)}"

cp /usr/share/OVMF/OVMF_VARS_4M.fd .

qemu-system-x86_64 -cpu host \
                   -machine type=q35,accel=kvm \
                   -m 2048 \
                   -nographic \
                   -netdev id=net00,type=user,hostfwd=tcp::2222-:22 \
                   -device virtio-net-pci,netdev=net00 \
                   -drive if=virtio,format=$format,file=final.vhd \
                   -drive if=virtio,format=raw,file=seed.img \
                   -drive if=pflash,format=raw,file=/usr/share/OVMF/OVMF_CODE_4M.ms.fd,readonly=true \
                   -drive if=pflash,format=raw,file=OVMF_VARS_4M.ms.fd \
                   -chardev socket,id=chrtpm,path=/tmp/mytpm0/swtpm-sock.ctrl \
                   -tpmdev emulator,id=tpm0,chardev=chrtpm \
                   -device tpm-tis,tpmdev=tpm0
```

To connect to the running machine:

```bash
key=[path to the ssh key registered in your launchpad account]
ssh -i $key ubuntu@127.0.0.1 -p 2222

```

```{seealso}
For more information about the booting process as well as ways to verify the integrity of the rootfs, see [](../reference/architecture).
```
