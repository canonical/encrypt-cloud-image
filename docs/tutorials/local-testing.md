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
- `virt-firmware`, provides the `virt-fw-vars` tool

```bash
sudo apt install -y tpm2-tools golang swtpm
```

```bash
pipx install virt-firmware
```

````{note}
`pipx install virt-firmware` can fail to build its `crypt_r` dependency if no C compiler is installed.
On recent Ubuntu releases you can install the `python3-virt-firmware` package instead:

```bash
sudo apt install -y python3-virt-firmware
```
````

```bash
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

There are two supported workflows for image provisioning. Please follow one of these depending on your intended scenario:

- [Provision an image for CVM with FDE](../how-to/encrypt-only.md)
- [Provision an image with OS disk integrity for ephemeral VMs](../how-to/integrity-only.md)

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

Start the vTPM in a separate terminal. QEMU needs swtpm to be started with only a control socket,
which is a different invocation from the one used with `tpm2-tools` during provisioning. Reuse the
same state directory (`/tmp/mytpm0`), because an FDE key is sealed to the SRK stored in it:

```bash
swtpm socket --ctrl type=unixio,path=/tmp/mytpm0/swtpm-sock.ctrl \
             --tpmstate dir=/tmp/mytpm0 \
             --tpm2
```

swtpm exits when QEMU exits, so start it again before each boot.

QEMU uses a local `OVMF_VARS_4M.ms.fd` copy of the UEFI variables:

- for an image provisioned for [CVM with FDE](../how-to/encrypt-only.md), use the copy that
  `uefi-config.json` was generated from. Don't overwrite it with a fresh copy, otherwise the FDE key
  can't be unsealed.
- for an [integrity-only image](../how-to/integrity-only.md), create the copy now:

  ```bash
  cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd .
  ```

Finally the customized image can be booted in QEMU with something like:

```bash
format="${FORMAT:-$(qemu-img info --output=json input.vhd | jq -r .format)}"

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

```{note}
On the first boot of the image, shim adds a boot entry and resets the system. If QEMU is started with
`-no-reboot`, it exits after a message like `BdsDxe: starting Boot0002 ... Reset System`. This is
expected, and boot entries aren't measured to PCR 7, so it doesn't affect unsealing. Start swtpm and
QEMU again to continue booting.
```

To connect to the running machine:

```bash
key=[path to the ssh key registered in your launchpad account]
ssh -i $key ubuntu@127.0.0.1 -p 2222

```

```{seealso}
For more information about the booting process as well as ways to verify the integrity of the rootfs, see [](../reference/architecture).
```
