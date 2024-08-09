(local-testing)=
# Local provisioning and booting with QEMU tutorial

This tutorial describes how to provision an Ubuntu image with the
`encrypt-cloud-image` tool for various different scenarios.

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
initramfs to handle the mounting and TPM measurement operations. You can ask
CPC to provide an initial image to you or build one yourself using the instructions
in [](../explanation/building.md). See [](../reference/architecture.md) for
more details.

## Provision the image

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

## Boot the image in QEMU

