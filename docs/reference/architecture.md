(architecture)=
# Architecture

`encrypt-cloud-images` expects as input Ubuntu cloud images with the following characteristics:
- come in vhd format
- boot the kernel directly from UEFI using a UKI (without GRUB)

The kernel UKI contains the kernel image and initrd in one EFI artifact signed for secure boot.
The initrd that is used is generated by [](https://github.com/snapcore/core-initrd). This includes
some of the logic that runs during the initramfs stage with `snap-bootstrap` containing most of it,
and several other systemd services and scripts containing the rest. `core-initrd` sets the kernel
cmdline with `snapd_recovery_mode=cloudimg-rootfs` for certain kernel flavors as post installation
script.

## Default CVM mode (gen1)
`snap-bootstrap` is [part of the snapd repo](https://github.com/canonical/snapd/tree/master/cmd/snap-bootstrap)
and is responsible (among others) for setting up the partitions, including communications with the TPM,
unsealing operations etc. Currently it contains a special mode for confidential VMs which is triggered when
`snapd_recovery_mode=cloudimg-rootfs` is found in the kernel cmdline.

In the default CVM mode, `snap-bootstrap` will perform the following:
- try and provision an available TPM using an SRK template file under a fixed path in the ESP (`tpm2-srk.tmpl`).
After provisioning the template file is deleted.
- try and unseal the FDE key for the rootfs using a key that is saved in a sealed blob in the ESP under `ESP/device/fde/cloudimg-rootfs.sealed-key`.
- decrypt the rootfs and continue booting.


## Manifest CVM mode (gen2)
CVM mode also supports mounting of an unencrypted rootfs which is integrity protected using a manifest from the ESP.
This manifest is generated using [](../reference/integrity-protect)) and contains the dm-verity root hash of the
rootfs partition. `snap-bootstrap` will parse information for the manifest and perform the following:
1. if only one partition is detected in the manifest, this partition is also required to have a dm-verity root hash
and will be mounted by `snap-bootstrap` using overlayfs. A tmpfs-based writable upper layer will be automatically
created to contain the writable state of the system. This mode essentially enables ephemeral VMs with an integrity
protected rootfs.
2. if a second partition is also included in the manifest, it will be used as a persistent writable layer. The
`encrypt` subcommand can then be used to encrypt the persistent writable partition the same way as in the default CVM
mode.

This manifest is signed with a private key whose public counterpart along with its signature can be found next to the
manifest file. `snap-bootstrap` will verify the manifest's signature and then measure the signing key to the TPM in
PCR 12.

For both of the above cases, it is assumed that there exists a remote attestation step that verifies that the system
is booted using a manifest that is considered trusted. That is by verifying that the manifest used was signed with a key
that is owned by the image user using a TPM quote.

```{important}
WIP: Support for this is not yet added as this requires integration with systemd's TCG log in order to log the measurement of
the aforementioned public key. For an example of how this verification can currently be done check
[](../explanation/verify-rootfs-integrity)
```

## FDE key unsealing

The [](../reference/deploy.md) command is used to seal the FDE key to a specific TPM using several different profiles and
stores it in the ESP. The sealed key will be only unsealed if the specific TPM is present when the system boots and if the
system matches the specific configuration as defined by the profiles.

`snap-bootstrap` performs the unsealing operations for keys matching (using their partition label) encrypted partitions on
the disk.


