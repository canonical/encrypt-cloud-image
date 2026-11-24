(uefi-sb-extract-ppa-keys)=

# Extract a ppa's UEFI signing certificate

If you built your signed UKI in a ppa, it is possible to extract the uefi.crt from the secure boot
signed artifact.

```bash
wget http://ppa.launchpadcontent.net/sespiros/azure-cvm-rootfs-integrity/ubuntu/dists/noble/main/signed/linux-generate-azure-amd64/6.8.0-1014.16/signed.tar.gz
tar -xvzf signed.tar.gz
```

The signing certificate should be under `6.8.0-1014.16/control/uefi.crt`.

(custom-cert)=

# Enable secure boot with a custom cert

In order to allow your custom built image to be booted with secure boot using the tutorial in
[](../tutorials/local-testing.md), your own certificate needs to be added to the local
`OVMF_VARS_4M.ms.fd` copy. Do this right after copying the file and before booting it for the
first time:

```bash
owner=$(uuidgen)

virt-fw-vars -i OVMF_VARS_4M.ms.fd --add-db $owner uefi.crt -o custom_vars.ms.fd
mv custom_vars.ms.fd OVMF_VARS_4M.ms.fd
```

For the encrypted image case, then continue with [](../how-to/encrypt-only.md): boot the copy once
and generate `uefi-config.json` from it. Because the whole `db` variable is taken from the copy, the
UEFI configuration used for sealing the key already includes your certificate, and no separate step
is needed for it.
