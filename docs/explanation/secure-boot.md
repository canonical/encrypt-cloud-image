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
[](../tutorials/local-testing.md), several more steps are required.

Before the `--extract-certs` step you should include your own certificate in the `OVMF_VARS_4M.ms.fd` file:
```bash
owner=$(uuidgen)

virt-fw-vars -i OVMF_VARS_4M.ms.fd --add-db $owner uefi.crt -o custom_vars.ms.fd
```

Also for the encrypted image case, the certificate should be included in the uefi configuration for the key sealing so
before the `create-uefi-config` step, you need to manually create your cert's esl file:
```bash
cert-to-efi-sig-list -g $owner certs/db-$owner-testUEFI.pem certs/db-3.esl
```
