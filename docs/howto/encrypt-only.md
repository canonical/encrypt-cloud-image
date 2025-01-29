# Provision an image for CVM with FDE

This workflow describes the image provisioning process for a confidential
VM using FDE. The FDE operations are backed by a vTPM which is required for
booting. The process is split in 2 parts:
- encrypting the rootfs and then
- restrict usage of the FDE key to systems that match a specific system
   state (sealing) using the vTPM.

The following sections describe the provisioning process for a local QEMU VM.

## Encrypt the rootfs
The first step is done using the [](../reference/encrypt.md) command:
```bash
sudo encrypt-cloud-image encrypt -o encrypted.vhd \
                                 --override-datasources "NoCloud" \
                                 input.vhd
```

## Bind FDE key to a virtual TPM
The second step is done using the [](../reference/deploy.md) command. There are 2
prerequisites:
1. creation of the SRK template that will be used by the Guest's vTPM.
2. creation of the guest UEFI configuration parameters in order to seal the FDE key
  to the QEMU vm's secure boot variables.


### 1. Setting up a vTPM and generating an SRK primary key

Using swtpm this is an example invocation to get a software TPM up and running:

```bash
mkdir /tmp/mytpm0
swtpm socket --server type=unixio,path=/tmp/mytpm0/swtpm-sock \
             --ctrl type=unixio,path=/tmp/mytpm0/swtpm-sock.ctrl,mode=0600 \
             --tpmstate dir=/tmp/mytpm0 \
             --tpm2 \
             --flags not-need-init,startup-clear
```

To create an SRK:
```bash
export TPM2TOOLS_TCTI="swtpm:path=/tmp/mytpm0/swtpm-sock"
tpm2_createprimary -c srk.ctx
tpm2_readpublic -c srk.ctx -o srk.pub
```

### 2. Preparing the guest's UEFI configuration

QEMU and OVMF is used for local testing. In order to create the guest's UEFI configuration:

- copy the `OVMF_VARS_4M.ms.fd` UEFI variables locally so that they can be modified if needed

```bash
cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd .
```

- use `virt-fw-vars` to extract the certificates

```bash
mkdir certs
cd certs
virt-fw-vars -i ../OVMF_VARS_4M.ms.fd --extract-certs
cd ..
```

```{note}
`--extract-certs` doesn't support extraction of EFI signature lists of type other than X509 and
OVMF_VARS_4M.ms.fd also contains a dbx which contains an EFI signature list of type SHA256 which
contains a SHA256 hash of an empty file. This needs to also be extracted separately:

```bash
# This is extracted using
#
# virt-fw-vars -i ../OVMF_VARS_4M.ms.fd --output-json vars.json
#
# then extracting the data field of the dbx variable to a separate file i.e dbx
#
# cat dbx | xxd -r -p | base64
db="JhbEwUxQkkCsqUH5NpNDKEwAAAAAAAAAMAAAAKOouqAdBKhIvIfDbRIbXj3jsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ=="
echo $db | base64 -d > certs/dbx-sha256-of-emptyfile.esl
```

- convert the pem certificates to EFI signature lists

```{caution}
Order matters when combining the EFI signature lists. A wrong order can lead to the key not being able
to be unsealed and a prompt for a recovery key when booting.
```

```bash
globalvar="8be4df61-93ca-11d2-aa0d-00e098032b8c"
msguid="77fa9abd-0359-4d32-bd60-28f4e78f784b"
rhguid="a0baa8a3-041d-48a8-bc87-c36d121b5e3d"

cert-to-efi-sig-list -g $globalvar certs/PK-$globalvar-UbuntuOVMFSecureBootPKKEKkey.pem certs/PK.esl
cert-to-efi-sig-list -g $msguid certs/db-$msguid-MicrosoftWindowsProductionPCA2011.pem certs/db-1.esl
cert-to-efi-sig-list -g $msguid certs/db-$msguid-MicrosoftCorporationUEFICA2011.pem certs/db-2.esl
cert-to-efi-sig-list -g $rhguid certs/KEK-$rhguid-UbuntuOVMFSecureBootPKKEKkey.pem certs/KEK-1.esl
cert-to-efi-sig-list -g $msguid certs/KEK-$msguid-MicrosoftCorporationKEKCA2011.pem certs/KEK-2.esl
```

- Call the `create-uefi-config` tool (part of `encrypt-cloud-image`)

```bash
create-uefi-config -i uefi-config.json -i certs
```

---

Finally the deploy command can be called to create the final TPM bound image:
```bash
sudo encrypt-cloud-image deploy --srk-pub srk.pub \
                                --uefi-config uefi-config.json \
                                --add-efi-secure-boot-profile \
                                encrypted.vhd

# This is the final image
mv encrypted.vhd final.vhd
```

For more information about each command and their arguments please refer to their respective
[reference pages](../reference/index).

For more information about the booting process, see [](../reference/architecture).
