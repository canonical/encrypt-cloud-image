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

- boot a VM once with this copy, for example a stock Ubuntu cloud image, using the
  `-drive if=pflash,format=raw,file=OVMF_VARS_4M.ms.fd` option. OVMF may update the Secure Boot
  variables stored in the file on first boot (see
  [LP: #2146560](https://bugs.launchpad.net/ubuntu/+source/edk2/+bug/2146560)), so the UEFI
  configuration must be generated from the booted copy to match what is measured at boot.

- generate `uefi-config.json` from the `PK`, `KEK`, `db` and `dbx` variables of the booted copy

```bash
virt-fw-vars -i OVMF_VARS_4M.ms.fd --output-json vars.json
python3 - <<'EOF'
import base64, json
with open("vars.json") as f:
    variables = {v["name"]: v for v in json.load(f)["variables"]}
config = {
    name: base64.b64encode(bytes.fromhex(variables[name]["data"])).decode("ascii")
    for name in ("PK", "KEK", "db", "dbx")
}
with open("uefi-config.json", "w") as f:
    json.dump(config, f, indent=2)
EOF
```

Finally the deploy command can be called to create the final TPM bound image:

```bash
sudo encrypt-cloud-image deploy --srk-pub srk.pub \
                                --uefi-config uefi-config.json \
                                --add-efi-secure-boot-profile \
                                encrypted.vhd

# This is the final image
mv encrypted.vhd final.vhd
```

The encrypted image must be booted with this same `OVMF_VARS_4M.ms.fd` copy.

For more information about each command and their arguments please refer to their respective
[reference pages](../reference/index).

For more information about the booting process, see [](../reference/architecture).
