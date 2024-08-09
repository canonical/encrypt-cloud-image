# Provision an image for CVM with FDE

This workflow describes the image provisioning process for a confidential
VM using FDE. The FDE operations are backed by a vTPM which is required for
booting. The process is split in 2 parts:
1) encrypting the rootfs and then
2) restrict usage of the FDE key to systems that match a specific system
   state (sealing) using the vTPM.

## Encrypt the rootfs
The first step is done using the [](../reference/encrypt.md) command:
```bash
sudo encrypt-cloud-image encrypt -o $output $input
```

## Bind FDE key to a TPM
The second step is done using the [](../reference/deploy.md) command. This step requires some
extra preparation.

### Create an external SRK

