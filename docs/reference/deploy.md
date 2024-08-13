(command-deploy)=
# `deploy`

Basic usage:
```bash
encrypt-cloud-image deploy --srk-pub srk.pub <encrypted_image>
```

This command expects an image pre-encrypted using the [](../reference/encrypt.md) command. It will
protect the FDE key to a virtual TPM associated with a specific guest instance, removing the cleartext
key in the process. Once this step has been performed, the image is only bootable on that specific guest
instance. The deploy step does not need access to the actual TPM but does need access to the public area of
the storage primary key (`--srk-pub` argument above).

## Protection options

### PCR policy configuration
The `deploy` subcommand has several options for customizing the PCR policy of the TPM protected key:
- `--add-efi-boot-manager-profile`: Protect the key with the *UEFI Boot Manager Code and Boot Attempts* profile,
as measured to PCR4 (see section 3.3.4.5 of the [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf)).
This requires the UEFI configuration of the guest to be supplied.
- `--add-efi-secure-boot-profile`: Protect the key with the *Secure Boot Policy* profile, as measured to PCR7
(see section 3.3.4.8 of the [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf)).
This requires the UEFI configuration of the guest to be supplied. Note that this profile requires that secure boot is enabled.
- `--add-ubuntu-kernel-profile`: Protect the key with the Ubuntu kernel image profile. The Ubuntu kernel
measures a set of properties to PCR12. This profile is required in order to protect keys outside of the early
boot environment.

```{caution}
`--add-ubuntu-kernel-profile` doesn't currently measure the kernel commandline but it adds a binding to PCR 12 with a measurement of 0.
That is because `snap-bootstrap` also measures an epoch of 0 prior to the unsealing operation. After the unsealing operation is done,
`snap-bootstrap` measures another 0 to PCR 12 which effectively "locks" the key and renders it unusable/unsealable by code running at
later stages.
```

### Guest UEFI configuration
By default, the `deploy` subcommand will use the UEFI configuration of the host environment. The UEFI configuration of the guest can be supplied in order to override this using one of the following options:
- `--uefi-config`: A file containing a JSON representation of the UEFI configuration, with the following fields:
  - `PK` [base64] - The value of the PK variable.
  - `KEK` [base64] - The value of the KEK variable.
  - `db` [base64] - The value of the db variable.
  - `dbx` [base64] - The value of the dbx variable.
  - `omitsReadyToBootEvent` [bool] - Whether the firmware omits the *Calling EFI Application From Boot Option* `EV_EFI_ACTION` event in PCR4.
- `--az-disk-profile`: documentation *TODO*

This is an example `deploy` invocation which uses the boot attempts and secure boot profile:
```bash
sudo encrypt-cloud-image deploy --srk-pub srk.pub \
                                --uefi-config uefi-config.json \
                                --add-efi-boot-manager-profile \
                                --add-efi-secure-boot-profile \
                                <encrypted_image>
```

## SRK template customization

This tool does not have access to the virtual TPM associated with a guest, and so the storage primary key (SRK)
must be created by and supplied from another tool as a `TPM2B_PUBLIC` structure serialized to a file in the
TPM wire format, using the `--srk-pub` option.

If the storage primary key is created with the standard template as defined in section
7.5.1 (*Foundational Elements of the TPM Provisioning Process - Storage Hierarchy - Storage Primary Key (SRK) Templates*)
of the [TCG TPM v2.0 Provisioning Guidance specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf),
then the `deploy` subcommand must be called with the `--standard-srk-template` option:

```bash
$ sudo ./encrypt-cloud-image deploy --srk-pub <srkpub_path> \
                                    --standard-srk-template <output_path>
```

If the storage primary key is not created with the standard template, then the template is inferred from a
combination of the supplied SRK public area (using the `--srk-pub` option) and the unique data supplied to
the `TPM2_CreatePrimary` command, which must be supplied to this tool as a `TPMU_PUBLIC_ID` structure
serialized to a file in the TPM wire format, using the `--srk-template-unique-data` option:

```bash
$ sudo ./encrypt-cloud-image deploy --srk-pub <srkpub_path> \
                                    --srk-template-unique-data <unique_data_path> \
                                    <output_path>
```

Note that the format of the data supplied via the `--srk-template-unique-data` option is not the same as the
format supplied to the `tpm2_createprimary` command via the `--unique-data` option. This tool expects it to be
in the TPM wire format which implies big-endian byte ordering, whereas `tpm2_createprimary` requires little-endian
byte ordering for this option.

If neither the `--standard-srk-template` or `--srk-template-unique-data` options are supplied, the template is assumed to have a unique area with zero-sized fields. This is the default when calling `tpm2_createprimary` without the `--unique-data` option.
