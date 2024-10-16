(verify-rootfs)=
# (WIP) How to verify the integrity of the rootfs

```{caution}
This API is subject to change.
```

Currently a manifest containing the rootfs's dm-verity root hash gets measured to PCR 12
in the initramfs stage but as snapd doesn't yet properly integrate with
[systemd's userspace TPM measurement log](https://github.com/systemd/systemd/blob/main/docs/TPM2_PCR_MEASUREMENTS.md), 
a few manual steps are required.

Measurements done are exposed via the stamped-action mechanism and need to be inserted in systemd's log. In a running VM:
```bash
sudo su
cd /run/snapd/snap-bootstrap
(echo -n -e '\x1e'; cat secboot-epoch-measured; echo) >> /run/log/systemd/tpm2-measure.log
(echo -n -e '\x1e'; cat secboot-manifest-measured; echo) >> /run/log/systemd/tpm2-measure.log
(echo -n -e '\x1e'; cat secboot-fence; echo) >> /run/log/systemd/tpm2-measure.log
```

Then the log can be checked against the TPM2 reported values with something like systemd's pcrlock tool.
```bash
sudo /usr/lib/systemd/systemd-pcrlock
```

Verify that PCR 12 value indeed matches the expected values.

