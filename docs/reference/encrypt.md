(command-encrypt)=
# `encrypt`

Basic usage:
```bash
encrypt-cloud-image encrypt -o <encrypted_image> <plain_image>
```

This command performs the encryption step without protecting the key to a specific guest instance.
The key is stored in cleartext inside the LUKS metadata. `encrypt` can be used to create a pool of
pre-encrypted images.

## Options

### Override cloud-init datasources
It may be desirable to override an image's enabled cloud-init datasources to facilitate debugging the encrypted image in QEMU.
To enable only the NoCloud datasource so that an image can be initialized with user data from a separate seed image:
```bash
$ sudo encrypt-cloud-image encrypt -o <encrypted_image> \
                                    --override-datasources "NoCloud" \
                                    <plain_image>
```
The `--override-datasources` option takes a comma-delimited list of datasources.

### Fixed size root partition
It is possible to grow the root partition to fill the image during the encryption step using the `--grow-root` option. This will also disable cloud-init's cc_growpart module:
```bash
$ sudo encrypt-cloud-image encrypt -o <encrypted_image> \
                                    --grow-root \
                                    <plain_image>
```
