(building)=
# (WIP) Building an image locally from scratch

Summary of the steps of the image building process for an Ubuntu cloud image based on noble:
1. (Optional) Build snapd.
2. (Optional) Build core-initrd.
3. (Optional) Build the linux-azure-fde kernel.
4. Build a cloud image using CPC's tooling https://github.com/ubuntu-bartenders/ubuntu-old-fashioned/blob/master/scripts/ubuntu-bartender/ubuntu-bartender

Steps marked as optional are only required if needed features are not available on the packaged
versions available in the Ubuntu archive.

## 1. Build snapd
TODO (straight forward)

## 2. Build core-initrd
TODO (straight forward)

## 3. Building the linux-azure-fde kernel UKI

To build the `linux-azure-fde` binary package required by CPC's tooling the following packages must be built in sequence:
1. `linux-signed-azure`'s' auxiliary `linux-generate-azure` package. This pulls in the `ubuntu-core-initramfs` binary
package that was built in the previous step and will run the script in core-initrd's postinst.d directory to generate the UKI.
This can be built manually and not wait on the kernel team's auxiliary bot to detect your packages in a ppa etc.
2. Sign the generated artifacts manually and place them in a local repo.
3. `linux-signed-azure` will pull the generated signed artifacts.
4. `linux-meta-azure` builds the final linux-azure-fde package.

For step 2, in order to replicate the signing service, you can use something like:
```bash
abi_version="6.8.0-1009"
version="${abi_version}.9"
topdir="/var/www/html/pool/noble/main/signed"

# Create a signing key
common_name="Spyros Seimenis local repo UEFI"
subject="/CN=${common_name}/"
openssl req -new -x509 -newkey rsa:2048 -subj $subject -keyout uefi.key -out uefi.crt -days 3650 -nodes -sha256

# Pull the generated files from the auxiliary package
cp ~/git-ubuntu/linux-signed-azure/debian/ancillary/binary/linux-generate-azure_${version}_amd64.tar.gz .
tar -xvzf linux-generate-azure_${version}_amd64.tar.gz

# Sign them
sbsign --key uefi.key --cert uefi.crt $version/boot/kernel.efi-${abi_version}-azure.efi
sbsign --key uefi.key --cert uefi.crt $version/boot/vmlinuz-${abi_version}-azure.efi
cp uefi.crt $version/control/

# Create signed tarball
tar -czvf signed.tar.gz $version
sha256sum signed.tar.gz > SHA256SUMS

gpg -abs 0o SHA256SUMS.gpg SHA256SUMS

# Upload to a locally configured archive/repo
repo_dir="/var/www/html/dists/main/signed/linux-generate-azure-amd64/${version}"
mkdir -p $repo_dir
cp signed.tar.gz $repo_dir
cp SHA256SUMS $repo_dir
cp SHA256SUMS.gpg $repo_dir
```

```{note}
This assumes a local repo setup that you sign with a key that is in your GPG keyring.
```

## 4. Building the final image using ubuntu-bartender from ubuntu-old-fashioned
```{note}
You need to point bartender to include your local repo and add an iptables rule for the multipass vm
to be able to see it.
```
TODO
