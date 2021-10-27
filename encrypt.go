// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/xerrors"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	"github.com/canonical/encrypt-cloud-image/internal/gpt"
	internal_ioutil "github.com/canonical/encrypt-cloud-image/internal/ioutil"
	"github.com/canonical/encrypt-cloud-image/internal/luks2"
)

const (
	luks2MetadataKiBSize = 512
	luks2HeaderKiBSize   = 16 * 1024
)

type encryptOptions struct {
	Output string `short:"o" long:"output" description:"Output image path"`

	KernelEfi string `long:"kernel-efi" description:"Path to kernel.efi for booting"`

	OverrideDatasources string `long:"override-datasources" description:"Override the cloud-init datasources with the supplied comma-delimited list of sources"`
	GrowRoot            bool   `long:"grow-root" description:"Grow the root partition to fill the available space, disabling cloud-init's cc_growpart"`

	Positional struct {
		Input string `positional-arg-name:"Source image path (file or block device)"`
	} `positional-args:"true" required:"true"`
}

func (o *encryptOptions) Execute(_ []string) error {
	return encryptImage(o)
}

func getBlockDeviceSize(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return f.Seek(0, io.SeekEnd)
}

func growPartition(diskDevPath, partDevPath string, partNum int) error {
	log.Infoln("growing encrypted partition")

	sz, err := getBlockDeviceSize(partDevPath)
	if err != nil {
		return xerrors.Errorf("cannot determine current partition size: %w", err)
	}
	log.Debugln("current size:", sz)

	cmd := internal_exec.LoggedCommand("growpart", diskDevPath, strconv.Itoa(partNum))
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("cannot grow partition: %w", err)
	}

	// XXX: This is a bit of a hack to avoid a race whilst the kernel
	// re-reads the partition table.
	time.Sleep(2 * time.Second)
	sz, err = getBlockDeviceSize(partDevPath)
	if err != nil {
		return xerrors.Errorf("cannot determine new partition size: %w", err)
	}
	log.Debugln("new size:", sz)

	return nil
}

func luks2Encrypt(path string, key []byte) error {
	cmd := internal_exec.LoggedCommand("cryptsetup",
		// verbose
		"-v",
		// batch processing, no password verification for formatting an existing LUKS container
		"-q",
		// encrypt plaintext volume
		"reencrypt", "--encrypt",
		// use LUKS2
		"--type", "luks2",
		// read the key from stdin
		"--key-file", "-",
		// use AES-256 with XTS block cipher mode (XTS requires 2 keys)
		"--cipher", "aes-xts-plain64", "--key-size", "512",
		// use argon2i as the KDF
		"--pbkdf", "argon2i",
		// set the KDF benchmark time
		"--iter-time", "100",
		// set the default metadata size to 512KiB
		"--luks2-metadata-size", fmt.Sprintf("%dk", luks2MetadataKiBSize),
		// specify the keyslots area size of 16MiB - (2 * 512KiB)
		"--luks2-keyslots-size", fmt.Sprintf("%dk", luks2HeaderKiBSize-(2*luks2MetadataKiBSize)),
		// reduce the device size by 2 * the header size, as required by cryptsetup
		"--reduce-device-size", fmt.Sprintf("%dk", 2*luks2HeaderKiBSize),
		path)
	cmd.Stdin = bytes.NewReader(key)

	return cmd.Run()
}

func luks2SetLabel(path, label string) error {
	cmd := internal_exec.LoggedCommand("cryptsetup", "-v", "config", "--label", label, path)
	return cmd.Run()
}

func growExtFS(path string) error {
	cmd := internal_exec.LoggedCommand("resize2fs", "-f", "-d", "30", path)
	return cmd.Run()
}

func shrinkExtFS(path string) error {
	cmd := internal_exec.LoggedCommand("resize2fs", "-fM", "-d", "62", path)
	return cmd.Run()
}

func encryptExtDevice(path string) error {
	log.Infoln("shrinking fileystem on", path)
	if err := shrinkExtFS(path); err != nil {
		return xerrors.Errorf("cannot shrink filesystem: %w", err)
	}

	// For tpm import sensitive data should not be larger than block size (64) else we get TPM_RC_KEY_SIZE
	// so with two keys we need to keep key size at 16 each.
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return xerrors.Errorf("cannot obtain primary unlock key: %w", err)
	}

	log.Infoln("encrypting", path)
	if err := luks2Encrypt(path, key[:]); err != nil {
		return xerrors.Errorf("cannot encrypt %s: %w", path, err)
	}

	log.Infoln("setting label")
	if err := luks2SetLabel(path, "cloudimg-rootfs-enc"); err != nil {
		return xerrors.Errorf("cannot set label: %w", err)
	}

	token := &luks2.Token{
		Type:     luks2TokenType,
		Keyslots: []int{0},
		Params: map[string]interface{}{
			luks2TokenKey: key[:],
		},
	}

	log.Infoln("importing cleartext token")
	if err := luks2.ImportToken(path, token); err != nil {
		return xerrors.Errorf("cannot import token into LUKS2 container: %w", err)
	}

	volumeName := filepath.Base(path)
	log.Infoln("attaching encrypted container as", volumeName)
	if err := luks2.Activate(volumeName, path, key[:]); err != nil {
		return xerrors.Errorf("cannot activate LUKS container: %w", err)
	}
	defer func() {
		log.Infoln("detaching", volumeName)
		if err := luks2.Deactivate(volumeName); err != nil {
			log.WithError(err).Panicln("cannot detach container")
		}
	}()
	path = filepath.Join("/dev/mapper", volumeName)

	log.Infoln("growing filesystem on", path)
	if err := growExtFS(path); err != nil {
		return xerrors.Errorf("cannot grow filesystem: %w", err)
	}

	return nil
}

func customizeRootFS(workingDir, path string, opts *encryptOptions) error {
	if opts.OverrideDatasources == "" && !opts.GrowRoot {
		return nil
	}

	log.Infoln("applying customizations to image")

	mountPath := filepath.Join(workingDir, "rootfs")
	if err := os.Mkdir(mountPath, 0700); err != nil {
		return xerrors.Errorf("cannot create directory to mount rootfs: %w", err)
	}

	log.Infoln("mounting root filesystem to", mountPath)

	unmount, err := mount(path, mountPath, "ext4")
	if err != nil {
		return xerrors.Errorf("cannot mount rootfs: %w", err)
	}
	defer unmount()

	// Disable secureboot-db.service
	if err := os.Symlink("/dev/null", filepath.Join(mountPath, "etc/systemd/system/secureboot-db.service")); err != nil {
		return xerrors.Errorf("cannot disable secureboot-db.service: %w", err)
	}

	cloudCfgDir := filepath.Join(mountPath, "etc/cloud/cloud.cfg.d")

	if opts.OverrideDatasources != "" {
		datasourceOverrideTmpl := `# this file was automatically created by github.com/canonical/encrypt-cloud-image
datasource_list: [ %s ]
`
		datasourceContent := fmt.Sprintf(datasourceOverrideTmpl, opts.OverrideDatasources)

		if err := ioutil.WriteFile(filepath.Join(cloudCfgDir, "99_datasources_override.cfg"), []byte(datasourceContent), 0644); err != nil {
			return xerrors.Errorf("cannot create datasource override file: %w", err)
		}
	}

	if opts.GrowRoot {
		disableGrowPart := `# this file was automatically created by github.com/canonical/encrypt-cloud-image
growpart:
    mode: off
`

		if err := ioutil.WriteFile(filepath.Join(cloudCfgDir, "99_disable_growpart.cfg"), []byte(disableGrowPart), 0644); err != nil {
			return xerrors.Errorf("cannot create growpart override file: %w", err)
		}
	}

	return nil
}

func validImageExt(ext string) bool {
	switch ext {
	case ".img", ".vhd":
		return true
	default:
		return false
	}
}

func tryToOpenImageFromZip(src io.ReaderAt, sz int64) (io.ReadCloser, error) {
	log.Debugln("trying zip")
	r, err := zip.NewReader(src, sz)
	switch {
	case err == zip.ErrFormat:
		return nil, nil
	case err != nil:
		return nil, xerrors.Errorf("cannot read zip: %w", err)
	}
	log.Debugln("iterating zip archive files")
	for _, zf := range r.File {
		log.Debugln("trying", zf.Name)
		if !validImageExt(filepath.Ext(zf.Name)) {
			log.Debugln("...skipping")
			continue
		}

		log.Debugln("...found file with valid extension")
		rc, err := zf.Open()
		if err != nil {
			return nil, xerrors.Errorf("cannot open image in ZIP file: %w", err)
		}
		return rc, nil
	}

	return nil, errors.New("no appropriate image found")
}

func tryToOpenArchivedImage(f *os.File) (r io.ReadCloser, err error) {
	log.Debugln("trying to find archived image from", f.Name())

	fi, err := f.Stat()
	if err != nil {
		return nil, xerrors.Errorf("cannot obtain file info: %w", err)
	}

	r, err = tryToOpenImageFromZip(f, fi.Size())
	if err != nil {
		return nil, xerrors.Errorf("cannot find image in zip: %w", err)
	}

	// TODO: Try other archive formats and compression combinations
	return r, nil
}

func prepareWorkingImage(workingDir string, f *os.File, opts *encryptOptions) (string, error) {
	r, err := tryToOpenArchivedImage(f)
	switch {
	case err != nil:
		return "", xerrors.Errorf("cannot open archived source image: %w", err)
	case r != nil:
		// Input file is an archive with a valid image
		defer func() {
			if err := r.Close(); err != nil {
				log.WithError(err).Warningln("cannot close source image")
			}
		}()
		if opts.Output == "" {
			return "", errors.New("must specify --ouptut if the supplied input source is an archive")
		}
	case opts.Output != "":
		// Input file is not an archive and we are not encrypting the source image
		r = f
	default:
		// Input file is not an archive and we are encrypting the source image
		return "", nil
	}

	path := filepath.Join(workingDir, filepath.Base(opts.Output))
	log.Infoln("making copy of source image to", path)
	if err := internal_ioutil.CopyFromReaderToFile(path, r); err != nil {
		return "", xerrors.Errorf("cannot make working copy of source image: %w", err)
	}

	return path, nil
}

func copyKernelToESP(workingDir, devPath, src string) error {
	path := filepath.Join(workingDir, "esp")
	if err := os.Mkdir(path, 0700); err != nil {
		return xerrors.Errorf("cannot create directory to mount ESP: %w", err)
	}

	log.Infoln("mounting ESP to", path)
	unmount, err := mount(devPath, path, "vfat")
	if err != nil {
		return xerrors.Errorf("cannot mount %s to %s: %w", devPath, path, err)
	}
	defer unmount()

	dst := filepath.Join(path, "EFI/ubuntu/grubx64.efi")
	if err := os.Remove(dst); err != nil {
		return xerrors.Errorf("cannot remove grub: %w", err)
	}
	if err := internal_ioutil.CopyFile(dst, src); err != nil {
		return xerrors.Errorf("cannot install kernel: %w", err)
	}

	return nil
}

func encryptImageOnDevice(workingDir, devicePath string, opts *encryptOptions) error {
	partitions, err := gpt.ReadPartitionTable(devicePath)
	if err != nil {
		return xerrors.Errorf("cannot read partition table from %s: %w", devicePath, err)
	}
	log.Debugln("partition table for", devicePath, ":", partitions)

	// XXX: Could there be more than one partition with this type?
	root := partitions.FindByPartitionType(linuxFilesystemGUID)
	if root == nil {
		return fmt.Errorf("cannot find partition with the type %v on %s", linuxFilesystemGUID, devicePath)
	}
	log.Debugln("rootfs partition on", devicePath, ":", root)
	rootDevPath := fmt.Sprintf("%sp%d", devicePath, root.Index)
	log.Infoln("device node for rootfs partition:", rootDevPath)

	if err := customizeRootFS(workingDir, rootDevPath, opts); err != nil {
		return xerrors.Errorf("cannot apply customizations to root filesystem: %w", err)
	}

	if err := encryptExtDevice(rootDevPath); err != nil {
		return xerrors.Errorf("cannot encrypt %s: %w", rootDevPath, err)
	}

	if opts.GrowRoot {
		if err := growPartition(devicePath, rootDevPath, root.Index); err != nil {
			return xerrors.Errorf("cannot grow root partition: %w", err)
		}
	}

	if opts.KernelEfi != "" {
		esp := partitions.FindByPartitionType(espGUID)
		if esp == nil {
			return fmt.Errorf("cannot find partition with the type %v on %s", espGUID, devicePath)
		}

		log.Debugln("ESP on", devicePath, ":", esp)
		espDevPath := fmt.Sprintf("%sp%d", devicePath, esp.Index)
		log.Infoln("device node for ESP:", espDevPath)

		if err := copyKernelToESP(workingDir, espDevPath, opts.KernelEfi); err != nil {
			return xerrors.Errorf("cannot copy kernel image to ESP: %w", err)
		}
	}

	return nil
}

func encryptImageFromFile(workingDir string, f *os.File, opts *encryptOptions) error {
	path, err := prepareWorkingImage(workingDir, f, opts)
	switch {
	case err != nil:
		return xerrors.Errorf("cannot prepare working image: %w", err)
	case path != "":
		// We aren't encrypting the source image
		defer func() {
			if err != nil {
				return
			}
			if err := os.Rename(path, opts.Output); err != nil {
				log.WithError(err).Panicln("cannot move working image to final path")
			}
		}()
	default:
		// We are encrypting the source image
		path = f.Name()
	}

	nbdConn, disconnectNbd, err := connectNbd(path)
	if err != nil {
		return xerrors.Errorf("cannot connect image to NBD device: %w", err)
	}
	log.Infoln("connected", path, "to", nbdConn.DevPath())
	defer disconnectNbd()

	return encryptImageOnDevice(workingDir, nbdConn.DevPath(), opts)
}

func encryptImage(opts *encryptOptions) error {
	path := opts.Positional.Input

	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("cannot open source file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return xerrors.Errorf("cannot obtain source file information: %w", err)
	}

	if opts.Output != "" && fi.Mode()&os.ModeDevice != 0 {
		return errors.New("cannot specify --output with a block device")
	}

	var baseDir string
	if opts.Output != "" {
		baseDir = filepath.Dir(opts.Output)
	}
	workingDir, cleanupWorkingDir, err := mkTempDir(baseDir)
	if err != nil {
		return xerrors.Errorf("cannot create working directory: %w", err)
	}
	defer cleanupWorkingDir()
	log.Infoln("temporary working directory:", workingDir)

	if fi.Mode()&os.ModeDevice != 0 {
		// Input file is a block device
		return encryptImageOnDevice(workingDir, path, opts)
	}

	// Input file is not a block device
	return encryptImageFromFile(workingDir, f, opts)
}

func init() {
	if _, err := parser.AddCommand("encrypt", "Encrypt an image without protecting the key to a specific guest instance", "", &encryptOptions{}); err != nil {
		log.WithError(err).Panicln("cannot add encrypt command")
	}
}
