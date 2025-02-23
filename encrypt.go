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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	internal_ioutil "github.com/canonical/encrypt-cloud-image/internal/ioutil"
	"github.com/canonical/encrypt-cloud-image/internal/luks2"
)

const (
	luks2MetadataKiBSize = 512
	luks2HeaderKiBSize   = 16 * 1024

	luks2GrowPartKeyslot = 10
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
	e := new(imageEncrypter)
	return e.run(o)
}

type growPartKeyData struct {
	Key  []byte `json:"key"`
	Slot int    `json:"slot"`
}

func getBlockDeviceSize(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return f.Seek(0, io.SeekEnd)
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
		// set the minimum KDF cost parameters
		"--pbkdf-force-iterations", "4", "--pbkdf-memory", "32768",
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
		return nil, fmt.Errorf("cannot read zip: %w", err)
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
			return nil, fmt.Errorf("cannot open image in ZIP file: %w", err)
		}
		return rc, nil
	}

	return nil, errors.New("no appropriate image found")
}

func tryToOpenArchivedImage(f *os.File) (r io.ReadCloser, err error) {
	log.Debugln("trying to find archived image from", f.Name())

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot obtain file info: %w", err)
	}

	r, err = tryToOpenImageFromZip(f, fi.Size())
	if err != nil {
		return nil, fmt.Errorf("cannot find image in zip: %w", err)
	}

	// TODO: Try other archive formats and compression combinations
	return r, nil
}

type imageEncrypter struct {
	encryptCloudImageBase

	opts   *encryptOptions
	failed bool
}

func (e *imageEncrypter) maybeCopyKernelToESP() error {
	if e.opts.KernelEfi == "" {
		return nil
	}

	e.enterScope()
	defer e.exitScope()

	path, err := e.mountESP()
	if err != nil {
		return err
	}

	dst := filepath.Join(path, "EFI/ubuntu/grubx64.efi")
	if err := os.Remove(dst); err != nil {
		return fmt.Errorf("cannot remove grub: %w", err)
	}
	if err := internal_ioutil.CopyFile(dst, e.opts.KernelEfi); err != nil {
		return fmt.Errorf("cannot install kernel: %w", err)
	}

	return nil
}

func (e *imageEncrypter) growRootPartition() error {
	log.Infoln("growing encrypted root partition")

	sz, err := getBlockDeviceSize(e.rootDevPath())
	if err != nil {
		return fmt.Errorf("cannot determine current partition size: %w", err)
	}
	log.Debugln("current size:", sz)

	cmd := internal_exec.LoggedCommand("growpart", e.devPath, strconv.Itoa(e.rootPartition.Index))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot grow partition: %w", err)
	}

	// XXX: This is a bit of a hack to avoid a race whilst the kernel
	// re-reads the partition table.
	time.Sleep(2 * time.Second)
	sz, err = getBlockDeviceSize(e.rootDevPath())
	if err != nil {
		return fmt.Errorf("cannot determine new partition size: %w", err)
	}
	log.Debugln("new size:", sz)

	return nil
}

func (e *imageEncrypter) encryptRootPartition() ([]byte, error) {
	devPath := e.rootDevPath()

	log.Infoln("shrinking fileystem on", devPath)
	if err := shrinkExtFS(devPath); err != nil {
		return nil, fmt.Errorf("cannot shrink filesystem: %w", err)
	}

	// For tpm import sensitive data should not be larger than block size (64) else we get TPM_RC_KEY_SIZE
	// so with two keys we need to keep key size at 16 each.
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("cannot obtain primary unlock key: %w", err)
	}

	log.Infoln("encrypting", devPath)
	if err := luks2Encrypt(devPath, key[:]); err != nil {
		return nil, fmt.Errorf("cannot encrypt %s: %w", devPath, err)
	}

	log.Infoln("setting label")
	if err := luks2SetLabel(devPath, "cloudimg-rootfs-enc"); err != nil {
		return nil, fmt.Errorf("cannot set label: %w", err)
	}

	token := &luks2.GenericToken{
		TokenType:     luks2TokenType,
		TokenKeyslots: []int{0},
		Params: map[string]interface{}{
			luks2TokenKey: key[:],
		},
	}

	log.Infoln("importing cleartext token")
	if err := luks2.ImportToken(devPath, token); err != nil {
		return nil, fmt.Errorf("cannot import token into LUKS2 container: %w", err)
	}

	e.enterScope()
	defer e.exitScope()

	volumeName := filepath.Base(devPath)
	log.Infoln("attaching encrypted container as", volumeName)
	if err := luks2.Activate(volumeName, devPath, key[:]); err != nil {
		return nil, fmt.Errorf("cannot activate LUKS container: %w", err)
	}
	e.addCleanup(func() error {
		log.Infoln("detaching", volumeName)
		if err := luks2.Deactivate(volumeName); err != nil {
			return fmt.Errorf("cannot detach container: %w", err)
		}
		return nil
	})
	path := filepath.Join("/dev/mapper", volumeName)

	log.Infoln("growing filesystem on", path)
	if err := growExtFS(path); err != nil {
		return nil, fmt.Errorf("cannot grow filesystem: %w", err)
	}

	return key[:], nil
}

func (e *imageEncrypter) customizeRootFS(growPartKey [32]byte) error {
	log.Infoln("applying customizations to image")

	e.enterScope()
	defer e.exitScope()

	path, err := e.mountRoot()
	if err != nil {
		return err
	}

	// Disable secureboot-db.service
	if err := os.Symlink("/dev/null", filepath.Join(path, "etc/systemd/system/secureboot-db.service")); err != nil {
		return fmt.Errorf("cannot disable secureboot-db.service: %w", err)
	}

	cloudCfgDir := filepath.Join(path, "etc/cloud/cloud.cfg.d")

	if e.opts.OverrideDatasources != "" {
		log.Debugln("overriding cloud-init datasources")

		datasourceOverrideTmpl := `# this file was automatically created by github.com/canonical/encrypt-cloud-image
datasource_list: [ %s ]
`
		datasourceContent := fmt.Sprintf(datasourceOverrideTmpl, e.opts.OverrideDatasources)

		if err := ioutil.WriteFile(filepath.Join(cloudCfgDir, "99_datasources_override.cfg"), []byte(datasourceContent), 0644); err != nil {
			return fmt.Errorf("cannot create datasource override file: %w", err)
		}
	}

	if e.opts.GrowRoot {
		log.Debugln("disabling cloud-init cc_growpart")

		disableGrowPart := `# this file was automatically created by github.com/canonical/encrypt-cloud-image
growpart:
    mode: off
`

		if err := ioutil.WriteFile(filepath.Join(cloudCfgDir, "99_disable_growpart.cfg"), []byte(disableGrowPart), 0644); err != nil {
			return fmt.Errorf("cannot create growpart override file: %w", err)
		}
	} else {
		log.Debugln("writing key data for cloud-init cc_growpart")

		data := growPartKeyData{
			Key:  growPartKey[:],
			Slot: luks2GrowPartKeyslot}
		b, err := json.Marshal(&data)
		if err != nil {
			return fmt.Errorf("cannot marshal key data for growpart: %w", err)
		}

		if err := ioutil.WriteFile(filepath.Join(path, "cc_growpart_keydata"), b, 0600); err != nil {
			return fmt.Errorf("cannot write key data for growpart: %w", err)
		}
	}

	return nil
}

func (e *imageEncrypter) encryptImageOnDevice() error {
	if e.devPath == "" {
		panic("no device path")
	}

	log.Infoln("encrypting image on", e.devPath)

	if err := e.detectPartitions(); err != nil {
		return err
	}

	var growPartKey [32]byte
	if !e.opts.GrowRoot {
		if _, err := rand.Read(growPartKey[:]); err != nil {
			return fmt.Errorf("cannot obtain key for cc_growpart: %w", err)
		}
	}

	if err := e.customizeRootFS(growPartKey); err != nil {
		return fmt.Errorf("cannot apply customizations to root filesystem: %w", err)
	}

	key, err := e.encryptRootPartition()
	if err != nil {
		return fmt.Errorf("cannot encrypt root partition: %w", err)
	}

	if !e.opts.GrowRoot {
		opts := luks2.AddKeyOptions{
			KDFOptions: luks2.KDFOptions{
				MemoryKiB:       32 * 1024,
				ForceIterations: 4},
			Slot: luks2GrowPartKeyslot}
		if err := luks2.AddKey(e.rootDevPath(), key, growPartKey[:], &opts); err != nil {
			return fmt.Errorf("cannot add key to container for cc_growpart: %w", err)
		}
	} else if err := e.growRootPartition(); err != nil {
		return fmt.Errorf("cannot grow root partition: %w", err)
	}

	if err := e.maybeCopyKernelToESP(); err != nil {
		return fmt.Errorf("cannot copy kernel image to ESP: %w", err)
	}

	return nil
}

func (e *imageEncrypter) prepareWorkingImage() (string, error) {
	f, err := os.Open(e.opts.Positional.Input)
	if err != nil {
		return "", fmt.Errorf("cannot open source image: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.WithError(err).Warningln("cannot close source image")
		}
	}()

	r, err := tryToOpenArchivedImage(f)
	switch {
	case err != nil:
		return "", fmt.Errorf("cannot open archived source image: %w", err)
	case r != nil:
		// Input file is an archive with a valid image
		defer func() {
			if err := r.Close(); err != nil {
				log.WithError(err).Warningln("cannot close unpacked source image")
			}
		}()
		if e.opts.Output == "" {
			return "", errors.New("must specify --ouptut if the supplied input source is an archive")
		}
	case e.opts.Output != "":
		// Input file is not an archive and we are not encrypting the source image
		r = f
	default:
		// Input file is not an archive and we are encrypting the source image
		return "", nil
	}

	path := filepath.Join(e.workingDirPath(), filepath.Base(e.opts.Output))
	log.Infoln("making copy of source image to", path)
	if err := internal_ioutil.CopyFromReaderToFile(path, r); err != nil {
		return "", fmt.Errorf("cannot make working copy of source image: %w", err)
	}

	return path, nil
}

func (e *imageEncrypter) encryptImageFromFile() error {
	path, err := e.prepareWorkingImage()
	switch {
	case err != nil:
		return fmt.Errorf("cannot prepare working image: %w", err)
	case path != "":
		// We aren't encrypting the source image
		e.addCleanup(func() error {
			if e.failed {
				return nil
			}
			if err := os.Rename(path, e.opts.Output); err != nil {
				return fmt.Errorf("cannot move working image to final path: %w", err)
			}
			return nil
		})
	default:
		// We are encrypting the source image
		path = e.opts.Positional.Input
	}

	if err := e.connectNbd(path); err != nil {
		return err
	}

	return e.encryptImageOnDevice()
}

func (e *imageEncrypter) setupWorkingDir() error {
	var baseDir string
	if e.opts.Output != "" {
		baseDir = filepath.Dir(e.opts.Output)
	}
	return e.encryptCloudImageBase.setupWorkingDir(baseDir)
}

func (e *imageEncrypter) run(opts *encryptOptions) error {
	e.opts = opts

	e.enterScope()
	defer e.exitScope()

	fi, err := os.Stat(opts.Positional.Input)
	if err != nil {
		return fmt.Errorf("cannot obtain source file information: %w", err)
	}

	if opts.Output != "" && fi.Mode()&os.ModeDevice != 0 {
		return errors.New("cannot specify --output with a block device")
	}

	if err := e.setupWorkingDir(); err != nil {
		return err
	}

	if fi.Mode()&os.ModeDevice != 0 {
		// Input file is a block device
		e.devPath = opts.Positional.Input
		if e.isNbdDevice() {
			if err := e.checkNbdPreRequisites(); err != nil {
				return err
			}
		}

		return e.encryptImageOnDevice()
	}

	// Input file is not a block device
	if err := e.checkNbdPreRequisites(); err != nil {
		return err
	}

	return e.encryptImageFromFile()
}

func init() {
	if _, err := parser.AddCommand("encrypt", "Encrypt an image without protecting the key to a specific guest instance", "", &encryptOptions{}); err != nil {
		log.WithError(err).Panicln("cannot add encrypt command")
	}
}
