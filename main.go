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
	"strings"
	"time"

	"github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/tcglog-parser"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/efienv"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/exec"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/gpt"
	internal_ioutil "github.com/chrisccoulson/encrypt-cloud-image/internal/ioutil"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/logutil"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/luks2"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/nbd"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"github.com/snapcore/secboot"
	secboot_efi "github.com/snapcore/secboot/efi"

	"golang.org/x/xerrors"
)

const (
	luks2MetadataKiBSize = 512
	luks2HeaderKiBSize   = 16 * 1024
)

var (
	espGUID             = efi.MakeGUID(0xC12A7328, 0xF81F, 0x11D2, 0xBA4B, [...]uint8{0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B})
	linuxFilesystemGUID = efi.MakeGUID(0x0FC63DAF, 0x8483, 0x4772, 0x8E79, [...]uint8{0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4})
)

type Options struct {
	Input string `short:"i" long:"input" description:"Input image path"`

	Output string `short:"o" long:"output" description:"Output image path"`

	Verbose bool `short:"v" long:"verbose" description:"Enable verbose debug output"`

	AddEFIBootManagerProfile bool `long:"add-efi-boot-manager-profile" description:"Protect the disk unlock key with the EFI boot manager code and boot attempts profile (PCR4)"`
	AddEFISecureBootProfile  bool `long:"add-efi-secure-boot-profile" description:"Protect the disk unlock key with the EFI secure boot policy profile (PCR7)"`
	AddUbuntuKernelProfile   bool `long:"add-ubuntu-kernel-profile" description:"Protect the disk unlock key with properties measured by the Ubuntu kernel (PCR12). Also prevents access outside of early boot"`

	AzDiskProfile string `long:"az-disk-profile" description:""`

	SRKPub                string `long:"srk-pub" description:"Path to SRK public area"`
	SRKTemplateUniqueData string `long:"srk-template-unique-data" description:"Path to the TPMU_PUBLIC_ID structure used to create the SRK"`
	StandardSRKTemplate   bool   `long:"standard-srk-template" description:"Indicate that the supplied SRK was created with the TCG TPM v2.0 Provisioning Guidance spec"`

	KernelEfi string `long:"kernel-efi" description:"Path to kernel.efi for booting"`

	OverrideDatasources string `long:"override-datasources" description:"Override the cloud-init datasources with the supplied comma-delimited list of sources"`
	GrowRoot            bool   `long:"grow-root" description:"Grow the root partition to fill the available space, disabling cloud-init's cc_growpart"`
}

type cleanupError struct {
	err error
}

func (e *cleanupError) Error() string {
	return e.err.Error()
}

func (e *cleanupError) Unwrap() error {
	return e.err
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

	cmd := exec.LoggedCommand("growpart", diskDevPath, strconv.Itoa(partNum))
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

func customizeRootFS(workingDir, path string, options *Options) error {
	if options.OverrideDatasources == "" && !options.GrowRoot {
		return nil
	}

	log.Infoln("applying customizations to image")

	mountPath := filepath.Join(workingDir, "rootfs")

	if err := os.Mkdir(mountPath, 0700); err != nil {
		return xerrors.Errorf("cannot create directory to mount rootfs: %w", err)
	}

	log.Infoln("mounting root filesystem")
	if err := mount(path, mountPath, "ext4"); err != nil {
		return xerrors.Errorf("cannot mount rootfs: %w", err)
	}
	defer func() {
		log.Infoln("unmounting root filesystem")
		if err := unmount(mountPath); err != nil {
			panic(&cleanupError{xerrors.Errorf("cannot unmount rootfs: %w", err)})
		}
	}()

	cloudCfgDir := filepath.Join(mountPath, "etc/cloud/cloud.cfg.d")

	if options.OverrideDatasources != "" {
		datasourceOverrideTmpl := `# this file was automatically created by github.com/chrisccoulson/encrypt-cloud-image
datasource_list: [ %s ]
`
		datasourceContent := fmt.Sprintf(datasourceOverrideTmpl, options.OverrideDatasources)

		if err := ioutil.WriteFile(filepath.Join(cloudCfgDir, "99_datasources_override.cfg"), []byte(datasourceContent), 0644); err != nil {
			return xerrors.Errorf("cannot create datasource override file: %w", err)
		}
	}

	if options.GrowRoot {
		disableGrowPart := `# this file was automatically created by github.com/chrisccoulson/encrypt-cloud-image
growpart:
    mode: off
`

		if err := ioutil.WriteFile(filepath.Join(cloudCfgDir, "99_disable_growpart.cfg"), []byte(disableGrowPart), 0644); err != nil {
			return xerrors.Errorf("cannot create growpart override file: %w", err)
		}
	}

	return nil
}

func readUniqueData(path string, alg tpm2.ObjectTypeId) (*tpm2.PublicIDU, error) {
	log.Debugln("reading unique data from", path)

	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("cannot open file: %w", err)
	}

	switch alg {
	case tpm2.ObjectTypeRSA:
		var rsa tpm2.PublicKeyRSA
		if _, err := mu.UnmarshalFromReader(f, &rsa); err != nil {
			return nil, xerrors.Errorf("cannot unmarshal unique data: %w", err)
		}
		return &tpm2.PublicIDU{RSA: rsa}, nil
	case tpm2.ObjectTypeECC:
		var ecc *tpm2.ECCPoint
		if _, err := mu.UnmarshalFromReader(f, &ecc); err != nil {
			return nil, xerrors.Errorf("cannot unmarshal unique data: %w", err)
		}
		return &tpm2.PublicIDU{ECC: ecc}, nil
	}

	return nil, errors.New("unsupported type")
}

func writeCustomSRKTemplate(srkPub *tpm2.Public, path string, options *Options) error {
	log.Infoln("writing custom SRK template to", path)

	b, err := mu.MarshalToBytes(srkPub)
	if err != nil {
		return xerrors.Errorf("cannot marshal SRKpub: %w", err)
	}

	var srkTmpl *tpm2.Public
	if _, err := mu.UnmarshalFromBytes(b, &srkTmpl); err != nil {
		return xerrors.Errorf("cannot unmarshal SRK template: %w", err)
	}
	srkTmpl.Unique = nil

	if options.SRKTemplateUniqueData != "" {
		u, err := readUniqueData(options.SRKTemplateUniqueData, srkTmpl.Type)
		if err != nil {
			return xerrors.Errorf("cannot read unique data: %w", err)
		}
		srkTmpl.Unique = u
	}

	b, err = mu.MarshalToBytes(srkTmpl)
	if err != nil {
		return xerrors.Errorf("cannot marshal SRK template: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return xerrors.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	if _, err := mu.MarshalToWriter(f, b); err != nil {
		return xerrors.Errorf("cannot write SRK template to file: %w", err)
	}

	return nil
}

func readPublicArea(path string) (*tpm2.Public, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pubBytes []byte
	if _, err := mu.UnmarshalFromReader(f, &pubBytes); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal public area bytes: %w", err)
	}

	var pub *tpm2.Public
	if _, err := mu.UnmarshalFromBytes(pubBytes, &pub); err != nil {
		return nil, xerrors.Errorf("cannot unmarshal public area: %w", err)
	}

	return pub, nil
}

func computePCRProtectionProfile(esp string, options *Options, env secboot_efi.HostEnvironment) (*secboot.PCRProtectionProfile, error) {
	log.Infoln("computing PCR protection profile")
	pcrProfile := secboot.NewPCRProtectionProfile()

	loadSequences := []*secboot_efi.ImageLoadEvent{
		{
			Source: secboot_efi.Firmware,
			Image:  secboot_efi.FileImage(filepath.Join(esp, "EFI/ubuntu/shimx64.efi")),
			Next: []*secboot_efi.ImageLoadEvent{
				{
					Source: secboot_efi.Shim,
					Image:  secboot_efi.FileImage(filepath.Join(esp, "EFI/ubuntu/grubx64.efi")),
				},
			},
		},
	}

	if options.AddEFIBootManagerProfile {
		log.Debugln("adding boot manager PCR profile")
		params := secboot_efi.BootManagerProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: loadSequences,
			Environment:   env}
		if err := secboot_efi.AddBootManagerProfile(pcrProfile, &params); err != nil {
			return nil, xerrors.Errorf("cannot add EFI boot manager profile: %w", err)
		}
	}

	if options.AddEFISecureBootProfile {
		log.Debugln("adding secure boot policy PCR profile")
		params := secboot_efi.SecureBootPolicyProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: loadSequences,
			Environment:   env}
		if err := secboot_efi.AddSecureBootPolicyProfile(pcrProfile, &params); err != nil {
			return nil, xerrors.Errorf("cannot add EFI secure boot policy profile: %w", err)
		}
	}

	if options.AddUbuntuKernelProfile {
		pcrProfile.AddPCRValue(tpm2.HashAlgorithmSHA256, 12, make([]byte, tpm2.HashAlgorithmSHA256.Size()))

		// Note, kernel EFI stub only measures a commandline if one is supplied
		// TODO: Add kernel commandline
		// TODO: Add snap model
	}

	log.Debugln("PCR profile:", pcrProfile)
	pcrs, digests, err := pcrProfile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute PCR digests: %w", err)
	}
	log.Infoln("PCR selection:", pcrs)
	log.Infoln("PCR digests:")
	for _, digest := range digests {
		log.Debugf(" %x\n", digest)
	}

	return pcrProfile, nil
}

func newEFIEnvironment(options *Options) (secboot_efi.HostEnvironment, error) {
	if options.AzDiskProfile == "" {
		return nil, nil
	}

	f, err := os.Open(options.AzDiskProfile)
	if err != nil {
		return nil, xerrors.Errorf("cannot open az disk profile resource: %w", err)
	}
	defer f.Close()

	var profile efienv.AzDisk
	dec := json.NewDecoder(f)
	if err := dec.Decode(&profile); err != nil {
		return nil, xerrors.Errorf("cannot decode az disk profile resource: %w", err)
	}

	env, err := efienv.NewEnvironmentFromAzDiskProfile(&profile, tcglog.AlgorithmIdList{tcglog.AlgorithmSha256})
	if err != nil {
		return nil, xerrors.Errorf("cannot create environment from az disk profile resource: %w", err)
	}

	return env, nil
}

func validImageExt(ext string) bool {
	switch ext {
	case ".img", ".vhd":
		return true
	default:
		return false
	}
}

func mount(dev, path, fs string) error {
	cmd := exec.LoggedCommand("mount", "-t", fs, dev, path)
	return cmd.Run()
}

func unmount(path string) error {
	cmd := exec.LoggedCommand("umount", path)
	return cmd.Run()
}

func luks2Encrypt(path string, key []byte) error {
	cmd := exec.LoggedCommand("cryptsetup",
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
	cmd := exec.LoggedCommand("cryptsetup", "-v", "config", "--label", label, path)
	return cmd.Run()
}

func growExtFS(path string) error {
	cmd := exec.LoggedCommand("resize2fs", "-f", "-d", "30", path)
	return cmd.Run()
}

func shrinkExtFS(path string) error {
	cmd := exec.LoggedCommand("resize2fs", "-fM", "-d", "62", path)
	return cmd.Run()
}

func encryptExtDevice(path string) (k []byte, err error) {
	log.Infoln("shrinking fileystem on", path)
	if err := shrinkExtFS(path); err != nil {
		return nil, xerrors.Errorf("cannot shrink filesystem: %w", err)
	}

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, xerrors.Errorf("cannot obtain primary unlock key: %w", err)
	}

	log.Infoln("encrypting", path)
	if err := luks2Encrypt(path, key[:]); err != nil {
		return nil, xerrors.Errorf("cannot encrypt %s: %w", path, err)
	}

	log.Infoln("setting label")
	if err := luks2SetLabel(path, "cloudimg-rootfs-enc"); err != nil {
		return nil, xerrors.Errorf("cannot set label: %w", err)
	}

	volumeName := filepath.Base(path)
	log.Infoln("attaching encrypted container as", volumeName)
	if err := luks2.Activate(volumeName, path, key[:]); err != nil {
		return nil, xerrors.Errorf("cannot activate LUKS container: %w", err)
	}
	defer func() {
		log.Infoln("detaching", volumeName)
		if err := luks2.Deactivate(volumeName); err != nil {
			panic(&cleanupError{xerrors.Errorf("cannot detach container: %w", err)})
		}
	}()
	path = filepath.Join("/dev/mapper", volumeName)

	log.Infoln("growing filesystem on", path)
	if err := growExtFS(path); err != nil {
		return nil, xerrors.Errorf("cannot grow filesystem: %w", err)
	}

	return key[:], nil
}

type zipFileReader struct {
	f *os.File
	io.ReadCloser
}

func (r *zipFileReader) Close() error {
	r.ReadCloser.Close()
	return r.f.Close()
}

func openSourceImage(path string) (io.ReadCloser, error) {
	log.Debugln("opening source image from", path)
	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("cannot open file: %w", err)
	}

	switch {
	case filepath.Ext(path) == ".zip":
		log.Debugln("detected zip archive")
		fi, err := f.Stat()
		if err != nil {
			return nil, xerrors.Errorf("cannot determine file size: %w", err)
		}
		r, err := zip.NewReader(f, fi.Size())
		if err != nil {
			return nil, xerrors.Errorf("cannot create ZIP reader: %w", err)
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
			return &zipFileReader{f, rc}, nil
		}
	case validImageExt(filepath.Ext(path)):
		log.Debugln("detecting unpacked and uncompressed image")
		return f, nil
	}

	return nil, errors.New("no appropriate image found")
}

func connectImage(workingDir string, options *Options) (*nbd.Connection, error) {
	srcImg, err := openSourceImage(options.Input)
	if err != nil {
		return nil, xerrors.Errorf("cannot open source image: %w", err)
	}
	defer func() {
		if err := srcImg.Close(); err != nil {
			log.Warningln("cannot close source image: %v", err)
		}
	}()

	workingImgPath := filepath.Join(workingDir, filepath.Base(options.Output))
	log.Infoln("making copy of source image to", workingImgPath)
	if err := internal_ioutil.CopyFromReaderToFile(workingImgPath, srcImg); err != nil {
		return nil, xerrors.Errorf("cannot make working copy of source image: %w", err)
	}

	nbdConn, err := nbd.ConnectImage(workingImgPath)
	if err != nil {
		return nil, xerrors.Errorf("cannot connect %s: %w", workingImgPath, err)
	}
	log.Infoln("connected", workingImgPath, "to", nbdConn.DevPath())
	return nbdConn, nil
}

func checkPrerequisites(options *Options) error {
	if options.Input == "" || options.Output == "" {
		return errors.New("missing required --input or --output option")
	}

	if options.SRKPub == "" {
		return errors.New("missing --srk-pub option")
	}

	if options.StandardSRKTemplate && options.SRKTemplateUniqueData != "" {
		return errors.New("cannot specify both --standard-srk-template and --srk-template-unique-data")
	}

	if !nbd.IsSupported() {
		return errors.New("cannot create nbd devices (is qemu-nbd installed?)")
	}
	if !nbd.IsModuleLoaded() {
		return errors.New("cannot create nbd devices because the required kernel module is not loaded")
	}

	return nil
}

func configureLogging() {
	log.SetOutput(ioutil.Discard)

	w := logutil.NewFormattedWriter(
		[]log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
			log.WarnLevel})
	w.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		PadLevelText:           true})
	w.SetOutput(os.Stderr)
	log.AddHook(w)

	w = logutil.NewFormattedWriter(
		[]log.Level{
			log.InfoLevel,
			log.DebugLevel,
			log.TraceLevel})
	w.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		PadLevelText:           true})
	w.SetOutput(os.Stdout)
	log.AddHook(w)
}

func run(args []string) (err error) {
	configureLogging()

	var options Options
	if _, err := flags.ParseArgs(&options, args); err != nil {
		return xerrors.Errorf("cannot parse arguments: %w", err)
	}

	if options.Verbose {
		log.SetLevel(log.DebugLevel)
		log.Debugln("Enabling verbose output")
	}

	log.Debugln("args:", strings.Join(args, " "))

	if err := checkPrerequisites(&options); err != nil {
		return err
	}

	workingDir, err := ioutil.TempDir(filepath.Dir(options.Output), "tmp.")
	if err != nil {
		return xerrors.Errorf("cannot create working directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(workingDir); err != nil {
			panic(&cleanupError{xerrors.Errorf("cannot remove working directory: %w", err)})
		}
	}()
	log.Infoln("temporary working directory:", workingDir)

	nbdConn, err := connectImage(workingDir, &options)
	if err != nil {
		return xerrors.Errorf("cannot connect working image to NBD device: %w", err)
	}
	defer func() {
		if err != nil {
			return
		}
		if err := os.Rename(nbdConn.SourcePath(), options.Output); err != nil {
			panic(&cleanupError{xerrors.Errorf("cannot move working image to final path: %w", err)})
		}
	}()
	defer func() {
		log.Infoln("disconnecting", nbdConn.DevPath())
		if err := nbdConn.Disconnect(); err != nil {
			panic(&cleanupError{xerrors.Errorf("cannot disconnect from %s: %w", nbdConn.DevPath(), err)})
		}
	}()

	partitions, err := gpt.ReadPartitionTable(nbdConn.DevPath())
	if err != nil {
		return xerrors.Errorf("cannot read partition table from %s: %w", nbdConn.DevPath(), err)
	}
	log.Debugln("partition table for", nbdConn.DevPath(), ":", partitions)

	// XXX: Could there be more than one partition with this type?
	root := partitions.FindByPartitionType(linuxFilesystemGUID)
	if root == nil {
		return fmt.Errorf("cannot find partition with the type %v on %s", linuxFilesystemGUID, nbdConn.DevPath())
	}
	log.Debugln("rootfs partition on", nbdConn.DevPath(), ":", root)
	rootDevPath := fmt.Sprintf("%sp%d", nbdConn.DevPath(), root.Index)
	log.Infoln("device node for rootfs partition:", rootDevPath)

	if err := customizeRootFS(workingDir, rootDevPath, &options); err != nil {
		return xerrors.Errorf("cannot apply customizations to root filesystem: %w", err)
	}

	key, err := encryptExtDevice(rootDevPath)
	if err != nil {
		return xerrors.Errorf("cannot encrypt %s: %w", rootDevPath, err)
	}

	if options.GrowRoot {
		if err := growPartition(nbdConn.DevPath(), rootDevPath, root.Index); err != nil {
			return xerrors.Errorf("cannot grow root partition: %w", err)
		}
	}

	esp := partitions.FindByPartitionType(espGUID)
	if esp == nil {
		return fmt.Errorf("cannot find partition with the type %v on %s", espGUID, nbdConn.DevPath())
	}
	log.Debugln("ESP on", nbdConn.DevPath(), ":", esp)
	espDevPath := fmt.Sprintf("%sp%d", nbdConn.DevPath(), esp.Index)
	log.Infoln("device node for ESP:", espDevPath)

	espPath := filepath.Join(workingDir, "esp")
	if err := os.Mkdir(espPath, 0700); err != nil {
		return xerrors.Errorf("cannot create directory to mount ESP: %w", err)
	}
	log.Infoln("mounting ESP")
	if err := mount(espDevPath, espPath, "vfat"); err != nil {
		return xerrors.Errorf("cannot mount %s to %s: %w", espDevPath, espPath, err)
	}
	defer func() {
		log.Infoln("unmounting ESP")
		if err := unmount(espPath); err != nil {
			panic(&cleanupError{xerrors.Errorf("cannot unmount %s: %w", espPath, err)})
		}
	}()

	if options.KernelEfi != "" {
		dst := filepath.Join(espPath, "EFI/ubuntu/grubx64.efi")
		if err := os.Remove(dst); err != nil {
			return xerrors.Errorf("cannot remove grub: %w", err)
		}
		if err := internal_ioutil.CopyFile(dst, options.KernelEfi); err != nil {
			return xerrors.Errorf("cannot install kernel: %w", err)
		}
	}

	efiEnv, err := newEFIEnvironment(&options)
	if err != nil {
		return xerrors.Errorf("cannot create EFI environment for target: %w", err)
	}

	pcrProfile, err := computePCRProtectionProfile(espPath, &options, efiEnv)
	if err != nil {
		return xerrors.Errorf("cannot compute PCR protection profile: %w", err)
	}

	srkPub, err := readPublicArea(options.SRKPub)
	if err != nil {
		return xerrors.Errorf("cannot read SRK public area: %w", err)
	}
	srkName, err := srkPub.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of SRK: %w", err)
	}
	log.Infof("supplied SRK name: %x\n", srkName)

	log.Infoln("creating importable sealed key object")
	params := secboot.KeyCreationParams{
		PCRProfile:             pcrProfile,
		PCRPolicyCounterHandle: tpm2.HandleNull}
	if _, err := secboot.SealKeyToExternalTPMStorageKey(srkPub, key, filepath.Join(espPath, "cloudimg-rootfs.sealed-key"), &params); err != nil {
		return xerrors.Errorf("cannot seal disk unlock key: %w", err)
	}

	if !options.StandardSRKTemplate {
		if err := writeCustomSRKTemplate(srkPub, filepath.Join(espPath, "tpm2-srk.tmpl"), &options); err != nil {
			return xerrors.Errorf("cannot write custom SRK template: %w", err)
		}
	}

	return nil
}

func main() {
	defer func() {
		if v := recover(); v != nil {
			if e, ok := v.(error); ok {
				var c *cleanupError
				if xerrors.As(e, &c) {
					log.Fatal(e)
				}
			}
			panic(v)
		}
	}()

	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
