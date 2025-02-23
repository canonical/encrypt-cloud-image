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
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/tcglog-parser"
	log "github.com/sirupsen/logrus"
	"github.com/snapcore/secboot"
	secboot_efi "github.com/snapcore/secboot/efi"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"

	"github.com/canonical/encrypt-cloud-image/internal/efienv"
	"github.com/canonical/encrypt-cloud-image/internal/luks2"
)

type deployOptions struct {
	RecoveryKeyFile          string `long:"recovery-key-file" description:"Add a recovery key from the supplied file. The key must be 16-bytes long"`
	AddEFIBootManagerProfile bool   `long:"add-efi-boot-manager-profile" description:"Protect the disk unlock key with the EFI boot manager code and boot attempts profile (PCR4)"`
	AddEFISecureBootProfile  bool   `long:"add-efi-secure-boot-profile" description:"Protect the disk unlock key with the EFI secure boot policy profile (PCR7)"`
	AddUbuntuKernelProfile   bool   `long:"add-ubuntu-kernel-profile" description:"Protect the disk unlock key with properties measured by the Ubuntu kernel (PCR12). Also prevents access outside of early boot"`

	AzDiskProfile string `long:"az-disk-profile" description:""`
	UefiConfig    string `long:"uefi-config" description:"JSON file describring the platform firmware configuration"`

	SRKTemplateUniqueData string `long:"srk-template-unique-data" description:"Path to the TPMU_PUBLIC_ID structure used to create the SRK"`
	SRKPub                string `long:"srk-pub" description:"Path to SRK public area" required:"true"`
	StandardSRKTemplate   bool   `long:"standard-srk-template" description:"Indicate that the supplied SRK was created with the TCG TPM v2.0 Provisioning Guidance spec"`

	Positional struct {
		Input string `positional-arg-name:"Source image path (file or block device)"`
	} `positional-args:"true" required:"true"`
}

func (o *deployOptions) Execute(_ []string) error {
	d := new(imageDeployer)
	return d.run(o)
}

func readUniqueData(path string, alg tpm2.ObjectTypeId) (*tpm2.PublicIDU, error) {
	log.Debugln("reading unique data from", path)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}

	switch alg {
	case tpm2.ObjectTypeRSA:
		var rsa tpm2.PublicKeyRSA
		if _, err := mu.UnmarshalFromReader(f, &rsa); err != nil {
			return nil, fmt.Errorf("cannot unmarshal unique data: %w", err)
		}
		return &tpm2.PublicIDU{RSA: rsa}, nil
	case tpm2.ObjectTypeECC:
		var ecc *tpm2.ECCPoint
		if _, err := mu.UnmarshalFromReader(f, &ecc); err != nil {
			return nil, fmt.Errorf("cannot unmarshal unique data: %w", err)
		}
		return &tpm2.PublicIDU{ECC: ecc}, nil
	}

	return nil, errors.New("unsupported type")
}

type imageDeployer struct {
	encryptCloudImageBase

	opts *deployOptions
}

func (d *imageDeployer) maybeAddRecoveryKey(key []byte) error {
	if d.opts.RecoveryKeyFile == "" {
		return nil
	}

	log.Infoln("Adding recovery key to image")
	b, err := ioutil.ReadFile(d.opts.RecoveryKeyFile)
	if err != nil {
		return fmt.Errorf("cannot read recovery key from file: %w", err)
	}
	if len(b) != 16 {
		return errors.New("recovery key must be 16 bytes")
	}

	var recoveryKey secboot.RecoveryKey
	copy(recoveryKey[:], b)
	return secboot.AddRecoveryKeyToLUKS2Container(d.rootDevPath(), key, recoveryKey, nil)
}

func (d *imageDeployer) maybeWriteCustomSRKTemplate(esp string, srkPub *tpm2.Public) error {
	if d.opts.StandardSRKTemplate {
		return nil
	}

	path := filepath.Join(esp, "tpm2-srk.tmpl")

	log.Infoln("writing custom SRK template to", path)

	b, err := mu.MarshalToBytes(srkPub)
	if err != nil {
		return fmt.Errorf("cannot marshal SRKpub: %w", err)
	}

	var srkTmpl *tpm2.Public
	if _, err := mu.UnmarshalFromBytes(b, &srkTmpl); err != nil {
		return fmt.Errorf("cannot unmarshal SRK template: %w", err)
	}
	srkTmpl.Unique = nil

	if d.opts.SRKTemplateUniqueData != "" {
		u, err := readUniqueData(d.opts.SRKTemplateUniqueData, srkTmpl.Type)
		if err != nil {
			return fmt.Errorf("cannot read unique data: %w", err)
		}
		srkTmpl.Unique = u
	}

	b, err = mu.MarshalToBytes(srkTmpl)
	if err != nil {
		return fmt.Errorf("cannot marshal SRK template: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	if _, err := mu.MarshalToWriter(f, b); err != nil {
		return fmt.Errorf("cannot write SRK template to file: %w", err)
	}

	return nil
}

func (d *imageDeployer) readSRKPublicArea() (*tpm2.Public, error) {
	f, err := os.Open(d.opts.SRKPub)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pubBytes []byte
	if _, err := mu.UnmarshalFromReader(f, &pubBytes); err != nil {
		return nil, fmt.Errorf("cannot unmarshal public area bytes: %w", err)
	}

	var pub *tpm2.Public
	if _, err := mu.UnmarshalFromBytes(pubBytes, &pub); err != nil {
		return nil, fmt.Errorf("cannot unmarshal public area: %w", err)
	}

	return pub, nil
}

func (d *imageDeployer) computePCRProtectionProfile(esp string, env secboot_efi.HostEnvironment) (*secboot_tpm2.PCRProtectionProfile, error) {
	log.Infoln("computing PCR protection profile")
	pcrProfile := secboot_tpm2.NewPCRProtectionProfile()

	// This function assumes that the boot architecture is Azure FDE (no grub)
	kernelPaths, err := filepath.Glob(filepath.Join(esp, "EFI/ubuntu/kernel.efi-*"))
	if err != nil {
		return nil, fmt.Errorf("cannot determine kernel paths: %w", err)
	}
	if _, err := os.Stat(filepath.Join(esp, "EFI/ubuntu/grubx64.efi")); err == nil {
		// Candidate images shipped a kernel at the grub path
		kernelPaths = append(kernelPaths, filepath.Join(esp, "EFI/ubuntu/grubx64.efi"))
	}

	var kernels []*secboot_efi.ImageLoadEvent
	for _, path := range kernelPaths {
		log.Debugln("found kernel", path)
		kernels = append(kernels, &secboot_efi.ImageLoadEvent{
			Source: secboot_efi.Shim,
			Image: secboot_efi.FileImage(path)})
	}

	loadSequences := &secboot_efi.ImageLoadEvent{
		Source: secboot_efi.Firmware,
		Image: secboot_efi.FileImage(filepath.Join(esp, "EFI/ubuntu/shimx64.efi")),
		Next: kernels}

	if d.opts.AddEFIBootManagerProfile {
		log.Debugln("adding boot manager PCR profile")
		params := secboot_efi.BootManagerProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: []*secboot_efi.ImageLoadEvent{loadSequences},
			Environment:   env}
		if err := secboot_efi.AddBootManagerProfile(pcrProfile, &params); err != nil {
			return nil, fmt.Errorf("cannot add EFI boot manager profile: %w", err)
		}
	}

	if d.opts.AddEFISecureBootProfile {
		log.Debugln("adding secure boot policy PCR profile")
		params := secboot_efi.SecureBootPolicyProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: []*secboot_efi.ImageLoadEvent{loadSequences},
			Environment:   env}
		if err := secboot_efi.AddSecureBootPolicyProfile(pcrProfile, &params); err != nil {
			return nil, fmt.Errorf("cannot add EFI secure boot policy profile: %w", err)
		}
	}

	if d.opts.AddUbuntuKernelProfile {
		pcrProfile.AddPCRValue(tpm2.HashAlgorithmSHA256, 12, make([]byte, tpm2.HashAlgorithmSHA256.Size()))

		// Note, kernel EFI stub only measures a commandline if one is supplied
		// TODO: Add kernel commandline
		// TODO: Add snap model

		// snap-bootstrap measures an epoch
		h := crypto.SHA256.New()
		binary.Write(h, binary.LittleEndian, uint32(0))
		pcrProfile.ExtendPCR(tpm2.HashAlgorithmSHA256, 12, h.Sum(nil))
	}

	log.Debugln("PCR profile:", pcrProfile)
	pcrValues, err := pcrProfile.ComputePCRValues(nil)
	if err != nil {
		return nil, fmt.Errorf("cannot compute PCR values: %w", err)
	}
	log.Infoln("PCR values:")
	for i, values := range pcrValues {
		log.Infof(" branch %d:\n", i)
		for alg := range values {
			for pcr := range values[alg] {
				log.Infof("  PCR%d,%v: %x\n", pcr, alg, values[alg][pcr])
			}
		}
	}
	pcrs, digests, err := pcrProfile.ComputePCRDigests(nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, fmt.Errorf("cannot compute PCR digests: %w", err)
	}
	log.Infoln("PCR selection:", pcrs)
	log.Infoln("PCR digests:")
	for _, digest := range digests {
		log.Debugf(" %x\n", digest)
	}

	return pcrProfile, nil
}

func (d *imageDeployer) newEFIEnvironment() (secboot_efi.HostEnvironment, error) {
	log.Infoln("creating EFI environment for guest")
	switch {
	case d.opts.AzDiskProfile != "":
		log.Debugln("creating EFI environment from supplied az disk profile")
		f, err := os.Open(d.opts.AzDiskProfile)
		if err != nil {
			return nil, fmt.Errorf("cannot open az disk profile resource: %w", err)
		}
		defer f.Close()

		var profile efienv.AzDisk
		dec := json.NewDecoder(f)
		if err := dec.Decode(&profile); err != nil {
			return nil, fmt.Errorf("cannot decode az disk profile resource: %w", err)
		}

		env, err := efienv.NewEnvironmentFromAzDiskProfile(&profile, tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA256})
		if err != nil {
			return nil, fmt.Errorf("cannot create environment from az disk profile resource: %w", err)
		}

		return env, nil
	case d.opts.UefiConfig != "":
		log.Debugln("creating EFI environment from supplied UEFI config")
		f, err := os.Open(d.opts.UefiConfig)
		if err != nil {
			return nil, fmt.Errorf("cannot open UEFI config: %w", err)
		}
		defer f.Close()

		var config efienv.Config
		dec := json.NewDecoder(f)
		if err := dec.Decode(&config); err != nil {
			return nil, fmt.Errorf("cannot decode UEFI config: %w", err)
		}

		return efienv.NewEnvironment(&config, tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA256}), nil
	}

	return nil, nil
}

func (d *imageDeployer) readKeyFromImage() (key []byte, removeToken func() error, err error) {
	log.Infoln("reading key from LUKS2 container")

	for _, partition := range d.partitions {
		devPathFormat, err := d.getDevPathFormat()
		if err != nil {
			return nil, nil, errors.New(err.Error())
		}

		path := fmt.Sprintf(devPathFormat, d.devPath, partition.Index)
		log.Debugln("trying", path)

		hdr, err := luks2.ReadHeader(path, luks2.LockModeBlocking)
		if err != nil {
			continue
		}

		for i, token := range hdr.Metadata.Tokens {
			if token.Type() != luks2TokenType {
				continue
			}

			log.Debugln("found token at index", i, "on", path)

			k, ok := token.(*luks2.GenericToken).Params[luks2TokenKey]
			if !ok {
				return nil, nil, errors.New("token has missing field")
			}

			s, ok := k.(string)
			if !ok {
				return nil, nil, errors.New("token data has the wrong type")
			}

			key, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return nil, nil, err
			}

			d.rootPartition = partition

			return key, func() error {
				log.Infoln("removing cleartext token from LUKS2 container")
				return luks2.RemoveToken(path, i)
			}, nil
		}
	}

	return nil, nil, errors.New("no valid LUKS2 container found")
}

func (d *imageDeployer) deployImageOnDevice() error {
	if d.devPath == "" {
		panic("no device path")
	}

	log.Infoln("deploying image on", d.devPath)

	if err := d.setupWorkingDir(""); err != nil {
		return err
	}

	if err := d.detectPartitions(); err != nil {
		return err
	}

	key, removeToken, err := d.readKeyFromImage()
	if err != nil {
		return fmt.Errorf("cannot load key from LUKS2 container: %w", err)
	}

	espPath, err := d.mountESP()
	if err != nil {
		return err
	}

	efiEnv, err := d.newEFIEnvironment()
	if err != nil {
		return fmt.Errorf("cannot create EFI environment for target: %w", err)
	}

	pcrProfile, err := d.computePCRProtectionProfile(espPath, efiEnv)
	if err != nil {
		return fmt.Errorf("cannot compute PCR protection profile: %w", err)
	}

	srkPub, err := d.readSRKPublicArea()
	if err != nil {
		return fmt.Errorf("cannot read SRK public area: %w", err)
	}
	srkName, err := srkPub.Name()
	if err != nil {
		return fmt.Errorf("cannot compute name of SRK: %w", err)
	}
	log.Infof("supplied SRK name: %x\n", srkName)

	keyDir := filepath.Join(espPath, "device/fde")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("cannot create directory to store sealed disk unlock key: %w", err)
	}

	log.Infoln("creating importable sealed key object")
	params := secboot_tpm2.KeyCreationParams{
		PCRProfile:             pcrProfile,
		PCRPolicyCounterHandle: tpm2.HandleNull}
	if _, err := secboot_tpm2.SealKeyToExternalTPMStorageKey(srkPub, key, filepath.Join(keyDir, "cloudimg-rootfs.sealed-key"), &params); err != nil {
		return fmt.Errorf("cannot seal disk unlock key: %w", err)
	}

	if err := d.maybeWriteCustomSRKTemplate(espPath, srkPub); err != nil {
		return fmt.Errorf("cannot write custom SRK template: %w", err)
	}

	if err := d.maybeAddRecoveryKey(key); err != nil {
		return fmt.Errorf("cannot add recovery key: %w", err)
	}

	if err := removeToken(); err != nil {
		return fmt.Errorf("cannot remove cleartext token from LUKS2 container: %w", err)
	}

	return nil
}

func (d *imageDeployer) deployImageFromFile() error {
	if err := d.connectNbd(d.opts.Positional.Input); err != nil {
		return err
	}

	return d.deployImageOnDevice()
}

func (d *imageDeployer) run(opts *deployOptions) error {
	d.opts = opts

	d.enterScope()
	defer d.exitScope()

	if opts.StandardSRKTemplate && opts.SRKTemplateUniqueData != "" {
		return errors.New("cannot specify both --standard-srk-template and --srk-template-unique-data")
	}

	if opts.AzDiskProfile != "" && opts.UefiConfig != "" {
		return errors.New("cannot specify both --az-disk-profile and --uefi-config")
	}

	fi, err := os.Stat(opts.Positional.Input)
	if err != nil {
		return fmt.Errorf("cannot obtain source file information: %w", err)
	}

	if fi.Mode()&os.ModeDevice != 0 {
		// Source file is a block device
		d.devPath = opts.Positional.Input
		if d.isNbdDevice() {
			if err := d.checkNbdPreRequisites(); err != nil {
				return err
			}
		}

		return d.deployImageOnDevice()
	}

	// Source file is not a block device
	if err := d.checkNbdPreRequisites(); err != nil {
		return err
	}

	return d.deployImageFromFile()
}

func init() {
	if _, err := parser.AddCommand("deploy", "Prepare an encrypted image for deployment to a specific guest instance", "", &deployOptions{}); err != nil {
		log.WithError(err).Panicln("cannot add deploy command")
	}
}
