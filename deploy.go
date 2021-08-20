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
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/tcglog-parser"
	log "github.com/sirupsen/logrus"
	secboot_efi "github.com/snapcore/secboot/efi"
	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/chrisccoulson/encrypt-cloud-image/internal/efienv"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/gpt"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/luks2"
)

type deployOptions struct {
	AddEFIBootManagerProfile bool `long:"add-efi-boot-manager-profile" description:"Protect the disk unlock key with the EFI boot manager code and boot attempts profile (PCR4)"`
	AddEFISecureBootProfile  bool `long:"add-efi-secure-boot-profile" description:"Protect the disk unlock key with the EFI secure boot policy profile (PCR7)"`
	AddUbuntuKernelProfile   bool `long:"add-ubuntu-kernel-profile" description:"Protect the disk unlock key with properties measured by the Ubuntu kernel (PCR12). Also prevents access outside of early boot"`

	AzDiskProfile string `long:"az-disk-profile" description:""`
	UefiConfig    string `long:"uefi-config" description:"JSON file describring the platform firmware configuration"`

	SRKTemplateUniqueData string `long:"srk-template-unique-data" description:"Path to the TPMU_PUBLIC_ID structure used to create the SRK"`
	SRKPub                string `long:"srk-pub" description:"Path to SRK public area" required:"true"`
	StandardSRKTemplate   bool   `long:"standard-srk-template" description:"Indicate that the supplied SRK was created with the TCG TPM v2.0 Provisioning Guidance spec"`

	Positional struct {
		Input string
	} `positional-args:"true" description:"Image path" required:"true"`
}

func (o *deployOptions) Execute(_ []string) error {
	if o.StandardSRKTemplate && o.SRKTemplateUniqueData != "" {
		return errors.New("cannot specify both --standard-srk-template and --srk-template-unique-data")
	}

	if o.AzDiskProfile != "" && o.UefiConfig != "" {
		return errors.New("cannot specify both --az-disk-profile and --uefi-config")
	}

	if strings.HasPrefix(o.Positional.Input, "/dev/") {
		return deployQemuDevice(o, o.Positional.Input)
	} else {
		return deployImage(o, o.Positional.Input)
	}
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

func writeCustomSRKTemplate(srkPub *tpm2.Public, path string, opts *deployOptions) error {
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

	if opts.SRKTemplateUniqueData != "" {
		u, err := readUniqueData(opts.SRKTemplateUniqueData, srkTmpl.Type)
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

func computePCRProtectionProfile(esp string, opts *deployOptions, env secboot_efi.HostEnvironment) (*secboot_tpm2.PCRProtectionProfile, error) {
	log.Infoln("computing PCR protection profile")
	pcrProfile := secboot_tpm2.NewPCRProtectionProfile()

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

	if opts.AddEFIBootManagerProfile {
		log.Debugln("adding boot manager PCR profile")
		params := secboot_efi.BootManagerProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: loadSequences,
			Environment:   env}
		if err := secboot_efi.AddBootManagerProfile(pcrProfile, &params); err != nil {
			return nil, xerrors.Errorf("cannot add EFI boot manager profile: %w", err)
		}
	}

	if opts.AddEFISecureBootProfile {
		log.Debugln("adding secure boot policy PCR profile")
		params := secboot_efi.SecureBootPolicyProfileParams{
			PCRAlgorithm:  tpm2.HashAlgorithmSHA256,
			LoadSequences: loadSequences,
			Environment:   env}
		if err := secboot_efi.AddSecureBootPolicyProfile(pcrProfile, &params); err != nil {
			return nil, xerrors.Errorf("cannot add EFI secure boot policy profile: %w", err)
		}
	}

	if opts.AddUbuntuKernelProfile {
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
		return nil, xerrors.Errorf("cannot compute PCR values: %w", err)
	}
	log.Infoln("PCR values:", pcrValues)
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
		return nil, xerrors.Errorf("cannot compute PCR digests: %w", err)
	}
	log.Infoln("PCR selection:", pcrs)
	log.Infoln("PCR digests:")
	for _, digest := range digests {
		log.Debugf(" %x\n", digest)
	}

	return pcrProfile, nil
}

func newEFIEnvironment(opts *deployOptions) (secboot_efi.HostEnvironment, error) {
	log.Infoln("creating EFI environment for guest")
	switch {
	case opts.AzDiskProfile != "":
		log.Debugln("creating EFI environment from supplied az disk profile")
		f, err := os.Open(opts.AzDiskProfile)
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
	case opts.UefiConfig != "":
		log.Debugln("creating EFI environment from supplied UEFI config")
		f, err := os.Open(opts.UefiConfig)
		if err != nil {
			return nil, xerrors.Errorf("cannot open UEFI config: %w", err)
		}
		defer f.Close()

		var config efienv.Config
		dec := json.NewDecoder(f)
		if err := dec.Decode(&config); err != nil {
			return nil, xerrors.Errorf("cannot decode UEFI config: %w", err)
		}

		return efienv.NewEnvironment(&config, tcglog.AlgorithmIdList{tcglog.AlgorithmSha256}), nil
	}

	return nil, nil
}

func readKeyFromImage(devicePath string, partitions gpt.Partitions) (key []byte, removeToken func() error, err error) {
	log.Infoln("reading key from LUKS2 container")

	for _, partition := range partitions {
		path := fmt.Sprintf("%sp%d", devicePath, partition.Index)
		log.Debugln("trying", path)

		hdr, err := luks2.ReadHeader(path, luks2.LockModeBlocking)
		if err != nil {
			continue
		}

		for i, token := range hdr.Metadata.Tokens {
			if token.Type != luks2TokenType {
				continue
			}

			log.Debugln("found token at index", i, "on", path)

			k, ok := token.Params[luks2TokenKey]
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

			return key, func() error {
				log.Infoln("removing cleartext token from LUKS2 container")
				return luks2.RemoveToken(path, i)
			}, nil
		}
	}

	return nil, nil, errors.New("no value LUKS2 container found")
}

func deployImageHelper(opts *deployOptions, qemuDevice string) error {
	workingDir, cleanupWorkingDir, err := mkTempDir("")
	if err != nil {
		return xerrors.Errorf("cannot create working directory: %w", err)
	}
	defer cleanupWorkingDir()
	log.Infoln("temporary working directory:", workingDir)
	partitions, err := gpt.ReadPartitionTable(qemuDevice)
	if err != nil {
		return xerrors.Errorf("cannot read partition table from %s: %w", qemuDevice, err)
	}
	log.Debugln("partition table for", qemuDevice, ":", partitions)

	key, removeToken, err := readKeyFromImage(qemuDevice, partitions)
	if err != nil {
		return xerrors.Errorf("cannot read key from LUKS2 container: %w", err)
	}

	esp := partitions.FindByPartitionType(espGUID)
	if esp == nil {
		return fmt.Errorf("cannot find partition with the type %v on %s", espGUID, qemuDevice)
	}
	log.Debugln("ESP on", qemuDevice, ":", esp)
	espDevPath := fmt.Sprintf("%sp%d", qemuDevice, esp.Index)
	log.Infoln("device node for ESP:", espDevPath)

	espPath := filepath.Join(workingDir, "esp")
	if err := os.Mkdir(espPath, 0700); err != nil {
		return xerrors.Errorf("cannot create directory to mount ESP: %w", err)
	}

	defer func() {
		if err := os.Remove(espPath); err != nil {
			log.WithError(err).Warningln("cannot remove path %s", espPath)
		}
	}()

	log.Infoln("mounting ESP to", espPath)
	unmountEsp, err := mount(espDevPath, espPath, "vfat")
	if err != nil {
		return xerrors.Errorf("cannot mount %s to %s: %w", espDevPath, espPath, err)
	}
	defer unmountEsp()

	efiEnv, err := newEFIEnvironment(opts)
	if err != nil {
		return xerrors.Errorf("cannot create EFI environment for target: %w", err)
	}

	pcrProfile, err := computePCRProtectionProfile(espPath, opts, efiEnv)
	if err != nil {
		return xerrors.Errorf("cannot compute PCR protection profile: %w", err)
	}

	srkPub, err := readPublicArea(opts.SRKPub)
	if err != nil {
		return xerrors.Errorf("cannot read SRK public area: %w", err)
	}
	srkName, err := srkPub.Name()
	if err != nil {
		return xerrors.Errorf("cannot compute name of SRK: %w", err)
	}
	log.Infof("supplied SRK name: %x\n", srkName)

	keyDir := filepath.Join(espPath, "device/fde")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return xerrors.Errorf("cannot create directory to store sealed disk unlock key: %w", err)
	}

	log.Infoln("creating importable sealed key object")
	params := secboot_tpm2.KeyCreationParams{
		PCRProfile:             pcrProfile,
		PCRPolicyCounterHandle: tpm2.HandleNull}
	if _, err := secboot_tpm2.SealKeyToExternalTPMStorageKey(srkPub, key, filepath.Join(keyDir, "cloudimg-rootfs.sealed-key"), &params); err != nil {
		return xerrors.Errorf("cannot seal disk unlock key: %w", err)
	}

	if !opts.StandardSRKTemplate {
		if err := writeCustomSRKTemplate(srkPub, filepath.Join(espPath, "tpm2-srk.tmpl"), opts); err != nil {
			return xerrors.Errorf("cannot write custom SRK template: %w", err)
		}
	}

	if err := removeToken(); err != nil {
		return xerrors.Errorf("cannot remove cleartext token from LUKS2 container: %w", err)
	}

	return nil

}

func deployQemuDevice(opts *deployOptions, qemuDevice string) error {
	if err := deployImageHelper(opts, qemuDevice); err != nil {
		return xerrors.Errorf("Encrypting inplace failed with %s", qemuDevice)
	}

	return nil
}

func deployImage(opts *deployOptions, imagePath string) error {
	nbdConn, disconnectNbd, err := connectNbd(imagePath)
	if err != nil {
		return xerrors.Errorf("cannot connect %s: %w", opts.Positional.Input, err)
	}
	defer disconnectNbd()
	log.Infoln("connected", imagePath, "to", nbdConn.DevPath())

	if err := deployImageHelper(opts, imagePath); err != nil {
		return xerrors.Errorf("cannot encrypt image device %s for %s", nbdConn.DevPath(), imagePath)
	}

	return nil
}

func init() {
	if _, err := parser.AddCommand("deploy", "Prepare an encrypted image for deployment to a specific guest instance", "", &deployOptions{}); err != nil {
		log.WithError(err).Panicln("cannot add deploy command")
	}
}
