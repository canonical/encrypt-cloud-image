// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	"github.com/canonical/encrypt-cloud-image/internal/gpt"
	internal_ioutil "github.com/canonical/encrypt-cloud-image/internal/ioutil"
	log "github.com/sirupsen/logrus"

	snapd_dmverity "github.com/snapcore/snapd/snap/integrity/dmverity"
	"golang.org/x/xerrors"
)

const (
	verityPartitionNum = 13
)

type integrityOptions struct {
	Output string `short:"o" long:"output" description:"Output image path"`

	Positional struct {
		Input string `positional-arg-name:"Source image path (file or block device)"`
	} `positional-args:"true" required:"true"`
}

func (o *integrityOptions) Execute(_ []string) error {
	d := new(imageIntegrityProtector)
	return d.run(o)
}

type imageIntegrityProtector struct {
	encryptCloudImageBase

	opts            *integrityOptions
	failed          bool
	verityPartition *gpt.PartitionEntry
}

func (i *imageIntegrityProtector) createIntegrityDataForRootPartition() (string, string, error) {
	devPath := i.rootDevPath()

	verityFilePath := filepath.Join(i.workingDirPath(), "rootfs.verity")

	// Run fsck on root partition before calculating verity data
	cmd := internal_exec.LoggedCommand("fsck", "-p", devPath)

	if err := cmd.Run(); err != nil {
		return "", "", err
	}

	log.Infoln("generating verity data for root partition")
	verityInfo, err := snapd_dmverity.Format(devPath, verityFilePath)
	if err != nil {
		return "", "", err
	}

	return verityInfo.RootHash, verityFilePath, nil
}

func (i *imageIntegrityProtector) updateVerityPartition(verityFilePath string) error {
	log.Infoln("updating verity partition ", i.verityDevPath())

	// XXX: this is a hack that populates the verity partition index which is used
	// by verityDevPath() in the dd command below. This is needed as the new
	// partition cannot be discovered unless the disk is remounted.
	i.verity = &gpt.PartitionEntry{
		Index: verityPartitionNum,
	}

	cmd := internal_exec.LoggedCommand("dd",
		"if="+verityFilePath,
		"of="+i.verityDevPath(),
	)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// These match the structs in snap-bootstrap
type ImageManifestPartition struct {
	FsLabel  string `json:"label"`
	RootHash string `json:"root_hash"`
	Overlay  string `json:"overlay"`
}

type ImageManifest struct {
	Partitions []ImageManifestPartition `json:"partitions"`
}

func (i *imageIntegrityProtector) integrityProtectImageOnDevice() error {
	if i.devPath == "" {
		panic("no device path")
	}

	i.enterScope()
	defer i.exitScope()

	if err := i.detectPartitions(); err != nil {
		return err
	}

	rootHash, verityFilePath, err := i.createIntegrityDataForRootPartition()
	if err != nil {
		return err
	}

	log.Infoln("dm-verity root hash for the root partition: ", rootHash)

	err = i.updateVerityPartition(verityFilePath)
	if err != nil {
		return err
	}

	log.Infoln("generating manifest with integrity information for image on", i.devPath)

	partition := ImageManifestPartition{
		FsLabel:  "cloudimg-rootfs",
		RootHash: rootHash,
		Overlay:  "lowerdir",
	}

	im := &ImageManifest{
		Partitions: []ImageManifestPartition{partition},
	}

	imJson, err := json.Marshal(im)
	if err != nil {
		return err
	}

	espPath, err := i.mountESP()
	if err != nil {
		return err
	}

	ukiRootPath := filepath.Join(espPath, "EFI/ubuntu")
	log.Infoln("creating manifest under", ukiRootPath)

	if err := os.WriteFile(filepath.Join(ukiRootPath, "manifest.json"), imJson, 0644); err != nil {
		return xerrors.Errorf("cannot create manifest file: %w", err)
	}

	return nil
}

func (i *imageIntegrityProtector) prepareWorkingImage() (string, error) {
	f, err := os.Open(i.opts.Positional.Input)
	if err != nil {
		return "", xerrors.Errorf("cannot open source image: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.WithError(err).Warningln("cannot close source image")
		}
	}()

	r, err := tryToOpenArchivedImage(f)
	switch {
	case err != nil:
		return "", xerrors.Errorf("cannot open archived source image: %w", err)
	case r != nil:
		// Input file is an archive with a valid image
		defer func() {
			if err := r.Close(); err != nil {
				log.WithError(err).Warningln("cannot close unpacked source image")
			}
		}()
		if i.opts.Output == "" {
			return "", errors.New("must specify --ouptut if the supplied input source is an archive")
		}
	case i.opts.Output != "":
		// Input file is not an archive and we are not encrypting the source image
		r = f
	default:
		// Input file is not an archive and we are encrypting the source image
		return "", nil
	}

	path := filepath.Join(i.workingDirPath(), filepath.Base(i.opts.Output))
	log.Infoln("making copy of source image to", path)
	if err := internal_ioutil.CopyFromReaderToFile(path, r); err != nil {
		return "", xerrors.Errorf("cannot make working copy of source image: %w", err)
	}

	return path, nil
}

func (i *imageIntegrityProtector) integrityProtectImageFromFile() error {
	path, err := i.prepareWorkingImage()
	switch {
	case err != nil:
		return xerrors.Errorf("cannot prepare working image: %w", err)
	case path != "":
		// We aren't encrypting the source image
		i.addCleanup(func() error {
			if i.failed {
				return nil
			}
			if err := os.Rename(path, i.opts.Output); err != nil {
				return xerrors.Errorf("cannot move working image to final path: %w", err)
			}
			return nil
		})
	default:
		// We are encrypting the source image
		path = i.opts.Positional.Input
	}

	if err := i.connectNbd(path); err != nil {
		return err
	}

	return i.integrityProtectImageOnDevice()
}

func (i *imageIntegrityProtector) setupWorkingDir() error {
	var baseDir string
	if i.opts.Output != "" {
		baseDir = filepath.Dir(i.opts.Output)
	}
	return i.encryptCloudImageBase.setupWorkingDir(baseDir)
}

func (i *imageIntegrityProtector) run(opts *integrityOptions) error {
	i.opts = opts

	i.enterScope()
	defer i.exitScope()

	fi, err := os.Stat(opts.Positional.Input)
	if err != nil {
		return xerrors.Errorf("cannot obtain source file information: %w", err)
	}

	if opts.Output != "" && fi.Mode()&os.ModeDevice != 0 {
		return errors.New("cannot specify --output with a block device")
	}

	if err := i.setupWorkingDir(); err != nil {
		return err
	}

	if fi.Mode()&os.ModeDevice != 0 {
		// Source file is a block device
		i.devPath = opts.Positional.Input
		if i.isNbdDevice() {
			if err := i.checkNbdPreRequisites(); err != nil {
				return err
			}
		}

		return i.integrityProtectImageOnDevice()
	}

	// Source file is not a block device
	if err := i.checkNbdPreRequisites(); err != nil {
		return err
	}

	return i.integrityProtectImageFromFile()
}

func init() {
	if _, err := parser.AddCommand("integrity-protect", "Generate dm-verity data for the root fs partition and a configurationo manifest", "", &integrityOptions{}); err != nil {
		log.WithError(err).Panicln("cannot add verity command")
	}
}
