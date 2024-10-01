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
	"github.com/canonical/encrypt-cloud-image/internal/fs"
	"github.com/canonical/encrypt-cloud-image/internal/gpt"
	log "github.com/sirupsen/logrus"

	snapd_dmverity "github.com/snapcore/snapd/snap/integrity/dmverity"
	"golang.org/x/xerrors"
)

const (
	verityPartitionNum = 2
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

func (o *integrityOptions) GetPositionalInput() string {
	return o.Positional.Input
}

func (o *integrityOptions) GetOutput() string {
	return o.Output
}

func sectorsFromBlocks(blockCount uint64) uint64 {
	fsSize := blockCount * fs.BlockSize
	// gpt.BlockSize corresponds to the sector size
	fsSectors := fsSize / gpt.BlockSize
	// partitions are aligned to 2048-sector boundaries
	return ((fsSectors-1)/2048 + 1) * 2048
}

type imageIntegrityProtector struct {
	encryptCloudImageBase

	opts            *integrityOptions
	failed          bool
	verityPartition *gpt.PartitionEntry
}

func (i *imageIntegrityProtector) prepareRootPartition() error {
	devPath := i.rootDevPath()

	log.Infoln("shrinking fileystem on", devPath)
	if err := shrinkExtFS(devPath); err != nil {
		return fmt.Errorf("cannot shrink filesystem: %w", err)
	}

	// If the image has been booted before, filesystem errors that will
	// be corrected on boot might cause verity errors.
	log.Infoln("running checks on", devPath)
	cmd := internal_exec.LoggedCommand("fsck", "-p", devPath)

	if err := cmd.Run(); err != nil {
		return err
	}

	log.Infoln("resizing partition", devPath)

	blockCount, err := fs.GetBlockCount(devPath)
	if err != nil {
		return err
	}

	endingLBA := uint64(i.rootPartition.StartingLBA) + sectorsFromBlocks(blockCount) - 1

	action := func() error {
		cmd = internal_exec.LoggedCommand("sgdisk",
			i.imagePath,
			"--delete",
			fmt.Sprintf("%d", 1),
			"--new",
			fmt.Sprintf("%d:%d:%d", 1, i.rootPartition.StartingLBA, endingLBA),
			"--change-name",
			fmt.Sprintf("%d:%s", 1, "cloudimg-rootfs"),
		)

		return cmd.Run()
	}

	return i.repartition(action)
}

func (i *imageIntegrityProtector) createIntegrityDataForRootPartition() (string, string, error) {
	verityFilePath := filepath.Join(i.workingDirPath(), "rootfs.verity")

	log.Infoln("generating verity data for root partition")
	verityInfo, err := snapd_dmverity.Format(i.rootDevPath(), verityFilePath)
	if err != nil {
		return "", "", err
	}

	return verityInfo.RootHash, verityFilePath, nil
}

func (i *imageIntegrityProtector) createVerityPartition(size uint64) error {
	action := func() error {
		if i.verity != nil {
			log.Infoln("deleting existing verity partition")

			cmd := internal_exec.LoggedCommand("sgdisk",
				i.imagePath,
				"--delete",
				fmt.Sprintf("%d", verityPartitionNum),
			)

			if err := cmd.Run(); err != nil {
				return err
			}
		}

		log.Infoln("creating a new verity partition")

		// align to the next 2048-sector boundary
		verityPartitionStart := i.rootPartition.EndingLBA/2048*2048 + 2048

		cmd := internal_exec.LoggedCommand("sgdisk",
			i.imagePath,
			"--move-second-header",
			"--new",
			fmt.Sprintf("%d:%d:+%dK", verityPartitionNum, verityPartitionStart, size/1024),
			"--typecode",
			fmt.Sprintf("%d:%s", verityPartitionNum, rootVerityPartitionAmd64GUID),
			"--change-name",
			fmt.Sprintf("%d:%s", verityPartitionNum, "cloudimg-rootfs-verity"),
		)

		if err := cmd.Run(); err != nil {
			return err
		}

		return nil
	}

	return i.repartition(action)
}

func (i *imageIntegrityProtector) createOrUpdateVerityPartition(verityFilePath string) error {
	fi, err := os.Stat(verityFilePath)
	if err != nil {
		return err
	}
	veritySize := uint64(fi.Size())

	create := true
	if i.verity != nil {
		partitionSize := uint64(i.verity.EndingLBA - i.verity.StartingLBA)

		if partitionSize >= veritySize {
			create = false
		}
	}

	if create {
		if err = i.createVerityPartition(veritySize); err != nil {
			return err
		}
	}

	// Update verity partition

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
	GptLabel string `json:"label"`
	RootHash string `json:"root_hash"`
	Overlay  string `json:"overlay"`
}

type ImageManifest struct {
	Partitions []ImageManifestPartition `json:"partitions"`
}

func (i *imageIntegrityProtector) integrityProtectImageOnDevice() error {
	if i.devPath == "" {
		log.Fatal("no device path")
	}

	i.enterScope()
	defer i.exitScope()

	if err := i.detectPartitions(); err != nil {
		return err
	}

	if err := i.prepareRootPartition(); err != nil {
		return err
	}

	rootHash, verityFilePath, err := i.createIntegrityDataForRootPartition()
	if err != nil {
		return err
	}

	log.Infoln("dm-verity root hash for the root partition: ", rootHash)

	if err = i.createOrUpdateVerityPartition(verityFilePath); err != nil {
		return err
	}

	log.Infoln("generating manifest with integrity information for image on", i.devPath)

	partition := ImageManifestPartition{
		GptLabel: "cloudimg-rootfs",
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
	log.Infoln("manifest.json:", string(imJson))

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

func (i *imageIntegrityProtector) integrityProtectImageFromFile() error {
	path, err := i.prepareWorkingImage(i.opts)
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
