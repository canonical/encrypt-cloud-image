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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/canonical/go-efilib"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	"github.com/canonical/encrypt-cloud-image/internal/gpt"
	"github.com/canonical/encrypt-cloud-image/internal/logutil"
	"github.com/canonical/encrypt-cloud-image/internal/nbd"
)

const (
	luks2TokenType = "ubuntu-fde-cloudimg-key"
	luks2TokenKey  = "ubuntu_fde_cloudimg_key"
)

var (
	Version             = "v1.0.1"
	espGUID             = efi.MakeGUID(0xC12A7328, 0xF81F, 0x11D2, 0xBA4B, [...]uint8{0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B})
	linuxFilesystemGUID = efi.MakeGUID(0x0FC63DAF, 0x8483, 0x4772, 0x8E79, [...]uint8{0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4})
)

type options struct {
	Verbose bool `short:"v" long:"verbose" description:"Enable verbose debug output"`
}

var (
	opts   options
	parser = flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
)

func mount(dev, path, fs string) (cleanup func() error, err error) {
	cmd := internal_exec.LoggedCommand("mount", "-t", fs, dev, path)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return func() error {
		log.Debugln("unmounting", path)
		cmd := internal_exec.LoggedCommand("umount", path)
		return cmd.Run()
	}, nil
}

type encryptCloudImageBase struct {
	cleanupHandlers [][]func() error

	workingDir string
	devPath    string

	partitions    gpt.Partitions
	rootPartition *gpt.PartitionEntry
	esp           *gpt.PartitionEntry
}

func (b *encryptCloudImageBase) getDevPathFormat() (string, error) {
	if strings.HasPrefix(b.devPath, "/dev/nbd") || strings.HasPrefix(b.devPath, "/dev/nvme") {
		return "%sp%d", nil
	} else if strings.HasPrefix(b.devPath, "/dev/sd") || strings.HasPrefix(b.devPath, "/dev/vd") {
		return "%s%d", nil
	} else {
		return "", fmt.Errorf("Unsupported device path: %s. Please look at the code to determine what is currently supported.", b.devPath)
	}
}

func (b *encryptCloudImageBase) isNbdDevice() bool {
	return strings.HasPrefix(b.devPath, "/dev/nbd")
}

func (b *encryptCloudImageBase) checkNbdPreRequisites() error {
	if !nbd.IsSupported() {
		return errors.New("cannot create nbd devices (is qemu-nbd installed?)")
	}
	if !nbd.IsModuleLoaded() {
		return errors.New("cannot create nbd devices because the required kernel module is not loaded")
	}

	return nil
}

func (b *encryptCloudImageBase) workingDirPath() string {
	if b.workingDir == "" {
		log.Panicln("missing call to setupWorkingDir")
	}
	return b.workingDir
}

func (b *encryptCloudImageBase) rootDevPath() string {
	if b.rootPartition == nil {
		log.Panicln("missing call to detectPartitions")
	}

	devPathFormat, err := b.getDevPathFormat()
	if err != nil {
		log.Panicln(err.Error())
	}

	return fmt.Sprintf(devPathFormat, b.devPath, b.rootPartition.Index)
}

func (b *encryptCloudImageBase) espDevPath() string {
	if b.esp == nil {
		log.Panicln("missing call to detectPartitions")
	}

	devPathFormat, err := b.getDevPathFormat()
	if err != nil {
		log.Panicln(err.Error())
	}

	return fmt.Sprintf(devPathFormat, b.devPath, b.esp.Index)
}

func (b *encryptCloudImageBase) addCleanup(fn func() error) {
	if len(b.cleanupHandlers) == 0 {
		log.Panicln("missing call to enterScope")
	}
	b.cleanupHandlers[0] = append(b.cleanupHandlers[0], fn)
}

func (b *encryptCloudImageBase) enterScope() {
	b.cleanupHandlers = append([][]func() error{{}}, b.cleanupHandlers...)
}

func (b *encryptCloudImageBase) exitScope() {
	if len(b.cleanupHandlers) == 0 {
		log.Panicln("too many calls to exitScope")
	}

	n := 0

	for len(b.cleanupHandlers[0]) > 0 {
		l := len(b.cleanupHandlers[0])
		fn := b.cleanupHandlers[0][l-1]
		b.cleanupHandlers[0] = b.cleanupHandlers[0][:l-1]
		if err := fn(); err != nil {
			log.WithError(err).Errorln(err)
			n += 1
		}
	}

	b.cleanupHandlers = b.cleanupHandlers[1:]

	if n > 0 {
		log.Panicln(n, "cleanup handlers failed")
	}
}

func (b *encryptCloudImageBase) setupWorkingDir(baseDir string) error {
	name, err := ioutil.TempDir(baseDir, "encrypt-cloud-image.")
	if err != nil {
		return fmt.Errorf("cannot setup working directory: %w", err)
	}
	b.workingDir = name
	log.Infoln("temporary working directory:", name)

	b.addCleanup(func() error {
		log.Debugln("removing", name)
		if err := os.RemoveAll(name); err != nil {
			return fmt.Errorf("cannot remove working directory: %w", err)
		}
		return nil
	})

	return nil
}

func (b *encryptCloudImageBase) connectNbd(path string) error {
	conn, err := nbd.ConnectImage(path)
	if err != nil {
		return fmt.Errorf("cannot connect %s to NBD device: %w", path, err)
	}
	b.devPath = conn.DevPath()
	log.Infoln("connected", path, "to", conn.DevPath())

	b.addCleanup(func() error {
		log.Debugln("disconnecting", conn.DevPath())
		if err := conn.Disconnect(); err != nil {
			return fmt.Errorf("cannot disconnect from %s: %w", conn.DevPath(), err)
		}
		return nil
	})

	return nil
}

func (b *encryptCloudImageBase) detectPartitions() error {
	partitions, err := gpt.ReadPartitionTable(b.devPath)
	if err != nil {
		return fmt.Errorf("cannot read partition table from %s: %w", b.devPath, err)
	}
	b.partitions = partitions
	log.Debugln("partition table for", b.devPath, ":", partitions)

	// XXX: Could there be more than one partition with this type?
	root := partitions.FindByPartitionType(linuxFilesystemGUID)
	if root == nil {
		return fmt.Errorf("cannot find partition with the type %v on %s", linuxFilesystemGUID, b.devPath)
	}
	log.Debugln("rootfs partition on", b.devPath, ":", root)
	b.rootPartition = root
	log.Infoln("device node for rootfs partition:", b.rootDevPath())

	esp := partitions.FindByPartitionType(espGUID)
	if esp == nil {
		return fmt.Errorf("cannot find partition with the type %v on %s", espGUID, b.devPath)
	}
	log.Debugln("ESP on", b.devPath, ":", esp)
	b.esp = esp
	log.Infoln("device node for ESP:", b.espDevPath())
	return nil
}

func (b *encryptCloudImageBase) mount(devPath, mountPath, fs string) error {
	unmount, err := mount(devPath, mountPath, fs)
	if err != nil {
		return err
	}

	b.addCleanup(func() error {
		if err := unmount(); err != nil {
			return fmt.Errorf("cannot unmount %s: %w", mountPath, err)
		}
		return nil
	})

	return nil
}

func (b *encryptCloudImageBase) mountRoot() (path string, err error) {
	path = filepath.Join(b.workingDirPath(), "rootfs")
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", fmt.Errorf("cannot create directory to mount rootfs: %w", err)
	}

	log.Infoln("mounting root filesystem to", path)

	if err := b.mount(b.rootDevPath(), path, "ext4"); err != nil {
		return "", fmt.Errorf("cannot mount rootfs: %w", err)
	}

	return path, nil
}

func (b *encryptCloudImageBase) mountESP() (path string, err error) {
	path = filepath.Join(b.workingDirPath(), "esp")
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", fmt.Errorf("cannot create directory to mount ESP: %w", err)
	}

	log.Infoln("mounting ESP to", path)

	if err := b.mount(b.espDevPath(), path, "vfat"); err != nil {
		return "", fmt.Errorf("cannot mount ESP: %w", err)
	}

	return path, nil
}

func runCommand(command flags.Commander, args []string) error {
	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
		log.Debugln("Enabling verbose output")
	}

	log.Debugln("args:", strings.Join(os.Args, " "))

	if err := checkPrerequisites(); err != nil {
		return err
	}

	return command.Execute(args)
}

func checkPrerequisites() error {
	for _, p := range []string{"cryptsetup", "resize2fs", "mount", "umount", "growpart"} {
		_, err := exec.LookPath(p)
		if err != nil {
			return fmt.Errorf("cannot continue: is %s installed?", p)
		}
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
		TimestampFormat:        time.RFC3339Nano,
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
		TimestampFormat:        time.RFC3339Nano,
		DisableLevelTruncation: true,
		PadLevelText:           true})
	w.SetOutput(os.Stdout)
	log.AddHook(w)
}

func run(args []string) (err error) {
	configureLogging()

	parser.CommandHandler = runCommand

	if _, err := parser.ParseArgs(args); err != nil {
		switch e := err.(type) {
		case *flags.Error:
			if e.Type == flags.ErrHelp {
				fmt.Fprintln(os.Stdout, err)
				return nil
			}
		}
		return err
	}

	return nil
}

func main() {
	log.Infoln("Version:", Version)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
