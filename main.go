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
	"strings"
	"time"

	"github.com/canonical/go-efilib"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	"github.com/canonical/encrypt-cloud-image/internal/logutil"
	"github.com/canonical/encrypt-cloud-image/internal/nbd"
)

const (
	luks2TokenType = "ubuntu-fde-cloudimg-key"
	luks2TokenKey  = "ubuntu_fde_cloudimg_key"
)

var (
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

func unmount(path string) error {
	cmd := internal_exec.LoggedCommand("umount", path)
	return cmd.Run()
}

func mount(dev, path, fs string) (cleanup func(), err error) {
	cmd := internal_exec.LoggedCommand("mount", "-t", fs, dev, path)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return func() {
		log.Debugln("unmounting", path)
		if err := unmount(path); err != nil {
			log.WithError(err).Panicln("cannot unmount", path)
		}
	}, nil
}

func connectNbd(path string) (conn *nbd.Connection, cleanup func(), err error) {
	conn, err = nbd.ConnectImage(path)
	if err != nil {
		return nil, nil, err
	}

	return conn, func() {
		log.Debugln("disconnecting", conn.DevPath())
		if err := conn.Disconnect(); err != nil {
			log.WithError(err).Panicln("cannot disconnect from", conn.DevPath())
		}
	}, nil
}

func mkTempDir(dir string) (name string, cleanup func(), err error) {
	name, err = ioutil.TempDir(dir, "encrypt-cloud-image.")
	if err != nil {
		return "", nil, err
	}
	return name, func() {
		log.Debugln("removing", name)
		if err := os.RemoveAll(name); err != nil {
			log.WithError(err).Panicln("cannot remove temporary directory")
		}
	}, nil
}

func runCommand(command flags.Commander, args []string) error {
	if opts.Verbose {
		log.SetLevel(log.DebugLevel)
		log.Debugln("Enabling verbose output")
	}

	log.Debugln("args:", strings.Join(args, " "))

	if err := checkPrerequisites(); err != nil {
		return err
	}

	return command.Execute(args)
}

func checkPrerequisites() error {
	if !nbd.IsSupported() {
		return errors.New("cannot create nbd devices (is qemu-nbd installed?)")
	}
	if !nbd.IsModuleLoaded() {
		return errors.New("cannot create nbd devices because the required kernel module is not loaded")
	}

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
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
