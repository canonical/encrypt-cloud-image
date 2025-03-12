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

package nbd

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
)

var (
	ErrKernelModuleNotLoaded = errors.New("nbd kernel module is not loaded")

	ErrNoDeviceAvailable = errors.New("no device is available")

	errDeviceBusy = errors.New("device is busy")

	addEventRE = regexp.MustCompile(`KERNEL\[[[:digit:]\.]+\] add[[:blank:]]+([^[:blank:]]+) \(block\)`)

	sysfsPath = "/sys"
)

type imageType int

const (
	imageTypeAutodetect imageType = iota
	imageTypeFixedVHD
	imageTypeRaw
)

func getMaxNBDs() (int, error) {
	b, err := ioutil.ReadFile(filepath.Join(sysfsPath, "module/nbd/parameters/nbds_max"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

type vhdFooter struct {
	Cookie         [8]byte
	Features       uint32
	Version        uint32
	DataOffset     uint64
	Timestamp      uint32
	CreatorApp     uint32
	CreatorVersion uint32
	CreatorOS      uint32
	OrigSize       uint64
	CurrentSize    uint64
	DiskGeometry   uint32
	Type           uint32
	Checksum       uint32
	UUID           [16]byte
	InSavedState   uint8
	Reserved       [427]byte
}

// isFixedVHD determines if the image at the supplied path looks like a fixed
// VHD image. Qemu isn't able to autodetect these because it doesn't look at the
// footer.
func isFixedVHD(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.WithError(err).Errorln("cannot open", path, "for fixed VHD autodetection")
		return false
	}
	defer f.Close()

	if _, err := f.Seek(-int64(binary.Size(vhdFooter{})), io.SeekEnd); err != nil {
		log.Debugln(path, "is not a VHD: not large enough")
		return false
	}

	var footer vhdFooter
	if err := binary.Read(f, binary.BigEndian, &footer); err != nil {
		log.WithError(err).Errorln("cannot read bytes from", path, "for fixed VHD autodetection")
		return false
	}

	log.Debugln("possible VHD footer cookie for", path, ":", footer.Cookie)
	if footer.Cookie != [8]byte{'c', 'o', 'n', 'e', 'c', 't', 'i', 'x'} {
		log.Debugln(path, "is not a VHD: incorrect cookie")
		return false
	}

	if footer.Type != 2 {
		log.Debugln(path, "is not a fixed VHD")
		return false
	}

	return true
}

type mbrPartitionEntry [16]byte

type mbr struct {
	Code       [446]byte
	Partitions [4]mbrPartitionEntry
	Signature  uint16
}

// isRaw determines if the image at the supplied path is a valid raw image, so
// that we can tell qemu that it is a raw image in order to disable the restrictions
// on block 0 writes. Note that we consider an image to be a valid raw image if it
// starts with a MBR.
func isRaw(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.WithError(err).Errorln("cannot open", path, "for raw image autodetection")
		return false
	}
	defer f.Close()

	var mbr mbr
	if err := binary.Read(f, binary.LittleEndian, &mbr); err != nil {
		log.Debugln(path, "does not have a valid MBR and so it's not a valid raw image: not large enough")
		return false
	}
	if mbr.Signature != 0xaa55 {
		log.Debugln(path, "does not have a valid MBR and so it's not a valid raw image: invalid MBR signature")
		return false
	}

	return true
}

// getImageTypeHint attempts to determine whether the image at the supplied
// path is one of the formats that qemu has difficulty autodetecting.
func getImageTypeHint(path string) imageType {
	log.Debugln("detecting type of image at", path)

	switch {
	case isFixedVHD(path):
		log.Debugln("detected a fixed VHD")
		return imageTypeFixedVHD
	case isRaw(path):
		log.Debugln("detected a raw image")
		return imageTypeRaw
	}

	log.Debugln("leaving qemu-nbd to autodetect the image type")
	return imageTypeAutodetect
}

type nbdDev int

func (d nbdDev) sysfsPath() string {
	return fmt.Sprintf(filepath.Join(sysfsPath, "devices/virtual/block/nbd%d"), int(d))
}

func (d nbdDev) isManagedByProcess(pid int) (bool, error) {
	b, err := ioutil.ReadFile(filepath.Join(d.sysfsPath(), "pid"))
	switch {
	case os.IsNotExist(err):
		return false, nil
	case err != nil:
		return false, err
	}

	currentPid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return false, err
	}

	taskDir, err := os.Open(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return false, err
	}
	defer taskDir.Close()

	tasks, err := taskDir.Readdir(0)
	if err != nil {
		return false, err
	}

	for _, t := range tasks {
		taskPid, err := strconv.Atoi(t.Name())
		if err != nil {
			return false, err
		}
		if taskPid == currentPid {
			return true, nil
		}
	}

	return false, nil
}

func (d nbdDev) devPath() string {
	return fmt.Sprintf("/dev/nbd%d", int(d))
}

func (d nbdDev) String() string {
	return d.devPath()
}

type Connection struct {
	sourcePath string
	imageType  imageType

	logger log.FieldLogger

	dev         nbdDev
	qemuNbdDone chan error
}

func (c *Connection) tryConnectToDevice(dev nbdDev) (err error) {
	c.logger.Debugln("trying to connect to", dev)

	udevadmCmd := internal_exec.LoggedCommand("udevadm", "monitor", "--kernel")
	udevadmMonitor, err := udevadmCmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := udevadmCmd.Start(); err != nil {
		return fmt.Errorf("cannot start udevadm monitor: %w", err)
	}

	c.logger.Debugln("started udevadm monitor")

	qemuNbdStarted := make(chan int)
	go func() {
		args := []string{"-v"}
		switch c.imageType {
		case imageTypeAutodetect:
		case imageTypeFixedVHD:
			args = append(args, "-f", "vpc")
		case imageTypeRaw:
			args = append(args, "-f", "raw")
		}
		args = append(args, "-c", dev.devPath(), c.sourcePath)
		cmd := internal_exec.LoggedCommand("qemu-nbd", args...)
		if err := cmd.Start(); err != nil {
			c.qemuNbdDone <- err
			return
		}

		qemuNbdStarted <- cmd.Process.Pid
		c.qemuNbdDone <- cmd.Wait()
	}()

	nbdConnected := make(chan struct{})
	monitorDone := make(chan error)
	go func() {
		s := bufio.NewScanner(udevadmMonitor)
		for s.Scan() {
			m := addEventRE.FindStringSubmatch(s.Text())
			if m == nil {
				continue
			}
			if filepath.Dir(filepath.Join(sysfsPath, m[1])) == dev.sysfsPath() {
				nbdConnected <- struct{}{}
			}
		}
		monitorDone <- s.Err()
	}()

	var pid int

	defer func() {
		c.logger.Debugln("killing udevadm monitor")
		if err := udevadmCmd.Process.Kill(); err != nil {
			log.WithError(err).Panicln("cannot kill udevadm monitor")
		}
		udevadmCmd.Wait()

		c.logger.Debugln("waiting for udevadm monitor scanner goroutine to finish")
	Loop:
		for {
			select {
			case <-nbdConnected:
			case <-monitorDone:
				break Loop
			}
		}
		c.logger.Debugln("successfully killed udevadm monitor")

		if err != nil && pid > 0 {
			c.logger.Debugln("encountered an error so making sure qemu-nbd is killed")
			p, _ := os.FindProcess(pid)
			if err := p.Kill(); err != nil {
				var e syscall.Errno
				if errors.As(err, &e) {
					log.WithError(err).Panicln("cannot kill qemu-nbd")
				}
			}
		}
	}()

	for {
		select {
		case err := <-c.qemuNbdDone:
			c.logger.Debugln("qemu-nbd exitted with an error:", err)
			var e *exec.ExitError
			if errors.As(err, &e) && e.ExitCode() == 1 {
				return errDeviceBusy
			}
			return fmt.Errorf("qemu-nbd failed: %w", err)
		case pid = <-qemuNbdStarted:
			c.logger.Debugln("qemu-nbd started with PID:", pid)
			managed, err := dev.isManagedByProcess(pid)
			switch {
			case err != nil:
				return fmt.Errorf("cannot determine if %s is managed by us: %w", dev, err)
			case managed:
				c.logger.Debugln("our qemu-nbd manages the NBD device")
				return nil
			case !managed:
				c.logger.Debugln("our qemu-nbd does not manage the NBD device")
			}
		case <-nbdConnected:
			c.logger.Debugln("an image was connected to the NBD device")
			if pid > 0 {
				managed, err := dev.isManagedByProcess(pid)
				switch {
				case err != nil:
					return fmt.Errorf("cannot determine if %s is managed by us: %w", dev, err)
				case managed:
					c.logger.Debugln("our qemu-nbd manages the NBD device")
					return nil
				case !managed:
					c.logger.Debugln("our qemu-nbd does not manage the NBD device")
				}
			} else {
				c.logger.Debugln("we haven't got the PID for qemu-nbd yet")
			}
		case err := <-monitorDone:
			return fmt.Errorf("udevadm monitor scanner goroutine returned unexpectedly: %w", err)
		}
	}
}

func (c *Connection) connect() error {
	maxDevices, err := getMaxNBDs()
	if err != nil {
		return fmt.Errorf("cannot determine maximum number of NBD devices: %w", err)
	}
	c.logger.Debugln("maximum number of NBD devices:", maxDevices)

	for i := 0; i < 100; i++ {
		c.logger.Debugln("loop", i)
		for j := 0; j < maxDevices; j++ {
			err := c.tryConnectToDevice(nbdDev(j))
			switch {
			case err == errDeviceBusy:
				c.logger.Debugln("device", j, "is already managed by another process")
			case err != nil:
				return fmt.Errorf("unexpected error when trying %s: %w", j, err)
			default:
				c.logger.Debugln("connected to device", j)
				c.dev = nbdDev(j)
				return nil
			}
		}
	}
	return ErrNoDeviceAvailable
}

func (c *Connection) SourcePath() string {
	return c.sourcePath
}

func (c *Connection) DevPath() string {
	return c.dev.devPath()
}

func (c *Connection) Disconnect() error {
	c.logger.Debugln("disconnecting")
	cmd := internal_exec.LoggedCommand("qemu-nbd", "-d", c.dev.devPath())
	if err := cmd.Run(); err != nil {
		return err
	}

	if err := <-c.qemuNbdDone; err != nil {
		c.logger.WithError(err).Warningln("qemu-nbd exitted with an error")
	}

	return nil
}

func ConnectImage(path string) (conn *Connection, err error) {
	log.Debugln("connecting", path, "to NBD device")
	if !IsModuleLoaded() {
		return nil, errors.New("nbd kernel module is not loaded")
	}
	if !IsSupported() {
		return nil, errors.New("not supported: is qemu-nbd installed?")
	}

	c := &Connection{sourcePath: path, imageType: getImageTypeHint(path), qemuNbdDone: make(chan error)}
	c.logger = log.WithField("nbd.Connection", fmt.Sprintf("%p", c))
	c.logger.Debugln("created Connection for", path)

	defer func() {
		if v := recover(); v != nil {
			if entry, ok := v.(*log.Entry); ok {
				if e, ok := entry.Data[log.ErrorKey]; ok {
					var s syscall.Errno
					if errors.As(e.(error), &s) {
						err = e.(error)
						return
					}
				}
			}
			panic(v)
		}
	}()

	if err := c.connect(); err != nil {
		return nil, err
	}

	return c, nil
}

func IsModuleLoaded() bool {
	_, err := os.Stat(filepath.Join(sysfsPath, "module/nbd"))
	return err == nil
}

func IsSupported() bool {
	_, err := exec.LookPath("qemu-nbd")
	return err == nil
}
