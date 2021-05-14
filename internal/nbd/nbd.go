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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	internal_exec "github.com/chrisccoulson/encrypt-cloud-image/internal/exec"
	log "github.com/sirupsen/logrus"

	"golang.org/x/xerrors"
)

var (
	ErrKernelModuleNotLoaded = errors.New("nbd kernel module is not loaded")

	ErrNoDeviceAvailable = errors.New("no device is available")

	errDeviceBusy = errors.New("device is busy")

	addEventRE = regexp.MustCompile(`KERNEL\[[[:digit:]\.]+\] add[[:blank:]]+([^[:blank:]]+) \(block\)`)

	sysfsPath = "/sys"
)

func getMaxNBDs() (int, error) {
	b, err := ioutil.ReadFile(filepath.Join(sysfsPath, "module/nbd/parameters/nbds_max"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
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

	logger log.FieldLogger

	dev        nbdDev
	qemuNbdErr chan error
}

func (c *Connection) tryConnectToDevice(path string, dev nbdDev) error {
	c.logger.Debugln("trying to connect to", dev)

	cmd := internal_exec.LoggedCommand("udevadm", "monitor", "--kernel")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return xerrors.Errorf("cannot start udevadm monitor: %w", err)
	}

	c.logger.Debugln("started udevadm monitor")

	qemuNbdStarted := make(chan int)
	go func() {
		cmd := internal_exec.LoggedCommand("qemu-nbd", "-v", "-c", dev.devPath(), path)
		if err := cmd.Start(); err != nil {
			c.qemuNbdErr <- err
			return
		}

		qemuNbdStarted <- cmd.Process.Pid
		c.qemuNbdErr <- cmd.Wait()
	}()

	nbdConnected := make(chan struct{})
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			m := addEventRE.FindStringSubmatch(s.Text())
			if m == nil {
				continue
			}
			if filepath.Dir(filepath.Join(sysfsPath, m[1])) == dev.sysfsPath() {
				nbdConnected <- struct{}{}
			}
		}
		close(nbdConnected)
	}()

	defer func() {
		c.logger.Debugln("killing udevadm monitor")
		if err := cmd.Process.Kill(); err != nil {
			c.logger.Warningln("cannot kill udevadm monitor:", err)
		}
		cmd.Wait()
		for {
			if _, ok := <-nbdConnected; !ok {
				break
			}
		}
		c.logger.Debugln("successfully killed udevadm monitor")
	}()

	var pid int

	for {
		select {
		case err := <-c.qemuNbdErr:
			c.logger.Debugln("qemu-nbd exitted with an error:", err)
			var e *exec.ExitError
			if xerrors.As(err, &e) && e.ExitCode() == 1 {
				return errDeviceBusy
			}
			return xerrors.Errorf("qemu-nbd failed: %w", err)
		case pid = <-qemuNbdStarted:
			c.logger.Debugln("qemu-nbd started with PID:", pid)
			managed, err := dev.isManagedByProcess(pid)
			switch {
			case err != nil:
				return xerrors.Errorf("cannot determine if %s is managed by us: %w", dev, err)
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
					return xerrors.Errorf("cannot determine if %s is managed by us: %w", dev, err)
				case managed:
					c.logger.Debugln("our qemu-nbd manages the NBD device")
					return nil
				case !managed:
					c.logger.Debugln("our qemu-nbd does not manage the NBD device")
				}
			} else {
				c.logger.Debugln("we haven't got the PID for qemu-nbd yet")
			}
		}
	}
}

func (c *Connection) connect(path string) error {
	maxDevices, err := getMaxNBDs()
	if err != nil {
		return xerrors.Errorf("cannot determine maximum number of NBD devices: %w", err)
	}
	c.logger.Debugln("maximum number of NBD devices:", maxDevices)

	for i := 0; i < 100; i++ {
		c.logger.Debugln("loop", i)
		for j := 0; j < maxDevices; j++ {
			err := c.tryConnectToDevice(path, nbdDev(j))
			switch {
			case err == errDeviceBusy:
				c.logger.Debugln("device", j, "is already managed by another process")
			case err != nil:
				return xerrors.Errorf("unexpected error when trying %s: %w", j, err)
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

	if err := <-c.qemuNbdErr; err != nil {
		c.logger.Warningln("qemu-nbd exitted with an error:", err)
	}

	return nil
}

func ConnectImage(path string) (*Connection, error) {
	log.Debugln("connecting", path, "to NBD device")
	if !IsModuleLoaded() {
		return nil, ErrKernelModuleNotLoaded
	}

	c := &Connection{sourcePath: path, qemuNbdErr: make(chan error)}
	c.logger = log.WithField("nbd.Connection", fmt.Sprintf("%p", c))
	c.logger.Debugln("created Connection for", path)

	if err := c.connect(path); err != nil {
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
