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

package nbd_test

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"

	. "github.com/canonical/encrypt-cloud-image/internal/nbd"
)

func Test(t *testing.T) { TestingT(t) }

type nbdSuite struct {
	testutil.BaseTest

	start time.Time

	sysfsPath string

	qemunbdStartedFifo string
	qemunbdExitFifo    string
	qemunbdKillSwitch  string
	qemunbdCmd         *testutil.MockCmd

	udevadmFifo string
	udevadmCmd  *testutil.MockCmd
}

func (s *nbdSuite) SetUpSuite(c *C) {
	s.start = time.Now()
}

func (s *nbdSuite) SetUpTest(c *C) {
	s.sysfsPath = c.MkDir()
	s.AddCleanup(MockSysfsPath(s.sysfsPath))
	c.Check(os.MkdirAll(filepath.Join(s.sysfsPath, "devices/virtual/block"), 0755), IsNil)

	dir := c.MkDir()

	s.qemunbdStartedFifo = filepath.Join(dir, "qemunbdStarted")
	c.Check(unix.Mkfifo(s.qemunbdStartedFifo, 0600), IsNil)

	s.qemunbdExitFifo = filepath.Join(dir, "qemunbdExit")
	c.Check(unix.Mkfifo(s.qemunbdExitFifo, 0600), IsNil)

	s.qemunbdKillSwitch = filepath.Join(dir, "qemunbdkillswitch")
	synchronizationFile := filepath.Join(dir, "udevadmdone")

	qemunbdScriptTpl := `
while [ $# -gt 0 ]; do
	case "$1" in
		-d)
			echo 0 > %[3]s
			exit 0
			;;
		-c)
			if [ -e %[4]s ]; then
				i=0
				# Synchronize this process with udevadm mocked command,
				# this way the qemu-nbd command doesn't return before
				# the udevadm mocked command had time to log its call.
				while [ ! -e %[5]s ] && [ $i -lt 100 ]; do
					i=$((i+1))
					sleep 0.001
				done
				rm -f %[5]s
				exit 1
			fi
			echo "$$:$2" > %[2]s
			exec %[1]s -mock-qemu-nbd %[3]s
			;;
		*)
			shift
			;;
	esac
done`
	s.qemunbdCmd = testutil.MockCommand(c, "qemu-nbd", fmt.Sprintf(qemunbdScriptTpl, os.Args[0], s.qemunbdStartedFifo, s.qemunbdExitFifo, s.qemunbdKillSwitch, synchronizationFile))
	s.AddCleanup(s.qemunbdCmd.Restore)

	s.udevadmFifo = filepath.Join(dir, "udevadm")
	c.Check(unix.Mkfifo(s.udevadmFifo, 0600), IsNil)

	udevadmScriptTpl := `touch %[3]s
exec %[1]s -mock-udevadm-monitor %[2]s
`

	s.udevadmCmd = testutil.MockCommand(c, "udevadm", fmt.Sprintf(udevadmScriptTpl, os.Args[0], s.udevadmFifo, synchronizationFile))
	s.AddCleanup(s.udevadmCmd.Restore)
}

func (s *nbdSuite) mockNbdModule(c *C, n int) {
	c.Check(os.MkdirAll(filepath.Join(s.sysfsPath, "module/nbd/parameters"), 0755), IsNil)
	c.Check(ioutil.WriteFile(filepath.Join(s.sysfsPath, "module/nbd/parameters/nbds_max"), []byte(strconv.Itoa(n)), 0644), IsNil)
}

func (s *nbdSuite) waitForQemuNbd(path string, iter int) (int, error) {
	pidChan := make(chan int)
	errChan := make(chan error)

	re := regexp.MustCompile(`([[:digit:]]+):(.*)`)
	go func() {
		pid, err := func() (int, error) {
			i := 0
			for {
				f, err := os.Open(s.qemunbdStartedFifo)
				if err != nil {
					return 0, err
				}

				scanner := bufio.NewScanner(f)
				scanner.Scan()
				f.Close()

				if scanner.Err() != nil {
					return 0, err
				}

				res := re.FindStringSubmatch(scanner.Text())
				if len(res) > 0 && res[2] == path {
					if i == iter {
						pid, err := strconv.Atoi(res[1])
						if err != nil {
							return 0, err
						}
						return pid, nil
					}
					i += 1
				}

				f, err = os.OpenFile(s.qemunbdExitFifo, os.O_WRONLY, 0)
				if err != nil {
					return 0, err
				}
				_, err = f.WriteString("1")
				f.Close()
				if err != nil {
					return 0, err
				}
			}
		}()
		if err != nil {
			errChan <- err
		} else {
			pidChan <- pid
		}
	}()

	var pid int
	select {
	case err := <-errChan:
		return 0, err
	case pid = <-pidChan:
	case <-time.After(5 * time.Second):
		return 0, errors.New("timed out waiting for qemu-nbd")
	}

	return pid, nil
}

func (s *nbdSuite) mockNbdConnection(path string, pid int) error {
	sysfsPath := filepath.Join(s.sysfsPath, path)
	if err := os.MkdirAll(sysfsPath, 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(sysfsPath, "pid"), []byte(strconv.Itoa(pid)), 0444)
}

func (s *nbdSuite) simulateKernelUevent(action, path, subsystem string) error {
	f, err := os.OpenFile(s.udevadmFifo, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	d := time.Since(s.start)
	sec := d / time.Second
	usec := (d - sec) / time.Microsecond
	_, err = f.WriteString(fmt.Sprintf("KERNEL[%d.%06d] %-8s %s (%s)\n", sec, usec, action, path, subsystem))
	return err
}

var _ = Suite(&nbdSuite{})

func (s *nbdSuite) TestConnectNoNBD(c *C) {
	_, err := ConnectImage("/path/to/image")
	c.Check(err, ErrorMatches, "nbd kernel module is not loaded")
}

type simulatedUevent struct {
	action    string
	path      string
	subsystem string
}

type testConnectImageData struct {
	maxNbds       int
	sourcePath    string
	dev           int
	iter          int
	expectedTries int
	uevents       []simulatedUevent
}

func (s *nbdSuite) testConnectImage(c *C, data *testConnectImageData) {
	s.mockNbdModule(c, data.maxNbds)

	for i := 0; i < data.maxNbds; i++ {
		if i == data.dev {
			continue
		}
		c.Check(s.mockNbdConnection(fmt.Sprintf(filepath.Join("devices/virtual/block/nbd%d"), i), 1), IsNil)
	}

	devPath := fmt.Sprintf(filepath.Join("/dev/nbd%d"), data.dev)

	helperDone := make(chan error)
	go func() {
		err := func() error {
			qemuNbdPid, err := s.waitForQemuNbd(devPath, data.iter)
			if err != nil {
				return err
			}
			if err := s.mockNbdConnection(fmt.Sprintf(filepath.Join("devices/virtual/block/nbd%d"), data.dev), qemuNbdPid); err != nil {
				return err
			}
			for _, e := range data.uevents {
				if err := s.simulateKernelUevent(e.action, e.path, e.subsystem); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			f, err := os.OpenFile(s.qemunbdKillSwitch, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				panic(err)
			}
			f.Close()
		}
		helperDone <- err
	}()

	conn, err := ConnectImage(data.sourcePath)
	c.Check(<-helperDone, IsNil)
	c.Assert(err, IsNil)

	c.Check(conn.SourcePath(), Equals, data.sourcePath)
	c.Check(conn.DevPath(), Equals, devPath)
	c.Check(conn.Disconnect(), IsNil)

	c.Assert(s.udevadmCmd.Calls(), HasLen, data.expectedTries)
	c.Check(s.udevadmCmd.Calls()[0], DeepEquals, []string{"udevadm", "monitor", "--kernel"})

	c.Assert(s.qemunbdCmd.Calls(), HasLen, data.expectedTries+1)
	c.Check(s.qemunbdCmd.Calls()[data.expectedTries-1], DeepEquals, []string{"qemu-nbd", "-v", "-c", devPath, data.sourcePath})
	c.Check(s.qemunbdCmd.Calls()[data.expectedTries], DeepEquals, []string{"qemu-nbd", "-d", devPath})
}

func (s *nbdSuite) TestConnectImage1(c *C) {
	s.testConnectImage(c, &testConnectImageData{
		maxNbds:       16,
		sourcePath:    "/path/to/image",
		dev:           0,
		iter:          0,
		expectedTries: 1,
		uevents: []simulatedUevent{
			{"change", "/devices/virtual/block/nbd0", "block"},
			{"add", "/devices/virtual/block/nbd0/nbd0p1", "block"}}})
}

func (s *nbdSuite) TestConnectImage2(c *C) {
	s.testConnectImage(c, &testConnectImageData{
		maxNbds:       16,
		sourcePath:    "/path/to/other/image",
		dev:           12,
		iter:          0,
		expectedTries: 13,
		uevents: []simulatedUevent{
			{"change", "/devices/virtual/block/nbd12", "block"},
			{"add", "/devices/virtual/block/nbd12/nbd12p1", "block"}}})
}

func (s *nbdSuite) TestConnectImage3(c *C) {
	s.testConnectImage(c, &testConnectImageData{
		maxNbds:       16,
		sourcePath:    "/path/to/image",
		dev:           2,
		iter:          2,
		expectedTries: 35,
		uevents: []simulatedUevent{
			{"change", "/devices/virtual/block/nbd2", "block"},
			{"add", "/devices/virtual/block/nbd2/nbd2p1", "block"}}})
}

func (s *nbdSuite) TestConnectFail(c *C) {
	nbDevices := 5
	s.mockNbdModule(c, nbDevices)

	for i := 0; i < nbDevices; i++ {
		c.Check(s.mockNbdConnection(fmt.Sprintf(filepath.Join("devices/virtual/block/nbd%d"), i), 1), IsNil)
	}

	f, err := os.OpenFile(s.qemunbdKillSwitch, os.O_RDWR|os.O_CREATE, 0644)
	c.Assert(err, IsNil)
	c.Check(f.Close(), IsNil)

	_, err = ConnectImage("/path/to/image")
	c.Check(err, ErrorMatches, "no device is available")

	c.Check(s.udevadmCmd.Calls(), HasLen, nbDevices*100)
	c.Check(s.qemunbdCmd.Calls(), HasLen, nbDevices*100)
}

type testGetImageTypeHintData struct {
	path     string
	expected ImageType
}

func (s *nbdSuite) testGetImageTypeHint(c *C, data *testGetImageTypeHintData) {
	c.Check(GetImageTypeHint(data.path), Equals, data.expected)
}

func (s *nbdSuite) TestGetImageTypeHintFixedVHD(c *C) {
	s.testGetImageTypeHint(c, &testGetImageTypeHintData{
		path:     "testdata/fixed.vhd",
		expected: ImageTypeFixedVHD,
	})
}

func (s *nbdSuite) TestGetImageTypeHintDynamicVHD(c *C) {
	s.testGetImageTypeHint(c, &testGetImageTypeHintData{
		path:     "testdata/dynamic.vhd",
		expected: ImageTypeAutodetect,
	})
}

func (s *nbdSuite) TestGetImageTypeHintQCow2(c *C) {
	s.testGetImageTypeHint(c, &testGetImageTypeHintData{
		path:     "testdata/test.qcow2",
		expected: ImageTypeAutodetect,
	})
}

func (s *nbdSuite) TestGetImageTypeHintRaw(c *C) {
	s.testGetImageTypeHint(c, &testGetImageTypeHintData{
		path:     "testdata/test.raw",
		expected: ImageTypeRaw,
	})
}

var (
	mockUdevadmMonitor = flag.String("mock-udevadm-monitor", "", "")
	mockQemuNbd        = flag.String("mock-qemu-nbd", "", "")
)

func runMockUdevadmMonitor() int {
	for {
		f, err := os.Open(*mockUdevadmMonitor)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			return 1
		}

		_, err = io.Copy(os.Stdout, f)
		f.Close()
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			return 1
		}
	}

	return 0
}

func runMockQemuNbd() int {
	f, err := os.Open(*mockQemuNbd)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	r, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	return r
}

func TestMain(m *testing.M) {
	flag.Parse()
	switch {
	case *mockUdevadmMonitor != "":
		os.Exit(runMockUdevadmMonitor())
	case *mockQemuNbd != "":
		os.Exit(runMockQemuNbd())
	default:
		os.Exit(m.Run())
	}
}
