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

package exec_test

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/snapcore/snapd/testutil"

	"golang.org/x/sys/unix"

	check "gopkg.in/check.v1"

	"github.com/canonical/encrypt-cloud-image/internal/exec"
)

func Test(t *testing.T) { check.TestingT(t) }

type logHook struct {
	mu      sync.Mutex
	fired   chan<- struct{}
	pending []*log.Entry
	entries []*log.Entry
}

func (h *logHook) recvEntry(c *check.C) *log.Entry {
	deadline := time.After(5 * time.Second)

	for {
		for len(h.entries) == 0 {
			h.mu.Lock()
			if len(h.pending) > 0 {
				h.entries = h.pending
				h.pending = nil
			} else {
				fired := make(chan struct{}, 1)
				h.fired = fired
				h.mu.Unlock()
				select {
				case <-fired:
				case <-deadline:
					c.Fatalf("timed out waiting for log entries")
					return nil
				}
				h.mu.Lock()
			}
			h.mu.Unlock()
		}

		select {
		case <-deadline:
			c.Fatalf("timed out waiting for log entry")
		default:
		}

		for len(h.entries) > 0 {
			e := h.entries[0]
			h.entries = h.entries[1:]

			if _, ok := e.Data["pid"]; ok {
				return e
			}
		}
	}
}

func (h *logHook) Fire(entry *log.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pending = append(h.pending, entry)

	if h.fired != nil {
		h.fired <- struct{}{}
		h.fired = nil
	}

	return nil
}

func (h *logHook) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
		log.TraceLevel}
}

type execSuite struct {
	savedLevel   log.Level
	savedLogDest io.Writer
	savedHooks   log.LevelHooks
	log          *logHook

	stdout string
	stderr string
	exit   string

	cmd *testutil.MockCmd
}

func (s *execSuite) SetUpSuite(c *check.C) {
	s.savedLevel = log.StandardLogger().Level
	s.savedLogDest = log.StandardLogger().Out
	log.SetLevel(log.DebugLevel)
	log.SetOutput(ioutil.Discard)

	dir := c.MkDir()

	s.stdout = filepath.Join(dir, "stdout")
	c.Check(unix.Mkfifo(s.stdout, 0600), check.IsNil)

	s.stderr = filepath.Join(dir, "stderr")
	c.Check(unix.Mkfifo(s.stderr, 0600), check.IsNil)

	s.exit = filepath.Join(dir, "exit")
	c.Check(unix.Mkfifo(s.exit, 0600), check.IsNil)

	scriptTpl := `exec %[1]s -child -stdout %[2]s -stderr %[3]s -exit %[4]s`

	s.cmd = testutil.MockCommand(c, "cmd", fmt.Sprintf(scriptTpl, os.Args[0], s.stdout, s.stderr, s.exit))
}

func (s *execSuite) SetUpTest(_ *check.C) {
	s.savedHooks = log.StandardLogger().Hooks
	s.log = &logHook{}
	log.AddHook(s.log)
}

func (s *execSuite) TearDownTest(_ *check.C) {
	log.StandardLogger().ReplaceHooks(s.savedHooks)
}

func (s *execSuite) TearDownSuite(_ *check.C) {
	if s.cmd != nil {
		s.cmd.Restore()
	}
	log.SetLevel(s.savedLevel)
	log.SetOutput(s.savedLogDest)
}

func (s *execSuite) runAsync(cmd *exec.LoggedCmd) <-chan error {
	c := make(chan error)
	go func() {
		c <- cmd.Run()
	}()
	return c
}

func (s *execSuite) sendBytes(c *check.C, path string, data []byte) {
	done := make(chan error)

	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			done <- err
			return
		}
		_, err = f.Write(data)
		if err != nil {
			done <- err
			return
		}
		done <- f.Close()
	}()

	select {
	case err := <-done:
		c.Assert(err, check.IsNil)
	case <-time.After(5 * time.Second):
		c.Fatalf("timed out trying to send bytes")
	}
}

func (s *execSuite) sendStdout(c *check.C, str string) {
	s.sendBytes(c, s.stdout, []byte(str))
}

func (s *execSuite) sendStderr(c *check.C, str string) {
	s.sendBytes(c, s.stderr, []byte(str))
}

func (s *execSuite) sendExit(c *check.C, n int) {
	s.sendBytes(c, s.exit, []byte(strconv.Itoa(n)))
}

var _ = check.Suite(&execSuite{})

func (s *execSuite) TestLoggedCommandArgs(c *check.C) {
	cmd := exec.LoggedCommand("cmd", "--foo", "bar")
	cmdErr := s.runAsync(cmd)

	s.sendExit(c, 0)
	c.Check(<-cmdErr, check.IsNil)
	c.Assert(s.cmd.Calls(), check.HasLen, 1)
	c.Check(s.cmd.Calls()[0], check.DeepEquals, []string{"cmd", "--foo", "bar"})
}

func (s *execSuite) TestLoggedCommandNotFound(c *check.C) {
	cmd := exec.LoggedCommand("xxxxxxxxxxxxxxxxxx")
	c.Check(cmd.Start(), check.ErrorMatches, "exec: \"xxxxxxxxxxxxxxxxxx\": executable file not found in \\$PATH")
	_, err := cmd.Cmd.Stdout.Write([]byte{0})
	c.Check(err, check.ErrorMatches, "write |1: file already closed")
	_, err = cmd.Cmd.Stderr.Write([]byte{0})
	c.Check(err, check.ErrorMatches, "write |1: file already closed")
}

func (s *execSuite) TestLoggedCommandError(c *check.C) {
	cmd := exec.LoggedCommand("cmd")
	cmdErr := s.runAsync(cmd)

	s.sendExit(c, 1)
	c.Check(<-cmdErr, check.ErrorMatches, "exit status 1")
}

func (s *execSuite) TestLoggedCommandStdout(c *check.C) {
	cmd := exec.LoggedCommand("cmd")
	c.Check(cmd.Start(), check.IsNil)

	s.sendStdout(c, "hello world\n")

	entry := s.log.recvEntry(c)
	c.Check(entry.Level, check.Equals, log.DebugLevel)
	c.Check(entry.Message, check.Equals, "hello world")

	s.sendExit(c, 0)
	c.Check(cmd.Wait(), check.IsNil)
}

func (s *execSuite) TestLoggedCommandStderr(c *check.C) {
	cmd := exec.LoggedCommand("cmd")
	c.Check(cmd.Start(), check.IsNil)

	s.sendStderr(c, "dlrow olleh\n")

	entry := s.log.recvEntry(c)
	c.Check(entry.Level, check.Equals, log.WarnLevel)
	c.Check(entry.Message, check.Equals, "dlrow olleh")

	s.sendExit(c, 0)
	c.Check(cmd.Wait(), check.IsNil)
}

func (s *execSuite) TestLoggedCommandStdoutPipe(c *check.C) {
	cmd := exec.LoggedCommand("cmd")
	rc, err := cmd.StdoutPipe()
	c.Assert(err, check.IsNil)

	c.Check(cmd.Start(), check.IsNil)

	s.sendStdout(c, "hello world\n")

	entry := s.log.recvEntry(c)
	c.Check(entry.Level, check.Equals, log.DebugLevel)
	c.Check(entry.Message, check.Equals, "hello world")

	scanner := bufio.NewScanner(rc)
	scanner.Scan()
	c.Check(scanner.Text(), check.Equals, "hello world")

	s.sendExit(c, 0)
	c.Check(cmd.Wait(), check.IsNil)
}

func (s *execSuite) TestLoggedCommandStderrPipe(c *check.C) {
	cmd := exec.LoggedCommand("cmd")
	rc, err := cmd.StderrPipe()
	c.Assert(err, check.IsNil)

	c.Check(cmd.Start(), check.IsNil)

	s.sendStderr(c, "dlrow olleh\n")

	entry := s.log.recvEntry(c)
	c.Check(entry.Level, check.Equals, log.WarnLevel)
	c.Check(entry.Message, check.Equals, "dlrow olleh")

	scanner := bufio.NewScanner(rc)
	scanner.Scan()
	c.Check(scanner.Text(), check.Equals, "dlrow olleh")

	s.sendExit(c, 0)
	c.Check(cmd.Wait(), check.IsNil)
}

var (
	child      = flag.Bool("child", false, "")
	stdoutPath = flag.String("stdout", "", "")
	stderrPath = flag.String("stderr", "", "")
	exitPath   = flag.String("exit", "", "")
)

func runChild() int {
	loggerProxy := func(out io.Writer, path string) {
		for {
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprint(os.Stderr, err)
				return
			}

			_, err = io.Copy(out, f)
			f.Close()
			if err != nil {
				fmt.Fprint(os.Stderr, err)
				return
			}
		}
	}

	go loggerProxy(os.Stdout, *stdoutPath)
	go loggerProxy(os.Stderr, *stderrPath)

	f, err := os.Open(*exitPath)
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

	r, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	return r
}

func TestMain(m *testing.M) {
	flag.Parse()
	if !*child {
		os.Exit(m.Run())
	}

	os.Exit(runChild())
}
