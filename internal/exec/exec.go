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

package exec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

type teeReadCloser struct {
	rc io.ReadCloser
	w  io.Writer
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p); err != nil {
			return n, err
		}
	}
	return n, err
}

func (t *teeReadCloser) Close() error {
	return t.rc.Close()
}

type LoggedCmd struct {
	*exec.Cmd

	logger log.FieldLogger

	childLogger log.FieldLogger
	numLoggers  int
	loggerDone  chan error

	Stdout io.Writer
	Stderr io.Writer

	closeAfterStartError []io.Closer
	closeAfterWait       []io.Closer
}

func LoggedCommand(name string, arg ...string) *LoggedCmd {
	c := &LoggedCmd{
		Cmd: exec.Command(name, arg...)}
	c.logger = log.WithField("exec.LoggedCmd", fmt.Sprintf("%p", c))
	c.logger.Debugf("created LoggedCmd for %s %s\n", name, strings.Join(arg, " "))
	return c
}

func (c *LoggedCmd) closeHandles(handles []io.Closer) {
	for _, h := range handles {
		h.Close()
	}
}

func (c *LoggedCmd) waitLoggers() (err error) {
	for i := 0; i < c.numLoggers; i++ {
		if e := <-c.loggerDone; e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (c *LoggedCmd) StdoutPipe() (io.ReadCloser, error) {
	if c.Stdout != nil {
		return nil, errors.New("stdout already set")
	}
	if c.Process != nil {
		return nil, errors.New("process already started")
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	c.closeAfterWait = append(c.closeAfterWait, pr, pw)
	c.Stdout = pw
	return pr, nil
}

func (c *LoggedCmd) StderrPipe() (io.ReadCloser, error) {
	if c.Stderr != nil {
		return nil, errors.New("stderr already set")
	}
	if c.Process != nil {
		return nil, errors.New("process already started")
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	c.closeAfterWait = append(c.closeAfterWait, pr, pw)
	c.Stderr = pw
	return pr, nil
}

func (c *LoggedCmd) Start() error {
	c.logger.Debugln("executing", strings.Join(c.Args, " "))

	var wg sync.WaitGroup
	wg.Add(1)

	logger := func(r io.ReadCloser, fn func(...interface{})) {
		wg.Wait()
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			fn(scanner.Text())
		}

		err := scanner.Err()
		if errors.Is(err, os.ErrClosed) {
			err = nil
		}

		// Avoid a deadlock in Wait() if scanner failed with an error before
		// the pipe was closed
		if err != nil {
			c.logger.WithError(scanner.Err()).Warningln("scanner failed with an error")
			r.Close()
		}

		c.loggerDone <- err
	}

	if c.Cmd.Stdout == nil {
		stdout, err := c.Cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("cannot obtain stdout pipe: %w", err)
		}
		c.closeAfterStartError = append(c.closeAfterStartError, stdout)

		if c.Stdout != nil {
			stdout = &teeReadCloser{stdout, c.Stdout}
		}

		go logger(stdout, func(v ...interface{}) { c.childLogger.Debugln(v...) })
		c.numLoggers += 1
	}

	if c.Cmd.Stderr == nil {
		stderr, err := c.Cmd.StderrPipe()
		if err != nil {
			c.closeHandles(c.closeAfterStartError)
			return fmt.Errorf("cannot obtain stderr pipe: %w", err)
		}

		if c.Stderr != nil {
			stderr = &teeReadCloser{stderr, c.Stderr}
		}

		go logger(stderr, func(v ...interface{}) { c.childLogger.Warningln(v...) })
		c.numLoggers += 1
		c.closeAfterStartError = append(c.closeAfterStartError, stderr)
	}

	c.loggerDone = make(chan error, c.numLoggers)

	if err := c.Cmd.Start(); err != nil {
		c.closeHandles(c.closeAfterStartError)
		wg.Done()
		c.waitLoggers()
		return err
	}

	c.logger.Debugln("executed command as PID", c.Process.Pid)
	c.childLogger = log.WithField("pid", c.Process.Pid)

	wg.Done()
	return nil
}

func (c *LoggedCmd) Wait() error {
	c.logger.Debugln("waiting")
	err := c.Cmd.Wait()
	c.logger.Debugln("waiting on logger goroutines to terminate")
	loggerErr := c.waitLoggers()
	c.logger.Debugln("done")

	c.closeHandles(c.closeAfterWait)

	if err != nil {
		return err
	}
	return loggerErr
}

func (c *LoggedCmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}
