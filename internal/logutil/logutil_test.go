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

package logutil_test

import (
	"bytes"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	. "gopkg.in/check.v1"

	. "github.com/canonical/encrypt-cloud-image/internal/logutil"
)

func Test(t *testing.T) { TestingT(t) }

type logutilSuite struct{}

var _ = Suite(&logutilSuite{})

func (s *logutilSuite) testFormattedWriterLevels(c *C, levels []log.Level) {
	w := NewFormattedWriter(levels)
	c.Check(w.Levels(), DeepEquals, levels)
}

func (s *logutilSuite) TestFormattedWriterLevels1(c *C) {
	s.testFormattedWriterLevels(c, []log.Level{log.PanicLevel, log.FatalLevel, log.ErrorLevel, log.WarnLevel})
}

func (s *logutilSuite) TestFormattedWriterLevels2(c *C) {
	s.testFormattedWriterLevels(c, []log.Level{log.InfoLevel, log.DebugLevel, log.TraceLevel})
}

func (s *logutilSuite) TestFormattedWriterDefaultOutput(c *C) {
	w := NewFormattedWriter(nil)
	c.Check(w.Output(), Equals, os.Stderr)
}

func (s *logutilSuite) TestFormattedWriterDefaultFormatter(c *C) {
	w := NewFormattedWriter(nil)
	c.Check(w.Formatter(), FitsTypeOf, &log.TextFormatter{})
}

type mockFormatter struct {
	lastEntry *log.Entry
}

func (f *mockFormatter) Format(entry *log.Entry) ([]byte, error) {
	f.lastEntry = entry
	return []byte("hello world\n"), nil
}

func (s *logutilSuite) TestFormatterWriterFire(c *C) {
	buf := new(bytes.Buffer)
	formatter := new(mockFormatter)

	w := NewFormattedWriter(nil)
	w.SetFormatter(formatter)
	w.SetOutput(buf)

	entry := &log.Entry{Logger: log.StandardLogger()}
	c.Check(w.Fire(entry), IsNil)
	c.Check(entry.Logger, Equals, log.StandardLogger())
	c.Check(buf.String(), Equals, "hello world\n")
	c.Check(formatter.lastEntry, Equals, entry)
}
