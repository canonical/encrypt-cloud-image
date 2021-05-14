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

package logutil

import (
	"io"

	log "github.com/sirupsen/logrus"
)

type FormattedWriter struct {
	log    *log.Logger
	levels []log.Level
}

func (w *FormattedWriter) Fire(entry *log.Entry) error {
	origLogger := entry.Logger
	entry.Logger = w.log
	defer func() {
		entry.Logger = origLogger
	}()

	line, err := entry.Bytes()
	if err != nil {
		return err
	}

	_, err = w.log.Out.Write(line)
	return err
}

func (w *FormattedWriter) Levels() []log.Level {
	return w.levels
}

func (w *FormattedWriter) Formatter() log.Formatter {
	return w.log.Formatter
}

func (w *FormattedWriter) SetFormatter(formatter log.Formatter) {
	w.log.SetFormatter(formatter)
}

func (w *FormattedWriter) Output() io.Writer {
	return w.log.Out
}

func (w *FormattedWriter) SetOutput(output io.Writer) {
	w.log.SetOutput(output)
}

func NewFormattedWriter(levels []log.Level) *FormattedWriter {
	return &FormattedWriter{log: log.New(), levels: levels}
}
