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
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/snapcore/secboot"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage:", os.Args[0], "[path|-]")
		os.Exit(1)
	}

	var r io.Reader
	if os.Args[1] == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
	}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(b) != 16 {
		fmt.Fprintln(os.Stderr, "invalid recovery key length - must be 16 bytes")
		os.Exit(1)
	}

	var recoveryKey secboot.RecoveryKey
	copy(recoveryKey[:], b)

	fmt.Println(recoveryKey)
}
