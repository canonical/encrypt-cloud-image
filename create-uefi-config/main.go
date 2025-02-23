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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/canonical/go-efilib"
	"github.com/jessevdk/go-flags"

	"github.com/canonical/encrypt-cloud-image/internal/efienv"
)

type Options struct {
	In  string `short:"i" long:"in" description:"Directory containing ESLs that comprise the platform's secure boot configuration"`
	Out string `short:"o" long:"out" description:"Output file name" required:"true"`

	OmitsReadyToBootSignal bool `long:"omits-ready-to-boot-signal" description:"The platform omits the \"Calling EFI Application from Boot Option\" EV_EFI_ACTION event in PCR4"`

	SaveDatabases string `long:"save-databases" description:"Write the contents of the database variables to the specified directory"`
}

func populateConfigFromVars(config *efienv.Config) error {
	for _, v := range []struct {
		name string
		guid efi.GUID
		dest *[]byte
	}{
		{
			name: "PK",
			guid: efi.GlobalVariable,
			dest: &config.PK,
		},
		{
			name: "KEK",
			guid: efi.GlobalVariable,
			dest: &config.KEK,
		},
		{
			name: "db",
			guid: efi.ImageSecurityDatabaseGuid,
			dest: &config.Db,
		},
		{
			name: "dbx",
			guid: efi.ImageSecurityDatabaseGuid,
			dest: &config.Dbx,
		},
	} {
		b, _, err := efi.ReadVariable(v.name, v.guid)
		if err != nil && err != efi.ErrVarNotExist {
			return fmt.Errorf("cannot read %s variable: %w", v.name, err)
		}

		*v.dest = b
	}

	return nil
}

func populateConfigFromESLs(config *efienv.Config, path string) error {
	pkPath := filepath.Join(path, "PK.esl")
	pk, err := ioutil.ReadFile(pkPath)
	switch {
	case err != nil && os.IsNotExist(err):
	case err != nil:
		return fmt.Errorf("cannot populate PK: %w", err)
	default:
		config.PK = pk
	}

	for _, d := range []struct {
		name string
		dest *[]byte
	}{
		{
			name: "KEK",
			dest: &config.KEK,
		},
		{
			name: "db",
			dest: &config.Db,
		},
		{
			name: "dbx",
			dest: &config.Dbx,
		},
	} {
		paths, err := filepath.Glob(filepath.Join(path, d.name+"-*.esl"))
		if err != nil {
			panic(err)
		}
		sort.Sort(sort.StringSlice(paths))

		var buf bytes.Buffer
		for _, path := range paths {
			err := func() error {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				if _, err := io.Copy(&buf, f); err != nil {
					return err
				}

				return nil
			}()
			if err != nil {
				return fmt.Errorf("cannot populate %s: %w", d.name, err)
			}
		}

		*d.dest = buf.Bytes()
	}

	return nil
}

func run(args []string) error {
	var options Options
	if _, err := flags.ParseArgs(&options, args); err != nil {
		return fmt.Errorf("cannot parse arguments: %w", err)
	}

	var config efienv.Config

	if options.In != "" {
		if err := populateConfigFromESLs(&config, options.In); err != nil {
			return fmt.Errorf("cannot populate config from ESLs: %w", err)
		}
	} else {
		if err := populateConfigFromVars(&config); err != nil {
			return fmt.Errorf("cannot populate config from EFI variables: %w", err)
		}
	}

	config.OmitsReadyToBootEvent = options.OmitsReadyToBootSignal

	f, err := os.OpenFile(options.Out, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("cannot create file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		return fmt.Errorf("cannot encode config: %w", err)
	}

	if options.SaveDatabases != "" {
		for _, d := range []struct {
			name string
			src  []byte
		}{
			{
				name: "PK",
				src:  config.PK,
			},
			{
				name: "KEK",
				src:  config.KEK,
			},
			{
				name: "db",
				src:  config.Db,
			},
			{
				name: "dbx",
				src:  config.Dbx,
			},
		} {
			if err := ioutil.WriteFile(filepath.Join(options.SaveDatabases, d.name), d.src, 0644); err != nil {
				return fmt.Errorf("cannot write file %s: %w", d.name, err)
			}
		}
	}

	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
