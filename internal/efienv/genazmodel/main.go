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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/canonical/go-efilib"
	"github.com/chrisccoulson/encrypt-cloud-image/internal/efienv"
	log "github.com/sirupsen/logrus"

	"golang.org/x/xerrors"
)

var (
	msOwnerGuid = efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
)

func writeSignatureDatabase(path string, db efi.SignatureDatabase) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return db.Write(f)
}

func encodeAzSignatureDb(db efi.SignatureDatabase) (out []*efienv.AzUefiSignatureList, err error) {
	for _, l := range db {
		azl := new(efienv.AzUefiSignatureList)

		switch l.Type {
		case efi.CertX509Guid:
			azl.Type = "x509"
		case efi.CertSHA256Guid:
			azl.Type = "sha256"
		default:
			return nil, fmt.Errorf("unrecognized signature list type: %v", l.Type)
		}

		for _, s := range l.Signatures {
			if s.Owner != msOwnerGuid {
				return nil, fmt.Errorf("invalid owner ID: %v", s.Owner)
			}

			azl.Value = append(azl.Value, s.Data)
		}

		out = append(out, azl)
	}

	return out, nil
}

func readSignatureList(path string) (*efi.SignatureList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return efi.ReadSignatureList(f)
}

func buildSignatureDatabase(paths []string) (efi.SignatureDatabase, error) {
	var db efi.SignatureDatabase
	for _, path := range paths {
		l, err := readSignatureList(path)
		if err != nil {
			return nil, xerrors.Errorf("cannot read ESL for %s: %w", path, err)
		}
		db = append(db, l)
	}
	return db, nil
}

func run(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: " + os.Args[0] + " <input_dir> <output_dir>")
	}

	input := args[0]
	output := args[1]

	profile := efienv.AzDisk{Properties: &efienv.AzDiskProperties{UefiSettings: &efienv.AzUefiSettings{Signatures: new(efienv.AzUefiSignatures)}}}

	var pk []*efienv.AzUefiSignatureList

	path := filepath.Join(input, "PK.esl")
	l, err := readSignatureList(path)
	switch {
	case err != nil && os.IsNotExist(err):
	case err != nil:
		return xerrors.Errorf("cannot open file %s: %w", path, err)
	default:
		azdb, err := encodeAzSignatureDb(efi.SignatureDatabase{l})
		if err != nil {
			return xerrors.Errorf("cannot encode PK to az format: %w", err)
		}
		profile.Properties.UefiSettings.Signatures.PK = azdb[0]

		if err := writeSignatureDatabase(filepath.Join(output, "PK"), efi.SignatureDatabase{l}); err != nil {
			return xerrors.Errorf("cannot encode PK: %w", err)
		}
	}

	for _, d := range []struct {
		name string
		dst  *[]*efienv.AzUefiSignatureList
	}{
		{
			"PK",
			&pk,
		},
		{
			"KEK",
			&profile.Properties.UefiSettings.Signatures.KEK,
		},
		{
			"db",
			&profile.Properties.UefiSettings.Signatures.Db,
		},
		{
			"dbx",
			&profile.Properties.UefiSettings.Signatures.Dbx,
		},
	} {
		paths, err := filepath.Glob(filepath.Join(input, d.name+"-*.esl"))
		if err != nil {
			panic(err)
		}
		sort.Sort(sort.StringSlice(paths))

		db, err := buildSignatureDatabase(paths)
		if err != nil {
			return xerrors.Errorf("cannot build signature database for %s: %w", d.name, err)
		}

		azdb, err := encodeAzSignatureDb(db)
		if err != nil {
			return xerrors.Errorf("cannot encode signature database %s to az format: %w", d.name, err)
		}

		*d.dst = azdb

		if err := writeSignatureDatabase(filepath.Join(output, d.name), db); err != nil {
			return xerrors.Errorf("cannot encode signature database %s: %w", d.name, err)
		}
	}

	f, err := os.OpenFile(filepath.Join(output, "disk.json"), os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return xerrors.Errorf("cannot create az template file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(profile)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
