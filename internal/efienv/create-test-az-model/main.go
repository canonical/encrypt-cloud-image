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
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-efilib"
	log "github.com/sirupsen/logrus"

	"github.com/canonical/encrypt-cloud-image/internal/efienv"
)

var (
	msOwnerGuid = efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
)

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

func run(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: " + os.Args[0] + " <input_file> <output_file>")
	}

	input := args[0]
	output := args[1]

	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	var config efienv.Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&config); err != nil {
		return fmt.Errorf("cannot decode config: %w", err)
	}

	profile := efienv.AzDisk{
		Type: "Microsoft.Compute/disks",
		Properties: &efienv.AzDiskProperties{
			UefiSettings: &efienv.AzUefiSettings{
				SignatureMode: "Replace",
				Signatures:    new(efienv.AzUefiSignatures)}}}

	r := bytes.NewReader(config.PK)
	l, err := efi.ReadSignatureList(r)
	switch {
	case err != nil && err == io.EOF:
	case err != nil:
		return fmt.Errorf("cannot read PK: %w", err)
	default:
		azdb, err := encodeAzSignatureDb(efi.SignatureDatabase{l})
		if err != nil {
			return fmt.Errorf("cannot encode PK to az format: %w", err)
		}
		profile.Properties.UefiSettings.Signatures.PK = azdb[0]
	}

	for _, d := range []struct {
		name string
		src  []byte
		dst  *[]*efienv.AzUefiSignatureList
	}{
		{
			name: "KEK",
			src:  config.KEK,
			dst:  &profile.Properties.UefiSettings.Signatures.KEK,
		},
		{
			name: "db",
			src:  config.Db,
			dst:  &profile.Properties.UefiSettings.Signatures.Db,
		},
		{
			name: "dbx",
			src:  config.Dbx,
			dst:  &profile.Properties.UefiSettings.Signatures.Dbx,
		},
	} {
		r := bytes.NewReader(d.src)
		db, err := efi.ReadSignatureDatabase(r)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", d.name, err)
		}

		azdb, err := encodeAzSignatureDb(db)
		if err != nil {
			return fmt.Errorf("cannot encode %s to az format: %w", d.name, err)
		}

		*d.dst = azdb
	}

	f, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("cannot create az template file: %w", err)
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
