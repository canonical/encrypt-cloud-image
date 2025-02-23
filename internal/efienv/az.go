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

package efienv

import (
	"bytes"
	"fmt"

	//"github.com/Azure/azure-sdk-for-go/sdk/profiles/latest/armcompute"
	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
)

var (
	msOwnerGuid = efi.MakeGUID(0x77fa9abd, 0x0359, 0x4d32, 0xbd60, [...]uint8{0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b})
)

type AzUefiSignatureList struct {
	Type  string   `json:"type"`
	Value [][]byte `json:"value"`
}

type AzUefiSignatures struct {
	PK  *AzUefiSignatureList   `json:"PK"`
	KEK []*AzUefiSignatureList `json:"KEK"`
	Db  []*AzUefiSignatureList `json:"db"`
	Dbx []*AzUefiSignatureList `json:"dbx"`
}

type AzUefiSettings struct {
	SignatureMode string            `json:"signatureMode"`
	Signatures    *AzUefiSignatures `json:"signatures"`
}

type AzDiskProperties struct {
	UefiSettings *AzUefiSettings `json:"uefiSettings"`
}

// XXX: Use armcompute.Disk when it has the right properties.
type AzDisk struct {
	Type       string            `json:"type"`
	Properties *AzDiskProperties `json:"properties"`
}

func decodeAzSignatureDb(azdb []*AzUefiSignatureList) (out efi.SignatureDatabase, err error) {
	for _, azl := range azdb {
		switch azl.Type {
		case "x509":
			for _, data := range azl.Value {
				out = append(out, &efi.SignatureList{
					Type:       efi.CertX509Guid,
					Signatures: []*efi.SignatureData{{Owner: msOwnerGuid, Data: data}}})
			}
		case "sha256":
			l := &efi.SignatureList{Type: efi.CertSHA256Guid}
			for _, data := range azl.Value {
				l.Signatures = append(l.Signatures, &efi.SignatureData{Owner: msOwnerGuid, Data: data})
			}
			out = append(out, l)
		default:
			return nil, fmt.Errorf("unrecognized signature list type: %v", azl.Type)
		}
	}

	return out, nil
}

func newConfigFromAzDiskProfile(profile *AzDisk) (*Config, error) {
	if profile.Type != "Microsoft.Compute/disks" {
		return nil, fmt.Errorf("unexpected resource type %s", profile.Type)
	}

	config := &Config{OmitsReadyToBootEvent: false}

	if profile.Properties == nil {
		return config, nil
	}
	if profile.Properties.UefiSettings == nil {
		return config, nil
	}
	if profile.Properties.UefiSettings.SignatureMode != "Replace" {
		return nil, fmt.Errorf("unexpected signatureMode %s", profile.Properties.UefiSettings.SignatureMode)
	}
	if profile.Properties.UefiSettings.Signatures == nil {
		return config, nil
	}

	signatures := profile.Properties.UefiSettings.Signatures

	var pk []*AzUefiSignatureList
	if signatures.PK != nil {
		pk = append(pk, signatures.PK)
	}

	for _, db := range []struct {
		name string
		src  []*AzUefiSignatureList
		dst  *[]byte
	}{
		{
			"PK",
			pk,
			&config.PK,
		},
		{
			"KEK",
			signatures.KEK,
			&config.KEK,
		},
		{
			"db",
			signatures.Db,
			&config.Db,
		},
		{
			"dbx",
			signatures.Dbx,
			&config.Dbx,
		},
	} {
		decoded, err := decodeAzSignatureDb(db.src)
		if err != nil {
			return nil, fmt.Errorf("cannot decode %s: %w", db.name, err)
		}

		encoded := new(bytes.Buffer)
		if err := decoded.Write(encoded); err != nil {
			return nil, fmt.Errorf("cannot encode %s: %w", db.name, err)
		}

		*db.dst = encoded.Bytes()
	}

	return config, nil
}

func NewEnvironmentFromAzDiskProfile(profile *AzDisk, logAlgorithms tcglog.AlgorithmIdList) (secboot_efi.HostEnvironment, error) {
	config, err := newConfigFromAzDiskProfile(profile)
	if err != nil {
		return nil, err
	}

	return NewEnvironment(config, logAlgorithms), nil
}
