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

	"golang.org/x/xerrors"
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
	Signatures *AzUefiSignatures `json:"signatures"`
}

type AzDiskProperties struct {
	UefiSettings *AzUefiSettings `json:"uefiSettings"`
}

// XXX: Use armcompute.Disk when it has the right properties.
type AzDisk struct {
	Properties *AzDiskProperties `json:"properties"`
}

func decodeAzSignatureDb(azdb []*AzUefiSignatureList) (out efi.SignatureDatabase, err error) {
	for _, azl := range azdb {
		l := new(efi.SignatureList)

		switch azl.Type {
		case "x509":
			l.Type = efi.CertX509Guid
		case "sha256":
			l.Type = efi.CertSHA256Guid
		default:
			return nil, fmt.Errorf("unrecognized signature list type: %v", azl.Type)
		}

		for _, data := range azl.Value {
			l.Signatures = append(l.Signatures, &efi.SignatureData{Owner: msOwnerGuid, Data: data})
		}

		out = append(out, l)
	}

	return out, nil
}

func NewEnvironmentFromAzDiskProfile(profile *AzDisk, logAlgs tcglog.AlgorithmIdList) (secboot_efi.HostEnvironment, error) {
	e := &env{logReadyToBootEvent: true, logAlgorithms: logAlgs}

	if profile.Properties == nil {
		return e, nil
	}
	if profile.Properties.UefiSettings == nil {
		return e, nil
	}
	if profile.Properties.UefiSettings.Signatures == nil {
		return e, nil
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
			&e.pk,
		},
		{
			"KEK",
			signatures.KEK,
			&e.kek,
		},
		{
			"db",
			signatures.Db,
			&e.db,
		},
		{
			"dbx",
			signatures.Dbx,
			&e.dbx,
		},
	} {
		decoded, err := decodeAzSignatureDb(db.src)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode %s: %w", db.name, err)
		}

		encoded := new(bytes.Buffer)
		if err := decoded.Write(encoded); err != nil {
			return nil, xerrors.Errorf("cannot encode %s: %w", db.name, err)
		}

		*db.dst = encoded.Bytes()
	}

	return e, nil
}
