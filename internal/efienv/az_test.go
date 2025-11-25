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

package efienv_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	check "gopkg.in/check.v1"

	"github.com/canonical/encrypt-cloud-image/internal/efienv"
)

type azSuite struct{}

var _ = check.Suite(&azSuite{})

func (s *azSuite) testNewEnvironmentFromAzDiskProfile(c *check.C) {
	f, err := os.Open("testdata/disk.json")
	c.Assert(err, check.IsNil)

	var profile efienv.AzDisk
	dec := json.NewDecoder(f)
	c.Check(dec.Decode(&profile), check.IsNil)
	c.Check(f.Close(), check.IsNil)

	env, err := efienv.NewEnvironmentFromAzDiskProfile(&profile, tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA256})
	c.Assert(err, check.IsNil)

	for _, v := range []struct {
		guid efi.GUID
		name string
	}{
		{
			efi.GlobalVariable,
			"PK",
		},
		{
			efi.GlobalVariable,
			"KEK",
		},
		{
			efi.ImageSecurityDatabaseGuid,
			"db",
		},
		{
			efi.ImageSecurityDatabaseGuid,
			"dbx",
		},
	} {
		data, attrs, err := efi.ReadVariable(env.VarContext(context.Background()), v.name, v.guid)
		c.Check(err, check.IsNil)
		c.Check(attrs, check.Equals, efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeRuntimeAccess|efi.AttributeBootserviceAccess|efi.AttributeNonVolatile)

		expected, err := os.ReadFile(filepath.Join("testdata", v.name))
		c.Check(err, check.IsNil)
		c.Check(data, check.DeepEquals, expected)
	}

	log, err := env.ReadEventLog()
	c.Assert(err, check.IsNil)
	c.Check(log.Spec.IsEFI_2(), check.Equals, true)
	c.Check(log.Algorithms, check.DeepEquals, tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA256})

	c.Assert(log.Events, check.HasLen, 8)
	c.Check(log.Events[0], isEFIVariableDriverConfigEvent, 7, "SecureBoot", efi.GlobalVariable, []byte{0x01})
	c.Check(log.Events[1], isEFIVariableDriverConfigEvent, 7, "PK", efi.GlobalVariable, []byte(nil))
	c.Check(log.Events[2], isEFIVariableDriverConfigEvent, 7, "KEK", efi.GlobalVariable, []byte(nil))
	c.Check(log.Events[3], isEFIVariableDriverConfigEvent, 7, "db", efi.ImageSecurityDatabaseGuid, []byte(nil))
	c.Check(log.Events[4], isEFIVariableDriverConfigEvent, 7, "dbx", efi.ImageSecurityDatabaseGuid, []byte(nil))
	c.Check(log.Events[5], isSeparatorEvent, 7, tcglog.SeparatorEventNormalValue)
	c.Check(log.Events[6], isEFIActionEvent, 4, tcglog.EFICallingEFIApplicationEvent)
	c.Check(log.Events[7], isSeparatorEvent, 4, tcglog.SeparatorEventNormalValue)
}

func (s *azSuite) TestNewEnvironmentFromAzDiskProfile1(c *check.C) {
	s.testNewEnvironmentFromAzDiskProfile(c)
}

func (s *azSuite) TestNewEnvironmentFromAzDiskProfile2(c *check.C) {
	s.testNewEnvironmentFromAzDiskProfile(c)
}
