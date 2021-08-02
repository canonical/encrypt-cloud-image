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
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	. "github.com/chrisccoulson/encrypt-cloud-image/internal/efienv"

	. "gopkg.in/check.v1"
)

type azSuite struct{}

var _ = Suite(&azSuite{})

func (s *azSuite) testNewEnvironmentFromAzDiskProfile(c *C, path string) {
	f, err := os.Open("testdata/disk.json")
	c.Assert(err, IsNil)

	var profile AzDisk
	dec := json.NewDecoder(f)
	c.Check(dec.Decode(&profile), IsNil)
	c.Check(f.Close(), IsNil)

	env, err := NewEnvironmentFromAzDiskProfile(&profile, tcglog.AlgorithmIdList{tcglog.AlgorithmSha256})
	c.Assert(err, IsNil)

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
		data, attrs, err := env.ReadVar(v.name, v.guid)
		c.Check(err, IsNil)
		c.Check(attrs, Equals, efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeRuntimeAccess|efi.AttributeBootserviceAccess|efi.AttributeNonVolatile)

		expected, err := ioutil.ReadFile(filepath.Join("testdata", v.name))
		c.Check(err, IsNil)
		c.Check(data, DeepEquals, expected)
	}

	log, err := env.ReadEventLog()
	c.Assert(err, IsNil)
	c.Check(log.Spec, Equals, tcglog.SpecEFI_2)
	c.Check(log.Algorithms, DeepEquals, tcglog.AlgorithmIdList{tcglog.AlgorithmSha256})

	c.Assert(log.Events, HasLen, 8)
	c.Check(log.Events[0], isEFIVariableDriverConfigEvent, 7, "SecureBoot", efi.GlobalVariable, []byte{0x01})
	c.Check(log.Events[1], isEFIVariableDriverConfigEvent, 7, "PK", efi.GlobalVariable, []byte(nil))
	c.Check(log.Events[2], isEFIVariableDriverConfigEvent, 7, "KEK", efi.GlobalVariable, []byte(nil))
	c.Check(log.Events[3], isEFIVariableDriverConfigEvent, 7, "db", efi.ImageSecurityDatabaseGuid, []byte(nil))
	c.Check(log.Events[4], isEFIVariableDriverConfigEvent, 7, "dbx", efi.ImageSecurityDatabaseGuid, []byte(nil))
	c.Check(log.Events[5], isSeparatorEvent, 7, tcglog.SeparatorEventNormalValue)
	c.Check(log.Events[6], isEFIActionEvent, 4, tcglog.EFICallingEFIApplicationEvent)
	c.Check(log.Events[7], isSeparatorEvent, 4, tcglog.SeparatorEventNormalValue)
}

func (s *azSuite) TestNewEnvironmentFromAzDiskProfile1(c *C) {
	s.testNewEnvironmentFromAzDiskProfile(c, "testdata/disk.json")
}

func (s *azSuite) TestNewEnvironmentFromAzDiskProfile2(c *C) {
	s.testNewEnvironmentFromAzDiskProfile(c, "testdata/disk2.json")
}
