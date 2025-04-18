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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/canonical/encrypt-cloud-image/internal/efienv"
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	check "gopkg.in/check.v1"
)

func Test(t *testing.T) { check.TestingT(t) }

type isEFIVariableDriverConfigEventChecker struct {
	*check.CheckerInfo
}

var (
	invalidEventTypeErrStr = "invalid event type"
	invalidPCRIndexErrStr  = "invalid PCR index"
	invalidDigestErrStr    = "invalid digest"
)

var isEFIVariableDriverConfigEvent = &isEFIVariableDriverConfigEventChecker{
	&check.CheckerInfo{Name: "isVariableDriverConfigEvent", Params: []string{"event", "pcr", "varName", "varGuid", "varData"}}}

func (checker *isEFIVariableDriverConfigEventChecker) Check(params []interface{}, names []string) (result bool, errorName string) {
	e, ok := params[0].(*tcglog.Event)
	if !ok {
		return false, names[0] + " is not an event"
	}

	if e.EventType != tcglog.EventTypeEFIVariableDriverConfig {
		return false, invalidEventTypeErrStr
	}

	pcr, ok := params[1].(int)
	if !ok {
		return false, names[1] + "is not a PCR index"
	}
	if tcglog.PCRIndex(pcr) != e.PCRIndex {
		return false, invalidPCRIndexErrStr
	}

	data, ok := e.Data.(*tcglog.EFIVariableData)
	if !ok {
		return false, "invalid event data type"
	}

	name, ok := params[2].(string)
	if !ok {
		return false, names[2] + " is not a variable name"
	}
	if data.UnicodeName != name {
		return false, "invalid variable name"
	}

	guid, ok := params[3].(efi.GUID)
	if !ok {
		return false, names[3] + " is not a variable GUID"
	}
	if data.VariableName != guid {
		return false, "invalid variable GUID"
	}

	if !reflect.DeepEqual(params[4], data.VariableData) {
		return false, "invalid variable data"
	}

	for alg, digest := range e.Digests {
		expected := tcglog.ComputeEFIVariableDataDigest(alg.GetHash(), data.UnicodeName, data.VariableName, data.VariableData)
		if !bytes.Equal(digest, expected) {
			return false, invalidDigestErrStr
		}
	}

	return true, ""
}

type isSeparatorEventChecker struct {
	*check.CheckerInfo
}

var isSeparatorEvent = &isSeparatorEventChecker{
	&check.CheckerInfo{Name: "isSeparatorEvent", Params: []string{"event", "pcr", "value"}}}

func (checker *isSeparatorEventChecker) Check(params []interface{}, names []string) (result bool, errorStr string) {
	e, ok := params[0].(*tcglog.Event)
	if !ok {
		return false, names[0] + " is not an event"
	}

	if e.EventType != tcglog.EventTypeSeparator {
		return false, invalidEventTypeErrStr
	}

	pcr, ok := params[1].(int)
	if !ok {
		return false, names[1] + "is not a PCR index"
	}
	if tcglog.PCRIndex(pcr) != e.PCRIndex {
		return false, invalidPCRIndexErrStr
	}

	data, ok := e.Data.(*tcglog.SeparatorEventData)
	if !ok {
		return false, "invalid event data type"
	}
	if data.IsError() {
		return false, "invalid event data"
	}

	value, ok := params[2].(uint32)
	if !ok {
		return false, "invalid value type"
	}

	for alg, digest := range e.Digests {
		expected := tcglog.ComputeSeparatorEventDigest(alg.GetHash(), value)
		if !bytes.Equal(digest, expected) {
			return false, invalidDigestErrStr
		}
	}

	return true, ""
}

type isEFIActionEventChecker struct {
	*check.CheckerInfo
}

var isEFIActionEvent = &isEFIActionEventChecker{
	&check.CheckerInfo{
		Name:   "isEFIActionEvent",
		Params: []string{"event", "pcr", "action"}}}

func (checker *isEFIActionEventChecker) Check(params []interface{}, names []string) (result bool, errorStr string) {
	e, ok := params[0].(*tcglog.Event)
	if !ok {
		return false, names[0] + " is not an event"
	}

	if e.EventType != tcglog.EventTypeEFIAction {
		return false, invalidEventTypeErrStr
	}

	pcr, ok := params[1].(int)
	if !ok {
		return false, names[1] + "is not a PCR index"
	}
	if tcglog.PCRIndex(pcr) != e.PCRIndex {
		return false, invalidPCRIndexErrStr
	}

	if e.Data != params[2] {
		return false, "invalid event data"
	}

	for alg, digest := range e.Digests {
		expected := tcglog.ComputeStringEventDigest(alg.GetHash(), e.Data.String())
		if !bytes.Equal(digest, expected) {
			return false, invalidDigestErrStr
		}
	}

	return true, ""
}

type efienvSuite struct{}

var _ = check.Suite(&efienvSuite{})

type testNewEnvironmentData struct {
	path                  string
	logAlgs               tcglog.AlgorithmIdList
	omitsReadyToBootEvent bool
}

func (s *efienvSuite) testNewEnvironment(c *check.C, data *testNewEnvironmentData) {
	f, err := os.Open(data.path)
	c.Assert(err, check.IsNil)

	var config efienv.Config
	dec := json.NewDecoder(f)
	c.Check(dec.Decode(&config), check.IsNil)
	c.Check(f.Close(), check.IsNil)

	env := efienv.NewEnvironment(&config, data.logAlgs)

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
		c.Check(err, check.IsNil)
		c.Check(attrs, check.Equals, efi.AttributeTimeBasedAuthenticatedWriteAccess|efi.AttributeRuntimeAccess|efi.AttributeBootserviceAccess|efi.AttributeNonVolatile)

		expected, err := ioutil.ReadFile(filepath.Join("testdata", v.name))
		c.Check(err, check.IsNil)
		c.Check(data, check.DeepEquals, expected)
	}

	log, err := env.ReadEventLog()
	c.Assert(err, check.IsNil)
	c.Check(log.Spec.IsEFI_2(), check.Equals, true)
	c.Check(log.Algorithms, check.DeepEquals, data.logAlgs)

	totalEvents := 8
	if data.omitsReadyToBootEvent {
		totalEvents--
	}

	c.Assert(log.Events, check.HasLen, totalEvents)
	c.Check(log.Events[0], isEFIVariableDriverConfigEvent, 7, "SecureBoot", efi.GlobalVariable, []byte{0x01})
	c.Check(log.Events[1], isEFIVariableDriverConfigEvent, 7, "PK", efi.GlobalVariable, []byte(nil))
	c.Check(log.Events[2], isEFIVariableDriverConfigEvent, 7, "KEK", efi.GlobalVariable, []byte(nil))
	c.Check(log.Events[3], isEFIVariableDriverConfigEvent, 7, "db", efi.ImageSecurityDatabaseGuid, []byte(nil))
	c.Check(log.Events[4], isEFIVariableDriverConfigEvent, 7, "dbx", efi.ImageSecurityDatabaseGuid, []byte(nil))
	c.Check(log.Events[5], isSeparatorEvent, 7, tcglog.SeparatorEventNormalValue)
	if !data.omitsReadyToBootEvent {
		c.Check(log.Events[6], isEFIActionEvent, 4, tcglog.EFICallingEFIApplicationEvent)
		c.Check(log.Events[7], isSeparatorEvent, 4, tcglog.SeparatorEventNormalValue)
	} else {
		c.Check(log.Events[6], isSeparatorEvent, 4, tcglog.SeparatorEventNormalValue)
	}
}

func (s *efienvSuite) TestNewEnvironment1(c *check.C) {
	s.testNewEnvironment(c, &testNewEnvironmentData{
		path:                  "testdata/uefi.json",
		logAlgs:               tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA256},
		omitsReadyToBootEvent: false,
	})
}

func (s *efienvSuite) TestNewEnvironment2(c *check.C) {
	s.testNewEnvironment(c, &testNewEnvironmentData{
		path:                  "testdata/uefi-omits-rtb-event.json",
		logAlgs:               tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA256},
		omitsReadyToBootEvent: true,
	})
}

func (s *efienvSuite) TestNewEnvironment3(c *check.C) {
	s.testNewEnvironment(c, &testNewEnvironmentData{
		path:                  "testdata/uefi.json",
		logAlgs:               tcglog.AlgorithmIdList{tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256},
		omitsReadyToBootEvent: false,
	})
}
