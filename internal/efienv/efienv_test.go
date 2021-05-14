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
	"reflect"
	"testing"

	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type isEFIVariableDriverConfigEventChecker struct {
	*CheckerInfo
}

var isEFIVariableDriverConfigEvent = &isEFIVariableDriverConfigEventChecker{
	&CheckerInfo{Name: "isVariableDriverConfigEvent", Params: []string{"event", "pcr", "varName", "varGuid", "varData"}}}

func (checker *isEFIVariableDriverConfigEventChecker) Check(params []interface{}, names []string) (result bool, error string) {
	e, ok := params[0].(*tcglog.Event)
	if !ok {
		return false, names[0] + " is not an event"
	}

	if e.EventType != tcglog.EventTypeEFIVariableDriverConfig {
		return false, "invalid event type"
	}

	pcr, ok := params[1].(int)
	if !ok {
		return false, names[1] + "is not a PCR index"
	}
	if tcglog.PCRIndex(pcr) != e.PCRIndex {
		return false, "invalid PCR index"
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
			return false, "invalid digest"
		}
	}

	return true, ""
}

type isSeparatorEventChecker struct {
	*CheckerInfo
}

var isSeparatorEvent = &isSeparatorEventChecker{
	&CheckerInfo{Name: "isSeparatorEvent", Params: []string{"event", "pcr", "value"}}}

func (checker *isSeparatorEventChecker) Check(params []interface{}, names []string) (result bool, error string) {
	e, ok := params[0].(*tcglog.Event)
	if !ok {
		return false, names[0] + " is not an event"
	}

	if e.EventType != tcglog.EventTypeSeparator {
		return false, "invalid event type"
	}

	pcr, ok := params[1].(int)
	if !ok {
		return false, names[1] + "is not a PCR index"
	}
	if tcglog.PCRIndex(pcr) != e.PCRIndex {
		return false, "invalid PCR index"
	}

	data, ok := e.Data.(*tcglog.SeparatorEventData)
	if !ok {
		return false, "invalid event data type"
	}
	if data.IsError {
		return false, "invalid event data"
	}

	value, ok := params[2].(uint32)
	if !ok {
		return false, "invalid value type"
	}

	for alg, digest := range e.Digests {
		expected := tcglog.ComputeSeparatorEventDigest(alg.GetHash(), value)
		if !bytes.Equal(digest, expected) {
			return false, "invalid digest"
		}
	}

	return true, ""
}

type isEFIActionEventChecker struct {
	*CheckerInfo
}

var isEFIActionEvent = &isEFIActionEventChecker{
	&CheckerInfo{
		Name:   "isEFIActionEvent",
		Params: []string{"event", "pcr", "action"}}}

func (checker *isEFIActionEventChecker) Check(params []interface{}, names []string) (result bool, error string) {
	e, ok := params[0].(*tcglog.Event)
	if !ok {
		return false, names[0] + " is not an event"
	}

	if e.EventType != tcglog.EventTypeEFIAction {
		return false, "invalid event type"
	}

	pcr, ok := params[1].(int)
	if !ok {
		return false, names[1] + "is not a PCR index"
	}
	if tcglog.PCRIndex(pcr) != e.PCRIndex {
		return false, "invalid PCR index"
	}

	if e.Data != params[2] {
		return false, "invalid event data"
	}

	for alg, digest := range e.Digests {
		expected := tcglog.ComputeStringEventDigest(alg.GetHash(), e.Data.String())
		if !bytes.Equal(digest, expected) {
			return false, "invalid digest"
		}
	}

	return true, ""
}
