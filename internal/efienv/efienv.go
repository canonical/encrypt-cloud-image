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
	"encoding/json"
	"fmt"

	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
)

type configRaw struct {
	PK                    []byte   `json:"PK"`
	KEK                   []byte   `json:"KEK"`
	Db                    []byte   `json:"db"`
	Dbx                   []byte   `json:"dbx"`
	LogAlgorithms         []string `json:"logAlgorithms"`
	OmitsReadyToBootEvent bool     `json:"omitsReadyToBootEvent"`
}

type Config struct {
	PK  []byte
	KEK []byte
	Db  []byte
	Dbx []byte

	LogAlgorithms         tcglog.AlgorithmIdList
	OmitsReadyToBootEvent bool
}

func (c Config) MarshalJSON() ([]byte, error) {
	raw := configRaw{
		PK:                    c.PK,
		KEK:                   c.KEK,
		Db:                    c.Db,
		Dbx:                   c.Dbx,
		OmitsReadyToBootEvent: c.OmitsReadyToBootEvent}

	for _, a := range c.LogAlgorithms {
		var s string
		switch a {
		case tcglog.AlgorithmSha1:
			s = "sha1"
		case tcglog.AlgorithmSha256:
			s = "sha256"
		case tcglog.AlgorithmSha384:
			s = "sha384"
		case tcglog.AlgorithmSha512:
			s = "sha512"
		default:
			panic("unrecognized algorithm")
		}

		raw.LogAlgorithms = append(raw.LogAlgorithms, s)
	}

	return json.Marshal(raw)
}

func (c *Config) UnmarshalJSON(d []byte) error {
	var raw configRaw
	if err := json.Unmarshal(d, &raw); err != nil {
		return err
	}

	c.PK = raw.PK
	c.KEK = raw.KEK
	c.Db = raw.Db
	c.Dbx = raw.Dbx

	for _, s := range raw.LogAlgorithms {
		var a tcglog.AlgorithmId
		switch s {
		case "sha1":
			a = tcglog.AlgorithmSha1
		case "sha256":
			a = tcglog.AlgorithmSha256
		case "sha384":
			a = tcglog.AlgorithmSha384
		case "sha512":
			a = tcglog.AlgorithmSha512
		default:
			return fmt.Errorf("invalid algorithm: %s", s)
		}

		c.LogAlgorithms = append(c.LogAlgorithms, a)
	}

	c.OmitsReadyToBootEvent = raw.OmitsReadyToBootEvent

	return nil
}

type env struct {
	*Config
}

func (e *env) makeEFIVariableDriverConfigEvent(pcr tcglog.PCRIndex, name string, guid efi.GUID, data []byte) *tcglog.Event {
	digests := make(tcglog.DigestMap)
	for _, alg := range e.LogAlgorithms {
		digests[alg] = tcglog.ComputeEFIVariableDataDigest(alg.GetHash(), name, guid, data)
	}

	return &tcglog.Event{
		PCRIndex:  pcr,
		EventType: tcglog.EventTypeEFIVariableDriverConfig,
		Digests:   digests,
		Data: &tcglog.EFIVariableData{
			VariableName: guid,
			UnicodeName:  name,
			VariableData: data}}
}

func (e *env) makeSeparatorEvent(pcr tcglog.PCRIndex) *tcglog.Event {
	digests := make(tcglog.DigestMap)
	for _, alg := range e.LogAlgorithms {
		digests[alg] = tcglog.ComputeSeparatorEventDigest(alg.GetHash(), tcglog.SeparatorEventNormalValue)
	}

	return &tcglog.Event{
		PCRIndex:  pcr,
		EventType: tcglog.EventTypeSeparator,
		Digests:   digests,
		Data:      new(tcglog.SeparatorEventData)}
}

func (e *env) makeEFIActionEvent(pcr tcglog.PCRIndex, data tcglog.EventData) *tcglog.Event {
	digests := make(tcglog.DigestMap)
	for _, alg := range e.LogAlgorithms {
		digests[alg] = tcglog.ComputeStringEventDigest(alg.GetHash(), data.String())
	}

	return &tcglog.Event{
		PCRIndex:  pcr,
		EventType: tcglog.EventTypeEFIAction,
		Digests:   digests,
		Data:      data}
}

func (e *env) ReadVar(name string, guid efi.GUID) ([]byte, efi.VariableAttributes, error) {
	authVarPayload := func(data []byte) ([]byte, efi.VariableAttributes, error) {
		return data, efi.AttributeTimeBasedAuthenticatedWriteAccess | efi.AttributeRuntimeAccess | efi.AttributeBootserviceAccess | efi.AttributeNonVolatile, nil
	}

	switch guid {
	case efi.GlobalVariable:
		switch name {
		case "PK":
			return authVarPayload(e.PK)
		case "KEK":
			return authVarPayload(e.KEK)
		}
	case efi.ImageSecurityDatabaseGuid:
		switch name {
		case "db":
			return authVarPayload(e.Db)
		case "dbx":
			return authVarPayload(e.Dbx)
		}
	}

	return nil, 0, efi.ErrVariableNotFound
}

func (e *env) ReadEventLog() (*tcglog.Log, error) {
	log := &tcglog.Log{Spec: tcglog.SpecEFI_2, Algorithms: e.LogAlgorithms}

	log.Events = append(log.Events, e.makeEFIVariableDriverConfigEvent(7, "SecureBoot", efi.GlobalVariable, []byte{0x01}))
	log.Events = append(log.Events, e.makeEFIVariableDriverConfigEvent(7, "PK", efi.GlobalVariable, nil))
	log.Events = append(log.Events, e.makeEFIVariableDriverConfigEvent(7, "KEK", efi.GlobalVariable, nil))
	log.Events = append(log.Events, e.makeEFIVariableDriverConfigEvent(7, "db", efi.ImageSecurityDatabaseGuid, nil))
	log.Events = append(log.Events, e.makeEFIVariableDriverConfigEvent(7, "dbx", efi.ImageSecurityDatabaseGuid, nil))
	log.Events = append(log.Events, e.makeSeparatorEvent(7))

	if !e.OmitsReadyToBootEvent {
		log.Events = append(log.Events, e.makeEFIActionEvent(4, tcglog.EFICallingEFIApplicationEvent))
	}
	log.Events = append(log.Events, e.makeSeparatorEvent(4))

	return log, nil
}

func NewEnvironment(config *Config) secboot_efi.HostEnvironment {
	return &env{config}
}
