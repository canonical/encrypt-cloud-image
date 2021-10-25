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
	"github.com/canonical/go-efilib"
	"github.com/canonical/tcglog-parser"
	secboot_efi "github.com/snapcore/secboot/efi"
)

type Config struct {
	PK                    []byte `json:"PK"`
	KEK                   []byte `json:"KEK"`
	Db                    []byte `json:"db"`
	Dbx                   []byte `json:"dbx"`
	OmitsReadyToBootEvent bool   `json:"omitsReadyToBootEvent"`
}

type env struct {
	*Config
	logAlgorithms tcglog.AlgorithmIdList
}

func (e *env) makeEFIVariableDriverConfigEvent(pcr tcglog.PCRIndex, name string, guid efi.GUID, data []byte) *tcglog.Event {
	digests := make(tcglog.DigestMap)
	for _, alg := range e.logAlgorithms {
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
	for _, alg := range e.logAlgorithms {
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
	for _, alg := range e.logAlgorithms {
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

	return nil, 0, efi.ErrVarNotExist
}

func (e *env) ReadEventLog() (*tcglog.Log, error) {
	log := &tcglog.Log{Spec: tcglog.Spec{PlatformType: tcglog.PlatformTypeEFI, Major: 2}, Algorithms: e.logAlgorithms}

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

func NewEnvironment(config *Config, logAlgorithms tcglog.AlgorithmIdList) secboot_efi.HostEnvironment {
	return &env{config, logAlgorithms}
}
