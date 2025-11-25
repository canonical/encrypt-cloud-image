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
	"context"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
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

func (e *env) makeEFIVariableDriverConfigEvent(pcr tpm2.Handle, name string, guid efi.GUID, data []byte) *tcglog.Event {
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

func (e *env) makeSeparatorEvent(pcr tpm2.Handle) *tcglog.Event {
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

func (e *env) makeEFIActionEvent(pcr tpm2.Handle, data tcglog.EventData) *tcglog.Event {
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

type varsBackend struct {
	*Config
}

func (b varsBackend) Get(name string, guid efi.GUID) (efi.VariableAttributes, []byte, error) {
	authVarPayload := func(data []byte) (efi.VariableAttributes, []byte, error) {
		return efi.AttributeTimeBasedAuthenticatedWriteAccess | efi.AttributeRuntimeAccess |
			efi.AttributeBootserviceAccess | efi.AttributeNonVolatile, data, nil
	}

	switch guid {
	case efi.GlobalVariable:
		switch name {
		case "PK":
			return authVarPayload(b.PK)
		case "KEK":
			return authVarPayload(b.KEK)
		}
	case efi.ImageSecurityDatabaseGuid:
		switch name {
		case "db":
			return authVarPayload(b.Db)
		case "dbx":
			return authVarPayload(b.Dbx)
		}
	}

	return 0, nil, efi.ErrVarNotExist
}

func (b varsBackend) List() ([]efi.VariableDescriptor, error) {
	return []efi.VariableDescriptor{
		{Name: "PK", GUID: efi.GlobalVariable},
		{Name: "KEK", GUID: efi.GlobalVariable},
		{Name: "db", GUID: efi.ImageSecurityDatabaseGuid},
		{Name: "dbx", GUID: efi.ImageSecurityDatabaseGuid},
	}, nil
}

// This is required to satisfy the efi.VarsBackend interface but is otherwise unused.
func (b varsBackend) Set(_ string, _ efi.GUID, _ efi.VariableAttributes, _ []byte) error {
	panic("unimplemented")
}

// This is left here to enforce that the varsBackend type satisfies the efi.VarsBackend interface.
// The vars backends is passed via opaque context attribute and non-compliance with its interface wouldn't be caught
// at compile time otherwise.
var _ efi.VarsBackend = varsBackend{}

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

func (e *env) VarContext(parent context.Context) context.Context {
	return context.WithValue(parent, efi.VarsBackendKey{}, varsBackend{e.Config})
}

func NewEnvironment(config *Config, logAlgorithms tcglog.AlgorithmIdList) secboot_efi.HostEnvironment {
	return &env{config, logAlgorithms}
}
