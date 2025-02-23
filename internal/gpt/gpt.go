package gpt

import (
	"encoding/binary"
	"fmt"
	"errors"
	"io"
	"os"

	"github.com/canonical/go-efilib"
)

const (
	blockSize           = 512
	gptSignature uint64 = 0x5452415020494645
)

var emptyPartitionType efi.GUID

type chsAddress [3]uint8

type mbrPartitionEntry struct {
	Flag         uint8
	StartAddress chsAddress
	Type         uint8
	EndAddress   chsAddress
	StartingLBA  uint32
	Length       uint32
}

type mbr struct {
	Code       [446]byte
	Partitions [4]mbrPartitionEntry
	Signature  uint16
}

type PartitionEntry struct {
	*efi.PartitionEntry
	Index int
}

type Partitions []*PartitionEntry

func (partitions Partitions) FindByPartitionType(t efi.GUID) *PartitionEntry {
	for _, p := range partitions {
		if p.PartitionTypeGUID == t {
			return p
		}
	}
	return nil
}

func ReadPartitionTable(path string) (Partitions, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}

	var mbr mbr
	if err := binary.Read(io.NewSectionReader(f, 0, 512), binary.LittleEndian, &mbr); err != nil {
		return nil, err
	}
	if mbr.Signature != 0xaa55 {
		return nil, errors.New("invalid MBR signature")
	}

	validPmbr := false
	for _, p := range mbr.Partitions {
		if p.Type == 0xee {
			validPmbr = true
			break
		}
	}
	if !validPmbr {
		return nil, errors.New("no valid PMBR detected")
	}

	hdr, err := efi.ReadPartitionTableHeader(io.NewSectionReader(f, blockSize, blockSize), false)
	if err != nil {
		return nil, fmt.Errorf("cannot read GPT header: %w", err)
	}

	entReader := io.NewSectionReader(f, blockSize*2, int64(hdr.NumberOfPartitionEntries*hdr.SizeOfPartitionEntry))
	entries, err := efi.ReadPartitionEntries(entReader, hdr.NumberOfPartitionEntries, hdr.SizeOfPartitionEntry)
	if err != nil {
		return nil, fmt.Errorf("cannot read partition entries: %w", err)
	}

	var partitions Partitions
	for i, p := range entries {
		if p.PartitionTypeGUID == emptyPartitionType {
			continue
		}
		partitions = append(partitions, &PartitionEntry{p, i + 1})
	}

	return partitions, nil
}
