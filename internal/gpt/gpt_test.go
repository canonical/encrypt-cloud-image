package gpt

import (
	"crypto/rand"
	"testing"

	efi "github.com/canonical/go-efilib"
)

func generatePartitionEntry(t *testing.T) *PartitionEntry {
	var GUID efi.GUID = [16]byte{}
	_, err := rand.Read(GUID[:])
	if err != nil {
		// Per rand.Read doc, this should never happen:
		//    Read fills b with cryptographically secure random bytes.
		//    It never returns an error, and always fills b entirely.
		t.Fatal("failed to generate random UUID")
	}

	return &PartitionEntry{
		PartitionEntry: &efi.PartitionEntry{
			UniquePartitionGUID: GUID,
		},
	}
}

func TestFindByUUID(t *testing.T) {
	partition1 := generatePartitionEntry(t)
	partition2 := generatePartitionEntry(t)
	partition3 := generatePartitionEntry(t)

	table := []struct {
		Name          string
		UUIDStr       string
		Parts         Partitions
		ExpectedEntry *PartitionEntry
	}{
		{"simple", partition3.UniquePartitionGUID.String(), Partitions{partition1, partition2, partition3}, partition3},
		{"wrong UUID", "foobar", Partitions{partition1}, nil},
		{"no partition", partition1.UniquePartitionGUID.String(), Partitions{}, nil},
		{"no partition matching", partition1.UniquePartitionGUID.String(), Partitions{partition2, partition3}, nil},
		{"nil partition list", partition1.UniquePartitionGUID.String(), nil, nil},
	}

	for _, testParams := range table {
		t.Run(testParams.Name, func(t *testing.T) {
			partition := testParams.Parts.FindByUUID(testParams.UUIDStr)
			if partition != testParams.ExpectedEntry {
				t.Errorf("Wrong partition entry returned by FindByUUID(%s) on %v. Got %v, expected %v.", testParams.UUIDStr, testParams.Parts, partition, testParams.ExpectedEntry)
			}
		})
	}
}
