// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package luks2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/snapcore/snapd/osutil"
)

const (
	// AnySlot tells a command to automatically choose an appropriate slot
	// as opposed to hard coding one.
	AnySlot = -1
)

var (
	keySize = 64
)

// cryptsetupCmd is a helper for running the cryptsetup command. If stdin is supplied, data read
// from it is supplied to cryptsetup via its stdin. If callback is supplied, it will be invoked
// after cryptsetup has started.
func cryptsetupCmd(stdin io.Reader, callback func(cmd *exec.Cmd) error, args ...string) error {
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = stdin

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start cryptsetup: %w", err)
	}

	var cbErr error
	if callback != nil {
		cbErr = callback(cmd)
	}

	err := cmd.Wait()

	switch {
	case cbErr != nil:
		return cbErr
	case err != nil:
		return fmt.Errorf("cryptsetup failed with: %v", osutil.OutputErr(b.Bytes(), err))
	}

	return nil
}

// KDFOptions specifies parameters for the Argon2 KDF.
type KDFOptions struct {
	// TargetDuration specifies the target time for benchmarking of the
	// time and memory cost parameters. If it is zero then the cryptsetup
	// default is used. If ForceIterations is not zero then this is ignored.
	TargetDuration time.Duration

	// MemoryKiB specifies the maximum memory cost in KiB when ForceIterations
	// is zero, or the actual memory cost in KiB when ForceIterations is not zero.
	// If this is set to zero, then the cryptsetup default is used.
	MemoryKiB int

	// ForceIterations specifies the time cost. If set to zero, the time
	// and memory cost are determined by benchmarking the algorithm based on
	// the specified TargetDuration. Set to a non-zero number to force the
	// time cost to the value of this field, and the memory cost to the value
	// of MemoryKiB, disabling benchmarking.
	ForceIterations int

	// Parallel sets the maximum number of parallel threads. Cryptsetup may
	// choose a lower value based on its own maximum and the number of available
	// CPU cores.
	Parallel int
}

func (options *KDFOptions) appendArguments(args []string) []string {
	// use argon2i as the KDF
	args = append(args, "--pbkdf", "argon2i")

	switch {
	case options.ForceIterations != 0:
		// Disable benchmarking by forcing the time cost
		args = append(args,
			"--pbkdf-force-iterations", strconv.Itoa(options.ForceIterations))
	case options.TargetDuration != 0:
		args = append(args,
			"--iter-time", strconv.FormatInt(int64(options.TargetDuration/time.Millisecond), 10))
	}

	if options.MemoryKiB != 0 {
		args = append(args, "--pbkdf-memory", strconv.Itoa(options.MemoryKiB))
	}

	if options.Parallel != 0 {
		args = append(args, "--pbkdf-parallel", strconv.Itoa(options.Parallel))
	}

	return args
}

// FormatOptions provide the options for formatting a new LUKS2 volume.
type FormatOptions struct {
	// MetadataKiBSize sets the size of the metadata area in KiB.
	// This size includes the 4KiB fixed-size binary header, with
	// the remaining space for the JSON area. Set to zero to use
	// the cryptsetup default. Must be any power of 2 between
	// 16KiB and 4MiB.
	MetadataKiBSize int

	// KeyslotsAreaKiBSize sets the size of the binary keyslots
	// area in KiB. Set to zero to use the cryptsetup default.
	// Must be a multiple of 4KiB.
	KeyslotsAreaKiBSize int

	// KDFOptions describes the KDF options for the initial
	// key slot.
	KDFOptions KDFOptions
}

// Format will initialize a LUKS2 container with the specified options and set the primary key to the
// supplied key. The label for the new container will be set to the supplied label. This can only be
// called on a device that is not mapped.
//
// The container will be configured to encrypt data with AES-256 and XTS block cipher mode. The
// KDF for the primary keyslot will be configured to use argon2i with the supplied benchmark time.
//
// WARNING: This function is destructive. Calling this on an existing LUKS2 container will make the
// data contained inside of it irretrievable.
func Format(devicePath, label string, key []byte, opts *FormatOptions) error {
	if opts == nil {
		var defaultOpts FormatOptions
		opts = &defaultOpts
	}

	args := []string{
		// batch processing, no password verification for formatting an existing LUKS container
		"-q",
		// formatting a new volume
		"luksFormat",
		// use LUKS2
		"--type", "luks2",
		// read the key from stdin
		"--key-file", "-",
		// use AES-256 with XTS block cipher mode (XTS requires 2 keys)
		"--cipher", "aes-xts-plain64", "--key-size", strconv.Itoa(keySize * 8),
		// set LUKS2 label
		"--label", label}

	// apply KDF options
	args = opts.KDFOptions.appendArguments(args)

	if opts.MetadataKiBSize != 0 {
		// override the default metadata area size if specified
		args = append(args, "--luks2-metadata-size", fmt.Sprintf("%dk", opts.MetadataKiBSize))
	}
	if opts.KeyslotsAreaKiBSize != 0 {
		// override the default keyslots area size if specified
		args = append(args, "--luks2-keyslots-size", fmt.Sprintf("%dk", opts.KeyslotsAreaKiBSize))
	}

	args = append(args,
		// device to format
		devicePath)

	return cryptsetupCmd(bytes.NewReader(key), nil, args...)
}

// AddKeyOptions provides the options for adding a key to a LUKS2 volume
type AddKeyOptions struct {
	// KDFOptions describes the KDF options for the new key slot.
	KDFOptions KDFOptions

	// Slot is the keyslot to use. Note that the default value is slot 0. In
	// order to automatically choose a slot, use AnySlot.
	Slot int
}

// AddKey adds the supplied key in to a new keyslot for specified LUKS2 container. In order to do this,
// an existing key must be provided. The KDF for the new keyslot will be configured to use argon2i with
// the supplied benchmark time. The key will be added to the supplied slot.
//
// If options is not supplied, the default KDF benchmark time is used and the command will
// automatically choose an appropriate slot.
func AddKey(devicePath string, existingKey, key []byte, options *AddKeyOptions) error {
	if options == nil {
		options = &AddKeyOptions{Slot: AnySlot}
	}

	fifoPath, cleanupFifo, err := mkFifo()
	if err != nil {
		return fmt.Errorf("cannot create FIFO for passing existing key to cryptsetup: %w", err)
	}
	defer cleanupFifo()

	args := []string{
		// add a new key
		"luksAddKey",
		// LUKS2 only
		"--type", "luks2",
		// read existing key from named pipe
		"--key-file", fifoPath}

	// apply KDF options
	args = options.KDFOptions.appendArguments(args)

	if options.Slot != AnySlot {
		args = append(args, "--key-slot", strconv.Itoa(options.Slot))
	}

	args = append(args,
		// container to add key to
		devicePath,
		// read new key from stdin.
		// Note that we can't supply the new key and existing key via the same channel
		// because pipes and FIFOs aren't seekable - we would need to use an actual file
		// in order to be able to do this.
		"-")

	writeExistingKeyToFifo := func(cmd *exec.Cmd) error {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		if err != nil {
			// If we fail to open the write end, the read end will be blocked in open(), so
			// kill the process.
			baseErr := fmt.Errorf("cannot open FIFO for passing existing key to cryptsetup: %w", err)
			if killErr := cmd.Process.Kill(); killErr != nil {
				return fmt.Errorf("%w (failed to kill process: %s)", err, killErr)
			}
			return baseErr
		}

		if _, err := f.Write(existingKey); err != nil {
			// The read end is open and blocked inside read(). Closing our write end will result in the
			// read end returning 0 bytes (EOF) and continuing cleanly.
			baseErr := fmt.Errorf("cannot pass existing key to cryptsetup: %w", err)
			if err := f.Close(); err != nil {
				// If we can't close the write end, the read end will remain blocked inside read(),
				// so kill the process.
				if killErr := cmd.Process.Kill(); killErr != nil {
					return fmt.Errorf("%w (failed to kill process: %s)", err, killErr)
				}
			}
			return baseErr
		}

		if err := f.Close(); err != nil {
			// If we can't close the write end, the read end will remain blocked inside read(),
			// so kill the process.
			baseErr := fmt.Errorf("cannot close write end of FIFO: %w", err)
			if killErr := cmd.Process.Kill(); killErr != nil {
				return fmt.Errorf("%w (failed to kill process: %s)", err, killErr)
			}
			return baseErr
		}

		return nil
	}

	return cryptsetupCmd(bytes.NewReader(key), writeExistingKeyToFifo, args...)
}

// ImportToken imports the supplied token in to the JSON metadata area of the specified LUKS2 container.
func ImportToken(devicePath string, token Token) error {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("cannot serialize token: %w", err)
	}

	return cryptsetupCmd(bytes.NewReader(tokenJSON), nil, "token", "import", devicePath)
}

// RemoveToken removes the token with the supplied ID from the JSON metadata area of the specified
// LUKS2 container.
func RemoveToken(devicePath string, id int) error {
	return cryptsetupCmd(nil, nil, "token", "remove", "--token-id", strconv.Itoa(id), devicePath)
}

// KillSlot erases the keyslot with the supplied slot number from the specified LUKS2 container.
// Note that a valid key for a remaining keyslot must be supplied, in order to prevent the last
// keyslot from being erased.
func KillSlot(devicePath string, slot int, key []byte) error {
	return cryptsetupCmd(bytes.NewReader(key), nil, "luksKillSlot", "--type", "luks2", "--key-file", "-", devicePath, strconv.Itoa(slot))
}

// SetSlotPriority sets the priority of the keyslot with the supplied slot number on
// the specified LUKS2 container.
func SetSlotPriority(devicePath string, slot int, priority SlotPriority) error {
	return cryptsetupCmd(nil, nil, "config", "--priority", priority.String(), "--key-slot", strconv.Itoa(slot), devicePath)
}
