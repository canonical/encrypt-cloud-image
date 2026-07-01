package main

import (
	"testing"
)

func TestEncryptionStateValidate(t *testing.T) {
	tests := []struct {
		name        string
		state       encryptionState
		expectError string // empty if no error expected
	}{
		{
			name: "valid state with all fields",
			state: encryptionState{
				WorkingDir:  "/tmp/working",
				UnlockKey:   "base64encodedkey==",
				GrowPartKey: "base64encodedgrowkey==",
			},
			expectError: "",
		},
		{
			name: "valid state with empty GrowPartKey",
			state: encryptionState{
				WorkingDir:  "/tmp/working",
				UnlockKey:   "base64encodedkey==",
				GrowPartKey: "",
			},
			expectError: "",
		},
		{
			name: "invalid state with empty WorkingDir",
			state: encryptionState{
				WorkingDir:  "",
				UnlockKey:   "base64encodedkey==",
				GrowPartKey: "base64encodedgrowkey==",
			},
			expectError: "working_dir is required in encryption state",
		},
		{
			name: "invalid state with empty UnlockKey",
			state: encryptionState{
				WorkingDir:  "/tmp/working",
				UnlockKey:   "",
				GrowPartKey: "base64encodedgrowkey==",
			},
			expectError: "unlock_key is required in encryption state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.state.Validate()
			if tt.expectError == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectError)
				} else if err.Error() != tt.expectError {
					t.Errorf("expected error %q, got %q", tt.expectError, err.Error())
				}
			}
		})
	}
}
