// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

package smb

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

func TestIsSharingViolation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"raw response error", &smb2.ResponseError{Code: ntStatusSharingViolation}, true},
		{"wrapped in PathError", &os.PathError{Op: "remove", Path: "x", Err: &smb2.ResponseError{Code: ntStatusSharingViolation}}, true},
		{"different NTSTATUS", &os.PathError{Op: "remove", Path: "x", Err: &smb2.ResponseError{Code: ntStatusObjectNameNotFound}}, false},
		{"fmt-wrapped", fmt.Errorf("retrieval: %w", &smb2.ResponseError{Code: ntStatusSharingViolation}), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSharingViolation(tc.err); got != tc.want {
				t.Errorf("IsSharingViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"name not found", &os.PathError{Op: "open", Path: "x", Err: &smb2.ResponseError{Code: ntStatusObjectNameNotFound}}, true},
		{"path not found", &os.PathError{Op: "open", Path: "x", Err: &smb2.ResponseError{Code: ntStatusObjectPathNotFound}}, true},
		{"os.ErrNotExist sentinel (smb2 translates name_not_found here)", &os.PathError{Op: "open", Path: "__output", Err: os.ErrNotExist}, true},
		{"bare os.ErrNotExist", os.ErrNotExist, true},
		{"sharing violation", &os.PathError{Op: "remove", Path: "x", Err: &smb2.ResponseError{Code: ntStatusSharingViolation}}, false},
		{"unrelated error", errors.New("no such file"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNotFound(tc.err); got != tc.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
