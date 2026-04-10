// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package dcerpc

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseUUID parses a UUID string like "000001A0-0000-0000-C000-000000000046" to [16]byte.
// The UUID is stored in the DCE/RPC wire format (Data1 little-endian, Data2/Data3 little-endian).
func ParseUUID(s string) ([16]byte, error) {
	var result [16]byte

	// Remove dashes
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ToLower(s)

	if len(s) != 32 {
		return result, fmt.Errorf("invalid UUID length: %d", len(s))
	}

	// Decode hex string
	data, err := hex.DecodeString(s)
	if err != nil {
		return result, fmt.Errorf("invalid UUID hex: %v", err)
	}

	// UUID structure in memory/wire format:
	// Data1: 4 bytes, little-endian (reversed from string)
	// Data2: 2 bytes, little-endian (reversed from string)
	// Data3: 2 bytes, little-endian (reversed from string)
	// Data4: 8 bytes, big-endian (as-is)

	// Data1 (bytes 0-3 in string): reverse
	result[0] = data[3]
	result[1] = data[2]
	result[2] = data[1]
	result[3] = data[0]

	// Data2 (bytes 4-5 in string): reverse
	result[4] = data[5]
	result[5] = data[4]

	// Data3 (bytes 6-7 in string): reverse
	result[6] = data[7]
	result[7] = data[6]

	// Data4 (bytes 8-15 in string): as-is
	copy(result[8:], data[8:])

	return result, nil
}

// MustParseUUID parses a UUID string and panics on error.
// Use this for compile-time constants.
func MustParseUUID(s string) [16]byte {
	result, err := ParseUUID(s)
	if err != nil {
		panic(fmt.Sprintf("invalid UUID %q: %v", s, err))
	}
	return result
}

// FormatUUID formats a [16]byte UUID as a string like "000001a0-0000-0000-c000-000000000046"
func FormatUUID(uuid [16]byte) string {
	// Reverse the byte order for display
	data := make([]byte, 16)

	// Data1: reverse
	data[0] = uuid[3]
	data[1] = uuid[2]
	data[2] = uuid[1]
	data[3] = uuid[0]

	// Data2: reverse
	data[4] = uuid[5]
	data[5] = uuid[4]

	// Data3: reverse
	data[6] = uuid[7]
	data[7] = uuid[6]

	// Data4: as-is
	copy(data[8:], uuid[8:])

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		data[0:4],
		data[4:6],
		data[6:8],
		data[8:10],
		data[10:16],
	)
}
