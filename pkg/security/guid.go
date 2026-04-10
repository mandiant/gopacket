// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// GUID represents a Windows GUID in mixed-endian (MS) binary format.
// Layout: Data1 (4 bytes LE) | Data2 (2 bytes LE) | Data3 (2 bytes LE) | Data4 (8 bytes raw)
type GUID [16]byte

// ParseGUID parses a GUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into binary.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "{}")

	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return g, fmt.Errorf("invalid GUID format: expected 5 parts, got %d", len(parts))
	}

	// Validate lengths: 8-4-4-4-12
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return g, fmt.Errorf("invalid GUID format: wrong part lengths")
	}

	// Data1: 4 bytes, stored little-endian
	d1, err := hex.DecodeString(parts[0])
	if err != nil {
		return g, fmt.Errorf("invalid GUID Data1: %v", err)
	}
	binary.LittleEndian.PutUint32(g[0:4], binary.BigEndian.Uint32(d1))

	// Data2: 2 bytes, stored little-endian
	d2, err := hex.DecodeString(parts[1])
	if err != nil {
		return g, fmt.Errorf("invalid GUID Data2: %v", err)
	}
	binary.LittleEndian.PutUint16(g[4:6], binary.BigEndian.Uint16(d2))

	// Data3: 2 bytes, stored little-endian
	d3, err := hex.DecodeString(parts[2])
	if err != nil {
		return g, fmt.Errorf("invalid GUID Data3: %v", err)
	}
	binary.LittleEndian.PutUint16(g[6:8], binary.BigEndian.Uint16(d3))

	// Data4: 8 bytes raw (first 2 from parts[3], last 6 from parts[4])
	d4a, err := hex.DecodeString(parts[3])
	if err != nil {
		return g, fmt.Errorf("invalid GUID Data4a: %v", err)
	}
	copy(g[8:10], d4a)

	d4b, err := hex.DecodeString(parts[4])
	if err != nil {
		return g, fmt.Errorf("invalid GUID Data4b: %v", err)
	}
	copy(g[10:16], d4b)

	return g, nil
}

// String returns the GUID in standard string format.
func (g GUID) String() string {
	d1 := binary.LittleEndian.Uint32(g[0:4])
	d2 := binary.LittleEndian.Uint16(g[4:6])
	d3 := binary.LittleEndian.Uint16(g[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", d1, d2, d3, g[8:10], g[10:16])
}

// IsZero returns true if the GUID is all zeros.
func (g GUID) IsZero() bool {
	for _, b := range g {
		if b != 0 {
			return false
		}
	}
	return true
}
