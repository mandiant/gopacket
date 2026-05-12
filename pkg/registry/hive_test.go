// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

package registry

import (
	"encoding/binary"
	"strings"
	"testing"
)

// synthHive builds the minimum bytes Open() will accept: a valid header with
// signature, root offset, and zeroed first hbin. Tests use this to construct
// hives with specific cell bytes without needing a real registry file.
func synthHive(t *testing.T, cellsAt4096 []byte) *Hive {
	t.Helper()
	// 4096 bytes of header + 4096 bytes of hbin = 8192 minimum.
	data := make([]byte, 8192+len(cellsAt4096))
	// Header signature 'regf'
	binary.LittleEndian.PutUint32(data[4:], regfMagic)
	// Root offset at header[36:40] is irrelevant for readCell-only tests.
	binary.LittleEndian.PutUint32(data[36:40], 0)
	copy(data[4096:], cellsAt4096)
	return &Hive{data: data, rootOffset: 0}
}

// TestReadCellRejectsMalformedSizes covers the inputs that used to panic in
// pkg/registry/hive.go: cell headers whose raw size field was 0 or a
// negative value with absolute magnitude smaller than the 4-byte header.
// All of these must now return an error, not crash.
func TestReadCellRejectsMalformedSizes(t *testing.T) {
	cases := []struct {
		name     string
		rawSize  int32
		wantSub  string
	}{
		{"zero size", 0, "free or zero-sized"},
		{"positive (free cell)", 64, "free or zero-sized"},
		{"negative -1", -1, "invalid size"},
		{"negative -3", -3, "invalid size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Lay the raw cell header at the very start of the first hbin
			// (hbin data begins at offset 4096 in the hive, offset 0 from
			// the cell-offset perspective).
			cell := make([]byte, 8)
			binary.LittleEndian.PutUint32(cell, uint32(c.rawSize))
			h := synthHive(t, cell)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("readCell panicked on %q: %v", c.name, r)
				}
			}()
			_, err := h.readCell(0)
			if err == nil {
				t.Fatalf("readCell returned nil error for %q", c.name)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("readCell error %q did not contain %q", err.Error(), c.wantSub)
			}
		})
	}
}

// TestReadCellReturnsDataForValidCell confirms the happy path still works:
// a -16 size header should yield a 12-byte slice.
func TestReadCellReturnsDataForValidCell(t *testing.T) {
	cell := make([]byte, 16)
	var neg int32 = -16
	binary.LittleEndian.PutUint32(cell, uint32(neg))
	copy(cell[4:], []byte("hello, world"))
	h := synthHive(t, cell)

	data, err := h.readCell(0)
	if err != nil {
		t.Fatalf("readCell error: %v", err)
	}
	if string(data) != "hello, world" {
		t.Fatalf("readCell returned %q, want %q", string(data), "hello, world")
	}
}

// TestGetValueDataResidentLengthRejected covers the input that originally
// panicked in GetValueData: a VK with the resident flag set and a lower-31
// length greater than the 4-byte DataOffset field. Found by kajaaz via Zorya
// (issue #25). The guard must return an error, not crash.
func TestGetValueDataResidentLengthRejected(t *testing.T) {
	// h.data is unused on the resident path; the guard short-circuits before
	// any cell read happens.
	h := &Hive{}

	for _, dataLen := range []uint32{5, 8, 0xFF, 0x7FFFFFFF} {
		t.Run("dataLen="+strings.ToUpper(uintHex(dataLen)), func(t *testing.T) {
			vk := &VKRecord{
				DataLen:    dataLen | 0x80000000, // set resident flag
				DataOffset: 0xDEADBEEF,
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetValueData panicked: %v", r)
				}
			}()
			data, err := h.GetValueData(vk)
			if err == nil {
				t.Fatalf("GetValueData returned nil error; got data=%v", data)
			}
			if !strings.Contains(err.Error(), "exceeds maximum of 4 bytes") {
				t.Fatalf("GetValueData error %q did not contain expected substring", err.Error())
			}
		})
	}
}

// TestGetValueDataResidentLengthAllowed confirms the happy path still works:
// a resident value of 1..4 bytes returns the inline DataOffset bytes.
func TestGetValueDataResidentLengthAllowed(t *testing.T) {
	h := &Hive{}
	// DataOffset 0x44434241 = bytes 'A','B','C','D' little-endian.
	for dataLen, want := range map[uint32]string{
		1: "A",
		2: "AB",
		3: "ABC",
		4: "ABCD",
	} {
		t.Run("dataLen="+uintHex(dataLen), func(t *testing.T) {
			vk := &VKRecord{
				DataLen:    dataLen | 0x80000000,
				DataOffset: 0x44434241,
			}
			data, err := h.GetValueData(vk)
			if err != nil {
				t.Fatalf("GetValueData error: %v", err)
			}
			if string(data) != want {
				t.Fatalf("GetValueData returned %q, want %q", string(data), want)
			}
		})
	}
}

// uintHex is a tiny helper for table-driven test names.
func uintHex(v uint32) string {
	const hex = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = hex[v&0xF]
		v >>= 4
	}
	return string(buf[i:])
}
