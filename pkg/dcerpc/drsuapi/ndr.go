// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NDR decoder primitives used to parse DRSUAPI responses. This is not a
// full generic NDR framework: it provides the specific primitives the
// DRSUAPI code needs (alignment, conformant and conformant-varying array
// headers, pointer referent IDs, UTF-16LE strings) so that the hand-rolled
// parsers in this package can follow NDR rules explicitly rather than
// relying on empirical byte offsets.
//
// NDR rules this decoder encodes:
//
//   - Primitives have natural alignment: USHORT=2, ULONG/DWORD=4,
//     LONGLONG/UHYPER=8. Before reading a primitive, the cursor is aligned
//     to that primitive's size by skipping padding bytes.
//
//   - A struct's alignment is the maximum alignment of its fields. Before
//     reading a struct, align to that maximum.
//
//   - Conformant array: MaxCount (ULONG) precedes the elements.
//
//   - Conformant-varying array: MaxCount (ULONG) + Offset (ULONG) +
//     ActualCount (ULONG) precedes the elements; Offset is almost always 0
//     and ActualCount is the actual element count on the wire.
//
//   - Early conformance: a conformant or conformant-varying array embedded
//     in a struct has its MaxCount hoisted to the front of the struct,
//     before all other fields.
//
//   - Pointer: ULONG referent ID. If non-zero, the pointed-to data is
//     serialized in "deferred data" order AFTER the enclosing struct's
//     fixed part, following the order pointers appear in the struct.

package drsuapi

import (
	"encoding/binary"
	"fmt"

	"github.com/mandiant/gopacket/pkg/utf16le"
)

// Decoder walks an NDR byte stream.
type Decoder struct {
	data []byte
	pos  int
	err  error
}

// NewDecoder creates a decoder positioned at offset 0.
func NewDecoder(data []byte) *Decoder {
	return &Decoder{data: data}
}

// Pos returns the current byte offset.
func (d *Decoder) Pos() int { return d.pos }

// Err returns the first error encountered, if any. Callers that want
// per-call error handling should check Err after a block of reads.
func (d *Decoder) Err() error { return d.err }

// Remaining is the number of bytes left to read.
func (d *Decoder) Remaining() int { return len(d.data) - d.pos }

// Fail records a sticky error on the decoder. Subsequent reads become
// no-ops returning zero values, so a caller that aborts a helper for
// structural reasons (e.g. exceeded a bounds cap) MUST call Fail before
// returning so downstream helpers don't read from an unadvanced cursor and
// drift the rest of the stream.
func (d *Decoder) Fail(format string, args ...interface{}) {
	if d.err == nil {
		d.err = fmt.Errorf(format, args...)
	}
}

// SeekTo moves the cursor to an absolute offset. Fails softly if out of
// range: the error is recorded and subsequent reads return zero values.
// If a prior error is already set, leaves both error and position alone so
// the first-failure context survives downstream Skip/Align calls.
func (d *Decoder) SeekTo(pos int) {
	if d.err != nil {
		return
	}
	if pos < 0 || pos > len(d.data) {
		d.err = fmt.Errorf("ndr: seek to out-of-range offset %d (len=%d)", pos, len(d.data))
		return
	}
	d.pos = pos
}

// Skip advances the cursor by n bytes. A negative n seeks backward.
func (d *Decoder) Skip(n int) { d.SeekTo(d.pos + n) }

// Align moves the cursor forward to the next multiple of n. NDR requires
// padding to each primitive's natural alignment before reading.
func (d *Decoder) Align(n int) {
	if n <= 1 {
		return
	}
	rem := d.pos % n
	if rem != 0 {
		d.Skip(n - rem)
	}
}

// ReadUint8 reads a single byte (no alignment).
func (d *Decoder) ReadUint8() uint8 {
	if d.err != nil {
		return 0
	}
	if d.pos+1 > len(d.data) {
		d.err = fmt.Errorf("ndr: short read at offset %d (uint8)", d.pos)
		return 0
	}
	v := d.data[d.pos]
	d.pos++
	return v
}

// ReadUint16 reads a USHORT with 2-byte alignment.
func (d *Decoder) ReadUint16() uint16 {
	d.Align(2)
	if d.err != nil {
		return 0
	}
	if d.pos+2 > len(d.data) {
		d.err = fmt.Errorf("ndr: short read at offset %d (uint16)", d.pos)
		return 0
	}
	v := binary.LittleEndian.Uint16(d.data[d.pos:])
	d.pos += 2
	return v
}

// ReadUint32 reads a ULONG/DWORD with 4-byte alignment.
func (d *Decoder) ReadUint32() uint32 {
	d.Align(4)
	if d.err != nil {
		return 0
	}
	if d.pos+4 > len(d.data) {
		d.err = fmt.Errorf("ndr: short read at offset %d (uint32)", d.pos)
		return 0
	}
	v := binary.LittleEndian.Uint32(d.data[d.pos:])
	d.pos += 4
	return v
}

// ReadUint64 reads a LONGLONG/UHYPER with 8-byte alignment.
func (d *Decoder) ReadUint64() uint64 {
	d.Align(8)
	if d.err != nil {
		return 0
	}
	if d.pos+8 > len(d.data) {
		d.err = fmt.Errorf("ndr: short read at offset %d (uint64)", d.pos)
		return 0
	}
	v := binary.LittleEndian.Uint64(d.data[d.pos:])
	d.pos += 8
	return v
}

// ReadBytes reads n raw bytes with no alignment. Returns a slice that
// aliases the underlying buffer; copy before mutating.
func (d *Decoder) ReadBytes(n int) []byte {
	if d.err != nil {
		return nil
	}
	if d.pos+n > len(d.data) {
		d.err = fmt.Errorf("ndr: short read at offset %d (%d bytes)", d.pos, n)
		return nil
	}
	v := d.data[d.pos : d.pos+n]
	d.pos += n
	return v
}

// ReadGUID reads a 16-byte GUID. GUIDs in NDR require 4-byte alignment
// (their max internal alignment, since UUID is a struct of DWORD/USHORTs).
func (d *Decoder) ReadGUID() [16]byte {
	d.Align(4)
	var g [16]byte
	if b := d.ReadBytes(16); b != nil {
		copy(g[:], b)
	}
	return g
}

// ReadPointer reads a pointer referent ID (ULONG). Zero means NULL, which
// means the pointed-to data is NOT serialized. Non-zero means the deferred
// data for this pointer will appear later.
func (d *Decoder) ReadPointer() uint32 { return d.ReadUint32() }

// ReadConformance reads the MaxCount prefix of a conformant array (ULONG,
// 4-byte aligned).
func (d *Decoder) ReadConformance() uint32 { return d.ReadUint32() }

// ReadConformantVaryingHeader reads the MaxCount + Offset + ActualCount
// prefix of a conformant-varying array. Returns (maxCount, offset,
// actualCount). Most callers ignore offset (always 0) and use actualCount
// as the element count.
func (d *Decoder) ReadConformantVaryingHeader() (maxCount, offset, actualCount uint32) {
	maxCount = d.ReadUint32()
	offset = d.ReadUint32()
	actualCount = d.ReadUint32()
	return
}

// ReadUTF16LEString reads chars * 2 bytes as UTF-16LE, trimming a trailing
// null character if present.
func (d *Decoder) ReadUTF16LEString(chars uint32) string {
	if chars == 0 {
		return ""
	}
	b := d.ReadBytes(int(chars) * 2)
	if b == nil {
		return ""
	}
	s := utf16le.DecodeToString(b)
	// Trim trailing NULs. NDR usually includes the null terminator in the
	// serialized length, so callers see it as a stray empty codepoint.
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}
