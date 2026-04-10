// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package nspi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// STAT structure (2.3.7)
type STAT struct {
	SortType       uint32
	ContainerID    uint32
	CurrentRec     uint32
	Delta          int32
	NumPos         uint32
	TotalRecs      uint32
	CodePage       uint32
	TemplateLocale uint32
	SortLocale     uint32
}

// Marshal serializes the STAT structure
func (s *STAT) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, s.SortType)
	binary.Write(buf, binary.LittleEndian, s.ContainerID)
	binary.Write(buf, binary.LittleEndian, s.CurrentRec)
	binary.Write(buf, binary.LittleEndian, s.Delta)
	binary.Write(buf, binary.LittleEndian, s.NumPos)
	binary.Write(buf, binary.LittleEndian, s.TotalRecs)
	binary.Write(buf, binary.LittleEndian, s.CodePage)
	binary.Write(buf, binary.LittleEndian, s.TemplateLocale)
	binary.Write(buf, binary.LittleEndian, s.SortLocale)
	return buf.Bytes()
}

// Unmarshal deserializes the STAT structure
func (s *STAT) Unmarshal(data []byte) error {
	if len(data) < 36 {
		return fmt.Errorf("data too short for STAT")
	}
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &s.SortType)
	binary.Read(r, binary.LittleEndian, &s.ContainerID)
	binary.Read(r, binary.LittleEndian, &s.CurrentRec)
	binary.Read(r, binary.LittleEndian, &s.Delta)
	binary.Read(r, binary.LittleEndian, &s.NumPos)
	binary.Read(r, binary.LittleEndian, &s.TotalRecs)
	binary.Read(r, binary.LittleEndian, &s.CodePage)
	binary.Read(r, binary.LittleEndian, &s.TemplateLocale)
	binary.Read(r, binary.LittleEndian, &s.SortLocale)
	return nil
}

// NewSTAT creates a default STAT structure
func NewSTAT() *STAT {
	return &STAT{
		SortType:       SortTypeDisplayName,
		ContainerID:    0,
		CurrentRec:     MID_BEGINNING_OF_TABLE,
		Delta:          0,
		NumPos:         0,
		TotalRecs:      0,
		CodePage:       CP_TELETEX,
		TemplateLocale: NSPI_DEFAULT_LOCALE,
		SortLocale:     NSPI_DEFAULT_LOCALE,
	}
}

// ContextHandle represents an NSPI context handle
type ContextHandle struct {
	Attributes uint32
	UUID       [16]byte
}

// Marshal serializes the context handle
func (h *ContextHandle) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, h.Attributes)
	buf.Write(h.UUID[:])
	return buf.Bytes()
}

// Unmarshal deserializes the context handle
func (h *ContextHandle) Unmarshal(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("data too short for ContextHandle")
	}
	h.Attributes = binary.LittleEndian.Uint32(data[:4])
	copy(h.UUID[:], data[4:20])
	return nil
}

// IsNull checks if the context handle is null
func (h *ContextHandle) IsNull() bool {
	for _, b := range h.UUID {
		if b != 0 {
			return false
		}
	}
	return true
}

// PropertyTag represents a MAPI property tag
type PropertyTag uint32

// ID returns the property ID (upper 16 bits)
func (p PropertyTag) ID() uint16 {
	return uint16(p >> 16)
}

// Type returns the property type (lower 16 bits)
func (p PropertyTag) Type() uint16 {
	return uint16(p & 0xFFFF)
}

// PropertyTagArray represents an array of property tags
type PropertyTagArray struct {
	Values []PropertyTag
}

// Marshal serializes the property tag array
func (a *PropertyTagArray) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(a.Values)))
	for _, v := range a.Values {
		binary.Write(buf, binary.LittleEndian, uint32(v))
	}
	return buf.Bytes()
}

// MarshalNDR serializes the property tag array in NDR format.
// The IDL defines: [size_is(cValues+1)] DWORD aulPropTag[]
// This is a conformant-varying array. Wire format:
//
//	MaxCount(4) = cValues+1, cValues(4), Offset(4) = 0, ActualCount(4) = cValues, elements
func (a *PropertyTagArray) MarshalNDR() []byte {
	buf := new(bytes.Buffer)

	count := uint32(len(a.Values))
	binary.Write(buf, binary.LittleEndian, count+1)   // MaxCount = cValues + 1
	binary.Write(buf, binary.LittleEndian, count)     // cValues
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset (conformant-varying)
	binary.Write(buf, binary.LittleEndian, count)     // ActualCount

	for _, v := range a.Values {
		binary.Write(buf, binary.LittleEndian, uint32(v))
	}

	return buf.Bytes()
}

// PropertyValue represents a MAPI property value
type PropertyValue struct {
	Tag   PropertyTag
	Value interface{} // Can be int16, int32, int64, string, []byte, etc.
}

// PropertyRow represents a row of property values
type PropertyRow struct {
	Reserved uint32
	Values   []PropertyValue
}

// PropertyRowSet represents a set of property rows
type PropertyRowSet struct {
	Rows []PropertyRow
}

// BinaryObject wraps binary data for proper display
type BinaryObject []byte

// String returns hex representation
func (b BinaryObject) String() string {
	return fmt.Sprintf("%x", []byte(b))
}

// ndrReader wraps a byte slice with offset tracking for NDR parsing
type ndrReader struct {
	data   []byte
	offset int
}

func newNDRReader(data []byte) *ndrReader {
	return &ndrReader{data: data, offset: 0}
}

func (r *ndrReader) remaining() int {
	return len(r.data) - r.offset
}

func (r *ndrReader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("not enough data for uint16 at offset %d", r.offset)
	}
	v := binary.LittleEndian.Uint16(r.data[r.offset:])
	r.offset += 2
	return v, nil
}

func (r *ndrReader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("not enough data for uint32 at offset %d", r.offset)
	}
	v := binary.LittleEndian.Uint32(r.data[r.offset:])
	r.offset += 4
	return v, nil
}

func (r *ndrReader) readInt32() (int32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("not enough data for int32 at offset %d", r.offset)
	}
	v := int32(binary.LittleEndian.Uint32(r.data[r.offset:]))
	r.offset += 4
	return v, nil
}

func (r *ndrReader) readUint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("not enough data for uint64 at offset %d", r.offset)
	}
	v := binary.LittleEndian.Uint64(r.data[r.offset:])
	r.offset += 8
	return v, nil
}

func (r *ndrReader) readBytes(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, fmt.Errorf("not enough data for %d bytes at offset %d", n, r.offset)
	}
	v := make([]byte, n)
	copy(v, r.data[r.offset:r.offset+n])
	r.offset += n
	return v, nil
}

func (r *ndrReader) align(n int) {
	if r.offset%n != 0 {
		r.offset += n - (r.offset % n)
	}
}

func (r *ndrReader) skip(n int) error {
	if r.remaining() < n {
		return fmt.Errorf("not enough data to skip %d bytes at offset %d", n, r.offset)
	}
	r.offset += n
	return nil
}

// readNDRConformantVaryingString reads an NDR conformant-varying Unicode string
func (r *ndrReader) readNDRConformantVaryingString() (string, error) {
	r.align(4)
	// MaxCount
	maxCount, err := r.readUint32()
	if err != nil {
		return "", err
	}
	_ = maxCount
	// Offset
	offset, err := r.readUint32()
	if err != nil {
		return "", err
	}
	_ = offset
	// ActualCount
	actualCount, err := r.readUint32()
	if err != nil {
		return "", err
	}
	if actualCount == 0 {
		return "", nil
	}
	// Read UTF-16LE chars
	byteLen := int(actualCount) * 2
	strData, err := r.readBytes(byteLen)
	if err != nil {
		return "", err
	}
	r.align(4)
	s := utf16ToString(strData)
	// Strip trailing null
	s = strings.TrimRight(s, "\x00")
	return s, nil
}

// readNDRConformantVaryingStringA reads an NDR conformant-varying ANSI string
func (r *ndrReader) readNDRConformantVaryingStringA() (string, error) {
	r.align(4)
	maxCount, err := r.readUint32()
	if err != nil {
		return "", err
	}
	_ = maxCount
	offset, err := r.readUint32()
	if err != nil {
		return "", err
	}
	_ = offset
	actualCount, err := r.readUint32()
	if err != nil {
		return "", err
	}
	if actualCount == 0 {
		return "", nil
	}
	strData, err := r.readBytes(int(actualCount))
	if err != nil {
		return "", err
	}
	r.align(4)
	s := string(strData)
	s = strings.TrimRight(s, "\x00")
	return s, nil
}

// readBinary_r reads an NDR Binary_r structure (cb + pointer to data)
func (r *ndrReader) readBinary_r() ([]byte, error) {
	r.align(4)
	cb, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	ptr, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = ptr
	_ = cb
	// Actual data will be read from deferred pointer data
	// Return placeholder - caller must handle deferral
	return nil, nil
}

// readBinaryData reads deferred binary data (conformant array of bytes)
func (r *ndrReader) readBinaryData() ([]byte, error) {
	r.align(4)
	// MaxCount
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if maxCount == 0 {
		return []byte{}, nil
	}
	data, err := r.readBytes(int(maxCount))
	if err != nil {
		return nil, err
	}
	r.align(4)
	return data, nil
}

// propValArmWireSize returns the NDR wire size of the PROP_VAL_UNION arm payload
// (excluding the 4-byte union discriminant tag) for a given property type.
// 2-byte arms are followed by 2 bytes of alignment padding (handled by align(4) after read).
func propValArmWireSize(propType uint16) int {
	switch propType {
	case PtypInteger16, PtypBoolean:
		return 2 // short/ushort, followed by 2 bytes padding
	case PtypBinary,
		PtypTime,
		PtypInteger64,
		PtypCurrency,
		PtypFloating64,
		PtypFloatingTime,
		PtypMultipleInt16,
		PtypMultipleInt32,
		PtypMultipleStr8,
		PtypMultipleStr,
		PtypMultipleTime,
		PtypMultipleGuid,
		PtypMultipleBin:
		return 8 // Binary_r, FILETIME, LONGLONG, or count+pointer structs
	default:
		// PtypInteger32, PtypErrorCode, PtypNull, PtypEmbeddedTable,
		// PtypString (LPWSTR pointer), PtypString8 (LPSTR pointer),
		// PtypGuid (FlatUID_r pointer), PtypFloating32, PtypUnspecified
		return 4
	}
}

// ParsePropertyRowSet parses a PropertyRowSet_r from NDR response data.
// The NDR format is:
//   - Pointer referent for ppRows (4 bytes)
//   - cRows (4 bytes)
//   - Conformant array max count (4 bytes)
//   - For each row: Reserved(4), cValues(4), lpProps pointer ref(4)
//   - Deferred: for each row's lpProps: conformant array of PropertyValue_r
//   - Each PropertyValue_r: ulPropTag(4), dwAlignPad(4), union value (8 bytes)
//   - Further deferred data for strings, binary, etc.
func ParsePropertyRowSet(data []byte, propTags []PropertyTag) (*PropertyRowSet, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short for PropertyRowSet")
	}

	r := newNDRReader(data)
	result := &PropertyRowSet{}

	// PropertyRowSet_r is a conformant structure with conformant array aRow.
	// NDR wire format: MaxCount(4) + cRows(4) + PropertyRow_r[cRows]
	// NOTE: The pointer referent for ppRows should already be handled by the caller.

	// Conformant array MaxCount
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}

	// cRows
	cRows, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if cRows == 0 {
		return result, nil
	}
	_ = maxCount

	// Phase 1: Read fixed-size row headers
	type rowHeader struct {
		reserved   uint32
		cValues    uint32
		lpPropsPtr uint32
	}
	headers := make([]rowHeader, cRows)
	for i := uint32(0); i < cRows; i++ {
		h := rowHeader{}
		h.reserved, err = r.readUint32()
		if err != nil {
			return nil, fmt.Errorf("row %d header: %v", i, err)
		}
		h.cValues, err = r.readUint32()
		if err != nil {
			return nil, fmt.Errorf("row %d cValues: %v", i, err)
		}
		h.lpPropsPtr, err = r.readUint32()
		if err != nil {
			return nil, fmt.Errorf("row %d lpProps ptr: %v", i, err)
		}
		headers[i] = h
	}

	// Phase 2: For each row with non-null lpProps, read the PropertyValue_r array
	for i := uint32(0); i < cRows; i++ {
		row := PropertyRow{Reserved: headers[i].reserved}

		if headers[i].lpPropsPtr == 0 {
			result.Rows = append(result.Rows, row)
			continue
		}

		// Conformant array MaxCount for lpProps
		propMaxCount, err := r.readUint32()
		if err != nil {
			return nil, fmt.Errorf("row %d props maxcount: %v", i, err)
		}
		_ = propMaxCount

		// Read each PropertyValue_r inline part.
		// NDR wire format per PropertyValue_r:
		//   ulPropTag(4) + dwAlignPad(4) + PROP_VAL_UNION
		// PROP_VAL_UNION = discriminant_tag(4) + arm_payload(variable)
		// Arm payload sizes: 2 bytes (short/boolean), 4 bytes (long/pointer),
		// or 8 bytes (Binary_r, FILETIME, multi-value structs).
		type propFixed struct {
			tag      uint32
			alignPad uint32
			// Arm payload data (up to 8 bytes)
			unionData [8]byte
		}

		numProps := headers[i].cValues
		fixedProps := make([]propFixed, numProps)

		for j := uint32(0); j < numProps; j++ {
			pf := propFixed{}

			// ulPropTag (4 bytes)
			pf.tag, err = r.readUint32()
			if err != nil {
				return nil, fmt.Errorf("row %d prop %d tag: %v", i, j, err)
			}

			// dwAlignPad (4 bytes)
			pf.alignPad, err = r.readUint32()
			if err != nil {
				return nil, fmt.Errorf("row %d prop %d alignpad: %v", i, j, err)
			}

			// PROP_VAL_UNION discriminant tag (4 bytes) - skip
			_, err = r.readUint32()
			if err != nil {
				return nil, fmt.Errorf("row %d prop %d union tag: %v", i, j, err)
			}

			// Read arm payload - size depends on property type
			propType := PropertyTag(pf.tag).Type()
			armSize := propValArmWireSize(propType)
			ud, err := r.readBytes(armSize)
			if err != nil {
				return nil, fmt.Errorf("row %d prop %d union arm (%d bytes): %v", i, j, armSize, err)
			}
			copy(pf.unionData[:], ud)

			// Align to 4 bytes (handles 2-byte arm padding)
			r.align(4)

			fixedProps[j] = pf
		}

		// Phase 3: Read deferred pointer data for each property
		for j := uint32(0); j < numProps; j++ {
			pf := fixedProps[j]
			tag := PropertyTag(pf.tag)
			pv := PropertyValue{Tag: tag}

			propType := tag.Type()

			switch propType {
			case PtypInteger16:
				pv.Value = int32(int16(binary.LittleEndian.Uint16(pf.unionData[:])))
			case PtypInteger32, PtypErrorCode:
				pv.Value = int32(binary.LittleEndian.Uint32(pf.unionData[:]))
			case PtypBoolean:
				pv.Value = binary.LittleEndian.Uint16(pf.unionData[:]) != 0
			case PtypInteger64:
				pv.Value = int64(binary.LittleEndian.Uint64(pf.unionData[:]))
			case PtypTime:
				pv.Value = binary.LittleEndian.Uint64(pf.unionData[:])
			case PtypString:
				// LPWSTR - pointer referent in union, deferred string data
				ptr := binary.LittleEndian.Uint32(pf.unionData[:])
				if ptr != 0 {
					s, err := r.readNDRConformantVaryingString()
					if err != nil {
						pv.Value = ""
					} else {
						pv.Value = s
					}
				} else {
					pv.Value = ""
				}
			case PtypString8:
				// LPSTR - pointer referent in union, deferred string data
				ptr := binary.LittleEndian.Uint32(pf.unionData[:])
				if ptr != 0 {
					s, err := r.readNDRConformantVaryingStringA()
					if err != nil {
						pv.Value = ""
					} else {
						pv.Value = s
					}
				} else {
					pv.Value = ""
				}
			case PtypBinary:
				// Binary_r in union: cb(4) + pointer(4)
				cb := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && cb > 0 {
					binData, err := r.readBinaryData()
					if err != nil {
						pv.Value = BinaryObject(nil)
					} else {
						pv.Value = BinaryObject(binData)
					}
				} else {
					pv.Value = BinaryObject(nil)
				}
			case PtypGuid:
				// FlatUID_r pointer in union
				ptr := binary.LittleEndian.Uint32(pf.unionData[:])
				if ptr != 0 {
					guidData, err := r.readBytes(16)
					if err != nil {
						pv.Value = BinaryObject(nil)
					} else {
						pv.Value = BinaryObject(guidData)
					}
				} else {
					pv.Value = BinaryObject(nil)
				}
			case PtypMultipleStr:
				// WStringArray_r: cValues(4) + pointer to array of LPWSTR
				mvCount := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && mvCount > 0 {
					strs, err := readMVStringW(r, mvCount)
					if err != nil {
						pv.Value = []string{}
					} else {
						pv.Value = strs
					}
				} else {
					pv.Value = []string{}
				}
			case PtypMultipleStr8:
				// StringArray_r: cValues(4) + pointer to array of LPSTR
				mvCount := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && mvCount > 0 {
					strs, err := readMVStringA(r, mvCount)
					if err != nil {
						pv.Value = []string{}
					} else {
						pv.Value = strs
					}
				} else {
					pv.Value = []string{}
				}
			case PtypMultipleBin:
				// BinaryArray_r: cValues(4) + pointer to array of Binary_r
				mvCount := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && mvCount > 0 {
					bins, err := readMVBinary(r, mvCount)
					if err != nil {
						pv.Value = []BinaryObject{}
					} else {
						pv.Value = bins
					}
				} else {
					pv.Value = []BinaryObject{}
				}
			case PtypMultipleInt32:
				// LongArray_r: cValues(4) + pointer to array of LONG
				mvCount := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && mvCount > 0 {
					vals, err := readMVLong(r, mvCount)
					if err != nil {
						pv.Value = []int32{}
					} else {
						pv.Value = vals
					}
				} else {
					pv.Value = []int32{}
				}
			case PtypMultipleTime:
				// DateTimeArray_r: cValues(4) + pointer to array of FILETIME
				mvCount := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && mvCount > 0 {
					vals, err := readMVTime(r, mvCount)
					if err != nil {
						pv.Value = []uint64{}
					} else {
						pv.Value = vals
					}
				} else {
					pv.Value = []uint64{}
				}
			case PtypMultipleGuid:
				// FlatUIDArray_r: cValues(4) + pointer to array of FlatUID_r
				mvCount := binary.LittleEndian.Uint32(pf.unionData[:4])
				ptr := binary.LittleEndian.Uint32(pf.unionData[4:])
				if ptr != 0 && mvCount > 0 {
					vals, err := readMVGuid(r, mvCount)
					if err != nil {
						pv.Value = []BinaryObject{}
					} else {
						pv.Value = vals
					}
				} else {
					pv.Value = []BinaryObject{}
				}
			default:
				// PtypNull, PtypEmbeddedTable, PtypUnspecified - store as int32
				pv.Value = int32(binary.LittleEndian.Uint32(pf.unionData[:]))
			}

			row.Values = append(row.Values, pv)
		}

		result.Rows = append(result.Rows, row)
	}

	return result, nil
}

// readMVStringW reads a multi-valued Unicode string array from NDR
func readMVStringW(r *ndrReader, count uint32) ([]string, error) {
	r.align(4)
	// Conformant array of pointers
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = maxCount

	// Read pointer referents
	ptrs := make([]uint32, count)
	for i := uint32(0); i < count; i++ {
		ptrs[i], err = r.readUint32()
		if err != nil {
			return nil, err
		}
	}

	// Read deferred strings
	result := make([]string, count)
	for i := uint32(0); i < count; i++ {
		if ptrs[i] != 0 {
			s, err := r.readNDRConformantVaryingString()
			if err != nil {
				return nil, err
			}
			result[i] = s
		}
	}
	return result, nil
}

// readMVStringA reads a multi-valued ANSI string array from NDR
func readMVStringA(r *ndrReader, count uint32) ([]string, error) {
	r.align(4)
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = maxCount

	ptrs := make([]uint32, count)
	for i := uint32(0); i < count; i++ {
		ptrs[i], err = r.readUint32()
		if err != nil {
			return nil, err
		}
	}

	result := make([]string, count)
	for i := uint32(0); i < count; i++ {
		if ptrs[i] != 0 {
			s, err := r.readNDRConformantVaryingStringA()
			if err != nil {
				return nil, err
			}
			result[i] = s
		}
	}
	return result, nil
}

// readMVBinary reads a multi-valued binary array from NDR
func readMVBinary(r *ndrReader, count uint32) ([]BinaryObject, error) {
	r.align(4)
	// Conformant array of Binary_r
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = maxCount

	// Each Binary_r: cb(4) + pointer(4)
	type binEntry struct {
		cb  uint32
		ptr uint32
	}
	entries := make([]binEntry, count)
	for i := uint32(0); i < count; i++ {
		entries[i].cb, err = r.readUint32()
		if err != nil {
			return nil, err
		}
		entries[i].ptr, err = r.readUint32()
		if err != nil {
			return nil, err
		}
	}

	// Read deferred binary data
	result := make([]BinaryObject, count)
	for i := uint32(0); i < count; i++ {
		if entries[i].ptr != 0 && entries[i].cb > 0 {
			data, err := r.readBinaryData()
			if err != nil {
				return nil, err
			}
			result[i] = BinaryObject(data)
		}
	}
	return result, nil
}

// readMVLong reads a multi-valued LONG array from NDR
func readMVLong(r *ndrReader, count uint32) ([]int32, error) {
	r.align(4)
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = maxCount

	result := make([]int32, count)
	for i := uint32(0); i < count; i++ {
		result[i], err = r.readInt32()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// readMVTime reads a multi-valued FILETIME array from NDR
func readMVTime(r *ndrReader, count uint32) ([]uint64, error) {
	r.align(4)
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = maxCount

	result := make([]uint64, count)
	for i := uint32(0); i < count; i++ {
		result[i], err = r.readUint64()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// readMVGuid reads a multi-valued GUID array from NDR
func readMVGuid(r *ndrReader, count uint32) ([]BinaryObject, error) {
	r.align(4)
	maxCount, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_ = maxCount

	// Array of FlatUID_r pointers
	ptrs := make([]uint32, count)
	var err2 error
	for i := uint32(0); i < count; i++ {
		ptrs[i], err2 = r.readUint32()
		if err2 != nil {
			return nil, err2
		}
	}

	result := make([]BinaryObject, count)
	for i := uint32(0); i < count; i++ {
		if ptrs[i] != 0 {
			data, err := r.readBytes(16)
			if err != nil {
				return nil, err
			}
			result[i] = BinaryObject(data)
		}
	}
	return result, nil
}

// utf16ToString converts UTF-16LE bytes to string
func utf16ToString(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	u16s := make([]uint16, len(data)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(u16s))
}

// stringToUTF16 converts string to UTF-16LE bytes
func stringToUTF16(s string) []byte {
	u16s := utf16.Encode([]rune(s))
	result := make([]byte, len(u16s)*2)
	for i, u := range u16s {
		binary.LittleEndian.PutUint16(result[i*2:], u)
	}
	return result
}

// FormatSID converts a binary SID to string format S-1-5-21-...
func FormatSID(data []byte) string {
	if len(data) < 8 {
		return fmt.Sprintf("0x%x", data)
	}
	revision := data[0]
	subAuthCount := int(data[1])
	authority := uint64(0)
	for i := 0; i < 6; i++ {
		authority = (authority << 8) | uint64(data[2+i])
	}

	if len(data) < 8+subAuthCount*4 {
		return fmt.Sprintf("0x%x", data)
	}

	parts := []string{fmt.Sprintf("S-%d-%d", revision, authority)}
	for i := 0; i < subAuthCount; i++ {
		offset := 8 + i*4
		subAuth := binary.LittleEndian.Uint32(data[offset:])
		parts = append(parts, fmt.Sprintf("%d", subAuth))
	}
	return strings.Join(parts, "-")
}

// FormatFileTime converts a Windows FILETIME (100-nanosecond intervals since
// January 1, 1601) to a human-readable string in local time (matching Impacket)
func FormatFileTime(ft uint64) string {
	if ft == 0 {
		return "Never"
	}
	// Windows epoch is January 1, 1601. Unix epoch is January 1, 1970.
	// Difference in 100-nanosecond intervals: 116444736000000000
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return fmt.Sprintf("0x%016x", ft)
	}
	unixSec := (int64(ft) - epochDiff) / 10000000
	t := time.Unix(unixSec, 0)
	return t.Format("2006-01-02 15:04:05")
}

// FormatGUID formats 16 bytes as a GUID string (little-endian fields)
func FormatGUID(data []byte) string {
	if len(data) != 16 {
		return fmt.Sprintf("0x%x", data)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(data[0:4]),
		binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]),
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

// AddressBookEntry represents a parsed address book entry
type AddressBookEntry struct {
	MId        int32
	Name       string
	GUID       []byte
	Flags      uint32
	Depth      uint32
	IsMaster   bool
	ParentGUID []byte
	Count      uint32
	StartMId   uint32
	Printed    bool
	Properties map[PropertyTag]interface{}
}

// SimplifyPropertyRow converts a PropertyRow to a map for easier access
func SimplifyPropertyRow(row *PropertyRow) map[PropertyTag]interface{} {
	result := make(map[PropertyTag]interface{})
	for _, pv := range row.Values {
		result[pv.Tag] = pv.Value
	}
	return result
}
