package registry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	regfMagic = 0x66676572 // "regf"
	hbinMagic = 0x6e696268 // "hbin"
	nkSig     = 0x6b6e     // "nk"
	vkSig     = 0x6b76     // "vk"
	lfSig     = 0x666c     // "lf"
	lhSig     = 0x686c     // "lh"
	liSig     = 0x696c     // "li"
	riSig     = 0x6972     // "ri"
	skSig     = 0x6b73     // "sk"
)

// NK flags
const (
	KEY_HIVE_ENTRY = 0x0004
	KEY_NO_DELETE  = 0x0008
	KEY_SYM_LINK   = 0x0010
	KEY_COMP_NAME  = 0x0020
)

// Hive represents a parsed registry hive
type Hive struct {
	data       []byte
	rootOffset int32
}

// Open parses a registry hive from bytes
func Open(data []byte) (*Hive, error) {
	if len(data) < 4096 {
		return nil, fmt.Errorf("hive too small: %d bytes", len(data))
	}

	// Verify magic
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != regfMagic {
		return nil, fmt.Errorf("invalid hive magic: 0x%08x", magic)
	}

	// Root cell offset is at offset 36
	rootOffset := int32(binary.LittleEndian.Uint32(data[36:40]))

	return &Hive{
		data:       data,
		rootOffset: rootOffset,
	}, nil
}

// cellOffset converts a cell offset to actual data offset
// Cell offsets are relative to the first hbin (offset 4096)
func (h *Hive) cellOffset(offset int32) int {
	return int(offset) + 4096
}

// readCell reads a cell at the given offset and returns its data
func (h *Hive) readCell(offset int32) ([]byte, error) {
	pos := h.cellOffset(offset)
	if pos < 4096 || pos >= len(h.data)-4 {
		return nil, fmt.Errorf("invalid cell offset: %d", offset)
	}

	// Cell size is first 4 bytes (negative = allocated, positive = free)
	size := int32(binary.LittleEndian.Uint32(h.data[pos : pos+4]))
	if size > 0 {
		return nil, fmt.Errorf("cell is free at offset %d", offset)
	}
	size = -size

	if pos+int(size) > len(h.data) {
		return nil, fmt.Errorf("cell extends beyond hive: %d + %d > %d", pos, size, len(h.data))
	}

	return h.data[pos+4 : pos+int(size)], nil
}

// NKRecord represents a key node
type NKRecord struct {
	Signature       uint16
	Flags           uint16
	LastModified    uint64
	Access          uint32
	ParentOffset    int32
	SubKeyCount     uint32
	SubKeyCountVol  uint32
	SubKeyListOffset int32
	SubKeyListOffsetVol int32
	ValueCount      uint32
	ValueListOffset int32
	SecurityOffset  int32
	ClassOffset     int32
	MaxSubKeyNameLen uint32
	MaxSubKeyClassLen uint32
	MaxValueNameLen uint32
	MaxValueDataLen uint32
	WorkVar         uint32
	NameLen         uint16
	ClassLen        uint16
	Name            string
}

// parseNK parses an NK (key node) record
func (h *Hive) parseNK(offset int32) (*NKRecord, error) {
	cell, err := h.readCell(offset)
	if err != nil {
		return nil, err
	}

	if len(cell) < 76 {
		return nil, fmt.Errorf("NK cell too small: %d", len(cell))
	}

	nk := &NKRecord{}
	r := bytes.NewReader(cell)

	binary.Read(r, binary.LittleEndian, &nk.Signature)
	if nk.Signature != nkSig {
		return nil, fmt.Errorf("invalid NK signature: 0x%04x", nk.Signature)
	}

	binary.Read(r, binary.LittleEndian, &nk.Flags)
	binary.Read(r, binary.LittleEndian, &nk.LastModified)
	binary.Read(r, binary.LittleEndian, &nk.Access)
	binary.Read(r, binary.LittleEndian, &nk.ParentOffset)
	binary.Read(r, binary.LittleEndian, &nk.SubKeyCount)
	binary.Read(r, binary.LittleEndian, &nk.SubKeyCountVol)
	binary.Read(r, binary.LittleEndian, &nk.SubKeyListOffset)
	binary.Read(r, binary.LittleEndian, &nk.SubKeyListOffsetVol)
	binary.Read(r, binary.LittleEndian, &nk.ValueCount)
	binary.Read(r, binary.LittleEndian, &nk.ValueListOffset)
	binary.Read(r, binary.LittleEndian, &nk.SecurityOffset)
	binary.Read(r, binary.LittleEndian, &nk.ClassOffset)
	binary.Read(r, binary.LittleEndian, &nk.MaxSubKeyNameLen)
	binary.Read(r, binary.LittleEndian, &nk.MaxSubKeyClassLen)
	binary.Read(r, binary.LittleEndian, &nk.MaxValueNameLen)
	binary.Read(r, binary.LittleEndian, &nk.MaxValueDataLen)
	binary.Read(r, binary.LittleEndian, &nk.WorkVar)
	binary.Read(r, binary.LittleEndian, &nk.NameLen)
	binary.Read(r, binary.LittleEndian, &nk.ClassLen)

	// Read name
	if nk.NameLen > 0 {
		nameBytes := make([]byte, nk.NameLen)
		r.Read(nameBytes)

		if nk.Flags&KEY_COMP_NAME != 0 {
			// ASCII name
			nk.Name = string(nameBytes)
		} else {
			// UTF-16LE name
			chars := make([]uint16, nk.NameLen/2)
			for i := 0; i < len(chars); i++ {
				chars[i] = binary.LittleEndian.Uint16(nameBytes[i*2:])
			}
			nk.Name = string(utf16.Decode(chars))
		}
	}

	return nk, nil
}

// VKRecord represents a value node
type VKRecord struct {
	Signature  uint16
	NameLen    uint16
	DataLen    uint32
	DataOffset uint32
	DataType   uint32
	Flags      uint16
	Spare      uint16
	Name       string
}

// parseVK parses a VK (value node) record
func (h *Hive) parseVK(offset int32) (*VKRecord, error) {
	cell, err := h.readCell(offset)
	if err != nil {
		return nil, err
	}

	if len(cell) < 20 {
		return nil, fmt.Errorf("VK cell too small: %d", len(cell))
	}

	vk := &VKRecord{}
	r := bytes.NewReader(cell)

	binary.Read(r, binary.LittleEndian, &vk.Signature)
	if vk.Signature != vkSig {
		return nil, fmt.Errorf("invalid VK signature: 0x%04x", vk.Signature)
	}

	binary.Read(r, binary.LittleEndian, &vk.NameLen)
	binary.Read(r, binary.LittleEndian, &vk.DataLen)
	binary.Read(r, binary.LittleEndian, &vk.DataOffset)
	binary.Read(r, binary.LittleEndian, &vk.DataType)
	binary.Read(r, binary.LittleEndian, &vk.Flags)
	binary.Read(r, binary.LittleEndian, &vk.Spare)

	// Read name
	if vk.NameLen > 0 {
		nameBytes := make([]byte, vk.NameLen)
		r.Read(nameBytes)

		if vk.Flags&0x0001 != 0 {
			// ASCII name
			vk.Name = string(nameBytes)
		} else {
			// UTF-16LE name
			chars := make([]uint16, vk.NameLen/2)
			for i := 0; i < len(chars); i++ {
				chars[i] = binary.LittleEndian.Uint16(nameBytes[i*2:])
			}
			vk.Name = string(utf16.Decode(chars))
		}
	}

	return vk, nil
}

// GetValueData retrieves the data for a value record
func (h *Hive) GetValueData(vk *VKRecord) ([]byte, error) {
	dataLen := vk.DataLen & 0x7FFFFFFF
	isResident := vk.DataLen&0x80000000 != 0

	if isResident {
		// Data is stored in the DataOffset field itself (up to 4 bytes)
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, vk.DataOffset)
		return data[:dataLen], nil
	}

	// Data is in a separate cell
	cell, err := h.readCell(int32(vk.DataOffset))
	if err != nil {
		return nil, err
	}

	if int(dataLen) > len(cell) {
		dataLen = uint32(len(cell))
	}

	return cell[:dataLen], nil
}

// FindKey locates a subkey by path (e.g., "SAM\\Domains\\Account")
func (h *Hive) FindKey(path string) (int32, error) {
	parts := strings.Split(path, "\\")

	currentOffset := h.rootOffset

	for _, part := range parts {
		if part == "" {
			continue
		}

		nk, err := h.parseNK(currentOffset)
		if err != nil {
			return 0, fmt.Errorf("failed to parse key: %v", err)
		}

		found := false
		subKeys, err := h.enumSubKeys(nk)
		if err != nil {
			return 0, fmt.Errorf("failed to enum subkeys: %v", err)
		}

		for _, sk := range subKeys {
			if strings.EqualFold(sk.name, part) {
				currentOffset = sk.offset
				found = true
				break
			}
		}

		if !found {
			return 0, fmt.Errorf("key not found: %s", part)
		}
	}

	return currentOffset, nil
}

type subKeyInfo struct {
	name   string
	offset int32
}

// enumSubKeys enumerates subkeys of a key
func (h *Hive) enumSubKeys(nk *NKRecord) ([]subKeyInfo, error) {
	if nk.SubKeyCount == 0 || nk.SubKeyListOffset == -1 {
		return nil, nil
	}

	cell, err := h.readCell(nk.SubKeyListOffset)
	if err != nil {
		return nil, err
	}

	if len(cell) < 4 {
		return nil, fmt.Errorf("subkey list too small")
	}

	sig := binary.LittleEndian.Uint16(cell[0:2])
	count := binary.LittleEndian.Uint16(cell[2:4])

	var subKeys []subKeyInfo

	switch sig {
	case lfSig, lhSig:
		// LF/LH list: entries are [offset, hash] pairs
		for i := uint16(0); i < count; i++ {
			entryOff := 4 + int(i)*8
			if entryOff+4 > len(cell) {
				break
			}
			offset := int32(binary.LittleEndian.Uint32(cell[entryOff : entryOff+4]))

			subNK, err := h.parseNK(offset)
			if err != nil {
				continue
			}
			subKeys = append(subKeys, subKeyInfo{name: subNK.Name, offset: offset})
		}

	case liSig:
		// LI list: entries are just offsets
		for i := uint16(0); i < count; i++ {
			entryOff := 4 + int(i)*4
			if entryOff+4 > len(cell) {
				break
			}
			offset := int32(binary.LittleEndian.Uint32(cell[entryOff : entryOff+4]))

			subNK, err := h.parseNK(offset)
			if err != nil {
				continue
			}
			subKeys = append(subKeys, subKeyInfo{name: subNK.Name, offset: offset})
		}

	case riSig:
		// RI list: entries are offsets to sub-lists
		for i := uint16(0); i < count; i++ {
			entryOff := 4 + int(i)*4
			if entryOff+4 > len(cell) {
				break
			}
			subListOffset := int32(binary.LittleEndian.Uint32(cell[entryOff : entryOff+4]))

			// Recursively process sub-list
			subCell, err := h.readCell(subListOffset)
			if err != nil {
				continue
			}

			subSig := binary.LittleEndian.Uint16(subCell[0:2])
			subCount := binary.LittleEndian.Uint16(subCell[2:4])

			if subSig == lfSig || subSig == lhSig {
				for j := uint16(0); j < subCount; j++ {
					subEntryOff := 4 + int(j)*8
					if subEntryOff+4 > len(subCell) {
						break
					}
					offset := int32(binary.LittleEndian.Uint32(subCell[subEntryOff : subEntryOff+4]))

					subNK, err := h.parseNK(offset)
					if err != nil {
						continue
					}
					subKeys = append(subKeys, subKeyInfo{name: subNK.Name, offset: offset})
				}
			}
		}

	default:
		return nil, fmt.Errorf("unknown subkey list signature: 0x%04x", sig)
	}

	return subKeys, nil
}

// GetValue retrieves a value from a key
func (h *Hive) GetValue(keyOffset int32, valueName string) (uint32, []byte, error) {
	nk, err := h.parseNK(keyOffset)
	if err != nil {
		return 0, nil, err
	}

	if nk.ValueCount == 0 || nk.ValueListOffset == -1 {
		return 0, nil, fmt.Errorf("key has no values")
	}

	// Read value list
	cell, err := h.readCell(nk.ValueListOffset)
	if err != nil {
		return 0, nil, err
	}

	// Value list is an array of offsets
	for i := uint32(0); i < nk.ValueCount; i++ {
		if int(i*4+4) > len(cell) {
			break
		}
		vkOffset := int32(binary.LittleEndian.Uint32(cell[i*4 : i*4+4]))

		vk, err := h.parseVK(vkOffset)
		if err != nil {
			continue
		}

		// Check for default value (empty name)
		if valueName == "" && vk.NameLen == 0 {
			data, err := h.GetValueData(vk)
			return vk.DataType, data, err
		}

		if strings.EqualFold(vk.Name, valueName) {
			data, err := h.GetValueData(vk)
			return vk.DataType, data, err
		}
	}

	return 0, nil, fmt.Errorf("value not found: %s", valueName)
}

// GetClassName retrieves the class name of a key
func (h *Hive) GetClassName(keyOffset int32) (string, error) {
	nk, err := h.parseNK(keyOffset)
	if err != nil {
		return "", err
	}

	if nk.ClassOffset == -1 || nk.ClassLen == 0 {
		return "", nil
	}

	cell, err := h.readCell(nk.ClassOffset)
	if err != nil {
		return "", err
	}

	if int(nk.ClassLen) > len(cell) {
		return "", fmt.Errorf("class name extends beyond cell")
	}

	// Class name is UTF-16LE
	chars := make([]uint16, nk.ClassLen/2)
	for i := 0; i < len(chars); i++ {
		chars[i] = binary.LittleEndian.Uint16(cell[i*2:])
	}

	return string(utf16.Decode(chars)), nil
}

// FindSubKey locates a direct child subkey by name and returns its offset
func (h *Hive) FindSubKey(parentOffset int32, name string) (int32, error) {
	nk, err := h.parseNK(parentOffset)
	if err != nil {
		return 0, err
	}

	subKeys, err := h.enumSubKeys(nk)
	if err != nil {
		return 0, err
	}

	for _, sk := range subKeys {
		if strings.EqualFold(sk.name, name) {
			return sk.offset, nil
		}
	}

	return 0, fmt.Errorf("subkey not found: %s", name)
}

// GetClassNameRaw retrieves the raw class name bytes of a key without UTF-16 decoding
func (h *Hive) GetClassNameRaw(keyOffset int32) ([]byte, error) {
	nk, err := h.parseNK(keyOffset)
	if err != nil {
		return nil, err
	}

	if nk.ClassOffset == -1 || nk.ClassLen == 0 {
		return nil, nil
	}

	cell, err := h.readCell(nk.ClassOffset)
	if err != nil {
		return nil, err
	}

	return cell, nil
}

// EnumSubKeys lists subkey names of a key
func (h *Hive) EnumSubKeys(keyOffset int32) ([]string, error) {
	nk, err := h.parseNK(keyOffset)
	if err != nil {
		return nil, err
	}

	subKeys, err := h.enumSubKeys(nk)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(subKeys))
	for i, sk := range subKeys {
		names[i] = sk.name
	}

	return names, nil
}

// EnumValues lists value names of a key
func (h *Hive) EnumValues(keyOffset int32) ([]string, error) {
	nk, err := h.parseNK(keyOffset)
	if err != nil {
		return nil, err
	}

	if nk.ValueCount == 0 || nk.ValueListOffset == -1 {
		return nil, nil
	}

	cell, err := h.readCell(nk.ValueListOffset)
	if err != nil {
		return nil, err
	}

	var names []string
	for i := uint32(0); i < nk.ValueCount; i++ {
		if int(i*4+4) > len(cell) {
			break
		}
		vkOffset := int32(binary.LittleEndian.Uint32(cell[i*4 : i*4+4]))

		vk, err := h.parseVK(vkOffset)
		if err != nil {
			continue
		}

		names = append(names, vk.Name)
	}

	return names, nil
}

// RootOffset returns the root key offset
func (h *Hive) RootOffset() int32 {
	return h.rootOffset
}

// Data returns the raw hive bytes for saving
func (h *Hive) Data() []byte {
	return h.data
}

// SetValueData overwrites the data of a named value under the given key.
// The new data must be exactly the same length as the existing data.
func (h *Hive) SetValueData(keyOffset int32, valueName string, newData []byte) error {
	nk, err := h.parseNK(keyOffset)
	if err != nil {
		return err
	}

	if nk.ValueCount == 0 || nk.ValueListOffset == -1 {
		return fmt.Errorf("key has no values")
	}

	// Read value list
	cell, err := h.readCell(nk.ValueListOffset)
	if err != nil {
		return err
	}

	for i := uint32(0); i < nk.ValueCount; i++ {
		if int(i*4+4) > len(cell) {
			break
		}
		vkOffset := int32(binary.LittleEndian.Uint32(cell[i*4 : i*4+4]))

		vk, err := h.parseVK(vkOffset)
		if err != nil {
			continue
		}

		match := false
		if valueName == "" && vk.NameLen == 0 {
			match = true
		} else if strings.EqualFold(vk.Name, valueName) {
			match = true
		}

		if !match {
			continue
		}

		dataLen := vk.DataLen & 0x7FFFFFFF
		isResident := vk.DataLen&0x80000000 != 0

		if uint32(len(newData)) != dataLen {
			return fmt.Errorf("data length mismatch: existing %d, new %d", dataLen, len(newData))
		}

		if isResident {
			// Data stored inline in the VK record's DataOffset field
			// VK cell starts at cellOffset(vkOffset)+4 (skip cell size)
			// DataOffset is at bytes 8..12 of the VK record (after sig:2 + nameLen:2 + dataLen:4)
			vkPos := h.cellOffset(vkOffset) + 4 // skip cell size dword
			dataFieldPos := vkPos + 8            // offset of DataOffset field
			copy(h.data[dataFieldPos:dataFieldPos+int(dataLen)], newData)
			return nil
		}

		// Data is in a separate cell; overwrite in place
		dataPos := h.cellOffset(int32(vk.DataOffset)) + 4 // skip cell size
		copy(h.data[dataPos:dataPos+int(dataLen)], newData)
		return nil
	}

	return fmt.Errorf("value not found: %s", valueName)
}
