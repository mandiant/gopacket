package security

import (
	"encoding/binary"
	"fmt"
)

// ACE represents an Access Control Entry.
type ACE struct {
	Type                uint8
	Flags               uint8
	Mask                uint32
	ObjectFlags         uint32
	ObjectType          GUID
	InheritedObjectType GUID
	SID                 *SID
}

// IsObjectACE returns true if this is an object-type ACE.
func (a *ACE) IsObjectACE() bool {
	return a.Type == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
		a.Type == ACCESS_DENIED_OBJECT_ACE_TYPE ||
		a.Type == SYSTEM_AUDIT_OBJECT_ACE_TYPE
}

// ParseACE parses a single ACE from binary data, returning the ACE and bytes consumed.
func ParseACE(data []byte) (*ACE, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("ACE too short: need at least 8 bytes, got %d", len(data))
	}

	ace := &ACE{
		Type:  data[0],
		Flags: data[1],
	}
	aceSize := int(binary.LittleEndian.Uint16(data[2:4]))
	if len(data) < aceSize {
		return nil, 0, fmt.Errorf("ACE size %d exceeds available data %d", aceSize, len(data))
	}

	ace.Mask = binary.LittleEndian.Uint32(data[4:8])

	offset := 8
	if ace.IsObjectACE() {
		if len(data) < offset+4 {
			return nil, 0, fmt.Errorf("object ACE too short for ObjectFlags")
		}
		ace.ObjectFlags = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		if ace.ObjectFlags&ACE_OBJECT_TYPE_PRESENT != 0 {
			if len(data) < offset+16 {
				return nil, 0, fmt.Errorf("object ACE too short for ObjectType")
			}
			copy(ace.ObjectType[:], data[offset:offset+16])
			offset += 16
		}

		if ace.ObjectFlags&ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
			if len(data) < offset+16 {
				return nil, 0, fmt.Errorf("object ACE too short for InheritedObjectType")
			}
			copy(ace.InheritedObjectType[:], data[offset:offset+16])
			offset += 16
		}
	}

	// Parse SID from remaining data
	sid, _, err := ParseSIDBytes(data[offset:aceSize])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse ACE SID: %v", err)
	}
	ace.SID = sid

	return ace, aceSize, nil
}

// Marshal serializes the ACE to binary format.
func (a *ACE) Marshal() []byte {
	var body []byte

	// Mask (4 bytes)
	maskBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(maskBuf, a.Mask)
	body = append(body, maskBuf...)

	if a.IsObjectACE() {
		// Determine object flags based on content
		flags := uint32(0)
		if !a.ObjectType.IsZero() {
			flags |= ACE_OBJECT_TYPE_PRESENT
		}
		if !a.InheritedObjectType.IsZero() {
			flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT
		}

		flagsBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(flagsBuf, flags)
		body = append(body, flagsBuf...)

		if flags&ACE_OBJECT_TYPE_PRESENT != 0 {
			body = append(body, a.ObjectType[:]...)
		}
		if flags&ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
			body = append(body, a.InheritedObjectType[:]...)
		}
	}

	// SID
	body = append(body, a.SID.Marshal()...)

	// Build header: Type(1) + Flags(1) + Size(2)
	aceSize := 4 + len(body) // 4 bytes header + body
	header := make([]byte, 4)
	header[0] = a.Type
	header[1] = a.Flags
	binary.LittleEndian.PutUint16(header[2:4], uint16(aceSize))

	return append(header, body...)
}

// Matches checks if this ACE matches the given criteria.
func (a *ACE) Matches(sid *SID, objectType *GUID, mask uint32) bool {
	if sid != nil && !a.SID.Equal(sid) {
		return false
	}
	if mask != 0 && (a.Mask&mask) != mask {
		return false
	}
	if objectType != nil && !objectType.IsZero() {
		if a.ObjectType.IsZero() || a.ObjectType != *objectType {
			return false
		}
	}
	return true
}
