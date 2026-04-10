// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/binary"
	"fmt"
)

// SecurityDescriptor represents a Windows self-relative security descriptor.
type SecurityDescriptor struct {
	Revision uint8
	Sbz1     uint8
	Control  uint16
	Owner    *SID
	Group    *SID
	SACL     *ACL
	DACL     *ACL
}

// ParseSecurityDescriptor parses a self-relative security descriptor from binary data.
func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short: need at least 20 bytes, got %d", len(data))
	}

	sd := &SecurityDescriptor{
		Revision: data[0],
		Sbz1:     data[1],
		Control:  binary.LittleEndian.Uint16(data[2:4]),
	}

	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	groupOffset := binary.LittleEndian.Uint32(data[8:12])
	saclOffset := binary.LittleEndian.Uint32(data[12:16])
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	// Parse Owner SID
	if ownerOffset != 0 {
		if int(ownerOffset) >= len(data) {
			return nil, fmt.Errorf("owner offset %d exceeds data length %d", ownerOffset, len(data))
		}
		sid, _, err := ParseSIDBytes(data[ownerOffset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse owner SID: %v", err)
		}
		sd.Owner = sid
	}

	// Parse Group SID
	if groupOffset != 0 {
		if int(groupOffset) >= len(data) {
			return nil, fmt.Errorf("group offset %d exceeds data length %d", groupOffset, len(data))
		}
		sid, _, err := ParseSIDBytes(data[groupOffset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse group SID: %v", err)
		}
		sd.Group = sid
	}

	// Parse SACL
	if saclOffset != 0 && sd.Control&SE_SACL_PRESENT != 0 {
		if int(saclOffset) >= len(data) {
			return nil, fmt.Errorf("SACL offset %d exceeds data length %d", saclOffset, len(data))
		}
		acl, err := ParseACL(data[saclOffset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse SACL: %v", err)
		}
		sd.SACL = acl
	}

	// Parse DACL
	if daclOffset != 0 && sd.Control&SE_DACL_PRESENT != 0 {
		if int(daclOffset) >= len(data) {
			return nil, fmt.Errorf("DACL offset %d exceeds data length %d", daclOffset, len(data))
		}
		acl, err := ParseACL(data[daclOffset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse DACL: %v", err)
		}
		sd.DACL = acl
	}

	return sd, nil
}

// Marshal serializes the security descriptor to self-relative binary format.
func (sd *SecurityDescriptor) Marshal() []byte {
	// Start after the 20-byte header
	offset := uint32(20)
	var ownerBytes, groupBytes, saclBytes, daclBytes []byte

	// Set control flags
	control := sd.Control | SE_SELF_RELATIVE

	// Marshal components and calculate offsets
	var ownerOffset, groupOffset, saclOffset, daclOffset uint32

	if sd.SACL != nil && control&SE_SACL_PRESENT != 0 {
		saclBytes = sd.SACL.Marshal()
		saclOffset = offset
		offset += uint32(len(saclBytes))
	}

	if sd.DACL != nil && control&SE_DACL_PRESENT != 0 {
		daclBytes = sd.DACL.Marshal()
		daclOffset = offset
		offset += uint32(len(daclBytes))
	}

	if sd.Owner != nil {
		ownerBytes = sd.Owner.Marshal()
		ownerOffset = offset
		offset += uint32(len(ownerBytes))
	}

	if sd.Group != nil {
		groupBytes = sd.Group.Marshal()
		groupOffset = offset
		offset += uint32(len(groupBytes))
	}

	// Build the buffer
	buf := make([]byte, 20)
	buf[0] = sd.Revision
	buf[1] = sd.Sbz1
	binary.LittleEndian.PutUint16(buf[2:4], control)
	binary.LittleEndian.PutUint32(buf[4:8], ownerOffset)
	binary.LittleEndian.PutUint32(buf[8:12], groupOffset)
	binary.LittleEndian.PutUint32(buf[12:16], saclOffset)
	binary.LittleEndian.PutUint32(buf[16:20], daclOffset)

	buf = append(buf, saclBytes...)
	buf = append(buf, daclBytes...)
	buf = append(buf, ownerBytes...)
	buf = append(buf, groupBytes...)

	return buf
}
