// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/binary"
	"fmt"
)

// ACL represents an Access Control List.
type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
	ACEs        []*ACE
}

// ParseACL parses an ACL from binary data.
func ParseACL(data []byte) (*ACL, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ACL too short: need at least 8 bytes, got %d", len(data))
	}

	acl := &ACL{
		AclRevision: data[0],
		Sbz1:        data[1],
		AclSize:     binary.LittleEndian.Uint16(data[2:4]),
		AceCount:    binary.LittleEndian.Uint16(data[4:6]),
		Sbz2:        binary.LittleEndian.Uint16(data[6:8]),
	}

	offset := 8
	for i := 0; i < int(acl.AceCount); i++ {
		if offset >= len(data) {
			return nil, fmt.Errorf("ACL truncated: expected %d ACEs, parsed %d", acl.AceCount, i)
		}
		ace, consumed, err := ParseACE(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse ACE %d: %v", i, err)
		}
		acl.ACEs = append(acl.ACEs, ace)
		offset += consumed
	}

	return acl, nil
}

// Marshal serializes the ACL to binary format, recalculating size and count.
func (acl *ACL) Marshal() []byte {
	// Serialize all ACEs first
	var aceData []byte
	for _, ace := range acl.ACEs {
		aceData = append(aceData, ace.Marshal()...)
	}

	// Header is 8 bytes
	totalSize := 8 + len(aceData)
	buf := make([]byte, 8)
	buf[0] = acl.AclRevision
	buf[1] = 0 // Sbz1
	binary.LittleEndian.PutUint16(buf[2:4], uint16(totalSize))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(acl.ACEs)))
	binary.LittleEndian.PutUint16(buf[6:8], 0) // Sbz2

	return append(buf, aceData...)
}

// AddACE appends an ACE to the ACL.
func (acl *ACL) AddACE(ace *ACE) {
	acl.ACEs = append(acl.ACEs, ace)
	acl.AceCount = uint16(len(acl.ACEs))
}

// RemoveACE removes an ACE at the given index.
func (acl *ACL) RemoveACE(index int) {
	if index < 0 || index >= len(acl.ACEs) {
		return
	}
	acl.ACEs = append(acl.ACEs[:index], acl.ACEs[index+1:]...)
	acl.AceCount = uint16(len(acl.ACEs))
}
