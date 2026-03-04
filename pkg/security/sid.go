package security

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// SID represents a Windows Security Identifier.
type SID struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority [6]byte
	SubAuthority        []uint32
}

// ParseSID parses a string-format SID (e.g., "S-1-5-21-...").
func ParseSID(s string) (*SID, error) {
	if !strings.HasPrefix(s, "S-") && !strings.HasPrefix(s, "s-") {
		return nil, fmt.Errorf("invalid SID format: must start with S-")
	}

	parts := strings.Split(s[2:], "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SID format: too few components")
	}

	revision, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid SID revision: %v", err)
	}

	authority, err := strconv.ParseUint(parts[1], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid SID authority: %v", err)
	}

	sid := &SID{
		Revision:          uint8(revision),
		SubAuthorityCount: uint8(len(parts) - 2),
	}

	// Authority is stored as big-endian 6 bytes
	binary.BigEndian.PutUint16(sid.IdentifierAuthority[0:2], uint16(authority>>32))
	binary.BigEndian.PutUint32(sid.IdentifierAuthority[2:6], uint32(authority))

	for i := 2; i < len(parts); i++ {
		sub, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID sub-authority %d: %v", i-2, err)
		}
		sid.SubAuthority = append(sid.SubAuthority, uint32(sub))
	}

	return sid, nil
}

// ParseSIDBytes parses a binary SID and returns the SID and bytes consumed.
func ParseSIDBytes(data []byte) (*SID, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("SID too short: need at least 8 bytes, got %d", len(data))
	}

	sid := &SID{
		Revision:          data[0],
		SubAuthorityCount: data[1],
	}
	copy(sid.IdentifierAuthority[:], data[2:8])

	needed := 8 + int(sid.SubAuthorityCount)*4
	if len(data) < needed {
		return nil, 0, fmt.Errorf("SID too short: need %d bytes, got %d", needed, len(data))
	}

	sid.SubAuthority = make([]uint32, sid.SubAuthorityCount)
	for i := 0; i < int(sid.SubAuthorityCount); i++ {
		offset := 8 + i*4
		sid.SubAuthority[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	return sid, needed, nil
}

// String returns the string representation of the SID.
func (s *SID) String() string {
	// Build authority value from 6 bytes (big-endian)
	var authority uint64
	authBuf := make([]byte, 8)
	copy(authBuf[2:], s.IdentifierAuthority[:])
	authority = binary.BigEndian.Uint64(authBuf)

	result := fmt.Sprintf("S-%d-%d", s.Revision, authority)
	for _, sub := range s.SubAuthority {
		result += fmt.Sprintf("-%d", sub)
	}
	return result
}

// Marshal serializes the SID to binary format.
func (s *SID) Marshal() []byte {
	size := s.Size()
	buf := make([]byte, size)
	buf[0] = s.Revision
	buf[1] = uint8(len(s.SubAuthority))
	copy(buf[2:8], s.IdentifierAuthority[:])
	for i, sub := range s.SubAuthority {
		binary.LittleEndian.PutUint32(buf[8+i*4:], sub)
	}
	return buf
}

// Size returns the binary size of the SID.
func (s *SID) Size() int {
	return 8 + len(s.SubAuthority)*4
}

// Equal returns true if two SIDs are identical.
func (s *SID) Equal(other *SID) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s.Revision != other.Revision {
		return false
	}
	if s.IdentifierAuthority != other.IdentifierAuthority {
		return false
	}
	if len(s.SubAuthority) != len(other.SubAuthority) {
		return false
	}
	for i := range s.SubAuthority {
		if s.SubAuthority[i] != other.SubAuthority[i] {
			return false
		}
	}
	return true
}
