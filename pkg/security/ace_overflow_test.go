package security

import (
	"encoding/binary"
	"testing"
)

// A malformed object ACE whose AceSize is smaller than the object header it
// declares must be rejected, not panic. ParseACE advances `offset` past the
// object-type GUIDs (up to 28 bytes) but then slices data[offset:aceSize];
// when aceSize < offset the slice bounds are inverted and Go panics.
func TestParseACE_ObjectAceSizeBelowHeaderNoPanic(t *testing.T) {
	data := make([]byte, 32)
	data[0] = ACCESS_ALLOWED_OBJECT_ACE_TYPE     // object ACE
	data[1] = 0                                  // flags
	binary.LittleEndian.PutUint16(data[2:4], 12) // AceSize = 12 (>=8, <= len)
	binary.LittleEndian.PutUint32(data[4:8], 0)  // Mask
	// ObjectFlags at [8:12] with OBJECT_TYPE_PRESENT so offset advances to 28.
	binary.LittleEndian.PutUint32(data[8:12], ACE_OBJECT_TYPE_PRESENT)
	// data[12:28] is the 16-byte ObjectType GUID (zeros), present in the buffer.

	// Must return an error, not panic.
	_, _, err := ParseACE(data)
	if err == nil {
		t.Fatalf("expected error for object ACE with AceSize below object header")
	}
}
