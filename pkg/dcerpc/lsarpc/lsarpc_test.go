// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package lsarpc

import (
	"encoding/hex"
	"testing"
)

func TestParseSIDToBytes(t *testing.T) {
	tests := []struct {
		name    string
		sid     string
		wantErr bool
		wantHex string // expected raw SID bytes (no NDR MaxCount prefix)
	}{
		{
			name:    "domain SID",
			sid:     "S-1-5-21-138049077-1787988515-2254875099",
			wantErr: false,
			wantHex: "01040000000000051500000035763a08238a926adba96686",
		},
		{
			name:    "domain SID with RID 500",
			sid:     "S-1-5-21-138049077-1787988515-2254875099-500",
			wantErr: false,
			wantHex: "0105000000000005150000003576" + "3a08238a926adba96686f4010000",
		},
		{
			name:    "BUILTIN SID",
			sid:     "S-1-5-32-544",
			wantErr: false,
			wantHex: "0102000000000005200000002002" + "0000",
		},
		{
			name:    "everyone SID",
			sid:     "S-1-1-0",
			wantErr: false,
			wantHex: "010100000000000100000000",
		},
		{
			name:    "invalid - no prefix",
			sid:     "1-5-21",
			wantErr: true,
		},
		{
			name:    "invalid - too few parts",
			sid:     "S-1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSIDToBytes(tt.sid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSIDToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Errorf("ParseSIDToBytes() = %s, want %s", gotHex, tt.wantHex)
			}
		})
	}
}

func TestEncodeSIDForNDR(t *testing.T) {
	tests := []struct {
		name    string
		sid     string
		wantErr bool
		wantHex string // includes NDR MaxCount prefix
	}{
		{
			name:    "domain SID with RID 500",
			sid:     "S-1-5-21-138049077-1787988515-2254875099-500",
			wantErr: false,
			// MaxCount(4)=5 + Rev(1)=1 + SubAuthCount(1)=5 + Auth(6)=5 + SubAuth(5*4)
			wantHex: "050000000105000000000005150000003576" + "3a08238a926adba96686f4010000",
		},
		{
			name:    "BUILTIN Administrators",
			sid:     "S-1-5-32-544",
			wantErr: false,
			// MaxCount(4)=2 + Rev(1)=1 + SubAuthCount(1)=2 + Auth(6)=5 + SubAuth(2*4)
			wantHex: "020000000102000000000005200000002002" + "0000",
		},
		{
			name:    "everyone SID S-1-1-0",
			sid:     "S-1-1-0",
			wantErr: false,
			// MaxCount(4)=1 + Rev(1)=1 + SubAuthCount(1)=1 + Auth(6)=1 + SubAuth(1*4)
			wantHex: "01000000010100000000000100000000",
		},
		{
			name:    "invalid SID",
			sid:     "not-a-sid",
			wantErr: true,
		},
		{
			name:    "invalid sub-authority",
			sid:     "S-1-5-abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeSIDForNDR(tt.sid)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeSIDForNDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Errorf("encodeSIDForNDR() = %s, want %s", gotHex, tt.wantHex)
			}
		})
	}
}

func TestReadUTF16(t *testing.T) {
	tests := []struct {
		name      string
		dataHex   string
		charCount int
		want      string
	}{
		{
			name:      "LIQUORSTORE",
			dataHex:   "4c004900510055004f005200530054004f00520045000000",
			charCount: 11,
			want:      "LIQUORSTORE",
		},
		{
			name:      "Administrator",
			dataHex:   "410064006d0069006e006900730074007200610074006f007200",
			charCount: 13,
			want:      "Administrator",
		},
		{
			name:      "Guest",
			dataHex:   "47007500650073007400",
			charCount: 5,
			want:      "Guest",
		},
		{
			name:      "krbtgt",
			dataHex:   "6b0072006200740067007400",
			charCount: 6,
			want:      "krbtgt",
		},
		{
			name:      "with null terminator",
			dataHex:   "41004200430000",
			charCount: 4, // includes null
			want:      "ABC",
		},
		{
			name:      "empty",
			dataHex:   "",
			charCount: 0,
			want:      "",
		},
		{
			name:      "charCount exceeds data",
			dataHex:   "4100",
			charCount: 5,
			want:      "A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.dataHex)
			got := readUTF16(data, tt.charCount)
			if got != tt.want {
				t.Errorf("readUTF16() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Sample LsarQueryInformationPolicy response fixture.
// Domain: LIQUORSTORE, SID: S-1-5-21-138049077-1787988515-2254875099
const queryDomainSIDResponseHex = "00000200050000001600180004000200080002000c000000000000000b0000004c004900510055004f005200530054004f005200450000000400000001040000000000051500000035763a08238a926adba9668600000000"

func TestParseDomainSIDResponse(t *testing.T) {
	resp, err := hex.DecodeString(queryDomainSIDResponseHex)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	// Simulate what QueryDomainSID does internally
	// The response format is parsed in QueryDomainSID(), but we can test
	// the key components. The last 4 bytes are the return value.
	retVal := uint32(resp[len(resp)-4]) | uint32(resp[len(resp)-3])<<8 |
		uint32(resp[len(resp)-2])<<16 | uint32(resp[len(resp)-1])<<24
	if retVal != ERROR_SUCCESS {
		t.Fatalf("Unexpected return value: 0x%08x", retVal)
	}

	// Verify the domain name is embedded in the response
	// "LIQUORSTORE" in UTF-16LE
	domainUTF16 := "4c004900510055004f005200530054004f00520045"
	if !containsHex(resp, domainUTF16) {
		t.Error("Response does not contain expected domain name")
	}

	// Verify the SID components are present
	// SubAuth values for S-1-5-21-138049077-1787988515-2254875099
	// 21 = 0x15 → 15000000, 138049077 = 0x083a7635 → 35763a08
	expectedSIDHex := "15000000" + "35763a08" + "238a926a" + "dba96686"
	if !containsHex(resp, expectedSIDHex) {
		t.Error("Response does not contain expected SID sub-authorities")
	}
}

// Sample LsarLookupSids response fixture for 10 SIDs (RIDs 500-509).
// 3 resolved, 7 unknown. Return value: STATUS_SOME_NOT_MAPPED (0x00000107)
const lookupSids10ResponseHex = "000002000100000004000200200000000100000016001800080002000c0002000c000000000000000b0000004c004900510055004f005200530054004f005200450000000400000001040000000000051500000035763a08238a926adba966860a000000100002000a000000010000001a001a001400020000000000010000000a000a001800020000000000010000000c000c001c0002000000000008000000100012002000020000000000080000001000120024000200000000000800000010001200280002000000000008000000100012002c000200000000000800000010001200300002000000000008000000100012003400020000000000080000001000120038000200000000000d000000000000000d000000410064006d0069006e006900730074007200610074006f00720000000500000000000000050000004700750065007300740000000600000000000000060000006b0072006200740067007400090000000000000008000000300030003000300030003100460037000900000000000000080000003000300030003000300031004600380009000000000000000800000030003000300030003000310046003900090000000000000008000000300030003000300030003100460041000900000000000000080000003000300030003000300031004600420009000000000000000800000030003000300030003000310046004300090000000000000008000000300030003000300030003100460044000300000007010000"

func TestParseLookupSidsResponse(t *testing.T) {
	resp, err := hex.DecodeString(lookupSids10ResponseHex)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	sids := make([]string, 10)
	baseSID := "S-1-5-21-138049077-1787988515-2254875099"
	for i := 0; i < 10; i++ {
		sids[i] = baseSID + "-" + itoa(500+i)
	}

	results, err := parseLookupSidsResponse(resp, sids)
	if err != nil {
		t.Fatalf("parseLookupSidsResponse() error: %v", err)
	}

	if len(results) != 10 {
		t.Fatalf("Expected 10 results, got %d", len(results))
	}

	// Verify resolved entries
	expectedResolved := []struct {
		index   int
		name    string
		domain  string
		sidType uint16
	}{
		{0, "Administrator", "LIQUORSTORE", SidTypeUser},
		{1, "Guest", "LIQUORSTORE", SidTypeUser},
		{2, "krbtgt", "LIQUORSTORE", SidTypeUser},
	}

	for _, exp := range expectedResolved {
		r := results[exp.index]
		if r.Name != exp.name {
			t.Errorf("Result[%d].Name = %q, want %q", exp.index, r.Name, exp.name)
		}
		if r.Domain != exp.domain {
			t.Errorf("Result[%d].Domain = %q, want %q", exp.index, r.Domain, exp.domain)
		}
		if r.SidType != exp.sidType {
			t.Errorf("Result[%d].SidType = %d, want %d", exp.index, r.SidType, exp.sidType)
		}
	}

	// Verify unresolved entries (RIDs 503-509) are SidTypeUnknown
	for i := 3; i < 10; i++ {
		if results[i].SidType != SidTypeUnknown {
			t.Errorf("Result[%d].SidType = %d, want %d (SidTypeUnknown)",
				i, results[i].SidType, SidTypeUnknown)
		}
	}
}

func TestParseLookupSidsResponseSidTypes(t *testing.T) {
	resp, err := hex.DecodeString(lookupSids10ResponseHex)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	sids := make([]string, 10)
	baseSID := "S-1-5-21-138049077-1787988515-2254875099"
	for i := 0; i < 10; i++ {
		sids[i] = baseSID + "-" + itoa(500+i)
	}

	results, err := parseLookupSidsResponse(resp, sids)
	if err != nil {
		t.Fatalf("parseLookupSidsResponse() error: %v", err)
	}

	// Verify SidTypeStr is set correctly for all results
	for i, r := range results {
		expectedStr, ok := SidTypeName[r.SidType]
		if !ok {
			t.Errorf("Result[%d]: unknown SidType %d", i, r.SidType)
			continue
		}
		if r.SidTypeStr != expectedStr {
			t.Errorf("Result[%d].SidTypeStr = %q, want %q", i, r.SidTypeStr, expectedStr)
		}
	}
}

func TestParseLookupSidsResponseDomainAssignment(t *testing.T) {
	resp, err := hex.DecodeString(lookupSids10ResponseHex)
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	sids := make([]string, 10)
	baseSID := "S-1-5-21-138049077-1787988515-2254875099"
	for i := 0; i < 10; i++ {
		sids[i] = baseSID + "-" + itoa(500+i)
	}

	results, err := parseLookupSidsResponse(resp, sids)
	if err != nil {
		t.Fatalf("parseLookupSidsResponse() error: %v", err)
	}

	// All resolved entries should have domain = "LIQUORSTORE"
	for i := 0; i < 3; i++ {
		if results[i].Domain != "LIQUORSTORE" {
			t.Errorf("Result[%d].Domain = %q, want %q", i, results[i].Domain, "LIQUORSTORE")
		}
	}
}

func TestSidTypeName(t *testing.T) {
	expected := map[uint16]string{
		1:  "SidTypeUser",
		2:  "SidTypeGroup",
		3:  "SidTypeDomain",
		4:  "SidTypeAlias",
		5:  "SidTypeWellKnownGroup",
		6:  "SidTypeDeletedAccount",
		7:  "SidTypeInvalid",
		8:  "SidTypeUnknown",
		9:  "SidTypeComputer",
		10: "SidTypeLabel",
	}

	for typ, name := range expected {
		got, ok := SidTypeName[typ]
		if !ok {
			t.Errorf("SidTypeName[%d] not found", typ)
			continue
		}
		if got != name {
			t.Errorf("SidTypeName[%d] = %q, want %q", typ, got, name)
		}
	}

	if len(SidTypeName) != len(expected) {
		t.Errorf("SidTypeName has %d entries, want %d", len(SidTypeName), len(expected))
	}
}

func TestEncodeSIDForNDRRoundTrip(t *testing.T) {
	// Encode a SID, then verify the structure is valid
	sid := "S-1-5-21-138049077-1787988515-2254875099-1104"
	data, err := encodeSIDForNDR(sid)
	if err != nil {
		t.Fatalf("encodeSIDForNDR() error: %v", err)
	}

	// Parse it back
	if len(data) < 4 {
		t.Fatal("encoded data too short")
	}

	// First 4 bytes: MaxCount (SubAuthorityCount)
	maxCount := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	if maxCount != 5 {
		t.Errorf("MaxCount = %d, want 5", maxCount)
	}

	// Revision
	if data[4] != 1 {
		t.Errorf("Revision = %d, want 1", data[4])
	}

	// SubAuthorityCount
	if data[5] != 5 {
		t.Errorf("SubAuthorityCount = %d, want 5", data[5])
	}

	// Authority (big-endian 6 bytes) = 5
	auth := uint64(0)
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(data[6+i])
	}
	if auth != 5 {
		t.Errorf("Authority = %d, want 5", auth)
	}

	// Total length: 4 (MaxCount) + 1 (Rev) + 1 (Count) + 6 (Auth) + 5*4 (SubAuth) = 32
	expectedLen := 4 + 1 + 1 + 6 + 5*4
	if len(data) != expectedLen {
		t.Errorf("encoded length = %d, want %d", len(data), expectedLen)
	}
}

func TestParseLookupSidsResponseEmpty(t *testing.T) {
	// Simulate STATUS_NONE_MAPPED response - test the early return path
	// in LookupSids (not parseLookupSidsResponse directly)
	sids := []string{
		"S-1-5-21-138049077-1787988515-2254875099-9999",
	}

	// Construct a minimal valid response with no mappings
	// ReferencedDomains ptr = NULL, TranslatedNames = {0, NULL}, MappedCount=0, RetVal=STATUS_NONE_MAPPED
	respHex := "00000000" + // ReferencedDomains ptr = NULL
		"00000000" + // TranslatedNames.Entries = 0
		"00000000" + // TranslatedNames.Names = NULL
		"00000000" + // MappedCount = 0
		"730000c0" // ReturnValue = STATUS_NONE_MAPPED (0xC0000073)

	resp, _ := hex.DecodeString(respHex)

	// This would normally be handled by LookupSids' early return for STATUS_NONE_MAPPED
	// but let's verify parseLookupSidsResponse handles NULL ReferencedDomains
	results, err := parseLookupSidsResponse(resp[:len(resp)-4], sids)
	if err != nil {
		t.Fatalf("parseLookupSidsResponse() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].SidType != SidTypeUnknown {
		t.Errorf("Result.SidType = %d, want %d", results[0].SidType, SidTypeUnknown)
	}
}

// helper for int to string without importing strconv in test
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// containsHex checks if a byte slice contains the given hex-encoded substring
func containsHex(data []byte, hexStr string) bool {
	search, err := hex.DecodeString(hexStr)
	if err != nil {
		return false
	}
	for i := 0; i <= len(data)-len(search); i++ {
		match := true
		for j := 0; j < len(search); j++ {
			if data[i+j] != search[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
