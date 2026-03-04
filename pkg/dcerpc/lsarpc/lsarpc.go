package lsarpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
	"unicode/utf16"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
)

// MS-LSAT (LSA Translation Methods)
// UUID: 12345778-1234-ABCD-EF00-0123456789AB v0.0

var UUID = [16]byte{
	0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
	0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
}

const MajorVersion = 0
const MinorVersion = 0

// Opnums
const (
	OpLsarClose                    = 0
	OpLsarQueryInformationPolicy   = 7
	OpLsarLookupNames              = 14
	OpLsarLookupSids               = 15
	OpLsarRetrievePrivateData      = 43
	OpLsarOpenPolicy2              = 44
)

// Access Masks
const (
	POLICY_LOOKUP_NAMES    = 0x00000800
	POLICY_VIEW_LOCAL      = 0x00000001
	POLICY_GET_PRIVATE_INFO = 0x00000004
)

// Policy Information Classes
const (
	PolicyPrimaryDomainInformation = 3
	PolicyAccountDomainInformation = 5
)

// SID_NAME_USE types
const (
	SidTypeUser           = 1
	SidTypeGroup          = 2
	SidTypeDomain         = 3
	SidTypeAlias          = 4
	SidTypeWellKnownGroup = 5
	SidTypeDeletedAccount = 6
	SidTypeInvalid        = 7
	SidTypeUnknown        = 8
	SidTypeComputer       = 9
	SidTypeLabel          = 10
)

// SidTypeName maps SID_NAME_USE to display strings
var SidTypeName = map[uint16]string{
	SidTypeUser:           "SidTypeUser",
	SidTypeGroup:          "SidTypeGroup",
	SidTypeDomain:         "SidTypeDomain",
	SidTypeAlias:          "SidTypeAlias",
	SidTypeWellKnownGroup: "SidTypeWellKnownGroup",
	SidTypeDeletedAccount: "SidTypeDeletedAccount",
	SidTypeInvalid:        "SidTypeInvalid",
	SidTypeUnknown:        "SidTypeUnknown",
	SidTypeComputer:       "SidTypeComputer",
	SidTypeLabel:          "SidTypeLabel",
}

const ERROR_SUCCESS = 0
const STATUS_SOME_NOT_MAPPED = 0x00000107
const STATUS_NONE_MAPPED = 0xC0000073

// LookupResult holds a resolved SID entry
type LookupResult struct {
	SID        string
	Domain     string
	Name       string
	SidType    uint16
	SidTypeStr string
}

// LSA Client
type LsaClient struct {
	client       *dcerpc.Client
	policyHandle []byte
}

func NewLsaClient(client *dcerpc.Client) (*LsaClient, error) {
	lsa := &LsaClient{client: client}

	// Open Policy
	if err := lsa.OpenPolicy2(); err != nil {
		return nil, err
	}

	return lsa, nil
}

// NewClientFromRPC creates an LsaClient without automatically opening the policy
// Use OpenPolicy2() or OpenPolicyForSecrets() to open the policy with desired access
func NewClientFromRPC(client *dcerpc.Client) *LsaClient {
	return &LsaClient{client: client}
}

func (lsa *LsaClient) OpenPolicy2() error {
	buf := new(bytes.Buffer)

	// SystemName: unique pointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ObjectAttributes (embedded structure):
	// Length (ULONG) = 24
	binary.Write(buf, binary.LittleEndian, uint32(24))
	// RootDirectory (unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// ObjectName (PSTRING, NULL pointer)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Attributes (ULONG) = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// SecurityDescriptor (unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// SecurityQualityOfService (unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// DesiredAccess
	binary.Write(buf, binary.LittleEndian, uint32(POLICY_LOOKUP_NAMES|POLICY_VIEW_LOCAL))

	resp, err := lsa.client.Call(OpLsarOpenPolicy2, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 24 {
		return fmt.Errorf("OpenPolicy2 response too short (%d bytes)", len(resp))
	}

	// PolicyHandle (20 bytes) + ReturnValue (4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != ERROR_SUCCESS {
		return fmt.Errorf("OpenPolicy2 failed: 0x%08x", retVal)
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	lsa.policyHandle = handle

	if build.Debug {
		log.Printf("[D] LSA: OpenPolicy2 succeeded, handle: %x", handle)
	}

	return nil
}

// QueryDomainSID retrieves the local/account domain SID (PolicyAccountDomainInformation)
func (lsa *LsaClient) QueryDomainSID() (string, string, error) {
	return lsa.queryDomainInfo(PolicyAccountDomainInformation)
}

// QueryPrimaryDomainSID retrieves the primary (AD) domain SID (PolicyPrimaryDomainInformation)
func (lsa *LsaClient) QueryPrimaryDomainSID() (string, string, error) {
	return lsa.queryDomainInfo(PolicyPrimaryDomainInformation)
}

func (lsa *LsaClient) queryDomainInfo(infoClass uint16) (string, string, error) {
	buf := new(bytes.Buffer)

	// PolicyHandle
	buf.Write(lsa.policyHandle)

	// InformationClass
	binary.Write(buf, binary.LittleEndian, infoClass)

	resp, err := lsa.client.Call(OpLsarQueryInformationPolicy, buf.Bytes())
	if err != nil {
		return "", "", fmt.Errorf("QueryInformationPolicy failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] LSA: QueryInformationPolicy response (%d bytes): %x", len(resp), resp)
	}

	// Parse response:
	// Pointer to LSAPR_POLICY_INFORMATION (referent ID, 4 bytes)
	// InformationClass discriminant (USHORT, 2 bytes + 2 padding)
	// PolicyAccountDomainInformation structure:
	//   DomainName: RPC_UNICODE_STRING (Length USHORT, MaxLength USHORT, Buffer unique ptr 4 bytes)
	//   DomainSid: PRPC_SID (unique ptr 4 bytes)
	//   [deferred] DomainName buffer data
	//   [deferred] DomainSid data
	// ReturnValue (4 bytes at end)

	if len(resp) < 8 {
		return "", "", fmt.Errorf("QueryDomainSID response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != ERROR_SUCCESS {
		return "", "", fmt.Errorf("QueryInformationPolicy failed: 0x%08x", retVal)
	}

	offset := 0

	// Referent pointer to policy info
	refPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	if refPtr == 0 {
		return "", "", fmt.Errorf("NULL policy information returned")
	}

	// Information class discriminant (USHORT + 2 padding)
	respInfoClass := binary.LittleEndian.Uint16(resp[offset:])
	offset += 2
	offset += 2 // padding
	if respInfoClass != infoClass {
		return "", "", fmt.Errorf("unexpected information class: %d", respInfoClass)
	}

	// RPC_UNICODE_STRING DomainName
	nameLen := binary.LittleEndian.Uint16(resp[offset:])
	offset += 2
	_ = binary.LittleEndian.Uint16(resp[offset:]) // MaxLength
	offset += 2
	namePtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// PRPC_SID DomainSid
	sidPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Parse deferred DomainName buffer
	var domainName string
	if namePtr != 0 && nameLen > 0 {
		if offset+12 > len(resp) {
			return "", "", fmt.Errorf("response too short for domain name")
		}
		// MaxCount, Offset, ActualCount
		_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
		offset += 4
		_ = binary.LittleEndian.Uint32(resp[offset:]) // Offset
		offset += 4
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		if offset+int(actualCount)*2 > len(resp) {
			return "", "", fmt.Errorf("response too short for domain name data")
		}
		domainName = readUTF16(resp[offset:], int(actualCount))
		offset += int(actualCount) * 2
		// Align to 4 bytes
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	// Parse deferred DomainSid
	var domainSID string
	if sidPtr != 0 {
		if offset+8 > len(resp) {
			return "", "", fmt.Errorf("response too short for domain SID")
		}
		// SubAuthorityCount as conformant MaxCount
		subAuthCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// SID structure
		if offset+8+int(subAuthCount)*4 > len(resp) {
			return "", "", fmt.Errorf("response too short for SID data")
		}
		revision := resp[offset]
		offset++
		sidSubAuthCount := resp[offset]
		offset++
		_ = sidSubAuthCount

		// IdentifierAuthority (6 bytes, big-endian)
		var auth uint64
		for i := 0; i < 6; i++ {
			auth = (auth << 8) | uint64(resp[offset+i])
		}
		offset += 6

		// SubAuthority array
		var parts []string
		parts = append(parts, fmt.Sprintf("S-%d-%d", revision, auth))
		for i := 0; i < int(subAuthCount); i++ {
			sub := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			parts = append(parts, fmt.Sprintf("%d", sub))
		}
		domainSID = strings.Join(parts, "-")
	}

	if build.Debug {
		log.Printf("[D] LSA: Domain: %s, SID: %s", domainName, domainSID)
	}

	return domainName, domainSID, nil
}

// LookupSids resolves a batch of SID strings to names
func (lsa *LsaClient) LookupSids(sids []string) ([]LookupResult, error) {
	buf := new(bytes.Buffer)

	// PolicyHandle (20 bytes)
	buf.Write(lsa.policyHandle)

	// SidEnumBuffer structure (fixed fields):
	// Entries (ULONG)
	binary.Write(buf, binary.LittleEndian, uint32(len(sids)))
	// SidInfo pointer (unique, non-NULL referent ID)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))

	// --- SidEnumBuffer deferred: SidInfo referent ---
	// In NDR, deferred pointer referents come immediately after the
	// structure's fixed fields, before the next parameter.

	// Conformant array MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(sids)))

	// Array of LSAPR_SID_INFORMATION entries (each has a unique pointer to SID)
	for i := range sids {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020004+i*4))
	}

	// Deferred SID data for each pointer
	for _, s := range sids {
		sidBytes, err := encodeSIDForNDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid SID %q: %v", s, err)
		}
		buf.Write(sidBytes)
	}

	// TranslatedNames ([in, out]):
	// Entries = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Names pointer = NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// LookupLevel (LSAP_LOOKUP_LEVEL enum, serialized as USHORT)
	binary.Write(buf, binary.LittleEndian, uint16(1)) // LsapLookupWksta
	// Alignment padding to 4-byte boundary for next ULONG
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// MappedCount ([in, out])
	binary.Write(buf, binary.LittleEndian, uint32(0))

	if build.Debug {
		log.Printf("[D] LSA: LookupSids request (%d SIDs, %d bytes)", len(sids), buf.Len())
	}

	resp, err := lsa.client.Call(OpLsarLookupSids, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("LookupSids RPC call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] LSA: LookupSids response (%d bytes)", len(resp))
	}

	if len(resp) < 12 {
		return nil, fmt.Errorf("LookupSids response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != ERROR_SUCCESS && retVal != STATUS_SOME_NOT_MAPPED {
		if retVal == STATUS_NONE_MAPPED {
			// None mapped - return empty results
			results := make([]LookupResult, len(sids))
			for i, sid := range sids {
				results[i] = LookupResult{
					SID:        sid,
					SidType:    SidTypeUnknown,
					SidTypeStr: "SidTypeUnknown",
				}
			}
			return results, nil
		}
		return nil, fmt.Errorf("LookupSids failed: 0x%08x", retVal)
	}

	// Parse response
	return parseLookupSidsResponse(resp, sids)
}

// parseLookupSidsResponse parses the NDR response from LsarLookupSids
func parseLookupSidsResponse(resp []byte, sids []string) ([]LookupResult, error) {
	offset := 0

	// --- ReferencedDomains (PLSAPR_REFERENCED_DOMAIN_LIST) ---
	// Unique pointer
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for ReferencedDomains pointer")
	}
	refDomPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	var domains []string
	if refDomPtr != 0 {
		// LSAPR_REFERENCED_DOMAIN_LIST:
		// Entries (ULONG)
		if offset+4 > len(resp) {
			return nil, fmt.Errorf("response too short for domain entries")
		}
		domEntries := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// Domains pointer (unique)
		if offset+4 > len(resp) {
			return nil, fmt.Errorf("response too short for domains pointer")
		}
		domainsPtr := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// MaxEntries (ULONG)
		if offset+4 > len(resp) {
			return nil, fmt.Errorf("response too short for max entries")
		}
		_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxEntries
		offset += 4

		if domainsPtr != 0 && domEntries > 0 {
			// Conformant array MaxCount
			if offset+4 > len(resp) {
				return nil, fmt.Errorf("response too short for domain array maxcount")
			}
			_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
			offset += 4

			// Read domain entries (Name + Sid pointer)
			type domainEntry struct {
				nameLen    uint16
				nameMaxLen uint16
				namePtr    uint32
				sidPtr     uint32
			}
			var domEntryList []domainEntry
			for i := 0; i < int(domEntries); i++ {
				if offset+12 > len(resp) {
					return nil, fmt.Errorf("response too short for domain entry %d", i)
				}
				de := domainEntry{
					nameLen:    binary.LittleEndian.Uint16(resp[offset:]),
					nameMaxLen: binary.LittleEndian.Uint16(resp[offset+2:]),
					namePtr:    binary.LittleEndian.Uint32(resp[offset+4:]),
					sidPtr:     binary.LittleEndian.Uint32(resp[offset+8:]),
				}
				offset += 12
				domEntryList = append(domEntryList, de)
			}

			// Read deferred data for each domain
			for _, de := range domEntryList {
				var name string
				if de.namePtr != 0 && de.nameLen > 0 {
					if offset+12 > len(resp) {
						domains = append(domains, "")
						continue
					}
					_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
					offset += 4
					_ = binary.LittleEndian.Uint32(resp[offset:]) // Offset
					offset += 4
					actualCount := binary.LittleEndian.Uint32(resp[offset:])
					offset += 4

					dataLen := int(actualCount) * 2
					if offset+dataLen > len(resp) {
						domains = append(domains, "")
						continue
					}
					name = readUTF16(resp[offset:], int(actualCount))
					offset += dataLen
					// Align to 4 bytes
					if offset%4 != 0 {
						offset += 4 - (offset % 4)
					}
				}

				// Skip SID data
				if de.sidPtr != 0 {
					if offset+4 > len(resp) {
						domains = append(domains, name)
						continue
					}
					subAuthCount := binary.LittleEndian.Uint32(resp[offset:])
					offset += 4
					// Skip SID body: 1 (rev) + 1 (subAuthCount) + 6 (auth) + subAuthCount*4
					sidBodyLen := 8 + int(subAuthCount)*4
					if offset+sidBodyLen > len(resp) {
						domains = append(domains, name)
						continue
					}
					offset += sidBodyLen
				}

				domains = append(domains, name)
			}
		}
	}

	// --- TranslatedNames ---
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for TranslatedNames entries")
	}
	nameEntries := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Names pointer (unique)
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for names pointer")
	}
	namesPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	results := make([]LookupResult, len(sids))
	for i := range results {
		results[i] = LookupResult{
			SID:        sids[i],
			SidType:    SidTypeUnknown,
			SidTypeStr: "SidTypeUnknown",
		}
	}

	if namesPtr != 0 && nameEntries > 0 {
		// Conformant array MaxCount
		if offset+4 > len(resp) {
			return results, nil
		}
		_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
		offset += 4

		// Read TranslatedName entries
		type translatedName struct {
			use       uint16
			nameLen   uint16
			nameMax   uint16
			namePtr   uint32
			domIndex  int32
		}
		var nameList []translatedName
		for i := 0; i < int(nameEntries); i++ {
			if offset+16 > len(resp) {
				break
			}
			tn := translatedName{
				use:     binary.LittleEndian.Uint16(resp[offset:]),
				nameLen: binary.LittleEndian.Uint16(resp[offset+4:]),
				nameMax: binary.LittleEndian.Uint16(resp[offset+6:]),
				namePtr: binary.LittleEndian.Uint32(resp[offset+8:]),
			}
			// SID_NAME_USE is a USHORT + 2 padding bytes
			// Then RPC_UNICODE_STRING (2+2+4 = 8 bytes)
			// Then DomainIndex (LONG, 4 bytes)
			tn.domIndex = int32(binary.LittleEndian.Uint32(resp[offset+12:]))
			offset += 16
			nameList = append(nameList, tn)
		}

		// Read deferred name data
		for i, tn := range nameList {
			if i >= len(results) {
				break
			}

			results[i].SidType = tn.use
			if typeName, ok := SidTypeName[tn.use]; ok {
				results[i].SidTypeStr = typeName
			}

			if tn.domIndex >= 0 && int(tn.domIndex) < len(domains) {
				results[i].Domain = domains[tn.domIndex]
			}

			if tn.namePtr != 0 && tn.nameLen > 0 {
				if offset+12 > len(resp) {
					continue
				}
				_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
				offset += 4
				_ = binary.LittleEndian.Uint32(resp[offset:]) // Offset
				offset += 4
				actualCount := binary.LittleEndian.Uint32(resp[offset:])
				offset += 4

				dataLen := int(actualCount) * 2
				if offset+dataLen > len(resp) {
					continue
				}
				results[i].Name = readUTF16(resp[offset:], int(actualCount))
				offset += dataLen
				// Align to 4 bytes
				if offset%4 != 0 {
					offset += 4 - (offset % 4)
				}
			}
		}
	}

	return results, nil
}

// RetrievePrivateData retrieves an LSA secret by name
// This requires POLICY_GET_PRIVATE_INFO access (you may need to open a new policy handle)
func (lsa *LsaClient) RetrievePrivateData(keyName string) ([]byte, error) {
	buf := new(bytes.Buffer)

	// PolicyHandle (20 bytes)
	buf.Write(lsa.policyHandle)

	// KeyName: RPC_UNICODE_STRING (embedded structure with inline deferred data)
	// According to Impacket's NDR serialization, embedded pointer data comes
	// immediately after the structure, before the next top-level parameter.
	//
	// Structure:
	// - Length (USHORT): length in bytes (NOT including null terminator)
	// - MaximumLength (USHORT): same as Length
	// - Buffer (unique pointer): pointer to the string
	// - [DEFERRED] Buffer data (conformant varying string, NO null terminator)
	utf16Name := utf16.Encode([]rune(keyName))
	charCount := uint16(len(utf16Name))
	byteLen := charCount * 2
	binary.Write(buf, binary.LittleEndian, byteLen)            // Length (no null)
	binary.Write(buf, binary.LittleEndian, byteLen)            // MaximumLength (same as Length)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Buffer pointer (non-NULL)

	// KeyName Buffer deferred data (conformant varying string) - comes BEFORE EncryptedData
	// MaxCount = MaximumLength / sizeof(WCHAR) = charCount
	// ActualCount = same as MaxCount
	// NOTE: No null terminator in wire data (matching Impacket)
	maxCharCount := uint32(charCount)
	actualCharCount := uint32(charCount)
	binary.Write(buf, binary.LittleEndian, maxCharCount)    // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Offset
	binary.Write(buf, binary.LittleEndian, actualCharCount) // ActualCount

	for _, c := range utf16Name {
		binary.Write(buf, binary.LittleEndian, c)
	}
	// NO null terminator - matching Impacket's behavior

	// Align to 4-byte boundary before EncryptedData pointer
	// With 20 chars (40 bytes), we're already aligned
	// With 47 chars (94 bytes), we need 2 bytes padding
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}

	// EncryptedData: PLSAPR_CR_CIPHER_VALUE (unique pointer, NULL on input)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pointer

	var resp []byte
	var err error
	if lsa.client.Authenticated {
		resp, err = lsa.client.CallAuthAuto(OpLsarRetrievePrivateData, buf.Bytes())
	} else {
		resp, err = lsa.client.Call(OpLsarRetrievePrivateData, buf.Bytes())
	}
	if err != nil {
		return nil, fmt.Errorf("RetrievePrivateData call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] LSA: RetrievePrivateData response (%d bytes): %x", len(resp), resp)
	}

	// Response format:
	// - EncryptedData: PLSAPR_CR_CIPHER_VALUE (unique pointer)
	//   - Pointer referent ID
	//   - LSAPR_CR_CIPHER_VALUE structure:
	//     - Length (DWORD)
	//     - MaximumLength (DWORD)
	//     - Buffer (unique pointer)
	//   - Buffer data (conformant array)
	// - ReturnValue (NTSTATUS at end)

	if len(resp) < 8 {
		return nil, fmt.Errorf("RetrievePrivateData response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != ERROR_SUCCESS {
		return nil, fmt.Errorf("RetrievePrivateData failed: 0x%08x", retVal)
	}

	// Parse the response
	offset := 0

	if build.Debug {
		log.Printf("[D] LSA: Response (%d bytes) hex: %x", len(resp), resp)
	}

	// EncryptedData pointer
	dataPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	if dataPtr == 0 {
		return nil, fmt.Errorf("NULL encrypted data returned")
	}

	// LSAPR_CR_CIPHER_VALUE structure
	// Length
	dataLen := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// MaximumLength
	maxLen := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Buffer pointer
	bufPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if build.Debug {
		log.Printf("[D] LSA: dataPtr=0x%x, dataLen=%d, maxLen=%d, bufPtr=0x%x", dataPtr, dataLen, maxLen, bufPtr)
	}

	if bufPtr == 0 {
		return nil, fmt.Errorf("NULL buffer in encrypted data")
	}

	// Deferred buffer data (conformant array)
	// MaxCount
	maxCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Offset (always 0 for LSAPR_CR_CIPHER_VALUE)
	_ = binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// ActualCount
	actualCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if build.Debug {
		log.Printf("[D] LSA: maxCount=%d, actualCount=%d, remaining bytes=%d, offset=%d", maxCount, actualCount, len(resp)-offset-4, offset)
	}

	// Use actualCount for the data length
	actualLen := actualCount
	if actualLen == 0 {
		actualLen = dataLen
	}

	// Actual data
	if offset+int(actualLen) > len(resp)-4 { // -4 for the return value at end
		return nil, fmt.Errorf("data length exceeds response size")
	}

	encryptedData := make([]byte, actualLen)
	copy(encryptedData, resp[offset:])
	if build.Debug {
		log.Printf("[D] LSA: Returning %d bytes of encrypted data", len(encryptedData))
	}

	return encryptedData, nil
}

// OpenPolicyForSecrets opens the policy with access rights needed for secret retrieval
func (lsa *LsaClient) OpenPolicyForSecrets() error {
	buf := new(bytes.Buffer)

	// SystemName: unique pointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ObjectAttributes (embedded structure):
	binary.Write(buf, binary.LittleEndian, uint32(24)) // Length
	binary.Write(buf, binary.LittleEndian, uint32(0))  // RootDirectory (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))  // ObjectName (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))  // Attributes
	binary.Write(buf, binary.LittleEndian, uint32(0))  // SecurityDescriptor (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))  // SecurityQualityOfService (NULL)

	// DesiredAccess - use only GET_PRIVATE_INFO for secret retrieval (matching Impacket)
	binary.Write(buf, binary.LittleEndian, uint32(POLICY_GET_PRIVATE_INFO))

	var resp []byte
	var err error
	if lsa.client.Authenticated {
		resp, err = lsa.client.CallAuthAuto(OpLsarOpenPolicy2, buf.Bytes())
	} else {
		resp, err = lsa.client.Call(OpLsarOpenPolicy2, buf.Bytes())
	}
	if err != nil {
		return err
	}

	if len(resp) < 24 {
		return fmt.Errorf("OpenPolicy2 response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != ERROR_SUCCESS {
		return fmt.Errorf("OpenPolicy2 failed: 0x%08x", retVal)
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	lsa.policyHandle = handle

	if build.Debug {
		log.Printf("[D] LSA: OpenPolicyForSecrets succeeded, handle: %x", handle)
	}

	return nil
}

// LookupNameResult holds a resolved name entry
type LookupNameResult struct {
	Name   string
	Domain string
	SID    []byte  // raw binary SID
	SIDStr string  // string form S-1-...
	Use    uint16  // SID_NAME_USE
}

// LookupNames resolves account names to SIDs via LsarLookupNames (OpNum 14).
// Names can be in the form "DOMAIN\user", "user", or well-known names.
func (lsa *LsaClient) LookupNames(names []string) ([]LookupNameResult, error) {
	buf := new(bytes.Buffer)

	// PolicyHandle (20 bytes)
	buf.Write(lsa.policyHandle)

	// Count (number of names)
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// Names: conformant varying array of RPC_UNICODE_STRING
	// MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// Inline RPC_UNICODE_STRING entries (Length, MaxLength, pointer)
	for i, name := range names {
		utf16Name := utf16.Encode([]rune(name))
		nameLen := uint16(len(utf16Name) * 2)
		binary.Write(buf, binary.LittleEndian, nameLen)                            // Length
		binary.Write(buf, binary.LittleEndian, nameLen)                            // MaximumLength
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000+i*4))             // Buffer pointer
	}

	// Deferred string data for each name
	for _, name := range names {
		utf16Name := utf16.Encode([]rune(name))
		binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // MaxCount
		binary.Write(buf, binary.LittleEndian, uint32(0))              // Offset
		binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // ActualCount
		for _, c := range utf16Name {
			binary.Write(buf, binary.LittleEndian, c)
		}
		// Align to 4 bytes
		dataLen := len(utf16Name) * 2
		if dataLen%4 != 0 {
			buf.Write(make([]byte, 4-dataLen%4))
		}
	}

	// TranslatedSids ([in, out]):
	// Entries = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Sids pointer = NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// LookupLevel: LsapLookupWksta = 1
	binary.Write(buf, binary.LittleEndian, uint16(1))
	// Padding
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// MappedCount
	binary.Write(buf, binary.LittleEndian, uint32(0))

	if build.Debug {
		log.Printf("[D] LSA: LookupNames request (%d names, %d bytes)", len(names), buf.Len())
	}

	resp, err := lsa.client.Call(OpLsarLookupNames, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("LookupNames RPC call failed: %v", err)
	}

	if len(resp) < 12 {
		return nil, fmt.Errorf("LookupNames response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != ERROR_SUCCESS && retVal != STATUS_SOME_NOT_MAPPED {
		if retVal == STATUS_NONE_MAPPED {
			results := make([]LookupNameResult, len(names))
			for i, n := range names {
				results[i] = LookupNameResult{Name: n, Use: SidTypeUnknown}
			}
			return results, fmt.Errorf("none of the names could be mapped")
		}
		return nil, fmt.Errorf("LookupNames failed: 0x%08x", retVal)
	}

	return parseLookupNamesResponse(resp, names)
}

// parseLookupNamesResponse parses the NDR response from LsarLookupNames.
// Response format: ReferencedDomains + TranslatedSids + MappedCount + ReturnValue
func parseLookupNamesResponse(resp []byte, names []string) ([]LookupNameResult, error) {
	offset := 0

	// --- ReferencedDomains (PLSAPR_REFERENCED_DOMAIN_LIST) ---
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for ReferencedDomains pointer")
	}
	refDomPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	type domainInfo struct {
		name string
		sid  []byte // raw binary SID
	}
	var domains []domainInfo

	if refDomPtr != 0 {
		if offset+4 > len(resp) {
			return nil, fmt.Errorf("response too short for domain entries")
		}
		domEntries := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		if offset+4 > len(resp) {
			return nil, fmt.Errorf("response too short for domains pointer")
		}
		domainsPtr := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// MaxEntries
		if offset+4 > len(resp) {
			return nil, fmt.Errorf("response too short for max entries")
		}
		offset += 4

		if domainsPtr != 0 && domEntries > 0 {
			// Conformant array MaxCount
			if offset+4 > len(resp) {
				return nil, fmt.Errorf("response too short for domain array maxcount")
			}
			offset += 4

			type domEntry struct {
				nameLen uint16
				namePtr uint32
				sidPtr  uint32
			}
			var domEntryList []domEntry
			for i := 0; i < int(domEntries); i++ {
				if offset+12 > len(resp) {
					break
				}
				de := domEntry{
					nameLen: binary.LittleEndian.Uint16(resp[offset:]),
					namePtr: binary.LittleEndian.Uint32(resp[offset+4:]),
					sidPtr:  binary.LittleEndian.Uint32(resp[offset+8:]),
				}
				offset += 12
				domEntryList = append(domEntryList, de)
			}

			for _, de := range domEntryList {
				di := domainInfo{}
				if de.namePtr != 0 && de.nameLen > 0 {
					if offset+12 > len(resp) {
						domains = append(domains, di)
						continue
					}
					offset += 4 // MaxCount
					offset += 4 // Offset
					actualCount := binary.LittleEndian.Uint32(resp[offset:])
					offset += 4

					dataLen := int(actualCount) * 2
					if offset+dataLen > len(resp) {
						domains = append(domains, di)
						continue
					}
					di.name = readUTF16(resp[offset:], int(actualCount))
					offset += dataLen
					if offset%4 != 0 {
						offset += 4 - (offset % 4)
					}
				}

				if de.sidPtr != 0 {
					if offset+4 > len(resp) {
						domains = append(domains, di)
						continue
					}
					subAuthCount := binary.LittleEndian.Uint32(resp[offset:])
					offset += 4
					sidBodyLen := 8 + int(subAuthCount)*4
					if offset+sidBodyLen > len(resp) {
						domains = append(domains, di)
						continue
					}
					di.sid = make([]byte, sidBodyLen)
					copy(di.sid, resp[offset:offset+sidBodyLen])
					offset += sidBodyLen
				}

				domains = append(domains, di)
			}
		}
	}

	// --- TranslatedSids (LSAPR_TRANSLATED_SIDS) ---
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for TranslatedSids entries")
	}
	sidEntries := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for sids pointer")
	}
	sidsPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	results := make([]LookupNameResult, len(names))
	for i := range results {
		results[i] = LookupNameResult{Name: names[i], Use: SidTypeUnknown}
	}

	if sidsPtr != 0 && sidEntries > 0 {
		// Conformant array MaxCount
		if offset+4 > len(resp) {
			return results, nil
		}
		offset += 4

		// LSAPR_TRANSLATED_SID entries: Use(2) + pad(2) + RelativeId(4) + DomainIndex(4) = 12 bytes each
		type translatedSid struct {
			use      uint16
			rid      uint32
			domIndex int32
		}
		var sidList []translatedSid
		for i := 0; i < int(sidEntries); i++ {
			if offset+12 > len(resp) {
				break
			}
			ts := translatedSid{
				use:      binary.LittleEndian.Uint16(resp[offset:]),
				rid:      binary.LittleEndian.Uint32(resp[offset+4:]),
				domIndex: int32(binary.LittleEndian.Uint32(resp[offset+8:])),
			}
			offset += 12
			sidList = append(sidList, ts)
		}

		for i, ts := range sidList {
			if i >= len(results) {
				break
			}
			results[i].Use = ts.use

			if ts.domIndex >= 0 && int(ts.domIndex) < len(domains) {
				dom := domains[ts.domIndex]
				results[i].Domain = dom.name

				// Build full SID: domain SID + RID
				if len(dom.sid) >= 8 {
					fullSID := make([]byte, len(dom.sid)+4)
					copy(fullSID, dom.sid)
					fullSID[1]++ // increment SubAuthorityCount
					binary.LittleEndian.PutUint32(fullSID[len(dom.sid):], ts.rid)
					results[i].SID = fullSID
					results[i].SIDStr = formatSID(fullSID)
				}
			}
		}
	}

	return results, nil
}

// formatSID converts raw binary SID to string form.
func formatSID(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}
	revision := sid[0]
	subAuthCount := int(sid[1])
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(sid[2+i])
	}
	s := fmt.Sprintf("S-%d-%d", revision, auth)
	for i := 0; i < subAuthCount; i++ {
		off := 8 + i*4
		if off+4 > len(sid) {
			break
		}
		sub := binary.LittleEndian.Uint32(sid[off:])
		s += fmt.Sprintf("-%d", sub)
	}
	return s
}

func (lsa *LsaClient) Close() {
	if lsa.policyHandle != nil {
		buf := new(bytes.Buffer)
		buf.Write(lsa.policyHandle)
		lsa.client.Call(OpLsarClose, buf.Bytes())
		lsa.policyHandle = nil
	}
}

// encodeSIDForNDR encodes a SID string into NDR format for use in LookupSids
func encodeSIDForNDR(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "S-") {
		return nil, fmt.Errorf("invalid SID format")
	}
	parts := strings.Split(s[2:], "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SID: too few components")
	}

	rev, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid revision: %v", err)
	}
	auth, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid authority: %v", err)
	}

	subAuths := make([]uint32, len(parts)-2)
	for i := 2; i < len(parts); i++ {
		val, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid sub-authority %d: %v", i-2, err)
		}
		subAuths[i-2] = uint32(val)
	}

	buf := new(bytes.Buffer)

	// NDR conformant array: SubAuthorityCount as MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(subAuths)))

	// RPC_SID structure
	buf.WriteByte(byte(rev))             // Revision
	buf.WriteByte(byte(len(subAuths)))   // SubAuthorityCount

	// IdentifierAuthority (6 bytes, big-endian)
	var authBytes [6]byte
	for i := 0; i < 6; i++ {
		authBytes[5-i] = byte(auth >> (uint(i) * 8))
	}
	buf.Write(authBytes[:])

	// SubAuthority array
	for _, sub := range subAuths {
		binary.Write(buf, binary.LittleEndian, sub)
	}

	return buf.Bytes(), nil
}

// ParseSIDToBytes parses a SID string to raw binary (without NDR wrapping)
func ParseSIDToBytes(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "S-") {
		return nil, fmt.Errorf("invalid SID")
	}
	parts := strings.Split(s[2:], "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SID")
	}

	rev, _ := strconv.Atoi(parts[0])
	auth, _ := strconv.ParseUint(parts[1], 10, 64)

	subAuths := make([]uint32, len(parts)-2)
	for i := 2; i < len(parts); i++ {
		val, _ := strconv.ParseUint(parts[i], 10, 32)
		subAuths[i-2] = uint32(val)
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(rev))
	buf.WriteByte(byte(len(subAuths)))

	var authBytes [6]byte
	for i := 0; i < 6; i++ {
		authBytes[5-i] = byte(auth >> (uint(i) * 8))
	}
	buf.Write(authBytes[:])

	for _, sub := range subAuths {
		binary.Write(buf, binary.LittleEndian, sub)
	}

	return buf.Bytes(), nil
}

// readUTF16 reads a UTF-16LE encoded string from a byte slice
func readUTF16(data []byte, charCount int) string {
	if len(data) < charCount*2 {
		charCount = len(data) / 2
	}
	u16s := make([]uint16, charCount)
	for i := 0; i < charCount; i++ {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Remove null terminator if present
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

// writeWideString writes a UTF-16LE string with NDR conformant varying array format
func writeWideString(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // null terminator
	charCount := uint32(len(utf16Chars))

	// Conformant varying string
	binary.Write(buf, binary.LittleEndian, charCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, charCount) // ActualCount

	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}
