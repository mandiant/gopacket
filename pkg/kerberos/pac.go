// SPDX-License-Identifier: Apache-2.0

package kerberos

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopacket/pkg/utf16le"

	"golang.org/x/crypto/md4"
)

// PAC Buffer Types (MS-PAC 2.4)
const (
	PACTypeLogonInfo      = 1
	PACTypeCredentialInfo = 2
	PACTypeServerChecksum = 6
	PACTypeKDCChecksum    = 7
	PACTypeClientInfo     = 10
	PACTypeDelegationInfo = 11
	PACTypeUPNDNSInfo     = 12
	PACTypeAttributesInfo = 17
	PACTypeRequestorSID   = 18
)

// Checksum Types
const (
	ChecksumHMACMD5      = 0xFFFFFF76 // -138 as uint32
	ChecksumSHA196AES128 = 15
	ChecksumSHA196AES256 = 16
)

// User Account Control Flags
const (
	UACNormalAccount      = 0x00000010
	UACDontExpirePassword = 0x00000200
)

// Group Attributes
const (
	SEGroupMandatory        = 0x00000001
	SEGroupEnabledByDefault = 0x00000002
	SEGroupEnabled          = 0x00000004
)

// User Flags
const (
	LogonExtraSIDs = 0x0020
)

// FileTime represents Windows FILETIME
type FileTime struct {
	Low  uint32
	High uint32
}

// TimeToFileTime converts time.Time to Windows FileTime
func TimeToFileTime(t time.Time) FileTime {
	if t.IsZero() {
		return FileTime{Low: 0xFFFFFFFF, High: 0x7FFFFFFF}
	}
	// Windows epoch: Jan 1, 1601. Unix epoch: Jan 1, 1970.
	const epochDiff = 116444736000000000
	ns := t.UnixNano()/100 + epochDiff
	return FileTime{
		Low:  uint32(ns),
		High: uint32(ns >> 32),
	}
}

// NeverTime returns a FileTime representing "never"
func NeverTime() FileTime {
	return FileTime{Low: 0xFFFFFFFF, High: 0x7FFFFFFF}
}

// SID represents a Windows Security Identifier
type SID struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority [6]byte
	SubAuthority        []uint32
}

// ParseSID parses a SID string like "S-1-5-21-..."
func ParseSID(s string) (*SID, error) {
	if !strings.HasPrefix(s, "S-") {
		return nil, fmt.Errorf("invalid SID: must start with S-")
	}

	parts := strings.Split(s[2:], "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SID: not enough components")
	}

	rev, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid SID revision: %v", err)
	}

	auth, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid SID authority: %v", err)
	}

	var subs []uint32
	for i := 2; i < len(parts); i++ {
		sub, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID sub-authority: %v", err)
		}
		subs = append(subs, uint32(sub))
	}

	var authBytes [6]byte
	for i := 0; i < 6; i++ {
		authBytes[5-i] = byte(auth >> (8 * i))
	}

	return &SID{
		Revision:            uint8(rev),
		SubAuthorityCount:   uint8(len(subs)),
		IdentifierAuthority: authBytes,
		SubAuthority:        subs,
	}, nil
}

// String returns the SID as a string
func (s *SID) String() string {
	auth := uint64(0)
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(s.IdentifierAuthority[i])
	}
	result := fmt.Sprintf("S-%d-%d", s.Revision, auth)
	for _, sub := range s.SubAuthority {
		result += fmt.Sprintf("-%d", sub)
	}
	return result
}

// GroupMembership represents a group RID and attributes
type GroupMembership struct {
	RelativeID uint32
	Attributes uint32
}

// ExtraSID represents an extra SID with attributes
type ExtraSID struct {
	SID        *SID
	Attributes uint32
}

// PAC represents a Privilege Attribute Certificate
type PAC struct {
	// User information
	Username        string
	Domain          string
	DomainSID       *SID
	UserID          uint32
	PrimaryGroupID  uint32
	Groups          []uint32
	GroupAttributes []uint32
	ExtraSIDs       []*SID
	ExtraSIDAttrs   []uint32

	FullName           string
	LogonScript        string
	ProfilePath        string
	HomeDirectory      string
	HomeDirectoryDrive string

	LogonServer        string
	LogonCount         uint16
	BadPasswordCount   uint16
	UserAccountControl uint32
	UserFlags          uint32
	UserSessionKey     [16]byte
	SubAuthStatus      uint32
	Reserved3          uint32
	FailedILogonCount  uint32

	// Timestamps
	LogonTime            time.Time
	LogoffTime           time.Time
	KickOffTime          time.Time
	PasswordLastSet      time.Time
	PasswordCanChange    time.Time
	PasswordMustChange   time.Time
	LastSuccessfulILogon time.Time
	LastFailedILogon     time.Time

	// UPN_DNS_INFO (type 12)
	UPN            string
	DNSDomainName  string
	SamAccountName string
	UPNFlags       uint32

	// PAC_ATTRIBUTES_INFO (type 17)
	AttributesFlags uint32

	// UPN SID (from UPN_DNS_INFO extended format)
	UPNSid *SID

	// PAC_REQUESTOR (type 18)
	RequestorSID *SID

	// Client Info (type 10) - separate from LogonInfo fields
	ClientInfoTime time.Time
	ClientInfoName string

	// Delegation Info (type 11)
	S4U2ProxyTarget   string
	TransitedServices []string

	// Signature data
	ServerChecksumType uint32
	ServerChecksumData []byte
	KDCChecksumType    uint32
	KDCChecksumData    []byte
	ServerKey          []byte
	KDCKey             []byte
	EncType            int32

	// Credential Info (Encrypted)
	CredentialInfo []byte

	// Conditional buffer flags
	ExtraPAC bool // include UPN_DNS_INFO (type 12)
	OldPAC   bool // exclude AttributesInfo (type 17) + RequestorSID (type 18)
}

// NewPAC creates a new PAC with default values
func NewPAC(username, domain string, domainSID *SID, userID, primaryGroup uint32, groups []uint32) *PAC {
	now := time.Now().UTC()
	expiry := now.Add(10 * 365 * 24 * time.Hour) // 10 years

	return &PAC{
		Username:       username,
		Domain:         domain,
		DomainSID:      domainSID,
		UserID:         userID,
		PrimaryGroupID: primaryGroup,
		Groups:         groups,
		LogonTime:      now,
		LogoffTime:     expiry,
		KickOffTime:    expiry,
		EncType:        23, // RC4 by default
	}
}

// DecryptCredentialInfo decrypts the PAC_CREDENTIAL_INFO buffer using the AS-REP key
// Returns the decrypted data (which usually contains NTLM hash / password)
func (p *PAC) DecryptCredentialInfo(key []byte) ([]byte, error) {
	if len(p.CredentialInfo) < 24 { // Version(4) + EType(4) + Data(16+)
		return nil, fmt.Errorf("credential info too short")
	}

	etype := int32(binary.LittleEndian.Uint32(p.CredentialInfo[4:8]))

	// Skip 8 bytes header (Version + EType)
	cipherText := p.CredentialInfo[8:]

	// RC4-HMAC (EType 23) per RFC 4757:
	//   K1 = HMAC-MD5(Key, Usage)
	//   K3 = HMAC-MD5(K1, Checksum)
	//   Plaintext = RC4(K3, Ciphertext[16:])
	if etype == 23 {
		// Checksum is the first 16 bytes, ciphertext follows.
		if len(cipherText) < 16 {
			return nil, fmt.Errorf("ciphertext too short")
		}
		data := cipherText[16:]

		// Key usage 0 is used for PAC server checksum data.
		usage := make([]byte, 4)

		h := hmac.New(md5.New, key)
		h.Write(usage)
		k1Hash := h.Sum(nil)

		h2 := hmac.New(md5.New, k1Hash)
		h2.Write(cipherText[:16]) // Checksum
		k3 := h2.Sum(nil)

		decrypted := make([]byte, len(data))
		rc4Cipher, err := rc4.NewCipher(k3)
		if err != nil {
			return nil, err
		}
		rc4Cipher.XORKeyStream(decrypted, data)
		return decrypted, nil
	}

	return nil, fmt.Errorf("unsupported encryption type: %d", etype)
}

// pacBuffer holds a PAC buffer type and its marshaled data
type pacBuffer struct {
	bufType uint32
	data    []byte
}

// Marshal serializes the PAC to bytes
func (p *PAC) Marshal() ([]byte, error) {
	// Build individual buffers
	logonInfo, err := p.marshalLogonInfo()
	if err != nil {
		return nil, err
	}

	// Always-included buffers
	buffers := []pacBuffer{
		{PACTypeLogonInfo, logonInfo},
		{PACTypeClientInfo, p.marshalClientInfo()},
	}

	// Conditionally include UPN_DNS_INFO (only when ExtraPAC=true)
	// Placed before ATTRIBUTES/REQUESTOR to match Impacket buffer ordering
	if p.ExtraPAC {
		buffers = append(buffers, pacBuffer{PACTypeUPNDNSInfo, p.marshalUPNDNSInfo()})
	}

	// Conditionally include AttributesInfo + RequestorSID (excluded when OldPAC=true)
	if !p.OldPAC {
		buffers = append(buffers,
			pacBuffer{PACTypeAttributesInfo, p.marshalAttributesInfo()},
			pacBuffer{PACTypeRequestorSID, p.marshalRequestorSID()},
		)
	}

	// Signatures always last
	buffers = append(buffers,
		pacBuffer{PACTypeServerChecksum, p.marshalSignature(PACTypeServerChecksum)},
		pacBuffer{PACTypeKDCChecksum, p.marshalSignature(PACTypeKDCChecksum)},
	)

	// Calculate offsets dynamically
	bufferCount := uint32(len(buffers))
	headerSize := 8 + (bufferCount * 16)
	if headerSize%8 != 0 {
		headerSize += 8 - (headerSize % 8)
	}

	offsets := make([]uint64, len(buffers))
	offset := uint64(headerSize)
	for i, b := range buffers {
		offsets[i] = offset
		offset += uint64(len(b.data))
		if offset%8 != 0 {
			offset += 8 - (offset % 8)
		}
	}

	// Build PAC
	var buf bytes.Buffer

	// Header
	binary.Write(&buf, binary.LittleEndian, bufferCount)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // Version

	// Buffer entries
	for i, b := range buffers {
		writeBufferEntry(&buf, b.bufType, uint32(len(b.data)), offsets[i])
	}

	// Pad header
	for buf.Len() < int(headerSize) {
		buf.WriteByte(0)
	}

	// Write buffers with padding
	for i, b := range buffers {
		for buf.Len() < int(offsets[i]) {
			buf.WriteByte(0)
		}
		buf.Write(b.data)
	}

	// Add trailing padding to align to 8 bytes (matches Impacket)
	for buf.Len()%8 != 0 {
		buf.WriteByte(0)
	}

	return buf.Bytes(), nil
}

// marshalUPNDNSInfo creates PAC_UPN_DNS_INFO (type 12)
func (p *PAC) marshalUPNDNSInfo() []byte {
	var buf bytes.Buffer

	// Match Impacket: UPN is lowercased, DNS domain is uppercased
	upn := strings.ToLower(p.Username) + "@" + strings.ToLower(p.Domain)
	dnsDomain := strings.ToUpper(p.Domain)
	samName := p.Username

	upnBytes := utf16le.EncodeStringToBytes(upn)
	dnsBytes := utf16le.EncodeStringToBytes(dnsDomain)
	samBytes := utf16le.EncodeStringToBytes(samName)

	// Build user SID for extended format (domain SID + user RID)
	userSID := &SID{
		Revision:            p.DomainSID.Revision,
		SubAuthorityCount:   p.DomainSID.SubAuthorityCount + 1,
		IdentifierAuthority: p.DomainSID.IdentifierAuthority,
		SubAuthority:        append(append([]uint32{}, p.DomainSID.SubAuthority...), p.UserID),
	}
	var sidBuf bytes.Buffer
	sidBuf.WriteByte(userSID.Revision)
	sidBuf.WriteByte(userSID.SubAuthorityCount)
	sidBuf.Write(userSID.IdentifierAuthority[:])
	for _, sub := range userSID.SubAuthority {
		binary.Write(&sidBuf, binary.LittleEndian, sub)
	}
	sidBytes := sidBuf.Bytes()

	// Flags = 2 (extended format with SamName + SID, matching Impacket)
	flags := uint32(2)

	// Extended header: base (12) + SamNameLength(2) + SamNameOffset(2) + SidLength(2) + SidOffset(2) + padding(2)
	headerSize := uint16(22)

	// Compute data offsets (all relative to start of buffer)
	upnOff := headerSize
	dnsOff := upnOff + uint16(len(upnBytes))
	samOff := dnsOff + uint16(len(dnsBytes))
	// SID must be 4-byte aligned
	sidOff := samOff + uint16(len(samBytes))
	if sidOff%4 != 0 {
		sidOff += 4 - (sidOff % 4)
	}

	// Base header (12 bytes)
	binary.Write(&buf, binary.LittleEndian, uint16(len(upnBytes)))
	binary.Write(&buf, binary.LittleEndian, upnOff)
	binary.Write(&buf, binary.LittleEndian, uint16(len(dnsBytes)))
	binary.Write(&buf, binary.LittleEndian, dnsOff)
	binary.Write(&buf, binary.LittleEndian, flags)

	// Extended fields (10 bytes)
	binary.Write(&buf, binary.LittleEndian, uint16(len(samBytes)))
	binary.Write(&buf, binary.LittleEndian, samOff)
	binary.Write(&buf, binary.LittleEndian, uint16(len(sidBytes)))
	binary.Write(&buf, binary.LittleEndian, sidOff)

	// Padding to headerSize
	for buf.Len() < int(headerSize) {
		buf.WriteByte(0)
	}

	// Data section
	buf.Write(upnBytes)
	buf.Write(dnsBytes)
	buf.Write(samBytes)
	// Pad to SID alignment
	for buf.Len() < int(sidOff) {
		buf.WriteByte(0)
	}
	buf.Write(sidBytes)

	return buf.Bytes()
}

func writeBufferEntry(buf *bytes.Buffer, bufType uint32, size uint32, offset uint64) {
	binary.Write(buf, binary.LittleEndian, bufType)
	binary.Write(buf, binary.LittleEndian, size)
	binary.Write(buf, binary.LittleEndian, offset)
}

// marshalLogonInfo creates KERB_VALIDATION_INFO in NDR format
func (p *PAC) marshalLogonInfo() ([]byte, error) {
	var buf bytes.Buffer

	// NDR Common Header
	buf.Write([]byte{0x01, 0x10, 0x08, 0x00})
	binary.Write(&buf, binary.LittleEndian, uint32(0xCCCCCCCC))

	// Private Header (length placeholder + filler)
	lenPos := buf.Len()
	binary.Write(&buf, binary.LittleEndian, uint32(0))          // Will fill in later
	binary.Write(&buf, binary.LittleEndian, uint32(0xCCCCCCCC)) // Filler (matches Impacket)

	startPos := buf.Len()

	// Top-level pointer referent ID (required for NDR pointer serialization)
	binary.Write(&buf, binary.LittleEndian, uint32(0x0000498c)) // Referent ID

	// KERB_VALIDATION_INFO fixed portion
	writeFileTime(&buf, p.LogonTime) // LogonTime
	writeFileTimeNever(&buf)         // LogoffTime (never)
	writeFileTimeNever(&buf)         // KickOffTime (never)
	writeFileTime(&buf, p.LogonTime) // PasswordLastSet
	writeFileTimeZero(&buf)          // PasswordCanChange (zero = not set)
	writeFileTimeNever(&buf)         // PasswordMustChange (never)

	// String headers (Length, MaxLength, Pointer)
	refID := uint32(0x00020000)

	// EffectiveName (username)
	writeUnicodeStringHeader(&buf, p.Username, &refID)
	// FullName (empty to match Impacket)
	writeUnicodeStringHeader(&buf, "", &refID)
	// LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive (empty)
	for i := 0; i < 4; i++ {
		writeUnicodeStringHeader(&buf, "", &refID)
	}

	// LogonCount, BadPasswordCount
	binary.Write(&buf, binary.LittleEndian, uint16(500))
	binary.Write(&buf, binary.LittleEndian, uint16(0))

	// UserID, PrimaryGroupID
	binary.Write(&buf, binary.LittleEndian, p.UserID)
	binary.Write(&buf, binary.LittleEndian, p.PrimaryGroupID)

	// GroupCount
	binary.Write(&buf, binary.LittleEndian, uint32(len(p.Groups)))
	// GroupIDs pointer
	if len(p.Groups) > 0 {
		binary.Write(&buf, binary.LittleEndian, refID)
		refID++
	} else {
		binary.Write(&buf, binary.LittleEndian, uint32(0))
	}

	// UserFlags
	userFlags := uint32(0)
	if len(p.ExtraSIDs) > 0 {
		userFlags |= LogonExtraSIDs
	}
	binary.Write(&buf, binary.LittleEndian, userFlags)

	// UserSessionKey (16 bytes zeroed)
	buf.Write(make([]byte, 16))

	// LogonServer (empty)
	writeUnicodeStringHeader(&buf, "", &refID)
	// LogonDomainName
	writeUnicodeStringHeader(&buf, p.Domain, &refID)

	// LogonDomainID pointer
	binary.Write(&buf, binary.LittleEndian, refID)
	refID++

	// Reserved1
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// UserAccountControl
	binary.Write(&buf, binary.LittleEndian, uint32(UACNormalAccount|UACDontExpirePassword))

	// SubAuthStatus, LastSuccessfulILogon, LastFailedILogon, FailedILogonCount, Reserved3
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.Write(make([]byte, 16)) // Two FILETIMEs
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// SIDCount
	binary.Write(&buf, binary.LittleEndian, uint32(len(p.ExtraSIDs)))
	// ExtraSIDs pointer
	if len(p.ExtraSIDs) > 0 {
		binary.Write(&buf, binary.LittleEndian, refID)
		refID++
	} else {
		binary.Write(&buf, binary.LittleEndian, uint32(0))
	}

	// ResourceGroupDomainSID (null)
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// ResourceGroupCount
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// ResourceGroupIDs (null)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Now write deferred data

	// EffectiveName content
	writeUnicodeStringContent(&buf, p.Username)
	// FullName content (empty)
	writeUnicodeStringContent(&buf, "")
	// Empty strings: LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive
	for i := 0; i < 4; i++ {
		writeUnicodeStringContent(&buf, "")
	}

	// GroupIDs array
	if len(p.Groups) > 0 {
		binary.Write(&buf, binary.LittleEndian, uint32(len(p.Groups)))
		for _, gid := range p.Groups {
			binary.Write(&buf, binary.LittleEndian, gid)
			binary.Write(&buf, binary.LittleEndian, uint32(SEGroupMandatory|SEGroupEnabledByDefault|SEGroupEnabled))
		}
	}

	// LogonServer content (empty)
	writeUnicodeStringContent(&buf, "")
	// LogonDomainName content
	writeUnicodeStringContent(&buf, p.Domain)

	// LogonDomainID (SID)
	writeSID(&buf, p.DomainSID)

	// ExtraSIDs
	if len(p.ExtraSIDs) > 0 {
		binary.Write(&buf, binary.LittleEndian, uint32(len(p.ExtraSIDs)))
		// Pointers and attributes
		for i := range p.ExtraSIDs {
			binary.Write(&buf, binary.LittleEndian, refID+uint32(i))
			binary.Write(&buf, binary.LittleEndian, uint32(SEGroupMandatory|SEGroupEnabledByDefault|SEGroupEnabled))
		}
		// Actual SIDs
		for _, sid := range p.ExtraSIDs {
			writeSID(&buf, sid)
		}
	}

	// Update length in private header
	data := buf.Bytes()
	objLen := uint32(len(data) - startPos)
	binary.LittleEndian.PutUint32(data[lenPos:], objLen)

	return data, nil
}

func writeFileTime(buf *bytes.Buffer, t time.Time) {
	ft := TimeToFileTime(t)
	binary.Write(buf, binary.LittleEndian, ft.Low)
	binary.Write(buf, binary.LittleEndian, ft.High)
}

func writeFileTimeNever(buf *bytes.Buffer) {
	ft := NeverTime()
	binary.Write(buf, binary.LittleEndian, ft.Low)
	binary.Write(buf, binary.LittleEndian, ft.High)
}

func writeFileTimeZero(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
}

func writeUnicodeStringHeader(buf *bytes.Buffer, s string, refID *uint32) {
	length := uint16(len(s) * 2)
	binary.Write(buf, binary.LittleEndian, length)
	binary.Write(buf, binary.LittleEndian, length)
	// Always write a non-null pointer (even for empty strings) to match Impacket
	binary.Write(buf, binary.LittleEndian, *refID)
	*refID++
}

func writeUnicodeStringContent(buf *bytes.Buffer, s string) {
	// Always write the conformant array header, even for empty strings
	chars := uint32(len(s))
	binary.Write(buf, binary.LittleEndian, chars)     // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, chars)     // ActualCount

	if len(s) == 0 {
		return
	}

	// UTF-16LE
	for _, r := range s {
		binary.Write(buf, binary.LittleEndian, uint16(r))
	}
	// Pad to 4 bytes
	if (len(s)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(s)*2)%4))
	}
}

func writeSID(buf *bytes.Buffer, sid *SID) {
	binary.Write(buf, binary.LittleEndian, uint32(sid.SubAuthorityCount))
	buf.WriteByte(sid.Revision)
	buf.WriteByte(sid.SubAuthorityCount)
	buf.Write(sid.IdentifierAuthority[:])
	for _, sub := range sid.SubAuthority {
		binary.Write(buf, binary.LittleEndian, sub)
	}
}

// marshalClientInfo creates PAC_CLIENT_INFO
func (p *PAC) marshalClientInfo() []byte {
	var buf bytes.Buffer

	ft := TimeToFileTime(p.LogonTime)
	binary.Write(&buf, binary.LittleEndian, ft.Low)
	binary.Write(&buf, binary.LittleEndian, ft.High)

	binary.Write(&buf, binary.LittleEndian, uint16(len(p.Username)*2))

	for _, r := range p.Username {
		binary.Write(&buf, binary.LittleEndian, uint16(r))
	}

	return buf.Bytes()
}

// marshalAttributesInfo creates PAC_ATTRIBUTES_INFO (type 17)
// Per MS-PAC 2.12: Contains flags about PAC request
func (p *PAC) marshalAttributesInfo() []byte {
	var buf bytes.Buffer

	// FlagsLength (in bits) - 2 flags = 2 bits, but minimum size is 32 bits
	binary.Write(&buf, binary.LittleEndian, uint32(2))
	// Flags:
	// 0x00000001 = PAC_WAS_REQUESTED
	// 0x00000002 = PAC_WAS_GIVEN_IMPLICITLY
	binary.Write(&buf, binary.LittleEndian, uint32(0x00000001))

	return buf.Bytes()
}

// marshalRequestorSID creates PAC_REQUESTOR (type 18)
// Per MS-PAC 2.13: Contains the SID of the requesting user
func (p *PAC) marshalRequestorSID() []byte {
	var buf bytes.Buffer

	// Build the user SID (domain SID + user RID)
	userSID := &SID{
		Revision:            p.DomainSID.Revision,
		SubAuthorityCount:   p.DomainSID.SubAuthorityCount + 1,
		IdentifierAuthority: p.DomainSID.IdentifierAuthority,
		SubAuthority:        append(append([]uint32{}, p.DomainSID.SubAuthority...), p.UserID),
	}

	// Write the SID directly (not as NDR pointer, just raw SID bytes)
	buf.WriteByte(userSID.Revision)
	buf.WriteByte(userSID.SubAuthorityCount)
	buf.Write(userSID.IdentifierAuthority[:])
	for _, sub := range userSID.SubAuthority {
		binary.Write(&buf, binary.LittleEndian, sub)
	}

	return buf.Bytes()
}

// marshalSignature creates a signature buffer with zeroed signature
func (p *PAC) marshalSignature(sigType uint32) []byte {
	var buf bytes.Buffer

	checksumType := uint32(ChecksumHMACMD5)
	sigLen := 16

	switch p.EncType {
	case 17:
		checksumType = ChecksumSHA196AES128
		sigLen = 12
	case 18:
		checksumType = ChecksumSHA196AES256
		sigLen = 12
	}

	binary.Write(&buf, binary.LittleEndian, checksumType)
	buf.Write(make([]byte, sigLen))

	return buf.Bytes()
}

// Sign calculates and sets the PAC signatures
func (p *PAC) Sign(serverKey, kdcKey []byte) error {
	p.ServerKey = serverKey
	p.KDCKey = kdcKey

	// Marshal PAC with zeroed signatures
	pacData, err := p.Marshal()
	if err != nil {
		return err
	}

	// Find signature offsets
	serverSigOffset, kdcSigOffset := p.findSignatureOffsets(pacData)

	// Calculate server checksum over PAC data (with zeroed signatures)
	serverSig, err := p.calculateChecksum(pacData, serverKey)
	if err != nil {
		return err
	}

	// Calculate KDC checksum over server signature
	kdcSig, err := p.calculateChecksum(serverSig, kdcKey)
	if err != nil {
		return err
	}

	// Copy signatures into PAC data
	copy(pacData[serverSigOffset+4:], serverSig)
	copy(pacData[kdcSigOffset+4:], kdcSig)

	return nil
}

func (p *PAC) findSignatureOffsets(pacData []byte) (serverOff, kdcOff int) {
	bufferCount := binary.LittleEndian.Uint32(pacData[0:4])

	for i := uint32(0); i < bufferCount; i++ {
		offset := 8 + i*16
		bufType := binary.LittleEndian.Uint32(pacData[offset:])
		bufOffset := binary.LittleEndian.Uint64(pacData[offset+8:])

		switch bufType {
		case PACTypeServerChecksum:
			serverOff = int(bufOffset)
		case PACTypeKDCChecksum:
			kdcOff = int(bufOffset)
		}
	}
	return
}

func (p *PAC) calculateChecksum(data, key []byte) ([]byte, error) {
	switch p.EncType {
	case 17, 18:
		return p.aesChecksum(data, key)
	default:
		return p.hmacMD5Checksum(data, key)
	}
}

// hmacMD5Checksum implements KERB_CHECKSUM_HMAC_MD5 (MS-PAC)
func (p *PAC) hmacMD5Checksum(data, key []byte) ([]byte, error) {
	// KERB_CHECKSUM_HMAC_MD5 algorithm:
	// 1. Ksign = HMAC-MD5(Key, "signaturekey\0")
	// 2. tmp = MD5(usage_le || data)
	// 3. checksum = HMAC-MD5(Ksign, tmp)
	const usage = 17 // PAC checksum key usage

	// Step 1: Derive Ksign
	ksignMac := hmac.New(md5.New, key)
	ksignMac.Write([]byte("signaturekey\x00"))
	ksign := ksignMac.Sum(nil)

	// Step 2: Compute tmp = MD5(usage || data)
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, usage)
	tmpHash := md5.New()
	tmpHash.Write(usageBytes)
	tmpHash.Write(data)
	tmp := tmpHash.Sum(nil)

	// Step 3: checksum = HMAC-MD5(Ksign, tmp)
	mac := hmac.New(md5.New, ksign)
	mac.Write(tmp)
	return mac.Sum(nil), nil
}

// aesChecksum implements HMAC-SHA1-96 for AES
func (p *PAC) aesChecksum(data, key []byte) ([]byte, error) {
	// Simplified - real implementation needs proper key derivation
	mac := hmac.New(md5.New, key) // Placeholder
	mac.Write(data)
	sum := mac.Sum(nil)
	if len(sum) > 12 {
		sum = sum[:12]
	}
	return sum, nil
}

// GetNTHash computes NT hash from password
func GetNTHash(password string) []byte {
	h := md4.New()
	for _, r := range password {
		h.Write([]byte{byte(r), byte(r >> 8)})
	}
	return h.Sum(nil)
}

// ParsePAC parses the PAC data
func ParsePAC(data []byte) (*PAC, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("PAC data too short")
	}

	bufferCount := binary.LittleEndian.Uint32(data[0:4])
	version := binary.LittleEndian.Uint32(data[4:8])

	if version != 0 {
		return nil, fmt.Errorf("invalid PAC version: %d", version)
	}

	p := &PAC{
		EncType: 23, // Default, updated if Signature found
	}

	for i := uint32(0); i < bufferCount; i++ {
		offset := 8 + i*16
		if len(data) < int(offset+16) {
			return nil, fmt.Errorf("PAC header too short")
		}

		bufType := binary.LittleEndian.Uint32(data[offset:])
		bufSize := binary.LittleEndian.Uint32(data[offset+4:])
		bufOffset := binary.LittleEndian.Uint64(data[offset+8:])

		if uint64(len(data)) < bufOffset+uint64(bufSize) {
			continue // Skip invalid buffers
		}

		bufData := data[bufOffset : bufOffset+uint64(bufSize)]

		switch bufType {
		case PACTypeClientInfo:
			p.parseClientInfo(bufData)
		case PACTypeLogonInfo:
			p.parseLogonInfo(bufData)
		case PACTypeCredentialInfo:
			p.CredentialInfo = bufData
		case PACTypeDelegationInfo:
			p.parseDelegationInfo(bufData)
		case PACTypeServerChecksum:
			p.parseChecksum(bufData, true)
		case PACTypeKDCChecksum:
			p.parseChecksum(bufData, false)
		case PACTypeUPNDNSInfo:
			p.parseUPNDNSInfo(bufData)
		case PACTypeAttributesInfo:
			p.parseAttributesInfo(bufData)
		case PACTypeRequestorSID:
			p.parseRequestorSID(bufData)
		}
	}

	return p, nil
}

func (p *PAC) parseClientInfo(data []byte) {
	if len(data) < 10 {
		return
	}
	p.ClientInfoTime = FileTime{
		Low:  binary.LittleEndian.Uint32(data[0:4]),
		High: binary.LittleEndian.Uint32(data[4:8]),
	}.Time()

	nameLen := binary.LittleEndian.Uint16(data[8:10])
	if len(data) >= 10+int(nameLen) {
		nameBytes := data[10 : 10+nameLen]
		p.ClientInfoName = utf16le.DecodeToString(nameBytes)
	}
}

func readFileTime(data []byte, offset int) time.Time {
	if len(data) < offset+8 {
		return time.Time{}
	}
	ft := FileTime{
		Low:  binary.LittleEndian.Uint32(data[offset : offset+4]),
		High: binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
	}
	return ft.Time()
}

func (p *PAC) parseLogonInfo(data []byte) {
	// Skip NDR Header (16 bytes)
	const ndrHeaderSize = 16
	const fixedPartSize = 220 // Size of KERB_VALIDATION_INFO fixed part

	if len(data) < ndrHeaderSize+fixedPartSize {
		return
	}

	// Read timestamps from fixed part
	p.LogonTime = readFileTime(data, ndrHeaderSize+4)
	p.LogoffTime = readFileTime(data, ndrHeaderSize+12)
	p.KickOffTime = readFileTime(data, ndrHeaderSize+20)
	p.PasswordLastSet = readFileTime(data, ndrHeaderSize+28)
	p.PasswordCanChange = readFileTime(data, ndrHeaderSize+36)
	p.PasswordMustChange = readFileTime(data, ndrHeaderSize+44)

	// Read LogonCount, BadPasswordCount
	p.LogonCount = binary.LittleEndian.Uint16(data[ndrHeaderSize+100 : ndrHeaderSize+102])
	p.BadPasswordCount = binary.LittleEndian.Uint16(data[ndrHeaderSize+102 : ndrHeaderSize+104])

	// Read UserID and PrimaryGroupID
	p.UserID = binary.LittleEndian.Uint32(data[ndrHeaderSize+104 : ndrHeaderSize+108])
	p.PrimaryGroupID = binary.LittleEndian.Uint32(data[ndrHeaderSize+108 : ndrHeaderSize+112])

	// Read UserFlags
	p.UserFlags = binary.LittleEndian.Uint32(data[ndrHeaderSize+120 : ndrHeaderSize+124])

	// Read UserSessionKey (16 bytes)
	copy(p.UserSessionKey[:], data[ndrHeaderSize+124:ndrHeaderSize+140])

	// Read UserAccountControl
	p.UserAccountControl = binary.LittleEndian.Uint32(data[ndrHeaderSize+168 : ndrHeaderSize+172])

	// Read SubAuthStatus, LastSuccessfulILogon, LastFailedILogon, FailedILogonCount, Reserved3
	p.SubAuthStatus = binary.LittleEndian.Uint32(data[ndrHeaderSize+172 : ndrHeaderSize+176])
	p.LastSuccessfulILogon = readFileTime(data, ndrHeaderSize+176)
	p.LastFailedILogon = readFileTime(data, ndrHeaderSize+184)
	p.FailedILogonCount = binary.LittleEndian.Uint32(data[ndrHeaderSize+192 : ndrHeaderSize+196])
	p.Reserved3 = binary.LittleEndian.Uint32(data[ndrHeaderSize+196 : ndrHeaderSize+200])

	currentOffset := ndrHeaderSize + fixedPartSize

	// Helper to read NDR conformant unicode string
	readString := func(headerOffset int) string {
		ptr := binary.LittleEndian.Uint32(data[headerOffset+4 : headerOffset+8])
		if ptr != 0 && len(data) >= currentOffset+12 {
			actualCount := binary.LittleEndian.Uint32(data[currentOffset+8 : currentOffset+12])
			dataLen := int(actualCount * 2)
			padded := dataLen
			if padded%4 != 0 {
				padded += 4 - (padded % 4)
			}

			s := ""
			if actualCount > 0 && len(data) >= currentOffset+12+dataLen {
				s = utf16le.DecodeToString(data[currentOffset+12 : currentOffset+12+dataLen])
			}

			currentOffset += 12 + padded
			return s
		}
		return ""
	}

	// 1. EffectiveName (Username)
	if name := readString(ndrHeaderSize + 52); name != "" {
		p.Username = name
	}
	// 2. FullName
	p.FullName = readString(ndrHeaderSize + 60)
	// 3. LogonScript
	p.LogonScript = readString(ndrHeaderSize + 68)
	// 4. ProfilePath
	p.ProfilePath = readString(ndrHeaderSize + 76)
	// 5. HomeDirectory
	p.HomeDirectory = readString(ndrHeaderSize + 84)
	// 6. HomeDirectoryDrive
	p.HomeDirectoryDrive = readString(ndrHeaderSize + 92)

	// Read Groups
	groupCount := binary.LittleEndian.Uint32(data[ndrHeaderSize+112 : ndrHeaderSize+116])
	groupPtr := binary.LittleEndian.Uint32(data[ndrHeaderSize+116 : ndrHeaderSize+120])

	if groupCount > 0 && groupPtr != 0 {
		if len(data) >= currentOffset+4 {
			currentOffset += 4 // MaxCount
			p.Groups = make([]uint32, 0, groupCount)
			p.GroupAttributes = make([]uint32, 0, groupCount)
			for i := uint32(0); i < groupCount; i++ {
				if len(data) < currentOffset+8 {
					break
				}
				rid := binary.LittleEndian.Uint32(data[currentOffset : currentOffset+4])
				attr := binary.LittleEndian.Uint32(data[currentOffset+4 : currentOffset+8])
				p.Groups = append(p.Groups, rid)
				p.GroupAttributes = append(p.GroupAttributes, attr)
				currentOffset += 8
			}
		}
	}

	// Read LogonServer, LogonDomainName
	p.LogonServer = readString(ndrHeaderSize + 140)
	if domain := readString(ndrHeaderSize + 148); domain != "" {
		p.Domain = domain
	}

	// Read LogonDomainID (SID)
	domainIDPtr := binary.LittleEndian.Uint32(data[ndrHeaderSize+156 : ndrHeaderSize+160])
	if domainIDPtr != 0 {
		sid, size, err := ParseNDRSID(data[currentOffset:])
		if err == nil {
			p.DomainSID = sid
			currentOffset += size
		}
	}

	// Read ExtraSIDs
	sidCount := binary.LittleEndian.Uint32(data[ndrHeaderSize+200 : ndrHeaderSize+204])
	sidPtr := binary.LittleEndian.Uint32(data[ndrHeaderSize+204 : ndrHeaderSize+208])

	if sidCount > 0 && sidPtr != 0 {
		if len(data) >= currentOffset+4 {
			currentOffset += 4 // MaxCount

			type sidAttr struct {
				ptr  uint32
				attr uint32
			}
			attrs := make([]sidAttr, 0, sidCount)
			for i := uint32(0); i < sidCount; i++ {
				if len(data) < currentOffset+8 {
					break
				}
				ptr := binary.LittleEndian.Uint32(data[currentOffset : currentOffset+4])
				attr := binary.LittleEndian.Uint32(data[currentOffset+4 : currentOffset+8])
				attrs = append(attrs, sidAttr{ptr, attr})
				currentOffset += 8
			}

			p.ExtraSIDs = make([]*SID, 0, sidCount)
			p.ExtraSIDAttrs = make([]uint32, 0, sidCount)
			for _, sa := range attrs {
				if sa.ptr != 0 {
					sid, size, err := ParseNDRSID(data[currentOffset:])
					if err == nil {
						p.ExtraSIDs = append(p.ExtraSIDs, sid)
						p.ExtraSIDAttrs = append(p.ExtraSIDAttrs, sa.attr)
						currentOffset += size
					}
				}
			}
		}
	}
}

func (p *PAC) parseDelegationInfo(data []byte) {
	// S4U_DELEGATION_INFO is NDR encoded
	// Simplified parsing: skip NDR headers, read S4U2proxyTarget and TransitedServices
	if len(data) < 20 {
		return
	}
	// Skip NDR common header (16 bytes) + referent ID (4 bytes)
	offset := 20

	// Read S4U2proxyTarget (RPC_UNICODE_STRING: Length, MaxLength, Pointer)
	if len(data) < offset+12 {
		return
	}
	targetLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 8 // Skip Length, MaxLength, Pointer
	// Read TransitedListSize
	if len(data) < offset+4 {
		return
	}
	transitedCount := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	// Skip TransitedServices pointer
	offset += 4

	// Deferred: S4U2proxyTarget string content
	if len(data) < offset+12 {
		return
	}
	offset += 8 // MaxCount + Offset
	actualCount := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	strLen := int(actualCount * 2)
	if int(targetLen) < strLen {
		strLen = int(targetLen)
	}
	if len(data) >= offset+strLen {
		p.S4U2ProxyTarget = utf16le.DecodeToString(data[offset : offset+strLen])
		offset += int(actualCount * 2)
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	// Deferred: TransitedServices array
	if transitedCount > 0 && len(data) >= offset+4 {
		maxCount := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
		// Read array of RPC_UNICODE_STRING headers
		type ustr struct {
			length uint16
			ptr    uint32
		}
		headers := make([]ustr, 0, maxCount)
		for i := uint32(0); i < maxCount; i++ {
			if len(data) < offset+8 {
				break
			}
			l := binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 4 // Length + MaxLength
			ptr := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			headers = append(headers, ustr{l, ptr})
		}
		// Read deferred string data
		for _, h := range headers {
			if h.ptr == 0 || len(data) < offset+12 {
				continue
			}
			offset += 8 // MaxCount + Offset
			ac := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			sl := int(ac * 2)
			if int(h.length) < sl {
				sl = int(h.length)
			}
			if len(data) >= offset+sl {
				p.TransitedServices = append(p.TransitedServices, utf16le.DecodeToString(data[offset:offset+sl]))
				offset += int(ac * 2)
				if offset%4 != 0 {
					offset += 4 - (offset % 4)
				}
			}
		}
	}
}

func (p *PAC) parseChecksum(data []byte, isServer bool) {
	if len(data) < 4 {
		return
	}
	checksumType := binary.LittleEndian.Uint32(data[0:4])
	checksumData := data[4:]
	if isServer {
		p.ServerChecksumType = checksumType
		p.ServerChecksumData = checksumData
		p.ServerKey = data
	} else {
		p.KDCChecksumType = checksumType
		p.KDCChecksumData = checksumData
		p.KDCKey = data
	}
}

func (p *PAC) parseUPNDNSInfo(data []byte) {
	if len(data) < 12 {
		return
	}
	upnLen := binary.LittleEndian.Uint16(data[0:2])
	upnOffset := binary.LittleEndian.Uint16(data[2:4])
	dnsLen := binary.LittleEndian.Uint16(data[4:6])
	dnsOffset := binary.LittleEndian.Uint16(data[6:8])
	p.UPNFlags = binary.LittleEndian.Uint32(data[8:12])

	if int(upnOffset)+int(upnLen) <= len(data) {
		p.UPN = utf16le.DecodeToString(data[upnOffset : upnOffset+upnLen])
	}
	if int(dnsOffset)+int(dnsLen) <= len(data) {
		p.DNSDomainName = utf16le.DecodeToString(data[dnsOffset : dnsOffset+dnsLen])
	}

	// Extended format (flags & 0x2): SamAccountName and SID after the base header
	if p.UPNFlags&0x2 != 0 && len(data) >= 24 {
		samLen := binary.LittleEndian.Uint16(data[12:14])
		samOffset := binary.LittleEndian.Uint16(data[14:16])
		sidLen := binary.LittleEndian.Uint16(data[16:18])
		sidOffset := binary.LittleEndian.Uint16(data[18:20])

		if int(samOffset)+int(samLen) <= len(data) {
			p.SamAccountName = utf16le.DecodeToString(data[samOffset : samOffset+samLen])
		}
		if sidLen > 0 && int(sidOffset)+int(sidLen) <= len(data) {
			sid, _, err := parseRawSID(data[sidOffset : sidOffset+sidLen])
			if err == nil {
				p.UPNSid = sid
			}
		}
	}
}

func (p *PAC) parseAttributesInfo(data []byte) {
	if len(data) < 8 {
		return
	}
	// FlagsLength at offset 0 (uint32, in bits)
	// Flags at offset 4 (uint32)
	p.AttributesFlags = binary.LittleEndian.Uint32(data[4:8])
}

func (p *PAC) parseRequestorSID(data []byte) {
	if len(data) < 8 {
		return
	}
	sid, _, err := parseRawSID(data)
	if err == nil {
		p.RequestorSID = sid
	}
}

// parseRawSID parses a raw SID (not NDR wrapped)
func parseRawSID(data []byte) (*SID, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("data too short for raw SID")
	}
	revision := data[0]
	subAuthCount := data[1]
	var auth [6]byte
	copy(auth[:], data[2:8])

	size := 8 + int(subAuthCount)*4
	if len(data) < size {
		return nil, 0, fmt.Errorf("data too short for SID sub authorities")
	}

	subs := make([]uint32, subAuthCount)
	for i := 0; i < int(subAuthCount); i++ {
		subs[i] = binary.LittleEndian.Uint32(data[8+i*4 : 8+(i+1)*4])
	}

	return &SID{
		Revision:            revision,
		SubAuthorityCount:   subAuthCount,
		IdentifierAuthority: auth,
		SubAuthority:        subs,
	}, size, nil
}

// ParseNDRSID parses a SID from NDR format (Count + SID)
func ParseNDRSID(data []byte) (*SID, int, error) {
	if len(data) < 12 {
		return nil, 0, fmt.Errorf("data too short for SID")
	}
	// NDR Conformant Array Size (4 bytes) - ignored but consumed
	// _ := binary.LittleEndian.Uint32(data[0:4])

	revision := data[4]
	subAuthCount := data[5]
	var auth [6]byte
	copy(auth[:], data[6:12])

	size := 12 + int(subAuthCount)*4
	if len(data) < size {
		return nil, 0, fmt.Errorf("data too short for SID sub authorities")
	}

	subs := make([]uint32, subAuthCount)
	for i := 0; i < int(subAuthCount); i++ {
		subs[i] = binary.LittleEndian.Uint32(data[12+i*4 : 12+(i+1)*4])
	}

	return &SID{
		Revision:            revision,
		SubAuthorityCount:   subAuthCount,
		IdentifierAuthority: auth,
		SubAuthority:        subs,
	}, size, nil
}

func (ft FileTime) Time() time.Time {
	ns := int64(ft.High)<<32 | int64(ft.Low)
	// Windows epoch 1601-01-01
	const epochDiff = 116444736000000000
	if ns == 0 || ns == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	return time.Unix(0, (ns-epochDiff)*100).UTC()
}
