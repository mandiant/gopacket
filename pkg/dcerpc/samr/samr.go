package samr

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
)

// SAMR UUID: 12345778-1234-ABCD-EF00-0123456789AC v1.0
var UUID = [16]byte{
	0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
	0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac,
}

const MajorVersion = 1
const MinorVersion = 0

// Operation numbers
const (
	OpSamrCloseHandle                   = 1
	OpSamrLookupDomainInSamServer       = 5
	OpSamrEnumerateDomainsInSamServer   = 6
	OpSamrOpenDomain                    = 7
	OpSamrLookupNamesInDomain           = 17
	OpSamrOpenUser                      = 34
	OpSamrDeleteUser                    = 35
	OpSamrSetInformationUser            = 37
	OpSamrChangePasswordUser            = 38
	OpSamrCreateUser2InDomain           = 50
	OpSamrUnicodeChangePasswordUser2    = 55
	OpSamrConnect5                      = 64
)

// SAM Account type flags (for SamrCreateUser2InDomain AccountType parameter)
const (
	USER_NORMAL_ACCOUNT            = 0x00000010
	USER_INTERDOMAIN_TRUST_ACCOUNT = 0x00000040
	USER_WORKSTATION_TRUST_ACCOUNT = 0x00000080
	USER_SERVER_TRUST_ACCOUNT      = 0x00000100
)

// User information levels for SamrSetInformationUser
const (
	UserInternal1Information = 18 // ENCRYPTED_NT_OWF_PASSWORD (16 bytes) - for password reset with hash
	UserInternal5Information = 24 // SAMPR_ENCRYPTED_USER_PASSWORD (516 bytes) + PasswordExpired
)

// SamrClient provides SAMR RPC operations for managing domain accounts.
type SamrClient struct {
	client       *dcerpc.Client
	sessionKey   []byte
	serverHandle []byte // 20 bytes
	domainHandle []byte // 20 bytes
	domainSID    []byte // variable length binary SID
}

// NewSamrClient creates a new SAMR client wrapping the given DCE/RPC client.
// The sessionKey is the SMB session key needed for password encryption.
func NewSamrClient(client *dcerpc.Client, sessionKey []byte) *SamrClient {
	return &SamrClient{
		client:     client,
		sessionKey: sessionKey,
	}
}

// call wraps the RPC call to automatically use authenticated calls when needed.
// For RPC over TCP with Packet Privacy, we need CallAuthAuto.
// For RPC over SMB (named pipe), the regular Call works because encryption is at SMB level.
func (s *SamrClient) call(opNum uint16, payload []byte) ([]byte, error) {
	if s.client.Authenticated {
		return s.client.CallAuthAuto(opNum, payload)
	}
	return s.client.Call(opNum, payload)
}

// Connect performs SamrConnect5 to obtain a server handle.
func (s *SamrClient) Connect() error {
	buf := new(bytes.Buffer)

	// ServerName: [in] unique pointer to RPC_UNICODE_STRING
	// Pointer (referent ID)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
	// MaxCount, Offset, ActualCount for conformant varying string "\\"
	writeRPCUnicodeStr(buf, "\\")

	// DesiredAccess: SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN
	binary.Write(buf, binary.LittleEndian, uint32(0x30))

	// InVersion: 1
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// InRevisionInfo (SAMPR_REVISION_INFO union, switched on InVersion=1):
	// SAMPR_REVISION_INFO_V1: Revision(4) + SupportedFeatures(4)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // union discriminant
	binary.Write(buf, binary.LittleEndian, uint32(3)) // Revision = 3
	binary.Write(buf, binary.LittleEndian, uint32(0)) // SupportedFeatures = 0

	resp, err := s.call(OpSamrConnect5, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrConnect5 failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SAMR: Connect5 response (%d bytes): %x", len(resp), resp)
	}

	// Response: OutVersion(4) + OutRevisionInfo(union disc 4 + body 8) + ServerHandle(20) + ReturnValue(4)
	// Total minimum: 4 + 4 + 8 + 20 + 4 = 40
	if len(resp) < 40 {
		return fmt.Errorf("SamrConnect5 response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrConnect5 failed: NTSTATUS 0x%08x", retVal)
	}

	// ServerHandle is 20 bytes before the return value
	s.serverHandle = make([]byte, 20)
	copy(s.serverHandle, resp[len(resp)-24:len(resp)-4])

	if build.Debug {
		log.Printf("[D] SAMR: Connect5 succeeded, handle: %x", s.serverHandle)
	}

	return nil
}

// OpenDomain looks up the domain by name and opens a handle to it.
func (s *SamrClient) OpenDomain(domainName string) error {
	// Step 1: LookupDomainInSamServer to get domain SID
	if err := s.lookupDomain(domainName); err != nil {
		return err
	}

	// Step 2: OpenDomain with the SID
	return s.openDomain()
}

// lookupDomain performs SamrLookupDomainInSamServer.
func (s *SamrClient) lookupDomain(domainName string) error {
	buf := new(bytes.Buffer)

	// ServerHandle (20 bytes)
	buf.Write(s.serverHandle)

	// Name: RPC_UNICODE_STRING (inline: Length, MaximumLength, pointer)
	utf16Name := utf16.Encode([]rune(domainName))
	nameLen := uint16(len(utf16Name) * 2)
	binary.Write(buf, binary.LittleEndian, nameLen)            // Length (bytes)
	binary.Write(buf, binary.LittleEndian, nameLen)            // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Buffer pointer (referent)

	// Deferred: conformant varying array
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))              // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // ActualCount
	for _, c := range utf16Name {
		binary.Write(buf, binary.LittleEndian, c)
	}
	// Align to 4 bytes
	if (len(utf16Name)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(utf16Name)*2)%4))
	}

	resp, err := s.call(OpSamrLookupDomainInSamServer, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrLookupDomainInSamServer failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SAMR: LookupDomain response (%d bytes): %x", len(resp), resp)
	}

	// Response: DomainId (unique pointer + SID) + ReturnValue(4)
	if len(resp) < 8 {
		return fmt.Errorf("LookupDomain response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrLookupDomainInSamServer failed: NTSTATUS 0x%08x", retVal)
	}

	// Parse: pointer(4) + SubAuthorityCount as MaxCount(4) + SID body
	offset := 0
	ptr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	if ptr == 0 {
		return fmt.Errorf("NULL domain SID returned")
	}

	// MaxCount (conformant array of SubAuthorities)
	subAuthCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// SID: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority[](4*count)
	sidLen := 8 + int(subAuthCount)*4
	if offset+sidLen > len(resp)-4 {
		return fmt.Errorf("LookupDomain response too short for SID data")
	}

	s.domainSID = make([]byte, sidLen)
	copy(s.domainSID, resp[offset:offset+sidLen])

	if build.Debug {
		log.Printf("[D] SAMR: Domain SID: %x", s.domainSID)
	}

	return nil
}

// openDomain performs SamrOpenDomain.
func (s *SamrClient) openDomain() error {
	buf := new(bytes.Buffer)

	// ServerHandle (20 bytes)
	buf.Write(s.serverHandle)

	// DesiredAccess: MAXIMUM_ALLOWED
	binary.Write(buf, binary.LittleEndian, uint32(0x02000000))

	// DomainId: RPC_SID (conformant: MaxCount + SID body)
	subAuthCount := int(s.domainSID[1])
	binary.Write(buf, binary.LittleEndian, uint32(subAuthCount)) // MaxCount
	buf.Write(s.domainSID)

	resp, err := s.call(OpSamrOpenDomain, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrOpenDomain failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SAMR: OpenDomain response (%d bytes): %x", len(resp), resp)
	}

	// Response: DomainHandle(20) + ReturnValue(4)
	if len(resp) < 24 {
		return fmt.Errorf("OpenDomain response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != 0 {
		return fmt.Errorf("SamrOpenDomain failed: NTSTATUS 0x%08x", retVal)
	}

	s.domainHandle = make([]byte, 20)
	copy(s.domainHandle, resp[:20])

	if build.Debug {
		log.Printf("[D] SAMR: OpenDomain succeeded, handle: %x", s.domainHandle)
	}

	return nil
}

// CreateComputer creates a machine account and sets its password.
func (s *SamrClient) CreateComputer(name, password string) error {
	// Ensure name ends with $
	if !strings.HasSuffix(name, "$") {
		name = name + "$"
	}

	userHandle, _, err := s.createUser2(name, USER_WORKSTATION_TRUST_ACCOUNT)
	if err != nil {
		return err
	}
	defer s.closeHandle(userHandle)

	// Set password
	if err := s.setPassword(userHandle, password); err != nil {
		return fmt.Errorf("failed to set password: %v", err)
	}

	return nil
}

// AccountExists checks if a machine account exists by name.
func (s *SamrClient) AccountExists(name string) bool {
	if !strings.HasSuffix(name, "$") {
		name = name + "$"
	}
	_, err := s.lookupName(name)
	return err == nil
}

// SetComputerPassword sets the password on an existing machine account.
func (s *SamrClient) SetComputerPassword(name, password string) error {
	if !strings.HasSuffix(name, "$") {
		name = name + "$"
	}

	// Lookup the name to get the RID
	rid, err := s.lookupName(name)
	if err != nil {
		return fmt.Errorf("failed to lookup computer account: %v", err)
	}

	// Open the user by RID
	userHandle, err := s.openUser(rid)
	if err != nil {
		return err
	}
	defer s.closeHandle(userHandle)

	// Set password
	if err := s.setPassword(userHandle, password); err != nil {
		return fmt.Errorf("failed to set password: %v", err)
	}

	return nil
}

// DeleteComputer deletes a machine account by name.
func (s *SamrClient) DeleteComputer(name string) error {
	if !strings.HasSuffix(name, "$") {
		name = name + "$"
	}

	// Lookup the name to get the RID
	rid, err := s.lookupName(name)
	if err != nil {
		return fmt.Errorf("failed to lookup computer account: %v", err)
	}

	// Open the user by RID
	userHandle, err := s.openUser(rid)
	if err != nil {
		return err
	}

	// Delete the user
	return s.deleteUser(userHandle)
}

// createUser2 performs SamrCreateUser2InDomain.
func (s *SamrClient) createUser2(name string, accountType uint32) ([]byte, uint32, error) {
	buf := new(bytes.Buffer)

	// DomainHandle (20 bytes)
	buf.Write(s.domainHandle)

	// Name: RPC_UNICODE_STRING
	utf16Name := utf16.Encode([]rune(name))
	nameLen := uint16(len(utf16Name) * 2)
	binary.Write(buf, binary.LittleEndian, nameLen)            // Length
	binary.Write(buf, binary.LittleEndian, nameLen)            // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Buffer pointer

	// Deferred string data
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))              // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // ActualCount
	for _, c := range utf16Name {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if (len(utf16Name)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(utf16Name)*2)%4))
	}

	// AccountType
	binary.Write(buf, binary.LittleEndian, accountType)

	// DesiredAccess: MAXIMUM_ALLOWED
	binary.Write(buf, binary.LittleEndian, uint32(0x000F07FF))

	resp, err := s.call(OpSamrCreateUser2InDomain, buf.Bytes())
	if err != nil {
		return nil, 0, fmt.Errorf("SamrCreateUser2InDomain failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SAMR: CreateUser2 response (%d bytes): %x", len(resp), resp)
	}

	// Response: UserHandle(20) + GrantedAccess(4) + RelativeId(4) + ReturnValue(4)
	if len(resp) < 32 {
		return nil, 0, fmt.Errorf("CreateUser2 response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[28:32])
	if retVal != 0 {
		return nil, 0, fmt.Errorf("SamrCreateUser2InDomain failed: NTSTATUS 0x%08x", retVal)
	}

	userHandle := make([]byte, 20)
	copy(userHandle, resp[:20])
	rid := binary.LittleEndian.Uint32(resp[24:28])

	if build.Debug {
		log.Printf("[D] SAMR: CreateUser2 succeeded, RID: %d, handle: %x", rid, userHandle)
	}

	return userHandle, rid, nil
}

// setPassword performs SamrSetInformationUser (OpNum 37) with level 18 (UserInternal1Information).
// This is used for admin password reset and encrypts the NT hash with the session key.
func (s *SamrClient) setPassword(userHandle []byte, password string) error {
	// Compute NT hash of the new password
	newNTHash := ntHash(password)

	// Encrypt NT hash with session key using SAM DES encryption
	encryptedNT, err := samEncryptNTLMHash(newNTHash, s.sessionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt NT hash: %v", err)
	}

	buf := new(bytes.Buffer)

	// UserHandle (20 bytes)
	buf.Write(userHandle)

	// UserInformationClass: uint16 = 18 (UserInternal1Information)
	binary.Write(buf, binary.LittleEndian, uint16(UserInternal1Information))

	// SAMPR_USER_INFO_BUFFER union tag: uint16 = 18
	binary.Write(buf, binary.LittleEndian, uint16(UserInternal1Information))

	// SAMPR_USER_INTERNAL1_INFORMATION structure:
	// EncryptedNtOwfPassword: ENCRYPTED_LM_OWF_PASSWORD (16 bytes)
	buf.Write(encryptedNT)

	// EncryptedLmOwfPassword: ENCRYPTED_LM_OWF_PASSWORD (16 bytes) - zeroed/NULL
	buf.Write(make([]byte, 16))

	// NtPasswordPresent: UCHAR = 1
	buf.WriteByte(1)

	// LmPasswordPresent: UCHAR = 0
	buf.WriteByte(0)

	// PasswordExpired: UCHAR = 0 (don't expire)
	buf.WriteByte(0)

	if build.Debug {
		log.Printf("[D] SAMR: SetInformationUser payload: %d bytes, first 32 bytes: %x", buf.Len(), buf.Bytes()[:32])
	}

	resp, err := s.call(OpSamrSetInformationUser, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrSetInformationUser failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("SetInformationUser response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrSetInformationUser failed: NTSTATUS 0x%08x", retVal)
	}

	if build.Debug {
		log.Printf("[D] SAMR: SetInformationUser succeeded (password set)")
	}

	return nil
}

// samEncryptNTLMHash encrypts an NT hash using the session key with SAM DES encryption.
// This is the same algorithm as encryptOldNtHashWithNewNtHash but uses the session key.
func samEncryptNTLMHash(hashToEncrypt []byte, key []byte) ([]byte, error) {
	if len(hashToEncrypt) != 16 || len(key) < 14 {
		return nil, fmt.Errorf("invalid hash or key length")
	}

	block1 := hashToEncrypt[:8]
	block2 := hashToEncrypt[8:16]

	key1 := transformKey(key[:7])
	key2 := transformKey(key[7:14])

	cipher1, err := des.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	cipher2, err := des.NewCipher(key2)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, 16)
	cipher1.Encrypt(encrypted[:8], block1)
	cipher2.Encrypt(encrypted[8:], block2)

	return encrypted, nil
}

// lookupName performs SamrLookupNamesInDomain to resolve a name to a RID.
func (s *SamrClient) lookupName(name string) (uint32, error) {
	buf := new(bytes.Buffer)

	// DomainHandle (20 bytes)
	buf.Write(s.domainHandle)

	// Count (number of names to look up)
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// Names: conformant varying array [size_is(1000), length_is(Count)]
	// Conformant: MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(1000))
	// Varying: Offset + ActualCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, uint32(1)) // ActualCount

	// Inline RPC_UNICODE_STRING element(s)
	utf16Name := utf16.Encode([]rune(name))
	nameLen := uint16(len(utf16Name) * 2)
	binary.Write(buf, binary.LittleEndian, nameLen)            // Length (bytes, no null)
	binary.Write(buf, binary.LittleEndian, nameLen)            // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Buffer pointer (referent ID)

	// Deferred: LPWSTR referent data for element 0
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // MaxCount (chars)
	binary.Write(buf, binary.LittleEndian, uint32(0))              // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16Name))) // ActualCount (chars)
	for _, c := range utf16Name {
		binary.Write(buf, binary.LittleEndian, c)
	}
	if (len(utf16Name)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(utf16Name)*2)%4))
	}

	resp, err := s.call(OpSamrLookupNamesInDomain, buf.Bytes())
	if err != nil {
		return 0, fmt.Errorf("SamrLookupNamesInDomain failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SAMR: LookupNames response (%d bytes): %x", len(resp), resp)
	}

	// Response: RelativeIds (SAMPR_ULONG_ARRAY) + Use (SAMPR_ULONG_ARRAY) + ReturnValue(4)
	// SAMPR_ULONG_ARRAY: Count(4) + Pointer(4) + [MaxCount(4) + Elements...]
	if len(resp) < 4 {
		return 0, fmt.Errorf("LookupNames response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return 0, fmt.Errorf("SamrLookupNamesInDomain failed: NTSTATUS 0x%08x", retVal)
	}

	// Parse RelativeIds array
	offset := 0
	// Count
	count := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	if count == 0 {
		return 0, fmt.Errorf("name not found: %s", name)
	}
	// Pointer
	offset += 4
	// MaxCount
	offset += 4
	// First element (RID)
	if offset+4 > len(resp) {
		return 0, fmt.Errorf("LookupNames response truncated")
	}
	rid := binary.LittleEndian.Uint32(resp[offset:])

	if build.Debug {
		log.Printf("[D] SAMR: LookupNames: %s -> RID %d", name, rid)
	}

	return rid, nil
}

// openUser performs SamrOpenUser.
func (s *SamrClient) openUser(rid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// DomainHandle (20 bytes)
	buf.Write(s.domainHandle)

	// DesiredAccess: MAXIMUM_ALLOWED
	binary.Write(buf, binary.LittleEndian, uint32(0xF03FF))

	// UserId (RID)
	binary.Write(buf, binary.LittleEndian, rid)

	resp, err := s.call(OpSamrOpenUser, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrOpenUser failed: %v", err)
	}

	// Response: UserHandle(20) + ReturnValue(4)
	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenUser response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrOpenUser failed: NTSTATUS 0x%08x", retVal)
	}

	userHandle := make([]byte, 20)
	copy(userHandle, resp[:20])

	return userHandle, nil
}

// deleteUser performs SamrDeleteUser.
func (s *SamrClient) deleteUser(userHandle []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(userHandle)

	resp, err := s.call(OpSamrDeleteUser, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrDeleteUser failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("DeleteUser response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrDeleteUser failed: NTSTATUS 0x%08x", retVal)
	}

	if build.Debug {
		log.Printf("[D] SAMR: DeleteUser succeeded")
	}

	return nil
}

// closeHandle performs SamrCloseHandle.
func (s *SamrClient) closeHandle(handle []byte) {
	buf := new(bytes.Buffer)
	buf.Write(handle)
	s.call(OpSamrCloseHandle, buf.Bytes())
}

// Close closes the domain and server handles.
func (s *SamrClient) Close() {
	if s.domainHandle != nil {
		s.closeHandle(s.domainHandle)
		s.domainHandle = nil
	}
	if s.serverHandle != nil {
		s.closeHandle(s.serverHandle)
		s.serverHandle = nil
	}
}

// encryptPassword encrypts the password for SAMR SetInformationUser level 26.
// Format: random_padding[512 - pwdLen] + pwd_utf16le[pwdLen] + length_le32[4] = 516 bytes
// Encryption: MD5(sessionKey + length_bytes) -> RC4 key -> encrypt 516 bytes
// encryptPassword builds a 516-byte SAMPR_ENCRYPTED_USER_PASSWORD buffer.
// Encryption: RC4 with key = SessionKey (16 bytes)
func encryptPassword(pwdUTF16LE []byte, sessionKey []byte) ([]byte, error) {
	pwdLen := len(pwdUTF16LE)
	if pwdLen > 512 {
		return nil, fmt.Errorf("password too long")
	}

	// Build 516-byte plaintext buffer (SAMPR_USER_PASSWORD)
	buffer := make([]byte, 516)

	// Fill with random padding (left side)
	if _, err := rand.Read(buffer[:512-pwdLen]); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %v", err)
	}

	// Copy password right-justified in the 512-byte region
	copy(buffer[512-pwdLen:512], pwdUTF16LE)

	// Append password length as uint32 LE (bytes of UTF-16LE password)
	binary.LittleEndian.PutUint32(buffer[512:], uint32(pwdLen))

	// RC4 encrypt with session key directly
	cipher, err := rc4.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create RC4 cipher: %v", err)
	}
	cipher.XORKeyStream(buffer, buffer)

	return buffer, nil
}

// SetUserPassword sets/resets the password on a user account using admin privileges.
// This is the "reset" operation that doesn't require knowing the old password.
func (s *SamrClient) SetUserPassword(username, newPassword string) error {
	// Lookup the name to get the RID
	rid, err := s.lookupName(username)
	if err != nil {
		return fmt.Errorf("failed to lookup user account: %v", err)
	}

	// Open the user by RID
	userHandle, err := s.openUser(rid)
	if err != nil {
		return err
	}
	defer s.closeHandle(userHandle)

	// Set password using SamrSetInformationUser (level 24)
	if err := s.setPassword(userHandle, newPassword); err != nil {
		return fmt.Errorf("failed to set password: %v", err)
	}

	return nil
}

// ChangeUserPassword changes a user's password using the old password for authentication.
// This uses SamrUnicodeChangePasswordUser2 which doesn't require a user handle.
// Structure order per MS-SAMR 3.1.5.10.3:
//   ServerName, UserName, NewPasswordEncryptedWithOldNt, OldNtOwfPasswordEncryptedWithNewNt,
//   LmPresent, NewPasswordEncryptedWithOldLm, OldLmOwfPasswordEncryptedWithNewNt
func (s *SamrClient) ChangeUserPassword(username, oldPassword, newPassword string) error {
	// Pre-compute encrypted values
	newPwdEncrypted, err := encryptPasswordWithOldNtHash(newPassword, oldPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt new password: %v", err)
	}

	oldNtEncrypted, err := encryptOldNtHashWithNewNtHash(oldPassword, newPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt old NT hash: %v", err)
	}

	buf := new(bytes.Buffer)

	// ServerName: [in] PRPC_UNICODE_STRING (unique pointer)
	// NULL pointer for ServerName
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// UserName: [in] RPC_UNICODE_STRING (embedded struct)
	// For embedded structs, the deferred data (string buffer) follows immediately
	utf16User := utf16.Encode([]rune(username))
	userLen := uint16(len(utf16User) * 2)
	binary.Write(buf, binary.LittleEndian, userLen)            // Length (bytes)
	binary.Write(buf, binary.LittleEndian, userLen)            // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Buffer pointer (referent ID)

	// UserName string data - immediately follows the embedded struct
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16User))) // MaxCount (chars)
	binary.Write(buf, binary.LittleEndian, uint32(0))              // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(utf16User))) // ActualCount (chars)
	for _, c := range utf16User {
		binary.Write(buf, binary.LittleEndian, c)
	}
	// Align to 4 bytes
	if (len(utf16User)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(utf16User)*2)%4))
	}

	// NewPasswordEncryptedWithOldNt: [in] PSAMPR_ENCRYPTED_USER_PASSWORD (unique pointer)
	// Pointer followed immediately by its data (per Impacket's serialization)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020004)) // Pointer referent ID
	buf.Write(newPwdEncrypted)                                 // 516 bytes of encrypted data

	// OldNtOwfPasswordEncryptedWithNewNt: [in] PENCRYPTED_NT_OWF_PASSWORD (unique pointer)
	// Pointer followed immediately by its data
	binary.Write(buf, binary.LittleEndian, uint32(0x00020008)) // Pointer referent ID
	buf.Write(oldNtEncrypted)                                  // 16 bytes of encrypted hash

	// LmPresent: [in] UCHAR
	buf.WriteByte(0) // 0 = no LM

	// Alignment padding to 4 bytes
	buf.Write(make([]byte, 3))

	// NewPasswordEncryptedWithOldLm: [in] PSAMPR_ENCRYPTED_USER_PASSWORD (unique pointer)
	// NULL since LmPresent=0
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// OldLmOwfPasswordEncryptedWithNewNt: [in] PENCRYPTED_LM_OWF_PASSWORD (unique pointer)
	// NULL since LmPresent=0
	binary.Write(buf, binary.LittleEndian, uint32(0))

	if build.Debug {
		log.Printf("[D] SAMR: UnicodeChangePasswordUser2 payload: %d bytes", buf.Len())
	}

	resp, err := s.call(OpSamrUnicodeChangePasswordUser2, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrUnicodeChangePasswordUser2 failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("UnicodeChangePasswordUser2 response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrUnicodeChangePasswordUser2 failed: NTSTATUS 0x%08x", retVal)
	}

	if build.Debug {
		log.Printf("[D] SAMR: UnicodeChangePasswordUser2 succeeded")
	}

	return nil
}

// UserExists checks if a user account exists by name.
func (s *SamrClient) UserExists(name string) bool {
	_, err := s.lookupName(name)
	return err == nil
}

// LookupName looks up a username and returns its RID. Exported for external use.
func (s *SamrClient) LookupName(name string) (uint32, error) {
	return s.lookupName(name)
}

// OpenUser opens a user handle by RID. Exported for external use.
func (s *SamrClient) OpenUser(rid uint32) ([]byte, error) {
	return s.openUser(rid)
}

// CloseHandle closes a handle. Exported for external use.
func (s *SamrClient) CloseHandle(handle []byte) {
	s.closeHandle(handle)
}

// writeRPCUnicodeStr writes a conformant varying UTF-16LE string (with null terminator).
// Used for simple string pointers (not RPC_UNICODE_STRING struct).
func writeRPCUnicodeStr(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // null terminator
	charCount := uint32(len(utf16Chars))

	binary.Write(buf, binary.LittleEndian, charCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, charCount) // ActualCount
	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}
	// Align to 4 bytes
	dataLen := int(charCount) * 2
	if dataLen%4 != 0 {
		buf.Write(make([]byte, 4-dataLen%4))
	}
}

// ntHash computes the NT hash (MD4 of UTF-16LE password).
func ntHash(password string) []byte {
	utf16Pwd := utf16.Encode([]rune(password))
	pwdBytes := make([]byte, len(utf16Pwd)*2)
	for i, c := range utf16Pwd {
		binary.LittleEndian.PutUint16(pwdBytes[i*2:], c)
	}
	h := md4.New()
	h.Write(pwdBytes)
	return h.Sum(nil)
}

// encryptPasswordWithOldNtHash encrypts new password with old NT hash for SamrUnicodeChangePasswordUser2.
// Returns 516-byte SAMPR_ENCRYPTED_USER_PASSWORD.
func encryptPasswordWithOldNtHash(newPassword, oldPassword string) ([]byte, error) {
	// Encode new password as UTF-16LE
	utf16Pwd := utf16.Encode([]rune(newPassword))
	pwdBytes := make([]byte, len(utf16Pwd)*2)
	for i, c := range utf16Pwd {
		binary.LittleEndian.PutUint16(pwdBytes[i*2:], c)
	}

	pwdLen := len(pwdBytes)
	if pwdLen > 512 {
		return nil, fmt.Errorf("password too long")
	}

	// Build 516-byte plaintext buffer
	buffer := make([]byte, 516)

	// Fill with random padding (left side)
	if _, err := rand.Read(buffer[:512-pwdLen]); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %v", err)
	}

	// Copy password right-justified in the 512-byte region
	copy(buffer[512-pwdLen:512], pwdBytes)

	// Append password length as uint32 LE
	binary.LittleEndian.PutUint32(buffer[512:], uint32(pwdLen))

	// RC4 encrypt with old NT hash
	oldNT := ntHash(oldPassword)
	cipher, err := rc4.NewCipher(oldNT)
	if err != nil {
		return nil, fmt.Errorf("failed to create RC4 cipher: %v", err)
	}
	cipher.XORKeyStream(buffer, buffer)

	return buffer, nil
}

// encryptOldNtHashWithNewNtHash encrypts old NT hash with new NT hash using SAM DES encryption.
// Returns 16-byte ENCRYPTED_NT_OWF_PASSWORD per MS-SAMR Section 2.2.11.1.1.
func encryptOldNtHashWithNewNtHash(oldPassword, newPassword string) ([]byte, error) {
	oldNT := ntHash(oldPassword)
	newNT := ntHash(newPassword)

	// SAM DES encryption: split into two 8-byte blocks, encrypt each with derived DES keys
	block1 := oldNT[:8]
	block2 := oldNT[8:16]

	// Transform 7 bytes of key into 8-byte DES key
	key1 := transformKey(newNT[:7])
	key2 := transformKey(newNT[7:14])

	cipher1, err := des.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %v", err)
	}
	cipher2, err := des.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %v", err)
	}

	encrypted := make([]byte, 16)
	cipher1.Encrypt(encrypted[:8], block1)
	cipher2.Encrypt(encrypted[8:], block2)

	return encrypted, nil
}

// transformKey expands 7 bytes into an 8-byte DES key with parity bits.
// This is the standard SAM key transformation per MS-SAMR.
func transformKey(key7 []byte) []byte {
	key := make([]byte, 8)
	key[0] = key7[0] >> 1
	key[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
	key[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
	key[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
	key[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
	key[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
	key[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
	key[7] = key7[6] & 0x7F

	// Set parity bits (odd parity)
	for i := range key {
		key[i] = (key[i] << 1) | parityBit(key[i])
	}
	return key
}

// parityBit computes odd parity for a byte.
func parityBit(b byte) byte {
	// Count set bits
	count := 0
	for b > 0 {
		count += int(b & 1)
		b >>= 1
	}
	// Return 1 if count is even (to make odd parity)
	if count%2 == 0 {
		return 1
	}
	return 0
}

// Operation numbers for user enumeration
const (
	OpSamrEnumerateUsersInDomain   = 13
	OpSamrEnumerateGroupsInDomain  = 11
	OpSamrEnumerateAliasesInDomain = 15
	OpSamrGetAliasMembership       = 16
	OpSamrLookupIdsInDomain        = 18
	OpSamrOpenGroup                = 19
	OpSamrAddMemberToGroup         = 22
	OpSamrRemoveMemberFromGroup    = 24
	OpSamrGetMembersInGroup        = 25
	OpSamrOpenAlias                = 27
	OpSamrAddMemberToAlias         = 31
	OpSamrRemoveMemberFromAlias    = 32
	OpSamrGetMembersInAlias        = 33
	OpSamrGetGroupsForUser         = 39
	OpSamrSetInformationUser2      = 58
	OpSamrRidToSid                 = 65
)

// DomainUser represents a user in the domain
type DomainUser struct {
	Name string
	RID  uint32
}

// EnumerateDomainUsers returns all users in the domain.
func (s *SamrClient) EnumerateDomainUsers() ([]DomainUser, error) {
	return s.EnumerateDomainUsersByType(0)
}

// EnumerateDomainUsersByType returns users matching the given account type filter.
// Pass 0 for all accounts, USER_NORMAL_ACCOUNT for regular users,
// USER_WORKSTATION_TRUST_ACCOUNT for computers, etc.
func (s *SamrClient) EnumerateDomainUsersByType(accountType uint32) ([]DomainUser, error) {
	var users []DomainUser
	var resumeHandle uint32 = 0

	for {
		buf := new(bytes.Buffer)

		// DomainHandle (20 bytes)
		buf.Write(s.domainHandle)

		// EnumerationContext (resume handle)
		binary.Write(buf, binary.LittleEndian, resumeHandle)

		// UserAccountControl filter
		binary.Write(buf, binary.LittleEndian, accountType)

		// PreferredMaximumLength
		binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF))

		resp, err := s.call(OpSamrEnumerateUsersInDomain, buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("SamrEnumerateUsersInDomain failed: %v", err)
		}

		if build.Debug {
			log.Printf("[D] SAMR: EnumerateUsers response (%d bytes)", len(resp))
		}

		// Response format:
		// EnumerationContext (4 bytes)
		// Buffer (pointer + SAMPR_ENUMERATION_BUFFER)
		// CountReturned (4 bytes)
		// ReturnValue (4 bytes)

		if len(resp) < 16 {
			return nil, fmt.Errorf("EnumerateUsers response too short (%d bytes)", len(resp))
		}

		// Get return value (last 4 bytes)
		retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])

		// STATUS_MORE_ENTRIES = 0x00000105
		// STATUS_SUCCESS = 0x00000000
		if retVal != 0 && retVal != 0x00000105 {
			return nil, fmt.Errorf("SamrEnumerateUsersInDomain failed: NTSTATUS 0x%08x", retVal)
		}

		// Parse response
		offset := 0

		// EnumerationContext (new resume handle)
		resumeHandle = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// Buffer pointer
		bufPtr := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		if bufPtr == 0 {
			break // No more data
		}

		// EntriesRead (count of users in this batch)
		entriesRead := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		// Buffer pointer (referent)
		offset += 4

		// MaxCount (conformant array size)
		offset += 4

		// Parse user entries
		for i := uint32(0); i < entriesRead; i++ {
			if offset+12 > len(resp)-4 {
				break
			}

			// RelativeId (RID)
			rid := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			// Name: RPC_UNICODE_STRING (Length, MaxLength, pointer)
			nameLen := binary.LittleEndian.Uint16(resp[offset:])
			offset += 2
			offset += 2 // MaxLength
			offset += 4 // Pointer (will be dereferenced later)

			users = append(users, DomainUser{
				RID:  rid,
				Name: "", // Will be filled in later
			})
			_ = nameLen
		}

		// Now parse the deferred string data
		// The string data follows the array of structures
		for i := range users {
			if offset+12 > len(resp)-4 {
				break
			}

			// MaxCount
			maxCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			// Offset in array
			offset += 4
			// ActualCount
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			if actualCount > maxCount || actualCount > 1000 {
				continue
			}

			// Read UTF-16LE characters
			nameBytes := resp[offset : offset+int(actualCount)*2]
			offset += int(actualCount) * 2
			// Align to 4 bytes
			if (int(actualCount)*2)%4 != 0 {
				offset += 4 - (int(actualCount)*2)%4
			}

			// Convert UTF-16LE to string
			name := decodeUTF16LE(nameBytes)
			users[i].Name = name
		}

		// CountReturned is at len(resp)-8
		// ReturnValue is at len(resp)-4

		// If no more entries, stop
		if retVal == 0 {
			break
		}
	}

	return users, nil
}

// decodeUTF16LE converts UTF-16LE bytes to a Go string
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

// Operation numbers for additional SAMR operations
const (
	OpSamrQueryInformationUser2 = 47
)

// User information class levels
const (
	UserAllInformation = 21
)

// UserAccountControl flags (SAMR specific - different from ADS_UF flags)
// See MS-SAMR 2.2.1.12 USER_ACCOUNT_CONTROL Codes
const (
	USER_ACCOUNT_DISABLED       = 0x00000001
	USER_PASSWORD_NOT_REQUIRED  = 0x00000004
	USER_DONT_EXPIRE_PASSWORD   = 0x00000200 // Note: different from ADS_UF_DONT_EXPIRE_PASSWD (0x10000)
)

// UserAllInfo contains all user information
type UserAllInfo struct {
	LastLogon             int64
	LastLogoff            int64
	PasswordLastSet       int64
	AccountExpires        int64
	PasswordCanChange     int64
	PasswordMustChange    int64
	UserName              string
	FullName              string
	HomeDirectory         string
	HomeDirectoryDrive    string
	ScriptPath            string
	ProfilePath           string
	AdminComment          string
	WorkStations          string
	UserComment           string
	Parameters            string
	PrimaryGroupID        uint32
	UserAccountControl    uint32
	CountryCode           uint16
	CodePage              uint16
	BadPasswordCount      uint16
	LogonCount            uint16
}

// QueryUserInfo queries detailed information about a user
func (s *SamrClient) QueryUserInfo(userHandle []byte) (*UserAllInfo, error) {
	buf := new(bytes.Buffer)

	// UserHandle (20 bytes)
	buf.Write(userHandle)

	// UserInformationClass: UserAllInformation = 21
	binary.Write(buf, binary.LittleEndian, uint16(UserAllInformation))

	resp, err := s.call(OpSamrQueryInformationUser2, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrQueryInformationUser2 failed: %v", err)
	}

	if len(resp) < 200 {
		return nil, fmt.Errorf("QueryUserInfo response too short (%d bytes)", len(resp))
	}

	// Check return value (last 4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrQueryInformationUser2 failed: NTSTATUS 0x%08x", retVal)
	}

	if build.Debug {
		log.Printf("[D] SAMR: QueryUserInfo response (%d bytes)", len(resp))
	}

	info := &UserAllInfo{}

	// Response structure:
	// - Buffer pointer (4 bytes, unique pointer)
	// - Union discriminant (2 bytes, padded to 4)
	// - SAMPR_USER_ALL_INFORMATION structure
	// - Deferred data (strings, blobs)
	// - Return value (4 bytes)

	offset := 0

	// Buffer pointer
	offset += 4

	// Union discriminant (padded to 4 bytes)
	offset += 4

	// SAMPR_USER_ALL_INFORMATION structure
	// 6 LARGE_INTEGER values (8 bytes each) = 48 bytes
	// LastLogon
	info.LastLogon = int64(binary.LittleEndian.Uint64(resp[offset:]))
	offset += 8
	// LastLogoff
	info.LastLogoff = int64(binary.LittleEndian.Uint64(resp[offset:]))
	offset += 8
	// PasswordLastSet
	info.PasswordLastSet = int64(binary.LittleEndian.Uint64(resp[offset:]))
	offset += 8
	// AccountExpires
	info.AccountExpires = int64(binary.LittleEndian.Uint64(resp[offset:]))
	offset += 8
	// PasswordCanChange
	info.PasswordCanChange = int64(binary.LittleEndian.Uint64(resp[offset:]))
	offset += 8
	// PasswordMustChange
	info.PasswordMustChange = int64(binary.LittleEndian.Uint64(resp[offset:]))
	offset += 8

	// Track ALL RPC_UNICODE_STRING fields with their pointers
	// Deferred data is serialized in the order pointers appear
	type stringField struct {
		name   string
		length uint16
		hasPtr bool
	}
	var fields []stringField

	// Helper to read RPC_UNICODE_STRING and add to fields
	readStringField := func(name string) {
		length := binary.LittleEndian.Uint16(resp[offset:])
		ptr := binary.LittleEndian.Uint32(resp[offset+4:])
		fields = append(fields, stringField{name, length, ptr != 0})
		offset += 8
	}

	// UserName (index 0)
	readStringField("UserName")
	// FullName (index 1)
	readStringField("FullName")
	// HomeDirectory (index 2)
	readStringField("HomeDirectory")
	// HomeDirectoryDrive (index 3)
	readStringField("HomeDirectoryDrive")
	// ScriptPath (index 4)
	readStringField("ScriptPath")
	// ProfilePath (index 5)
	readStringField("ProfilePath")
	// AdminComment (index 6)
	readStringField("AdminComment")
	// WorkStations (index 7)
	readStringField("WorkStations")
	// UserComment (index 8)
	readStringField("UserComment")
	// Parameters (index 9)
	readStringField("Parameters")

	// 2 RPC_SHORT_BLOB fields (8 bytes each: Length 2, MaxLength 2, pointer 4)
	// LmOwfPassword
	lmBlobHasPtr := binary.LittleEndian.Uint32(resp[offset+4:]) != 0
	offset += 8
	// NtOwfPassword
	ntBlobHasPtr := binary.LittleEndian.Uint32(resp[offset+4:]) != 0
	offset += 8

	// PrivateData RPC_UNICODE_STRING (index 10)
	readStringField("PrivateData")

	// SecurityDescriptor (SAMPR_SR_SECURITY_DESCRIPTOR: Length 4, pointer 4)
	secDescHasPtr := binary.LittleEndian.Uint32(resp[offset+4:]) != 0
	offset += 8

	// UserId (4 bytes)
	offset += 4
	// PrimaryGroupId (4 bytes)
	info.PrimaryGroupID = binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	// UserAccountControl (4 bytes)
	info.UserAccountControl = binary.LittleEndian.Uint32(resp[offset:])
	if build.Debug {
		log.Printf("[D] SAMR: UserAccountControl=0x%08x, PrimaryGroupID=%d", info.UserAccountControl, info.PrimaryGroupID)
	}
	offset += 4
	// WhichFields (4 bytes)
	offset += 4

	// LogonHours (SAMPR_LOGON_HOURS: UnitsPerWeek 2, padding 2, pointer 4)
	logonHoursHasPtr := binary.LittleEndian.Uint32(resp[offset+4:]) != 0
	offset += 8

	// BadPasswordCount (2 bytes)
	info.BadPasswordCount = binary.LittleEndian.Uint16(resp[offset:])
	offset += 2
	// LogonCount (2 bytes)
	info.LogonCount = binary.LittleEndian.Uint16(resp[offset:])
	offset += 2
	// CountryCode (2 bytes)
	info.CountryCode = binary.LittleEndian.Uint16(resp[offset:])
	offset += 2
	// CodePage (2 bytes)
	info.CodePage = binary.LittleEndian.Uint16(resp[offset:])
	offset += 2

	// 4 boolean bytes
	// LmPasswordPresent, NtPasswordPresent, PasswordExpired, PrivateDataSensitive
	offset += 4

	// Now parse deferred data in order
	// Strings come first (in field order), then blobs
	// IMPORTANT: Even if length=0, if hasPtr=true there's still deferred data (empty array)
	stringValues := make(map[string]string)
	for _, f := range fields {
		if f.hasPtr {
			var val string
			val, offset = readNDRString(resp, offset)
			stringValues[f.name] = val
		}
	}

	// Skip blobs
	if lmBlobHasPtr {
		offset += 16 // 16 bytes for LM hash
	}
	if ntBlobHasPtr {
		offset += 16 // 16 bytes for NT hash
	}
	if secDescHasPtr {
		// Security descriptor - variable length, skip MaxCount(4) + data
		if offset+4 <= len(resp) {
			secLen := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4 + int(secLen)
		}
	}
	if logonHoursHasPtr {
		// LogonHours - 21 bytes (168 bits / 8)
		offset += 21
	}

	// Extract all string fields
	info.UserName = stringValues["UserName"]
	info.FullName = stringValues["FullName"]
	info.HomeDirectory = stringValues["HomeDirectory"]
	info.HomeDirectoryDrive = stringValues["HomeDirectoryDrive"]
	info.ScriptPath = stringValues["ScriptPath"]
	info.ProfilePath = stringValues["ProfilePath"]
	info.AdminComment = stringValues["AdminComment"]
	info.WorkStations = stringValues["WorkStations"]
	info.UserComment = stringValues["UserComment"]
	info.Parameters = stringValues["Parameters"]

	return info, nil
}

// readNDRString reads a conformant varying string from NDR buffer
func readNDRString(data []byte, offset int) (string, int) {
	if offset+12 > len(data) {
		return "", offset
	}

	// MaxCount (4 bytes)
	maxCount := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	// Offset (4 bytes) - usually 0
	offset += 4
	// ActualCount (4 bytes)
	actualCount := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if actualCount > maxCount || actualCount > 10000 {
		return "", offset
	}

	strLen := int(actualCount) * 2 // UTF-16LE
	if offset+strLen > len(data) {
		return "", offset
	}

	str := decodeUTF16LE(data[offset : offset+strLen])
	offset += strLen

	// Align to 4 bytes
	if strLen%4 != 0 {
		offset += 4 - (strLen % 4)
	}

	return str, offset
}


// DomainSID returns the raw binary domain SID.
func (s *SamrClient) DomainSID() []byte {
	return s.domainSID
}

// DomainHandle returns the current domain handle.
func (s *SamrClient) DomainHandle() []byte {
	return s.domainHandle
}

// OpenBuiltinDomain opens the "Builtin" domain handle.
// GetDomainHandle returns the current domain handle.
func (s *SamrClient) GetDomainHandle() []byte {
	return s.domainHandle
}

// After calling this, domainHandle points to the Builtin domain.
// Save and restore the previous domainHandle/domainSID if you need both.
func (s *SamrClient) OpenBuiltinDomain() ([]byte, []byte, error) {
	// Save current state
	savedHandle := s.domainHandle
	savedSID := s.domainSID

	// Lookup and open "Builtin" domain
	if err := s.lookupDomain("Builtin"); err != nil {
		s.domainHandle = savedHandle
		s.domainSID = savedSID
		return nil, nil, fmt.Errorf("failed to lookup Builtin domain: %v", err)
	}
	if err := s.openDomain(); err != nil {
		s.domainHandle = savedHandle
		s.domainSID = savedSID
		return nil, nil, fmt.Errorf("failed to open Builtin domain: %v", err)
	}

	builtinHandle := s.domainHandle
	builtinSID := s.domainSID

	// Restore original state
	s.domainHandle = savedHandle
	s.domainSID = savedSID

	return builtinHandle, builtinSID, nil
}

// EnumerateDomainGroups returns all groups in the domain (OpNum 11).
func (s *SamrClient) EnumerateDomainGroups() ([]DomainUser, error) {
	return s.enumerateEntities(OpSamrEnumerateGroupsInDomain, false)
}

// EnumerateDomainAliases returns all aliases in the domain (OpNum 15).
func (s *SamrClient) EnumerateDomainAliases(domainHandle []byte) ([]DomainUser, error) {
	return s.enumerateEntitiesWithHandle(OpSamrEnumerateAliasesInDomain, domainHandle)
}

// enumerateEntities is a generic enumerator for groups/aliases (no account type filter).
func (s *SamrClient) enumerateEntities(opNum uint16, _ bool) ([]DomainUser, error) {
	return s.enumerateEntitiesWithHandle(opNum, s.domainHandle)
}

// enumerateEntitiesWithHandle enumerates entities using a specific domain handle.
func (s *SamrClient) enumerateEntitiesWithHandle(opNum uint16, domainHandle []byte) ([]DomainUser, error) {
	var entities []DomainUser
	var resumeHandle uint32 = 0

	for {
		buf := new(bytes.Buffer)
		buf.Write(domainHandle)
		binary.Write(buf, binary.LittleEndian, resumeHandle)
		binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF))

		resp, err := s.call(opNum, buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("enumerate (opnum %d) failed: %v", opNum, err)
		}

		if len(resp) < 16 {
			return nil, fmt.Errorf("enumerate response too short (%d bytes)", len(resp))
		}

		retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if retVal != 0 && retVal != 0x00000105 {
			return nil, fmt.Errorf("enumerate failed: NTSTATUS 0x%08x", retVal)
		}

		offset := 0
		resumeHandle = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		bufPtr := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		if bufPtr == 0 {
			break
		}

		entriesRead := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		offset += 4 // Buffer referent
		offset += 4 // MaxCount

		batch := make([]DomainUser, entriesRead)
		for i := uint32(0); i < entriesRead; i++ {
			if offset+12 > len(resp)-4 {
				break
			}
			rid := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			offset += 2 // Length
			offset += 2 // MaxLength
			offset += 4 // Pointer
			batch[i].RID = rid
		}

		for i := range batch {
			if offset+12 > len(resp)-4 {
				break
			}
			maxCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4
			offset += 4 // Offset
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			if actualCount > maxCount || actualCount > 1000 {
				continue
			}

			nameBytes := resp[offset : offset+int(actualCount)*2]
			offset += int(actualCount) * 2
			if (int(actualCount)*2)%4 != 0 {
				offset += 4 - (int(actualCount)*2)%4
			}

			batch[i].Name = decodeUTF16LE(nameBytes)
		}

		entities = append(entities, batch...)

		if retVal == 0 {
			break
		}
	}

	return entities, nil
}

// OpenGroup opens a group by RID and returns its handle.
func (s *SamrClient) OpenGroup(rid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(s.domainHandle)
	binary.Write(buf, binary.LittleEndian, uint32(0x02000000)) // MAXIMUM_ALLOWED
	binary.Write(buf, binary.LittleEndian, rid)

	resp, err := s.call(OpSamrOpenGroup, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrOpenGroup failed: %v", err)
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenGroup response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrOpenGroup failed: NTSTATUS 0x%08x", retVal)
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// GetMembersInGroup returns the member RIDs and attributes of a group.
func (s *SamrClient) GetMembersInGroup(groupHandle []byte) ([]uint32, error) {
	buf := new(bytes.Buffer)
	buf.Write(groupHandle)

	resp, err := s.call(OpSamrGetMembersInGroup, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrGetMembersInGroup failed: %v", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("GetMembersInGroup response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrGetMembersInGroup failed: NTSTATUS 0x%08x", retVal)
	}

	// Response: Members pointer (4) -> MemberCount (4) + Members pointer (4) + Attributes pointer (4)
	// Then deferred: MaxCount (4) + RIDs... then MaxCount (4) + Attributes...
	offset := 0
	membersPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if membersPtr == 0 {
		return nil, nil
	}

	memberCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	offset += 4 // Members array pointer
	offset += 4 // Attributes array pointer

	if memberCount == 0 {
		return nil, nil
	}

	// Deferred: Members array (MaxCount + RIDs)
	offset += 4 // MaxCount
	rids := make([]uint32, memberCount)
	for i := uint32(0); i < memberCount; i++ {
		if offset+4 > len(resp)-4 {
			break
		}
		rids[i] = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
	}

	return rids, nil
}

// AddMemberToGroup adds a member RID to a group with default attributes.
func (s *SamrClient) AddMemberToGroup(groupHandle []byte, rid uint32) error {
	buf := new(bytes.Buffer)
	buf.Write(groupHandle)
	binary.Write(buf, binary.LittleEndian, rid)
	binary.Write(buf, binary.LittleEndian, uint32(0x00000007)) // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

	resp, err := s.call(OpSamrAddMemberToGroup, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrAddMemberToGroup failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("AddMemberToGroup response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrAddMemberToGroup failed: NTSTATUS 0x%08x", retVal)
	}
	return nil
}

// RemoveMemberFromGroup removes a member RID from a group.
func (s *SamrClient) RemoveMemberFromGroup(groupHandle []byte, rid uint32) error {
	buf := new(bytes.Buffer)
	buf.Write(groupHandle)
	binary.Write(buf, binary.LittleEndian, rid)

	resp, err := s.call(OpSamrRemoveMemberFromGroup, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrRemoveMemberFromGroup failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("RemoveMemberFromGroup response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrRemoveMemberFromGroup failed: NTSTATUS 0x%08x", retVal)
	}
	return nil
}

// OpenAlias opens an alias (local group) by RID and returns its handle.
func (s *SamrClient) OpenAlias(domainHandle []byte, rid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(domainHandle)
	binary.Write(buf, binary.LittleEndian, uint32(0x02000000)) // MAXIMUM_ALLOWED
	binary.Write(buf, binary.LittleEndian, rid)

	resp, err := s.call(OpSamrOpenAlias, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrOpenAlias failed: %v", err)
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenAlias response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrOpenAlias failed: NTSTATUS 0x%08x", retVal)
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// GetMembersInAlias returns the SIDs of members in an alias (local group).
func (s *SamrClient) GetMembersInAlias(aliasHandle []byte) ([][]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(aliasHandle)

	resp, err := s.call(OpSamrGetMembersInAlias, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrGetMembersInAlias failed: %v", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("GetMembersInAlias response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrGetMembersInAlias failed: NTSTATUS 0x%08x", retVal)
	}

	// Response: SAMPR_PSID_ARRAY { Count(4), Sids pointer(4) }
	// Deferred: MaxCount(4) + array of SID pointers, then deferred SID data
	offset := 0
	memberCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	sidsPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if sidsPtr == 0 || memberCount == 0 {
		return nil, nil
	}

	// MaxCount
	offset += 4

	// Array of SID pointers
	sidPtrs := make([]uint32, memberCount)
	for i := uint32(0); i < memberCount; i++ {
		if offset+4 > len(resp)-4 {
			break
		}
		sidPtrs[i] = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
	}

	// Deferred SID data
	var sids [][]byte
	for i := uint32(0); i < memberCount; i++ {
		if sidPtrs[i] == 0 {
			sids = append(sids, nil)
			continue
		}
		if offset+4 > len(resp)-4 {
			break
		}
		// Each SID: MaxCount(4) + SID body (Revision(1) + SubAuthCount(1) + Auth(6) + SubAuth[]*4)
		subAuthCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		sidLen := 8 + int(subAuthCount)*4
		if offset+sidLen > len(resp)-4 {
			break
		}

		sid := make([]byte, sidLen)
		copy(sid, resp[offset:offset+sidLen])
		offset += sidLen
		sids = append(sids, sid)
	}

	return sids, nil
}

// AddMemberToAlias adds a SID to an alias (local group).
func (s *SamrClient) AddMemberToAlias(aliasHandle []byte, sid []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(aliasHandle)

	// MemberId: RPC_SID (conformant: MaxCount + SID body)
	subAuthCount := int(sid[1])
	binary.Write(buf, binary.LittleEndian, uint32(subAuthCount))
	buf.Write(sid)

	resp, err := s.call(OpSamrAddMemberToAlias, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrAddMemberToAlias failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("AddMemberToAlias response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrAddMemberToAlias failed: NTSTATUS 0x%08x", retVal)
	}
	return nil
}

// RemoveMemberFromAlias removes a SID from an alias (local group).
func (s *SamrClient) RemoveMemberFromAlias(aliasHandle []byte, sid []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(aliasHandle)

	// MemberId: RPC_SID (conformant: MaxCount + SID body)
	subAuthCount := int(sid[1])
	binary.Write(buf, binary.LittleEndian, uint32(subAuthCount))
	buf.Write(sid)

	resp, err := s.call(OpSamrRemoveMemberFromAlias, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrRemoveMemberFromAlias failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("RemoveMemberFromAlias response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrRemoveMemberFromAlias failed: NTSTATUS 0x%08x", retVal)
	}
	return nil
}

// GetGroupsForUser returns the group RIDs that a user belongs to.
func (s *SamrClient) GetGroupsForUser(userHandle []byte) ([]uint32, error) {
	buf := new(bytes.Buffer)
	buf.Write(userHandle)

	resp, err := s.call(OpSamrGetGroupsForUser, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrGetGroupsForUser failed: %v", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("GetGroupsForUser response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrGetGroupsForUser failed: NTSTATUS 0x%08x", retVal)
	}

	// Response: Groups pointer(4) -> MembershipCount(4) + Groups pointer(4)
	// Deferred: MaxCount(4) + array of GROUP_MEMBERSHIP (RID(4) + Attributes(4))
	offset := 0
	groupsPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if groupsPtr == 0 {
		return nil, nil
	}

	membershipCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	offset += 4 // Groups array pointer

	if membershipCount == 0 {
		return nil, nil
	}

	offset += 4 // MaxCount
	rids := make([]uint32, membershipCount)
	for i := uint32(0); i < membershipCount; i++ {
		if offset+8 > len(resp)-4 {
			break
		}
		rids[i] = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		offset += 4 // Attributes
	}

	return rids, nil
}

// GetAliasMembership returns alias RIDs that a set of SIDs belong to.
func (s *SamrClient) GetAliasMembership(domainHandle []byte, sids [][]byte) ([]uint32, error) {
	buf := new(bytes.Buffer)
	buf.Write(domainHandle)

	// SidArray: Count(4) + Sids pointer(4)
	binary.Write(buf, binary.LittleEndian, uint32(len(sids)))
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Sids pointer

	// Conformant array MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(sids)))

	// Array of SID pointers
	for i := range sids {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020004+i*4))
	}

	// Deferred SID data
	for _, sid := range sids {
		subAuthCount := int(sid[1])
		binary.Write(buf, binary.LittleEndian, uint32(subAuthCount))
		buf.Write(sid)
	}

	resp, err := s.call(OpSamrGetAliasMembership, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrGetAliasMembership failed: %v", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("GetAliasMembership response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrGetAliasMembership failed: NTSTATUS 0x%08x", retVal)
	}

	// Response: Membership (SAMPR_ULONG_ARRAY): Count(4) + Pointer(4)
	// Deferred: MaxCount(4) + RIDs...
	offset := 0
	count := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	ptr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if ptr == 0 || count == 0 {
		return nil, nil
	}

	offset += 4 // MaxCount
	rids := make([]uint32, count)
	for i := uint32(0); i < count; i++ {
		if offset+4 > len(resp)-4 {
			break
		}
		rids[i] = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
	}

	return rids, nil
}

// LookupIds resolves an array of RIDs to names within the current domain.
func (s *SamrClient) LookupIds(rids []uint32) ([]string, error) {
	return s.LookupIdsInDomain(s.domainHandle, rids)
}

// LookupIdsInDomain resolves RIDs to names within a specific domain handle.
func (s *SamrClient) LookupIdsInDomain(domainHandle []byte, rids []uint32) ([]string, error) {
	buf := new(bytes.Buffer)
	buf.Write(domainHandle)

	// Count
	binary.Write(buf, binary.LittleEndian, uint32(len(rids)))

	// RelativeIds: conformant varying array [size_is(1000), length_is(Count)]
	binary.Write(buf, binary.LittleEndian, uint32(1000))       // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))           // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(rids)))   // ActualCount

	for _, rid := range rids {
		binary.Write(buf, binary.LittleEndian, rid)
	}

	resp, err := s.call(OpSamrLookupIdsInDomain, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("SamrLookupIdsInDomain failed: %v", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("LookupIds response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("SamrLookupIdsInDomain failed: NTSTATUS 0x%08x", retVal)
	}

	// Response: Names (SAMPR_RETURNED_USTRING_ARRAY): Count(4) + Element pointer(4)
	// Deferred: MaxCount(4) + array of RPC_UNICODE_STRING, then deferred string data
	// Then Use array (SAMPR_ULONG_ARRAY)
	offset := 0
	nameCount := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	namesPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	names := make([]string, len(rids))

	if namesPtr == 0 || nameCount == 0 {
		return names, nil
	}

	// MaxCount
	offset += 4

	// Array of RPC_UNICODE_STRING (Length(2) + MaxLength(2) + Pointer(4))
	type stringEntry struct {
		length uint16
		ptr    uint32
	}
	entries := make([]stringEntry, nameCount)
	for i := uint32(0); i < nameCount; i++ {
		if offset+8 > len(resp)-4 {
			break
		}
		entries[i].length = binary.LittleEndian.Uint16(resp[offset:])
		offset += 2
		offset += 2 // MaxLength
		entries[i].ptr = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
	}

	// Deferred string data
	for i := uint32(0); i < nameCount; i++ {
		if entries[i].ptr == 0 {
			continue
		}
		if offset+12 > len(resp)-4 {
			break
		}
		var val string
		val, offset = readNDRString(resp, offset)
		if int(i) < len(names) {
			names[i] = val
		}
	}

	return names, nil
}

// RidToSid converts a RID to a full SID using the domain SID.
func (s *SamrClient) RidToSid(rid uint32) []byte {
	// Build SID by appending the RID to the domain SID
	sid := make([]byte, len(s.domainSID)+4)
	copy(sid, s.domainSID)
	// Increment SubAuthorityCount
	sid[1]++
	// Append RID
	binary.LittleEndian.PutUint32(sid[len(s.domainSID):], rid)
	return sid
}

// SetUserAccountControl sets the UserAccountControl value on a user handle.
// Uses SamrSetInformationUser2 (OpNum 58) with UserControlInformation (level 16).
func (s *SamrClient) SetUserAccountControl(userHandle []byte, uac uint32) error {
	buf := new(bytes.Buffer)
	buf.Write(userHandle)

	// UserInformationClass: 16 (UserControlInformation)
	binary.Write(buf, binary.LittleEndian, uint16(16))

	// Union tag: 16
	binary.Write(buf, binary.LittleEndian, uint16(16))

	// USER_CONTROL_INFORMATION: UserAccountControl (ULONG)
	binary.Write(buf, binary.LittleEndian, uac)

	resp, err := s.call(OpSamrSetInformationUser2, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SamrSetInformationUser2 failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("SetUserAccountControl response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SamrSetInformationUser2 failed: NTSTATUS 0x%08x", retVal)
	}

	return nil
}

// LookupNameInDomain looks up a name in a specific domain handle.
func (s *SamrClient) LookupNameInDomain(domainHandle []byte, name string) (uint32, error) {
	// Save and swap domain handle
	saved := s.domainHandle
	s.domainHandle = domainHandle
	rid, err := s.lookupName(name)
	s.domainHandle = saved
	return rid, err
}

// CreateUser2 creates a user account in the domain. Exported wrapper.
func (s *SamrClient) CreateUser2(name string, accountType uint32) ([]byte, uint32, error) {
	return s.createUser2(name, accountType)
}

// SetPassword sets the password on a user handle. Exported wrapper.
func (s *SamrClient) SetPassword(userHandle []byte, password string) error {
	return s.setPassword(userHandle, password)
}

// DeleteUser deletes a user by handle. Exported wrapper.
func (s *SamrClient) DeleteUser(userHandle []byte) error {
	return s.deleteUser(userHandle)
}

// FormatSID converts a raw binary SID to its string representation (S-1-5-...).
func FormatSID(sid []byte) string {
	if len(sid) < 8 {
		return fmt.Sprintf("(invalid SID: %x)", sid)
	}
	revision := sid[0]
	subAuthCount := int(sid[1])

	// IdentifierAuthority (6 bytes, big-endian)
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

// EnumerateDomains returns all domains in the SAM server
func (s *SamrClient) EnumerateDomains() ([]string, error) {
	var domains []string
	var resumeHandle uint32 = 0

	for {
		buf := new(bytes.Buffer)

		// ServerHandle (20 bytes)
		buf.Write(s.serverHandle)

		// EnumerationContext (resume handle)
		binary.Write(buf, binary.LittleEndian, resumeHandle)

		// PreferredMaximumLength
		binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF))

		resp, err := s.call(OpSamrEnumerateDomainsInSamServer, buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("SamrEnumerateDomainsInSamServer failed: %v", err)
		}

		if len(resp) < 16 {
			return nil, fmt.Errorf("EnumerateDomains response too short")
		}

		// Get return value (last 4 bytes)
		retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if retVal != 0 && retVal != 0x00000105 {
			return nil, fmt.Errorf("SamrEnumerateDomainsInSamServer failed: NTSTATUS 0x%08x", retVal)
		}

		// Parse response - similar to EnumerateUsers but for domains
		offset := 0
		resumeHandle = binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		bufPtr := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		if bufPtr == 0 {
			break
		}

		entriesRead := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4
		offset += 4 // Buffer referent
		offset += 4 // MaxCount

		// Skip the array of RPC_SID_NAME_USE structures
		for i := uint32(0); i < entriesRead; i++ {
			offset += 4 // Index
			offset += 8 // Name RPC_UNICODE_STRING (len, maxlen, ptr)
		}

		// Parse string data
		for i := uint32(0); i < entriesRead; i++ {
			if offset+12 > len(resp)-4 {
				break
			}
			offset += 4 // MaxCount
			offset += 4 // Offset
			actualCount := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			if actualCount > 1000 || offset+int(actualCount)*2 > len(resp)-4 {
				break
			}

			nameBytes := resp[offset : offset+int(actualCount)*2]
			offset += int(actualCount) * 2
			if (int(actualCount)*2)%4 != 0 {
				offset += 4 - (int(actualCount)*2)%4
			}

			domains = append(domains, decodeUTF16LE(nameBytes))
		}

		if retVal == 0 {
			break
		}
	}

	return domains, nil
}
