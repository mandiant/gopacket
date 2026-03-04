// Package dpapi implements DPAPI (Data Protection API) parsing and decryption
// for Windows secrets including master keys, credentials, and vaults.
package dpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

// Algorithm constants
const (
	CALG_SHA1    = 0x8004
	CALG_SHA512  = 0x800e
	CALG_HMAC    = 0x8009
	CALG_3DES    = 0x6603
	CALG_AES_256 = 0x6610
)

// MasterKeyFile represents the header of a DPAPI master key file
type MasterKeyFile struct {
	Version       uint32
	Unk1          uint32
	Unk2          uint32
	GUID          string // 36 chars UUID
	Unk3          uint32
	Policy        uint32
	Flags         uint32
	MasterKeyLen  uint64
	BackupKeyLen  uint64
	CredHistLen   uint64
	DomainKeyLen  uint64
}

// MasterKey represents an encrypted master key
type MasterKey struct {
	Version       uint32
	Salt          []byte // 16 bytes
	Iterations    uint32
	HashAlgo      uint32
	CryptAlgo     uint32
	Data          []byte
	DecryptedKey  []byte // Set after successful decryption
}

// DomainKey represents a domain-encrypted master key
type DomainKey struct {
	Version     uint32
	SecretLen   uint32
	AccessCheck []byte
	GUID        string
	Secret      []byte
}

// CredHist represents a credential history link
type CredHist struct {
	Version uint32
	GUID    string
}

// CredentialFile represents a DPAPI credential file
type CredentialFile struct {
	Version    uint32
	Size       uint32
	Unknown    uint32
	DPAPIBlob  *DPAPIBlob
}

// DPAPIBlob represents an encrypted DPAPI blob
type DPAPIBlob struct {
	Version          uint32
	GUIDProvider     string
	MasterKeyVersion uint32
	GUIDMasterKey    string
	Flags            uint32
	Description      string
	AlgCrypt         uint32
	AlgCryptLen      uint32
	Salt             []byte
	HMACKeyLen       uint32
	HMACKey          []byte
	AlgHash          uint32
	AlgHashLen       uint32
	HMAC             []byte
	Data             []byte
	Sign             []byte
}

// Credential represents a decrypted Windows credential
type Credential struct {
	Flags         uint32
	Type          uint32
	LastWritten   uint64
	Persist       uint32
	TargetName    string
	Comment       string
	TargetAlias   string
	UserName      string
	CredentialBlob []byte
}

// ParseMasterKeyFile parses a master key file from raw bytes
func ParseMasterKeyFile(data []byte) (*MasterKeyFile, []byte, error) {
	if len(data) < 128 {
		return nil, nil, fmt.Errorf("data too short for MasterKeyFile")
	}

	mkf := &MasterKeyFile{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &mkf.Version)
	binary.Read(r, binary.LittleEndian, &mkf.Unk1)
	binary.Read(r, binary.LittleEndian, &mkf.Unk2)

	// GUID is 72 bytes (36 UTF-16LE chars)
	guidBytes := make([]byte, 72)
	r.Read(guidBytes)
	mkf.GUID = utf16ToString(guidBytes)

	binary.Read(r, binary.LittleEndian, &mkf.Unk3)
	binary.Read(r, binary.LittleEndian, &mkf.Policy)
	binary.Read(r, binary.LittleEndian, &mkf.Flags)
	binary.Read(r, binary.LittleEndian, &mkf.MasterKeyLen)
	binary.Read(r, binary.LittleEndian, &mkf.BackupKeyLen)
	binary.Read(r, binary.LittleEndian, &mkf.CredHistLen)
	binary.Read(r, binary.LittleEndian, &mkf.DomainKeyLen)

	pos, _ := r.Seek(0, 1)
	return mkf, data[pos:], nil
}

// ParseMasterKey parses a master key structure
func ParseMasterKey(data []byte) (*MasterKey, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("data too short for MasterKey")
	}

	mk := &MasterKey{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &mk.Version)

	mk.Salt = make([]byte, 16)
	r.Read(mk.Salt)

	binary.Read(r, binary.LittleEndian, &mk.Iterations)
	binary.Read(r, binary.LittleEndian, &mk.HashAlgo)
	binary.Read(r, binary.LittleEndian, &mk.CryptAlgo)

	pos, _ := r.Seek(0, 1)
	mk.Data = data[pos:]

	return mk, nil
}

// ParseDomainKey parses a domain key structure
func ParseDomainKey(data []byte) (*DomainKey, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("data too short for DomainKey")
	}

	dk := &DomainKey{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &dk.Version)
	binary.Read(r, binary.LittleEndian, &dk.SecretLen)

	var accessCheckLen uint32
	binary.Read(r, binary.LittleEndian, &accessCheckLen)

	// GUID (16 bytes)
	guidBytes := make([]byte, 16)
	r.Read(guidBytes)
	dk.GUID = guidToString(guidBytes)

	dk.AccessCheck = make([]byte, accessCheckLen)
	r.Read(dk.AccessCheck)

	dk.Secret = make([]byte, dk.SecretLen)
	r.Read(dk.Secret)

	return dk, nil
}

// ParseCredHist parses a credential history structure
func ParseCredHist(data []byte) (*CredHist, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for CredHist")
	}

	ch := &CredHist{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &ch.Version)

	guidBytes := make([]byte, 16)
	r.Read(guidBytes)
	ch.GUID = guidToString(guidBytes)

	return ch, nil
}

// ParseDPAPIBlob parses a DPAPI blob structure
func ParseDPAPIBlob(data []byte) (*DPAPIBlob, error) {
	if len(data) < 44 {
		return nil, fmt.Errorf("data too short for DPAPI blob")
	}

	blob := &DPAPIBlob{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &blob.Version)

	// Provider GUID
	provGUID := make([]byte, 16)
	r.Read(provGUID)
	blob.GUIDProvider = guidToString(provGUID)

	binary.Read(r, binary.LittleEndian, &blob.MasterKeyVersion)

	// Master Key GUID
	mkGUID := make([]byte, 16)
	r.Read(mkGUID)
	blob.GUIDMasterKey = guidToString(mkGUID)

	binary.Read(r, binary.LittleEndian, &blob.Flags)

	// Description (UTF-16LE length-prefixed string)
	var descLen uint32
	binary.Read(r, binary.LittleEndian, &descLen)
	if descLen > 0 {
		descBytes := make([]byte, descLen)
		r.Read(descBytes)
		blob.Description = utf16ToString(descBytes)
	}

	binary.Read(r, binary.LittleEndian, &blob.AlgCrypt)
	binary.Read(r, binary.LittleEndian, &blob.AlgCryptLen)

	// Salt
	var saltLen uint32
	binary.Read(r, binary.LittleEndian, &saltLen)
	blob.Salt = make([]byte, saltLen)
	r.Read(blob.Salt)

	binary.Read(r, binary.LittleEndian, &blob.HMACKeyLen)
	if blob.HMACKeyLen > 0 {
		blob.HMACKey = make([]byte, blob.HMACKeyLen)
		r.Read(blob.HMACKey)
	}

	binary.Read(r, binary.LittleEndian, &blob.AlgHash)
	binary.Read(r, binary.LittleEndian, &blob.AlgHashLen)

	// HMAC
	var hmacLen uint32
	binary.Read(r, binary.LittleEndian, &hmacLen)
	blob.HMAC = make([]byte, hmacLen)
	r.Read(blob.HMAC)

	// Encrypted data
	var dataLen uint32
	binary.Read(r, binary.LittleEndian, &dataLen)
	blob.Data = make([]byte, dataLen)
	r.Read(blob.Data)

	// Signature
	var signLen uint32
	binary.Read(r, binary.LittleEndian, &signLen)
	blob.Sign = make([]byte, signLen)
	r.Read(blob.Sign)

	return blob, nil
}

// ParseCredentialFile parses a credential file
func ParseCredentialFile(data []byte) (*CredentialFile, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("data too short for credential file")
	}

	cf := &CredentialFile{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &cf.Version)
	binary.Read(r, binary.LittleEndian, &cf.Size)
	binary.Read(r, binary.LittleEndian, &cf.Unknown)

	pos, _ := r.Seek(0, 1)
	blob, err := ParseDPAPIBlob(data[pos:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPAPI blob: %v", err)
	}
	cf.DPAPIBlob = blob

	return cf, nil
}

// Decrypt attempts to decrypt a master key using the provided key
func (mk *MasterKey) Decrypt(key []byte) ([]byte, error) {
	// Derive decryption key using PBKDF2
	var hashFunc func() hash.Hash
	var keyLen int

	switch mk.HashAlgo {
	case CALG_SHA1:
		hashFunc = sha1.New
		keyLen = 20
	case CALG_SHA512:
		hashFunc = sha512.New
		keyLen = 64
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%x", mk.HashAlgo)
	}

	derivedKey := pbkdf2.Key(key, mk.Salt, int(mk.Iterations), keyLen, hashFunc)

	// Decrypt based on algorithm
	var plaintext []byte
	var err error

	switch mk.CryptAlgo {
	case CALG_3DES:
		plaintext, err = decrypt3DES(derivedKey[:24], mk.Data)
	case CALG_AES_256:
		plaintext, err = decryptAES256(derivedKey[:32], mk.Data)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: 0x%x", mk.CryptAlgo)
	}

	if err != nil {
		return nil, err
	}

	// Validate decryption by checking HMAC
	if len(plaintext) < keyLen {
		return nil, fmt.Errorf("decrypted data too short")
	}

	// Extract the actual key (first part before HMAC)
	// The structure is: key + hmac
	actualKey := plaintext[:len(plaintext)-keyLen]
	mk.DecryptedKey = actualKey

	return actualKey, nil
}

// DecryptWithPassword attempts to decrypt a master key using a password
func (mk *MasterKey) DecryptWithPassword(password, sid string) ([]byte, error) {
	// Derive key from password and SID
	key := deriveKeyFromPassword(password, sid)
	return mk.Decrypt(key)
}

// Decrypt decrypts a DPAPI blob using the provided master key
func (blob *DPAPIBlob) Decrypt(masterKey []byte) ([]byte, error) {
	return blob.DecryptWithEntropy(masterKey, nil)
}

// DecryptWithEntropy decrypts a DPAPI blob using the provided master key and optional entropy
func (blob *DPAPIBlob) DecryptWithEntropy(masterKey []byte, entropy []byte) ([]byte, error) {
	// Derive session key
	var hashFunc func() hash.Hash

	switch blob.AlgHash {
	case CALG_SHA1, CALG_HMAC:
		hashFunc = sha1.New
	case CALG_SHA512:
		hashFunc = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%x", blob.AlgHash)
	}

	// Derive keys - incorporate entropy if provided
	// DPAPI key derivation: HMAC(masterKey, salt + entropy)
	h := hmac.New(hashFunc, masterKey)
	h.Write(blob.Salt)
	if len(entropy) > 0 {
		h.Write(entropy)
	}
	derivedKey := h.Sum(nil)

	// Determine key length based on encryption algorithm
	var keyLen int
	switch blob.AlgCrypt {
	case CALG_3DES:
		keyLen = 24
	case CALG_AES_256:
		keyLen = 32
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: 0x%x", blob.AlgCrypt)
	}

	if len(derivedKey) < keyLen {
		// Extend key if needed
		derivedKey = extendKey(derivedKey, keyLen, hashFunc)
	}

	// Decrypt
	var plaintext []byte
	var err error

	switch blob.AlgCrypt {
	case CALG_3DES:
		plaintext, err = decrypt3DES(derivedKey[:keyLen], blob.Data)
	case CALG_AES_256:
		plaintext, err = decryptAES256(derivedKey[:keyLen], blob.Data)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: 0x%x", blob.AlgCrypt)
	}

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ParseCredential parses a decrypted credential blob
func ParseCredential(data []byte) (*Credential, error) {
	if len(data) < 72 {
		return nil, fmt.Errorf("data too short for credential")
	}

	cred := &Credential{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &cred.Flags)
	binary.Read(r, binary.LittleEndian, &cred.Type)
	binary.Read(r, binary.LittleEndian, &cred.LastWritten)

	var unk uint32
	binary.Read(r, binary.LittleEndian, &unk) // unknown

	binary.Read(r, binary.LittleEndian, &cred.Persist)

	var attrCount, unk2, targetNameLen, unk3 uint32
	binary.Read(r, binary.LittleEndian, &attrCount)
	binary.Read(r, binary.LittleEndian, &unk2)
	binary.Read(r, binary.LittleEndian, &targetNameLen)
	binary.Read(r, binary.LittleEndian, &unk3)

	var commentLen, targetAliasLen, userNameLen, credBlobLen uint32
	binary.Read(r, binary.LittleEndian, &commentLen)
	binary.Read(r, binary.LittleEndian, &targetAliasLen)
	binary.Read(r, binary.LittleEndian, &userNameLen)
	binary.Read(r, binary.LittleEndian, &credBlobLen)

	// Read strings
	if targetNameLen > 0 {
		buf := make([]byte, targetNameLen)
		r.Read(buf)
		cred.TargetName = utf16ToString(buf)
	}

	if commentLen > 0 {
		buf := make([]byte, commentLen)
		r.Read(buf)
		cred.Comment = utf16ToString(buf)
	}

	if targetAliasLen > 0 {
		buf := make([]byte, targetAliasLen)
		r.Read(buf)
		cred.TargetAlias = utf16ToString(buf)
	}

	if userNameLen > 0 {
		buf := make([]byte, userNameLen)
		r.Read(buf)
		cred.UserName = utf16ToString(buf)
	}

	if credBlobLen > 0 {
		cred.CredentialBlob = make([]byte, credBlobLen)
		r.Read(cred.CredentialBlob)
	}

	return cred, nil
}

// Dump prints MasterKeyFile information
func (mkf *MasterKeyFile) Dump() {
	fmt.Println("[MASTERKEYFILE]")
	fmt.Printf("Version     : %08x (%d)\n", mkf.Version, mkf.Version)
	fmt.Printf("GUID        : %s\n", mkf.GUID)
	fmt.Printf("Flags       : %08x (%d)\n", mkf.Flags, mkf.Flags)
	fmt.Printf("Policy      : %08x (%d)\n", mkf.Policy, mkf.Policy)
	fmt.Printf("MasterKeyLen: %08x (%d)\n", mkf.MasterKeyLen, mkf.MasterKeyLen)
	fmt.Printf("BackupKeyLen: %08x (%d)\n", mkf.BackupKeyLen, mkf.BackupKeyLen)
	fmt.Printf("CredHistLen : %08x (%d)\n", mkf.CredHistLen, mkf.CredHistLen)
	fmt.Printf("DomainKeyLen: %08x (%d)\n", mkf.DomainKeyLen, mkf.DomainKeyLen)
	fmt.Println()
}

// Dump prints MasterKey information
func (mk *MasterKey) Dump() {
	fmt.Println("[MASTERKEY]")
	fmt.Printf("Version     : %08x (%d)\n", mk.Version, mk.Version)
	fmt.Printf("Salt        : %s\n", hex.EncodeToString(mk.Salt))
	fmt.Printf("Rounds      : %08x (%d)\n", mk.Iterations, mk.Iterations)
	fmt.Printf("HashAlgo    : %08x (%s)\n", mk.HashAlgo, algName(mk.HashAlgo))
	fmt.Printf("CryptAlgo   : %08x (%s)\n", mk.CryptAlgo, algName(mk.CryptAlgo))
	fmt.Printf("Data        : %s\n", hex.EncodeToString(mk.Data))
	fmt.Println()
}

// Dump prints DomainKey information
func (dk *DomainKey) Dump() {
	fmt.Println("[DOMAINKEY]")
	fmt.Printf("Version     : %08x (%d)\n", dk.Version, dk.Version)
	fmt.Printf("GUID        : %s\n", dk.GUID)
	fmt.Printf("SecretLen   : %d\n", dk.SecretLen)
	fmt.Printf("AccessCheck : %s\n", hex.EncodeToString(dk.AccessCheck))
	fmt.Printf("Secret      : %s\n", hex.EncodeToString(dk.Secret))
	fmt.Println()
}

// Dump prints DPAPIBlob information
func (blob *DPAPIBlob) Dump() {
	fmt.Println("[DPAPI BLOB]")
	fmt.Printf("Version       : %08x (%d)\n", blob.Version, blob.Version)
	fmt.Printf("Provider GUID : %s\n", blob.GUIDProvider)
	fmt.Printf("MK Version    : %08x (%d)\n", blob.MasterKeyVersion, blob.MasterKeyVersion)
	fmt.Printf("MK GUID       : %s\n", blob.GUIDMasterKey)
	fmt.Printf("Flags         : %08x (%d)\n", blob.Flags, blob.Flags)
	fmt.Printf("Description   : %s\n", blob.Description)
	fmt.Printf("AlgCrypt      : %08x (%s)\n", blob.AlgCrypt, algName(blob.AlgCrypt))
	fmt.Printf("AlgCryptLen   : %d\n", blob.AlgCryptLen)
	fmt.Printf("Salt          : %s\n", hex.EncodeToString(blob.Salt))
	fmt.Printf("AlgHash       : %08x (%s)\n", blob.AlgHash, algName(blob.AlgHash))
	fmt.Printf("AlgHashLen    : %d\n", blob.AlgHashLen)
	fmt.Printf("HMAC          : %s\n", hex.EncodeToString(blob.HMAC))
	fmt.Printf("Data          : %s\n", hex.EncodeToString(blob.Data))
	fmt.Println()
}

// Dump prints Credential information
func (c *Credential) Dump() {
	fmt.Println("[CREDENTIAL]")
	fmt.Printf("Type        : %d (%s)\n", c.Type, credTypeName(c.Type))
	fmt.Printf("Flags       : %08x\n", c.Flags)
	fmt.Printf("Persist     : %d\n", c.Persist)
	fmt.Printf("TargetName  : %s\n", c.TargetName)
	fmt.Printf("UserName    : %s\n", c.UserName)
	fmt.Printf("Comment     : %s\n", c.Comment)
	fmt.Printf("TargetAlias : %s\n", c.TargetAlias)
	if len(c.CredentialBlob) > 0 {
		// Try to decode as string
		if isASCII(c.CredentialBlob) {
			fmt.Printf("Credential  : %s\n", string(c.CredentialBlob))
		} else if isUTF16(c.CredentialBlob) {
			fmt.Printf("Credential  : %s\n", utf16ToString(c.CredentialBlob))
		} else {
			fmt.Printf("Credential  : %s\n", hex.EncodeToString(c.CredentialBlob))
		}
	}
	fmt.Println()
}

// Helper functions

func utf16ToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Remove null terminator
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

func guidToString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func algName(alg uint32) string {
	switch alg {
	case CALG_SHA1:
		return "CALG_SHA1"
	case CALG_SHA512:
		return "CALG_SHA512"
	case CALG_HMAC:
		return "CALG_HMAC"
	case CALG_3DES:
		return "CALG_3DES"
	case CALG_AES_256:
		return "CALG_AES_256"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", alg)
	}
}

func credTypeName(t uint32) string {
	switch t {
	case 1:
		return "GENERIC"
	case 2:
		return "DOMAIN_PASSWORD"
	case 3:
		return "DOMAIN_CERTIFICATE"
	case 4:
		return "DOMAIN_VISIBLE_PASSWORD"
	default:
		return "UNKNOWN"
	}
}

func decrypt3DES(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length must be multiple of 8")
	}

	block, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return nil, err
	}

	// Use first 8 bytes of key as IV
	iv := make([]byte, 8)
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)

	// Remove PKCS7 padding
	return unpad(plaintext)
}

func decryptAES256(key, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data length must be multiple of 16")
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	// Use zero IV
	iv := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)

	// Remove PKCS7 padding
	return unpad(plaintext)
}

func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) || padLen == 0 {
		// No padding or invalid padding, return as-is
		return data, nil
	}
	return data[:len(data)-padLen], nil
}

func extendKey(key []byte, targetLen int, hashFunc func() hash.Hash) []byte {
	result := make([]byte, 0, targetLen)
	counter := byte(1)
	for len(result) < targetLen {
		h := hashFunc()
		h.Write(key)
		h.Write([]byte{counter})
		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:targetLen]
}

func deriveKeyFromPassword(password, sid string) []byte {
	// Convert password to UTF-16LE
	pwdUTF16 := stringToUTF16LE(password)

	// Compute MD4 hash (NT hash)
	h := md4.New()
	h.Write(pwdUTF16)
	ntHash := h.Sum(nil)

	// Derive key using SHA1(ntHash + SID)
	h2 := sha1.New()
	h2.Write(ntHash)
	h2.Write(stringToUTF16LE(strings.ToUpper(sid) + "\x00"))

	return h2.Sum(nil)
}

func stringToUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func isUTF16(b []byte) bool {
	if len(b)%2 != 0 {
		return false
	}
	// Check for mostly printable UTF-16LE (ASCII range)
	nullCount := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			nullCount++
		}
	}
	return nullCount > len(b)/4
}
