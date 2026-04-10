// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package dpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// CredHistFile represents a CREDHIST file containing a chain of credential history entries
type CredHistFile struct {
	Version uint32
	GUID    string
	Entries []*CredHistEntry
}

// CredHistEntry represents a single entry in the credential history chain
type CredHistEntry struct {
	Version       uint32
	GUID          string
	UserSID       string
	HashAlgo      uint32
	CryptAlgo     uint32
	Salt          []byte
	Rounds        uint32
	HMACLen       uint32
	CipherTextLen uint32
	CipherText    []byte
	DecryptedKey  []byte
	DecryptedHMAC []byte
	SHA1          []byte // SHA1 of password used
	NTHash        []byte // NTLM hash of password
}

// ParseCredHistFile parses a CREDHIST file
func ParseCredHistFile(data []byte) (*CredHistFile, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for CREDHIST file")
	}

	chf := &CredHistFile{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &chf.Version)

	// Root GUID (16 bytes)
	guidBytes := make([]byte, 16)
	r.Read(guidBytes)
	chf.GUID = guidToString(guidBytes)

	// Parse entries
	offset := 20
	for offset < len(data) {
		entry, bytesRead, err := parseCredHistEntry(data[offset:])
		if err != nil {
			break
		}
		chf.Entries = append(chf.Entries, entry)
		offset += bytesRead

		if bytesRead == 0 {
			break
		}
	}

	return chf, nil
}

// parseCredHistEntry parses a single CREDHIST entry
func parseCredHistEntry(data []byte) (*CredHistEntry, int, error) {
	if len(data) < 56 {
		return nil, 0, fmt.Errorf("data too short for CREDHIST entry")
	}

	entry := &CredHistEntry{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &entry.Version)

	// GUID (16 bytes)
	guidBytes := make([]byte, 16)
	r.Read(guidBytes)
	entry.GUID = guidToString(guidBytes)

	// User SID as structure
	// Skip some fields and read SID
	var sidLen uint32
	binary.Read(r, binary.LittleEndian, &sidLen)
	if sidLen > 0 && sidLen < 256 {
		sidBytes := make([]byte, sidLen)
		r.Read(sidBytes)
		entry.UserSID = parseSIDBytes(sidBytes)
	}

	binary.Read(r, binary.LittleEndian, &entry.HashAlgo)
	binary.Read(r, binary.LittleEndian, &entry.CryptAlgo)

	// Salt (16 bytes typically)
	var saltLen uint32
	binary.Read(r, binary.LittleEndian, &saltLen)
	if saltLen > 0 && saltLen <= 64 {
		entry.Salt = make([]byte, saltLen)
		r.Read(entry.Salt)
	}

	binary.Read(r, binary.LittleEndian, &entry.Rounds)
	binary.Read(r, binary.LittleEndian, &entry.HMACLen)
	binary.Read(r, binary.LittleEndian, &entry.CipherTextLen)

	if entry.CipherTextLen > 0 && entry.CipherTextLen < 65536 {
		entry.CipherText = make([]byte, entry.CipherTextLen)
		r.Read(entry.CipherText)
	}

	pos, _ := r.Seek(0, 1)
	return entry, int(pos), nil
}

// parseSIDBytes parses a binary SID structure to string format
func parseSIDBytes(data []byte) string {
	if len(data) < 8 {
		return hex.EncodeToString(data)
	}

	revision := data[0]
	subAuthCount := int(data[1])

	// 6-byte identifier authority (big-endian)
	identAuth := uint64(data[2])<<40 | uint64(data[3])<<32 | uint64(data[4])<<24 |
		uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])

	sid := fmt.Sprintf("S-%d-%d", revision, identAuth)

	// Sub-authorities (32-bit, little-endian)
	offset := 8
	for i := 0; i < subAuthCount && offset+4 <= len(data); i++ {
		subAuth := binary.LittleEndian.Uint32(data[offset:])
		sid += fmt.Sprintf("-%d", subAuth)
		offset += 4
	}

	return sid
}

// Decrypt attempts to decrypt this CREDHIST entry using a key derived from password
func (entry *CredHistEntry) Decrypt(key []byte) error {
	if len(entry.CipherText) == 0 {
		return fmt.Errorf("no cipher text to decrypt")
	}

	// Derive decryption key using PBKDF2
	var hashFunc func() hash.Hash
	var keyLen int

	switch entry.HashAlgo {
	case CALG_SHA1:
		hashFunc = sha1.New
		keyLen = 20
	case CALG_SHA512:
		hashFunc = sha512.New
		keyLen = 64
	default:
		return fmt.Errorf("unsupported hash algorithm: 0x%x", entry.HashAlgo)
	}

	derivedKey := pbkdf2.Key(key, entry.Salt, int(entry.Rounds), keyLen, hashFunc)

	// Decrypt based on algorithm
	var plaintext []byte
	var err error

	switch entry.CryptAlgo {
	case CALG_3DES:
		plaintext, err = decrypt3DES(derivedKey[:24], entry.CipherText)
	case CALG_AES_256:
		plaintext, err = decryptAES256(derivedKey[:32], entry.CipherText)
	default:
		return fmt.Errorf("unsupported encryption algorithm: 0x%x", entry.CryptAlgo)
	}

	if err != nil {
		return err
	}

	// Parse decrypted data
	// Structure: SHA1(password) (20 bytes) + NTLM hash (16 bytes)
	if len(plaintext) >= 36 {
		entry.SHA1 = plaintext[:20]
		entry.NTHash = plaintext[20:36]
	}
	entry.DecryptedKey = plaintext

	return nil
}

// DecryptWithPassword attempts to decrypt using a password and SID
func (entry *CredHistEntry) DecryptWithPassword(password, sid string) error {
	key := deriveKeyFromPassword(password, sid)
	return entry.Decrypt(key)
}

// DecryptWithNTHash attempts to decrypt using an NTLM hash and SID
func (entry *CredHistEntry) DecryptWithNTHash(ntHash []byte, sid string) error {
	// Derive key using SHA1(ntHash + SID)
	h := sha1.New()
	h.Write(ntHash)
	h.Write(stringToUTF16LE(sid + "\x00"))
	key := h.Sum(nil)
	return entry.Decrypt(key)
}

// VerifyPassword verifies if a password matches this entry
func (entry *CredHistEntry) VerifyPassword(password string) bool {
	if entry.SHA1 == nil {
		return false
	}

	// Compute SHA1 of password (UTF-16LE)
	h := sha1.New()
	h.Write(stringToUTF16LE(password))
	computed := h.Sum(nil)

	return hmac.Equal(computed, entry.SHA1)
}

// GetDecryptedNTHash returns the decrypted NTLM hash if available
func (entry *CredHistEntry) GetDecryptedNTHash() []byte {
	return entry.NTHash
}

// Dump prints CREDHIST file information
func (chf *CredHistFile) Dump() {
	fmt.Println("[CREDHIST FILE]")
	fmt.Printf("Version  : %d\n", chf.Version)
	fmt.Printf("GUID     : %s\n", chf.GUID)
	fmt.Printf("Entries  : %d\n", len(chf.Entries))
	fmt.Println()

	for i, entry := range chf.Entries {
		fmt.Printf("[ENTRY %d]\n", i)
		entry.Dump()
	}
}

// Dump prints a single CREDHIST entry
func (entry *CredHistEntry) Dump() {
	fmt.Printf("  Version   : %d\n", entry.Version)
	fmt.Printf("  GUID      : %s\n", entry.GUID)
	fmt.Printf("  User SID  : %s\n", entry.UserSID)
	fmt.Printf("  HashAlgo  : 0x%x (%s)\n", entry.HashAlgo, algName(entry.HashAlgo))
	fmt.Printf("  CryptAlgo : 0x%x (%s)\n", entry.CryptAlgo, algName(entry.CryptAlgo))
	fmt.Printf("  Salt      : %s\n", hex.EncodeToString(entry.Salt))
	fmt.Printf("  Rounds    : %d\n", entry.Rounds)
	if entry.SHA1 != nil {
		fmt.Printf("  SHA1      : %s\n", hex.EncodeToString(entry.SHA1))
	}
	if entry.NTHash != nil {
		fmt.Printf("  NT Hash   : %s\n", hex.EncodeToString(entry.NTHash))
	}
	fmt.Println()
}

// WalkChain attempts to decrypt the entire credential history chain
// starting with the provided password and SID
func (chf *CredHistFile) WalkChain(password, sid string) ([]*CredHistEntry, error) {
	var decrypted []*CredHistEntry

	// Start with the provided password
	currentKey := deriveKeyFromPassword(password, sid)

	for _, entry := range chf.Entries {
		// Try to decrypt this entry
		if err := entry.Decrypt(currentKey); err != nil {
			// Try with the entry's SID if different
			if entry.UserSID != "" && entry.UserSID != sid {
				altKey := deriveKeyFromPassword(password, entry.UserSID)
				if err := entry.Decrypt(altKey); err != nil {
					continue
				}
			} else {
				continue
			}
		}

		decrypted = append(decrypted, entry)

		// Use the decrypted NT hash to derive key for next entry
		if entry.NTHash != nil {
			h := sha1.New()
			h.Write(entry.NTHash)
			useSID := sid
			if entry.UserSID != "" {
				useSID = entry.UserSID
			}
			h.Write(stringToUTF16LE(useSID + "\x00"))
			currentKey = h.Sum(nil)
		}
	}

	return decrypted, nil
}
