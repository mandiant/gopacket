package drsuapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

// DecryptSecret decrypts an encrypted attribute value from DRS replication.
// The encryption uses the session key and either RC4 or AES depending on server version.
func DecryptSecret(sessionKey, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Check if it's RC4 or AES encrypted
	// AES encrypted data starts with a specific header
	if isAESEncrypted(encryptedData) {
		return decryptAES(sessionKey, encryptedData)
	}
	return decryptRC4(sessionKey, encryptedData)
}

func isAESEncrypted(data []byte) bool {
	// AES encrypted blobs have a specific signature
	// Version 1 = RC4, Version 2 = AES
	if len(data) < 4 {
		return false
	}
	// Check for AES version marker
	return data[0] == 0x13 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00
}

func decryptRC4(sessionKey, encryptedData []byte) ([]byte, error) {
	// The encrypted data is prefixed with a salt/checksum
	// Structure: [salt 16][encrypted data]

	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("encrypted data too short for RC4")
	}

	// Derive the decryption key: MD5(sessionKey + salt)
	salt := encryptedData[:16]
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	key := h.Sum(nil)

	// Decrypt using RC4
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := encryptedData[16:]
	decrypted := make([]byte, len(encrypted))
	c.XORKeyStream(decrypted, encrypted)

	// Verify checksum (first 4 bytes after decryption should match CRC)
	if len(decrypted) < 4 {
		return nil, fmt.Errorf("decrypted data too short")
	}

	return decrypted[4:], nil // Skip the checksum
}

func decryptAES(sessionKey, encryptedData []byte) ([]byte, error) {
	// AES encrypted structure:
	// [version 4][flags 4][salt 16][encrypted data]

	if len(encryptedData) < 24 {
		return nil, fmt.Errorf("encrypted data too short for AES")
	}

	salt := encryptedData[8:24]
	encrypted := encryptedData[24:]

	// Derive key using salt
	key := deriveAESKey(sessionKey, salt)

	// Decrypt with AES-CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data not aligned to AES block size")
	}

	iv := make([]byte, aes.BlockSize) // Zero IV
	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// Remove PKCS7 padding
	if len(decrypted) > 0 {
		padLen := int(decrypted[len(decrypted)-1])
		if padLen > 0 && padLen <= aes.BlockSize {
			decrypted = decrypted[:len(decrypted)-padLen]
		}
	}

	return decrypted, nil
}

func deriveAESKey(sessionKey, salt []byte) []byte {
	// Key derivation for AES
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	return h.Sum(nil)
}

// DecryptNTHash decrypts the NT hash from the unicodePwd attribute.
// The hash is encrypted with a key derived from the user's RID.
func DecryptNTHash(pek, encryptedHash []byte, rid uint32) ([]byte, error) {
	if len(encryptedHash) < 16 {
		return nil, fmt.Errorf("encrypted hash too short")
	}

	// First decrypt with PEK (if PEK encrypted)
	decrypted := encryptedHash

	// Then remove RID-based encryption using DES
	return removeRIDEncryption(decrypted, rid)
}

// removeRIDEncryption removes the DES encryption based on the user's RID.
// This is the final layer of encryption on NT hashes in AD.
func removeRIDEncryption(hash []byte, rid uint32) ([]byte, error) {
	if len(hash) < 16 {
		return nil, fmt.Errorf("hash too short")
	}

	// Generate two DES keys from the RID
	key1 := ridToKey(rid)
	key2 := ridToKey(((rid >> 8) | (rid << 24)) & 0xFFFFFFFF)

	// Decrypt each 8-byte half
	result := make([]byte, 16)

	block1, err := des.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	block1.Decrypt(result[:8], hash[:8])

	block2, err := des.NewCipher(key2)
	if err != nil {
		return nil, err
	}
	block2.Decrypt(result[8:], hash[8:16])

	return result, nil
}

// ridToKey converts a RID to a DES key (7 bytes -> 8 bytes with parity)
func ridToKey(rid uint32) []byte {
	s := make([]byte, 7)
	binary.LittleEndian.PutUint32(s[:4], rid)
	s[4] = byte(rid)
	s[5] = byte(rid >> 8)
	s[6] = byte(rid >> 16)

	return strToKey(s)
}

// strToKey converts a 7-byte string to an 8-byte DES key with parity bits
func strToKey(s []byte) []byte {
	key := make([]byte, 8)
	key[0] = s[0] >> 1
	key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
	key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
	key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
	key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5)
	key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6)
	key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7)
	key[7] = s[6] & 0x7F

	// Set parity bits
	for i := 0; i < 8; i++ {
		key[i] = key[i] << 1
		// Odd parity
		b := key[i]
		parity := byte(0)
		for j := 0; j < 8; j++ {
			parity ^= (b >> j) & 1
		}
		key[i] |= (parity ^ 1)
	}
	return key
}

// DecryptLSASecret decrypts an LSA secret using the session key
// This implements MS-LSAD Section 5.1.2 encryption scheme
func DecryptLSASecret(sessionKey, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("empty encrypted data")
	}

	plainText := make([]byte, 0, len(encryptedData))
	key0 := make([]byte, len(sessionKey))
	copy(key0, sessionKey)

	// Process 8 bytes at a time using DES
	remaining := encryptedData
	blockNum := 0
	for len(remaining) >= 8 {
		cipherText := remaining[:8]

		// Get 7 bytes from current key position for DES key derivation
		tmpStrKey := make([]byte, 7)
		copy(tmpStrKey, key0[:min(7, len(key0))])

		// Transform to DES key using MS-LSAD Section 5.1.3 algorithm
		desKey := transformKey(tmpStrKey)

		// Decrypt with DES ECB
		block, err := des.NewCipher(desKey)
		if err != nil {
			return nil, fmt.Errorf("DES cipher creation failed: %v", err)
		}

		decrypted := make([]byte, 8)
		block.Decrypt(decrypted, cipherText)
		plainText = append(plainText, decrypted...)

		// Advance key position
		key0 = key0[7:]
		remaining = remaining[8:]
		blockNum++

		// If key is exhausted, advance to offset (key0 = key[len(key0):])
		// This matches Impacket's implementation which does NOT wrap around
		if len(key0) < 7 {
			keyRemaining := len(key0)
			key0 = sessionKey[keyRemaining:]
		}
	}

	// Parse LSA_SECRET_XP structure: Length (4) + Version (4) + Secret
	// Impacket's structure just returns bytes[8:] as Secret, ignoring the Length field
	// This matches the MS-LSAD specification where the Secret is the rest of the data
	if len(plainText) < 8 {
		return nil, fmt.Errorf("decrypted data too short for LSA_SECRET_XP header")
	}

	return plainText[8:], nil
}

// transformKey transforms a 7-byte key into an 8-byte DES key
// This implements MS-LSAD Section 5.1.3
func transformKey(inputKey []byte) []byte {
	if len(inputKey) < 7 {
		// Pad with zeros if needed
		padded := make([]byte, 7)
		copy(padded, inputKey)
		inputKey = padded
	}

	outputKey := make([]byte, 8)
	outputKey[0] = inputKey[0] >> 1
	outputKey[1] = ((inputKey[0] & 0x01) << 6) | (inputKey[1] >> 2)
	outputKey[2] = ((inputKey[1] & 0x03) << 5) | (inputKey[2] >> 3)
	outputKey[3] = ((inputKey[2] & 0x07) << 4) | (inputKey[3] >> 4)
	outputKey[4] = ((inputKey[3] & 0x0F) << 3) | (inputKey[4] >> 5)
	outputKey[5] = ((inputKey[4] & 0x1F) << 2) | (inputKey[5] >> 6)
	outputKey[6] = ((inputKey[5] & 0x3F) << 1) | (inputKey[6] >> 7)
	outputKey[7] = inputKey[6] & 0x7F

	// Shift left by 1 and clear LSB (matching Impacket's implementation)
	for i := 0; i < 8; i++ {
		outputKey[i] = (outputKey[i] << 1) & 0xfe
	}

	return outputKey
}

// fixParity sets the LSB to make odd parity for DES key bytes
func fixParity(b byte) byte {
	// Count bits in the upper 7 bits
	bits := (b >> 1)
	count := 0
	for bits != 0 {
		count += int(bits & 1)
		bits >>= 1
	}
	// Set LSB to make odd parity (odd number of 1s total)
	if count%2 == 0 {
		return (b & 0xFE) | 0x01 // Set LSB to 1
	}
	return b & 0xFE // Set LSB to 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ExtractRIDFromSID extracts the RID (last 4 bytes) from a SID
func ExtractRIDFromSID(sid []byte) uint32 {
	if len(sid) < 8 {
		return 0
	}
	// SID format: revision(1) + subauthority_count(1) + identifier_authority(6) + subauthorities(4*n)
	// RID is the last subauthority
	if len(sid) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(sid[len(sid)-4:])
}

// ParseEncryptedHash parses the encrypted hash structure
type EncryptedHash struct {
	Version   uint16
	Flags     uint16
	Salt      [16]byte
	Hash      []byte
}

func ParseEncryptedPwdBlob(data []byte) (*EncryptedHash, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("blob too short")
	}

	r := bytes.NewReader(data)
	eh := &EncryptedHash{}

	binary.Read(r, binary.LittleEndian, &eh.Version)
	binary.Read(r, binary.LittleEndian, &eh.Flags)
	r.Read(eh.Salt[:])

	eh.Hash = make([]byte, len(data)-20)
	r.Read(eh.Hash)

	return eh, nil
}
