package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// Magic strings used in SAM hash computation
var (
	QWERTY     = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	DIGITS     = []byte("0123456789012345678901234567890123456789\x00")
	NTPASSWORD = []byte("NTPASSWORD\x00")
	LMPASSWORD = []byte("LMPASSWORD\x00")
)

// SAM revision constants
const (
	SAM_REVISION_1 = 1 // RC4
	SAM_REVISION_2 = 2 // RC4
	SAM_REVISION_3 = 3 // AES
)

// ComputeHashedBootKey derives the hashed boot key from the SAM F value
// For revision 1/2: MD5(F.salt + QWERTY + bootKey + DIGITS) -> RC4 decrypt F.key
// For revision 3: AES decrypt
func ComputeHashedBootKey(samF []byte, bootKey []byte) ([]byte, int, error) {
	if len(samF) < 0x60 {
		return nil, 0, fmt.Errorf("SAM F value too short: %d", len(samF))
	}

	// Revision is at offset 0
	revision := int(samF[0])

	switch revision {
	case SAM_REVISION_1, SAM_REVISION_2:
		// Salt is at offset 0x70 (112), 16 bytes
		// Encrypted key is at offset 0x80 (128), 32 bytes
		if len(samF) < 0xA0 {
			return nil, revision, fmt.Errorf("SAM F value too short for revision %d", revision)
		}

		salt := samF[0x70:0x80]
		encKey := samF[0x80:0xA0]

		// Compute RC4 key
		h := md5.New()
		h.Write(salt)
		h.Write(QWERTY)
		h.Write(bootKey)
		h.Write(DIGITS)
		rc4Key := h.Sum(nil)

		// Decrypt
		cipher, err := rc4.NewCipher(rc4Key)
		if err != nil {
			return nil, revision, err
		}

		hashedBootKey := make([]byte, 32)
		cipher.XORKeyStream(hashedBootKey, encKey)

		return hashedBootKey[:16], revision, nil

	case SAM_REVISION_3:
		// AES encrypted (Windows Vista+)
		// Structure at 0x70:
		//   0x70: Header/Revision (4 bytes)
		//   0x74: Length of encrypted data (4 bytes)
		//   0x78: Salt (16 bytes)
		//   0x88: Encrypted data (Length bytes)
		if len(samF) < 0xA8 {
			return nil, revision, fmt.Errorf("SAM F value too short for revision 3: got %d, need %d", len(samF), 0xA8)
		}

		// Data length is at 0x74
		dataLen := int(samF[0x74]) | int(samF[0x75])<<8 | int(samF[0x76])<<16 | int(samF[0x77])<<24

		if dataLen <= 0 || dataLen > 256 {
			// Fallback: try fixed 32-byte key
			dataLen = 32
		}

		if len(samF) < 0x88+dataLen {
			return nil, revision, fmt.Errorf("SAM F value truncated: got %d bytes, need %d", len(samF), 0x88+dataLen)
		}

		salt := samF[0x78:0x88]
		encData := samF[0x88 : 0x88+dataLen]

		// AES-CBC decrypt with bootKey
		hashedBootKey, err := aesDecrypt(bootKey, salt, encData)
		if err != nil {
			return nil, revision, err
		}

		return hashedBootKey[:16], revision, nil

	default:
		return nil, revision, fmt.Errorf("unknown SAM revision: %d", revision)
	}
}

// DecryptSAMHashRC4 decrypts a SAM hash using RC4 (revision 1/2)
func DecryptSAMHashRC4(hashedBootKey []byte, rid uint32, encHash []byte, isNT bool) ([]byte, error) {
	if len(encHash) != 16 {
		return nil, fmt.Errorf("invalid encrypted hash length: %d", len(encHash))
	}

	// Compute RC4 key: MD5(hashedBootKey + RID + NTPASSWORD/LMPASSWORD)
	h := md5.New()
	h.Write(hashedBootKey)

	// RID as little-endian bytes
	ridBytes := []byte{byte(rid), byte(rid >> 8), byte(rid >> 16), byte(rid >> 24)}
	h.Write(ridBytes)

	if isNT {
		h.Write(NTPASSWORD)
	} else {
		h.Write(LMPASSWORD)
	}

	rc4Key := h.Sum(nil)

	// RC4 decrypt
	cipher, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, 16)
	cipher.XORKeyStream(decrypted, encHash)

	// Remove RID-based DES encryption
	return removeRIDEncryption(decrypted, rid)
}

// DecryptSAMHashAES decrypts a SAM hash using AES (revision 3)
func DecryptSAMHashAES(hashedBootKey []byte, rid uint32, encHashData []byte, isNT bool) ([]byte, error) {
	// AES encrypted hash structure:
	// [0:2] - revision
	// [2:4] - data length
	// [4:20] - salt (16 bytes)
	// [20:] - encrypted data

	if len(encHashData) < 24 {
		return nil, fmt.Errorf("AES hash data too short: %d", len(encHashData))
	}

	salt := encHashData[4:20]
	encData := encHashData[20:]

	return DecryptSAMHashAESWithSalt(hashedBootKey, rid, salt, encData, isNT)
}

// DecryptSAMHashAESWithSalt decrypts a SAM hash using AES with separate salt
func DecryptSAMHashAESWithSalt(hashedBootKey []byte, rid uint32, salt, encData []byte, isNT bool) ([]byte, error) {
	// AES decrypt
	decrypted, err := aesDecrypt(hashedBootKey, salt, encData)
	if err != nil {
		return nil, err
	}

	if len(decrypted) < 16 {
		return nil, fmt.Errorf("decrypted data too short")
	}

	// Remove RID-based DES encryption
	return removeRIDEncryption(decrypted[:16], rid)
}

// DecryptNTDSHashWithRID decrypts an NTDS hash using RID-derived DES keys
// This is used after PEK decryption to remove the inner DES encryption layer
func DecryptNTDSHashWithRID(encHash []byte, rid uint32) ([]byte, error) {
	return removeRIDEncryption(encHash, rid)
}

// removeRIDEncryption removes the DES encryption layer using RID-derived keys
func removeRIDEncryption(hash []byte, rid uint32) ([]byte, error) {
	if len(hash) != 16 {
		return nil, fmt.Errorf("hash must be 16 bytes")
	}

	// The two DES keys are derived from a 14-byte sequence made by repeating
	// the 4-byte RID (little-endian): rid + rid + rid + rid[:2]
	// key1 uses bytes 0-6, key2 uses bytes 7-13
	ridBytes := []byte{
		byte(rid),
		byte(rid >> 8),
		byte(rid >> 16),
		byte(rid >> 24),
	}

	// Build 14-byte sequence: rid repeated
	seq := make([]byte, 14)
	for i := 0; i < 14; i++ {
		seq[i] = ridBytes[i%4]
	}

	// Generate two DES keys
	key1 := strToKey(seq[0:7])
	key2 := strToKey(seq[7:14])

	// DES-ECB decrypt each half
	result := make([]byte, 16)

	block1, err := des.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	block1.Decrypt(result[0:8], hash[0:8])

	block2, err := des.NewCipher(key2)
	if err != nil {
		return nil, err
	}
	block2.Decrypt(result[8:16], hash[8:16])

	return result, nil
}

// strToKey converts 7 bytes to an 8-byte DES key with parity bits
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
		key[i] = (key[i] << 1) | oddParity(key[i])
	}

	return key
}

// oddParity returns 1 if the byte has odd parity (even number of 1 bits), 0 otherwise
func oddParity(b byte) byte {
	p := byte(0)
	for i := 0; i < 7; i++ {
		p ^= (b >> i) & 1
	}
	return p ^ 1
}

// aesDecrypt performs AES-CBC decryption
func aesDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES key must be 16 bytes")
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("AES IV must be 16 bytes")
	}
	if len(data) == 0 || len(data)%16 != 0 {
		// Pad data if needed
		if len(data)%16 != 0 {
			padLen := 16 - (len(data) % 16)
			data = append(data, make([]byte, padLen)...)
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	result := make([]byte, len(data))
	mode.CryptBlocks(result, data)

	return result, nil
}

// sha256With1000Rounds computes SHA256(key || value*1000)
// This matches Impacket's __sha256 function used for LSA key derivation
func sha256With1000Rounds(key, value []byte) []byte {
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(value)
	}
	return h.Sum(nil)
}

// PBKDF2SHA256 derives a key using PBKDF2 with SHA256
func PBKDF2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// aesDecryptImpacketStyle matches Impacket's CryptoCommon.decryptAES behavior
// When useZeroIV is true, it creates a new CBC cipher with zero IV for each 16-byte block
// This is how Impacket decrypts PolEKList and secrets
// Key can be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively
func aesDecryptImpacketStyle(key, data []byte, useZeroIV bool) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 16, 24, or 32 bytes, got %d", len(key))
	}

	// Pad data if needed
	if len(data)%16 != 0 {
		padLen := 16 - (len(data) % 16)
		data = append(data, make([]byte, padLen)...)
	}

	// Use full key - Go's aes.NewCipher selects AES-128/192/256 based on key length
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	zeroIV := make([]byte, 16)
	result := make([]byte, len(data))

	if useZeroIV {
		// Impacket style: create new cipher for each 16-byte block
		for i := 0; i < len(data); i += 16 {
			mode := cipher.NewCBCDecrypter(block, zeroIV)
			mode.CryptBlocks(result[i:i+16], data[i:i+16])
		}
	} else {
		// Standard CBC decryption
		mode := cipher.NewCBCDecrypter(block, zeroIV)
		mode.CryptBlocks(result, data)
	}

	return result, nil
}

// LSA secret decryption constants
var (
	LSA_SECRET_KEY_LOCAL = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// DecryptLSASecretRC4 decrypts an LSA secret using RC4
func DecryptLSASecretRC4(lsaKey, encSecret []byte) ([]byte, error) {
	if len(encSecret) < 12 {
		return nil, fmt.Errorf("encrypted secret too short")
	}

	// Structure: [version:4][flags:4][data...]
	// For old format: data is RC4 encrypted with MD5(lsaKey + salt)

	// Compute decryption key
	h := md5.New()
	h.Write(lsaKey)

	// For simple case, use lsaKey directly as RC4 key
	cipher, err := rc4.NewCipher(lsaKey[:16])
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encSecret))
	cipher.XORKeyStream(decrypted, encSecret)

	return decrypted, nil
}

// DecryptLSASecretAES decrypts an LSA secret using AES (Vista+ style)
func DecryptLSASecretAES(lsaKey, encSecret []byte) ([]byte, error) {
	if len(encSecret) < 60 {
		return nil, fmt.Errorf("encrypted secret too short for AES: %d", len(encSecret))
	}

	// LSA_SECRET structure (Vista+):
	// [0:4] - Version
	// [4:20] - EncKeyID (16 bytes)
	// [20:24] - EncAlgorithm
	// [24:28] - Flags
	// [28:] - EncryptedData

	encryptedData := encSecret[28:]

	// Derive decryption key: SHA256(LSAKey || EncryptedData[:32] * 1000)
	tmpKey := sha256With1000Rounds(lsaKey, encryptedData[:32])

	// Decrypt EncryptedData[32:] using Impacket-style AES (zero IV per block)
	decrypted, err := aesDecryptImpacketStyle(tmpKey, encryptedData[32:], true)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// ComputeLSAKey derives the LSA key from boot key and policy data
func ComputeLSAKey(bootKey, polSecretEncryptionKey []byte, revision int) ([]byte, error) {
	if revision >= 3 {
		// AES mode
		if len(polSecretEncryptionKey) < 60 {
			return nil, fmt.Errorf("policy key too short for AES")
		}
		// [0:4] - version
		// [4:36] - unknown
		// [36:52] - IV
		// [52:] - encrypted key
		iv := polSecretEncryptionKey[36:52]
		encKey := polSecretEncryptionKey[52:]

		return aesDecrypt(bootKey, iv, encKey)
	}

	// RC4 mode
	if len(polSecretEncryptionKey) < 76 {
		return nil, fmt.Errorf("policy key too short for RC4")
	}

	// [0:4] - version
	// [4:20] - unknown
	// [20:36] - unknown
	// [36:52] - unknown
	// [52:68] - encrypted key 1
	// [68:76] - checksum

	h := md5.New()
	h.Write(bootKey)
	for i := 0; i < 1000; i++ {
		h.Write(polSecretEncryptionKey[52:68])
	}
	rc4Key := h.Sum(nil)

	cipher, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, err
	}

	lsaKey := make([]byte, 16)
	cipher.XORKeyStream(lsaKey, polSecretEncryptionKey[68:84])

	return lsaKey, nil
}

// DecryptNLKMKey decrypts the NL$KM key used for cached credentials
func DecryptNLKMKey(lsaKey, encNLKM []byte) ([]byte, error) {
	// NLKM is encrypted with the LSA key
	if len(encNLKM) < 60 {
		return nil, fmt.Errorf("NL$KM too short")
	}

	// Try AES first (version >= 3)
	version := int(encNLKM[0]) | int(encNLKM[1])<<8 | int(encNLKM[2])<<16 | int(encNLKM[3])<<24

	if version >= 3 {
		return DecryptLSASecretAES(lsaKey, encNLKM)
	}

	return DecryptLSASecretRC4(lsaKey, encNLKM)
}

// SHA256With1000Rounds computes SHA256(key || value*1000)
// Exported version of sha256With1000Rounds for NTDS.DIT parsing
func SHA256With1000Rounds(key, value []byte) []byte {
	return sha256With1000Rounds(key, value)
}

// MD5With1000Rounds computes MD5(key || value*1000)
// Used for PEK decryption in older Windows versions
func MD5With1000Rounds(key, value []byte) []byte {
	h := md5.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(value)
	}
	return h.Sum(nil)
}

// RC4Decrypt decrypts data using RC4
func RC4Decrypt(key, data []byte) []byte {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil
	}
	result := make([]byte, len(data))
	cipher.XORKeyStream(result, data)
	return result
}

// AESDecryptImpacketStyle is the exported version of aesDecryptImpacketStyle
// When useZeroIV is true, it creates a new CBC cipher with zero IV for each 16-byte block
func AESDecryptImpacketStyle(key, data []byte, useZeroIV bool) ([]byte, error) {
	return aesDecryptImpacketStyle(key, data, useZeroIV)
}

// addRIDEncryption applies the DES encryption layer using RID-derived keys (reverse of removeRIDEncryption)
func addRIDEncryption(hash []byte, rid uint32) ([]byte, error) {
	if len(hash) != 16 {
		return nil, fmt.Errorf("hash must be 16 bytes")
	}

	ridBytes := []byte{
		byte(rid),
		byte(rid >> 8),
		byte(rid >> 16),
		byte(rid >> 24),
	}

	seq := make([]byte, 14)
	for i := 0; i < 14; i++ {
		seq[i] = ridBytes[i%4]
	}

	key1 := strToKey(seq[0:7])
	key2 := strToKey(seq[7:14])

	result := make([]byte, 16)

	block1, err := des.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	block1.Encrypt(result[0:8], hash[0:8])

	block2, err := des.NewCipher(key2)
	if err != nil {
		return nil, err
	}
	block2.Encrypt(result[8:16], hash[8:16])

	return result, nil
}

// EncryptSAMHashRC4 encrypts a plain hash using RC4 (revision 1/2) for writing back to SAM
func EncryptSAMHashRC4(hashedBootKey []byte, rid uint32, plainHash []byte, isNT bool) ([]byte, error) {
	if len(plainHash) != 16 {
		return nil, fmt.Errorf("plain hash must be 16 bytes")
	}

	// First apply RID-based DES encryption
	desEncrypted, err := addRIDEncryption(plainHash, rid)
	if err != nil {
		return nil, err
	}

	// Compute RC4 key: MD5(hashedBootKey + RID + NTPASSWORD/LMPASSWORD)
	h := md5.New()
	h.Write(hashedBootKey)
	ridBytes := []byte{byte(rid), byte(rid >> 8), byte(rid >> 16), byte(rid >> 24)}
	h.Write(ridBytes)
	if isNT {
		h.Write(NTPASSWORD)
	} else {
		h.Write(LMPASSWORD)
	}
	rc4Key := h.Sum(nil)

	// RC4 encrypt
	c, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, 16)
	c.XORKeyStream(encrypted, desEncrypted)

	return encrypted, nil
}

// EncryptSAMHashAES encrypts a plain hash using AES (revision 3) for writing back to SAM
func EncryptSAMHashAES(hashedBootKey []byte, rid uint32, plainHash []byte, salt []byte, isNT bool) ([]byte, error) {
	if len(plainHash) != 16 {
		return nil, fmt.Errorf("plain hash must be 16 bytes")
	}

	// First apply RID-based DES encryption
	desEncrypted, err := addRIDEncryption(plainHash, rid)
	if err != nil {
		return nil, err
	}

	// AES-CBC encrypt
	encrypted, err := aesEncrypt(hashedBootKey, salt, desEncrypted)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// aesEncrypt performs AES-CBC encryption
func aesEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("AES key must be 16 bytes")
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("AES IV must be 16 bytes")
	}
	// Pad data to AES block size if needed
	if len(data)%16 != 0 {
		padLen := 16 - (len(data) % 16)
		data = append(data, make([]byte, padLen)...)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(result, data)

	return result, nil
}
