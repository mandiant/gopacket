// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package drsuapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"unicode/utf16"
)

// KerberosKey represents a Kerberos encryption key
type KerberosKey struct {
	KeyType  uint32 // 18=AES256, 17=AES128, 3=DES-MD5, 1=DES-CRC, 0xffffff74=RC4
	KeyValue []byte
}

// Kerberos key type constants
const (
	KERB_ETYPE_DES_CBC_CRC             = 1
	KERB_ETYPE_DES_CBC_MD5             = 3
	KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 = 17
	KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 = 18
	KERB_ETYPE_RC4_HMAC                = 0xffffff74
)

// USER_PROPERTIES header constants
const (
	userPropertiesSignature = 0x0050
	userPropertiesHeaderLen = 112 // Total header size before UserProperties array
)

// ParseSupplementalCredentials parses the decrypted supplementalCredentials
// attribute and extracts Kerberos keys
func ParseSupplementalCredentials(data []byte) ([]KerberosKey, error) {
	if len(data) < userPropertiesHeaderLen {
		return nil, nil // Too short, no keys
	}

	// USER_PROPERTIES structure:
	// [0:4]   Reserved1
	// [4:8]   Length
	// [8:10]  Reserved2
	// [10:12] Reserved3
	// [12:108] Reserved4 (96 bytes)
	// [108:110] PropertySignature (0x0050)
	// [110:112] PropertyCount
	// [112:]  UserProperties array

	signature := binary.LittleEndian.Uint16(data[108:110])
	if signature != userPropertiesSignature {
		return nil, nil // Invalid signature
	}

	propertyCount := binary.LittleEndian.Uint16(data[110:112])
	if propertyCount == 0 {
		return nil, nil
	}

	// Parse USER_PROPERTY entries
	offset := userPropertiesHeaderLen
	var keys []KerberosKey

	for i := uint16(0); i < propertyCount && offset < len(data); i++ {
		if offset+6 > len(data) {
			break
		}

		// USER_PROPERTY:
		// [0:2] NameLength
		// [2:4] ValueLength
		// [4:6] Reserved
		// [6:6+NameLength] PropertyName (UTF-16LE)
		// [6+NameLength:6+NameLength+ValueLength] PropertyValue

		nameLen := binary.LittleEndian.Uint16(data[offset : offset+2])
		valueLen := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		// reserved := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
		offset += 6

		if offset+int(nameLen) > len(data) {
			break
		}

		// Decode property name from UTF-16LE
		propertyName := decodeUTF16LE(data[offset : offset+int(nameLen)])
		offset += int(nameLen)

		if offset+int(valueLen) > len(data) {
			break
		}

		propertyValue := data[offset : offset+int(valueLen)]
		offset += int(valueLen)

		// Check for Kerberos keys property
		if propertyName == "Primary:Kerberos-Newer-Keys" {
			// PropertyValue is hex-encoded
			decoded, err := hex.DecodeString(string(propertyValue))
			if err != nil {
				continue
			}
			parsedKeys := parseKerbStoredCredentialNew(decoded)
			keys = append(keys, parsedKeys...)
		}
	}

	return keys, nil
}

// parseKerbStoredCredentialNew parses KERB_STORED_CREDENTIAL_NEW structure (Revision 4)
func parseKerbStoredCredentialNew(data []byte) []KerberosKey {
	if len(data) < 24 {
		return nil
	}

	// KERB_STORED_CREDENTIAL_NEW:
	// [0:2]   Revision (should be 4)
	// [2:4]   Flags
	// [4:6]   CredentialCount
	// [6:8]   ServiceCredentialCount
	// [8:10]  OldCredentialCount
	// [10:12] OlderCredentialCount
	// [12:14] DefaultSaltLength
	// [14:16] DefaultSaltMaximumLength
	// [16:20] DefaultSaltOffset
	// [20:24] DefaultIterationCount
	// [24:]   Buffer (contains KERB_KEY_DATA_NEW entries followed by key data)

	revision := binary.LittleEndian.Uint16(data[0:2])
	if revision != 4 {
		// Try legacy format (Revision 3)
		return parseKerbStoredCredentialLegacy(data)
	}

	credentialCount := binary.LittleEndian.Uint16(data[4:6])
	if credentialCount == 0 {
		return nil
	}

	// Buffer starts at offset 24
	buffer := data[24:]

	// Each KERB_KEY_DATA_NEW is 24 bytes
	// [0:2]   Reserved1
	// [2:4]   Reserved2
	// [4:8]   Reserved3
	// [8:12]  IterationCount
	// [12:16] KeyType
	// [16:20] KeyLength
	// [20:24] KeyOffset

	var keys []KerberosKey
	keyDataOffset := 0

	for i := uint16(0); i < credentialCount; i++ {
		if keyDataOffset+24 > len(buffer) {
			break
		}

		keyData := buffer[keyDataOffset : keyDataOffset+24]
		keyDataOffset += 24

		keyType := binary.LittleEndian.Uint32(keyData[12:16])
		keyLength := binary.LittleEndian.Uint32(keyData[16:20])
		keyOffset := binary.LittleEndian.Uint32(keyData[20:24])

		// KeyOffset is relative to start of KERB_STORED_CREDENTIAL_NEW (data), not buffer
		if int(keyOffset)+int(keyLength) > len(data) {
			continue
		}

		keyValue := make([]byte, keyLength)
		copy(keyValue, data[keyOffset:keyOffset+keyLength])

		keys = append(keys, KerberosKey{
			KeyType:  keyType,
			KeyValue: keyValue,
		})
	}

	return keys
}

// parseKerbStoredCredentialLegacy parses KERB_STORED_CREDENTIAL structure (Revision 3)
func parseKerbStoredCredentialLegacy(data []byte) []KerberosKey {
	if len(data) < 16 {
		return nil
	}

	// KERB_STORED_CREDENTIAL (Revision 3):
	// [0:2]   Revision (should be 3)
	// [2:4]   Flags
	// [4:6]   CredentialCount
	// [6:8]   OldCredentialCount
	// [8:10]  DefaultSaltLength
	// [10:12] DefaultSaltMaximumLength
	// [12:16] DefaultSaltOffset
	// [16:]   Buffer

	revision := binary.LittleEndian.Uint16(data[0:2])
	if revision != 3 {
		return nil
	}

	credentialCount := binary.LittleEndian.Uint16(data[4:6])
	if credentialCount == 0 {
		return nil
	}

	// Buffer starts at offset 16
	buffer := data[16:]

	// KERB_KEY_DATA (legacy) is 20 bytes
	// [0:2]   Reserved1
	// [2:4]   Reserved2
	// [4:8]   Reserved3
	// [8:12]  KeyType
	// [12:16] KeyLength
	// [16:20] KeyOffset

	var keys []KerberosKey
	keyDataOffset := 0

	for i := uint16(0); i < credentialCount; i++ {
		if keyDataOffset+20 > len(buffer) {
			break
		}

		keyData := buffer[keyDataOffset : keyDataOffset+20]
		keyDataOffset += 20

		keyType := binary.LittleEndian.Uint32(keyData[8:12])
		keyLength := binary.LittleEndian.Uint32(keyData[12:16])
		keyOffset := binary.LittleEndian.Uint32(keyData[16:20])

		// KeyOffset is relative to start of KERB_STORED_CREDENTIAL (data)
		if int(keyOffset)+int(keyLength) > len(data) {
			continue
		}

		keyValue := make([]byte, keyLength)
		copy(keyValue, data[keyOffset:keyOffset+keyLength])

		keys = append(keys, KerberosKey{
			KeyType:  keyType,
			KeyValue: keyValue,
		})
	}

	return keys
}

// decodeUTF16LE decodes a UTF-16LE byte slice to a string
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}

	// Remove null terminator if present
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s))
}

// GetKeyTypeName returns the human-readable name for a Kerberos key type
func GetKeyTypeName(keyType uint32) string {
	switch keyType {
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
		return "aes256-cts-hmac-sha1-96"
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
		return "aes128-cts-hmac-sha1-96"
	case KERB_ETYPE_DES_CBC_MD5:
		return "des-cbc-md5"
	case KERB_ETYPE_DES_CBC_CRC:
		return "des-cbc-crc"
	case KERB_ETYPE_RC4_HMAC:
		return "rc4_hmac"
	default:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, keyType)
		return "unknown-0x" + hex.EncodeToString(buf.Bytes())
	}
}
