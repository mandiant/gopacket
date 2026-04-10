// SPDX-License-Identifier: Apache-2.0

package dpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Vault schema GUIDs
var (
	// Windows Web Credentials
	VaultSchemaWebCredentials = [16]byte{
		0x3E, 0x0E, 0x35, 0xBE, 0x1B, 0x77, 0xD3, 0x01,
		0xBD, 0xFC, 0x00, 0xC0, 0x4F, 0xC2, 0xF3, 0xB7,
	}
	// Windows Credential Picker Protector
	VaultSchemaCredPickerProtector = [16]byte{
		0xE6, 0x9D, 0x70, 0x74, 0x39, 0x7E, 0x5E, 0x40,
		0xB1, 0x81, 0xC0, 0x26, 0x10, 0x81, 0x95, 0xF9,
	}
	// Windows Domain Password Credential
	VaultSchemaDomainPassword = [16]byte{
		0xE4, 0x6C, 0x2E, 0x92, 0xC2, 0x74, 0x0E, 0x49,
		0x80, 0xBE, 0xA6, 0x2F, 0x5E, 0xE7, 0x85, 0xE3,
	}
	// Windows Domain Certificate Credential
	VaultSchemaDomainCertificate = [16]byte{
		0x27, 0x1E, 0xE6, 0x88, 0xBB, 0x5D, 0x9F, 0x47,
		0xB5, 0x49, 0xE4, 0x73, 0x9B, 0xB0, 0xD0, 0x14,
	}
	// Windows Extended Credential
	VaultSchemaExtended = [16]byte{
		0x15, 0xE3, 0xA7, 0x3D, 0x30, 0xCA, 0xE3, 0x4E,
		0x8A, 0x25, 0xCE, 0x83, 0x05, 0x03, 0x05, 0x3E,
	}
	// Windows Domain Password Credential (NGC)
	VaultSchemaNGCPassword = [16]byte{
		0x83, 0x3E, 0x0A, 0xF9, 0x8D, 0x47, 0x75, 0x42,
		0x8A, 0xC7, 0xCD, 0xF9, 0xAD, 0x97, 0x4F, 0x42,
	}
)

// VaultPolicy represents a VPOL file structure
type VaultPolicy struct {
	Version     uint32
	GUID        string
	Description string
	Unknown1    uint32
	Unknown2    uint32
	Unknown3    uint32
	DPAPIBlob   *DPAPIBlob
	KeyAES256   []byte // Decrypted AES-256 key
	KeyAES128   []byte // Decrypted AES-128 key
}

// VaultCredential represents a VCRD file structure
type VaultCredential struct {
	SchemaGUID     string
	Unknown1       uint32
	LastWritten    uint64
	Unknown2       uint32
	Unknown3       uint32
	FriendlyName   string
	AttributeCount uint32
	Attributes     []*VaultAttribute
	DecryptedClear []byte
}

// VaultAttribute represents an attribute in a vault credential
type VaultAttribute struct {
	ID       uint32
	Unknown1 uint32
	Unknown2 uint32
	Unknown3 uint32
	HasIV    bool
	IV       []byte
	Data     []byte
}

// VaultAttributeItem represents a decoded vault attribute
type VaultAttributeItem struct {
	ID       uint32
	Keyword  string
	Resource string
	Identity string
	Password string
}

// ParseVaultPolicy parses a VPOL file
func ParseVaultPolicy(data []byte) (*VaultPolicy, error) {
	if len(data) < 36 {
		return nil, fmt.Errorf("data too short for vault policy")
	}

	vp := &VaultPolicy{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &vp.Version)

	// GUID (16 bytes)
	guidBytes := make([]byte, 16)
	r.Read(guidBytes)
	vp.GUID = guidToString(guidBytes)

	// Description length and string
	var descLen uint32
	binary.Read(r, binary.LittleEndian, &descLen)
	if descLen > 0 && descLen < 4096 {
		descBytes := make([]byte, descLen)
		r.Read(descBytes)
		vp.Description = utf16ToString(descBytes)
	}

	// Read unknown fields based on version
	if vp.Version >= 1 {
		binary.Read(r, binary.LittleEndian, &vp.Unknown1)
		binary.Read(r, binary.LittleEndian, &vp.Unknown2)
		binary.Read(r, binary.LittleEndian, &vp.Unknown3)
	}

	// The rest should be a DPAPI blob
	pos, _ := r.Seek(0, 1)
	if pos < int64(len(data)) {
		// Skip to DPAPI blob
		// The DPAPI blob typically starts with version 0x01 at a certain offset
		remaining := data[pos:]

		// Try to find DPAPI blob start (version = 1)
		for i := 0; i < len(remaining)-4; i++ {
			if binary.LittleEndian.Uint32(remaining[i:i+4]) == 1 {
				// Check if this looks like a DPAPI blob (provider GUID follows)
				if i+20 < len(remaining) {
					blob, err := ParseDPAPIBlob(remaining[i:])
					if err == nil {
						vp.DPAPIBlob = blob
						break
					}
				}
			}
		}
	}

	return vp, nil
}

// ParseVaultCredential parses a VCRD file
func ParseVaultCredential(data []byte) (*VaultCredential, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("data too short for vault credential")
	}

	vc := &VaultCredential{}
	r := bytes.NewReader(data)

	// Schema GUID (16 bytes)
	schemaGUID := make([]byte, 16)
	r.Read(schemaGUID)
	vc.SchemaGUID = guidToString(schemaGUID)

	binary.Read(r, binary.LittleEndian, &vc.Unknown1)
	binary.Read(r, binary.LittleEndian, &vc.LastWritten)
	binary.Read(r, binary.LittleEndian, &vc.Unknown2)
	binary.Read(r, binary.LittleEndian, &vc.Unknown3)

	// Friendly name
	var friendlyLen uint32
	binary.Read(r, binary.LittleEndian, &friendlyLen)
	if friendlyLen > 0 && friendlyLen < 4096 {
		friendlyBytes := make([]byte, friendlyLen)
		r.Read(friendlyBytes)
		vc.FriendlyName = utf16ToString(friendlyBytes)
	}

	// Attribute count
	binary.Read(r, binary.LittleEndian, &vc.AttributeCount)

	// Skip unknown count field
	var unknownCount uint32
	binary.Read(r, binary.LittleEndian, &unknownCount)

	// Parse attributes
	for i := uint32(0); i < vc.AttributeCount; i++ {
		attr, err := parseVaultAttribute(r)
		if err != nil {
			break
		}
		vc.Attributes = append(vc.Attributes, attr)
	}

	return vc, nil
}

// parseVaultAttribute parses a single vault attribute
func parseVaultAttribute(r *bytes.Reader) (*VaultAttribute, error) {
	attr := &VaultAttribute{}

	binary.Read(r, binary.LittleEndian, &attr.ID)

	// Check for end marker
	if attr.ID == 0 {
		return nil, fmt.Errorf("end of attributes")
	}

	binary.Read(r, binary.LittleEndian, &attr.Unknown1)
	binary.Read(r, binary.LittleEndian, &attr.Unknown2)
	binary.Read(r, binary.LittleEndian, &attr.Unknown3)

	// Check if there's an IV
	var hasIV uint32
	binary.Read(r, binary.LittleEndian, &hasIV)
	attr.HasIV = hasIV == 1

	if attr.HasIV {
		attr.IV = make([]byte, 16)
		r.Read(attr.IV)
	}

	// Data
	var dataLen uint32
	binary.Read(r, binary.LittleEndian, &dataLen)
	if dataLen > 0 && dataLen < 65536 {
		attr.Data = make([]byte, dataLen)
		r.Read(attr.Data)
	}

	return attr, nil
}

// Decrypt decrypts the vault policy using a master key
func (vp *VaultPolicy) Decrypt(masterKey []byte) error {
	if vp.DPAPIBlob == nil {
		return fmt.Errorf("no DPAPI blob in vault policy")
	}

	decrypted, err := vp.DPAPIBlob.Decrypt(masterKey)
	if err != nil {
		return err
	}

	// The decrypted data contains AES keys
	// Format: key_count (4 bytes) + [key_size (4) + key_data]...
	if len(decrypted) < 4 {
		return fmt.Errorf("decrypted data too short")
	}

	r := bytes.NewReader(decrypted)
	var keyCount uint32
	binary.Read(r, binary.LittleEndian, &keyCount)

	for i := uint32(0); i < keyCount && i < 10; i++ {
		var keySize uint32
		if err := binary.Read(r, binary.LittleEndian, &keySize); err != nil {
			break
		}
		if keySize > 64 {
			break
		}

		key := make([]byte, keySize)
		if _, err := r.Read(key); err != nil {
			break
		}

		switch keySize {
		case 32:
			vp.KeyAES256 = key
		case 16:
			vp.KeyAES128 = key
		}
	}

	return nil
}

// Decrypt decrypts vault credential attributes using policy keys
func (vc *VaultCredential) Decrypt(keyAES256, keyAES128 []byte) error {
	for _, attr := range vc.Attributes {
		if len(attr.Data) == 0 {
			continue
		}

		var key []byte
		if len(attr.IV) > 0 {
			// Use AES-256 with IV for encrypted attributes
			if len(keyAES256) > 0 {
				key = keyAES256
			}
		}

		if key != nil && len(attr.Data) > 0 && len(attr.Data)%16 == 0 {
			// AES-CBC decryption with IV
			decrypted, err := decryptAES256WithIV(key, attr.IV, attr.Data)
			if err == nil {
				attr.Data = decrypted
			}
		}
	}

	return nil
}

// decryptAES256WithIV decrypts using AES-256-CBC with a specific IV
func decryptAES256WithIV(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data length must be multiple of 16")
	}

	if len(iv) != 16 {
		return nil, fmt.Errorf("IV must be 16 bytes")
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)

	// Remove PKCS7 padding
	return unpad(plaintext)
}

// Dump prints vault policy information
func (vp *VaultPolicy) Dump() {
	fmt.Println("[VAULT POLICY]")
	fmt.Printf("Version     : %d\n", vp.Version)
	fmt.Printf("GUID        : %s\n", vp.GUID)
	fmt.Printf("Description : %s\n", vp.Description)
	if vp.DPAPIBlob != nil {
		fmt.Printf("DPAPI Blob  : present (MK GUID: %s)\n", vp.DPAPIBlob.GUIDMasterKey)
	}
	if len(vp.KeyAES256) > 0 {
		fmt.Printf("AES-256 Key : %s\n", hex.EncodeToString(vp.KeyAES256))
	}
	if len(vp.KeyAES128) > 0 {
		fmt.Printf("AES-128 Key : %s\n", hex.EncodeToString(vp.KeyAES128))
	}
	fmt.Println()
}

// Dump prints vault credential information
func (vc *VaultCredential) Dump() {
	fmt.Println("[VAULT CREDENTIAL]")
	fmt.Printf("Schema GUID   : %s\n", vc.SchemaGUID)
	fmt.Printf("Friendly Name : %s\n", vc.FriendlyName)
	fmt.Printf("Last Written  : %d\n", vc.LastWritten)
	fmt.Printf("Attributes    : %d\n", len(vc.Attributes))

	for i, attr := range vc.Attributes {
		fmt.Printf("\n  [Attribute %d]\n", i)
		fmt.Printf("  ID       : %d\n", attr.ID)
		if attr.HasIV {
			fmt.Printf("  IV       : %s\n", hex.EncodeToString(attr.IV))
		}
		if len(attr.Data) > 0 {
			// Try to decode as string
			if isASCII(attr.Data) {
				fmt.Printf("  Data     : %s\n", string(attr.Data))
			} else if isUTF16(attr.Data) {
				fmt.Printf("  Data     : %s\n", utf16ToString(attr.Data))
			} else {
				fmt.Printf("  Data     : %s\n", hex.EncodeToString(attr.Data))
			}
		}
	}
	fmt.Println()
}

// GetSchemaName returns a human-readable name for the vault schema
func (vc *VaultCredential) GetSchemaName() string {
	switch vc.SchemaGUID {
	case guidToString(VaultSchemaWebCredentials[:]):
		return "Web Credentials"
	case guidToString(VaultSchemaCredPickerProtector[:]):
		return "Credential Picker Protector"
	case guidToString(VaultSchemaDomainPassword[:]):
		return "Domain Password Credential"
	case guidToString(VaultSchemaDomainCertificate[:]):
		return "Domain Certificate Credential"
	case guidToString(VaultSchemaExtended[:]):
		return "Extended Credential"
	case guidToString(VaultSchemaNGCPassword[:]):
		return "NGC Password Credential"
	default:
		return "Unknown Schema"
	}
}
