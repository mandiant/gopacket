// SPDX-License-Identifier: Apache-2.0

package dpapi

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
)

// BKRP GUIDs for backup key retrieval
var (
	// BACKUPKEY_BACKUP_GUID - 7F752B10-178E-11D1-AB8F-00805F14DB40 - backup a secret (ServerWrap)
	BACKUPKEY_BACKUP_GUID = [16]byte{
		0x10, 0x2B, 0x75, 0x7F, 0x8E, 0x17, 0xD1, 0x11,
		0xAB, 0x8F, 0x00, 0x80, 0x5F, 0x14, 0xDB, 0x40,
	}

	// BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID - 018FF48A-EABA-40C6-8F6D-72370240E967 - retrieve backup key
	BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = [16]byte{
		0x8A, 0xF4, 0x8F, 0x01, 0xBA, 0xEA, 0xC6, 0x40,
		0x8F, 0x6D, 0x72, 0x37, 0x02, 0x40, 0xE9, 0x67,
	}

	// BACKUPKEY_RESTORE_GUID_WIN2K - 7FE94D50-178E-11D1-AB8F-00805F14DB40 - legacy restore (ServerWrap)
	BACKUPKEY_RESTORE_GUID_WIN2K = [16]byte{
		0x50, 0x4D, 0xE9, 0x7F, 0x8E, 0x17, 0xD1, 0x11,
		0xAB, 0x8F, 0x00, 0x80, 0x5F, 0x14, 0xDB, 0x40,
	}
)

// BackupKey represents a domain backup key
type BackupKey struct {
	Version     uint32
	Magic       uint32
	KeyLength   uint32
	Certificate []byte
	PrivateKey  *rsa.PrivateKey
	PVKData     []byte
}

// PVKFileHeader represents the PVK file header
type PVKFileHeader struct {
	Magic      uint32 // 0xb0b5f11e
	Reserved   uint32
	KeyType    uint32
	Encrypted  uint32
	SaltLength uint32
	KeyLength  uint32
}

// PreferredBackupKey represents the GUID pointing to the preferred backup key
type PreferredBackupKey struct {
	GUID [16]byte
}

// PrivateKeyBlob represents a PRIVATEKEYBLOB structure
type PrivateKeyBlob struct {
	PublicKeyStruc struct {
		Type     byte
		Version  byte
		Reserved uint16
		AlgID    uint32
	}
	RSAPubKey struct {
		Magic  uint32 // "RSA2" = 0x32415352
		BitLen uint32
		PubExp uint32
	}
	Modulus         []byte
	Prime1          []byte // p
	Prime2          []byte // q
	Exponent1       []byte // d mod (p-1)
	Exponent2       []byte // d mod (q-1)
	Coefficient     []byte // q^-1 mod p
	PrivateExponent []byte // d
}

// ParseBackupKeyResponse parses the response from BKRP
func ParseBackupKeyResponse(data []byte) (*BackupKey, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short for backup key")
	}

	bk := &BackupKey{}

	// Check first byte to determine format
	if data[0] == 0x30 {
		// DER-encoded X.509 certificate (starts with SEQUENCE)
		// This is the response from BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID
		bk.Certificate = data
		bk.Version = 1

		// Try to extract the public key from the certificate
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				// Store as a partial private key (just the public part)
				bk.PrivateKey = &rsa.PrivateKey{
					PublicKey: *rsaKey,
				}
			}
		}
		return bk, nil
	}

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &bk.Version)

	// Check for PVK magic first
	if binary.LittleEndian.Uint32(data[0:4]) == 0xb0b5f11e {
		return parsePVKBackupKey(data)
	}

	// Version 2 BACKUP_KEY structure from LSA secret
	if bk.Version == 2 {
		return ParsePrivateKeyData(data)
	}

	// Version 1 - certificate with length prefix
	r.Seek(0, 0)
	var certLen uint32
	binary.Read(r, binary.LittleEndian, &certLen)

	if certLen > uint32(len(data)-4) {
		// Try parsing as raw PRIVATEKEYBLOB
		return parsePrivateKeyBlob(data)
	}

	bk.Certificate = make([]byte, certLen)
	r.Read(bk.Certificate)

	return bk, nil
}

// parsePVKBackupKey parses a PVK-format backup key
func parsePVKBackupKey(data []byte) (*BackupKey, error) {
	bk := &BackupKey{}
	bk.PVKData = data

	// Check PVK magic
	if len(data) < 24 {
		return nil, fmt.Errorf("data too short for PVK header")
	}

	// PVK header
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0xb0b5f11e {
		// Not a PVK file, might be raw PRIVATEKEYBLOB
		return parsePrivateKeyBlob(data)
	}

	// Parse PVK header
	hdr := &PVKFileHeader{
		Magic:      magic,
		Reserved:   binary.LittleEndian.Uint32(data[4:8]),
		KeyType:    binary.LittleEndian.Uint32(data[8:12]),
		Encrypted:  binary.LittleEndian.Uint32(data[12:16]),
		SaltLength: binary.LittleEndian.Uint32(data[16:20]),
		KeyLength:  binary.LittleEndian.Uint32(data[20:24]),
	}

	if hdr.Encrypted != 0 {
		return nil, fmt.Errorf("encrypted PVK files not supported")
	}

	// Key data starts after header and salt
	keyData := data[24+hdr.SaltLength:]
	return parsePrivateKeyBlob(keyData)
}

// parsePrivateKeyBlob parses a Windows PRIVATEKEYBLOB structure
func parsePrivateKeyBlob(data []byte) (*BackupKey, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for PRIVATEKEYBLOB")
	}

	bk := &BackupKey{}
	pkb := &PrivateKeyBlob{}

	r := bytes.NewReader(data)

	// PUBLICKEYSTRUC
	binary.Read(r, binary.LittleEndian, &pkb.PublicKeyStruc.Type)
	binary.Read(r, binary.LittleEndian, &pkb.PublicKeyStruc.Version)
	binary.Read(r, binary.LittleEndian, &pkb.PublicKeyStruc.Reserved)
	binary.Read(r, binary.LittleEndian, &pkb.PublicKeyStruc.AlgID)

	// RSAPUBKEY
	binary.Read(r, binary.LittleEndian, &pkb.RSAPubKey.Magic)
	binary.Read(r, binary.LittleEndian, &pkb.RSAPubKey.BitLen)
	binary.Read(r, binary.LittleEndian, &pkb.RSAPubKey.PubExp)

	// Check magic
	if pkb.RSAPubKey.Magic != 0x32415352 { // "RSA2"
		return nil, fmt.Errorf("invalid RSA key magic: 0x%x", pkb.RSAPubKey.Magic)
	}

	byteLen := int(pkb.RSAPubKey.BitLen / 8)
	halfLen := byteLen / 2

	// Read key components
	pkb.Modulus = make([]byte, byteLen)
	r.Read(pkb.Modulus)

	pkb.Prime1 = make([]byte, halfLen)
	r.Read(pkb.Prime1)

	pkb.Prime2 = make([]byte, halfLen)
	r.Read(pkb.Prime2)

	pkb.Exponent1 = make([]byte, halfLen)
	r.Read(pkb.Exponent1)

	pkb.Exponent2 = make([]byte, halfLen)
	r.Read(pkb.Exponent2)

	pkb.Coefficient = make([]byte, halfLen)
	r.Read(pkb.Coefficient)

	pkb.PrivateExponent = make([]byte, byteLen)
	r.Read(pkb.PrivateExponent)

	// Convert to Go RSA key (need to reverse byte order - Windows uses little-endian)
	bk.PrivateKey = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(reverseBytes(pkb.Modulus)),
			E: int(pkb.RSAPubKey.PubExp),
		},
		D: new(big.Int).SetBytes(reverseBytes(pkb.PrivateExponent)),
		Primes: []*big.Int{
			new(big.Int).SetBytes(reverseBytes(pkb.Prime1)),
			new(big.Int).SetBytes(reverseBytes(pkb.Prime2)),
		},
	}

	// Precompute for better performance
	bk.PrivateKey.Precompute()

	return bk, nil
}

// ToPEM converts the backup key to PEM format
func (bk *BackupKey) ToPEM() ([]byte, error) {
	if bk.PrivateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}

	derBytes := x509.MarshalPKCS1PrivateKey(bk.PrivateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// ToPVK converts the backup key to PVK format
func (bk *BackupKey) ToPVK() []byte {
	if bk.PVKData != nil {
		return bk.PVKData
	}
	// Future enhancement: Implement conversion from RSA key to PVK
	return nil
}

// Dump prints backup key information
func (bk *BackupKey) Dump() {
	fmt.Println("[BACKUP KEY]")
	fmt.Printf("Version     : %d\n", bk.Version)
	if bk.PrivateKey != nil {
		fmt.Printf("Key Size    : %d bits\n", bk.PrivateKey.N.BitLen())
		fmt.Printf("Public Exp  : %d\n", bk.PrivateKey.E)
		fmt.Printf("Modulus     : %s...\n", hex.EncodeToString(bk.PrivateKey.N.Bytes()[:32]))
	}
	if len(bk.Certificate) > 0 {
		fmt.Printf("Certificate : %d bytes\n", len(bk.Certificate))
	}
	fmt.Println()
}

// reverseBytes reverses a byte slice (for little-endian to big-endian conversion)
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// ParsePrivateKeyData parses raw backup key data from LSA secrets
// The format depends on the version stored in LSA
func ParsePrivateKeyData(data []byte) (*BackupKey, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short")
	}

	// Check for PVK magic (0xb0b5f11e)
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic == 0xb0b5f11e {
		return parsePVKBackupKey(data)
	}

	// Check for PRIVATEKEYBLOB header (bType=0x07, bVersion=0x02)
	if data[0] == 0x07 && data[1] == 0x02 {
		return parsePrivateKeyBlob(data)
	}

	// Check version field (version 2 = BACKUP_KEY structure from LSA secret)
	version := binary.LittleEndian.Uint32(data[0:4])
	if version == 2 {
		// BACKUP_KEY structure (from G$BCKUPKEY_<GUID>):
		// Version (4) + PrivKeyLength (4) + CertificateLength (4) + PrivKey + Cert
		if len(data) < 12 {
			return nil, fmt.Errorf("data too short for v2 structure")
		}

		privKeyLen := binary.LittleEndian.Uint32(data[4:8])
		certLen := binary.LittleEndian.Uint32(data[8:12])

		offset := uint32(12)
		if uint32(len(data)) < offset+privKeyLen+certLen {
			return nil, fmt.Errorf("data too short for v2 content: have %d, need %d", len(data), offset+privKeyLen+certLen)
		}

		// Parse private key blob (starts at offset 12)
		bk, err := parsePrivateKeyBlob(data[offset : offset+privKeyLen])
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		// Store certificate
		if certLen > 0 {
			bk.Certificate = make([]byte, certLen)
			copy(bk.Certificate, data[offset+privKeyLen:])
		}
		bk.Version = 2

		return bk, nil
	}

	// Try version 1 (P_BACKUP_KEY structure)
	if version == 1 {
		// P_BACKUP_KEY: Version(4) + KeyLength(4) + CertLen(4) + Key(KeyLen) + Cert(CertLen)
		if len(data) < 12 {
			return nil, fmt.Errorf("data too short for v1 structure")
		}

		keyLen := binary.LittleEndian.Uint32(data[4:8])
		certLen := binary.LittleEndian.Uint32(data[8:12])

		offset := 12
		if uint32(len(data)) < uint32(offset)+keyLen+certLen {
			return nil, fmt.Errorf("data too short for v1 content")
		}

		// The key data is a PRIVATEKEYBLOB
		bk, err := parsePrivateKeyBlob(data[offset : uint32(offset)+keyLen])
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		bk.Certificate = make([]byte, certLen)
		copy(bk.Certificate, data[uint32(offset)+keyLen:])
		bk.Version = 1

		return bk, nil
	}

	// Try as raw PRIVATEKEYBLOB
	return parsePrivateKeyBlob(data)
}

// DecryptWithBackupKey decrypts a domain key using the domain backup key
func DecryptWithBackupKey(domainKey *DomainKey, backupKey *BackupKey) ([]byte, error) {
	if backupKey.PrivateKey == nil {
		return nil, fmt.Errorf("backup key has no private key")
	}

	// The domain key secret is RSA encrypted
	// We need to use PKCS1v15 decryption
	plaintext, err := rsa.DecryptPKCS1v15(nil, backupKey.PrivateKey, domainKey.Secret)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %v", err)
	}

	return plaintext, nil
}

// LoadPVKFile loads a backup key from a PVK file
func LoadPVKFile(data []byte) (*BackupKey, error) {
	return parsePVKBackupKey(data)
}

// LoadPEMFile loads a backup key from a PEM file
func LoadPEMFile(data []byte) (*BackupKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var privateKey *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return &BackupKey{
		PrivateKey: privateKey,
		Version:    1,
	}, nil
}

// LoadBackupKeyFile loads a backup key from either PVK or PEM format
func LoadBackupKeyFile(data []byte) (*BackupKey, error) {
	// Check for PEM format
	if bytes.HasPrefix(data, []byte("-----BEGIN")) {
		return LoadPEMFile(data)
	}

	// Check for PVK magic
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[0:4]) == 0xb0b5f11e {
		return LoadPVKFile(data)
	}

	// Try parsing as raw PRIVATEKEYBLOB
	return parsePrivateKeyBlob(data)
}
