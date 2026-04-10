// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

// Package dpaping implements DPAPI-NG (Data Protection API - Next Generation) decryption
// for LAPS v2 encrypted passwords.
package dpaping

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"

	"gopacket/pkg/dcerpc/gkdi"
)

var (
	KDS_SERVICE_LABEL    = utf16le("KDS service\x00")
	KEK_PUBLIC_KEY_LABEL = utf16le("KDS public key\x00")
)

// EncryptedPasswordBlob represents the msLAPS-EncryptedPassword structure.
type EncryptedPasswordBlob struct {
	TimestampLower uint32
	TimestampUpper uint32
	Length         uint32
	Flags          uint32
	Blob           []byte
}

// KeyIdentifier represents the key identifier from CMS KEKRecipientInfo.
type KeyIdentifier struct {
	Version    uint32
	Magic      uint32
	Flags      uint32
	L0Index    uint32
	L1Index    uint32
	L2Index    uint32
	RootKeyID  [16]byte
	UnknownLen uint32
	DomainLen  uint32
	ForestLen  uint32
	Unknown    []byte
	Domain     []byte
	Forest     []byte
}

// CMSEnvelopedData holds parsed CMS EnvelopedData fields needed for decryption.
type CMSEnvelopedData struct {
	KeyIdentifier []byte // Raw key identifier bytes
	EncryptedKey  []byte // Wrapped CEK
	IV            []byte // Content encryption IV/nonce
	Ciphertext    []byte // Encrypted content
	SID           string // Security identifier from key attributes
}

// ParseEncryptedPasswordBlob parses the msLAPS-EncryptedPassword attribute value.
func ParseEncryptedPasswordBlob(data []byte) (*EncryptedPasswordBlob, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short for EncryptedPasswordBlob")
	}

	blob := &EncryptedPasswordBlob{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &blob.TimestampLower)
	binary.Read(r, binary.LittleEndian, &blob.TimestampUpper)
	binary.Read(r, binary.LittleEndian, &blob.Length)
	binary.Read(r, binary.LittleEndian, &blob.Flags)

	blob.Blob = make([]byte, blob.Length)
	r.Read(blob.Blob)

	return blob, nil
}

// ParseCMSEnvelopedData parses the CMS EnvelopedData structure from the blob.
// This is a simplified DER parser for the specific CMS structure used in LAPS v2.
func ParseCMSEnvelopedData(data []byte) (*CMSEnvelopedData, []byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("data too short for CMS")
	}

	cms := &CMSEnvelopedData{}
	pos := 0

	// ContentInfo SEQUENCE
	if data[pos] != 0x30 {
		return nil, nil, fmt.Errorf("expected SEQUENCE at start")
	}
	pos++
	_, pos = readDerLength(data, pos)

	// contentType OID (1.2.840.113549.1.7.3 = enveloped-data)
	if data[pos] != 0x06 {
		return nil, nil, fmt.Errorf("expected OID for contentType")
	}
	pos++
	oidLen, pos := readDerLength(data, pos)
	pos += oidLen // Skip OID

	// content [0] EXPLICIT EnvelopedData
	if data[pos] != 0xa0 {
		return nil, nil, fmt.Errorf("expected context tag [0]")
	}
	pos++
	_, pos = readDerLength(data, pos)

	// EnvelopedData SEQUENCE
	if data[pos] != 0x30 {
		return nil, nil, fmt.Errorf("expected EnvelopedData SEQUENCE")
	}
	pos++
	envDataLen, newPos := readDerLength(data, pos)
	envDataEnd := newPos + envDataLen
	pos = newPos

	// version INTEGER
	if data[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected version INTEGER")
	}
	pos++
	verLen, pos := readDerLength(data, pos)
	pos += verLen // Skip version

	// recipientInfos SET
	if data[pos] != 0x31 {
		return nil, nil, fmt.Errorf("expected recipientInfos SET")
	}
	pos++
	recipInfosLen, newPos := readDerLength(data, pos)
	recipInfosEnd := newPos + recipInfosLen
	pos = newPos

	// Parse KEKRecipientInfo [2]
	if data[pos] != 0xa2 {
		return nil, nil, fmt.Errorf("expected KEKRecipientInfo [2], got 0x%02x", data[pos])
	}
	pos++
	_, pos = readDerLength(data, pos)

	// version INTEGER
	if data[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected kekri version")
	}
	pos++
	kekVerLen, pos := readDerLength(data, pos)
	pos += kekVerLen

	// kekid KEKIdentifier SEQUENCE
	if data[pos] != 0x30 {
		return nil, nil, fmt.Errorf("expected kekid SEQUENCE")
	}
	pos++
	kekidLen, newPos := readDerLength(data, pos)
	kekidEnd := newPos + kekidLen
	pos = newPos

	// keyIdentifier OCTET STRING
	if data[pos] != 0x04 {
		return nil, nil, fmt.Errorf("expected keyIdentifier OCTET STRING")
	}
	pos++
	keyIdLen, pos := readDerLength(data, pos)
	cms.KeyIdentifier = data[pos : pos+keyIdLen]
	pos += keyIdLen

	// date [0] OPTIONAL - skip if present
	if pos < kekidEnd && data[pos] == 0x80 {
		pos++
		dateLen, newPos := readDerLength(data, pos)
		pos = newPos + dateLen
	}

	// other [1] OPTIONAL - contains SID
	if pos < kekidEnd && data[pos] == 0xa1 {
		pos++
		otherLen, newPos := readDerLength(data, pos)
		otherEnd := newPos + otherLen
		pos = newPos

		// OtherKeyAttribute SEQUENCE
		if data[pos] == 0x30 {
			pos++
			_, pos = readDerLength(data, pos)

			// keyAttrId OID - skip
			if data[pos] == 0x06 {
				pos++
				attrOidLen, pos2 := readDerLength(data, pos)
				pos = pos2 + attrOidLen
			}

			// keyAttr ANY - contains SID
			// This is a SET containing SEQUENCE with OID and UTF8String
			if pos < otherEnd && data[pos] == 0x31 {
				pos++
				_, pos = readDerLength(data, pos)

				if data[pos] == 0x30 {
					pos++
					_, pos = readDerLength(data, pos)

					// Skip OID
					if data[pos] == 0x06 {
						pos++
						sidOidLen, pos2 := readDerLength(data, pos)
						pos = pos2 + sidOidLen
					}

					// Read SID (UTF8String or PrintableString)
					if data[pos] == 0x0c || data[pos] == 0x13 {
						pos++
						sidLen, pos2 := readDerLength(data, pos)
						cms.SID = string(data[pos2 : pos2+sidLen])
						pos = pos2 + sidLen
					}
				}
			}
		}
		pos = otherEnd
	}
	pos = kekidEnd

	// keyEncryptionAlgorithm AlgorithmIdentifier - skip
	if data[pos] == 0x30 {
		pos++
		algLen, pos2 := readDerLength(data, pos)
		pos = pos2 + algLen
	}

	// encryptedKey OCTET STRING
	if data[pos] != 0x04 {
		return nil, nil, fmt.Errorf("expected encryptedKey OCTET STRING, got 0x%02x", data[pos])
	}
	pos++
	encKeyLen, pos := readDerLength(data, pos)
	cms.EncryptedKey = data[pos : pos+encKeyLen]
	pos += encKeyLen

	pos = recipInfosEnd

	// encryptedContentInfo EncryptedContentInfo SEQUENCE
	if data[pos] != 0x30 {
		return nil, nil, fmt.Errorf("expected encryptedContentInfo SEQUENCE")
	}
	pos++
	encContentLen, newPos := readDerLength(data, pos)
	encContentEnd := newPos + encContentLen
	pos = newPos

	// contentType OID - skip
	if data[pos] == 0x06 {
		pos++
		ctOidLen, pos2 := readDerLength(data, pos)
		pos = pos2 + ctOidLen
	}

	// contentEncryptionAlgorithm AlgorithmIdentifier
	if data[pos] == 0x30 {
		pos++
		ceaLen, newPos := readDerLength(data, pos)
		ceaEnd := newPos + ceaLen
		pos = newPos

		// Skip algorithm OID
		if data[pos] == 0x06 {
			pos++
			ceaOidLen, pos2 := readDerLength(data, pos)
			pos = pos2 + ceaOidLen
		}

		// parameters - contains IV for AES-GCM
		// SEQUENCE containing OCTET STRING (nonce) and INTEGER (tag length)
		if pos < ceaEnd && data[pos] == 0x30 {
			pos++
			_, pos = readDerLength(data, pos)

			// nonce OCTET STRING
			if data[pos] == 0x04 {
				pos++
				ivLen, pos2 := readDerLength(data, pos)
				cms.IV = data[pos2 : pos2+ivLen]
				pos = pos2 + ivLen
			}
		}
		pos = ceaEnd
	}

	// encryptedContent [0] IMPLICIT OCTET STRING
	if data[pos] == 0x80 {
		pos++
		encLen, pos2 := readDerLength(data, pos)
		cms.Ciphertext = data[pos2 : pos2+encLen]
		pos = pos2 + encLen
	}
	pos = encContentEnd

	// Return remaining data after CMS structure
	remaining := data[envDataEnd:]
	if pos < len(data) {
		remaining = data[pos:]
	}

	return cms, remaining, nil
}

// readDerLength reads a DER length and returns the length value and new position.
func readDerLength(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return 0, pos
	}
	b := data[pos]
	pos++
	if b < 0x80 {
		return int(b), pos
	}
	numBytes := int(b & 0x7f)
	if numBytes == 0 || pos+numBytes > len(data) {
		return 0, pos
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[pos])
		pos++
	}
	return length, pos
}

// ParseKeyIdentifier parses the key identifier from CMS.
func ParseKeyIdentifier(data []byte) (*KeyIdentifier, error) {
	if len(data) < 52 {
		return nil, fmt.Errorf("data too short for KeyIdentifier: %d", len(data))
	}

	ki := &KeyIdentifier{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &ki.Version)
	binary.Read(r, binary.LittleEndian, &ki.Magic)
	binary.Read(r, binary.LittleEndian, &ki.Flags)
	binary.Read(r, binary.LittleEndian, &ki.L0Index)
	binary.Read(r, binary.LittleEndian, &ki.L1Index)
	binary.Read(r, binary.LittleEndian, &ki.L2Index)
	r.Read(ki.RootKeyID[:])
	binary.Read(r, binary.LittleEndian, &ki.UnknownLen)
	binary.Read(r, binary.LittleEndian, &ki.DomainLen)
	binary.Read(r, binary.LittleEndian, &ki.ForestLen)

	ki.Unknown = make([]byte, ki.UnknownLen)
	r.Read(ki.Unknown)

	ki.Domain = make([]byte, ki.DomainLen)
	r.Read(ki.Domain)

	ki.Forest = make([]byte, ki.ForestLen)
	r.Read(ki.Forest)

	return ki, nil
}

// IsPublicKey returns true if the key identifier uses public key derivation.
func (ki *KeyIdentifier) IsPublicKey() bool {
	return ki.Flags&1 != 0
}

// CreateSecurityDescriptor creates a security descriptor for the GKDI GetKey call.
// The SID should be in string format like "S-1-5-21-..."
func CreateSecurityDescriptor(sid string) []byte {
	// Build a minimal security descriptor with:
	// - Owner SID: S-1-5-18 (Local System)
	// - Group SID: S-1-5-18 (Local System)
	// - DACL with:
	//   - ACE allowing SID with mask 0x03
	//   - ACE allowing S-1-1-0 (Everyone) with mask 0x02

	ownerSid := parseSidToBytes("S-1-5-18")
	groupSid := parseSidToBytes("S-1-5-18")
	targetSid := parseSidToBytes(sid)
	everyoneSid := parseSidToBytes("S-1-1-0")

	// Build ACEs
	ace1 := buildAce(0x00, 0x03, targetSid)   // ACCESS_ALLOWED_ACE, mask=3
	ace2 := buildAce(0x00, 0x02, everyoneSid) // ACCESS_ALLOWED_ACE, mask=2

	// Build ACL
	aclSize := 8 + len(ace1) + len(ace2)
	acl := make([]byte, aclSize)
	acl[0] = 0x02 // AclRevision
	acl[1] = 0x00 // Sbz1
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], 2) // AceCount
	binary.LittleEndian.PutUint16(acl[6:8], 0) // Sbz2
	copy(acl[8:], ace1)
	copy(acl[8+len(ace1):], ace2)

	// Calculate offsets
	headerSize := 20
	ownerOffset := headerSize
	groupOffset := ownerOffset + len(ownerSid)
	daclOffset := groupOffset + len(groupSid)
	totalSize := daclOffset + len(acl)

	sd := make([]byte, totalSize)
	sd[0] = 0x01 // Revision
	sd[1] = 0x00 // Sbz1
	// Control: SE_DACL_PRESENT | SE_SELF_RELATIVE = 0x8004
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004)
	binary.LittleEndian.PutUint32(sd[4:8], uint32(ownerOffset))
	binary.LittleEndian.PutUint32(sd[8:12], uint32(groupOffset))
	binary.LittleEndian.PutUint32(sd[12:16], 0) // No SACL
	binary.LittleEndian.PutUint32(sd[16:20], uint32(daclOffset))

	copy(sd[ownerOffset:], ownerSid)
	copy(sd[groupOffset:], groupSid)
	copy(sd[daclOffset:], acl)

	return sd
}

func buildAce(aceType, mask byte, sid []byte) []byte {
	aceSize := 4 + 4 + len(sid)
	ace := make([]byte, aceSize)
	ace[0] = aceType                                         // AceType
	ace[1] = 0x00                                            // AceFlags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize)) // AceSize
	binary.LittleEndian.PutUint32(ace[4:8], uint32(mask))    // Mask
	copy(ace[8:], sid)
	return ace
}

func parseSidToBytes(sidStr string) []byte {
	// Parse SID string like "S-1-5-21-..." to binary format
	var revision, subAuthCount byte
	var authority uint64
	var subAuths []uint32

	var parts []string
	current := ""
	for _, c := range sidStr {
		if c == '-' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	if len(parts) < 3 || parts[0] != "S" {
		return []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0} // Default to S-1-1-0
	}

	fmt.Sscanf(parts[1], "%d", &revision)
	fmt.Sscanf(parts[2], "%d", &authority)

	for i := 3; i < len(parts); i++ {
		var subAuth uint32
		fmt.Sscanf(parts[i], "%d", &subAuth)
		subAuths = append(subAuths, subAuth)
	}

	subAuthCount = byte(len(subAuths))
	sidLen := 8 + 4*len(subAuths)
	sid := make([]byte, sidLen)

	sid[0] = byte(revision)
	sid[1] = subAuthCount
	// Authority is 6 bytes big-endian
	sid[2] = byte(authority >> 40)
	sid[3] = byte(authority >> 32)
	sid[4] = byte(authority >> 24)
	sid[5] = byte(authority >> 16)
	sid[6] = byte(authority >> 8)
	sid[7] = byte(authority)

	for i, subAuth := range subAuths {
		binary.LittleEndian.PutUint32(sid[8+i*4:], subAuth)
	}

	return sid
}

// ComputeL2Key derives the L2 key from the group key envelope.
func ComputeL2Key(keyID *KeyIdentifier, gke *gkdi.GroupKeyEnvelope) ([]byte, error) {
	l1 := int32(gke.L1Index)
	l1Key := gke.L1Key
	l2 := int32(gke.L2Index)
	l2Key := gke.L2Key

	reseedL2 := l2 == 31 || l1 != int32(keyID.L1Index)

	kdfHashName := gke.GetKdfHashName()

	if l2 != 31 && l1 != int32(keyID.L1Index) {
		l1--
	}

	// Derive L1 keys down to the target L1 index
	for l1 != int32(keyID.L1Index) {
		reseedL2 = true
		l1--

		context := computeKdfContext(gke.RootKeyID[:], int32(gke.L0Index), l1, -1)
		l1Key = kdf(kdfHashName, l1Key, KDS_SERVICE_LABEL, context, 64)
	}

	// Reseed L2 if needed
	if reseedL2 {
		l2 = 31
		context := computeKdfContext(gke.RootKeyID[:], int32(gke.L0Index), l1, l2)
		l2Key = kdf(kdfHashName, l1Key, KDS_SERVICE_LABEL, context, 64)
	}

	// Derive L2 keys down to the target L2 index
	for l2 != int32(keyID.L2Index) {
		l2--
		context := computeKdfContext(gke.RootKeyID[:], int32(gke.L0Index), l1, l2)
		l2Key = kdf(kdfHashName, l2Key, KDS_SERVICE_LABEL, context, 64)
	}

	return l2Key, nil
}

// ComputeKEK computes the Key Encryption Key from the group key envelope and key identifier.
func ComputeKEK(gke *gkdi.GroupKeyEnvelope, keyID *KeyIdentifier) ([]byte, error) {
	l2Key, err := ComputeL2Key(keyID, gke)
	if err != nil {
		return nil, err
	}

	var kekSecret []byte
	var kekContext []byte

	if keyID.IsPublicKey() {
		// Generate KEK secret from public key
		kekSecret, kekContext, err = generateKekSecretFromPubkey(gke, keyID, l2Key)
		if err != nil {
			return nil, err
		}
	} else {
		kekSecret = l2Key
		kekContext = keyID.Unknown
	}

	kdfHashName := gke.GetKdfHashName()
	return kdf(kdfHashName, kekSecret, KDS_SERVICE_LABEL, kekContext, 32), nil
}

func generateKekSecretFromPubkey(gke *gkdi.GroupKeyEnvelope, keyID *KeyIdentifier, l2Key []byte) ([]byte, []byte, error) {
	kdfHashName := gke.GetKdfHashName()
	secAlgo := gke.GetSecAlgoName()

	privateKeyLen := (gke.PrivKeyLen + 7) / 8
	privateKey := kdf(kdfHashName, l2Key, KDS_SERVICE_LABEL, gke.SecAlgo, int(privateKeyLen))

	if secAlgo == "DH" {
		// Parse FFC DH Key from keyID.Unknown
		if len(keyID.Unknown) < 20 {
			return nil, nil, fmt.Errorf("FFCDH key data too short")
		}

		// Skip magic and key length header
		keyLen := binary.LittleEndian.Uint32(keyID.Unknown[4:8])
		offset := 8

		fieldOrder := keyID.Unknown[offset : offset+int(keyLen)]
		offset += int(keyLen)
		generator := keyID.Unknown[offset : offset+int(keyLen)]
		offset += int(keyLen)
		pubKey := keyID.Unknown[offset : offset+int(keyLen)]

		// Compute shared secret: pubKey^privateKey mod fieldOrder
		pubKeyInt := new(big.Int).SetBytes(pubKey)
		privKeyInt := new(big.Int).SetBytes(privateKey)
		fieldOrderInt := new(big.Int).SetBytes(fieldOrder)
		_ = generator // Not used in computation

		sharedSecretInt := new(big.Int).Exp(pubKeyInt, privKeyInt, fieldOrderInt)
		sharedSecret := sharedSecretInt.Bytes()

		// Compute KEK using KDF
		kekContext := KEK_PUBLIC_KEY_LABEL
		otherInfo := append(utf16le("SHA512\x00"), kekContext...)
		otherInfo = append(otherInfo, KDS_SERVICE_LABEL...)

		kekSecret := computeKdfHash(32, sharedSecret, otherInfo)
		return kekSecret, kekContext, nil
	} else if secAlgo == "ECDH_P256" || secAlgo == "ECDH_P384" {
		return nil, nil, fmt.Errorf("ECDH not yet implemented")
	}

	return nil, nil, fmt.Errorf("unknown security algorithm: %s", secAlgo)
}

// AESKeyUnwrap performs AES key unwrap (RFC 3394).
func AESKeyUnwrap(kek, wrappedKey []byte) ([]byte, error) {
	if len(wrappedKey) < 24 || len(wrappedKey)%8 != 0 {
		return nil, fmt.Errorf("invalid wrapped key length: %d", len(wrappedKey))
	}

	aiv := []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

	n := len(wrappedKey)/8 - 1
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrappedKey[(i+1)*8:(i+2)*8])
	}
	a := make([]byte, 8)
	copy(a, wrappedKey[0:8])

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			aXor := binary.BigEndian.Uint64(a) ^ t
			binary.BigEndian.PutUint64(a, aXor)

			buf := append(a, r[i]...)
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}

	if !bytes.Equal(a, aiv) {
		return nil, fmt.Errorf("key unwrap failed: invalid AIV")
	}

	result := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		result = append(result, r[i]...)
	}

	return result, nil
}

// DecryptContent decrypts the CMS content using AES-GCM.
func DecryptContent(cek, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// For LAPS v2, the ciphertext includes the GCM tag appended
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM decryption failed: %v", err)
	}

	return plaintext, nil
}

// Helper functions

func computeKdfContext(keyGuid []byte, l0, l1, l2 int32) []byte {
	buf := new(bytes.Buffer)
	buf.Write(keyGuid)
	binary.Write(buf, binary.LittleEndian, l0)
	binary.Write(buf, binary.LittleEndian, l1)
	binary.Write(buf, binary.LittleEndian, l2)
	return buf.Bytes()
}

func kdf(hashAlgStr string, secret, label, context []byte, length int) []byte {
	var h func() hash.Hash
	if hashAlgStr == "SHA512" || hashAlgStr == "" {
		h = sha512.New
	} else if hashAlgStr == "SHA256" {
		h = sha256.New
	} else {
		h = sha512.New // Default
	}

	return sp800108Counter(secret, h, length, label, context)
}

// sp800108Counter implements NIST SP 800-108 KDF in Counter Mode.
func sp800108Counter(master []byte, prf func() hash.Hash, keyLen int, label, context []byte) []byte {
	keyLenEnc := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLenEnc, uint32(keyLen*8))

	var dk []byte
	i := uint32(1)

	for len(dk) < keyLen {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, i)

		info := append(counterBytes, label...)
		info = append(info, 0x00)
		info = append(info, context...)
		info = append(info, keyLenEnc...)

		mac := hmac.New(prf, master)
		mac.Write(info)
		dk = append(dk, mac.Sum(nil)...)

		i++
		if i > 0xFFFFFFFF {
			break
		}
	}

	return dk[:keyLen]
}

func computeKdfHash(length int, keyMaterial, otherInfo []byte) []byte {
	var output []byte
	counter := uint32(1)

	for len(output) < length {
		h := sha256.New()
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		h.Write(counterBytes)
		h.Write(keyMaterial)
		h.Write(otherInfo)
		output = append(output, h.Sum(nil)...)
		counter++
	}

	return output[:length]
}

func utf16le(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = 0
	}
	return result
}
