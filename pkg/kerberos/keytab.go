// SPDX-License-Identifier: Apache-2.0

package kerberos

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// BuildKeytabFromNTHash creates a keytab from an NTLM hash for pass-the-hash attacks.
// The NTLM hash is used directly as the RC4-HMAC key (etype 23).
func BuildKeytabFromNTHash(username, realm, nthash string) (*keytab.Keytab, error) {
	// Parse the NTLM hash
	hashBytes, err := hex.DecodeString(nthash)
	if err != nil {
		return nil, fmt.Errorf("invalid NTLM hash: %v", err)
	}
	if len(hashBytes) != 16 {
		return nil, fmt.Errorf("NTLM hash must be 16 bytes (32 hex chars), got %d", len(hashBytes))
	}

	// Build keytab binary
	// Format: https://web.mit.edu/kerberos/krb5-devel/doc/formats/keytab_file_format.html
	var buf bytes.Buffer

	// Header
	buf.WriteByte(0x05) // First byte is always 5
	buf.WriteByte(0x02) // Version 2 (big-endian)

	// Build entry
	entryBuf := buildKeytabEntry(username, realm, hashBytes)

	// Write entry length (int32 big-endian)
	binary.Write(&buf, binary.BigEndian, int32(len(entryBuf)))

	// Write entry
	buf.Write(entryBuf)

	// Parse the keytab
	kt := keytab.New()
	if err := kt.Unmarshal(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to parse keytab: %v", err)
	}

	return kt, nil
}

// buildKeytabEntry builds a single keytab entry in binary format
func buildKeytabEntry(username, realm string, keyValue []byte) []byte {
	var buf bytes.Buffer

	// Principal
	// num_components (int16) - for version 2, doesn't include realm
	components := []string{username}
	binary.Write(&buf, binary.BigEndian, int16(len(components)))

	// Realm (counted string: int16 length + data)
	binary.Write(&buf, binary.BigEndian, int16(len(realm)))
	buf.WriteString(realm)

	// Components (each is: int16 length + data)
	for _, comp := range components {
		binary.Write(&buf, binary.BigEndian, int16(len(comp)))
		buf.WriteString(comp)
	}

	// Name type (int32) - KRB_NT_PRINCIPAL = 1
	binary.Write(&buf, binary.BigEndian, int32(1))

	// Timestamp (uint32) - Unix timestamp
	binary.Write(&buf, binary.BigEndian, uint32(time.Now().Unix()))

	// KVNO (uint8)
	buf.WriteByte(1)

	// Key type (int16) - RC4_HMAC = 23
	binary.Write(&buf, binary.BigEndian, int16(etypeID.RC4_HMAC))

	// Key length (int16)
	binary.Write(&buf, binary.BigEndian, int16(len(keyValue)))

	// Key value
	buf.Write(keyValue)

	return buf.Bytes()
}

// ParseHashes parses the LMHASH:NTHASH format and returns the NT hash
func ParseHashes(hashes string) (string, error) {
	parts := strings.Split(hashes, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid hash format, expected LMHASH:NTHASH")
	}

	nthash := parts[1]
	if len(nthash) != 32 {
		return "", fmt.Errorf("NT hash must be 32 hex characters, got %d", len(nthash))
	}

	// Validate it's valid hex
	if _, err := hex.DecodeString(nthash); err != nil {
		return "", fmt.Errorf("invalid NT hash: %v", err)
	}

	return nthash, nil
}
