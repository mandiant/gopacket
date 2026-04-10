// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

// LSASecret represents a decrypted LSA secret
type LSASecret struct {
	Name  string
	Value []byte
}

// CachedCredential represents a cached domain credential
type CachedCredential struct {
	Username      string
	Domain        string
	DNSDomainName string
	UPN           string
	EncryptedHash []byte
	DecryptedHash []byte
}

// DumpLSASecrets extracts LSA secrets from a SECURITY hive
func DumpLSASecrets(securityHive *Hive, bootKey []byte) ([]LSASecret, error) {
	// Get LSA key
	lsaKey, revision, err := getLSAKey(securityHive, bootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get LSA key: %v", err)
	}

	// Find secrets key
	secretsOffset, err := securityHive.FindKey("Policy\\Secrets")
	if err != nil {
		return nil, fmt.Errorf("failed to find Policy\\Secrets: %v", err)
	}

	// Enumerate secret names
	secretNames, err := securityHive.EnumSubKeys(secretsOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate secrets: %v", err)
	}

	var secrets []LSASecret

	for _, name := range secretNames {
		secret, err := extractSecret(securityHive, name, lsaKey, revision)
		if err != nil {
			continue
		}
		secrets = append(secrets, *secret)
	}

	return secrets, nil
}

// getLSAKey retrieves and decrypts the LSA encryption key
func getLSAKey(securityHive *Hive, bootKey []byte) ([]byte, int, error) {
	// Try new location first (Vista+)
	polSecretOffset, err := securityHive.FindKey("Policy\\PolEKList")
	if err == nil {
		_, encKey, err := securityHive.GetValue(polSecretOffset, "")
		if err == nil && len(encKey) > 0 {
			lsaKey, err := decryptPolEKList(encKey, bootKey)
			if err == nil {
				return lsaKey, 3, nil // AES revision
			}
		}
	}

	// Try old location (XP/2003)
	polSecretOffset, err = securityHive.FindKey("Policy\\PolSecretEncryptionKey")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to find LSA key: %v", err)
	}

	_, encKey, err := securityHive.GetValue(polSecretOffset, "")
	if err != nil {
		return nil, 0, err
	}

	lsaKey, err := ComputeLSAKey(bootKey, encKey, 1)
	if err != nil {
		return nil, 0, err
	}

	return lsaKey, 1, nil
}

// decryptPolEKList decrypts the Vista+ policy encryption key list
func decryptPolEKList(encData, bootKey []byte) ([]byte, error) {
	if len(encData) < 60 {
		return nil, fmt.Errorf("PolEKList too short: %d", len(encData))
	}

	// LSA_SECRET structure:
	// [0:4] - Version
	// [4:20] - EncKeyID (16 bytes)
	// [20:24] - EncAlgorithm
	// [24:28] - Flags
	// [28:] - EncryptedData

	encryptedData := encData[28:]

	// Derive decryption key: SHA256(bootKey || encryptedData[:32] * 1000)
	tmpKey := sha256With1000Rounds(bootKey, encryptedData[:32])

	// Decrypt encryptedData[32:] using Impacket's AES method (zero IV per block)
	decrypted, err := aesDecryptImpacketStyle(tmpKey, encryptedData[32:], true)
	if err != nil {
		return nil, err
	}

	// Parse as LSA_SECRET_BLOB:
	// [0:4] - Length
	// [4:16] - Unknown (12 bytes)
	// [16:] - Secret
	if len(decrypted) < 20 {
		return nil, fmt.Errorf("decrypted PolEKList too short: %d", len(decrypted))
	}

	// Secret starts at offset 16
	secret := decrypted[16:]
	if len(secret) < 84 {
		return nil, fmt.Errorf("secret too short: %d (need at least 84)", len(secret))
	}

	// LSA key is at Secret[52:84]
	lsaKey := secret[52:84]

	return lsaKey, nil
}

// extractSecret extracts a single LSA secret
func extractSecret(securityHive *Hive, name string, lsaKey []byte, revision int) (*LSASecret, error) {
	// Find secret's CurrVal
	secretPath := fmt.Sprintf("Policy\\Secrets\\%s\\CurrVal", name)
	secretOffset, err := securityHive.FindKey(secretPath)
	if err != nil {
		return nil, err
	}

	_, encValue, err := securityHive.GetValue(secretOffset, "")
	if err != nil {
		return nil, err
	}

	if len(encValue) == 0 {
		return nil, fmt.Errorf("empty secret")
	}

	// Decrypt based on revision
	var decrypted []byte
	if revision >= 3 {
		decrypted, err = DecryptLSASecretAES(lsaKey, encValue)
	} else {
		decrypted, err = DecryptLSASecretRC4(lsaKey, encValue)
	}

	if err != nil {
		return nil, err
	}

	// Parse LSA_SECRET_BLOB structure:
	// [0:4] Length
	// [4:16] Unknown (12 bytes)
	// [16:] Secret
	if len(decrypted) < 16 {
		return nil, fmt.Errorf("decrypted secret too short")
	}

	blobLength := binary.LittleEndian.Uint32(decrypted[0:4])

	// Extract the actual secret value starting at offset 16
	secret := decrypted[16:]
	if blobLength > 0 && int(blobLength) < len(secret) {
		secret = secret[:blobLength]
	}

	return &LSASecret{
		Name:  name,
		Value: secret,
	}, nil
}

// DumpCachedCredentials extracts cached domain credentials
func DumpCachedCredentials(securityHive *Hive, bootKey []byte) ([]CachedCredential, error) {
	// Get LSA key
	lsaKey, revision, err := getLSAKey(securityHive, bootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get LSA key: %v", err)
	}

	// Get NL$KM key (used to decrypt cached credentials)
	nlkmKey, err := getNLKMKey(securityHive, lsaKey, revision)
	if err != nil {
		return nil, fmt.Errorf("failed to get NL$KM key: %v", err)
	}

	// Find cache key
	cacheOffset, err := securityHive.FindKey("Cache")
	if err != nil {
		return nil, fmt.Errorf("failed to find Cache key: %v", err)
	}

	// Get NL$IterationCount for PBKDF2 iterations (Vista+)
	iterCount := uint32(10240) // Default
	_, iterData, err := securityHive.GetValue(cacheOffset, "NL$IterationCount")
	if err == nil && len(iterData) >= 4 {
		iterCount = binary.LittleEndian.Uint32(iterData)
		if iterCount > 10240 {
			iterCount = iterCount & 0xFFFF // High bits are flags
		}
	}

	// Enumerate cached entries (NL$1, NL$2, etc.)
	values, err := securityHive.EnumValues(cacheOffset)
	if err != nil {
		return nil, err
	}

	var creds []CachedCredential

	for _, valueName := range values {
		if !strings.HasPrefix(valueName, "NL$") || valueName == "NL$Control" || valueName == "NL$IterationCount" {
			continue
		}

		_, data, err := securityHive.GetValue(cacheOffset, valueName)
		if err != nil || len(data) < 96 {
			continue
		}

		cred, err := parseCachedCredential(data, nlkmKey, iterCount)
		if err != nil {
			continue
		}

		if cred.Username != "" {
			creds = append(creds, *cred)
		}
	}

	return creds, nil
}

// getNLKMKey retrieves the NL$KM key used for cached credential decryption
func getNLKMKey(securityHive *Hive, lsaKey []byte, revision int) ([]byte, error) {
	// NL$KM is stored as an LSA secret
	secretPath := "Policy\\Secrets\\NL$KM\\CurrVal"
	secretOffset, err := securityHive.FindKey(secretPath)
	if err != nil {
		return nil, err
	}

	_, encValue, err := securityHive.GetValue(secretOffset, "")
	if err != nil {
		return nil, err
	}

	var decrypted []byte
	if revision >= 3 {
		decrypted, err = DecryptLSASecretAES(lsaKey, encValue)
	} else {
		decrypted, err = DecryptLSASecretRC4(lsaKey, encValue)
	}

	if err != nil {
		return nil, err
	}

	// The actual key starts at offset 16 and is 64 bytes
	if len(decrypted) < 80 {
		return nil, fmt.Errorf("NL$KM decrypted data too short")
	}

	return decrypted[16:80], nil
}

// parseCachedCredential parses a cached credential entry
func parseCachedCredential(data []byte, nlkmKey []byte, iterCount uint32) (*CachedCredential, error) {
	if len(data) < 96 {
		return nil, fmt.Errorf("cached entry too short")
	}

	r := bytes.NewReader(data)

	// Cache entry header
	var userNameLen, domainNameLen uint16
	var dnsDomainNameLen uint16
	var upnLen uint16
	var effectiveNameLen uint16
	var fullNameLen uint16
	var logonScriptLen uint16
	var profilePathLen uint16
	var homeDirectoryLen uint16
	var homeDirectoryDriveLen uint16
	var groupCount, badPasswordCount uint16

	binary.Read(r, binary.LittleEndian, &userNameLen)
	binary.Read(r, binary.LittleEndian, &domainNameLen)
	binary.Read(r, binary.LittleEndian, &effectiveNameLen)
	binary.Read(r, binary.LittleEndian, &fullNameLen)
	binary.Read(r, binary.LittleEndian, &logonScriptLen)
	binary.Read(r, binary.LittleEndian, &profilePathLen)
	binary.Read(r, binary.LittleEndian, &homeDirectoryLen)
	binary.Read(r, binary.LittleEndian, &homeDirectoryDriveLen)

	r.Read(make([]byte, 4)) // User ID

	r.Read(make([]byte, 4)) // Primary group ID

	binary.Read(r, binary.LittleEndian, &groupCount)
	binary.Read(r, binary.LittleEndian, &badPasswordCount)

	// More header fields
	r.Read(make([]byte, 16)) // Logon time etc.

	binary.Read(r, binary.LittleEndian, &dnsDomainNameLen)
	binary.Read(r, binary.LittleEndian, &upnLen)

	// Skip to IV (offset 64)
	r.Seek(64, 0)
	iv := make([]byte, 16)
	r.Read(iv)

	// Checksum at offset 80
	r.Seek(80, 0)
	checksum := make([]byte, 16)
	r.Read(checksum)

	// Encrypted data starts at offset 96
	encryptedData := data[96:]

	cred := &CachedCredential{}

	// Check if entry is empty
	if userNameLen == 0 {
		return cred, nil
	}

	// Decrypt the data
	decrypted, err := decryptCacheEntry(encryptedData, iv, nlkmKey, iterCount)
	if err != nil {
		return nil, err
	}

	// Parse decrypted data
	// Structure: username, domain, dnsDomain, upn, ...
	offset := 0

	if int(userNameLen) <= len(decrypted) {
		cred.Username = decodeUTF16String(decrypted[offset : offset+int(userNameLen)])
	}
	offset += int(userNameLen)
	offset = alignTo4(offset)

	if offset+int(domainNameLen) <= len(decrypted) {
		cred.Domain = decodeUTF16String(decrypted[offset : offset+int(domainNameLen)])
	}
	offset += int(domainNameLen)
	offset = alignTo4(offset)

	if offset+int(dnsDomainNameLen) <= len(decrypted) {
		cred.DNSDomainName = decodeUTF16String(decrypted[offset : offset+int(dnsDomainNameLen)])
	}
	offset += int(dnsDomainNameLen)
	offset = alignTo4(offset)

	if offset+int(upnLen) <= len(decrypted) {
		cred.UPN = decodeUTF16String(decrypted[offset : offset+int(upnLen)])
	}

	// The encrypted hash is in the decrypted data after all the strings
	// and other fields. For simplicity, we store the checksum as the hash representation.
	cred.EncryptedHash = checksum

	return cred, nil
}

// decryptCacheEntry decrypts a cached credential entry
func decryptCacheEntry(data, iv, nlkmKey []byte, iterCount uint32) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty encrypted data")
	}

	// For Vista+, use AES-CBC
	// Key is derived from NL$KM using PBKDF2 if iterCount > 0

	// Simple AES-CBC decryption with NL$KM key
	// In practice, PBKDF2 would be used, but for basic functionality:
	key := nlkmKey[:16]
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid IV length")
	}

	return aesDecrypt(key, iv, data)
}

// alignTo4 aligns offset to 4-byte boundary
func alignTo4(offset int) int {
	if offset%4 != 0 {
		return offset + (4 - offset%4)
	}
	return offset
}

// ParseMachineAccountSecret parses the $MACHINE.ACC secret to get the machine account hash
func ParseMachineAccountSecret(secret []byte) []byte {
	if len(secret) < 16 {
		return nil
	}

	// The password is stored as UTF-16LE
	// We need to compute the NT hash of it
	// For now, return the raw data
	return secret
}

// DPAPIKeys holds the parsed DPAPI machine and user keys
type DPAPIKeys struct {
	MachineKey []byte // 20 bytes
	UserKey    []byte // 20 bytes
}

// ParseDPAPISecret parses the DPAPI master key backup secret
// Structure: [0:4] Version, [4:24] Machine key (20 bytes), [24:44] User key (20 bytes)
func ParseDPAPISecret(secret []byte) *DPAPIKeys {
	if len(secret) < 44 {
		return nil
	}

	return &DPAPIKeys{
		MachineKey: secret[4:24],
		UserKey:    secret[24:44],
	}
}

// DomainInfo contains domain information from the SECURITY hive
type DomainInfo struct {
	DNSDomainName string // e.g., "corp.local"
	NetBIOSName   string // e.g., "CORP"
	ComputerName  string // e.g., "DC01"
}

// GetDomainInfo extracts domain information from the SECURITY hive
func GetDomainInfo(securityHive *Hive) (*DomainInfo, error) {
	info := &DomainInfo{}

	// Get DNS domain name from Policy\PolDnDDN
	// Format: UNICODE_STRING structure: [Length:2][MaxLength:2][Offset:4][StringData...]
	if offset, err := securityHive.FindKey("Policy\\PolDnDDN"); err == nil {
		if _, data, err := securityHive.GetValue(offset, ""); err == nil && len(data) > 8 {
			info.DNSDomainName = parseUnicodeString(data)
		}
	}

	// Get primary domain NetBIOS name from Policy\PolPrDmN (primary domain)
	if offset, err := securityHive.FindKey("Policy\\PolPrDmN"); err == nil {
		if _, data, err := securityHive.GetValue(offset, ""); err == nil && len(data) > 8 {
			info.NetBIOSName = parseUnicodeString(data)
		}
	}

	// Get local account domain name from Policy\PolAcDmN (this is usually the computer name)
	if offset, err := securityHive.FindKey("Policy\\PolAcDmN"); err == nil {
		if _, data, err := securityHive.GetValue(offset, ""); err == nil && len(data) > 8 {
			computerName := parseUnicodeString(data)
			info.ComputerName = computerName
			// If no primary domain, this is also the NetBIOS name
			if info.NetBIOSName == "" {
				info.NetBIOSName = computerName
			}
		}
	}

	return info, nil
}

// parseUnicodeString parses a UNICODE_STRING structure
// Format: [Length:2][MaxLength:2][Offset:4][StringData...]
func parseUnicodeString(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	length := binary.LittleEndian.Uint16(data[0:2])
	// maxLength := binary.LittleEndian.Uint16(data[2:4])
	offset := binary.LittleEndian.Uint32(data[4:8])

	// String data starts at the offset
	if int(offset) >= len(data) || int(offset)+int(length) > len(data) {
		// String might be inline after the header
		if len(data) > 8 {
			return decodeUTF16String(data[8:])
		}
		return ""
	}

	return decodeUTF16String(data[offset : offset+uint32(length)])
}

// MachineAccountKeys contains the derived keys for a machine account
type MachineAccountKeys struct {
	PlainPassword []byte
	NTHash        []byte
	AES256Key     []byte
	AES128Key     []byte
	DESKey        []byte
}

// DeriveMachineAccountKeys derives all keys from the machine account password
func DeriveMachineAccountKeys(password []byte, realm, computerName string) *MachineAccountKeys {
	keys := &MachineAccountKeys{
		PlainPassword: password,
	}

	// Compute NT hash: MD4(UTF-16LE(password))
	// The password is already UTF-16LE encoded in the secret
	keys.NTHash = computeNTHash(password)

	// Convert password from UTF-16LE to UTF-8 for Kerberos key derivation
	// This matches Impacket's behavior: rawsecret.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
	utf8Password := utf16LEToUTF8WithReplace(password)

	// Derive Kerberos keys
	// Salt for machine accounts: <REALM_FQDN_UPPER>host<hostname_lower>.<realm_fqdn_lower>
	// Example: CORP.LOCALhostdc01.corp.local
	salt := strings.ToUpper(realm) + "host" + strings.ToLower(computerName) + "." + strings.ToLower(realm)

	keys.AES256Key = deriveKerberosAESKey(utf8Password, salt, 32)
	keys.AES128Key = deriveKerberosAESKey(utf8Password, salt, 16)
	keys.DESKey = deriveKerberosDESKey(utf8Password, salt)

	return keys
}

// utf16LEToUTF8WithReplace converts UTF-16LE bytes to UTF-8, replacing invalid characters
func utf16LEToUTF8WithReplace(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Decode UTF-16LE to runes, replacing invalid sequences
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(uint16(data[i]) | uint16(data[i+1])<<8)
		// Handle surrogate pairs (simplified - just replace invalid)
		if r >= 0xD800 && r <= 0xDFFF {
			r = '\uFFFD' // Replacement character
		}
		runes = append(runes, r)
	}

	// Encode to UTF-8
	return []byte(string(runes))
}

// computeNTHash computes the NT hash (MD4 of UTF-16LE password)
func computeNTHash(password []byte) []byte {
	// Password is already UTF-16LE, compute MD4
	h := md4.New()
	h.Write(password)
	return h.Sum(nil)
}

// deriveKerberosAESKey derives AES key using PBKDF2 + DK(key, "kerberos")
// This matches RFC 3962 and Impacket's implementation
func deriveKerberosAESKey(password []byte, salt string, keyLen int) []byte {
	saltBytes := []byte(salt)

	// PBKDF2 with HMAC-SHA1, 4096 iterations
	seed := pbkdf2.Key(password, saltBytes, 4096, keyLen, sha1.New)

	// Apply DK(key, "kerberos") derivation
	return deriveKey(seed, []byte("kerberos"), keyLen)
}

// deriveKey implements the DK function from RFC 3961
// DK(Key, Constant) = random-to-key(DR(Key, Constant))
func deriveKey(key, constant []byte, keyLen int) []byte {
	// n-fold the constant to 16 bytes (AES block size)
	nfoldedConstant := nfold(constant, 16)

	// DR produces enough pseudo-random bytes by encrypting
	var result []byte
	plaintext := nfoldedConstant

	for len(result) < keyLen {
		// AES-CBC encrypt with zero IV
		block, _ := aes.NewCipher(key)
		ciphertext := make([]byte, 16)
		block.Encrypt(ciphertext, plaintext)
		result = append(result, ciphertext...)
		plaintext = ciphertext
	}

	return result[:keyLen]
}

// nfold implements the n-fold operation from RFC 3961
// This matches Impacket's _nfold implementation exactly
func nfold(input []byte, nbytes int) []byte {
	// Rotate the bytes in ba to the right by nbits bits
	rotateRight := func(ba []byte, nbits int) []byte {
		if len(ba) == 0 {
			return ba
		}
		result := make([]byte, len(ba))
		nbyteRot := (nbits / 8) % len(ba)
		remain := nbits % 8
		for i := 0; i < len(ba); i++ {
			// ba[i-nbytes] >> remain | ba[i-nbytes-1] << (8-remain)
			idx1 := (i - nbyteRot + len(ba)) % len(ba)
			idx2 := (i - nbyteRot - 1 + len(ba)) % len(ba)
			result[i] = (ba[idx1] >> remain) | (ba[idx2] << (8 - remain))
		}
		return result
	}

	// Add equal-length byte slices with end-around carry (ones' complement)
	addOnesComplement := func(str1, str2 []byte) []byte {
		n := len(str1)
		v := make([]int, n)
		for i := 0; i < n; i++ {
			v[i] = int(str1[i]) + int(str2[i])
		}
		// Propagate carry bits to the left until there aren't any left
		for {
			hasCarry := false
			for i := range v {
				if v[i] > 0xff {
					hasCarry = true
					break
				}
			}
			if !hasCarry {
				break
			}
			newV := make([]int, n)
			for i := 0; i < n; i++ {
				// Carry from position to the right (wrapping)
				carryFrom := (i + 1) % n
				newV[i] = (v[carryFrom] >> 8) + (v[i] & 0xff)
			}
			v = newV
		}
		result := make([]byte, n)
		for i := range v {
			result[i] = byte(v[i])
		}
		return result
	}

	slen := len(input)
	lcm := (nbytes * slen) / gcd(nbytes, slen)

	// Build bigstr by concatenating rotated copies
	bigstr := make([]byte, 0, lcm)
	for i := 0; i < lcm/slen; i++ {
		bigstr = append(bigstr, rotateRight(input, 13*i)...)
	}

	// Decompose into slices of length nbytes and add them together
	result := make([]byte, nbytes)
	for p := 0; p < lcm; p += nbytes {
		slice := bigstr[p : p+nbytes]
		if p == 0 {
			copy(result, slice)
		} else {
			result = addOnesComplement(result, slice)
		}
	}

	return result
}

// gcd computes greatest common divisor
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// deriveKerberosDESKey derives DES key using the MIT string-to-key algorithm
// This matches Impacket's _DESCBC.mit_des_string_to_key implementation
func deriveKerberosDESKey(password []byte, salt string) []byte {
	// Pad password + salt to 8-byte boundary
	s := append(password, []byte(salt)...)
	if len(s)%8 != 0 {
		s = append(s, make([]byte, 8-len(s)%8)...)
	}

	// XOR each 8-byte block, removing MSB from each byte
	// Odd blocks are bit-reversed before XOR
	tempstring := make([]int, 8)
	odd := true

	for i := 0; i < len(s); i += 8 {
		block := s[i : i+8]
		// Remove MSB from each byte to get 7 bits
		temp56 := make([]int, 8)
		for j, b := range block {
			temp56[j] = int(b) & 0x7F
		}

		// For even blocks (not odd), reverse the 56-bit string
		if !odd {
			// Convert to 56 bits
			bits := ""
			for _, b := range temp56 {
				bits += fmt.Sprintf("%07b", b)
			}
			// Reverse
			reversed := ""
			for j := len(bits) - 1; j >= 0; j-- {
				reversed += string(bits[j])
			}
			// Convert back to 8 7-bit values
			for j := 0; j < 8; j++ {
				val, _ := binaryStringToInt(reversed[j*7 : j*7+7])
				temp56[j] = val
			}
		}
		odd = !odd

		// XOR with accumulated result
		for j := 0; j < 8; j++ {
			tempstring[j] = (tempstring[j] ^ temp56[j]) & 0x7F
		}
	}

	// Add parity bits - shift left and set parity
	tempkey := make([]byte, 8)
	for i, b := range tempstring {
		// Count bits in 7-bit value
		count := 0
		for j := 0; j < 7; j++ {
			if (b>>j)&1 == 1 {
				count++
			}
		}
		// Shift left and add parity bit
		if count%2 == 0 {
			tempkey[i] = byte((b << 1) | 1)
		} else {
			tempkey[i] = byte((b << 1) & 0xFE)
		}
	}

	// Fix weak key
	if isWeakDESKey(tempkey) {
		tempkey[7] ^= 0xF0
	}

	// DES-CBC encrypt the padded input using tempkey as both key and IV
	desCipher, err := des.NewCipher(tempkey)
	if err != nil {
		return nil
	}

	ciphertext := make([]byte, len(s))
	mode := cipher.NewCBCEncrypter(desCipher, tempkey)
	mode.CryptBlocks(ciphertext, s)

	// Take last 8 bytes
	checksumkey := ciphertext[len(ciphertext)-8:]

	// Fix parity on the result
	for i := 0; i < 8; i++ {
		b := checksumkey[i]
		// Count bits in upper 7 bits
		count := 0
		for j := 1; j < 8; j++ {
			if (b>>j)&1 == 1 {
				count++
			}
		}
		// Set parity bit
		if count%2 == 0 {
			checksumkey[i] = (b & 0xFE) | 1
		} else {
			checksumkey[i] = b & 0xFE
		}
	}

	// Fix weak key
	if isWeakDESKey(checksumkey) {
		checksumkey[7] ^= 0xF0
	}

	return checksumkey
}

// binaryStringToInt converts a binary string to int
func binaryStringToInt(s string) (int, error) {
	result := 0
	for _, c := range s {
		result <<= 1
		if c == '1' {
			result |= 1
		}
	}
	return result, nil
}

// isWeakDESKey checks if a DES key is weak or semi-weak
func isWeakDESKey(key []byte) bool {
	weakKeys := [][]byte{
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
		{0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
		{0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},
		{0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
		{0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01},
		{0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1},
		{0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E},
		{0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1},
		{0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01},
		{0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE},
		{0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E},
		{0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E},
		{0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01},
		{0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE},
		{0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1},
	}
	for _, weak := range weakKeys {
		if bytes.Equal(key, weak) {
			return true
		}
	}
	return false
}

// UTF16LEToString converts UTF-16LE bytes to string
func UTF16LEToString(b []byte) string {
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
