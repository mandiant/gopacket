package registry

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// SAMUser represents a user account extracted from SAM
type SAMUser struct {
	Username string
	RID      uint32
	NTHash   []byte
	LMHash   []byte
	Enabled  bool
}

// Empty hashes
var (
	EmptyLMHash = []byte{0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee}
	EmptyNTHash = []byte{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0}
)

// DumpSAM extracts all user hashes from a SAM hive
func DumpSAM(samHive *Hive, bootKey []byte) ([]SAMUser, error) {
	// Get SAM account domain F value for hashed boot key
	accountsOffset, err := samHive.FindKey("SAM\\Domains\\Account")
	if err != nil {
		return nil, fmt.Errorf("failed to find SAM\\Domains\\Account: %v", err)
	}

	_, samF, err := samHive.GetValue(accountsOffset, "F")
	if err != nil {
		return nil, fmt.Errorf("failed to get Account F value: %v", err)
	}

	// Compute hashed boot key
	hashedBootKey, revision, err := ComputeHashedBootKey(samF, bootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hashed boot key: %v", err)
	}

	// Find users key
	usersOffset, err := samHive.FindKey("SAM\\Domains\\Account\\Users")
	if err != nil {
		return nil, fmt.Errorf("failed to find Users key: %v", err)
	}

	// Enumerate user RIDs
	userRIDs, err := samHive.EnumSubKeys(usersOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate users: %v", err)
	}

	var users []SAMUser

	for _, ridStr := range userRIDs {
		// Skip "Names" key
		if ridStr == "Names" {
			continue
		}

		// Parse RID from hex string
		var rid uint32
		_, err := fmt.Sscanf(ridStr, "%08X", &rid)
		if err != nil {
			continue
		}

		user, err := extractUser(samHive, usersOffset, ridStr, rid, hashedBootKey, revision)
		if err != nil {
			continue
		}

		users = append(users, *user)
	}

	return users, nil
}

// extractUser extracts a single user's data
func extractUser(samHive *Hive, usersOffset int32, ridStr string, rid uint32, hashedBootKey []byte, revision int) (*SAMUser, error) {
	// Find user key
	userPath := fmt.Sprintf("SAM\\Domains\\Account\\Users\\%s", ridStr)
	userOffset, err := samHive.FindKey(userPath)
	if err != nil {
		return nil, err
	}

	// Get V value containing user data
	_, vData, err := samHive.GetValue(userOffset, "V")
	if err != nil {
		return nil, err
	}

	if len(vData) < 0xCC {
		return nil, fmt.Errorf("V value too short")
	}

	// Parse V structure offsets
	// Offsets are stored as [offset, length, unknown] triplets
	// Username is at index 0 (offset 0x0C)
	// NT hash is at index 13 (0xA8)
	// LM hash is at index 12 (0x9C)

	user := &SAMUser{
		RID:     rid,
		Enabled: true,
	}

	// Get username
	nameOffset := binary.LittleEndian.Uint32(vData[0x0C:0x10]) + 0xCC
	nameLen := binary.LittleEndian.Uint32(vData[0x10:0x14])
	if int(nameOffset+nameLen) <= len(vData) {
		user.Username = decodeUTF16String(vData[nameOffset : nameOffset+nameLen])
	}

	// Get LM hash
	lmOffset := binary.LittleEndian.Uint32(vData[0x9C:0xA0]) + 0xCC
	lmLen := binary.LittleEndian.Uint32(vData[0xA0:0xA4])

	if lmLen > 0 && int(lmOffset+lmLen) <= len(vData) {
		lmData := vData[lmOffset : lmOffset+lmLen]
		user.LMHash, _ = decryptHash(lmData, hashedBootKey, rid, false, revision)
	}
	if user.LMHash == nil {
		user.LMHash = EmptyLMHash
	}

	// Get NT hash
	ntOffset := binary.LittleEndian.Uint32(vData[0xA8:0xAC]) + 0xCC
	ntLen := binary.LittleEndian.Uint32(vData[0xAC:0xB0])

	if ntLen > 0 && int(ntOffset+ntLen) <= len(vData) {
		ntData := vData[ntOffset : ntOffset+ntLen]
		user.NTHash, _ = decryptHash(ntData, hashedBootKey, rid, true, revision)
	}
	if user.NTHash == nil {
		user.NTHash = EmptyNTHash
	}

	// Check user account control flags
	uacOffset := binary.LittleEndian.Uint32(vData[0x38:0x3C]) + 0xCC
	if int(uacOffset+4) <= len(vData) {
		uac := binary.LittleEndian.Uint32(vData[uacOffset : uacOffset+4])
		// Account disabled flag is 0x0001
		user.Enabled = (uac & 0x0001) == 0
	}

	return user, nil
}

// decryptHash decrypts a SAM hash
func decryptHash(encData []byte, hashedBootKey []byte, rid uint32, isNT bool, revision int) ([]byte, error) {
	if len(encData) < 4 {
		return nil, fmt.Errorf("encrypted hash data too short")
	}

	// Structure:
	// [0:2] PekID
	// [2:4] Revision (1=RC4, 2=AES)
	// [4:8] DataOffset (for AES, offset to encrypted data after salt)
	// For RC4: [8:24] encrypted hash (16 bytes)
	// For AES: [8:24] salt (16 bytes), [24+] encrypted data
	pekRevision := int(encData[2]) | int(encData[3])<<8

	switch pekRevision {
	case 1:
		// RC4 format: [PekID:2][Revision:2][DataOffset:4][encHash:16]
		if len(encData) < 24 {
			return nil, fmt.Errorf("RC4 hash data too short: %d", len(encData))
		}
		return DecryptSAMHashRC4(hashedBootKey, rid, encData[8:24], isNT)

	case 2:
		// AES format: [PekID:2][Revision:2][DataOffset:4][salt:16][encData:16+]
		if len(encData) < 40 {
			return nil, fmt.Errorf("AES hash data too short: %d", len(encData))
		}
		// DataOffset tells us where the encrypted data starts (relative to salt)
		dataOffset := int(encData[4]) | int(encData[5])<<8 | int(encData[6])<<16 | int(encData[7])<<24
		salt := encData[8:24]
		if dataOffset == 0 {
			dataOffset = 16 // Default: encrypted data immediately after salt
		}
		encHash := encData[8+dataOffset:]
		if len(encHash) < 16 {
			return nil, fmt.Errorf("AES encrypted hash too short")
		}
		return DecryptSAMHashAESWithSalt(hashedBootKey, rid, salt, encHash, isNT)

	default:
		return nil, fmt.Errorf("unknown hash revision: %d", pekRevision)
	}
}

// GetUserByName finds a user by username
func GetUserByName(samHive *Hive, bootKey []byte, username string) (*SAMUser, error) {
	users, err := DumpSAM(samHive, bootKey)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user not found: %s", username)
}

// GetUserByRID finds a user by RID
func GetUserByRID(samHive *Hive, bootKey []byte, rid uint32) (*SAMUser, error) {
	users, err := DumpSAM(samHive, bootKey)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.RID == rid {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user not found with RID: %d", rid)
}

// EditSAMPassword edits a user's NT and LM hashes in an offline SAM hive.
// The hive is modified in-place. Use samHive.Data() to retrieve the modified bytes.
func EditSAMPassword(samHive *Hive, bootKey []byte, username string, newNTHash []byte, newLMHash []byte) error {
	// Get SAM account domain F value for hashed boot key
	accountsOffset, err := samHive.FindKey("SAM\\Domains\\Account")
	if err != nil {
		return fmt.Errorf("failed to find SAM\\Domains\\Account: %v", err)
	}

	_, samF, err := samHive.GetValue(accountsOffset, "F")
	if err != nil {
		return fmt.Errorf("failed to get Account F value: %v", err)
	}

	hashedBootKey, revision, err := ComputeHashedBootKey(samF, bootKey)
	if err != nil {
		return fmt.Errorf("failed to compute hashed boot key: %v", err)
	}

	// Find the user's RID by enumerating SAM\Domains\Account\Users
	usersOffset, err := samHive.FindKey("SAM\\Domains\\Account\\Users")
	if err != nil {
		return fmt.Errorf("failed to find Users key: %v", err)
	}

	userRIDs, err := samHive.EnumSubKeys(usersOffset)
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %v", err)
	}

	var foundRID uint32
	var ridStr string
	for _, rs := range userRIDs {
		if rs == "Names" {
			continue
		}
		var rid uint32
		if _, err := fmt.Sscanf(rs, "%08X", &rid); err != nil {
			continue
		}
		// Read V value to get username
		userPath := fmt.Sprintf("SAM\\Domains\\Account\\Users\\%s", rs)
		userOffset, err := samHive.FindKey(userPath)
		if err != nil {
			continue
		}
		_, vData, err := samHive.GetValue(userOffset, "V")
		if err != nil || len(vData) < 0xCC {
			continue
		}
		nameOffset := binary.LittleEndian.Uint32(vData[0x0C:0x10]) + 0xCC
		nameLen := binary.LittleEndian.Uint32(vData[0x10:0x14])
		if int(nameOffset+nameLen) > len(vData) {
			continue
		}
		name := decodeUTF16String(vData[nameOffset : nameOffset+nameLen])
		if name == username {
			foundRID = rid
			ridStr = rs
			break
		}
	}

	if foundRID == 0 {
		return fmt.Errorf("user not found: %s", username)
	}

	userPath := fmt.Sprintf("SAM\\Domains\\Account\\Users\\%s", ridStr)
	userOffset, err := samHive.FindKey(userPath)
	if err != nil {
		return err
	}

	_, vData, err := samHive.GetValue(userOffset, "V")
	if err != nil {
		return fmt.Errorf("failed to get V value: %v", err)
	}

	if len(vData) < 0xCC {
		return fmt.Errorf("V value too short")
	}

	// Read current hashes for display
	ntOffset := binary.LittleEndian.Uint32(vData[0xA8:0xAC]) + 0xCC
	ntLen := binary.LittleEndian.Uint32(vData[0xAC:0xB0])
	lmOffset := binary.LittleEndian.Uint32(vData[0x9C:0xA0]) + 0xCC
	lmLen := binary.LittleEndian.Uint32(vData[0xA0:0xA4])

	// Decrypt old hashes for display
	var oldNT, oldLM []byte
	if ntLen > 0 && int(ntOffset+ntLen) <= len(vData) {
		oldNT, _ = decryptHash(vData[ntOffset:ntOffset+ntLen], hashedBootKey, foundRID, true, revision)
	}
	if oldNT == nil {
		oldNT = EmptyNTHash
	}
	if lmLen > 0 && int(lmOffset+lmLen) <= len(vData) {
		oldLM, _ = decryptHash(vData[lmOffset:lmOffset+lmLen], hashedBootKey, foundRID, false, revision)
	}
	if oldLM == nil {
		oldLM = EmptyLMHash
	}

	fmt.Printf("[*] Target user: %s (RID %d)\n", username, foundRID)
	fmt.Printf("[*] Old NT Hash: %s\n", hex.EncodeToString(oldNT))
	fmt.Printf("[*] Old LM Hash: %s\n", hex.EncodeToString(oldLM))

	// Build new V value with encrypted hashes
	newV := make([]byte, len(vData))
	copy(newV, vData)

	// Encrypt and write NT hash
	if ntLen > 0 && int(ntOffset+ntLen) <= len(vData) {
		ntData := vData[ntOffset : ntOffset+ntLen]
		pekRevision := int(ntData[2]) | int(ntData[3])<<8

		newEncNT, err := encryptHash(newNTHash, hashedBootKey, foundRID, true, pekRevision, ntData)
		if err != nil {
			return fmt.Errorf("failed to encrypt NT hash: %v", err)
		}
		copy(newV[ntOffset:ntOffset+ntLen], newEncNT)
	}

	// Encrypt and write LM hash
	if lmLen > 0 && int(lmOffset+lmLen) <= len(vData) {
		lmData := vData[lmOffset : lmOffset+lmLen]
		pekRevision := int(lmData[2]) | int(lmData[3])<<8

		newEncLM, err := encryptHash(newLMHash, hashedBootKey, foundRID, false, pekRevision, lmData)
		if err != nil {
			return fmt.Errorf("failed to encrypt LM hash: %v", err)
		}
		copy(newV[lmOffset:lmOffset+lmLen], newEncLM)
	}

	// Verify the new V is the same length
	if len(newV) != len(vData) {
		return fmt.Errorf("V value size changed: %d -> %d", len(vData), len(newV))
	}

	// Write back
	if !bytes.Equal(newV, vData) {
		if err := samHive.SetValueData(userOffset, "V", newV); err != nil {
			return fmt.Errorf("failed to write V value: %v", err)
		}
	}

	fmt.Printf("[*] New NT Hash: %s\n", hex.EncodeToString(newNTHash))
	fmt.Printf("[*] New LM Hash: %s\n", hex.EncodeToString(newLMHash))
	fmt.Println("[+] Password hashes updated successfully in SAM hive")

	return nil
}

// encryptHash encrypts a plain hash for writing back into the SAM V value.
// origEncData is the original encrypted blob used to preserve the header and salt.
func encryptHash(plainHash []byte, hashedBootKey []byte, rid uint32, isNT bool, pekRevision int, origEncData []byte) ([]byte, error) {
	result := make([]byte, len(origEncData))
	copy(result, origEncData)

	// For pekRevision 2 (AES), the blob needs at least 40 bytes (8 header + 16 salt + 16 ciphertext).
	// Accounts with empty passwords often have only 24-byte blobs even with pekRevision=2.
	// In that case, fall back to RC4 format (pekRevision=1) which fits in 24 bytes.
	if pekRevision == 2 && len(result) < 40 {
		pekRevision = 1
		// Update revision field in the blob header to 1
		result[2] = 1
		result[3] = 0
	}

	switch pekRevision {
	case 1:
		// RC4: header is [PekID:2][Revision:2][DataOffset:4], encrypted hash at [8:24]
		if len(result) < 24 {
			return nil, fmt.Errorf("RC4 hash blob too short: %d", len(result))
		}
		encHash, err := EncryptSAMHashRC4(hashedBootKey, rid, plainHash, isNT)
		if err != nil {
			return nil, err
		}
		copy(result[8:24], encHash)
		return result, nil

	case 2:
		// AES: header is [PekID:2][Revision:2][DataOffset:4][Salt:16][EncData...]
		// Generate a new random salt
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %v", err)
		}
		copy(result[8:24], salt)

		dataOffset := int(origEncData[4]) | int(origEncData[5])<<8 | int(origEncData[6])<<16 | int(origEncData[7])<<24
		if dataOffset == 0 {
			dataOffset = 16
		}

		encHash, err := EncryptSAMHashAES(hashedBootKey, rid, plainHash, salt, isNT)
		if err != nil {
			return nil, err
		}
		copy(result[8+dataOffset:], encHash)
		return result, nil

	default:
		return nil, fmt.Errorf("unknown hash revision: %d", pekRevision)
	}
}
