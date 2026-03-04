package drsuapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/utf16le"
)

// DRSUAPI UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
var UUID = [16]byte{
	0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11,
	0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
}

const MajorVersion = 4
const MinorVersion = 0

// NTDSAPI_CLIENT_GUID - standard client GUID for DRSUAPI (5.137 in MS-DRSR)
// e24d201a-4fd6-11d1-a3da-0000f875ae0d
var NTDSAPI_CLIENT_GUID = [16]byte{
	0x1a, 0x20, 0x4d, 0xe2, 0xd6, 0x4f, 0xd1, 0x11,
	0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d,
}

// DRS_EXTENSIONS_INT used in Bind (5.39 in MS-DRSR)
type DrsExtensions struct {
	Cb            uint32
	Flags         uint32
	SiteObjGuid   [16]byte // GUID
	Pid           uint32
	DwReplEpoch   uint32
	DwFlagsExt    uint32
	ConfigObjGUID [16]byte
	DwExtCaps     uint32
}

// BindResult contains DsBind results
type BindResult struct {
	Handle     []byte         // Context handle (20 bytes)
	ServerGUID [16]byte       // Server DSA GUID
	Extensions *DrsExtensions // Server capabilities
}

// DCInfo contains DC information from DsDomainControllerInfo
type DCInfo struct {
	NtdsDsaObjectGuid [16]byte
	ServerObjectGuid  [16]byte
	ComputerObjectGuid [16]byte
	DnsHostName       string
	NetbiosName       string
}

// DsDomainControllerInfo retrieves DC information including the DSA GUID
func DsDomainControllerInfo(client *dcerpc.Client, hBind []byte, domain string) (*DCInfo, error) {
	buf := new(bytes.Buffer)

	// [in] DRS_HANDLE hDrs
	buf.Write(hBind)

	// [in] DWORD dwInVersion = 1
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// [in] DRS_MSG_DCINFOREQ with union tag = 1
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Union tag

	// DRS_MSG_DCINFOREQ_V1: Domain (LPWSTR), InfoLevel (DWORD)
	// Domain pointer
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID

	// InfoLevel = 2 (to get V2 response with NtdsDsaObjectGuid)
	binary.Write(buf, binary.LittleEndian, uint32(2))

	// Deferred: Domain string (LPWSTR)
	domainWide := utf16le.EncodeStringToBytes(domain)
	charCount := uint32(len(domain) + 1)
	binary.Write(buf, binary.LittleEndian, charCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, charCount) // ActualCount
	buf.Write(domainWide)
	buf.Write([]byte{0, 0}) // Null terminator

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4))
	}

	if build.Debug {
		log.Printf("[D] DsDomainControllerInfo request payload (%d bytes): %x", buf.Len(), buf.Bytes())
	}

	// Call OpDsGetDCInfo (opnum 16)
	var resp []byte
	var err error
	if client.Authenticated {
		resp, err = client.CallAuthAuto(OpDsGetDCInfo, buf.Bytes())
	} else {
		resp, err = client.Call(OpDsGetDCInfo, buf.Bytes())
	}
	if err != nil {
		return nil, err
	}

	return parseDCInfoResponse(resp)
}

func parseDCInfoResponse(resp []byte) (*DCInfo, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	if build.Debug {
		log.Printf("[D] DsDomainControllerInfo raw response (%d bytes): %x", len(resp), resp)
	}

	r := bytes.NewReader(resp)

	// [out] DWORD* pdwOutVersion
	var outVersion uint32
	binary.Read(r, binary.LittleEndian, &outVersion)

	// Union tag
	var unionTag uint32
	binary.Read(r, binary.LittleEndian, &unionTag)

	if build.Debug {
		log.Printf("[D] DsDomainControllerInfo: outVersion=%d, unionTag=%d", outVersion, unionTag)
	}

	// For V2 response, we need to parse DS_DOMAIN_CONTROLLER_INFO_2W
	// cItems, rItems pointer
	var cItems uint32
	binary.Read(r, binary.LittleEndian, &cItems)

	var ptrItems uint32
	binary.Read(r, binary.LittleEndian, &ptrItems)

	if cItems == 0 || ptrItems == 0 {
		return nil, fmt.Errorf("no DC info items returned")
	}

	// Array conformance
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Parse DS_DOMAIN_CONTROLLER_INFO_2W structure
	// This is complex with many LPWSTR pointers followed by deferred data
	// For now, let's try to extract just the GUIDs which are at fixed positions

	result := &DCInfo{}

	// Skip the string pointers and BOOLs to get to the GUIDs
	// Structure: 7 LPWSTR ptrs + 3 BOOLs + 4 GUIDs
	// We need to skip the pointers and read GUIDs later

	// For a simpler approach, scan for the GUID pattern at the end
	// The 4 GUIDs (SiteObjectGuid, ComputerObjectGuid, ServerObjectGuid, NtdsDsaObjectGuid)
	// are 16 bytes each = 64 bytes total, likely at the end before deferred strings

	// Let's read through the structure more carefully
	// Read all string pointers (7)
	for i := 0; i < 7; i++ {
		var ptr uint32
		binary.Read(r, binary.LittleEndian, &ptr)
	}

	// Read 3 BOOLs (fIsPdc, fDsEnabled, fIsGc)
	for i := 0; i < 3; i++ {
		var b uint32
		binary.Read(r, binary.LittleEndian, &b)
	}

	// Read 4 GUIDs (16 bytes each)
	// SiteObjectGuid
	var siteGuid [16]byte
	r.Read(siteGuid[:])

	// ComputerObjectGuid
	r.Read(result.ComputerObjectGuid[:])

	// ServerObjectGuid
	r.Read(result.ServerObjectGuid[:])

	// NtdsDsaObjectGuid - this is what we need!
	r.Read(result.NtdsDsaObjectGuid[:])

	if build.Debug {
		log.Printf("[D] DsDomainControllerInfo: NtdsDsaObjectGuid=%x", result.NtdsDsaObjectGuid)
	}

	return result, nil
}

// DsBind performs the initial handshake and returns the context handle.
func DsBind(client *dcerpc.Client) (*BindResult, error) {
	buf := new(bytes.Buffer)

	// [in] UUID* puuidClientDsa (Pointer!)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Ptr 1

	// [in] DRS_EXTENSIONS* pextClient (Pointer!)
	binary.Write(buf, binary.LittleEndian, uint32(2)) // Ptr 2

	// --- Deferred Pointers ---

	// Ptr 1: ClientDsaUuid Data (16 bytes) - use NTDSAPI_CLIENT_GUID
	buf.Write(NTDSAPI_CLIENT_GUID[:])

	// Ptr 2: DRS_EXTENSIONS Structure
	// Request all capabilities we need
	clientFlags := uint32(
		DRS_EXT_GETCHGREQ_V6 |
			DRS_EXT_STRONG_ENCRYPTION |
			DRS_EXT_GETCHGREPLY_V6 |
			DRS_EXT_GETCHGREQ_V8 |
			DRS_EXT_GETCHGREPLY_V7)

	// DRS_EXTENSIONS_INT structure (52 bytes for rgb):
	// dwFlags (4) + SiteObjGuid (16) + Pid (4) + dwReplEpoch (4) +
	// dwFlagsExt (4) + ConfigObjGUID (16) + dwExtCaps (4) = 52 bytes
	ext := DrsExtensions{
		Cb:        52, // Size of rgb[] data
		Flags:     clientFlags,
		Pid:       0,
		DwExtCaps: 0xffffffff, // Request all capabilities
	}

	// DRS_EXTENSIONS has conformant array rgb[]:
	// NDR encoding: [MaxCount][cb][rgb...]
	binary.Write(buf, binary.LittleEndian, uint32(52)) // MaxCount for rgb array
	binary.Write(buf, binary.LittleEndian, ext.Cb)     // cb field
	// rgb data (DRS_EXTENSIONS_INT fields):
	binary.Write(buf, binary.LittleEndian, ext.Flags)
	buf.Write(ext.SiteObjGuid[:])
	binary.Write(buf, binary.LittleEndian, ext.Pid)
	binary.Write(buf, binary.LittleEndian, ext.DwReplEpoch)
	binary.Write(buf, binary.LittleEndian, ext.DwFlagsExt)
	buf.Write(ext.ConfigObjGUID[:])
	binary.Write(buf, binary.LittleEndian, ext.DwExtCaps)

	// Call IDL_DRSBind (use sealed call if authenticated)
	var resp []byte
	var err error
	if client.Authenticated {
		resp, err = client.CallAuthAuto(OpDsBind, buf.Bytes())
	} else {
		resp, err = client.Call(OpDsBind, buf.Bytes())
	}
	if err != nil {
		return nil, err
	}

	// Response structure per MS-DRSR:
	// [out] DRS_EXTENSIONS** ppextServer - pointer then deferred data
	// [out, ref] DRS_HANDLE* phDrs - context handle (policy handle - 20 bytes)

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	if build.Debug {
		log.Printf("[D] DsBind response: %d bytes, hex: %x", len(resp), resp)
	}

	// Response structure for IDL_DRSBind:
	// The response contains ppextServer and phDrs, but the exact layout
	// depends on NDR marshalling rules. Based on analysis:
	// - First 4 bytes: ppextServer pointer (referent ID)
	// - Followed by DRS_EXTENSIONS data (if pointer non-null)
	// - Context handle (phDrs) comes at a specific offset

	// The context handle appears to be at a fixed offset after the extensions
	// Looking at the response structure, let's find the handle by looking
	// for the pattern or using the last 20 bytes before trailing zeros

	result := &BindResult{}

	// Parse ppextServer - this is a conformant structure in NDR
	// Structure: [referent_id][conformance_count][cb][rgb...]
	r := bytes.NewReader(resp)
	var ptrExt uint32
	binary.Read(r, binary.LittleEndian, &ptrExt)

	if build.Debug {
		log.Printf("[D] DsBind ppextServer pointer: 0x%08x", ptrExt)
	}

	if ptrExt != 0 {
		// DRS_EXTENSIONS is a conformant structure in NDR
		// The conformance (MaxCount) comes before the structure body
		// Then cb field, then rgb[] bytes
		var maxCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)

		var cb uint32
		binary.Read(r, binary.LittleEndian, &cb)

		if build.Debug {
			log.Printf("[D] DsBind extensions: maxCount=%d, cb=%d, reader pos after cb=%d",
				maxCount, cb, int(r.Size())-r.Len())
		}

		// Read rgb[] bytes - the actual size is cb, NOT maxCount
		// maxCount is the conformant array size, cb is the inline field
		rgb := make([]byte, cb)
		n, _ := r.Read(rgb)

		if build.Debug {
			log.Printf("[D] DsBind extensions: read %d rgb bytes, reader pos=%d",
				n, int(r.Size())-r.Len())
		}

		// Parse the extension data from rgb[]
		// DRS_EXTENSIONS_INT: Flags(4) + SiteObjGuid(16) + Pid(4) + dwReplEpoch(4) +
		//                     dwFlagsExt(4) + ConfigObjGUID(16) + dwExtCaps(4) = 52 bytes
		if len(rgb) >= 24 {
			sExt := &DrsExtensions{Cb: cb}
			sExt.Flags = binary.LittleEndian.Uint32(rgb[0:4])
			copy(sExt.SiteObjGuid[:], rgb[4:20])
			sExt.Pid = binary.LittleEndian.Uint32(rgb[20:24])
			if len(rgb) >= 28 {
				sExt.DwReplEpoch = binary.LittleEndian.Uint32(rgb[24:28])
			}
			if len(rgb) >= 32 {
				sExt.DwFlagsExt = binary.LittleEndian.Uint32(rgb[28:32])
			}
			if len(rgb) >= 48 {
				copy(sExt.ConfigObjGUID[:], rgb[32:48])
			}
			if len(rgb) >= 52 {
				sExt.DwExtCaps = binary.LittleEndian.Uint32(rgb[48:52])
			}
			result.Extensions = sExt

			if build.Debug {
				log.Printf("[D] DsBind extensions parsed: flags=0x%08x, pid=%d, replEpoch=%d, extCaps=0x%08x",
					sExt.Flags, sExt.Pid, sExt.DwReplEpoch, sExt.DwExtCaps)
			}
		}
	}

	// The context handle (20 bytes) comes after extensions
	result.Handle = make([]byte, 20)
	n, _ := r.Read(result.Handle)

	if build.Debug {
		log.Printf("[D] DsBind handle (%d bytes): %x", n, result.Handle)
		// Also show remaining bytes (should be return code)
		remaining := make([]byte, r.Len())
		r.Read(remaining)
		log.Printf("[D] DsBind remaining: %x", remaining)
	}

	return result, nil
}
