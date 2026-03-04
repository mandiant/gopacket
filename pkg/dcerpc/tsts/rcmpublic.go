package tsts

import (
	"bytes"
	"encoding/binary"
	"log"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
)

// RCMPublicClient wraps the RCMPublic interface (TermSrv_API_service pipe).
type RCMPublicClient struct {
	client *dcerpc.Client
}

// NewRCMPublicClient creates a new RCMPublic client.
func NewRCMPublicClient(client *dcerpc.Client) *RCMPublicClient {
	return &RCMPublicClient{client: client}
}

// GetClientData retrieves client data for a session (Opnum 0).
// Returns nil, nil if no client data is available (e.g. console session).
func (r *RCMPublicClient) GetClientData(sessionId int32) (*ClientData, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, sessionId)

	resp, err := r.client.CallAuthAuto(OpRpcGetClientData, buf.Bytes())
	if err != nil {
		// Some sessions (like console) may not have client data
		if build.Debug {
			log.Printf("[D] TSTS RCMPublic: GetClientData failed for session %d: %v", sessionId, err)
		}
		return nil, nil
	}

	if build.Debug {
		log.Printf("[D] TSTS RCMPublic: GetClientData response (%d bytes)", len(resp))
	}

	// Response: NDR pointer → WINSTATIONCLIENT struct + pOutBuffByteLen(4) + ErrorCode(4)
	if len(resp) < 12 {
		return nil, nil
	}

	// Check ErrorCode at end
	errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if errCode != 0 {
		return nil, nil
	}

	// Skip NDR pointer (4 bytes referent)
	offset := 4

	// WINSTATIONCLIENT is a flat structure. Parse fields sequentially.
	// Layout (based on Impacket's WINSTATIONCLIENT structure):
	//
	// FLAGS (6 bytes)
	// ClientName: WCHAR[21] = 42 bytes
	// Domain: WCHAR[18] = 36 bytes
	// UserName: WCHAR[21] = 42 bytes
	// Password: WCHAR[15] = 30 bytes
	// WorkDirectory: WCHAR[257] = 514 bytes
	// InitialProgram: WCHAR[257] = 514 bytes
	// SerialNumber: ULONG (4 bytes)
	// EncryptionLevel: BYTE (1 byte)
	// [alignment to 4 bytes: 3 bytes padding]
	// ClientAddressFamily: ULONG (4 bytes)
	// ClientAddress: WCHAR[31] = 62 bytes
	// [alignment: 2 bytes]
	// HRes: USHORT (2 bytes)
	// VRes: USHORT (2 bytes)
	// ColorDepth: USHORT (2 bytes)
	// ProtocolType: USHORT (2 bytes)
	// KeyboardLayout: ULONG (4 bytes)
	// KeyboardType: ULONG (4 bytes)
	// KeyboardSubType: ULONG (4 bytes)
	// KeyboardFunctionKey: ULONG (4 bytes)
	// imeFileName: WCHAR[33] = 66 bytes
	// [alignment: 2 bytes]
	// ClientDirectory: WCHAR[257] = 514 bytes
	// [alignment: 2 bytes]
	// ClientLicense: WCHAR[33] = 66 bytes
	// [alignment: 2 bytes]
	// ClientModem: WCHAR[41] = 82 bytes
	// [alignment: 2 bytes]
	// ClientBuildNumber: ULONG (4 bytes)
	// ClientHardwareId: ULONG (4 bytes)
	// ClientProductId: USHORT (2 bytes)
	// OutBufCountHost: USHORT (2 bytes)
	// OutBufCountClient: USHORT (2 bytes)
	// OutBufLength: USHORT (2 bytes)
	// AudioDriverName: WCHAR[9] = 18 bytes
	// [alignment: 2 bytes]
	// ClientTimeZone: TS_TIME_ZONE_INFORMATION (172 bytes)
	//   Bias(4) + StandardName(32*2=64) + StandardDate(16) + StandardBias(4)
	//   + DaylightName(32*2=64) + DaylightDate(16) + DaylightBias(4)

	data := resp[offset:]
	if len(data) < 100 {
		return nil, nil
	}

	cd := &ClientData{}
	pos := 0

	// FLAGS (6 bytes)
	pos += 6

	// ClientName: WCHAR[21]
	if pos+clientNameLength*2 > len(data) {
		return cd, nil
	}
	cd.ClientName = readFixedWideString(data[pos:], clientNameLength)
	pos += clientNameLength * 2

	// Domain: WCHAR[18]
	if pos+domainLength*2 > len(data) {
		return cd, nil
	}
	cd.Domain = readFixedWideString(data[pos:], domainLength)
	pos += domainLength * 2

	// UserName: WCHAR[21]
	if pos+userNameLength*2 > len(data) {
		return cd, nil
	}
	cd.UserName = readFixedWideString(data[pos:], userNameLength)
	pos += userNameLength * 2

	// Password: WCHAR[15]
	pos += passwordLength * 2

	// WorkDirectory: WCHAR[257]
	pos += directoryLength * 2

	// InitialProgram: WCHAR[257]
	pos += initialProgLength * 2

	// SerialNumber (4)
	pos += 4

	// EncryptionLevel (1)
	pos += 1

	// Alignment to 4 bytes
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	// ClientAddressFamily (4)
	pos += 4

	// ClientAddress: WCHAR[31]
	if pos+clientAddrLength*2 > len(data) {
		return cd, nil
	}
	cd.ClientAddress = readFixedWideString(data[pos:], clientAddrLength)
	pos += clientAddrLength * 2

	// Align to 2 for USHORT
	if pos%2 != 0 {
		pos++
	}

	// HRes (2)
	if pos+4 > len(data) {
		return cd, nil
	}
	cd.HRes = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	// VRes (2)
	cd.VRes = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	// ColorDepth (2)
	pos += 2
	// ProtocolType (2)
	pos += 2

	// KeyboardLayout (4)
	pos += 4
	// KeyboardType (4)
	pos += 4
	// KeyboardSubType (4)
	pos += 4
	// KeyboardFunctionKey (4)
	pos += 4

	// imeFileName: WCHAR[33]
	pos += imeFileNameLength * 2

	// Align
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	// ClientDirectory: WCHAR[257]
	pos += directoryLength * 2

	// Align
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	// ClientLicense: WCHAR[33]
	pos += clientLicenseLength * 2

	// Align
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	// ClientModem: WCHAR[41]
	pos += clientModemLength * 2

	// Align
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	// ClientBuildNumber (4)
	pos += 4
	// ClientHardwareId (4)
	pos += 4
	// ClientProductId (2)
	pos += 2
	// OutBufCountHost (2)
	pos += 2
	// OutBufCountClient (2)
	pos += 2
	// OutBufLength (2)
	pos += 2

	// AudioDriverName: WCHAR[9]
	pos += audioDriverLength * 2

	// Align to 4
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	// ClientTimeZone: TS_TIME_ZONE_INFORMATION (172 bytes)
	// Bias(4) + StandardName(32*2=64) + StandardDate(16) + StandardBias(4)
	// + DaylightName(32*2=64) + DaylightDate(16) + DaylightBias(4) = 172
	if pos+172 <= len(data) {
		// Skip Bias (4)
		pos += 4
		// StandardName: WCHAR[32]
		cd.ClientTimeZone = readFixedWideString(data[pos:], 32)
		pos += 64 // StandardName
		pos += 16 // StandardDate
		pos += 4  // StandardBias
		pos += 64 // DaylightName
		pos += 16 // DaylightDate
		pos += 4  // DaylightBias
	}

	return cd, nil
}
