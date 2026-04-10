// SPDX-License-Identifier: Apache-2.0

package tsts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

// MS-TSTS Terminal Services Terminal Server Runtime Interface Protocol
// Four RPC interfaces across three named pipes.

// Interface UUIDs (wire format)
var (
	TermSrvEnumerationUUID = dcerpc.MustParseUUID("88143fd0-c28d-4b2b-8fef-8d882f6a9390")
	TermSrvSessionUUID     = dcerpc.MustParseUUID("484809d6-4239-471b-b5bc-61df8c23ac48")
	RCMPublicUUID          = dcerpc.MustParseUUID("bde95fdf-eee0-45de-9e12-e5a61cd0d4fe")
	LegacyAPIUUID          = dcerpc.MustParseUUID("5ca4a760-ebb1-11cf-8611-00a0245420ed")
)

const MajorVersion = 1
const MinorVersion = 0

// Pipe names
const (
	PipeLSMAPI        = "LSM_API_service"
	PipeTermSrvAPI    = "TermSrv_API_service"
	PipeCtxWinStation = "Ctx_WinStation_API_service"
)

// TermSrvEnumeration opnums
const (
	OpRpcOpenEnum      = 0
	OpRpcCloseEnum     = 1
	OpRpcGetEnumResult = 5
)

// TermSrvSession opnums
const (
	OpRpcOpenSession             = 0
	OpRpcCloseSession            = 1
	OpRpcConnect                 = 2
	OpRpcDisconnect              = 3
	OpRpcLogoff                  = 4
	OpRpcShowMessageBox          = 9
	OpRpcGetSessionInformationEx = 17
)

// RCMPublic opnums
const (
	OpRpcGetClientData = 0
)

// LegacyAPI opnums
const (
	OpRpcWinStationOpenServer       = 0
	OpRpcWinStationCloseServer      = 1
	OpRpcWinStationShutdownSystem   = 15
	OpRpcWinStationTerminateProcess = 37
	OpRpcWinStationGetAllProcesses  = 43
)

// WINSTATIONSTATECLASS enum values
const (
	StateActive       = 0
	StateConnected    = 1
	StateConnectQuery = 2
	StateShadow       = 3
	StateDisconnected = 4
	StateIdle         = 5
	StateListen       = 6
	StateReset        = 7
	StateDown         = 8
	StateInit         = 9
)

// StateName returns the display name for a WINSTATIONSTATECLASS value.
func StateName(state uint32) string {
	switch state {
	case StateActive:
		return "Active"
	case StateConnected:
		return "Connected"
	case StateConnectQuery:
		return "ConnectQuery"
	case StateShadow:
		return "Shadow"
	case StateDisconnected:
		return "Disconnected"
	case StateIdle:
		return "Idle"
	case StateListen:
		return "Listen"
	case StateReset:
		return "Reset"
	case StateDown:
		return "Down"
	case StateInit:
		return "Init"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// SESSIONFLAGS enum values
const (
	SessionFlagUnknown = 0xFFFFFFFF
	SessionFlagLock    = 0x00000000
	SessionFlagUnlock  = 0x00000001
)

// SessionFlagName returns the display name for a SESSIONFLAGS value.
func SessionFlagName(flags uint32) string {
	switch flags {
	case SessionFlagUnknown:
		return "WTS_SESSIONSTATE_UNKNOWN"
	case SessionFlagLock:
		return "WTS_SESSIONSTATE_LOCK"
	case SessionFlagUnlock:
		return "WTS_SESSIONSTATE_UNLOCK"
	default:
		return fmt.Sprintf("Unknown(0x%x)", flags)
	}
}

// DesktopStateName returns the short display name for desktop state.
func DesktopStateName(flags uint32) string {
	switch flags {
	case SessionFlagUnknown:
		return ""
	case SessionFlagLock:
		return "Locked"
	case SessionFlagUnlock:
		return "Unlocked"
	default:
		return ""
	}
}

// Shutdown flags
const (
	ShutdownLogoff   = 1
	ShutdownShutdown = 2
	ShutdownReboot   = 4
	ShutdownPoweroff = 8
)

// WINSTATIONCLIENT field lengths (character counts, NOT bytes)
const (
	clientNameLength    = 21  // CLIENTNAME_LENGTH+1
	domainLength        = 18  // DOMAIN_LENGTH+1
	userNameLength      = 21  // USERNAME_LENGTH+1
	passwordLength      = 15  // PASSWORD_LENGTH+1
	directoryLength     = 257 // DIRECTORY_LENGTH+1
	initialProgLength   = 257 // INITIALPROGRAM_LENGTH+1
	clientAddrLength    = 31  // CLIENTADDRESS_LENGTH+1
	imeFileNameLength   = 33  // IMEFILENAME_LENGTH+1
	clientLicenseLength = 33  // CLIENTLICENSE_LENGTH+1
	clientModemLength   = 41  // CLIENTMODEM_LENGTH+1
	audioDriverLength   = 9   // AUDIODRIVENAME_LENGTH (no +1)
	clientProductIdLen  = 32  // CLIENT_PRODUCT_ID_LENGTH
)

// SessionEnumLevel1 represents a session from enumeration.
type SessionEnumLevel1 struct {
	SessionId int32
	State     uint32
	Name      string // WCHAR[33]
}

// SessionInfoEx holds extended session information.
type SessionInfoEx struct {
	SessionState   uint32
	SessionFlags   uint32
	SessionName    string
	DomainName     string
	UserName       string
	ConnectTime    time.Time
	DisconnectTime time.Time
	LogonTime      time.Time
	LastInputTime  time.Time
}

// ClientData holds WINSTATIONCLIENT data for a session.
type ClientData struct {
	ClientName     string
	Domain         string
	UserName       string
	ClientAddress  string
	HRes, VRes     uint16
	ClientTimeZone string
}

// ProcessInfo holds information about a running process.
type ProcessInfo struct {
	ImageName       string
	UniqueProcessId uint32
	SessionId       uint32
	WorkingSetSize  uint32
	SID             string
}

// NDR helpers

// writeWideString writes a UTF-16LE string with NDR conformant varying format.
func writeWideString(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // null terminator
	charCount := uint32(len(utf16Chars))

	binary.Write(buf, binary.LittleEndian, charCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, charCount) // ActualCount

	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}

// readFixedWideString reads a fixed-size WCHAR array and returns the null-trimmed string.
func readFixedWideString(data []byte, maxChars int) string {
	byteLen := maxChars * 2
	if len(data) < byteLen {
		byteLen = len(data)
	}
	charCount := byteLen / 2
	u16s := make([]uint16, charCount)
	for i := 0; i < charCount; i++ {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	// Trim null terminators
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

// readFileTime converts a Windows FILETIME (100ns since 1601-01-01) to time.Time.
func readFileTime(data []byte) time.Time {
	if len(data) < 8 {
		return time.Time{}
	}
	ft := binary.LittleEndian.Uint64(data)
	if ft == 0 {
		return time.Time{}
	}
	// Windows epoch: January 1, 1601. Difference to Unix epoch in 100ns ticks.
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	unixNano := int64(ft-epochDiff) * 100
	return time.Unix(0, unixNano)
}

// writeContextHandle writes a 20-byte context handle to the buffer.
func writeContextHandle(buf *bytes.Buffer, handle []byte) {
	if len(handle) == 20 {
		buf.Write(handle)
	} else {
		buf.Write(make([]byte, 20))
	}
}

// readContextHandle reads a 20-byte context handle from data.
func readContextHandle(data []byte) []byte {
	if len(data) < 20 {
		return make([]byte, 20)
	}
	h := make([]byte, 20)
	copy(h, data[:20])
	return h
}

// formatSID converts raw binary SID bytes to string form S-1-5-...
func formatSID(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}
	revision := sid[0]
	subAuthCount := int(sid[1])
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(sid[2+i])
	}
	s := fmt.Sprintf("S-%d-%d", revision, auth)
	for i := 0; i < subAuthCount; i++ {
		off := 8 + i*4
		if off+4 > len(sid) {
			break
		}
		sub := binary.LittleEndian.Uint32(sid[off:])
		s += fmt.Sprintf("-%d", sub)
	}
	return s
}

// knownSID translates well-known SIDs to friendly names.
func knownSID(sid string) string {
	known := map[string]string{
		"S-1-5-10": "SELF",
		"S-1-5-13": "TERMINAL SERVER USER",
		"S-1-5-11": "Authenticated Users",
		"S-1-5-12": "RESTRICTED",
		"S-1-5-14": "Authenticated Users",
		"S-1-5-15": "This Organization",
		"S-1-5-17": "IUSR",
		"S-1-5-18": "SYSTEM",
		"S-1-5-19": "LOCAL SERVICE",
		"S-1-5-20": "NETWORK SERVICE",
	}
	if name, ok := known[sid]; ok {
		return name
	}
	parts := strings.Split(sid, "-")
	// DWM-N: S-1-5-90-0-N
	if strings.HasPrefix(sid, "S-1-5-90-0-") && len(parts) == 6 {
		return fmt.Sprintf("DWM-%s", parts[5])
	}
	// UMFD-N: S-1-5-96-0-N
	if strings.HasPrefix(sid, "S-1-5-96-0-") && len(parts) == 6 {
		return fmt.Sprintf("UMFD-%s", parts[5])
	}
	return sid
}
