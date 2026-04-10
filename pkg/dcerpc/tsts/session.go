// SPDX-License-Identifier: Apache-2.0

package tsts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
)

// SessionClient wraps the TermSrvSession interface (LSM_API_service pipe).
type SessionClient struct {
	client *dcerpc.Client
}

// NewSessionClient creates a new TermSrvSession client.
func NewSessionClient(client *dcerpc.Client) *SessionClient {
	return &SessionClient{client: client}
}

// OpenSession opens a session handle (Opnum 0).
// Request: SessionId(4) + zero handle(20). Response: SESSION_HANDLE(20) + ErrorCode(4).
func (s *SessionClient) OpenSession(sessionId int32) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, sessionId)
	buf.Write(make([]byte, 20)) // zero handle

	resp, err := s.client.CallAuthAuto(OpRpcOpenSession, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("OpenSession call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Session: OpenSession response (%d bytes): %x", len(resp), resp)
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenSession response too short (%d bytes)", len(resp))
	}

	errCode := binary.LittleEndian.Uint32(resp[20:24])
	if errCode != 0 {
		return nil, fmt.Errorf("OpenSession failed: 0x%08x", errCode)
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// CloseSession closes a session handle (Opnum 1).
func (s *SessionClient) CloseSession(handle []byte) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)

	_, err := s.client.CallAuthAuto(OpRpcCloseSession, buf.Bytes())
	return err
}

// Connect connects a session to a target session (Opnum 2).
// Error code 0x1 means success (quirk in the protocol).
func (s *SessionClient) Connect(handle []byte, targetSessionId int32, password string) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)
	binary.Write(buf, binary.LittleEndian, targetSessionId)

	if password == "" {
		password = "\x00" // At minimum a null-terminated empty string
	}
	writeWideString(buf, password)

	resp, err := s.client.CallAuthAuto(OpRpcConnect, buf.Bytes())
	if err != nil {
		// Error code 0x1 means success (per Impacket)
		if err.Error() == "RPC Fault: status=0x00000001" {
			return nil
		}
		return fmt.Errorf("Connect call failed: %v", err)
	}

	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if errCode != 0 && errCode != 1 {
			return fmt.Errorf("Connect failed: 0x%08x", errCode)
		}
	}

	return nil
}

// Disconnect disconnects a session (Opnum 3).
func (s *SessionClient) Disconnect(handle []byte) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)

	resp, err := s.client.CallAuthAuto(OpRpcDisconnect, buf.Bytes())
	if err != nil {
		return fmt.Errorf("Disconnect call failed: %v", err)
	}

	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if errCode != 0 {
			return fmt.Errorf("Disconnect failed: 0x%08x", errCode)
		}
	}

	return nil
}

// Logoff signs out a session (Opnum 4).
// Error code 0x10000000 means success (quirk in the protocol).
func (s *SessionClient) Logoff(handle []byte) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)

	resp, err := s.client.CallAuthAuto(OpRpcLogoff, buf.Bytes())
	if err != nil {
		// Error code 0x10000000 means success (per Impacket)
		if err.Error() == "RPC Fault: status=0x10000000" {
			return nil
		}
		return fmt.Errorf("Logoff call failed: %v", err)
	}

	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if errCode != 0 && errCode != 0x10000000 {
			return fmt.Errorf("Logoff failed: 0x%08x", errCode)
		}
	}

	return nil
}

// ShowMessageBox sends a message box to a session (Opnum 9).
func (s *SessionClient) ShowMessageBox(handle []byte, title, message string, style, timeout uint32, doNotWait bool) error {
	if title == "" {
		title = " "
	}

	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)
	writeWideString(buf, title)
	writeWideString(buf, message)
	binary.Write(buf, binary.LittleEndian, style)
	binary.Write(buf, binary.LittleEndian, timeout)

	var bWait uint32
	if doNotWait {
		bWait = 1
	}
	binary.Write(buf, binary.LittleEndian, bWait)

	resp, err := s.client.CallAuthAuto(OpRpcShowMessageBox, buf.Bytes())
	if err != nil {
		return fmt.Errorf("ShowMessageBox call failed: %v", err)
	}

	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if errCode != 0 {
			return fmt.Errorf("ShowMessageBox failed: 0x%08x", errCode)
		}
	}

	return nil
}

// GetSessionInformationEx retrieves extended session info (Opnum 17).
func (s *SessionClient) GetSessionInformationEx(sessionId int32) (*SessionInfoEx, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, sessionId)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Level = 1

	resp, err := s.client.CallAuthAuto(OpRpcGetSessionInformationEx, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("GetSessionInformationEx call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Session: GetSessionInformationEx response (%d bytes)", len(resp))
	}

	// Response format:
	// LSMSessionInfoExPtr: NDR pointer → union:
	//   tag(4) → LSM_SessionInfo_Level1:
	//     SessionState (4)
	//     SessionFlags (4)
	//     SessionName  (33*2=66 bytes)
	//     DomainName   (18*2=36 bytes)
	//     UserName     (21*2=42 bytes)
	//     ConnectTime  (8)
	//     DisconnectTime (8)
	//     LogonTime    (8)
	//     LastInputTime  (8)
	//     ProtocolDataSize (4)
	//     ProtocolData (NDR pointer)
	// ErrorCode (4)

	// There is an NDR pointer wrapper + level indicator first.
	// Typical layout: refPtr(4) + tag(4) + data...

	if len(resp) < 20 {
		return nil, fmt.Errorf("GetSessionInformationEx response too short")
	}

	offset := 0

	// Skip referent pointer
	_ = binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Union tag
	_ = binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// SessionState
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for SessionState")
	}
	sessionState := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// SessionFlags
	if offset+4 > len(resp) {
		return nil, fmt.Errorf("response too short for SessionFlags")
	}
	sessionFlags := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// SessionName: WCHAR[33] = 66 bytes
	if offset+66 > len(resp) {
		return nil, fmt.Errorf("response too short for SessionName")
	}
	sessionName := readFixedWideString(resp[offset:], 33)
	offset += 66

	// No alignment needed - WCHAR arrays are 2-byte aligned

	// DomainName: WCHAR[18] = 36 bytes
	if offset+36 > len(resp) {
		return nil, fmt.Errorf("response too short for DomainName")
	}
	domainName := readFixedWideString(resp[offset:], 18)
	offset += 36

	// UserName: WCHAR[21] = 42 bytes
	if offset+42 > len(resp) {
		return nil, fmt.Errorf("response too short for UserName")
	}
	userName := readFixedWideString(resp[offset:], 21)
	offset += 42

	// Align to 8 bytes for LARGE_INTEGER
	if offset%8 != 0 {
		offset += 8 - (offset % 8)
	}

	// ConnectTime (FILETIME, 8)
	if offset+8 > len(resp) {
		return nil, fmt.Errorf("response too short for ConnectTime")
	}
	connectTime := readFileTime(resp[offset:])
	offset += 8

	// DisconnectTime
	if offset+8 > len(resp) {
		return nil, fmt.Errorf("response too short for DisconnectTime")
	}
	disconnectTime := readFileTime(resp[offset:])
	offset += 8

	// LogonTime
	if offset+8 > len(resp) {
		return nil, fmt.Errorf("response too short for LogonTime")
	}
	logonTime := readFileTime(resp[offset:])
	offset += 8

	// LastInputTime
	if offset+8 > len(resp) {
		return nil, fmt.Errorf("response too short for LastInputTime")
	}
	lastInputTime := readFileTime(resp[offset:])
	offset += 8

	// ErrorCode at end
	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if errCode != 0 {
			return nil, fmt.Errorf("GetSessionInformationEx failed: 0x%08x", errCode)
		}
	}

	return &SessionInfoEx{
		SessionState:   sessionState,
		SessionFlags:   sessionFlags,
		SessionName:    sessionName,
		DomainName:     domainName,
		UserName:       userName,
		ConnectTime:    connectTime,
		DisconnectTime: disconnectTime,
		LogonTime:      logonTime,
		LastInputTime:  lastInputTime,
	}, nil
}
