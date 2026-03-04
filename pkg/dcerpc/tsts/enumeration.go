package tsts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
)

// EnumerationClient wraps the TermSrvEnumeration interface (LSM_API_service pipe).
type EnumerationClient struct {
	client *dcerpc.Client
}

// NewEnumerationClient creates a new TermSrvEnumeration client.
func NewEnumerationClient(client *dcerpc.Client) *EnumerationClient {
	return &EnumerationClient{client: client}
}

// OpenEnum opens an enumeration handle (Opnum 0).
func (e *EnumerationClient) OpenEnum() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(make([]byte, 20)) // zero handle (hBinding)

	resp, err := e.client.CallAuthAuto(OpRpcOpenEnum, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("OpenEnum call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Enum: OpenEnum response (%d bytes): %x", len(resp), resp)
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("OpenEnum response too short (%d bytes)", len(resp))
	}

	// Response: ENUM_HANDLE(20) + ErrorCode(4)
	errCode := binary.LittleEndian.Uint32(resp[20:24])
	if errCode != 0 {
		return nil, fmt.Errorf("OpenEnum failed: 0x%08x", errCode)
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	return handle, nil
}

// CloseEnum closes an enumeration handle (Opnum 1).
func (e *EnumerationClient) CloseEnum(handle []byte) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)

	resp, err := e.client.CallAuthAuto(OpRpcCloseEnum, buf.Bytes())
	if err != nil {
		return fmt.Errorf("CloseEnum call failed: %v", err)
	}

	if len(resp) < 24 {
		return nil
	}

	errCode := binary.LittleEndian.Uint32(resp[20:24])
	if errCode != 0 {
		return fmt.Errorf("CloseEnum failed: 0x%08x", errCode)
	}

	return nil
}

// GetEnumResult retrieves session enumeration results (Opnum 5).
func (e *EnumerationClient) GetEnumResult(handle []byte) ([]SessionEnumLevel1, error) {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Level = 1

	resp, err := e.client.CallAuthAuto(OpRpcGetEnumResult, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("GetEnumResult call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Enum: GetEnumResult response (%d bytes)", len(resp))
	}

	// Response: NDR pointer → conformant array of SessionEnum_Level1 + pEntries(4) + ErrorCode(4)
	// Parse:
	// Referent ptr (4)
	// If non-null:
	//   MaxCount (4)
	//   For each entry:
	//     Level (4) + union_tag (4) + SessionId (4) + State (4) + Name (33*2=66 bytes)
	//   Alignment padding as needed
	// pEntries (4)
	// ErrorCode (4)

	if len(resp) < 12 {
		return nil, fmt.Errorf("GetEnumResult response too short")
	}

	offset := 0

	// Referent pointer
	refPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	var sessions []SessionEnumLevel1

	if refPtr != 0 {
		if offset+4 > len(resp) {
			return nil, fmt.Errorf("GetEnumResult: response too short for MaxCount")
		}
		maxCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		for i := uint32(0); i < maxCount; i++ {
			// Each entry: Level(4) + union_tag(4) + SessionId(4) + State(4) + Name(33*2=66)
			entrySize := 4 + 4 + 4 + 4 + 66
			if offset+entrySize > len(resp) {
				break
			}

			// Level
			_ = binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			// Union tag
			_ = binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			// SessionId
			sessionId := int32(binary.LittleEndian.Uint32(resp[offset:]))
			offset += 4

			// State
			state := binary.LittleEndian.Uint32(resp[offset:])
			offset += 4

			// Name: WCHAR[33] = 66 bytes
			name := readFixedWideString(resp[offset:], 33)
			offset += 66

			// Align to 4-byte boundary
			if offset%4 != 0 {
				offset += 4 - (offset % 4)
			}

			sessions = append(sessions, SessionEnumLevel1{
				SessionId: sessionId,
				State:     state,
				Name:      name,
			})
		}
	}

	// Read pEntries and ErrorCode from the end
	// They're at: len(resp) - 8 for pEntries, len(resp) - 4 for ErrorCode
	if len(resp) >= 4 {
		errCode := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if errCode != 0 {
			return nil, fmt.Errorf("GetEnumResult failed: 0x%08x", errCode)
		}
	}

	return sessions, nil
}

// GetSessionList is a convenience method: OpenEnum + GetEnumResult + CloseEnum.
func (e *EnumerationClient) GetSessionList() ([]SessionEnumLevel1, error) {
	handle, err := e.OpenEnum()
	if err != nil {
		return nil, err
	}
	defer e.CloseEnum(handle)

	return e.GetEnumResult(handle)
}
