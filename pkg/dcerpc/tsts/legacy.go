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

// LegacyClient wraps the LegacyAPI interface (Ctx_WinStation_API_service pipe).
// Provides: OpenServer, CloseServer, ShutdownSystem, TerminateProcess, GetAllProcesses.
type LegacyClient struct {
	client *dcerpc.Client
}

// NewLegacyClient creates a new LegacyAPI client.
func NewLegacyClient(client *dcerpc.Client) *LegacyClient {
	return &LegacyClient{client: client}
}

// OpenServer opens a server handle (Opnum 0).
// Response: pResult(4) + SERVER_HANDLE(20) + ErrorCode(1 padded to 4, BOOLEAN).
func (l *LegacyClient) OpenServer() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(make([]byte, 20)) // zero handle

	resp, err := l.client.CallAuthAuto(OpRpcWinStationOpenServer, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("OpenServer call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Legacy: OpenServer response (%d bytes): %x", len(resp), resp)
	}

	// Response layout: pResult(4) + SERVER_HANDLE(20) + ErrorCode(BOOLEAN, last byte)
	if len(resp) < 25 {
		return nil, fmt.Errorf("OpenServer response too short (%d bytes)", len(resp))
	}

	// ErrorCode is the last byte (BOOLEAN)
	errorCode := resp[len(resp)-1]
	if errorCode == 0 {
		return nil, fmt.Errorf("OpenServer failed: server returned false")
	}

	// SERVER_HANDLE is at offset 4 (after pResult)
	handle := make([]byte, 20)
	copy(handle, resp[4:24])

	return handle, nil
}

// CloseServer closes a server handle (Opnum 1).
func (l *LegacyClient) CloseServer(handle []byte) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)

	_, err := l.client.CallAuthAuto(OpRpcWinStationCloseServer, buf.Bytes())
	return err
}

// ShutdownSystem sends a shutdown event (Opnum 15).
func (l *LegacyClient) ShutdownSystem(handle []byte, clientLogonId uint32, flags uint32) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)
	binary.Write(buf, binary.LittleEndian, clientLogonId)
	binary.Write(buf, binary.LittleEndian, flags)

	resp, err := l.client.CallAuthAuto(OpRpcWinStationShutdownSystem, buf.Bytes())
	if err != nil {
		return fmt.Errorf("ShutdownSystem call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Legacy: ShutdownSystem response (%d bytes): %x", len(resp), resp)
	}

	// ErrorCode is the last byte (BOOLEAN)
	if len(resp) > 0 && resp[len(resp)-1] == 0 {
		return fmt.Errorf("ShutdownSystem failed")
	}

	return nil
}

// TerminateProcess kills a process by PID (Opnum 37).
func (l *LegacyClient) TerminateProcess(handle []byte, pid uint32, exitCode uint32) error {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)
	binary.Write(buf, binary.LittleEndian, pid)
	binary.Write(buf, binary.LittleEndian, exitCode)

	resp, err := l.client.CallAuthAuto(OpRpcWinStationTerminateProcess, buf.Bytes())
	if err != nil {
		return fmt.Errorf("TerminateProcess call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Legacy: TerminateProcess response (%d bytes): %x", len(resp), resp)
	}

	// ErrorCode is the last byte (BOOLEAN)
	if len(resp) > 0 && resp[len(resp)-1] == 0 {
		return fmt.Errorf("TerminateProcess failed for PID %d", pid)
	}

	return nil
}

// GetAllProcesses returns all running processes (Opnum 43).
// Uses raw parsing like Impacket (gives up on proper NDR for this method).
func (l *LegacyClient) GetAllProcesses(handle []byte) ([]ProcessInfo, error) {
	buf := new(bytes.Buffer)
	writeContextHandle(buf, handle)
	binary.Write(buf, binary.LittleEndian, uint32(0))      // Level = 0
	binary.Write(buf, binary.LittleEndian, uint32(0x8000)) // pNumberOfProcesses

	resp, err := l.client.CallAuthAuto(OpRpcWinStationGetAllProcesses, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("GetAllProcesses call failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TSTS Legacy: GetAllProcesses response (%d bytes)", len(resp))
	}

	if len(resp) < 10 {
		return nil, fmt.Errorf("GetAllProcesses response too short (%d bytes)", len(resp))
	}

	// ErrorCode is the last byte (BOOLEAN)
	errorCode := resp[len(resp)-1]
	if errorCode == 0 {
		return nil, fmt.Errorf("GetAllProcesses failed")
	}

	// pResult (4 bytes) at start
	// pNumberOfProcesses (4 bytes) follows
	numProcs := binary.LittleEndian.Uint32(resp[4:8])
	if numProcs == 0 {
		return nil, nil
	}

	// Strip trailing ErrorCode byte
	data := resp[8 : len(resp)-1]

	if build.Debug {
		log.Printf("[D] TSTS Legacy: numProcs=%d, data len=%d", numProcs, len(data))
	}

	return parseAllProcesses(data, int(numProcs))
}

// parseAllProcesses parses the raw response buffer from GetAllProcesses.
// This uses the same heuristic approach as Impacket (tsts.py lines 3539-3587):
// Skip NDR overhead, scan for process records using alignment heuristic.
func parseAllProcesses(data []byte, expectedCount int) ([]ProcessInfo, error) {
	var procs []ProcessInfo

	// Step 1: Skip NDR pointer overhead (TS_ALL_PROCESSES_INFO_ARRAY fixed parts).
	// Impacket scans for 0x0200 bytes and skips past them until gap > 12 bytes.
	for {
		idx := bytes.Index(data, []byte{0x02, 0x00})
		if idx < 0 {
			break
		}
		if idx > 12 {
			break
		}
		data = data[idx+2:]
	}

	// Step 2: Parse TS_SYS_PROCESS_INFORMATION records one by one.
	// Layout (offsets from record start):
	//   0: NextEntryOffset(4), 4: NumberOfThreads(4),
	//   8: SpareLi1-3(24), 32: CreateTime(8), 40: UserTime(8), 48: KernelTime(8),
	//  56: ImageName.Length(2), 58: ImageName.MaxLen(2), 60: ImageName.Buffer(4),
	//  64: BasePriority(4), 68: UniqueProcessId(4), 72: InheritedFrom(4),
	//  76: HandleCount(4), 80: SessionId(4), 84: SpareUl3(4),
	//  88-103: Virtual/PageFault sizes, 104: WorkingSetSize(4),
	// 108-135: Quota/Pagefile/PrivatePageCount fields
	// Total fixed: 136 bytes
	// Then deferred: ImageName(MaxCount+Offset+ActualCount + WCHARs) + SID(ActualCount + bytes)

	prevLen := 0 // Length of previously parsed record (0 for first iteration)
	for len(data) > 1 {
		if len(data[prevLen:]) < 16 {
			break
		}

		// Alignment heuristic: read 4 DWORDs starting at prevLen offset.
		// NumberOfThreads (always > 0) tells us alignment.
		b := binary.LittleEndian.Uint32(data[prevLen : prevLen+4])
		c := binary.LittleEndian.Uint32(data[prevLen+4 : prevLen+8])
		d := binary.LittleEndian.Uint32(data[prevLen+8 : prevLen+12])
		e := binary.LittleEndian.Uint32(data[prevLen+12 : prevLen+16])

		if b != 0 {
			data = data[prevLen-4:]
		} else if c != 0 {
			data = data[prevLen:]
		} else if d != 0 {
			data = data[prevLen+4:]
		} else if e != 0 {
			data = data[prevLen+8:]
		} else {
			break
		}

		if len(data) < 136 {
			break
		}

		imageNameLen := int(binary.LittleEndian.Uint16(data[56:58]))
		uniqueProcessId := binary.LittleEndian.Uint32(data[68:72])
		sessionId := binary.LittleEndian.Uint32(data[80:84])
		workingSetSize := binary.LittleEndian.Uint32(data[104:108])

		// After fixed part (136 bytes): deferred ImageName as conformant varying WCHAR string
		pos := 136

		// ImageName: MaxCount(4) + Offset(4) + ActualCount(4) + WCHARs
		var imageName string
		if pos+12 <= len(data) {
			// maxCount := binary.LittleEndian.Uint32(data[pos:])
			pos += 4
			pos += 4 // offset
			actualCount := binary.LittleEndian.Uint32(data[pos:])
			pos += 4
			charBytes := int(actualCount) * 2
			if charBytes > 0 && pos+charBytes <= len(data) {
				imageName = readFixedWideString(data[pos:pos+charBytes], int(actualCount))
				pos += charBytes
			}
		}

		// Align to 4 bytes
		if pos%4 != 0 {
			pos += 4 - (pos % 4)
		}

		// SID: ActualCount(4) + raw bytes
		var sidStr string
		if pos+4 <= len(data) {
			sidActualCount := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			pos += 4
			if sidActualCount > 0 && pos+sidActualCount <= len(data) {
				sidBytes := data[pos : pos+sidActualCount]
				sidStr = formatSID(sidBytes)
				if sidStr != "" {
					sidStr = knownSID(sidStr)
				}
				pos += sidActualCount
			}
		}

		// Align total consumed to 4 bytes
		if pos%4 != 0 {
			pos += 4 - (pos % 4)
		}

		if build.Debug && len(procs) < 3 {
			log.Printf("[D] TSTS Legacy: proc[%d] PID=%d SID=%d WS=%d Name=%q rawLen=%d imgNameLen=%d",
				len(procs), uniqueProcessId, sessionId, workingSetSize, imageName, pos, imageNameLen)
		}

		procs = append(procs, ProcessInfo{
			ImageName:       imageName,
			UniqueProcessId: uniqueProcessId,
			SessionId:       sessionId,
			WorkingSetSize:  workingSetSize,
			SID:             sidStr,
		})

		prevLen = pos
	}

	return procs, nil
}
