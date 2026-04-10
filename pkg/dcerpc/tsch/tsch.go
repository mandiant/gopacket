// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package tsch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

// MS-TSCH (Task Scheduler Service Remote Protocol)
// ITaskSchedulerService Interface
// UUID: 86D35949-83C9-4044-B424-DB363231FD0C v1.0

var UUID = [16]byte{
	0x49, 0x59, 0xd3, 0x86, 0xc9, 0x83, 0x44, 0x40,
	0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c,
}

const MajorVersion = 1
const MinorVersion = 0

// Operation numbers
const (
	OpSchRpcHighestVersion        = 0
	OpSchRpcRegisterTask          = 1
	OpSchRpcRetrieveTask          = 2
	OpSchRpcCreateFolder          = 3
	OpSchRpcSetSecurity           = 4
	OpSchRpcGetSecurity           = 5
	OpSchRpcEnumFolders           = 6
	OpSchRpcEnumTasks             = 7
	OpSchRpcEnumInstances         = 8
	OpSchRpcDelete                = 9
	OpSchRpcRename                = 10
	OpSchRpcScheduledRuntimes     = 11
	OpSchRpcRun                   = 12
	OpSchRpcStop                  = 13
	OpSchRpcGetInstanceInfo       = 14
	OpSchRpcStopInstance          = 15
	OpSchRpcGetTaskInfo           = 16
	OpSchRpcGetNumberOfMissedRuns = 17
	OpSchRpcEnableTask            = 18
)

// Task flags for SchRpcRegisterTask
const (
	TASK_VALIDATE_ONLY                = 0x01
	TASK_CREATE                       = 0x02
	TASK_UPDATE                       = 0x04
	TASK_CREATE_OR_UPDATE             = 0x06
	TASK_DISABLE                      = 0x08
	TASK_DONT_ADD_PRINCIPAL_ACE       = 0x10
	TASK_IGNORE_REGISTRATION_TRIGGERS = 0x20
)

// Logon types
const (
	TASK_LOGON_NONE                          = 0
	TASK_LOGON_PASSWORD                      = 1
	TASK_LOGON_S4U                           = 2
	TASK_LOGON_INTERACTIVE_TOKEN             = 3
	TASK_LOGON_GROUP                         = 4
	TASK_LOGON_SERVICE_ACCOUNT               = 5
	TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6
)

// Run flags for SchRpcRun
const (
	TASK_RUN_AS_SELF            = 0x1
	TASK_RUN_IGNORE_CONSTRAINTS = 0x2
	TASK_RUN_USE_SESSION_ID     = 0x4
	TASK_RUN_USER_SID           = 0x8
)

// SYSTEMTIME represents a Windows SYSTEMTIME structure
type SYSTEMTIME struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

// TaskScheduler manages task scheduler operations via MS-TSCH RPC
type TaskScheduler struct {
	client *dcerpc.Client
}

// NewTaskScheduler creates a new task scheduler client
func NewTaskScheduler(client *dcerpc.Client) *TaskScheduler {
	return &TaskScheduler{client: client}
}

// call issues an RPC call, automatically using authenticated transport if available.
func (ts *TaskScheduler) call(opNum uint16, payload []byte) ([]byte, error) {
	if ts.client.Authenticated {
		return ts.client.CallAuthAuto(opNum, payload)
	}
	return ts.client.Call(opNum, payload)
}

// RegisterTask registers a new task with the task scheduler service.
// path is the task path (e.g. "\TaskName"), xml is the task definition XML,
// flags controls creation behavior (TASK_CREATE, TASK_UPDATE, etc.).
func (ts *TaskScheduler) RegisterTask(path, xml string, flags uint32) (string, error) {
	buf := new(bytes.Buffer)

	// path (LPWSTR - unique pointer)
	if path == "" {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pointer
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // referent ID
		writeWideString(buf, path)
	}

	// xml (WSTR - conformant varying string, not a pointer)
	writeWideString(buf, xml)

	// flags
	binary.Write(buf, binary.LittleEndian, flags)

	// sddl (LPWSTR - unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// logonType
	binary.Write(buf, binary.LittleEndian, uint32(TASK_LOGON_NONE))

	// cCreds
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pCreds (unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := ts.call(OpSchRpcRegisterTask, buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("SchRpcRegisterTask RPC call failed: %v", err)
	}

	// Response: pActualPath (unique pointer to LPWSTR), pErrorInfo (unique pointer), ReturnValue (HRESULT)
	if len(resp) < 4 {
		return "", fmt.Errorf("response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return "", fmt.Errorf("SchRpcRegisterTask returned error 0x%08x", retVal)
	}

	// Try to extract actual path from response
	actualPath := path
	if len(resp) > 8 {
		ptrVal := binary.LittleEndian.Uint32(resp[0:4])
		if ptrVal != 0 && len(resp) > 16 {
			if s := readWideString(resp[4:]); s != "" {
				actualPath = s
			}
		}
	}

	return actualPath, nil
}

// Run triggers immediate execution of a registered task.
func (ts *TaskScheduler) Run(path string) error {
	return ts.RunWithFlags(path, 0, 0)
}

// RunWithSessionId triggers execution of a task in a specific user session.
// This is useful for running GUI applications in a user's desktop session.
// Note: When using session ID, there's typically no output capture.
func (ts *TaskScheduler) RunWithSessionId(path string, sessionId uint32) error {
	return ts.RunWithFlags(path, TASK_RUN_USE_SESSION_ID, sessionId)
}

// RunWithFlags triggers execution with specified flags and session ID.
func (ts *TaskScheduler) RunWithFlags(path string, flags, sessionId uint32) error {
	buf := new(bytes.Buffer)

	// path (WSTR - conformant varying string)
	writeWideString(buf, path)

	// cArgs
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pArgs (unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// flags
	binary.Write(buf, binary.LittleEndian, flags)

	// sessionId
	binary.Write(buf, binary.LittleEndian, sessionId)

	// user (LPWSTR - unique pointer, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := ts.call(OpSchRpcRun, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SchRpcRun RPC call failed: %v", err)
	}

	// Response: pGuid (16 bytes) + ReturnValue (4 bytes)
	if len(resp) < 20 {
		return fmt.Errorf("response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return fmt.Errorf("SchRpcRun returned error 0x%08x", retVal)
	}

	return nil
}

// GetLastRunInfo retrieves information about the last run of a task.
// Returns the last run time and return code.
func (ts *TaskScheduler) GetLastRunInfo(path string) (*SYSTEMTIME, uint32, error) {
	buf := new(bytes.Buffer)

	// path (WSTR - conformant varying string)
	writeWideString(buf, path)

	resp, err := ts.call(OpSchRpcGetTaskInfo, buf.Bytes())
	if err != nil {
		// Try the dedicated GetLastRunInfo opnum if GetTaskInfo fails
		return ts.getLastRunInfoDirect(path)
	}

	// Response structure is complex, fall back to direct method
	if len(resp) < 4 {
		return ts.getLastRunInfoDirect(path)
	}

	return ts.getLastRunInfoDirect(path)
}

// getLastRunInfoDirect uses a simpler approach to get last run info
// by polling the task status. This matches Impacket's hSchRpcGetLastRunInfo.
func (ts *TaskScheduler) getLastRunInfoDirect(path string) (*SYSTEMTIME, uint32, error) {
	// OpSchRpcGetLastRunInfo is not a standard opnum in MS-TSCH
	// Impacket implements it as opnum 13 (which is actually SchRpcStop)
	// The actual implementation uses SchRpcGetTaskInfo (opnum 16)

	buf := new(bytes.Buffer)
	writeWideString(buf, path)

	// SchRpcGetTaskInfo parameters:
	// path: WSTR
	// flags: DWORD (use 0)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // flags

	resp, err := ts.call(OpSchRpcGetTaskInfo, buf.Bytes())
	if err != nil {
		return nil, 0, fmt.Errorf("SchRpcGetTaskInfo failed: %v", err)
	}

	// Parse response - this is a simplified parse
	// The full response contains TASK_INFO structure
	if len(resp) < 24 {
		return nil, 0, fmt.Errorf("response too short")
	}

	// Extract SYSTEMTIME from response (starts at offset 4 after enabled flag)
	// Structure: Enabled(4) + SYSTEMTIME(16) + LastReturnCode(4) + ...
	st := &SYSTEMTIME{}
	r := bytes.NewReader(resp[4:])
	binary.Read(r, binary.LittleEndian, &st.Year)
	binary.Read(r, binary.LittleEndian, &st.Month)
	binary.Read(r, binary.LittleEndian, &st.DayOfWeek)
	binary.Read(r, binary.LittleEndian, &st.Day)
	binary.Read(r, binary.LittleEndian, &st.Hour)
	binary.Read(r, binary.LittleEndian, &st.Minute)
	binary.Read(r, binary.LittleEndian, &st.Second)
	binary.Read(r, binary.LittleEndian, &st.Milliseconds)

	var lastReturnCode uint32
	binary.Read(r, binary.LittleEndian, &lastReturnCode)

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, 0, fmt.Errorf("SchRpcGetTaskInfo returned error 0x%08x", retVal)
	}

	return st, lastReturnCode, nil
}

// HasTaskRun checks if the task has run by checking if Year != 0 in LastRunTime.
func (st *SYSTEMTIME) HasRun() bool {
	return st != nil && st.Year != 0
}

// Delete removes a registered task.
func (ts *TaskScheduler) Delete(path string) error {
	buf := new(bytes.Buffer)

	// path (WSTR - conformant varying string)
	writeWideString(buf, path)

	// flags
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := ts.call(OpSchRpcDelete, buf.Bytes())
	if err != nil {
		return fmt.Errorf("SchRpcDelete RPC call failed: %v", err)
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short (%d bytes)", len(resp))
	}

	retVal := binary.LittleEndian.Uint32(resp[:4])
	if retVal != 0 {
		return fmt.Errorf("SchRpcDelete returned error 0x%08x", retVal)
	}

	return nil
}

// writeWideString writes a UTF-16LE conformant varying string in NDR format.
func writeWideString(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // null terminator
	charCount := uint32(len(utf16Chars))

	// Conformant varying string: MaxCount, Offset, ActualCount
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

// readWideString reads a conformant varying string from NDR-encoded data.
func readWideString(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// maxCount := binary.LittleEndian.Uint32(data[0:4])
	// offset := binary.LittleEndian.Uint32(data[4:8])
	actualCount := binary.LittleEndian.Uint32(data[8:12])

	if actualCount == 0 {
		return ""
	}

	charData := data[12:]
	if int(actualCount*2) > len(charData) {
		return ""
	}

	u16s := make([]uint16, actualCount)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(charData[i*2 : i*2+2])
	}

	// Trim null terminator
	if len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s))
}
