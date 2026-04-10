// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

// Package remcomsvc provides the RemComSvc binary and protocol structures
// for psexec-style remote command execution via named pipes.
//
// RemComSvc is a Windows service that creates named pipes for stdin/stdout/stderr
// communication, enabling true interactive shell functionality.
package remcomsvc

import (
	_ "embed"
	"encoding/binary"
)

//go:embed remcomsvc.exe
var Binary []byte

// Pipe names used by RemComSvc
const (
	CommunicationPipe = `RemCom_communicaton`
	StdoutPipePrefix  = `RemCom_stdout`
	StdinPipePrefix   = `RemCom_stdin`
	StderrPipePrefix  = `RemCom_stderr`
)

// Message represents the command message sent to RemComSvc
// Total size: 4628 bytes
type Message struct {
	Command    [4096]byte // Command to execute
	WorkingDir [260]byte  // Working directory
	Priority   uint32     // Process priority (default 0x20 = NORMAL_PRIORITY_CLASS)
	ProcessID  uint32     // Client process ID for pipe naming
	Machine    [260]byte  // Machine identifier for pipe naming
	NoWait     uint32     // If non-zero, don't wait for process completion
}

// MessageSize is the fixed size of a RemCom message
const MessageSize = 4096 + 260 + 4 + 4 + 260 + 4 // 4628 bytes

// Response represents the response from RemComSvc after command execution
type Response struct {
	ErrorCode  uint32 // Windows error code
	ReturnCode uint32 // Process return code
}

// ResponseSize is the fixed size of a RemCom response
const ResponseSize = 8

// NewMessage creates a new Message with the given command and machine ID
func NewMessage(command, workingDir, machine string, processID uint32) *Message {
	msg := &Message{
		Priority:  0x20, // NORMAL_PRIORITY_CLASS
		ProcessID: processID,
		NoWait:    0,
	}

	// Copy command (null-terminated)
	copy(msg.Command[:], command)

	// Copy working directory (null-terminated)
	copy(msg.WorkingDir[:], workingDir)

	// Copy machine identifier (null-terminated)
	copy(msg.Machine[:], machine)

	return msg
}

// Bytes serializes the message to bytes for transmission
func (m *Message) Bytes() []byte {
	buf := make([]byte, MessageSize)

	// Command (4096 bytes)
	copy(buf[0:4096], m.Command[:])

	// WorkingDir (260 bytes)
	copy(buf[4096:4356], m.WorkingDir[:])

	// Priority (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(buf[4356:4360], m.Priority)

	// ProcessID (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(buf[4360:4364], m.ProcessID)

	// Machine (260 bytes)
	copy(buf[4364:4624], m.Machine[:])

	// NoWait (4 bytes, little-endian)
	binary.LittleEndian.PutUint32(buf[4624:4628], m.NoWait)

	return buf
}

// ParseResponse parses a response from bytes
func ParseResponse(data []byte) *Response {
	if len(data) < ResponseSize {
		return nil
	}
	return &Response{
		ErrorCode:  binary.LittleEndian.Uint32(data[0:4]),
		ReturnCode: binary.LittleEndian.Uint32(data[4:8]),
	}
}

// PipeName returns the full pipe name for a given prefix, machine, and process ID
func PipeName(prefix, machine string, processID uint32) string {
	return prefix + machine + itoa(processID)
}

// itoa converts uint32 to string without importing strconv
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
