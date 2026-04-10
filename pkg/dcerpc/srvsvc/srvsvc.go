// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package srvsvc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

var UUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

const MajorVersion = 3
const MinorVersion = 0

// NetrSessionEnum OpNum 12
const OpNetrSessionEnum = 12

// NetrServerGetInfo OpNum 21
const OpNetrServerGetInfo = 21

// GetInfoLevel101 retrieves and parses basic server info.
func GetInfoLevel101(client *dcerpc.Client, serverName string) (string, error) {
	buf := new(bytes.Buffer)

	// Request Marshaling
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // ServerName Ptr
	utf16Name := utf16.Encode([]rune(serverName))
	utf16Name = append(utf16Name, 0)
	count := uint32(len(utf16Name))
	binary.Write(buf, binary.LittleEndian, count)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, count)
	for _, r := range utf16Name {
		binary.Write(buf, binary.LittleEndian, r)
	}
	if (len(utf16Name)*2)%4 != 0 {
		buf.Write([]byte{0, 0})
	}
	binary.Write(buf, binary.LittleEndian, uint32(101)) // Level

	resp, err := client.Call(OpNetrServerGetInfo, buf.Bytes())
	if err != nil {
		return "", err
	}

	// Response Unmarshaling (SERVER_INFO_101)
	// Structure:
	//   PTR to Info Struct
	//   Level (101)
	//   SERVER_INFO_101 struct {
	//     DWORD PlatformID
	//     PTR Name
	//     DWORD VerMajor
	//     DWORD VerMinor
	//     DWORD Type
	//     PTR Comment
	//   }
	//   Name Data (NDR String)
	//   Comment Data (NDR String)

	r := bytes.NewReader(resp)
	var ptrInfo, level, platformID, ptrName, verMaj, verMin, sType, ptrComment uint32

	binary.Read(r, binary.LittleEndian, &ptrInfo)
	binary.Read(r, binary.LittleEndian, &level)
	binary.Read(r, binary.LittleEndian, &platformID)
	binary.Read(r, binary.LittleEndian, &ptrName)
	binary.Read(r, binary.LittleEndian, &verMaj)
	binary.Read(r, binary.LittleEndian, &verMin)
	binary.Read(r, binary.LittleEndian, &sType)
	binary.Read(r, binary.LittleEndian, &ptrComment)

	// Decode Name String
	name, _ := decodeNDRString(r)

	return fmt.Sprintf("OS: Windows %d.%d (Platform: %d, Type: 0x%x) Name: %s", verMaj, verMin, platformID, sType, name), nil
}

// SessionInfo10 represents a SESSION_INFO_10 entry.
type SessionInfo10 struct {
	Cname      string // Client name (source host)
	Username   string
	ActiveTime uint32
	IdleTime   uint32
}

// NetrSessionEnum retrieves sessions from the target via SRVSVC (level 10).
func NetrSessionEnum(client *dcerpc.Client) ([]SessionInfo10, error) {
	buf := new(bytes.Buffer)

	// ServerName: NULL pointer (local server)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ClientName: NULL pointer (all clients)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// UserName: NULL pointer (all users)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// InfoStruct: SESSION_ENUM_STRUCT
	// Level = 10
	binary.Write(buf, binary.LittleEndian, uint32(10))
	// Switch value = 10
	binary.Write(buf, binary.LittleEndian, uint32(10))
	// Level10 container pointer (referent ID, non-NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
	// SESSION_INFO_10_CONTAINER (deferred): EntriesRead = 0, Buffer = NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// PreferedMaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF))

	// ResumeHandle: pointer + value
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // pointer referent
	binary.Write(buf, binary.LittleEndian, uint32(0))          // value

	resp, err := client.Call(OpNetrSessionEnum, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return parseSessionEnumResponse(resp)
}

func parseSessionEnumResponse(resp []byte) ([]SessionInfo10, error) {
	if len(resp) < 20 {
		return nil, fmt.Errorf("session enum response too short: %d bytes", len(resp))
	}

	// Check return value (last 4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("NetrSessionEnum failed: NTSTATUS 0x%08x", retVal)
	}

	r := bytes.NewReader(resp)

	// Level
	var level uint32
	binary.Read(r, binary.LittleEndian, &level)

	// Switch value
	var switchVal uint32
	binary.Read(r, binary.LittleEndian, &switchVal)

	// Level10 container pointer (referent)
	var containerPtr uint32
	binary.Read(r, binary.LittleEndian, &containerPtr)

	if containerPtr == 0 {
		return nil, nil
	}

	// SESSION_INFO_10_CONTAINER (deferred): EntriesRead + Buffer pointer
	var entriesRead uint32
	binary.Read(r, binary.LittleEndian, &entriesRead)

	var bufPtr uint32
	binary.Read(r, binary.LittleEndian, &bufPtr)

	if bufPtr == 0 || entriesRead == 0 {
		return nil, nil
	}

	// Array MaxCount
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	_ = maxCount

	// Read SESSION_INFO_10 entries: cname_ptr(4) + username_ptr(4) + active_time(4) + idle_time(4)
	type sessionEntry struct {
		CnamePtr    uint32
		UsernamePtr uint32
		ActiveTime  uint32
		IdleTime    uint32
	}

	entries := make([]sessionEntry, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		binary.Read(r, binary.LittleEndian, &entries[i].CnamePtr)
		binary.Read(r, binary.LittleEndian, &entries[i].UsernamePtr)
		binary.Read(r, binary.LittleEndian, &entries[i].ActiveTime)
		binary.Read(r, binary.LittleEndian, &entries[i].IdleTime)
	}

	// Read deferred strings (cname then username for each entry)
	sessions := make([]SessionInfo10, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		cname := ""
		username := ""

		if entries[i].CnamePtr != 0 {
			s, err := decodeNDRString(r)
			if err == nil {
				cname = s
			}
		}
		if entries[i].UsernamePtr != 0 {
			s, err := decodeNDRString(r)
			if err == nil {
				username = s
			}
		}

		sessions = append(sessions, SessionInfo10{
			Cname:      cname,
			Username:   username,
			ActiveTime: entries[i].ActiveTime,
			IdleTime:   entries[i].IdleTime,
		})
	}

	return sessions, nil
}

func decodeNDRString(r *bytes.Reader) (string, error) {
	var max, offset, actual uint32
	if err := binary.Read(r, binary.LittleEndian, &max); err != nil {
		return "", err
	}
	binary.Read(r, binary.LittleEndian, &offset)
	binary.Read(r, binary.LittleEndian, &actual)

	data := make([]uint16, actual)
	binary.Read(r, binary.LittleEndian, &data)

	// Pad to 4-byte boundary
	bytesRead := actual * 2
	if bytesRead%4 != 0 {
		pad := 4 - (bytesRead % 4)
		r.Seek(int64(pad), 1)
	}

	// Trim null terminator
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}

	return string(utf16.Decode(data)), nil
}
