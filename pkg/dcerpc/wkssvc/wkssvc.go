package wkssvc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

// WKSSVC UUID: 6BFFD098-A112-3610-9833-46C3F87E345A v1.0
var UUID = [16]byte{
	0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36,
	0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a,
}

const MajorVersion = 1
const MinorVersion = 0

// NetrWkstaUserEnum OpNum 2
const OpNetrWkstaUserEnum = 2

// WkstaUserInfo1 represents a WKSTA_USER_INFO_1 entry.
type WkstaUserInfo1 struct {
	Username    string
	LogonDomain string
	OthDomains  string
	LogonServer string
}

// NetrWkstaUserEnum retrieves logged-on users from the target via WKSSVC (level 1).
func NetrWkstaUserEnum(client *dcerpc.Client) ([]WkstaUserInfo1, error) {
	buf := new(bytes.Buffer)

	// ServerName: NULL pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// InfoStruct: WKSTA_USER_ENUM_STRUCT
	// Level = 1
	binary.Write(buf, binary.LittleEndian, uint32(1))
	// Switch value = 1
	binary.Write(buf, binary.LittleEndian, uint32(1))
	// Level1 container pointer (referent ID, non-NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
	// WKSTA_USER_INFO_1_CONTAINER (deferred): EntriesRead = 0, Buffer = NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// PreferedMaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF))

	// ResumeHandle: pointer + value
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // pointer referent
	binary.Write(buf, binary.LittleEndian, uint32(0))          // value

	resp, err := client.Call(OpNetrWkstaUserEnum, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return parseWkstaUserEnumResponse(resp)
}

func parseWkstaUserEnumResponse(resp []byte) ([]WkstaUserInfo1, error) {
	if len(resp) < 20 {
		return nil, fmt.Errorf("wksta user enum response too short: %d bytes", len(resp))
	}

	// Check return value (last 4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("NetrWkstaUserEnum failed: NTSTATUS 0x%08x", retVal)
	}

	r := bytes.NewReader(resp)

	// Level
	var level uint32
	binary.Read(r, binary.LittleEndian, &level)

	// Switch value
	var switchVal uint32
	binary.Read(r, binary.LittleEndian, &switchVal)

	// Level1 container pointer (referent)
	var containerPtr uint32
	binary.Read(r, binary.LittleEndian, &containerPtr)

	if containerPtr == 0 {
		return nil, nil
	}

	// WKSTA_USER_INFO_1_CONTAINER (deferred): EntriesRead + Buffer pointer
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

	// Read WKSTA_USER_INFO_1 entries:
	// username_ptr(4) + logon_domain_ptr(4) + oth_domains_ptr(4) + logon_server_ptr(4)
	type userEntry struct {
		UsernamePtr    uint32
		LogonDomainPtr uint32
		OthDomainsPtr  uint32
		LogonServerPtr uint32
	}

	entries := make([]userEntry, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		binary.Read(r, binary.LittleEndian, &entries[i].UsernamePtr)
		binary.Read(r, binary.LittleEndian, &entries[i].LogonDomainPtr)
		binary.Read(r, binary.LittleEndian, &entries[i].OthDomainsPtr)
		binary.Read(r, binary.LittleEndian, &entries[i].LogonServerPtr)
	}

	// Read deferred strings in order
	users := make([]WkstaUserInfo1, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		var username, logonDomain, othDomains, logonServer string

		if entries[i].UsernamePtr != 0 {
			username = decodeNDRString(r)
		}
		if entries[i].LogonDomainPtr != 0 {
			logonDomain = decodeNDRString(r)
		}
		if entries[i].OthDomainsPtr != 0 {
			othDomains = decodeNDRString(r)
		}
		if entries[i].LogonServerPtr != 0 {
			logonServer = decodeNDRString(r)
		}

		users = append(users, WkstaUserInfo1{
			Username:    username,
			LogonDomain: logonDomain,
			OthDomains:  othDomains,
			LogonServer: logonServer,
		})
	}

	return users, nil
}

func decodeNDRString(r *bytes.Reader) string {
	var max, offset, actual uint32
	if err := binary.Read(r, binary.LittleEndian, &max); err != nil {
		return ""
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

	return string(utf16.Decode(data))
}
