// SPDX-License-Identifier: Apache-2.0

package tds

import (
	"encoding/binary"
	"fmt"
)

// TDSPacket represents a TDS protocol packet
type TDSPacket struct {
	Type     uint8
	Status   uint8
	Length   uint16
	SPID     uint16
	PacketID uint8
	Window   uint8
	Data     []byte
}

// Marshal serializes the TDS packet
func (p *TDSPacket) Marshal() []byte {
	p.Length = uint16(8 + len(p.Data))
	buf := make([]byte, p.Length)
	buf[0] = p.Type
	buf[1] = p.Status
	binary.BigEndian.PutUint16(buf[2:4], p.Length)
	binary.BigEndian.PutUint16(buf[4:6], p.SPID)
	buf[6] = p.PacketID
	buf[7] = p.Window
	copy(buf[8:], p.Data)
	return buf
}

// Unmarshal deserializes a TDS packet from bytes
func (p *TDSPacket) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("TDS packet too short: %d bytes", len(data))
	}
	p.Type = data[0]
	p.Status = data[1]
	p.Length = binary.BigEndian.Uint16(data[2:4])
	p.SPID = binary.BigEndian.Uint16(data[4:6])
	p.PacketID = data[6]
	p.Window = data[7]
	if len(data) >= int(p.Length) {
		p.Data = data[8:p.Length]
	} else {
		p.Data = data[8:]
	}
	return nil
}

// PreLoginOption represents a prelogin option
type PreLoginOption struct {
	Token  uint8
	Offset uint16
	Length uint16
}

// PreLoginPacket represents a TDS PRELOGIN packet
type PreLoginPacket struct {
	Version    []byte
	Encryption uint8
	Instance   string
	ThreadID   uint32
}

// Marshal serializes the prelogin packet
func (p *PreLoginPacket) Marshal() []byte {
	// Calculate offsets
	// Header: 5 options * 5 bytes each + 1 terminator = 26 bytes
	headerSize := 21 // 4 options * 5 bytes + terminator
	versionOffset := uint16(headerSize)
	encryptionOffset := versionOffset + uint16(len(p.Version))
	instanceOffset := encryptionOffset + 1
	threadIDOffset := instanceOffset + uint16(len(p.Instance)+1)

	// Build header
	buf := make([]byte, 0, 256)

	// Version option (token 0)
	buf = append(buf, 0x00)                                          // Token
	buf = append(buf, byte(versionOffset>>8), byte(versionOffset))   // Offset (big endian)
	buf = append(buf, byte(len(p.Version)>>8), byte(len(p.Version))) // Length

	// Encryption option (token 1)
	buf = append(buf, 0x01)
	buf = append(buf, byte(encryptionOffset>>8), byte(encryptionOffset))
	buf = append(buf, 0x00, 0x01) // Length = 1

	// Instance option (token 2)
	buf = append(buf, 0x02)
	buf = append(buf, byte(instanceOffset>>8), byte(instanceOffset))
	instLen := uint16(len(p.Instance) + 1)
	buf = append(buf, byte(instLen>>8), byte(instLen))

	// ThreadID option (token 3)
	buf = append(buf, 0x03)
	buf = append(buf, byte(threadIDOffset>>8), byte(threadIDOffset))
	buf = append(buf, 0x00, 0x04) // Length = 4

	// Terminator
	buf = append(buf, 0xFF)

	// Data
	buf = append(buf, p.Version...)
	buf = append(buf, p.Encryption)
	buf = append(buf, []byte(p.Instance)...)
	buf = append(buf, 0x00) // Null terminator for instance
	buf = append(buf, byte(p.ThreadID), byte(p.ThreadID>>8), byte(p.ThreadID>>16), byte(p.ThreadID>>24))

	return buf
}

// ParsePreLoginResponse parses a prelogin response
func ParsePreLoginResponse(data []byte) (*PreLoginPacket, error) {
	p := &PreLoginPacket{}

	// Parse options
	offset := 0
	for offset < len(data) && data[offset] != 0xFF {
		if offset+5 > len(data) {
			break
		}
		token := data[offset]
		optOffset := binary.BigEndian.Uint16(data[offset+1:])
		optLength := binary.BigEndian.Uint16(data[offset+3:])
		offset += 5

		if int(optOffset)+int(optLength) > len(data) {
			continue
		}

		switch token {
		case 0x00: // Version
			p.Version = data[optOffset : optOffset+optLength]
		case 0x01: // Encryption
			if optLength >= 1 {
				p.Encryption = data[optOffset]
			}
		case 0x02: // Instance
			p.Instance = string(data[optOffset : optOffset+optLength-1])
		case 0x03: // ThreadID
			if optLength >= 4 {
				p.ThreadID = binary.LittleEndian.Uint32(data[optOffset:])
			}
		}
	}

	return p, nil
}

// LoginPacket represents a TDS LOGIN7 packet
type LoginPacket struct {
	TDSVersion     uint32
	PacketSize     uint32
	ClientProgVer  uint32
	ClientPID      uint32
	ConnectionID   uint32
	OptionFlags1   uint8
	OptionFlags2   uint8
	TypeFlags      uint8
	OptionFlags3   uint8
	ClientTimeZone int32
	ClientLCID     uint32
	HostName       string
	UserName       string
	Password       string
	AppName        string
	ServerName     string
	CltIntName     string
	Database       string
	SSPI           []byte
	AtchDBFile     string
}

// encryptPassword encrypts password using TDS password encoding
func encryptPassword(password string) []byte {
	data := encodeUTF16LE(password)
	for i := range data {
		data[i] = ((data[i] & 0x0f) << 4) | ((data[i] & 0xf0) >> 4)
		data[i] ^= 0xa5
	}
	return data
}

// encodeUTF16LE encodes a string as UTF-16LE
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	return buf
}

// decodeUTF16LE decodes UTF-16LE bytes to string
func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	runes := make([]rune, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		runes[i/2] = rune(data[i]) | rune(data[i+1])<<8
	}
	return string(runes)
}

// Marshal serializes the login packet
func (p *LoginPacket) Marshal() []byte {
	// Encode strings as UTF-16LE
	hostName := encodeUTF16LE(p.HostName)
	userName := encodeUTF16LE(p.UserName)
	password := encryptPassword(p.Password)
	appName := encodeUTF16LE(p.AppName)
	serverName := encodeUTF16LE(p.ServerName)
	cltIntName := encodeUTF16LE(p.CltIntName)
	database := encodeUTF16LE(p.Database)
	atchDBFile := encodeUTF16LE(p.AtchDBFile)

	// Fixed header size
	headerSize := 94 // Base login header without variable data

	// Calculate offsets
	offset := uint16(headerSize)
	hostNameOffset := offset
	offset += uint16(len(hostName))

	userNameOffset := uint16(0)
	if len(userName) > 0 {
		userNameOffset = offset
	}
	offset += uint16(len(userName))

	passwordOffset := uint16(0)
	if len(password) > 0 {
		passwordOffset = offset
	}
	offset += uint16(len(password))

	appNameOffset := offset
	offset += uint16(len(appName))

	serverNameOffset := offset
	offset += uint16(len(serverName))

	// Unused
	unusedOffset := uint16(0)

	cltIntNameOffset := offset
	offset += uint16(len(cltIntName))

	// Language (not used)
	languageOffset := uint16(0)

	databaseOffset := uint16(0)
	if len(database) > 0 {
		databaseOffset = offset
	}
	offset += uint16(len(database))

	sspiOffset := offset
	offset += uint16(len(p.SSPI))

	atchDBFileOffset := offset
	offset += uint16(len(atchDBFile))

	// Total length
	totalLength := uint32(offset)

	// Build packet
	buf := make([]byte, totalLength)

	// Length
	binary.LittleEndian.PutUint32(buf[0:4], totalLength)
	// TDS Version (LE per MS-TDS spec)
	binary.LittleEndian.PutUint32(buf[4:8], p.TDSVersion)
	// Packet size
	binary.LittleEndian.PutUint32(buf[8:12], p.PacketSize)
	// Client prog version (LE per MS-TDS spec)
	binary.LittleEndian.PutUint32(buf[12:16], p.ClientProgVer)
	// Client PID
	binary.LittleEndian.PutUint32(buf[16:20], p.ClientPID)
	// Connection ID
	binary.LittleEndian.PutUint32(buf[20:24], p.ConnectionID)
	// Option flags
	buf[24] = p.OptionFlags1
	buf[25] = p.OptionFlags2
	buf[26] = p.TypeFlags
	buf[27] = p.OptionFlags3
	// Client timezone
	binary.LittleEndian.PutUint32(buf[28:32], uint32(p.ClientTimeZone))
	// Client LCID
	binary.LittleEndian.PutUint32(buf[32:36], p.ClientLCID)

	// Offsets and lengths
	binary.LittleEndian.PutUint16(buf[36:38], hostNameOffset)
	binary.LittleEndian.PutUint16(buf[38:40], uint16(len(hostName)/2))
	binary.LittleEndian.PutUint16(buf[40:42], userNameOffset)
	binary.LittleEndian.PutUint16(buf[42:44], uint16(len(userName)/2))
	binary.LittleEndian.PutUint16(buf[44:46], passwordOffset)
	binary.LittleEndian.PutUint16(buf[46:48], uint16(len(password)/2))
	binary.LittleEndian.PutUint16(buf[48:50], appNameOffset)
	binary.LittleEndian.PutUint16(buf[50:52], uint16(len(appName)/2))
	binary.LittleEndian.PutUint16(buf[52:54], serverNameOffset)
	binary.LittleEndian.PutUint16(buf[54:56], uint16(len(serverName)/2))
	binary.LittleEndian.PutUint16(buf[56:58], unusedOffset)
	binary.LittleEndian.PutUint16(buf[58:60], 0) // Unused length
	binary.LittleEndian.PutUint16(buf[60:62], cltIntNameOffset)
	binary.LittleEndian.PutUint16(buf[62:64], uint16(len(cltIntName)/2))
	binary.LittleEndian.PutUint16(buf[64:66], languageOffset)
	binary.LittleEndian.PutUint16(buf[66:68], 0) // Language length
	binary.LittleEndian.PutUint16(buf[68:70], databaseOffset)
	binary.LittleEndian.PutUint16(buf[70:72], uint16(len(database)/2))

	// Client ID (6 bytes)
	copy(buf[72:78], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	// SSPI
	binary.LittleEndian.PutUint16(buf[78:80], sspiOffset)
	binary.LittleEndian.PutUint16(buf[80:82], uint16(len(p.SSPI)))

	// AtchDBFile
	binary.LittleEndian.PutUint16(buf[82:84], atchDBFileOffset)
	binary.LittleEndian.PutUint16(buf[84:86], uint16(len(atchDBFile)/2))

	// Change password (not implemented)
	binary.LittleEndian.PutUint16(buf[86:88], 0)
	binary.LittleEndian.PutUint16(buf[88:90], 0)

	// SSPI long
	binary.LittleEndian.PutUint32(buf[90:94], 0)

	// Variable data
	dataOffset := headerSize
	copy(buf[dataOffset:], hostName)
	dataOffset += len(hostName)
	copy(buf[dataOffset:], userName)
	dataOffset += len(userName)
	copy(buf[dataOffset:], password)
	dataOffset += len(password)
	copy(buf[dataOffset:], appName)
	dataOffset += len(appName)
	copy(buf[dataOffset:], serverName)
	dataOffset += len(serverName)
	copy(buf[dataOffset:], cltIntName)
	dataOffset += len(cltIntName)
	copy(buf[dataOffset:], database)
	dataOffset += len(database)
	copy(buf[dataOffset:], p.SSPI)
	dataOffset += len(p.SSPI)
	copy(buf[dataOffset:], atchDBFile)

	return buf
}
