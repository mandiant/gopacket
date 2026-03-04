package mqtt

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"

	"gopacket/pkg/transport"
)

// Packet types
const (
	PacketConnect     = 1 << 4
	PacketConnAck     = 2 << 4
	PacketPublish     = 3 << 4
	PacketPubAck      = 4 << 4
	PacketSubscribe   = 8 << 4
	PacketSubAck      = 9 << 4
	PacketUnsubscribe = 10 << 4
	PacketUnsubAck    = 11 << 4
	PacketPingReq     = 12 << 4
	PacketPingResp    = 13 << 4
	PacketDisconnect  = 14 << 4
)

// Connect flags
const (
	ConnectCleanSession = 0x02
	ConnectPassword     = 0x40
	ConnectUsername      = 0x80
)

// ConnAckMessages maps return codes to human-readable messages
var ConnAckMessages = map[byte]string{
	0x00: "Connection Accepted",
	0x01: "Connection Refused, unacceptable protocol version",
	0x02: "Connection Refused, identifier rejected",
	0x03: "Connection Refused, Server unavailable",
	0x04: "Connection Refused, bad user name or password",
	0x05: "Connection Refused, not authorized",
}

// Connection represents an MQTT connection to a broker
type Connection struct {
	conn net.Conn
}

// NewConnection establishes a TCP (optionally TLS) connection to an MQTT broker
func NewConnection(host string, port int, useSSL bool) (*Connection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %v", addr, err)
	}

	if useSSL {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake: %v", err)
		}
		return &Connection{conn: tlsConn}, nil
	}

	return &Connection{conn: conn}, nil
}

// Connect sends an MQTT CONNECT packet and reads the CONNACK response
func (c *Connection) Connect(clientID, username, password string) error {
	var payload []byte

	// Protocol name (MQIsdp for v3.1 compat, same as Impacket default)
	payload = append(payload, mqttString("MQIsdp")...)
	// Protocol version
	payload = append(payload, 3)
	// Connect flags
	flags := byte(ConnectCleanSession)
	if username != "" {
		flags |= ConnectUsername | ConnectPassword
	}
	payload = append(payload, flags)
	// Keep alive (60s)
	payload = append(payload, 0, 60)
	// Client ID
	payload = append(payload, mqttString(clientID)...)
	// Username + password
	if username != "" {
		payload = append(payload, mqttString(username)...)
		payload = append(payload, mqttString(password)...)
	}

	// Send CONNECT
	pkt := encodePacket(PacketConnect, payload)
	if _, err := c.conn.Write(pkt); err != nil {
		return fmt.Errorf("send CONNECT: %v", err)
	}

	// Read CONNACK (type 0x20, remaining length 2, session present, return code)
	buf := make([]byte, 256)
	n, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read CONNACK: %v", err)
	}
	if n < 4 {
		return fmt.Errorf("CONNACK too short: %d bytes", n)
	}
	if buf[0] != PacketConnAck {
		return fmt.Errorf("expected CONNACK (0x%02x), got 0x%02x", PacketConnAck, buf[0])
	}

	// Return code is at offset 3 (after type, remaining length=2, session present)
	returnCode := buf[3]
	if returnCode != 0 {
		msg, ok := ConnAckMessages[returnCode]
		if !ok {
			msg = fmt.Sprintf("unknown error code 0x%02x", returnCode)
		}
		return fmt.Errorf("%s", msg)
	}

	return nil
}

// Close sends DISCONNECT and closes the underlying connection
func (c *Connection) Close() error {
	pkt := encodePacket(PacketDisconnect, nil)
	c.conn.Write(pkt)
	return c.conn.Close()
}

// mqttString encodes a string with a 2-byte big-endian length prefix
func mqttString(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b[:2], uint16(len(s)))
	copy(b[2:], s)
	return b
}

// encodePacket builds an MQTT fixed-header packet
func encodePacket(packetType byte, payload []byte) []byte {
	var buf []byte
	buf = append(buf, packetType)
	buf = append(buf, encodeRemainingLength(len(payload))...)
	buf = append(buf, payload...)
	return buf
}

// encodeRemainingLength encodes the variable-length remaining length field
func encodeRemainingLength(length int) []byte {
	if length == 0 {
		return []byte{0}
	}
	var encoded []byte
	for length > 0 {
		b := byte(length % 128)
		length /= 128
		if length > 0 {
			b |= 128
		}
		encoded = append(encoded, b)
	}
	return encoded
}
