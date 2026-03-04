package rpch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// RTSCookie represents an RTS Cookie (2.2.3.1)
type RTSCookie struct {
	Cookie [16]byte
}

// Marshal serializes the cookie
func (c *RTSCookie) Marshal() []byte {
	return c.Cookie[:]
}

// Unmarshal deserializes the cookie
func (c *RTSCookie) Unmarshal(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("data too short for RTSCookie")
	}
	copy(c.Cookie[:], data[:16])
	return nil
}

// EncodedClientAddress represents a client address (2.2.3.2)
type EncodedClientAddress struct {
	AddressType   uint32 // 0 = IPv4, 1 = IPv6
	ClientAddress []byte // 4 bytes for IPv4, 16 bytes for IPv6
	Padding       [12]byte
}

// Marshal serializes the client address
func (a *EncodedClientAddress) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, a.AddressType)
	buf.Write(a.ClientAddress)
	buf.Write(a.Padding[:])
	return buf.Bytes()
}

// FlowControlAck represents a flow control acknowledgment (2.2.3.4)
type FlowControlAck struct {
	BytesReceived   uint32
	AvailableWindow uint32
	ChannelCookie   RTSCookie
}

// Marshal serializes the flow control ack
func (f *FlowControlAck) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, f.BytesReceived)
	binary.Write(buf, binary.LittleEndian, f.AvailableWindow)
	buf.Write(f.ChannelCookie.Marshal())
	return buf.Bytes()
}

// RTSCommand represents a generic RTS command
type RTSCommand interface {
	Marshal() []byte
	Type() uint32
}

// ReceiveWindowSizeCmd (2.2.3.5.1)
type ReceiveWindowSizeCmd struct {
	ReceiveWindowSize uint32
}

func (c *ReceiveWindowSizeCmd) Type() uint32 { return RTS_CMD_RECEIVE_WINDOW_SIZE }
func (c *ReceiveWindowSizeCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_RECEIVE_WINDOW_SIZE))
	binary.Write(buf, binary.LittleEndian, c.ReceiveWindowSize)
	return buf.Bytes()
}

// FlowControlAckCmd (2.2.3.5.2)
type FlowControlAckCmd struct {
	Ack FlowControlAck
}

func (c *FlowControlAckCmd) Type() uint32 { return RTS_CMD_FLOW_CONTROL_ACK }
func (c *FlowControlAckCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_FLOW_CONTROL_ACK))
	buf.Write(c.Ack.Marshal())
	return buf.Bytes()
}

// ConnectionTimeoutCmd (2.2.3.5.3)
type ConnectionTimeoutCmd struct {
	ConnectionTimeout uint32
}

func (c *ConnectionTimeoutCmd) Type() uint32 { return RTS_CMD_CONNECTION_TIMEOUT }
func (c *ConnectionTimeoutCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_CONNECTION_TIMEOUT))
	binary.Write(buf, binary.LittleEndian, c.ConnectionTimeout)
	return buf.Bytes()
}

// CookieCmd (2.2.3.5.4)
type CookieCmd struct {
	Cookie RTSCookie
}

func (c *CookieCmd) Type() uint32 { return RTS_CMD_COOKIE }
func (c *CookieCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_COOKIE))
	buf.Write(c.Cookie.Marshal())
	return buf.Bytes()
}

// ChannelLifetimeCmd (2.2.3.5.5)
type ChannelLifetimeCmd struct {
	ChannelLifetime uint32
}

func (c *ChannelLifetimeCmd) Type() uint32 { return RTS_CMD_CHANNEL_LIFETIME }
func (c *ChannelLifetimeCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_CHANNEL_LIFETIME))
	binary.Write(buf, binary.LittleEndian, c.ChannelLifetime)
	return buf.Bytes()
}

// ClientKeepaliveCmd (2.2.3.5.6)
type ClientKeepaliveCmd struct {
	ClientKeepalive uint32
}

func (c *ClientKeepaliveCmd) Type() uint32 { return RTS_CMD_CLIENT_KEEPALIVE }
func (c *ClientKeepaliveCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_CLIENT_KEEPALIVE))
	binary.Write(buf, binary.LittleEndian, c.ClientKeepalive)
	return buf.Bytes()
}

// VersionCmd (2.2.3.5.7)
type VersionCmd struct {
	Version uint32
}

func (c *VersionCmd) Type() uint32 { return RTS_CMD_VERSION }
func (c *VersionCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_VERSION))
	binary.Write(buf, binary.LittleEndian, c.Version)
	return buf.Bytes()
}

// EmptyCmd (2.2.3.5.8)
type EmptyCmd struct{}

func (c *EmptyCmd) Type() uint32 { return RTS_CMD_EMPTY }
func (c *EmptyCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_EMPTY))
	return buf.Bytes()
}

// AssociationGroupIDCmd (2.2.3.5.12)
type AssociationGroupIDCmd struct {
	AssociationGroupID RTSCookie
}

func (c *AssociationGroupIDCmd) Type() uint32 { return RTS_CMD_ASSOCIATION_GROUP_ID }
func (c *AssociationGroupIDCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_ASSOCIATION_GROUP_ID))
	buf.Write(c.AssociationGroupID.Marshal())
	return buf.Bytes()
}

// DestinationCmd (2.2.3.5.13)
type DestinationCmd struct {
	Destination uint32
}

func (c *DestinationCmd) Type() uint32 { return RTS_CMD_DESTINATION }
func (c *DestinationCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_DESTINATION))
	binary.Write(buf, binary.LittleEndian, c.Destination)
	return buf.Bytes()
}

// ClientAddressCmd (2.2.3.5.11)
type ClientAddressCmd struct {
	ClientAddress EncodedClientAddress
}

func (c *ClientAddressCmd) Type() uint32 { return RTS_CMD_CLIENT_ADDRESS }
func (c *ClientAddressCmd) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(RTS_CMD_CLIENT_ADDRESS))
	buf.Write(c.ClientAddress.Marshal())
	return buf.Bytes()
}

// RTSHeader represents the RTS PDU header
type RTSHeader struct {
	Version       uint8
	VersionMinor  uint8
	PacketType    uint8
	PacketFlags   uint8
	DataRep       [4]byte
	FragLength    uint16
	AuthLength    uint16
	CallID        uint32
	Flags         uint16
	NumberOfCmds  uint16
}

// RTSPacket represents an RTS PDU
type RTSPacket struct {
	Header   RTSHeader
	Commands []RTSCommand
}

// Marshal serializes an RTS packet
func (p *RTSPacket) Marshal() []byte {
	// Marshal commands first to get length
	cmdBuf := new(bytes.Buffer)
	for _, cmd := range p.Commands {
		cmdBuf.Write(cmd.Marshal())
	}
	cmdData := cmdBuf.Bytes()

	// Set header fields
	p.Header.Version = 5
	p.Header.VersionMinor = 0
	p.Header.PacketType = MSRPC_RTS
	p.Header.PacketFlags = PFC_FIRST_FRAG | PFC_LAST_FRAG
	p.Header.DataRep = [4]byte{0x10, 0, 0, 0} // Little endian
	p.Header.AuthLength = 0
	p.Header.NumberOfCmds = uint16(len(p.Commands))
	p.Header.FragLength = uint16(20 + len(cmdData)) // Header(16) + Flags(2) + NumCmds(2) + Commands

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, p.Header.Version)
	binary.Write(buf, binary.LittleEndian, p.Header.VersionMinor)
	binary.Write(buf, binary.LittleEndian, p.Header.PacketType)
	binary.Write(buf, binary.LittleEndian, p.Header.PacketFlags)
	buf.Write(p.Header.DataRep[:])
	binary.Write(buf, binary.LittleEndian, p.Header.FragLength)
	binary.Write(buf, binary.LittleEndian, p.Header.AuthLength)
	binary.Write(buf, binary.LittleEndian, p.Header.CallID)
	binary.Write(buf, binary.LittleEndian, p.Header.Flags)
	binary.Write(buf, binary.LittleEndian, p.Header.NumberOfCmds)
	buf.Write(cmdData)

	return buf.Bytes()
}

// NewCONNA1Packet creates the CONN/A1 RTS packet (sent on OUT channel).
// Structure: Version, VirtualConnectionCookie, OutChannelCookie, ReceiveWindowSize
// Total size: 76 bytes (matches OUT channel Content-Length)
func NewCONNA1Packet(virtualConnCookie, outChannelCookie RTSCookie) *RTSPacket {
	return &RTSPacket{
		Header: RTSHeader{
			Flags: RTS_FLAG_NONE,
		},
		Commands: []RTSCommand{
			&VersionCmd{Version: DEFAULT_RTS_VERSION},
			&CookieCmd{Cookie: virtualConnCookie},
			&CookieCmd{Cookie: outChannelCookie},
			&ReceiveWindowSizeCmd{ReceiveWindowSize: DEFAULT_RECEIVE_WINDOW_SIZE},
		},
	}
}

// NewCONNB1Packet creates the CONN/B1 RTS packet (sent on IN channel).
// Structure: Version, VirtualConnectionCookie, InChannelCookie, ChannelLifetime,
//
//	ClientKeepalive, AssociationGroupId
func NewCONNB1Packet(virtualConnCookie, inChannelCookie RTSCookie, assocGroupID RTSCookie) *RTSPacket {
	return &RTSPacket{
		Header: RTSHeader{
			Flags: RTS_FLAG_NONE,
		},
		Commands: []RTSCommand{
			&VersionCmd{Version: DEFAULT_RTS_VERSION},
			&CookieCmd{Cookie: virtualConnCookie},
			&CookieCmd{Cookie: inChannelCookie},
			&ChannelLifetimeCmd{ChannelLifetime: DEFAULT_CHANNEL_LIFETIME},
			&ClientKeepaliveCmd{ClientKeepalive: DEFAULT_CLIENT_KEEPALIVE},
			&AssociationGroupIDCmd{AssociationGroupID: assocGroupID},
		},
	}
}

// ParseRTSHeader parses an RTS header from data
func ParseRTSHeader(data []byte) (*RTSHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for RTS header")
	}

	h := &RTSHeader{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &h.Version)
	binary.Read(r, binary.LittleEndian, &h.VersionMinor)
	binary.Read(r, binary.LittleEndian, &h.PacketType)
	binary.Read(r, binary.LittleEndian, &h.PacketFlags)
	r.Read(h.DataRep[:])
	binary.Read(r, binary.LittleEndian, &h.FragLength)
	binary.Read(r, binary.LittleEndian, &h.AuthLength)
	binary.Read(r, binary.LittleEndian, &h.CallID)
	binary.Read(r, binary.LittleEndian, &h.Flags)
	binary.Read(r, binary.LittleEndian, &h.NumberOfCmds)

	return h, nil
}
