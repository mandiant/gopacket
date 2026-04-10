// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package rpch

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/transport"
)

// Transport implements RPC over HTTP v2 transport
type Transport struct {
	// Connection settings
	RemoteName  string // Target hostname for HTTP Host header/SPN (e.g., exchange.domain.com)
	ConnectHost string // IP or hostname to actually connect to (if different from RemoteName)
	RPCHostname string // RPC server name (NetBIOS or GUID)
	Port        int    // Usually 443 for HTTPS

	// Credentials
	Username string
	Password string
	Domain   string
	LMHash   string
	NTHash   string

	// Authentication
	AuthType     int  // AUTH_NTLM or AUTH_BASIC
	UseBasicAuth bool // Force basic auth
	UseKerberos  bool // Use Kerberos authentication
	AESKey       string
	DCIP         string
	Realm        string

	// Internal state
	inConn            net.Conn // IN channel connection
	outConn           net.Conn // OUT channel connection
	inReader          *bufio.Reader
	outReader         *bufio.Reader
	outBodyReader     io.Reader // HTTP response body reader (handles chunked decoding)
	virtualConnCookie RTSCookie
	inChannelCookie   RTSCookie
	outChannelCookie  RTSCookie
	assocGroupID      RTSCookie
	connected         bool
	rtsPingReceived   bool

	// TLS config
	tlsConfig *tls.Config
}

// NewTransport creates a new RPC over HTTP v2 transport
func NewTransport(remoteName string) *Transport {
	return &Transport{
		RemoteName: remoteName,
		Port:       443,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certs
		},
	}
}

// connectAddr returns the host:port to dial. Uses ConnectHost if set, otherwise RemoteName.
func (t *Transport) connectAddr() string {
	host := t.RemoteName
	if t.ConnectHost != "" {
		host = t.ConnectHost
	}
	return fmt.Sprintf("%s:%d", host, t.Port)
}

// SetCredentials sets the authentication credentials
func (t *Transport) SetCredentials(username, password, domain, lmhash, nthash string) {
	t.Username = username
	t.Password = password
	t.Domain = domain
	t.LMHash = lmhash
	t.NTHash = nthash
}

// generateCookie generates a random 16-byte cookie
func generateCookie() RTSCookie {
	var cookie RTSCookie
	rand.Read(cookie.Cookie[:])
	return cookie
}

// Connect establishes the RPC over HTTP v2 connection
func (t *Transport) Connect() error {
	// Generate cookies
	t.virtualConnCookie = generateCookie()
	t.inChannelCookie = generateCookie()
	t.outChannelCookie = generateCookie()
	t.assocGroupID = generateCookie()

	if build.Debug {
		log.Printf("[D] RPCH: Connecting to %s:%d", t.RemoteName, t.Port)
		log.Printf("[D] RPCH: VirtualConnCookie: %x", t.virtualConnCookie.Cookie)
		log.Printf("[D] RPCH: InChannelCookie: %x", t.inChannelCookie.Cookie)
		log.Printf("[D] RPCH: OutChannelCookie: %x", t.outChannelCookie.Cookie)
	}

	// Establish OUT channel first
	if err := t.establishOutChannel(); err != nil {
		return fmt.Errorf("failed to establish OUT channel: %v", err)
	}

	// Establish IN channel
	if err := t.establishInChannel(); err != nil {
		t.outConn.Close()
		return fmt.Errorf("failed to establish IN channel: %v", err)
	}

	t.connected = true
	return nil
}

// establishOutChannel establishes the OUT data channel
func (t *Transport) establishOutChannel() error {
	// Connect to server
	conn, err := transport.DialTLS("tcp", t.connectAddr(), t.tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %v", err)
	}
	t.outConn = conn
	t.outReader = bufio.NewReader(conn)

	// Build RPC_OUT_DATA request
	rpcPath := "/rpc/rpcproxy.dll"
	if t.RPCHostname != "" {
		rpcPath = fmt.Sprintf("/rpc/rpcproxy.dll?%s:6004", t.RPCHostname)
	}

	// Build HTTP request
	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", HTTP_METHOD_RPC_OUT_DATA, rpcPath)
	req += fmt.Sprintf("Host: %s\r\n", t.RemoteName)
	req += "Accept: application/rpc\r\n"
	req += "User-Agent: MSRPC\r\n"
	req += "Content-Length: 76\r\n"
	req += "Connection: Keep-Alive\r\n"
	req += "Cache-Control: no-cache\r\n"
	req += "Pragma: no-cache\r\n"

	// Add authentication
	if t.UseBasicAuth {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s\\%s:%s", t.Domain, t.Username, t.Password)))
		req += fmt.Sprintf("Authorization: Basic %s\r\n", auth)
	}

	req += "\r\n"

	if build.Debug {
		log.Printf("[D] RPCH: OUT channel request:\n%s", req)
	}

	// Send request
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("failed to send OUT request: %v", err)
	}

	// Send CONN/A1 RTS packet on OUT channel
	connA1 := NewCONNA1Packet(t.virtualConnCookie, t.outChannelCookie)
	if _, err := conn.Write(connA1.Marshal()); err != nil {
		return fmt.Errorf("failed to send CONN/A1: %v", err)
	}

	// Read response
	resp, err := http.ReadResponse(t.outReader, nil)
	if err != nil {
		return fmt.Errorf("failed to read OUT response: %v", err)
	}

	if build.Debug {
		log.Printf("[D] RPCH: OUT channel response: %s", resp.Status)
	}

	if resp.StatusCode == 401 {
		return fmt.Errorf("%s", RPC_PROXY_HTTP_IN_DATA_401_ERR)
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("%s", RPC_PROXY_RPC_OUT_DATA_404_ERR)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected OUT response: %s", resp.Status)
	}

	// Read CONN/A3 or similar response
	rtsData := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := t.outReader.Read(rtsData)
	conn.SetReadDeadline(time.Time{})
	if err != nil && err != io.EOF {
		if build.Debug {
			log.Printf("[D] RPCH: Warning reading OUT RTS response: %v", err)
		}
	}

	if n > 0 {
		if build.Debug {
			log.Printf("[D] RPCH: OUT channel RTS response (%d bytes): %x", n, rtsData[:n])
		}
		// Parse RTS response if needed
		if n >= 20 {
			header, _ := ParseRTSHeader(rtsData[:n])
			if header != nil && header.PacketType == MSRPC_RTS {
				if build.Debug {
					log.Printf("[D] RPCH: Received RTS packet, flags: 0x%04x, cmds: %d", header.Flags, header.NumberOfCmds)
				}
			}
		}
	}

	return nil
}

// establishInChannel establishes the IN data channel
func (t *Transport) establishInChannel() error {
	// Connect to server
	conn, err := transport.DialTLS("tcp", t.connectAddr(), t.tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %v", err)
	}
	t.inConn = conn
	t.inReader = bufio.NewReader(conn)

	// Build RPC_IN_DATA request
	rpcPath := "/rpc/rpcproxy.dll"
	if t.RPCHostname != "" {
		rpcPath = fmt.Sprintf("/rpc/rpcproxy.dll?%s:6004", t.RPCHostname)
	}

	// Build HTTP request with chunked transfer encoding
	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", HTTP_METHOD_RPC_IN_DATA, rpcPath)
	req += fmt.Sprintf("Host: %s\r\n", t.RemoteName)
	req += "Accept: application/rpc\r\n"
	req += "User-Agent: MSRPC\r\n"
	req += "Content-Length: 1073741824\r\n" // Large content length for streaming
	req += "Connection: Keep-Alive\r\n"
	req += "Cache-Control: no-cache\r\n"
	req += "Pragma: no-cache\r\n"

	// Add authentication
	if t.UseBasicAuth {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s\\%s:%s", t.Domain, t.Username, t.Password)))
		req += fmt.Sprintf("Authorization: Basic %s\r\n", auth)
	}

	req += "\r\n"

	if build.Debug {
		log.Printf("[D] RPCH: IN channel request:\n%s", req)
	}

	// Send request
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("failed to send IN request: %v", err)
	}

	// Send CONN/B1 RTS packet on IN channel
	connB1 := NewCONNB1Packet(t.virtualConnCookie, t.inChannelCookie, t.assocGroupID)
	if _, err := conn.Write(connB1.Marshal()); err != nil {
		return fmt.Errorf("failed to send CONN/B1: %v", err)
	}

	// For IN channel, we might get a response or it might just be accepted
	// Read with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respLine := make([]byte, 1024)
	n, err := t.inReader.Read(respLine)
	conn.SetReadDeadline(time.Time{})

	if n > 0 {
		respStr := string(respLine[:n])
		if build.Debug {
			log.Printf("[D] RPCH: IN channel response: %s", respStr)
		}

		if strings.Contains(respStr, "401") {
			return fmt.Errorf("%s", RPC_PROXY_HTTP_IN_DATA_401_ERR)
		}
		if strings.Contains(respStr, "404") {
			return fmt.Errorf("%s", RPC_PROXY_CONN_A1_404_ERR)
		}
	}

	return nil
}

// Write sends data over the IN channel
func (t *Transport) Write(data []byte) (int, error) {
	if !t.connected || t.inConn == nil {
		return 0, fmt.Errorf("not connected")
	}
	return t.inConn.Write(data)
}

// Read receives data from the OUT channel, handling chunked encoding and RTS PINGs.
// Uses outBodyReader (which is resp.Body from the HTTP 200 response) when available.
// Go's http.ReadResponse automatically handles chunked transfer encoding.
func (t *Transport) Read(buf []byte) (int, error) {
	if !t.connected || t.outConn == nil {
		return 0, fmt.Errorf("not connected")
	}

	reader := t.outBodyReader
	if reader == nil {
		reader = t.outReader
	}

	for {
		n, err := reader.Read(buf)
		if err != nil {
			return n, err
		}

		// Check if this is an RTS PING packet
		if n >= 20 {
			header, _ := ParseRTSHeader(buf[:n])
			if header != nil && header.PacketType == MSRPC_RTS {
				if header.Flags&RTS_FLAG_PING != 0 {
					t.rtsPingReceived = true
					if build.Debug {
						log.Printf("[D] RPCH: Received RTS PING")
					}
					continue
				}
			}
		}

		return n, nil
	}
}

// readFull reads exactly n bytes from the OUT channel reader, handling
// short reads from the HTTP chunked transfer stream.
func (t *Transport) readFull(buf []byte) error {
	reader := t.outBodyReader
	if reader == nil {
		reader = t.outReader
	}
	_, err := io.ReadFull(reader, buf)
	return err
}

// readPDU reads a complete DCE/RPC PDU from the OUT channel.
// It first reads the 16-byte common header to get frag_length,
// then reads the remaining bytes. Returns the full PDU.
func (t *Transport) readPDU() ([]byte, error) {
	// Read common header (16 bytes) to get frag_length
	header := make([]byte, 16)
	if err := t.readFull(header); err != nil {
		return nil, fmt.Errorf("failed to read PDU header: %v", err)
	}

	fragLen := binary.LittleEndian.Uint16(header[8:10])
	if fragLen < 16 {
		return nil, fmt.Errorf("invalid frag_length: %d", fragLen)
	}

	// Read the rest of the PDU
	pdu := make([]byte, fragLen)
	copy(pdu, header)
	if fragLen > 16 {
		if err := t.readFull(pdu[16:]); err != nil {
			return nil, fmt.Errorf("failed to read PDU body: %v", err)
		}
	}

	// Check for RTS PING and skip if needed
	if pdu[2] == MSRPC_RTS && fragLen >= 20 {
		h, _ := ParseRTSHeader(pdu)
		if h != nil && h.Flags&RTS_FLAG_PING != 0 {
			t.rtsPingReceived = true
			if build.Debug {
				log.Printf("[D] RPCH: Received RTS PING, reading next PDU")
			}
			return t.readPDU() // recursively read next PDU
		}
	}

	return pdu, nil
}

// Close closes both channels
func (t *Transport) Close() error {
	t.connected = false
	var errs []error

	if t.inConn != nil {
		if err := t.inConn.Close(); err != nil {
			errs = append(errs, err)
		}
		t.inConn = nil
	}

	if t.outConn != nil {
		if err := t.outConn.Close(); err != nil {
			errs = append(errs, err)
		}
		t.outConn = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// IsPingReceived returns true if an RTS PING was received
func (t *Transport) IsPingReceived() bool {
	return t.rtsPingReceived
}

// RPCBind performs an RPC bind operation
func (t *Transport) RPCBind(interfaceUUID [16]byte, major, minor uint16) error {
	// Build Bind PDU
	buf := new(bytes.Buffer)

	// Common header
	buf.WriteByte(5)                 // Version
	buf.WriteByte(0)                 // VersionMinor
	buf.WriteByte(11)                // PacketType: Bind
	buf.WriteByte(0x03)              // PacketFlags: FirstFrag | LastFrag
	buf.Write([]byte{0x10, 0, 0, 0}) // DataRep: Little endian

	// Will fill FragLength later
	fragLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(0)) // FragLength placeholder

	binary.Write(buf, binary.LittleEndian, uint16(0)) // AuthLength
	binary.Write(buf, binary.LittleEndian, uint32(1)) // CallID

	// Bind header
	binary.Write(buf, binary.LittleEndian, uint16(5840)) // MaxXmitFrag
	binary.Write(buf, binary.LittleEndian, uint16(5840)) // MaxRecvFrag
	binary.Write(buf, binary.LittleEndian, uint32(0))    // AssocGroup

	// Context list
	buf.WriteByte(1)                                  // NumContexts
	buf.WriteByte(0)                                  // Reserved
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Reserved

	// Context item
	binary.Write(buf, binary.LittleEndian, uint16(0))                                                                 // ContextID
	buf.WriteByte(1)                                                                                                  // NumTransItems
	buf.WriteByte(0)                                                                                                  // Reserved
	buf.Write(interfaceUUID[:])                                                                                       // Interface UUID
	binary.Write(buf, binary.LittleEndian, major)                                                                     // Interface version
	binary.Write(buf, binary.LittleEndian, minor)                                                                     // Interface minor version
	buf.Write([]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}) // NDR transfer syntax
	binary.Write(buf, binary.LittleEndian, uint32(2))                                                                 // Transfer syntax version

	// Update FragLength
	data := buf.Bytes()
	binary.LittleEndian.PutUint16(data[fragLenPos:], uint16(len(data)))

	if build.Debug {
		log.Printf("[D] RPCH: Sending Bind PDU (%d bytes): %x", len(data), data)
	}

	// Send bind
	if _, err := t.Write(data); err != nil {
		return fmt.Errorf("failed to send Bind: %v", err)
	}

	// Read complete response PDU
	respBuf, err := t.readPDU()
	if err != nil {
		return fmt.Errorf("failed to read Bind response: %v", err)
	}

	if build.Debug {
		log.Printf("[D] RPCH: Bind response (%d bytes): %x", len(respBuf), respBuf)
	}

	// Check packet type
	if respBuf[2] != 12 { // BindAck
		if respBuf[2] == 13 { // BindNak
			reason := uint16(0)
			if len(respBuf) >= 22 {
				reason = binary.LittleEndian.Uint16(respBuf[20:22])
			}
			return fmt.Errorf("bind rejected (BindNak, reason=0x%04x)", reason)
		}
		return fmt.Errorf("unexpected response type: %d", respBuf[2])
	}

	if build.Debug {
		log.Printf("[D] RPCH: Bind successful")
	}

	return nil
}

// RPCCall sends an RPC request and returns the response
func (t *Transport) RPCCall(opNum uint16, data []byte, callID uint32) ([]byte, error) {
	// Build Request PDU
	buf := new(bytes.Buffer)

	// Common header
	buf.WriteByte(5)                 // Version
	buf.WriteByte(0)                 // VersionMinor
	buf.WriteByte(0)                 // PacketType: Request
	buf.WriteByte(0x03)              // PacketFlags: FirstFrag | LastFrag
	buf.Write([]byte{0x10, 0, 0, 0}) // DataRep: Little endian

	fragLen := uint16(24 + len(data)) // Header(16) + ReqHeader(8) + Data
	binary.Write(buf, binary.LittleEndian, fragLen)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // AuthLength
	binary.Write(buf, binary.LittleEndian, callID)    // CallID

	// Request header
	binary.Write(buf, binary.LittleEndian, uint32(len(data))) // AllocHint
	binary.Write(buf, binary.LittleEndian, uint16(0))         // ContextID
	binary.Write(buf, binary.LittleEndian, opNum)             // OpNum

	// Data
	buf.Write(data)

	// Send request
	if _, err := t.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send Request: %v", err)
	}

	// Read and reassemble response PDU(s), handling fragmentation.
	// DCE/RPC responses may span multiple fragments.
	var stubData []byte

	for {
		pdu, err := t.readPDU()
		if err != nil {
			return nil, fmt.Errorf("failed to read Response: %v", err)
		}

		if len(pdu) < 24 {
			return nil, fmt.Errorf("response too short: %d bytes", len(pdu))
		}

		pduType := pdu[2]
		pduFlags := pdu[3]

		if build.Debug {
			log.Printf("[D] RPCH: Response PDU (%d bytes, type=%d, flags=0x%02x)", len(pdu), pduType, pduFlags)
		}

		// Check packet type
		if pduType == 3 { // Fault
			status := binary.LittleEndian.Uint32(pdu[24:28])
			return nil, fmt.Errorf("RPC Fault: status=0x%08x", status)
		}

		if pduType != 2 { // Response
			return nil, fmt.Errorf("unexpected response type: %d", pduType)
		}

		// Append stub data from this fragment
		stubData = append(stubData, pdu[24:]...)

		// Check if this is the last fragment (PFC_LAST_FRAG = 0x02)
		if pduFlags&0x02 != 0 {
			break
		}
	}

	return stubData, nil
}
