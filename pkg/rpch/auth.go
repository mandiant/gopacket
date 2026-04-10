// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package rpch

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/ntlm"
	"gopacket/pkg/session"
	"gopacket/pkg/transport"
)

// AUTH types
const (
	AUTH_NONE  = 0
	AUTH_NTLM  = 1
	AUTH_BASIC = 2
)

// AuthTransport extends Transport with NTLM authentication support
type AuthTransport struct {
	*Transport
	ntlmClient *ntlm.Client
	ntHash     []byte
}

// NewAuthTransport creates a new authenticated RPC over HTTP v2 transport
func NewAuthTransport(remoteName string) *AuthTransport {
	return &AuthTransport{
		Transport: NewTransport(remoteName),
	}
}

// ConnectWithNTLM establishes connection using NTLM authentication.
// The flow follows the MS-RPCH spec (matching Impacket):
//  1. Establish IN channel (HTTP + NTLM auth)
//  2. Establish OUT channel (HTTP + NTLM auth)
//  3. Send CONN/A1 on OUT channel
//  4. Send CONN/B1 on IN channel
//  5. Read HTTP 200 + RTS response from OUT channel
func (t *AuthTransport) ConnectWithNTLM() error {
	// Generate cookies
	t.virtualConnCookie = generateCookie()
	t.inChannelCookie = generateCookie()
	t.outChannelCookie = generateCookie()
	t.assocGroupID = generateCookie()

	if build.Debug {
		log.Printf("[D] RPCH: Connecting with NTLM to %s:%d", t.RemoteName, t.Port)
	}

	// Parse NT hash if provided
	if t.NTHash != "" {
		t.ntHash, _ = hex.DecodeString(t.NTHash)
	}

	// Create NTLM client
	t.ntlmClient = &ntlm.Client{
		User:     t.Username,
		Password: t.Password,
		Hash:     t.ntHash,
		Domain:   t.Domain,
	}

	// Step 1: Establish OUT channel with NTLM (just HTTP + auth, no RTS yet)
	if err := t.establishOutChannelNTLM(); err != nil {
		return fmt.Errorf("failed to establish OUT channel: %v", err)
	}

	// Step 2: Establish IN channel with NTLM (just HTTP + auth, no RTS yet)
	if err := t.establishInChannelNTLM(); err != nil {
		if t.outConn != nil {
			t.outConn.Close()
		}
		return fmt.Errorf("failed to establish IN channel: %v", err)
	}

	// Step 3: Create the RPC tunnel (send RTS packets, read responses)
	if err := t.createTunnel(); err != nil {
		t.Close()
		return fmt.Errorf("failed to create tunnel: %v", err)
	}

	t.connected = true
	return nil
}

// ConnectWithKerberos establishes connection using Kerberos (HTTP Negotiate) authentication.
// The flow is simpler than NTLM since Kerberos only needs a single request per channel:
//  1. Generate AP-REQ for SPN HTTP/<RemoteName>
//  2. Wrap in SPNEGO and send as "Authorization: Negotiate <token>"
//  3. Server responds with 200 if auth succeeds
//  4. Create RPC tunnel (same as NTLM path)
func (t *AuthTransport) ConnectWithKerberos(creds *session.Credentials) error {
	// Generate cookies
	t.virtualConnCookie = generateCookie()
	t.inChannelCookie = generateCookie()
	t.outChannelCookie = generateCookie()
	t.assocGroupID = generateCookie()

	if build.Debug {
		log.Printf("[D] RPCH: Connecting with Kerberos to %s:%d", t.RemoteName, t.Port)
	}

	// Build session target for KDC lookup
	target := session.Target{
		Host: t.RemoteName,
	}
	dcIP := t.DCIP
	if dcIP == "" {
		dcIP = creds.DCIP
	}

	// Create Kerberos client
	krbClient, err := kerberos.NewClientFromSession(creds, target, dcIP)
	if err != nil {
		return fmt.Errorf("failed to create Kerberos client: %v", err)
	}

	// Derive RPC hostname from NTLM-less approach: use the first component of the FQDN uppercase
	if t.RPCHostname == "" {
		parts := strings.Split(t.RemoteName, ".")
		if len(parts) > 0 {
			t.RPCHostname = strings.ToUpper(parts[0])
			if build.Debug {
				log.Printf("[D] RPCH: Derived RPC hostname: %s", t.RPCHostname)
			}
		}
	}

	// Step 1: Establish OUT channel with Kerberos
	outConn, outReader, err := t.kerberosAuthOnConn(krbClient, HTTP_METHOD_RPC_OUT_DATA, "76")
	if err != nil {
		return fmt.Errorf("failed to establish OUT channel: %v", err)
	}
	t.outConn = outConn
	t.outReader = outReader

	// Step 2: Establish IN channel with Kerberos
	inConn, inReader, err := t.kerberosAuthOnConn(krbClient, HTTP_METHOD_RPC_IN_DATA, "1073741824")
	if err != nil {
		if t.outConn != nil {
			t.outConn.Close()
		}
		return fmt.Errorf("failed to establish IN channel: %v", err)
	}
	t.inConn = inConn
	t.inReader = inReader

	// Step 3: Create the RPC tunnel (send RTS packets, read responses)
	if err := t.createTunnel(); err != nil {
		t.Close()
		return fmt.Errorf("failed to create tunnel: %v", err)
	}

	t.connected = true
	return nil
}

// kerberosAuthOnConn performs Kerberos (HTTP Negotiate) authentication on a single
// TLS connection. Unlike NTLM, this is a single request — no challenge/response.
func (t *AuthTransport) kerberosAuthOnConn(krbClient *kerberos.Client, method string, contentLength string) (*tls.Conn, *bufio.Reader, error) {
	conn, err := transport.DialTLS("tcp", t.connectAddr(), t.tlsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS dial failed: %v", err)
	}

	rpcPath := "/rpc/rpcproxy.dll"
	if t.RPCHostname != "" {
		rpcPath = fmt.Sprintf("/rpc/rpcproxy.dll?%s:6004", t.RPCHostname)
	}

	// Generate AP-REQ for HTTP SPN
	spn := fmt.Sprintf("HTTP/%s", t.RemoteName)
	if build.Debug {
		log.Printf("[D] RPCH: Generating Kerberos AP-REQ for SPN: %s", spn)
	}

	apReqBytes, _, err := krbClient.GenerateAPReqFull(spn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to generate AP-REQ: %v", err)
	}

	// Wrap in SPNEGO
	spnegoToken, err := kerberos.WrapInSPNEGO(apReqBytes)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to wrap in SPNEGO: %v", err)
	}

	// Build HTTP request with Negotiate auth
	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, rpcPath)
	req += fmt.Sprintf("Host: %s\r\n", t.RemoteName)
	req += "Accept: application/rpc\r\n"
	req += "User-Agent: MSRPC\r\n"
	req += fmt.Sprintf("Content-Length: %s\r\n", contentLength)
	req += "Connection: Keep-Alive\r\n"
	req += "Cache-Control: no-cache\r\n"
	req += "Pragma: no-cache\r\n"
	req += fmt.Sprintf("Authorization: Negotiate %s\r\n", base64.StdEncoding.EncodeToString(spnegoToken))
	req += "\r\n"

	if build.Debug {
		log.Printf("[D] RPCH: %s Kerberos Negotiate", method)
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to send Negotiate request: %v", err)
	}

	reader := bufio.NewReader(conn)
	return conn, reader, nil
}

// ntlmAuthOnConn performs the full NTLM 3-way handshake on a single TLS
// connection, returning the authenticated connection and its buffered reader.
// The HTTP method (RPC_IN_DATA or RPC_OUT_DATA) and Content-Length are specified.
func (t *AuthTransport) ntlmAuthOnConn(method string, contentLength string) (*tls.Conn, *bufio.Reader, error) {
	conn, err := transport.DialTLS("tcp", t.connectAddr(), t.tlsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS dial failed: %v", err)
	}

	rpcPath := "/rpc/rpcproxy.dll"
	if t.RPCHostname != "" {
		rpcPath = fmt.Sprintf("/rpc/rpcproxy.dll?%s:6004", t.RPCHostname)
	}

	// --- NTLM Type 1 (Negotiate) ---
	negotiateMsg, err := t.ntlmClient.Negotiate()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("NTLM negotiate failed: %v", err)
	}

	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, rpcPath)
	req += fmt.Sprintf("Host: %s\r\n", t.RemoteName)
	req += "Accept: application/rpc\r\n"
	req += "User-Agent: MSRPC\r\n"
	req += "Content-Length: 0\r\n"
	req += "Connection: Keep-Alive\r\n"
	req += fmt.Sprintf("Authorization: NTLM %s\r\n", base64.StdEncoding.EncodeToString(negotiateMsg))
	req += "\r\n"

	if build.Debug {
		log.Printf("[D] RPCH: %s NTLM Negotiate", method)
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to send negotiate: %v", err)
	}

	// --- Read Type 2 (Challenge) on SAME connection ---
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to read challenge: %v", err)
	}
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if resp.StatusCode != 401 {
		conn.Close()
		return nil, nil, fmt.Errorf("expected 401, got %d", resp.StatusCode)
	}

	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(authHeader, "NTLM ") {
		conn.Close()
		return nil, nil, fmt.Errorf("no NTLM challenge in response")
	}

	challengeB64 := strings.TrimPrefix(authHeader, "NTLM ")
	challengeMsg, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to decode challenge: %v", err)
	}

	// Extract RPC hostname from challenge if we don't have one
	if t.RPCHostname == "" {
		targetName := extractTargetNameFromChallenge(challengeMsg)
		if targetName != "" {
			t.RPCHostname = targetName
			rpcPath = fmt.Sprintf("/rpc/rpcproxy.dll?%s:6004", t.RPCHostname)
			if build.Debug {
				log.Printf("[D] RPCH: Extracted RPC hostname from NTLM: %s", t.RPCHostname)
			}
		}
	}

	// --- NTLM Type 3 (Authenticate) on SAME connection ---
	authMsg, err := t.ntlmClient.Authenticate(challengeMsg)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("NTLM authenticate failed: %v", err)
	}

	req = fmt.Sprintf("%s %s HTTP/1.1\r\n", method, rpcPath)
	req += fmt.Sprintf("Host: %s\r\n", t.RemoteName)
	req += "Accept: application/rpc\r\n"
	req += "User-Agent: MSRPC\r\n"
	req += fmt.Sprintf("Content-Length: %s\r\n", contentLength)
	req += "Connection: Keep-Alive\r\n"
	req += fmt.Sprintf("Authorization: NTLM %s\r\n", base64.StdEncoding.EncodeToString(authMsg))
	req += "\r\n"

	if build.Debug {
		log.Printf("[D] RPCH: %s NTLM Authenticate", method)
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to send auth: %v", err)
	}

	return conn, reader, nil
}

// establishOutChannelNTLM sets up the OUT channel HTTP+NTLM connection
func (t *AuthTransport) establishOutChannelNTLM() error {
	conn, reader, err := t.ntlmAuthOnConn(HTTP_METHOD_RPC_OUT_DATA, "76")
	if err != nil {
		return err
	}
	t.outConn = conn
	t.outReader = reader
	return nil
}

// establishInChannelNTLM sets up the IN channel HTTP+NTLM connection
func (t *AuthTransport) establishInChannelNTLM() error {
	conn, reader, err := t.ntlmAuthOnConn(HTTP_METHOD_RPC_IN_DATA, "1073741824")
	if err != nil {
		return err
	}
	t.inConn = conn
	t.inReader = reader
	return nil
}

// createTunnel sends the CONN/A1 and CONN/B1 RTS packets and waits for the
// server's response to establish the virtual connection.
func (t *AuthTransport) createTunnel() error {
	// Send CONN/A1 on OUT channel
	connA1 := NewCONNA1Packet(t.virtualConnCookie, t.outChannelCookie)
	if build.Debug {
		data := connA1.Marshal()
		log.Printf("[D] RPCH: Sending CONN/A1 on OUT channel (%d bytes)", len(data))
	}
	if _, err := t.outConn.Write(connA1.Marshal()); err != nil {
		return fmt.Errorf("failed to send CONN/A1: %v", err)
	}

	// Send CONN/B1 on IN channel
	connB1 := NewCONNB1Packet(t.virtualConnCookie, t.inChannelCookie, t.assocGroupID)
	if build.Debug {
		data := connB1.Marshal()
		log.Printf("[D] RPCH: Sending CONN/B1 on IN channel (%d bytes)", len(data))
	}
	if _, err := t.inConn.Write(connB1.Marshal()); err != nil {
		return fmt.Errorf("failed to send CONN/B1: %v", err)
	}

	// Read HTTP 200 response from OUT channel
	t.outConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(t.outReader, nil)
	t.outConn.SetReadDeadline(time.Time{})
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
		return fmt.Errorf("unexpected response: %s", resp.Status)
	}

	// Save the response body reader — Go's http package handles chunked
	// decoding automatically, so reading from resp.Body gives us decoded data.
	t.outBodyReader = resp.Body

	if build.Debug {
		te := resp.Header.Get("Transfer-Encoding")
		if te != "" {
			log.Printf("[D] RPCH: Transfer-Encoding: %s", te)
		}
	}

	// Read RTS response packets (CONN/A3 and CONN/C2).
	// We need to consume both before proceeding to the RPC Bind.
	// Temporarily set connected so Read() works.
	wasConnected := t.connected
	t.connected = true

	for i := 0; i < 2; i++ {
		rtsBuf := make([]byte, 1024)
		t.outConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := t.Read(rtsBuf)
		t.outConn.SetReadDeadline(time.Time{})
		if err != nil {
			if build.Debug {
				log.Printf("[D] RPCH: Warning reading RTS packet %d: %v", i, err)
			}
			break
		}
		if n > 0 && build.Debug {
			if n >= 20 {
				header, _ := ParseRTSHeader(rtsBuf[:n])
				if header != nil {
					log.Printf("[D] RPCH: RTS packet %d (%d bytes): type=%d flags=0x%04x cmds=%d",
						i, n, header.PacketType, header.Flags, header.NumberOfCmds)
				} else {
					log.Printf("[D] RPCH: RTS packet %d (%d bytes): %x", i, n, rtsBuf[:n])
				}
			}
		}
	}

	t.connected = wasConnected

	// Also consume any response on the IN channel (some servers send 100 Continue)
	t.inConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	inData := make([]byte, 1024)
	inN, _ := t.inReader.Read(inData)
	t.inConn.SetReadDeadline(time.Time{})
	if inN > 0 && build.Debug {
		log.Printf("[D] RPCH: IN channel response (%d bytes): %s", inN, string(inData[:inN]))
	}

	return nil
}

// extractTargetNameFromChallenge tries to extract the computer name from
// the NTLM challenge's Target Info AV_PAIR list (MsvAvNbComputerName).
// This is the server's own NetBIOS name, which is what the RPC proxy needs.
func extractTargetNameFromChallenge(challenge []byte) string {
	if len(challenge) < 56 {
		return ""
	}

	// Check signature and type
	if !bytes.Equal(challenge[:8], []byte("NTLMSSP\x00")) {
		return ""
	}
	if challenge[8] != 2 {
		return ""
	}

	// Target Info fields (offset 40-47)
	tiLen := int(challenge[40]) | int(challenge[41])<<8
	tiOffset := int(challenge[44]) | int(challenge[45])<<8 | int(challenge[46])<<16 | int(challenge[47])<<24

	if tiOffset+tiLen > len(challenge) || tiLen < 4 {
		return extractTargetNameField(challenge)
	}

	// Parse AV_PAIRs looking for MsvAvNbComputerName (AvId=1)
	pos := tiOffset
	end := tiOffset + tiLen
	for pos+4 <= end {
		avID := int(challenge[pos]) | int(challenge[pos+1])<<8
		avLen := int(challenge[pos+2]) | int(challenge[pos+3])<<8
		pos += 4
		if avID == 0 { // MsvAvEOL
			break
		}
		if pos+avLen > end {
			break
		}
		if avID == 1 { // MsvAvNbComputerName
			data := challenge[pos : pos+avLen]
			var name []byte
			for i := 0; i+1 < len(data); i += 2 {
				if data[i+1] == 0 {
					name = append(name, data[i])
				}
			}
			return string(name)
		}
		pos += avLen
	}

	return extractTargetNameField(challenge)
}

// extractTargetNameField extracts the target name field from NTLM Type 2
func extractTargetNameField(challenge []byte) string {
	if len(challenge) < 20 {
		return ""
	}
	targetLen := int(challenge[12]) | int(challenge[13])<<8
	targetOffset := int(challenge[16]) | int(challenge[17])<<8 | int(challenge[18])<<16 | int(challenge[19])<<24
	if targetOffset+targetLen > len(challenge) {
		return ""
	}
	targetData := challenge[targetOffset : targetOffset+targetLen]
	var name []byte
	for i := 0; i+1 < len(targetData); i += 2 {
		if targetData[i+1] == 0 {
			name = append(name, targetData[i])
		}
	}
	return string(name)
}
