// SPDX-License-Identifier: Apache-2.0

package kerberos

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"gopacket/internal/build"
	"gopacket/pkg/session"
)

// OID for Kerberos V5 (GSSAPI)
var oidKerberos = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// OID for MS KRB5 (Microsoft Kerberos 5) - used in SPNEGO
var oidMSKRB5 = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}

// OID for SPNEGO
var oidSPNEGO = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

type Client struct {
	KrbClient *client.Client
	ccache    *credentials.CCache // Store ccache for service ticket lookup
	cfg       *config.Config
	realm     string
	username  string
}

func NewClientFromSession(creds *session.Credentials, target session.Target, dcIP string) (*Client, error) {
	realm := strings.ToUpper(creds.Domain)
	if realm == "" {
		return nil, fmt.Errorf("domain/realm is required for Kerberos")
	}

	kdc := dcIP
	if kdc == "" {
		kdc = target.Host
	}

	// 1. CCACHE - check environment variable first
	ccachePath := os.Getenv("KRB5CCNAME")
	if ccachePath != "" {
		// Handle FILE: prefix (standard ccache path format)
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
	} else {
		// Look for <username>.ccache in current directory
		localCCache := creds.Username + ".ccache"
		if _, err := os.Stat(localCCache); err == nil {
			// Found local ccache - ask user before using
			fmt.Printf("[*] Found ccache file: %s\n", localCCache)
			fmt.Print("[?] Use this for Kerberos authentication? [Y/n]: ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			if response == "" || response == "y" || response == "yes" {
				ccachePath = localCCache
			}
		}
	}

	// If using ccache, try to load it; on failure fall through to password/keytab
	if ccachePath != "" {
		ccache, err := loadCCacheSafe(ccachePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] CCache file is not found. Skipping...\n")
			ccachePath = ""
		} else {
			// Get the actual realm from the ccache's default principal
			// This handles cases where the domain in the target string differs
			// from the full Kerberos realm (e.g., "corp" vs "CORP.LOCAL")
			if ccache.DefaultPrincipal.Realm != "" {
				ccacheRealm := strings.ToUpper(ccache.DefaultPrincipal.Realm)
				if build.Debug {
					fmt.Printf("[D] Kerberos: Using realm from ccache: %s\n", ccacheRealm)
				}
				realm = ccacheRealm
			}

			// Create config with the correct realm from ccache
			cfgStr := fmt.Sprintf(`
[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
[realms]
  %s = {
    kdc = %s:88
  }
`, realm, realm, kdc)
			cfg, err := config.NewFromString(cfgStr)
			if err != nil {
				return nil, fmt.Errorf("failed to create krb5 config: %v", err)
			}

			krbClient := &Client{
				cfg:      cfg,
				realm:    realm,
				username: creds.Username,
				ccache:   ccache,
			}

			// Try to create client from ccache (requires TGT)
			cl, err := client.NewFromCCache(ccache, cfg)
			if err == nil {
				krbClient.KrbClient = cl
			}
			// If no TGT, we'll use service tickets from ccache directly in GenerateAPReq

			return krbClient, nil
		}
	}

	// Create config for non-ccache cases
	cfgStr := fmt.Sprintf(`
[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
[realms]
  %s = {
    kdc = %s:88
  }
`, realm, realm, kdc)
	cfg, err := config.NewFromString(cfgStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create krb5 config: %v", err)
	}

	krbClient := &Client{
		cfg:      cfg,
		realm:    realm,
		username: creds.Username,
	}

	// 2. Keytab file
	if creds.Keytab != "" {
		kt, err := keytab.Load(creds.Keytab)
		if err != nil {
			return nil, fmt.Errorf("failed to load keytab %s: %v", creds.Keytab, err)
		}
		krbClient.KrbClient = client.NewWithKeytab(creds.Username, realm, kt, cfg, client.DisablePAFXFAST(true))
		return krbClient, nil
	}

	// 3. Key (AES/RC4) or Password
	if creds.Password != "" {
		// Check if it's an AES key (64 hex chars)?
		// Note: Manual Keytab construction is blocked by unexported keytab.entry in gokrb5 v8.
		// For now, treat everything as a password.
		krbClient.KrbClient = client.NewWithPassword(creds.Username, realm, creds.Password, cfg, client.DisablePAFXFAST(true))
		return krbClient, nil
	}
	return nil, fmt.Errorf("no valid kerberos credentials found (set KRB5CCNAME, provide password, or use -keytab)")
}

// loadCCacheSafe loads a ccache file, recovering from panics caused by
// malformed or empty files (gokrb5's Unmarshal can panic on invalid data).
func loadCCacheSafe(path string) (ccache *credentials.CCache, err error) {
	defer func() {
		if r := recover(); r != nil {
			ccache = nil
			err = fmt.Errorf("invalid ccache file: %v", r)
		}
	}()
	ccache, err = credentials.LoadCCache(path)
	return
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// getServiceTicketFromCCache looks for an existing service ticket in the ccache (like impacket)
func (c *Client) getServiceTicketFromCCache(spn string) (*messages.Ticket, types.EncryptionKey, bool) {
	if c.ccache == nil {
		return nil, types.EncryptionKey{}, false
	}

	// Parse SPN into PrincipalName
	sname, _ := types.ParseSPNString(spn)

	// Try to get entry from ccache
	cred, found := c.ccache.GetEntry(sname)
	if !found {
		return nil, types.EncryptionKey{}, false
	}

	// Unmarshal ticket bytes into Ticket structure
	var ticket messages.Ticket
	if err := ticket.Unmarshal(cred.Ticket); err != nil {
		return nil, types.EncryptionKey{}, false
	}

	return &ticket, cred.Key, true
}

// GenerateAPReq returns the raw bytes of an AP-REQ for the given SPN.
// Returns: (apReqBytes, sessionKeyBytes, encryptionType, error)
func (c *Client) GenerateAPReq(spn string) ([]byte, []byte, error) {
	apReq, key, err := c.GenerateAPReqFull(spn)
	if err != nil {
		return nil, nil, err
	}
	return apReq, key.KeyValue, nil
}

// GenerateAPReqFull returns the raw bytes of an AP-REQ and the full encryption key.
// This creates a simple AP-REQ that will be wrapped in SPNEGO by the SMB2 library.
func (c *Client) GenerateAPReqFull(spn string) ([]byte, types.EncryptionKey, error) {
	var tkt *messages.Ticket
	var key types.EncryptionKey

	// First, try to get service ticket from ccache (like impacket)
	if cachedTkt, cachedKey, found := c.getServiceTicketFromCCache(spn); found {
		if build.Debug {
			fmt.Printf("[D] Kerberos: Using cached service ticket for %s\n", spn)
		}
		tkt = cachedTkt
		key = cachedKey
	} else if c.KrbClient != nil {
		// Fall back to TGT-based flow
		if build.Debug {
			fmt.Printf("[D] Kerberos: No cached ticket for %s, requesting from KDC\n", spn)
		}
		if err := c.KrbClient.Login(); err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("login failed: %v", err)
		}
		ticket, sessionKey, err := c.KrbClient.GetServiceTicket(spn)
		if err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("failed to get service ticket: %v", err)
		}
		if build.Debug {
			fmt.Printf("[D] Kerberos: Got TGS from KDC, etype=%d\n", sessionKey.KeyType)
		}
		tkt = &ticket
		key = sessionKey
	} else {
		return nil, types.EncryptionKey{}, fmt.Errorf("no TGT available and no cached service ticket for %s", spn)
	}

	// Create AP_REQ (simple approach that worked before)
	cname := types.PrincipalName{
		NameType:   1, // KRB_NT_PRINCIPAL
		NameString: []string{c.username},
	}
	auth, err := types.NewAuthenticator(c.realm, cname)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to create authenticator: %v", err)
	}

	// GSSAPI checksum flags
	auth.Cksum = types.Checksum{
		CksumType: 0x8003, // GSSAPI
		Checksum:  make([]byte, 24),
	}

	apReq, err := messages.NewAPReq(*tkt, key, auth)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to create AP-REQ: %v", err)
	}

	b, err := apReq.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}

	if build.Debug {
		fmt.Printf("[D] Kerberos: AP-REQ created (%d bytes)\n", len(b))
	}

	return b, key, nil
}

// WrapInSPNEGO wraps a raw GSSAPI KRB5 token in SPNEGO NegTokenInit format.
// This is required for DCE/RPC auth type 9 (GSS_NEGOTIATE) and HTTP Negotiate auth.
func WrapInSPNEGO(krb5Token []byte) ([]byte, error) {
	// Build NegTokenInit structure manually to match Impacket's format
	// MechTypes: [MS KRB5 OID only] (like Impacket)
	msKrb5OID, _ := asn1.Marshal(oidMSKRB5)
	mechTypesSeq := wrapASN1Sequence(msKrb5OID)
	mechTypesCtx := wrapASN1Context(0, mechTypesSeq)

	// MechToken: the raw KRB5 GSSAPI token (context tag [2] + OCTET STRING)
	mechTokenOctet := wrapASN1OctetString(krb5Token)
	mechTokenCtx := wrapASN1Context(2, mechTokenOctet)

	// NegTokenInit SEQUENCE
	negTokenInit := bytes.NewBuffer(nil)
	negTokenInit.Write(mechTypesCtx)
	negTokenInit.Write(mechTokenCtx)
	negTokenInitSeq := wrapASN1Sequence(negTokenInit.Bytes())

	// Wrap in context [0] for NegotiationToken choice (NegTokenInit)
	negToken := wrapASN1Context(0, negTokenInitSeq)

	// Wrap everything in APPLICATION 0x60 with SPNEGO OID
	spnegoOID, _ := asn1.Marshal(oidSPNEGO)
	spnegoContent := bytes.NewBuffer(nil)
	spnegoContent.Write(spnegoOID)
	spnegoContent.Write(negToken)

	return wrapASN1Application(spnegoContent.Bytes()), nil
}

// GenerateDCERPCToken returns a manually constructed AP-REQ wrapped in SPNEGO for DCE/RPC binding.
// Crucially, this sets the Sequence Number to 0 as required by DCE/RPC.
func (c *Client) GenerateDCERPCToken(spn string) ([]byte, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var key types.EncryptionKey

	// Get ticket (cached or fresh)
	if cachedTkt, cachedKey, found := c.getServiceTicketFromCCache(spn); found {
		tkt = *cachedTkt
		key = cachedKey
	} else if c.KrbClient != nil {
		if err := c.KrbClient.Login(); err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("login failed: %v", err)
		}
		ticket, sessionKey, err := c.KrbClient.GetServiceTicket(spn)
		if err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("failed to get service ticket: %v", err)
		}
		tkt = ticket
		key = sessionKey
	} else {
		return nil, types.EncryptionKey{}, fmt.Errorf("no ticket available")
	}

	// Manual AP-REQ construction to control Sequence Number
	cname := types.NewPrincipalName(1, c.username)
	auth, err := types.NewAuthenticator(c.realm, cname)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to create authenticator: %v", err)
	}

	// Force Sequence Number to 0 (Crucial for DCE/RPC binding)
	auth.SeqNumber = 0

	// Create GSSAPI Checksum (0x8003)
	// Flags must include GSS_C_DCE_STYLE (0x1000) for DCE/RPC!
	// This is a Microsoft extension that tells the server we're doing DCE/RPC style authentication
	const GSS_C_DCE_STYLE = 0x1000
	flags := gssapi.ContextFlagMutual | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence |
		gssapi.ContextFlagConf | gssapi.ContextFlagInteg | GSS_C_DCE_STYLE

	checksumBytes := buildGSSAPIChecksum(16, nil, flags)

	auth.Cksum = types.Checksum{
		CksumType: 0x8003, // GSSAPI
		Checksum:  checksumBytes,
	}

	// Create AP_REQ
	apReq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to create AP_REQ: %v", err)
	}

	// Set mutual-required flag (bit 2) like Impacket does
	types.SetFlag(&apReq.APOptions, 2)

	// Marshal AP_REQ
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to marshal AP_REQ: %v", err)
	}

	// Wrap in SPNEGO
	spnegoToken, err := wrapSPNEGOToken(apReqBytes)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to wrap in SPNEGO: %v", err)
	}

	if build.Debug {
		fmt.Printf("[D] Kerberos: Manual DCERPC Token created (SeqNum=0), size=%d\n", len(spnegoToken))
	}

	return spnegoToken, key, nil
}

// wrapSPNEGOToken wraps an AP-REQ in SPNEGO NegTokenInit format.
// This is required for Windows DCE/RPC Kerberos authentication.
func wrapSPNEGOToken(apReq []byte) ([]byte, error) {
	// First wrap the AP-REQ in GSSAPI format (OID + token-id + AP-REQ)
	oidBytes, err := asn1.Marshal(oidKerberos)
	if err != nil {
		return nil, err
	}

	// mechToken: OID + token-id(0x01 0x00) + AP-REQ
	mechToken := make([]byte, 0, len(oidBytes)+2+len(apReq))
	mechToken = append(mechToken, oidBytes...)
	mechToken = append(mechToken, 0x01, 0x00) // AP-REQ token ID
	mechToken = append(mechToken, apReq...)

	// Wrap in APPLICATION 0x60 tag for the mechToken
	gssToken := wrapASN1Application(mechToken)

	// Build SPNEGO NegTokenInit
	// Structure:
	// APPLICATION [0] (0xa0) {
	//   SEQUENCE {
	//     [0] mechTypes: SEQUENCE { OID, OID, ... }
	//     [2] mechToken: OCTET STRING
	//   }
	// }

	// Encode mechTypes - ONLY MS KRB5 OID (what Windows expects)
	// Impacket only uses MS KRB5, not both OIDs
	msKrb5OID, _ := asn1.Marshal(oidMSKRB5)

	// MechTypeList: SEQUENCE of OIDs (only MS KRB5)
	mechTypes := wrapASN1Sequence(msKrb5OID)

	// Wrap mechTypes in context [0]
	mechTypesCtx := wrapASN1Context(0, mechTypes)

	// Wrap gssToken (mechToken) in OCTET STRING then context [2]
	mechTokenOctet := wrapASN1OctetString(gssToken)
	mechTokenCtx := wrapASN1Context(2, mechTokenOctet)

	// Build NegTokenInit SEQUENCE
	negTokenInit := bytes.NewBuffer(nil)
	negTokenInit.Write(mechTypesCtx)
	negTokenInit.Write(mechTokenCtx)
	negTokenInitSeq := wrapASN1Sequence(negTokenInit.Bytes())

	// Wrap in context [0] for NegotiationToken choice
	negToken := wrapASN1Context(0, negTokenInitSeq)

	// Finally wrap everything in APPLICATION 0x60 with SPNEGO OID
	spnegoOID, _ := asn1.Marshal(oidSPNEGO)
	spnegoToken := bytes.NewBuffer(nil)
	spnegoToken.Write(spnegoOID)
	spnegoToken.Write(negToken)

	return wrapASN1Application(spnegoToken.Bytes()), nil
}

// ASN.1 Helpers

// wrapASN1Application wraps data in ASN.1 APPLICATION tag (0x60)
func wrapASN1Application(data []byte) []byte {
	return wrapASN1Tag(0x60, data)
}

// wrapASN1Sequence wraps data in ASN.1 SEQUENCE tag (0x30)
func wrapASN1Sequence(data []byte) []byte {
	return wrapASN1Tag(0x30, data)
}

// wrapASN1Context wraps data in ASN.1 context-specific tag
func wrapASN1Context(tag int, data []byte) []byte {
	return wrapASN1Tag(byte(0xa0+tag), data)
}

// wrapASN1OctetString wraps data in ASN.1 OCTET STRING tag (0x04)
func wrapASN1OctetString(data []byte) []byte {
	return wrapASN1Tag(0x04, data)
}

// wrapASN1Tag wraps data with the given ASN.1 tag
func wrapASN1Tag(tag byte, data []byte) []byte {
	length := len(data)
	var result []byte

	if length < 128 {
		result = make([]byte, 2+length)
		result[0] = tag
		result[1] = byte(length)
		copy(result[2:], data)
	} else if length < 256 {
		result = make([]byte, 3+length)
		result[0] = tag
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
	} else {
		result = make([]byte, 4+length)
		result[0] = tag
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], data)
	}
	return result
}

// buildGSSAPIChecksum creates a GSSAPI checksum for Kerberos auth.
// This matches impacket's CheckSumField binary format (NOT ASN.1!):
//
//	Lgth:  4 bytes little-endian uint32 (value = 16)
//	Bnd:   16 bytes channel bindings (usually zeros)
//	Flags: 4 bytes little-endian uint32
//
// Total: 24 bytes
func buildGSSAPIChecksum(lgth int, bnd []byte, flags int) []byte {
	buf := make([]byte, 24)

	// Lgth: 4 bytes little-endian
	binary.LittleEndian.PutUint32(buf[0:4], uint32(lgth))

	// Bnd: 16 bytes channel bindings (copy if provided, otherwise zeros)
	if len(bnd) > 0 {
		copy(buf[4:20], bnd)
	}
	// else already zero-filled

	// Flags: 4 bytes little-endian
	binary.LittleEndian.PutUint32(buf[20:24], uint32(flags))

	return buf
}

// encodeASN1Integer encodes an integer as ASN.1 DER
func encodeASN1Integer(val int) []byte {
	if val == 0 {
		return []byte{0x02, 0x01, 0x00}
	}

	// Determine bytes needed
	var bytes []byte
	v := val
	for v > 0 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
		v >>= 8
	}

	// Add leading zero if high bit is set (to ensure positive)
	if bytes[0]&0x80 != 0 {
		bytes = append([]byte{0x00}, bytes...)
	}

	result := make([]byte, 2+len(bytes))
	result[0] = 0x02 // INTEGER tag
	result[1] = byte(len(bytes))
	copy(result[2:], bytes)
	return result
}

// encodeASN1OctetString encodes data as ASN.1 OCTET STRING
func encodeASN1OctetString(data []byte) []byte {
	result := make([]byte, 2+len(data))
	result[0] = 0x04 // OCTET STRING tag
	result[1] = byte(len(data))
	copy(result[2:], data)
	return result
}

// encodeASN1Sequence wraps data in ASN.1 SEQUENCE
func encodeASN1Sequence(data []byte) []byte {
	result := make([]byte, 2+len(data))
	result[0] = 0x30 // SEQUENCE tag
	result[1] = byte(len(data))
	copy(result[2:], data)
	return result
}

// GetAPReq is a helper function to get a Kerberos AP-REQ token for a given SPN.
// This is used by services like MSSQL that need Kerberos authentication.
// Parameters:
//   - spn: Service Principal Name (e.g., "MSSQLSvc/server.domain.local:1433")
//   - username: Kerberos principal name
//   - password: User password (can be empty if using hashes/aesKey/ccache)
//   - domain: Kerberos realm
//   - hashes: NTLM hashes in format "LMHASH:NTHASH" (optional)
//   - aesKey: AES key for Kerberos (optional)
//   - kdcHost: KDC hostname/IP (optional, uses domain if empty)
//   - channelBinding: Channel binding token (optional, for TLS channel binding)
//
// Returns the SPNEGO-wrapped AP-REQ token suitable for use in authentication.
func GetAPReq(spn, username, password, domain, hashes, aesKey, kdcHost string, channelBinding []byte) ([]byte, error) {
	// Create credentials
	creds := &session.Credentials{
		Username: username,
		Password: password,
		Domain:   domain,
		AESKey:   aesKey,
	}

	if hashes != "" {
		parts := strings.SplitN(hashes, ":", 2)
		if len(parts) == 2 {
			creds.Hash = parts[1]
		}
	}

	// Create target for KDC
	target := session.Target{
		Host: kdcHost,
	}
	if kdcHost == "" {
		target.Host = domain
	}

	// Create Kerberos client
	krbClient, err := NewClientFromSession(creds, target, kdcHost)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kerberos client: %v", err)
	}

	// Generate AP-REQ with optional channel binding
	apReq, key, err := krbClient.GenerateAPReqWithBinding(spn, channelBinding)
	if err != nil {
		return nil, err
	}
	_ = key // Session key not needed for MSSQL

	// Wrap in SPNEGO
	spnegoToken, err := wrapSPNEGOToken(apReq)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap in SPNEGO: %v", err)
	}

	return spnegoToken, nil
}

// GenerateAPReqWithBinding creates an AP-REQ with optional channel binding.
func (c *Client) GenerateAPReqWithBinding(spn string, channelBinding []byte) ([]byte, types.EncryptionKey, error) {
	var tkt *messages.Ticket
	var key types.EncryptionKey

	// First, try to get service ticket from ccache
	if cachedTkt, cachedKey, found := c.getServiceTicketFromCCache(spn); found {
		if build.Debug {
			fmt.Printf("[D] Kerberos: Using cached service ticket for %s\n", spn)
		}
		tkt = cachedTkt
		key = cachedKey
	} else if c.KrbClient != nil {
		// Fall back to TGT-based flow
		if build.Debug {
			fmt.Printf("[D] Kerberos: No cached ticket for %s, requesting from KDC\n", spn)
		}
		if err := c.KrbClient.Login(); err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("login failed: %v", err)
		}
		ticket, sessionKey, err := c.KrbClient.GetServiceTicket(spn)
		if err != nil {
			return nil, types.EncryptionKey{}, fmt.Errorf("failed to get service ticket: %v", err)
		}
		tkt = &ticket
		key = sessionKey
	} else {
		return nil, types.EncryptionKey{}, fmt.Errorf("no TGT available and no cached service ticket for %s", spn)
	}

	// Create AP_REQ
	cname := types.PrincipalName{
		NameType:   1, // KRB_NT_PRINCIPAL
		NameString: []string{c.username},
	}
	auth, err := types.NewAuthenticator(c.realm, cname)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to create authenticator: %v", err)
	}

	// GSSAPI checksum flags with optional channel binding
	// GSS_C_REPLAY_FLAG = 4, GSS_C_SEQUENCE_FLAG = 8
	flags := 4 | 8
	var bnd []byte
	if len(channelBinding) > 0 {
		bnd = channelBinding
	}
	auth.Cksum = types.Checksum{
		CksumType: 0x8003, // GSSAPI
		Checksum:  buildGSSAPIChecksum(16, bnd, flags),
	}

	apReq, err := messages.NewAPReq(*tkt, key, auth)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("failed to create AP-REQ: %v", err)
	}

	b, err := apReq.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, err
	}

	return b, key, nil
}
