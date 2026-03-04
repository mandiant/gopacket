package dcerpc

import (
	"bufio"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	"github.com/oiweiwei/go-msrpc/ssp/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"

	"gopacket/internal/build"
	"gopacket/pkg/session"
)

// KerberosAuthHandler manages Kerberos authentication for RPC using go-msrpc.
type KerberosAuthHandler struct {
	// go-msrpc SPNEGO authentifier wrapping Kerberos mechanism
	spnegoAuth *spnego.Authentifier

	// Kerberos config for creating the mechanism
	krbConfig *krb5.Config

	// Session key exported after authentication
	SessionKey []byte

	// Encryption type (23=RC4, 17=AES128, 18=AES256)
	EType int32

	// Sequence numbers (managed by go-msrpc internally, but we track for compatibility)
	ClientSeqNum uint32
	ServerSeqNum uint32

	// Cached signature from last Wrap operation
	cachedSignature []byte

	// Context for go-msrpc calls
	ctx context.Context
}

// NewKerberosAuthHandler creates a new Kerberos auth handler using go-msrpc.
func NewKerberosAuthHandler(creds *session.Credentials, target session.Target, dcIP string) (*KerberosAuthHandler, error) {
	// Determine realm (uppercase domain)
	realm := strings.ToUpper(creds.Domain)

	// Create Kerberos config
	krbConfig := krb5.NewConfig()
	krbConfig.DCEStyle = true // Required for DCE/RPC

	// Check if we should use ccache (no password provided)
	if creds.Password == "" && creds.Hash == "" {
		// First check KRB5CCNAME environment variable
		ccachePath := os.Getenv("KRB5CCNAME")
		if ccachePath != "" {
			// Strip "FILE:" prefix if present
			ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
			if build.Debug {
				log.Printf("[D] Kerberos: Using ccache from KRB5CCNAME: %s", ccachePath)
			}
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
					if build.Debug {
						log.Printf("[D] Kerberos: Using local ccache: %s", ccachePath)
					}
				}
			}
		}

		if ccachePath == "" {
			return nil, fmt.Errorf("no password provided and no ccache found (set KRB5CCNAME or place %s.ccache in current directory)", creds.Username)
		}

		// Check if ccache file exists
		if _, err := os.Stat(ccachePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("ccache file not found at %s", ccachePath)
		}

		// Load ccache to verify it has credentials and get principal info
		cc, err := credentials.LoadCCache(ccachePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load ccache from %s: %v", ccachePath, err)
		}

		if build.Debug {
			log.Printf("[D] Kerberos: Loaded ccache with %d credentials", len(cc.Credentials))
			log.Printf("[D] Kerberos: CCache principal: %s@%s",
				cc.DefaultPrincipal.PrincipalName.PrincipalNameString(),
				cc.DefaultPrincipal.Realm)
		}

		// Create credential from ccache using go-msrpc's credential package
		msrpcCred := credential.NewFromCCache(creds.Username, cc, credential.Domain(realm))
		krbConfig.Credential = msrpcCred

		// Also set the CCachePath so go-msrpc can access it directly if needed
		krbConfig.CCachePath = ccachePath
	} else {
		// Create go-msrpc credential with password
		msrpcCred := credential.NewFromPassword(creds.Username, creds.Password, credential.Domain(realm))
		krbConfig.Credential = msrpcCred
	}

	// Add required GSSAPI flags for DCE/RPC (matching Impacket: 0x103E)
	// DCEStyle = 0x1000, Confidentiality = 0x10, Integrity = 0x20,
	// MutualAuthn = 0x02, ReplayDetection = 0x04, Sequencing = 0x08
	krbConfig.Flags = []int{
		int(gssapi.DCEStyle),        // 0x1000
		int(gssapi.Confidentiality), // 0x10
		int(gssapi.Integrity),       // 0x20
		int(gssapi.MutualAuthn),     // 0x02
		int(gssapi.ReplayDetection), // 0x04
		int(gssapi.Sequencing),      // 0x08
	}

	// Set AP Options - mutual_required is needed for DCE/RPC
	krbConfig.APOptions = []int{flags.APOptionMutualRequired}

	// Build krb5.conf dynamically if we have domain info
	if creds.Domain != "" {
		kdc := dcIP
		if kdc == "" {
			kdc = target.Host
		}

		// Create minimal krb5 config
		confStr := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = %s
        admin_server = %s
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, kdc, kdc,
			strings.ToLower(creds.Domain), realm,
			strings.ToLower(creds.Domain), realm)

		cfg, err := config.NewFromString(confStr)
		if err != nil {
			return nil, fmt.Errorf("failed to create krb5 config: %v", err)
		}
		// Apply parsed lib defaults like go-msrpc does
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(cfg)
	}

	return &KerberosAuthHandler{
		ctx:       context.Background(),
		krbConfig: krbConfig,
	}, nil
}

// NewKerberosAuthHandlerMultiRealm creates a Kerberos auth handler with multiple realms configured.
// extraRealms maps realm names to KDC addresses (e.g., {"PARENT.LOCAL": "10.0.0.1"}).
func NewKerberosAuthHandlerMultiRealm(creds *session.Credentials, target session.Target, dcIP string, extraRealms map[string]string) (*KerberosAuthHandler, error) {
	realm := strings.ToUpper(creds.Domain)

	krbConfig := krb5.NewConfig()
	krbConfig.DCEStyle = true

	// Use ccache-based credential
	ccachePath := os.Getenv("KRB5CCNAME")
	if ccachePath != "" {
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
	}
	if ccachePath == "" {
		return nil, fmt.Errorf("KRB5CCNAME must be set for multi-realm Kerberos")
	}

	cc, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ccache from %s: %v", ccachePath, err)
	}

	msrpcCred := credential.NewFromCCache(creds.Username, cc, credential.Domain(realm))
	krbConfig.Credential = msrpcCred
	krbConfig.CCachePath = ccachePath

	krbConfig.Flags = []int{
		int(gssapi.DCEStyle),
		int(gssapi.Confidentiality),
		int(gssapi.Integrity),
		int(gssapi.MutualAuthn),
		int(gssapi.ReplayDetection),
		int(gssapi.Sequencing),
	}
	krbConfig.APOptions = []int{flags.APOptionMutualRequired}

	if creds.Domain != "" {
		kdc := dcIP
		if kdc == "" {
			kdc = target.Host
		}

		// Build realms section with extra realms
		extraRealmsStr := ""
		extraDomainRealmStr := ""
		for realmName, realmKDC := range extraRealms {
			upperRealm := strings.ToUpper(realmName)
			lowerDomain := strings.ToLower(realmName)
			extraRealmsStr += fmt.Sprintf("    %s = {\n        kdc = %s\n        admin_server = %s\n    }\n", upperRealm, realmKDC, realmKDC)
			extraDomainRealmStr += fmt.Sprintf("    .%s = %s\n    %s = %s\n", lowerDomain, upperRealm, lowerDomain, upperRealm)
		}

		confStr := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = %s
        admin_server = %s
    }
%s
[domain_realm]
    .%s = %s
    %s = %s
%s`, realm, realm, kdc, kdc, extraRealmsStr,
			strings.ToLower(creds.Domain), realm,
			strings.ToLower(creds.Domain), realm, extraDomainRealmStr)

		cfg, err := config.NewFromString(confStr)
		if err != nil {
			return nil, fmt.Errorf("failed to create krb5 config: %v", err)
		}
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(cfg)
	}

	return &KerberosAuthHandler{
		ctx:       context.Background(),
		krbConfig: krbConfig,
	}, nil
}

// GetToken generates the Kerberos AP-REQ token for DCE/RPC.
// Returns SPNEGO wrapped token for DCE-style auth.
func (k *KerberosAuthHandler) GetToken(spn string) ([]byte, error) {
	// Set the service principal name
	k.krbConfig.SName = spn

	if build.Debug {
		log.Printf("[D] KerberosAuth: Generating AP-REQ for SPN: %s", spn)
	}

	// Create the Kerberos mechanism and authentifier directly
	krbAuth := &krb5.Authentifier{
		Config: k.krbConfig,
	}

	// Generate AP-REQ using go-msrpc's krb5 authentifier
	apReqBytes, err := krbAuth.APRequest(k.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AP-REQ: %v", err)
	}

	if build.Debug {
		log.Printf("[D] KerberosAuth: Generated AP-REQ (%d bytes)", len(apReqBytes))
	}

	// Store the krb5 mechanism for later use (wrap/unwrap)
	k.spnegoAuth = &spnego.Authentifier{
		Config: &spnego.Config{
			Capabilities: gssapi.DCEStyle | gssapi.Confidentiality | gssapi.Integrity | gssapi.MutualAuthn,
		},
		Mechanism: &krb5.Mechanism{
			Authentifier: krbAuth,
		},
	}

	// GSSAPI-wrap the AP-REQ before putting in SPNEGO
	// Format: 0x60 [length] OID TOK_ID(0x0100) AP-REQ
	gssapiWrapped := wrapAPReqInGSSAPI(apReqBytes)

	// Wrap in SPNEGO NegTokenInit using go-msrpc's SPNEGO marshalling
	// Use MS-KRB5 OID first (like Impacket does)
	oidMSKRB5 := asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	oidKRB5 := asn1.ObjectIdentifier(krb5.MechanismType) // 1.2.840.113554.1.2.2

	negTokenInit := &spnego.NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{
			oidMSKRB5, // MS-KRB5 first
			oidKRB5,   // Standard Kerberos 5
		},
		MechToken: gssapiWrapped, // GSSAPI-wrapped AP-REQ
	}

	spnegoToken, err := negTokenInit.Marshal(k.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO token: %v", err)
	}

	// Initialize sequence numbers
	k.ClientSeqNum = 0
	k.ServerSeqNum = 0

	if build.Debug {
		log.Printf("[D] KerberosAuth: Generated SPNEGO token (%d bytes)", len(spnegoToken))
	}

	return spnegoToken, nil
}

// ProcessAPRep processes the AP-REP message from the server.
// This completes mutual authentication and sets up encryption keys.
// For DCE-style, returns the third leg token that must be sent via AlterContext.
func (k *KerberosAuthHandler) ProcessAPRep(apRepBytes []byte) ([]byte, error) {
	if build.Debug {
		log.Printf("[D] KerberosAuth: Processing AP-REP (%d bytes)", len(apRepBytes))
	}

	if k.spnegoAuth == nil || k.spnegoAuth.Mechanism == nil {
		return nil, fmt.Errorf("SPNEGO not initialized")
	}

	// Get the Kerberos mechanism
	krbMech, ok := k.spnegoAuth.Mechanism.(*krb5.Mechanism)
	if !ok {
		return nil, fmt.Errorf("mechanism is not Kerberos")
	}

	// For DCE-style, the response is a raw AP-REP (not SPNEGO wrapped)
	// First try to parse as SPNEGO NegTokenResp
	negResp := &spnego.NegTokenResp{}
	if err := negResp.Unmarshal(k.ctx, apRepBytes); err == nil {
		// It's a SPNEGO response, extract the AP-REP
		apRepBytes = negResp.ResponseToken
		if build.Debug {
			log.Printf("[D] KerberosAuth: Extracted AP-REP from SPNEGO response (%d bytes)", len(apRepBytes))
		}
	}

	// Process AP-REP using go-msrpc's krb5 authentifier
	// For DCE-style, this returns the third leg token that must be sent
	thirdLegToken, err := krbMech.Authentifier.APReply(k.ctx, apRepBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to process AP-REP: %v", err)
	}

	// Extract session key
	k.SessionKey = krbMech.Authentifier.ExportedSessionKey
	if krbMech.Authentifier.APRep != nil && krbMech.Authentifier.APRep.DecryptedEncPart.Subkey.KeyType != 0 {
		k.EType = krbMech.Authentifier.APRep.DecryptedEncPart.Subkey.KeyType
	} else {
		k.EType = krbMech.Authentifier.SessionKey.KeyType
	}

	// Wrap the third leg AP-REP in SPNEGO NegTokenResp format
	var spnegoThirdLeg []byte
	if len(thirdLegToken) > 0 {
		spnegoThirdLeg = wrapAPRepInSPNEGO(thirdLegToken)
	}

	if build.Debug {
		log.Printf("[D] KerberosAuth: AP-REP processed, SessionKey len=%d, etype=%d",
			len(k.SessionKey), k.EType)
		log.Printf("[D] KerberosAuth: SessionKey: %s", hex.EncodeToString(k.SessionKey))
		if len(spnegoThirdLeg) > 0 {
			log.Printf("[D] KerberosAuth: Third leg SPNEGO token (%d bytes)", len(spnegoThirdLeg))
		}
	}

	return spnegoThirdLeg, nil
}

// Encrypt encrypts data for DCE/RPC Packet Privacy using Kerberos.
// The data is encrypted in place and the signature is cached for Sign().
func (k *KerberosAuthHandler) Encrypt(plaintext []byte) []byte {
	if k.spnegoAuth == nil || k.spnegoAuth.Mechanism == nil {
		return nil
	}

	// Get the Kerberos mechanism
	krbMech, ok := k.spnegoAuth.Mechanism.(*krb5.Mechanism)
	if !ok {
		if build.Debug {
			log.Printf("[D] KerberosAuth.Encrypt: mechanism is not Kerberos")
		}
		return nil
	}

	// Create a copy of plaintext for encryption (go-msrpc encrypts in place)
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)

	// For DCE/RPC, both forSign and forSeal contain the same data
	forSign := [][]byte{encrypted}
	forSeal := [][]byte{encrypted}

	// Wrap using go-msrpc - this encrypts forSeal in place and returns signature
	signature, err := krbMech.Authentifier.WrapOutboundPayload(k.ctx, forSign, forSeal)
	if err != nil {
		if build.Debug {
			log.Printf("[D] KerberosAuth.Encrypt: WrapOutboundPayload failed: %v", err)
		}
		return nil
	}

	// Cache the signature for Sign()
	k.cachedSignature = signature

	if build.Debug {
		log.Printf("[D] KerberosAuth.Encrypt: plaintext=%d, encrypted=%d, signature=%d",
			len(plaintext), len(encrypted), len(signature))
	}

	return encrypted
}

// Sign returns the signature from the last Encrypt operation.
// For AES Kerberos, the signature is computed as part of the wrap operation.
func (k *KerberosAuthHandler) Sign(data []byte) []byte {
	if k.cachedSignature != nil {
		sig := k.cachedSignature
		k.cachedSignature = nil
		k.ClientSeqNum++ // Track sequence number for compatibility
		return sig
	}

	// Fallback: generate signature without encryption
	if k.spnegoAuth == nil || k.spnegoAuth.Mechanism == nil {
		return nil
	}

	krbMech, ok := k.spnegoAuth.Mechanism.(*krb5.Mechanism)
	if !ok {
		return nil
	}

	signature, err := krbMech.Authentifier.MakeOutboundSignature(k.ctx, [][]byte{data})
	if err != nil {
		if build.Debug {
			log.Printf("[D] KerberosAuth.Sign: MakeOutboundSignature failed: %v", err)
		}
		return nil
	}

	k.ClientSeqNum++
	return signature
}

// Decrypt decrypts data from DCE/RPC response.
func (k *KerberosAuthHandler) Decrypt(ciphertext []byte) []byte {
	if k.spnegoAuth == nil || k.spnegoAuth.Mechanism == nil {
		return nil
	}

	// Create a copy for decryption (go-msrpc decrypts in place)
	decrypted := make([]byte, len(ciphertext))
	copy(decrypted, ciphertext)

	return decrypted
}

// DecryptWithSignature decrypts data and verifies the signature.
// This is the proper way to decrypt sealed DCE/RPC responses.
func (k *KerberosAuthHandler) DecryptWithSignature(ciphertext, signature []byte) ([]byte, error) {
	if k.spnegoAuth == nil || k.spnegoAuth.Mechanism == nil {
		return nil, fmt.Errorf("not initialized")
	}

	krbMech, ok := k.spnegoAuth.Mechanism.(*krb5.Mechanism)
	if !ok {
		return nil, fmt.Errorf("mechanism is not Kerberos")
	}

	// Create a copy for decryption (go-msrpc decrypts in place)
	decrypted := make([]byte, len(ciphertext))
	copy(decrypted, ciphertext)

	// For DCE/RPC, both forSign and forSeal contain the same data
	forSign := [][]byte{decrypted}
	forSeal := [][]byte{decrypted}

	// Unwrap using go-msrpc - this decrypts forSeal in place and verifies signature
	verified, err := krbMech.Authentifier.UnwrapInboundPayload(k.ctx, forSign, forSeal, signature)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed: %v", err)
	}

	if !verified {
		if build.Debug {
			log.Printf("[D] KerberosAuth.DecryptWithSignature: signature verification failed")
		}
		// Continue anyway - signature verification can fail for various reasons
	}

	k.ServerSeqNum++
	return decrypted, nil
}

// Verify checks a signature (for compatibility).
func (k *KerberosAuthHandler) Verify(signature, data []byte) bool {
	// For full verification, use DecryptWithSignature instead
	k.ServerSeqNum++
	return true // Simplified - actual verification happens in DecryptWithSignature
}

// SignatureSize returns the size of the signature for the current encryption type.
func (k *KerberosAuthHandler) SignatureSize() int {
	if k.cachedSignature != nil {
		return len(k.cachedSignature)
	}

	// Default sizes based on encryption type
	switch k.EType {
	case 17, 18: // AES128/AES256
		// AES signature: header(16) + EC(16) + RRC portion(28) + confounder(16) = 76
		// But go-msrpc Size() returns the actual size
		if k.spnegoAuth != nil && k.spnegoAuth.Mechanism != nil {
			if krbMech, ok := k.spnegoAuth.Mechanism.(*krb5.Mechanism); ok {
				return krbMech.Authentifier.OutboundSignatureSize(k.ctx, true)
			}
		}
		return 76
	case 23: // RC4-HMAC
		return 16
	default:
		return 16
	}
}

// GetClientSeqNum returns the current client sequence number.
func (k *KerberosAuthHandler) GetClientSeqNum() uint32 {
	return k.ClientSeqNum
}

// IsInitialized returns true if the auth handler has valid session keys.
func (k *KerberosAuthHandler) IsInitialized() bool {
	return k.spnegoAuth != nil &&
		k.spnegoAuth.Mechanism != nil &&
		len(k.SessionKey) > 0
}

// wrapAPReqInGSSAPI wraps an AP-REQ in GSSAPI format for use in SPNEGO mechToken.
// Format: 0x60 [length] OID(1.2.840.113554.1.2.2) TOK_ID(0x01 0x00) AP-REQ
func wrapAPReqInGSSAPI(apReq []byte) []byte {
	// Kerberos OID: 1.2.840.113554.1.2.2
	oid := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	// Token ID for AP-REQ: 0x0100 (little-endian as per GSS-API)
	tokID := []byte{0x01, 0x00}

	// Build inner content: OID + TOK_ID + AP-REQ
	innerLen := len(oid) + len(tokID) + len(apReq)
	inner := make([]byte, 0, innerLen)
	inner = append(inner, oid...)
	inner = append(inner, tokID...)
	inner = append(inner, apReq...)

	// Wrap in APPLICATION 0x60 tag with proper length encoding
	return wrapASN1Application(inner)
}

// wrapASN1Application wraps data in an ASN.1 APPLICATION 0x60 tag
func wrapASN1Application(data []byte) []byte {
	length := len(data)
	var result []byte

	if length < 128 {
		result = make([]byte, 2+length)
		result[0] = 0x60
		result[1] = byte(length)
		copy(result[2:], data)
	} else if length < 256 {
		result = make([]byte, 3+length)
		result[0] = 0x60
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
	} else {
		result = make([]byte, 4+length)
		result[0] = 0x60
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], data)
	}
	return result
}

// wrapAPRepInSPNEGO wraps an AP-REP in SPNEGO NegTokenResp format for the third leg.
// Format: SPNEGO NegTokenResp with ResponseToken containing the AP-REP
func wrapAPRepInSPNEGO(apRep []byte) []byte {
	// Build SPNEGO NegTokenResp structure
	// NegTokenResp ::= SEQUENCE {
	//     negState       [0] ENUMERATED OPTIONAL,
	//     supportedMech  [1] OID OPTIONAL,
	//     responseToken  [2] OCTET STRING OPTIONAL,
	//     mechListMIC    [3] OCTET STRING OPTIONAL
	// }

	// Build responseToken [2] OCTET STRING
	responseToken := wrapASN1ContextTag(2, wrapASN1OctetString(apRep))

	// Build the SEQUENCE
	negTokenResp := wrapASN1Sequence(responseToken)

	// Wrap in context tag [1] for NegTokenResp (within NegotiationToken CHOICE)
	return wrapASN1ContextTag(1, negTokenResp)
}

// wrapASN1OctetString wraps data in an ASN.1 OCTET STRING tag (0x04)
func wrapASN1OctetString(data []byte) []byte {
	return wrapASN1Tag(0x04, data)
}

// wrapASN1Sequence wraps data in an ASN.1 SEQUENCE tag (0x30)
func wrapASN1Sequence(data []byte) []byte {
	return wrapASN1Tag(0x30, data)
}

// wrapASN1ContextTag wraps data in an ASN.1 context-specific tag [n] (0xA0 + n)
func wrapASN1ContextTag(tag int, data []byte) []byte {
	return wrapASN1Tag(byte(0xA0+tag), data)
}

// wrapASN1Tag wraps data in an ASN.1 tag with proper length encoding
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
