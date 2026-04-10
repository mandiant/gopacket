// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
	"gopacket/pkg/kerberos"
)

var debugGSSAPI = os.Getenv("DEBUG_GSSAPI") != ""

// OID for Kerberos V5 (GSSAPI)
var oidKerberos = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// KerberosGSSAPIClient implements go-ldap's GSSAPIClient interface
// using our kerberos.Client for Kerberos SASL authentication.
type KerberosGSSAPIClient struct {
	krbClient  *kerberos.Client
	sessionKey types.EncryptionKey
	seqNum     uint64
}

// NewKerberosGSSAPIClient creates a new GSSAPIClient for LDAP Kerberos auth.
func NewKerberosGSSAPIClient(krbClient *kerberos.Client) *KerberosGSSAPIClient {
	return &KerberosGSSAPIClient{
		krbClient: krbClient,
	}
}

// InitSecContext generates the initial GSSAPI token for Kerberos authentication.
// Implements GSSAPIClient.InitSecContext.
func (g *KerberosGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	if debugGSSAPI {
		log.Printf("[GSSAPI] InitSecContext called: target=%s, token=%d bytes", target, len(token))
	}

	if token != nil {
		// Server sent a response token (AP-REP or SASL challenge)
		if debugGSSAPI {
			log.Printf("[GSSAPI] InitSecContext continuation: server sent %d bytes", len(token))
			log.Printf("[GSSAPI] Server token hex: %s", hex.EncodeToString(token))
		}
		// Signal context is established, go-ldap will call NegotiateSaslAuth next
		// Return empty token, needContinue=false
		return nil, false, nil
	}

	// Generate AP-REQ for the target SPN and get full encryption key
	apReq, key, err := g.krbClient.GenerateAPReqFull(target)
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate AP-REQ: %v", err)
	}
	g.sessionKey = key

	if debugGSSAPI {
		log.Printf("[GSSAPI] Generated AP-REQ: %d bytes, session key type: %d", len(apReq), key.KeyType)
	}

	// Wrap AP-REQ in GSSAPI token format
	gssToken, err := wrapGSSAPIToken(apReq)
	if err != nil {
		return nil, false, fmt.Errorf("failed to wrap GSSAPI token: %v", err)
	}

	if debugGSSAPI {
		log.Printf("[GSSAPI] Wrapped token: %d bytes", len(gssToken))
	}

	// Return needContinue=true to have go-ldap call us again with server's response
	// This ensures we get the SASL challenge for NegotiateSaslAuth
	return gssToken, true, nil
}

// InitSecContextWithOptions is the same as InitSecContext but with additional options.
// Implements GSSAPIClient.InitSecContextWithOptions.
func (g *KerberosGSSAPIClient) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	if debugGSSAPI {
		log.Printf("[GSSAPI] InitSecContextWithOptions: options=%v", options)
	}
	// Options are not used in our implementation
	return g.InitSecContext(target, token)
}

// NegotiateSaslAuth completes the SASL authentication handshake.
// It receives the server's security layer token and returns our response.
// Implements GSSAPIClient.NegotiateSaslAuth.
func (g *KerberosGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	// The server sends a wrapped token describing supported security layers:
	// Byte 0: Supported security layers bitmask
	//   bit 0 = no security layer
	//   bit 1 = integrity only
	//   bit 2 = integrity and confidentiality
	// Bytes 1-3: Maximum receive buffer size (big-endian)

	if debugGSSAPI {
		log.Printf("[GSSAPI] NegotiateSaslAuth: received %d bytes from server", len(token))
		log.Printf("[GSSAPI] Server token hex: %s", hex.EncodeToString(token))
		log.Printf("[GSSAPI] Session key type: %d, len: %d", g.sessionKey.KeyType, len(g.sessionKey.KeyValue))
	}

	if len(token) < 4 {
		return nil, fmt.Errorf("invalid server security token: too short")
	}

	// Unwrap the server's token using gokrb5's WrapToken
	var wt gssapi.WrapToken
	err := wt.Unmarshal(token, true) // true = expect from acceptor
	if err != nil {
		if debugGSSAPI {
			log.Printf("[GSSAPI] WrapToken unmarshal failed: %v, trying MIC token", err)
		}
		// Try as MIC token instead
		return g.handleMICToken(token, authzid)
	}

	if debugGSSAPI {
		log.Printf("[GSSAPI] WrapToken unmarshaled: Flags=%02x, EC=%d, RRC=%d, SeqNum=%d, Payload=%d bytes",
			wt.Flags, wt.EC, wt.RRC, wt.SndSeqNum, len(wt.Payload))
	}

	// Verify the token
	valid, err := wt.Verify(g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil || !valid {
		if debugGSSAPI {
			log.Printf("[GSSAPI] WrapToken verify failed: %v, valid=%v", err, valid)
		}
		// Try without verification as fallback
		return g.handleMICToken(token, authzid)
	}

	// Parse server's security layers from unwrapped payload
	if len(wt.Payload) < 4 {
		return nil, fmt.Errorf("invalid unwrapped token: too short")
	}

	serverLayers := wt.Payload[0]
	serverMaxBuf := uint32(wt.Payload[1])<<16 | uint32(wt.Payload[2])<<8 | uint32(wt.Payload[3])
	if debugGSSAPI {
		log.Printf("[GSSAPI] Server offers: layers=0x%02x, maxbuf=%d", serverLayers, serverMaxBuf)
	}

	// Build response: select no security layer (0x01) since we don't want to wrap all LDAP traffic
	// This should work if server offers it (bit 0 set)
	response := make([]byte, 4+len(authzid))
	if serverLayers&0x01 != 0 {
		response[0] = 0x01 // No security layer
		response[1] = 0x00
		response[2] = 0x00
		response[3] = 0x00
	} else {
		// Server requires security layer, use integrity
		response[0] = 0x04 // Integrity protection
		response[1] = 0x00
		response[2] = 0xFF
		response[3] = 0xFF
	}
	if authzid != "" {
		copy(response[4:], []byte(authzid))
	}

	if debugGSSAPI {
		log.Printf("[GSSAPI] Sending response: layer=0x%02x", response[0])
	}

	// Wrap response using gokrb5's WrapToken
	g.seqNum++
	wrapped, err := gssapi.NewInitiatorWrapToken(response, g.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap response: %v", err)
	}

	wrappedBytes, err := wrapped.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapped response: %v", err)
	}

	if debugGSSAPI {
		log.Printf("[GSSAPI] Wrapped response: %d bytes", len(wrappedBytes))
	}

	return wrappedBytes, nil
}

// handleMICToken handles the case where the server sends a MIC token (older format)
// or when WrapToken parsing fails.
func (g *KerberosGSSAPIClient) handleMICToken(token []byte, authzid string) ([]byte, error) {
	// Try to parse as MIC token (RFC 1964)
	var mt gssapi.MICToken
	err := mt.Unmarshal(token, true)

	var serverLayers byte = 0x07 // Assume all layers supported if we can't parse
	var serverMaxBuf uint32 = 65535

	if err == nil {
		if debugGSSAPI {
			log.Printf("[GSSAPI] MICToken unmarshaled: Flags=%02x, SeqNum=%d, Payload=%d bytes",
				mt.Flags, mt.SndSeqNum, len(mt.Payload))
		}
		// Verify the MIC token
		valid, verr := mt.Verify(g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SIGN)
		if verr == nil && valid && len(mt.Payload) >= 4 {
			serverLayers = mt.Payload[0]
			serverMaxBuf = uint32(mt.Payload[1])<<16 | uint32(mt.Payload[2])<<8 | uint32(mt.Payload[3])
		}
	} else if debugGSSAPI {
		log.Printf("[GSSAPI] MICToken unmarshal also failed: %v", err)
		// Try to parse raw token - maybe it's just the 4-byte security layer data
		if len(token) >= 4 {
			serverLayers = token[0]
			serverMaxBuf = uint32(token[1])<<16 | uint32(token[2])<<8 | uint32(token[3])
			log.Printf("[GSSAPI] Raw token parse: layers=0x%02x, maxbuf=%d", serverLayers, serverMaxBuf)
		}
	}

	if debugGSSAPI {
		log.Printf("[GSSAPI] Using: layers=0x%02x, maxbuf=%d", serverLayers, serverMaxBuf)
	}

	// Build response - prefer no security layer if available
	response := make([]byte, 4+len(authzid))
	if serverLayers&0x01 != 0 {
		response[0] = 0x01 // No security layer
		response[1] = 0x00
		response[2] = 0x00
		response[3] = 0x00
	} else if serverLayers&0x02 != 0 {
		response[0] = 0x02 // Integrity only
		response[1] = 0x00
		response[2] = 0xFF
		response[3] = 0xFF
	} else {
		response[0] = 0x04 // Confidentiality
		response[1] = 0x00
		response[2] = 0xFF
		response[3] = 0xFF
	}
	if authzid != "" {
		copy(response[4:], []byte(authzid))
	}

	if debugGSSAPI {
		log.Printf("[GSSAPI] MIC path: Sending response with layer=0x%02x", response[0])
	}

	// Wrap response using gokrb5's WrapToken
	g.seqNum++
	wrapped, err := gssapi.NewInitiatorWrapToken(response, g.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap response: %v", err)
	}

	wrappedBytes, err := wrapped.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapped response: %v", err)
	}

	return wrappedBytes, nil
}

// DeleteSecContext cleans up the security context.
// Implements GSSAPIClient.DeleteSecContext.
func (g *KerberosGSSAPIClient) DeleteSecContext() error {
	g.sessionKey = types.EncryptionKey{}
	return nil
}

// wrapGSSAPIToken wraps an AP-REQ in GSSAPI token format.
// Format: [OID length][OID][AP-REQ]
func wrapGSSAPIToken(apReq []byte) ([]byte, error) {
	// GSSAPI token format (RFC 2743):
	// 0x60 [length] [OID tag 0x06] [OID length] [OID] [token]

	// Encode the Kerberos OID
	oidBytes, err := asn1.Marshal(oidKerberos)
	if err != nil {
		return nil, err
	}

	// Build inner token: OID + AP-REQ (with krb5 token tag 0x01 0x00)
	innerToken := make([]byte, 0, len(oidBytes)+2+len(apReq))
	innerToken = append(innerToken, oidBytes...)
	innerToken = append(innerToken, 0x01, 0x00) // Kerberos AP-REQ token ID
	innerToken = append(innerToken, apReq...)

	// Wrap in APPLICATION tag (0x60)
	return wrapASN1Application(innerToken), nil
}

// wrapASN1Application wraps data in ASN.1 APPLICATION tag (0x60)
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
