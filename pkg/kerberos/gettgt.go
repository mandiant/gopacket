// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package kerberos

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"gopacket/pkg/transport"
	"unicode/utf16"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"golang.org/x/crypto/md4"
)

// TGTRequest holds configuration for a TGT request.
type TGTRequest struct {
	Username      string
	Password      string
	Domain        string
	NTHash        string
	AESKey        string
	DCIP          string
	DCHost        string
	Service       string // SPN for requesting service ticket via AS-REQ (optional)
	PrincipalType int32  // Principal name type (default: KRB_NT_PRINCIPAL)
}

// TGTResult holds the result of a successful TGT request.
type TGTResult struct {
	Ticket     []byte // Marshaled ticket bytes
	SessionKey types.EncryptionKey
	CName      types.PrincipalName
	SName      types.PrincipalName
	Realm      string
	AuthTime   time.Time
	EndTime    time.Time
	RenewTill  time.Time
	Flags      uint32
}

// GetTGT requests a TGT from the KDC and returns the result.
func GetTGT(req *TGTRequest) (*TGTResult, error) {
	realm := strings.ToUpper(req.Domain)

	// Determine KDC host
	kdcHost := req.DCIP
	if kdcHost == "" {
		kdcHost = req.DCHost
	}
	if kdcHost == "" {
		kdcHost = req.Domain
	}

	// Determine encryption type and derive key
	var encType int32
	var key []byte
	var err error

	if req.AESKey != "" {
		keyBytes, err := hex.DecodeString(req.AESKey)
		if err != nil {
			return nil, fmt.Errorf("invalid AES key: %v", err)
		}
		switch len(keyBytes) {
		case 16:
			encType = 17 // AES128
		case 32:
			encType = 18 // AES256
		default:
			return nil, fmt.Errorf("AES key must be 16 or 32 bytes (got %d)", len(keyBytes))
		}
		key = keyBytes
	} else if req.NTHash != "" {
		hashStr := req.NTHash
		if strings.Contains(hashStr, ":") {
			parts := strings.Split(hashStr, ":")
			hashStr = parts[len(parts)-1]
		}
		key, err = hex.DecodeString(hashStr)
		if err != nil {
			return nil, fmt.Errorf("invalid NT hash: %v", err)
		}
		encType = 23 // RC4-HMAC
	} else if req.Password != "" {
		// Derive RC4-HMAC key from password (MD4 of UTF-16LE password)
		key = ntHash(req.Password)
		encType = 23 // RC4-HMAC
	} else {
		return nil, fmt.Errorf("no authentication method specified (need password, hash, or aesKey)")
	}

	// Build AS-REQ
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DefaultTktEnctypes = []string{etypeName(encType)}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{encType}
	cfg.LibDefaults.Forwardable = true

	// Determine principal type
	principalType := int32(nametype.KRB_NT_PRINCIPAL)
	if req.PrincipalType != 0 {
		principalType = req.PrincipalType
	}
	cName := types.NewPrincipalName(principalType, req.Username)

	// Determine service name (default: krbtgt/REALM, or custom SPN via -service)
	var sName types.PrincipalName
	if req.Service != "" {
		sName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, req.Service)
	} else {
		sName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)
	}

	asReq, err := messages.NewASReq(realm, cfg, cName, sName)
	if err != nil {
		return nil, fmt.Errorf("failed to create AS-REQ: %v", err)
	}

	// Add PA-ENC-TIMESTAMP pre-authentication
	paTimestamp, err := buildPAEncTimestamp(key, encType)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-ENC-TIMESTAMP: %v", err)
	}
	asReq.PAData = append(asReq.PAData, paTimestamp)

	// Marshal and send
	b, err := asReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}

	respBuf, err := sendKDCRequest(kdcHost, b)
	if err != nil {
		return nil, err
	}

	// Parse response
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		var krbErr messages.KRBError
		if errErr := krbErr.Unmarshal(respBuf); errErr == nil {
			return nil, translateKRBError(krbErr)
		}
		return nil, fmt.Errorf("failed to unmarshal AS-REP: %v", err)
	}

	// Decrypt the encrypted part to get session key (usage 3 = AS-REP enc part)
	et, err := crypto.GetEtype(encType)
	if err != nil {
		return nil, fmt.Errorf("unsupported encryption type %d: %v", encType, err)
	}

	decrypted, err := et.DecryptMessage(key, asRep.EncPart.Cipher, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AS-REP: %v (wrong password/key?)", err)
	}

	// Parse EncASRepPart
	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(decrypted); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted AS-REP part: %v", err)
	}

	// Marshal the ticket for ccache storage
	ticketBytes, err := asRep.Ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ticket: %v", err)
	}

	// Determine flags from the response
	flags := uint32(0x50e10000) // Default: forwardable, proxiable, renewable, initial, pre_authent, enc_pa_rep

	result := &TGTResult{
		Ticket:     ticketBytes,
		SessionKey: encPart.Key,
		CName:      asRep.CName,
		SName:      sName,
		Realm:      realm,
		AuthTime:   encPart.AuthTime,
		EndTime:    encPart.EndTime,
		RenewTill:  encPart.RenewTill,
		Flags:      flags,
	}

	return result, nil
}

// SaveTGT saves a TGT result to a ccache file.
func SaveTGT(filename string, result *TGTResult) error {
	return saveToCCache(filename, result.Ticket, result.SessionKey,
		result.CName, result.Realm, result.SName,
		result.AuthTime, result.EndTime, result.RenewTill, result.Flags)
}

// buildPAEncTimestamp creates a PA-ENC-TIMESTAMP pre-authentication data.
func buildPAEncTimestamp(key []byte, encType int32) (types.PAData, error) {
	now := time.Now().UTC()

	// PA-ENC-TS-ENC ::= SEQUENCE {
	//   patimestamp [0] KerberosTime,
	//   pausec      [1] Microseconds OPTIONAL
	// }
	timestamp := types.PAEncTSEnc{
		PATimestamp: now,
		PAUSec:      int(now.Nanosecond() / 1000),
	}

	tsBytes, err := asn1.Marshal(timestamp)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to marshal timestamp: %v", err)
	}

	// Encrypt with the user's key (usage 1 = AS-REQ PA-ENC-TIMESTAMP)
	et, err := crypto.GetEtype(encType)
	if err != nil {
		return types.PAData{}, fmt.Errorf("unsupported etype: %v", err)
	}

	_, encrypted, err := et.EncryptMessage(key, tsBytes, 1)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to encrypt timestamp: %v", err)
	}

	// Build EncryptedData structure
	encData := types.EncryptedData{
		EType:  encType,
		KVNO:   0,
		Cipher: encrypted,
	}

	encDataBytes, err := encData.Marshal()
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to marshal encrypted data: %v", err)
	}

	return types.PAData{
		PADataType:  2, // PA-ENC-TIMESTAMP
		PADataValue: encDataBytes,
	}, nil
}

// sendKDCRequest sends a Kerberos message to the KDC and returns the response.
func sendKDCRequest(kdcHost string, data []byte) ([]byte, error) {
	addr := fmt.Sprintf("%s:88", kdcHost)
	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC %s: %v", addr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send: 4-byte big-endian length + data
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	if _, err := conn.Write(append(header, data...)); err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// Read response length
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, fmt.Errorf("failed to read response header: %v", err)
	}
	respLen := binary.BigEndian.Uint32(respHeader)

	if respLen > 1024*1024 {
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}

	// Read response body
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return respBuf, nil
}

// ntHash computes the MD4 hash of the UTF-16LE encoded password.
func ntHash(password string) []byte {
	utf16Chars := utf16.Encode([]rune(password))
	b := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// etypeName returns the string name for an encryption type ID.
func etypeName(etype int32) string {
	switch etype {
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 23:
		return "rc4-hmac"
	default:
		return "rc4-hmac"
	}
}

// translateKRBError provides a human-readable error from a KRB-ERROR.
func translateKRBError(e messages.KRBError) error {
	code := e.ErrorCode
	switch code {
	case 6:
		return fmt.Errorf("client not found in Kerberos database (KDC_ERR_C_PRINCIPAL_UNKNOWN)")
	case 7:
		return fmt.Errorf("server not found in Kerberos database (KDC_ERR_S_PRINCIPAL_UNKNOWN)")
	case 14:
		return fmt.Errorf("KDC has no support for PADATA type (pre-authentication type not supported)")
	case 18:
		return fmt.Errorf("client's credentials have been revoked (KDC_ERR_CLIENT_REVOKED)")
	case 23:
		return fmt.Errorf("ticket has expired (KDC_ERR_TKT_EXPIRED)")
	case 24:
		return fmt.Errorf("pre-authentication failed (KDC_ERR_PREAUTH_FAILED) - invalid password/key")
	case 25:
		return fmt.Errorf("additional pre-authentication required (KDC_ERR_PREAUTH_REQUIRED)")
	case 37:
		return fmt.Errorf("clock skew too great (KDC_ERR_SKEW) - sync time with DC")
	case 68:
		return fmt.Errorf("principal valid for pre-authentication only")
	default:
		return fmt.Errorf("KDC error code %d: %s", code, e.EText)
	}
}
