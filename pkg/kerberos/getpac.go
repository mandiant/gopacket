// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package kerberos

import (
	"encoding/asn1"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PACRequest holds configuration for a PAC retrieval request.
type PACRequest struct {
	Username   string
	Password   string
	Domain     string
	NTHash     string
	AESKey     string
	DCIP       string
	TargetUser string // User whose PAC we want to retrieve
}

// GetPAC retrieves the PAC for the target user using S4U2Self + User-to-User.
// This allows retrieving another user's PAC with just normal user credentials.
func GetPAC(req *PACRequest) (*PAC, error) {
	realm := strings.ToUpper(req.Domain)

	// Build kerberos config
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	cfg.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}

	kdcHost := req.DCIP
	if kdcHost == "" {
		kdcHost = req.Domain
	}

	// Step 1: Get TGT
	fmt.Printf("[*] Getting TGT for %s\n", req.Username)
	tgtReq := &TGTRequest{
		Username: req.Username,
		Password: req.Password,
		Domain:   req.Domain,
		NTHash:   req.NTHash,
		AESKey:   req.AESKey,
		DCIP:     req.DCIP,
	}

	tgtResult, err := GetTGT(tgtReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get TGT: %v", err)
	}

	// Unmarshal the TGT ticket
	var tgt messages.Ticket
	if err := tgt.Unmarshal(tgtResult.Ticket); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TGT: %v", err)
	}

	sessionKey := tgtResult.SessionKey

	// Step 2: S4U2Self + U2U
	fmt.Printf("[*] Requesting S4U2Self+U2U for %s\n", req.TargetUser)

	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, req.Username)
	// Request ticket to ourselves
	sName := types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, req.Username)

	// Build body with S4U2Self + U2U flags
	body := messages.KDCReqBody{
		KDCOptions:        types.NewKrbFlags(),
		Realm:             realm,
		SName:             sName,
		Till:              time.Now().UTC().Add(time.Hour * 10),
		Nonce:             int(rand.Int31()),
		EType:             cfg.LibDefaults.DefaultTGSEnctypeIDs,
		AdditionalTickets: []messages.Ticket{tgt}, // Include our TGT for U2U
	}

	// Set flags using gokrb5 constants
	types.SetFlag(&body.KDCOptions, flags.Forwardable)
	types.SetFlag(&body.KDCOptions, flags.Renewable)
	types.SetFlag(&body.KDCOptions, flags.RenewableOK)
	types.SetFlag(&body.KDCOptions, flags.Canonicalize)
	types.SetFlag(&body.KDCOptions, flags.EncTktInSkey) // U2U flag

	// Build PA-TGS-REQ
	apReqBytes, err := buildPATGSReq(body, tgt, sessionKey, realm, cName)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-TGS-REQ: %v", err)
	}

	// Build PA-FOR-USER for S4U2Self
	paForUser, err := buildPAForUser(req.TargetUser, realm, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-FOR-USER: %v", err)
	}

	// Assemble TGS-REQ
	tgsReq := messages.TGSReq{
		KDCReqFields: messages.KDCReqFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_TGS_REQ,
			PAData: types.PADataSequence{
				types.PAData{
					PADataType:  patype.PA_TGS_REQ,
					PADataValue: apReqBytes,
				},
				paForUser,
			},
			ReqBody: body,
		},
	}

	// Marshal and send
	b, err := tgsReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGS-REQ: %v", err)
	}

	respBuf, err := sendKDCRequest(kdcHost, b)
	if err != nil {
		return nil, err
	}

	// Parse TGS-REP
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		var krbErr messages.KRBError
		if errErr := krbErr.Unmarshal(respBuf); errErr == nil {
			return nil, translateKRBError(krbErr)
		}
		return nil, fmt.Errorf("failed to unmarshal TGS-REP: %v", err)
	}

	// Step 3: Decrypt the ticket
	// With U2U, the ticket is encrypted with our TGT session key (not service key)
	fmt.Printf("[*] Decrypting ticket\n")

	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("unsupported etype %d: %v", sessionKey.KeyType, err)
	}

	// Key usage 2 = ticket encryption
	decryptedTicket, err := et.DecryptMessage(sessionKey.KeyValue, tgsRep.Ticket.EncPart.Cipher, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ticket: %v", err)
	}

	// Step 4: Parse EncTicketPart to get authorization-data (PAC)
	var encTicket messages.EncTicketPart
	if err := encTicket.Unmarshal(decryptedTicket); err != nil {
		return nil, fmt.Errorf("failed to parse EncTicketPart: %v", err)
	}

	// Find PAC in authorization-data
	pac, err := extractPACFromAuthData(encTicket.AuthorizationData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PAC: %v", err)
	}

	return pac, nil
}

// setS4UU2UFlags sets the KDC options for S4U2Self + U2U
// From Impacket getPac.py:
//
//	forwardable (bit 1)
//	renewable (bit 8)
//	renewable_ok (bit 27)
//	canonicalize (bit 15)
//	enc_tkt_in_skey (bit 26)
func setS4UU2UFlags() []byte {
	// Bits are numbered from MSB (bit 0) to LSB
	// In a 32-bit field packed into 4 bytes (big-endian order for bits):
	// Byte 0: bits 0-7, Byte 1: bits 8-15, Byte 2: bits 16-23, Byte 3: bits 24-31
	//
	// forwardable (1):      byte 0, bit 6 (0x40)
	// renewable (8):        byte 1, bit 0 (0x80)
	// canonicalize (15):    byte 1, bit 7 (0x01)
	// enc-tkt-in-skey (26): byte 3, bit 2 (0x20)
	// renewable-ok (27):    byte 3, bit 3 (0x10)

	opts := make([]byte, 4)
	opts[0] = 0x40 // forwardable
	opts[1] = 0x81 // renewable + canonicalize
	opts[3] = 0x30 // enc-tkt-in-skey + renewable-ok

	return opts
}

// extractPACFromAuthData extracts the PAC from Kerberos authorization-data
func extractPACFromAuthData(authData types.AuthorizationData) (*PAC, error) {
	for _, ad := range authData {
		// AD-IF-RELEVANT (type 1) contains nested authorization-data
		if ad.ADType == 1 {
			// Parse as AD-IF-RELEVANT (SEQUENCE OF AuthorizationData)
			var nestedAD types.AuthorizationData
			rest, err := asn1.Unmarshal(ad.ADData, &nestedAD)
			if err != nil {
				// Try parsing raw
				nestedAD = parseRawAuthData(ad.ADData)
			}
			_ = rest

			for _, nested := range nestedAD {
				// AD-WIN2K-PAC (type 128)
				if nested.ADType == 128 {
					return ParsePAC(nested.ADData)
				}
			}
		}

		// Direct AD-WIN2K-PAC
		if ad.ADType == 128 {
			return ParsePAC(ad.ADData)
		}
	}

	return nil, fmt.Errorf("no PAC found in authorization-data")
}

// parseRawAuthData manually parses authorization-data when ASN.1 unmarshal fails
func parseRawAuthData(data []byte) types.AuthorizationData {
	var result types.AuthorizationData

	// Simple parsing: look for AD-WIN2K-PAC marker
	// AuthorizationDataEntry ::= SEQUENCE { ad-type [0] INTEGER, ad-data [1] OCTET STRING }
	offset := 0
	for offset < len(data)-4 {
		// Look for SEQUENCE tag
		if data[offset] != 0x30 {
			offset++
			continue
		}

		// Try to parse length
		seqLen := 0
		lenStart := offset + 1
		if data[lenStart] < 0x80 {
			seqLen = int(data[lenStart])
			lenStart++
		} else if data[lenStart] == 0x81 {
			if lenStart+1 >= len(data) {
				break
			}
			seqLen = int(data[lenStart+1])
			lenStart += 2
		} else if data[lenStart] == 0x82 {
			if lenStart+2 >= len(data) {
				break
			}
			seqLen = int(data[lenStart+1])<<8 | int(data[lenStart+2])
			lenStart += 3
		} else {
			offset++
			continue
		}

		if lenStart+seqLen > len(data) {
			offset++
			continue
		}

		seqData := data[lenStart : lenStart+seqLen]

		// Look for ad-type [0] INTEGER with value 128
		if len(seqData) > 6 && seqData[0] == 0xa0 {
			// Context tag 0
			typeLen := int(seqData[1])
			if typeLen > 0 && 2+typeLen < len(seqData) {
				intData := seqData[2 : 2+typeLen]
				if len(intData) >= 3 && intData[0] == 0x02 { // INTEGER tag
					intLen := int(intData[1])
					if intLen == 2 && len(intData) >= 4 {
						adType := int(intData[2])<<8 | int(intData[3])
						if adType == 128 {
							// Found AD-WIN2K-PAC, extract ad-data
							dataStart := 2 + typeLen
							if dataStart < len(seqData) && seqData[dataStart] == 0xa1 {
								// Context tag 1
								octetStart := dataStart + 2
								if octetStart < len(seqData) && seqData[octetStart] == 0x04 {
									// OCTET STRING
									octetLen := 0
									octetDataStart := octetStart + 2
									if seqData[octetStart+1] < 0x80 {
										octetLen = int(seqData[octetStart+1])
									} else if seqData[octetStart+1] == 0x82 {
										octetLen = int(seqData[octetStart+2])<<8 | int(seqData[octetStart+3])
										octetDataStart += 2
									}
									if octetDataStart+octetLen <= len(seqData) {
										result = append(result, types.AuthorizationDataEntry{
											ADType: 128,
											ADData: seqData[octetDataStart : octetDataStart+octetLen],
										})
									}
								}
							}
						}
					}
				}
			}
		}

		offset = lenStart + seqLen
	}

	return result
}

// Ensure setKDCFlagBytes is available (may already be in getst.go)
func init() {
	// Seed random for nonce generation
	rand.Seed(time.Now().UnixNano())
}

// Helper to set KDC flag bits (same as in getst.go but needed here)
func setKDCFlagBytesHelper(positions ...int) []byte {
	opts := make([]byte, 4)
	for _, pos := range positions {
		byteIdx := pos / 8
		bitIdx := uint(7 - (pos % 8))
		if byteIdx < len(opts) {
			opts[byteIdx] |= 1 << bitIdx
		}
	}
	return opts
}

// Constant for enc-tkt-in-skey flag position
const flagEncTktInSkey = 26
