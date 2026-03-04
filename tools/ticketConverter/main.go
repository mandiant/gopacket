package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ASN.1 marshal structs for KRB-CRED (gokrb5 lacks Marshal support)

type marshalEncryptedData struct {
	EType  int    `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type marshalKrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"generalstring,optional,explicit,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
}

type marshalEncKrbCredPart struct {
	TicketInfo []marshalKrbCredInfo `asn1:"explicit,tag:0"`
}

type marshalKRBCred struct {
	PVNO    int                  `asn1:"explicit,tag:0"`
	MsgType int                  `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue        `asn1:"explicit,tag:2"`
	EncPart marshalEncryptedData `asn1:"explicit,tag:3"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input_file> <output_file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Converts between ccache and kirbi (KRB-CRED) ticket formats.\n")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read %s: %v\n", inputFile, err)
		os.Exit(1)
	}

	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Empty input file\n")
		os.Exit(1)
	}

	switch data[0] {
	case 0x76: // ASN.1 APPLICATION 22 tag → kirbi
		fmt.Println("[*] converting kirbi to ccache...")
		if err := kirbiToCCache(data, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	case 0x05: // CCache format
		fmt.Println("[*] converting ccache to kirbi...")
		if err := ccacheToKirbi(inputFile, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown file format (first byte: 0x%02x)\n", data[0])
		os.Exit(1)
	}

	fmt.Println("[+] done")
}

func ccacheToKirbi(inputFile, outputFile string) error {
	ccache, err := credentials.LoadCCache(inputFile)
	if err != nil {
		return fmt.Errorf("failed to load ccache: %v", err)
	}

	if len(ccache.Credentials) == 0 {
		return fmt.Errorf("no credentials in ccache")
	}

	// Find first non-config credential
	var cred *credentials.Credential
	for _, c := range ccache.Credentials {
		if len(c.Server.PrincipalName.NameString) > 0 && c.Server.PrincipalName.NameString[0] == "X-CACHECONF:" {
			continue
		}
		cred = c
		break
	}
	if cred == nil {
		return fmt.Errorf("no non-config credentials in ccache")
	}

	// Marshal the ticket from the credential
	var ticket messages.Ticket
	if err := ticket.Unmarshal(cred.Ticket); err != nil {
		return fmt.Errorf("failed to unmarshal ticket from ccache: %v", err)
	}

	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal ticket: %v", err)
	}

	// Build SEQUENCE OF Ticket wrapped in context tag [2] (explicit)
	// Inner: SEQUENCE (0x30) containing the marshaled ticket(s)
	innerSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ticketBytes,
	}
	innerBytes, err := asn1.Marshal(innerSeq)
	if err != nil {
		return fmt.Errorf("failed to marshal tickets inner sequence: %v", err)
	}
	// The struct field has explicit,tag:2 but RawValue with FullBytes bypasses it,
	// so we pre-build the context [2] CONSTRUCTED wrapper
	ticketsRaw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      innerBytes,
	}

	// Build KrbCredInfo - omit AuthTime (Impacket behavior)
	credInfo := marshalKrbCredInfo{
		Key: types.EncryptionKey{
			KeyType:  cred.Key.KeyType,
			KeyValue: cred.Key.KeyValue,
		},
		PRealm: ccache.DefaultPrincipal.Realm,
		PName:  ccache.DefaultPrincipal.PrincipalName,
		Flags:     cred.TicketFlags,
		StartTime: cred.StartTime.UTC(),
		EndTime:   cred.EndTime.UTC(),
		RenewTill: cred.RenewTill.UTC(),
		SRealm:    cred.Server.Realm,
		SName:     cred.Server.PrincipalName,
	}

	// Marshal EncKrbCredPart
	encPart := marshalEncKrbCredPart{
		TicketInfo: []marshalKrbCredInfo{credInfo},
	}
	encPartBytes, err := asn1.Marshal(encPart)
	if err != nil {
		return fmt.Errorf("failed to marshal EncKrbCredPart: %v", err)
	}
	encPartBytes = addASNAppTag(encPartBytes, asnAppTag.EncKrbCredPart)

	// Build KRB-CRED
	krbCred := marshalKRBCred{
		PVNO:    5,
		MsgType: 22,
		Tickets: ticketsRaw,
		EncPart: marshalEncryptedData{
			EType:  0,
			Cipher: encPartBytes,
		},
	}
	krbCredBytes, err := asn1.Marshal(krbCred)
	if err != nil {
		return fmt.Errorf("failed to marshal KRB-CRED: %v", err)
	}
	krbCredBytes = addASNAppTag(krbCredBytes, asnAppTag.KRBCred)

	return os.WriteFile(outputFile, krbCredBytes, 0600)
}

func kirbiToCCache(data []byte, outputFile string) error {
	var krbCred messages.KRBCred
	if err := krbCred.Unmarshal(data); err != nil {
		return fmt.Errorf("failed to unmarshal KRB-CRED: %v", err)
	}

	if krbCred.EncPart.EType != 0 {
		return fmt.Errorf("encrypted KRB-CRED (etype %d) not supported; only unencrypted (etype 0) kirbi files are supported", krbCred.EncPart.EType)
	}

	// Parse EncKrbCredPart from Cipher (etype=0 means no encryption)
	var encPart messages.EncKrbCredPart
	if err := encPart.Unmarshal(krbCred.EncPart.Cipher); err != nil {
		return fmt.Errorf("failed to unmarshal EncKrbCredPart: %v", err)
	}

	if len(encPart.TicketInfo) == 0 {
		return fmt.Errorf("no ticket info in KRB-CRED")
	}
	if len(krbCred.Tickets) == 0 {
		return fmt.Errorf("no tickets in KRB-CRED")
	}

	info := encPart.TicketInfo[0]

	// Marshal the ticket to DER
	ticketBytes, err := krbCred.Tickets[0].Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal ticket: %v", err)
	}

	// Build ccache
	var buf bytes.Buffer

	// Version 0x0504
	buf.Write([]byte{0x05, 0x04})

	// Header (DeltaTime)
	binary.Write(&buf, binary.BigEndian, uint16(12)) // header length
	binary.Write(&buf, binary.BigEndian, uint16(1))  // tag: DeltaTime
	binary.Write(&buf, binary.BigEndian, uint16(8))  // tag length
	binary.Write(&buf, binary.BigEndian, uint32(0xFFFFFFFF)) // time offset seconds
	binary.Write(&buf, binary.BigEndian, uint32(0))        // time offset usec

	// Default principal from KrbCredInfo
	writeCCachePrincipal(&buf, info.PName, info.PRealm)

	// Credential
	// Client principal
	writeCCachePrincipal(&buf, info.PName, info.PRealm)
	// Server principal
	writeCCachePrincipal(&buf, info.SName, info.SRealm)

	// Session key
	binary.Write(&buf, binary.BigEndian, uint16(info.Key.KeyType))
	binary.Write(&buf, binary.BigEndian, uint16(0)) // etype (unused in ccache v4)
	binary.Write(&buf, binary.BigEndian, uint16(len(info.Key.KeyValue)))
	buf.Write(info.Key.KeyValue)

	// Times: authtime = starttime (Impacket behavior)
	authTime := info.StartTime
	binary.Write(&buf, binary.BigEndian, uint32(authTime.Unix()))
	binary.Write(&buf, binary.BigEndian, uint32(info.StartTime.Unix()))
	binary.Write(&buf, binary.BigEndian, uint32(info.EndTime.Unix()))
	binary.Write(&buf, binary.BigEndian, uint32(info.RenewTill.Unix()))

	// is_skey
	buf.WriteByte(0)

	// Ticket flags - BitString bytes are the raw flag bytes
	// pyasn1 (used by Impacket) encodes named bits with BitLength=31 and a
	// 1-bit shift. Detect this and correct to get proper ccache flag bytes.
	var flagsVal uint32
	if len(info.Flags.Bytes) >= 4 {
		flagsVal = uint32(info.Flags.Bytes[0])<<24 | uint32(info.Flags.Bytes[1])<<16 |
			uint32(info.Flags.Bytes[2])<<8 | uint32(info.Flags.Bytes[3])
		if info.Flags.BitLength == 31 {
			// pyasn1 named bits encoding: shift right by 1 to correct
			flagsVal >>= 1
		}
	}
	binary.Write(&buf, binary.BigEndian, flagsVal)

	// Addresses (none)
	binary.Write(&buf, binary.BigEndian, uint32(0))
	// Auth data (none)
	binary.Write(&buf, binary.BigEndian, uint32(0))

	// Ticket
	binary.Write(&buf, binary.BigEndian, uint32(len(ticketBytes)))
	buf.Write(ticketBytes)

	// Second ticket (none)
	binary.Write(&buf, binary.BigEndian, uint32(0))

	return os.WriteFile(outputFile, buf.Bytes(), 0600)
}

func writeCCachePrincipal(buf *bytes.Buffer, name types.PrincipalName, realm string) {
	binary.Write(buf, binary.BigEndian, uint32(name.NameType))
	binary.Write(buf, binary.BigEndian, uint32(len(name.NameString)))
	binary.Write(buf, binary.BigEndian, uint32(len(realm)))
	buf.WriteString(realm)
	for _, comp := range name.NameString {
		binary.Write(buf, binary.BigEndian, uint32(len(comp)))
		buf.WriteString(comp)
	}
}

func addASNAppTag(b []byte, tag int) []byte {
	r := asn1.RawValue{
		Class:      asn1.ClassApplication,
		IsCompound: true,
		Tag:        tag,
		Bytes:      b,
	}
	ab, _ := asn1.Marshal(r)
	return ab
}
