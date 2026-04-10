// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	gokrbasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"gopacket/pkg/kerberos"
)

// ASN.1 structures for decrypting ticket enc-part (from ticketer.go)
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

var (
	password    = flag.String("p", "", "Cleartext password of the service account")
	hexPassword = flag.String("hp", "", "Hex password of the service account")
	user        = flag.String("u", "", "Service account name (for salt derivation)")
	domain      = flag.String("d", "", "FQDN domain (for salt derivation)")
	salt        = flag.String("s", "", "Explicit salt for key derivation")
	rc4Key      = flag.String("rc4", "", "RC4/NT hash hex key")
	aesKey      = flag.String("aes", "", "AES128 or AES256 hex key")
	aesKeyFlag  = flag.String("aesKey", "", "AES key (alias for -aes)")
	asrepKey    = flag.String("asrep-key", "", "AS-REP key for PAC_CREDENTIALS_INFO decryption")
	debug       = flag.Bool("debug", false, "Debug output")
	timestamps  = flag.Bool("ts", false, "Timestamps on logging")
)

func main() {
	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	ticketPath := flag.Arg(0)

	// Merge -aesKey into -aes
	if *aesKey == "" && *aesKeyFlag != "" {
		*aesKey = *aesKeyFlag
	}

	// Load ccache
	ccache, err := loadCCacheSafe(ticketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error loading ccache: %v\n", err)
		os.Exit(1)
	}

	// Filter out config entries
	creds := ccache.GetEntries()

	fmt.Printf("\nNumber of credentials in cache: %d\n", len(creds))

	for i, cred := range creds {
		parseCredential(cred, i)
	}
}

func parseCredential(cred *credentials.Credential, index int) {
	fmt.Printf("\nParsing credential[%d]:\n", index)

	// Session key
	fmt.Printf("%-30s: %s\n", "Ticket Session Key", hex.EncodeToString(cred.Key.KeyValue))

	// User info
	clientName := strings.Join(cred.Client.PrincipalName.NameString, "/")
	fmt.Printf("%-30s: %s\n", "User Name", clientName)
	fmt.Printf("%-30s: %s\n", "User Realm", cred.Client.Realm)

	// Service info
	serverName := strings.Join(cred.Server.PrincipalName.NameString, "/")
	fmt.Printf("%-30s: %s\n", "Service Name", serverName)
	fmt.Printf("%-30s: %s\n", "Service Realm", cred.Server.Realm)

	// Timestamps
	fmt.Printf("%-30s: %s\n", "Start Time", formatTime(cred.StartTime))
	endStr := formatTime(cred.EndTime)
	if !cred.EndTime.IsZero() && time.Now().After(cred.EndTime) {
		endStr += " (expired)"
	}
	fmt.Printf("%-30s: %s\n", "End Time", endStr)
	renewStr := formatTime(cred.RenewTill)
	if !cred.RenewTill.IsZero() && cred.RenewTill.Unix() > 0 && time.Now().After(cred.RenewTill) {
		renewStr += " (expired)"
	}
	fmt.Printf("%-30s: %s\n", "RenewTill", renewStr)

	// Flags
	fmt.Printf("%-30s: %s\n", "Flags", formatFlags(cred.TicketFlags))

	// Key type and base64
	fmt.Printf("%-30s: %s\n", "KeyType", etypeName(cred.Key.KeyType))
	fmt.Printf("%-30s: %s\n", "Base64(key)", base64.StdEncoding.EncodeToString(cred.Key.KeyValue))

	// Kerberoast hash (only for service tickets, not krbtgt)
	if !isKrbtgt(cred) {
		hash := formatKerberoastHash(cred)
		if hash != "" {
			fmt.Printf("%-30s: %s\n", "Kerberoast hash", hash)
		}
	}

	// Parse ticket ASN.1 outer layer
	fmt.Printf("%-30s:\n", fmt.Sprintf("Decoding unencrypted data in credential[%d]['ticket']", index))

	var ticket messages.Ticket
	if err := ticket.Unmarshal(cred.Ticket); err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Failed to parse ticket: %v\n", err)
		return
	}

	sname := strings.Join(ticket.SName.NameString, "/")
	fmt.Printf("  %-28s: %s\n", "Service Name", sname)
	fmt.Printf("  %-28s: %s\n", "Service Realm", ticket.Realm)
	fmt.Printf("  %-28s: %s (etype %d)\n", "Encryption type", etypeName(ticket.EncPart.EType), ticket.EncPart.EType)

	// Try to decrypt if key provided
	ekeys := generateKerberosKeys()
	key, ok := ekeys[ticket.EncPart.EType]
	if !ok {
		if len(ekeys) > 0 {
			fmt.Fprintf(os.Stderr, "[-] Could not find the correct encryption key! Ticket is encrypted with %s (etype %d), but only keytype(s) %s were calculated/supplied\n",
				etypeName(ticket.EncPart.EType), ticket.EncPart.EType, formatKeyTypes(ekeys))
		} else {
			fmt.Fprintf(os.Stderr, "[-] Could not find the correct encryption key! Ticket is encrypted with %s (etype %d), but no keys/creds were supplied\n",
				etypeName(ticket.EncPart.EType), ticket.EncPart.EType)
		}
		return
	}

	decryptAndShowEncPart(ticket, key, index)
}

func decryptAndShowEncPart(ticket messages.Ticket, key []byte, index int) {
	etype := ticket.EncPart.EType
	cipher := ticket.EncPart.Cipher

	e, err := crypto.GetEtype(etype)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Unsupported encryption type: %d\n", etype)
		return
	}

	// Decrypt with key usage 2 (AS-REP/TGS-REP ticket)
	plaintext, err := e.DecryptMessage(key, cipher, 2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Ciphertext integrity failed. Most likely the account password or AES key is incorrect\n")
		return
	}

	fmt.Printf("%-30s:\n", fmt.Sprintf("Decoding credential[%d]['ticket']['enc-part']", index))

	// Strip APPLICATION 3 tag if present
	plaintext = stripASN1App(plaintext, 3)

	// Unmarshal EncTicketPart
	var encPart encTicketPartASN1
	_, err = gokrbasn1.Unmarshal(plaintext, &encPart)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [-] Failed to decode EncTicketPart: %v\n", err)
		return
	}

	// Find PAC in authorization data
	for _, ad := range encPart.AuthorizationData {
		if ad.ADType == 1 { // AD-IF-RELEVANT
			var innerAD []authorizationDataEntryASN1
			_, err := gokrbasn1.Unmarshal(ad.ADData, &innerAD)
			if err != nil {
				continue
			}
			for _, inner := range innerAD {
				if inner.ADType == 128 { // AD-WIN2K-PAC
					pac, err := kerberos.ParsePAC(inner.ADData)
					if err != nil {
						fmt.Fprintf(os.Stderr, "  [-] Failed to parse PAC: %v\n", err)
						return
					}
					printPAC(pac)
					return
				}
			}
		}
	}

	fmt.Println("  [-] No PAC found in ticket")
}

func printPAC(pac *kerberos.PAC) {
	// LoginInfo (Impacket uses "LoginInfo" not "LogonInfo")
	fmt.Printf("  %-28s\n", "LoginInfo")
	fmt.Printf("    %-26s: %s\n", "Logon Time", formatTime(pac.LogonTime))
	fmt.Printf("    %-26s: %s\n", "Logoff Time", formatTime(pac.LogoffTime))
	fmt.Printf("    %-26s: %s\n", "Kickoff Time", formatTime(pac.KickOffTime))
	fmt.Printf("    %-26s: %s\n", "Password Last Set", formatTime(pac.PasswordLastSet))
	fmt.Printf("    %-26s: %s\n", "Password Can Change", formatTime(pac.PasswordCanChange))
	fmt.Printf("    %-26s: %s\n", "Password Must Change", formatTime(pac.PasswordMustChange))
	fmt.Printf("    %-26s: %s\n", "LastSuccessfulILogon", formatTime(pac.LastSuccessfulILogon))
	fmt.Printf("    %-26s: %s\n", "LastFailedILogon", formatTime(pac.LastFailedILogon))
	fmt.Printf("    %-26s: %d\n", "FailedILogonCount", pac.FailedILogonCount)
	fmt.Printf("    %-26s: %s\n", "Account Name", pac.Username)
	fmt.Printf("    %-26s: %s\n", "Full Name", pac.FullName)
	fmt.Printf("    %-26s: %s\n", "Logon Script", pac.LogonScript)
	fmt.Printf("    %-26s: %s\n", "Profile Path", pac.ProfilePath)
	fmt.Printf("    %-26s: %s\n", "Home Dir", pac.HomeDirectory)
	fmt.Printf("    %-26s: %s\n", "Dir Drive", pac.HomeDirectoryDrive)
	fmt.Printf("    %-26s: %d\n", "Logon Count", pac.LogonCount)
	fmt.Printf("    %-26s: %d\n", "Bad Password Count", pac.BadPasswordCount)
	fmt.Printf("    %-26s: %d\n", "User RID", pac.UserID)
	fmt.Printf("    %-26s: %d\n", "Group RID", pac.PrimaryGroupID)
	fmt.Printf("    %-26s: %d\n", "Group Count", len(pac.Groups))

	// Groups as comma-separated RIDs
	rids := make([]string, len(pac.Groups))
	for i, gid := range pac.Groups {
		rids[i] = fmt.Sprintf("%d", gid)
	}
	fmt.Printf("    %-26s: %s\n", "Groups", strings.Join(rids, ", "))

	// Groups (decoded) with multiline
	var decoded []string
	unknownCount := 0
	for _, gid := range pac.Groups {
		name := ridName(gid)
		if name != "" {
			decoded = append(decoded, fmt.Sprintf("(%d) %s", gid, name))
		} else {
			unknownCount++
		}
	}
	if unknownCount > 0 {
		suffix := ""
		if unknownCount > 1 {
			suffix = "s"
		}
		decoded = append(decoded, fmt.Sprintf("+%d Unknown custom group%s", unknownCount, suffix))
	}
	if len(decoded) > 0 {
		fmt.Printf("    %-26s: %s\n", "Groups (decoded)", decoded[0])
		for _, d := range decoded[1:] {
			fmt.Printf("%32s%s\n", "", d)
		}
	} else {
		fmt.Printf("    %-26s:\n", "Groups (decoded)")
	}

	// User Flags with enum names
	fmt.Printf("    %-26s: %s\n", "User Flags", formatUserFlags(pac.UserFlags))
	fmt.Printf("    %-26s: %s\n", "User Session Key", hex.EncodeToString(pac.UserSessionKey[:]))
	fmt.Printf("    %-26s: %s\n", "Logon Server", pac.LogonServer)
	fmt.Printf("    %-26s: %s\n", "Logon Domain Name", pac.Domain)
	if pac.DomainSID != nil {
		fmt.Printf("    %-26s: %s\n", "Logon Domain SID", pac.DomainSID.String())
	} else {
		fmt.Printf("    %-26s:\n", "Logon Domain SID")
	}

	// User Account Control with USER_ACCOUNT codes
	fmt.Printf("    %-26s: %s\n", "User Account Control", formatUAC(pac.UserAccountControl))

	// Extra SIDs
	fmt.Printf("    %-26s: %d\n", "Extra SID Count", len(pac.ExtraSIDs))
	if len(pac.ExtraSIDs) > 0 {
		var sidStrs []string
		for i, sid := range pac.ExtraSIDs {
			attr := uint32(0)
			if i < len(pac.ExtraSIDAttrs) {
				attr = pac.ExtraSIDAttrs[i]
			}
			sidStr := sid.String()
			// Try full SID match, then RID match for domain SIDs
			groupName := sidName(sidStr)
			if groupName == "" {
				parts := strings.Split(sidStr, "-")
				if len(parts) == 8 {
					groupName = ridName(parseUint32(parts[len(parts)-1]))
				}
			}
			nameStr := ""
			if groupName != "" {
				nameStr = " " + groupName
			}
			sidStrs = append(sidStrs, fmt.Sprintf("%s%s (%s)", sidStr, nameStr, formatSEGroupAttrs(attr)))
		}
		if len(sidStrs) > 0 {
			fmt.Printf("    %-26s: %s\n", "Extra SIDs", sidStrs[0])
			for _, s := range sidStrs[1:] {
				fmt.Printf("%32s%s\n", "", s)
			}
		}
	} else {
		fmt.Printf("    %-26s:\n", "Extra SIDs")
	}

	// Resource Group fields
	fmt.Printf("    %-26s:\n", "Resource Group Domain SID")
	fmt.Printf("    %-26s: %d\n", "Resource Group Count", 0)
	fmt.Printf("    %-26s: \n", "Resource Group Ids")

	// LMKey (always zeroed in PAC, 8 bytes)
	fmt.Printf("    %-26s: %s\n", "LMKey", "0000000000000000")
	fmt.Printf("    %-26s: %d\n", "SubAuthStatus", pac.SubAuthStatus)
	fmt.Printf("    %-26s: %d\n", "Reserved3", pac.Reserved3)

	// ClientName
	fmt.Printf("  %-28s\n", "ClientName")
	fmt.Printf("    %-26s: %s\n", "Client Id", formatTime(pac.ClientInfoTime))
	fmt.Printf("    %-26s: %s\n", "Client Name", pac.ClientInfoName)

	// UpnDns
	if pac.UPN != "" || pac.DNSDomainName != "" || pac.SamAccountName != "" {
		fmt.Printf("  %-28s\n", "UpnDns")
		fmt.Printf("    %-26s: %s\n", "Flags", formatUpnDnsFlags(pac.UPNFlags))
		fmt.Printf("    %-26s: %s\n", "UPN", pac.UPN)
		fmt.Printf("    %-26s: %s\n", "DNS Domain Name", pac.DNSDomainName)
		if pac.UPNFlags&0x2 != 0 {
			if pac.SamAccountName != "" {
				fmt.Printf("    %-26s: %s\n", "SamAccountName", pac.SamAccountName)
			}
			if pac.UPNSid != nil {
				fmt.Printf("    %-26s: %s\n", "UserSid", pac.UPNSid.String())
			}
		}
	}

	// DelegationInfo
	if pac.S4U2ProxyTarget != "" {
		fmt.Printf("  %-28s\n", "DelegationInfo")
		fmt.Printf("    %-26s: %s\n", "S4U2proxyTarget", pac.S4U2ProxyTarget)
		fmt.Printf("    %-26s: %d\n", "TransitedListSize", len(pac.TransitedServices))
		fmt.Printf("    %-26s: %s\n", "S4UTransitedServices", strings.Join(pac.TransitedServices, ", "))
	}

	// Attributes Info
	if pac.AttributesFlags != 0 {
		fmt.Printf("  %-28s\n", "Attributes Info")
		fmt.Printf("    %-26s: %s\n", "Flags", formatAttributesFlags(pac.AttributesFlags))
	}

	// Requestor Info
	if pac.RequestorSID != nil {
		fmt.Printf("  %-28s\n", "Requestor Info")
		fmt.Printf("    %-26s: %s\n", "UserSid", pac.RequestorSID.String())
	}

	// Credential Info
	if len(pac.CredentialInfo) > 0 {
		fmt.Printf("  %-28s\n", "Credential Info")
		if *asrepKey == "" {
			fmt.Printf("    %-26s: %s\n", "Encryption Type", "<Cannot decrypt, --asrep-key missing>")
		} else {
			keyBytes, err := hex.DecodeString(*asrepKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    [-] Invalid AS-REP key: %v\n", err)
			} else {
				decrypted, err := pac.DecryptCredentialInfo(keyBytes)
				if err != nil {
					fmt.Fprintf(os.Stderr, "    [-] Decryption failed: %v\n", err)
				} else {
					parseCredentialInfo(decrypted)
				}
			}
		}
	}

	// Server Checksum
	if len(pac.ServerChecksumData) > 0 {
		fmt.Printf("  %-28s\n", "ServerChecksum")
		fmt.Printf("    %-26s: %s\n", "Signature Type", checksumTypeName(pac.ServerChecksumType))
		fmt.Printf("    %-26s: %s\n", "Signature", hex.EncodeToString(pac.ServerChecksumData))
	}

	// KDC Checksum
	if len(pac.KDCChecksumData) > 0 {
		fmt.Printf("  %-28s\n", "KDCChecksum")
		fmt.Printf("    %-26s: %s\n", "Signature Type", checksumTypeName(pac.KDCChecksumType))
		fmt.Printf("    %-26s: %s\n", "Signature", hex.EncodeToString(pac.KDCChecksumData))
	}
}

func parseCredentialInfo(data []byte) {
	// Simplified credential info display
	if len(data) > 0 {
		fmt.Printf("    %-26s: %s\n", "Data", hex.EncodeToString(data))
	}
}

// generateKerberosKeys builds all possible decryption keys from provided flags.
// Matches Impacket: generates keys for ALL cipher types from password, picks matching one.
func generateKerberosKeys() map[int32][]byte {
	ekeys := make(map[int32][]byte)

	// Direct key: --rc4
	if *rc4Key != "" {
		key, err := hex.DecodeString(*rc4Key)
		if err == nil && len(key) == 16 {
			ekeys[etypeID.RC4_HMAC] = key
		}
	}

	// Direct key: --aes or -aesKey
	if *aesKey != "" {
		key, err := hex.DecodeString(*aesKey)
		if err == nil {
			switch len(key) {
			case 32:
				ekeys[etypeID.AES256_CTS_HMAC_SHA1_96] = key
			case 16:
				ekeys[etypeID.AES128_CTS_HMAC_SHA1_96] = key
			}
		}
	}

	// Password or hex-password based key derivation
	if *password != "" || *hexPassword != "" {
		keySalt := *salt
		if keySalt == "" && *user != "" && *domain != "" {
			// Compute salt from user/domain (matching Impacket)
			if strings.HasSuffix(*user, "$") {
				// Computer account: DOMAINhostmachine.domain
				keySalt = strings.ToUpper(*domain) + "host" + strings.ToLower(strings.TrimSuffix(*user, "$")) + "." + strings.ToLower(*domain)
			} else {
				keySalt = strings.ToUpper(*domain) + *user
			}
		}

		allCiphers := []int32{
			etypeID.RC4_HMAC,
			etypeID.AES256_CTS_HMAC_SHA1_96,
			etypeID.AES128_CTS_HMAC_SHA1_96,
		}

		for _, cipher := range allCiphers {
			if cipher == etypeID.RC4_HMAC && *hexPassword != "" {
				// RC4 from hex password: MD4(unhexlify(hex_pass))
				rawBytes, err := hex.DecodeString(*hexPassword)
				if err == nil {
					ekeys[cipher] = kerberos.GetNTHash(string(rawBytes))
				}
			} else if keySalt != "" {
				rawSecret := *password
				if rawSecret == "" && *hexPassword != "" {
					rawSecret = *hexPassword // Use hex password as string for AES derivation
				}
				e, err := crypto.GetEtype(cipher)
				if err != nil {
					continue
				}
				key, err := e.StringToKey(rawSecret, keySalt, "")
				if err != nil {
					continue
				}
				ekeys[cipher] = key
			}
		}
	}

	return ekeys
}

// stripASN1App strips an ASN.1 APPLICATION tag wrapper if present.
func stripASN1App(data []byte, tag int) []byte {
	expectedTag := byte(0x60 + tag)
	if len(data) < 2 || data[0] != expectedTag {
		return data
	}
	offset := 1
	length := int(data[offset])
	if length&0x80 != 0 {
		numBytes := length & 0x7f
		offset++
		length = 0
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[offset])
			offset++
		}
	} else {
		offset++
	}
	return data[offset:]
}

// Helper functions

func etypeName(etype int32) string {
	// Match Impacket: uses underscores in names
	switch etype {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		return "aes128_cts_hmac_sha1_96"
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		return "aes256_cts_hmac_sha1_96"
	case etypeID.RC4_HMAC:
		return "rc4_hmac"
	case etypeID.RC4_HMAC_EXP:
		return "rc4_hmac_exp"
	case etypeID.DES3_CBC_SHA1_KD:
		return "des3_cbc_sha1_kd"
	case etypeID.DES_CBC_MD5:
		return "des_cbc_md5"
	default:
		return fmt.Sprintf("etype_%d", etype)
	}
}

func checksumTypeName(ctype uint32) string {
	switch ctype {
	case kerberos.ChecksumHMACMD5:
		return "HMAC_MD5"
	case kerberos.ChecksumSHA196AES128:
		return "hmac_sha1_96_aes128"
	case kerberos.ChecksumSHA196AES256:
		return "hmac_sha1_96_aes256"
	default:
		return fmt.Sprintf("0x%x", ctype)
	}
}

func formatKeyTypes(ekeys map[int32][]byte) string {
	names := make([]string, 0, len(ekeys))
	for etype := range ekeys {
		names = append(names, fmt.Sprintf("%s (%d)", etypeName(etype), etype))
	}
	return strings.Join(names, ", ")
}

func formatFlags(bf gokrbasn1.BitString) string {
	var raw uint32
	for i := 0; i < len(bf.Bytes) && i < 4; i++ {
		raw |= uint32(bf.Bytes[i]) << (24 - uint(i)*8)
	}

	// Match Impacket's TicketFlags names (underscores)
	flagNames := []struct {
		bit  int
		name string
	}{
		{flags.Reserved, "reserved"},
		{flags.Forwardable, "forwardable"},
		{flags.Forwarded, "forwarded"},
		{flags.Proxiable, "proxiable"},
		{flags.Proxy, "proxy"},
		{flags.MayPostDate, "may_postdate"},
		{flags.PostDated, "postdated"},
		{flags.Invalid, "invalid"},
		{flags.Renewable, "renewable"},
		{flags.Initial, "initial"},
		{flags.PreAuthent, "pre_authent"},
		{flags.HWAuthent, "hw_authent"},
		{flags.OKAsDelegate, "ok_as_delegate"},
		{flags.EncPARep, "enc_pa_rep"},
	}

	var set []string
	for _, f := range flagNames {
		if bf.At(f.bit) != 0 {
			set = append(set, f.name)
		}
	}

	return fmt.Sprintf("(0x%x) %s", raw, strings.Join(set, ", "))
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "Infinity (absolute time)"
	}
	if t.Year() > 9000 || t.Unix() <= 0 {
		return "Infinity (absolute time)"
	}
	// Match Impacket: 24-hour clock with AM/PM suffix
	// Python's %H is 24-hour, %p adds AM/PM based on locale
	hour := t.Hour()
	ampm := "AM"
	if hour >= 12 {
		ampm = "PM"
	}
	return fmt.Sprintf("%02d/%02d/%04d %02d:%02d:%02d %s",
		t.Day(), int(t.Month()), t.Year(),
		hour, t.Minute(), t.Second(), ampm)
}

func formatUserFlags(uf uint32) string {
	type uflag struct {
		value uint32
		name  string
	}
	allFlags := []uflag{
		{0x0020, "LOGON_EXTRA_SIDS"},
		{0x0200, "LOGON_RESOURCE_GROUPS"},
	}
	var names []string
	for _, f := range allFlags {
		if uf&f.value != 0 {
			names = append(names, f.name)
		}
	}
	return fmt.Sprintf("(%d) %s", uf, strings.Join(names, ", "))
}

// formatUAC formats UserAccountControl using MS-PAC USER_ACCOUNT codes
// (NOT the UF_ LDAP codes which have different values!)
func formatUAC(uac uint32) string {
	type uacFlag struct {
		value uint32
		name  string
	}
	allFlags := []uacFlag{
		{0x00000001, "USER_ACCOUNT_DISABLED"},
		{0x00000002, "USER_HOME_DIRECTORY_REQUIRED"},
		{0x00000004, "USER_PASSWORD_NOT_REQUIRED"},
		{0x00000008, "USER_TEMP_DUPLICATE_ACCOUNT"},
		{0x00000010, "USER_NORMAL_ACCOUNT"},
		{0x00000020, "USER_MNS_LOGON_ACCOUNT"},
		{0x00000040, "USER_INTERDOMAIN_TRUST_ACCOUNT"},
		{0x00000080, "USER_WORKSTATION_TRUST_ACCOUNT"},
		{0x00000100, "USER_SERVER_TRUST_ACCOUNT"},
		{0x00000200, "USER_DONT_EXPIRE_PASSWORD"},
		{0x00000400, "USER_ACCOUNT_AUTO_LOCKED"},
		{0x00000800, "USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED"},
		{0x00001000, "USER_SMARTCARD_REQUIRED"},
		{0x00002000, "USER_TRUSTED_FOR_DELEGATION"},
		{0x00004000, "USER_NOT_DELEGATED"},
		{0x00008000, "USER_USE_DES_KEY_ONLY"},
		{0x00010000, "USER_DONT_REQUIRE_PREAUTH"},
		{0x00020000, "USER_PASSWORD_EXPIRED"},
		{0x00040000, "USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"},
		{0x00080000, "USER_NO_AUTH_DATA_REQUIRED"},
		{0x00100000, "USER_PARTIAL_SECRETS_ACCOUNT"},
		{0x00200000, "USER_USE_AES_KEYS"},
	}
	var names []string
	for _, f := range allFlags {
		if uac&f.value != 0 {
			names = append(names, f.name)
		}
	}
	return fmt.Sprintf("(%d) %s", uac, strings.Join(names, ", "))
}

func formatSEGroupAttrs(attr uint32) string {
	type ga struct {
		value uint32
		name  string
	}
	allAttrs := []ga{
		{0x00000001, "SE_GROUP_MANDATORY"},
		{0x00000002, "SE_GROUP_ENABLED_BY_DEFAULT"},
		{0x00000004, "SE_GROUP_ENABLED"},
	}
	var names []string
	for _, a := range allAttrs {
		if attr&a.value != 0 {
			names = append(names, a.name)
		}
	}
	return strings.Join(names, ", ")
}

func formatUpnDnsFlags(f uint32) string {
	type uf struct {
		value uint32
		name  string
	}
	allFlags := []uf{
		{0x00000001, "U_UsernameOnly"},
		{0x00000002, "S_SidSamSupplied"},
	}
	var names []string
	for _, fl := range allFlags {
		if f&fl.value != 0 {
			names = append(names, fl.name)
		}
	}
	return fmt.Sprintf("(%d) %s", f, strings.Join(names, ", "))
}

func formatAttributesFlags(f uint32) string {
	type af struct {
		value uint32
		name  string
	}
	allFlags := []af{
		{0x00000001, "PAC_WAS_REQUESTED"},
		{0x00000002, "PAC_WAS_GIVEN_IMPLICITLY"},
	}
	var names []string
	for _, fl := range allFlags {
		if f&fl.value != 0 {
			names = append(names, fl.name)
		}
	}
	return fmt.Sprintf("(%d) %s", f, strings.Join(names, ", "))
}

func isKrbtgt(cred *credentials.Credential) bool {
	if len(cred.Server.PrincipalName.NameString) > 0 {
		return strings.EqualFold(cred.Server.PrincipalName.NameString[0], "krbtgt")
	}
	return false
}

func formatKerberoastHash(cred *credentials.Credential) string {
	if len(cred.Ticket) == 0 {
		return ""
	}

	var ticket messages.Ticket
	if err := ticket.Unmarshal(cred.Ticket); err != nil {
		return ""
	}

	etype := ticket.EncPart.EType
	cipher := ticket.EncPart.Cipher
	if len(cipher) == 0 {
		return ""
	}

	// Determine username for hash (match Impacket: use -u flag, default "USER")
	username := *user
	if username == "" {
		username = "USER"
	}
	username = strings.TrimSuffix(username, "$")

	// Determine domain for hash
	hashDomain := *domain
	if hashDomain == "" {
		hashDomain = ticket.Realm
	}
	hashDomain = strings.ToUpper(hashDomain)

	serverName := strings.Join(ticket.SName.NameString, "/")
	// Replace ':' with '~' in SPN (matches Impacket)
	spn := strings.ReplaceAll(serverName, ":", "~")

	switch etype {
	case etypeID.RC4_HMAC:
		if len(cipher) < 16 {
			return ""
		}
		checksum := hex.EncodeToString(cipher[:16])
		edata := hex.EncodeToString(cipher[16:])
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
			etype, username, hashDomain, spn, checksum, edata)
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		if len(cipher) < 12 {
			return ""
		}
		checksum := hex.EncodeToString(cipher[len(cipher)-12:])
		edata := hex.EncodeToString(cipher[:len(cipher)-12])
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype, username, hashDomain, spn, checksum, edata)
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		if len(cipher) < 12 {
			return ""
		}
		checksum := hex.EncodeToString(cipher[len(cipher)-12:])
		edata := hex.EncodeToString(cipher[:len(cipher)-12])
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype, username, hashDomain, spn, checksum, edata)
	case etypeID.DES_CBC_MD5:
		if len(cipher) < 16 {
			return ""
		}
		checksum := hex.EncodeToString(cipher[:16])
		edata := hex.EncodeToString(cipher[16:])
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
			etype, username, hashDomain, spn, checksum, edata)
	}

	return ""
}

func parseUint32(s string) uint32 {
	var v uint32
	fmt.Sscanf(s, "%d", &v)
	return v
}

// Well-known RID to name mapping (matches Impacket's MsBuiltInGroups)
func ridName(rid uint32) string {
	names := map[uint32]string{
		498: "Enterprise Read-Only Domain Controllers",
		512: "Domain Admins",
		513: "Domain Users",
		514: "Domain Guests",
		515: "Domain Computers",
		516: "Domain Controllers",
		517: "Cert Publishers",
		518: "Schema Admins",
		519: "Enterprise Admins",
		520: "Group Policy Creator Owners",
		521: "Read-Only Domain Controllers",
		522: "Cloneable Controllers",
		525: "Protected Users",
		526: "Key Admins",
		527: "Enterprise Key Admins",
		553: "RAS and IAS Servers",
		571: "Allowed RODC Password Replication Group",
		572: "Denied RODC Password Replication Group",
	}
	if name, ok := names[rid]; ok {
		return name
	}
	return ""
}

// Well-known SID to name mapping (matches Impacket's MsBuiltInGroups)
func sidName(sid string) string {
	names := map[string]string{
		"S-1-1-0":      "Everyone",
		"S-1-2-0":      "Local",
		"S-1-2-1":      "Console Logon",
		"S-1-3-0":      "Creator Owner",
		"S-1-3-1":      "Creator Group",
		"S-1-3-2":      "Owner Server",
		"S-1-3-3":      "Group Server",
		"S-1-3-4":      "Owner Rights",
		"S-1-5-1":      "Dialup",
		"S-1-5-2":      "Network",
		"S-1-5-3":      "Batch",
		"S-1-5-4":      "Interactive",
		"S-1-5-6":      "Service",
		"S-1-5-7":      "Anonymous Logon",
		"S-1-5-8":      "Proxy",
		"S-1-5-9":      "Enterprise Domain Controllers",
		"S-1-5-10":     "Self",
		"S-1-5-11":     "Authenticated Users",
		"S-1-5-12":     "Restricted Code",
		"S-1-5-13":     "Terminal Server User",
		"S-1-5-14":     "Remote Interactive Logon",
		"S-1-5-15":     "This Organization",
		"S-1-5-17":     "IUSR",
		"S-1-5-18":     "System (or LocalSystem)",
		"S-1-5-19":     "NT Authority (LocalService)",
		"S-1-5-20":     "Network Service",
		"S-1-5-32-544": "Administrators",
		"S-1-5-32-545": "Users",
		"S-1-5-32-546": "Guests",
		"S-1-5-32-547": "Power Users",
		"S-1-5-32-548": "Account Operators",
		"S-1-5-32-549": "Server Operators",
		"S-1-5-32-550": "Print Operators",
		"S-1-5-32-551": "Backup Operators",
		"S-1-5-32-552": "Replicators",
		"S-1-5-32-554": "Builtin\\Pre-Windows",
		"S-1-5-32-555": "Builtin\\Remote Desktop Users",
		"S-1-5-32-556": "Builtin\\Network Configuration Operators",
		"S-1-5-32-557": "Builtin\\Incoming Forest Trust Builders",
		"S-1-5-32-558": "Builtin\\Performance Monitor Users",
		"S-1-5-32-559": "Builtin\\Performance Log Users",
		"S-1-5-32-560": "Builtin\\Windows Authorization Access Group",
		"S-1-5-32-561": "Builtin\\Terminal Server License Servers",
		"S-1-5-32-562": "Builtin\\Distributed COM Users",
		"S-1-5-32-568": "Builtin\\IIS_IUSRS",
		"S-1-5-32-569": "Builtin\\Cryptographic Operators",
		"S-1-5-32-573": "Builtin\\Event Log Readers",
		"S-1-5-32-574": "Builtin\\Certificate Service DCOM Access",
		"S-1-5-32-575": "Builtin\\RDS Remote Access Servers",
		"S-1-5-32-576": "Builtin\\RDS Endpoint Servers",
		"S-1-5-32-577": "Builtin\\RDS Management Servers",
		"S-1-5-32-578": "Builtin\\Hyper-V Administrators",
		"S-1-5-32-579": "Builtin\\Access Control Assistance Operators",
		"S-1-5-32-580": "Builtin\\Remote Management Users",
		"S-1-5-64-10":  "NTLM Authentication",
		"S-1-5-64-14":  "SChannel Authentication",
		"S-1-5-64-21":  "Digest Authentication",
		"S-1-5-80":     "NT Service",
		"S-1-5-80-0":   "All Services",
		"S-1-5-83-0":   "NT VIRTUAL MACHINE\\Virtual Machines",
		"S-1-5-113":    "Local Account",
		"S-1-5-114":    "Local Account and member of Administrators group",
		"S-1-5-1000":   "Other Organization",
		"S-1-15-2-1":   "All app packages",
		"S-1-16-0":     "ML Untrusted",
		"S-1-16-4096":  "ML Low",
		"S-1-16-8192":  "ML Medium",
		"S-1-16-8448":  "ML Medium Plus",
		"S-1-16-12288": "ML High",
		"S-1-16-16384": "ML System",
		"S-1-16-20480": "ML Protected Process",
		"S-1-16-28672": "ML Secure Process",
		"S-1-18-1":     "Authentication authority asserted identity",
		"S-1-18-2":     "Service asserted identity",
		"S-1-18-3":     "Fresh public key identity",
		"S-1-18-4":     "Key trust identity",
		"S-1-18-5":     "Key property MFA",
		"S-1-18-6":     "Key property attestation",
	}
	if name, ok := names[sid]; ok {
		return name
	}
	return ""
}

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

func printUsage() {
	fmt.Println("gopacket v0.1.0 - describeTicket")
	fmt.Println()
	fmt.Println("Parses a ccache ticket file and displays credential information.")
	fmt.Println("With a decryption key, decrypts the ticket and shows the full PAC.")
	fmt.Println()
	fmt.Println("Usage: describeTicket [options] ticket.ccache")
	fmt.Println()
	fmt.Println("Positional:")
	fmt.Println("  ticket                Path to the .ccache ticket file")
	fmt.Println()
	fmt.Println("Decryption (optional):")
	fmt.Println("  -p PASSWORD           Cleartext password of the service account")
	fmt.Println("  -hp HEXPASSWORD       Hex password of the service account")
	fmt.Println("  -u USER               Service account name (for salt derivation)")
	fmt.Println("  -d DOMAIN             FQDN domain (for salt derivation)")
	fmt.Println("  -s SALT               Explicit salt for key derivation")
	fmt.Println("  -rc4 KEY              RC4/NT hash hex key")
	fmt.Println("  -aes KEY              AES128 or AES256 hex key")
	fmt.Println("  -aesKey KEY           AES key (alias for -aes)")
	fmt.Println("  --asrep-key KEY       AS-REP key for PAC_CREDENTIALS_INFO decryption")
	fmt.Println()
	fmt.Println("General:")
	fmt.Println("  -debug                Debug output")
	fmt.Println("  -ts                   Timestamps on logging")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  describeTicket administrator.ccache")
	fmt.Println("  describeTicket -aesKey <krbtgt_aes256> administrator.ccache")
	fmt.Println("  describeTicket -rc4 <nthash> administrator.ccache")
	fmt.Println("  describeTicket -p Password123 -u krbtgt -d domain.local administrator.ccache")
	fmt.Println()

	// Suppress unused variable warnings
	_ = debug
	_ = timestamps
	_ = types.NewKrbFlags
}
