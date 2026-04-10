// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/samr"
	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	computerName  = flag.String("computer-name", "", "Name of the computer account to add (default: random)")
	computerPass  = flag.String("computer-pass", "", "Password for the computer account (default: random)")
	method        = flag.String("method", "SAMR", "Method to use: SAMR or LDAPS")
	baseDN        = flag.String("baseDN", "", "Specify the baseDN for LDAP (default: auto from domain)")
	computerGroup = flag.String("computer-group", "", "Group to add the computer to (LDAP method, default: CN=Computers)")
	noAdd         = flag.Bool("no-add", false, "Don't add a new computer, just set the password on an existing one")
	deleteAcct    = flag.Bool("delete", false, "Delete an existing computer")
	domainNetbios = flag.String("domain-netbios", "", "Domain NetBIOS name. Required if the DC has multiple domains.")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	// Generate random computer name if not specified
	if *computerName == "" && !*deleteAcct && !*noAdd {
		*computerName = generateRandomName()
	}
	if *computerName == "" && (*deleteAcct || *noAdd) {
		log.Fatalf("[-] -computer-name is required when using -delete or -no-add")
	}
	// Strip trailing $ for display, add it where needed
	displayName := strings.TrimSuffix(*computerName, "$")

	// Generate random password if not specified
	if *computerPass == "" && !*deleteAcct {
		*computerPass = generateRandomPassword()
	}

	methodUpper := strings.ToUpper(*method)
	switch methodUpper {
	case "SAMR":
		doSAMR(opts, target, creds, displayName)
	case "LDAP", "LDAPS":
		doLDAP(opts, target, creds, displayName)
	default:
		log.Fatalf("[-] Unknown method: %s (use SAMR or LDAPS)", *method)
	}
}

func doSAMR(opts *flags.Options, target session.Target, creds session.Credentials, name string) {
	if target.Port == 0 {
		target.Port = 445
	}

	fmt.Printf("[*] Connecting to %s via SMB...\n", target.Addr())
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		log.Fatalf("[-] SMB connection failed: %v", err)
	}
	defer smbClient.Close()
	fmt.Println("[+] SMB session established.")

	// Get SMB session key for password encryption
	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		log.Fatalf("[-] Failed to obtain SMB session key")
	}

	// Open SAMR pipe
	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		log.Fatalf("[-] Failed to open SAMR pipe: %v", err)
	}

	// Create RPC client and bind
	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		log.Fatalf("[-] SAMR bind failed: %v", err)
	}
	fmt.Println("[+] SAMR bind successful.")

	// Create SAMR client
	samrClient := samr.NewSamrClient(rpcClient, sessionKey)

	// Connect to SAM
	if err := samrClient.Connect(); err != nil {
		log.Fatalf("[-] SamrConnect5 failed: %v", err)
	}
	defer samrClient.Close()

	// Determine the domain NetBIOS name to use for SAMR domain selection.
	// Matches Impacket behavior: enumerate domains, filter Builtin, use -domain-netbios
	// to disambiguate when the DC manages multiple domains.
	netbiosName := *domainNetbios
	if netbiosName == "" {
		netbiosName = creds.Domain
	}
	if netbiosName == "" {
		log.Fatalf("[-] Domain name required (specify as domain/user:pass@target)")
	}

	// Enumerate domains on the SAM server and select the right one
	domains, err := samrClient.EnumerateDomains()
	if err != nil {
		log.Fatalf("[-] Failed to enumerate domains: %v", err)
	}

	// Filter out "Builtin"
	var nonBuiltin []string
	for _, d := range domains {
		if !strings.EqualFold(d, "Builtin") {
			nonBuiltin = append(nonBuiltin, d)
		}
	}

	var selectedDomain string
	if len(nonBuiltin) > 1 {
		// Multiple domains — must match by NetBIOS name
		for _, d := range nonBuiltin {
			if strings.EqualFold(d, netbiosName) {
				selectedDomain = d
				break
			}
		}
		if selectedDomain == "" {
			fmt.Fprintf(os.Stderr, "[-] This server provides multiple domains and '%s' isn't one of them.\n", netbiosName)
			fmt.Fprintf(os.Stderr, "[-] Available domain(s):\n")
			for _, d := range domains {
				fmt.Fprintf(os.Stderr, "    * %s\n", d)
			}
			fmt.Fprintf(os.Stderr, "[-] Consider using -domain-netbios argument to specify which one you meant.\n")
			os.Exit(1)
		}
	} else if len(nonBuiltin) == 1 {
		selectedDomain = nonBuiltin[0]
	} else {
		log.Fatalf("[-] No non-Builtin domains found on the server")
	}

	if err := samrClient.OpenDomain(selectedDomain); err != nil {
		log.Fatalf("[-] Failed to open domain %s: %v", selectedDomain, err)
	}

	samrName := name + "$"

	if *deleteAcct {
		if err := samrClient.DeleteComputer(name); err != nil {
			log.Fatalf("[-] Failed to delete %s: %v", samrName, err)
		}
		fmt.Printf("[*] Successfully deleted %s.\n", samrName)
	} else if *noAdd {
		if err := samrClient.SetComputerPassword(name, *computerPass); err != nil {
			log.Fatalf("[-] Failed to set password of %s: %v", samrName, err)
		}
		fmt.Printf("[*] Successfully set password of %s to %s.\n", samrName, *computerPass)
	} else {
		// Check if account already exists
		if samrClient.AccountExists(name) {
			log.Fatalf("[-] Account %s already exists! If you want to change the password use -no-add.", samrName)
		}

		if err := samrClient.CreateComputer(name, *computerPass); err != nil {
			if strings.Contains(err.Error(), "0xc0000022") {
				log.Fatalf("[-] The user does not have the right to create a machine account. Machine account quota may have been exceeded.")
			}
			log.Fatalf("[-] Failed to create %s: %v", samrName, err)
		}
		fmt.Printf("[*] Successfully added machine account %s with password %s.\n", samrName, *computerPass)
	}
}

func doLDAP(opts *flags.Options, target session.Target, creds session.Credentials, name string) {
	if target.Port == 0 {
		target.Port = 636
	}

	fmt.Printf("[*] Connecting to %s via LDAPS...\n", target.Addr())
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(true); err != nil {
		log.Fatalf("[-] LDAPS connection failed: %v", err)
	}

	// Login
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	fmt.Printf("[*] Binding as %s...\n", creds.Username)
	if err := client.Login(); err != nil {
		log.Fatalf("[-] LDAP bind failed: %v", err)
	}
	fmt.Println("[+] LDAP bind successful.")

	// Get base DN
	domainBase := *baseDN
	if domainBase == "" {
		var err error
		domainBase, err = client.GetDefaultNamingContext()
		if err != nil {
			log.Fatalf("[-] Failed to get base DN: %v", err)
		}
	}

	// Determine computer container
	container := "CN=Computers"
	if *computerGroup != "" {
		container = *computerGroup
	}

	samrName := name + "$"
	computerDN := fmt.Sprintf("CN=%s,%s,%s", name, container, domainBase)

	if *deleteAcct {
		if err := client.Delete(computerDN); err != nil {
			log.Fatalf("[-] Failed to delete %s: %v", samrName, err)
		}
		fmt.Printf("[*] Successfully deleted %s.\n", samrName)
	} else if *noAdd {
		// Modify password on existing account
		quotedPwd := fmt.Sprintf("\"%s\"", *computerPass)
		encodedPwd := encodeUTF16LE(quotedPwd)

		changes := []ldap.ModifyChange{
			{Operation: 2, AttrName: "unicodePwd", AttrVals: []string{string(encodedPwd)}}, // ReplaceAttribute = 2
		}
		if err := client.Modify(computerDN, changes); err != nil {
			log.Fatalf("[-] Failed to set password of %s: %v", samrName, err)
		}
		fmt.Printf("[*] Successfully set password of %s to %s.\n", samrName, *computerPass)
	} else {
		// Check if account already exists
		filter := fmt.Sprintf("(sAMAccountName=%s)", samrName)
		result, err := client.Search(domainBase, filter, []string{"dn"})
		if err == nil && len(result.Entries) > 0 {
			log.Fatalf("[-] Account %s already exists! If you want to change the password use -no-add.", samrName)
		}

		// Build the domain name from base DN for DNS attributes
		domainParts := parseDNToDomain(domainBase)
		fqdn := fmt.Sprintf("%s.%s", name, domainParts)

		// Encode password as UTF-16LE quoted string for unicodePwd
		quotedPwd := fmt.Sprintf("\"%s\"", *computerPass)
		encodedPwd := encodeUTF16LE(quotedPwd)

		attrs := map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":     {samrName},
			"userAccountControl": {"4096"},
			"dNSHostName":        {fqdn},
			"servicePrincipalName": {
				"HOST/" + name,
				"HOST/" + fqdn,
				"RestrictedKrbHost/" + name,
				"RestrictedKrbHost/" + fqdn,
			},
			"unicodePwd": {string(encodedPwd)},
		}

		if err := client.Add(computerDN, attrs); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "Unwilling To Perform") || strings.Contains(errStr, "0x216D") {
				log.Fatalf("[-] Failed to add %s: machine account quota exceeded!", samrName)
			}
			if strings.Contains(errStr, "Insufficient Access") {
				log.Fatalf("[-] The user does not have sufficient access rights to create a machine account.")
			}
			log.Fatalf("[-] Failed to create %s: %v", samrName, err)
		}
		fmt.Printf("[*] Successfully added machine account %s with password %s.\n", samrName, *computerPass)
	}
}

// parseDNToDomain converts "DC=corp,DC=local" to "corp.local"
func parseDNToDomain(dn string) string {
	var parts []string
	for _, component := range strings.Split(dn, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.Join(parts, ".")
}

// encodeUTF16LE encodes a string as UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	utf16Chars := utf16.Encode([]rune(s))
	b := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// generateRandomName creates a random computer name like "DESKTOP-XXXXXXXX"
func generateRandomName() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return "DESKTOP-" + string(b)
}

// generateRandomPassword creates a random 32-character password.
func generateRandomPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
