package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/security"
	"gopacket/pkg/session"

	goldap "github.com/go-ldap/ldap/v3"
)

// Rights presets
type rightsPreset struct {
	ACEType    uint8
	Mask       uint32
	ObjectType *security.GUID // nil means standard ACE
}

var rightsPresets = map[string][]rightsPreset{
	"fullcontrol": {
		{ACEType: security.ACCESS_ALLOWED_ACE_TYPE, Mask: security.FULL_CONTROL},
	},
	"genericall": {
		{ACEType: security.ACCESS_ALLOWED_ACE_TYPE, Mask: security.GENERIC_ALL},
	},
	"dcsync": {
		{ACEType: security.ACCESS_ALLOWED_OBJECT_ACE_TYPE, Mask: security.DS_CONTROL_ACCESS, ObjectType: &security.GUID_DS_REPLICATION_GET_CHANGES},
		{ACEType: security.ACCESS_ALLOWED_OBJECT_ACE_TYPE, Mask: security.DS_CONTROL_ACCESS, ObjectType: &security.GUID_DS_REPLICATION_GET_CHANGES_ALL},
	},
	"writemembers": {
		{ACEType: security.ACCESS_ALLOWED_OBJECT_ACE_TYPE, Mask: security.DS_WRITE_PROP, ObjectType: &security.GUID_WRITE_MEMBERS},
	},
	"resetpassword": {
		{ACEType: security.ACCESS_ALLOWED_OBJECT_ACE_TYPE, Mask: security.DS_CONTROL_ACCESS, ObjectType: &security.GUID_RESET_PASSWORD},
	},
	"writedacl": {
		{ACEType: security.ACCESS_ALLOWED_ACE_TYPE, Mask: security.WRITE_DAC},
	},
	"writeowner": {
		{ACEType: security.ACCESS_ALLOWED_ACE_TYPE, Mask: security.WRITE_OWNER},
	},
}

// Backup format
type backupEntry struct {
	DN  string `json:"dn"`
	SD  string `json:"sd"` // hex-encoded raw SD
}

func main() {
	// Tool-specific flags
	action := flag.String("action", "read", "Action to perform: read, write, remove, backup, restore")
	targetObj := flag.String("target", "", "Target object (sAMAccountName) whose DACL to edit")
	targetSID := flag.String("target-sid", "", "Target object SID")
	targetDN := flag.String("target-dn", "", "Target object DN")
	principal := flag.String("principal", "", "Object, controlled by the attacker, to reference in the ACE (sAMAccountName)")
	principalSID := flag.String("principal-sid", "", "Principal SID")
	principalDN := flag.String("principal-dn", "", "Principal DN")
	rights := flag.String("rights", "", "Rights to grant: FullControl, DCSync, WriteMembers, ResetPassword, WriteDacl, WriteOwner, GenericAll, Custom")
	rightsGUID := flag.String("rights-guid", "", "Custom GUID for extended rights")
	aceType := flag.String("ace-type", "allowed", "ACE type: allowed or denied")
	inheritance := flag.Bool("inheritance", false, "Set CONTAINER_INHERIT and OBJECT_INHERIT flags")
	mask := flag.String("mask", "", "Force access mask: readwrite, write, self, allext, or hex (e.g. 0xFF)")
	backupFile := flag.String("file", "", "Backup/restore filename")
	useLDAPS := flag.Bool("use-ldaps", false, "Use LDAPS (port 636)")

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

	fmt.Printf("[*] Connecting to %s...\n", target.Addr())
	if err := client.Connect(*useLDAPS); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	// Login
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	fmt.Printf("[*] Binding as %s...\n", creds.Username)
	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}
	fmt.Println("[+] Bind successful.")

	// Get base DN
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get Naming Context: %v", err)
	}

	// Resolve target DN
	resolvedTargetDN, err := resolveTargetDN(client, baseDN, *targetObj, *targetSID, *targetDN)
	if err != nil {
		log.Fatalf("[-] Failed to resolve target: %v", err)
	}
	fmt.Printf("[*] Target DN: %s\n", resolvedTargetDN)

	// Parse -mask flag
	var forceMask *uint32
	if *mask != "" {
		m, err := parseMask(*mask)
		if err != nil {
			log.Fatalf("[-] Invalid mask value: %v", err)
		}
		forceMask = &m
	}

	switch strings.ToLower(*action) {
	case "read":
		doRead(client, resolvedTargetDN, *principal, *principalSID, *principalDN, baseDN)
	case "write":
		doWrite(client, baseDN, resolvedTargetDN, *principal, *principalSID, *principalDN, *rights, *rightsGUID, *aceType, *inheritance, *backupFile, forceMask)
	case "remove":
		doRemove(client, baseDN, resolvedTargetDN, *principal, *principalSID, *principalDN, *rights, *rightsGUID, *backupFile, forceMask)
	case "backup":
		doBackup(client, resolvedTargetDN, *backupFile)
	case "restore":
		doRestore(client, resolvedTargetDN, *backupFile)
	default:
		log.Fatalf("[-] Unknown action: %s", *action)
	}
}

func resolveTargetDN(client *ldap.Client, baseDN, targetName, targetSIDStr, targetDNStr string) (string, error) {
	if targetDNStr != "" {
		return targetDNStr, nil
	}

	var filter string
	if targetSIDStr != "" {
		// Convert SID string to binary for search
		sid, err := security.ParseSID(targetSIDStr)
		if err != nil {
			return "", fmt.Errorf("invalid SID: %v", err)
		}
		sidHex := hexEscapeBinary(sid.Marshal())
		filter = fmt.Sprintf("(objectSid=%s)", sidHex)
	} else if targetName != "" {
		filter = fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(targetName))
	} else {
		return "", fmt.Errorf("no target specified: use -target, -target-sid, or -target-dn")
	}

	results, err := client.Search(baseDN, filter, []string{"distinguishedName"})
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %v", err)
	}
	if len(results.Entries) == 0 {
		return "", fmt.Errorf("target not found")
	}

	return results.Entries[0].DN, nil
}

func resolvePrincipalSID(client *ldap.Client, baseDN, principalName, principalSIDStr, principalDNStr string) (*security.SID, error) {
	if principalSIDStr != "" {
		return security.ParseSID(principalSIDStr)
	}

	var filter string
	if principalDNStr != "" {
		filter = fmt.Sprintf("(distinguishedName=%s)", goldap.EscapeFilter(principalDNStr))
	} else if principalName != "" {
		filter = fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(principalName))
	} else {
		return nil, fmt.Errorf("no principal specified: use -principal, -principal-sid, or -principal-dn")
	}

	results, err := client.Search(baseDN, filter, []string{"objectSid"})
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}
	if len(results.Entries) == 0 {
		return nil, fmt.Errorf("principal not found")
	}

	sidRaw := results.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidRaw) == 0 {
		return nil, fmt.Errorf("principal has no objectSid")
	}

	sid, _, err := security.ParseSIDBytes(sidRaw)
	return sid, err
}

func fetchSecurityDescriptor(client *ldap.Client, targetDN string) ([]byte, error) {
	sdControl := ldap.NewControlMicrosoftSDFlags(security.DACL_SECURITY_INFORMATION | security.OWNER_SECURITY_INFORMATION | security.GROUP_SECURITY_INFORMATION)
	results, err := client.SearchWithControls(
		targetDN,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]goldap.Control{sdControl},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to read nTSecurityDescriptor: %v", err)
	}
	if len(results.Entries) == 0 {
		return nil, fmt.Errorf("target not found when reading SD")
	}

	sdRaw := results.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdRaw) == 0 {
		return nil, fmt.Errorf("nTSecurityDescriptor is empty")
	}
	return sdRaw, nil
}

func writeSecurityDescriptor(client *ldap.Client, targetDN string, sdBytes []byte) error {
	sdControl := ldap.NewControlMicrosoftSDFlags(security.DACL_SECURITY_INFORMATION)
	return client.ModifyRaw(targetDN, goldap.ReplaceAttribute, "nTSecurityDescriptor", sdBytes, []goldap.Control{sdControl})
}

func doRead(client *ldap.Client, targetDN, principalName, principalSIDStr, principalDNStr, baseDN string) {
	sdRaw, err := fetchSecurityDescriptor(client, targetDN)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	sd, err := security.ParseSecurityDescriptor(sdRaw)
	if err != nil {
		log.Fatalf("[-] Failed to parse security descriptor: %v", err)
	}

	if sd.DACL == nil {
		fmt.Println("[!] No DACL present on this object.")
		return
	}

	// Resolve principal SID for filtering if specified
	var filterSID *security.SID
	if principalName != "" || principalSIDStr != "" || principalDNStr != "" {
		filterSID, err = resolvePrincipalSID(client, baseDN, principalName, principalSIDStr, principalDNStr)
		if err != nil {
			log.Fatalf("[-] Failed to resolve principal: %v", err)
		}
		fmt.Printf("[*] Filtering by principal SID: %s\n", filterSID.String())
	}

	resolver := newSIDResolver(client, baseDN)

	fmt.Printf("\n[+] DACL for %s (%d ACEs):\n", targetDN, len(sd.DACL.ACEs))
	displayed := 0
	for i, ace := range sd.DACL.ACEs {
		if filterSID != nil && !ace.SID.Equal(filterSID) {
			continue
		}
		fmt.Printf("\n  ACE[%d]:\n", i)
		fmt.Println(security.FormatACE(ace, resolver.Resolve))
		displayed++
	}

	if filterSID != nil {
		fmt.Printf("\n[*] Displayed %d/%d ACEs matching principal.\n", displayed, len(sd.DACL.ACEs))
	}
}

func doWrite(client *ldap.Client, baseDN, targetDN, principalName, principalSIDStr, principalDNStr, rightsStr, rightsGUIDStr, aceTypeStr string, inheritance bool, backupFile string, forceMask *uint32) {
	// Resolve principal
	principalSID, err := resolvePrincipalSID(client, baseDN, principalName, principalSIDStr, principalDNStr)
	if err != nil {
		log.Fatalf("[-] Failed to resolve principal: %v", err)
	}
	fmt.Printf("[*] Principal SID: %s\n", principalSID.String())

	// Build ACEs based on rights
	aces, err := buildACEs(principalSID, rightsStr, rightsGUIDStr, aceTypeStr, inheritance, forceMask)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	// Fetch current SD
	sdRaw, err := fetchSecurityDescriptor(client, targetDN)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	// Auto-backup before modification
	autoBackup(targetDN, sdRaw, backupFile)

	sd, err := security.ParseSecurityDescriptor(sdRaw)
	if err != nil {
		log.Fatalf("[-] Failed to parse security descriptor: %v", err)
	}

	if sd.DACL == nil {
		sd.DACL = &security.ACL{AclRevision: 4}
		sd.Control |= security.SE_DACL_PRESENT
	}

	// Append ACEs
	for _, ace := range aces {
		sd.DACL.AddACE(ace)
	}

	// Write back
	newSD := sd.Marshal()
	if err := writeSecurityDescriptor(client, targetDN, newSD); err != nil {
		log.Fatalf("[-] Failed to write security descriptor: %v", err)
	}

	fmt.Printf("[+] Successfully added %d ACE(s) to %s\n", len(aces), targetDN)
}

func doRemove(client *ldap.Client, baseDN, targetDN, principalName, principalSIDStr, principalDNStr, rightsStr, rightsGUIDStr, backupFile string, forceMask *uint32) {
	// Resolve principal
	principalSID, err := resolvePrincipalSID(client, baseDN, principalName, principalSIDStr, principalDNStr)
	if err != nil {
		log.Fatalf("[-] Failed to resolve principal: %v", err)
	}
	fmt.Printf("[*] Principal SID: %s\n", principalSID.String())

	// Determine what to match
	presets, objectGUID, err := resolveRights(rightsStr, rightsGUIDStr)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	// Fetch current SD
	sdRaw, err := fetchSecurityDescriptor(client, targetDN)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	// Auto-backup before modification
	autoBackup(targetDN, sdRaw, backupFile)

	sd, err := security.ParseSecurityDescriptor(sdRaw)
	if err != nil {
		log.Fatalf("[-] Failed to parse security descriptor: %v", err)
	}

	if sd.DACL == nil {
		fmt.Println("[!] No DACL present, nothing to remove.")
		return
	}

	// Handle -rights Custom -mask: match a standard ACE with the forced mask
	isCustom := strings.EqualFold(rightsStr, "custom") && forceMask != nil && rightsGUIDStr == ""

	// Find and remove matching ACEs (iterate backward to preserve indices)
	removed := 0
	if isCustom {
		for i := len(sd.DACL.ACEs) - 1; i >= 0; i-- {
			ace := sd.DACL.ACEs[i]
			if ace.SID.Equal(principalSID) && (ace.Mask&*forceMask) == *forceMask {
				sd.DACL.RemoveACE(i)
				removed++
			}
		}
	} else if len(presets) > 0 {
		for _, preset := range presets {
			matchMask := preset.Mask
			if forceMask != nil {
				matchMask = *forceMask
			}
			for i := len(sd.DACL.ACEs) - 1; i >= 0; i-- {
				ace := sd.DACL.ACEs[i]
				if ace.SID.Equal(principalSID) && (ace.Mask&matchMask) == matchMask {
					if preset.ObjectType != nil {
						if ace.ObjectType != *preset.ObjectType {
							continue
						}
					}
					sd.DACL.RemoveACE(i)
					removed++
				}
			}
		}
	} else if objectGUID != nil {
		matchMask := uint32(security.DS_CONTROL_ACCESS)
		if forceMask != nil {
			matchMask = *forceMask
		}
		for i := len(sd.DACL.ACEs) - 1; i >= 0; i-- {
			ace := sd.DACL.ACEs[i]
			if ace.SID.Equal(principalSID) && ace.ObjectType == *objectGUID && (ace.Mask&matchMask) == matchMask {
				sd.DACL.RemoveACE(i)
				removed++
			}
		}
	} else {
		// Remove all ACEs for this principal
		for i := len(sd.DACL.ACEs) - 1; i >= 0; i-- {
			if sd.DACL.ACEs[i].SID.Equal(principalSID) {
				sd.DACL.RemoveACE(i)
				removed++
			}
		}
	}

	if removed == 0 {
		fmt.Println("[!] No matching ACEs found to remove.")
		return
	}

	// Write back
	newSD := sd.Marshal()
	if err := writeSecurityDescriptor(client, targetDN, newSD); err != nil {
		log.Fatalf("[-] Failed to write security descriptor: %v", err)
	}

	fmt.Printf("[+] Successfully removed %d ACE(s) from %s\n", removed, targetDN)
}

func doBackup(client *ldap.Client, targetDN, filename string) {
	if filename == "" {
		filename = "dacledit_backup.json"
	}

	sdRaw, err := fetchSecurityDescriptor(client, targetDN)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	entry := backupEntry{
		DN: targetDN,
		SD: hex.EncodeToString(sdRaw),
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		log.Fatalf("[-] Failed to marshal backup: %v", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		log.Fatalf("[-] Failed to write backup file: %v", err)
	}

	fmt.Printf("[+] Security descriptor backed up to %s\n", filename)
}

func doRestore(client *ldap.Client, targetDN, filename string) {
	if filename == "" {
		filename = "dacledit_backup.json"
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("[-] Failed to read backup file: %v", err)
	}

	var entry backupEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		log.Fatalf("[-] Failed to parse backup file: %v", err)
	}

	sdBytes, err := hex.DecodeString(entry.SD)
	if err != nil {
		log.Fatalf("[-] Failed to decode SD hex: %v", err)
	}

	// Use the DN from backup if target not explicitly specified
	dn := targetDN
	if dn == "" {
		dn = entry.DN
	}

	if err := writeSecurityDescriptor(client, dn, sdBytes); err != nil {
		log.Fatalf("[-] Failed to restore security descriptor: %v", err)
	}

	fmt.Printf("[+] Security descriptor restored to %s from %s\n", dn, filename)
}

func buildACEs(principalSID *security.SID, rightsStr, rightsGUIDStr, aceTypeStr string, inheritance bool, forceMask *uint32) ([]*security.ACE, error) {
	presets, objectGUID, err := resolveRights(rightsStr, rightsGUIDStr)
	if err != nil {
		return nil, err
	}

	// Determine ACE type override
	var aceTypeOverride *uint8
	switch strings.ToLower(aceTypeStr) {
	case "allowed":
		// Use preset defaults
	case "denied":
		denied := uint8(security.ACCESS_DENIED_ACE_TYPE)
		aceTypeOverride = &denied
	default:
		return nil, fmt.Errorf("invalid ace-type: %s (use 'allowed' or 'denied')", aceTypeStr)
	}

	var aceFlags uint8
	if inheritance {
		aceFlags = security.CONTAINER_INHERIT_ACE | security.OBJECT_INHERIT_ACE
	}

	var aces []*security.ACE

	// Handle -rights Custom with -mask: create a standard (non-object) ACE with the forced mask
	if strings.EqualFold(rightsStr, "custom") && forceMask != nil && rightsGUIDStr == "" {
		aceType := uint8(security.ACCESS_ALLOWED_ACE_TYPE)
		if aceTypeOverride != nil {
			aceType = *aceTypeOverride
		}
		aces = append(aces, &security.ACE{
			Type:  aceType,
			Flags: aceFlags,
			Mask:  *forceMask,
			SID:   principalSID,
		})
		return aces, nil
	}

	if len(presets) > 0 {
		for _, preset := range presets {
			ace := &security.ACE{
				Type:  preset.ACEType,
				Flags: aceFlags,
				Mask:  preset.Mask,
				SID:   principalSID,
			}
			// Apply force mask override
			if forceMask != nil {
				ace.Mask = *forceMask
			}
			if aceTypeOverride != nil {
				if preset.ObjectType != nil {
					// Object ACE denied variant
					ace.Type = security.ACCESS_DENIED_OBJECT_ACE_TYPE
				} else {
					ace.Type = *aceTypeOverride
				}
			}
			if preset.ObjectType != nil {
				ace.ObjectType = *preset.ObjectType
				ace.ObjectFlags = security.ACE_OBJECT_TYPE_PRESENT
			}
			aces = append(aces, ace)
		}
	} else if objectGUID != nil {
		aceType := uint8(security.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
		if aceTypeOverride != nil {
			aceType = security.ACCESS_DENIED_OBJECT_ACE_TYPE
		}
		aceMask := uint32(security.DS_CONTROL_ACCESS)
		if forceMask != nil {
			aceMask = *forceMask
		}
		aces = append(aces, &security.ACE{
			Type:        aceType,
			Flags:       aceFlags,
			Mask:        aceMask,
			ObjectFlags: security.ACE_OBJECT_TYPE_PRESENT,
			ObjectType:  *objectGUID,
			SID:         principalSID,
		})
	} else {
		return nil, fmt.Errorf("no rights specified: use -rights or -rights-guid")
	}

	return aces, nil
}

func resolveRights(rightsStr, rightsGUIDStr string) ([]rightsPreset, *security.GUID, error) {
	if rightsStr != "" {
		key := strings.ToLower(rightsStr)
		// "custom" is valid with -mask and/or -rights-guid, not a preset
		if key == "custom" {
			return nil, nil, nil
		}
		presets, ok := rightsPresets[key]
		if !ok {
			valid := make([]string, 0, len(rightsPresets)+1)
			for k := range rightsPresets {
				valid = append(valid, k)
			}
			valid = append(valid, "custom")
			return nil, nil, fmt.Errorf("unknown rights preset '%s'. Valid: %s", rightsStr, strings.Join(valid, ", "))
		}
		return presets, nil, nil
	}

	if rightsGUIDStr != "" {
		g, err := security.ParseGUID(rightsGUIDStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid rights-guid: %v", err)
		}
		return nil, &g, nil
	}

	return nil, nil, nil
}

func autoBackup(targetDN string, sdRaw []byte, backupFile string) {
	filename := backupFile
	if filename == "" {
		filename = "dacledit_backup.json"
	}

	entry := backupEntry{
		DN: targetDN,
		SD: hex.EncodeToString(sdRaw),
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Printf("[!] Warning: failed to create backup: %v\n", err)
		return
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		fmt.Printf("[!] Warning: failed to write backup file: %v\n", err)
		return
	}

	fmt.Printf("[*] Auto-backup saved to %s\n", filename)
}

// parseMask parses a mask value from the -mask flag.
// Supported named values: readwrite, write, self, allext.
// Also supports hex values like 0xFF.
func parseMask(s string) (uint32, error) {
	switch strings.ToLower(s) {
	case "readwrite":
		return security.DS_READ_PROP | security.DS_WRITE_PROP, nil // 0x30
	case "write":
		return security.DS_WRITE_PROP, nil // 0x20
	case "self":
		return security.DS_SELF, nil // 0x08
	case "allext":
		return security.DS_CONTROL_ACCESS, nil // 0x100
	default:
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			v, err := strconv.ParseUint(s[2:], 16, 32)
			if err != nil {
				return 0, fmt.Errorf("invalid hex mask '%s': %v", s, err)
			}
			return uint32(v), nil
		}
		return 0, fmt.Errorf("unknown mask '%s': use readwrite, write, self, allext, or a hex value (e.g. 0xFF)", s)
	}
}

func hexEscapeBinary(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	return b.String()
}

// sidResolver resolves SIDs to human-readable names via well-known tables and LDAP lookup.
type sidResolver struct {
	client    *ldap.Client
	baseDN    string
	domainSID string // domain SID prefix (e.g., "S-1-5-21-xxx-yyy-zzz")
	cache     map[string]string
}

func newSIDResolver(client *ldap.Client, baseDN string) *sidResolver {
	r := &sidResolver{
		client: client,
		baseDN: baseDN,
		cache:  make(map[string]string),
	}
	// Determine domain SID by looking up the domain object
	r.domainSID = r.lookupDomainSID()
	return r
}

func (r *sidResolver) lookupDomainSID() string {
	results, err := r.client.Search(r.baseDN, "(objectClass=domain)", []string{"objectSid"})
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

func (r *sidResolver) Resolve(sid *security.SID) string {
	sidStr := sid.String()

	// Check cache
	if name, ok := r.cache[sidStr]; ok {
		return name
	}

	// Check well-known SIDs
	if name, ok := security.WellKnownSIDs[sidStr]; ok {
		r.cache[sidStr] = name
		return name
	}

	// Check domain RIDs if this is a domain SID
	if r.domainSID != "" && strings.HasPrefix(sidStr, r.domainSID+"-") {
		ridStr := sidStr[len(r.domainSID)+1:]
		var rid uint64
		fmt.Sscanf(ridStr, "%d", &rid)
		if name, ok := security.WellKnownRIDs[uint32(rid)]; ok {
			result := fmt.Sprintf("%s (%s)", name, sidStr)
			r.cache[sidStr] = result
			return result
		}
	}

	// LDAP lookup
	name := r.ldapLookup(sid)
	if name != "" {
		result := fmt.Sprintf("%s (%s)", name, sidStr)
		r.cache[sidStr] = result
		return result
	}

	// Return just the SID string
	r.cache[sidStr] = ""
	return ""
}

func (r *sidResolver) ldapLookup(sid *security.SID) string {
	sidHex := hexEscapeBinary(sid.Marshal())
	filter := fmt.Sprintf("(objectSid=%s)", sidHex)
	results, err := r.client.Search(r.baseDN, filter, []string{"sAMAccountName"})
	if err != nil || len(results.Entries) == 0 {
		return ""
	}
	return results.Entries[0].GetAttributeValue("sAMAccountName")
}
