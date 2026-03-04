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

func main() {
	// Tool-specific flags
	action := flag.String("action", "read", "Action to perform: read, write")
	targetObj := flag.String("target", "", "Target object (sAMAccountName) whose owner to read/modify")
	targetSID := flag.String("target-sid", "", "Target object SID")
	targetDN := flag.String("target-dn", "", "Target object DN")
	newOwner := flag.String("new-owner", "", "New owner (sAMAccountName)")
	newOwnerSID := flag.String("new-owner-sid", "", "New owner SID")
	newOwnerDN := flag.String("new-owner-dn", "", "New owner DN")
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

	if creds.DCIP != "" && target.IP == "" {
		target.IP = creds.DCIP
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	client := ldap.NewClient(target, &creds)
	defer client.Close()

	fmt.Printf("[*] Connecting to %s...\n", target.Addr())
	if err := client.Connect(*useLDAPS); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	fmt.Printf("[*] Binding as %s...\n", creds.Username)
	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}
	fmt.Println("[+] Bind successful.")

	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get Naming Context: %v", err)
	}

	resolvedTargetDN, err := resolveTargetDN(client, baseDN, *targetObj, *targetSID, *targetDN)
	if err != nil {
		log.Fatalf("[-] Failed to resolve target: %v", err)
	}
	fmt.Printf("[*] Target DN: %s\n", resolvedTargetDN)

	switch strings.ToLower(*action) {
	case "read":
		doRead(client, baseDN, resolvedTargetDN)
	case "write":
		doWrite(client, baseDN, resolvedTargetDN, *newOwner, *newOwnerSID, *newOwnerDN)
	default:
		log.Fatalf("[-] Unknown action: %s (use 'read' or 'write')", *action)
	}
}

func resolveTargetDN(client *ldap.Client, baseDN, targetName, targetSIDStr, targetDNStr string) (string, error) {
	if targetDNStr != "" {
		return targetDNStr, nil
	}

	var filter string
	if targetSIDStr != "" {
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

func resolveNewOwnerSID(client *ldap.Client, baseDN, ownerName, ownerSIDStr, ownerDNStr string) (*security.SID, error) {
	if ownerSIDStr != "" {
		return security.ParseSID(ownerSIDStr)
	}

	var filter string
	if ownerDNStr != "" {
		filter = fmt.Sprintf("(distinguishedName=%s)", goldap.EscapeFilter(ownerDNStr))
	} else if ownerName != "" {
		filter = fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(ownerName))
	} else {
		return nil, fmt.Errorf("no new owner specified: use -new-owner, -new-owner-sid, or -new-owner-dn")
	}

	results, err := client.Search(baseDN, filter, []string{"objectSid"})
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}
	if len(results.Entries) == 0 {
		return nil, fmt.Errorf("new owner not found")
	}

	sidRaw := results.Entries[0].GetRawAttributeValue("objectSid")
	if len(sidRaw) == 0 {
		return nil, fmt.Errorf("new owner has no objectSid")
	}

	sid, _, err := security.ParseSIDBytes(sidRaw)
	return sid, err
}

func fetchOwnerDescriptor(client *ldap.Client, targetDN string) ([]byte, error) {
	sdControl := ldap.NewControlMicrosoftSDFlags(security.OWNER_SECURITY_INFORMATION)
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

func writeOwnerDescriptor(client *ldap.Client, targetDN string, sdBytes []byte) error {
	sdControl := ldap.NewControlMicrosoftSDFlags(security.OWNER_SECURITY_INFORMATION)
	return client.ModifyRaw(targetDN, goldap.ReplaceAttribute, "nTSecurityDescriptor", sdBytes, []goldap.Control{sdControl})
}

func resolveSIDToName(client *ldap.Client, baseDN string, sid *security.SID) string {
	// Check well-known SIDs first
	sidStr := sid.String()
	if name, ok := security.WellKnownSIDs[sidStr]; ok {
		return name
	}

	sidHex := hexEscapeBinary(sid.Marshal())
	filter := fmt.Sprintf("(objectSid=%s)", sidHex)
	results, err := client.Search(baseDN, filter, []string{"sAMAccountName"})
	if err != nil || len(results.Entries) == 0 {
		return ""
	}
	return results.Entries[0].GetAttributeValue("sAMAccountName")
}

func resolveSIDToDN(client *ldap.Client, baseDN string, sid *security.SID) string {
	sidHex := hexEscapeBinary(sid.Marshal())
	filter := fmt.Sprintf("(objectSid=%s)", sidHex)
	results, err := client.Search(baseDN, filter, []string{"distinguishedName"})
	if err != nil || len(results.Entries) == 0 {
		return ""
	}
	return results.Entries[0].DN
}

func printOwnerInfo(client *ldap.Client, baseDN string, owner *security.SID) {
	if owner == nil {
		fmt.Println("[!] No owner set on this object.")
		return
	}

	ownerSID := owner.String()
	ownerName := resolveSIDToName(client, baseDN, owner)
	ownerDN := resolveSIDToDN(client, baseDN, owner)

	fmt.Println("[*] Current owner information below")
	fmt.Printf("[*]   SID:               %s\n", ownerSID)
	if ownerName != "" {
		fmt.Printf("[*]   sAMAccountName:    %s\n", ownerName)
	}
	if ownerDN != "" {
		fmt.Printf("[*]   distinguishedName: %s\n", ownerDN)
	}
}

func fetchAndParseOwner(client *ldap.Client, targetDN string) ([]byte, *security.SecurityDescriptor) {
	sdRaw, err := fetchOwnerDescriptor(client, targetDN)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	sd, err := security.ParseSecurityDescriptor(sdRaw)
	if err != nil {
		log.Fatalf("[-] Failed to parse security descriptor: %v", err)
	}

	return sdRaw, sd
}

func doRead(client *ldap.Client, baseDN, targetDN string) {
	_, sd := fetchAndParseOwner(client, targetDN)
	printOwnerInfo(client, baseDN, sd.Owner)
}

func doWrite(client *ldap.Client, baseDN, targetDN, newOwner, newOwnerSIDStr, newOwnerDNStr string) {
	// Fetch SD once, display current owner, then modify
	_, sd := fetchAndParseOwner(client, targetDN)
	printOwnerInfo(client, baseDN, sd.Owner)

	// Resolve new owner SID
	newSID, err := resolveNewOwnerSID(client, baseDN, newOwner, newOwnerSIDStr, newOwnerDNStr)
	if err != nil {
		log.Fatalf("[-] Failed to resolve new owner: %v", err)
	}
	fmt.Printf("[*] New owner SID: %s\n", newSID.String())

	// Replace owner and write back
	sd.Owner = newSID
	newSD := sd.Marshal()
	if err := writeOwnerDescriptor(client, targetDN, newSD); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInsufficientAccessRights) {
			log.Fatalf("[-] Could not modify object, the server reports insufficient rights: %v", err)
		}
		if goldap.IsErrorWithCode(err, goldap.LDAPResultConstraintViolation) {
			log.Fatalf("[-] Could not modify object, the server reports a constrained violation: %v", err)
		}
		log.Fatalf("[-] Failed to write security descriptor: %v", err)
	}

	fmt.Println("[+] OwnerSid modified successfully!")
}

func hexEscapeBinary(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		fmt.Fprintf(&b, "\\%02x", c)
	}
	return b.String()
}
