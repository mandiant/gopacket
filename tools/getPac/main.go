// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/session"
)

func containsAt(s string) bool {
	return strings.Contains(s, "@")
}

var (
	targetUser = flag.String("targetUser", "", "The target user to retrieve the PAC of")
)

func main() {
	flag.Usage = printUsage
	opts := flags.Parse()

	if opts.TargetStr == "" {
		printUsage()
		os.Exit(1)
	}

	if *targetUser == "" {
		fmt.Fprintln(os.Stderr, "[-] -targetUser is required")
		printUsage()
		os.Exit(1)
	}

	// For getPac, target is optional - credentials format: domain/username[:password]
	// Append dummy target if not present
	targetStr := opts.TargetStr
	if !containsAt(targetStr) {
		targetStr = targetStr + "@_"
	}

	target, creds, err := session.ParseTargetString(targetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if creds.Domain == "" {
		fmt.Fprintln(os.Stderr, "[-] Domain is required")
		os.Exit(1)
	}

	if !opts.NoPass && creds.Password == "" && creds.Hash == "" && creds.AESKey == "" {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Determine KDC host
	kdcHost := creds.DCIP
	if kdcHost == "" {
		kdcHost = target.Host
	}
	if kdcHost == "" {
		kdcHost = creds.Domain
	}

	// Get PAC using S4U2Self + U2U
	pac, err := kerberos.GetPAC(&kerberos.PACRequest{
		Username:   creds.Username,
		Password:   creds.Password,
		Domain:     creds.Domain,
		NTHash:     creds.Hash,
		AESKey:     creds.AESKey,
		DCIP:       kdcHost,
		TargetUser: *targetUser,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to get PAC: %v\n", err)
		os.Exit(1)
	}

	// Display PAC information
	printPAC(pac)
}

func printPAC(pac *kerberos.PAC) {
	fmt.Println()

	// User info
	if pac.Username != "" {
		fmt.Printf("UserName: %s\n", pac.Username)
	}
	if pac.Domain != "" {
		fmt.Printf("Domain: %s\n", pac.Domain)
	}
	if pac.DomainSID != nil {
		fmt.Printf("Domain SID: %s\n", pac.DomainSID.String())
	}
	fmt.Printf("UserId: %d\n", pac.UserID)
	fmt.Printf("PrimaryGroupId: %d\n", pac.PrimaryGroupID)

	// Groups
	if len(pac.Groups) > 0 {
		fmt.Printf("\nGroup Memberships:\n")
		for i, gid := range pac.Groups {
			attr := uint32(0)
			if i < len(pac.GroupAttributes) {
				attr = pac.GroupAttributes[i]
			}
			fmt.Printf("  %d (attributes: 0x%x)\n", gid, attr)
		}
	}

	// Extra SIDs
	if len(pac.ExtraSIDs) > 0 {
		fmt.Printf("\nExtra SIDs:\n")
		for i, sid := range pac.ExtraSIDs {
			attr := uint32(0)
			if i < len(pac.ExtraSIDAttrs) {
				attr = pac.ExtraSIDAttrs[i]
			}
			fmt.Printf("  %s (attributes: 0x%x)\n", sid.String(), attr)
		}
	}

	// Account info
	fmt.Println()
	if pac.FullName != "" {
		fmt.Printf("FullName: %s\n", pac.FullName)
	}
	if pac.LogonServer != "" {
		fmt.Printf("LogonServer: %s\n", pac.LogonServer)
	}

	fmt.Printf("LogonCount: %d\n", pac.LogonCount)
	fmt.Printf("BadPasswordCount: %d\n", pac.BadPasswordCount)
	fmt.Printf("UserAccountControl: 0x%08x\n", pac.UserAccountControl)
	fmt.Printf("UserFlags: 0x%08x\n", pac.UserFlags)

	// Timestamps
	fmt.Println()
	if !pac.LogonTime.IsZero() {
		fmt.Printf("LogonTime: %s\n", pac.LogonTime.Format("2006-01-02 15:04:05 UTC"))
	}
	if !pac.LogoffTime.IsZero() {
		fmt.Printf("LogoffTime: %s\n", pac.LogoffTime.Format("2006-01-02 15:04:05 UTC"))
	}
	if !pac.PasswordLastSet.IsZero() {
		fmt.Printf("PasswordLastSet: %s\n", pac.PasswordLastSet.Format("2006-01-02 15:04:05 UTC"))
	}
	if !pac.PasswordCanChange.IsZero() {
		fmt.Printf("PasswordCanChange: %s\n", pac.PasswordCanChange.Format("2006-01-02 15:04:05 UTC"))
	}
	if !pac.PasswordMustChange.IsZero() {
		fmt.Printf("PasswordMustChange: %s\n", pac.PasswordMustChange.Format("2006-01-02 15:04:05 UTC"))
	}

	// UPN/DNS info
	if pac.UPN != "" {
		fmt.Printf("\nUPN: %s\n", pac.UPN)
	}
	if pac.DNSDomainName != "" {
		fmt.Printf("DNS Domain: %s\n", pac.DNSDomainName)
	}

	// Domain SID at the end (like Impacket)
	fmt.Println()
	if pac.DomainSID != nil {
		fmt.Printf("Domain SID: %s\n", pac.DomainSID.String())
	}
	fmt.Println()
}

func printUsage() {
	fmt.Println("Gets the PAC of the specified target user using S4U2Self + U2U")
	fmt.Println()
	fmt.Println("Usage: getPac [options] domain/username[:password]")
	fmt.Println()
	fmt.Println("Positional arguments:")
	fmt.Println("  credentials           domain/username[:password] - Valid domain credentials")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -targetUser string    The target user to retrieve the PAC of (required)")
	fmt.Println("  -debug                Turn DEBUG output ON")
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Println("  -hashes LMHASH:NTHASH   NTLM hashes")
	fmt.Println("  -aesKey hex             AES key for Kerberos")
	fmt.Println("  -dc-ip ip               IP address of the domain controller")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  getPac -targetUser administrator domain/user:password")
	fmt.Println("  getPac -targetUser administrator -hashes :hash domain/user")
	fmt.Println("  getPac -targetUser administrator -dc-ip 192.168.1.1 domain/user:password")
	fmt.Println()
}
