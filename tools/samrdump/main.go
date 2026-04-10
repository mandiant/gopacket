// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/samr"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	csvOutput = flag.Bool("csv", false, "Turn CSV output")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass && creds.Password == "" && creds.Hash == "" && creds.AESKey == "" {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("gopacket v0.1.0 - samrdump")
	fmt.Println()
	fmt.Printf("[*] Retrieving endpoint list from %s\n", target.Host)

	// Connect via SMB
	if target.Port == 0 {
		target.Port = 445
	}

	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	// Get session key for SAMR operations
	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to obtain SMB session key\n")
		os.Exit(1)
	}

	// Open SAMR pipe
	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open SAMR pipe: %v\n", err)
		os.Exit(1)
	}

	// Create DCE/RPC client and bind
	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SAMR bind failed: %v\n", err)
		os.Exit(1)
	}

	// Create SAMR client
	samrClient := samr.NewSamrClient(rpcClient, sessionKey)

	// Connect to SAMR
	if err := samrClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SAMR connect failed: %v\n", err)
		os.Exit(1)
	}
	defer samrClient.Close()

	// Enumerate domains
	domains, err := samrClient.EnumerateDomains()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to enumerate domains: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Found domain(s):")
	for _, domain := range domains {
		fmt.Printf(" . %s\n", domain)
	}
	fmt.Println()

	// Open the first non-Builtin domain
	var targetDomain string
	for _, d := range domains {
		if d != "Builtin" {
			targetDomain = d
			break
		}
	}
	if targetDomain == "" && len(domains) > 0 {
		targetDomain = domains[0]
	}

	fmt.Printf("[*] Looking up users in domain %s\n", targetDomain)

	if err := samrClient.OpenDomain(targetDomain); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open domain: %v\n", err)
		os.Exit(1)
	}

	// Enumerate users
	users, err := samrClient.EnumerateDomainUsers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to enumerate users: %v\n", err)
		os.Exit(1)
	}

	// User info storage for CSV mode
	type userEntry struct {
		name    string
		rid     uint32
		info    *samr.UserAllInfo
		pwdSet  string
		expire  string
		disable string
	}
	var entries []userEntry

	// Process each user - first print "Found user" lines
	for _, user := range users {
		fmt.Printf("Found user: %s, uid = %d\n", user.Name, user.RID)

		// Open user and query info
		userHandle, err := samrClient.OpenUser(user.RID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open user %s: %v\n", user.Name, err)
			continue
		}

		info, err := samrClient.QueryUserInfo(userHandle)
		samrClient.CloseHandle(userHandle)

		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to query user %s: %v\n", user.Name, err)
			continue
		}

		// Format password last set time
		pwdLastSet := "<never>"
		if info.PasswordLastSet != 0 {
			// Convert Windows FILETIME to Unix time
			unixTime := (info.PasswordLastSet - 116444736000000000) / 10000000
			pwdLastSet = time.Unix(unixTime, 0).Format("2006-01-02 15:04:05")
		}

		dontExpire := "False"
		if info.UserAccountControl&samr.USER_DONT_EXPIRE_PASSWORD != 0 {
			dontExpire = "True"
		}

		accountDisabled := "False"
		if info.UserAccountControl&samr.USER_ACCOUNT_DISABLED != 0 {
			accountDisabled = "True"
		}

		entries = append(entries, userEntry{
			name:    user.Name,
			rid:     user.RID,
			info:    info,
			pwdSet:  pwdLastSet,
			expire:  dontExpire,
			disable: accountDisabled,
		})
	}

	// Now output results
	if *csvOutput {
		// Note: Impacket has a bug where header says AdminComment,UserComment but data is UserComment,AdminComment
		// We match the header order (AdminComment, UserComment)
		fmt.Println("#Name,RID,FullName,PrimaryGroupId,BadPasswordCount,LogonCount,PasswordLastSet,PasswordDoesNotExpire,AccountIsDisabled,AdminComment,UserComment,ScriptPath")
		for _, e := range entries {
			fullName := cleanCSV(e.info.FullName)
			adminComment := cleanCSV(e.info.AdminComment)
			userComment := cleanCSV(e.info.UserComment)
			scriptPath := cleanCSV(e.info.ScriptPath)

			fmt.Printf("%s,%d,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s\n",
				e.name, e.rid, fullName, e.info.PrimaryGroupID,
				e.info.BadPasswordCount, e.info.LogonCount, e.pwdSet,
				e.expire, e.disable, adminComment, userComment, scriptPath)
		}
	} else {
		for _, e := range entries {
			base := fmt.Sprintf("%s (%d)", e.name, e.rid)
			fmt.Printf("%s/FullName: %s\n", base, e.info.FullName)
			fmt.Printf("%s/AdminComment: %s\n", base, e.info.AdminComment)
			fmt.Printf("%s/UserComment: %s\n", base, e.info.UserComment)
			fmt.Printf("%s/PrimaryGroupId: %d\n", base, e.info.PrimaryGroupID)
			fmt.Printf("%s/BadPasswordCount: %d\n", base, e.info.BadPasswordCount)
			fmt.Printf("%s/LogonCount: %d\n", base, e.info.LogonCount)
			fmt.Printf("%s/PasswordLastSet: %s\n", base, e.pwdSet)
			fmt.Printf("%s/PasswordDoesNotExpire: %s\n", base, e.expire)
			fmt.Printf("%s/AccountIsDisabled: %s\n", base, e.disable)
			fmt.Printf("%s/ScriptPath: %s\n", base, e.info.ScriptPath)
			fmt.Println()
		}
	}

	// Summary
	if len(entries) == 1 {
		fmt.Println("[*] Received one entry.")
	} else if len(entries) > 1 {
		fmt.Printf("[*] Received %d entries.\n", len(entries))
	} else {
		fmt.Println("[*] No entries received.")
	}
}

func cleanCSV(s string) string {
	return strings.ReplaceAll(s, ",", ".")
}
