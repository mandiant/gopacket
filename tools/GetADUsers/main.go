// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
)

var (
	requestUser = flag.String("user", "", "Requests data for specific user")
	allUsers    = flag.Bool("all", false, "Return all users, including those with no email addresses and disabled accounts")
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

	// Initialize Client
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	// Connect
	fmt.Printf("[*] Connecting to %s...\n", target.Addr())
	if err := client.Connect(false); err != nil {
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

	// Get Domain Context
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get Naming Context: %v", err)
	}
	fmt.Printf("[+] Found BaseDN: %s\n", baseDN)

	// Build search filter (matching Impacket's GetADUsers.py)
	var filter string
	if *allUsers {
		// -all: return all users including those with no email and disabled accounts
		filter = "(&(sAMAccountName=*)(objectCategory=user)"
	} else {
		// Default: only users with email, exclude disabled accounts
		// UF_ACCOUNTDISABLE = 0x2
		filter = "(&(sAMAccountName=*)(mail=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
	}

	if *requestUser != "" {
		filter += fmt.Sprintf("(sAMAccountName:=%s))", *requestUser)
	} else {
		filter += ")"
	}

	attributes := []string{"sAMAccountName", "pwdLastSet", "mail", "lastLogon"}

	results, err := client.Search(baseDN, filter, attributes)
	if err != nil {
		log.Fatalf("[-] Search failed: %v", err)
	}

	// Print table header (matching Impacket format)
	colLen := []int{20, 30, 19, 19}
	header := []string{"Name", "Email", "PasswordLastSet", "LastLogon"}
	fmt.Printf("%-*s  %-*s  %-*s  %-*s\n", colLen[0], header[0], colLen[1], header[1], colLen[2], header[2], colLen[3], header[3])
	for i, w := range colLen {
		if i > 0 {
			fmt.Print("  ")
		}
		for j := 0; j < w; j++ {
			fmt.Print("-")
		}
	}
	fmt.Println()

	for _, entry := range results.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		// Skip machine accounts (end with $)
		if len(name) > 0 && name[len(name)-1] == '$' {
			continue
		}
		mail := entry.GetAttributeValue("mail")
		pwdLastSet := formatFileTime(entry.GetAttributeValue("pwdLastSet"))
		lastLogon := formatFileTime(entry.GetAttributeValue("lastLogon"))
		fmt.Printf("%-*s  %-*s  %-*s  %-*s\n", colLen[0], name, colLen[1], mail, colLen[2], pwdLastSet, colLen[3], lastLogon)
	}
}

// formatFileTime converts a Windows FILETIME string (100-nanosecond intervals
// since 1601-01-01) to a human-readable timestamp, matching Impacket's getUnixTime().
func formatFileTime(s string) string {
	if s == "" || s == "0" {
		return "<never>"
	}
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "N/A"
	}
	// Convert Windows FILETIME to Unix timestamp:
	// Subtract the epoch difference (1601-01-01 to 1970-01-01) in 100ns intervals,
	// then convert to seconds.
	const epochDiff = 116444736000000000
	unixNano := (ft - epochDiff) * 100
	t := time.Unix(0, unixNano)
	return t.Format("2006-01-02 15:04:05")
}
