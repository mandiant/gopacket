package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
)

var (
	targetDomain = flag.String("target-domain", "", "Domain to query/request if different than the domain of the user. Allows for retrieving delegation info across trusts.")
	user         = flag.String("user", "", "Requests data for specific user")
	disabled     = flag.Bool("disabled", false, "Query disabled users too")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		printUsage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	// If -dc-ip is specified, use it as the connection IP for LDAP
	if creds.DCIP != "" {
		target.IP = creds.DCIP
	}

	if creds.Domain == "" {
		fmt.Fprintln(os.Stderr, "[-] Domain is required. Use: domain/user:pass@target or domain/user@target")
		os.Exit(1)
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Determine target domain for queries
	queryDomain := creds.Domain
	if *targetDomain != "" {
		queryDomain = *targetDomain
	}

	// Connect to LDAP
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(false); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection failed: %v\n", err)
		os.Exit(1)
	}

	// Bind using credentials
	loginUser := fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
	if err := client.LoginWithUser(loginUser); err != nil {
		// Fallback to domain\user format
		if err := client.Login(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Bind failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Build baseDN from query domain
	baseDN := domainToBaseDN(queryDomain)

	fmt.Printf("[*] Querying %s for delegation relationships...\n", queryDomain)

	// Find delegation relationships
	entries, err := client.FindDelegation(baseDN, *disabled, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] LDAP search failed: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No entries found!")
		return
	}

	// Print results in table format
	printTable(entries)
	fmt.Println()
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, fmt.Sprintf("dc=%s", part))
	}
	return strings.Join(dnParts, ",")
}

func printTable(entries []ldap.DelegationEntry) {
	// Calculate column widths
	header := []string{"AccountName", "AccountType", "DelegationType", "DelegationRightsTo", "SPN Exists"}
	colWidths := make([]int, len(header))

	for i, h := range header {
		colWidths[i] = len(h)
	}

	for _, e := range entries {
		row := []string{e.AccountName, e.AccountType, string(e.DelegationType), e.DelegationTo, e.SPNExists}
		for i, val := range row {
			if len(val) > colWidths[i] {
				colWidths[i] = len(val)
			}
		}
	}

	// Build format string
	formatParts := make([]string, len(header))
	for i, width := range colWidths {
		formatParts[i] = fmt.Sprintf("%%-%ds", width)
	}
	format := strings.Join(formatParts, "  ")

	// Print header
	headerRow := make([]interface{}, len(header))
	for i, h := range header {
		headerRow[i] = h
	}
	fmt.Printf(format+"\n", headerRow...)

	// Print separator
	sepParts := make([]string, len(header))
	for i, width := range colWidths {
		sepParts[i] = strings.Repeat("-", width)
	}
	fmt.Println(strings.Join(sepParts, "  "))

	// Print rows
	for _, e := range entries {
		row := []interface{}{e.AccountName, e.AccountType, string(e.DelegationType), e.DelegationTo, e.SPNExists}
		fmt.Printf(format+"\n", row...)
	}
}

func printUsage() {
	fmt.Println("Queries target domain for delegation relationships")
	fmt.Println()
	fmt.Println("Usage: findDelegation [options] target")
	fmt.Println()
	fmt.Println("Target format:")
	fmt.Println("  domain[/username[:password]]@<targetName or address>")
	fmt.Println("  domain/username[:password]@<targetName or address>")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -target-domain string   Domain to query if different than user domain (for cross-trust queries)")
	fmt.Println("  -user string            Request data for specific user only")
	fmt.Println("  -disabled               Query disabled users too")
	fmt.Println()
	fmt.Println("Delegation Types:")
	fmt.Println("  Unconstrained                      - Account can delegate to any service")
	fmt.Println("  Constrained                        - Account can delegate to specific services only")
	fmt.Println("  Constrained w/ Protocol Transition - Constrained + can obtain tickets without user interaction")
	fmt.Println("  Resource-Based Constrained         - Target service controls who can delegate to it")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  findDelegation domain.local/user:pass@dc.domain.local")
	fmt.Println("  findDelegation -user administrator domain.local/user:pass@dc.domain.local")
	fmt.Println("  findDelegation -disabled domain.local/user:pass@dc.domain.local")
	fmt.Println("  findDelegation -target-domain child.domain.local domain.local/user:pass@dc.domain.local")
	fmt.Println()
	flag.PrintDefaults()
}
