// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
)

var (
	resolveIP  bool
	userFilter string
)

func main() {
	// Register tool-specific flags before Parse()
	flag.BoolVar(&resolveIP, "resolveIP", false, "Tries to resolve the IP address of computer objects")
	flag.StringVar(&userFilter, "user", "", "Requests data for specific computer")

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

	// Set default LDAP port
	if target.Port == 0 {
		target.Port = 389
	}

	// Initialize LDAP Client
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	// Connect
	if err := client.Connect(false); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	// Login - convert to UPN format for simple bind if not using hash/Kerberos
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}

	// Get Domain Context
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get Naming Context: %v", err)
	}

	// Search for Computer objects
	filter := "(&(objectCategory=computer)(objectClass=computer))"
	if userFilter != "" {
		// Filter for specific computer - add $ if not present
		computerName := userFilter
		if !strings.HasSuffix(computerName, "$") {
			computerName += "$"
		}
		filter = fmt.Sprintf("(&(objectCategory=computer)(objectClass=computer)(sAMAccountName=%s))", computerName)
	}
	attributes := []string{
		"sAMAccountName",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemVersion",
	}

	fmt.Printf("[*] Querying %s for information about domain.\n", target.Host)

	results, err := client.SearchWithPaging(baseDN, filter, attributes, 100)
	if err != nil {
		log.Fatalf("[-] Search failed: %v", err)
	}

	// Determine DNS server for IP resolution
	var dnsServer string
	if resolveIP {
		// Use the target as DNS server (assumes target is DC)
		if target.IP != "" {
			dnsServer = target.IP
		} else {
			dnsServer = target.Host
		}
		// Override with -dc-ip if provided
		if creds.DCIP != "" {
			dnsServer = creds.DCIP
		}
	}

	// Print results in tabular format (matching Python's format)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if resolveIP {
		fmt.Fprintln(w, "SAM AcctName\tDNS Hostname\tOS Version\tOS\tIPAddress")
		fmt.Fprintln(w, "---------------\t-----------------------------------\t---------------\t-----------------------------------\t--------------------")
	} else {
		fmt.Fprintln(w, "SAM AcctName\tDNS Hostname\tOS Version\tOS")
		fmt.Fprintln(w, "---------------\t-----------------------------------\t---------------\t--------------------")
	}

	for _, entry := range results.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		dnsName := entry.GetAttributeValue("dNSHostName")
		osName := entry.GetAttributeValue("operatingSystem")
		osVer := entry.GetAttributeValue("operatingSystemVersion")

		if resolveIP {
			ip := resolveHostname(dnsName, dnsServer)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, dnsName, osVer, osName, ip)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, dnsName, osVer, osName)
		}
	}
	w.Flush()
}

// resolveHostname resolves a hostname to an IP address using the specified DNS server
func resolveHostname(hostname, dnsServer string) string {
	if hostname == "" {
		return ""
	}

	// Use custom resolver to query the DC's DNS
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}

	// Resolve using the custom resolver with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, hostname)
	if err != nil {
		return ""
	}

	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}
