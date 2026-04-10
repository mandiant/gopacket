// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"gopacket/internal/build"
	"gopacket/pkg/flags"
	"gopacket/pkg/transport"
)

var (
	dcIP    = flag.String("dc-ip", "", "IP Address of a domain controller or DNS resolver for the domain")
	dcHost  = flag.String("dc-host", "", "Hostname of a specific DC to check (skips DNS discovery)")
	domain  = flag.String("domain", "", "Domain name")
	timeout = flag.Int("timeout", 15, "DNS timeout in seconds")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "gopacket v0.1.0 - Impacket Clone in Go")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "LDAP signing and channel binding enumeration utility.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	// Standard flags
	debug := flag.Bool("debug", false, "Turn DEBUG output ON")
	ts := flag.Bool("ts", false, "Adds timestamp to every logging output")

	flags.CheckHelp()
	flag.Parse()

	// Validate required flags
	if *dcHost == "" && (*dcIP == "" || *domain == "") {
		fmt.Fprintln(os.Stderr, "Error: Either -dc-host or both -dc-ip and -domain are required")
		flag.Usage()
		os.Exit(1)
	}

	build.Debug = *debug
	build.Timestamp = *ts

	checker := &LDAPChecker{
		domain:  *domain,
		dcIP:    *dcIP,
		dcHost:  *dcHost,
		timeout: time.Duration(*timeout) * time.Second,
	}

	if *domain != "" {
		logInfo("Targeted domain: %s", *domain)
	}

	if err := checker.Run(); err != nil {
		logError("%v", err)
		os.Exit(1)
	}
}

type LDAPChecker struct {
	domain  string
	dcIP    string
	dcHost  string
	timeout time.Duration
}

func (c *LDAPChecker) Run() error {
	var dcList []string

	if c.dcHost != "" {
		// Direct DC specified, skip DNS discovery
		dcList = []string{c.dcHost}
		logInfo("Checking specified domain controller: %s", c.dcHost)
	} else {
		// Discover DCs via DNS
		var err error
		dcList, err = c.listDCs()
		if err != nil {
			return fmt.Errorf("failed to enumerate domain controllers: %v", err)
		}
		logInfo("Found %d domain controller(s) in %s", len(dcList), c.domain)
	}

	for _, dc := range dcList {
		signingRequired := c.checkLDAPSigning(dc)
		channelBindingStatus := c.checkLDAPSChannelBinding(dc)

		fmt.Printf("Hostname: %s\n", dc)
		fmt.Printf("\t> LDAP Signing Required: %v\n", signingRequired)
		fmt.Printf("\t> LDAPS Channel Binding Status: %s\n", channelBindingStatus)
	}

	return nil
}

func (c *LDAPChecker) listDCs() ([]string, error) {
	// Create custom resolver using the DC as DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: c.timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(c.dcIP, "53"))
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Query SRV records for domain controllers
	srvQuery := fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", c.domain)
	_, srvs, err := resolver.LookupSRV(ctx, "", "", srvQuery)
	if err != nil {
		return nil, fmt.Errorf("DNS SRV lookup failed: %v", err)
	}

	var dcList []string
	for _, srv := range srvs {
		hostname := strings.TrimSuffix(srv.Target, ".")
		dcList = append(dcList, hostname)
	}

	return dcList, nil
}

func (c *LDAPChecker) checkLDAPSigning(hostname string) bool {
	// Try to connect to LDAP without signing
	address := net.JoinHostPort(hostname, "389")

	conn, err := transport.DialTimeout("tcp", address, int(c.timeout.Seconds()))
	if err != nil {
		logDebug("Failed to connect to %s: %v", address, err)
		return false
	}

	ldapConn := goldap.NewConn(conn, false)
	ldapConn.Start()
	defer ldapConn.Close()

	// Try anonymous bind (or bind with empty credentials)
	// If signing is required, we'll get "strongerAuthRequired" error
	err = ldapConn.UnauthenticatedBind("")
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "strongerAuthRequired") ||
			strings.Contains(errStr, "Strong Auth Required") ||
			strings.Contains(strings.ToLower(errStr), "stronger") {
			logDebug("LDAP signing is enforced on %s", hostname)
			return true
		}
		logDebug("LDAP bind error on %s: %v", hostname, err)
	} else {
		logDebug("LDAP signing is not enforced on %s", hostname)
	}

	return false
}

func (c *LDAPChecker) checkLDAPSChannelBinding(hostname string) string {
	address := net.JoinHostPort(hostname, "636")

	// Connect with TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	conn, err := transport.DialTLS("tcp", address, tlsConfig)
	if err != nil {
		logDebug("Failed to connect to LDAPS on %s: %v", hostname, err)
		if strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "EOF") {
			return "No TLS cert"
		}
		return "Connection Failed"
	}

	ldapConn := goldap.NewConn(conn, true)
	ldapConn.Start()
	defer ldapConn.Close()

	// Try NTLM bind with invalid credentials
	// The error response tells us about channel binding requirements
	//
	// Error codes:
	// - data 80090346: SEC_E_BAD_BINDINGS - Channel binding required
	// - data 52e: Invalid credentials (normal, means CBT not strictly required)

	domain := c.domain
	if domain == "" {
		domain = "WORKGROUP"
	}

	// Use NTLMBindWithHash with an invalid hash to trigger NTLM auth
	err = ldapConn.NTLMBindWithHash(domain, "invaliduser", "00000000000000000000000000000000")
	if err != nil {
		errStr := err.Error()

		// Check for channel binding required error
		if strings.Contains(errStr, "80090346") {
			logDebug("LDAPS channel binding is set to 'Always' on %s", hostname)
			return "Always"
		}

		// Invalid credentials - CBT not strictly required
		if strings.Contains(errStr, "52e") || strings.Contains(errStr, "Invalid Credentials") {
			logDebug("LDAPS channel binding is 'Never' or 'When Supported' on %s", hostname)
			return "Never"
		}

		// Check for NTLM disabled
		if strings.Contains(errStr, "Strong Auth Required") || strings.Contains(errStr, "strongerAuthRequired") {
			logDebug("NTLM may be disabled on %s: %v", hostname, err)
			return "Unknown (NTLM disabled?)"
		}

		logDebug("LDAPS bind error on %s: %v", hostname, err)
	}

	return "Never"
}

func logInfo(format string, args ...interface{}) {
	prefix := "[*] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Printf(prefix+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	prefix := "[-] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Fprintf(os.Stderr, prefix+format+"\n", args...)
}

func logDebug(format string, args ...interface{}) {
	if !build.Debug {
		return
	}
	prefix := "[DEBUG] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Printf(prefix+format+"\n", args...)
}
