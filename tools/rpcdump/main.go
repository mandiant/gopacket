// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/transport"
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		fmt.Fprintf(os.Stderr, "Usage: rpcdump [options] [[domain/]username[:password]@]<target>\n")
		os.Exit(1)
	}

	fmt.Println("gopacket v0.1.0 - rpcdump")
	fmt.Println()

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	// Default port for rpcdump is 135, not 445
	portSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	if !portSet {
		opts.Port = 135
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Resolve target IP
	remoteHost := target.Host
	if target.IP != "" {
		remoteHost = target.IP
	}

	build.Log("[*] Retrieving endpoint list from %s", target.Host)

	var endpoints []epmapper.Endpoint

	port := opts.Port

	// Parse hashes for SMB transport
	var lmHash, ntHash string
	if creds.Hash != "" {
		parts := strings.SplitN(creds.Hash, ":", 2)
		if len(parts) == 2 {
			lmHash = parts[0]
			ntHash = parts[1]
		}
	}

	switch port {
	case 135, 593:
		// Direct TCP connection to epmapper - no auth needed
		endpoints, err = dumpViaTCP(remoteHost, port)
	case 139, 445:
		// SMB transport - requires authentication
		endpoints, err = dumpViaSMB(remoteHost, port, creds.Domain, creds.Username, creds.Password, lmHash, ntHash)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unsupported port: %d (use 135, 139, 445, or 593)\n", port)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Protocol failed: %v\n", err)
		os.Exit(1)
	}

	// Display results
	for _, ep := range endpoints {
		fmt.Printf("Protocol: %s \n", ep.Protocol)
		fmt.Printf("Provider: %s \n", ep.Provider)
		fmt.Printf("UUID    : %s %s %s\n", ep.UUID, ep.Version, ep.Annotation)
		fmt.Printf("Bindings: \n")
		for _, b := range ep.Bindings {
			fmt.Printf("          %s\n", b)
		}
		fmt.Println()
	}

	// Summary
	total := 0
	for _, ep := range endpoints {
		total += len(ep.Bindings)
	}
	if total == 1 {
		build.Log("[*] Received one endpoint.")
	} else if total > 0 {
		build.Log("[*] Received %d endpoints.", total)
	} else {
		build.Log("[*] No endpoints found.")
	}
}

func dumpViaTCP(host string, port int) ([]epmapper.Endpoint, error) {
	// Connect directly to endpoint mapper
	addr := fmt.Sprintf("%s:%d", host, port)
	if build.Debug {
		log.Printf("[D] Connecting to %s", addr)
	}
	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}
	defer conn.Close()

	if build.Debug {
		log.Printf("[D] Connected, creating DCE/RPC client")
	}

	// Create DCE/RPC client over TCP
	transport := dcerpc.NewTCPTransport(conn)
	client := dcerpc.NewClientTCP(transport)

	// Bind to endpoint mapper
	if build.Debug {
		log.Printf("[D] Binding to endpoint mapper (UUID: %x)", epmapper.UUID)
	}
	if err := client.Bind(epmapper.UUID, epmapper.MajorVersion, epmapper.MinorVersion); err != nil {
		return nil, fmt.Errorf("failed to bind to endpoint mapper: %v", err)
	}

	if build.Debug {
		log.Printf("[D] Bound successfully, calling ept_lookup")
	}

	// Create epmapper client and enumerate
	epmClient := epmapper.NewEpmClient(client)
	endpoints, err := epmClient.Lookup()
	if build.Debug {
		log.Printf("[D] Lookup returned %d endpoints, err=%v", len(endpoints), err)
	}
	return endpoints, err
}

func dumpViaSMB(host string, port int, domain, username, password, lmHash, ntHash string) ([]epmapper.Endpoint, error) {
	// Future enhancement: Implement SMB transport for epmapper
	// For now, just try TCP on port 135
	return dumpViaTCP(host, 135)
}
