// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"gopacket/pkg/tds"
)

var (
	timeout = flag.Duration("timeout", 5*time.Second, "Query timeout")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `gopacket v0.1.0 - mssqlinstance

SQL Server Browser Protocol discovery tool.

Queries the SQL Server Browser service (UDP 1434) to enumerate SQL Server
instances running on a target host.

Usage: %s [options] <target>

Options:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  %s 192.168.1.10
  %s -timeout 10s sqlserver.domain.local

Output Fields:
  ServerName    - NetBIOS name of the server
  InstanceName  - SQL Server instance name
  IsClustered   - Whether the instance is clustered
  Version       - SQL Server version
  tcp           - TCP port number
  np            - Named pipe path

Note: Requires the SQL Server Browser service to be running on the target.
`, os.Args[0], os.Args[0])
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("gopacket v0.1.0 - mssqlinstance")
	fmt.Println()

	target := flag.Arg(0)

	fmt.Printf("[*] Querying SQL Server Browser on %s...\n", target)
	fmt.Println()

	instances, err := tds.GetInstances(target, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}

	if len(instances) == 0 {
		fmt.Println("[-] No instances found (SQL Server Browser may not be running)")
		os.Exit(0)
	}

	fmt.Printf("[+] Found %d instance(s):\n", len(instances))
	fmt.Println()

	for i, inst := range instances {
		fmt.Printf("Instance %d:\n", i+1)
		if inst.ServerName != "" {
			fmt.Printf("  ServerName:   %s\n", inst.ServerName)
		}
		if inst.InstanceName != "" {
			fmt.Printf("  InstanceName: %s\n", inst.InstanceName)
		}
		if inst.IsClustered != "" {
			fmt.Printf("  IsClustered:  %s\n", inst.IsClustered)
		}
		if inst.Version != "" {
			fmt.Printf("  Version:      %s\n", inst.Version)
		}
		if inst.TCP != "" {
			fmt.Printf("  TCP Port:     %s\n", inst.TCP)
		}
		if inst.NamedPipe != "" {
			fmt.Printf("  Named Pipe:   %s\n", inst.NamedPipe)
		}
		fmt.Println()
	}
}
