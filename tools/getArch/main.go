package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/dcerpc/header"
	"gopacket/pkg/transport"
)

var (
	target  = flag.String("target", "", "Target name or address")
	targets = flag.String("targets", "", "Input file with targets (one per line)")
	timeout = flag.Int("timeout", 2, "Socket timeout in seconds")
	debug   = flag.Bool("debug", false, "Turn DEBUG output ON")
)

func main() {
	flag.Usage = printUsage
	flag.Parse()

	// Also check positional argument for target
	if *target == "" && flag.NArg() > 0 {
		*target = flag.Arg(0)
	}

	if *target == "" && *targets == "" {
		fmt.Fprintln(os.Stderr, "[-] You have to specify a target!")
		printUsage()
		os.Exit(1)
	}

	var machineList []string

	if *targets != "" {
		// Read targets from file
		file, err := os.Open(*targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open targets file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				machineList = append(machineList, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error reading targets file: %v\n", err)
			os.Exit(1)
		}
	} else {
		machineList = append(machineList, *target)
	}

	fmt.Printf("[*] Gathering OS architecture for %d machines\n", len(machineList))
	fmt.Printf("[*] Socket connect timeout set to %d secs\n", *timeout)

	for _, machine := range machineList {
		checkArch(machine, *timeout)
	}
}

func checkArch(machine string, timeoutSec int) {
	// Connect to port 135 (endpoint mapper)
	addr := fmt.Sprintf("%s:135", machine)
	conn, err := transport.DialTimeout("tcp", addr, timeoutSec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: %v\n", machine, err)
		return
	}
	defer conn.Close()

	// Set read/write timeout
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))

	transport := dcerpc.NewTCPTransport(conn)
	client := dcerpc.NewClientTCP(transport)

	// Try to bind to endpoint mapper with NDR64 syntax
	// If successful = 64-bit, if syntaxes_not_supported = 32-bit
	err = client.BindWithSyntax(
		epmapper.UUID,
		epmapper.MajorVersion,
		epmapper.MinorVersion,
		header.TransferSyntaxNDR64,
		1, // NDR64 version 1.0
	)

	if err != nil {
		if strings.Contains(err.Error(), "syntaxes_not_supported") {
			fmt.Printf("%s is 32-bit\n", machine)
		} else {
			fmt.Fprintf(os.Stderr, "[-] %s: %v\n", machine, err)
		}
		return
	}

	fmt.Printf("%s is 64-bit\n", machine)
}

func printUsage() {
	fmt.Println("gopacket v0.1.0 - Impacket Clone in Go")
	fmt.Println()
	fmt.Println("Gets the target system's OS architecture version")
	fmt.Println()
	fmt.Println("Usage: getArch [options] [target]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -target string    Target name or address")
	fmt.Println("  -targets string   Input file with targets (one per line)")
	fmt.Println("  -timeout int      Socket timeout in seconds (default 2)")
	fmt.Println("  -debug            Turn DEBUG output ON")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  getArch 192.168.1.1")
	fmt.Println("  getArch -target dc.domain.local")
	fmt.Println("  getArch -targets hosts.txt")
	fmt.Println("  getArch -targets hosts.txt -timeout 5")
	fmt.Println()
}
