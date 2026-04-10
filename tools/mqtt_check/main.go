// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"os"

	"gopacket/pkg/flags"
	"gopacket/pkg/mqtt"
	"gopacket/pkg/session"
)

func main() {
	clientID := flag.String("client-id", "", "Client ID used when authenticating (default random)")
	ssl := flag.Bool("ssl", false, "Turn SSL on")

	flags.ExtraUsageLine = ""
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

	// Default port for MQTT is 1883, not 445
	portSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	if !portSet {
		opts.Port = 1883
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	if *clientID == "" {
		*clientID = " "
	}

	address := target.Host
	if target.IP != "" {
		address = target.IP
	}

	conn, err := mqtt.NewConnection(address, opts.Port, *ssl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	err = conn.Connect(*clientID, creds.Username, creds.Password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Connection Accepted")
}
