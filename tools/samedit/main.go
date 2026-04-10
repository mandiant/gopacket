// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/pkg/kerberos"
	"gopacket/pkg/registry"
)

func main() {
	systemFile := flag.String("system", "", "SYSTEM hive file for bootkey extraction")
	bootKeyHex := flag.String("bootkey", "", "Hex bootkey value directly")
	password := flag.String("password", "", "New password to set")
	hashes := flag.String("hashes", "", "NTLM hash (LM:NT or just NT)")
	debug := flag.Bool("debug", false, "Debug output")
	ts := flag.Bool("ts", false, "Timestamps in output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <user> <sam>\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Edit a local user's password in an offline SAM hive file.")
		fmt.Fprintln(os.Stderr, "\nArguments:")
		fmt.Fprintln(os.Stderr, "  user    Username to edit")
		fmt.Fprintln(os.Stderr, "  sam     SAM hive file path")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *ts {
		log.SetFlags(log.LstdFlags)
	} else {
		log.SetFlags(0)
	}

	if *debug {
		log.Println("[DEBUG] Debug mode enabled")
	}

	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	username := args[0]
	samPath := args[1]

	// Validate: must provide -system or -bootkey (not both)
	if *systemFile == "" && *bootKeyHex == "" {
		log.Fatal("[-] Must provide either -system or -bootkey")
	}
	if *systemFile != "" && *bootKeyHex != "" {
		log.Fatal("[-] Provide either -system or -bootkey, not both")
	}

	// Validate: must provide -password or -hashes (not both)
	if *password == "" && *hashes == "" {
		log.Fatal("[-] Must provide either -password or -hashes")
	}
	if *password != "" && *hashes != "" {
		log.Fatal("[-] Provide either -password or -hashes, not both")
	}

	// Get boot key
	var bootKey []byte
	if *systemFile != "" {
		sysData, err := os.ReadFile(*systemFile)
		if err != nil {
			log.Fatalf("[-] Failed to read SYSTEM hive: %v", err)
		}
		sysHive, err := registry.Open(sysData)
		if err != nil {
			log.Fatalf("[-] Failed to parse SYSTEM hive: %v", err)
		}
		bootKey, err = registry.GetBootKey(sysHive)
		if err != nil {
			log.Fatalf("[-] Failed to extract boot key: %v", err)
		}
		if *debug {
			log.Printf("[DEBUG] Boot key: %s", hex.EncodeToString(bootKey))
		}
	} else {
		var err error
		bootKey, err = hex.DecodeString(*bootKeyHex)
		if err != nil || len(bootKey) != 16 {
			log.Fatal("[-] Invalid bootkey: must be 32 hex characters (16 bytes)")
		}
	}

	// Determine new hashes
	var newNTHash, newLMHash []byte
	if *password != "" {
		newNTHash = kerberos.GetNTHash(*password)
		newLMHash = registry.EmptyLMHash
		if *debug {
			log.Printf("[DEBUG] Computed NT hash from password: %s", hex.EncodeToString(newNTHash))
		}
	} else {
		parts := strings.Split(*hashes, ":")
		switch len(parts) {
		case 1:
			// Just NT hash
			var err error
			newNTHash, err = hex.DecodeString(parts[0])
			if err != nil || len(newNTHash) != 16 {
				log.Fatal("[-] Invalid NT hash: must be 32 hex characters")
			}
			newLMHash = registry.EmptyLMHash
		case 2:
			// LM:NT
			var err error
			if parts[0] != "" {
				newLMHash, err = hex.DecodeString(parts[0])
				if err != nil || len(newLMHash) != 16 {
					log.Fatal("[-] Invalid LM hash: must be 32 hex characters")
				}
			} else {
				newLMHash = registry.EmptyLMHash
			}
			newNTHash, err = hex.DecodeString(parts[1])
			if err != nil || len(newNTHash) != 16 {
				log.Fatal("[-] Invalid NT hash: must be 32 hex characters")
			}
		default:
			log.Fatal("[-] Invalid -hashes format: use LM:NT or just NT")
		}
	}

	// Read and parse SAM hive
	samData, err := os.ReadFile(samPath)
	if err != nil {
		log.Fatalf("[-] Failed to read SAM hive: %v", err)
	}

	samHive, err := registry.Open(samData)
	if err != nil {
		log.Fatalf("[-] Failed to parse SAM hive: %v", err)
	}

	// Edit the password
	if err := registry.EditSAMPassword(samHive, bootKey, username, newNTHash, newLMHash); err != nil {
		log.Fatalf("[-] Failed to edit password: %v", err)
	}

	// Write modified hive back
	if err := os.WriteFile(samPath, samHive.Data(), 0644); err != nil {
		log.Fatalf("[-] Failed to write SAM hive: %v", err)
	}

	fmt.Printf("[+] SAM hive saved to %s\n", samPath)
}
