// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/lsarpc"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	domainSids = flag.Bool("domain-sids", false, "Enumerate Domain SIDs (will likely forward requests to the DC)")
)

func main() {
	flags.ExtraUsageLine = "[maxRid]"
	flags.ExtraUsageText = "\nPositional:\n  maxRid              max Rid to check (default 4000)"
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	maxRid := 4000
	if len(opts.Arguments) > 0 {
		if v, err := strconv.Atoi(opts.Arguments[0]); err == nil {
			maxRid = v
		}
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass && creds.Password == "" && creds.Hash == "" && creds.AESKey == "" {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("gopacket v0.1.0 - lookupsid")
	fmt.Println()
	fmt.Printf("[*] Brute forcing SIDs at %s\n", target.Host)

	if target.Port == 0 {
		target.Port = 445
	}

	fmt.Printf("[*] StringBinding ncacn_np:%s[\\pipe\\lsarpc]\n", target.Host)

	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open lsarpc pipe: %v\n", err)
		os.Exit(1)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] LSARPC bind failed: %v\n", err)
		os.Exit(1)
	}

	lsaClient, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] LSA client creation failed: %v\n", err)
		os.Exit(1)
	}
	defer lsaClient.Close()

	var domainSID string
	if *domainSids {
		_, domainSID, err = lsaClient.QueryPrimaryDomainSID()
	} else {
		_, domainSID, err = lsaClient.QueryDomainSID()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to query domain SID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Domain SID is: %s\n", domainSID)

	const batchSize = 64
	for start := 0; start < maxRid; start += batchSize {
		end := start + batchSize
		if end > maxRid {
			end = maxRid
		}

		var sids []string
		for rid := start; rid < end; rid++ {
			sids = append(sids, fmt.Sprintf("%s-%d", domainSID, rid))
		}

		results, err := lsaClient.LookupSids(sids)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] LookupSids error: %v\n", err)
			continue
		}

		for i, r := range results {
			if r.SidType == lsarpc.SidTypeUnknown {
				continue
			}
			rid := start + i
			fmt.Printf("%d: %s\\%s (%s)\n", rid, r.Domain, r.Name, r.SidTypeStr)
		}
	}
}
