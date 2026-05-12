// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
)

var (
	service       = flag.String("service", "", "Request a Service Ticket directly through an AS-REQ")
	principalType = flag.String("principalType", "", "PrincipalType: NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST, NT_ENTERPRISE, etc.")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag_usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	if creds.Domain == "" {
		log.Fatalf("[-] Domain is required (specify as domain/user[:pass]@target)")
	}

	if creds.Username == "" {
		log.Fatalf("[-] Username is required")
	}

	// Determine authentication method
	password := creds.Password
	ntHash := creds.Hash
	aesKey := creds.AESKey

	if password == "" && ntHash == "" && aesKey == "" && !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
		password = creds.Password
	}

	if password == "" && ntHash == "" && aesKey == "" {
		log.Fatalf("[-] No authentication method specified (need password, -hashes, or -aesKey)")
	}

	// Determine KDC address
	dcIP := creds.DCIP
	dcHost := creds.DCHost
	if dcIP == "" && dcHost == "" {
		// Use target host if specified, otherwise domain name
		if target.Host != "" {
			dcIP = target.Host
		}
	}

	// Resolve principal type
	pType := int32(0) // default: KRB_NT_PRINCIPAL
	if *principalType != "" {
		pType = parsePrincipalType(*principalType)
	}

	req := &kerberos.TGTRequest{
		Username:      creds.Username,
		Password:      password,
		Domain:        creds.Domain,
		NTHash:        ntHash,
		AESKey:        aesKey,
		DCIP:          dcIP,
		DCHost:        dcHost,
		Service:       *service,
		PrincipalType: pType,
	}

	result, err := kerberos.GetTGT(req)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	// Determine output filename
	outFile := fmt.Sprintf("%s.ccache", creds.Username)
	if opts.OutputFile != "" {
		outFile = opts.OutputFile
	}

	if err := kerberos.SaveTGT(outFile, result); err != nil {
		log.Fatalf("[-] Failed to save TGT: %v", err)
	}

	fmt.Printf("[*] Saving ticket in %s\n", outFile)
}

func parsePrincipalType(s string) int32 {
	switch s {
	case "NT_UNKNOWN":
		return nametype.KRB_NT_UNKNOWN
	case "NT_PRINCIPAL":
		return nametype.KRB_NT_PRINCIPAL
	case "NT_SRV_INST":
		return nametype.KRB_NT_SRV_INST
	case "NT_SRV_HST":
		return nametype.KRB_NT_SRV_HST
	case "NT_SRV_XHST":
		return nametype.KRB_NT_SRV_XHST
	case "NT_UID":
		return nametype.KRB_NT_UID
	case "NT_ENTERPRISE":
		return nametype.KRB_NT_ENTERPRISE
	default:
		log.Fatalf("[-] Unknown principalType: %s", s)
		return 0
	}
}

func flag_usage() {
	fmt.Fprintf(os.Stderr, "Usage: getTGT [options] [domain/]username[:password]\n")
	fmt.Fprintf(os.Stderr, "\nGiven a password, hash or aesKey, it will request a TGT and save it as ccache\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  getTGT -dc-ip 10.0.0.1 domain.local/user:Password123\n")
	fmt.Fprintf(os.Stderr, "  getTGT -hashes :nthash domain.local/user@dc.domain.local\n")
	fmt.Fprintf(os.Stderr, "  getTGT -aesKey <key> domain.local/user@dc.domain.local\n")
	fmt.Fprintf(os.Stderr, "  getTGT -service cifs/dc.domain.local domain.local/user:pass@dc.domain.local\n")
}
