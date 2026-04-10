// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/samr"
	"gopacket/pkg/dcerpc/srvsvc"
	"gopacket/pkg/dcerpc/wkssvc"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
	"gopacket/pkg/transport"
)

func main() {
	targetHost := flag.String("target", "", "Target system to query info from. If not specified script will run in domain mode.")
	targetsFile := flag.String("targets", "", "Input file with targets system to query info from (one per line). If not specified script will run in domain mode.")
	filterUser := flag.String("user", "", "Filter output by this user")
	filterUsersFile := flag.String("users", "", "Input file with list of users to filter to output for")
	noLoop := flag.Bool("noloop", false, "Stop after the first probe")
	delay := flag.Int("delay", 10, "Seconds delay between starting each batch probe (default 10 seconds)")
	maxConnections := flag.Int("max-connections", 1000, "Max amount of connections to keep opened")
	_ = maxConnections // reserved for future connection pooling

	opts := flags.Parse()

	// Default: no timestamps. -ts flag enables them via build.Timestamp.
	if build.Timestamp {
		log.SetFlags(log.LstdFlags)
	} else {
		log.SetFlags(0)
	}
	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass && !creds.UseKerberos {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	// Build user filter set
	userFilter := make(map[string]bool)
	if *filterUser != "" {
		userFilter[strings.ToLower(*filterUser)] = true
	}
	if *filterUsersFile != "" {
		lines, err := readLines(*filterUsersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read users file: %v\n", err)
			os.Exit(1)
		}
		for _, u := range lines {
			userFilter[strings.ToLower(u)] = true
		}
	}

	// Determine target list
	log.Println("[*] Importing targets")
	var targets []string
	if *targetHost != "" {
		targets = []string{*targetHost}
	} else if *targetsFile != "" {
		lines, err := readLines(*targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read targets file: %v\n", err)
			os.Exit(1)
		}
		targets = lines
	} else {
		// Domain enumeration via SAMR — connect to the DC from the target string
		log.Printf("[*] Getting machine's list from %s", creds.Domain)
		discovered, err := enumerateDomainComputers(target, &creds)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Domain computer enumeration failed: %v\n", err)
			os.Exit(1)
		}
		targets = discovered
	}

	log.Printf("[*] Got %d machines", len(targets))

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[-] No targets to monitor")
		os.Exit(1)
	}

	// Detect our own local IP for self-session filtering
	myIP := getLocalIP(targets)

	// State tracking for change detection
	prevSessions := make(map[string]map[string]bool) // target -> set of "user@host"
	prevLogins := make(map[string]map[string]bool)   // target -> set of "domain\\user"

	for {
		// Check aliveness in parallel
		alive := checkAlive(targets)
		if len(alive) == 0 {
			log.Println("[*] No alive targets found")
		}

		for _, host := range alive {
			queryHost(host, target, &creds, userFilter, creds.Username, myIP, prevSessions, prevLogins)
		}

		if *noLoop {
			break
		}

		time.Sleep(time.Duration(*delay) * time.Second)
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// getLocalIP determines our local IP by connecting to the first target.
// This is used to filter out our own sessions from SRVSVC results.
func getLocalIP(targets []string) string {
	for _, t := range targets {
		addr := t
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "445")
		}
		conn, err := transport.DialTimeout("tcp", addr, 2)
		if err == nil {
			localAddr := conn.LocalAddr().(*net.TCPAddr).IP.String()
			conn.Close()
			return localAddr
		}
	}
	return ""
}

func enumerateDomainComputers(target session.Target, creds *session.Credentials) ([]string, error) {
	smbClient := smb.NewClient(target, creds)
	if err := smbClient.Connect(); err != nil {
		return nil, fmt.Errorf("SMB connection failed: %v", err)
	}
	defer smbClient.Close()

	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		return nil, fmt.Errorf("failed to open samr pipe: %v", err)
	}
	defer pipe.Close()

	client := dcerpc.NewClient(pipe)
	if err := client.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		return nil, fmt.Errorf("failed to bind SAMR: %v", err)
	}

	samrClient := samr.NewSamrClient(client, smbClient.GetSessionKey())
	if err := samrClient.Connect(); err != nil {
		return nil, fmt.Errorf("SAMR connect failed: %v", err)
	}
	defer samrClient.Close()

	// Find the non-Builtin domain
	domains, err := samrClient.EnumerateDomains()
	if err != nil {
		return nil, fmt.Errorf("enumerate domains failed: %v", err)
	}

	domainName := ""
	for _, d := range domains {
		if !strings.EqualFold(d, "Builtin") {
			domainName = d
			break
		}
	}
	if domainName == "" {
		return nil, fmt.Errorf("no non-Builtin domain found")
	}

	if err := samrClient.OpenDomain(domainName); err != nil {
		return nil, fmt.Errorf("open domain failed: %v", err)
	}

	// Enumerate workstation trust accounts (computer accounts)
	computers, err := samrClient.EnumerateDomainUsersByType(samr.USER_WORKSTATION_TRUST_ACCOUNT)
	if err != nil {
		return nil, fmt.Errorf("enumerate computers failed: %v", err)
	}

	var hosts []string
	for _, c := range computers {
		name := c.Name
		// Strip trailing $
		name = strings.TrimSuffix(name, "$")
		if name != "" {
			hosts = append(hosts, name)
		}
	}
	return hosts, nil
}

func checkAlive(targets []string) []string {
	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			addr := host
			if !strings.Contains(addr, ":") {
				addr = net.JoinHostPort(addr, "445")
			}
			conn, err := transport.DialTimeout("tcp", addr, 2)
			if err == nil {
				conn.Close()
				mu.Lock()
				alive = append(alive, host)
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return alive
}

// makeTarget builds a session.Target for connecting to a specific host.
// For Kerberos, target.Host must be a hostname (used for the SPN cifs/<host>),
// while target.IP is the actual TCP connection address.
func makeTarget(host string, baseTarget session.Target) session.Target {
	t := baseTarget
	if net.ParseIP(host) != nil {
		// It's an IP address — use as connection IP, keep baseTarget.Host for SPN
		t.IP = host
	} else {
		// It's a hostname — use as Host for SPN, let SMB resolve or use target-ip
		t.Host = host
		t.IP = ""
	}
	return t
}

// queryHost queries both sessions (SRVSVC) and logged-on users (WKSSVC) from a
// single SMB connection to the host.
func queryHost(host string, baseTarget session.Target, creds *session.Credentials, userFilter map[string]bool, myUser, myIP string, prevSessions, prevLogins map[string]map[string]bool) {
	t := makeTarget(host, baseTarget)

	smbClient := smb.NewClient(t, creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: SMB connect failed: %v\n", host, err)
		return
	}
	defer smbClient.Close()

	// Query sessions via SRVSVC
	querySessionsOnClient(host, smbClient, userFilter, myUser, myIP, prevSessions)

	// Query logged-on users via WKSSVC
	queryLoggedOnOnClient(host, smbClient, userFilter, prevLogins)
}

func querySessionsOnClient(host string, smbClient *smb.Client, userFilter map[string]bool, myUser, myIP string, prev map[string]map[string]bool) {
	pipe, err := smbClient.OpenPipe("srvsvc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: Failed to open srvsvc pipe: %v\n", host, err)
		return
	}
	defer pipe.Close()

	client := dcerpc.NewClient(pipe)
	if err := client.Bind(srvsvc.UUID, srvsvc.MajorVersion, srvsvc.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: Failed to bind srvsvc: %v\n", host, err)
		return
	}

	sessions, err := srvsvc.NetrSessionEnum(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: NetrSessionEnum failed: %v\n", host, err)
		return
	}

	// Build current state, deduplicated, keeping first occurrence for display
	current := make(map[string]bool)
	type sessionDisplay struct {
		username   string
		source     string
		activeTime uint32
		idleTime   uint32
	}
	var unique []sessionDisplay
	for _, s := range sessions {
		source := strings.TrimPrefix(s.Cname, "\\\\")

		// Skip our own session (like Impacket does)
		if strings.EqualFold(s.Username, myUser) && source == myIP {
			continue
		}

		if len(userFilter) > 0 && !userFilter[strings.ToLower(s.Username)] {
			continue
		}
		key := s.Username + "@" + s.Cname
		if !current[key] {
			current[key] = true
			unique = append(unique, sessionDisplay{
				username:   s.Username,
				source:     source,
				activeTime: s.ActiveTime,
				idleTime:   s.IdleTime,
			})
		}
	}

	// Detect changes
	prevState := prev[host]
	if prevState == nil {
		// First run: print all unique sessions
		for _, s := range unique {
			log.Printf("[*] %s: user %s logged from host %s - active: %d, idle: %d",
				host, s.username, s.source, s.activeTime, s.idleTime)
		}
	} else {
		// Print new logins
		for _, s := range unique {
			key := s.username + "@\\\\" + s.source
			if !prevState[key] {
				log.Printf("[*] %s: user %s logged from host %s - active: %d, idle: %d",
					host, s.username, s.source, s.activeTime, s.idleTime)
			}
		}
		// Print logoffs
		for key := range prevState {
			if !current[key] {
				parts := strings.SplitN(key, "@", 2)
				user := parts[0]
				source := ""
				if len(parts) > 1 {
					source = strings.TrimPrefix(parts[1], "\\\\")
				}
				log.Printf("[*] %s: user %s logged off from host %s", host, user, source)
			}
		}
	}

	prev[host] = current
}

func queryLoggedOnOnClient(host string, smbClient *smb.Client, userFilter map[string]bool, prev map[string]map[string]bool) {
	pipe, err := smbClient.OpenPipe("wkssvc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: Failed to open wkssvc pipe: %v\n", host, err)
		return
	}
	defer pipe.Close()

	client := dcerpc.NewClient(pipe)
	if err := client.Bind(wkssvc.UUID, wkssvc.MajorVersion, wkssvc.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: Failed to bind wkssvc: %v\n", host, err)
		return
	}

	users, err := wkssvc.NetrWkstaUserEnum(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s: NetrWkstaUserEnum failed: %v\n", host, err)
		return
	}

	// Build current state, deduplicated
	current := make(map[string]bool)
	var uniqueKeys []string
	for _, u := range users {
		if len(userFilter) > 0 && !userFilter[strings.ToLower(u.Username)] {
			continue
		}
		key := u.LogonDomain + "\\" + u.Username
		if !current[key] {
			current[key] = true
			uniqueKeys = append(uniqueKeys, key)
		}
	}

	// Detect changes
	prevState := prev[host]
	if prevState == nil {
		// First run: print all unique logins
		for _, key := range uniqueKeys {
			log.Printf("[*] %s: user %s logged in LOCALLY", host, key)
		}
	} else {
		// Print new logins
		for _, key := range uniqueKeys {
			if !prevState[key] {
				log.Printf("[*] %s: user %s logged in LOCALLY", host, key)
			}
		}
		// Print logoffs
		for key := range prevState {
			if !current[key] {
				log.Printf("[*] %s: user %s logged off LOCALLY", host, key)
			}
		}
	}

	prev[host] = current
}
