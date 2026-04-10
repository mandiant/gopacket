// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf16"

	"gopacket/pkg/dcerpc/gkdi"
	"gopacket/pkg/dpaping"
	"gopacket/pkg/flags"
	"gopacket/pkg/ldap"
	"gopacket/pkg/session"
)

var (
	computer string
	useLDAPS bool
)

// LAPSEntry holds LAPS password information for a computer
type LAPSEntry struct {
	Host               string
	LAPSUsername       string
	LAPSPassword       string
	LAPSPasswordExpiry string
	LAPSv2             bool
}

// GKDICache caches GroupKeyEnvelope responses to avoid redundant RPC calls
var gkdiCache = make(map[[16]byte]*gkdi.GroupKeyEnvelope)

func main() {
	// Register tool-specific flags before Parse()
	flag.StringVar(&computer, "computer", "", "Target a specific computer by its name")
	flag.BoolVar(&useLDAPS, "ldaps", false, "Enable LDAPS (LDAP over SSL)")

	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	// Set default LDAP port
	if target.Port == 0 {
		if useLDAPS {
			target.Port = 636
		} else {
			target.Port = 389
		}
	}

	// Initialize LDAP Client
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	// Connect (use TLS if LDAPS is requested)
	if err := client.Connect(useLDAPS); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}

	// Login - convert to UPN format for simple bind if not using hash/Kerberos
	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	if err := client.Login(); err != nil {
		log.Fatalf("[-] Bind failed: %v", err)
	}

	// Get Domain Context
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get Naming Context: %v", err)
	}

	// Build LDAP filter for computers with LAPS attributes
	filter := "(&(objectCategory=computer)(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))"
	if computer != "" {
		// Filter for specific computer
		computerName := computer
		if !strings.HasSuffix(computerName, "$") {
			computerName += "$"
		}
		filter = fmt.Sprintf("(&(objectCategory=computer)(objectClass=computer)(sAMAccountName=%s)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))", computerName)
	}

	// LAPS attributes to retrieve
	attributes := []string{
		"sAMAccountName",
		"ms-Mcs-AdmPwd",                 // LAPS v1 password
		"ms-Mcs-AdmPwdExpirationTime",   // LAPS v1 expiration
		"msLAPS-Password",               // LAPS v2 plaintext (JSON)
		"msLAPS-EncryptedPassword",      // LAPS v2 encrypted
		"msLAPS-PasswordExpirationTime", // LAPS v2 expiration
	}

	results, err := client.SearchWithPaging(baseDN, filter, attributes, 100)
	if err != nil {
		log.Fatalf("[-] Search failed: %v", err)
	}

	var entries []LAPSEntry

	for _, entry := range results.Entries {
		samName := entry.GetAttributeValue("sAMAccountName")

		// Try LAPS v1 first
		lapsv1Pwd := entry.GetAttributeValue("ms-Mcs-AdmPwd")
		lapsv1Exp := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")

		// Try LAPS v2 plaintext
		lapsv2Pwd := entry.GetAttributeValue("msLAPS-Password")
		lapsv2Exp := entry.GetAttributeValue("msLAPS-PasswordExpirationTime")

		// Try LAPS v2 encrypted
		lapsv2EncPwd := entry.GetRawAttributeValue("msLAPS-EncryptedPassword")

		var lapsEntry LAPSEntry
		lapsEntry.Host = samName

		if lapsv1Pwd != "" {
			// LAPS v1 (Legacy LAPS doesn't store username, it's always local Administrator)
			lapsEntry.LAPSUsername = "N/A"
			lapsEntry.LAPSPassword = lapsv1Pwd
			lapsEntry.LAPSPasswordExpiry = formatWindowsTime(lapsv1Exp)
			lapsEntry.LAPSv2 = false
			entries = append(entries, lapsEntry)
		} else if lapsv2Pwd != "" {
			// LAPS v2 plaintext (JSON format)
			lapsEntry.LAPSv2 = true
			if username, password, ok := parseLAPSv2JSON(lapsv2Pwd); ok {
				lapsEntry.LAPSUsername = username
				lapsEntry.LAPSPassword = password
			}
			lapsEntry.LAPSPasswordExpiry = formatWindowsTime(lapsv2Exp)
			entries = append(entries, lapsEntry)
		} else if len(lapsv2EncPwd) > 0 {
			// LAPS v2 encrypted - requires MS-GKDI RPC to decrypt
			lapsEntry.LAPSv2 = true
			lapsEntry.LAPSPasswordExpiry = formatWindowsTime(lapsv2Exp)

			// Attempt decryption
			username, password, err := decryptLAPSv2Password(lapsv2EncPwd, target, &creds)
			if err != nil {
				log.Printf("[!] Failed to decrypt LAPS v2 password for %s: %v", samName, err)
				lapsEntry.LAPSUsername = "N/A"
				lapsEntry.LAPSPassword = fmt.Sprintf("[Decryption failed: %v]", err)
			} else {
				lapsEntry.LAPSUsername = username
				lapsEntry.LAPSPassword = password
			}
			entries = append(entries, lapsEntry)
		}
	}

	if len(entries) == 0 {
		if computer != "" {
			log.Fatalf("[-] No LAPS data returned for %s", computer)
		} else {
			log.Fatalf("[-] No LAPS data returned")
		}
	}

	// Print results
	printResults(entries)

	// Write to file if specified
	if opts.OutputFile != "" {
		writeResults(entries, opts.OutputFile)
	}
}

// decryptLAPSv2Password decrypts an encrypted LAPS v2 password using MS-GKDI.
func decryptLAPSv2Password(encryptedBlob []byte, target session.Target, creds *session.Credentials) (username, password string, err error) {
	// Parse the encrypted password blob
	blob, err := dpaping.ParseEncryptedPasswordBlob(encryptedBlob)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse encrypted blob: %v", err)
	}

	// Parse the CMS EnvelopedData structure
	cms, remaining, err := dpaping.ParseCMSEnvelopedData(blob.Blob)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse CMS: %v", err)
	}

	// Parse the key identifier
	keyID, err := dpaping.ParseKeyIdentifier(cms.KeyIdentifier)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse key identifier: %v", err)
	}

	// Check cache for existing GroupKeyEnvelope
	var gke *gkdi.GroupKeyEnvelope
	if cached, ok := gkdiCache[keyID.RootKeyID]; ok {
		gke = cached
	} else {
		// Create security descriptor from SID
		if cms.SID == "" {
			return "", "", fmt.Errorf("no SID found in CMS structure")
		}
		targetSD := dpaping.CreateSecurityDescriptor(cms.SID)

		// Connect to GKDI service
		gkdiClient, err := gkdi.NewClient(target, creds)
		if err != nil {
			return "", "", fmt.Errorf("failed to connect to GKDI: %v", err)
		}
		defer gkdiClient.Close()

		// Call GetKey
		gke, err = gkdiClient.GetKey(
			targetSD,
			&keyID.RootKeyID,
			int32(keyID.L0Index),
			int32(keyID.L1Index),
			int32(keyID.L2Index),
		)
		if err != nil {
			return "", "", fmt.Errorf("GKDI GetKey failed: %v", err)
		}

		// Cache the result
		gkdiCache[keyID.RootKeyID] = gke
	}

	// Compute KEK
	kek, err := dpaping.ComputeKEK(gke, keyID)
	if err != nil {
		return "", "", fmt.Errorf("failed to compute KEK: %v", err)
	}

	// Unwrap CEK
	cek, err := dpaping.AESKeyUnwrap(kek, cms.EncryptedKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to unwrap CEK: %v", err)
	}

	// Decrypt content
	plaintext, err := dpaping.DecryptContent(cek, cms.IV, cms.Ciphertext)
	if err != nil {
		// Try with remaining data as ciphertext (some formats append auth tag differently)
		if len(remaining) > 0 {
			combinedCiphertext := append(cms.Ciphertext, remaining...)
			plaintext, err = dpaping.DecryptContent(cek, cms.IV, combinedCiphertext)
		}
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt content: %v", err)
		}
	}

	// Parse the decrypted JSON
	// Format: {"n":"Administrator","t":"2024-01-01T00:00:00","p":"password"}
	// The plaintext may have trailing data (18 bytes of metadata)
	jsonData := plaintext
	if len(jsonData) > 18 {
		// Try to find the end of JSON object
		for i := len(jsonData) - 1; i >= 0; i-- {
			if jsonData[i] == '}' {
				jsonData = jsonData[:i+1]
				break
			}
		}
	}

	// Convert from UTF-16LE to string
	jsonStr := utf16ToString(jsonData)

	username, password, ok := parseLAPSv2JSON(jsonStr)
	if !ok {
		return "", "", fmt.Errorf("failed to parse decrypted JSON: %s", jsonStr)
	}

	return username, password, nil
}

// utf16ToString converts UTF-16LE bytes to a Go string
func utf16ToString(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}

	// Check for BOM
	start := 0
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		start = 2
	}

	// Convert pairs of bytes to uint16
	u16s := make([]uint16, 0, (len(b)-start)/2)
	for i := start; i+1 < len(b); i += 2 {
		u16 := uint16(b[i]) | uint16(b[i+1])<<8
		if u16 == 0 {
			break
		}
		u16s = append(u16s, u16)
	}

	return string(utf16.Decode(u16s))
}

// parseLAPSv2JSON parses the LAPS v2 JSON format
// Format: {"n":"Administrator","t":"2024-01-01T00:00:00","p":"password"}
func parseLAPSv2JSON(jsonStr string) (username, password string, ok bool) {
	var data struct {
		N string `json:"n"` // username
		T string `json:"t"` // timestamp
		P string `json:"p"` // password
	}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return "", "", false
	}
	return data.N, data.P, true
}

// formatWindowsTime converts Windows FILETIME to human-readable format
func formatWindowsTime(fileTimeStr string) string {
	if fileTimeStr == "" || fileTimeStr == "0" {
		return "N/A"
	}

	var fileTime int64
	fmt.Sscanf(fileTimeStr, "%d", &fileTime)
	if fileTime == 0 {
		return "N/A"
	}

	// Windows FILETIME is 100-nanosecond intervals since January 1, 1601
	// Convert to Unix timestamp
	const windowsEpochDiff = 116444736000000000 // 100-ns intervals between 1601 and 1970
	unixNano := (fileTime - windowsEpochDiff) * 100
	t := time.Unix(0, unixNano)

	return t.Format("2006-01-02 15:04:05")
}

func printResults(entries []LAPSEntry) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Host\tLAPS Username\tLAPS Password\tLAPS Password Expiration\tLAPSv2")
	fmt.Fprintln(w, "----\t-------------\t-------------\t------------------------\t------")

	for _, e := range entries {
		lapsv2Str := "False"
		if e.LAPSv2 {
			lapsv2Str = "True"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Host, e.LAPSUsername, e.LAPSPassword, e.LAPSPasswordExpiry, lapsv2Str)
	}
	w.Flush()
}

func writeResults(entries []LAPSEntry, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Printf("[-] Failed to create output file: %v", err)
		return
	}
	defer f.Close()

	w := tabwriter.NewWriter(f, 0, 0, 1, '\t', 0)
	fmt.Fprintln(w, "Host\tLAPS Username\tLAPS Password\tLAPS Password Expiration\tLAPSv2")

	for _, e := range entries {
		lapsv2Str := "False"
		if e.LAPSv2 {
			lapsv2Str = "True"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Host, e.LAPSUsername, e.LAPSPassword, e.LAPSPasswordExpiry, lapsv2Str)
	}
	w.Flush()
	fmt.Printf("[+] Results written to %s\n", filename)
}
