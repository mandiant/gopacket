// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
	"gopacket/pkg/thirdparty/smb2"
)

// File attribute constants from MS-FSCC 2.6
const (
	FILE_ATTRIBUTE_READONLY              = 0x00000001
	FILE_ATTRIBUTE_HIDDEN                = 0x00000002
	FILE_ATTRIBUTE_SYSTEM                = 0x00000004
	FILE_ATTRIBUTE_VOLUME                = 0x00000008
	FILE_ATTRIBUTE_DIRECTORY             = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE               = 0x00000020
	FILE_ATTRIBUTE_NORMAL                = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY             = 0x00000100
	FILE_ATTRIBUTE_SPARSE_FILE           = 0x00000200
	FILE_ATTRIBUTE_REPARSE_POINT         = 0x00000400
	FILE_ATTRIBUTE_COMPRESSED            = 0x00000800
	FILE_ATTRIBUTE_OFFLINE               = 0x00001000
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   = 0x00002000
	FILE_ATTRIBUTE_ENCRYPTED             = 0x00004000
	FILE_ATTRIBUTE_NO_SCRUB_DATA         = 0x00020000
	FILE_ATTRIBUTE_RECALL_ON_OPEN        = 0x00040000
	FILE_ATTRIBUTE_PINNED                = 0x00080000
	FILE_ATTRIBUTE_UNPINNED              = 0x00100000
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
)

// FileAttributes represents parsed file attributes
type FileAttributes struct {
	Readonly           bool
	Hidden             bool
	System             bool
	Volume             bool
	Directory          bool
	Archive            bool
	Normal             bool
	Temporary          bool
	SparseFile         bool
	ReparsePoint       bool
	Compressed         bool
	Offline            bool
	NotContentIndexed  bool
	Encrypted          bool
	NoScrubData        bool
	RecallOnOpen       bool
	Pinned             bool
	Unpinned           bool
	RecallOnDataAccess bool
}

// Pack converts FileAttributes to a uint32 bitmask
func (fa *FileAttributes) Pack() uint32 {
	var attrs uint32
	if fa.Readonly {
		attrs |= FILE_ATTRIBUTE_READONLY
	}
	if fa.Hidden {
		attrs |= FILE_ATTRIBUTE_HIDDEN
	}
	if fa.System {
		attrs |= FILE_ATTRIBUTE_SYSTEM
	}
	if fa.Volume {
		attrs |= FILE_ATTRIBUTE_VOLUME
	}
	if fa.Directory {
		attrs |= FILE_ATTRIBUTE_DIRECTORY
	}
	if fa.Archive {
		attrs |= FILE_ATTRIBUTE_ARCHIVE
	}
	if fa.Normal {
		attrs |= FILE_ATTRIBUTE_NORMAL
	}
	if fa.Temporary {
		attrs |= FILE_ATTRIBUTE_TEMPORARY
	}
	if fa.SparseFile {
		attrs |= FILE_ATTRIBUTE_SPARSE_FILE
	}
	if fa.ReparsePoint {
		attrs |= FILE_ATTRIBUTE_REPARSE_POINT
	}
	if fa.Compressed {
		attrs |= FILE_ATTRIBUTE_COMPRESSED
	}
	if fa.Offline {
		attrs |= FILE_ATTRIBUTE_OFFLINE
	}
	if fa.NotContentIndexed {
		attrs |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	}
	if fa.Encrypted {
		attrs |= FILE_ATTRIBUTE_ENCRYPTED
	}
	if fa.NoScrubData {
		attrs |= FILE_ATTRIBUTE_NO_SCRUB_DATA
	}
	if fa.RecallOnOpen {
		attrs |= FILE_ATTRIBUTE_RECALL_ON_OPEN
	}
	if fa.Pinned {
		attrs |= FILE_ATTRIBUTE_PINNED
	}
	if fa.Unpinned {
		attrs |= FILE_ATTRIBUTE_UNPINNED
	}
	if fa.RecallOnDataAccess {
		attrs |= FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
	}
	return attrs
}

// Unpack creates FileAttributes from a uint32 bitmask
func UnpackAttributes(attrs uint32) *FileAttributes {
	return &FileAttributes{
		Readonly:           attrs&FILE_ATTRIBUTE_READONLY != 0,
		Hidden:             attrs&FILE_ATTRIBUTE_HIDDEN != 0,
		System:             attrs&FILE_ATTRIBUTE_SYSTEM != 0,
		Volume:             attrs&FILE_ATTRIBUTE_VOLUME != 0,
		Directory:          attrs&FILE_ATTRIBUTE_DIRECTORY != 0,
		Archive:            attrs&FILE_ATTRIBUTE_ARCHIVE != 0,
		Normal:             attrs&FILE_ATTRIBUTE_NORMAL != 0,
		Temporary:          attrs&FILE_ATTRIBUTE_TEMPORARY != 0,
		SparseFile:         attrs&FILE_ATTRIBUTE_SPARSE_FILE != 0,
		ReparsePoint:       attrs&FILE_ATTRIBUTE_REPARSE_POINT != 0,
		Compressed:         attrs&FILE_ATTRIBUTE_COMPRESSED != 0,
		Offline:            attrs&FILE_ATTRIBUTE_OFFLINE != 0,
		NotContentIndexed:  attrs&FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0,
		Encrypted:          attrs&FILE_ATTRIBUTE_ENCRYPTED != 0,
		NoScrubData:        attrs&FILE_ATTRIBUTE_NO_SCRUB_DATA != 0,
		RecallOnOpen:       attrs&FILE_ATTRIBUTE_RECALL_ON_OPEN != 0,
		Pinned:             attrs&FILE_ATTRIBUTE_PINNED != 0,
		Unpinned:           attrs&FILE_ATTRIBUTE_UNPINNED != 0,
		RecallOnDataAccess: attrs&FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0,
	}
}

// String returns a compact representation of the attributes
func (fa *FileAttributes) String() string {
	var b strings.Builder
	if fa.Readonly {
		b.WriteRune('R')
	} else {
		b.WriteRune('-')
	}
	if fa.Hidden {
		b.WriteRune('H')
	} else {
		b.WriteRune('-')
	}
	if fa.System {
		b.WriteRune('S')
	} else {
		b.WriteRune('-')
	}
	if fa.Volume {
		b.WriteRune('V')
	} else {
		b.WriteRune('-')
	}
	if fa.Directory {
		b.WriteRune('D')
	} else {
		b.WriteRune('-')
	}
	if fa.Archive {
		b.WriteRune('A')
	} else {
		b.WriteRune('-')
	}
	if fa.Normal {
		b.WriteRune('N')
	} else {
		b.WriteRune('-')
	}
	if fa.Temporary {
		b.WriteRune('T')
	} else {
		b.WriteRune('-')
	}
	if fa.Compressed {
		b.WriteRune('C')
	} else {
		b.WriteRune('-')
	}
	if fa.Offline {
		b.WriteRune('O')
	} else {
		b.WriteRune('-')
	}
	if fa.Encrypted {
		b.WriteRune('E')
	} else {
		b.WriteRune('-')
	}
	if fa.Pinned {
		b.WriteRune('P')
	} else {
		b.WriteRune('-')
	}
	if fa.Unpinned {
		b.WriteRune('U')
	} else {
		b.WriteRune('-')
	}
	return b.String()
}

var (
	shareName string
	filePath  string
	timeout   int

	// Set action flags
	setReadonly   bool
	setHidden     bool
	setSystem     bool
	setArchive    bool
	setNormal     bool
	setTemporary  bool
	setCompressed bool
	setOffline    bool
	setEncrypted  bool
	setPinned     bool
	setUnpinned   bool
)

func main() {
	// Define tool-specific flags
	flag.StringVar(&shareName, "share", "", "The share in which the file resides")
	flag.StringVar(&filePath, "path", "", "The path of the file whose attributes to query or modify")
	flag.IntVar(&timeout, "timeout", 60, "Set connection timeout (seconds)")

	// Set action attribute flags
	flag.BoolVar(&setReadonly, "r", false, "Set readonly attribute")
	flag.BoolVar(&setHidden, "H", false, "Set hidden attribute")
	flag.BoolVar(&setSystem, "s", false, "Set system attribute")
	flag.BoolVar(&setArchive, "a", false, "Set archive attribute")
	flag.BoolVar(&setNormal, "n", false, "Set normal attribute (clears all others)")
	flag.BoolVar(&setTemporary, "t", false, "Set temporary attribute")
	flag.BoolVar(&setCompressed, "c", false, "Set compressed attribute")
	flag.BoolVar(&setOffline, "o", false, "Set offline attribute")
	flag.BoolVar(&setEncrypted, "e", false, "Set encrypted attribute")
	flag.BoolVar(&setPinned, "p", false, "Set pinned attribute")
	flag.BoolVar(&setUnpinned, "u", false, "Set unpinned attribute")

	opts := flags.Parse()

	if opts.TargetStr == "" {
		printUsage()
		os.Exit(1)
	}

	// Get action from remaining arguments
	action := ""
	if len(opts.Arguments) > 0 {
		action = opts.Arguments[0]
	}

	if action == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: action required (query or set)")
		printUsage()
		os.Exit(1)
	}

	if action != "query" && action != "set" {
		fmt.Fprintf(os.Stderr, "[-] Error: invalid action '%s' (must be 'query' or 'set')\n", action)
		os.Exit(1)
	}

	if shareName == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: -share is required")
		os.Exit(1)
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: -path is required")
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

	// Connect to SMB (authentication is done in Connect)
	client := smb.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(); err != nil {
		log.Fatalf("[-] Failed to connect/login: %v", err)
	}

	// Mount the share
	share, err := client.Session.Mount(shareName)
	if err != nil {
		log.Fatalf("[-] Failed to mount share '%s': %v", shareName, err)
	}
	defer share.Umount()

	// Normalize path (convert forward slashes to backslashes for Windows)
	normalizedPath := filepath.ToSlash(filePath)
	normalizedPath = strings.ReplaceAll(normalizedPath, "/", "\\")
	normalizedPath = strings.TrimPrefix(normalizedPath, "\\")

	if action == "query" {
		// Query file attributes
		attrs, err := queryAttributes(share, normalizedPath)
		if err != nil {
			log.Fatalf("[-] Failed to query attributes: %v", err)
		}
		fmt.Printf("%s %s %s\n", attrs.String(), shareName, filePath)
	} else if action == "set" {
		// Set file attributes
		newAttrs := &FileAttributes{
			Readonly:   setReadonly,
			Hidden:     setHidden,
			System:     setSystem,
			Archive:    setArchive,
			Normal:     setNormal,
			Temporary:  setTemporary,
			Compressed: setCompressed,
			Offline:    setOffline,
			Encrypted:  setEncrypted,
			Pinned:     setPinned,
			Unpinned:   setUnpinned,
		}

		if err := setAttributes(share, normalizedPath, newAttrs); err != nil {
			log.Fatalf("[-] Failed to set attributes: %v", err)
		}
		fmt.Printf("%s %s %s\n", newAttrs.String(), shareName, filePath)
	}
}

func queryAttributes(share *smb2.Share, path string) (*FileAttributes, error) {
	// Open file with read attributes access
	f, err := share.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	// Get file stat which includes attributes
	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %v", err)
	}

	// Extract attributes from stat
	// The smb2.FileStat has FileAttributes field
	if fileStat, ok := stat.(*smb2.FileStat); ok {
		return UnpackAttributes(fileStat.FileAttributes), nil
	}

	return nil, fmt.Errorf("unexpected stat type")
}

func setAttributes(share *smb2.Share, path string, attrs *FileAttributes) error {
	// Pack the attributes into a uint32 bitmask
	attrValue := attrs.Pack()

	// If no attributes are set, use NORMAL
	if attrValue == 0 {
		attrValue = FILE_ATTRIBUTE_NORMAL
	}

	// Use the library's SetFileAttributes method which opens the file with
	// FILE_WRITE_ATTRIBUTES access and sets the attributes directly
	return share.SetFileAttributes(path, attrValue)
}

func printUsage() {
	fmt.Println("File Attribute Modification Utility")
	fmt.Println()
	fmt.Println("Usage: attrib [options] target <action>")
	fmt.Println()
	fmt.Println("Target:")
	fmt.Println("  [[domain/]username[:password]@]<targetName or address>")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  query    Query current file/directory attributes")
	fmt.Println("  set      Modify file/directory attributes")
	fmt.Println()
	fmt.Println("Required Options:")
	fmt.Println("  -share string    The share in which the file resides")
	fmt.Println("  -path string     The path of the file to query or modify")
	fmt.Println()
	fmt.Println("Set Action Flags (use with 'set' action):")
	fmt.Println("  -r    Set readonly attribute")
	fmt.Println("  -H    Set hidden attribute")
	fmt.Println("  -s    Set system attribute")
	fmt.Println("  -a    Set archive attribute")
	fmt.Println("  -n    Set normal attribute (clears all others)")
	fmt.Println("  -t    Set temporary attribute")
	fmt.Println("  -c    Set compressed attribute")
	fmt.Println("  -o    Set offline attribute")
	fmt.Println("  -e    Set encrypted attribute")
	fmt.Println("  -p    Set pinned attribute")
	fmt.Println("  -u    Set unpinned attribute")
	fmt.Println()
	fmt.Println("Attribute Output Format:")
	fmt.Println("  R=Readonly, H=Hidden, S=System, V=Volume, D=Directory")
	fmt.Println("  A=Archive, N=Normal, T=Temporary, C=Compressed")
	fmt.Println("  O=Offline, E=Encrypted, P=Pinned, U=Unpinned")
	fmt.Println()
	flag.PrintDefaults()
}
