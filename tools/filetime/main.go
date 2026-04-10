// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
	"gopacket/pkg/thirdparty/smb2"
)

var (
	// Which timestamps to target (for touch)
	targetCreate bool
	targetAccess bool
	targetWrite  bool
	targetModify bool

	// Touch options
	refShare  string
	refPath   string
	timestamp string
	validate  bool
)

func main() {
	// Target timestamp flags (for touch) - defined before Parse
	flag.BoolVar(&targetCreate, "c", false, "Change the CreationTime of the file / directory")
	flag.BoolVar(&targetCreate, "create", false, "Change the CreationTime of the file / directory")
	flag.BoolVar(&targetAccess, "a", false, "Change the LastAccessTime of the file / directory")
	flag.BoolVar(&targetAccess, "access", false, "Change the LastAccessTime of the file / directory")
	flag.BoolVar(&targetWrite, "w", false, "Change the LastWriteTime of the file / directory")
	flag.BoolVar(&targetWrite, "write", false, "Change the LastWriteTime of the file / directory")
	flag.BoolVar(&targetModify, "m", false, "Change the ChangeTime of the file / directory")
	flag.BoolVar(&targetModify, "modify", false, "Change the ChangeTime of the file / directory")

	// Touch options
	flag.StringVar(&timestamp, "t", "", "Specify a timestamp to set (format: YYYY-MM-DD_HH:MM:SS.mmmmmm)")
	flag.StringVar(&timestamp, "timestamp", "", "Specify a timestamp to set (format: YYYY-MM-DD_HH:MM:SS.mmmmmm)")
	flag.BoolVar(&validate, "v", false, "Query the file after touching to verify the changes")
	flag.BoolVar(&validate, "validate", false, "Query the file after touching to verify the changes")

	opts := flags.Parse()

	// Parse positional arguments: target share path {stat,touch}
	if opts.TargetStr == "" || len(opts.Arguments) < 3 {
		printUsage()
		os.Exit(1)
	}

	shareName := opts.Arguments[0]
	filePath := opts.Arguments[1]
	action := opts.Arguments[2]

	// Parse remaining arguments after action for touch-specific options
	// This handles flags that come after the action (like Impacket does)
	if len(opts.Arguments) > 3 {
		remainingArgs := opts.Arguments[3:]
		for i := 0; i < len(remainingArgs); i++ {
			arg := remainingArgs[i]
			switch arg {
			case "-c", "--create":
				targetCreate = true
			case "-a", "--access":
				targetAccess = true
			case "-w", "--write":
				targetWrite = true
			case "-m", "--modify":
				targetModify = true
			case "-v", "--validate":
				validate = true
			case "-t", "--timestamp":
				if i+1 < len(remainingArgs) {
					timestamp = remainingArgs[i+1]
					i++
				}
			case "-r", "--reference":
				if i+2 < len(remainingArgs) {
					refShare = remainingArgs[i+1]
					refPath = remainingArgs[i+2]
					i += 2
				} else {
					fmt.Fprintln(os.Stderr, "[-] Error: -r/--reference requires <share> <path> arguments")
					os.Exit(1)
				}
			}
		}
	}

	if action != "stat" && action != "touch" {
		fmt.Fprintf(os.Stderr, "[-] Error: invalid action '%s' (must be 'stat' or 'touch')\n", action)
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

	// Connect to SMB
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

	// Normalize path
	normalizedPath := normalizePath(filePath)

	if action == "stat" {
		doStat(share, shareName, filePath, normalizedPath)
	} else if action == "touch" {
		doTouch(client, share, shareName, filePath, normalizedPath)
	}
}

func doStat(share *smb2.Share, shareName, displayPath, normalizedPath string) {
	// Get file info
	stat, err := share.Stat(normalizedPath)
	if err != nil {
		log.Fatalf("[-] Failed to stat file: %v", err)
	}

	fileStat, ok := stat.(*smb2.FileStat)
	if !ok {
		log.Fatal("[-] Failed to get file stat")
	}

	// Format path with backslashes for display
	displayPath = strings.ReplaceAll(displayPath, "/", "\\")

	fmt.Printf("[*] Queried FileTimes for '%s' on share '%s'!\n\n", displayPath, shareName)
	fmt.Printf("CreationTime: %s\n", formatTimeImpacket(fileStat.CreationTime))
	fmt.Printf("LastAccessTime: %s\n", formatTimeImpacket(fileStat.LastAccessTime))
	fmt.Printf("LastWriteTime: %s\n", formatTimeImpacket(fileStat.LastWriteTime))
	fmt.Printf("ChangeTime: %s\n", formatTimeImpacket(fileStat.ChangeTime))
}

func doTouch(client *smb.Client, share *smb2.Share, shareName, displayPath, normalizedPath string) {
	// Validate that at least one timestamp target is specified
	if !targetCreate && !targetAccess && !targetWrite && !targetModify {
		// Default to all timestamps like touch command
		targetCreate = true
		targetAccess = true
		targetWrite = true
		targetModify = true
	}

	// Prepare the timestamps to set
	var creationTime, accessTime, writeTime, changeTime *time.Time
	var displayCreation, displayAccess, displayWrite, displayChange time.Time

	if refShare != "" && refPath != "" {
		// Get timestamps from reference file
		refTimes, err := getRefFileTimes(client, refShare, refPath)
		if err != nil {
			log.Fatalf("[-] Failed to get reference file timestamps: %v", err)
		}

		// Use the corresponding timestamp from the reference file for each target
		if targetCreate {
			creationTime = &refTimes.CreationTime
			displayCreation = refTimes.CreationTime
		}
		if targetAccess {
			accessTime = &refTimes.LastAccessTime
			displayAccess = refTimes.LastAccessTime
		}
		if targetWrite {
			writeTime = &refTimes.LastWriteTime
			displayWrite = refTimes.LastWriteTime
		}
		if targetModify {
			changeTime = &refTimes.ChangeTime
			displayChange = refTimes.ChangeTime
		}
	} else if timestamp != "" {
		// Parse the timestamp
		t, err := parseTimestamp(timestamp)
		if err != nil {
			log.Fatalf("[-] Failed to parse timestamp: %v", err)
		}

		if targetCreate {
			creationTime = &t
			displayCreation = t
		}
		if targetAccess {
			accessTime = &t
			displayAccess = t
		}
		if targetWrite {
			writeTime = &t
			displayWrite = t
		}
		if targetModify {
			changeTime = &t
			displayChange = t
		}
	} else {
		// Default to current time
		now := time.Now()

		if targetCreate {
			creationTime = &now
			displayCreation = now
		}
		if targetAccess {
			accessTime = &now
			displayAccess = now
		}
		if targetWrite {
			writeTime = &now
			displayWrite = now
		}
		if targetModify {
			changeTime = &now
			displayChange = now
		}
	}

	// Set the timestamps
	err := share.SetFileTimes(normalizedPath, creationTime, accessTime, writeTime, changeTime)
	if err != nil {
		log.Fatalf("[-] Failed to set timestamps: %v", err)
	}

	// Format path with backslashes for display
	displayPath = strings.ReplaceAll(displayPath, "/", "\\")

	// Output like Impacket
	fmt.Printf("[*] Changing FileTimes for '%s' on share '%s'!\n\n", displayPath, shareName)

	// Show what was set (or N/A for unchanged)
	if targetCreate {
		fmt.Printf("CreationTime: %s\n", formatTimeImpacket(displayCreation))
	} else {
		fmt.Printf("CreationTime: N/A\n")
	}
	if targetAccess {
		fmt.Printf("LastAccessTime: %s\n", formatTimeImpacket(displayAccess))
	} else {
		fmt.Printf("LastAccessTime: N/A\n")
	}
	if targetWrite {
		fmt.Printf("LastWriteTime: %s\n", formatTimeImpacket(displayWrite))
	} else {
		fmt.Printf("LastWriteTime: N/A\n")
	}
	if targetModify {
		fmt.Printf("ChangeTime: %s\n", formatTimeImpacket(displayChange))
	} else {
		fmt.Printf("ChangeTime: N/A\n")
	}

	// Validate if requested
	if validate {
		fmt.Println()
		fmt.Printf("[*] Validating Updated FileTimes for '%s' on share '%s'!\n\n", displayPath, shareName)

		stat, err := share.Stat(normalizedPath)
		if err != nil {
			log.Fatalf("[-] Failed to validate timestamps: %v", err)
		}

		fileStat, ok := stat.(*smb2.FileStat)
		if !ok {
			log.Fatal("[-] Failed to get file stat")
		}

		fmt.Printf("CreationTime: %s\n", formatTimeImpacket(fileStat.CreationTime))
		fmt.Printf("LastAccessTime: %s\n", formatTimeImpacket(fileStat.LastAccessTime))
		fmt.Printf("LastWriteTime: %s\n", formatTimeImpacket(fileStat.LastWriteTime))
		fmt.Printf("ChangeTime: %s\n", formatTimeImpacket(fileStat.ChangeTime))
	}
}

// RefFileTimes holds all timestamps from a reference file
type RefFileTimes struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
}

func getRefFileTimes(client *smb.Client, refShareName, refFilePath string) (*RefFileTimes, error) {
	// Mount the reference share
	refShareMount, err := client.Session.Mount(refShareName)
	if err != nil {
		return nil, fmt.Errorf("failed to mount reference share '%s': %v", refShareName, err)
	}
	defer refShareMount.Umount()

	refPathNorm := normalizePath(refFilePath)

	stat, err := refShareMount.Stat(refPathNorm)
	if err != nil {
		return nil, fmt.Errorf("failed to stat reference file: %v", err)
	}

	fileStat, ok := stat.(*smb2.FileStat)
	if !ok {
		return nil, fmt.Errorf("failed to get reference file stat")
	}

	return &RefFileTimes{
		CreationTime:   fileStat.CreationTime,
		LastAccessTime: fileStat.LastAccessTime,
		LastWriteTime:  fileStat.LastWriteTime,
		ChangeTime:     fileStat.ChangeTime,
	}, nil
}

func parseTimestamp(ts string) (time.Time, error) {
	// Format: YYYY-MM-DD_HH:MM:SS.mmmmmm
	// Example: 2020-01-01_12:00:00.000000

	// Replace underscore with space for parsing
	ts = strings.Replace(ts, "_", " ", 1)

	// Try parsing with microseconds
	t, err := time.ParseInLocation("2006-01-02 15:04:05.000000", ts, time.Local)
	if err == nil {
		return t, nil
	}

	// Try without microseconds
	t, err = time.ParseInLocation("2006-01-02 15:04:05", ts, time.Local)
	if err == nil {
		return t, nil
	}

	// Try with milliseconds
	t, err = time.ParseInLocation("2006-01-02 15:04:05.000", ts, time.Local)
	if err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid timestamp format (expected YYYY-MM-DD_HH:MM:SS.mmmmmm)")
}

func formatTimeImpacket(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	// Format like Impacket: 2022-03-02T19:54:16
	return t.Format("2006-01-02T15:04:05")
}

func normalizePath(path string) string {
	// Convert forward slashes to backslashes for Windows
	path = filepath.ToSlash(path)
	path = strings.ReplaceAll(path, "/", "\\")
	path = strings.TrimPrefix(path, "\\")
	return path
}

func printUsage() {
	fmt.Println("File / Directory Timestamp Querying & Modification Utility implementation.")
	fmt.Println()
	fmt.Println("Usage: filetime [options] target share path {stat,touch} [touch-options]")
	fmt.Println()
	fmt.Println("Positional arguments:")
	fmt.Println("  target              [[domain/]username[:password]@]<targetName or address>")
	fmt.Println("  share               The share in which the desired file / directory resides")
	fmt.Println("  path                The path of the file / directory to query or modify")
	fmt.Println("  {stat,touch}        Action to perform")
	fmt.Println()
	fmt.Println("Touch options:")
	fmt.Println("  -c, --create        Change the CreationTime of the file / directory")
	fmt.Println("  -a, --access        Change the LastAccessTime of the file / directory")
	fmt.Println("  -w, --write         Change the LastWriteTime of the file / directory")
	fmt.Println("  -m, --modify        Change the ChangeTime of the file / directory")
	fmt.Println("  -r, --reference <share> <path>")
	fmt.Println("                      Specify a file / directory to reference and copy timestamps")
	fmt.Println("  -t, --timestamp STAMP")
	fmt.Println("                      Specify a timestamp to set (format: YYYY-MM-DD_HH:MM:SS.mmmmmm)")
	fmt.Println("  -v, --validate      Query the file after touching to verify the changes")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Query file timestamps")
	fmt.Println("  filetime user:pass@target C$ Windows/explorer.exe stat")
	fmt.Println()
	fmt.Println("  # Set all timestamps to current time")
	fmt.Println("  filetime user:pass@target C$ test.txt touch")
	fmt.Println()
	fmt.Println("  # Set only creation time to specific timestamp")
	fmt.Println("  filetime user:pass@target C$ test.txt touch -c -t 2020-01-01_12:00:00.000000")
	fmt.Println()
	fmt.Println("  # Copy timestamps from reference file")
	fmt.Println("  filetime user:pass@target C$ test.txt touch -r C$ Windows/explorer.exe")
	fmt.Println()
	fmt.Println("  # Set timestamps and verify")
	fmt.Println("  filetime user:pass@target C$ test.txt touch -v -t 2020-01-01_12:00:00.000000")
	fmt.Println()
	flag.PrintDefaults()
}
