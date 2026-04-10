// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopacket/pkg/ntfs"
)

func main() {
	flag.Usage = printUsage

	extract := flag.String("extract", "", "Extracts pathname (e.g. \\windows\\system32\\config\\sam)")
	_ = flag.Bool("debug", false, "Turn DEBUG output ON")

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	volumePath := flag.Arg(0)

	vol, err := ntfs.Open(volumePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open volume: %v\n", err)
		os.Exit(1)
	}
	defer vol.Close()

	rootINode, err := vol.GetINode(ntfs.FileRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read root directory: %v\n", err)
		os.Exit(1)
	}

	shell := &Shell{
		vol:     vol,
		current: rootINode,
		pwd:     "\\",
		root:    rootINode,
	}

	if *extract != "" {
		shell.doGet(*extract)
		return
	}

	shell.run()
}

// Shell provides the interactive mini-shell for browsing an NTFS volume
type Shell struct {
	vol     *ntfs.Volume
	current *ntfs.INode
	root    *ntfs.INode
	pwd     string
}

func (s *Shell) run() {
	fmt.Println("Type help for list of commands")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("%s>", s.pwd)
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToLower(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch cmd {
		case "exit", "quit":
			return
		case "help":
			s.doHelp()
		case "pwd":
			fmt.Println(s.pwd)
		case "ls":
			s.doLs()
		case "cd":
			s.doCd(arg)
		case "cat":
			s.doCat(arg)
		case "get":
			s.doGet(arg)
		case "hexdump":
			s.doHexdump(arg)
		case "lcd":
			s.doLcd(arg)
		case "shell":
			s.doShell(arg)
		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}

func (s *Shell) doHelp() {
	fmt.Println()
	fmt.Println(" cd {path} - changes the current directory to {path}")
	fmt.Println(" pwd - shows current remote directory")
	fmt.Println(" ls  - lists all the files in the current directory")
	fmt.Println(" lcd - change local directory")
	fmt.Println(" get {filename} - downloads the filename from the current path")
	fmt.Println(" cat {filename} - prints the contents of filename")
	fmt.Println(" hexdump {filename} - hexdumps the contents of filename")
	fmt.Println(" shell {cmd} - execute local command")
	fmt.Println(" exit - terminates the server process (and this session)")
	fmt.Println()
}

func (s *Shell) doLs() {
	entries, err := s.current.Walk()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return
	}

	for _, e := range entries {
		attrs := e.PrintableAttrs()
		modified := ""
		if !e.LastModified.IsZero() {
			modified = e.LastModified.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%s %s %15d %s \n", attrs, modified, e.DataSize, e.Name)
	}
}

func (s *Shell) doCd(path string) {
	if path == "" {
		return
	}

	path = strings.ReplaceAll(path, "/", "\\")
	newPath := normalizePath(s.pwd, path)

	inode, err := s.resolvePath(newPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] Directory not found")
		return
	}

	if !inode.IsDirectory() {
		fmt.Fprintln(os.Stderr, "[-] Not a directory!")
		return
	}

	s.current = inode
	s.pwd = newPath
}

func (s *Shell) doCat(path string) {
	if path == "" {
		fmt.Fprintln(os.Stderr, "[-] Usage: cat <filename>")
		return
	}

	path = strings.ReplaceAll(path, "/", "\\")
	fullPath := normalizePath(s.pwd, path)

	inode, err := s.resolvePath(fullPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] Not found!")
		return
	}

	if inode.IsDirectory() {
		fmt.Fprintln(os.Stderr, "[-] It's a directory!")
		return
	}

	if inode.IsCompressed() || inode.IsEncrypted() || inode.IsSparse() {
		fmt.Fprintln(os.Stderr, "[-] Cannot handle compressed/encrypted/sparse files! :(")
		return
	}

	dataSize := inode.GetDataSize()
	chunkSize := int64(4096 * 10)
	var written int64

	for written < int64(dataSize) {
		toRead := chunkSize
		if int64(dataSize)-written < toRead {
			toRead = int64(dataSize) - written
		}
		chunk, err := inode.ReadFileChunk(written, toRead)
		if err != nil || len(chunk) == 0 {
			break
		}
		os.Stdout.Write(chunk)
		written += int64(len(chunk))
	}

	fmt.Fprintf(os.Stderr, "%d bytes read\n", dataSize)
}

func (s *Shell) doGet(path string) {
	if path == "" {
		fmt.Fprintln(os.Stderr, "[-] Usage: get <filename>")
		return
	}

	path = strings.ReplaceAll(path, "/", "\\")
	fullPath := normalizePath(s.pwd, path)

	inode, err := s.resolvePath(fullPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] Not found!")
		return
	}

	if inode.IsDirectory() {
		fmt.Fprintln(os.Stderr, "[-] It's a directory!")
		return
	}

	if inode.IsCompressed() || inode.IsEncrypted() || inode.IsSparse() {
		fmt.Fprintln(os.Stderr, "[-] Cannot handle compressed/encrypted/sparse files! :(")
		return
	}

	outputName := filepath.Base(strings.ReplaceAll(fullPath, "\\", "/"))
	fh, err := os.Create(outputName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create %s: %v\n", outputName, err)
		return
	}
	defer fh.Close()

	dataSize := inode.GetDataSize()
	chunkSize := int64(4096 * 10)
	var written int64

	for written < int64(dataSize) {
		toRead := chunkSize
		if int64(dataSize)-written < toRead {
			toRead = int64(dataSize) - written
		}
		chunk, err := inode.ReadFileChunk(written, toRead)
		if err != nil || len(chunk) == 0 {
			break
		}
		fh.Write(chunk)
		written += int64(len(chunk))
	}

	fmt.Fprintf(os.Stderr, "%d bytes read\n", dataSize)
}

func (s *Shell) doHexdump(path string) {
	if path == "" {
		fmt.Fprintln(os.Stderr, "[-] Usage: hexdump <filename>")
		return
	}

	path = strings.ReplaceAll(path, "/", "\\")
	fullPath := normalizePath(s.pwd, path)

	inode, err := s.resolvePath(fullPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] Not found!")
		return
	}

	if inode.IsDirectory() {
		fmt.Fprintln(os.Stderr, "[-] It's a directory!")
		return
	}

	data, err := inode.ReadFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return
	}

	fmt.Print(hex.Dump(data))
	fmt.Fprintf(os.Stderr, "%d bytes read\n", len(data))
}

func (s *Shell) doLcd(path string) {
	if path == "" {
		wd, _ := os.Getwd()
		fmt.Println(wd)
		return
	}
	if err := os.Chdir(path); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return
	}
	wd, _ := os.Getwd()
	fmt.Println(wd)
}

func (s *Shell) doShell(line string) {
	if line == "" {
		return
	}
	cmd := exec.Command("sh", "-c", line)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func (s *Shell) resolvePath(path string) (*ntfs.INode, error) {
	if path == "\\" {
		return s.root, nil
	}

	var current *ntfs.INode
	if strings.HasPrefix(path, "\\") {
		current = s.root
	} else {
		current = s.current
	}

	parts := strings.Split(path, "\\")
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			// Simplified: resolve from root for the whole path
			continue
		}

		entry := current.FindFirst(part)
		if entry == nil {
			return nil, fmt.Errorf("'%s' not found", part)
		}

		inode, err := s.vol.GetINode(entry.INodeNumber)
		if err != nil {
			return nil, fmt.Errorf("read inode %d: %v", entry.INodeNumber, err)
		}
		current = inode
	}

	return current, nil
}

func normalizePath(base, path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	if strings.HasPrefix(path, "\\") {
		return cleanPath(path)
	}
	return cleanPath(base + "\\" + path)
}

func cleanPath(path string) string {
	parts := strings.Split(path, "\\")
	var result []string
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(result) > 0 {
				result = result[:len(result)-1]
			}
			continue
		}
		result = append(result, p)
	}
	if len(result) == 0 {
		return "\\"
	}
	return "\\" + strings.Join(result, "\\")
}

func printUsage() {
	fmt.Println("gopacket v0.1.0 - Impacket Clone in Go")
	fmt.Println()
	fmt.Println("NTFS explorer (read-only)")
	fmt.Println()
	fmt.Println("Usage: ntfs-read [options] <volume>")
	fmt.Println()
	fmt.Println("Positional arguments:")
	fmt.Println("  volume             NTFS volume to open (e.g. \\\\.\\C: or /dev/disk1s1)")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -extract pathname  Extracts pathname (e.g. \\windows\\system32\\config\\sam)")
	fmt.Println("  -debug             Turn DEBUG output ON")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ntfs-read /dev/sda1")
	fmt.Println("  ntfs-read /tmp/ntfs.img")
	fmt.Println("  ntfs-read -extract '\\windows\\system32\\config\\sam' /dev/sda1")
	fmt.Println()
}
