package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"path/filepath"

	"github.com/chzyer/readline"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/srvsvc"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

func main() {
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

	// Handle OutputFile

	if opts.OutputFile != "" {
		f, err := os.OpenFile(opts.OutputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("[-] Failed to open output file: %v", err)
		}
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}

	client := smb.NewClient(target, &creds)
	defer client.Close()

	fmt.Printf("[*] Connecting to %s...\n", target.Addr())
	if err := client.Connect(); err != nil {
		log.Fatalf("[-] Connection failed: %v", err)
	}
	fmt.Println("[+] SMB Session established.")

	shell(client, target.Host, opts.InputFile)
}

func shell(client *smb.Client, hostname string, inputFile string) {
	var scanner *bufio.Scanner
	var l *readline.Instance
	var err error

	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Printf("[-] Failed to open input file: %v\n", err)
			return
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	} else {
		completer := readline.NewPrefixCompleter(
			readline.PcItem("shares"),
			readline.PcItem("use", readline.PcItemDynamic(func(line string) []string {
				shares, _ := client.ListShares()
				return shares
			})),
			readline.PcItem("ls", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("lls", readline.PcItemDynamic(func(line string) []string { return completeLocal(line) })),
			readline.PcItem("cd", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("mkdir"),
			readline.PcItem("rmdir", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("rm", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("cat", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("rename", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("pwd"),
			readline.PcItem("info"),
			readline.PcItem("tree", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("mget"),
			readline.PcItem("get", readline.PcItemDynamic(func(line string) []string { return completeRemote(client, line) })),
			readline.PcItem("put", readline.PcItemDynamic(func(line string) []string { return completeLocal(line) })),
			readline.PcItem("lcd", readline.PcItemDynamic(func(line string) []string { return completeLocal(line) })),
			readline.PcItem("hcd", readline.PcItemDynamic(func(line string) []string { return completeLocal(line) })),
			readline.PcItem("close"),
			readline.PcItem("logoff"),
			readline.PcItem("exit"),
			readline.PcItem("quit"),
			readline.PcItem("help"),
		)

		l, err = readline.NewEx(&readline.Config{
			Prompt:          "# ",
			AutoComplete:    completer,
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",
			HistoryFile:     "/tmp/smbclient_history",
		})
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
	}

	currentShare := ""
	BS := string(rune(92)) // Backslash

	for {
		var line string
		if scanner != nil {
			if !scanner.Scan() { break }
			line = scanner.Text()
			fmt.Printf("# %s\n", line)
		} else {
			path := client.GetCurrentPath()
			if path == "" { path = BS }
			ps := currentShare; if ps == "" { ps = "?" }
			l.SetPrompt(fmt.Sprintf("SMB (%s%s%s:%s)> ", hostname, BS, ps, path))

			line, err = l.Readline()
			if err != nil { break }
		}

		line = strings.TrimSpace(line)
		args := splitArgs(line)
		if len(args) == 0 { continue }
		cmd := strings.ToLower(args[0])

		switch cmd {
		case "exit", "quit": return
		case "close", "logoff":
			client.Close()
			fmt.Println("[+] Session closed.")
			return
		case "lcd", "hcd":
			if len(args) < 2 { wd, _ := os.Getwd(); fmt.Printf("Local directory: %s\n", wd); continue }
			if err := os.Chdir(strings.Join(args[1:], " ")); err != nil {
				fmt.Printf("[-] Error: %v\n", err)
			} else { wd, _ := os.Getwd(); fmt.Printf("[+] Local directory: %s\n", wd) }
		case "shares":
			s, err := client.ListShares(); if err != nil { fmt.Printf("[-] Error: %v\n", err); continue }
			for _, n := range s { fmt.Printf("    %s\n", n) }
		case "use":
			if len(args) < 2 { continue }
			if err := client.UseShare(args[1]); err != nil { fmt.Printf("[-] Error: %v\n", err); continue }
			currentShare = args[1]
		case "ls":
			dir := "."; if len(args) > 1 { dir = strings.Join(args[1:], " ") }
			f, err := client.Ls(dir); if err != nil { fmt.Printf("[-] Error: %v\n", err); continue }
			for _, fi := range f {
				m := "FILE"; if fi.IsDir() { m = "DIR " }
				fmt.Printf("    %s %10d %s\n", m, fi.Size(), fi.Name())
			}
		case "lls":
			dir := "."; if len(args) > 1 { dir = strings.Join(args[1:], " ") }
			f, err := os.ReadDir(dir); if err != nil { fmt.Printf("[-] Error: %v\n", err); continue }
			for _, fi := range f {
				info, _ := fi.Info(); m := "FILE"; if fi.IsDir() { m = "DIR " }
				fmt.Printf("    %s %10d %s\n", m, info.Size(), fi.Name())
			}
		case "cd":
			if len(args) < 2 { continue }
			if err := client.Cd(strings.Join(args[1:], " ")); err != nil { fmt.Printf("[-] Error: %v\n", err) }
		case "pwd": fmt.Printf("Current directory: %s\n", client.GetCurrentPath())
		case "get":
			if len(args) < 2 { continue }
			rem := args[1]; loc := rem; if len(args) > 2 { loc = args[2] }
			if err := client.Get(rem, loc); err != nil { fmt.Printf("[-] Error: %v\n", err) } else { fmt.Println("[+] Done.") }
		case "put":
			if len(args) < 2 { continue }
			loc := args[1]; rem := filepath.Base(loc); if len(args) > 2 { rem = args[2] }
			if err := client.Put(loc, rem); err != nil { fmt.Printf("[-] Error: %v\n", err) } else { fmt.Println("[+] Done.") }
		case "mkdir":
			if len(args) < 2 { continue }
			if err := client.Mkdir(strings.Join(args[1:], " ")); err != nil { fmt.Printf("[-] Error: %v\n", err) }
		case "rmdir":
			if len(args) < 2 { continue }
			if err := client.Rmdir(strings.Join(args[1:], " ")); err != nil { fmt.Printf("[-] Error: %v\n", err) }
		case "rm":
			if len(args) < 2 { continue }
			if err := client.Rm(strings.Join(args[1:], " ")); err != nil { fmt.Printf("[-] Error: %v\n", err) }
		case "cat":
			if len(args) < 2 { continue }
			c, err := client.Cat(strings.Join(args[1:], " ")); if err != nil { fmt.Printf("[-] Error: %v\n", err) } else { fmt.Println(c) }
		case "rename":
			if len(args) < 3 { continue }
			if err := client.Rename(args[1], args[2]); err != nil { fmt.Printf("[-] Error: %v\n", err) }
		case "tree":
			dir := "."; if len(args) > 1 { dir = strings.Join(args[1:], " ") }
			client.Tree(dir, func(p string, info os.FileInfo, err error) error {
				if err != nil { return nil }; fmt.Printf("|-- %s\n", info.Name()); return nil
			})
		case "mget":
			if len(args) < 2 { continue }
			client.Mget(args[1])
		case "info":
			p, err := client.OpenPipe("srvsvc"); if err != nil { fmt.Printf("[-] Error: %v\n", err); continue }
			rpc := dcerpc.NewClient(p)
			if err := rpc.Bind(srvsvc.UUID, 3, 0); err != nil { fmt.Printf("[-] Bind failed: %v\n", err); p.Close(); continue }
			inf, err := srvsvc.GetInfoLevel101(rpc, BS+BS+hostname)
			if err != nil { fmt.Printf("[-] Error: %v\n", err) } else { fmt.Printf("[+] %s\n", inf) }
			p.Close()
		case "help":
			fmt.Println(`
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 ls {wildcard} - lists all the files in the current directory
 lls {dirname} - lists all the files on the local filesystem.
 tree {filepath} - recursively lists all files in folder and sub folders
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 info - returns NetrServerInfo main results
 close - closes the current SMB Session
 exit - terminates the session
`)
		default: fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}

func completeLocal(line string) []string {
	args := splitArgs(line); if len(args) == 0 { return nil }
	matches, _ := filepath.Glob(args[len(args)-1] + "*")
	return matches
}

func completeRemote(client *smb.Client, line string) []string {
	f, err := client.Ls("."); if err != nil { return nil }
	var n []string
	for _, fi := range f {
		name := fi.Name(); if fi.IsDir() { name += "/" }
		n = append(n, name)
	}
	return n
}

func splitArgs(line string) []string {
	var a []string; var c strings.Builder; i, e := false, false; var q rune
	for _, r := range line {
		if e { c.WriteRune(r); e = false; continue }
		switch {
		case r == rune(92): e = true
		case (r == '"' || r == '\''):
			if !i { i = true; q = r } else if r == q { i = false; q = rune(0) } else { c.WriteRune(r) }
		case r == ' ' && !i: if c.Len() > 0 { a = append(a, c.String()); c.Reset() }
		default: c.WriteRune(r)
		}
	}
	if c.Len() > 0 { a = append(a, c.String()) }
	return a
}
