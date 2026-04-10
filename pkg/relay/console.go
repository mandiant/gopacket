// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"golang.org/x/term"
)

// runConsole starts the interactive MiniShell console (matches Impacket's MiniShell).
// Blocks the calling goroutine until the user types exit or Ctrl+D.
// If stdin is not a terminal (e.g., running in background), blocks on stopCh.
func runConsole(cfg *Config, socks *SOCKSServer) {
	// If stdin is not a terminal, skip the interactive console and block.
	// This allows running ntlmrelayx in the background without immediate exit.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Printf("[*] Non-interactive mode detected, blocking on stop channel")
		<-cfg.stopCh()
		return
	}

	completer := readline.NewPrefixCompleter(
		readline.PcItem("socks"),
		readline.PcItem("targets"),
		readline.PcItem("finished_attacks"),
		readline.PcItem("startservers"),
		readline.PcItem("stopservers"),
		readline.PcItem("exit"),
		readline.PcItem("help"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "ntlmrelayx> ",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		log.Printf("[!] Console init failed: %v", err)
		// Fall back to blocking on stop channel
		<-cfg.stopCh()
		return
	}
	defer rl.Close()

	fmt.Println("Type help for list of commands")

	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			// EOF (Ctrl+D) — exit
			if err == io.EOF {
				cmdExit(cfg)
				return
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		args := ""
		if len(parts) > 1 {
			args = strings.Join(parts[1:], " ")
		}

		switch cmd {
		case "socks":
			cmdSocks(socks, args)
		case "targets":
			cmdTargets(cfg)
		case "finished_attacks":
			cmdFinishedAttacks(cfg)
		case "startservers":
			cmdStartServers()
		case "stopservers":
			cmdStopServers()
		case "exit":
			cmdExit(cfg)
			return
		case "help":
			cmdHelp()
		default:
			fmt.Printf("Unknown command: %s. Type help for list of commands\n", cmd)
		}
	}
}

// cmdSocks lists active SOCKS relay sessions, optionally filtered.
// Matches Impacket's do_socks: socks [target=<val>|username=<val>|admin=<val>]
func cmdSocks(socks *SOCKSServer, args string) {
	if socks == nil {
		fmt.Println("No Relays Available!")
		return
	}

	relays := socks.ListRelayDetails()
	if len(relays) == 0 {
		fmt.Println("No Relays Available!")
		return
	}

	headers := []string{"Protocol", "Target", "Username", "AdminStatus", "Port"}

	// Convert to rows
	rows := make([][]string, len(relays))
	for i, r := range relays {
		rows[i] = []string{r.Protocol, r.Target, r.Username, r.AdminStatus, r.Port}
	}

	// Apply filter if provided (key=value, case-insensitive substring)
	if strings.Contains(args, "=") {
		filterParts := strings.SplitN(args, "=", 2)
		if len(filterParts) != 2 {
			fmt.Println("Expect target/username/admin = value")
			return
		}
		filterKey := strings.TrimSpace(strings.ToLower(filterParts[0]))
		filterVal := strings.TrimSpace(strings.ToLower(filterParts[1]))

		var colIdx int
		switch filterKey {
		case "target":
			colIdx = 1
		case "username":
			colIdx = 2
		case "admin":
			colIdx = 3
		default:
			fmt.Println("Expect : target / username / admin = value")
			return
		}

		var filtered [][]string
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row[colIdx]), filterVal) {
				filtered = append(filtered, row)
			}
		}

		if len(filtered) == 0 {
			fmt.Println("No relay matching filter available!")
			return
		}
		rows = filtered
	}

	printTable(headers, rows)
}

// cmdTargets lists all configured relay targets.
func cmdTargets(cfg *Config) {
	targets := cfg.GetOriginalTargets()
	if len(targets) == 0 {
		fmt.Println("No targets configured")
		return
	}
	for _, t := range targets {
		fmt.Println(t.URL())
	}
}

// cmdFinishedAttacks lists targets where attacks completed successfully.
// Matches Impacket: prints nothing if no attacks finished.
func cmdFinishedAttacks(cfg *Config) {
	attacks := cfg.GetFinishedAttacks()
	for target, identities := range attacks {
		fmt.Println(target)
		for _, id := range identities {
			fmt.Printf("  %s\n", id)
		}
	}
}

// cmdStartServers is a stub — server lifecycle requires restart.
func cmdStartServers() {
	log.Println("[*] Server start/stop requires restart (not yet implemented)")
}

// cmdStopServers is a stub — server lifecycle requires restart.
func cmdStopServers() {
	log.Println("[*] Server start/stop requires restart (not yet implemented)")
}

// cmdExit signals relay shutdown.
func cmdExit(cfg *Config) {
	fmt.Println("Shutting down, please wait!")
	cfg.Shutdown()
}

// cmdHelp prints available commands.
func cmdHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  socks                          - List active SOCKS relay sessions")
	fmt.Println("  socks <filter>=<value>         - Filter relays (target, username, admin)")
	fmt.Println("  targets                        - List configured relay targets")
	fmt.Println("  finished_attacks               - List targets with successful attacks")
	fmt.Println("  startservers                   - Start relay servers")
	fmt.Println("  stopservers                    - Stop relay servers")
	fmt.Println("  exit                           - Shutdown relay")
	fmt.Println("  help                           - Show this help")
}

// printTable formats data in aligned columns matching Impacket's MiniShell.printTable().
func printTable(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}

	// Calculate column widths
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Build format string: "%-Ns  %-Ns  ..." matching Impacket's 2-space column gap
	fmtParts := make([]string, len(colWidths))
	for i, w := range colWidths {
		fmtParts[i] = fmt.Sprintf("%%-%ds", w)
	}
	fmtStr := strings.Join(fmtParts, "  ")

	// Print header
	headerIface := make([]interface{}, len(headers))
	for i, h := range headers {
		headerIface[i] = h
	}
	fmt.Printf(fmtStr+"\n", headerIface...)

	// Print separator: dashes under each column (min 3)
	sepParts := make([]string, len(colWidths))
	for i, w := range colWidths {
		dashLen := w
		if dashLen < 3 {
			dashLen = 3
		}
		sepParts[i] = strings.Repeat("-", dashLen)
	}
	fmt.Println(strings.Join(sepParts, "  "))

	// Print rows
	for _, row := range rows {
		rowIface := make([]interface{}, len(headers))
		for i := range headers {
			if i < len(row) {
				rowIface[i] = row[i]
			} else {
				rowIface[i] = ""
			}
		}
		fmt.Printf(fmtStr+"\n", rowIface...)
	}
}
