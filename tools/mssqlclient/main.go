// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/tds"
)

var (
	database    = flag.String("db", "", "MSSQL database instance")
	windowsAuth = flag.Bool("windows-auth", false, "Use Windows Authentication (default: SQL auth)")
	showQueries = flag.Bool("show", false, "Show SQL queries")
	command     = flag.String("command", "", "SQL command to execute (non-interactive)")
	file        = flag.String("file", "", "File with SQL commands to execute")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("gopacket v0.1.0 - mssqlclient")
	fmt.Println()

	// Parse target
	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	// Default port for MSSQL is 1433, not 445
	portSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	if !portSet {
		opts.Port = 1433
	}

	// Handle password
	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	// Use aesKey implies Kerberos
	if creds.AESKey != "" {
		creds.UseKerberos = true
	}

	// Resolve target address
	targetAddr := target.Host
	if target.IP != "" {
		targetAddr = target.IP
	}

	// Create MSSQL client
	client := tds.NewClient(targetAddr, opts.Port, target.Host)

	// Connect
	fmt.Printf("[*] Connecting to %s:%d...\n", targetAddr, opts.Port)
	if err := client.Connect(targetAddr); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Authenticate
	if creds.UseKerberos {
		fmt.Println("[*] Using Kerberos authentication")
		kdcHost := creds.DCIP
		if kdcHost == "" {
			kdcHost = target.Host
		}
		if err := client.KerberosLogin(*database, creds.Username, creds.Password, creds.Domain, creds.Hash, creds.AESKey, kdcHost); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Kerberos login failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		authType := "SQL Server"
		if *windowsAuth {
			authType = "Windows"
		}
		fmt.Printf("[*] Using %s authentication\n", authType)
		if err := client.Login(*database, creds.Username, creds.Password, creds.Domain, creds.Hash, *windowsAuth); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Login failed: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("[+] Login successful!")

	// Create shell
	shell := NewSQLShell(client, *showQueries)

	// Execute commands from file
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Printf("SQL> %s\n", line)
			shell.Execute(line)
		}
		return
	}

	// Execute single command
	if *command != "" {
		fmt.Printf("SQL> %s\n", *command)
		shell.Execute(*command)
		return
	}

	// Interactive mode
	shell.Run()
}

// SQLShell provides an interactive SQL shell
type SQLShell struct {
	client      *tds.Client
	showQueries bool
}

// NewSQLShell creates a new SQL shell
func NewSQLShell(client *tds.Client, showQueries bool) *SQLShell {
	return &SQLShell{
		client:      client,
		showQueries: showQueries,
	}
}

// Run starts the interactive shell
func (s *SQLShell) Run() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("[!] Press help for extra shell commands")
	fmt.Println()

	for {
		fmt.Printf("SQL (%s)> ", s.client.CurrentDB())
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			break
		}

		s.Execute(line)
	}
}

// Execute executes a command
func (s *SQLShell) Execute(line string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToLower(parts[0])
	var args string
	if len(parts) > 1 {
		args = parts[1]
	}

	switch cmd {
	case "help":
		s.printHelp()
	case "enable_xp_cmdshell":
		s.enableXPCmdShell()
	case "disable_xp_cmdshell":
		s.disableXPCmdShell()
	case "xp_cmdshell":
		s.xpCmdShell(args)
	case "xp_dirtree":
		s.xpDirTree(args)
	case "sp_start_job":
		s.spStartJob(args)
	case "enum_db":
		s.enumDB()
	case "enum_links":
		s.enumLinks()
	case "enum_users":
		s.enumUsers()
	case "enum_logins":
		s.enumLogins()
	case "enum_owner":
		s.enumOwner()
	case "enum_impersonate":
		s.enumImpersonate()
	case "exec_as_user":
		s.execAsUser(args)
	case "exec_as_login":
		s.execAsLogin(args)
	case "show_query":
		s.showQueries = true
		fmt.Println("[*] Query display enabled")
	case "mask_query":
		s.showQueries = false
		fmt.Println("[*] Query display disabled")
	default:
		// Execute as SQL
		s.sqlQuery(line)
	}
}

func (s *SQLShell) printHelp() {
	fmt.Print(`
    exit                       - Exit the shell
    enable_xp_cmdshell         - Enable xp_cmdshell
    disable_xp_cmdshell        - Disable xp_cmdshell
    enum_db                    - Enumerate databases
    enum_links                 - Enumerate linked servers
    enum_impersonate           - Check logins that can be impersonated
    enum_logins                - Enumerate login users
    enum_users                 - Enumerate current db users
    enum_owner                 - Enumerate db owner
    exec_as_user {user}        - Impersonate with EXECUTE AS USER
    exec_as_login {login}      - Impersonate with EXECUTE AS LOGIN
    xp_cmdshell {cmd}          - Execute cmd using xp_cmdshell
    xp_dirtree {path}          - Execute xp_dirtree on path
    sp_start_job {cmd}         - Execute cmd using SQL Server Agent (blind)
    show_query                 - Show SQL queries
    mask_query                 - Hide SQL queries
`)
}

func (s *SQLShell) sqlQuery(query string) {
	if s.showQueries {
		fmt.Printf("[%%] %s\n", query)
	}

	rows, err := s.client.SQLQuery(query)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}

	s.printRows(rows)
}

func (s *SQLShell) printRows(rows []map[string]interface{}) {
	if len(rows) == 0 {
		return
	}

	// Get column order from first row
	columns := s.client.GetColumns()
	if len(columns) == 0 {
		return
	}

	// Calculate column widths
	widths := make(map[string]int)
	for _, col := range columns {
		widths[col.Name] = len(col.Name)
	}
	for _, row := range rows {
		for _, col := range columns {
			val := fmt.Sprintf("%v", row[col.Name])
			if len(val) > widths[col.Name] {
				widths[col.Name] = len(val)
			}
		}
	}

	// Cap widths
	for k, v := range widths {
		if v > 80 {
			widths[k] = 80
		}
	}

	// Print header
	for _, col := range columns {
		fmt.Printf("%-*s  ", widths[col.Name], col.Name)
	}
	fmt.Println()
	for _, col := range columns {
		fmt.Printf("%s  ", strings.Repeat("-", widths[col.Name]))
	}
	fmt.Println()

	// Print rows
	for _, row := range rows {
		for _, col := range columns {
			val := fmt.Sprintf("%v", row[col.Name])
			if len(val) > widths[col.Name] {
				val = val[:widths[col.Name]]
			}
			fmt.Printf("%-*s  ", widths[col.Name], val)
		}
		fmt.Println()
	}
}

func (s *SQLShell) enableXPCmdShell() {
	s.sqlQuery("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
}

func (s *SQLShell) disableXPCmdShell() {
	s.sqlQuery("exec sp_configure 'xp_cmdshell', 0;RECONFIGURE;exec sp_configure 'show advanced options', 0;RECONFIGURE;")
}

func (s *SQLShell) xpCmdShell(cmd string) {
	s.sqlQuery(fmt.Sprintf("exec master..xp_cmdshell '%s'", cmd))
}

func (s *SQLShell) xpDirTree(path string) {
	s.sqlQuery(fmt.Sprintf("exec master.sys.xp_dirtree '%s',1,1", path))
}

func (s *SQLShell) spStartJob(cmd string) {
	query := `DECLARE @job NVARCHAR(100);
SET @job='IdxDefrag'+CONVERT(NVARCHAR(36),NEWID());
EXEC msdb..sp_add_job @job_name=@job,@description='INDEXDEFRAG',@owner_login_name='sa',@delete_level=3;
EXEC msdb..sp_add_jobstep @job_name=@job,@step_id=1,@step_name='Defragmentation',@subsystem='CMDEXEC',@command='%s',@on_success_action=1;
EXEC msdb..sp_add_jobserver @job_name=@job;
EXEC msdb..sp_start_job @job_name=@job;`
	s.sqlQuery(fmt.Sprintf(query, cmd))
}

func (s *SQLShell) enumDB() {
	s.sqlQuery("select name, is_trustworthy_on from sys.databases")
}

func (s *SQLShell) enumLinks() {
	s.sqlQuery("EXEC sp_linkedservers")
	s.sqlQuery("EXEC sp_helplinkedsrvlogin")
}

func (s *SQLShell) enumUsers() {
	s.sqlQuery("EXEC sp_helpuser")
}

func (s *SQLShell) enumLogins() {
	s.sqlQuery(`select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin,
sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator,
sl.bulkadmin from master.sys.server_principals r left join master.sys.syslogins sl
on sl.sid = r.sid where r.type in ('S','E','X','U','G')`)
}

func (s *SQLShell) enumOwner() {
	s.sqlQuery("SELECT name [Database], suser_sname(owner_sid) [Owner] FROM sys.databases")
}

func (s *SQLShell) enumImpersonate() {
	s.sqlQuery(`SELECT 'LOGIN' as 'execute as', '' AS 'database',pe.permission_name,
pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor'
FROM sys.server_permissions pe JOIN sys.server_principals pr
ON pe.grantee_principal_id = pr.principal_Id
JOIN sys.server_principals pr2
ON pe.grantor_principal_id = pr2.principal_Id
WHERE pe.type = 'IM'`)
}

func (s *SQLShell) execAsUser(user string) {
	s.sqlQuery(fmt.Sprintf("execute as user='%s'", user))
}

func (s *SQLShell) execAsLogin(login string) {
	s.sqlQuery(fmt.Sprintf("execute as login='%s'", login))
}
