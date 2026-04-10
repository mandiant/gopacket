// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/lsarpc"
	"gopacket/pkg/dcerpc/tsts"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

func main() {
	// Custom flag parsing: standard flags, target, action, action-specific flags
	var stdArgs []string
	var target, action string
	var subArgs []string

	args := os.Args[1:]
	positionalCount := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if positionalCount >= 2 {
			subArgs = append(subArgs, arg)
			continue
		}

		if strings.HasPrefix(arg, "-") {
			stdArgs = append(stdArgs, arg)
			if isFlagWithValue(arg) && i+1 < len(args) {
				i++
				stdArgs = append(stdArgs, args[i])
			}
		} else {
			positionalCount++
			if positionalCount == 1 {
				target = arg
			} else {
				action = strings.ToLower(arg)
			}
		}
	}

	if target == "" || action == "" {
		printUsage()
		os.Exit(1)
	}

	// Parse action-specific flags
	subFlags := flag.NewFlagSet("tstool "+action, flag.ExitOnError)
	verbose := subFlags.Bool("v", false, "Verbose output")
	pid := subFlags.Int("pid", 0, "Process ID")
	name := subFlags.String("name", "", "Process image name")
	sessionID := subFlags.Int("session", -1, "Session ID")
	source := subFlags.Int("source", -1, "Source session ID")
	dest := subFlags.Int("dest", -1, "Destination session ID")
	password := subFlags.String("password", "", "Session password")
	title := subFlags.String("title", "", "Message box title")
	message := subFlags.String("message", "", "Message box message")
	doLogoff := subFlags.Bool("logoff", false, "Logoff flag for shutdown")
	doShutdown := subFlags.Bool("shutdown", false, "Shutdown flag")
	doReboot := subFlags.Bool("reboot", false, "Reboot flag for shutdown")
	doPoweroff := subFlags.Bool("poweroff", false, "Poweroff flag for shutdown")
	subFlags.Parse(subArgs)

	// Set os.Args for flags.Parse() to handle standard auth flags
	os.Args = append([]string{os.Args[0]}, append(stdArgs, target)...)

	opts := flags.Parse()

	if opts.TargetStr == "" {
		printUsage()
		os.Exit(1)
	}

	sess, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&sess, &creds)

	if !opts.NoPass && creds.Password == "" && creds.Hash == "" && creds.AESKey == "" {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("gopacket v0.1.0 - tstool")
	fmt.Println()

	// Connect via SMB
	if sess.Port == 0 {
		if opts.Port != 0 {
			sess.Port = opts.Port
		} else {
			sess.Port = 445
		}
	}

	smbClient := smb.NewClient(sess, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	// Build auth context for RPC binding
	authCtx := &authContext{
		creds:    &creds,
		kerberos: opts.Kerberos,
		hostname: sess.Host,
	}

	switch action {
	case "qwinsta":
		cmdQwinsta(smbClient, authCtx, *verbose)
	case "tasklist":
		cmdTasklist(smbClient, authCtx, *verbose)
	case "taskkill":
		cmdTaskkill(smbClient, authCtx, *pid, *name)
	case "tscon":
		if *source < 0 || *dest < 0 {
			fmt.Fprintf(os.Stderr, "[-] -source and -dest are required for tscon\n")
			os.Exit(1)
		}
		cmdTscon(smbClient, authCtx, *source, *dest, *password)
	case "tsdiscon":
		if *sessionID < 0 {
			fmt.Fprintf(os.Stderr, "[-] -session is required for tsdiscon\n")
			os.Exit(1)
		}
		cmdTsdiscon(smbClient, authCtx, *sessionID)
	case "logoff":
		if *sessionID < 0 {
			fmt.Fprintf(os.Stderr, "[-] -session is required for logoff\n")
			os.Exit(1)
		}
		cmdLogoff(smbClient, authCtx, *sessionID)
	case "shutdown":
		if !*doLogoff && !*doShutdown && !*doReboot && !*doPoweroff {
			fmt.Fprintf(os.Stderr, "[-] At least one flag is required: -logoff, -shutdown, -reboot or -poweroff\n")
			os.Exit(1)
		}
		var shutdownFlags uint32
		if *doLogoff {
			shutdownFlags |= tsts.ShutdownLogoff
		}
		if *doShutdown {
			shutdownFlags |= tsts.ShutdownShutdown
		}
		if *doReboot {
			shutdownFlags |= tsts.ShutdownReboot
		}
		if *doPoweroff {
			shutdownFlags |= tsts.ShutdownPoweroff
		}
		cmdShutdown(smbClient, authCtx, shutdownFlags)
	case "msg":
		if *sessionID < 0 {
			fmt.Fprintf(os.Stderr, "[-] -session is required for msg\n")
			os.Exit(1)
		}
		if *message == "" {
			fmt.Fprintf(os.Stderr, "[-] -message is required for msg\n")
			os.Exit(1)
		}
		cmdMsg(smbClient, authCtx, *sessionID, *title, *message)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown action: %s\n", action)
		printUsage()
		os.Exit(1)
	}
}

// authContext holds authentication info for RPC binding.
type authContext struct {
	creds    *session.Credentials
	kerberos bool
	hostname string
}

// openPipeAndBind opens a named pipe, creates an RPC client, and binds with authentication.
func openPipeAndBind(smbClient *smb.Client, pipeName string, uuid [16]byte, auth *authContext) (*dcerpc.Client, error) {
	pipe, err := smbClient.OpenPipe(pipeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe %s: %v", pipeName, err)
	}

	rpcClient := dcerpc.NewClient(pipe)

	if auth.kerberos {
		if err := rpcClient.BindAuthKerberos(uuid, tsts.MajorVersion, tsts.MinorVersion, auth.creds, auth.hostname); err != nil {
			return nil, fmt.Errorf("kerberos bind to %s failed: %v", pipeName, err)
		}
	} else {
		if err := rpcClient.BindAuth(uuid, tsts.MajorVersion, tsts.MinorVersion, auth.creds); err != nil {
			return nil, fmt.Errorf("bind to %s failed: %v", pipeName, err)
		}
	}

	return rpcClient, nil
}

func cmdQwinsta(smbClient *smb.Client, auth *authContext, verbose bool) {
	// 1. Get session list via TermSrvEnumeration
	enumRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvEnumerationUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	enumClient := tsts.NewEnumerationClient(enumRPC)

	sessions, err := enumClient.GetSessionList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] GetSessionList failed: %v\n", err)
		os.Exit(1)
	}

	if len(sessions) == 0 {
		fmt.Println("No sessions found...")
		return
	}

	// 2. Get session info via TermSrvSession
	sessRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvSessionUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	sessClient := tsts.NewSessionClient(sessRPC)

	type sessionData struct {
		tsts.SessionEnumLevel1
		info       *tsts.SessionInfoEx
		clientData *tsts.ClientData
	}

	var sessionList []sessionData
	for _, s := range sessions {
		sd := sessionData{SessionEnumLevel1: s}
		info, err := sessClient.GetSessionInformationEx(s.SessionId)
		if err == nil {
			sd.info = info
		}
		sessionList = append(sessionList, sd)
	}

	// 3. If verbose, get client data via RCMPublic
	if verbose {
		rcmRPC, err := openPipeAndBind(smbClient, tsts.PipeTermSrvAPI, tsts.RCMPublicUUID, auth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Warning: could not open RCMPublic: %v\n", err)
		} else {
			rcmClient := tsts.NewRCMPublicClient(rcmRPC)
			for i := range sessionList {
				cd, _ := rcmClient.GetClientData(sessionList[i].SessionId)
				if cd != nil {
					sessionList[i].clientData = cd
					if cd.UserName != "" && (sessionList[i].info == nil || sessionList[i].info.UserName == "") {
						if sessionList[i].info != nil {
							sessionList[i].info.UserName = cd.UserName
						}
					}
					if cd.Domain != "" && (sessionList[i].info == nil || sessionList[i].info.DomainName == "") {
						if sessionList[i].info != nil {
							sessionList[i].info.DomainName = cd.Domain
						}
					}
				}
			}
		}
	}

	// 4. Print results
	// Calculate column widths
	maxNameLen := len("SESSIONNAME")
	maxUserLen := len("USERNAME")
	maxIdLen := len("ID")
	maxStateLen := len("STATE")

	for _, sd := range sessionList {
		sessName := sd.Name
		if sd.info != nil && sd.info.SessionName != "" {
			sessName = sd.info.SessionName
		}
		if len(sessName)+1 > maxNameLen {
			maxNameLen = len(sessName) + 1
		}

		var fullUser string
		if sd.info != nil && sd.info.UserName != "" {
			if sd.info.DomainName != "" {
				fullUser = sd.info.DomainName + `\` + sd.info.UserName
			} else {
				fullUser = sd.info.UserName
			}
		}
		if len(fullUser)+1 > maxUserLen {
			maxUserLen = len(fullUser) + 1
		}

		idStr := strconv.Itoa(int(sd.SessionId))
		if len(idStr)+1 > maxIdLen {
			maxIdLen = len(idStr) + 1
		}

		stateName := tsts.StateName(sd.State)
		if len(stateName)+1 > maxStateLen {
			maxStateLen = len(stateName) + 1
		}
	}

	// Print header
	fmtStr := fmt.Sprintf("%%-%ds %%-%ds %%-%ds %%-%ds %%-9s %%-20s %%-20s",
		maxNameLen, maxUserLen, maxIdLen, maxStateLen)

	header := fmt.Sprintf(fmtStr, "SESSIONNAME", "USERNAME", "ID", "STATE", "Desktop", "ConnectTime", "DisconnectTime")

	var fmtVerbose string
	if verbose {
		maxClientName := len("ClientName")
		maxRemoteIp := len("RemoteAddress")
		for _, sd := range sessionList {
			if sd.clientData != nil {
				if len(sd.clientData.ClientName)+1 > maxClientName {
					maxClientName = len(sd.clientData.ClientName) + 1
				}
				if len(sd.clientData.ClientAddress)+1 > maxRemoteIp {
					maxRemoteIp = len(sd.clientData.ClientAddress) + 1
				}
			}
		}
		fmtVerbose = fmt.Sprintf("%%-%ds %%-%ds %%-11s %%-15s", maxClientName, maxRemoteIp)
		header += " " + fmt.Sprintf(fmtVerbose, "ClientName", "RemoteAddress", "Resolution", "ClientTimeZone")
	}

	fmt.Println(header)
	fmt.Println(strings.Repeat("=", len(header)))

	for _, sd := range sessionList {
		sessName := sd.Name
		var fullUser, desktop, connTime, discTime string

		if sd.info != nil {
			if sd.info.SessionName != "" {
				sessName = sd.info.SessionName
			}
			if sd.info.UserName != "" {
				if sd.info.DomainName != "" {
					fullUser = sd.info.DomainName + `\` + sd.info.UserName
				} else {
					fullUser = sd.info.UserName
				}
			}
			desktop = tsts.DesktopStateName(sd.info.SessionFlags)
			if sd.info.ConnectTime.Year() > 1601 {
				connTime = sd.info.ConnectTime.Format("2006/01/02 15:04:05")
			} else {
				connTime = "None"
			}
			if sd.info.DisconnectTime.Year() > 1601 {
				discTime = sd.info.DisconnectTime.Format("2006/01/02 15:04:05")
			} else {
				discTime = "None"
			}
		}

		row := fmt.Sprintf(fmtStr, sessName, fullUser,
			strconv.Itoa(int(sd.SessionId)),
			tsts.StateName(sd.State),
			desktop, connTime, discTime)

		if verbose && fmtVerbose != "" {
			clientName := ""
			remoteIp := ""
			resolution := ""
			tz := ""
			if sd.clientData != nil {
				clientName = sd.clientData.ClientName
				remoteIp = sd.clientData.ClientAddress
				if sd.clientData.HRes > 0 || sd.clientData.VRes > 0 {
					resolution = fmt.Sprintf("%dx%d", sd.clientData.HRes, sd.clientData.VRes)
				}
				tz = sd.clientData.ClientTimeZone
			}
			row += " " + fmt.Sprintf(fmtVerbose, clientName, remoteIp, resolution, tz)
		}

		fmt.Println(row)
	}
}

func cmdTasklist(smbClient *smb.Client, auth *authContext, verbose bool) {
	// 1. Get process list via LegacyAPI
	legacyRPC, err := openPipeAndBind(smbClient, tsts.PipeCtxWinStation, tsts.LegacyAPIUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	legacyClient := tsts.NewLegacyClient(legacyRPC)

	handle, err := legacyClient.OpenServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] OpenServer failed: %v\n", err)
		os.Exit(1)
	}
	defer legacyClient.CloseServer(handle)

	procs, err := legacyClient.GetAllProcesses(handle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] GetAllProcesses failed: %v\n", err)
		os.Exit(1)
	}

	if len(procs) == 0 {
		fmt.Println("No processes found")
		return
	}

	// 2. Collect unique SIDs and resolve via lsarpc
	sidMap := make(map[string]string) // SID string -> resolved name
	var uniqueSids []string
	for _, p := range procs {
		if p.SID != "" && strings.HasPrefix(p.SID, "S-") {
			if _, ok := sidMap[p.SID]; !ok {
				sidMap[p.SID] = p.SID
				uniqueSids = append(uniqueSids, p.SID)
			}
		}
	}

	if len(uniqueSids) > 0 {
		resolveSids(smbClient, sidMap, uniqueSids)
	}

	// 3. If verbose, get session info
	type sessInfo struct {
		name     string
		state    string
		username string
	}
	sessMap := make(map[uint32]sessInfo)

	if verbose {
		// Get session list + client data
		enumRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvEnumerationUUID, auth)
		if err == nil {
			enumClient := tsts.NewEnumerationClient(enumRPC)
			sessions, err := enumClient.GetSessionList()
			if err == nil {
				for _, s := range sessions {
					sessMap[uint32(s.SessionId)] = sessInfo{
						name:  s.Name,
						state: tsts.StateName(s.State),
					}
				}
			}
		}

		rcmRPC, err := openPipeAndBind(smbClient, tsts.PipeTermSrvAPI, tsts.RCMPublicUUID, auth)
		if err == nil {
			rcmClient := tsts.NewRCMPublicClient(rcmRPC)
			for sid := range sessMap {
				cd, _ := rcmClient.GetClientData(int32(sid))
				if cd != nil {
					si := sessMap[sid]
					var user string
					if cd.Domain != "" {
						user = cd.Domain + `\`
					}
					if cd.UserName != "" {
						user += cd.UserName
					}
					si.username = user
					sessMap[sid] = si
				}
			}
		}
	}

	// 4. Print results
	maxImageLen := len("Image Name")
	maxSidLen := len("SID")
	for _, p := range procs {
		if len(p.ImageName) > maxImageLen {
			maxImageLen = len(p.ImageName)
		}
		resolved := sidMap[p.SID]
		if resolved == "" {
			resolved = p.SID
		}
		if len(resolved) > maxSidLen {
			maxSidLen = len(resolved)
		}
	}

	if verbose {
		maxUserLen := len("SessUser")
		for _, si := range sessMap {
			if len(si.username)+1 > maxUserLen {
				maxUserLen = len(si.username) + 1
			}
		}

		fmtStr := fmt.Sprintf("%%-%ds %%-6s %%-6s %%-16s %%-11s %%-%ds %%-%ds %%12s",
			maxImageLen, maxUserLen, maxSidLen)

		fmt.Println(fmt.Sprintf(fmtStr, "Image Name", "PID", "SessID", "SessName", "State", "SessUser", "SID", "Mem Usage"))
		fmt.Println(strings.Repeat("=", maxImageLen+6+6+16+11+maxUserLen+maxSidLen+12+8))
		fmt.Println()

		for _, p := range procs {
			si := sessMap[p.SessionId]
			resolved := sidMap[p.SID]
			if resolved == "" {
				resolved = p.SID
			}
			state := si.state
			if state == "Disconnected" {
				state = "Disc"
			}
			mem := fmt.Sprintf("%d K", p.WorkingSetSize/1000)
			fmt.Println(fmt.Sprintf(fmtStr,
				p.ImageName,
				strconv.Itoa(int(p.UniqueProcessId)),
				strconv.Itoa(int(p.SessionId)),
				si.name,
				state,
				si.username,
				resolved,
				mem))
		}
	} else {
		fmtStr := fmt.Sprintf("%%-%ds %%-8s %%-11s %%-%ds %%12s", maxImageLen, maxSidLen)

		fmt.Println(fmt.Sprintf(fmtStr, "Image Name", "PID", "Session#", "SID", "Mem Usage"))
		fmt.Println(strings.Repeat("=", maxImageLen+8+11+maxSidLen+12+5))
		fmt.Println()

		for _, p := range procs {
			resolved := sidMap[p.SID]
			if resolved == "" {
				resolved = p.SID
			}
			mem := fmt.Sprintf("%d K", p.WorkingSetSize/1000)
			fmt.Println(fmt.Sprintf(fmtStr,
				p.ImageName,
				strconv.Itoa(int(p.UniqueProcessId)),
				strconv.Itoa(int(p.SessionId)),
				resolved,
				mem))
		}
	}
}

func resolveSids(smbClient *smb.Client, sidMap map[string]string, sids []string) {
	// Open lsarpc pipe for SID resolution
	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		return
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return
	}

	lsa, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		return
	}
	defer lsa.Close()

	// Batch resolve (max 32 at a time to be safe)
	batchSize := 32
	for i := 0; i < len(sids); i += batchSize {
		end := i + batchSize
		if end > len(sids) {
			end = len(sids)
		}
		batch := sids[i:end]

		results, err := lsa.LookupSids(batch)
		if err != nil {
			continue
		}

		for _, r := range results {
			if r.Domain != "" && r.Name != "" {
				sidMap[r.SID] = r.Domain + `\` + r.Name
			} else if r.Name != "" {
				sidMap[r.SID] = r.Name
			}
		}
	}
}

func cmdTaskkill(smbClient *smb.Client, auth *authContext, pid int, name string) {
	if pid == 0 && name == "" {
		fmt.Fprintf(os.Stderr, "[-] One of the following is required: -pid, -name\n")
		os.Exit(1)
	}

	legacyRPC, err := openPipeAndBind(smbClient, tsts.PipeCtxWinStation, tsts.LegacyAPIUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	legacyClient := tsts.NewLegacyClient(legacyRPC)

	handle, err := legacyClient.OpenServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] OpenServer failed: %v\n", err)
		os.Exit(1)
	}
	defer legacyClient.CloseServer(handle)

	var pidList []uint32
	if pid != 0 {
		pidList = append(pidList, uint32(pid))
	} else {
		// Find PIDs by name
		procs, err := legacyClient.GetAllProcesses(handle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] GetAllProcesses failed: %v\n", err)
			os.Exit(1)
		}
		for _, p := range procs {
			if strings.EqualFold(p.ImageName, name) {
				pidList = append(pidList, p.UniqueProcessId)
			}
		}
		if len(pidList) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Could not find %q in process list\n", name)
			os.Exit(1)
		}
	}

	for _, p := range pidList {
		fmt.Printf("Terminating PID: %d ...", p)
		if err := legacyClient.TerminateProcess(handle, p, 0); err != nil {
			fmt.Println("FAIL")
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		} else {
			fmt.Println("OK")
		}
	}
}

func cmdTscon(smbClient *smb.Client, auth *authContext, source, dest int, password string) {
	sessRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvSessionUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	sessClient := tsts.NewSessionClient(sessRPC)

	fmt.Printf("Connecting SessionID %d to %d ...", source, dest)
	handle, err := sessClient.OpenSession(int32(source))
	if err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] Could not open source SessionID %d: %v\n", source, err)
		os.Exit(1)
	}
	defer sessClient.CloseSession(handle)

	if err := sessClient.Connect(handle, int32(dest), password); err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func cmdTsdiscon(smbClient *smb.Client, auth *authContext, sessionID int) {
	sessRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvSessionUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	sessClient := tsts.NewSessionClient(sessRPC)

	fmt.Printf("Disconnecting SessionID: %d ...", sessionID)
	handle, err := sessClient.OpenSession(int32(sessionID))
	if err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sessClient.CloseSession(handle)

	if err := sessClient.Disconnect(handle); err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func cmdLogoff(smbClient *smb.Client, auth *authContext, sessionID int) {
	sessRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvSessionUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	sessClient := tsts.NewSessionClient(sessRPC)

	fmt.Printf("Signing-out SessionID: %d ...", sessionID)
	handle, err := sessClient.OpenSession(int32(sessionID))
	if err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sessClient.CloseSession(handle)

	if err := sessClient.Logoff(handle); err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func cmdShutdown(smbClient *smb.Client, auth *authContext, shutdownFlags uint32) {
	legacyRPC, err := openPipeAndBind(smbClient, tsts.PipeCtxWinStation, tsts.LegacyAPIUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	legacyClient := tsts.NewLegacyClient(legacyRPC)

	handle, err := legacyClient.OpenServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] OpenServer failed: %v\n", err)
		os.Exit(1)
	}
	defer legacyClient.CloseServer(handle)

	var flagNames []string
	if shutdownFlags&tsts.ShutdownLogoff != 0 {
		flagNames = append(flagNames, "logoff")
	}
	if shutdownFlags&tsts.ShutdownShutdown != 0 {
		flagNames = append(flagNames, "shutdown")
	}
	if shutdownFlags&tsts.ShutdownReboot != 0 {
		flagNames = append(flagNames, "reboot")
	}
	if shutdownFlags&tsts.ShutdownPoweroff != 0 {
		flagNames = append(flagNames, "poweroff")
	}

	fmt.Printf("Sending shutdown (%s) event ...", strings.Join(flagNames, "|"))
	if err := legacyClient.ShutdownSystem(handle, 0, shutdownFlags); err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func cmdMsg(smbClient *smb.Client, auth *authContext, sessionID int, title, message string) {
	sessRPC, err := openPipeAndBind(smbClient, tsts.PipeLSMAPI, tsts.TermSrvSessionUUID, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	sessClient := tsts.NewSessionClient(sessRPC)

	fmt.Printf("Sending message to SessionID: %d ...", sessionID)
	handle, err := sessClient.OpenSession(int32(sessionID))
	if err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sessClient.CloseSession(handle)

	if err := sessClient.ShowMessageBox(handle, title, message, 0, 0, true); err != nil {
		fmt.Println("FAIL")
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "gopacket v0.1.0 - tstool (Terminal Services manipulation)")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage: tstool [auth-flags] target <action> [action-flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Target:")
	fmt.Fprintln(os.Stderr, "  [[domain/]username[:password]@]<targetName or address>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Actions:")
	fmt.Fprintln(os.Stderr, "  qwinsta  [-v]                             List RDP sessions")
	fmt.Fprintln(os.Stderr, "  tasklist [-v]                             List running processes")
	fmt.Fprintln(os.Stderr, "  taskkill -pid N | -name ImageName         Kill process")
	fmt.Fprintln(os.Stderr, "  tscon    -source N -dest N [-password P]  Connect sessions")
	fmt.Fprintln(os.Stderr, "  tsdiscon -session N                       Disconnect session")
	fmt.Fprintln(os.Stderr, "  logoff   -session N                       Sign out session")
	fmt.Fprintln(os.Stderr, "  shutdown -logoff|-shutdown|-reboot|-poweroff  Remote shutdown")
	fmt.Fprintln(os.Stderr, "  msg      -session N -title T -message M   Send message box")
}

// isFlagWithValue returns true if the flag requires a value argument.
func isFlagWithValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	if idx := strings.Index(name, "="); idx >= 0 {
		return false
	}
	boolFlags := map[string]bool{
		"no-pass": true, "k": true, "ts": true, "debug": true,
		"v": true, "logoff": true, "shutdown": true, "reboot": true, "poweroff": true,
	}
	return !boolFlags[name]
}
