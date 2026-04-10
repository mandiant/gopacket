// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/tsch"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	noOutput      = flag.Bool("nooutput", false, "Don't retrieve command output")
	codec         = flag.String("codec", "", "Output encoding (e.g., cp850, utf-8)")
	timeout       = flag.Int("timeout", 30, "timeout in seconds waiting for command output")
	silentCommand = flag.Bool("silentcommand", false, "does not execute cmd.exe to run given command (no output)")
	sessionId     = flag.Int("session-id", -1, "Session ID to run the task in (requires SYSTEM privileges)")
)

// Task XML template matching Impacket's exact format
const taskXMLTemplate = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
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
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>`

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	// Set target.IP for Kerberos when -dc-ip is specified
	if creds.DCIP != "" {
		target.IP = creds.DCIP
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Connect via SMB
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	// Open atsvc pipe (Task Scheduler)
	atPipe, err := smbClient.OpenPipe("atsvc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open atsvc pipe: %v\n", err)
		os.Exit(1)
	}
	defer atPipe.Close()

	// Bind ITaskSchedulerService with authentication
	rpcClient := dcerpc.NewClient(atPipe)
	if creds.UseKerberos {
		if err := rpcClient.BindAuthKerberos(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, &creds, target.Host); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to bind ITaskSchedulerService (Kerberos): %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := rpcClient.BindAuth(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, &creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to bind ITaskSchedulerService: %v\n", err)
			os.Exit(1)
		}
	}

	ts := tsch.NewTaskScheduler(rpcClient)

	// Mount ADMIN$ for output retrieval
	if !*noOutput {
		if err := smbClient.UseShare("ADMIN$"); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to access ADMIN$ share: %v\n", err)
			os.Exit(1)
		}
	}

	// Create executor
	executor := &AtExec{
		ts:        ts,
		smbClient: smbClient,
		noOutput:  *noOutput,
		timeout:   *timeout,
		silent:    *silentCommand,
		sessionId: *sessionId,
	}

	// Get command
	command := opts.Command()
	if command == "" {
		executor.interactiveShell()
	} else {
		output, err := executor.execute(command)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)
	}
}

// AtExec handles remote command execution via Task Scheduler
type AtExec struct {
	ts        *tsch.TaskScheduler
	smbClient *smb.Client
	noOutput  bool
	timeout   int
	silent    bool
	sessionId int
}

func (e *AtExec) interactiveShell() {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press Ctrl+D or type 'exit' to quit")
	fmt.Println("[!] Type '!command' to run local commands")

	prompt := "C:\\Windows\\system32>"

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt)
		if !scanner.Scan() {
			fmt.Println()
			break
		}
		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" {
			continue
		}
		if strings.EqualFold(cmd, "exit") {
			break
		}

		// Local shell escape
		if strings.HasPrefix(cmd, "!") {
			localCmd := strings.TrimPrefix(cmd, "!")
			if localCmd == "" {
				fmt.Println("[!] Usage: !command - runs command on local system")
				continue
			}
			out, err := exec.Command("sh", "-c", localCmd).CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Local command error: %v\n", err)
			}
			fmt.Print(string(out))
			continue
		}

		output, err := e.execute(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
			continue
		}
		fmt.Print(output)
	}
}

func (e *AtExec) execute(command string) (string, error) {
	// Generate random task name and output file name
	taskName := generateRandomString(8)
	tmpFileName := generateRandomString(8) + ".tmp"

	// Build command and arguments like Impacket does
	var cmd, args string
	if e.silent {
		// Direct command: split on first space
		parts := strings.SplitN(command, " ", 2)
		cmd = parts[0]
		if len(parts) > 1 {
			args = parts[1]
		}
	} else {
		// Standard execution: cmd.exe /C command > output
		cmd = "cmd.exe"
		if e.noOutput {
			args = fmt.Sprintf("/C %s", command)
		} else {
			args = fmt.Sprintf("/C %s > %%windir%%\\Temp\\%s 2>&1", command, tmpFileName)
		}
	}

	// Build task XML with escaped command and arguments
	taskXML := fmt.Sprintf(taskXMLTemplate, xmlEscape(cmd), xmlEscape(args))

	taskPath := "\\" + taskName

	// Register the task
	_, err := e.ts.RegisterTask(taskPath, taskXML, tsch.TASK_CREATE)
	if err != nil {
		return "", fmt.Errorf("failed to register task: %v", err)
	}

	// Run the task immediately
	if e.sessionId >= 0 {
		err = e.ts.RunWithSessionId(taskPath, uint32(e.sessionId))
	} else {
		err = e.ts.Run(taskPath)
	}
	if err != nil {
		// Still try to clean up the task
		e.ts.Delete(taskPath)
		return "", fmt.Errorf("failed to run task: %v", err)
	}

	// Retrieve output or wait for completion
	var output string
	if !e.noOutput {
		output = e.getOutput(tmpFileName)
	} else {
		// When -nooutput is used, wait for task completion using GetLastRunInfo
		e.waitForTaskCompletion(taskPath)
	}

	// Delete the task
	e.ts.Delete(taskPath)

	return output, nil
}

// waitForTaskCompletion polls GetLastRunInfo until the task has run.
func (e *AtExec) waitForTaskCompletion(taskPath string) {
	maxIterations := e.timeout * 10 // 100ms intervals
	for i := 0; i < maxIterations; i++ {
		time.Sleep(100 * time.Millisecond)

		st, _, err := e.ts.GetLastRunInfo(taskPath)
		if err != nil {
			continue
		}

		// Task has run if LastRunTime is set (Year != 0)
		if st.HasRun() {
			return
		}
	}
}

func (e *AtExec) getOutput(tmpFileName string) string {
	// The output file is at Windows\Temp\<filename> relative to ADMIN$ share
	outputPath := "Temp\\" + tmpFileName

	// Poll for output file with timeout
	maxIterations := e.timeout * 10 // 100ms intervals
	for i := 0; i < maxIterations; i++ {
		time.Sleep(100 * time.Millisecond)

		content, err := e.smbClient.Cat(outputPath)
		if err == nil {
			// Delete the output file
			e.smbClient.Rm(outputPath)
			return content
		}

		// If sharing violation, command is still running
		if strings.Contains(err.Error(), "STATUS_SHARING_VIOLATION") {
			continue
		}

		// If file not found, keep waiting
		if strings.Contains(err.Error(), "STATUS_OBJECT_NAME_NOT_FOUND") {
			continue
		}
	}

	return ""
}

// xmlEscape escapes special XML characters to match Impacket's xml_escape
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return s
}

// generateRandomString generates a random alphanumeric string
func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
