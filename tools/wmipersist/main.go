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
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio/query"

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
	"github.com/mandiant/gopacket/pkg/transport"
)

var (
	comVersion = flag.String("com-version", "", "DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7")
)

func printUsage() {
	fmt.Fprintln(os.Stderr, flags.Banner())
	fmt.Fprintf(os.Stderr, `
usage: wmipersist [-h] [-debug] [-ts] [-com-version MAJOR_VERSION:MINOR_VERSION]
                  [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                  [-dc-ip ip address]
                  target {install,remove} ...

Creates/Removes a WMI Event Consumer/Filter and link between both to execute
Visual Basic based on the WQL filter or timer specified.

positional arguments:
  target                [domain/][username[:password]@]<address>
  {install,remove}      actions
    install             installs the wmi event consumer/filter
    remove              removes the wmi event consumer/filter

Install options:
  -name string          event name (required)
  -vbs string           VBS filename containing the script you want to run (required)
  -filter string        the WQL filter string that will trigger the script
  -timer string         the amount of milliseconds after the script will be triggered

Remove options:
  -name string          event name (required)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file
                        (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If omitted it use the domain
                        part (FQDN) specified in the target parameter

options:
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7
`)
}

func main() {
	// Intercept -h before flags.Parse() overrides usage
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			printUsage()
			os.Exit(0)
		}
	}

	opts := flags.Parse()
	flag.Usage = printUsage

	// Parse action and action-specific flags from remaining args
	args := opts.Arguments
	if opts.TargetStr == "" || len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	action := strings.ToLower(args[0])
	if action != "install" && action != "remove" {
		fmt.Fprintf(os.Stderr, "[-] Unknown action: %s (use install or remove)\n", args[0])
		os.Exit(1)
	}

	// Parse action-specific flags
	actionFlags := flag.NewFlagSet(action, flag.ExitOnError)
	name := actionFlags.String("name", "", "event name")
	var vbsFile, filter, timer *string
	if action == "install" {
		vbsFile = actionFlags.String("vbs", "", "VBS filename containing the script to run")
		filter = actionFlags.String("filter", "", "WQL filter string that will trigger the script")
		timer = actionFlags.String("timer", "", "milliseconds interval for script execution")
	}

	if err := actionFlags.Parse(args[1:]); err != nil {
		os.Exit(1)
	}

	if *name == "" {
		fmt.Fprintln(os.Stderr, "[-] -name is required")
		os.Exit(1)
	}

	if action == "install" {
		if *vbsFile == "" {
			fmt.Fprintln(os.Stderr, "[-] -vbs is required for install")
			os.Exit(1)
		}
		if (*filter == "" && *timer == "") || (*filter != "" && *timer != "") {
			fmt.Fprintln(os.Stderr, "[-] You have to either specify -filter or -timer (and not both)")
			os.Exit(1)
		}
	}

	// Read VBS file content if installing
	var vbsContent string
	if action == "install" {
		data, err := os.ReadFile(*vbsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read VBS file: %v\n", err)
			os.Exit(1)
		}
		vbsContent = string(data)
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

	// Parse COM version override
	var comVer *dcom.COMVersion
	if *comVersion != "" {
		var major, minor uint16
		_, err := fmt.Sscanf(*comVersion, "%d.%d", &major, &minor)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
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
		kdc := target.Host
		if creds.DCIP != "" {
			kdc = creds.DCIP
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
		ntHash, err := kerberos.ParseHashes(creds.Hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid hash format: %v\n", err)
			os.Exit(1)
		}
		gssapi.AddCredential(credential.NewFromNTHash(fullUser, ntHash))
		gssapi.AddMechanism(ssp.NTLM)
		gssapi.AddMechanism(ssp.SPNEGO)
	} else {
		gssapi.AddCredential(credential.NewFromPassword(fullUser, creds.Password))
		gssapi.AddMechanism(ssp.NTLM)
		gssapi.AddMechanism(ssp.SPNEGO)
	}

	securityOpts = append(securityOpts, dcerpc.WithLogger(log))

	ctx := gssapi.NewSecurityContext(context.Background())

	// Determine connection address: prefer target-ip over hostname
	connectAddr := target.Host
	if target.IP != "" {
		connectAddr = target.IP
	}

	// 1. Connect to Endpoint Mapper (Port 135)
	log.Info().Msgf("Connecting to %s:135", connectAddr)
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(connectAddr, "135"), dcerpc.WithDialer(transport.ContextDialer{}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Dial 135 failed: %v\n", err)
		os.Exit(1)
	}
	defer cc.Close(ctx)

	// 2. Object Exporter (to find bindings)
	objExp, err := iobjectexporter.NewObjectExporterClient(ctx, cc, securityOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewObjectExporterClient failed: %v\n", err)
		os.Exit(1)
	}

	srv, err := objExp.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] ServerAlive2 failed: %v\n", err)
		os.Exit(1)
	}

	// Use COM version from server or override
	version := srv.COMVersion
	if comVer != nil {
		version = comVer
	}

	// 3. Remote Activation
	actClient, err := iactivation.NewActivationClient(ctx, cc, securityOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewActivationClient failed: %v\n", err)
		os.Exit(1)
	}

	log.Info().Msg("Activating WMI...")
	act, err := actClient.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: version},
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

	// See wmiexec for rationale on the ncacn_ip_tcp prefix.
	wcc, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+connectAddr, append(endpoints, dcerpc.WithDialer(transport.ContextDialer{}))...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Dial WMI failed: %v\n", err)
		os.Exit(1)
	}
	defer wcc.Close(ctx)

	// 5. Login to WMI - use root/subscription namespace
	log.Info().Msg("Logging into WMI (root/subscription)...")
	wmiCtx := gssapi.NewSecurityContext(ctx)

	wmiOpts := append([]dcerpc.Option{dcom.WithIPID(std.IPID)}, securityOpts...)
	l1login, err := iwbemlevel1login.NewLevel1LoginClient(wmiCtx, wcc, wmiOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NewLevel1LoginClient failed: %v\n", err)
		os.Exit(1)
	}

	login, err := l1login.NTLMLogin(wmiCtx, &iwbemlevel1login.NTLMLoginRequest{
		This:            &dcom.ORPCThis{Version: version},
		NetworkResource: "//./root/subscription",
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

	// BUILTIN\Administrators SID bytes
	creatorSID := []uint8{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0}

	if action == "remove" {
		// Remove all WMI persistence objects
		ret, err := deleteInstance(wmiCtx, svcs, version,
			fmt.Sprintf(`ActiveScriptEventConsumer.Name="%s"`, *name))
		checkError("Removing ActiveScriptEventConsumer "+*name, ret, err)

		ret, err = deleteInstance(wmiCtx, svcs, version,
			fmt.Sprintf(`__EventFilter.Name="EF_%s"`, *name))
		checkError("Removing EventFilter EF_"+*name, ret, err)

		ret, err = deleteInstance(wmiCtx, svcs, version,
			fmt.Sprintf(`__IntervalTimerInstruction.TimerId="TI_%s"`, *name))
		checkError("Removing IntervalTimerInstruction TI_"+*name, ret, err)

		ret, err = deleteInstance(wmiCtx, svcs, version,
			fmt.Sprintf(`__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"%s\"",Filter="__EventFilter.Name=\"EF_%s\""`,
				*name, *name))
		checkError("Removing FilterToConsumerBinding "+*name, ret, err)
	} else {
		// Install: Create ActiveScriptEventConsumer
		consumerObj, err := spawnInstance(wmiCtx, svcs, version, "ActiveScriptEventConsumer", wmio.Values{
			"Name":            *name,
			"ScriptingEngine": "VBScript",
			"CreatorSID":      creatorSID,
			"ScriptText":      vbsContent,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create ActiveScriptEventConsumer instance: %v\n", err)
			os.Exit(1)
		}

		ret, err := putInstance(wmiCtx, svcs, version, consumerObj)
		checkError("Adding ActiveScriptEventConsumer "+*name, ret, err)

		if *filter != "" {
			// Filter mode: create __EventFilter with WQL filter
			filterObj, err := spawnInstance(wmiCtx, svcs, version, "__EventFilter", wmio.Values{
				"Name":           "EF_" + *name,
				"CreatorSID":     creatorSID,
				"Query":          *filter,
				"QueryLanguage":  "WQL",
				"EventNamespace": `root\cimv2`,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to create __EventFilter instance: %v\n", err)
				os.Exit(1)
			}

			ret, err = putInstance(wmiCtx, svcs, version, filterObj)
			checkError("Adding EventFilter EF_"+*name, ret, err)
		} else {
			// Timer mode: create __IntervalTimerInstruction and __EventFilter
			var timerMs int32
			_, err := fmt.Sscanf(*timer, "%d", &timerMs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Invalid timer value: %v\n", err)
				os.Exit(1)
			}

			timerObj, err := spawnInstance(wmiCtx, svcs, version, "__IntervalTimerInstruction", wmio.Values{
				"TimerId":               "TI_" + *name,
				"IntervalBetweenEvents": uint32(timerMs),
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to create __IntervalTimerInstruction instance: %v\n", err)
				os.Exit(1)
			}

			ret, err = putInstance(wmiCtx, svcs, version, timerObj)
			checkError("Adding IntervalTimerInstruction", ret, err)

			filterObj, err := spawnInstance(wmiCtx, svcs, version, "__EventFilter", wmio.Values{
				"Name":           "EF_" + *name,
				"CreatorSID":     creatorSID,
				"Query":          fmt.Sprintf(`select * from __TimerEvent where TimerID = "TI_%s" `, *name),
				"QueryLanguage":  "WQL",
				"EventNamespace": `root\subscription`,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to create __EventFilter instance: %v\n", err)
				os.Exit(1)
			}

			ret, err = putInstance(wmiCtx, svcs, version, filterObj)
			checkError("Adding EventFilter EF_"+*name, ret, err)
		}

		// Create FilterToConsumerBinding
		bindingObj, err := spawnInstance(wmiCtx, svcs, version, "__FilterToConsumerBinding", wmio.Values{
			"Filter":     fmt.Sprintf(`__EventFilter.Name="EF_%s"`, *name),
			"Consumer":   fmt.Sprintf(`ActiveScriptEventConsumer.Name="%s"`, *name),
			"CreatorSID": creatorSID,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create __FilterToConsumerBinding instance: %v\n", err)
			os.Exit(1)
		}

		ret, err = putInstance(wmiCtx, svcs, version, bindingObj)
		checkError("Adding FilterToConsumerBinding", ret, err)
	}
}

// spawnInstance fetches a class definition and creates an instance with the given
// property values, returning it as a wmi.ClassObject suitable for PutInstance.
func spawnInstance(ctx context.Context, svcs iwbemservices.ServicesClient, version *dcom.COMVersion, className string, values wmio.Values) (*wmi.ClassObject, error) {
	b := query.NewBuilder(ctx, svcs, version)
	return b.Spawn(className).Values(values, wmio.JSONValueToType).ClassObject()
}

func putInstance(ctx context.Context, svcs iwbemservices.ServicesClient, version *dcom.COMVersion, instance *wmi.ClassObject) (int32, error) {
	resp, err := svcs.PutInstance(ctx, &iwbemservices.PutInstanceRequest{
		This:     &dcom.ORPCThis{Version: version},
		Instance: instance,
		Flags:    0,
	})
	if err != nil {
		return 0, err
	}
	return resp.Return, nil
}

func deleteInstance(ctx context.Context, svcs iwbemservices.ServicesClient, version *dcom.COMVersion, objectPath string) (int32, error) {
	resp, err := svcs.DeleteInstance(ctx, &iwbemservices.DeleteInstanceRequest{
		This:       &dcom.ORPCThis{Version: version},
		ObjectPath: &oaut.String{Data: objectPath},
		Flags:      0,
	})
	if err != nil {
		return 0, err
	}
	return resp.Return, nil
}

func checkError(banner string, ret int32, err error) {
	if err != nil {
		// Try to extract WBEM status name and code from error string for cleaner output
		// e.g. "wmi: StatusNotFound (0x80041002)" -> "WBEM_E_NOT_FOUND (0x80041002)"
		errStr := err.Error()
		if name, code := extractWMIError(errStr); name != "" {
			fmt.Fprintf(os.Stderr, "[-] %s - ERROR: %s (0x%08x)\n", banner, name, code)
		} else {
			fmt.Fprintf(os.Stderr, "[-] %s - ERROR: %v\n", banner, err)
		}
		return
	}
	callStatus := uint32(ret)
	if callStatus != 0 {
		name := hresult.FromCode(callStatus)
		if name != nil {
			fmt.Fprintf(os.Stderr, "[-] %s - ERROR: %s (0x%08x)\n", banner, name, callStatus)
		} else {
			fmt.Fprintf(os.Stderr, "[-] %s - ERROR: 0x%08x\n", banner, callStatus)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[*] %s - OK\n", banner)
	}
}

// wmiStatusToWBEM maps go-msrpc WMI status names to Impacket-style WBEM names
var wmiStatusToWBEM = map[string]string{
	"StatusNotFound":         "WBEM_E_NOT_FOUND",
	"StatusAccessDenied":     "WBEM_E_ACCESS_DENIED",
	"StatusFailed":           "WBEM_E_FAILED",
	"StatusAlreadyExists":    "WBEM_E_ALREADY_EXISTS",
	"StatusInvalidParameter": "WBEM_E_INVALID_PARAMETER",
	"StatusInvalidClass":     "WBEM_E_INVALID_CLASS",
	"StatusInvalidObject":    "WBEM_E_INVALID_OBJECT",
	"StatusInvalidQuery":     "WBEM_E_INVALID_QUERY",
	"StatusInvalidNamespace": "WBEM_E_INVALID_NAMESPACE",
	"StatusProviderNotFound": "WBEM_E_PROVIDER_NOT_FOUND",
	"StatusProviderFailure":  "WBEM_E_PROVIDER_FAILURE",
	"StatusNotSupported":     "WBEM_E_NOT_SUPPORTED",
	"StatusOutOfMemory":      "WBEM_E_OUT_OF_MEMORY",
	"StatusPrivilegeNotHeld": "WBEM_E_PRIVILEGE_NOT_HELD",
}

// extractWMIError tries to extract a WMI status name and code from an error string
func extractWMIError(s string) (string, uint32) {
	// Extract hex code
	idx := strings.Index(s, "(0x")
	if idx < 0 {
		return "", 0
	}
	end := strings.Index(s[idx:], ")")
	if end < 0 {
		return "", 0
	}
	hexStr := s[idx+1 : idx+end]
	var code uint32
	if _, err := fmt.Sscanf(hexStr, "0x%x", &code); err != nil {
		return "", 0
	}

	// Try to extract the status name from "wmi: StatusXxx" pattern
	if wmiIdx := strings.Index(s, "wmi: "); wmiIdx >= 0 {
		rest := s[wmiIdx+5:]
		// Status name ends at space or (
		nameEnd := strings.IndexAny(rest, " (")
		if nameEnd > 0 {
			statusName := rest[:nameEnd]
			if wbemName, ok := wmiStatusToWBEM[statusName]; ok {
				return wbemName, code
			}
			// Return as-is if not in our map
			return statusName, code
		}
	}

	// Fall back to hresult
	if name := hresult.FromCode(code); name != nil {
		return fmt.Sprintf("%s", name), code
	}
	return fmt.Sprintf("Unknown"), code
}
