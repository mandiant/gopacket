// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/ienumwbemclassobject/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"
	"github.com/oiweiwei/go-msrpc/ndr"

	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	gokrb5config "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5credentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"

	"gopacket/pkg/flags"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/session"
)

// WBEM flags
const (
	WBEM_FLAG_RETURN_IMMEDIATELY     = 0x00000010
	WBEM_FLAG_FORWARD_ONLY           = 0x00000020
	WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x00020000
)

var (
	namespace    = flag.String("namespace", "//./root/cimv2", "namespace name (default //./root/cimv2)")
	inputFile    = flag.String("file", "", "input file with commands to execute in the WQL shell")
	rpcAuthLevel = flag.String("rpc-auth-level", "default", "default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy (RPC_C_AUTHN_LEVEL_PKT_PRIVACY)")
	comVersion   = flag.String("com-version", "", "DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7")
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

	// Apply RPC auth level
	switch strings.ToLower(*rpcAuthLevel) {
	case "privacy":
		securityOpts = append(securityOpts, dcerpc.WithSeal())
	case "integrity":
		// WithSign() already added above
	case "default", "":
		// Use default (sign only)
	default:
		fmt.Fprintf(os.Stderr, "[-] Invalid rpc-auth-level: %s (use default, integrity, or privacy)\n", *rpcAuthLevel)
		os.Exit(1)
	}

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

		krbConfig := krb5.NewConfig()
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(krb5Conf)
		krbConfig.DCEStyle = true

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

	// 1. Connect to Endpoint Mapper (Port 135)
	log.Info().Msgf("Connecting to %s:135", target.Host)
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(target.Host, "135"))
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

	wcc, err := dcerpc.Dial(ctx, target.Host, endpoints...)
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
		This:            &dcom.ORPCThis{Version: version},
		NetworkResource: *namespace,
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

	// Create the WQL shell
	shell := &WMIQuery{
		ctx:          wmiCtx,
		svcs:         svcs,
		conn:         wcc,
		version:      version,
		securityOpts: securityOpts,
		log:          log,
	}

	if *inputFile != "" {
		// File mode - read commands from file
		f, err := os.Open(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			fmt.Printf("WQL> %s\n", line)
			shell.processCommand(line)
		}
	} else {
		// Interactive mode
		shell.interactive()
	}
}

// WMIQuery handles the interactive WQL shell
type WMIQuery struct {
	ctx          context.Context
	svcs         iwbemservices.ServicesClient
	conn         dcerpc.Conn
	version      *dcom.COMVersion
	securityOpts []dcerpc.Option
	log          zerolog.Logger
}

func (q *WMIQuery) interactive() {
	fmt.Println("[!] Press help for extra shell commands")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("WQL> ")
		if !scanner.Scan() {
			fmt.Println()
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if q.processCommand(line) {
			break
		}
	}
}

// processCommand handles a single command. Returns true if shell should exit.
func (q *WMIQuery) processCommand(line string) bool {
	// Strip trailing semicolons like Impacket
	line = strings.TrimRight(line, ";")
	line = strings.TrimSpace(line)

	if line == "" {
		return false
	}

	lower := strings.ToLower(line)

	switch {
	case lower == "exit":
		return true

	case lower == "help":
		q.showHelp()

	case strings.HasPrefix(line, "!"):
		cmd := strings.TrimSpace(strings.TrimPrefix(line, "!"))
		if cmd == "" {
			return false
		}
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Local command error: %v\n", err)
		}
		fmt.Print(string(out))

	case strings.HasPrefix(lower, "lcd"):
		path := strings.TrimSpace(strings.TrimPrefix(line, line[:3]))
		if path == "" {
			wd, _ := os.Getwd()
			fmt.Println(wd)
		} else {
			if err := os.Chdir(path); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			}
		}

	case strings.HasPrefix(lower, "describe "):
		className := strings.TrimSpace(line[9:])
		q.describeClass(className)

	default:
		// Treat as WQL query
		q.execQuery(line)
	}

	return false
}

func (q *WMIQuery) showHelp() {
	fmt.Println(`
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 describe {class}           - describes class
 ! {cmd}                    - executes a local shell cmd
 `)
}

func (q *WMIQuery) execQuery(queryStr string) {
	// Execute WQL query via ExecQuery
	resp, err := q.svcs.ExecQuery(q.ctx, &iwbemservices.ExecQueryRequest{
		This:          &dcom.ORPCThis{Version: q.version},
		QueryLanguage: &oaut.String{Data: "WQL"},
		Query:         &oaut.String{Data: queryStr},
		Flags:         WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] ExecQuery failed: %v\n", err)
		return
	}

	if resp.Return != 0 {
		fmt.Fprintf(os.Stderr, "[-] ExecQuery returned error: 0x%08x\n", resp.Return)
		return
	}

	if resp.Enum == nil {
		fmt.Fprintln(os.Stderr, "[-] No enumerator returned")
		return
	}

	// Create enumerator client
	enumIPID := resp.Enum.InterfacePointer().IPID()
	enumOpts := append([]dcerpc.Option{dcom.WithIPID(enumIPID)}, q.securityOpts...)
	enumClient, err := ienumwbemclassobject.NewEnumClassObjectClient(q.ctx, q.conn, enumOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create enumerator client: %v\n", err)
		return
	}

	// Iterate results and print in Impacket format
	printHeader := true
	var columnNames []string

	for {
		nextResp, err := enumClient.Next(q.ctx, &ienumwbemclassobject.NextRequest{
			This:    &dcom.ORPCThis{Version: q.version},
			Timeout: 0x7FFFFFFF, // Large timeout
			Count:   1,
		})

		if err != nil {
			// S_FALSE (0x1) signals end of enumeration - the go-msrpc library
			// treats any non-zero HRESULT as error, but S_FALSE is normal
			if nextResp != nil && nextResp.Returned > 0 {
				// Got some results before error, process them below
			} else {
				// Check for S_FALSE / WBEM_S_FALSE / 0x00000001 (end of enumeration)
				errStr := err.Error()
				if strings.Contains(errStr, "S_FALSE") ||
					strings.Contains(errStr, "WBEM_S_FALSE") ||
					strings.Contains(errStr, "(0x00000001)") ||
					strings.Contains(errStr, "ERROR_INVALID_FUNCTION") {
					break
				}
				fmt.Fprintf(os.Stderr, "[-] Next failed: %v\n", err)
				break
			}
		}

		if nextResp.Returned == 0 {
			break
		}

		for _, obj := range nextResp.Objects {
			if obj == nil {
				continue
			}

			// Parse the ClassObject into a wmio.Object
			wmioObj, err := classObjectToWMIO(obj)
			if err != nil {
				q.log.Debug().Msgf("Failed to parse object: %v", err)
				continue
			}

			record := wmioObj.Values()
			if record == nil {
				continue
			}

			// Print header on first result
			if printHeader {
				// Get ordered column names from instance properties
				columnNames = getPropertyNames(wmioObj)
				fmt.Print("| ")
				for _, col := range columnNames {
					fmt.Printf("%s | ", col)
				}
				fmt.Println()
				printHeader = false
			}

			// Print values
			fmt.Print("| ")
			for _, key := range columnNames {
				val := record[key]
				formatValue(val)
				fmt.Print(" | ")
			}
			fmt.Println()
		}
	}
}

func (q *WMIQuery) describeClass(className string) {
	// Get the class object via GetObject
	resp, err := q.svcs.GetObject(q.ctx, &iwbemservices.GetObjectRequest{
		This:       &dcom.ORPCThis{Version: q.version},
		ObjectPath: &oaut.String{Data: className},
		Flags:      0,
		Object:     &wmi.ClassObject{},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] GetObject failed: %v\n", err)
		return
	}

	if resp.Return != 0 {
		fmt.Fprintf(os.Stderr, "[-] GetObject returned error: 0x%08x\n", resp.Return)
		return
	}

	if resp.Object == nil {
		fmt.Fprintln(os.Stderr, "[-] No object returned")
		return
	}

	// Parse into wmio.Object
	wmioObj, err := classObjectToWMIO(resp.Object)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to parse class object: %v\n", err)
		return
	}

	// Print class information matching Impacket's printInformation() format
	printClassInformation(wmioObj)
}

// printClassInformation outputs the WMI class description matching Impacket's format
func printClassInformation(obj *wmio.Object) {
	if obj == nil || obj.Class == nil {
		return
	}

	// Print each class in the hierarchy (parent first, then current)
	classes := []struct {
		class   *wmio.Class
		methods *wmio.Methods
	}{
		{&obj.Class.ParentClass, &obj.Class.ParentClassMethods},
		{&obj.Class.CurrentClass, &obj.Class.CurrentClassMethods},
	}

	for _, entry := range classes {
		cls := entry.class
		methods := entry.methods

		if cls.Name == "" {
			continue
		}

		// Print class-level qualifiers (just the name, matching Impacket)
		for _, q := range cls.Qualifiers {
			fmt.Printf("[%s]\n", formatClassQualifier(q))
		}

		// Print class declaration with derivation
		derivation := buildDerivationString(cls)
		fmt.Printf("class %s%s \n{\n", cls.Name, derivation)

		// Print properties
		for _, prop := range cls.Properties {
			// Print property qualifiers (filter CIMTYPE, show name(value))
			for _, q := range prop.Qualifiers {
				// Skip CIMTYPE qualifier like Impacket
				if strings.EqualFold(q.Name, "CIMTYPE") {
					continue
				}
				fmt.Printf("\t[%s]\n", formatQualifier(q))
			}

			// Print property type and name
			typeName := cimTypeToImpacketName(prop.Value.Type)
			if prop.Value.Value != nil && !prop.Nullable && !prop.InheritDefault {
				fmt.Printf("\t%s %s = %v\n", typeName, prop.Name, formatDefaultValue(prop.Value))
			} else {
				fmt.Printf("\t%s %s \n", typeName, prop.Name)
			}
			fmt.Println()
		}

		// Print methods
		if methods != nil {
			for _, method := range methods.Methods {
				printMethod(method)
			}
		}

		fmt.Println("}")
	}
}

// printMethod outputs a WMI method in Impacket format
func printMethod(method *wmio.Method) {
	// Print method qualifiers (use class-level format like Impacket)
	for _, q := range method.Qualifiers {
		fmt.Printf("\t[%s]\n", formatClassQualifier(q))
	}

	// Determine return type from output signature
	returnType := "uint32"
	var outParams []*wmio.Property
	if method.OutputSignature.Class != nil {
		for _, prop := range method.OutputSignature.Class.CurrentClass.Properties {
			if prop.Name == "ReturnValue" {
				returnType = cimTypeToImpacketName(prop.Value.Type)
			} else {
				outParams = append(outParams, prop)
			}
		}
	}

	// Collect input parameters
	var inParams []*wmio.Property
	if method.InputSignature.Class != nil {
		inParams = method.InputSignature.Class.CurrentClass.Properties
	}

	// If no parameters at all, use compact format like Impacket
	if len(inParams) == 0 && len(outParams) == 0 {
		fmt.Printf("\t%s %s();\n\n", returnType, method.Name)
		return
	}

	fmt.Printf("\t%s %s(\n", returnType, method.Name)

	// Print input parameters
	for _, param := range inParams {
		fmt.Printf(" \t\t[in]    %s %s,\n", cimTypeToImpacketName(param.Value.Type), param.Name)
	}

	// Print output parameters
	for _, param := range outParams {
		fmt.Printf(" \t\t[out]    %s %s,\n", cimTypeToImpacketName(param.Value.Type), param.Name)
	}

	fmt.Printf("\t);\n\n")
}

// classObjectToWMIO converts a wmi.ClassObject to a wmio.Object
func classObjectToWMIO(classObj *wmi.ClassObject) (*wmio.Object, error) {
	if classObj == nil || len(classObj.Data) == 0 {
		return nil, fmt.Errorf("empty class object")
	}

	ref := &dcom.ObjectReference{}
	if err := ndr.Unmarshal(classObj.Data, ref, ndr.Opaque); err != nil {
		return nil, fmt.Errorf("ndr unmarshal: %v", err)
	}

	custom, ok := ref.ObjectReference.GetValue().(*dcom.ObjectReferenceCustom)
	if !ok || len(custom.ObjectData) == 0 {
		return nil, fmt.Errorf("not a custom object reference or empty data")
	}

	obj, err := wmio.Unmarshal(custom.ObjectData)
	if err != nil {
		return nil, fmt.Errorf("wmio unmarshal: %v", err)
	}

	return obj, nil
}

// getPropertyNames returns property names in order from the wmio.Object
func getPropertyNames(obj *wmio.Object) []string {
	if obj == nil || obj.Instance == nil {
		return nil
	}

	names := make([]string, len(obj.Instance.Properties))
	for i, prop := range obj.Instance.Properties {
		names[i] = prop.Name
	}
	return names
}

// formatValue prints a property value matching Impacket's output style
func formatValue(val interface{}) {
	if val == nil {
		fmt.Print("None")
		return
	}

	switch v := val.(type) {
	case []interface{}:
		// Array values - print space separated like Impacket
		for i, item := range v {
			if i > 0 {
				fmt.Print(" ")
			}
			fmt.Print(item)
		}
	case wmio.Values:
		// Nested object
		fmt.Print("{object}")
	default:
		fmt.Print(v)
	}
}

// formatClassQualifier formats a class-level qualifier (just the name, matching Impacket)
func formatClassQualifier(q *wmio.Qualifier) string {
	if q == nil {
		return ""
	}
	return q.Name
}

// formatQualifier formats a property/method qualifier in Impacket style [name(value)]
func formatQualifier(q *wmio.Qualifier) string {
	if q == nil {
		return ""
	}

	// Boolean qualifiers show (True) or (False) like Impacket
	if q.Value.Type == wmio.Bool {
		if v, ok := q.Value.Value.(bool); ok {
			if v {
				return fmt.Sprintf("%s(True)", q.Name)
			}
			return fmt.Sprintf("%s(False)", q.Name)
		}
		return q.Name
	}

	// String qualifiers
	if q.Value.Type == wmio.String {
		if v, ok := q.Value.Value.(string); ok {
			return fmt.Sprintf("%s(%s)", q.Name, v)
		}
	}

	// Array qualifiers
	if q.Value.Type.IsArray() {
		return formatArrayQualifier(q)
	}

	// Numeric/other qualifiers
	if q.Value.Value != nil {
		return fmt.Sprintf("%s(%v)", q.Name, q.Value.Value)
	}

	return q.Name
}

// formatArrayQualifier formats array-type qualifiers
func formatArrayQualifier(q *wmio.Qualifier) string {
	switch v := q.Value.Value.(type) {
	case []string:
		items := make([]string, len(v))
		for i, s := range v {
			items[i] = fmt.Sprintf("'%s'", s)
		}
		return fmt.Sprintf("%s([%s])", q.Name, strings.Join(items, ", "))
	default:
		return fmt.Sprintf("%s(%v)", q.Name, q.Value.Value)
	}
}

// buildDerivationString builds the class derivation/hierarchy string
func buildDerivationString(cls *wmio.Class) string {
	if len(cls.Derivation) == 0 {
		return ""
	}

	parts := make([]string, len(cls.Derivation))
	for i, d := range cls.Derivation {
		parts[i] = d + " "
	}
	return " : " + strings.Join(parts, " : ")
}

// cimTypeToImpacketName converts a CIM type to Impacket's displayed type name
func cimTypeToImpacketName(t wmio.CIMType) string {
	switch t {
	case wmio.Int8:
		return "sint8"
	case wmio.Uint8:
		return "uint8"
	case wmio.Int16:
		return "sint16"
	case wmio.Uint16:
		return "uint16"
	case wmio.Int32:
		return "sint32"
	case wmio.Uint32:
		return "uint32"
	case wmio.Int64:
		return "sint64"
	case wmio.Uint64:
		return "uint64"
	case wmio.Float32:
		return "real32"
	case wmio.Float64:
		return "real64"
	case wmio.Bool:
		return "boolean"
	case wmio.String:
		return "string"
	case wmio.DateTime:
		return "datetime"
	case wmio.Ref:
		return "ref"
	case wmio.CIMObject:
		return "object"
	default:
		return t.String()
	}
}

// formatDefaultValue formats a property default value for display
func formatDefaultValue(v wmio.Value) string {
	if v.Value == nil {
		return ""
	}
	return fmt.Sprintf("%v", v.Value)
}
