// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/svcctl"
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
	subFlags := flag.NewFlagSet("services "+action, flag.ExitOnError)
	serviceName := subFlags.String("name", "", "Service name")
	displayName := subFlags.String("display", "", "Display name (for create/change)")
	binaryPath := subFlags.String("path", "", "Binary path (for create/change)")
	serviceType := subFlags.Int("service_type", -1, "Service type (for change)")
	startType := subFlags.Int("start_type", -1, "Start type (for change)")
	startName := subFlags.String("start_name", "", "Service start name / account (for change)")
	password := subFlags.String("password", "", "Password for service account (for change)")
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

	fmt.Println("gopacket v0.1.0 - services")
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

	// Open svcctl pipe
	pipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open svcctl pipe: %v\n", err)
		os.Exit(1)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] svcctl bind failed: %v\n", err)
		os.Exit(1)
	}

	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open SCManager: %v\n", err)
		os.Exit(1)
	}
	defer sc.Close()

	switch action {
	case "list":
		cmdList(sc)
	case "start":
		requireName(*serviceName)
		cmdStart(sc, *serviceName)
	case "stop":
		requireName(*serviceName)
		cmdStop(sc, *serviceName)
	case "delete":
		requireName(*serviceName)
		cmdDelete(sc, *serviceName)
	case "status":
		requireName(*serviceName)
		cmdStatus(sc, *serviceName)
	case "config":
		requireName(*serviceName)
		cmdConfig(sc, *serviceName)
	case "create":
		requireName(*serviceName)
		if *binaryPath == "" {
			fmt.Fprintf(os.Stderr, "[-] -path is required for create\n")
			os.Exit(1)
		}
		cmdCreate(sc, *serviceName, *displayName, *binaryPath)
	case "change":
		requireName(*serviceName)
		cmdChange(sc, *serviceName, *displayName, *binaryPath, *serviceType, *startType, *startName, *password)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown action: %s\n", action)
		printUsage()
		os.Exit(1)
	}
}

func requireName(name string) {
	if name == "" {
		fmt.Fprintf(os.Stderr, "[-] -name is required for this action\n")
		os.Exit(1)
	}
}

func cmdList(sc *svcctl.ServiceController) {
	fmt.Println("[*] Listing services available on target")
	entries, err := sc.EnumServicesStatus(
		svcctl.SERVICE_KERNEL_DRIVER|svcctl.SERVICE_FILE_SYSTEM_DRIVER|svcctl.SERVICE_WIN32_OWN_PROCESS|svcctl.SERVICE_WIN32_SHARE_PROCESS|svcctl.SERVICE_INTERACTIVE_PROCESS,
		svcctl.SERVICE_STATE_ALL,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] EnumServicesStatus failed: %v\n", err)
		os.Exit(1)
	}

	for _, e := range entries {
		state := svcctl.GetServiceState(e.Status.CurrentState)
		fmt.Printf("%30s - %70s -  %s\n", e.ServiceName, e.DisplayName, state)
	}
	fmt.Printf("Total Services: %d\n", len(entries))
}

func cmdStart(sc *svcctl.ServiceController, name string) {
	handle, err := sc.OpenService(name, svcctl.SERVICE_START)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sc.CloseServiceHandle(handle)

	fmt.Printf("[*] Starting service %s\n", name)
	if err := sc.StartService(handle); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func cmdStop(sc *svcctl.ServiceController, name string) {
	handle, err := sc.OpenService(name, svcctl.SERVICE_STOP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sc.CloseServiceHandle(handle)

	fmt.Printf("[*] Stopping service %s\n", name)
	if _, err := sc.StopService(handle); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func cmdDelete(sc *svcctl.ServiceController, name string) {
	handle, err := sc.OpenService(name, 0x10000) // DELETE standard right
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sc.CloseServiceHandle(handle)

	fmt.Printf("[*] Deleting service %s\n", name)
	if err := sc.DeleteService(handle); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func cmdStatus(sc *svcctl.ServiceController, name string) {
	handle, err := sc.OpenService(name, svcctl.SERVICE_QUERY_STATUS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sc.CloseServiceHandle(handle)

	status, err := sc.QueryServiceStatus(handle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s - %s\n", name, svcctl.GetServiceState(status.CurrentState))
}

func cmdConfig(sc *svcctl.ServiceController, name string) {
	fmt.Printf("[*] Querying service config for %s\n", name)
	handle, err := sc.OpenService(name, svcctl.SERVICE_QUERY_CONFIG)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sc.CloseServiceHandle(handle)

	config, err := sc.QueryServiceConfig(handle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("TYPE              : %2d -  %s\n", config.ServiceType, serviceTypeName(config.ServiceType))
	fmt.Printf("START_TYPE        : %2d -  %s\n", config.StartType, startTypeName(config.StartType))
	fmt.Printf("ERROR_CONTROL     : %2d -  %s\n", config.ErrorControl, errorControlName(config.ErrorControl))
	fmt.Printf("BINARY_PATH_NAME  : %s\n", config.BinaryPathName)
	fmt.Printf("LOAD_ORDER_GROUP  : %s\n", config.LoadOrderGroup)
	fmt.Printf("TAG               : %d\n", config.TagId)
	fmt.Printf("DISPLAY_NAME      : %s\n", config.DisplayName)
	fmt.Printf("DEPENDENCIES      : %s\n", config.Dependencies)
	fmt.Printf("SERVICE_START_NAME: %s\n", config.ServiceStartName)
}

func cmdCreate(sc *svcctl.ServiceController, name, display, path string) {
	fmt.Printf("[*] Creating service %s\n", name)
	handle, err := sc.CreateService(name, display, path,
		svcctl.SERVICE_WIN32_OWN_PROCESS,
		svcctl.SERVICE_DEMAND_START,
		svcctl.ERROR_NORMAL,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	sc.CloseServiceHandle(handle)
}

func cmdChange(sc *svcctl.ServiceController, name, display, path string, svcType, startType int, startName, password string) {
	handle, err := sc.OpenService(name, svcctl.SERVICE_CHANGE_CONFIG)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer sc.CloseServiceHandle(handle)

	params := &svcctl.ChangeServiceConfigParams{
		ServiceType:      svcctl.SERVICE_NO_CHANGE,
		StartType:        svcctl.SERVICE_NO_CHANGE,
		ErrorControl:     svcctl.SERVICE_NO_CHANGE,
		BinaryPathName:   path,
		DisplayName:      display,
		ServiceStartName: startName,
		Password:         password,
	}

	if svcType >= 0 {
		params.ServiceType = uint32(svcType)
	}
	if startType >= 0 {
		params.StartType = uint32(startType)
	}

	fmt.Printf("[*] Changing service config for %s\n", name)
	if err := sc.ChangeServiceConfig(handle, params); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func serviceTypeName(t uint32) string {
	// Matches Impacket's format: print("FLAG ", end=' ') gives "FLAG  " (2 trailing spaces)
	var s string
	if t&svcctl.SERVICE_KERNEL_DRIVER != 0 {
		s += "SERVICE_KERNEL_DRIVER  "
	}
	if t&svcctl.SERVICE_FILE_SYSTEM_DRIVER != 0 {
		s += "SERVICE_FILE_SYSTEM_DRIVER  "
	}
	if t&svcctl.SERVICE_WIN32_OWN_PROCESS != 0 {
		s += "SERVICE_WIN32_OWN_PROCESS  "
	}
	if t&svcctl.SERVICE_WIN32_SHARE_PROCESS != 0 {
		s += "SERVICE_WIN32_SHARE_PROCESS  "
	}
	if t&svcctl.SERVICE_INTERACTIVE_PROCESS != 0 {
		s += "SERVICE_INTERACTIVE_PROCESS  "
	}
	if s == "" {
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
	return s
}

func startTypeName(t uint32) string {
	switch t {
	case svcctl.SERVICE_BOOT_START:
		return "BOOT START"
	case svcctl.SERVICE_SYSTEM_START:
		return "SYSTEM START"
	case svcctl.SERVICE_AUTO_START:
		return "AUTO START"
	case svcctl.SERVICE_DEMAND_START:
		return "DEMAND START"
	case svcctl.SERVICE_DISABLED:
		return "DISABLED"
	default:
		return fmt.Sprintf("UNKNOWN (0x%x)", t)
	}
}

func errorControlName(t uint32) string {
	switch t {
	case svcctl.ERROR_IGNORE:
		return "IGNORE"
	case svcctl.ERROR_NORMAL:
		return "NORMAL"
	case svcctl.ERROR_SEVERE:
		return "SEVERE"
	case svcctl.ERROR_CRITICAL:
		return "CRITICAL"
	default:
		return fmt.Sprintf("UNKNOWN (0x%x)", t)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "gopacket v0.1.0 - services")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage: services [auth-flags] target <action> [action-flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Target:")
	fmt.Fprintln(os.Stderr, "  [[domain/]username[:password]@]<targetName or address>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Actions:")
	fmt.Fprintln(os.Stderr, "  list                                       List available services")
	fmt.Fprintln(os.Stderr, "  start   -name <svc>                        Start a service")
	fmt.Fprintln(os.Stderr, "  stop    -name <svc>                        Stop a service")
	fmt.Fprintln(os.Stderr, "  delete  -name <svc>                        Delete a service")
	fmt.Fprintln(os.Stderr, "  status  -name <svc>                        Query service status")
	fmt.Fprintln(os.Stderr, "  config  -name <svc>                        Query service configuration")
	fmt.Fprintln(os.Stderr, "  create  -name <svc> -display <n> -path <p> Create a service")
	fmt.Fprintln(os.Stderr, "  change  -name <svc> [options]              Change service configuration")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Change options:")
	fmt.Fprintln(os.Stderr, "  -display <name>      Display name")
	fmt.Fprintln(os.Stderr, "  -path <binary>       Binary path")
	fmt.Fprintln(os.Stderr, "  -service_type <N>    Service type")
	fmt.Fprintln(os.Stderr, "  -start_type <N>      Start type")
	fmt.Fprintln(os.Stderr, "  -start_name <acct>   Service start name / account")
	fmt.Fprintln(os.Stderr, "  -password <pw>       Password for service account")
}

// isFlagWithValue returns true if the flag requires a value argument.
func isFlagWithValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	if idx := strings.Index(name, "="); idx >= 0 {
		return false
	}
	boolFlags := map[string]bool{
		"no-pass": true, "k": true, "ts": true, "debug": true,
	}
	return !boolFlags[name]
}
