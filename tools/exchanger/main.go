// exchanger is a tool for connecting to MS Exchange via RPC over HTTP v2
// and querying the NSPI (Name Service Provider Interface) to enumerate
// address books and extract user information.
//
// This is a Go port of Impacket's exchanger.py
//
// Usage:
//
//	exchanger [options] target nspi <subcommand>
//
// Subcommands:
//
//	list-tables  - List address books
//	dump-tables  - Dump address book contents
//	guid-known   - Retrieve AD objects by GUID
//	dnt-lookup   - Lookup Distinguished Name Tags
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"gopacket/internal/build"
	"gopacket/pkg/mapi"
	"gopacket/pkg/nspi"
	"gopacket/pkg/session"
)

const VERSION = "1.0.0"

// Command-line options
type Options struct {
	// Target
	Target   string
	TargetIP string

	// Authentication
	Hashes   string
	Kerberos bool
	NoPass   bool
	AESKey   string
	DCIP     string

	// Connection
	RPCHostname string

	// Output
	Debug          bool
	Timestamp      bool
	OutputFile     string
	OutputType     string // hex or base64
	ExtendedOutput bool

	// Subcommand options
	Module     string
	Submodule  string
	Count      bool   // For list-tables
	LookupType string // MINIMAL, EXTENDED, FULL, GUIDS
	RowsPerReq int
	Name       string // For dump-tables
	GUID       string // For dump-tables/guid-known
	GUIDFile   string // For guid-known
	StartDNT   int    // For dnt-lookup
	StopDNT    int    // For dnt-lookup
}

// writer handles output to both stdout and optional file
type writer struct {
	file *os.File
}

func newWriter(outputFile string) (*writer, error) {
	w := &writer{}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}
		w.file = f
	}
	return w, nil
}

func (w *writer) Close() {
	if w.file != nil {
		w.file.Close()
	}
}

func (w *writer) Printf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	fmt.Print(s)
	if w.file != nil {
		io.WriteString(w.file, s)
	}
}

func (w *writer) Println(args ...interface{}) {
	s := fmt.Sprintln(args...)
	fmt.Print(s)
	if w.file != nil {
		io.WriteString(w.file, s)
	}
}

func printBanner() {
	fmt.Println("gopacket Exchanger v" + VERSION + " - MS Exchange NSPI Client")
	fmt.Println()
}

func printUsage() {
	printBanner()
	fmt.Println("Usage: exchanger [options] target nspi <subcommand>")
	fmt.Println()
	fmt.Println("Target:")
	fmt.Println("  [[domain/]username[:password]@]<targetName or address>")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -debug              Turn DEBUG output ON")
	fmt.Println("  -ts                 Add timestamp to logging output")
	fmt.Println("  -rpc-hostname       RPC server name (NetBIOS or GUID format)")
	fmt.Println("  -hashes LMHASH:NTHASH  NTLM hashes for authentication")
	fmt.Println("  -k                  Use Kerberos authentication")
	fmt.Println("  -no-pass            Don't ask for password (useful for -k)")
	fmt.Println("  -aesKey hex key     AES key to use for Kerberos Authentication")
	fmt.Println("  -dc-ip ip address   IP Address of the domain controller")
	fmt.Println("  -target-ip ip address  IP Address of the target machine")
	fmt.Println()
	fmt.Println("NSPI Subcommands:")
	fmt.Println("  list-tables    List address books")
	fmt.Println("  dump-tables    Dump address book contents")
	fmt.Println("  guid-known     Retrieve AD objects by GUID")
	fmt.Println("  dnt-lookup     Lookup Distinguished Name Tags")
	fmt.Println()
	fmt.Println("Run 'exchanger target nspi <subcommand> -h' for subcommand help")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Check for help
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			printUsage()
			os.Exit(0)
		}
	}

	// Parse common flags
	opts := &Options{
		OutputType: "hex",
		RowsPerReq: 50,
	}

	// Find target and module/submodule
	args := os.Args[1:]
	var nonFlagArgs []string

	// First pass: collect non-flag arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			// Handle flag with value
			switch arg {
			case "-debug":
				opts.Debug = true
			case "-ts":
				opts.Timestamp = true
			case "-count":
				opts.Count = true
			case "-k":
				opts.Kerberos = true
			case "-no-pass":
				opts.NoPass = true
			case "-aesKey":
				if i+1 < len(args) {
					i++
					opts.AESKey = args[i]
				}
			case "-dc-ip":
				if i+1 < len(args) {
					i++
					opts.DCIP = args[i]
				}
			case "-target-ip":
				if i+1 < len(args) {
					i++
					opts.TargetIP = args[i]
				}
			case "-rpc-hostname":
				if i+1 < len(args) {
					i++
					opts.RPCHostname = args[i]
				}
			case "-hashes":
				if i+1 < len(args) {
					i++
					opts.Hashes = args[i]
				}
			case "-output-file":
				if i+1 < len(args) {
					i++
					opts.OutputFile = args[i]
				}
			case "-output-type":
				if i+1 < len(args) {
					i++
					opts.OutputType = args[i]
				}
			case "-lookup-type":
				if i+1 < len(args) {
					i++
					opts.LookupType = args[i]
				}
			case "-rows-per-request":
				if i+1 < len(args) {
					i++
					fmt.Sscanf(args[i], "%d", &opts.RowsPerReq)
				}
			case "-name":
				if i+1 < len(args) {
					i++
					opts.Name = args[i]
				}
			case "-guid":
				if i+1 < len(args) {
					i++
					opts.GUID = args[i]
				}
			case "-guid-file":
				if i+1 < len(args) {
					i++
					opts.GUIDFile = args[i]
				}
			case "-start-dnt":
				if i+1 < len(args) {
					i++
					fmt.Sscanf(args[i], "%d", &opts.StartDNT)
				}
			case "-stop-dnt":
				if i+1 < len(args) {
					i++
					fmt.Sscanf(args[i], "%d", &opts.StopDNT)
				}
			}
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}

	if len(nonFlagArgs) < 1 {
		printUsage()
		os.Exit(1)
	}

	opts.Target = nonFlagArgs[0]
	if len(nonFlagArgs) >= 2 {
		opts.Module = strings.ToLower(nonFlagArgs[1])
	}
	if len(nonFlagArgs) >= 3 {
		opts.Submodule = strings.ToLower(nonFlagArgs[2])
	}

	// Set debug flags
	if opts.Debug {
		build.Debug = true
		opts.ExtendedOutput = true
	}
	if opts.Timestamp {
		build.Timestamp = true
	}

	// Validate module
	if opts.Module == "" || opts.Module != "nspi" {
		fmt.Println("Error: Currently only 'nspi' module is supported")
		printUsage()
		os.Exit(1)
	}

	// Validate submodule
	validSubmodules := map[string]bool{
		"list-tables": true,
		"dump-tables": true,
		"guid-known":  true,
		"dnt-lookup":  true,
	}
	if opts.Submodule == "" || !validSubmodules[opts.Submodule] {
		fmt.Println("Error: Invalid or missing submodule")
		fmt.Println("Valid submodules: list-tables, dump-tables, guid-known, dnt-lookup")
		os.Exit(1)
	}

	// Parse target
	target, creds, err := session.ParseTargetString(opts.Target)
	if err != nil {
		fmt.Printf("Error parsing target: %v\n", err)
		os.Exit(1)
	}

	// Apply hashes if provided
	if opts.Hashes != "" {
		creds.Hash = opts.Hashes
	}

	// Apply Kerberos settings
	if opts.Kerberos {
		creds.UseKerberos = true
	}
	if opts.AESKey != "" {
		creds.AESKey = opts.AESKey
	}
	if opts.DCIP != "" {
		creds.DCIP = opts.DCIP
	}

	// Prompt for password if needed (skip for -no-pass or Kerberos with ccache)
	if !opts.NoPass && creds.Password == "" && creds.Hash == "" && creds.AESKey == "" && creds.Username != "" {
		session.EnsurePassword(&creds)
	}

	// Run exchanger
	printBanner()
	if err := run(opts, target, creds); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func run(opts *Options, target session.Target, creds session.Credentials) error {
	// The target.Host from the target string is the FQDN (for SPN/TLS SNI).
	// If -target-ip is specified, we connect to that IP but keep the FQDN as RemoteName.
	remoteName := target.Host
	connectHost := target.Host
	if opts.TargetIP != "" {
		connectHost = opts.TargetIP
	}

	// Create NSPI client - remoteName is the TLS/SPN hostname, connectHost is where we connect
	client := nspi.NewClient(remoteName, opts.RPCHostname)
	client.SetCredentials(creds.Username, creds.Password, creds.Domain, creds.Hash)

	// If target-ip specified, connect to IP but keep FQDN for Host header/SPN
	if connectHost != remoteName {
		client.Transport.ConnectHost = connectHost
	}

	// Configure Kerberos if requested
	if creds.UseKerberos {
		client.SetKerberosConfig(true, &creds)
		client.Transport.DCIP = creds.DCIP
	}

	// Connect
	fmt.Printf("[*] Connecting to %s...\n", connectHost)
	if err := client.Connect(); err != nil {
		return fmt.Errorf("connect failed: %v", err)
	}
	defer client.Disconnect()

	fmt.Println("[+] Connected successfully")

	// Run subcommand
	switch opts.Submodule {
	case "list-tables":
		return runListTables(client, opts)
	case "dump-tables":
		return runDumpTables(client, opts)
	case "guid-known":
		return runGUIDKnown(client, opts)
	case "dnt-lookup":
		return runDNTLookup(client, opts)
	}

	return nil
}

func runListTables(client *nspi.Client, opts *Options) error {
	fmt.Println("[*] Retrieving address book hierarchy...")

	// Get hierarchy table
	if err := client.GetSpecialTable(); err != nil {
		return err
	}

	// Load counts if requested
	if opts.Count {
		for mid := range client.HTable {
			client.UpdateStat(mid)
			client.HTable[mid].Count = client.Stat.TotalRecs
			client.HTable[mid].StartMId = client.Stat.CurrentRec
		}
	}

	// Open output writer
	out, err := newWriter(opts.OutputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// Print hierarchy
	printHierarchyTable(client, opts, out, nil)

	// Print parentless objects
	for mid, entry := range client.HTable {
		if !entry.Printed && mid != 0 {
			out.Println("Found parentless object!")
			out.Printf("Name: %s\n", entry.Name)
			if entry.GUID != nil {
				out.Printf("Guid: %s\n", nspi.FormatGUID(entry.GUID))
			}
			if entry.ParentGUID != nil {
				out.Printf("Parent guid: %s\n", nspi.FormatGUID(entry.ParentGUID))
			}
			dword := intToDword(mid)
			out.Printf("Assigned MId: 0x%.08X (%d)\n", dword, mid)
			flags := mapi.ParseBitmask(mapi.ContainerFlagsValues, entry.Flags)
			out.Printf("Flags: %s\n", strings.Join(flags, " | "))
			if entry.IsMaster {
				out.Println("PR_EMS_AB_IS_MASTER attribute is set!")
			}
			out.Println()
		}
	}

	return nil
}

func printHierarchyTable(client *nspi.Client, opts *Options, out *writer, parentGUID []byte) {
	// Iterate in server insertion order (matching Impacket's Python dict behavior)
	var mids []int32
	for _, mid := range client.HTableOrder {
		entry := client.HTable[mid]
		if entry == nil {
			continue
		}
		if parentGUID == nil && entry.ParentGUID == nil {
			mids = append(mids, mid)
		} else if parentGUID != nil && entry.ParentGUID != nil && string(entry.ParentGUID) == string(parentGUID) {
			mids = append(mids, mid)
		}
	}

	for _, mid := range mids {
		entry := client.HTable[mid]
		entry.Printed = true
		indent := strings.Repeat("    ", int(entry.Depth))

		// Name
		out.Printf("%s%s\n", indent, entry.Name)

		// Count
		if opts.Count {
			out.Printf("%sTotalRecs: %d\n", indent, entry.Count)
		}

		// GUID
		if entry.GUID != nil {
			out.Printf("%sGuid: %s\n", indent, nspi.FormatGUID(entry.GUID))
		} else if mid == 0 {
			out.Printf("%sGuid: None\n", indent)
		}

		// Master flag
		if entry.IsMaster {
			out.Printf("%sPR_EMS_AB_IS_MASTER attribute is set!\n", indent)
		}

		// Extended info
		if opts.ExtendedOutput {
			dword := intToDword(mid)
			out.Printf("%sAssigned MId: 0x%.08X (%d)\n", indent, dword, mid)

			if opts.Count && entry.StartMId > 0 {
				if entry.StartMId == 2 {
					out.Printf("%sAssigned first record MId: 0x00000002 (MID_END_OF_TABLE)\n", indent)
				} else {
					out.Printf("%sAssigned first record MId: 0x%.08X (%d)\n", indent, entry.StartMId, entry.StartMId)
				}
			}

			flags := mapi.ParseBitmask(mapi.ContainerFlagsValues, entry.Flags)
			out.Printf("%sFlags: %s\n", indent, strings.Join(flags, " | "))
		}

		out.Println()

		// Recurse for children
		if entry.GUID != nil {
			printHierarchyTable(client, opts, out, entry.GUID)
		}
	}
}

func runDumpTables(client *nspi.Client, opts *Options) error {
	// Default to GAL if neither name nor GUID specified (matches Impacket)
	if opts.Name == "" && opts.GUID == "" {
		opts.Name = "GAL"
	}
	if opts.Name != "" && opts.GUID != "" {
		fmt.Println("Error: specify only one of -name or -guid")
		return nil
	}

	// Determine property tags based on lookup type
	lookupType := strings.ToUpper(opts.LookupType)
	if lookupType == "" {
		lookupType = "MINIMAL"
	}

	var propTags []nspi.PropertyTag
	var useExplicitTable bool

	switch lookupType {
	case "MINIMAL":
		propTags = getMinimalProps()
	case "GUIDS":
		propTags = []nspi.PropertyTag{nspi.PropertyTag(mapi.PR_EMS_AB_OBJECT_GUID)}
	case "EXTENDED":
		propTags = getExtendedProps()
		useExplicitTable = true
	case "FULL":
		// Query all available properties
		props, err := client.QueryColumns()
		if err != nil {
			return err
		}
		propTags = props
		useExplicitTable = true
	default:
		propTags = getMinimalProps()
	}

	// Find table MId
	var tableMId int32 = 0

	if opts.Name != "" {
		nameLower := strings.ToLower(opts.Name)
		if nameLower == "gal" || nameLower == "default global address list" || nameLower == "global address list" {
			fmt.Println("[*] Looking up Global Address List")
			tableMId = 0
		} else {
			// Load hierarchy and find by name
			if err := client.GetSpecialTable(); err != nil {
				return err
			}

			found := false
			for mid, entry := range client.HTable {
				if strings.EqualFold(entry.Name, opts.Name) {
					tableMId = mid
					found = true
					fmt.Printf("[*] Looking up %s\n", entry.Name)
					break
				}
			}

			if !found {
				return fmt.Errorf("address book '%s' not found", opts.Name)
			}
		}
	} else if opts.GUID != "" {
		// Find by GUID
		if err := client.GetSpecialTable(); err != nil {
			return err
		}

		guidBytes, _ := parseGUID(opts.GUID)
		found := false
		for mid, entry := range client.HTable {
			if entry.GUID != nil && string(entry.GUID) == string(guidBytes) {
				tableMId = mid
				found = true
				fmt.Printf("[*] Looking up %s\n", entry.Name)
				break
			}
		}

		if !found {
			return fmt.Errorf("address book with GUID %s not found", opts.GUID)
		}
	}

	// Open output writer
	out, err := newWriter(opts.OutputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// Update stat to check for empty table
	if err := client.UpdateStat(tableMId); err != nil {
		return err
	}
	if client.Stat.CurrentRec == nspi.MID_END_OF_TABLE {
		fmt.Println("[*] Table is empty")
		return nil
	}

	totalRows := 0
	delimiter := "======================="

	if useExplicitTable {
		// Two-phase query: first get MIds via PR_INSTANCE_KEY, then fetch full properties
		firstReqProps := []nspi.PropertyTag{nspi.PropertyTag(mapi.PR_INSTANCE_KEY)}

		if err := client.LoadHTableContainerID(); err != nil {
			return err
		}

		err := client.QueryRowsWithCallback(tableMId, uint32(opts.RowsPerReq), firstReqProps, func(rowSet *nspi.PropertyRowSet) error {
			// Extract MIds from PR_INSTANCE_KEY
			var eTable []uint32
			for _, row := range rowSet.Rows {
				props := nspi.SimplifyPropertyRow(&row)
				if v, ok := props[nspi.PropertyTag(mapi.PR_INSTANCE_KEY)]; ok {
					if bin, ok := v.(nspi.BinaryObject); ok && len(bin) >= 4 {
						mid := binary.LittleEndian.Uint32([]byte(bin))
						eTable = append(eTable, mid)
					}
				}
			}

			if len(eTable) == 0 {
				return nil
			}

			// Second query with full properties using explicit table
			fullRowSet, err := client.QueryRowsExplicit(client.AnyExistingContainerID, uint32(opts.RowsPerReq), propTags, eTable)
			if err != nil {
				return err
			}

			if fullRowSet != nil {
				for i := range fullRowSet.Rows {
					printPropertyRowOrdered(&fullRowSet.Rows[i], opts, out)
					out.Println(delimiter)
					totalRows++
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else if lookupType == "GUIDS" {
		// GUIDS mode: only print GUIDs
		err := client.QueryRowsWithCallback(tableMId, uint32(opts.RowsPerReq), propTags, func(rowSet *nspi.PropertyRowSet) error {
			for _, row := range rowSet.Rows {
				props := nspi.SimplifyPropertyRow(&row)
				if v, ok := props[nspi.PropertyTag(mapi.PR_EMS_AB_OBJECT_GUID)]; ok {
					if bin, ok := v.(nspi.BinaryObject); ok && len(bin) == 16 {
						out.Println(nspi.FormatGUID([]byte(bin)))
						totalRows++
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		// MINIMAL mode: direct query with pagination
		err := client.QueryRowsWithCallback(tableMId, uint32(opts.RowsPerReq), propTags, func(rowSet *nspi.PropertyRowSet) error {
			for i := range rowSet.Rows {
				printPropertyRowOrdered(&rowSet.Rows[i], opts, out)
				out.Println(delimiter)
				totalRows++
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	fmt.Printf("[+] Total rows: %d\n", totalRows)

	return nil
}

func runGUIDKnown(client *nspi.Client, opts *Options) error {
	if opts.GUID == "" && opts.GUIDFile == "" {
		fmt.Println("Error: specify -guid or -guid-file")
		return nil
	}
	if opts.GUID != "" && opts.GUIDFile != "" {
		fmt.Println("Error: specify only one of -guid or -guid-file")
		return nil
	}

	// Determine property tags
	lookupType := strings.ToUpper(opts.LookupType)
	if lookupType == "" {
		lookupType = "MINIMAL"
	}

	var propTags []nspi.PropertyTag
	switch lookupType {
	case "MINIMAL":
		propTags = getMinimalProps()
	case "EXTENDED":
		propTags = getExtendedProps()
	case "FULL":
		props, err := client.QueryColumns()
		if err != nil {
			return err
		}
		propTags = props
	default:
		propTags = getMinimalProps()
	}

	// Open output writer
	out, err := newWriter(opts.OutputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	delimiter := "======================="

	if opts.GUID != "" {
		// Single GUID lookup
		dn := nspi.GetDNFromGUID(opts.GUID)
		if dn == "" {
			return fmt.Errorf("invalid GUID format: %s", opts.GUID)
		}

		fmt.Printf("[*] Looking up GUID %s...\n", opts.GUID)

		rowSet, err := client.ResolveNamesW([]string{dn}, propTags)
		if err != nil {
			return err
		}

		if rowSet == nil || len(rowSet.Rows) == 0 {
			return fmt.Errorf("object with GUID %s not found", opts.GUID)
		}

		for i := range rowSet.Rows {
			printPropertyRowOrdered(&rowSet.Rows[i], opts, out)
			if i < len(rowSet.Rows)-1 {
				out.Println(delimiter)
			}
		}
	} else {
		// File-based lookup
		fmt.Printf("[*] Looking up GUIDs from %s...\n", opts.GUIDFile)

		f, err := os.Open(opts.GUIDFile)
		if err != nil {
			return fmt.Errorf("failed to open GUID file: %v", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		var batch []string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			dn := nspi.GetDNFromGUID(line)
			if dn == "" {
				fmt.Printf("[!] Invalid GUID: %s, skipping\n", line)
				continue
			}
			batch = append(batch, dn)

			// Process in batches
			if len(batch) >= opts.RowsPerReq {
				if err := resolveAndPrintBatch(client, batch, propTags, opts, out, delimiter); err != nil {
					fmt.Printf("[!] Batch error: %v\n", err)
				}
				batch = nil
			}
		}

		// Process remaining
		if len(batch) > 0 {
			if err := resolveAndPrintBatch(client, batch, propTags, opts, out, delimiter); err != nil {
				fmt.Printf("[!] Batch error: %v\n", err)
			}
		}
	}

	return nil
}

func resolveAndPrintBatch(client *nspi.Client, names []string, propTags []nspi.PropertyTag, opts *Options, out *writer, delimiter string) error {
	rowSet, err := client.ResolveNamesW(names, propTags)
	if err != nil {
		return err
	}

	if rowSet != nil {
		for i := range rowSet.Rows {
			printPropertyRowOrdered(&rowSet.Rows[i], opts, out)
			out.Println(delimiter)
		}
	}
	return nil
}

func runDNTLookup(client *nspi.Client, opts *Options) error {
	if opts.StartDNT == 0 {
		opts.StartDNT = 500000
	}
	if opts.StopDNT == 0 {
		opts.StopDNT = opts.StartDNT + 10000
	}
	if opts.RowsPerReq == 0 {
		opts.RowsPerReq = 350
	}

	// Determine property tags
	lookupType := strings.ToUpper(opts.LookupType)
	if lookupType == "" {
		lookupType = "EXTENDED"
	}

	var propTags []nspi.PropertyTag
	switch lookupType {
	case "EXTENDED":
		propTags = getExtendedProps()
	case "GUIDS":
		propTags = []nspi.PropertyTag{nspi.PropertyTag(mapi.PR_EMS_AB_OBJECT_GUID)}
	case "FULL":
		props, err := client.QueryColumns()
		if err != nil {
			return err
		}
		propTags = props
	default:
		propTags = getExtendedProps()
	}

	// Need a valid container ID for explicit table queries
	if err := client.LoadHTableContainerID(); err != nil {
		return err
	}

	// Open output writer
	out, err := newWriter(opts.OutputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	delimiter := "======================="

	fmt.Printf("[*] Looking up DNTs from %d to %d...\n", opts.StartDNT, opts.StopDNT)

	step := opts.RowsPerReq
	rstep := 1
	if opts.StopDNT < opts.StartDNT {
		step = -step
		rstep = -1
	}

	stopDNT := opts.StopDNT + rstep
	dnt1 := opts.StartDNT
	dnt2 := opts.StartDNT + step

	for {
		if step > 0 && dnt2 > stopDNT {
			dnt2 = stopDNT
		} else if step < 0 && dnt2 < stopDNT {
			dnt2 = stopDNT
		}

		out.Printf("# MIds %d-%d:\n", dnt1, dnt2-rstep)

		// Build explicit table as range of MIds
		var eTable []uint32
		if step > 0 {
			for i := dnt1; i < dnt2; i += rstep {
				eTable = append(eTable, uint32(i))
			}
		} else {
			for i := dnt1; i > dnt2; i += rstep {
				eTable = append(eTable, uint32(i))
			}
		}

		if len(eTable) > 0 {
			// First check if range has entries (optimization)
			checkProps := []nspi.PropertyTag{nspi.PropertyTag(mapi.PR_EMS_AB_OBJECT_GUID)}
			checkSet, err := client.QueryRowsExplicit(client.AnyExistingContainerID, uint32(len(eTable)), checkProps, eTable)
			if err != nil {
				out.Printf("[!] Error: %v\n", err)
			} else if checkSet != nil && hasValidRows(checkSet) {
				// Range has entries, fetch full data
				rowSet, err := client.QueryRowsExplicit(client.AnyExistingContainerID, uint32(len(eTable)), propTags, eTable)
				if err != nil {
					out.Printf("[!] Error: %v\n", err)
				} else if rowSet != nil {
					for i := range rowSet.Rows {
						printPropertyRowOrdered(&rowSet.Rows[i], opts, out)
						out.Println(delimiter)
					}
				}
			}
		}

		if dnt2 == stopDNT {
			break
		}

		dnt1 += step
		dnt2 += step
	}

	return nil
}

// hasValidRows checks if a PropertyRowSet has any non-error rows
func hasValidRows(rowSet *nspi.PropertyRowSet) bool {
	for _, row := range rowSet.Rows {
		for _, pv := range row.Values {
			// If property type is not error (0x000A), row is valid
			if pv.Tag.Type() != 0x000A {
				return true
			}
		}
	}
	return false
}

func printPropertyRow(props map[nspi.PropertyTag]interface{}, opts *Options, out *writer) {
	// This version uses the map; prefer printPropertyRowOrdered for correct order
	for tag, value := range props {
		printOneProperty(tag, value, opts, out)
	}
}

func printPropertyRowOrdered(row *nspi.PropertyRow, opts *Options, out *writer) {
	for _, pv := range row.Values {
		printOneProperty(pv.Tag, pv.Value, opts, out)
	}
}

func printOneProperty(tag nspi.PropertyTag, value interface{}, opts *Options, out *writer) {
	propType := tag.Type()

	// Skip errors
	if propType == 0x000A {
		return
	}

	// Skip embedded tables
	if propType == 0x000D {
		return
	}

	// Get property name
	propName := mapi.GetPropertyName(uint32(tag))
	if propName == "" {
		propName = fmt.Sprintf("0x%.8x", uint32(tag))
	}

	if opts.ExtendedOutput {
		propName = fmt.Sprintf("%s, 0x%.8x", propName, uint32(tag))
	}

	// Format value
	valueStr := formatValue(tag, value, opts)

	out.Printf("%s: %s\n", propName, valueStr)
}

func formatValue(tag nspi.PropertyTag, value interface{}, opts *Options) string {
	propID := tag.ID()

	switch v := value.(type) {
	case nspi.BinaryObject:
		if v == nil {
			return ""
		}
		// Special handling for well-known binary properties
		switch propID {
		case 0x8c6d: // objectGUID
			if len(v) == 16 {
				return nspi.FormatGUID([]byte(v))
			}
		case 0x8c73: // msExchMailboxGuid
			if len(v) == 16 {
				return nspi.FormatGUID([]byte(v))
			}
		case 0x8027: // objectSid
			return nspi.FormatSID([]byte(v))
		case 0x8c75: // msExchMasterAccountSid
			if len(v) > 0 {
				return nspi.FormatSID([]byte(v))
			}
		case 0x0fff, 0x0ff9, 0x3902: // PR_ENTRYID, PR_RECORD_KEY, PR_TEMPLATEID - decode as PermanentEntryID DN
			dn := extractDNFromEntryID([]byte(v))
			if dn != "" {
				return dn
			}
		case 0x0ff6: // PR_INSTANCE_KEY - decode as signed int32
			if len(v) >= 4 {
				return fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32([]byte(v))))
			}
		case 0x0ff8, 0x68c4: // PR_MAPPING_SIGNATURE, ExchangeObjectId - GUID format
			if len(v) == 16 {
				return nspi.FormatGUID([]byte(v))
			}
		case 0x300b: // PR_SEARCH_KEY - ASCII string
			s := strings.TrimRight(string(v), "\x00")
			if isPrintableASCII(s) {
				return s
			}
		}
		return encodeBinary([]byte(v), opts.OutputType)
	case []byte:
		return encodeBinary(v, opts.OutputType)
	case string:
		return v
	case []string:
		// Format as Python-style list to match Impacket
		quoted := make([]string, len(v))
		for i, s := range v {
			// Check if string has non-ASCII bytes that aren't valid UTF-8
			// Valid UTF-8 non-ASCII (like §) displays normally; invalid bytes use Python bytes repr
			if hasNonASCII(s) && !utf8.ValidString(s) {
				quoted[i] = formatPythonBytes(s)
			} else {
				quoted[i] = fmt.Sprintf("'%s'", s)
			}
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	case int32:
		return fmt.Sprintf("%d", v)
	case int16:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case uint64:
		// Check if this is a FILETIME property
		propType := tag.Type()
		if propType == nspi.PtypTime {
			return nspi.FormatFileTime(v)
		}
		return fmt.Sprintf("%d", v)
	case bool:
		// Impacket displays booleans as 1/0
		if v {
			return "1"
		}
		return "0"
	case []nspi.BinaryObject:
		var parts []string
		for _, b := range v {
			parts = append(parts, encodeBinary([]byte(b), opts.OutputType))
		}
		return strings.Join(parts, ", ")
	case []int32:
		var parts []string
		for _, n := range v {
			parts = append(parts, fmt.Sprintf("%d", n))
		}
		return strings.Join(parts, ", ")
	case []uint64:
		var parts []string
		for _, t := range v {
			parts = append(parts, nspi.FormatFileTime(t))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func getMinimalProps() []nspi.PropertyTag {
	return []nspi.PropertyTag{
		nspi.PropertyTag(0x3a00001F), // mailNickname
		nspi.PropertyTag(0x39fe001F), // mail
		nspi.PropertyTag(0x80270102), // objectSID
		nspi.PropertyTag(0x30070040), // whenCreated
		nspi.PropertyTag(0x30080040), // whenChanged
		nspi.PropertyTag(0x8c6d0102), // objectGUID
	}
}

func getExtendedProps() []nspi.PropertyTag {
	return append(getMinimalProps(), []nspi.PropertyTag{
		// Names
		nspi.PropertyTag(0x3a0f001f), // cn
		nspi.PropertyTag(0x8202001f), // name
		nspi.PropertyTag(0x0fff0102), // PR_ENTRYID
		nspi.PropertyTag(0x3001001f), // PR_DISPLAY_NAME
		nspi.PropertyTag(0x3a20001f), // PR_TRANSMITABLE_DISPLAY_NAME
		nspi.PropertyTag(0x39ff001f), // displayNamePrintable
		nspi.PropertyTag(0x800f101f), // proxyAddresses
		nspi.PropertyTag(0x8171001f), // lDAPDisplayName
		nspi.PropertyTag(0x8102101f), // ou
		nspi.PropertyTag(0x804b001f), // adminDisplayName
		// Text Properties
		nspi.PropertyTag(0x806f101f), // description
		nspi.PropertyTag(0x3004001f), // info
		nspi.PropertyTag(0x8069001f), // c
		nspi.PropertyTag(0x3a26001f), // co
		nspi.PropertyTag(0x3a2a001f), // postalCode
		nspi.PropertyTag(0x3a28001f), // st
		nspi.PropertyTag(0x3a29001f), // streetAddress
		nspi.PropertyTag(0x3a09001f), // homePhone
		nspi.PropertyTag(0x3a1c001f), // mobile
		nspi.PropertyTag(0x3a1b101f), // otherTelephone
		nspi.PropertyTag(0x3a16001f), // company
		nspi.PropertyTag(0x3a18001f), // department
		nspi.PropertyTag(0x3a17001f), // title
		nspi.PropertyTag(0x3a11001f), // sn
		nspi.PropertyTag(0x3a0a001f), // initials
		nspi.PropertyTag(0x3a06001f), // givenName
		// Attributes of Types
		nspi.PropertyTag(0x0ffe0003), // PR_OBJECT_TYPE
		nspi.PropertyTag(0x39000003), // PR_DISPLAY_TYPE
		nspi.PropertyTag(0x80bd0003), // instanceType
		// Exchange Extension Attributes
		nspi.PropertyTag(0x802d001f), // extensionAttribute1
		nspi.PropertyTag(0x802e001f), // extensionAttribute2
		nspi.PropertyTag(0x802f001f), // extensionAttribute3
		nspi.PropertyTag(0x8030001f), // extensionAttribute4
		nspi.PropertyTag(0x8031001f), // extensionAttribute5
		nspi.PropertyTag(0x8032001f), // extensionAttribute6
		nspi.PropertyTag(0x8033001f), // extensionAttribute7
		nspi.PropertyTag(0x8034001f), // extensionAttribute8
		nspi.PropertyTag(0x8035001f), // extensionAttribute9
		nspi.PropertyTag(0x8036001f), // extensionAttribute10
		nspi.PropertyTag(0x8c57001f), // extensionAttribute11
		nspi.PropertyTag(0x8c58001f), // extensionAttribute12
		nspi.PropertyTag(0x8c59001f), // extensionAttribute13
		nspi.PropertyTag(0x8c60001f), // extensionAttribute14
		nspi.PropertyTag(0x8c61001f), // extensionAttribute15
		// Configuration
		nspi.PropertyTag(0x81b6101e), // protocolSettings
		nspi.PropertyTag(0x8c9f001e), // msExchUserCulture
		nspi.PropertyTag(0x8c730102), // msExchMailboxGuid
		nspi.PropertyTag(0x8c96101e), // msExchResourceAddressLists
		nspi.PropertyTag(0x8c750102), // msExchMasterAccountSid
		nspi.PropertyTag(0x8cb5000b), // msExchEnableModeration
		nspi.PropertyTag(0x8cb30003), // msExchGroupJoinRestriction
		nspi.PropertyTag(0x8ce20003), // msExchGroupMemberCount
		// Useful when looking up DNTs
		nspi.PropertyTag(0x813b101e), // subRefs
		nspi.PropertyTag(0x8170101e), // networkAddress
		nspi.PropertyTag(0x8011001e), // targetAddress
		nspi.PropertyTag(0x8175101e), // url
		// Useful for distinguishing accounts
		nspi.PropertyTag(0x8c6a1102), // userCertificate
		// Assigned MId
		nspi.PropertyTag(0x0ff60102), // PR_INSTANCE_KEY
	}...)
}

func encodeBinary(data []byte, outputType string) string {
	if outputType == "base64" {
		return base64.StdEncoding.EncodeToString(data)
	}
	return "0x" + hex.EncodeToString(data)
}

func parseGUID(s string) ([]byte, error) {
	// Remove dashes
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return nil, fmt.Errorf("invalid GUID length")
	}
	return hex.DecodeString(s)
}

// hasNonASCII checks if a string has any non-ASCII bytes
func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e {
			return true
		}
	}
	return false
}

// formatPythonBytes formats a string as Python bytes repr: b'...\xNN...'
func formatPythonBytes(s string) string {
	var buf strings.Builder
	buf.WriteString("b'")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			buf.WriteByte(c)
		} else {
			fmt.Fprintf(&buf, "\\x%02x", c)
		}
	}
	buf.WriteByte('\'')
	return buf.String()
}

// isPrintableASCII checks if a string contains only printable ASCII characters
func isPrintableASCII(s string) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(s) > 0
}

// extractDNFromEntryID extracts the Distinguished Name from a PermanentEntryID.
// Format: flags(4) + providerUID(16) + version(4) + displayType(4) + DN(null-terminated ASCII string)
// Only permanent entry IDs (flags[0] == 0x00) have a DN field.
func extractDNFromEntryID(data []byte) string {
	if len(data) < 29 { // 4+16+4+4+1 minimum
		return ""
	}
	// Check if this is a permanent entry ID (flags byte 0 should be 0x00)
	// Ephemeral entry IDs (0x87 etc.) don't contain DNs
	if data[0] != 0x00 {
		return ""
	}
	dn := string(data[28:])
	dn = strings.TrimRight(dn, "\x00")
	// Sanity check: DN should start with "/" for NSPI format
	if len(dn) > 0 && dn[0] == '/' {
		return dn
	}
	return ""
}

func intToDword(n int32) uint32 {
	if n >= 0 {
		return uint32(n)
	}
	return uint32(int64(n) + (1 << 32))
}

// Dummy flag package usage to avoid errors
var _ = flag.NewFlagSet("dummy", flag.ExitOnError)
