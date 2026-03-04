package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/svcctl"
	"gopacket/pkg/dcerpc/winreg"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

func main() {
	// Custom flag parsing: standard flags, target, command, command flags
	var stdArgs []string
	var target, command string
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
				command = strings.ToLower(arg)
			}
		}
	}

	if target == "" || command == "" {
		printUsage()
		os.Exit(1)
	}

	// Parse subcommand flags
	subFlags := flag.NewFlagSet("reg "+command, flag.ExitOnError)
	keyName := subFlags.String("keyName", "", "Target registry key (e.g. HKLM\\SOFTWARE\\Microsoft)")
	valueName := subFlags.String("v", "", "Registry value name")
	valueDefault := subFlags.Bool("ve", false, "Query/delete the default (empty) value")
	recursive := subFlags.Bool("s", false, "Recurse subkeys")
	valueType := subFlags.String("vt", "REG_SZ", "Value type (REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD)")
	valueData := subFlags.String("vd", "", "Value data")
	deleteAll := subFlags.Bool("va", false, "Delete all values under the key")
	outputPath := subFlags.String("o", "", "Output UNC path for save/backup (e.g. \\\\host\\share\\file)")
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

	fmt.Println("gopacket v0.1.0 - reg")
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

	// Ensure RemoteRegistry service is running via SVCCTL
	serviceStarted := ensureRemoteRegistry(smbClient)

	// Open winreg pipe
	winregPipe, err := smbClient.OpenPipe("winreg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open winreg pipe: %v\n", err)
		os.Exit(1)
	}

	rpcClient := dcerpc.NewClient(winregPipe)
	if err := rpcClient.Bind(winreg.UUID, winreg.MajorVersion, winreg.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] winreg bind failed: %v\n", err)
		os.Exit(1)
	}

	// Execute command
	switch command {
	case "query":
		if *keyName == "" {
			fmt.Fprintf(os.Stderr, "[-] -keyName is required for query\n")
			os.Exit(1)
		}
		cmdQuery(rpcClient, *keyName, *valueName, *valueDefault, *recursive)

	case "add":
		if *keyName == "" {
			fmt.Fprintf(os.Stderr, "[-] -keyName is required for add\n")
			os.Exit(1)
		}
		cmdAdd(rpcClient, *keyName, *valueName, *valueType, *valueData)

	case "delete":
		if *keyName == "" {
			fmt.Fprintf(os.Stderr, "[-] -keyName is required for delete\n")
			os.Exit(1)
		}
		cmdDelete(rpcClient, *keyName, *valueName, *valueDefault, *deleteAll)

	case "save":
		if *keyName == "" || *outputPath == "" {
			fmt.Fprintf(os.Stderr, "[-] -keyName and -o are required for save\n")
			os.Exit(1)
		}
		cmdSave(rpcClient, *keyName, *outputPath)

	case "backup":
		if *outputPath == "" {
			fmt.Fprintf(os.Stderr, "[-] -o is required for backup\n")
			os.Exit(1)
		}
		cmdBackup(rpcClient, *outputPath)

	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	// Cleanup: stop RemoteRegistry if we started it
	if serviceStarted {
		stopRemoteRegistry(smbClient)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "gopacket v0.1.0 - reg")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage: reg [auth-flags] target <command> [command-flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Target:")
	fmt.Fprintln(os.Stderr, "  [[domain/]username[:password]@]<targetName or address>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  query    Query registry key/values")
	fmt.Fprintln(os.Stderr, "  add      Add registry key/value")
	fmt.Fprintln(os.Stderr, "  delete   Delete registry key/value")
	fmt.Fprintln(os.Stderr, "  save     Save registry key to file")
	fmt.Fprintln(os.Stderr, "  backup   Backup SAM, SYSTEM, SECURITY hives")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Command flags:")
	fmt.Fprintln(os.Stderr, "  -keyName KEY    Target registry key (e.g. HKLM\\SOFTWARE\\Microsoft)")
	fmt.Fprintln(os.Stderr, "  -v NAME         Registry value name")
	fmt.Fprintln(os.Stderr, "  -ve             Query/delete the default (empty) value")
	fmt.Fprintln(os.Stderr, "  -s              Recurse subkeys (query)")
	fmt.Fprintln(os.Stderr, "  -vt TYPE        Value type for add (REG_SZ, REG_DWORD, etc.)")
	fmt.Fprintln(os.Stderr, "  -vd DATA        Value data for add")
	fmt.Fprintln(os.Stderr, "  -va             Delete all values under the key")
	fmt.Fprintln(os.Stderr, "  -o PATH         Output UNC path for save/backup")
}

// isFlagWithValue returns true if the flag requires a value argument.
func isFlagWithValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	if idx := strings.Index(name, "="); idx >= 0 {
		return false
	}
	boolFlags := map[string]bool{
		"no-pass": true, "k": true, "ts": true, "debug": true,
		"ve": true, "s": true, "va": true,
	}
	return !boolFlags[name]
}

// parseKeyName splits "HKLM\path\to\key" into root key prefix and subkey path
func parseKeyName(keyName string) (string, string) {
	parts := strings.SplitN(keyName, `\`, 2)
	root := strings.ToUpper(parts[0])
	subKey := ""
	if len(parts) > 1 {
		subKey = parts[1]
	}
	return root, subKey
}

// openRootKey opens the appropriate root key handle
func openRootKey(client *dcerpc.Client, rootName string, samDesired uint32) ([]byte, error) {
	switch rootName {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return winreg.OpenLocalMachine(client, samDesired)
	case "HKU", "HKEY_USERS":
		return winreg.OpenUsers(client, samDesired)
	case "HKCR", "HKEY_CLASSES_ROOT":
		return winreg.OpenClassesRoot(client, samDesired)
	case "HKCU", "HKEY_CURRENT_USER":
		return winreg.OpenCurrentUser(client, samDesired)
	default:
		return nil, fmt.Errorf("unsupported root key: %s (use HKLM, HKU, HKCR, or HKCU)", rootName)
	}
}

// cmdQuery implements the "query" subcommand
func cmdQuery(client *dcerpc.Client, keyName, valueName string, valueDefault, recursive bool) {
	rootName, subKey := parseKeyName(keyName)

	rootHandle, err := openRootKey(client, rootName, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open root key: %v\n", err)
		os.Exit(1)
	}
	defer winreg.BaseRegCloseKey(client, rootHandle)

	if valueName != "" {
		// Query specific value
		querySpecificValue(client, rootHandle, subKey, keyName, valueName)
	} else if valueDefault {
		// Query default value
		querySpecificValue(client, rootHandle, subKey, keyName, "")
	} else {
		// Query all subkeys and values
		queryKey(client, rootHandle, subKey, keyName, recursive)
	}
}

func querySpecificValue(client *dcerpc.Client, rootHandle []byte, subKey, fullKeyName, valueName string) {
	var keyHandle []byte
	var err error
	if subKey != "" {
		keyHandle, err = winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.KEY_READ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", fullKeyName, err)
			os.Exit(1)
		}
		defer winreg.BaseRegCloseKey(client, keyHandle)
	} else {
		keyHandle = rootHandle
	}

	valType, data, err := winreg.BaseRegQueryValue(client, keyHandle, valueName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to query value '%s': %v\n", valueName, err)
		os.Exit(1)
	}

	fmt.Println(fullKeyName)
	displayName := valueName
	if displayName == "" {
		displayName = "(Default)"
	}
	printValue(displayName, valType, data)
}

func queryKey(client *dcerpc.Client, rootHandle []byte, subKey, fullKeyName string, recursive bool) {
	var keyHandle []byte
	var err error
	if subKey != "" {
		keyHandle, err = winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.KEY_READ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", fullKeyName, err)
			os.Exit(1)
		}
		defer winreg.BaseRegCloseKey(client, keyHandle)
	} else {
		keyHandle = rootHandle
	}

	info, err := winreg.BaseRegQueryInfoKey(client, keyHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to query key info: %v\n", err)
		os.Exit(1)
	}

	if !recursive {
		// Non-recursive: print key header, values, then subkey paths
		fmt.Println(fullKeyName)

		// Debug: show key info
		if build.Debug {
			fmt.Fprintf(os.Stderr, "[D] QueryInfoKey: SubKeys=%d, Values=%d, MaxNameLen=%d, MaxDataLen=%d\n",
				info.SubKeys, info.Values, info.MaxValueNameLen, info.MaxValueDataLen)
		}

		for i := uint32(0); i < info.Values; i++ {
			name, valType, data, err := winreg.BaseRegEnumValue(client, keyHandle, i, info.MaxValueNameLen+1, info.MaxValueDataLen)
			if err != nil {
				if build.Debug {
					fmt.Fprintf(os.Stderr, "[D] BaseRegEnumValue(%d) error: %v\n", i, err)
				}
				break
			}
			displayName := name
			if displayName == "" {
				displayName = "(Default)"
			}
			printValue(displayName, valType, data)
		}

		for i := uint32(0); i < info.SubKeys; i++ {
			name, _, err := winreg.BaseRegEnumKey(client, keyHandle, i)
			if err != nil {
				break
			}
			childFullKey := fullKeyName + `\` + name
			fmt.Println(childFullKey)
		}
	} else {
		// Recursive: enumerate subkeys, for each print path\, values, then recurse
		var subKeyNames []string
		for i := uint32(0); i < info.SubKeys; i++ {
			name, _, err := winreg.BaseRegEnumKey(client, keyHandle, i)
			if err != nil {
				break
			}
			subKeyNames = append(subKeyNames, name)
		}

		for _, skName := range subKeyNames {
			childSubKey := subKey
			if childSubKey != "" {
				childSubKey += `\` + skName
			} else {
				childSubKey = skName
			}
			childFullKey := fullKeyName + `\` + skName

			// Print subkey path with trailing backslash (Impacket format: relative to root)
			fmt.Println(childSubKey + `\`)

			// Open subkey and print its values
			childHandle, err := winreg.BaseRegOpenKey(client, rootHandle, childSubKey, 0, winreg.KEY_READ)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", childFullKey, err)
				continue
			}

			childInfo, err := winreg.BaseRegQueryInfoKey(client, childHandle)
			if err != nil {
				winreg.BaseRegCloseKey(client, childHandle)
				continue
			}

			for i := uint32(0); i < childInfo.Values; i++ {
				name, valType, data, err := winreg.BaseRegEnumValue(client, childHandle, i, childInfo.MaxValueNameLen+1, childInfo.MaxValueDataLen)
				if err != nil {
					break
				}
				displayName := name
				if displayName == "" {
					displayName = "(Default)"
				}
				printValue(displayName, valType, data)
			}

			winreg.BaseRegCloseKey(client, childHandle)

			// Recurse into this subkey
			queryKeyRecurse(client, rootHandle, childSubKey, childFullKey)
		}
	}
}

// queryKeyRecurse handles recursive enumeration of subkeys (called by queryKey in recursive mode)
func queryKeyRecurse(client *dcerpc.Client, rootHandle []byte, subKey, fullKeyName string) {
	keyHandle, err := winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.KEY_READ)
	if err != nil {
		return
	}
	defer winreg.BaseRegCloseKey(client, keyHandle)

	info, err := winreg.BaseRegQueryInfoKey(client, keyHandle)
	if err != nil {
		return
	}

	var subKeyNames []string
	for i := uint32(0); i < info.SubKeys; i++ {
		name, _, err := winreg.BaseRegEnumKey(client, keyHandle, i)
		if err != nil {
			break
		}
		subKeyNames = append(subKeyNames, name)
	}

	for _, skName := range subKeyNames {
		childSubKey := subKey + `\` + skName
		childFullKey := fullKeyName + `\` + skName

		// Print subkey path with trailing backslash
		fmt.Println(childSubKey + `\`)

		// Open and print values
		childHandle, err := winreg.BaseRegOpenKey(client, rootHandle, childSubKey, 0, winreg.KEY_READ)
		if err != nil {
			continue
		}

		childInfo, err := winreg.BaseRegQueryInfoKey(client, childHandle)
		if err != nil {
			winreg.BaseRegCloseKey(client, childHandle)
			continue
		}

		for i := uint32(0); i < childInfo.Values; i++ {
			name, valType, data, err := winreg.BaseRegEnumValue(client, childHandle, i, childInfo.MaxValueNameLen+1, childInfo.MaxValueDataLen)
			if err != nil {
				break
			}
			displayName := name
			if displayName == "" {
				displayName = "(Default)"
			}
			printValue(displayName, valType, data)
		}

		winreg.BaseRegCloseKey(client, childHandle)

		// Recurse
		queryKeyRecurse(client, rootHandle, childSubKey, childFullKey)
	}
}

// printValue displays a registry value in Impacket-compatible format
// Impacket uses: \tValueName\tREG_TYPE\t value
func printValue(name string, valType uint32, data []byte) {
	typeName := valueTypeName(valType)

	switch valType {
	case winreg.REG_SZ, winreg.REG_EXPAND_SZ:
		str := utf16LEToString(data)
		fmt.Printf("\t%s\t%s\t %s\n", name, typeName, str)

	case winreg.REG_DWORD:
		val := uint32(0)
		if len(data) >= 4 {
			val = binary.LittleEndian.Uint32(data[:4])
		}
		fmt.Printf("\t%s\t%s\t 0x%x\n", name, typeName, val)

	case winreg.REG_DWORD_BIG_ENDIAN:
		val := uint32(0)
		if len(data) >= 4 {
			val = binary.BigEndian.Uint32(data[:4])
		}
		fmt.Printf("\t%s\t%s\t 0x%x\n", name, typeName, val)

	case winreg.REG_QWORD:
		val := uint64(0)
		if len(data) >= 8 {
			val = binary.LittleEndian.Uint64(data[:8])
		}
		fmt.Printf("\t%s\t%s\t 0x%x\n", name, typeName, val)

	case winreg.REG_BINARY:
		fmt.Printf("\t%s\t%s\t \n", name, typeName)
		printHexDump(data)

	case winreg.REG_MULTI_SZ:
		strs := utf16LEToMultiString(data)
		fmt.Printf("\t%s\t%s\t %s\n", name, typeName, strings.Join(strs, "\n\t\t\t "))

	default:
		if len(data) > 0 {
			fmt.Printf("\t%s\t%s\t \n", name, typeName)
			printHexDump(data)
		} else {
			fmt.Printf("\t%s\t%s\t \n", name, typeName)
		}
	}
}

func valueTypeName(t uint32) string {
	switch t {
	case winreg.REG_NONE:
		return "REG_NONE"
	case winreg.REG_SZ:
		return "REG_SZ"
	case winreg.REG_EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case winreg.REG_BINARY:
		return "REG_BINARY"
	case winreg.REG_DWORD:
		return "REG_DWORD"
	case winreg.REG_DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case winreg.REG_LINK:
		return "REG_LINK"
	case winreg.REG_MULTI_SZ:
		return "REG_MULTI_SZ"
	case winreg.REG_RESOURCE_LIST:
		return "REG_RESOURCE_LIST"
	case winreg.REG_FULL_RESOURCE_DESCRIPTOR:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case winreg.REG_RESOURCE_REQUIREMENTS_LIST:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case winreg.REG_QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_TYPE(%d)", t)
	}
}

func utf16LEToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Trim null terminators
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

func utf16LEToMultiString(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Split on null terminators, double null = end
	var result []string
	var current []uint16
	for _, c := range u16s {
		if c == 0 {
			if len(current) > 0 {
				result = append(result, string(utf16.Decode(current)))
				current = nil
			} else {
				break // double null
			}
		} else {
			current = append(current, c)
		}
	}
	if len(current) > 0 {
		result = append(result, string(utf16.Decode(current)))
	}
	return result
}

// printHexDump prints data in Impacket's hex dump format with offset and ASCII
func printHexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Hex part: two groups of 8 bytes separated by extra space
		hexPart := ""
		for j, b := range chunk {
			if j == 8 {
				hexPart += " "
			}
			hexPart += fmt.Sprintf("%02X ", b)
		}

		// ASCII part
		asciiPart := ""
		for _, b := range chunk {
			if b >= 0x20 && b <= 0x7e {
				asciiPart += string(b)
			} else {
				asciiPart += "."
			}
		}

		fmt.Printf(" \t%04x   %-49s  %s\n", i, hexPart, asciiPart)
	}
}

// cmdAdd implements the "add" subcommand
func cmdAdd(client *dcerpc.Client, keyName, valueName, valueTypeStr, valueData string) {
	rootName, subKey := parseKeyName(keyName)

	rootHandle, err := openRootKey(client, rootName, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open root key: %v\n", err)
		os.Exit(1)
	}
	defer winreg.BaseRegCloseKey(client, rootHandle)

	// Create (or open existing) the key
	var keyHandle []byte
	if subKey != "" {
		keyHandle, err = winreg.BaseRegCreateKey(client, rootHandle, subKey, winreg.KEY_ALL_ACCESS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create key %s: %v\n", keyName, err)
			os.Exit(1)
		}
		defer winreg.BaseRegCloseKey(client, keyHandle)
	} else {
		keyHandle = rootHandle
	}

	if valueName == "" {
		// Just creating the key
		fmt.Printf("[+] Key %s created successfully.\n", keyName)
		return
	}

	// Set the value
	valType := parseValueType(valueTypeStr)
	data := encodeValueData(valType, valueData)

	if err := winreg.BaseRegSetValue(client, keyHandle, valueName, valType, data); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to set value '%s': %v\n", valueName, err)
		os.Exit(1)
	}

	fmt.Printf("[+] Value '%s' set successfully under %s.\n", valueName, keyName)
}

func parseValueType(s string) uint32 {
	switch strings.ToUpper(s) {
	case "REG_SZ":
		return winreg.REG_SZ
	case "REG_EXPAND_SZ":
		return winreg.REG_EXPAND_SZ
	case "REG_BINARY":
		return winreg.REG_BINARY
	case "REG_DWORD":
		return winreg.REG_DWORD
	case "REG_QWORD":
		return winreg.REG_QWORD
	case "REG_MULTI_SZ":
		return winreg.REG_MULTI_SZ
	case "REG_NONE":
		return winreg.REG_NONE
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown value type: %s\n", s)
		os.Exit(1)
		return 0
	}
}

func encodeValueData(valType uint32, data string) []byte {
	switch valType {
	case winreg.REG_SZ, winreg.REG_EXPAND_SZ:
		return stringToUTF16LE(data)

	case winreg.REG_DWORD:
		val, err := strconv.ParseUint(data, 0, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid DWORD value: %s\n", data)
			os.Exit(1)
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(val))
		return buf

	case winreg.REG_QWORD:
		val, err := strconv.ParseUint(data, 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid QWORD value: %s\n", data)
			os.Exit(1)
		}
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, val)
		return buf

	case winreg.REG_BINARY:
		// Expect hex string
		data = strings.ReplaceAll(data, " ", "")
		b := make([]byte, len(data)/2)
		for i := 0; i < len(b); i++ {
			val, err := strconv.ParseUint(data[i*2:i*2+2], 16, 8)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Invalid hex data at position %d: %v\n", i*2, err)
				os.Exit(1)
			}
			b[i] = byte(val)
		}
		return b

	case winreg.REG_MULTI_SZ:
		// Strings separated by \0
		parts := strings.Split(data, `\0`)
		var result []uint16
		for _, p := range parts {
			encoded := utf16.Encode([]rune(p))
			result = append(result, encoded...)
			result = append(result, 0) // null terminator
		}
		result = append(result, 0) // final double null
		buf := make([]byte, len(result)*2)
		for i, c := range result {
			binary.LittleEndian.PutUint16(buf[i*2:], c)
		}
		return buf

	default:
		return []byte(data)
	}
}

func stringToUTF16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	encoded = append(encoded, 0) // null terminator
	buf := make([]byte, len(encoded)*2)
	for i, c := range encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	return buf
}

// cmdDelete implements the "delete" subcommand
func cmdDelete(client *dcerpc.Client, keyName, valueName string, valueDefault, deleteAll bool) {
	rootName, subKey := parseKeyName(keyName)

	rootHandle, err := openRootKey(client, rootName, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open root key: %v\n", err)
		os.Exit(1)
	}
	defer winreg.BaseRegCloseKey(client, rootHandle)

	if valueName != "" {
		// Delete specific value
		var keyHandle []byte
		if subKey != "" {
			keyHandle, err = winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.KEY_ALL_ACCESS)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", keyName, err)
				os.Exit(1)
			}
			defer winreg.BaseRegCloseKey(client, keyHandle)
		} else {
			keyHandle = rootHandle
		}

		if err := winreg.BaseRegDeleteValue(client, keyHandle, valueName); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to delete value '%s': %v\n", valueName, err)
			os.Exit(1)
		}
		fmt.Printf("[+] Value '%s' deleted from %s.\n", valueName, keyName)

	} else if valueDefault {
		// Delete default value
		var keyHandle []byte
		if subKey != "" {
			keyHandle, err = winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.KEY_ALL_ACCESS)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", keyName, err)
				os.Exit(1)
			}
			defer winreg.BaseRegCloseKey(client, keyHandle)
		} else {
			keyHandle = rootHandle
		}

		if err := winreg.BaseRegDeleteValue(client, keyHandle, ""); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to delete default value: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Default value deleted from %s.\n", keyName)

	} else if deleteAll {
		// Delete all values under the key
		var keyHandle []byte
		if subKey != "" {
			keyHandle, err = winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.KEY_ALL_ACCESS)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", keyName, err)
				os.Exit(1)
			}
			defer winreg.BaseRegCloseKey(client, keyHandle)
		} else {
			keyHandle = rootHandle
		}

		info, err := winreg.BaseRegQueryInfoKey(client, keyHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to query key info: %v\n", err)
			os.Exit(1)
		}

		// Collect all value names first
		var valueNames []string
		for i := uint32(0); i < info.Values; i++ {
			name, _, _, err := winreg.BaseRegEnumValue(client, keyHandle, i, info.MaxValueNameLen+1, info.MaxValueDataLen)
			if err != nil {
				break
			}
			valueNames = append(valueNames, name)
		}

		for _, vn := range valueNames {
			if err := winreg.BaseRegDeleteValue(client, keyHandle, vn); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to delete value '%s': %v\n", vn, err)
			} else {
				displayName := vn
				if displayName == "" {
					displayName = "(Default)"
				}
				fmt.Printf("[+] Deleted value '%s'.\n", displayName)
			}
		}

	} else {
		// Delete the key itself
		if subKey == "" {
			fmt.Fprintf(os.Stderr, "[-] Cannot delete a root key\n")
			os.Exit(1)
		}

		if err := winreg.BaseRegDeleteKey(client, rootHandle, subKey); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to delete key %s: %v\n", keyName, err)
			os.Exit(1)
		}
		fmt.Printf("[+] Key %s deleted successfully.\n", keyName)
	}
}

// cmdSave implements the "save" subcommand
func cmdSave(client *dcerpc.Client, keyName, outputPath string) {
	rootName, subKey := parseKeyName(keyName)

	rootHandle, err := openRootKey(client, rootName, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open root key: %v\n", err)
		os.Exit(1)
	}
	defer winreg.BaseRegCloseKey(client, rootHandle)

	var keyHandle []byte
	if subKey != "" {
		keyHandle, err = winreg.BaseRegOpenKey(client, rootHandle, subKey, 0, winreg.MAXIMUM_ALLOWED)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open key %s: %v\n", keyName, err)
			os.Exit(1)
		}
		defer winreg.BaseRegCloseKey(client, keyHandle)
	} else {
		keyHandle = rootHandle
	}

	if err := winreg.BaseRegSaveKey(client, keyHandle, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to save key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Key %s saved to %s.\n", keyName, outputPath)
}

// cmdBackup implements the "backup" subcommand - saves SAM, SYSTEM, SECURITY hives
func cmdBackup(client *dcerpc.Client, outputPath string) {
	rootHandle, err := winreg.OpenLocalMachine(client, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open HKLM: %v\n", err)
		os.Exit(1)
	}
	defer winreg.BaseRegCloseKey(client, rootHandle)

	hives := []struct {
		name     string
		fileName string
	}{
		{"SAM", "SAM"},
		{"SYSTEM", "SYSTEM"},
		{"SECURITY", "SECURITY"},
	}

	// Ensure outputPath ends with separator
	basePath := strings.TrimRight(outputPath, `\`)

	for _, hive := range hives {
		keyHandle, err := winreg.BaseRegOpenKey(client, rootHandle, hive.name, 0, winreg.MAXIMUM_ALLOWED)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open HKLM\\%s: %v\n", hive.name, err)
			continue
		}

		savePath := basePath + `\` + hive.fileName
		err = winreg.BaseRegSaveKey(client, keyHandle, savePath)
		winreg.BaseRegCloseKey(client, keyHandle)

		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to save %s: %v\n", hive.name, err)
			continue
		}

		fmt.Printf("[+] HKLM\\%s saved to %s\n", hive.name, savePath)
	}
}

// ensureRemoteRegistry checks if the RemoteRegistry service is running and starts it if needed.
// Returns true if we started the service (and should stop it on cleanup).
func ensureRemoteRegistry(smbClient *smb.Client) bool {
	pipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: Could not open svcctl pipe to check RemoteRegistry: %v\n", err)
		return false
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: svcctl bind failed: %v\n", err)
		return false
	}

	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: Failed to open SCManager: %v\n", err)
		return false
	}
	defer sc.Close()

	serviceHandle, err := sc.OpenService("RemoteRegistry", svcctl.SERVICE_START|svcctl.SERVICE_STOP|svcctl.SERVICE_QUERY_STATUS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: Failed to open RemoteRegistry service: %v\n", err)
		return false
	}
	defer sc.CloseServiceHandle(serviceHandle)

	status, err := sc.QueryServiceStatus(serviceHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: Failed to query RemoteRegistry status: %v\n", err)
		return false
	}

	if status.CurrentState == svcctl.SERVICE_RUNNING {
		fmt.Println("[*] RemoteRegistry service is already running.")
		return false
	}

	fmt.Println("[*] Starting RemoteRegistry service...")
	if err := sc.StartService(serviceHandle); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: Failed to start RemoteRegistry: %v\n", err)
		return false
	}

	// Wait for service to start
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		status, err = sc.QueryServiceStatus(serviceHandle)
		if err == nil && status.CurrentState == svcctl.SERVICE_RUNNING {
			fmt.Println("[+] RemoteRegistry service started.")
			return true
		}
	}

	fmt.Println("[+] RemoteRegistry service start requested.")
	return true
}

// stopRemoteRegistry stops the RemoteRegistry service
func stopRemoteRegistry(smbClient *smb.Client) {
	pipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		return
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return
	}

	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		return
	}
	defer sc.Close()

	serviceHandle, err := sc.OpenService("RemoteRegistry", svcctl.SERVICE_STOP|svcctl.SERVICE_QUERY_STATUS)
	if err != nil {
		return
	}
	defer sc.CloseServiceHandle(serviceHandle)

	_, err = sc.StopService(serviceHandle)
	if err != nil {
		// Silently ignore expected errors like dependent services still running
		return
	}
	fmt.Println("[*] RemoteRegistry service stopped.")
}
