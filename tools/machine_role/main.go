package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

// MS-DSSP interface UUID: 3919286A-B10C-11D0-9BA8-00C04FD92EF5 v0.0
var dsspUUID = dcerpc.MustParseUUID("3919286A-B10C-11D0-9BA8-00C04FD92EF5")

var machineRoles = []string{
	"Standalone Workstation",
	"Domain-joined Workstation",
	"Standalone Server",
	"Domain-joined Server",
	"Backup Domain Controller",
	"Primary Domain Controller",
}

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

	if !opts.NoPass && !creds.UseKerberos {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
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

	// Open lsarpc pipe (DSSP binds on same pipe)
	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open lsarpc pipe: %v\n", err)
		os.Exit(1)
	}
	defer pipe.Close()

	// Create DCE-RPC client and bind to DSSP interface
	client := dcerpc.NewClient(pipe)
	if err := client.Bind(dsspUUID, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to bind to MS-DSSP: %v\n", err)
		os.Exit(1)
	}

	// DsRolerGetPrimaryDomainInformation - opnum 0, InfoLevel 1
	req := make([]byte, 4)
	binary.LittleEndian.PutUint16(req[0:2], 1) // InfoLevel = DsRolePrimaryDomainInfoBasic

	resp, err := client.Call(0, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] DsRolerGetPrimaryDomainInformation failed: %v\n", err)
		os.Exit(1)
	}

	// Parse NDR response for level 1 (DsRolePrimaryDomainInfoBasic)
	// Layout:
	//   [0:4]   Top-level pointer referent ID
	//   [4:8]   Union discriminant (info level = 1)
	//   [8:12]  MachineRole (uint16 padded to 4)
	//   [12:16] Flags (uint32)
	//   [16:20] DomainNameFlat pointer referent ID
	//   [20:24] DomainNameDns pointer referent ID
	//   [24:28] DomainForestName pointer referent ID
	//   [28:44] DomainGuid (16 bytes)
	//   [44:]   Deferred string data
	//   Last 4 bytes: ReturnValue

	if len(resp) < 48 {
		fmt.Fprintf(os.Stderr, "[-] Response too short (%d bytes)\n", len(resp))
		os.Exit(1)
	}

	machineRole := binary.LittleEndian.Uint16(resp[8:10])
	domainGuid := resp[28:44]

	// Parse deferred NDR strings starting at offset 44
	offset := 44
	domainNameFlat, offset, err := readNDRString(resp, offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to parse NetBIOS domain name: %v\n", err)
		os.Exit(1)
	}
	domainNameDns, offset, err := readNDRString(resp, offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to parse DNS domain name: %v\n", err)
		os.Exit(1)
	}
	domainForestName, offset, err := readNDRString(resp, offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to parse forest name: %v\n", err)
		os.Exit(1)
	}
	_ = offset

	// Check return value (last 4 bytes of response)
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		fmt.Fprintf(os.Stderr, "[-] Server returned error: 0x%08x\n", retVal)
		os.Exit(1)
	}

	// Display results
	roleStr := "Unknown"
	if int(machineRole) < len(machineRoles) {
		roleStr = machineRoles[machineRole]
	}

	guid := formatGUID(domainGuid)

	fmt.Printf("Machine Role: %s\n", roleStr)
	fmt.Printf("NetBIOS Domain Name: %s\n", domainNameFlat)
	fmt.Printf("Domain Name: %s\n", domainNameDns)
	fmt.Printf("Forest Name: %s\n", domainForestName)
	fmt.Printf("Domain GUID: %s\n", guid)
}

// readNDRString reads an NDR conformant/varying unicode string at the given
// offset. Returns the decoded string and the new offset past the string data.
// NDR string layout: MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE data
// (padded to 4-byte alignment).
func readNDRString(data []byte, off int) (string, int, error) {
	if off+12 > len(data) {
		return "", off, fmt.Errorf("not enough data for NDR string header at offset %d", off)
	}

	// maxCount := binary.LittleEndian.Uint32(data[off : off+4])
	off += 4
	// stringOffset := binary.LittleEndian.Uint32(data[off : off+4])
	off += 4
	actualCount := binary.LittleEndian.Uint32(data[off : off+4])
	off += 4

	byteLen := int(actualCount) * 2
	if off+byteLen > len(data) {
		return "", off, fmt.Errorf("not enough data for NDR string body at offset %d (need %d)", off, byteLen)
	}

	u16 := make([]uint16, actualCount)
	for i := 0; i < int(actualCount); i++ {
		u16[i] = binary.LittleEndian.Uint16(data[off+i*2 : off+i*2+2])
	}
	off += byteLen

	// Strip null terminator if present
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}

	// Align to 4 bytes
	if off%4 != 0 {
		off += 4 - (off % 4)
	}

	return string(utf16.Decode(u16)), off, nil
}

// formatGUID formats a 16-byte Windows GUID in standard dash notation.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	// GUID fields: Data1(4 LE) - Data2(2 LE) - Data3(2 LE) - Data4(8 BE)
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X", d1, d2, d3, b[8:10], b[10:16])
}
