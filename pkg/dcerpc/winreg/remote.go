package winreg

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

// RemoteOps handles remote registry operations
type RemoteOps struct {
	smbClient *smb.Client
	rpcClient *dcerpc.Client
	pipe      io.Closer
	hklm      []byte // HKEY_LOCAL_MACHINE handle
	tempFiles []string
}

// NewRemoteOps creates a new remote operations handler
func NewRemoteOps(smbClient *smb.Client, creds *session.Credentials) (*RemoteOps, error) {
	// Open winreg pipe
	pipe, err := smbClient.OpenPipe("winreg")
	if err != nil {
		return nil, fmt.Errorf("failed to open winreg pipe: %v", err)
	}

	// Create DCE/RPC client
	rpcClient := dcerpc.NewClient(pipe)

	// Bind to winreg interface
	if err := rpcClient.Bind(UUID, MajorVersion, MinorVersion); err != nil {
		pipe.Close()
		return nil, fmt.Errorf("failed to bind winreg: %v", err)
	}

	if build.Debug {
		log.Printf("[D] RemoteOps: Bound to winreg interface")
	}

	return &RemoteOps{
		smbClient: smbClient,
		rpcClient: rpcClient,
		pipe:      pipe,
	}, nil
}

// GetBootKey retrieves the boot key directly via registry queries
// The boot key is scrambled across 4 keys in SYSTEM\CurrentControlSet\Control\Lsa
func (r *RemoteOps) GetBootKey() ([]byte, error) {
	// Open HKLM
	hklm, err := OpenLocalMachine(r.rpcClient, MAXIMUM_ALLOWED)
	if err != nil {
		return nil, fmt.Errorf("failed to open HKLM: %v", err)
	}
	r.hklm = hklm

	if build.Debug {
		log.Printf("[D] RemoteOps: Opened HKLM handle")
	}

	// Determine current control set
	controlSet, err := r.getCurrentControlSet()
	if err != nil {
		return nil, fmt.Errorf("failed to get current control set: %v", err)
	}

	if build.Debug {
		log.Printf("[D] RemoteOps: Using %s", controlSet)
	}

	// Boot key is derived from class names of these 4 keys
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}
	var bootKeyParts []byte

	for _, keyName := range keyNames {
		path := fmt.Sprintf("SYSTEM\\%s\\Control\\Lsa\\%s", controlSet, keyName)

		keyHandle, err := BaseRegOpenKey(r.rpcClient, hklm, path, 1, KEY_READ)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}

		keyInfo, err := BaseRegQueryInfoKey(r.rpcClient, keyHandle)
		BaseRegCloseKey(r.rpcClient, keyHandle)

		if err != nil {
			return nil, fmt.Errorf("failed to query info for %s: %v", path, err)
		}

		if build.Debug {
			log.Printf("[D] RemoteOps: %s class name: %s", keyName, keyInfo.ClassName)
		}

		bootKeyParts = append(bootKeyParts, []byte(keyInfo.ClassName)...)
	}

	// Descramble the boot key
	bootKey, err := descrambleBootKey(bootKeyParts)
	if err != nil {
		return nil, fmt.Errorf("failed to descramble boot key: %v", err)
	}

	return bootKey, nil
}

// getCurrentControlSet determines which ControlSet is currently in use
func (r *RemoteOps) getCurrentControlSet() (string, error) {
	// Open SYSTEM\Select key
	selectKey, err := BaseRegOpenKey(r.rpcClient, r.hklm, "SYSTEM\\Select", 1, KEY_READ)
	if err != nil {
		return "", err
	}
	defer BaseRegCloseKey(r.rpcClient, selectKey)

	// Read "Current" value
	_, data, err := BaseRegQueryValue(r.rpcClient, selectKey, "Current")
	if err != nil {
		return "", err
	}

	if len(data) < 4 {
		return "", fmt.Errorf("invalid Current value")
	}

	current := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	return fmt.Sprintf("ControlSet%03d", current), nil
}

// SaveHive saves a registry hive to a remote temp file
func (r *RemoteOps) SaveHive(hiveName string) (string, error) {
	if r.hklm == nil {
		hklm, err := OpenLocalMachine(r.rpcClient, MAXIMUM_ALLOWED)
		if err != nil {
			return "", fmt.Errorf("failed to open HKLM: %v", err)
		}
		r.hklm = hklm
	}

	// Open the hive key with MAXIMUM_ALLOWED access for backup operations
	hiveKey, err := BaseRegOpenKey(r.rpcClient, r.hklm, hiveName, 1, MAXIMUM_ALLOWED)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %v", hiveName, err)
	}
	defer BaseRegCloseKey(r.rpcClient, hiveKey)

	// Generate random filename
	fileName := randomFileName() + ".tmp"
	remotePath := "..\\Temp\\" + fileName // Relative to SYSTEM32

	if build.Debug {
		log.Printf("[D] RemoteOps: Saving %s to %s", hiveName, remotePath)
	}

	// Save the hive
	err = BaseRegSaveKey(r.rpcClient, hiveKey, remotePath)
	if err != nil {
		return "", fmt.Errorf("failed to save %s: %v", hiveName, err)
	}

	r.tempFiles = append(r.tempFiles, fileName)
	return fileName, nil
}

// DownloadHive downloads a saved hive file via SMB
func (r *RemoteOps) DownloadHive(fileName string) ([]byte, error) {
	// Mount ADMIN$ share
	if err := r.smbClient.UseShare("ADMIN$"); err != nil {
		return nil, fmt.Errorf("failed to mount ADMIN$: %v", err)
	}

	// Navigate to Temp directory
	if err := r.smbClient.Cd("Temp"); err != nil {
		return nil, fmt.Errorf("failed to cd to Temp: %v", err)
	}

	if build.Debug {
		log.Printf("[D] RemoteOps: Downloading %s from ADMIN$\\Temp", fileName)
	}

	// Read the file
	content, err := r.smbClient.Cat(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", fileName, err)
	}

	return []byte(content), nil
}

// Cleanup removes temporary hive files
func (r *RemoteOps) Cleanup() {
	if len(r.tempFiles) == 0 {
		return
	}

	// Mount ADMIN$ share
	if err := r.smbClient.UseShare("ADMIN$"); err != nil {
		if build.Debug {
			log.Printf("[D] RemoteOps: Cleanup failed to mount ADMIN$: %v", err)
		}
		return
	}

	// Navigate to Temp
	if err := r.smbClient.Cd("Temp"); err != nil {
		if build.Debug {
			log.Printf("[D] RemoteOps: Cleanup failed to cd to Temp: %v", err)
		}
		return
	}

	for _, fileName := range r.tempFiles {
		if err := r.smbClient.Rm(fileName); err != nil {
			if build.Debug {
				log.Printf("[D] RemoteOps: Failed to delete %s: %v", fileName, err)
			}
		} else if build.Debug {
			log.Printf("[D] RemoteOps: Deleted %s", fileName)
		}
	}

	r.tempFiles = nil
}

// Close releases resources
func (r *RemoteOps) Close() {
	r.Cleanup()
	if r.hklm != nil {
		BaseRegCloseKey(r.rpcClient, r.hklm)
		r.hklm = nil
	}
	if r.pipe != nil {
		r.pipe.Close()
		r.pipe = nil
	}
}

// Boot key permutation table
var bootKeyPermutation = []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

// descrambleBootKey descrambles the boot key from class name parts
func descrambleBootKey(scrambled []byte) ([]byte, error) {
	// Class names are hex encoded, concatenated = 32 hex chars = 16 bytes
	scrambledStr := strings.ToLower(string(scrambled))
	if len(scrambledStr) != 32 {
		return nil, fmt.Errorf("invalid boot key parts length: %d (expected 32)", len(scrambledStr))
	}

	decoded, err := hex.DecodeString(scrambledStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode boot key: %v", err)
	}

	if len(decoded) != 16 {
		return nil, fmt.Errorf("invalid decoded boot key length: %d", len(decoded))
	}

	// Apply permutation
	bootKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bootKey[i] = decoded[bootKeyPermutation[i]]
	}

	return bootKey, nil
}

// randomFileName generates a random 8-character filename
func randomFileName() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
