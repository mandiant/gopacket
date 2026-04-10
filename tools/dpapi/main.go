// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/bkrp"
	"gopacket/pkg/dcerpc/drsuapi"
	"gopacket/pkg/dcerpc/lsarpc"
	"gopacket/pkg/dpapi"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	// Subcommand flags
	file        = flag.String("file", "", "File to parse/decrypt")
	sid         = flag.String("sid", "", "SID of the user")
	pvk         = flag.String("pvk", "", "Domain backup privatekey file (PVK format)")
	key         = flag.String("key", "", "Specific key to use for decryption (hex)")
	password    = flag.String("password", "", "User's password")
	system      = flag.String("system", "", "SYSTEM hive file")
	security    = flag.String("security", "", "SECURITY hive file")
	export      = flag.Bool("export", false, "Export keys to file")
	vcrd        = flag.String("vcrd", "", "Vault Credential file")
	vpol        = flag.String("vpol", "", "Vault Policy file")
	entropy     = flag.String("entropy", "", "Entropy string for unprotect")
	entropyFile = flag.String("entropy-file", "", "File with binary entropy")
	entry       = flag.Int("entry", -1, "Entry index in CREDHIST")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `dpapi - DPAPI secrets decryption tool

Usage: dpapi [options] <action> [action-options]

Actions:
  backupkeys     Retrieve domain backup keys from DC
  masterkey      Parse and decrypt master key files
  credential     Parse and decrypt credential files
  vault          Parse and decrypt vault files
  unprotect      Decrypt DPAPI-protected data
  credhist       Parse CREDHIST files

Examples:
  Retrieve domain backup keys:
    dpapi backupkeys -t domain/admin:password@DC

  Parse a master key file:
    dpapi masterkey -file masterkey_file

  Decrypt master key with password:
    dpapi masterkey -file masterkey_file -sid S-1-5-21-... -password 'Password123'

  Decrypt master key with domain backup key:
    dpapi masterkey -file masterkey_file -pvk domain_backup.pvk

  Parse a credential file:
    dpapi credential -file cred_file

  Decrypt credential with master key:
    dpapi credential -file cred_file -key 0xABCDEF...

Options:
`)
		flag.PrintDefaults()
	}
}

func main() {
	// Custom parsing to handle subcommands
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Find the action
	action := ""
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			// Check if it's a known action
			switch strings.ToLower(arg) {
			case "backupkeys", "masterkey", "credential", "vault", "unprotect", "credhist":
				action = strings.ToLower(arg)
			}
			break
		}
	}

	if action == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Remove the action from os.Args so flag.Parse() sees the target correctly
	// Find and remove the action from args
	newArgs := []string{os.Args[0]}
	actionFound := false
	for _, arg := range os.Args[1:] {
		if !actionFound && strings.ToLower(arg) == action {
			actionFound = true
			continue
		}
		newArgs = append(newArgs, arg)
	}
	os.Args = newArgs

	switch action {
	case "backupkeys":
		doBackupKeys()
	case "masterkey":
		doMasterKey()
	case "credential":
		doCredential()
	case "vault":
		doVault()
	case "unprotect":
		doUnprotect()
	case "credhist":
		doCredHist()
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}

func doBackupKeys() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		fmt.Fprintln(os.Stderr, "[-] Target required for backupkeys action")
		fmt.Fprintln(os.Stderr, "Usage: dpapi backupkeys domain/admin:password@DC")
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target: %v", err)
	}
	opts.ApplyToSession(&target, &creds)

	fmt.Printf("[*] Retrieving domain backup keys from %s\n", target.Host)

	// Connect via SMB
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		log.Fatalf("[-] SMB connection failed: %v", err)
	}
	defer smbClient.Close()

	// Get session key (needed for decrypting LSA secrets)
	// For SMB named pipe, we need to use the SMB session key
	smbSessionKey := smbClient.GetSessionKey()
	if len(smbSessionKey) == 0 {
		log.Fatal("[-] Failed to get session key")
	}
	if build.Debug {
		fmt.Printf("[D] SMB Session key: %x\n", smbSessionKey)
	}

	// Try LSARPC method first (gets private key)
	// Note: This method requires specific access rights and may not work on all DCs
	fmt.Println("[*] Attempting to retrieve private backup key via LSARPC...")

	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		log.Fatalf("[-] Failed to open lsarpc pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	// Use non-authenticated RPC bind - rely on SMB layer auth for LSARPC
	// This matches Impacket's default behavior for named pipe transport
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		log.Fatalf("[-] LSARPC bind failed: %v", err)
	}
	if build.Debug {
		fmt.Printf("[D] RPC Authenticated (non-auth bind): %v\n", rpcClient.Authenticated)
		if rpcClient.Auth != nil {
			fmt.Printf("[D] RPC NTLM SessionKey: %x\n", rpcClient.Auth.SessionKey)
		}
	}

	// Get the session key for LSA secret decryption
	// Per MS-LSAD, the session key for named pipe transport is the SMB session key
	// (NOT the RPC layer's NTLM session key)
	sessionKey := smbSessionKey
	if build.Debug {
		fmt.Printf("[D] Using SMB SessionKey for LSA decryption: %x\n", sessionKey)
	}

	lsaClient := lsarpc.NewClientFromRPC(rpcClient)
	if err := lsaClient.OpenPolicyForSecrets(); err != nil {
		fmt.Printf("[!] Failed to open policy for secrets: %v\n", err)
		fmt.Println("[*] Falling back to BKRP method (public key only)...")
		doBackupKeysBKRP(smbClient, &creds)
		return
	}
	defer lsaClient.Close()

	// Get the preferred backup key GUID, then retrieve the actual key
	fmt.Println("[*] Retrieving preferred backup key GUID...")
	for _, keyName := range []string{"G$BCKUPKEY_PREFERRED"} {
		encryptedGUID, err := lsaClient.RetrievePrivateData(keyName)
		if err != nil {
			fmt.Printf("[!] Failed to retrieve %s: %v\n", keyName, err)
			continue
		}

		if build.Debug {
			fmt.Printf("[D] Encrypted data (%d bytes): %x\n", len(encryptedGUID), encryptedGUID[:min(64, len(encryptedGUID))])
			fmt.Printf("[D] Session key (%d bytes): %x\n", len(sessionKey), sessionKey)
		}

		// Decrypt the GUID using session key
		guidData, err := drsuapi.DecryptLSASecret(sessionKey, encryptedGUID)
		if err != nil {
			fmt.Printf("[!] Failed to decrypt %s: %v\n", keyName, err)
			continue
		}

		if len(guidData) < 16 {
			fmt.Printf("[!] Decrypted GUID too short: %d bytes\n", len(guidData))
			continue
		}

		// Parse GUID and construct the key name
		guid := formatGUID(guidData[:16])
		fmt.Printf("[+] Found backup key GUID: %s\n", guid)

		// Now retrieve the actual backup key
		backupKeyName := fmt.Sprintf("G$BCKUPKEY_%s", guid)
		fmt.Printf("[*] Retrieving backup key: %s\n", backupKeyName)

		encryptedKey, err := lsaClient.RetrievePrivateData(backupKeyName)
		if err != nil {
			fmt.Printf("[!] Failed to retrieve backup key: %v\n", err)
			continue
		}

		// Decrypt the backup key
		keyData, err := drsuapi.DecryptLSASecret(sessionKey, encryptedKey)
		if err != nil {
			fmt.Printf("[!] Failed to decrypt backup key: %v\n", err)
			continue
		}

		fmt.Printf("[+] Retrieved backup key data (%d bytes)\n", len(keyData))

		// Parse the backup key
		bk, err := dpapi.ParseBackupKeyResponse(keyData)
		if err != nil {
			fmt.Printf("[!] Failed to parse backup key: %v\n", err)
			// Try as raw PRIVATEKEYBLOB
			fmt.Printf("[*] Trying to parse as raw key data...\n")
			bk, err = dpapi.ParsePrivateKeyData(keyData)
			if err != nil {
				fmt.Printf("[!] Failed to parse as private key: %v\n", err)
				if build.Debug {
					fmt.Printf("[D] First 32 bytes: %x\n", keyData[:min(32, len(keyData))])
				}
				continue
			}
		}

		bk.Dump()

		// Export if requested
		if *export && bk.PrivateKey != nil {
			pemData, err := bk.ToPEM()
			if err != nil {
				fmt.Printf("[!] Failed to convert to PEM: %v\n", err)
			} else {
				pemFile := "domain_backup_key.pem"
				if err := os.WriteFile(pemFile, pemData, 0600); err != nil {
					fmt.Printf("[!] Failed to write PEM file: %v\n", err)
				} else {
					fmt.Printf("[+] Exported backup key to %s\n", pemFile)
				}
			}

			if bk.PVKData != nil {
				pvkFile := "domain_backup_key.pvk"
				if err := os.WriteFile(pvkFile, bk.PVKData, 0600); err != nil {
					fmt.Printf("[!] Failed to write PVK file: %v\n", err)
				} else {
					fmt.Printf("[+] Exported backup key to %s\n", pvkFile)
				}
			}
		}

		return // Success
	}

	// Fallback to BKRP method
	fmt.Println("[*] Falling back to BKRP method (retrieves public key certificate)...")
	fmt.Println("[!] Note: For private key, use secretsdump to extract from registry")
	doBackupKeysBKRP(smbClient, &creds)
}

// doBackupKeysBKRP retrieves the backup key using BKRP (only gets public key)
func doBackupKeysBKRP(smbClient *smb.Client, creds *session.Credentials) {
	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		log.Fatalf("[-] Failed to open lsarpc pipe: %v", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.BindAuth(bkrp.UUID, bkrp.MajorVersion, bkrp.MinorVersion, creds); err != nil {
		log.Fatalf("[-] BKRP bind failed: %v", err)
	}

	bkrpClient := bkrp.NewClient(rpcClient)

	fmt.Println("[*] Requesting domain backup key via BKRP...")
	backupKeyData, err := bkrpClient.GetBackupKey()
	if err != nil {
		log.Fatalf("[-] Failed to get backup key: %v", err)
	}

	fmt.Printf("[+] Retrieved backup key (%d bytes)\n", len(backupKeyData))

	bk, err := dpapi.ParseBackupKeyResponse(backupKeyData)
	if err != nil {
		log.Fatalf("[-] Failed to parse backup key: %v", err)
	}

	bk.Dump()

	if *export && bk.PrivateKey != nil {
		pemData, err := bk.ToPEM()
		if err != nil {
			log.Fatalf("[-] Failed to convert to PEM: %v", err)
		}

		pemFile := "domain_backup_key.pem"
		if err := os.WriteFile(pemFile, pemData, 0600); err != nil {
			log.Fatalf("[-] Failed to write PEM file: %v", err)
		}
		fmt.Printf("[+] Exported backup key to %s\n", pemFile)
	}
}

// formatGUID formats a 16-byte GUID as a string
func formatGUID(data []byte) string {
	if len(data) < 16 {
		return hex.EncodeToString(data)
	}
	// GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	// Data1 (4 bytes, little-endian), Data2 (2 bytes, LE), Data3 (2 bytes, LE), Data4 (8 bytes, big-endian)
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uint32(data[0])|uint32(data[1])<<8|uint32(data[2])<<16|uint32(data[3])<<24,
		uint16(data[4])|uint16(data[5])<<8,
		uint16(data[6])|uint16(data[7])<<8,
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

func doMasterKey() {
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "[-] -file is required for masterkey action")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("[-] Failed to read file: %v", err)
	}

	fmt.Printf("[*] Parsing master key file: %s\n", *file)

	mkf, remaining, err := dpapi.ParseMasterKeyFile(data)
	if err != nil {
		log.Fatalf("[-] Failed to parse master key file: %v", err)
	}
	mkf.Dump()

	var mk *dpapi.MasterKey
	if mkf.MasterKeyLen > 0 {
		mk, err = dpapi.ParseMasterKey(remaining[:mkf.MasterKeyLen])
		if err != nil {
			log.Fatalf("[-] Failed to parse master key: %v", err)
		}
		mk.Dump()
		remaining = remaining[mkf.MasterKeyLen:]
	}

	if mkf.BackupKeyLen > 0 {
		bkmk, err := dpapi.ParseMasterKey(remaining[:mkf.BackupKeyLen])
		if err != nil {
			fmt.Printf("[!] Failed to parse backup key: %v\n", err)
		} else {
			fmt.Println("[BACKUP KEY]")
			bkmk.Dump()
		}
		remaining = remaining[mkf.BackupKeyLen:]
	}

	var dk *dpapi.DomainKey
	if mkf.CredHistLen > 0 {
		ch, err := dpapi.ParseCredHist(remaining[:mkf.CredHistLen])
		if err != nil {
			fmt.Printf("[!] Failed to parse cred hist: %v\n", err)
		} else {
			fmt.Printf("[CREDHIST] GUID: %s\n\n", ch.GUID)
		}
		remaining = remaining[mkf.CredHistLen:]
	}

	if mkf.DomainKeyLen > 0 {
		dk, err = dpapi.ParseDomainKey(remaining[:mkf.DomainKeyLen])
		if err != nil {
			fmt.Printf("[!] Failed to parse domain key: %v\n", err)
		} else {
			dk.Dump()
		}
	}

	// Try decryption
	if mk != nil {
		if *key != "" {
			// Direct key decryption
			keyBytes, err := parseHexKey(*key)
			if err != nil {
				log.Fatalf("[-] Invalid key format: %v", err)
			}
			decrypted, err := mk.Decrypt(keyBytes)
			if err != nil {
				fmt.Printf("[-] Decryption failed: %v\n", err)
			} else {
				fmt.Printf("[+] Decrypted master key: 0x%s\n", hex.EncodeToString(decrypted))
			}
		} else if *password != "" && *sid != "" {
			// Password-based decryption
			decrypted, err := mk.DecryptWithPassword(*password, *sid)
			if err != nil {
				fmt.Printf("[-] Decryption failed: %v\n", err)
			} else {
				fmt.Printf("[+] Decrypted master key: 0x%s\n", hex.EncodeToString(decrypted))
			}
		} else if *pvk != "" && dk != nil {
			// Domain backup key decryption
			pvkData, err := os.ReadFile(*pvk)
			if err != nil {
				log.Fatalf("[-] Failed to read PVK file: %v", err)
			}

			backupKey, err := dpapi.LoadBackupKeyFile(pvkData)
			if err != nil {
				log.Fatalf("[-] Failed to parse backup key file: %v", err)
			}

			fmt.Printf("[*] Using domain backup key (%d-bit RSA)\n", backupKey.PrivateKey.N.BitLen())

			// Decrypt domain key to get master key
			decrypted, err := dpapi.DecryptWithBackupKey(dk, backupKey)
			if err != nil {
				fmt.Printf("[-] Domain key decryption failed: %v\n", err)
			} else {
				fmt.Printf("[+] Decrypted master key: 0x%s\n", hex.EncodeToString(decrypted))
			}
		}
	}
}

func doCredential() {
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "[-] -file is required for credential action")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("[-] Failed to read file: %v", err)
	}

	fmt.Printf("[*] Parsing credential file: %s\n", *file)

	cf, err := dpapi.ParseCredentialFile(data)
	if err != nil {
		log.Fatalf("[-] Failed to parse credential file: %v", err)
	}

	fmt.Printf("[CREDENTIAL FILE]\n")
	fmt.Printf("Version : %d\n", cf.Version)
	fmt.Printf("Size    : %d\n", cf.Size)
	fmt.Println()

	if cf.DPAPIBlob != nil {
		cf.DPAPIBlob.Dump()

		// Try decryption if key provided
		if *key != "" {
			keyBytes, err := parseHexKey(*key)
			if err != nil {
				log.Fatalf("[-] Invalid key format: %v", err)
			}

			decrypted, err := cf.DPAPIBlob.Decrypt(keyBytes)
			if err != nil {
				fmt.Printf("[-] Decryption failed: %v\n", err)
			} else {
				fmt.Printf("[+] Decrypted data (%d bytes)\n", len(decrypted))

				// Try to parse as credential
				cred, err := dpapi.ParseCredential(decrypted)
				if err != nil {
					fmt.Printf("[*] Raw decrypted data:\n%s\n", hex.Dump(decrypted))
				} else {
					cred.Dump()
				}
			}
		}
	}
}

func doVault() {
	flag.Parse()
	if *vcrd == "" && *vpol == "" {
		fmt.Fprintln(os.Stderr, "[-] -vcrd or -vpol is required for vault action")
		os.Exit(1)
	}

	var vaultPolicy *dpapi.VaultPolicy
	var keyAES256, keyAES128 []byte

	if *vpol != "" {
		data, err := os.ReadFile(*vpol)
		if err != nil {
			log.Fatalf("[-] Failed to read vpol file: %v", err)
		}
		fmt.Printf("[*] Parsing vault policy file: %s\n", *vpol)

		vaultPolicy, err = dpapi.ParseVaultPolicy(data)
		if err != nil {
			log.Fatalf("[-] Failed to parse vault policy: %v", err)
		}
		vaultPolicy.Dump()

		// Try decryption if key provided
		if *key != "" && vaultPolicy.DPAPIBlob != nil {
			keyBytes, err := parseHexKey(*key)
			if err != nil {
				log.Fatalf("[-] Invalid key format: %v", err)
			}

			if err := vaultPolicy.Decrypt(keyBytes); err != nil {
				fmt.Printf("[-] Vault policy decryption failed: %v\n", err)
			} else {
				fmt.Printf("[+] Decrypted vault policy keys:\n")
				if len(vaultPolicy.KeyAES256) > 0 {
					fmt.Printf("    AES-256: 0x%s\n", hex.EncodeToString(vaultPolicy.KeyAES256))
					keyAES256 = vaultPolicy.KeyAES256
				}
				if len(vaultPolicy.KeyAES128) > 0 {
					fmt.Printf("    AES-128: 0x%s\n", hex.EncodeToString(vaultPolicy.KeyAES128))
					keyAES128 = vaultPolicy.KeyAES128
				}
			}
		}
	}

	if *vcrd != "" {
		data, err := os.ReadFile(*vcrd)
		if err != nil {
			log.Fatalf("[-] Failed to read vcrd file: %v", err)
		}
		fmt.Printf("[*] Parsing vault credential file: %s\n", *vcrd)

		vaultCred, err := dpapi.ParseVaultCredential(data)
		if err != nil {
			log.Fatalf("[-] Failed to parse vault credential: %v", err)
		}

		fmt.Printf("[*] Schema: %s\n", vaultCred.GetSchemaName())
		vaultCred.Dump()

		// Try decryption if we have vault policy keys
		if len(keyAES256) > 0 || len(keyAES128) > 0 {
			if err := vaultCred.Decrypt(keyAES256, keyAES128); err != nil {
				fmt.Printf("[!] Vault credential decryption failed: %v\n", err)
			} else {
				fmt.Printf("[+] Decrypted vault credential attributes:\n")
				vaultCred.Dump()
			}
		}
	}
}

func doUnprotect() {
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "[-] -file is required for unprotect action")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("[-] Failed to read file: %v", err)
	}

	fmt.Printf("[*] Parsing DPAPI blob: %s\n", *file)

	blob, err := dpapi.ParseDPAPIBlob(data)
	if err != nil {
		log.Fatalf("[-] Failed to parse DPAPI blob: %v", err)
	}

	blob.Dump()

	if *key != "" {
		keyBytes, err := parseHexKey(*key)
		if err != nil {
			log.Fatalf("[-] Invalid key format: %v", err)
		}

		// Parse entropy if provided
		var entropyBytes []byte
		if *entropy != "" {
			// Try parsing as hex first
			entropyBytes, err = parseHexKey(*entropy)
			if err != nil {
				// Use as raw string (UTF-16LE encoded)
				entropyBytes = stringToUTF16LE(*entropy)
			}
		} else if *entropyFile != "" {
			entropyBytes, err = os.ReadFile(*entropyFile)
			if err != nil {
				log.Fatalf("[-] Failed to read entropy file: %v", err)
			}
		}

		if len(entropyBytes) > 0 {
			fmt.Printf("[*] Using entropy: %s\n", hex.EncodeToString(entropyBytes))
		}

		decrypted, err := blob.DecryptWithEntropy(keyBytes, entropyBytes)
		if err != nil {
			fmt.Printf("[-] Decryption failed: %v\n", err)
		} else {
			fmt.Printf("[+] Decrypted data (%d bytes):\n", len(decrypted))
			fmt.Printf("%s\n", hex.Dump(decrypted))
		}
	}
}

// stringToUTF16LE converts a string to UTF-16LE bytes
func stringToUTF16LE(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2)
	for i, r := range runes {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}

func doCredHist() {
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "[-] -file is required for credhist action")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("[-] Failed to read file: %v", err)
	}

	fmt.Printf("[*] Parsing CREDHIST file: %s\n", *file)

	chf, err := dpapi.ParseCredHistFile(data)
	if err != nil {
		log.Fatalf("[-] Failed to parse CREDHIST file: %v", err)
	}

	chf.Dump()

	// Try decryption if password and SID provided
	if *password != "" && *sid != "" {
		fmt.Printf("[*] Attempting to walk credential history chain...\n")

		decrypted, err := chf.WalkChain(*password, *sid)
		if err != nil {
			fmt.Printf("[-] Chain walking failed: %v\n", err)
		}

		if len(decrypted) > 0 {
			fmt.Printf("[+] Successfully decrypted %d entries:\n\n", len(decrypted))
			for i, entry := range decrypted {
				fmt.Printf("[DECRYPTED ENTRY %d]\n", i)
				if entry.SHA1 != nil {
					fmt.Printf("  SHA1 Hash : %s\n", hex.EncodeToString(entry.SHA1))
				}
				if entry.NTHash != nil {
					fmt.Printf("  NT Hash   : %s\n", hex.EncodeToString(entry.NTHash))
				}
				fmt.Println()
			}
		}
	}

	// Show specific entry if requested
	if *entry >= 0 && *entry < len(chf.Entries) {
		fmt.Printf("[*] Showing entry %d details:\n", *entry)
		chf.Entries[*entry].Dump()
	}
}

func parseHexKey(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
