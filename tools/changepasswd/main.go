// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/epmapper"
	"github.com/mandiant/gopacket/pkg/dcerpc/samr"
	"github.com/mandiant/gopacket/pkg/flags"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/mandiant/gopacket/pkg/transport"

	goldap "github.com/go-ldap/ldap/v3"
	krbclient "github.com/mandiant/gopacket/pkg/third_party/gokrb5/client"
	krbconfig "github.com/mandiant/gopacket/pkg/third_party/gokrb5/config"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/crypto"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/nametype"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/kadmin"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
)

var (
	newPassVal   string
	newHashesVal string
	protocolVal  string
	resetVal     bool
	altUserVal   string
	altPassVal   string
	altHashVal   string
	kpasswdIPVal string
)

func init() {
	flag.StringVar(&newPassVal, "newpass", "", "New password for the target user")
	flag.StringVar(&newHashesVal, "newhashes", "", "New NTLM hashes, format is NTHASH or LMHASH:NTHASH")

	flag.StringVar(&protocolVal, "protocol", "smb-samr", "Protocol to use: smb-samr, rpc-samr, kpasswd, or ldap")
	flag.StringVar(&protocolVal, "p", "smb-samr", "Protocol to use (shorthand for -protocol)")

	flag.BoolVar(&resetVal, "reset", false, "Reset password with admin privileges (may bypass some policies)")
	flag.BoolVar(&resetVal, "admin", false, "Reset password with admin privileges (shorthand for -reset)")

	flag.StringVar(&altUserVal, "altuser", "", "Alternative username for authentication (for reset)")
	flag.StringVar(&altPassVal, "altpass", "", "Alternative password for authentication")
	flag.StringVar(&altHashVal, "althash", "", "Alternative NT hash for authentication")
	flag.StringVar(&altHashVal, "althashes", "", "Alternative NT hash (alias for -althash)")

	flag.StringVar(&kpasswdIPVal, "kpasswd-ip", "", "kpasswd server host (defaults to -dc-ip; use this when the kpasswd server is a different host from the KDC, e.g. PDC emulator vs RODC)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `changepasswd - Change or reset passwords over different protocols

Usage: changepasswd [options] [[domain/]username[:password]@]<hostname or address>

Examples:
  SAMR protocol over SMB transport (default, -protocol smb-samr is implied):
    changepasswd contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
    changepasswd contoso.local/j.doe@DC1 -hashes :fc525c9683e8fe067095ba2ddc971889 -newpass 'N3wPassw0rd!'

  Password reset with admin privileges:
    changepasswd -reset contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!' -altuser administrator -altpass 'Adm1nPassw0rd!'
    changepasswd -reset contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!' -altuser CONTOSO/administrator -k

  SAMR protocol over MS-RPC transport:
    changepasswd -protocol rpc-samr contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'

  Kerberos kpasswd protocol (-k is implied):
    changepasswd -p kpasswd contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
    changepasswd -p kpasswd -reset contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!' -altuser CONTOSO/admin -k

  LDAP password change:
    changepasswd -protocol ldap contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
    changepasswd -protocol ldap -k contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!'

Options:
`)
		flag.PrintDefaults()
	}
}

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Parse target (the user whose password will be changed)
	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}
	opts.ApplyToSession(&target, &creds)

	targetUsername := creds.Username
	targetDomain := creds.Domain
	oldPassword := creds.Password

	// Handle hashes for old password auth
	oldPwdHashNT := ""
	if opts.Hashes != "" {
		parts := strings.Split(opts.Hashes, ":")
		if len(parts) == 2 {
			oldPwdHashNT = parts[1]
		} else {
			oldPwdHashNT = opts.Hashes
		}
	}

	// Parse new password/hash
	newPassword := newPassVal
	newPwdHashNT := ""
	if newHashesVal != "" {
		parts := strings.Split(newHashesVal, ":")
		if len(parts) == 2 {
			newPwdHashNT = parts[1]
		} else {
			newPwdHashNT = newHashesVal
		}
	}

	// Validate we have a new password
	if newPassword == "" && newPwdHashNT == "" {
		fmt.Print("New password: ")
		var pw string
		fmt.Scanln(&pw)
		newPassword = pw
	}

	// Parse alternative credentials for reset
	authUsername := targetUsername
	authPassword := oldPassword
	authDomain := targetDomain
	authHashNT := oldPwdHashNT

	if altUserVal != "" {
		if strings.Contains(altUserVal, "/") {
			parts := strings.SplitN(altUserVal, "/", 2)
			authDomain = parts[0]
			authUsername = parts[1]
		} else {
			authUsername = altUserVal
		}
		authPassword = altPassVal
		if altHashVal != "" {
			parts := strings.Split(altHashVal, ":")
			if len(parts) == 2 {
				authHashNT = parts[1]
			} else {
				authHashNT = altHashVal
			}
		} else {
			authHashNT = ""
		}
	}

	// If reset mode, we need auth credentials
	if resetVal && altUserVal == "" {
		// Use the same auth credentials as target
		authPassword = oldPassword
		authHashNT = oldPwdHashNT
	}

	// Validate auth
	if !resetVal && oldPassword == "" && oldPwdHashNT == "" && !opts.NoPass {
		log.Fatal("[-] Current password required for password change. Use -hashes or provide password in target string.")
	}

	// kpasswd implies Kerberos authentication
	protocolLower := strings.ToLower(protocolVal)
	if protocolLower == "kpasswd" && !opts.Kerberos {
		fmt.Println("[*] Using the kpasswd protocol implies Kerberos authentication (-k)")
		opts.Kerberos = true
	}

	switch protocolLower {
	case "smb-samr":
		doSMBSAMR(opts, target, targetUsername, targetDomain, oldPassword, newPassword, newPwdHashNT,
			authUsername, authPassword, authDomain, authHashNT)
	case "rpc-samr":
		doRPCSAMR(opts, target, targetUsername, targetDomain, oldPassword, newPassword, newPwdHashNT,
			authUsername, authPassword, authDomain, authHashNT)
	case "kpasswd":
		doKpasswd(opts, target, targetUsername, targetDomain, oldPassword, newPassword,
			authUsername, authPassword, authDomain, authHashNT)
	case "ldap", "ldaps":
		doLDAP(opts, target, targetUsername, targetDomain, oldPassword, newPassword,
			authUsername, authPassword, authDomain, authHashNT)
	default:
		log.Fatalf("[-] Unsupported protocol: %s (use smb-samr, rpc-samr, kpasswd, or ldap)", protocolVal)
	}
}

func doSMBSAMR(opts *flags.Options, target session.Target, targetUsername, targetDomain, oldPassword, newPassword, newPwdHashNT,
	authUsername, authPassword, authDomain, authHashNT string) {

	if target.Port == 0 {
		target.Port = 445
	}

	// Build auth credentials
	authCreds := session.Credentials{
		Username:    authUsername,
		Password:    authPassword,
		Domain:      authDomain,
		Hash:        authHashNT,
		UseKerberos: opts.Kerberos,
		AESKey:      opts.AesKey,
		DCIP:        opts.DcIP,
	}

	if resetVal {
		fmt.Printf("[*] Setting the password of %s\\%s as %s\\%s\n", targetDomain, targetUsername, authDomain, authUsername)
	} else {
		fmt.Printf("[*] Changing the password of %s\\%s\n", targetDomain, targetUsername)
	}

	fmt.Printf("[*] Connecting to %s via SMB...\n", target.Addr())
	smbClient := smb.NewClient(target, &authCreds)
	if err := smbClient.Connect(); err != nil {
		log.Fatalf("[-] SMB connection failed: %v", err)
	}
	defer smbClient.Close()

	fmt.Printf("[*] Connecting to DCE/RPC as %s\\%s\n", authDomain, authUsername)

	// Get SMB session key
	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		log.Fatalf("[-] Failed to obtain SMB session key")
	}

	// Open SAMR pipe
	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		log.Fatalf("[-] Failed to open SAMR pipe: %v", err)
	}

	// Create RPC client and bind
	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		log.Fatalf("[-] SAMR bind failed: %v", err)
	}

	// Create SAMR client
	samrClient := samr.NewSamrClient(rpcClient, sessionKey)

	// Connect to SAM
	if err := samrClient.Connect(); err != nil {
		log.Fatalf("[-] SamrConnect5 failed: %v", err)
	}
	defer samrClient.Close()

	// Open domain
	domain := targetDomain
	if domain == "" {
		domain = "Builtin"
	}
	if err := samrClient.OpenDomain(domain); err != nil {
		log.Fatalf("[-] Failed to open domain %s: %v", domain, err)
	}

	if resetVal {
		// Admin password reset using SamrSetInformationUser
		if newPassword == "" && newPwdHashNT != "" {
			log.Fatal("[-] Password reset with hash not implemented for SMB-SAMR (use plaintext password)")
		}

		if err := samrClient.SetUserPassword(targetUsername, newPassword); err != nil {
			if strings.Contains(err.Error(), "0xc0000022") {
				log.Fatalf("[-] Access denied: %s\\%s does not have permission to reset %s's password", authDomain, authUsername, targetUsername)
			}
			log.Fatalf("[-] Failed to reset password: %v", err)
		}
		fmt.Println("[+] Password was changed successfully.")
		fmt.Println("[!] User no longer has valid AES keys for Kerberos, until they change their password again.")
	} else {
		// Password change using SamrUnicodeChangePasswordUser2
		if newPassword == "" {
			log.Fatal("[-] New password in plaintext required for password change")
		}

		if err := samrClient.ChangeUserPassword(targetUsername, oldPassword, newPassword); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "0xc000006a") {
				log.Fatalf("[-] Authentication failure: wrong current password")
			}
			if strings.Contains(errStr, "0xc000006c") {
				log.Fatalf("[-] Password restriction: password does not meet complexity requirements or history policy")
			}
			if strings.Contains(errStr, "0xc0000224") {
				log.Fatalf("[-] Password must be changed before first logon")
			}
			log.Fatalf("[-] Failed to change password: %v", err)
		}
		fmt.Println("[+] Password was changed successfully.")
	}
}

func doRPCSAMR(opts *flags.Options, target session.Target, targetUsername, targetDomain, oldPassword, newPassword, newPwdHashNT,
	authUsername, authPassword, authDomain, authHashNT string) {

	if resetVal {
		fmt.Printf("[*] Setting the password of %s\\%s as %s\\%s\n", targetDomain, targetUsername, authDomain, authUsername)
	} else {
		fmt.Printf("[*] Changing the password of %s\\%s\n", targetDomain, targetUsername)
	}

	// Use EPMapper to find SAMR endpoint on TCP
	fmt.Printf("[*] Querying endpoint mapper on %s:135 for SAMR...\n", target.Host)
	port, err := epmapper.MapTCPEndpoint(target.Host, samr.UUID, samr.MajorVersion)
	if err != nil {
		log.Fatalf("[-] Failed to map SAMR endpoint: %v", err)
	}
	fmt.Printf("[*] Found SAMR endpoint on port %d\n", port)

	// Connect via TCP
	fmt.Printf("[*] Connecting to %s:%d via TCP...\n", target.Host, port)
	transport, err := dcerpc.DialTCP(target.Host, port)
	if err != nil {
		log.Fatalf("[-] TCP connection failed: %v", err)
	}
	defer transport.Close()

	// Create RPC client
	rpcClient := dcerpc.NewClientTCP(transport)

	// Build auth credentials
	authCreds := session.Credentials{
		Username:    authUsername,
		Password:    authPassword,
		Domain:      authDomain,
		Hash:        authHashNT,
		UseKerberos: opts.Kerberos,
		AESKey:      opts.AesKey,
		DCIP:        opts.DcIP,
	}

	// Bind to SAMR with authentication
	fmt.Printf("[*] Binding to SAMR as %s\\%s\n", authDomain, authUsername)
	if authCreds.UseKerberos {
		// Use Kerberos authentication
		if err := rpcClient.BindAuthKerberos(samr.UUID, samr.MajorVersion, samr.MinorVersion, &authCreds, target.Host); err != nil {
			log.Fatalf("[-] SAMR Kerberos bind failed: %v", err)
		}
	} else {
		// Use NTLM authentication
		if err := rpcClient.BindAuth(samr.UUID, samr.MajorVersion, samr.MinorVersion, &authCreds); err != nil {
			log.Fatalf("[-] SAMR bind failed: %v", err)
		}
	}

	// Get session key from the auth handler
	sessionKey := rpcClient.GetSessionKey()
	if len(sessionKey) == 0 {
		log.Fatalf("[-] Failed to obtain session key")
	}

	// Create SAMR client
	samrClient := samr.NewSamrClient(rpcClient, sessionKey)

	// Connect to SAM
	if err := samrClient.Connect(); err != nil {
		log.Fatalf("[-] SamrConnect5 failed: %v", err)
	}
	defer samrClient.Close()

	// Open domain
	domain := targetDomain
	if domain == "" {
		domain = "Builtin"
	}
	if err := samrClient.OpenDomain(domain); err != nil {
		log.Fatalf("[-] Failed to open domain %s: %v", domain, err)
	}

	if resetVal {
		// Admin password reset using SamrSetInformationUser
		if newPassword == "" && newPwdHashNT != "" {
			log.Fatal("[-] Password reset with hash not implemented for RPC-SAMR (use plaintext password)")
		}

		fmt.Println("[!] Warning: MS-RPC transport does not allow password reset in default Active Directory configuration. Trying anyway.")
		if err := samrClient.SetUserPassword(targetUsername, newPassword); err != nil {
			if strings.Contains(err.Error(), "0xc0000022") {
				log.Fatalf("[-] Access denied: %s\\%s does not have permission to reset %s's password", authDomain, authUsername, targetUsername)
			}
			log.Fatalf("[-] Failed to reset password: %v", err)
		}
		fmt.Println("[+] Password was changed successfully.")
		fmt.Println("[!] User no longer has valid AES keys for Kerberos, until they change their password again.")
	} else {
		// Password change using SamrUnicodeChangePasswordUser2
		if newPassword == "" {
			fmt.Println("[!] Warning: MS-RPC transport requires new password in plaintext in default Active Directory configuration. Trying anyway.")
		}

		if err := samrClient.ChangeUserPassword(targetUsername, oldPassword, newPassword); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "0xc000006a") {
				log.Fatalf("[-] Authentication failure: wrong current password")
			}
			if strings.Contains(errStr, "0xc000006c") {
				log.Fatalf("[-] Password restriction: password does not meet complexity requirements or history policy")
			}
			if strings.Contains(errStr, "0xc0000224") {
				log.Fatalf("[-] Password must be changed before first logon")
			}
			log.Fatalf("[-] Failed to change password: %v", err)
		}
		fmt.Println("[+] Password was changed successfully.")
	}
}

func doKpasswd(opts *flags.Options, target session.Target, targetUsername, targetDomain, oldPassword, newPassword,
	authUsername, authPassword, authDomain, authHashNT string) {

	if newPassword == "" {
		log.Fatal("[-] kpasswd requires the new password as plaintext")
	}

	realm := strings.ToUpper(authDomain)
	if realm == "" {
		realm = strings.ToUpper(targetDomain)
	}
	if realm == "" {
		log.Fatal("[-] Domain/realm is required for kpasswd protocol")
	}

	// Determine KDC host
	kdc := opts.DcIP
	if kdc == "" {
		kdc = target.Host
	}

	// Allow the kpasswd server to be split from the KDC. In AD, password
	// changes are processed only by writable DCs (often the PDC emulator),
	// so a -dc-ip pointed at an RODC needs an explicit -kpasswd-ip override
	// pointed at a writable DC. Default to the KDC when unset.
	kpasswdHost := kpasswdIPVal
	if kpasswdHost == "" {
		kpasswdHost = kdc
	}

	// Build krb5 config via the shared helper so the opsec defaults
	// (udp_preference_limit=1, dns_lookup_kdc=false, dns_lookup_realm=false)
	// stay synchronized with the rest of the tool.
	cfg, err := krbconfig.NewFromString(kerberos.SynthesizeKrb5ConfigWithKpasswd(realm, kdc, kpasswdHost))
	if err != nil {
		log.Fatalf("[-] Failed to create krb5 config: %v", err)
	}

	if resetVal {
		// Password reset (set-password) — admin sets target's password
		// Uses RFC 3244 kpasswd set-password with TargName/TargRealm fields
		fmt.Printf("[*] Setting the password of %s\\%s as %s\\%s via kpasswd\n",
			targetDomain, targetUsername, authDomain, authUsername)

		// Create Kerberos client with admin credentials
		var krbClient *krbclient.Client
		if authPassword != "" {
			krbClient = krbclient.NewWithPassword(kerberos.TransportKDCDialer{}, authUsername, realm, authPassword, cfg,
				krbclient.DisablePAFXFAST(true))
		} else if authHashNT != "" {
			// Use RC4-HMAC with NT hash as keytab
			log.Fatal("[-] kpasswd with NT hash requires password or AES key. Use -altpass or -aesKey.")
		} else if opts.AesKey != "" {
			log.Fatal("[-] kpasswd with AES key via keytab not yet implemented. Use password authentication.")
		} else {
			log.Fatal("[-] No credentials provided for kpasswd authentication")
		}

		// Login to get TGT
		if err := krbClient.Login(); err != nil {
			log.Fatalf("[-] Kerberos login failed: %v", err)
		}

		// Request TGS for kadmin/changepw service
		tgt, tgtKey, err := krbClient.GetServiceTicket("kadmin/changepw")
		if err != nil {
			log.Fatalf("[-] Failed to get kadmin/changepw ticket: %v", err)
		}

		// Build target principal name for set-password
		targetRealm := strings.ToUpper(targetDomain)
		if targetRealm == "" {
			targetRealm = realm
		}
		targetCName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, targetUsername)
		authCName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, authUsername)

		// Build ChangePasswdData with target principal (RFC 3244 set-password)
		chgPasswd := kadmin.ChangePasswdData{
			NewPasswd: []byte(newPassword),
			TargName:  targetCName,
			TargRealm: targetRealm,
		}
		chpwdb, err := chgPasswd.Marshal()
		if err != nil {
			log.Fatalf("[-] Failed to marshal ChangePasswdData: %v", err)
		}

		// Generate authenticator
		auth, err := types.NewAuthenticator(realm, authCName)
		if err != nil {
			log.Fatalf("[-] Failed to create authenticator: %v", err)
		}
		etype, err := crypto.GetEtype(tgtKey.KeyType)
		if err != nil {
			log.Fatalf("[-] Failed to get etype: %v", err)
		}
		if err := auth.GenerateSeqNumberAndSubKey(etype.GetETypeID(), etype.GetKeyByteSize()); err != nil {
			log.Fatalf("[-] Failed to generate subkey: %v", err)
		}
		subKey := auth.SubKey

		// Generate AP_REQ
		apReq, err := messages.NewAPReq(tgt, tgtKey, auth)
		if err != nil {
			log.Fatalf("[-] Failed to create AP_REQ: %v", err)
		}

		// Build KRB-PRIV with ChangePasswdData
		kp := messages.EncKrbPrivPart{
			UserData:       chpwdb,
			Timestamp:      auth.CTime,
			Usec:           auth.Cusec,
			SequenceNumber: auth.SeqNumber,
		}
		kpriv := messages.NewKRBPriv(kp)
		if err := kpriv.EncryptEncPart(subKey); err != nil {
			log.Fatalf("[-] Failed to encrypt KRB-PRIV: %v", err)
		}

		// Build the kpasswd request
		req := kadmin.Request{
			APREQ:   apReq,
			KRBPriv: kpriv,
		}

		reqBytes, err := req.Marshal()
		if err != nil {
			log.Fatalf("[-] Failed to marshal kpasswd request: %v", err)
		}

		// Send to kpasswd service (TCP port 464). Use kpasswdHost not kdc so
		// the -kpasswd-ip override actually targets the writable DC.
		fmt.Printf("[*] Sending kpasswd set-password request to %s...\n", kerberos.FormatKDC(kpasswdHost, "464"))
		respBytes, err := sendKpasswd(kpasswdHost, reqBytes)
		if err != nil {
			log.Fatalf("[-] Failed to send kpasswd request: %v", err)
		}

		// Decode the reply
		var reply kadmin.Reply
		if err := reply.Unmarshal(respBytes); err != nil {
			log.Fatalf("[-] Failed to unmarshal kpasswd reply: %v", err)
		}
		if err := reply.Decrypt(subKey); err != nil {
			log.Fatalf("[-] Failed to decrypt kpasswd reply: %v", err)
		}

		if reply.ResultCode != 0 {
			log.Fatalf("[-] kpasswd error (code %d): %s", reply.ResultCode, reply.Result)
		}
		fmt.Printf("[+] Password was set successfully for %s\\%s.\n", targetDomain, targetUsername)
	} else {
		// Password change — user changes their own password
		fmt.Printf("[*] Changing the password of %s\\%s via kpasswd\n", targetDomain, targetUsername)

		// Build Kerberos client with the target user's credentials
		var krbClient *krbclient.Client
		if authPassword != "" {
			krbClient = krbclient.NewWithPassword(kerberos.TransportKDCDialer{}, authUsername, realm, authPassword, cfg,
				krbclient.DisablePAFXFAST(true))
		} else if authHashNT != "" {
			log.Fatal("[-] kpasswd with NT hash requires password. Use password authentication.")
		} else {
			log.Fatal("[-] No credentials provided for kpasswd authentication")
		}

		fmt.Printf("[*] Sending kpasswd change-password request to %s...\n", kerberos.FormatKDC(kpasswdHost, "464"))
		ok, err := krbClient.ChangePasswd(newPassword)
		if err != nil {
			log.Fatalf("[-] kpasswd failed: %v", err)
		}
		if !ok {
			log.Fatal("[-] kpasswd returned failure")
		}
		fmt.Println("[+] Password was changed successfully.")
	}
}

// sendKpasswd sends a kpasswd request to the KDC on TCP port 464 and returns the response.
func sendKpasswd(kdc string, data []byte) ([]byte, error) {
	addr := kerberos.FormatKDC(kdc, "464")
	conn, err := transport.DialTimeout("tcp", addr, 10)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to kpasswd %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// TCP framing: 4-byte big-endian length prefix
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := conn.Write(append(header, data...)); err != nil {
		return nil, fmt.Errorf("failed to send: %v", err)
	}

	// Read response
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, fmt.Errorf("failed to read response header: %v", err)
	}
	respLen := binary.BigEndian.Uint32(respHeader)
	if respLen > 1024*1024 {
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	return respBuf, nil
}

func doLDAP(opts *flags.Options, target session.Target, targetUsername, targetDomain, oldPassword, newPassword,
	authUsername, authPassword, authDomain, authHashNT string) {

	if target.Port == 0 {
		target.Port = 636
	}

	// Build auth credentials
	authCreds := session.Credentials{
		Username:    authUsername,
		Password:    authPassword,
		Domain:      authDomain,
		Hash:        authHashNT,
		UseKerberos: opts.Kerberos,
		AESKey:      opts.AesKey,
		DCIP:        opts.DcIP,
	}

	if resetVal {
		fmt.Printf("[*] Setting the password of %s\\%s as %s\\%s\n", targetDomain, targetUsername, authDomain, authUsername)
	} else {
		fmt.Printf("[*] Changing the password of %s\\%s\n", targetDomain, targetUsername)
	}

	fmt.Printf("[*] Connecting to %s via LDAPS...\n", target.Addr())
	client := ldap.NewClient(target, &authCreds)
	defer client.Close()

	if err := client.Connect(true); err != nil {
		log.Fatalf("[-] LDAPS connection failed: %v", err)
	}

	// Use UPN format for LDAP bind
	if authDomain != "" && authCreds.Hash == "" && !authCreds.UseKerberos {
		authCreds.Username = fmt.Sprintf("%s@%s", authUsername, authDomain)
		authCreds.Domain = ""
		client = ldap.NewClient(target, &authCreds)
		if err := client.Connect(true); err != nil {
			log.Fatalf("[-] LDAPS connection failed: %v", err)
		}
	}

	fmt.Printf("[*] Binding as %s...\n", authCreds.Username)
	if err := client.Login(); err != nil {
		log.Fatalf("[-] LDAP bind failed: %v", err)
	}

	// Get base DN
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		log.Fatalf("[-] Failed to get base DN: %v", err)
	}

	// Find target user DN
	filter := fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(targetUsername))
	result, err := client.Search(baseDN, filter, []string{"distinguishedName"})
	if err != nil || len(result.Entries) == 0 {
		log.Fatalf("[-] Could not find target user %s in LDAP", targetUsername)
	}
	targetDN := result.Entries[0].DN
	fmt.Printf("[*] Found target: %s\n", targetDN)

	if resetVal {
		// Admin password set (replace unicodePwd)
		newPwdEncoded := encodeUnicodePwd(newPassword)
		changes := []ldap.ModifyChange{
			{Operation: goldap.ReplaceAttribute, AttrName: "unicodePwd", AttrVals: []string{string(newPwdEncoded)}},
		}
		if err := client.Modify(targetDN, changes); err != nil {
			if strings.Contains(err.Error(), "Constraint Violation") {
				log.Fatalf("[-] Password constraint violation: new password does not meet policy requirements")
			}
			if strings.Contains(err.Error(), "Insufficient Access") {
				log.Fatalf("[-] Insufficient access rights to reset password")
			}
			log.Fatalf("[-] Failed to reset password: %v", err)
		}
		fmt.Printf("[+] Password was changed successfully for %s\n", targetDN)
	} else {
		// Password change (delete old, add new)
		if oldPassword == "" {
			log.Fatal("[-] LDAP password change requires old password in plaintext")
		}

		oldPwdEncoded := encodeUnicodePwd(oldPassword)
		newPwdEncoded := encodeUnicodePwd(newPassword)

		// Build modify request with delete old + add new
		modReq := goldap.NewModifyRequest(targetDN, nil)
		modReq.Delete("unicodePwd", []string{string(oldPwdEncoded)})
		modReq.Add("unicodePwd", []string{string(newPwdEncoded)})

		if err := client.ModifyRequest(modReq); err != nil {
			if strings.Contains(err.Error(), "Constraint Violation") {
				log.Fatalf("[-] Password constraint violation: wrong old password or new password does not meet policy")
			}
			log.Fatalf("[-] Failed to change password: %v", err)
		}
		fmt.Printf("[+] Password was changed successfully for %s\n", targetDN)
	}
}

// encodeUnicodePwd encodes password for LDAP unicodePwd attribute.
// Password must be surrounded by quotes and UTF-16LE encoded.
func encodeUnicodePwd(password string) []byte {
	quoted := fmt.Sprintf("\"%s\"", password)
	utf16Chars := utf16.Encode([]rune(quoted))
	b := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}
