// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/lsarpc"
	"gopacket/pkg/dcerpc/samr"
	"gopacket/pkg/flags"
	"gopacket/pkg/session"
	"gopacket/pkg/smb"
)

func main() {
	// We need custom flag parsing: target comes first, then subcommand, then subcommand flags.
	// Standard flags (auth, connection) appear before the target.
	// Everything after the subcommand name goes to the subcommand's flag set.

	// Phase 1: Find target (first non-flag) and subcommand (second non-flag).
	// Everything before the subcommand that starts with - is a standard flag.
	// Everything from the subcommand onward (including its flags) is subcommand territory.
	var stdArgs []string
	var target, command string
	var subArgs []string

	args := os.Args[1:]
	positionalCount := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if positionalCount >= 2 {
			// Everything after the subcommand name is a subcommand arg
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
	subFlags := flag.NewFlagSet("net "+command, flag.ExitOnError)
	nameFlag := subFlags.String("name", "", "Account/group name to query")
	createFlag := subFlags.String("create", "", "Account name to create")
	removeFlag := subFlags.String("remove", "", "Account name to remove")
	enableFlag := subFlags.String("enable", "", "Account name to enable")
	disableFlag := subFlags.String("disable", "", "Account name to disable")
	newPasswd := subFlags.String("newPasswd", "", "Password for -create")
	joinFlag := subFlags.String("join", "", "User/account to add to group (requires -name)")
	unjoinFlag := subFlags.String("unjoin", "", "User/account to remove from group (requires -name)")
	subFlags.Parse(subArgs)

	// Set os.Args for flags.Parse() to handle standard auth flags
	os.Args = append([]string{os.Args[0]}, append(stdArgs, target)...)

	// Re-register and parse standard flags
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

	fmt.Println("gopacket v0.1.0 - net")
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

	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Failed to obtain SMB session key\n")
		os.Exit(1)
	}

	// Open SAMR pipe
	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open SAMR pipe: %v\n", err)
		os.Exit(1)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SAMR bind failed: %v\n", err)
		os.Exit(1)
	}

	samrClient := samr.NewSamrClient(rpcClient, sessionKey)
	if err := samrClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SAMR connect failed: %v\n", err)
		os.Exit(1)
	}
	defer samrClient.Close()

	// Enumerate domains and open the target domain (non-Builtin)
	domains, err := samrClient.EnumerateDomains()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to enumerate domains: %v\n", err)
		os.Exit(1)
	}

	var targetDomain string
	for _, d := range domains {
		if d != "Builtin" {
			targetDomain = d
			break
		}
	}
	if targetDomain == "" && len(domains) > 0 {
		targetDomain = domains[0]
	}

	if err := samrClient.OpenDomain(targetDomain); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open domain '%s': %v\n", targetDomain, err)
		os.Exit(1)
	}

	switch command {
	case "user":
		handleUser(samrClient, smbClient, targetDomain, *nameFlag, *createFlag, *removeFlag, *enableFlag, *disableFlag, *newPasswd)
	case "computer":
		handleComputer(samrClient, smbClient, targetDomain, *nameFlag, *createFlag, *removeFlag, *enableFlag, *disableFlag, *newPasswd)
	case "group":
		handleGroup(samrClient, targetDomain, *nameFlag, *joinFlag, *unjoinFlag)
	case "localgroup":
		handleLocalGroup(samrClient, smbClient, targetDomain, *nameFlag, *joinFlag, *unjoinFlag)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "gopacket v0.1.0 - net")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Usage: net [auth-flags] target <command> [command-flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Target:")
	fmt.Fprintln(os.Stderr, "  [[domain/]username[:password]@]<targetName or address>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  user         Enumerate/manage domain user accounts")
	fmt.Fprintln(os.Stderr, "  computer     Enumerate/manage computer accounts")
	fmt.Fprintln(os.Stderr, "  group        Enumerate/manage domain groups")
	fmt.Fprintln(os.Stderr, "  localgroup   Enumerate/manage local groups (aliases)")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Per-command flags:")
	fmt.Fprintln(os.Stderr, "  -name NAME       Query detailed info / specify group for -join/-unjoin")
	fmt.Fprintln(os.Stderr, "  -create NAME     Create account (requires -newPasswd)")
	fmt.Fprintln(os.Stderr, "  -remove NAME     Delete account")
	fmt.Fprintln(os.Stderr, "  -enable NAME     Enable account")
	fmt.Fprintln(os.Stderr, "  -disable NAME    Disable account")
	fmt.Fprintln(os.Stderr, "  -newPasswd PASS  Password for -create")
	fmt.Fprintln(os.Stderr, "  -join USER       Add user to group (requires -name)")
	fmt.Fprintln(os.Stderr, "  -unjoin USER     Remove user from group (requires -name)")
}

// isFlagWithValue returns true if the flag requires a value argument.
func isFlagWithValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	// Strip =value if present
	if idx := strings.Index(name, "="); idx >= 0 {
		return false // value is embedded
	}
	boolFlags := map[string]bool{
		"no-pass": true, "k": true, "ts": true, "debug": true, "csv": true,
	}
	return !boolFlags[name]
}

// handleUser implements the "user" subcommand.
func handleUser(samrClient *samr.SamrClient, smbClient *smb.Client, domain string,
	name, create, remove, enable, disable, newPasswd string) {

	switch {
	case create != "":
		if newPasswd == "" {
			fmt.Fprintf(os.Stderr, "[-] -newPasswd is required with -create\n")
			os.Exit(1)
		}
		userHandle, _, err := samrClient.CreateUser2(create, samr.USER_NORMAL_ACCOUNT)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create user '%s': %v\n", create, err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(userHandle)

		if err := samrClient.SetPassword(userHandle, newPasswd); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to set password: %v\n", err)
			os.Exit(1)
		}

		// Enable the account (clear ACCOUNTDISABLE bit)
		info, err := samrClient.QueryUserInfo(userHandle)
		if err == nil {
			uac := info.UserAccountControl &^ samr.USER_ACCOUNT_DISABLED
			samrClient.SetUserAccountControl(userHandle, uac)
		}

		fmt.Printf("[+] User '%s' created successfully.\n", create)

	case remove != "":
		rid, err := samrClient.LookupName(remove)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] User '%s' not found: %v\n", remove, err)
			os.Exit(1)
		}
		userHandle, err := samrClient.OpenUser(rid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open user: %v\n", err)
			os.Exit(1)
		}
		if err := samrClient.DeleteUser(userHandle); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to delete user: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] User '%s' deleted successfully.\n", remove)

	case enable != "":
		setAccountDisabled(samrClient, enable, false)

	case disable != "":
		setAccountDisabled(samrClient, disable, true)

	case name != "":
		queryUserDetail(samrClient, smbClient, domain, name)

	default:
		// Enumerate normal user accounts (excludes machine accounts)
		fmt.Println("[*] Enumerating users ..")
		users, err := samrClient.EnumerateDomainUsersByType(samr.USER_NORMAL_ACCOUNT)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to enumerate users: %v\n", err)
			os.Exit(1)
		}
		for i, u := range users {
			fmt.Printf("  %d. %s\n", i+1, u.Name)
		}
	}
}

// handleComputer implements the "computer" subcommand.
func handleComputer(samrClient *samr.SamrClient, smbClient *smb.Client, domain string,
	name, create, remove, enable, disable, newPasswd string) {

	switch {
	case create != "":
		if newPasswd == "" {
			fmt.Fprintf(os.Stderr, "[-] -newPasswd is required with -create\n")
			os.Exit(1)
		}
		compName := create
		if !strings.HasSuffix(compName, "$") {
			compName += "$"
		}
		if err := samrClient.CreateComputer(compName, newPasswd); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create computer '%s': %v\n", create, err)
			os.Exit(1)
		}
		fmt.Printf("[+] Computer '%s' created successfully.\n", create)

	case remove != "":
		if err := samrClient.DeleteComputer(remove); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to delete computer: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Computer '%s' deleted successfully.\n", remove)

	case enable != "":
		compName := enable
		if !strings.HasSuffix(compName, "$") {
			compName += "$"
		}
		setAccountDisabled(samrClient, compName, false)

	case disable != "":
		compName := disable
		if !strings.HasSuffix(compName, "$") {
			compName += "$"
		}
		setAccountDisabled(samrClient, compName, true)

	case name != "":
		compName := name
		if !strings.HasSuffix(compName, "$") {
			compName += "$"
		}
		queryUserDetail(samrClient, smbClient, domain, compName)

	default:
		// Enumerate computer accounts (workstation + server trust accounts)
		fmt.Println("[*] Enumerating computers ..")
		users, err := samrClient.EnumerateDomainUsersByType(samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to enumerate computer accounts: %v\n", err)
			os.Exit(1)
		}
		for i, u := range users {
			fmt.Printf("  %d. %s\n", i+1, u.Name)
		}
	}
}

// handleGroup implements the "group" subcommand.
func handleGroup(samrClient *samr.SamrClient, domain string, name, join, unjoin string) {
	switch {
	case name != "" && join != "":
		// Add user to group
		groupRid, err := samrClient.LookupName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Group '%s' not found: %v\n", name, err)
			os.Exit(1)
		}
		groupHandle, err := samrClient.OpenGroup(groupRid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open group: %v\n", err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(groupHandle)

		userRid, err := samrClient.LookupName(join)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] User '%s' not found: %v\n", join, err)
			os.Exit(1)
		}

		if err := samrClient.AddMemberToGroup(groupHandle, userRid); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add member: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] User '%s' added to group '%s'.\n", join, name)

	case name != "" && unjoin != "":
		// Remove user from group
		groupRid, err := samrClient.LookupName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Group '%s' not found: %v\n", name, err)
			os.Exit(1)
		}
		groupHandle, err := samrClient.OpenGroup(groupRid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open group: %v\n", err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(groupHandle)

		userRid, err := samrClient.LookupName(unjoin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] User '%s' not found: %v\n", unjoin, err)
			os.Exit(1)
		}

		if err := samrClient.RemoveMemberFromGroup(groupHandle, userRid); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to remove member: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] User '%s' removed from group '%s'.\n", unjoin, name)

	case name != "":
		// List group members
		groupRid, err := samrClient.LookupName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Group '%s' not found: %v\n", name, err)
			os.Exit(1)
		}
		groupHandle, err := samrClient.OpenGroup(groupRid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open group: %v\n", err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(groupHandle)

		memberRids, err := samrClient.GetMembersInGroup(groupHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to get group members: %v\n", err)
			os.Exit(1)
		}

		if len(memberRids) == 0 {
			return
		}

		names, err := samrClient.LookupIds(memberRids)
		if err != nil {
			for i, rid := range memberRids {
				fmt.Printf("  %d. RID %d\n", i+1, rid)
			}
			return
		}

		for i, n := range names {
			if n != "" {
				fmt.Printf("  %d. %s\n", i+1, n)
			} else {
				fmt.Printf("  %d. RID %d\n", i+1, memberRids[i])
			}
		}

	default:
		// Enumerate all groups
		fmt.Println("[*] Enumerating groups ..")
		groups, err := samrClient.EnumerateDomainGroups()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to enumerate groups: %v\n", err)
			os.Exit(1)
		}
		for i, g := range groups {
			fmt.Printf("  %d. %s\n", i+1, g.Name)
		}
	}
}

// handleLocalGroup implements the "localgroup" subcommand.
func handleLocalGroup(samrClient *samr.SamrClient, smbClient *smb.Client, domain string, name, join, unjoin string) {
	// Open Builtin domain for alias operations
	builtinHandle, _, err := samrClient.OpenBuiltinDomain()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open Builtin domain: %v\n", err)
		os.Exit(1)
	}
	defer samrClient.CloseHandle(builtinHandle)

	switch {
	case name != "" && join != "":
		// Add user to local group
		aliasRid, err := samrClient.LookupNameInDomain(builtinHandle, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Local group '%s' not found: %v\n", name, err)
			os.Exit(1)
		}
		aliasHandle, err := samrClient.OpenAlias(builtinHandle, aliasRid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open local group: %v\n", err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(aliasHandle)

		// Resolve user to SID via LSA (supports cross-domain and well-known names)
		userSid := resolveNameToSID(samrClient, smbClient, join)
		if userSid == nil {
			fmt.Fprintf(os.Stderr, "[-] Could not resolve '%s' to a SID\n", join)
			os.Exit(1)
		}

		if err := samrClient.AddMemberToAlias(aliasHandle, userSid); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add member: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] User '%s' added to local group '%s'.\n", join, name)

	case name != "" && unjoin != "":
		// Remove user from local group
		aliasRid, err := samrClient.LookupNameInDomain(builtinHandle, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Local group '%s' not found: %v\n", name, err)
			os.Exit(1)
		}
		aliasHandle, err := samrClient.OpenAlias(builtinHandle, aliasRid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open local group: %v\n", err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(aliasHandle)

		// Resolve user to SID via LSA (supports cross-domain and well-known names)
		userSid := resolveNameToSID(samrClient, smbClient, unjoin)
		if userSid == nil {
			fmt.Fprintf(os.Stderr, "[-] Could not resolve '%s' to a SID\n", unjoin)
			os.Exit(1)
		}

		if err := samrClient.RemoveMemberFromAlias(aliasHandle, userSid); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to remove member: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] User '%s' removed from local group '%s'.\n", unjoin, name)

	case name != "":
		// List local group members
		aliasRid, err := samrClient.LookupNameInDomain(builtinHandle, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Local group '%s' not found: %v\n", name, err)
			os.Exit(1)
		}
		aliasHandle, err := samrClient.OpenAlias(builtinHandle, aliasRid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open local group: %v\n", err)
			os.Exit(1)
		}
		defer samrClient.CloseHandle(aliasHandle)

		memberSids, err := samrClient.GetMembersInAlias(aliasHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to get alias members: %v\n", err)
			os.Exit(1)
		}

		if len(memberSids) == 0 {
			return
		}

		// Resolve SIDs using LSA
		sidStrings := make([]string, len(memberSids))
		for i, sid := range memberSids {
			sidStrings[i] = samr.FormatSID(sid)
		}

		// Try to resolve via LSA
		lsaResults := resolveSidsViaLSA(smbClient, sidStrings)
		if lsaResults != nil {
			for i, r := range lsaResults {
				displayName := r.SID
				if r.Name != "" {
					displayName = r.Name
				}
				fmt.Printf("  %d. %s\n", i+1, displayName)
			}
		} else {
			for i, sid := range sidStrings {
				fmt.Printf("  %d. %s\n", i+1, sid)
			}
		}

	default:
		// Enumerate all aliases in Builtin domain
		fmt.Println("[*] Enumerating localgroups ..")
		aliases, err := samrClient.EnumerateDomainAliases(builtinHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to enumerate local groups: %v\n", err)
			os.Exit(1)
		}
		for i, a := range aliases {
			fmt.Printf("  %d. %s\n", i+1, a.Name)
		}
	}
}

// resolveSidsViaLSA opens a separate LSA pipe to resolve SIDs to names.
func resolveSidsViaLSA(smbClient *smb.Client, sids []string) []lsarpc.LookupResult {
	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		return nil
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return nil
	}

	lsaClient, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		return nil
	}
	defer lsaClient.Close()

	results, err := lsaClient.LookupSids(sids)
	if err != nil {
		return nil
	}
	return results
}

// resolveNameToSID resolves an account name to a binary SID.
// First tries LSA LookupNames (handles cross-domain and well-known names),
// then falls back to SAMR LookupName + RidToSid for the current domain.
func resolveNameToSID(samrClient *samr.SamrClient, smbClient *smb.Client, name string) []byte {
	// Try LSA first
	sid := resolveNameViaLSA(smbClient, name)
	if sid != nil {
		return sid
	}

	// Fallback: SAMR lookup in current domain
	rid, err := samrClient.LookupName(name)
	if err != nil {
		return nil
	}
	return samrClient.RidToSid(rid)
}

// resolveNameViaLSA opens an LSA pipe and resolves a name to a binary SID.
func resolveNameViaLSA(smbClient *smb.Client, name string) []byte {
	pipe, err := smbClient.OpenPipe("lsarpc")
	if err != nil {
		return nil
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(lsarpc.UUID, lsarpc.MajorVersion, lsarpc.MinorVersion); err != nil {
		return nil
	}

	lsaClient, err := lsarpc.NewLsaClient(rpcClient)
	if err != nil {
		return nil
	}
	defer lsaClient.Close()

	results, err := lsaClient.LookupNames([]string{name})
	if err != nil {
		return nil
	}
	if len(results) > 0 && len(results[0].SID) > 0 {
		return results[0].SID
	}
	return nil
}

// setAccountDisabled enables or disables a user account.
func setAccountDisabled(samrClient *samr.SamrClient, name string, disabled bool) {
	rid, err := samrClient.LookupName(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Account '%s' not found: %v\n", name, err)
		os.Exit(1)
	}

	userHandle, err := samrClient.OpenUser(rid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open account: %v\n", err)
		os.Exit(1)
	}
	defer samrClient.CloseHandle(userHandle)

	info, err := samrClient.QueryUserInfo(userHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to query account info: %v\n", err)
		os.Exit(1)
	}

	var newUAC uint32
	if disabled {
		newUAC = info.UserAccountControl | samr.USER_ACCOUNT_DISABLED
	} else {
		newUAC = info.UserAccountControl &^ samr.USER_ACCOUNT_DISABLED
	}

	if err := samrClient.SetUserAccountControl(userHandle, newUAC); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to update account control: %v\n", err)
		os.Exit(1)
	}

	action := "enabled"
	if disabled {
		action = "disabled"
	}
	fmt.Printf("[+] Account '%s' %s successfully.\n", name, action)
}

// queryUserDetail queries and prints detailed user info.
func queryUserDetail(samrClient *samr.SamrClient, smbClient *smb.Client, domain, name string) {
	rid, err := samrClient.LookupName(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] User '%s' not found: %v\n", name, err)
		os.Exit(1)
	}

	userHandle, err := samrClient.OpenUser(rid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open user: %v\n", err)
		os.Exit(1)
	}
	defer samrClient.CloseHandle(userHandle)

	info, err := samrClient.QueryUserInfo(userHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to query user info: %v\n", err)
		os.Exit(1)
	}

	printUserInfo(name, rid, info)

	// Get local group (alias) memberships via Builtin domain
	var localGroupNames []string
	groupRids, err := samrClient.GetGroupsForUser(userHandle)

	builtinHandle, _, err2 := samrClient.OpenBuiltinDomain()
	if err2 == nil {
		defer samrClient.CloseHandle(builtinHandle)

		// Build SIDs: user SID + primary group SID (for transitive membership)
		userSid := samrClient.RidToSid(rid)
		sidsToCheck := [][]byte{userSid}
		if info.PrimaryGroupID != 0 {
			primaryGroupSid := samrClient.RidToSid(info.PrimaryGroupID)
			sidsToCheck = append(sidsToCheck, primaryGroupSid)
		}
		// Also include all global group SIDs for full transitive resolution
		if groupRids != nil {
			for _, gRid := range groupRids {
				sidsToCheck = append(sidsToCheck, samrClient.RidToSid(gRid))
			}
		}
		aliasRids, err := samrClient.GetAliasMembership(builtinHandle, sidsToCheck)
		if err == nil && len(aliasRids) > 0 {
			aliasNames, err := samrClient.LookupIdsInDomain(builtinHandle, aliasRids)
			if err == nil {
				localGroupNames = aliasNames
			}
		}
	}

	// Print local group memberships (Impacket format)
	fmt.Println("Local Group Memberships")
	for _, an := range localGroupNames {
		fmt.Printf("  * %s\n", an)
	}
	fmt.Println()

	// Print global group memberships (Impacket format: lowercase 'm' in "memberships")
	fmt.Println("Global Group memberships")
	if err == nil && len(groupRids) > 0 {
		groupNames, err := samrClient.LookupIds(groupRids)
		if err == nil {
			for _, gn := range groupNames {
				if gn != "" {
					fmt.Printf("  * %s\n", gn)
				}
			}
		}
	}
}

// formatFileTime formats a Windows FILETIME (100ns intervals since 1601-01-01) as a string.
// Uses Impacket's date format: MM/DD/YYYY HH:MM:SS AM/PM
func formatFileTime(ft int64) string {
	if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return "Never"
	}
	unixTime := (ft - 116444736000000000) / 10000000
	if unixTime < 0 || unixTime > 32503680000 { // sanity: before 1970 or after 3000
		return "Never"
	}
	t := time.Unix(unixTime, 0)
	// Impacket uses 24-hour clock with AM/PM suffix (Python %H:%M:%S %p)
	ampm := "AM"
	if t.Hour() >= 12 {
		ampm = "PM"
	}
	return t.Format("01/02/2006 15:04:05") + " " + ampm
}

// printUserInfo prints the standard user info fields, matching Impacket's net.py output format exactly.
func printUserInfo(name string, rid uint32, info *samr.UserAllInfo) {
	// Impacket uses 31-char left-padded field labels
	fmt.Printf("%-31s%s\n", "User name", name)
	fmt.Printf("%-31s%s\n", "Full name", info.FullName)
	fmt.Printf("%-31s%s\n", "Comment", info.AdminComment)
	fmt.Printf("%-31s%s\n", "User's comment", info.UserComment)
	fmt.Printf("%-31s%03d (System Default)\n", "Country/region code", info.CountryCode)

	accountActive := "Yes"
	if info.UserAccountControl&samr.USER_ACCOUNT_DISABLED != 0 {
		accountActive = "No"
	}
	fmt.Printf("%-31s%s\n", "Account active", accountActive)

	fmt.Printf("%-31s%s\n", "Account expires", formatFileTime(info.AccountExpires))
	fmt.Println()

	fmt.Printf("%-31s%s\n", "Password last set", formatFileTime(info.PasswordLastSet))

	// "Password expires": if DONT_EXPIRE is set, show "Never", otherwise show PasswordMustChange
	pwdExpires := "Never"
	if info.UserAccountControl&samr.USER_DONT_EXPIRE_PASSWORD == 0 {
		pwdExpires = formatFileTime(info.PasswordMustChange)
	}
	fmt.Printf("%-31s%s\n", "Password expires", pwdExpires)

	fmt.Printf("%-31s%s\n", "Password changeable", formatFileTime(info.PasswordCanChange))

	pwdRequired := "Yes"
	if info.UserAccountControl&samr.USER_PASSWORD_NOT_REQUIRED != 0 {
		pwdRequired = "No"
	}
	fmt.Printf("%-31s%s\n", "Password required", pwdRequired)

	mayChangePwd := "Yes"
	if info.PasswordCanChange == 0 || info.PasswordCanChange == 0x7FFFFFFFFFFFFFFF {
		mayChangePwd = "No"
	}
	fmt.Printf("%-31s%s\n", "User may change password", mayChangePwd)
	fmt.Println()

	workstations := info.WorkStations
	if workstations == "" {
		workstations = "All"
	}
	fmt.Printf("%-31s%s\n", "Workstations allowed", workstations)
	fmt.Printf("%-31s%s\n", "Logon script", info.ScriptPath)
	fmt.Printf("%-31s%s\n", "User profile", info.ProfilePath)
	fmt.Printf("%-31s%s\n", "Home directory", info.HomeDirectory)
	fmt.Printf("%-31s%s\n", "Last logon", formatFileTime(info.LastLogon))
	fmt.Printf("%-31s%d\n", "Logon count", info.LogonCount)
	fmt.Println()
	fmt.Printf("%-31s%s\n", "Logon hours allowed", "All")
	fmt.Println()
}
