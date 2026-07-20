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
