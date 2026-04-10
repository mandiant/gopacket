// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package ldap

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// UserAccountControl flags for delegation
const (
	UF_ACCOUNTDISABLE                         = 0x00000002
	UF_TRUSTED_FOR_DELEGATION                 = 0x00080000 // Unconstrained delegation
	UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000 // Protocol transition
)

// DelegationType represents the type of delegation configured
type DelegationType string

const (
	DelegationUnconstrained                DelegationType = "Unconstrained"
	DelegationConstrainedWithTransition    DelegationType = "Constrained w/ Protocol Transition"
	DelegationConstrainedWithoutTransition DelegationType = "Constrained"
	DelegationResourceBased                DelegationType = "Resource-Based Constrained"
)

// DelegationEntry represents a delegation relationship found in AD
type DelegationEntry struct {
	AccountName    string
	AccountType    string // Computer, User, etc.
	DelegationType DelegationType
	DelegationTo   string // The target of delegation rights (SPN or account name)
	SPNExists      string // "Yes", "No", or "-"
}

// FindDelegation searches for all delegation relationships in the domain.
// includeDisabled: if true, includes disabled accounts in results
// specificUser: if not empty, filters results to this specific sAMAccountName
func (c *Client) FindDelegation(baseDN string, includeDisabled bool, specificUser string) ([]DelegationEntry, error) {
	// Build search filter for accounts with any type of delegation
	// - UserAccountControl:1.2.840.113556.1.4.803:=16777216 (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
	// - UserAccountControl:1.2.840.113556.1.4.803:=524288 (TRUSTED_FOR_DELEGATION)
	// - msDS-AllowedToDelegateTo=* (Constrained delegation targets)
	// - msDS-AllowedToActOnBehalfOfOtherIdentity=* (RBCD)

	searchFilter := "(&(|(UserAccountControl:1.2.840.113556.1.4.803:=16777216)(UserAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"

	// Add disabled filter - only exclude disabled accounts if includeDisabled is false
	if !includeDisabled {
		searchFilter += "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
	}

	// Add specific user filter
	if specificUser != "" {
		searchFilter += fmt.Sprintf("(sAMAccountName=%s))", specificUser)
	} else {
		searchFilter += ")"
	}

	attributes := []string{
		"sAMAccountName",
		"userAccountControl",
		"objectCategory",
		"msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
	}

	results, err := c.SearchWithPaging(baseDN, searchFilter, attributes, 999)
	if err != nil {
		return nil, err
	}

	var entries []DelegationEntry

	for _, entry := range results.Entries {
		sAMAccountName := entry.GetAttributeValue("sAMAccountName")
		uacStr := entry.GetAttributeValue("userAccountControl")
		objectCategory := entry.GetAttributeValue("objectCategory")
		allowedToDelegateTo := entry.GetAttributeValues("msDS-AllowedToDelegateTo")
		rbcdData := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")

		// Extract object type from objectCategory (e.g., "CN=Computer,CN=Schema,..." -> "Computer")
		objectType := "Unknown"
		if objectCategory != "" {
			parts := strings.Split(objectCategory, ",")
			if len(parts) > 0 {
				objectType = strings.TrimPrefix(parts[0], "CN=")
			}
		}

		// Parse userAccountControl
		var uac int64
		if uacStr != "" {
			uac, _ = strconv.ParseInt(uacStr, 10, 64)
		}

		// Determine delegation type from UAC flags
		isUnconstrained := uac&UF_TRUSTED_FOR_DELEGATION != 0
		hasProtocolTransition := uac&UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION != 0

		// Process unconstrained delegation
		if isUnconstrained {
			spnExists := c.checkSPNExists(baseDN, fmt.Sprintf("HOST/%s", strings.TrimSuffix(sAMAccountName, "$")))
			entries = append(entries, DelegationEntry{
				AccountName:    sAMAccountName,
				AccountType:    objectType,
				DelegationType: DelegationUnconstrained,
				DelegationTo:   "N/A",
				SPNExists:      spnExists,
			})
		}

		// Process constrained delegation (msDS-AllowedToDelegateTo)
		if len(allowedToDelegateTo) > 0 {
			delegationType := DelegationConstrainedWithoutTransition
			if hasProtocolTransition {
				delegationType = DelegationConstrainedWithTransition
			}

			for _, target := range allowedToDelegateTo {
				spnExists := c.checkSPNExists(baseDN, target)
				entries = append(entries, DelegationEntry{
					AccountName:    sAMAccountName,
					AccountType:    objectType,
					DelegationType: delegationType,
					DelegationTo:   target,
					SPNExists:      spnExists,
				})
			}
		}

		// Process Resource-Based Constrained Delegation (RBCD)
		if len(rbcdData) > 0 {
			// Parse the security descriptor to extract SIDs
			sids := parseSecurityDescriptorSIDs(rbcdData)

			for _, sid := range sids {
				// Look up the account name for this SID
				accountName, accountType := c.lookupSID(baseDN, sid, includeDisabled)
				if accountName != "" {
					spnExists := c.checkSPNExists(baseDN, fmt.Sprintf("HOST/%s", strings.TrimSuffix(accountName, "$")))
					entries = append(entries, DelegationEntry{
						AccountName:    accountName,
						AccountType:    accountType,
						DelegationType: DelegationResourceBased,
						DelegationTo:   sAMAccountName, // RBCD: the account in the attribute can delegate TO this account
						SPNExists:      spnExists,
					})
				}
			}
		}
	}

	return entries, nil
}

// checkSPNExists checks if an SPN exists in the directory
func (c *Client) checkSPNExists(baseDN, spn string) string {
	filter := fmt.Sprintf("(servicePrincipalName=%s)", escapeLDAPFilter(spn))
	results, err := c.Search(baseDN, filter, []string{"distinguishedName"})
	if err != nil || len(results.Entries) == 0 {
		return "No"
	}
	return "Yes"
}

// lookupSID looks up an account by SID and returns (sAMAccountName, objectType)
func (c *Client) lookupSID(baseDN, sid string, includeDisabled bool) (string, string) {
	filter := fmt.Sprintf("(objectSid=%s)", sid)
	if !includeDisabled {
		filter = fmt.Sprintf("(&(objectSid=%s)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", sid)
	}

	results, err := c.Search(baseDN, filter, []string{"sAMAccountName", "objectCategory"})
	if err != nil || len(results.Entries) == 0 {
		return "", ""
	}

	entry := results.Entries[0]
	accountName := entry.GetAttributeValue("sAMAccountName")
	objectCategory := entry.GetAttributeValue("objectCategory")

	objectType := "Unknown"
	if objectCategory != "" {
		parts := strings.Split(objectCategory, ",")
		if len(parts) > 0 {
			objectType = strings.TrimPrefix(parts[0], "CN=")
		}
	}

	return accountName, objectType
}

// parseSecurityDescriptorSIDs parses an NT Security Descriptor and extracts SIDs from the DACL
func parseSecurityDescriptorSIDs(data []byte) []string {
	var sids []string

	if len(data) < 20 {
		return sids
	}

	// Security Descriptor structure (simplified):
	// Offset 0: Revision (1 byte)
	// Offset 1: Sbz1 (1 byte)
	// Offset 2: Control (2 bytes)
	// Offset 4: OffsetOwner (4 bytes)
	// Offset 8: OffsetGroup (4 bytes)
	// Offset 12: OffsetSacl (4 bytes)
	// Offset 16: OffsetDacl (4 bytes)

	daclOffset := binary.LittleEndian.Uint32(data[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(data) {
		return sids
	}

	// ACL structure:
	// Offset 0: AclRevision (1 byte)
	// Offset 1: Sbz1 (1 byte)
	// Offset 2: AclSize (2 bytes)
	// Offset 4: AceCount (2 bytes)
	// Offset 6: Sbz2 (2 bytes)
	// Offset 8: ACEs start

	dacl := data[daclOffset:]
	if len(dacl) < 8 {
		return sids
	}

	aceCount := binary.LittleEndian.Uint16(dacl[4:6])
	aceOffset := uint32(8)

	for i := uint16(0); i < aceCount && int(aceOffset) < len(dacl); i++ {
		if int(aceOffset)+4 > len(dacl) {
			break
		}

		// ACE structure:
		// Offset 0: AceType (1 byte)
		// Offset 1: AceFlags (1 byte)
		// Offset 2: AceSize (2 bytes)
		// Offset 4: Mask (4 bytes) - for ACCESS_ALLOWED_ACE
		// Offset 8: SID starts

		aceSize := binary.LittleEndian.Uint16(dacl[aceOffset+2 : aceOffset+4])
		if aceSize == 0 {
			break
		}

		// ACCESS_ALLOWED_ACE_TYPE = 0x00
		aceType := dacl[aceOffset]
		if aceType == 0x00 && int(aceOffset)+8 < len(dacl) {
			// Extract SID
			sidOffset := aceOffset + 8
			sid := parseSID(dacl[sidOffset:])
			if sid != "" {
				sids = append(sids, sid)
			}
		}

		aceOffset += uint32(aceSize)
	}

	return sids
}

// parseSID parses a binary SID and returns its string representation (S-1-5-21-...)
func parseSID(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := data[1]

	if len(data) < 8+int(subAuthCount)*4 {
		return ""
	}

	// Identifier Authority (6 bytes, big-endian)
	var identAuth uint64
	for i := 0; i < 6; i++ {
		identAuth = (identAuth << 8) | uint64(data[2+i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, identAuth)

	// Sub-authorities (4 bytes each, little-endian)
	for i := uint8(0); i < subAuthCount; i++ {
		offset := 8 + int(i)*4
		subAuth := binary.LittleEndian.Uint32(data[offset : offset+4])
		sid = fmt.Sprintf("%s-%d", sid, subAuth)
	}

	return sid
}

// escapeLDAPFilter escapes special characters in LDAP filter values
func escapeLDAPFilter(s string) string {
	// Escape special LDAP filter characters: * ( ) \ NUL
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
	)
	return replacer.Replace(s)
}
