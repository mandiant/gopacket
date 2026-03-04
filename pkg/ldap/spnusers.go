package ldap

import (
	"strconv"
	"time"
)

// UserSPN represents a user account with Service Principal Names set.
type UserSPN struct {
	Username    string
	DN          string
	SPNs        []string
	MemberOf    string
	PwdLastSet  time.Time
	LastLogon   time.Time
	Delegation  string
}

// SPNQueryOptions controls how the SPN user search is performed.
type SPNQueryOptions struct {
	Stealth     bool // Remove servicePrincipalName=* filter (stealth mode)
	MachineOnly bool // Query computer accounts instead of person accounts
}

// FindSPNUsers searches for user accounts with servicePrincipalName attribute set.
// This is used for Kerberoasting - these accounts can have their TGS tickets requested
// and cracked offline.
func (c *Client) FindSPNUsers(baseDN string) ([]UserSPN, error) {
	return c.FindSPNUsersWithOptions(baseDN, SPNQueryOptions{})
}

// FindSPNUsersWithOptions searches for accounts with SPNs using the given options.
// When Stealth is true, the servicePrincipalName=* filter is omitted (pulls all accounts,
// filters client-side). When MachineOnly is true, objectCategory=computer is used instead
// of objectCategory=person.
func (c *Client) FindSPNUsersWithOptions(baseDN string, opts SPNQueryOptions) ([]UserSPN, error) {
	// Build the LDAP filter based on options
	var filter string
	if opts.MachineOnly {
		if opts.Stealth {
			// Computer accounts, no SPN filter
			filter = "(&(objectCategory=computer)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		} else {
			filter = "(&(objectCategory=computer)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		}
	} else {
		if opts.Stealth {
			// Person accounts, no SPN filter — stealth mode
			filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		} else {
			// Default: person accounts with SPN set, excluding disabled
			filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		}
	}

	attributes := []string{
		"sAMAccountName",
		"distinguishedName",
		"servicePrincipalName",
		"memberOf",
		"pwdLastSet",
		"lastLogon",
		"userAccountControl",
	}

	results, err := c.Search(baseDN, filter, attributes)
	if err != nil {
		return nil, err
	}

	var users []UserSPN
	for _, entry := range results.Entries {
		spns := entry.GetAttributeValues("servicePrincipalName")

		// In stealth mode, skip entries that have no SPNs (client-side filter)
		if opts.Stealth && len(spns) == 0 {
			continue
		}

		user := UserSPN{
			Username: entry.GetAttributeValue("sAMAccountName"),
			DN:       entry.GetAttributeValue("distinguishedName"),
			SPNs:     spns,
			MemberOf: entry.GetAttributeValue("memberOf"),
		}

		// Parse pwdLastSet (Windows FILETIME)
		if pwdLastSetStr := entry.GetAttributeValue("pwdLastSet"); pwdLastSetStr != "" {
			if pwdLastSet, err := strconv.ParseInt(pwdLastSetStr, 10, 64); err == nil && pwdLastSet > 0 {
				user.PwdLastSet = filetimeToTime(pwdLastSet)
			}
		}

		// Parse lastLogon (Windows FILETIME)
		if lastLogonStr := entry.GetAttributeValue("lastLogon"); lastLogonStr != "" {
			if lastLogon, err := strconv.ParseInt(lastLogonStr, 10, 64); err == nil && lastLogon > 0 {
				user.LastLogon = filetimeToTime(lastLogon)
			}
		}

		// Check delegation flags
		if uacStr := entry.GetAttributeValue("userAccountControl"); uacStr != "" {
			if uac, err := strconv.ParseInt(uacStr, 10, 64); err == nil {
				if uac&0x80000 != 0 { // TRUSTED_FOR_DELEGATION
					user.Delegation = "unconstrained"
				} else if uac&0x1000000 != 0 { // TRUSTED_TO_AUTH_FOR_DELEGATION
					user.Delegation = "constrained"
				}
			}
		}

		users = append(users, user)
	}
	return users, nil
}

// filetimeToTime converts Windows FILETIME to Go time.Time
func filetimeToTime(ft int64) time.Time {
	// Windows FILETIME is 100-nanosecond intervals since January 1, 1601
	// Unix epoch is January 1, 1970
	// Difference is 116444736000000000 100-nanosecond intervals
	const epochDiff = 116444736000000000
	if ft <= epochDiff {
		return time.Time{}
	}
	nsec := (ft - epochDiff) * 100
	return time.Unix(0, nsec)
}
