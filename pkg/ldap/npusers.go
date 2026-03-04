package ldap

// UserNP represents a user who might not require pre-authentication.
type UserNP struct {
	Username string
	DN       string
}

// FindNPUsers searches for users with the UF_DONT_REQUIRE_PREAUTH flag (0x400000) set.
func (c *Client) FindNPUsers(baseDN string) ([]UserNP, error) {
	// Filter for users where (userAccountControl & 4194304) is true
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{"sAMAccountName", "distinguishedName"}

	results, err := c.Search(baseDN, filter, attributes)
	if err != nil {
		return nil, err
	}

	var users []UserNP
	for _, entry := range results.Entries {
		users = append(users, UserNP{
			Username: entry.GetAttributeValue("sAMAccountName"),
			DN:       entry.GetAttributeValue("distinguishedName"),
		})
	}
	return users, nil
}
