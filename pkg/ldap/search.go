// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"fmt"

	goldap "github.com/go-ldap/ldap/v3"
)

// Search performs a generic LDAP search.
func (c *Client) Search(baseDN string, filter string, attributes []string) (*goldap.SearchResult, error) {
	if c.Conn == nil {
		return nil, fmt.Errorf("connection not established")
	}

	searchRequest := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree, // Scope
		goldap.NeverDerefAliases, // DerefAliases
		0,                        // SizeLimit (0 = no limit)
		0,                        // TimeLimit (0 = no limit)
		false,                    // TypesOnly
		filter,                   // Filter
		attributes,               // Attributes
		nil,                      // Controls
	)

	return c.Conn.Search(searchRequest)
}

// SearchWithControls performs an LDAP search with the specified controls.
func (c *Client) SearchWithControls(baseDN string, filter string, attributes []string, controls []goldap.Control) (*goldap.SearchResult, error) {
	if c.Conn == nil {
		return nil, fmt.Errorf("connection not established")
	}

	searchRequest := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		controls,
	)

	return c.Conn.Search(searchRequest)
}

// SearchWithPaging performs an LDAP search with paging support for large result sets.
func (c *Client) SearchWithPaging(baseDN string, filter string, attributes []string, pageSize uint32) (*goldap.SearchResult, error) {
	if c.Conn == nil {
		return nil, fmt.Errorf("connection not established")
	}

	searchRequest := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	return c.Conn.SearchWithPaging(searchRequest, pageSize)
}

// SearchBase performs an LDAP search at BASE scope (single object).
func (c *Client) SearchBase(baseDN string, filter string, attributes []string) (*goldap.SearchResult, error) {
	if c.Conn == nil {
		return nil, fmt.Errorf("connection not established")
	}

	searchRequest := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	return c.Conn.Search(searchRequest)
}

// GetDefaultNamingContext retrieves the root domain context (e.g., DC=corp,DC=local).
func (c *Client) GetDefaultNamingContext() (string, error) {
	// Query the RootDSE
	searchRequest := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := c.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) != 1 {
		return "", fmt.Errorf("failed to retrieve RootDSE")
	}

	return sr.Entries[0].GetAttributeValue("defaultNamingContext"), nil
}

// GetSchemaNamingContext returns the schema naming context from the RootDSE.
func (c *Client) GetSchemaNamingContext() (string, error) {
	searchRequest := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"schemaNamingContext"},
		nil,
	)

	sr, err := c.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) != 1 {
		return "", fmt.Errorf("failed to retrieve RootDSE")
	}

	return sr.Entries[0].GetAttributeValue("schemaNamingContext"), nil
}
