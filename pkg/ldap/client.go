// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	goldap "github.com/go-ldap/ldap/v3"
	"gopacket/pkg/session"
	"gopacket/pkg/transport"
)

// Client wraps the underlying LDAP connection to provide a unified interface.
type Client struct {
	Conn    *goldap.Conn
	Target  session.Target
	Session *session.Credentials
	dialer  *transport.Dialer
}

// NewClient creates a new LDAP client instance.
func NewClient(target session.Target, creds *session.Credentials) *Client {
	return &Client{
		Target:  target,
		Session: creds,
		dialer:  &transport.Dialer{},
	}
}

// Close terminates the LDAP connection.
func (c *Client) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}
