// SPDX-License-Identifier: Apache-2.0

package session

import (
	"fmt"
	"net"
)

// Target represents the remote system we are interacting with.
type Target struct {
	Host string
	IP   string // Optional: Connection IP if different from Host (e.g. for Kerberos with DNS issues)
	Port int
	IPv6 bool // Prefer IPv6 connections
}

// Addr returns the connection address, preferring IP if set.
// Uses net.JoinHostPort to correctly handle IPv6 addresses (e.g. [::1]:445).
func (t Target) Addr() string {
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", t.Port))
}

// Network returns the network string for net.Dial.
// Returns "tcp6" when IPv6 is requested, "tcp" otherwise.
func (t Target) Network() string {
	if t.IPv6 {
		return "tcp6"
	}
	return "tcp"
}
