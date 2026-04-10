// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"fmt"
	"net"
	"strings"
)

// SessionData holds NTLM challenge data from the original relay handshake,
// replayed to SOCKS clients during skipAuthentication.
// Matches Impacket's sessionData dict stored in activeRelays.
type SessionData struct {
	// ChallengeMessage is the raw NTLM Type2 challenge from the target.
	// Used by SMB and LDAP plugins to present to SOCKS clients.
	ChallengeMessage []byte

	// MSSQLChallengeTDS is the full TDS packet containing the NTLM challenge.
	// Used by the MSSQL plugin.
	MSSQLChallengeTDS []byte

	// MSSQLAuthAnswer is the TDS LOGIN_ACK response from the real server.
	// Replayed to SOCKS clients after fake auth.
	MSSQLAuthAnswer []byte
}

// SOCKSPlugin defines the interface for protocol-aware SOCKS proxy plugins.
// Each plugin handles the protocol-specific authentication faking and tunneling
// for a particular protocol (SMB, LDAP, HTTP, MSSQL).
// Matches Impacket's SocksRelay base class in socksserver.py.
type SOCKSPlugin interface {
	// InitConnection performs any protocol-specific connection setup
	// (e.g., wrapping the socket in a framing layer).
	InitConnection(clientConn net.Conn) error

	// SkipAuthentication fakes the protocol-level authentication with the SOCKS client.
	// It replays the stored NTLM challenge, extracts the username from the client's
	// response, and looks up the corresponding relay session.
	// Returns the matched username (for InUse tracking) and any error.
	SkipAuthentication(clientConn net.Conn, sessionData *SessionData, lookupRelay func(username string) *ActiveRelay) (string, error)

	// TunnelConnection proxies traffic between the SOCKS client and the relayed target.
	// Protocol-specific: handles message framing, strips signing, intercepts logoff, etc.
	TunnelConnection(clientConn net.Conn, relay *ActiveRelay) error
}

// socksPlugins maps scheme names to plugin factory functions.
var socksPlugins = map[string]func() SOCKSPlugin{
	"smb":   func() SOCKSPlugin { return &SMBSocksPlugin{} },
	"ldap":  func() SOCKSPlugin { return &LDAPSocksPlugin{} },
	"ldaps": func() SOCKSPlugin { return &LDAPSocksPlugin{useTLS: true} },
	"http":  func() SOCKSPlugin { return &HTTPSocksPlugin{} },
	"https": func() SOCKSPlugin { return &HTTPSocksPlugin{} },
	"mssql": func() SOCKSPlugin { return &MSSQLSocksPlugin{} },
}

// getPluginForScheme returns a new SOCKSPlugin instance for the given scheme.
func getPluginForScheme(scheme string) (SOCKSPlugin, error) {
	factory, ok := socksPlugins[scheme]
	if !ok {
		return nil, fmt.Errorf("no SOCKS plugin for scheme %q", scheme)
	}
	return factory(), nil
}

// getSchemeForTarget looks up the scheme from active relays for a given host:port.
func (s *SOCKSServer) getSchemeForTarget(host string, port int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", host, port)
	users, ok := s.activeRelays[key]
	if !ok {
		return ""
	}
	for _, relay := range users {
		return relay.Scheme
	}
	return ""
}

// GetRelayByUsername finds an active relay for the given target and username.
// Tries both "DOMAIN\USER" and "DOMAIN_NETBIOS\USER" formats (Impacket does both).
func (s *SOCKSServer) GetRelayByUsername(host string, port int, username string) *ActiveRelay {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", host, port)
	users, ok := s.activeRelays[key]
	if !ok {
		// Try without port (some schemes use default ports)
		return nil
	}

	// Exact match (already uppercased by caller)
	if relay, ok := users[username]; ok {
		return relay
	}

	return nil
}

// GetSessionData returns the SessionData for a given target.
func (s *SOCKSServer) GetSessionData(host string, port int) *SessionData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", host, port)
	sd, ok := s.sessionData[key]
	if !ok {
		return nil
	}
	return sd
}

// normalizeUsername converts backslash separators and ensures uppercase for matching.
func normalizeUsername(username string) string {
	return strings.ToUpper(strings.Replace(username, "/", "\\", 1))
}
