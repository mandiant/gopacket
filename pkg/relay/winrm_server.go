// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"log"
)

// WinRMRelayServer wraps an HTTPRelayServer on port 5985 for WinRM relay.
// WinRM uses HTTP+NTLM on /wsman — identical to existing HTTP server.
// Matches Impacket's winrmrelayserver.py.
type WinRMRelayServer struct {
	httpServer *HTTPRelayServer
}

// NewWinRMRelayServer creates a new WinRM relay server on the given address.
func NewWinRMRelayServer(listenAddr string, config *Config) *WinRMRelayServer {
	return &WinRMRelayServer{
		httpServer: NewHTTPRelayServer(listenAddr, config),
	}
}

// Start begins listening for WinRM (HTTP) connections, implements ProtocolServer.
func (s *WinRMRelayServer) Start(resultChan chan<- AuthResult) error {
	if err := s.httpServer.Start(resultChan); err != nil {
		return err
	}
	// Override the log message to indicate WinRM
	log.Printf("[*] WinRM relay server listening on %s", s.httpServer.listenAddr)
	return nil
}

// Stop closes the WinRM server, implements ProtocolServer.
func (s *WinRMRelayServer) Stop() error {
	return s.httpServer.Stop()
}

// WinRMSRelayServer wraps an HTTPSRelayServer on port 5986 for WinRM over HTTPS.
type WinRMSRelayServer struct {
	httpsServer *HTTPSRelayServer
}

// NewWinRMSRelayServer creates a new WinRM over HTTPS relay server.
func NewWinRMSRelayServer(listenAddr string, config *Config) (*WinRMSRelayServer, error) {
	httpsServer, err := NewHTTPSRelayServer(listenAddr, config)
	if err != nil {
		return nil, err
	}
	return &WinRMSRelayServer{httpsServer: httpsServer}, nil
}

// Start begins listening for WinRM (HTTPS) connections, implements ProtocolServer.
func (s *WinRMSRelayServer) Start(resultChan chan<- AuthResult) error {
	if err := s.httpsServer.Start(resultChan); err != nil {
		return err
	}
	log.Printf("[*] WinRMS relay server listening on %s", s.httpsServer.listenAddr)
	return nil
}

// Stop closes the WinRMS server, implements ProtocolServer.
func (s *WinRMSRelayServer) Stop() error {
	return s.httpsServer.Stop()
}
