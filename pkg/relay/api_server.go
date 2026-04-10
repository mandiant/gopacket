// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
)

// APIServer exposes relay session data as a REST API, matching Impacket's
// Flask server on port 9090 when SOCKS mode is enabled.
type APIServer struct {
	addr     string
	listener net.Listener
	socks    *SOCKSServer
	server   *http.Server
}

// NewAPIServer creates a new REST API server.
func NewAPIServer(addr string, socks *SOCKSServer) *APIServer {
	return &APIServer{
		addr:  addr,
		socks: socks,
	}
}

// Start begins serving the REST API in a background goroutine.
func (a *APIServer) Start() error {
	listener, err := net.Listen("tcp", a.addr)
	if err != nil {
		return fmt.Errorf("REST API listen on %s: %v", a.addr, err)
	}
	a.listener = listener

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleRoot)
	mux.HandleFunc("/ntlmrelayx/api/v1.0/relays", a.handleRelays)

	a.server = &http.Server{Handler: mux}

	log.Printf("[*] REST API started on %s", a.addr)
	go a.server.Serve(listener)
	return nil
}

// Stop shuts down the REST API server.
func (a *APIServer) Stop() {
	if a.server != nil {
		a.server.Close()
	}
}

// handleRoot serves "Relays available: N!" matching Impacket's index route.
func (a *APIServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	relays := a.socks.ListRelayDetails()
	fmt.Fprintf(w, "Relays available: %d!", len(relays))
}

// handleRelays returns relay sessions as a JSON array-of-arrays matching
// Impacket's /ntlmrelayx/api/v1.0/relays format:
//
//	[["SMB","192.168.1.100","DOMAIN\\COMPUTER$","TRUE","445","0"],...]
func (a *APIServer) handleRelays(w http.ResponseWriter, r *http.Request) {
	relays := a.socks.ListRelayDetails()

	result := make([][]string, 0, len(relays))
	for _, ri := range relays {
		result = append(result, []string{
			ri.Protocol,
			ri.Target,
			ri.Username,
			ri.AdminStatus,
			ri.Port,
			"0", // client_id placeholder — matches Impacket's 6-field format
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
