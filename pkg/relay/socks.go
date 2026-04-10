// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopacket/internal/build"
)

// SOCKSServer implements a SOCKS5 proxy that routes connections through relayed sessions.
// Uses protocol-aware plugins (SMB, LDAP, HTTP, MSSQL) to fake authentication and
// tunnel traffic, matching Impacket's socksserver.py + socksplugins/ architecture.
type SOCKSServer struct {
	addr     string
	listener net.Listener
	mu       sync.RWMutex
	// activeRelays maps "targetHost:targetPort" -> map["DOMAIN\USER" (uppercased)] -> *ActiveRelay
	activeRelays map[string]map[string]*ActiveRelay
	// sessionData maps "targetHost:targetPort" -> *SessionData (shared NTLM challenge data)
	sessionData map[string]*SessionData
	stopCh      chan struct{}
}

// ActiveRelay represents a relayed session available for SOCKS proxying.
type ActiveRelay struct {
	Target   string // host:port
	Username string // DOMAIN\user
	Scheme   string // smb, ldap, ldaps, http, https, mssql
	Client   ProtocolClient
	LastUsed time.Time
	InUse    bool // true when a SOCKS client is actively using this relay
	mu       sync.Mutex
}

// NewSOCKSServer creates a new SOCKS5 proxy server.
func NewSOCKSServer(addr string) *SOCKSServer {
	return &SOCKSServer{
		addr:         addr,
		activeRelays: make(map[string]map[string]*ActiveRelay),
		sessionData:  make(map[string]*SessionData),
		stopCh:       make(chan struct{}),
	}
}

// Start begins listening for SOCKS5 connections.
func (s *SOCKSServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen on %s: %v", s.addr, err)
	}
	s.listener = listener
	log.Printf("[*] SOCKS5 proxy started on %s", s.addr)

	go s.acceptLoop()
	go s.keepAliveLoop()
	return nil
}

// Stop shuts down the SOCKS5 server.
func (s *SOCKSServer) Stop() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
}

// AddRelay registers a new relayed session for SOCKS proxying.
func (s *SOCKSServer) AddRelay(target, username, scheme string, client ProtocolClient, sd *SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := normalizeTarget(target, scheme)
	userKey := strings.ToUpper(username)

	if _, ok := s.activeRelays[key]; !ok {
		s.activeRelays[key] = make(map[string]*ActiveRelay)
	}

	// If a relay for this username already exists, discard the new connection (Impacket behavior:
	// keeps the existing session alive and kills the incoming duplicate)
	if _, ok := s.activeRelays[key][userKey]; ok {
		log.Printf("[*] SOCKS: Relay for %s at %s already exists. Discarding", username, target)
		client.Kill()
		return
	}

	s.activeRelays[key][userKey] = &ActiveRelay{
		Target:   target,
		Username: username,
		Scheme:   scheme,
		Client:   client,
		LastUsed: time.Now(),
	}

	// Store session data at target level (shared across users for same target)
	if sd != nil {
		s.sessionData[key] = sd
	}

	log.Printf("[*] SOCKS: Added relay %s -> %s as %s", scheme, target, username)
}

// GetRelay finds an active relay for the given target.
func (s *SOCKSServer) GetRelay(host string, port int) *ActiveRelay {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", host, port)

	users, ok := s.activeRelays[key]
	if !ok {
		return nil
	}

	// Return first available relay (Impacket does the same)
	for _, relay := range users {
		return relay
	}
	return nil
}

// ListRelays returns all active relays for display.
func (s *SOCKSServer) ListRelays() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []string
	for target, users := range s.activeRelays {
		for user, relay := range users {
			result = append(result, fmt.Sprintf("%s -> %s (%s) [%s]",
				relay.Scheme, target, user, time.Since(relay.LastUsed).Round(time.Second)))
		}
	}
	return result
}

// RelayInfo holds structured relay session info for console display.
type RelayInfo struct {
	Protocol    string // "SMB", "LDAP", etc.
	Target      string // host IP/name
	Username    string // "DOMAIN\user"
	AdminStatus string // "TRUE", "FALSE", "N/A"
	Port        string // "445"
}

// ListRelayDetails returns structured relay info matching Impacket's API format.
func (s *SOCKSServer) ListRelayDetails() []RelayInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []RelayInfo
	for target, users := range s.activeRelays {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			host = target
			portStr = "0"
		}

		for _, relay := range users {
			protocol := strings.ToUpper(relay.Scheme)

			adminStatus := "N/A"
			if relay.Client != nil {
				if relay.Client.IsAdmin() {
					adminStatus = "TRUE"
				} else {
					adminStatus = "FALSE"
				}
			}

			result = append(result, RelayInfo{
				Protocol:    protocol,
				Target:      host,
				Username:    relay.Username,
				AdminStatus: adminStatus,
				Port:        portStr,
			})
		}
	}
	return result
}

func normalizeTarget(target, scheme string) string {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = DefaultPort(scheme)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (s *SOCKSServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				if build.Debug {
					log.Printf("[D] SOCKS: accept error: %v", err)
				}
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKSServer) keepAliveLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Collect dead relays under RLock, then delete under Lock
			type deadRelay struct {
				target string
				user   string
			}
			var dead []deadRelay

			s.mu.RLock()
			for target, users := range s.activeRelays {
				for user, relay := range users {
					relay.mu.Lock()
					inUse := relay.InUse
					relay.mu.Unlock()
					if inUse {
						continue
					}

					if err := relay.Client.KeepAlive(); err != nil {
						if build.Debug {
							log.Printf("[D] SOCKS: keepalive failed for %s@%s: %v", user, target, err)
						}
						dead = append(dead, deadRelay{target, user})
					}
				}
			}
			s.mu.RUnlock()

			// Remove dead relays under write lock
			if len(dead) > 0 {
				s.mu.Lock()
				for _, d := range dead {
					if users, ok := s.activeRelays[d.target]; ok {
						delete(users, d.user)
						if len(users) == 0 {
							delete(s.activeRelays, d.target)
						}
					}
				}
				s.mu.Unlock()
			}
		}
	}
}

// handleConnection implements the SOCKS5 protocol handshake and dispatches to plugins.
func (s *SOCKSServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	version := buf[0]
	if version != 0x05 {
		if build.Debug {
			log.Printf("[D] SOCKS: unsupported version %d", version)
		}
		return
	}

	// Reply: no authentication required
	conn.Write([]byte{0x05, 0x00})

	// SOCKS5 request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Parse request
	cmd := buf[1]
	if cmd != 0x01 { // CONNECT
		// Send failure reply
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	addrType := buf[3]
	var targetHost string
	var targetPort int
	var addrEnd int

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetHost = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = int(binary.BigEndian.Uint16(buf[8:10]))
		addrEnd = 10
	case 0x03: // Domain name
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetHost = string(buf[5 : 5+domainLen])
		targetPort = int(binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen]))
		addrEnd = 7 + domainLen
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[20:22]))
		addrEnd = 22
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = addrEnd

	if build.Debug {
		log.Printf("[D] SOCKS: CONNECT request to %s:%d", targetHost, targetPort)
	}

	// DNS pass-through: port 53 connections bypass relay lookup and connect directly.
	// Matches Impacket's socksserver.py which forwards DNS traffic transparently.
	if targetPort == 53 {
		s.handleDNSPassthrough(conn, targetHost, targetPort)
		return
	}

	// Check if we have any relays for this target
	scheme := s.getSchemeForTarget(targetHost, targetPort)
	if scheme == "" {
		log.Printf("[*] SOCKS: No relay available for %s:%d", targetHost, targetPort)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Get session data for this target
	sd := s.GetSessionData(targetHost, targetPort)

	// Get plugin for this protocol
	plugin, err := getPluginForScheme(scheme)
	if err != nil {
		log.Printf("[-] SOCKS: %v", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	log.Printf("[*] SOCKS: %s CONNECT to %s:%d — dispatching to %s plugin", conn.RemoteAddr(), targetHost, targetPort, strings.ToUpper(scheme))

	// Send success reply (SOCKS handshake complete)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)

	conn.SetDeadline(time.Time{}) // Remove deadline for protocol handling

	// Initialize plugin connection (protocol-specific framing setup)
	if err := plugin.InitConnection(conn); err != nil {
		log.Printf("[-] SOCKS: %s initConnection failed: %v", strings.ToUpper(scheme), err)
		return
	}

	// Run skipAuthentication — fakes protocol-level auth with the SOCKS client
	// and looks up the relay session by username
	lookupRelay := func(username string) *ActiveRelay {
		return s.GetRelayByUsername(targetHost, targetPort, username)
	}

	matchedUser, err := plugin.SkipAuthentication(conn, sd, lookupRelay)
	if err != nil {
		log.Printf("[-] SOCKS: %s skipAuthentication failed for %s:%d: %v",
			strings.ToUpper(scheme), targetHost, targetPort, err)
		return
	}

	// Find the relay and mark it as in use
	relay := s.GetRelayByUsername(targetHost, targetPort, strings.ToUpper(matchedUser))
	if relay == nil {
		log.Printf("[-] SOCKS: relay disappeared for %s after auth", matchedUser)
		return
	}

	relay.mu.Lock()
	relay.InUse = true
	relay.LastUsed = time.Now()
	relay.mu.Unlock()

	log.Printf("[*] SOCKS: %s session started for %s via %s", strings.ToUpper(scheme), matchedUser, relay.Target)

	// Run tunnelConnection — protocol-aware traffic proxying
	if err := plugin.TunnelConnection(conn, relay); err != nil {
		if build.Debug {
			log.Printf("[D] SOCKS: %s tunnel ended for %s: %v", strings.ToUpper(scheme), matchedUser, err)
		}
	}

	// Mark relay as no longer in use
	relay.mu.Lock()
	relay.InUse = false
	relay.mu.Unlock()

	log.Printf("[*] SOCKS: %s session ended for %s", strings.ToUpper(scheme), matchedUser)
}

// handleDNSPassthrough creates a direct TCP connection to the target DNS server
// and proxies data bidirectionally, bypassing the relay session lookup.
// Matches Impacket's socksserver.py DNS pass-through behavior.
func (s *SOCKSServer) handleDNSPassthrough(clientConn net.Conn, host string, port int) {
	target := fmt.Sprintf("%s:%d", host, port)

	remotConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if build.Debug {
			log.Printf("[D] SOCKS: DNS pass-through to %s failed: %v", target, err)
		}
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer remotConn.Close()

	// Send SOCKS success reply
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	clientConn.SetDeadline(time.Time{})

	if build.Debug {
		log.Printf("[D] SOCKS: DNS pass-through established to %s", target)
	}

	// Bidirectional proxy
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(remotConn, clientConn); errCh <- err }()
	go func() { _, err := io.Copy(clientConn, remotConn); errCh <- err }()
	<-errCh
}
