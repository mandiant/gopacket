// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"gopacket/internal/build"
)

// HTTPSRelayServer wraps HTTPRelayServer with TLS.
// Reuses the same ServeHTTP handler — only the listener is TLS-wrapped.
type HTTPSRelayServer struct {
	listenAddr string
	config     *Config
	httpServer *HTTPRelayServer
	tlsConfig  *tls.Config
	server     *http.Server
	listener   net.Listener
}

// NewHTTPSRelayServer creates a new HTTPS relay server.
// If CertFile/KeyFile are set in config, loads them; otherwise generates a self-signed cert.
func NewHTTPSRelayServer(listenAddr string, config *Config) (*HTTPSRelayServer, error) {
	var tlsCert tls.Certificate
	var err error

	if config.CertFile != "" && config.KeyFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert/key: %v", err)
		}
	} else {
		tlsCert, err = generateSelfSignedTLSCert(config.BindIP)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	return &HTTPSRelayServer{
		listenAddr: listenAddr,
		config:     config,
		tlsConfig:  tlsConfig,
	}, nil
}

// Start begins listening for HTTPS connections, implements ProtocolServer.
func (s *HTTPSRelayServer) Start(resultChan chan<- AuthResult) error {
	// Create the underlying HTTP relay server (for its handler and state)
	s.httpServer = NewHTTPRelayServer(s.listenAddr, s.config)
	s.httpServer.authCh = resultChan

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}

	tlsLn := tls.NewListener(ln, s.tlsConfig)
	s.listener = tlsLn

	s.server = &http.Server{
		Handler: s.httpServer, // reuse HTTPRelayServer's ServeHTTP
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				s.httpServer.mu.Lock()
				delete(s.httpServer.sessions, conn.RemoteAddr().String())
				s.httpServer.mu.Unlock()
			}
		},
	}

	log.Printf("[*] HTTPS relay server listening on %s", s.listenAddr)

	go func() {
		if err := s.server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			if build.Debug {
				log.Printf("[D] HTTPS relay server: serve error: %v", err)
			}
		}
	}()

	return nil
}

// Stop closes the HTTPS server, implements ProtocolServer.
func (s *HTTPSRelayServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// generateSelfSignedTLSCert creates a self-signed TLS certificate for the HTTPS relay server.
// RSA 2048, CN=localhost, SANs include localhost, 127.0.0.1, and the bind IP if provided.
func generateSelfSignedTLSCert(bindIP string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	if bindIP != "" {
		if ip := net.ParseIP(bindIP); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
