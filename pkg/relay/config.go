package relay

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// Config holds the full relay configuration.
type Config struct {
	// Target
	TargetAddr string        // Single target URL (smb://host:port)
	TargetList []TargetEntry // Parsed from -tf file
	targetMu   sync.Mutex
	targetIdx  int

	// Server
	ListenAddr string // Default ":445" for SMB
	SMBPort    int    // Default 445
	HTTPPort   int    // Default 80
	HTTPSPort  int    // Default 443
	WCFPort    int    // Default 9389
	RawPort    int    // Default 6666
	RPCPort    int    // Default 135
	WinRMPort  int    // Default 5985
	WinRMSPort int    // Default 5986

	// Server toggles
	NoSMBServer   bool
	NoHTTPServer  bool
	NoWCFServer   bool
	NoRawServer   bool
	NoRPCServer   bool
	NoWinRMServer bool

	// TLS
	CertFile string
	KeyFile  string
	BindIP   string

	// Attack
	Attack  string // shares, smbexec, samdump, ldapdump, delegate, etc.
	Command string // command for smbexec/tschexec
	ExeFile string // executable to upload and run

	// LDAP attack options
	EscalateUser      string
	DelegateAccess    bool
	ShadowCredentials bool
	ShadowTarget      string
	AddComputer       string
	delegateTarget    string // set by relay orchestrator from relayed username
	DumpDomain        bool
	DumpLAPS          bool
	DumpGMSA          bool
	DumpADCS          bool
	AddDNSRecord      [2]string // [name, IP]
	NoDump            bool
	NoDA              bool
	NoACL             bool
	NoValidatePrivs   bool

	// ADCS
	ADCSAttack bool
	Template   string
	AltName    string

	// RPC relay
	RPCMode    string // "TSCH" or "ICPR" (default: "TSCH")
	ICPRCAName string // CA name for ICPR certificate request

	// MSSQL
	Queries []string

	// NTLM manipulation
	RemoveMIC  bool
	RemoveSign bool
	NTLMv1     bool

	// SOCKS
	SOCKSEnabled bool
	SOCKSAddr    string // Default "127.0.0.1:1080"
	APIPort      int    // REST API port (default 9090, Impacket -http-api-port)

	// Relay behavior
	KeepRelaying bool
	NoMultiRelay bool
	RandomTarget bool

	// General
	Debug       bool
	LootDir     string
	OutputFile  string
	IPv6        bool
	Interactive bool
	EnumAdmins  bool

	// WPAD
	WPADHost    string
	WPADAuthNum int
	ServeImage  string

	// internal
	stopOnce        sync.Once
	stopChan        chan struct{}
	originalTargets []TargetEntry            // full target list (immutable after init)
	candidates      []TargetEntry            // working copy of targets
	finishedAttacks map[string]map[string]bool // targetURL → {identity → true}
	failedAttacks   map[string]map[string]bool // targetURL → {identity → true}
	relayedUser     string // username from relayed NTLM Type3 (set per-session)
	relayedDomain   string // domain from relayed NTLM Type3 (set per-session)
}

// stopCh returns the stop channel, creating it if needed.
func (c *Config) stopCh() <-chan struct{} {
	c.stopOnce.Do(func() {
		c.stopChan = make(chan struct{})
	})
	return c.stopChan
}

// Shutdown signals all relay goroutines to stop by closing the stop channel.
func (c *Config) Shutdown() {
	c.stopOnce.Do(func() {
		c.stopChan = make(chan struct{})
	})
	select {
	case <-c.stopChan:
		// Already closed
	default:
		close(c.stopChan)
	}
}

// TargetEntry represents a parsed relay target URL.
type TargetEntry struct {
	Scheme string // "smb", "ldap", "ldaps", "http", "https", "mssql", "rpc", "imap", "winrm", "winrms"
	Host   string
	Port   int
	Path   string // URL path (e.g., "/certsrv/certfnsh.asp") — used by HTTP relay client
}

// Addr returns host:port for dialing.
func (t TargetEntry) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// URL returns the target as a URL string.
func (t TargetEntry) URL() string {
	base := fmt.Sprintf("%s://%s:%d", t.Scheme, t.Host, t.Port)
	if t.Path != "" && t.Path != "/" {
		return base + t.Path
	}
	return base
}

// DefaultPort returns the default port for a protocol scheme.
func DefaultPort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "smb":
		return 445
	case "ldap":
		return 389
	case "ldaps":
		return 636
	case "http":
		return 80
	case "https":
		return 443
	case "mssql":
		return 1433
	case "rpc":
		return 135
	case "imap":
		return 143
	case "imaps":
		return 993
	case "winrm":
		return 5985
	case "winrms":
		return 5986
	case "smtp":
		return 25
	default:
		return 445
	}
}

// ParseTargetURL parses a target URL string into a TargetEntry.
// Accepted formats: smb://host, smb://host:port, host, host:port
func ParseTargetURL(raw string) (*TargetEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}

	// If no scheme, assume SMB
	if !strings.Contains(raw, "://") {
		// Could be host or host:port
		host, portStr, err := net.SplitHostPort(raw)
		if err != nil {
			// Just a host, no port
			return &TargetEntry{
				Scheme: "smb",
				Host:   raw,
				Port:   445,
			}, nil
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		return &TargetEntry{
			Scheme: "smb",
			Host:   host,
			Port:   port,
		}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("no host in target URL: %s", raw)
	}

	port := DefaultPort(scheme)
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port in URL: %s", u.Port())
		}
	}

	// Preserve URL path for HTTP/HTTPS targets (e.g., /certsrv/certfnsh.asp)
	path := u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	return &TargetEntry{
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Path:   path,
	}, nil
}

// InitTargets initializes the target processor. Call once before relay loop starts.
// Shuffles targets if RandomTarget is set (matches Impacket -ra behavior).
func (c *Config) InitTargets() {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	// Build original targets list
	if len(c.TargetList) > 0 {
		c.originalTargets = make([]TargetEntry, len(c.TargetList))
		copy(c.originalTargets, c.TargetList)
	} else if c.TargetAddr != "" {
		t, err := ParseTargetURL(c.TargetAddr)
		if err == nil {
			c.originalTargets = []TargetEntry{*t}
		}
	}

	// Shuffle if -ra (random) flag set — done once at startup (matches Impacket)
	if c.RandomTarget && len(c.originalTargets) > 1 {
		rand.Shuffle(len(c.originalTargets), func(i, j int) {
			c.originalTargets[i], c.originalTargets[j] = c.originalTargets[j], c.originalTargets[i]
		})
	}

	c.finishedAttacks = make(map[string]map[string]bool)
	c.failedAttacks = make(map[string]map[string]bool)
	c.candidates = make([]TargetEntry, len(c.originalTargets))
	copy(c.candidates, c.originalTargets)
}

// GetTarget returns the next target for a relay session.
// For single targets, returns that target directly.
// For multi-target, selects based on the identity (DOMAIN\user) and tracking state.
func (c *Config) GetTarget() *TargetEntry {
	return c.GetTargetForIdentity("")
}

// GetTargetForIdentity returns the next target for a specific relayed identity.
// Matches Impacket's TargetsProcessor.getTarget() behavior:
// - Pops targets from candidates list (consumed on use)
// - When candidates empty, reloads from originalTargets minus already-attacked
// - With identity: skips targets this user already attacked
// - In --no-multirelay mode, each target is attacked only once regardless of user
func (c *Config) GetTargetForIdentity(identity string) *TargetEntry {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	// Single target mode — always return it
	if len(c.originalTargets) == 0 {
		if c.TargetAddr == "" {
			return nil
		}
		t, err := ParseTargetURL(c.TargetAddr)
		if err != nil {
			return nil
		}
		return t
	}

	identity = strings.ToUpper(identity)

	return c.getTargetLocked(identity)
}

// getTargetLocked selects the next target (must hold targetMu).
// Matches Impacket's generalCandidates.pop() / search-and-remove pattern.
func (c *Config) getTargetLocked(identity string) *TargetEntry {
	if identity != "" {
		// Search for a target not yet attacked by this user
		for i, t := range c.candidates {
			targetKey := t.URL()

			if c.NoMultiRelay {
				if c.isTargetDone(targetKey) {
					continue
				}
			} else {
				if c.isAttackedBy(targetKey, identity) {
					continue
				}
			}

			// Found valid candidate — remove from list and return
			result := c.candidates[i]
			c.candidates = append(c.candidates[:i], c.candidates[i+1:]...)
			return &result
		}
	} else if c.NoMultiRelay {
		// No identity, --no-multirelay: find first unattacked target
		for i, t := range c.candidates {
			if !c.isTargetDone(t.URL()) {
				result := c.candidates[i]
				c.candidates = append(c.candidates[:i], c.candidates[i+1:]...)
				return &result
			}
		}
	} else if len(c.candidates) > 0 {
		// No identity, multiRelay: pop from end (matches Impacket generalCandidates.pop())
		idx := len(c.candidates) - 1
		result := c.candidates[idx]
		c.candidates = c.candidates[:idx]
		return &result
	}

	// Candidates exhausted — try to reload
	c.reloadCandidates()

	if len(c.candidates) > 0 {
		// Pop from newly reloaded candidates
		idx := len(c.candidates) - 1
		result := c.candidates[idx]
		c.candidates = c.candidates[:idx]
		return &result
	}

	if c.KeepRelaying {
		// Full reset: clear all tracking and reload everything
		log.Printf("[*] All targets processed, reloading (--keep-relaying)")
		c.finishedAttacks = make(map[string]map[string]bool)
		c.failedAttacks = make(map[string]map[string]bool)
		c.candidates = make([]TargetEntry, len(c.originalTargets))
		copy(c.candidates, c.originalTargets)

		if len(c.candidates) > 0 {
			idx := len(c.candidates) - 1
			result := c.candidates[idx]
			c.candidates = c.candidates[:idx]
			return &result
		}
	}

	return nil
}

// reloadCandidates rebuilds candidates from originalTargets minus already-attacked.
// Matches Impacket's reload logic when generalCandidates is empty.
func (c *Config) reloadCandidates() {
	c.candidates = c.candidates[:0]
	for _, t := range c.originalTargets {
		targetKey := t.URL()
		if !c.isTargetDone(targetKey) {
			c.candidates = append(c.candidates, t)
		}
	}
}

// RegisterAttack records that a target was attacked by a specific identity.
// success=true means relay succeeded; success=false means it failed.
// Matches Impacket's TargetsProcessor.registerTarget().
func (c *Config) RegisterAttack(target *TargetEntry, identity string, success bool) {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	identity = strings.ToUpper(identity)
	targetKey := target.URL()

	if success {
		if c.finishedAttacks[targetKey] == nil {
			c.finishedAttacks[targetKey] = make(map[string]bool)
		}
		c.finishedAttacks[targetKey][identity] = true
	} else {
		if c.failedAttacks[targetKey] == nil {
			c.failedAttacks[targetKey] = make(map[string]bool)
		}
		c.failedAttacks[targetKey][identity] = true
	}
}

// isTargetDone returns true if any user has attacked this target (for --no-multirelay).
func (c *Config) isTargetDone(targetKey string) bool {
	if len(c.finishedAttacks[targetKey]) > 0 {
		return true
	}
	if len(c.failedAttacks[targetKey]) > 0 {
		return true
	}
	return false
}

// isAttackedBy returns true if a specific identity already attacked this target.
func (c *Config) isAttackedBy(targetKey, identity string) bool {
	if c.finishedAttacks[targetKey] != nil && c.finishedAttacks[targetKey][identity] {
		return true
	}
	if c.failedAttacks[targetKey] != nil && c.failedAttacks[targetKey][identity] {
		return true
	}
	return false
}

// GetOriginalTargets returns a copy of the original targets list (thread-safe).
func (c *Config) GetOriginalTargets() []TargetEntry {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	result := make([]TargetEntry, len(c.originalTargets))
	copy(result, c.originalTargets)
	return result
}

// GetFinishedAttacks returns a snapshot of finished attacks: targetURL → []identity (thread-safe).
func (c *Config) GetFinishedAttacks() map[string][]string {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()

	result := make(map[string][]string)
	for target, identities := range c.finishedAttacks {
		for id := range identities {
			result[target] = append(result[target], id)
		}
	}
	return result
}
