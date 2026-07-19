// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smb

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/mandiant/gopacket/internal/build"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/third_party/smb2"
	"github.com/mandiant/gopacket/pkg/transport"
	"github.com/mandiant/gopacket/pkg/utf16le"
)

type Client struct {
	Session   *smb2.Session
	Target    session.Target
	Creds     *session.Credentials
	conn      net.Conn
	initiator smb2.Initiator

	injectedDialer proxy.ContextDialer // set by WithDialer; nil = use default
	injectedConn   net.Conn            // set by WithConn; nil = dial
	ownsConn       bool                // true when we dialed c.conn; gates Close()

	currentShare *smb2.Share
	ipcShare     *smb2.Share
	currentPath  string
}

// Option configures a Client at construction. See WithDialer / WithConn.
type Option func(*Client)

// WithDialer routes the SMB connect (and, under Kerberos, the KDC dial) through
// d instead of the default proxy-aware transport. Supplying a dialer BYPASSES
// the global -proxy egress control; the caller owns egress.
func WithDialer(d proxy.ContextDialer) Option {
	return func(c *Client) { c.injectedDialer = d }
}

// WithConn uses an already-open connection for the SMB session instead of
// dialing. BYPASSES the global -proxy egress control. The caller must set
// Target.Host correctly, since the Kerberos SPN ("cifs/<Target.Host>") is
// derived from it even when the socket is injected.
//
// Ownership: if Connect() fails before a session is established, the injected
// conn is left open for the caller to manage. On a SUCCESSFUL session,
// however, Close() performs an SMB Logoff that tears down the underlying
// transport and closes the conn — including an injected one. A caller that
// must keep the conn alive past the SMB session should not call Close().
//
// Under Kerberos, the KDC dial honors WithDialer if one was also supplied;
// WithConn alone leaves the KDC dial on the default proxy-aware path and
// Connect() logs a warning.
func WithConn(conn net.Conn) Option {
	return func(c *Client) { c.injectedConn = conn }
}

func NewClient(target session.Target, creds *session.Credentials, opts ...Option) *Client {
	c := &Client{
		Target:      target,
		Creds:       creds,
		currentPath: "\\",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// socketDialer returns the dialer for the SMB socket: the injected one, or the
// proxy-aware default.
func (c *Client) socketDialer() proxy.ContextDialer {
	if c.injectedDialer != nil {
		return c.injectedDialer
	}
	return transport.ContextDialer{}
}

// kerberosOptions forwards an injected dialer to the KDC dial so a caller's
// custom transport also carries Kerberos traffic. Returns nil when nothing was
// injected, preserving the default proxy-aware KDC path.
func (c *Client) kerberosOptions() []kerberos.Option {
	if c.injectedDialer == nil {
		return nil
	}
	return []kerberos.Option{kerberos.WithKDCDialer(c.injectedDialer)}
}

// kdcFallbackWarning reports whether a conn was injected without a dialer, in
// which case the KDC dial cannot ride the injected transport (a single SMB
// socket can't reach the KDC) and falls back to the default path.
func (c *Client) kdcFallbackWarning() bool {
	return c.injectedConn != nil && c.injectedDialer == nil
}

// dialConn returns the injected conn if present, otherwise dials address with
// the default connect timeout. The explicit timeout is load-bearing: the proxy
// branch of transport.DialContext does not inject one on its own. It also
// records ownsConn so Close() never closes a caller-owned conn.
func (c *Client) dialConn(ctx context.Context, address string) (net.Conn, error) {
	if c.injectedConn != nil {
		c.ownsConn = false
		return c.injectedConn, nil
	}
	c.ownsConn = true
	dctx, cancel := context.WithTimeout(ctx, transport.DefaultTimeout*time.Second)
	defer cancel()
	return c.socketDialer().DialContext(dctx, "tcp", address)
}

// closeConnIfOwned closes the transport conn only when this client dialed it,
// leaving a caller-supplied (WithConn) conn open.
func (c *Client) closeConnIfOwned() {
	if c.conn != nil && c.ownsConn {
		c.conn.Close()
	}
}

func (c *Client) Connect() error {

	port := c.Target.Port

	if port == 0 {
		port = 445
	}

	host := c.Target.Host
	if c.Target.IP != "" {
		host = c.Target.IP
	}

	address := fmt.Sprintf("%s:%d", host, port)

	if build.Debug {

		log.Printf("[D] SMB: Attempting connection to %s", address)

	}

	conn, err := c.dialConn(context.Background(), address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	c.conn = conn

	var initiator smb2.Initiator

	if c.Creds.UseKerberos {
		if build.Debug {
			log.Printf("[D] SMB: Using Kerberos Authentication")
		}

		if c.kdcFallbackWarning() {
			log.Printf("[!] SMB: injected connection set without WithDialer; the Kerberos KDC dial uses the default transport and will NOT ride your injected stack")
		}
		kClient, err := kerberos.NewClientFromSession(c.Creds, c.Target, c.Creds.DCIP, c.kerberosOptions()...)
		if err != nil {
			return fmt.Errorf("failed to create kerberos client: %v", err)
		}

		spn := fmt.Sprintf("cifs/%s", c.Target.Host)
		initiator = &KerberosInitiator{
			KrbClient: kClient,
			TargetSPN: spn,
		}
	} else {
		// NTLM
		ntlmInit := &smb2.NTLMInitiator{
			User:     c.Creds.Username,
			Password: c.Creds.Password,
			Domain:   c.Creds.Domain,
		}
		// Handle Pass-the-Hash
		if c.Creds.Hash != "" {
			parts := strings.Split(c.Creds.Hash, ":")
			ntHashStr := ""
			if len(parts) == 2 {
				ntHashStr = parts[1]
			} else if len(parts) == 1 {
				ntHashStr = parts[0]
			}
			if ntHashStr != "" {
				ntHashBytes, err := hex.DecodeString(ntHashStr)
				if err == nil && len(ntHashBytes) == 16 {
					ntlmInit.Hash = ntHashBytes
					ntlmInit.Password = ""
				}
			}
		}
		initiator = ntlmInit
	}

	d := &smb2.Dialer{

		Initiator: initiator,

		Negotiator: smb2.Negotiator{
			RequireMessageSigning: true,
		},
	}

	if build.Debug {

		log.Printf("[D] SMB: Negotiating and Authenticating as %s\\%s", c.Creds.Domain, c.Creds.Username)
	}

	s, err := d.Dial(conn)
	if err != nil {
		c.closeConnIfOwned()
		return fmt.Errorf("SMB login failed: %v", err)
	}

	c.Session = s
	c.initiator = initiator
	return nil
}

// GetSessionKey returns the SMB session key used for signing/encryption.
func (c *Client) GetSessionKey() []byte {
	if c.initiator != nil {
		return c.initiator.SessionKey()
	}
	return nil
}

// GetDNSHostName returns the server's DNS hostname from the NTLM challenge.
func (c *Client) GetDNSHostName() string {
	if ntlmInit, ok := c.initiator.(*smb2.NTLMInitiator); ok {
		info := ntlmInit.InfoMap()
		if info != nil {
			return info.DnsComputerName
		}
	}
	return ""
}

// GetDNSTreeName returns the forest DNS name from the NTLM challenge.
func (c *Client) GetDNSTreeName() string {
	if ntlmInit, ok := c.initiator.(*smb2.NTLMInitiator); ok {
		info := ntlmInit.InfoMap()
		if info != nil {
			return info.DnsTreeName
		}
	}
	return ""
}

func (c *Client) Close() {
	if c.currentShare != nil {
		c.currentShare.Umount()
	}
	if c.ipcShare != nil {
		c.ipcShare.Umount()
	}
	if c.Session != nil {
		// Logoff tears down the smb2 transport, which closes the underlying
		// conn even when it was injected via WithConn. That is why
		// closeConnIfOwned below only needs to guard the no-session (failed
		// Connect) path. See WithConn's doc for the ownership contract.
		c.Session.Logoff()
	}
	c.closeConnIfOwned()
}

func (c *Client) ListShares() ([]string, error) {
	if c.Session == nil {
		return nil, fmt.Errorf("session not established")
	}
	names, err := c.Session.ListSharenames()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (c *Client) UseShare(name string) error {
	share, err := c.Session.Mount(name)
	if err != nil {
		return err
	}
	if c.currentShare != nil {
		c.currentShare.Umount()
	}
	c.currentShare = share
	c.currentPath = ""
	return nil
}

func (c *Client) Ls(dir string) ([]os.FileInfo, error) {
	if c.currentShare == nil {
		return nil, fmt.Errorf("no share selected")
	}
	p := path.Join(c.currentPath, dir)
	return c.currentShare.ReadDir(p)
}

func (c *Client) Cd(dir string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	newPath := path.Join(c.currentPath, dir)

	// Prevent going above root
	if strings.HasPrefix(newPath, "..") {
		c.currentPath = ""
		return nil
	}

	// Verify it exists and is a directory
	info, err := c.currentShare.Stat(newPath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	c.currentPath = newPath
	return nil
}

func (c *Client) Get(remoteFile, localFile string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	src, err := c.currentShare.Open(path.Join(c.currentPath, remoteFile))
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func (c *Client) Put(localFile, remoteFile string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	src, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := c.currentShare.Create(path.Join(c.currentPath, remoteFile))
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func (c *Client) GetCurrentPath() string {
	return c.currentPath
}

func (c *Client) Mkdir(dir string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	p := path.Join(c.currentPath, dir)
	return c.currentShare.Mkdir(p, 0755)
}

func (c *Client) Rmdir(dir string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	p := path.Join(c.currentPath, dir)
	return c.currentShare.Remove(p)
}

func (c *Client) Rm(file string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	p := path.Join(c.currentPath, file)
	return c.currentShare.Remove(p)
}

func (c *Client) Cat(file string) (string, error) {
	if c.currentShare == nil {
		return "", fmt.Errorf("no share selected")
	}
	f, err := c.currentShare.Open(path.Join(c.currentPath, file))
	if err != nil {
		return "", err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (c *Client) Rename(oldPath, newPath string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}
	op := path.Join(c.currentPath, oldPath)
	np := path.Join(c.currentPath, newPath)
	return c.currentShare.Rename(op, np)
}

// --- Extended Features ---

// TreeWalkFunc is called for each file found by Tree
type TreeWalkFunc func(path string, info os.FileInfo, err error) error

// Tree recursively lists files.
func (c *Client) Tree(root string, fn TreeWalkFunc) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}

	// Helper for recursive walk
	var walk func(currentPath string) error
	walk = func(currentPath string) error {
		files, err := c.currentShare.ReadDir(currentPath)
		if err != nil {
			return fn(currentPath, nil, err)
		}

		for _, f := range files {
			fullPath := path.Join(currentPath, f.Name())
			if err := fn(fullPath, f, nil); err != nil {
				return err
			}
			if f.IsDir() {
				if err := walk(fullPath); err != nil {
					return err
				}
			}
		}
		return nil
	}

	startPath := path.Join(c.currentPath, root)
	return walk(startPath)
}

// Mget downloads multiple files matching a pattern.
func (c *Client) Mget(pattern string) error {
	if c.currentShare == nil {
		return fmt.Errorf("no share selected")
	}

	files, err := c.currentShare.ReadDir(c.currentPath)
	if err != nil {
		return err
	}

	for _, f := range files {
		match, _ := filepath.Match(pattern, f.Name())
		if match && !f.IsDir() {
			fmt.Printf("Downloading %s...\n", f.Name())
			if err := c.Get(f.Name(), f.Name()); err != nil {
				fmt.Printf("[-] Failed to download %s: %v\n", f.Name(), err)
			}
		}
	}
	return nil
}

// fsctlSrvEnumerateSnapshots is FSCTL_SRV_ENUMERATE_SNAPSHOTS per MS-FSCC
// 2.3.23 / MS-SMB2 2.2.31. Enumerates VSS shadow copies on the share.
const fsctlSrvEnumerateSnapshots = 0x00144064

// EnumerateSnapshots returns the VSS shadow-copy tokens available on the
// currently selected share, formatted as `@GMT-YYYY.MM.DD-HH.MM.SS`. Requires
// a share to be selected via UseShare. Returns an empty slice if no snapshots
// exist. Implements the two-call size-probe pattern from MS-SMB2 2.2.32.
func (c *Client) EnumerateSnapshots() ([]string, error) {
	if c.currentShare == nil {
		return nil, fmt.Errorf("no share selected")
	}

	f, err := c.currentShare.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open share root: %v", err)
	}
	defer f.Close()

	// First call with just enough buffer for the 12-byte SRV_SNAPSHOT_ARRAY
	// header. The server returns SnapShotArraySize so we know how large the
	// second call's buffer needs to be.
	hdr, err := f.Ioctl(fsctlSrvEnumerateSnapshots, nil, 16)
	if err != nil {
		return nil, fmt.Errorf("ioctl (probe): %v", err)
	}
	if len(hdr) < 12 {
		return nil, fmt.Errorf("snapshot probe response too short: %d bytes", len(hdr))
	}
	arraySize := binary.LittleEndian.Uint32(hdr[8:12])
	if arraySize == 0 {
		return []string{}, nil
	}

	// Second call, request header + full payload.
	resp, err := f.Ioctl(fsctlSrvEnumerateSnapshots, nil, 12+int(arraySize))
	if err != nil {
		return nil, fmt.Errorf("ioctl (full): %v", err)
	}
	if len(resp) < 12 {
		return nil, fmt.Errorf("snapshot response too short: %d bytes", len(resp))
	}
	numReturned := binary.LittleEndian.Uint32(resp[4:8])
	arraySize = binary.LittleEndian.Uint32(resp[8:12])
	if uint32(len(resp)) < 12+arraySize {
		return nil, fmt.Errorf("snapshot payload truncated: got %d, want %d", len(resp), 12+arraySize)
	}
	data := resp[12 : 12+arraySize]

	// The payload is a sequence of UTF-16LE NUL-terminated strings followed by
	// a final UTF-16LE NUL terminator. Walk two bytes at a time looking for
	// UTF-16 NULs.
	var out []string
	for i := 0; i+1 < len(data); {
		end := i
		for end+1 < len(data) {
			if data[end] == 0 && data[end+1] == 0 {
				break
			}
			end += 2
		}
		if end == i {
			break // list terminator
		}
		out = append(out, utf16le.DecodeToString(data[i:end]))
		i = end + 2
		if uint32(len(out)) >= numReturned {
			break
		}
	}
	return out, nil
}
