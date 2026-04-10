// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package smb

import (
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

	"gopacket/internal/build"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/session"
	"gopacket/pkg/thirdparty/smb2"
	"gopacket/pkg/transport"
)

type Client struct {
	Session   *smb2.Session
	Target    session.Target
	Creds     *session.Credentials
	dialer    *transport.Dialer
	conn      net.Conn
	initiator smb2.Initiator

	currentShare *smb2.Share
	ipcShare     *smb2.Share
	currentPath  string
}

func NewClient(target session.Target, creds *session.Credentials) *Client {
	return &Client{
		Target:      target,
		Creds:       creds,
		dialer:      &transport.Dialer{},
		currentPath: "\\",
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

	conn, err := c.dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	c.conn = conn

	var initiator smb2.Initiator

	if c.Creds.UseKerberos {
		if build.Debug {
			log.Printf("[D] SMB: Using Kerberos Authentication")
		}

		kClient, err := kerberos.NewClientFromSession(c.Creds, c.Target, c.Creds.DCIP)
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

			SpecifiedDialect:      0x0210,
			RequireMessageSigning: true,
		},
	}

	if build.Debug {

		log.Printf("[D] SMB: Negotiating and Authenticating as %s\\%s", c.Creds.Domain, c.Creds.Username)
	}

	s, err := d.Dial(conn)
	if err != nil {
		conn.Close()
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
		c.Session.Logoff()
	}
	if c.conn != nil {
		c.conn.Close()
	}
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
