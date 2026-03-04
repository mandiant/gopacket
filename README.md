# gopacket

A complete Go implementation of [Impacket](https://github.com/fortra/impacket) — 63 tools and 24 library packages for Windows network protocol interaction, Active Directory enumeration, and attack execution. Built as a native Go framework so you can compile once and run anywhere without Python dependencies.

> **Alpha Release** — gopacket is under active development. Core tools have been tested against Active Directory lab environments, but edge cases and protocol quirks are expected. If something isn't working, please test the same operation with Impacket side-by-side and include both outputs in your bug report. This helps us quickly identify whether it's a gopacket-specific issue or a shared protocol limitation.

## Installation

```bash
git clone https://mandiant-pf-experimental-internal.googlesource.com/paullus/gopacket
cd gopacket

# Build and install all tools as gopacket-<toolname> on your PATH
./install.sh

# Or just build without installing
./install.sh --build-only

# Or build with make
make build
```

Requires Go 1.21+ and GCC (CGO is used for some dependencies).

To uninstall:
```bash
./install.sh --uninstall
```

## Tools (63)

### Remote Execution
| Tool | Description |
|------|-------------|
| **psexec** | Remote command execution via SMB service creation |
| **smbexec** | Remote command execution via SMB (stealthier than psexec) |
| **wmiexec** | Remote command execution via WMI |
| **dcomexec** | Remote command execution via DCOM |
| **atexec** | Remote command execution via Task Scheduler |

### Credential Dumping & DPAPI
| Tool | Description |
|------|-------------|
| **secretsdump** | SAM/LSA/NTDS.dit extraction and DCSync (remote + offline) |
| **dpapi** | DPAPI backup key extraction |
| **esentutl** | Offline ESE database parser (NTDS.dit) |
| **registry-read** | Offline Windows registry hive parser |

### Kerberos
| Tool | Description |
|------|-------------|
| **getTGT** | Request a TGT with password, hash, or AES key |
| **getST** | Request a service ticket with S4U2Self/S4U2Proxy |
| **GetUserSPNs** | Kerberoasting — find and request SPNs |
| **GetNPUsers** | AS-REP roasting — find accounts without pre-auth |
| **ticketer** | Golden/silver ticket forging |
| **ticketConverter** | Convert between ccache and kirbi formats |
| **describeTicket** | Parse and decrypt Kerberos tickets |
| **getPac** | Request and parse PAC information |
| **keylistattack** | KERB-KEY-LIST-REQ attack (RODC) |
| **raiseChild** | Child-to-parent domain escalation via golden ticket |

### Active Directory Enumeration
| Tool | Description |
|------|-------------|
| **GetADUsers** | Enumerate domain users via LDAP |
| **GetADComputers** | Enumerate domain computers via LDAP |
| **GetLAPSPassword** | Read LAPS passwords via LDAP |
| **findDelegation** | Find delegation configurations |
| **lookupsid** | SID brute-forcing via LSARPC |
| **samrdump** | Enumerate users via SAMR |
| **rpcdump** | Dump RPC endpoints via epmapper |
| **rpcmap** | Scan for accessible RPC interfaces |
| **net** | net user/group/computer enumeration via SAMR/LSARPC |
| **netview** | Enumerate sessions, shares, and logged-on users |
| **CheckLDAPStatus** | Check LDAP signing and channel binding requirements |
| **DumpNTLMInfo** | Dump NTLM authentication info from SMB negotiation |
| **getArch** | Detect remote OS architecture via RPC |
| **machine_role** | Detect machine role (DC, server, workstation) |

### Active Directory Attacks
| Tool | Description |
|------|-------------|
| **addcomputer** | Create/modify/delete machine accounts (SAMR + LDAP) |
| **rbcd** | Resource-Based Constrained Delegation manipulation |
| **dacledit** | Read/write DACLs on AD objects |
| **owneredit** | Read/modify object ownership |
| **samedit** | SAM account name spoofing (CVE-2021-42278/42287) |
| **badsuccessor** | BadSuccessor / backup operator escalation |
| **changepasswd** | Change/reset passwords via SAMR and LDAP |

### SMB Tools
| Tool | Description |
|------|-------------|
| **smbclient** | Interactive SMB client (shares, ls, get, put, etc.) |
| **smbserver** | SMB server for file sharing |
| **attrib** | Query/modify file attributes via SMB |
| **filetime** | Query/modify file timestamps via SMB |
| **services** | Remote service management via SVCCTL |
| **reg** | Remote registry operations via WINREG |
| **Get-GPPPassword** | Extract Group Policy Preferences passwords from SYSVOL |
| **karmaSMB** | Rogue SMB server for hash capture |

### NTLM Relay
| Tool | Description |
|------|-------------|
| **ntlmrelayx** | Full NTLM relay framework with multi-protocol support |

ntlmrelayx supports:
- **Capture servers:** SMB, HTTP/HTTPS, WCF (ADWS), RAW, RPC, WinRM
- **Relay clients:** SMB, LDAP/LDAPS, HTTP/HTTPS, MSSQL, WinRM, RPC
- **Attacks:** secretsdump, smbexec, ldapdump, RBCD delegation, ACL abuse, shadow credentials, ADCS ESC8, addcomputer, DNS manipulation, and more
- **Infrastructure:** SOCKS5 proxy with protocol-aware plugins, interactive console, REST API, multi-target round-robin, WPAD serving

### SQL Server
| Tool | Description |
|------|-------------|
| **mssqlclient** | Interactive MSSQL client with SQL/Windows/Kerberos auth |
| **mssqlinstance** | MSSQL instance discovery via SQL Browser |

### WMI
| Tool | Description |
|------|-------------|
| **wmiquery** | Interactive WMI query shell |
| **wmipersist** | WMI event subscription persistence |

### Terminal Services
| Tool | Description |
|------|-------------|
| **tstool** | Terminal Services session and process enumeration |

### Other Protocols
| Tool | Description |
|------|-------------|
| **rdp_check** | RDP authentication check |
| **mqtt_check** | MQTT authentication check |
| **exchanger** | Exchange Web Services client |

### Utilities
| Tool | Description |
|------|-------------|
| **ntfs-read** | Offline NTFS filesystem parser |
| **ping** / **ping6** | ICMP ping |
| **sniff** / **sniffer** | Network packet capture |
| **split** | Split large files |

## Authentication

All network tools support three authentication methods:

```bash
# Password
gopacket-secretsdump 'domain/user:password@target'

# NTLM hash (pass-the-hash)
gopacket-secretsdump -hashes ':nthash' 'domain/user@target'

# Kerberos (pass-the-ticket)
KRB5CCNAME=ticket.ccache gopacket-secretsdump -k -no-pass 'domain/user@target'
```

### Common Flags

| Flag | Description |
|------|-------------|
| `-hashes LMHASH:NTHASH` | NTLM hash authentication (LM hash can be empty) |
| `-k` | Use Kerberos authentication |
| `-no-pass` | Don't prompt for password (use with `-k` or `-hashes`) |
| `-dc-ip IP` | IP address of the domain controller |
| `-target-ip IP` | IP address of the target (when using hostname for Kerberos) |
| `-port PORT` | Target port (defaults vary by tool) |
| `-debug` | Enable debug output |

### Quick Examples

```bash
# Dump domain hashes via DCSync
gopacket-secretsdump 'corp.local/admin:Password1@dc01.corp.local'

# Interactive SMB shell
gopacket-smbclient -hashes ':aabbccdd...' 'corp.local/admin@fileserver'

# Kerberoast
gopacket-getuserspns 'corp.local/user:pass@dc01.corp.local'

# Golden ticket
gopacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain corp.local admin

# NTLM relay with SOCKS proxy
sudo gopacket-ntlmrelayx -t smb://target -socks

# LDAP relay for RBCD
sudo gopacket-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access
```

## Library

The `pkg/` directory contains 24 reusable protocol packages that can be imported independently:

| Package | Description |
|---------|-------------|
| **smb** | SMB2/3 client with NTLM and Kerberos auth |
| **ldap** | LDAP client with NTLM/Kerberos bind |
| **dcerpc** | DCE/RPC client + 20 service implementations (DRSUAPI, SAMR, SVCCTL, LSARPC, WINREG, NETLOGON, DCOM, TSCH, EPMAPPER, etc.) |
| **kerberos** | Kerberos client, ticket forging (golden/silver), S4U2Self/S4U2Proxy |
| **ntlm** | NTLM authentication protocol |
| **relay** | NTLM relay framework (servers, clients, attacks, SOCKS) |
| **tds** | SQL Server TDS protocol |
| **ese** | Extensible Storage Engine parser |
| **registry** | Windows registry hive parser |
| **ntfs** | NTFS filesystem parser |
| **security** | Security descriptors, ACLs, SIDs |
| **dpapi** | DPAPI structures |
| **mqtt** | MQTT protocol client |
| **session** | Target/credential parsing (`domain/user:pass@host`) |
| **flags** | Unified CLI flag framework |

## Missing Features (vs Impacket)

gopacket aims for full Impacket parity. The following are not yet implemented:

**Relay protocol clients:**
- IMAP relay client + attack (requires Exchange/IMAP server)
- SMTP relay client (requires SMTP server)

**Relay attack modules:**
- SCCM policies/DP attacks (requires SCCM infrastructure)

**Standalone tools:**
- `ifmap.py` (DCOM interface mapping)
- `mimikatz.py` (limited Mimikatz over RPC)
- `goldenPac.py` (MS14-068 — obsolete on patched systems)
- `smbrelayx.py` (superseded by ntlmrelayx)
- `kintercept.py` (Kerberos interception)

These gaps are low priority — most require niche infrastructure to test or are obsoleted by newer techniques.

## Known Limitations

These are protocol-level limitations shared with Impacket, not gopacket bugs:

- **SMB to LDAPS relay** fails on patched DCs due to NTLM MIC validation (post-CVE-2019-1040). Use HTTP coercion instead.
- **WinRM relay** blocked by EPA (Extended Protection for Authentication) on patched Server 2019+.
- **RPC relay attacks** (tschexec, enum-local-admins) require PKT_INTEGRITY which is unavailable in relay sessions.
- **LDAP relay to port 389** fails on DCs requiring LDAP signing. Always relay to LDAPS (port 636).

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for detailed information on each issue and workarounds.

## Reporting Issues

> This is an alpha release. Bugs are expected.

If you encounter a problem:

1. Run the same operation with Impacket and note whether it succeeds or fails
2. Re-run with `-debug` and capture the full output
3. Include both outputs in your report

**Bug Reports:** [https://forms.gle/CaJ8hJ1UT8Wm7zp3A](https://forms.gle/CaJ8hJ1UT8Wm7zp3A)

**Feature Requests / QoL Improvements:** [https://forms.gle/o6CLbWBLM1oXJ6yQ6](https://forms.gle/o6CLbWBLM1oXJ6yQ6)

## Notes

- Kerberos authentication requires a valid ccache file (TGT or service ticket)
- For Kerberos, use the FQDN hostname — not an IP address
- If `KRB5CCNAME` is not set, tools will look for `<username>.ccache` in the current directory
- All tools work through proxychains
- This project is for authorized security testing and research purposes only
