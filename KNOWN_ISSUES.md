# gopacket ntlmrelayx — Known Issues

## How to Report Issues

When reporting, please include:
- Exact command line used (both gopacket and coercion command)
- Full output with `-debug` flag enabled
- Target OS version and patch level if known
- Whether the same operation works with Impacket's ntlmrelayx

---

## 1. SMB Relay: Registry Access Denied (samdump / secretsdump)

**Symptom:** `BaseRegOpenKey(SYSTEM\Select) failed: 0x00000005` (ACCESS_DENIED) when running `samdump` or `secretsdump` via SMB relay.

**Details:** The relay authenticates successfully, the winreg named pipe opens, and the HKLM root handle is obtained — but opening `SYSTEM\Select` (needed for boot key extraction) returns ACCESS_DENIED. This affects both `samdump` (new default) and `secretsdump`.

**Root cause (suspected):** The relayed SMB session token may have a restricted impersonation level ("Identification" instead of "Impersonation") depending on the target's configuration, Windows patch level, or the relayed account's privileges. The winreg service may enforce stricter access checks on subkeys than on the root HKLM handle.

**Workaround:** Use direct (non-relay) secretsdump with credentials obtained through other means (e.g., relay to LDAP for credential extraction, then use `secretsdump` directly).

**Not affected:** Standalone `secretsdump` with direct credentials works perfectly. Other SMB relay attacks (`shares`, `smbexec`) work fine over the same relay session.

**Status:** Needs investigation. May be environment-specific. Compare with Impacket's ntlmrelayx default SMB attack on the same target.

---

## 2. Standalone secretsdump: Panic in Cached Credentials Parser

**Symptom:** `panic: runtime error: slice bounds out of range [5052:5048]` in `pkg/registry/hive.go:82` when parsing the SECURITY hive's cached domain logon entries.

**Details:** SAM hashes and LSA secrets dump correctly, but parsing `NL$` cached credential entries causes an out-of-bounds slice access in the registry hive cell reader. Occurs after successfully dumping several cached entries.

**Workaround:** SAM hashes and LSA secrets are dumped before the panic occurs, so those results are usable. The panic only affects cached domain logon credentials.

**Status:** Bug in `pkg/registry/hive.go` `readCell()` — needs bounds checking fix.

---

## 3. tschexec / enum-local-admins: RPC Access Denied

**Symptom:** `RPC Fault 0x05 (ACCESS_DENIED)` when running `tschexec` or `enumlocaladmins` via relay.

**Details:** Task Scheduler (TSCH) and SAMR require RPC-level authentication (PKT_INTEGRITY / PKT_PRIVACY) which is not available in relay sessions. The relay provides session-level auth (SMB session setup) but cannot provide packet-level RPC signing/encryption because we don't have the session key.

**This is the same limitation as Impacket** — these attacks only work with Impacket's `-auth-smb` flag which provides full RPC auth. Relay mode cannot provide this.

**Workaround:** Use `smbexec` for command execution via relay instead. For local admin enumeration, use `shares` attack — access to ADMIN$ confirms local admin.

**Status:** By design. Would require implementing RPC-level NTLM auth forwarding, which is not feasible without the session key.

---

## 4. SMB Relay: Intermittent PIPE_NOT_AVAILABLE (0xc00000ac)

**Symptom:** `create failed: status=0xc00000ac` when opening the `winreg` named pipe on the relay target.

**Details:** The Remote Registry service may not be running or may be slow to respond to pipe connection requests. This is transient — retrying (via `--keep-relaying`) typically succeeds.

**Workaround:** Ensure the Remote Registry service is running on the target before relaying. Or use `--keep-relaying` to automatically retry on the next coerced authentication.

**Status:** Consider adding auto-retry or service start logic (Impacket starts RemoteRegistry automatically via SVCCTL before winreg operations).

---

## 5. Shadow Credentials: Certificate Generation Not Implemented

**Symptom:** `-attack shadowcreds` reads existing `msDS-KeyCredentialLink` values but cannot write new shadow credentials.

**Details:** The attack requires generating a self-signed X.509 certificate and constructing a `KeyCredentialLink` structure (CBOR-encoded). The LDAP write path works, but the certificate generation is not implemented.

**Workaround:** Use `pywhisker` (Python) to generate shadow credentials, or use the `delegate` (RBCD) attack instead for similar privilege escalation.

**Status:** Stub. Needs Go X.509 certificate generation + CBOR KeyCredentialLink encoding.

---

## 6. LDAP Relay: Plain LDAP (Port 389) Post-Auth Signing Failure

**Symptom:** LDAP relay to port 389 authenticates successfully but subsequent LDAP operations fail with signing errors on patched DCs.

**Details:** After NTLM bind with NEGOTIATE_SIGN set, the DC requires LDAP message signing on all subsequent operations. The underlying `go-ldap` library doesn't support LDAP signing, so post-auth operations fail.

**Workaround:** Always relay to LDAPS (port 636) instead of plain LDAP (port 389). LDAPS uses TLS for transport security, so LDAP-level signing is not required.

**Status:** By design. Would require implementing LDAP message signing in the go-ldap fork. LDAPS is the recommended relay path.

---

## 7. SMB→LDAPS Relay Fails on Patched DCs

**Symptom:** Relay from SMB capture to LDAPS target fails with MIC validation errors.

**Details:** SMB clients always set NEGOTIATE_SIGN in NTLM Type 1. When relaying cross-protocol (SMB→LDAPS), stripping this flag from Type 1 causes the MIC in Type 3 to be invalid (the client computed the MIC over the original Type 1 with SIGN set). The `--remove-mic` flag strips the MIC from Type 3, but patched DCs (post-CVE-2019-1040) reject messages with missing MIC.

**This is the same limitation as Impacket.** SMB→LDAPS relay is fundamentally broken on patched DCs.

**Workaround:** Use HTTP coercion (WebClient service + PetitPotam) to capture authentication over HTTP instead of SMB. HTTP clients don't set NEGOTIATE_SIGN, so HTTP→LDAPS relay works on patched DCs.

**Status:** By design (protocol limitation). Not fixable.

---

## 8. Remaining Gaps (Low Priority)

These Impacket features are not yet implemented due to infrastructure requirements:

| Feature | Requirement |
|---------|-------------|
| IMAP relay client + attack | Needs Exchange/IMAP server |
| SMTP relay client | Needs SMTP server |
| SCCM policies/DP attacks | Needs SCCM infrastructure |
