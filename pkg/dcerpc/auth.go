// SPDX-License-Identifier: Apache-2.0

package dcerpc

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/ntlm"
	"gopacket/pkg/session"
)

// RPCAuthHandler is the interface for RPC authentication handlers.
// Both NTLM and Kerberos auth handlers implement this interface.
type RPCAuthHandler interface {
	Encrypt(plaintext []byte) []byte
	Decrypt(ciphertext []byte) []byte
	Sign(data []byte) []byte
	Verify(signature, data []byte) bool
	GetClientSeqNum() uint32
	IsInitialized() bool
}

// AuthHandler manages the authentication context for RPC (NTLM).
type AuthHandler struct {
	Creds *session.Credentials

	// NTLM State
	ntlmClient *ntlm.Client

	// Session Key (negotiated)
	SessionKey []byte

	// Full NTLM Session for Seal/Unseal operations
	Session *ntlm.Session

	// Separate sequence numbers for each direction
	// Client->Server uses ClientSeqNum, Server->Client uses ServerSeqNum
	ClientSeqNum uint32
	ServerSeqNum uint32
}

func NewAuthHandler(creds *session.Credentials) *AuthHandler {
	return &AuthHandler{Creds: creds}
}

// GetNegotiateToken generates the initial token (NTLM Negotiate).
func (a *AuthHandler) GetNegotiateToken() ([]byte, error) {
	// Prepare Hash bytes if present
	var hashBytes []byte
	if a.Creds.Hash != "" {
		parts := strings.Split(a.Creds.Hash, ":")
		ntHashStr := parts[0]
		if len(parts) == 2 {
			ntHashStr = parts[1]
		}
		if ntHashStr != "" {
			hashBytes, _ = hex.DecodeString(ntHashStr)
		}
	}

	c := &ntlm.Client{
		User:        a.Creds.Username,
		Password:    a.Creds.Password,
		Hash:        hashBytes,
		Domain:      a.Creds.Domain,
		Workstation: "GOPACKET",
	}

	if build.Debug {
		log.Printf("[D] NTLM Client: User=%s, Domain=%s, HasPassword=%v, HasHash=%v",
			c.User, c.Domain, c.Password != "", len(c.Hash) > 0)
	}

	a.ntlmClient = c
	return c.Negotiate()
}

// GetAuthenticateToken processes the challenge and returns the auth token.
func (a *AuthHandler) GetAuthenticateToken(challenge []byte) ([]byte, error) {
	if a.ntlmClient == nil {
		return nil, fmt.Errorf("auth not initialized")
	}

	auth, err := a.ntlmClient.Authenticate(challenge)
	if err != nil {
		return nil, err
	}

	// Store full session for Seal/Unseal operations
	a.Session = a.ntlmClient.Session()
	a.SessionKey = a.Session.SessionKey()

	// Initialize separate sequence numbers for each direction
	a.ClientSeqNum = 0
	a.ServerSeqNum = 0

	if build.Debug {
		log.Printf("[D] NTLM Session established")
		log.Printf("[D] NTLM SessionKey: %s", hex.EncodeToString(a.SessionKey))
	}

	return auth, nil
}

// Seal encrypts data and returns [signature][ciphertext].
// Updates ClientSeqNum automatically.
func (a *AuthHandler) Seal(plaintext []byte) []byte {
	if a.Session == nil {
		return nil
	}
	if build.Debug {
		log.Printf("[D] NTLM Seal: plaintext len=%d, SeqNum=%d", len(plaintext), a.ClientSeqNum)
		log.Printf("[D] NTLM Seal: plaintext hex: %s", hex.EncodeToString(plaintext))
	}
	sealed, newSeq := a.Session.Seal(nil, plaintext, a.ClientSeqNum)
	if build.Debug {
		log.Printf("[D] NTLM Seal: signature: %s", hex.EncodeToString(sealed[:16]))
		log.Printf("[D] NTLM Seal: ciphertext: %s", hex.EncodeToString(sealed[16:]))
	}
	a.ClientSeqNum = newSeq
	return sealed
}

// Unseal decrypts data from [signature][ciphertext] format.
// Updates ServerSeqNum automatically.
func (a *AuthHandler) Unseal(ciphertext []byte) ([]byte, error) {
	if a.Session == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	plaintext, newSeq, err := a.Session.Unseal(nil, ciphertext, a.ServerSeqNum)
	if err != nil {
		return nil, err
	}
	a.ServerSeqNum = newSeq
	return plaintext, nil
}

// Encrypt encrypts data for DCE/RPC Packet Privacy.
// Must be called before Sign. Does not update SeqNum (Sign does that).
func (a *AuthHandler) Encrypt(plaintext []byte) []byte {
	if a.Session == nil {
		return nil
	}
	return a.Session.Encrypt(plaintext)
}

// Sign computes signature over data (typically the full PDU minus auth verifier).
// Must be called after Encrypt. Updates ClientSeqNum.
func (a *AuthHandler) Sign(data []byte) []byte {
	if a.Session == nil {
		return nil
	}
	sig, newSeq := a.Session.Sign(data, a.ClientSeqNum)
	if build.Debug {
		log.Printf("[D] AuthHandler.Sign: ClientSeqNum=%d->%d, computed signature: %s", a.ClientSeqNum, newSeq, hex.EncodeToString(sig))
	}
	a.ClientSeqNum = newSeq
	return sig
}

// Decrypt decrypts data from DCE/RPC response.
func (a *AuthHandler) Decrypt(ciphertext []byte) []byte {
	if a.Session == nil {
		return nil
	}
	return a.Session.Decrypt(ciphertext)
}

// Verify checks signature over data (typically full response PDU minus auth verifier).
// Updates ServerSeqNum to keep in sync with RC4 state.
func (a *AuthHandler) Verify(signature, data []byte) bool {
	if a.Session == nil {
		return false
	}
	ok, newSeq := a.Session.Verify(signature, data, a.ServerSeqNum)
	if build.Debug {
		log.Printf("[D] AuthHandler.Verify: dataLen=%d, ServerSeqNum=%d->%d, ok=%v", len(data), a.ServerSeqNum, newSeq, ok)
	}
	// Always update ServerSeqNum to keep in sync with RC4 state
	a.ServerSeqNum = newSeq
	return ok
}

// GetClientSeqNum returns the current client sequence number.
// Implements RPCAuthHandler interface.
func (a *AuthHandler) GetClientSeqNum() uint32 {
	return a.ClientSeqNum
}

// IsInitialized returns true if the auth handler has a valid session.
// Implements RPCAuthHandler interface.
func (a *AuthHandler) IsInitialized() bool {
	return a.Session != nil
}
