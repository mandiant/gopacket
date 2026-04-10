// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package ntlm

import (
	"bytes"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"log"

	"gopacket/internal/build"
	"gopacket/pkg/utf16le"
)

type Session struct {
	isClientSide bool

	user string

	negotiateFlags     uint32
	exportedSessionKey []byte
	clientSigningKey   []byte
	serverSigningKey   []byte

	clientHandle *rc4.Cipher
	serverHandle *rc4.Cipher

	infoMap map[uint16][]byte
}

func (s *Session) User() string {
	return s.user
}

func (s *Session) SessionKey() []byte {
	return s.exportedSessionKey
}

type InfoMap struct {
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
	// Flags           uint32
	// Timestamp       time.Time
	// SingleHost
	// TargetName string
	// ChannelBindings
}

// InfoMap returns the negotiated target information block as a structured map.
func (s *Session) InfoMap() *InfoMap {
	return &InfoMap{
		NbComputerName:  utf16le.DecodeToString(s.infoMap[MsvAvNbComputerName]),
		NbDomainName:    utf16le.DecodeToString(s.infoMap[MsvAvNbDomainName]),
		DnsComputerName: utf16le.DecodeToString(s.infoMap[MsvAvDnsComputerName]),
		DnsDomainName:   utf16le.DecodeToString(s.infoMap[MsvAvDnsDomainName]),
		DnsTreeName:     utf16le.DecodeToString(s.infoMap[MsvAvDnsTreeName]),
		// Flags:           le.Uint32(s.infoMap[MsvAvFlags]),
	}
}

func (s *Session) Overhead() int {
	return 16
}

// Encrypt encrypts data using the client's RC4 handle.
// For DCE/RPC Packet Privacy, call this first before Sign.
func (s *Session) Encrypt(plaintext []byte) []byte {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL == 0 {
		return plaintext
	}
	ciphertext := make([]byte, len(plaintext))
	s.clientHandle.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// Sign computes a signature (MAC) over the given data.
// For DCE/RPC, this should be called AFTER Encrypt, on the full PDU data.
func (s *Session) Sign(data []byte, seqNum uint32) ([]byte, uint32) {
	if build.Debug {
		log.Printf("[D] Session.Sign: flags=0x%08x, seqNum=%d, dataLen=%d", s.negotiateFlags, seqNum, len(data))
	}
	if s.isClientSide {
		return mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, data)
	}
	return mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, data)
}

// Decrypt decrypts data using the server's RC4 handle.
func (s *Session) Decrypt(ciphertext []byte) []byte {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL == 0 {
		return ciphertext
	}
	plaintext := make([]byte, len(ciphertext))
	s.serverHandle.XORKeyStream(plaintext, ciphertext)
	return plaintext
}

// Verify checks a signature over data using server handle.
func (s *Session) Verify(signature, data []byte, seqNum uint32) (bool, uint32) {
	var expected []byte
	if s.isClientSide {
		expected, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, data)
	} else {
		expected, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, data)
	}
	if build.Debug && !bytes.Equal(signature, expected) {
		log.Printf("[D] Session.Verify MISMATCH: got=%s, expected=%s", hex.EncodeToString(signature), hex.EncodeToString(expected))
	}
	return bytes.Equal(signature, expected), seqNum
}

func (s *Session) Sum(plaintext []byte, seqNum uint32) ([]byte, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		return nil, 0
	}

	if s.isClientSide {
		return mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	}
	return mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
}

func (s *Session) CheckSum(Sum, plaintext []byte, seqNum uint32) (bool, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		if Sum == nil {
			return true, 0
		}
		return false, 0
	}

	if s.isClientSide {
		ret, seqNum := mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		if !bytes.Equal(Sum, ret) {
			return false, 0
		}
		return true, seqNum
	}
	ret, seqNum := mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	if !bytes.Equal(Sum, ret) {
		return false, 0
	}
	return true, seqNum
}

func (s *Session) Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32) {
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+16)

	if build.Debug {
		log.Printf("[D] Session.Seal: flags=0x%08x, isClient=%v, seqNum=%d", s.negotiateFlags, s.isClientSide, seqNum)
		log.Printf("[D] Session.Seal: clientSigningKey=%s", hex.EncodeToString(s.clientSigningKey))
		log.Printf("[D] Session.Seal: exportedSessionKey=%s", hex.EncodeToString(s.exportedSessionKey))
	}

	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.clientHandle.XORKeyStream(ciphertext[16:], plaintext)

		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(ciphertext[16:], plaintext)

		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	}

	return ret, seqNum
}

func (s *Session) Unseal(dst, ciphertext []byte, seqNum uint32) ([]byte, uint32, error) {
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-16)

	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.serverHandle.XORKeyStream(plaintext, ciphertext[16:])

		var Sum []byte

		if s.isClientSide {
			Sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			Sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], Sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(plaintext, ciphertext[16:])

		var Sum []byte

		if s.isClientSide {
			Sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			Sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], Sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	default:
		copy(plaintext, ciphertext[16:])
		for _, s := range ciphertext[:16] {
			if s != 0x0 {
				return nil, 0, errors.New("signature mismatch")
			}
		}
	}

	return ret, seqNum, nil
}
