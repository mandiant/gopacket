package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/mandiant/gopacket/pkg/third_party/smb2/internal/crypto/ccm"
	"github.com/mandiant/gopacket/pkg/third_party/smb2/internal/crypto/cmac"

	. "github.com/mandiant/gopacket/pkg/third_party/smb2/internal/erref"
	. "github.com/mandiant/gopacket/pkg/third_party/smb2/internal/smb2"
)

func sessionSetup(conn *conn, i Initiator, ctx context.Context) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})

	outputToken, err := spnego.InitSecContext()
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	req := &SessionSetupRequest{
		Flags:             0,
		Capabilities:      conn.capabilities & (SMB2_GLOBAL_CAP_DFS),
		Channel:           0,
		SecurityBuffer:    outputToken,
		PreviousSessionId: 0,
	}

	if conn.requireSigning {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	req.CreditCharge = 1
	req.CreditRequestResponse = conn.account.initRequest()

	rr, err := conn.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := conn.recv(rr)
	if err != nil {
		return nil, err
	}

	p := PacketCodec(pkt)
	status := NtStatus(p.Status())

	// gopacket Fix: Allow STATUS_SUCCESS for Kerberos immediate auth
	if status != STATUS_MORE_PROCESSING_REQUIRED && status != STATUS_SUCCESS {
		return nil, &InvalidResponseError{fmt.Sprintf("expected status: %v or %v, got %v", STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, status)}
	}

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return nil, err
	}

	r := SessionSetupResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	sessionFlags := r.SessionFlags()
	if conn.requireSigning {
		if sessionFlags&SMB2_SESSION_FLAG_IS_GUEST != 0 {
			return nil, &InvalidResponseError{"guest account doesn't support signing"}
		}
		if sessionFlags&SMB2_SESSION_FLAG_IS_NULL != 0 {
			return nil, &InvalidResponseError{"anonymous account doesn't support signing"}
		}
	}

	s := &session{
		conn:           conn,
		treeConnTables: make(map[uint32]*treeConn),
		sessionFlags:   sessionFlags,
		sessionId:      p.SessionId(),
	}

	switch conn.dialect {
	case SMB311:
		s.preauthIntegrityHashValue = conn.preauthIntegrityHashValue

		// Hash the SESSION_SETUP request we just sent.
		s.updatePreauthIntegrity(conn.preauthIntegrityHashId, rr.pkt)

		// Only hash the response when the exchange continues (another leg
		// follows). The final SESSION_SETUP response — STATUS_SUCCESS, which
		// Kerberos returns on the very first leg — is NOT part of the preauth
		// integrity hash. Folding it in (and then re-hashing this leg's request
		// again below) produced the wrong SMB 3.1.1 signing key for the
		// single-leg Kerberos path.
		if status == STATUS_MORE_PROCESSING_REQUIRED {
			s.updatePreauthIntegrity(conn.preauthIntegrityHashId, pkt)
		}
	}

	// gopacket Fix: Only proceed to second leg if MORE_PROCESSING_REQUIRED
	if status == STATUS_MORE_PROCESSING_REQUIRED {
		outputToken, err = spnego.AcceptSecContext(r.SecurityBuffer())
		if err != nil {
			return nil, &InvalidResponseError{err.Error()}
		}

		req.SecurityBuffer = outputToken

		req.CreditRequestResponse = 0

		// We set session before sending packet just for setting hdr.SessionId.
		// But, we should not permit access from receiver until the session information is completed.
		conn.session = s

		rr, err = s.send(req, ctx)
		if err != nil {
			return nil, err
		}

		// Chain this (second) SESSION_SETUP request into the preauth hash.
		// Its response is the final one (STATUS_SUCCESS) and is excluded.
		if conn.dialect == SMB311 {
			s.updatePreauthIntegrity(conn.preauthIntegrityHashId, rr.pkt)
		}

		pkt, err = s.recv(rr)
		if err != nil {
			return nil, err
		}

		res, err = accept(SMB2_SESSION_SETUP, pkt)
		if err != nil {
			return nil, err
		}

		r = SessionSetupResponseDecoder(res)
		if r.IsInvalid() {
			return nil, &InvalidResponseError{"broken session setup response format"}
		}

		if NtStatus(PacketCodec(pkt).Status()) != STATUS_SUCCESS {
			return nil, &InvalidResponseError{"broken session setup response format"}
		}

		s.sessionFlags = r.SessionFlags()
	} else {
		// STATUS_SUCCESS immediately.
		// We still need to populate session s logic below (Key derivation).
		// We might want to call AcceptSecContext just to finalize state if there is a token (Mutual Auth)
		// but go-smb2 logic above puts it in 'outputToken' which is then sent.
		// If we are SUCCESS, we don't send.
		
		// Ensure conn.session is set
		conn.session = s
	}

	// now, allow access from receiver
	s.enableSession()

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
		SessionKey := spnego.SessionKey()

		switch conn.dialect {
		case SMB202, SMB210:
			s.signer = hmac.New(sha256.New, SessionKey)
			s.verifier = hmac.New(sha256.New, SessionKey)
		case SMB300, SMB302:
			signingKey := kdf(SessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)
			s.verifier = cmac.New(ciph)

			// s.applicationKey = kdf(SessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))

			encryptionKey := kdf(SessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
			decryptionKey := kdf(SessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

			ciph, err = aes.NewCipher(encryptionKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
		case SMB311:
			// Session.PreauthIntegrityHashValue is already finalized above:
			// every participating SESSION_SETUP message was chained in as it
			// was sent/received, so derive the signing key directly from it.
			signingKey := kdf(SessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)
			s.verifier = cmac.New(ciph)

			// s.applicationKey = kdf(SessionKey, []byte("SMBAppKey\x00"), preauthIntegrityHashValue)

			encryptionKey := kdf(SessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])
			decryptionKey := kdf(SessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])

			switch s.cipherId {
			case AES128CCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			case AES128GCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			}
		}
	}

	return s, nil
}

type session struct {
	*conn
	treeConnTables            map[uint32]*treeConn
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	signer    hash.Hash
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// applicationKey []byte
}

func (s *session) logoff(ctx context.Context) error {
	req := new(LogoffRequest)

	req.CreditCharge = 1

	_, err := s.sendRecv(SMB2_LOGOFF, req, ctx)
	if err != nil {
		return err
	}

	s.conn.rdone <- struct{}{}
	s.conn.t.Close()

	return nil
}

func (s *session) sendRecv(cmd uint16, req Packet, ctx context.Context) (res []byte, err error) {
	rr, err := s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (s *session) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = s.conn.recv(rr)
	if err != nil {
		return nil, err
	}
	if sessionId := PacketCodec(pkt).SessionId(); sessionId != s.sessionId {
		return nil, &InvalidResponseError{fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId)}
	}
	return pkt, err
}

// updatePreauthIntegrity folds data into Session.PreauthIntegrityHashValue
// (MS-SMB2 3.2.5.3.1). The negotiate exchange seeds the value on the conn; the
// session then chains each SMB2 SESSION_SETUP message that participates in the
// preauth hash. The final SESSION_SETUP response (STATUS_SUCCESS) is excluded
// by the caller.
func (s *session) updatePreauthIntegrity(hashId uint16, data []byte) {
	switch hashId {
	case SHA512:
		h := sha512.New()
		h.Write(s.preauthIntegrityHashValue[:])
		h.Write(data)
		h.Sum(s.preauthIntegrityHashValue[:0])
	}
}

func (s *session) sign(pkt []byte) []byte {
	p := PacketCodec(pkt)

	p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)

	h := s.signer

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return pkt
}

func (s *session) verify(pkt []byte) (ok bool) {
	p := PacketCodec(pkt)

	signature := append([]byte{}, p.Signature()...)

	p.SetSignature(zero[:])

	h := s.verifier

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	// Constant-time compare: these are cryptographic MACs (HMAC-SHA256 /
	// AES-CMAC), so avoid leaking match position via timing.
	return hmac.Equal(signature, p.Signature())
}

func (s *session) encrypt(pkt []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 52+len(pkt)+16)

	t := TransformCodec(c)

	t.SetProtocolId()
	t.SetNonce(nonce)
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(Encrypted)
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	t := TransformCodec(pkt)

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}