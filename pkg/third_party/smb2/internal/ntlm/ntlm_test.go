package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"

	"testing"

	"github.com/mandiant/gopacket/pkg/third_party/smb2/internal/utf16le"
)

func TestNtowfv2(t *testing.T) {
	USER := utf16le.EncodeStringToBytes("USER")
	password := utf16le.EncodeStringToBytes("Password")
	domain := utf16le.EncodeStringToBytes("Domain")
	ntlmv2Hash, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if err != nil {
		t.Fatal(err)
	}

	ret := ntowfv2(USER, password, domain)

	if !bytes.Equal(ret, ntlmv2Hash) {
		t.Errorf("expected %v, got %v", ntlmv2Hash, ret)
	}
}

type simpleEncoder []byte

func (s simpleEncoder) size() int {
	return len(s)
}

func (s simpleEncoder) encode(bs []byte) {
	copy(bs, s)
}

func TestNtlmv2ClientChallenge(t *testing.T) {
	ntlmv2Hash, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if err != nil {
		t.Fatal(err)
	}
	serverChallenge, err := hex.DecodeString("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	clientChallenge, err := hex.DecodeString("aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := hex.DecodeString("0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	targetInfo, err := hex.DecodeString(
		"0200" + "0c00" + "44006f006d00610069006e00" + // MsvAvNbDomainName + dataLen + data
			"0100" + "0c00" + "530065007200760065007200" + // MsvAvNbComputerName + dataLen + data
			"0000" + "0000") // MsvAvEOL + dataLen
	if err != nil {
		t.Fatal(err)
	}
	temp, err := hex.DecodeString("01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	ntlmv2Response, err := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c")
	if err != nil {
		t.Fatal(err)
	}

	h := hmac.New(md5.New, ntlmv2Hash)

	ret := make([]byte, 16+28+len(targetInfo)+4)
	encodeNtlmv2Response(ret, h, serverChallenge, clientChallenge, timestamp, simpleEncoder(targetInfo))

	if !bytes.Equal(ret[16:], temp) {
		t.Errorf("expected %v, got %v", temp, ret[16:])
	}

	if !bytes.Equal(ret[:16], ntlmv2Response) {
		t.Errorf("expected %v, got %v", ntlmv2Response, ret[:16])
	}
}

func TestSessionBaseKey(t *testing.T) {
	ntlmv2Hash, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if err != nil {
		t.Fatal(err)
	}

	ntlmv2Response, err := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c")
	if err != nil {
		t.Fatal(err)
	}

	sessionBaseKey, err := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if err != nil {
		t.Fatal(err)
	}

	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(ntlmv2Response)
	ret := h.Sum(nil)

	if !bytes.Equal(ret, sessionBaseKey) {
		t.Errorf("expected %v, got %v", sessionBaseKey, ret)
	}
}

func TestEncryptedSessionKey(t *testing.T) {
	randomSessionKey, err := hex.DecodeString("55555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	sessionBaseKey, err := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if err != nil {
		t.Fatal(err)
	}
	encryptedSessionKey, err := hex.DecodeString("c5dad2544fc9799094ce1ce90bc9d03e")
	if err != nil {
		t.Fatal(err)
	}

	keyExchangeKey := sessionBaseKey

	cipher, err := rc4.NewCipher(keyExchangeKey)
	if err != nil {
		t.Fatal(err)
	}

	ret := make([]byte, 16)

	cipher.XORKeyStream(ret, randomSessionKey)

	if !bytes.Equal(ret, encryptedSessionKey) {
		t.Errorf("expected %v, got %v", encryptedSessionKey, ret)
	}
}

func TestSealKey(t *testing.T) {
	randomSessionKey, err := hex.DecodeString("55555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	clientSealKey, err := hex.DecodeString("59f600973cc4960a25480a7c196e4c58")
	if err != nil {
		t.Fatal(err)
	}

	ret := sealKey(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|NTLMSSP_NEGOTIATE_128, randomSessionKey, true)

	if !bytes.Equal(ret, clientSealKey) {
		t.Errorf("expected %v, got %v", clientSealKey, ret)
	}
}

func TestSignKey(t *testing.T) {
	randomSessionKey, err := hex.DecodeString("55555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	clientSignKey, err := hex.DecodeString("4788dc861b4782f35d43fd98fe1a2d39")
	if err != nil {
		t.Fatal(err)
	}

	ret := signKey(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, randomSessionKey, true)

	if !bytes.Equal(ret, clientSignKey) {
		t.Errorf("expected %v, got %v", clientSignKey, ret)
	}
}

func TestSeal(t *testing.T) {
	seqNum := uint32(0)
	clientSealKey, err := hex.DecodeString("59f600973cc4960a25480a7c196e4c58")
	if err != nil {
		t.Fatal(err)
	}
	clientSignKey, err := hex.DecodeString("4788dc861b4782f35d43fd98fe1a2d39")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString("54e50165bf1936dc996020c1811b0f06fb5f")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString("010000007fb38ec5c55d497600000000")
	if err != nil {
		t.Fatal(err)
	}
	clientHandle, err := rc4.NewCipher(clientSealKey)
	if err != nil {
		t.Fatal(err)
	}
	plainText := utf16le.EncodeStringToBytes("Plaintext")
	ret := make([]byte, len(plainText)+16)
	clientHandle.XORKeyStream(ret[16:], plainText)
	mac(ret[:0], NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|NTLMSSP_NEGOTIATE_KEY_EXCH, clientHandle, clientSignKey, seqNum, plainText)

	if !bytes.Equal(ret[16:], data) {
		t.Errorf("expected %v, got %v", data, ret[16:])
	}

	if !bytes.Equal(ret[:16], signature) {
		t.Errorf("expected %v, got %v", signature, ret[:16])
	}
}

func TestAnonymousAuthenticate(t *testing.T) {
	// Empty User/Password/Hash => true anonymous (null session) bind.
	// Set Domain/Workstation to confirm they're stripped from the token
	// rather than leaked into the payload.
	c := &Client{
		Domain:      "SHOULD_NOT_APPEAR",
		Workstation: "SHOULD_NOT_APPEAR",
	}

	s := NewServer("server")

	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}

	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}

	amsg, err := c.Authenticate(cmsg)
	if err != nil {
		t.Fatalf("anonymous Authenticate returned error: %v", err)
	}
	if amsg == nil {
		t.Fatal("anonymous Authenticate returned nil message")
	}

	if le.Uint32(amsg[60:64])&NTLMSSP_ANONYMOUS == 0 {
		t.Errorf("NTLMSSP_ANONYMOUS flag not set in NegotiateFlags %#x", le.Uint32(amsg[60:64]))
	}

	if got := le.Uint16(amsg[12:14]); got != 1 {
		t.Errorf("LmChallengeResponseLen = %d, want 1", got)
	}

	if got := le.Uint16(amsg[20:22]); got != 0 {
		t.Errorf("NtChallengeResponseLen = %d, want 0", got)
	}

	if got := le.Uint16(amsg[28:30]); got != 0 {
		t.Errorf("DomainNameLen = %d, want 0 (must not leak)", got)
	}

	if got := le.Uint16(amsg[36:38]); got != 0 {
		t.Errorf("UserNameLen = %d, want 0", got)
	}

	if got := le.Uint16(amsg[44:46]); got != 0 {
		t.Errorf("WorkstationLen = %d, want 0 (must not leak)", got)
	}

	// LmChallengeResponse must be a single 0x00 byte at its declared offset.
	lmOff := le.Uint32(amsg[16:20])
	if int(lmOff) >= len(amsg) {
		t.Fatalf("LmChallengeResponseBufferOffset %d out of range (len %d)", lmOff, len(amsg))
	}
	if amsg[lmOff] != 0 {
		t.Errorf("LmChallengeResponse byte = %#x, want 0x00", amsg[lmOff])
	}

	// No session key for a null session.
	if c.Session() != nil {
		t.Error("expected nil session for anonymous bind")
	}

	// No MIC on the anonymous path.
	if !bytes.Equal(amsg[72:88], make([]byte, 16)) {
		t.Errorf("expected zero MIC, got %x", amsg[72:88])
	}
}

func TestClientServer(t *testing.T) {
	c := &Client{
		User:     "user",
		Password: "password",
	}

	s := NewServer("server")

	s.AddAccount("user", "password")

	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}

	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}

	amsg, err := c.Authenticate(cmsg)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Authenticate(amsg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Session() == nil {
		t.Error("error")
	}
	if s.Session() == nil {
		t.Error("error")
	}
}
