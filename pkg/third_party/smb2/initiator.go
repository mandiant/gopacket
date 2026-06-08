package smb2

import (
	"encoding/asn1"

	"github.com/mandiant/gopacket/pkg/third_party/smb2/internal/ntlm"
	"github.com/mandiant/gopacket/pkg/third_party/smb2/internal/spnego"
)

type Initiator interface {
	OID() asn1.ObjectIdentifier
	InitSecContext() ([]byte, error)            // GSS_Init_sec_context
	AcceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	Sum(bs []byte) []byte                       // GSS_getMIC
	SessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	ntlm   *ntlm.Client
	seqNum uint32
}

func (i *NTLMInitiator) OID() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMInitiator) InitSecContext() ([]byte, error) {
	i.ntlm = &ntlm.Client{
		User:        i.User,
		Password:    i.Password,
		Hash:        i.Hash,
		Domain:      i.Domain,
		Workstation: i.Workstation,
		TargetSPN:   i.TargetSPN,
	}
	nmsg, err := i.ntlm.Negotiate()
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.ntlm.Authenticate(sc)
	if err != nil {
		return nil, err
	}
	return amsg, nil
}

func (i *NTLMInitiator) Sum(bs []byte) []byte {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMInitiator) SessionKey() []byte {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) infoMap() *ntlm.InfoMap {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	return i.ntlm.Session().InfoMap()
}

// InfoMap returns the NTLM target info from the authentication exchange.
func (i *NTLMInitiator) InfoMap() *ntlm.InfoMap {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	return i.ntlm.Session().InfoMap()
}
