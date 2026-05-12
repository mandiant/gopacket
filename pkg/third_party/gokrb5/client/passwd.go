package client

import (
	"fmt"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/kadmin"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the password of the client to the value provided.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, err
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	err = r.Decrypt(key)
	if err != nil {
		return false, err
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %v", r.ResultCode, r.Result, r.KRBError)
	}
	cl.Credentials.WithPassword(newPasswd)
	return true, nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (r kadmin.Reply, err error) {
	_, kps, err := cl.Config.GetKpasswdServers(cl.Credentials.Domain(), true)
	if err != nil {
		return
	}
	b, err := msg.Marshal()
	if err != nil {
		return
	}
	// TCP-only. RFC 3244 allows both UDP and TCP for kpasswd; modern KDCs
	// (every AD DC, MIT krb5, Heimdal) all listen on TCP/464. We skip UDP
	// because (a) the UDPPreferenceLimit logic in the rest of this fork
	// forces TCP anyway, (b) a UDP→TCP fallback for kpasswd cannot rely on
	// checkForKRBError since kpasswd wraps responses in RFC 3244 framing
	// rather than emitting a bare ASN.1 KRBError at offset 0, and (c) under
	// the project's TransportKDCDialer + ErrUDPUnderProxy contract, UDP
	// would fail-closed under -proxy anyway.
	rb, err := cl.dialSendTCP(kps, b)
	if err != nil {
		return
	}
	err = r.Unmarshal(rb)
	return
}
