package smb2

import (
	"encoding/asn1"

	"gopacket/pkg/thirdparty/smb2/internal/spnego"
)

type spnegoClient struct {
	mechs        []Initiator
	mechTypes    []asn1.ObjectIdentifier
	selectedMech Initiator
}

func newSpnegoClient(mechs []Initiator) *spnegoClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.OID()
	}
	// Default selectedMech to the first one (Optimistic Token)
	// If the server rejects/negotiates, AcceptSecContext will update it.
	// This prevents panic if AcceptSecContext is skipped (Immediate Success).
	return &spnegoClient{
		mechs:        mechs,
		mechTypes:    mechTypes,
		selectedMech: mechs[0], 
	}
}

func (c *spnegoClient) OID() asn1.ObjectIdentifier {
	return spnego.SpnegoOid
}

func (c *spnegoClient) InitSecContext() (negTokenInitBytes []byte, err error) {
	mechToken, err := c.mechs[0].InitSecContext()
	if err != nil {
		return nil, err
	}
	negTokenInitBytes, err = spnego.EncodeNegTokenInit(c.mechTypes, mechToken)
	if err != nil {
		return nil, err
	}
	return negTokenInitBytes, nil
}

func (c *spnegoClient) AcceptSecContext(negTokenRespBytes []byte) (negTokenRespBytes1 []byte, err error) {
	negTokenResp, err := spnego.DecodeNegTokenResp(negTokenRespBytes)
	if err != nil {
		return nil, err
	}

	// Update selectedMech based on server response
	if negTokenResp.SupportedMech != nil {
		for i, mechType := range c.mechTypes {
			if mechType.Equal(negTokenResp.SupportedMech) {
				c.selectedMech = c.mechs[i]
				break
			}
		}
	}

	responseToken, err := c.selectedMech.AcceptSecContext(negTokenResp.ResponseToken)
	if err != nil {
		return nil, err
	}

	ms, err := asn1.Marshal(c.mechTypes)
	if err != nil {
		return nil, err
	}

	mechListMIC := c.selectedMech.Sum(ms)

	negTokenRespBytes1, err = spnego.EncodeNegTokenResp(1, nil, responseToken, mechListMIC)
	if err != nil {
		return nil, err
	}

	return negTokenRespBytes1, nil
}

func (c *spnegoClient) Sum(bs []byte) []byte {
	if c.selectedMech == nil {
		return nil
	}
	return c.selectedMech.Sum(bs)
}

func (c *spnegoClient) SessionKey() []byte {
	if c.selectedMech == nil {
		return nil
	}
	return c.selectedMech.SessionKey()
}