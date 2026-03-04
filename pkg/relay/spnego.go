package relay

import (
	"encoding/asn1"
	"fmt"

	"github.com/geoffgarside/ber"
)

// OIDs for SPNEGO/NTLM
var (
	spnegoOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	nlmpOid   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

// negHints is "not_defined_in_RFC4178@please_ignore"
var negHints = asn1.RawValue{
	FullBytes: []byte{
		0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24,
		0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69,
		0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52,
		0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70,
		0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67,
		0x6e, 0x6f, 0x72, 0x65,
	},
}

// negTokenInit for marshaling inner struct only
type negTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

type negTokenInit2 struct {
	MechTypes []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags  asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken []byte                  `asn1:"explicit,optional,tag:2"`
	NegHints  asn1.RawValue           `asn1:"explicit,optional,tag:3"`
}

// negTokenResp for marshaling inner struct only
type negTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"optional,explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
	ResponseToken []byte                `asn1:"optional,explicit,tag:2"`
	MechListMIC   []byte                `asn1:"optional,explicit,tag:3"`
}

// initialContextTokenDecode is for BER decoding the NegTokenInit from victim's SESSION_SETUP.
// Init is NOT a slice because the wire format has a single NegTokenInit SEQUENCE inside [0],
// not a SEQUENCE OF.
type initialContextTokenDecode struct {
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init     negTokenInit          `asn1:"optional,explicit,tag:0"`
}

// encodeNegTokenInit2 creates the SPNEGO hint token for the NEGOTIATE response.
func encodeNegTokenInit2(mechTypes []asn1.ObjectIdentifier) ([]byte, error) {
	// Marshal NegTokenInit2 struct (produces SEQUENCE { fields... })
	inner := negTokenInit2{
		MechTypes: mechTypes,
		NegHints:  negHints,
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}

	// Wrap in [0] EXPLICIT context tag (NegTokenInit choice in SPNEGO)
	tagged0 := wrapExplicitTag(0, innerBytes)

	// Marshal SPNEGO OID
	oidBytes, err := asn1.Marshal(spnegoOid)
	if err != nil {
		return nil, err
	}

	// Combine OID + [0]{NegTokenInit} and wrap in APPLICATION 0
	payload := append(oidBytes, tagged0...)
	return wrapApplicationTag(0, payload), nil
}

// encodeNegTokenInitWithToken wraps a token in a SPNEGO NegTokenInit
// (APPLICATION 0 { OID spnego, [0] { NegTokenInit } })
func encodeNegTokenInitWithToken(mechTypes []asn1.ObjectIdentifier, token []byte) ([]byte, error) {
	// Marshal NegTokenInit struct
	inner := negTokenInit{
		MechTypes: mechTypes,
		MechToken: token,
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}

	// Wrap in [0] EXPLICIT context tag
	tagged0 := wrapExplicitTag(0, innerBytes)

	// Marshal SPNEGO OID
	oidBytes, err := asn1.Marshal(spnegoOid)
	if err != nil {
		return nil, err
	}

	// Combine and wrap in APPLICATION 0
	payload := append(oidBytes, tagged0...)
	return wrapApplicationTag(0, payload), nil
}

// encodeNegTokenResp wraps an NTLM token in a SPNEGO NegTokenResp
// ([1] { SEQUENCE { negState, supportedMech, responseToken } })
func encodeNegTokenResp(state asn1.Enumerated, mech asn1.ObjectIdentifier, token []byte) ([]byte, error) {
	// Marshal NegTokenResp struct (produces SEQUENCE { fields... })
	inner := negTokenResp{
		NegState:      state,
		SupportedMech: mech,
		ResponseToken: token,
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}

	// Wrap in [1] EXPLICIT context tag
	return wrapExplicitTag(1, innerBytes), nil
}

// encodeNegTokenRespAcceptCompleted builds a minimal SPNEGO NegTokenResp
// with only NegState=accept-completed (0x00). Used for the final SESSION_SETUP
// success response in the SMB SOCKS plugin. Matches Impacket's behavior.
func encodeNegTokenRespAcceptCompleted() []byte {
	// Manually encode: [1] { SEQUENCE { [0] ENUM { 0 } } }
	// NegState ENUMERATED accept-completed = 0
	enumBytes := []byte{0x0a, 0x01, 0x00}                         // ENUMERATED, len=1, value=0
	taggedEnum := []byte{0xa0, byte(len(enumBytes))}               // [0] EXPLICIT tag
	taggedEnum = append(taggedEnum, enumBytes...)
	seq := []byte{0x30, byte(len(taggedEnum))}                     // SEQUENCE
	seq = append(seq, taggedEnum...)
	// Wrap in [1] EXPLICIT context tag
	return wrapExplicitTag(1, seq)
}

// negTokenRespAuth is a minimal NegTokenResp with only ResponseToken.
// Used for the client's Type3 auth message — Impacket sends only ResponseToken
// without NegState or SupportedMech.
type negTokenRespAuth struct {
	ResponseToken []byte `asn1:"explicit,tag:2"`
}

// encodeNegTokenRespAuth wraps an NTLM Type3 in a SPNEGO NegTokenResp
// containing only the ResponseToken field (no NegState, no SupportedMech).
// This matches Impacket's behavior for the relay client's final auth message.
func encodeNegTokenRespAuth(token []byte) ([]byte, error) {
	inner := negTokenRespAuth{
		ResponseToken: token,
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}
	return wrapExplicitTag(1, innerBytes), nil
}

// decodeNegTokenInit extracts the MechToken (raw NTLM) from victim's SESSION_SETUP
func decodeNegTokenInit(bs []byte) ([]byte, error) {
	var init initialContextTokenDecode
	_, err := ber.UnmarshalWithParams(bs, &init, "application,tag:0")
	if err != nil {
		return nil, fmt.Errorf("failed to decode NegTokenInit: %v", err)
	}
	if len(init.Init.MechToken) == 0 {
		return nil, fmt.Errorf("no MechToken in NegTokenInit")
	}
	return init.Init.MechToken, nil
}

// decodeNegTokenResp extracts the ResponseToken (raw NTLM) from a SPNEGO NegTokenResp
func decodeNegTokenResp(bs []byte) ([]byte, error) {
	var resp negTokenResp
	_, err := ber.UnmarshalWithParams(bs, &resp, "explicit,tag:1")
	if err != nil {
		return nil, fmt.Errorf("failed to decode NegTokenResp: %v", err)
	}
	return resp.ResponseToken, nil
}

// wrapExplicitTag wraps data in an ASN.1 context-specific explicit tag
func wrapExplicitTag(tag int, data []byte) []byte {
	tagByte := byte(0xa0 | tag) // context-specific, constructed
	lenBytes := encodeASN1Length(len(data))
	result := make([]byte, 1+len(lenBytes)+len(data))
	result[0] = tagByte
	copy(result[1:], lenBytes)
	copy(result[1+len(lenBytes):], data)
	return result
}

// wrapApplicationTag wraps data in an ASN.1 APPLICATION tag
func wrapApplicationTag(tag int, data []byte) []byte {
	tagByte := byte(0x60 | tag) // application, constructed
	lenBytes := encodeASN1Length(len(data))
	result := make([]byte, 1+len(lenBytes)+len(data))
	result[0] = tagByte
	copy(result[1:], lenBytes)
	copy(result[1+len(lenBytes):], data)
	return result
}

// encodeASN1Length encodes a length in ASN.1 DER format
func encodeASN1Length(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length < 0x100 {
		return []byte{0x81, byte(length)}
	}
	if length < 0x10000 {
		return []byte{0x82, byte(length >> 8), byte(length)}
	}
	return []byte{0x83, byte(length >> 16), byte(length >> 8), byte(length)}
}
