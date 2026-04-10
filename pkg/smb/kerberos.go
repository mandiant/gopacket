// SPDX-License-Identifier: Apache-2.0

package smb

import (
	"encoding/asn1"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/types"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/thirdparty/smb2"
)

// OID for Kerberos V5
var OIDKerberos = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

type KerberosInitiator struct {
	KrbClient *kerberos.Client
	TargetSPN string

	sessionKey types.EncryptionKey // Full key including type for MIC calculation
}

func (k *KerberosInitiator) OID() asn1.ObjectIdentifier {
	return OIDKerberos
}

func (k *KerberosInitiator) InitSecContext() ([]byte, error) {
	// Generate AP-REQ with full key (includes encryption type)
	apReq, key, err := k.KrbClient.GenerateAPReqFull(k.TargetSPN)
	if err != nil {
		return nil, err
	}
	k.sessionKey = key
	return apReq, nil
}

func (k *KerberosInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
	// Handle mutual auth response (AP-REP) if needed.
	// For SMB, we usually just succeed if we get here?
	// Real implementation should parse AP-REP and verify signature.
	return nil, nil
}

func (k *KerberosInitiator) Sum(b []byte) []byte {
	// GSS_GetMIC for Kerberos (RFC 4121)
	// This is used for SPNEGO mechListMIC during authentication
	if k.sessionKey.KeyValue == nil {
		return nil
	}

	// Create MIC token using gokrb5's GSSAPI support
	micToken, err := gssapi.NewInitiatorMICToken(b, k.sessionKey)
	if err != nil {
		return nil
	}

	micBytes, err := micToken.Marshal()
	if err != nil {
		return nil
	}

	return micBytes
}

func (k *KerberosInitiator) SessionKey() []byte {
	// SMB2 expects a 16-byte session key for signing/encryption
	// AES256 keys are 32 bytes, but SMB2 derives a 16-byte signing key from it
	if len(k.sessionKey.KeyValue) > 16 {
		return k.sessionKey.KeyValue[:16]
	}
	return k.sessionKey.KeyValue
}

// Verify compliance
var _ smb2.Initiator = (*KerberosInitiator)(nil)
