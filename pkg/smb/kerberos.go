// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smb

import (
	"encoding/asn1"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/gssapi"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/types"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/third_party/smb2"
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
