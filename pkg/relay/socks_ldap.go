// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"gopacket/internal/build"
)

// LDAP message tags
const (
	ldapTagSearchRequest = 3
	ldapTagSearchDone    = 5
	ldapTagSearchEntry   = 4
	ldapTagUnbindRequest = 2
	ldapTagExtendedReq   = 23
)

// StartTLS OID
const startTLSOID = "1.3.6.1.4.1.1466.20037"

// LDAPSocksPlugin implements the SOCKS plugin for LDAP/LDAPS protocol.
// Fakes SICILY NTLM bind with the SOCKS client using the stored challenge,
// then proxies BER-encoded LDAP messages. Matches Impacket's socksplugins/ldap.py.
type LDAPSocksPlugin struct {
	useTLS bool
}

func (p *LDAPSocksPlugin) InitConnection(clientConn net.Conn) error {
	return nil
}

func (p *LDAPSocksPlugin) SkipAuthentication(clientConn net.Conn, sd *SessionData, lookupRelay func(string) *ActiveRelay) (string, error) {
	if sd == nil || len(sd.ChallengeMessage) == 0 {
		return "", fmt.Errorf("no NTLM challenge data available")
	}

	for {
		// Read LDAP message from client
		clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		packet, err := ber.ReadPacket(clientConn)
		clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			return "", fmt.Errorf("read LDAP message: %v", err)
		}

		if len(packet.Children) < 2 {
			return "", fmt.Errorf("invalid LDAP message: expected at least 2 children")
		}

		msgID := packet.Children[0]
		op := packet.Children[1]

		// Handle pre-auth search requests (capability discovery)
		if op.Tag == ldapTagSearchRequest {
			if err := p.handlePreAuthSearch(clientConn, msgID, op); err != nil {
				return "", fmt.Errorf("pre-auth search: %v", err)
			}
			continue
		}

		// Must be a BindRequest (APPLICATION 0)
		if op.ClassType != ber.ClassApplication || op.Tag != 0 {
			return "", fmt.Errorf("expected BindRequest, got class=%d tag=%d", op.ClassType, op.Tag)
		}

		if len(op.Children) < 3 {
			return "", fmt.Errorf("invalid BindRequest: expected at least 3 children")
		}

		// Get the auth child
		authChild := op.Children[2]

		switch authChild.Tag {
		case ber.Tag(sicilyDiscoveryTag): // Tag 9: SICILY_PACKAGE_DISCOVERY
			if build.Debug {
				log.Printf("[D] SOCKS LDAP: SICILY discovery request")
			}
			// Reply with success, matchedDN = "NTLM"
			if err := p.sendBindResponse(clientConn, msgID, 0, "NTLM", ""); err != nil {
				return "", fmt.Errorf("send discovery response: %v", err)
			}

		case ber.Tag(sicilyNegotiateTag): // Tag 10: SICILY_NEGOTIATE_NTLM
			if build.Debug {
				log.Printf("[D] SOCKS LDAP: SICILY negotiate (Type1)")
			}

			// Strip NEGOTIATE_SIGN and NEGOTIATE_SEAL from stored Type2 challenge
			type2 := stripChallengeSignAndSealFlags(sd.ChallengeMessage)

			// Reply with Type2 challenge in matchedDN field (SICILY convention)
			if err := p.sendBindResponseWithChallenge(clientConn, msgID, 0, type2); err != nil {
				return "", fmt.Errorf("send challenge response: %v", err)
			}

		case ber.Tag(sicilyResponseTag): // Tag 11: SICILY_RESPONSE_NTLM
			if build.Debug {
				log.Printf("[D] SOCKS LDAP: SICILY response (Type3)")
			}

			// Extract NTLM Type3 from the auth data
			type3 := authChild.Data.Bytes()

			// Extract username from Type3
			domain, user := extractNTLMType3Info(type3)
			username := fmt.Sprintf("%s\\%s", strings.ToUpper(domain), strings.ToUpper(user))

			if build.Debug {
				log.Printf("[D] SOCKS LDAP: client authenticated as %s", username)
			}

			// Look up relay for this username
			relay := lookupRelay(username)
			if relay == nil {
				// Try NetBIOS domain (first part before '.')
				if idx := strings.Index(domain, "."); idx > 0 {
					netbios := strings.ToUpper(domain[:idx])
					altUsername := fmt.Sprintf("%s\\%s", netbios, strings.ToUpper(user))
					relay = lookupRelay(altUsername)
					if relay != nil {
						username = altUsername
					}
				}
			}

			if relay == nil {
				// Send invalid credentials
				p.sendBindResponse(clientConn, msgID, ldapResultInvalidCredentials, "", "")
				return "", fmt.Errorf("no relay found for user %s", username)
			}

			// Check if relay is already in use
			relay.mu.Lock()
			if relay.InUse {
				relay.mu.Unlock()
				p.sendBindResponse(clientConn, msgID, ldapResultInvalidCredentials, "", "session in use")
				return "", fmt.Errorf("relay for %s is already in use", username)
			}
			relay.mu.Unlock()

			// Send bind success
			if err := p.sendBindResponse(clientConn, msgID, 0, "", ""); err != nil {
				return "", fmt.Errorf("send auth success: %v", err)
			}

			log.Printf("[+] SOCKS LDAP: authenticated %s — routing through relay", username)
			return username, nil

		default:
			// Simple bind or other auth — try to handle as simple NTLM
			if build.Debug {
				log.Printf("[D] SOCKS LDAP: unexpected auth tag %d", authChild.Tag)
			}

			// Handle simple bind with empty creds as SICILY discovery
			if authChild.Tag == 0 {
				if err := p.sendBindResponse(clientConn, msgID, 0, "NTLM", ""); err != nil {
					return "", fmt.Errorf("send simple bind response: %v", err)
				}
				continue
			}

			return "", fmt.Errorf("unsupported auth tag %d", authChild.Tag)
		}
	}
}

func (p *LDAPSocksPlugin) TunnelConnection(clientConn net.Conn, relay *ActiveRelay) error {
	ldapClient, ok := relay.Client.(*LDAPRelayClient)
	if !ok || ldapClient.conn == nil {
		return fmt.Errorf("LDAP relay client has no underlying connection")
	}

	serverConn := ldapClient.conn

	// Bidirectional BER message proxying with select-like behavior
	errCh := make(chan error, 2)

	// Client → Server goroutine
	go func() {
		for {
			packet, err := ber.ReadPacket(clientConn)
			if err != nil {
				errCh <- fmt.Errorf("read from client: %v", err)
				return
			}

			if len(packet.Children) >= 2 {
				op := packet.Children[1]

				// Drop UnbindRequest (don't let SOCKS client destroy the relay session)
				if op.Tag == ldapTagUnbindRequest {
					if build.Debug {
						log.Printf("[D] SOCKS LDAP: dropping UnbindRequest from client")
					}
					errCh <- nil
					return
				}

				// Block StartTLS ExtendedRequest (would break the unencrypted tunnel)
				if op.Tag == ldapTagExtendedReq && len(op.Children) > 0 {
					if oid, ok := op.Children[0].Value.(string); ok && oid == startTLSOID {
						if build.Debug {
							log.Printf("[D] SOCKS LDAP: blocking StartTLS request")
						}
						continue
					}
				}
			}

			// Forward to server
			if _, err := serverConn.Write(packet.Bytes()); err != nil {
				errCh <- fmt.Errorf("write to server: %v", err)
				return
			}
		}
	}()

	// Server → Client goroutine
	go func() {
		for {
			packet, err := ber.ReadPacket(serverConn)
			if err != nil {
				errCh <- fmt.Errorf("read from server: %v", err)
				return
			}

			// Forward to client
			if _, err := clientConn.Write(packet.Bytes()); err != nil {
				errCh <- fmt.Errorf("write to client: %v", err)
				return
			}
		}
	}()

	// Wait for either direction to finish
	err := <-errCh
	return err
}

// handlePreAuthSearch handles pre-auth LDAP search requests from the client.
// Responds with Active Directory capabilities and forces NTLM auth.
// Matches Impacket's LDAP SOCKS plugin pre-auth search handling.
func (p *LDAPSocksPlugin) handlePreAuthSearch(conn net.Conn, msgID *ber.Packet, searchReq *ber.Packet) error {
	if len(searchReq.Children) < 7 {
		return nil
	}

	// Get the requested attributes
	attrs := searchReq.Children[6]
	var requestedAttrs []string
	for _, attr := range attrs.Children {
		if v, ok := attr.Value.(string); ok {
			requestedAttrs = append(requestedAttrs, strings.ToLower(v))
		}
	}

	if build.Debug {
		log.Printf("[D] SOCKS LDAP: pre-auth search for attrs: %v", requestedAttrs)
	}

	for _, attr := range requestedAttrs {
		switch attr {
		case "supportedsaslmechanisms":
			// Reply with only NTLM — force client to use NTLM auth
			if err := p.sendSearchEntry(conn, msgID, "", "supportedSASLMechanisms", []string{"NTLM"}); err != nil {
				return err
			}
		case "supportedcapabilities":
			// Reply with Active Directory capability OIDs
			if err := p.sendSearchEntry(conn, msgID, "", "supportedCapabilities", []string{
				"1.2.840.113556.1.4.800",  // LDAP_CAP_ACTIVE_DIRECTORY_OID
				"1.2.840.113556.1.4.1670", // LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
				"1.2.840.113556.1.4.1791", // LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
				"1.2.840.113556.1.4.1935", // LDAP_CAP_ACTIVE_DIRECTORY_V61_OID
			}); err != nil {
				return err
			}
		}
	}

	// Send SearchResultDone
	return p.sendSearchDone(conn, msgID, 0)
}

// sendBindResponse sends an LDAP BindResponse.
func (p *LDAPSocksPlugin) sendBindResponse(conn net.Conn, msgID *ber.Packet, resultCode int, matchedDN, diagnostic string) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	// Use same MessageID
	msgIDVal := int64(0)
	if v, ok := msgID.Value.(int64); ok {
		msgIDVal = v
	}
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgIDVal, "MessageID"))

	// BindResponse (APPLICATION 1)
	bindResp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "Bind Response")
	bindResp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "resultCode"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, matchedDN, "matchedDN"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))

	packet.AppendChild(bindResp)

	_, err := conn.Write(packet.Bytes())
	return err
}

// sendBindResponseWithChallenge sends a BindResponse with raw NTLM Type2 challenge
// in the serverSaslCreds field (context tag 7). Falls back to matchedDN for SICILY compatibility.
func (p *LDAPSocksPlugin) sendBindResponseWithChallenge(conn net.Conn, msgID *ber.Packet, resultCode int, challenge []byte) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	msgIDVal := int64(0)
	if v, ok := msgID.Value.(int64); ok {
		msgIDVal = v
	}
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgIDVal, "MessageID"))

	// BindResponse (APPLICATION 1)
	bindResp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 1, nil, "Bind Response")
	bindResp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "resultCode"))
	// SICILY puts the Type2 challenge in matchedDN
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(challenge), "matchedDN"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	// Also add serverSaslCreds (context tag 7) for standard SASL clients
	bindResp.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string(challenge), "serverSaslCreds"))

	packet.AppendChild(bindResp)

	_, err := conn.Write(packet.Bytes())
	return err
}

// sendSearchEntry sends a SearchResultEntry with the given attribute values.
func (p *LDAPSocksPlugin) sendSearchEntry(conn net.Conn, msgID *ber.Packet, dn, attrName string, values []string) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	msgIDVal := int64(0)
	if v, ok := msgID.Value.(int64); ok {
		msgIDVal = v
	}
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgIDVal, "MessageID"))

	// SearchResultEntry (APPLICATION 4)
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapTagSearchEntry, nil, "SearchResultEntry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))

	// Attributes (SEQUENCE OF PartialAttribute)
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")

	// Single attribute
	attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
	attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attrName, "type"))

	// Values (SET OF)
	valSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, 17, nil, "vals") // Tag 17 = SET
	for _, v := range values {
		valSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
	}
	attr.AppendChild(valSet)
	attrs.AppendChild(attr)
	entry.AppendChild(attrs)
	packet.AppendChild(entry)

	_, err := conn.Write(packet.Bytes())
	return err
}

// sendSearchDone sends a SearchResultDone.
func (p *LDAPSocksPlugin) sendSearchDone(conn net.Conn, msgID *ber.Packet, resultCode int) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	msgIDVal := int64(0)
	if v, ok := msgID.Value.(int64); ok {
		msgIDVal = v
	}
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgIDVal, "MessageID"))

	// SearchResultDone (APPLICATION 5)
	done := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapTagSearchDone, nil, "SearchResultDone")
	done.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "resultCode"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))

	packet.AppendChild(done)

	_, err := conn.Write(packet.Bytes())
	return err
}

// stripChallengeSignAndSealFlags strips NEGOTIATE_SIGN and NEGOTIATE_SEAL from an NTLM Type2 challenge.
// LDAP plugins strip both (unlike SMB which only strips SIGN) because LDAP signing/sealing
// would wrap every subsequent message in NTLM security context.
// Matches Impacket: challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)
func stripChallengeSignAndSealFlags(type2 []byte) []byte {
	if len(type2) < 24 {
		return type2
	}
	msg := make([]byte, len(type2))
	copy(msg, type2)

	// Flags in Type2 are at offset 20 (4 bytes, little-endian)
	flags := binary.LittleEndian.Uint32(msg[20:24])
	flags &^= ntlmsspNegotiateSign
	flags &^= ntlmsspNegotiateSeal
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	return msg
}
