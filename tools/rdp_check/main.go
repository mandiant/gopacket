package main

import (
	"crypto/tls"
	"encoding/asn1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"gopacket/pkg/flags"
	"gopacket/pkg/ntlm"
	"gopacket/pkg/session"
	"gopacket/pkg/transport"
)

// tsRequest represents a CredSSP TSRequest structure (MS-CSSP 2.2.1).
type tsRequest struct {
	Version    int           `asn1:"explicit,tag:0"`
	NegoTokens asn1.RawValue `asn1:"explicit,optional,tag:1"`
	AuthInfo   []byte        `asn1:"explicit,optional,tag:2"`
	PubKeyAuth []byte        `asn1:"explicit,optional,tag:3"`
	ErrorCode  int           `asn1:"explicit,optional,tag:4"`
}

// subjectPublicKeyInfo is used to parse the SubjectPublicKey from a certificate.
type subjectPublicKeyInfo struct {
	Algorithm asn1.RawValue
	PublicKey asn1.BitString
}

// RDP negotiation constants.
const (
	protocolHybrid = 0x02
	protocolSSL    = 0x01
)

func main() {
	opts := flags.Parse()
	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	// Default port for RDP is 3389 (flags defaults to 445 for SMB).
	if target.Port == 0 || target.Port == 445 {
		target.Port = 3389
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	// Parse NT hash for pass-the-hash.
	var ntHash []byte
	if creds.Hash != "" {
		parts := strings.Split(creds.Hash, ":")
		hashStr := parts[len(parts)-1]
		ntHash, err = hex.DecodeString(hashStr)
		if err != nil || len(ntHash) != 16 {
			log.Fatalf("[-] Invalid NT hash: %s", hashStr)
		}
	}

	// Step 1: TCP connect.
	addr := target.Addr()
	conn, err := transport.Dial(target.Network(), addr)
	if err != nil {
		log.Fatalf("[-] Failed to connect to %s: %v", addr, err)
	}
	defer conn.Close()

	// Step 2: Send X.224 Connection Request with RDP Negotiation Request.
	// TPKT header (4) + X.224 CR (7) + RDP_NEG_REQ (8) = 19 bytes.
	x224CR := []byte{
		// TPKT header
		0x03, 0x00, 0x00, 0x13,
		// X.224 Connection Request
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
		// RDP_NEG_REQ: type=1, flags=0, length=8, protocols=HYBRID|SSL
		0x01, 0x00, 0x08, 0x00,
		byte(protocolHybrid | protocolSSL), 0x00, 0x00, 0x00,
	}

	if _, err := conn.Write(x224CR); err != nil {
		log.Fatalf("[-] Failed to send X.224 Connection Request: %v", err)
	}

	// Step 3: Read X.224 Connection Confirm.
	ccBuf := make([]byte, 256)
	n, err := conn.Read(ccBuf)
	if err != nil {
		log.Fatalf("[-] Failed to read X.224 Connection Confirm: %v", err)
	}
	ccBuf = ccBuf[:n]

	// Verify TPKT and minimum length for negotiation response.
	if len(ccBuf) < 19 || ccBuf[0] != 0x03 {
		log.Fatalf("[-] Invalid X.224 Connection Confirm response")
	}

	// Check RDP_NEG_RSP: type byte at offset 11 should be 0x02 (TYPE_RDP_NEG_RSP).
	if ccBuf[11] != 0x02 {
		if ccBuf[11] == 0x03 {
			log.Fatalf("[-] Server returned RDP_NEG_FAILURE — NLA/CredSSP not supported")
		}
		log.Fatalf("[-] Unexpected negotiation response type: 0x%02X", ccBuf[11])
	}

	// Check that server selected PROTOCOL_HYBRID.
	selectedProto := uint32(ccBuf[15]) | uint32(ccBuf[16])<<8 | uint32(ccBuf[17])<<16 | uint32(ccBuf[18])<<24
	if selectedProto&protocolHybrid == 0 {
		log.Fatalf("[-] Server does not support CredSSP/NLA (selected protocol: 0x%X)", selectedProto)
	}

	// Step 4: TLS handshake.
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Fatalf("[-] TLS handshake failed: %v", err)
	}
	defer tlsConn.Close()

	// Extract the SubjectPublicKey from the server certificate.
	// MS-CSSP requires the ASN.1-encoded SubjectPublicKey sub-field,
	// not the full SubjectPublicKeyInfo wrapper.
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Fatalf("[-] No server certificate received")
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(certs[0].RawSubjectPublicKeyInfo, &spki); err != nil {
		log.Fatalf("[-] Failed to parse server public key: %v", err)
	}
	serverPubKey := spki.PublicKey.Bytes

	// Step 5: CredSSP/NTLM authentication.
	client := &ntlm.Client{
		User:     creds.Username,
		Password: creds.Password,
		Domain:   creds.Domain,
		Hash:     ntHash,
	}

	// 5a: Generate NTLM Type 1 (Negotiate).
	type1, err := client.Negotiate()
	if err != nil {
		log.Fatalf("[-] NTLM negotiate failed: %v", err)
	}

	// 5b: Send TSRequest with Type 1.
	if err := sendTSRequest(tlsConn, type1, nil); err != nil {
		log.Fatalf("[-] Failed to send TSRequest (Type 1): %v", err)
	}

	// 5c: Receive TSRequest with Type 2 (Challenge).
	tsResp, err := recvTSRequest(tlsConn)
	if err != nil {
		log.Fatalf("[-] Failed to receive TSRequest (Type 2): %v", err)
	}

	type2 := extractNegoToken(tsResp)
	if type2 == nil {
		log.Fatalf("[-] No NTLM challenge in server TSRequest")
	}

	// 5d: Generate NTLM Type 3 (Authenticate).
	type3, err := client.Authenticate(type2)
	if err != nil {
		log.Fatalf("[-] NTLM authenticate failed: %v", err)
	}

	sess := client.Session()
	if sess == nil {
		log.Fatalf("[-] NTLM session not established")
	}

	// 5e: Seal the server's public key for pubKeyAuth.
	sealedPubKey, _ := sess.Seal(nil, serverPubKey, 0)

	// 5f: Send TSRequest with Type 3 + sealed public key.
	if err := sendTSRequest(tlsConn, type3, sealedPubKey); err != nil {
		log.Fatalf("[-] Failed to send TSRequest (Type 3): %v", err)
	}

	// 5g: Read final response.
	finalResp, err := recvTSRequest(tlsConn)
	if err != nil {
		fmt.Println("[-] Access Denied")
		os.Exit(1)
	}

	if finalResp.ErrorCode != 0 || len(finalResp.PubKeyAuth) == 0 {
		fmt.Println("[-] Access Denied")
		os.Exit(1)
	}

	fmt.Println("[*] Access Granted")
}

// sendTSRequest marshals and sends a TSRequest over the TLS connection.
func sendTSRequest(conn *tls.Conn, negoToken, pubKeyAuth []byte) error {
	ts := tsRequest{
		Version: 2,
	}

	if negoToken != nil {
		// Build negoTokens: [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING }
		// Go's asn1.Marshal ignores struct field tags for RawValue,
		// so we set the [1] tag directly on the RawValue.
		octetStr := mustMarshalOctetString(negoToken)

		tag0 := mustMarshalRaw(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: octetStr,
		})

		innerSeq := mustMarshalRaw(asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
			Bytes: tag0,
		})

		outerSeq := mustMarshalRaw(asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
			Bytes: innerSeq,
		})

		ts.NegoTokens = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      outerSeq,
		}
	}

	if pubKeyAuth != nil {
		ts.PubKeyAuth = pubKeyAuth
	}

	data, err := asn1.Marshal(ts)
	if err != nil {
		return fmt.Errorf("marshal TSRequest: %w", err)
	}

	_, err = conn.Write(data)
	return err
}

// recvTSRequest reads and unmarshals a TSRequest from the TLS connection.
func recvTSRequest(conn *tls.Conn) (*tsRequest, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	data := buf[:n]

	totalLen := asn1TotalLength(data)
	for len(data) < totalLen {
		more := make([]byte, 4096)
		nn, err := conn.Read(more)
		if err != nil {
			if err == io.EOF && len(data) > 0 {
				break
			}
			return nil, err
		}
		data = append(data, more[:nn]...)
	}

	var ts tsRequest
	_, err = asn1.Unmarshal(data, &ts)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TSRequest: %w", err)
	}
	return &ts, nil
}

// extractNegoToken extracts the NTLM token from a TSRequest's negoTokens field.
func extractNegoToken(ts *tsRequest) []byte {
	// negoTokens content (after [1] explicit is stripped by asn1.Unmarshal):
	// SEQUENCE OF SEQUENCE { [0] OCTET STRING }
	data := ts.NegoTokens.Bytes
	if len(data) == 0 {
		return nil
	}

	// Outer SEQUENCE OF
	var outerSeq asn1.RawValue
	if _, err := asn1.Unmarshal(data, &outerSeq); err != nil {
		return nil
	}

	// Inner SEQUENCE
	var innerSeq asn1.RawValue
	if _, err := asn1.Unmarshal(outerSeq.Bytes, &innerSeq); err != nil {
		return nil
	}

	// [0] EXPLICIT wrapper
	var tag0 asn1.RawValue
	if _, err := asn1.Unmarshal(innerSeq.Bytes, &tag0); err != nil {
		return nil
	}

	// OCTET STRING containing the NTLM token
	var token []byte
	if _, err := asn1.Unmarshal(tag0.Bytes, &token); err != nil {
		return tag0.Bytes
	}

	return token
}

// mustMarshalOctetString marshals data as an ASN.1 OCTET STRING.
func mustMarshalOctetString(data []byte) []byte {
	b, err := asn1.Marshal(data)
	if err != nil {
		panic(err)
	}
	return b
}

// mustMarshalRaw marshals an asn1.RawValue.
func mustMarshalRaw(v asn1.RawValue) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// asn1TotalLength parses the ASN.1 header to determine the total encoded length.
func asn1TotalLength(data []byte) int {
	if len(data) < 2 {
		return len(data)
	}

	lenByte := data[1]
	if lenByte < 0x80 {
		return int(lenByte) + 2
	}

	numLenBytes := int(lenByte & 0x7F)
	if len(data) < 2+numLenBytes {
		return len(data)
	}

	length := 0
	for i := 0; i < numLenBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}
	return length + 2 + numLenBytes
}
