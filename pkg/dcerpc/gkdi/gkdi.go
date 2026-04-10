// SPDX-License-Identifier: Apache-2.0

// Package gkdi implements the MS-GKDI (Group Key Distribution Protocol) RPC client.
// This is used to retrieve group keys for decrypting LAPS v2 encrypted passwords.
package gkdi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/session"
)

// GKDI Interface UUID: B9785960-524F-11DF-8B6D-83DCDED72085
var GKDI_UUID = [16]byte{
	0x60, 0x59, 0x78, 0xB9, 0x4F, 0x52, 0xDF, 0x11,
	0x8B, 0x6D, 0x83, 0xDC, 0xDE, 0xD7, 0x20, 0x85,
}

const (
	GKDI_VERSION_MAJOR = 1
	GKDI_VERSION_MINOR = 0
	OPNUM_GET_KEY      = 0
)

// Client wraps the DCE/RPC client for GKDI operations.
type Client struct {
	rpc *dcerpc.Client
}

// GroupKeyEnvelope represents the response from GetKey.
type GroupKeyEnvelope struct {
	Version    uint32
	Magic      uint32
	Flags      uint32
	L0Index    uint32
	L1Index    uint32
	L2Index    uint32
	RootKeyID  [16]byte
	KdfAlgoLen uint32
	KdfParaLen uint32
	SecAlgoLen uint32
	SecParaLen uint32
	PrivKeyLen uint32
	PubKeyLen  uint32
	L1KeyLen   uint32
	L2KeyLen   uint32
	DomainLen  uint32
	ForestLen  uint32
	KdfAlgo    []byte
	KdfPara    []byte
	SecAlgo    []byte
	SecPara    []byte
	Domain     []byte
	Forest     []byte
	L1Key      []byte
	L2Key      []byte
}

// KDFParameter represents the KDF parameters structure.
type KDFParameter struct {
	Unknown1 uint32
	Unknown2 uint32
	HashLen  uint32
	Unknown3 uint32
	HashName string
}

// NewClient creates a new GKDI client using TCP transport.
func NewClient(target session.Target, creds *session.Credentials) (*Client, error) {
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}

	// Use endpoint mapper to find GKDI endpoint
	port, err := epmapper.MapTCPEndpoint(host, GKDI_UUID, GKDI_VERSION_MAJOR)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve GKDI endpoint: %v", err)
	}

	// Connect to the resolved endpoint
	transport, err := dcerpc.DialTCP(host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to GKDI: %v", err)
	}

	rpc := dcerpc.NewClientTCP(transport)

	// Bind with authentication
	if creds.UseKerberos {
		err = rpc.BindAuthKerberos(GKDI_UUID, GKDI_VERSION_MAJOR, GKDI_VERSION_MINOR, creds, target.Host)
	} else {
		err = rpc.BindAuth(GKDI_UUID, GKDI_VERSION_MAJOR, GKDI_VERSION_MINOR, creds)
	}
	if err != nil {
		transport.Close()
		return nil, fmt.Errorf("failed to bind: %v", err)
	}

	return &Client{rpc: rpc}, nil
}

// Close closes the GKDI client connection.
func (c *Client) Close() {
	if c.rpc != nil && c.rpc.Transport != nil {
		c.rpc.Transport.Close()
	}
}

// GetKey calls the GetKey RPC operation to retrieve a group key.
// targetSD is the security descriptor for access control.
// rootKeyID is the root key identifier (can be nil for default).
// l0, l1, l2 are the key indices (-1 for default).
func (c *Client) GetKey(targetSD []byte, rootKeyID *[16]byte, l0, l1, l2 int32) (*GroupKeyEnvelope, error) {
	// Build the request
	buf := new(bytes.Buffer)

	// cbTargetSD (ULONG)
	binary.Write(buf, binary.LittleEndian, uint32(len(targetSD)))

	// pbTargetSD (conformant array)
	// MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(targetSD)))
	buf.Write(targetSD)

	// Align to 4 bytes
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}

	// pRootKeyID (PGUID - pointer to GUID)
	if rootKeyID != nil {
		binary.Write(buf, binary.LittleEndian, uint32(1)) // Ref ID (non-null)
		buf.Write(rootKeyID[:])
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pointer
	}

	// L0KeyID (LONG)
	binary.Write(buf, binary.LittleEndian, l0)
	// L1KeyID (LONG)
	binary.Write(buf, binary.LittleEndian, l1)
	// L2KeyID (LONG)
	binary.Write(buf, binary.LittleEndian, l2)

	// Call GetKey
	resp, err := c.rpc.CallAuthAuto(OPNUM_GET_KEY, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("GetKey call failed: %v", err)
	}

	// Parse response
	return parseGetKeyResponse(resp)
}

func parseGetKeyResponse(data []byte) (*GroupKeyEnvelope, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	r := bytes.NewReader(data)

	// pcbOut (ULONG)
	var cbOut uint32
	binary.Read(r, binary.LittleEndian, &cbOut)

	// pbbOut (PBYTE_ARRAY - pointer)
	var refID uint32
	binary.Read(r, binary.LittleEndian, &refID)

	if refID == 0 {
		// Check error code
		r.Seek(int64(len(data)-4), 0)
		var errCode uint32
		binary.Read(r, binary.LittleEndian, &errCode)
		return nil, fmt.Errorf("GetKey failed with error: 0x%08x", errCode)
	}

	// MaxCount
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Read the envelope data
	envelopeData := make([]byte, maxCount)
	r.Read(envelopeData)

	// Parse GroupKeyEnvelope
	return parseGroupKeyEnvelope(envelopeData)
}

func parseGroupKeyEnvelope(data []byte) (*GroupKeyEnvelope, error) {
	if len(data) < 72 { // Minimum header size
		return nil, fmt.Errorf("envelope data too short: %d", len(data))
	}

	gke := &GroupKeyEnvelope{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &gke.Version)
	binary.Read(r, binary.LittleEndian, &gke.Magic)
	binary.Read(r, binary.LittleEndian, &gke.Flags)
	binary.Read(r, binary.LittleEndian, &gke.L0Index)
	binary.Read(r, binary.LittleEndian, &gke.L1Index)
	binary.Read(r, binary.LittleEndian, &gke.L2Index)
	r.Read(gke.RootKeyID[:])
	binary.Read(r, binary.LittleEndian, &gke.KdfAlgoLen)
	binary.Read(r, binary.LittleEndian, &gke.KdfParaLen)
	binary.Read(r, binary.LittleEndian, &gke.SecAlgoLen)
	binary.Read(r, binary.LittleEndian, &gke.SecParaLen)
	binary.Read(r, binary.LittleEndian, &gke.PrivKeyLen)
	binary.Read(r, binary.LittleEndian, &gke.PubKeyLen)
	binary.Read(r, binary.LittleEndian, &gke.L1KeyLen)
	binary.Read(r, binary.LittleEndian, &gke.L2KeyLen)
	binary.Read(r, binary.LittleEndian, &gke.DomainLen)
	binary.Read(r, binary.LittleEndian, &gke.ForestLen)

	// Read variable length fields
	gke.KdfAlgo = make([]byte, gke.KdfAlgoLen)
	r.Read(gke.KdfAlgo)

	gke.KdfPara = make([]byte, gke.KdfParaLen)
	r.Read(gke.KdfPara)

	gke.SecAlgo = make([]byte, gke.SecAlgoLen)
	r.Read(gke.SecAlgo)

	gke.SecPara = make([]byte, gke.SecParaLen)
	r.Read(gke.SecPara)

	gke.Domain = make([]byte, gke.DomainLen)
	r.Read(gke.Domain)

	gke.Forest = make([]byte, gke.ForestLen)
	r.Read(gke.Forest)

	gke.L1Key = make([]byte, gke.L1KeyLen)
	r.Read(gke.L1Key)

	gke.L2Key = make([]byte, gke.L2KeyLen)
	r.Read(gke.L2Key)

	return gke, nil
}

// GetKdfHashName returns the KDF hash algorithm name from the KDF parameters.
func (gke *GroupKeyEnvelope) GetKdfHashName() string {
	if len(gke.KdfPara) < 16 {
		return "SHA512" // Default
	}
	// Parse KDFParameter structure
	r := bytes.NewReader(gke.KdfPara)
	var unknown1, unknown2, hashLen, unknown3 uint32
	binary.Read(r, binary.LittleEndian, &unknown1)
	binary.Read(r, binary.LittleEndian, &unknown2)
	binary.Read(r, binary.LittleEndian, &hashLen)
	binary.Read(r, binary.LittleEndian, &unknown3)

	if hashLen > 0 && int(hashLen) <= len(gke.KdfPara)-16 {
		hashName := gke.KdfPara[16 : 16+hashLen]
		// Convert from UTF-16LE
		return utf16ToString(hashName)
	}
	return "SHA512"
}

// GetSecAlgoName returns the security algorithm name.
func (gke *GroupKeyEnvelope) GetSecAlgoName() string {
	return utf16ToString(gke.SecAlgo)
}

func utf16ToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	// Simple UTF-16LE to string conversion
	var result []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			break
		}
		if b[i+1] == 0 {
			result = append(result, b[i])
		}
	}
	return string(result)
}
