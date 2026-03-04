package dcerpc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc/header"
	"gopacket/pkg/session"
	"gopacket/pkg/structure"
	"gopacket/pkg/thirdparty/smb2"
)

type Client struct {
	Transport     Transport    // Underlying transport (TCP or Pipe)
	CallID        uint32
	MaxFrag       uint16
	Auth          *AuthHandler          // Set after successful BindAuth (NTLM)
	KrbAuth       *KerberosAuthHandler  // Set after successful BindAuthKerberos
	AuthType      uint8                 // AuthnWinNT (10) or AuthnKerberos (16)
	Authenticated bool                  // True when using packet privacy
	ContextID     uint16                // Current presentation context ID
	AuthCtxID     uint32                // Auth context ID for sec_trailer
	Contexts      map[[16]byte]uint16   // Map of Interface UUID to Context ID
	AssocGroup    uint32                // Association Group ID from BindAck
}

// InterfaceBinding represents an interface to bind to
type InterfaceBinding struct {
	InterfaceUUID [16]byte
	Major, Minor  uint16
}

// GetWindowsMaxFrag returns a standard MaxFrag size used by legitimate Windows versions.
func GetWindowsMaxFrag() uint16 {
	// 4280: Common in older Windows/Impacket
	// 5840: Modern Windows (W10/2016+)
	// 2920: Seen in certain SMB-encapsulated RPC scenarios
	profiles := []uint16{4280, 5840, 2920}
	
n, err := rand.Int(rand.Reader, big.NewInt(int64(len(profiles))))
	if err != nil {
		return 5840 // Default to modern if RNG fails
	}
	return profiles[n.Int64()]
}

// NewClient creates a Client from an SMB named pipe.
func NewClient(pipe *smb2.File) *Client {
	return &Client{
		Transport: NewPipeTransport(pipe),
		CallID:    1,
		MaxFrag:   GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}
}

// NewClientTCP creates a Client from a TCP transport.
func NewClientTCP(transport *TCPTransport) *Client {
	return &Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}
}

func (c *Client) readFull(buf []byte) error {
	return readFull(c.Transport, buf)
}

// Bind negotiates the interface and transfer syntax using default NDR.
func (c *Client) Bind(uuid [16]byte, major, minor uint16) error {
	return c.BindWithSyntax(uuid, major, minor, header.TransferSyntaxNDR, 2)
}

// BindWithSyntax negotiates the interface with a specific transfer syntax.
// Returns nil on success, error on failure. Use this to test for NDR64 support.
func (c *Client) BindWithSyntax(uuid [16]byte, major, minor uint16, transferSyntax [16]byte, transferVer uint32) error {
	// 1. Construct Bind Packet
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeBind,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0}, // Little Endian
		CallID:       c.CallID,
	}
	c.CallID++

	bind := header.BindHeader{
		MaxXmitFrag: c.MaxFrag,
		MaxRecvFrag: c.MaxFrag,
		AssocGroup:  0,
	}

	ctx := header.ContextItem{
		ContextID:       0,
		NumTransItems:   1,
		InterfaceUUID:   uuid,
		InterfaceVer:    major,
		InterfaceVerMin: minor,
		TransferSyntax:  transferSyntax,
		TransferVer:     transferVer,
	}

	buf := new(bytes.Buffer)
	
	// Write Common
	totalLen := 16 + 8 + 4 + 44
	common.FragLength = uint16(totalLen)
	
binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, bind)
	
	// Context List Header
	buf.WriteByte(1) // NumContexts
	buf.WriteByte(0) // Reserved
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Reserved
	
	// Context Item
	binary.Write(buf, binary.LittleEndian, ctx)
	
c.Contexts[uuid] = 0

	// 2. Send
	if build.Debug {
		log.Printf("[D] RPC: Binding to %x (ver %d.%d), MaxFrag: %d, CallID: %d", uuid, major, minor, c.MaxFrag, common.CallID)
	}
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write Bind: %v", err)
	}

	// 3. Read Ack Header
	headerBuf := make([]byte, 16)
	if err := c.readFull(headerBuf); err != nil {
		return fmt.Errorf("failed to read BindAck header: %v", err)
	}

	var ackHeader header.CommonHeader
	structure.UnpackLE(headerBuf, &ackHeader)

	// Read body regardless of packet type
	bodyLen := ackHeader.FragLength - 16
	body := make([]byte, bodyLen)
	if err := c.readFull(body); err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Handle BindNak - syntax not supported
	if ackHeader.PacketType == header.PktTypeBindNak {
		// BindNak body contains reject reason
		if len(body) >= 2 {
			// reason := binary.LittleEndian.Uint16(body[0:2])
			return fmt.Errorf("bind rejected: syntaxes_not_supported")
		}
		return fmt.Errorf("bind rejected (BindNak)")
	}

	if ackHeader.PacketType != header.PktTypeBindAck {
		return fmt.Errorf("expected BindAck (12), got %d", ackHeader.PacketType)
	}

	if build.Debug {
		log.Printf("[D] RPC: Received BindAck")
	}

	return nil
}

// Call sends a Request packet with OpNum and payload.
// Handles multi-fragment responses automatically.
func (c *Client) Call(opNum uint16, payload []byte) ([]byte, error) {
	// 1. Construct Request Packet
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeRequest,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
	}
	c.CallID++

	req := header.RequestHeader{
		AllocHint: uint32(len(payload)),
		ContextID: c.ContextID,
		OpNum:     opNum,
	}

	totalLen := 16 + 8 + len(payload)
	common.FragLength = uint16(totalLen)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, req)
	buf.Write(payload)

	// 2. Send
	if build.Debug {
		log.Printf("[D] RPC: Calling OpNum %d, PayloadLen: %d, CallID: %d", opNum, len(payload), common.CallID)
	}
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write Request: %v", err)
	}

	// 3. Read and reassemble multi-fragment response
	var allStubData []byte
	fragNum := 0

	for {
		// Read Response Header
		headerBuf := make([]byte, 16)
		if err := c.readFull(headerBuf); err != nil {
			return nil, fmt.Errorf("failed to read Response header: %v", err)
		}

		if build.Debug {
			log.Printf("[D] RPC Read (%d bytes): %x", len(headerBuf), headerBuf)
		}

		var respHeader header.CommonHeader
		structure.UnpackLE(headerBuf, &respHeader)

		if respHeader.PacketType == header.PktTypeFault {
			// Read fault body to get status code
			faultBodyLen := respHeader.FragLength - 16
			faultBody := make([]byte, faultBodyLen)
			if err := c.readFull(faultBody); err == nil && len(faultBody) >= 12 {
				status := binary.LittleEndian.Uint32(faultBody[8:12])
				if build.Debug {
					log.Printf("[D] RPC: Fault body: %x", faultBody)
				}
				return nil, fmt.Errorf("RPC Fault: status=0x%08x", status)
			}
			return nil, fmt.Errorf("RPC Fault")
		}
		if respHeader.PacketType != header.PktTypeResponse {
			return nil, fmt.Errorf("expected Response (2), got %d", respHeader.PacketType)
		}

		// Read Response Body
		bodyLen := respHeader.FragLength - 16
		body := make([]byte, bodyLen)
		if err := c.readFull(body); err != nil {
			return nil, fmt.Errorf("failed to read Response body: %v", err)
		}

		if build.Debug {
			log.Printf("[D] RPC Read (%d bytes): %x...", len(body), body[:min(64, len(body))])
			log.Printf("[D] RPC: Received Response fragment #%d (%d bytes, Flags: 0x%02x)",
				fragNum, len(body), respHeader.PacketFlags)
		}

		// Strip Response Header (8 bytes: AllocHint, ContextID, CancelCount, Reserved)
		if len(body) < 8 {
			return nil, fmt.Errorf("response body too short")
		}

		// Append stub data from this fragment
		allStubData = append(allStubData, body[8:]...)

		// Check if this is the last fragment
		if respHeader.PacketFlags&header.FlagLastFrag != 0 {
			break
		}
		fragNum++
	}

	if build.Debug {
		log.Printf("[D] RPC: Received Response (total %d bytes from %d fragments)", len(allStubData), fragNum+1)
	}

	return allStubData, nil
}

// CallAuth sends a sealed Request packet with OpNum and payload.
// Requires prior BindAuth() call.
// Per MS-RPCE 2.2.2.11.3.1, for Packet Privacy the signature is computed over
// [plaintext_stub + padding + sec_trailer], NOT just the plaintext stub.
func (c *Client) CallAuth(opNum uint16, payload []byte) ([]byte, error) {
	if !c.Authenticated || c.Auth == nil || c.Auth.Session == nil {
		return nil, fmt.Errorf("not authenticated, use BindAuth first")
	}

	// 1. Calculate padding (stub must be aligned to 4 bytes before trailer)
	stubLen := len(payload)
	padLen := (4 - (stubLen % 4)) % 4

	// 2. Build security trailer first (we need it for signature computation)
	secTrailer := header.SecTrailer{
		AuthType:  header.AuthnWinNT,
		AuthLevel: header.AuthnLevelPktPrivacy,
		PadLen:    uint8(padLen),
		Reserved:  0,
		ContextID: c.AuthCtxID, // Auth context ID from bind/alter_ctx
	}

	// Debug: fmt.Printf("[D] CallAuth: OpNum=%d, PresCtxID=%d, AuthCtxID=%d, SeqNum=%d\n",
	//	opNum, c.ContextID, c.AuthCtxID, c.Auth.ClientSeqNum)

	// 3. Construct Request Packet headers
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeRequest,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
		AuthLength:   16, // NTLMSSP signature size
	}
	c.CallID++

	req := header.RequestHeader{
		AllocHint: uint32(len(payload)),
		ContextID: c.ContextID,
		OpNum:     opNum,
	}

	// FragLength = Header(16) + ReqHeader(8) + EncStub + Pad + Trailer(8) + Sig(16)
	totalLen := 16 + 8 + stubLen + padLen + 8 + 16
	common.FragLength = uint16(totalLen)

	// 4. Build PDU structure first, then encrypt stub and compute signature
	//    Per MS-RPCE, try signing [Header + ReqHeader + plaintext_stub + padding + sec_trailer]

	// Encrypt the stub first (advances RC4 state)
	encryptedStub := c.Auth.Encrypt(payload)

	// Build the PDU without signature
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, req)

	// For signature: [Header + ReqHeader + PLAINTEXT stub + padding + sec_trailer]
	// The MAC is computed over the plaintext data (Impacket approach)
	signBuf := new(bytes.Buffer)
	binary.Write(signBuf, binary.LittleEndian, common)
	binary.Write(signBuf, binary.LittleEndian, req)
	signBuf.Write(payload) // plaintext stub
	signBuf.Write(make([]byte, padLen))
	binary.Write(signBuf, binary.LittleEndian, secTrailer)

	signature := c.Auth.Sign(signBuf.Bytes())

	// Continue building PDU with encrypted stub
	buf.Write(encryptedStub)
	buf.Write(make([]byte, padLen)) // Padding
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(signature)

	if build.Debug {
		log.Printf("[D] RPC: CallAuth OpNum %d, StubLen: %d, PadLen: %d", opNum, stubLen, padLen)
		log.Printf("[D] RPC: Sign input len: %d", signBuf.Len())
		log.Printf("[D] RPC: Signature: %x", signature)
	}

	// 8. Send
	if build.Debug {
		log.Printf("[D] RPC: Sending sealed request: %d bytes", buf.Len())
		log.Printf("[D] RPC: Full PDU hex: %x", buf.Bytes())
	}
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write sealed Request: %v", err)
	}

	// 8-11. Read and reassemble multi-fragment response
	var allStubData []byte
	isFirstFrag := true
	fragNum := 0

	for {
		// Read Response Header
	headerBuf := make([]byte, 16)
		if err := c.readFull(headerBuf); err != nil {
			return nil, fmt.Errorf("failed to read Response header: %v", err)
		}

		var respHeader header.CommonHeader
		structure.UnpackLE(headerBuf, &respHeader)

		if respHeader.PacketType == header.PktTypeFault {
			// Read fault body to get status code
			faultBodyLen := respHeader.FragLength - 16
			faultBody := make([]byte, faultBodyLen)
			if err := c.readFull(faultBody); err == nil && len(faultBody) >= 12 {
				status := binary.LittleEndian.Uint32(faultBody[8:12])
				if build.Debug {
					log.Printf("[D] RPC: Fault body: %x", faultBody)
				}
				return nil, fmt.Errorf("RPC Fault: status=0x%08x", status)
			}
			return nil, fmt.Errorf("RPC Fault")
		}
		if respHeader.PacketType != header.PktTypeResponse {
			return nil, fmt.Errorf("expected Response (2), got %d", respHeader.PacketType)
		}

		// Read Response Body
	bodyLen := respHeader.FragLength - 16
	body := make([]byte, bodyLen)
		if err := c.readFull(body); err != nil {
			return nil, fmt.Errorf("failed to read Response body: %v", err)
		}

		if build.Debug {
			log.Printf("[D] RPC: Received sealed Response fragment (%d bytes, AuthLen: %d, Flags: 0x%02x)",
				len(body), respHeader.AuthLength, respHeader.PacketFlags)
		}

		// Parse sealed response fragment
		// Body structure: [RespHeader(8)][EncryptedStub][Padding][SecTrailer(8)][Signature(AuthLength)]
		if len(body) < 8+8+int(respHeader.AuthLength) {
			return nil, fmt.Errorf("response body too short for sealed response")
		}

		// Extract signature (last AuthLength bytes)
		respSig := body[len(body)-int(respHeader.AuthLength):]

		// Extract security trailer (8 bytes before signature)
	trailerOffset := len(body) - int(respHeader.AuthLength) - 8
		if trailerOffset < 8 {
			return nil, fmt.Errorf("invalid response structure")
		}
		var respTrailer header.SecTrailer
		structure.UnpackLE(body[trailerOffset:trailerOffset+8], &respTrailer)

		// Extract and decrypt the entire encrypted blob (stub + padding)
		respPadLen := int(respTrailer.PadLen)
		var encryptedBlob []byte
		// Both first and continuation fragments have an 8-byte header:
		// First fragment: ResponseHeader (AllocHint, ContextID, CancelCount, Reserved)
		// Continuation: Still has AllocHint(4) + Reserved(4) indicating remaining bytes
		// This header is NOT encrypted, so we skip it.
		encryptedBlob = body[8:trailerOffset]

		if build.Debug && fragNum < 5 {
			log.Printf("[D] RPC: Frag#%d bodyLen=%d, trailerOffset=%d, encBlobLen=%d, padLen=%d, isFirst=%v",
				fragNum, len(body), trailerOffset, len(encryptedBlob), respPadLen, isFirstFrag)
			// Show first 32 bytes of ENCRYPTED data
			show := 32
			if len(encryptedBlob) < show {
				show = len(encryptedBlob)
			}
			log.Printf("[D] RPC: Frag#%d encrypted first %d bytes: %x", fragNum, show, encryptedBlob[:show])
		}

		// Decrypt FIRST (advances RC4 state by len(encryptedBlob))
		decryptedBlob := c.Auth.Decrypt(encryptedBlob)

		if build.Debug && fragNum < 5 {
			// Show first 32 bytes of decrypted data
			show := 32
			if len(decryptedBlob) < show {
				show = len(decryptedBlob)
			}
			log.Printf("[D] RPC: Frag#%d decrypted first %d bytes: %x", fragNum, show, decryptedBlob[:show])
		}

		// Then verify signature over PLAINTEXT data
		// Include: common header + response header + plaintext stub+padding + sec_trailer
		verifyBuf := new(bytes.Buffer)
		verifyBuf.Write(headerBuf)                             // common header (16 bytes)
		verifyBuf.Write(body[0:8])                             // response header (8 bytes)
		verifyBuf.Write(decryptedBlob)                         // decrypted stub+padding
		verifyBuf.Write(body[trailerOffset : trailerOffset+8]) // sec_trailer

		if !c.Auth.Verify(respSig, verifyBuf.Bytes()) {
			if build.Debug {
				log.Printf("[D] RPC: Signature verification failed for fragment")
			}
		}

		// Extract actual stub (excluding padding)
		actualStubLen := len(decryptedBlob) - respPadLen
		if actualStubLen < 0 {
			return nil, fmt.Errorf("invalid encrypted stub length")
		}
		fragStub := decryptedBlob[:actualStubLen]

		// Append to accumulated stub data
	allStubData = append(allStubData, fragStub...)

		if build.Debug {
			log.Printf("[D] RPC: Decrypted %d bytes of stub data (total: %d)", len(fragStub), len(allStubData))
		}

		// Check if this is the last fragment
		if respHeader.PacketFlags&header.FlagLastFrag != 0 {
			break
		}

		isFirstFrag = false
		fragNum++
	}

	return allStubData, nil
}

// CallAuthDCOM sends a sealed Request packet with an object UUID (IPID) for DCOM calls.
// The IPID identifies which interface instance on the server to call.
func (c *Client) CallAuthDCOM(opNum uint16, payload []byte, ipid [16]byte) ([]byte, error) {
	if !c.Authenticated || c.Auth == nil || c.Auth.Session == nil {
		return nil, fmt.Errorf("not authenticated, use BindAuth first")
	}

	// 1. Calculate padding (stub must be aligned to 4 bytes before trailer)
	stubLen := len(payload)
	padLen := (4 - (stubLen % 4)) % 4

	// 2. Build security trailer first (we need it for signature computation)
	secTrailer := header.SecTrailer{
		AuthType:  header.AuthnWinNT,
		AuthLevel: header.AuthnLevelPktPrivacy,
		PadLen:    uint8(padLen),
		Reserved:  0,
		ContextID: c.AuthCtxID, // Auth context ID from bind/alter_ctx
	}

	// Debug: fmt.Printf("[D] CallAuthDCOM: OpNum=%d, PresCtxID=%d, AuthCtxID=%d, SeqNum=%d\n",
	//	opNum, c.ContextID, c.AuthCtxID, c.Auth.ClientSeqNum)

	// 3. Construct Request Packet headers
	// For DCOM: Header(16) + ReqHeader(8) + IPID(16) + EncStub + Pad + Trailer(8) + Sig(16)
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeRequest,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag | header.FlagObjectUUID, // Include object UUID flag
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
		AuthLength:   16, // NTLMSSP signature size
	}
	c.CallID++

	req := header.RequestHeader{
		AllocHint: uint32(len(payload)),
		ContextID: c.ContextID, // Use current context ID
		OpNum:     opNum,
	}

	// FragLength = Header(16) + ReqHeader(8) + IPID(16) + EncStub + Pad + Trailer(8) + Sig(16)
	totalLen := 16 + 8 + 16 + stubLen + padLen + 8 + 16
	common.FragLength = uint16(totalLen)

	// 4. Encrypt the stub first (advances RC4 state)
	encryptedStub := c.Auth.Encrypt(payload)

	// 5. Build the PDU
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, req)
	buf.Write(ipid[:]) // Object UUID (IPID) - after request header, before stub

	// For signature: include headers + req + IPID + PLAINTEXT stub + padding + sec_trailer
	// The MAC is computed over the plaintext data (Impacket approach)
	signBuf := new(bytes.Buffer)
	binary.Write(signBuf, binary.LittleEndian, common)
	binary.Write(signBuf, binary.LittleEndian, req)
	signBuf.Write(ipid[:]) // Include IPID in signature
	signBuf.Write(payload) // plaintext stub
	signBuf.Write(make([]byte, padLen))
	binary.Write(signBuf, binary.LittleEndian, secTrailer)

	signature := c.Auth.Sign(signBuf.Bytes())

	// Continue building PDU with encrypted stub
	buf.Write(encryptedStub)
	buf.Write(make([]byte, padLen)) // Padding
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(signature)

	if build.Debug {
		log.Printf("[D] RPC: CallAuthDCOM OpNum %d, IPID: %x, StubLen: %d, ClientSeqNum: %d", opNum, ipid, stubLen, c.Auth.ClientSeqNum-1)
		log.Printf("[D] RPC: SignBuf len: %d, FragLen: %d, PresCtxID: %d, AuthCtxID: %d", signBuf.Len(), totalLen, c.ContextID, c.AuthCtxID)
		log.Printf("[D] RPC: Signature: %x", signature)
	}

	// 6. Send
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write DCOM Request: %v", err)
	}

	// 7. Read and reassemble multi-fragment response (same as CallAuth)
	var allStubData []byte
	fragNum := 0

	for {
		// Read Response Header
	headerBuf := make([]byte, 16)
		if err := c.readFull(headerBuf); err != nil {
			return nil, fmt.Errorf("failed to read Response header: %v", err)
		}

		var respHeader header.CommonHeader
		structure.UnpackLE(headerBuf, &respHeader)

		if respHeader.PacketType == header.PktTypeFault {
			faultBodyLen := respHeader.FragLength - 16
			faultBody := make([]byte, faultBodyLen)
			if err := c.readFull(faultBody); err == nil && len(faultBody) >= 12 {
				status := binary.LittleEndian.Uint32(faultBody[8:12])
				return nil, fmt.Errorf("RPC Fault: status=0x%08x", status)
			}
			return nil, fmt.Errorf("RPC Fault")
		}
		if respHeader.PacketType != header.PktTypeResponse {
			return nil, fmt.Errorf("expected Response (2), got %d", respHeader.PacketType)
		}

		// Read Response Body
	bodyLen := respHeader.FragLength - 16
	body := make([]byte, bodyLen)
		if err := c.readFull(body); err != nil {
			return nil, fmt.Errorf("failed to read Response body: %v", err)
		}

		// Parse sealed response fragment
		if len(body) < 8+8+int(respHeader.AuthLength) {
			return nil, fmt.Errorf("response body too short for sealed response")
		}

		// Extract signature
		respSig := body[len(body)-int(respHeader.AuthLength):]

		// Extract security trailer
	trailerOffset := len(body) - int(respHeader.AuthLength) - 8
		if trailerOffset < 8 {
			return nil, fmt.Errorf("invalid response structure")
		}
		var respTrailer header.SecTrailer
		structure.UnpackLE(body[trailerOffset:trailerOffset+8], &respTrailer)

		// Extract and decrypt
		respPadLen := int(respTrailer.PadLen)
		encryptedBlob := body[8:trailerOffset]

		// Decrypt FIRST (advances RC4 state by len(encryptedBlob))
		decryptedBlob := c.Auth.Decrypt(encryptedBlob)

		// Then verify signature over PLAINTEXT data
		// Include: common header + response header + plaintext stub+padding + sec_trailer
		verifyBuf := new(bytes.Buffer)
		verifyBuf.Write(headerBuf)         // common header (16 bytes)
		verifyBuf.Write(body[0:8])          // response header (8 bytes)
		verifyBuf.Write(decryptedBlob)      // decrypted stub+padding
		verifyBuf.Write(body[trailerOffset : trailerOffset+8]) // sec_trailer

		c.Auth.Verify(respSig, verifyBuf.Bytes())

		// Extract actual stub
		actualStubLen := len(decryptedBlob) - respPadLen
		if actualStubLen < 0 {
			return nil, fmt.Errorf("invalid encrypted stub length")
		}
		fragStub := decryptedBlob[:actualStubLen]

		allStubData = append(allStubData, fragStub...)

		if respHeader.PacketFlags&header.FlagLastFrag != 0 {
			break
		}
		fragNum++
	}

	return allStubData, nil
}

// BindAuth performs an authenticated Bind (Packet Privacy).
func (c *Client) BindAuth(uuid [16]byte, major, minor uint16, creds *session.Credentials) error {
	// 1. Initialize Auth Handler
	auth := NewAuthHandler(creds)
	negToken, err := auth.GetNegotiateToken()
	if err != nil {
		return fmt.Errorf("failed to get negotiate token: %v", err)
	}

	// 2. Construct Bind Packet with Auth
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeBind,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
	}
	c.CallID++

	bind := header.BindHeader{
		MaxXmitFrag: c.MaxFrag,
		MaxRecvFrag: c.MaxFrag,
		AssocGroup:  0,
	}

	ctx := header.ContextItem{
		ContextID:      0,
		NumTransItems:  1,
		InterfaceUUID:  uuid,
		InterfaceVer:   major,
		InterfaceVerMin: minor,
		TransferSyntax: header.TransferSyntaxNDR,
		TransferVer:    2,
	}

	// Use auth_ctx_id = ctx + 79231 like Impacket
	authCtxID := uint32(79231) // For initial bind, ctx=0

	secTrailer := header.SecTrailer{
		AuthType:   header.AuthnWinNT,
		AuthLevel:  header.AuthnLevelPktPrivacy,
		PadLen:     0, // Will calculate
		Reserved:   0,
		ContextID:  authCtxID,
	}

	// Calculation:
	// Body: Bind(8) + CtxList(4) + CtxItem(44) = 56 bytes.
	// We need 4-byte alignment for the Auth Trailer.
	// 56 is aligned. PadLen = 0.
	
	// Total Frag Length: Header(16) + Body(56) + Trailer(8) + TokenLen
	common.AuthLength = uint16(len(negToken))
	common.FragLength = 16 + 56 + 8 + common.AuthLength

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, bind)
	buf.WriteByte(1); buf.WriteByte(0); binary.Write(buf, binary.LittleEndian, uint16(0)) // Context List Header
	binary.Write(buf, binary.LittleEndian, ctx)
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(negToken)
	
c.Contexts[uuid] = 0

	// Send Bind
	if build.Debug {
		log.Printf("[D] RPC: Sending Bind with NTLM Negotiate (%d bytes)", len(negToken))
	}
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return err
	}

	// 3. Read BindAck
	// Use a larger buffer for BindAck as it might contain large Auth Tokens or exceed initial estimates
	readBuf := make([]byte, 65535)
	err = c.readFull(readBuf[:16]) // Read Header
	if err != nil { return err }
	
	var ackHeader header.CommonHeader
	structure.UnpackLE(readBuf[:16], &ackHeader)
	
	if ackHeader.FragLength > 65535 {
		return fmt.Errorf("BindAck too large: %d", ackHeader.FragLength)
	}

	// Read rest
	err = c.readFull(readBuf[16:ackHeader.FragLength])
	if err != nil { return err }
	
	if ackHeader.PacketType != header.PktTypeBindAck {
		return fmt.Errorf("expected BindAck, got %d", ackHeader.PacketType)
	}
	
	// Capture AssocGroup from BindAck body (offset 4 in body)
	// Body starts at offset 16 of readBuf
	if ackHeader.FragLength >= 24 { // 16 (Header) + 8 (BindAckHeader)
		c.AssocGroup = binary.LittleEndian.Uint32(readBuf[16+4 : 16+8])
		if build.Debug {
			log.Printf("[D] RPC: Captured AssocGroup: 0x%x", c.AssocGroup)
		}
	}
	
	if ackHeader.AuthLength == 0 {
		return fmt.Errorf("server did not return auth info")
	}
	
	// Token is at the end
	tokenOffset := int(ackHeader.FragLength) - int(ackHeader.AuthLength)
	challenge := readBuf[tokenOffset : int(ackHeader.FragLength)]

	if build.Debug {
		log.Printf("[D] RPC: Received Challenge (%d bytes)", len(challenge))
		log.Printf("[D] RPC: Challenge hex: %x", challenge)
	}
	
	// 4. Generate Authenticate Token
	authToken, err := auth.GetAuthenticateToken(challenge)
	if err != nil {
		return fmt.Errorf("failed to generate auth token: %v", err)
	}

	// 5. Send AlterContext
	common.PacketType = header.PktTypeAlterContext
	common.CallID = c.CallID
	c.CallID++
	common.AuthLength = uint16(len(authToken))
	common.FragLength = 16 + 56 + 8 + common.AuthLength
	
buf.Reset()
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, bind) 
	buf.WriteByte(1); buf.WriteByte(0); binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, ctx)
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(authToken)
	
	if build.Debug {
		log.Printf("[D] RPC: Sending AlterContext with NTLM Authenticate (%d bytes)", len(authToken))
		log.Printf("[D] RPC: Authenticate token hex: %x", authToken)
	}
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return err
	}
	
	// 6. Read AlterContextResp
	// Read Header
	err = c.readFull(readBuf[:16])
	if err != nil { return err }

	structure.UnpackLE(readBuf[:16], &ackHeader)
	if ackHeader.PacketType == header.PktTypeFault {
		// Read fault body
		// Fault PDU body: AllocHint(4), ContextID(2), CancelCount(1), Reserved(1), Status(4)
		if ackHeader.FragLength > 16 {
			faultBody := make([]byte, ackHeader.FragLength-16)
			c.readFull(faultBody)
			if len(faultBody) >= 12 {
				status := binary.LittleEndian.Uint32(faultBody[8:12])
				if build.Debug {
					log.Printf("[D] RPC: Bind Fault - status=0x%08x, body: %x", status, faultBody)
				}
				return fmt.Errorf("bind failed with RPC Fault: status=0x%08x", status)
			}
		}
		return fmt.Errorf("bind failed with RPC Fault")
	}
	if ackHeader.PacketType != header.PktTypeAlterContextResp {
		return fmt.Errorf("expected AlterContextResp (15), got %d", ackHeader.PacketType)
	}
	
	// Read Body
	err = c.readFull(readBuf[16:ackHeader.FragLength])
	if err != nil { return err }
	
	// Store auth handler for subsequent sealed calls
	c.Auth = auth
	c.Authenticated = true
	c.AuthCtxID = 79231 // Initial auth_ctx_id like Impacket (ctx + 79231, ctx=0 for initial bind)

	if build.Debug {
		log.Printf("[D] RPC: BindAuth Successful, AuthCtxID=%d", c.AuthCtxID)
	}

	return nil
}

// GetContextID returns the context ID for a given interface UUID, if it exists.
func (c *Client) GetContextID(uuid [16]byte) (uint16, bool) {
	ctxID, ok := c.Contexts[uuid]
	return ctxID, ok
}

// BindAuthMulti performs an authenticated Bind for multiple interfaces.
func (c *Client) BindAuthMulti(bindings []InterfaceBinding, creds *session.Credentials) error {
	// 1. Initialize Auth Handler
	auth := NewAuthHandler(creds)
	negToken, err := auth.GetNegotiateToken()
	if err != nil {
		return fmt.Errorf("failed to get negotiate token: %v", err)
	}

	// 2. Construct Bind Packet
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeBind,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
	}
	c.CallID++

	bind := header.BindHeader{
		MaxXmitFrag: c.MaxFrag,
		MaxRecvFrag: c.MaxFrag,
		AssocGroup:  0,
	}

	// Create Context Items
	buf := new(bytes.Buffer)
	
	// Context List Header
	// NumContexts (1 byte)
	buf.WriteByte(byte(len(bindings)))
	buf.WriteByte(0) // Reserved
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Reserved
	
	// Write each context item
	ctxBodyLen := 0
	for i, b := range bindings {
		ctxID := uint16(i)
		ctx := header.ContextItem{
			ContextID:      ctxID,
			NumTransItems:  1,
			InterfaceUUID:  b.InterfaceUUID,
			InterfaceVer:   b.Major,
			InterfaceVerMin: b.Minor,
			TransferSyntax: header.TransferSyntaxNDR,
			TransferVer:    2,
		}
		binary.Write(buf, binary.LittleEndian, ctx)
		ctxBodyLen += 44
		
		// Map context ID to UUID
	c.Contexts[b.InterfaceUUID] = ctxID
	}
	
	// Use auth_ctx_id = 79231 for initial bind
	authCtxID := uint32(79231)

	secTrailer := header.SecTrailer{
		AuthType:   header.AuthnWinNT,
		AuthLevel:  header.AuthnLevelPktPrivacy,
		PadLen:     0,
		Reserved:   0,
		ContextID:  authCtxID,
	}

	// Calculate lengths
	// Body: Bind(8) + CtxListHeader(4) + CtxItems(N*44)
	bodyLen := 8 + 4 + ctxBodyLen
	
	// Calculate padding for sec_trailer (4-byte alignment)
	padLen := (4 - (bodyLen % 4)) % 4
	secTrailer.PadLen = uint8(padLen)

	// Total Frag Length
	common.AuthLength = uint16(len(negToken))
	common.FragLength = uint16(16 + bodyLen + padLen + 8 + int(common.AuthLength))

	// Write Headers
	fullBuf := new(bytes.Buffer)
	binary.Write(fullBuf, binary.LittleEndian, common)
	binary.Write(fullBuf, binary.LittleEndian, bind)
	fullBuf.Write(buf.Bytes()) // Context List
	
	// Padding
	fullBuf.Write(make([]byte, padLen))
	
	// SecTrailer + Token
	binary.Write(fullBuf, binary.LittleEndian, secTrailer)
	fullBuf.Write(negToken)

	// Send Bind
	if _, err := c.Transport.Write(fullBuf.Bytes()); err != nil {
		return err
	}

	// 3. Read BindAck
	readBuf := make([]byte, 65535)
	if err := c.readFull(readBuf[:16]); err != nil { return err }
	
	var ackHeader header.CommonHeader
	structure.UnpackLE(readBuf[:16], &ackHeader)
	
	if ackHeader.FragLength > 65535 {
		return fmt.Errorf("BindAck too large")
	}

	if err := c.readFull(readBuf[16:ackHeader.FragLength]); err != nil { return err }
	
	if ackHeader.PacketType != header.PktTypeBindAck {
		return fmt.Errorf("expected BindAck, got %d", ackHeader.PacketType)
	}

	// Parse BindAck body to check results
	// Body: BindAckHeader(8) + PortAddr(...) + Padding + Results(...)
	// We read the whole body into readBuf[16:FragLen]

	// Skip BindAckHeader (MaxXmit etc) - 8 bytes
	// Then PortAddr (string)
	// PortAddr is a port_any_t: length(2) + string(length)
	if ackHeader.FragLength > 24 {
		portLen := binary.LittleEndian.Uint16(readBuf[24:26])
		// Skip PortAddr
		offset := 26 + int(portLen)
		// Align to 4 bytes? No, results list is 4-byte aligned from beginning of PDU?
		// [MS-RPCE] says PortAddr is followed by optional padding for 4-byte alignment of ResultList.
		// ResultList starts with nResults (1 byte).

		// Let's find the results.
		// ResultList usually comes after PortAddr padding.
		// But calculating exact offset is annoying.
		// However, we know Auth info is at the END.
		
		// Let's rely on the fact that we sent N contexts.
		// ResultList should have N results.
		// Each result is 24 bytes (Result, Reason, Syntax).
		// Wait, Result is: Result(2), Reason(2), TransferSyntax(UUID 16 + Ver 4) = 24 bytes.
		
		// We can scan for the results? No.
		
		if build.Debug {
			log.Printf("[D] RPC: Parsing BindAck results (offset %d)", offset)
		}
		
		// Try to read results
		if offset < int(ackHeader.FragLength) {
		    // Align offset
		    if offset % 4 != 0 {
		        offset += 4 - (offset % 4)
		    }
		    
		    if offset < int(ackHeader.FragLength) {
		        nResults := readBuf[offset]
		        offset++
		        offset += 3 // Reserved
		        
		        if build.Debug {
		             log.Printf("[D] RPC: BindAck returned %d results", nResults)
		        }
		        
		        for i := 0; i < int(nResults); i++ {
		            if offset+24 > int(ackHeader.FragLength) { break }
		            res := binary.LittleEndian.Uint16(readBuf[offset : offset+2])
		            reason := binary.LittleEndian.Uint16(readBuf[offset+2 : offset+4])
		            fmt.Printf("[D] RPC: Bind Result %d: Result=%d (0=Ack), Reason=%d\n", i, res, reason)
		            offset += 24
		        }
		    }
		}
	}
	
	if ackHeader.AuthLength == 0 {
		return fmt.Errorf("server did not return auth info")
	}
	
	tokenOffset := int(ackHeader.FragLength) - int(ackHeader.AuthLength)
	challenge := readBuf[tokenOffset : int(ackHeader.FragLength)]

	// 4. Generate Authenticate Token
	authToken, err := auth.GetAuthenticateToken(challenge)
	if err != nil {
		return fmt.Errorf("failed to generate auth token: %v", err)
	}

	// 5. Send AlterContext (actually Bind completion via AlterContext PDU)
	common.PacketType = header.PktTypeAlterContext
	common.CallID = c.CallID
	c.CallID++
	common.AuthLength = uint16(len(authToken))
	common.FragLength = 16 + 56 + 8 + common.AuthLength
	
	fullBuf.Reset()
	binary.Write(fullBuf, binary.LittleEndian, common)
	binary.Write(fullBuf, binary.LittleEndian, bind)
	fullBuf.Write(buf.Bytes()) // Reuse context list
	fullBuf.Write(make([]byte, padLen))
	binary.Write(fullBuf, binary.LittleEndian, secTrailer)
	fullBuf.Write(authToken)
	
	if _, err := c.Transport.Write(fullBuf.Bytes()); err != nil {
		return err
	}
	
	// 6. Read AlterContextResp
	if err := c.readFull(readBuf[:16]); err != nil { return err }

	structure.UnpackLE(readBuf[:16], &ackHeader)
	if ackHeader.PacketType == header.PktTypeFault {
		return fmt.Errorf("bind failed with RPC Fault")
	}
	
	if err := c.readFull(readBuf[16:ackHeader.FragLength]); err != nil { return err }
	
	c.Auth = auth
	c.Authenticated = true
	c.AuthCtxID = 79231
	c.ContextID = uint16(len(bindings) - 1) // Set last context ID

	if build.Debug {
		log.Printf("[D] RPC: BindAuthMulti Successful, %d contexts bound", len(bindings))
	}

	return nil
}

// BindAuthKerberos performs an authenticated Bind using Kerberos (Packet Privacy).
// Unlike NTLM, Kerberos is single round-trip (no challenge/response).
func (c *Client) BindAuthKerberos(uuid [16]byte, major, minor uint16, creds *session.Credentials, hostname string) error {
	// Create target for Kerberos
	target := session.Target{Host: hostname}

	// 1. Initialize Kerberos Auth Handler
	auth, err := NewKerberosAuthHandler(creds, target, creds.DCIP)
	if err != nil {
		return fmt.Errorf("failed to create kerberos auth handler: %v", err)
	}

	// Build SPN for the service
	// For SMB-based RPC: cifs/hostname
	// For TCP-based RPC: host/hostname (or ldap/hostname for directory services)
	// We use host/hostname which is a general-purpose SPN that works for most services
	spn := fmt.Sprintf("host/%s", hostname)

	// Get Kerberos token (AP-REQ wrapped in GSSAPI)
	krbToken, err := auth.GetToken(spn)
	if err != nil {
		return fmt.Errorf("failed to get kerberos token: %v", err)
	}

	// 2. Construct Bind Packet with Auth
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeBind,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
	}
	c.CallID++

	bind := header.BindHeader{
		MaxXmitFrag: c.MaxFrag,
		MaxRecvFrag: c.MaxFrag,
		AssocGroup:  0,
	}

	ctx := header.ContextItem{
		ContextID:       0,
		NumTransItems:   1,
		InterfaceUUID:   uuid,
		InterfaceVer:    major,
		InterfaceVerMin: minor,
		TransferSyntax:  header.TransferSyntaxNDR,
		TransferVer:     2,
	}

	// Use auth_ctx_id = 79231 like Impacket
	authCtxID := uint32(79231)

	secTrailer := header.SecTrailer{
		AuthType:  header.AuthnGSSNegotiate, // 9 for SPNEGO (Kerberos via GSSAPI) - NOT 16!
		AuthLevel: header.AuthnLevelPktPrivacy,
		PadLen:    0,
		Reserved:  0,
		ContextID: authCtxID,
	}

	// Calculate FragLength
	// Header(16) + Bind(8) + CtxList(4) + CtxItem(44) + Trailer(8) + Token
	common.AuthLength = uint16(len(krbToken))
	common.FragLength = 16 + 56 + 8 + common.AuthLength

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, bind)
	buf.WriteByte(1)
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Context List Header
	binary.Write(buf, binary.LittleEndian, ctx)
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(krbToken)

	c.Contexts[uuid] = 0

	// Send Bind
	if build.Debug {
		log.Printf("[D] RPC: Sending Bind with Kerberos token (%d bytes)", len(krbToken))
	}
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return err
	}

	// 3. Read BindAck
	readBuf := make([]byte, 65535)
	if err := c.readFull(readBuf[:16]); err != nil {
		return err
	}

	var ackHeader header.CommonHeader
	structure.UnpackLE(readBuf[:16], &ackHeader)

	if ackHeader.FragLength > 65535 {
		return fmt.Errorf("BindAck too large: %d", ackHeader.FragLength)
	}

	// Read rest
	if err := c.readFull(readBuf[16:ackHeader.FragLength]); err != nil {
		return err
	}

	if ackHeader.PacketType == header.PktTypeFault {
		faultBody := readBuf[16:ackHeader.FragLength]
		if len(faultBody) >= 12 {
			status := binary.LittleEndian.Uint32(faultBody[8:12])
			return fmt.Errorf("Kerberos bind failed with RPC Fault: status=0x%08x", status)
		}
		return fmt.Errorf("Kerberos bind failed with RPC Fault")
	}

	if ackHeader.PacketType == header.PktTypeBindNak {
		// Read Nak body
	nakBody := readBuf[16:ackHeader.FragLength]
		if len(nakBody) >= 2 {
			reason := binary.LittleEndian.Uint16(nakBody[0:2])
			return fmt.Errorf("Kerberos bind rejected (BindNak): reason=%d", reason)
		}
		return fmt.Errorf("Kerberos bind rejected (BindNak)")
	}

	if ackHeader.PacketType != header.PktTypeBindAck {
		return fmt.Errorf("expected BindAck, got %d", ackHeader.PacketType)
	}

	// Capture AssocGroup
	if ackHeader.FragLength >= 24 {
		c.AssocGroup = binary.LittleEndian.Uint32(readBuf[16+4 : 16+8])
		if build.Debug {
			log.Printf("[D] RPC: Captured AssocGroup: 0x%x", c.AssocGroup)
		}
	}

	// For Kerberos, if the server returns an auth token (AP-REP), we might need to process it
	// For basic Kerberos auth without mutual authentication, the bind is complete
	if build.Debug {
		log.Printf("[D] RPC: BindAck received, AuthLength=%d", ackHeader.AuthLength)
	}

	if ackHeader.AuthLength > 0 {
		// Extract auth verifier from end of packet
		// Format: ... SecTrailer(8) + AuthVerifier(AuthLength)
		authOffset := int(ackHeader.FragLength) - int(ackHeader.AuthLength) - 8
		if authOffset > 16 && int(ackHeader.FragLength) > authOffset+8 {
			authVerifier := readBuf[authOffset+8 : ackHeader.FragLength]
			if build.Debug {
				log.Printf("[D] RPC: BindAck auth verifier length=%d", len(authVerifier))
			}

			// Extract AP-REP from SPNEGO NegTokenResp
			apRepBytes := extractAPRepFromSPNEGO(authVerifier)
			if apRepBytes != nil {
				// ProcessAPRep returns the third leg token for DCE-style authentication
				thirdLegToken, err := auth.ProcessAPRep(apRepBytes)
				if err != nil {
					if build.Debug {
						log.Printf("[D] RPC: Failed to process AP-REP: %v (continuing anyway)", err)
					}
				} else {
					if build.Debug {
						log.Printf("[D] RPC: AP-REP processed successfully")
					}

					// For DCE-style Kerberos, send the third leg via AlterContext
					if len(thirdLegToken) > 0 {
						if build.Debug {
							log.Printf("[D] RPC: Sending third leg token via AlterContext (%d bytes)", len(thirdLegToken))
						}

						// Build AlterContext packet with third leg token
						alterCommon := header.CommonHeader{
							MajorVersion: 5,
							MinorVersion: 0,
							PacketType:   header.PktTypeAlterContext,
							PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
							DataRep:      [4]byte{0x10, 0, 0, 0},
							CallID:       c.CallID,
						}
						c.CallID++

						alterBind := header.BindHeader{
							MaxXmitFrag: c.MaxFrag,
							MaxRecvFrag: c.MaxFrag,
							AssocGroup:  c.AssocGroup,
						}

						alterCtx := header.ContextItem{
							ContextID:       0,
							NumTransItems:   1,
							InterfaceUUID:   uuid,
							InterfaceVer:    major,
							InterfaceVerMin: minor,
							TransferSyntax:  header.TransferSyntaxNDR,
							TransferVer:     2,
						}

						alterSecTrailer := header.SecTrailer{
							AuthType:  header.AuthnGSSNegotiate,
							AuthLevel: header.AuthnLevelPktPrivacy,
							PadLen:    0,
							Reserved:  0,
							ContextID: authCtxID,
						}

						// Header(16) + Bind(8) + CtxList(4) + CtxItem(44) + Trailer(8) + Token
						alterCommon.AuthLength = uint16(len(thirdLegToken))
						alterCommon.FragLength = 16 + 56 + 8 + alterCommon.AuthLength

						alterBuf := new(bytes.Buffer)
						binary.Write(alterBuf, binary.LittleEndian, alterCommon)
						binary.Write(alterBuf, binary.LittleEndian, alterBind)
						alterBuf.WriteByte(1)
						alterBuf.WriteByte(0)
						binary.Write(alterBuf, binary.LittleEndian, uint16(0))
						binary.Write(alterBuf, binary.LittleEndian, alterCtx)
						binary.Write(alterBuf, binary.LittleEndian, alterSecTrailer)
						alterBuf.Write(thirdLegToken)

						// Send AlterContext
						if _, err := c.Transport.Write(alterBuf.Bytes()); err != nil {
							return fmt.Errorf("failed to send AlterContext: %v", err)
						}

						// Read AlterContextResp
						alterRespBuf := make([]byte, c.MaxFrag)
						n, err := c.Transport.Read(alterRespBuf)
						if err != nil {
							return fmt.Errorf("failed to read AlterContextResp: %v", err)
						}

						if n < 16 {
							return fmt.Errorf("AlterContextResp too short: %d bytes", n)
						}

						alterRespHeader := header.CommonHeader{}
						binary.Read(bytes.NewReader(alterRespBuf[:16]), binary.LittleEndian, &alterRespHeader)

						if alterRespHeader.PacketType != header.PktTypeAlterContextResp {
							return fmt.Errorf("expected AlterContextResp (15), got %d", alterRespHeader.PacketType)
						}

						if build.Debug {
							log.Printf("[D] RPC: AlterContextResp received, third leg complete")
						}
					}
				}
			} else {
				if build.Debug {
					log.Printf("[D] RPC: No AP-REP found in auth verifier")
				}
			}
		}
	}

	// Store Kerberos auth handler
	c.KrbAuth = auth
	c.AuthType = header.AuthnGSSNegotiate // SPNEGO (Kerberos via GSSAPI)
	c.Authenticated = true
	c.AuthCtxID = authCtxID
	c.ContextID = 0 // Presentation context ID for the bound interface

	if build.Debug {
		log.Printf("[D] RPC: BindAuthKerberos Successful, AuthCtxID=%d", c.AuthCtxID)
	}

	return nil
}

// BindAuthKerberosWithHandler performs Kerberos-authenticated bind using a pre-configured auth handler.
// This is used when the caller needs to control realm/KDC configuration (e.g., cross-realm).
func (c *Client) BindAuthKerberosWithHandler(uuid [16]byte, major, minor uint16, auth *KerberosAuthHandler, spn string) error {
	// Get Kerberos token (AP-REQ wrapped in GSSAPI)
	krbToken, err := auth.GetToken(spn)
	if err != nil {
		return fmt.Errorf("failed to get kerberos token: %v", err)
	}

	// Use auth_ctx_id = 79231 like Impacket
	authCtxID := uint32(79231)

	// Build Bind Packet
	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeBind,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
	}
	c.CallID++

	bind := header.BindHeader{
		MaxXmitFrag: c.MaxFrag,
		MaxRecvFrag: c.MaxFrag,
		AssocGroup:  0,
	}

	ctx := header.ContextItem{
		ContextID:       0,
		NumTransItems:   1,
		InterfaceUUID:   uuid,
		InterfaceVer:    major,
		InterfaceVerMin: minor,
		TransferSyntax:  header.TransferSyntaxNDR,
		TransferVer:     2,
	}

	secTrailer := header.SecTrailer{
		AuthType:  header.AuthnGSSNegotiate,
		AuthLevel: header.AuthnLevelPktPrivacy,
		PadLen:    0,
		Reserved:  0,
		ContextID: authCtxID,
	}

	common.AuthLength = uint16(len(krbToken))
	common.FragLength = 16 + 56 + 8 + common.AuthLength

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, bind)
	buf.WriteByte(1)
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, ctx)
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(krbToken)

	c.Contexts[uuid] = 0

	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return err
	}

	// Read BindAck
	readBuf := make([]byte, 65535)
	if err := c.readFull(readBuf[:16]); err != nil {
		return err
	}

	var ackHeader header.CommonHeader
	structure.UnpackLE(readBuf[:16], &ackHeader)

	if ackHeader.FragLength > 65535 {
		return fmt.Errorf("BindAck too large: %d", ackHeader.FragLength)
	}

	if err := c.readFull(readBuf[16:ackHeader.FragLength]); err != nil {
		return err
	}

	if ackHeader.PacketType == header.PktTypeFault {
		faultBody := readBuf[16:ackHeader.FragLength]
		if len(faultBody) >= 12 {
			status := binary.LittleEndian.Uint32(faultBody[8:12])
			return fmt.Errorf("Kerberos bind failed with RPC Fault: status=0x%08x", status)
		}
		return fmt.Errorf("Kerberos bind failed with RPC Fault")
	}

	if ackHeader.PacketType == header.PktTypeBindNak {
		nakBody := readBuf[16:ackHeader.FragLength]
		if len(nakBody) >= 2 {
			reason := binary.LittleEndian.Uint16(nakBody[0:2])
			return fmt.Errorf("Kerberos bind rejected (BindNak): reason=%d", reason)
		}
		return fmt.Errorf("Kerberos bind rejected (BindNak)")
	}

	if ackHeader.PacketType != header.PktTypeBindAck {
		return fmt.Errorf("expected BindAck, got %d", ackHeader.PacketType)
	}

	// Capture AssocGroup
	if ackHeader.FragLength >= 24 {
		c.AssocGroup = binary.LittleEndian.Uint32(readBuf[16+4 : 16+8])
	}

	// Process AP-REP if present
	if ackHeader.AuthLength > 0 {
		authOffset := int(ackHeader.FragLength) - int(ackHeader.AuthLength) - 8
		if authOffset > 16 && int(ackHeader.FragLength) > authOffset+8 {
			authVerifier := readBuf[authOffset+8 : ackHeader.FragLength]
			apRepBytes := extractAPRepFromSPNEGO(authVerifier)
			if apRepBytes != nil {
				thirdLegToken, err := auth.ProcessAPRep(apRepBytes)
				if err != nil {
					if build.Debug {
						log.Printf("[D] RPC: Failed to process AP-REP: %v (continuing anyway)", err)
					}
				} else if len(thirdLegToken) > 0 {
					// Send third leg via AlterContext
					alterCommon := header.CommonHeader{
						MajorVersion: 5,
						MinorVersion: 0,
						PacketType:   header.PktTypeAlterContext,
						PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
						DataRep:      [4]byte{0x10, 0, 0, 0},
						CallID:       c.CallID,
					}
					c.CallID++

					alterBind := header.BindHeader{
						MaxXmitFrag: c.MaxFrag,
						MaxRecvFrag: c.MaxFrag,
						AssocGroup:  c.AssocGroup,
					}

					alterCtx := header.ContextItem{
						ContextID:       0,
						NumTransItems:   1,
						InterfaceUUID:   uuid,
						InterfaceVer:    major,
						InterfaceVerMin: minor,
						TransferSyntax:  header.TransferSyntaxNDR,
						TransferVer:     2,
					}

					alterSecTrailer := header.SecTrailer{
						AuthType:  header.AuthnGSSNegotiate,
						AuthLevel: header.AuthnLevelPktPrivacy,
						PadLen:    0,
						Reserved:  0,
						ContextID: authCtxID,
					}

					alterCommon.AuthLength = uint16(len(thirdLegToken))
					alterCommon.FragLength = 16 + 56 + 8 + alterCommon.AuthLength

					alterBuf := new(bytes.Buffer)
					binary.Write(alterBuf, binary.LittleEndian, alterCommon)
					binary.Write(alterBuf, binary.LittleEndian, alterBind)
					alterBuf.WriteByte(1)
					alterBuf.WriteByte(0)
					binary.Write(alterBuf, binary.LittleEndian, uint16(0))
					binary.Write(alterBuf, binary.LittleEndian, alterCtx)
					binary.Write(alterBuf, binary.LittleEndian, alterSecTrailer)
					alterBuf.Write(thirdLegToken)

					if _, err := c.Transport.Write(alterBuf.Bytes()); err != nil {
						return fmt.Errorf("failed to send AlterContext: %v", err)
					}

					alterRespBuf := make([]byte, c.MaxFrag)
					n, err := c.Transport.Read(alterRespBuf)
					if err != nil {
						return fmt.Errorf("failed to read AlterContextResp: %v", err)
					}

					if n < 16 {
						return fmt.Errorf("AlterContextResp too short: %d bytes", n)
					}

					alterRespHeader := header.CommonHeader{}
					binary.Read(bytes.NewReader(alterRespBuf[:16]), binary.LittleEndian, &alterRespHeader)

					if alterRespHeader.PacketType != header.PktTypeAlterContextResp {
						return fmt.Errorf("expected AlterContextResp (15), got %d", alterRespHeader.PacketType)
					}
				}
			}
		}
	}

	c.KrbAuth = auth
	c.AuthType = header.AuthnGSSNegotiate
	c.Authenticated = true
	c.AuthCtxID = authCtxID
	c.ContextID = 0

	return nil
}

// CallAuthAuto sends a sealed Request packet using whatever auth method was used for binding.
// It automatically selects NTLM or Kerberos based on how the connection was authenticated.
func (c *Client) CallAuthAuto(opNum uint16, payload []byte) ([]byte, error) {
	if c.AuthType == header.AuthnGSSNegotiate && c.KrbAuth != nil {
		return c.CallAuthKerberos(opNum, payload)
	}
	return c.CallAuth(opNum, payload)
}

// GetSessionKey returns the session key from whatever auth handler is active.
func (c *Client) GetSessionKey() []byte {
	if c.AuthType == header.AuthnGSSNegotiate && c.KrbAuth != nil {
		return c.KrbAuth.SessionKey
	}
	if c.Auth != nil {
		return c.Auth.SessionKey
	}
	return nil
}

// CallAuthKerberos sends a sealed Request packet using Kerberos authentication.
// This is similar to CallAuth but uses Kerberos crypto instead of NTLM.
func (c *Client) CallAuthKerberos(opNum uint16, payload []byte) ([]byte, error) {
	if !c.Authenticated || c.KrbAuth == nil || !c.KrbAuth.IsInitialized() {
		return nil, fmt.Errorf("not authenticated with Kerberos, use BindAuthKerberos first")
	}

	// 1. Calculate padding
	// The stub + padding must be aligned to 4 bytes for the sec_trailer
	stubLen := len(payload)
	padLen := (4 - (stubLen % 4)) % 4

	// 2. Encrypt FIRST (so we get the correct signature size for AES)
	// Per MS-RPCE, the PDU body (stub + padding) is input to GSS_Wrap
	plainStubWithPad := make([]byte, stubLen+padLen)
	copy(plainStubWithPad, payload)
	// Padding bytes are 0xBB (per Impacket)
	for i := stubLen; i < len(plainStubWithPad); i++ {
		plainStubWithPad[i] = 0xBB
	}

	encryptedStub := c.KrbAuth.Encrypt(plainStubWithPad)
	encStubLen := len(encryptedStub)

	// Now get the actual signature size (for AES, the signature is cached after Encrypt)
	sigLen := c.KrbAuth.SignatureSize()

	// 3. Build security trailer
	secTrailer := header.SecTrailer{
		AuthType:  header.AuthnGSSNegotiate, // SPNEGO (Kerberos via GSSAPI)
		AuthLevel: header.AuthnLevelPktPrivacy,
		PadLen:    uint8(padLen),
		Reserved:  0,
		ContextID: c.AuthCtxID,
	}

	// 4. Construct Request Packet headers
	// FragLength = Header(16) + ReqHeader(8) + EncStub + Trailer(8) + Sig
	totalLen := 16 + 8 + encStubLen + 8 + sigLen

	common := header.CommonHeader{
		MajorVersion: 5,
		MinorVersion: 0,
		PacketType:   header.PktTypeRequest,
		PacketFlags:  header.FlagFirstFrag | header.FlagLastFrag,
		DataRep:      [4]byte{0x10, 0, 0, 0},
		CallID:       c.CallID,
		AuthLength:   uint16(sigLen),
		FragLength:   uint16(totalLen),
	}
	c.CallID++

	req := header.RequestHeader{
		AllocHint: uint32(len(payload)),
		ContextID: c.ContextID,
		OpNum:     opNum,
	}

	// Build PDU
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, common)
	binary.Write(buf, binary.LittleEndian, req)

	// For signature: include headers + plaintext stub + padding + trailer
	signBuf := new(bytes.Buffer)
	binary.Write(signBuf, binary.LittleEndian, common)
	binary.Write(signBuf, binary.LittleEndian, req)
	signBuf.Write(plainStubWithPad) // plaintext stub + padding
	binary.Write(signBuf, binary.LittleEndian, secTrailer)

	signature := c.KrbAuth.Sign(signBuf.Bytes())

	// Continue building PDU with encrypted stub
	buf.Write(encryptedStub)
	// No separate padding write!
	binary.Write(buf, binary.LittleEndian, secTrailer)
	buf.Write(signature)

	if build.Debug {
		log.Printf("[D] RPC: CallAuthKerberos OpNum %d, StubLen: %d, PadLen: %d, EncStubLen: %d, FragLen: %d",
			opNum, stubLen, padLen, encStubLen, common.FragLength)
		log.Printf("[D] RPC: Signature (%d bytes): %x", len(signature), signature)
		log.Printf("[D] RPC: SecTrailer: type=%d level=%d pad=%d ctx=%d",
			secTrailer.AuthType, secTrailer.AuthLevel, secTrailer.PadLen, secTrailer.ContextID)
		log.Printf("[D] RPC: EncryptedStub (%d bytes): %x", len(encryptedStub), encryptedStub)
		log.Printf("[D] RPC: Full packet (%d bytes): %x", buf.Len(), buf.Bytes())
	}

	// Send
	if _, err := c.Transport.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write Kerberos sealed Request: %v", err)
	}

	// Read and reassemble response (similar to CallAuth)
	var allStubData []byte

	for {
		// Read Response Header
	headerBuf := make([]byte, 16)
		if err := c.readFull(headerBuf); err != nil {
			return nil, fmt.Errorf("failed to read Response header: %v", err)
		}

		var respHeader header.CommonHeader
		structure.UnpackLE(headerBuf, &respHeader)

		if respHeader.PacketType == header.PktTypeFault {
			faultBodyLen := respHeader.FragLength - 16
			faultBody := make([]byte, faultBodyLen)
			if err := c.readFull(faultBody); err == nil && len(faultBody) >= 12 {
				status := binary.LittleEndian.Uint32(faultBody[8:12])
				return nil, fmt.Errorf("RPC Fault: status=0x%08x", status)
			}
			return nil, fmt.Errorf("RPC Fault")
		}
		if respHeader.PacketType != header.PktTypeResponse {
			return nil, fmt.Errorf("expected Response (2), got %d", respHeader.PacketType)
		}

		// Read Response Body
	bodyLen := respHeader.FragLength - 16
	body := make([]byte, bodyLen)
		if err := c.readFull(body); err != nil {
			return nil, fmt.Errorf("failed to read Response body: %v", err)
		}

		// Parse sealed response fragment
		if len(body) < 8+8+int(respHeader.AuthLength) {
			return nil, fmt.Errorf("response body too short for sealed response")
		}

		// Extract signature
		respSig := body[len(body)-int(respHeader.AuthLength):]

		// Extract security trailer
	trailerOffset := len(body) - int(respHeader.AuthLength) - 8
		if trailerOffset < 8 {
			return nil, fmt.Errorf("invalid response structure")
		}
		var respTrailer header.SecTrailer
		structure.UnpackLE(body[trailerOffset:trailerOffset+8], &respTrailer)

		// Extract and decrypt
		respPadLen := int(respTrailer.PadLen)
		encryptedBlob := body[8:trailerOffset]

		// Decrypt using the proper method with signature verification
		decryptedBlob, err := c.KrbAuth.DecryptWithSignature(encryptedBlob, respSig)
		if err != nil {
			if build.Debug {
				log.Printf("[D] RPC: Kerberos decryption failed: %v", err)
			}
			// Fall back to raw data (might be plaintext in some error cases)
			decryptedBlob = encryptedBlob
		}

		// Extract actual stub
		actualStubLen := len(decryptedBlob) - respPadLen
		if actualStubLen < 0 {
			return nil, fmt.Errorf("invalid encrypted stub length")
		}
		fragStub := decryptedBlob[:actualStubLen]

		allStubData = append(allStubData, fragStub...)

		if respHeader.PacketFlags&header.FlagLastFrag != 0 {
			break
		}
	}

	return allStubData, nil
}

// extractAPRepFromSPNEGO extracts the AP-REP from a SPNEGO NegTokenResp.
// The response format is: NegTokenResp { responseToken: GSSAPI { AP-REP } }
func extractAPRepFromSPNEGO(data []byte) []byte {
	if len(data) < 4 {
		return nil
	}

	// Skip APPLICATION tag (0x60) if present (raw GSSAPI token)
	if data[0] == 0x60 {
		// Skip tag and length
		offset := 1
		if data[offset]&0x80 != 0 {
			lenBytes := int(data[offset] & 0x7f)
			offset += 1 + lenBytes
		} else {
			offset++
		}
		if offset >= len(data) {
			return nil
		}
		data = data[offset:]
	}

	// Look for NegTokenResp (context tag 0xa1)
	if data[0] == 0xa1 {
		offset := 1
		if data[offset]&0x80 != 0 {
			lenBytes := int(data[offset] & 0x7f)
			offset += 1 + lenBytes
		} else {
			offset++
		}
		if offset >= len(data) {
			return nil
		}
		data = data[offset:]
	}

	// Skip SEQUENCE tag (0x30)
	if len(data) > 2 && data[0] == 0x30 {
		offset := 1
		if data[offset]&0x80 != 0 {
			lenBytes := int(data[offset] & 0x7f)
			offset += 1 + lenBytes
		} else {
			offset++
		}
		if offset >= len(data) {
			return nil
		}
		data = data[offset:]
	}

	// Parse through the NegTokenResp fields looking for responseToken [2]
	for len(data) > 2 {
		tag := data[0]
		offset := 1
		var fieldLen int

		if data[offset]&0x80 != 0 {
			lenBytes := int(data[offset] & 0x7f)
			if lenBytes == 1 && offset+2 < len(data) {
				fieldLen = int(data[offset+1])
				offset += 2
			} else if lenBytes == 2 && offset+3 < len(data) {
				fieldLen = int(data[offset+1])<<8 | int(data[offset+2])
				offset += 3
			} else {
				break
			}
		} else {
			fieldLen = int(data[offset])
			offset++
		}

		if offset+fieldLen > len(data) {
			break
		}

		// responseToken is context tag [2] (0xa2)
		if tag == 0xa2 {
			tokenData := data[offset : offset+fieldLen]

			// Skip OCTET STRING tag if present
			if len(tokenData) > 2 && tokenData[0] == 0x04 {
				innerOffset := 1
				if tokenData[innerOffset]&0x80 != 0 {
					lenBytes := int(tokenData[innerOffset] & 0x7f)
					innerOffset += 1 + lenBytes
				} else {
					innerOffset++
				}
				if innerOffset < len(tokenData) {
					tokenData = tokenData[innerOffset:]
				}
			}

			// Now we should have the GSSAPI wrapped AP-REP
			// Format: 0x60 [len] OID [token-id] AP-REP
			if len(tokenData) > 10 && tokenData[0] == 0x60 {
				gssOffset := 1
				if tokenData[gssOffset]&0x80 != 0 {
					lenBytes := int(tokenData[gssOffset] & 0x7f)
					gssOffset += 1 + lenBytes
				} else {
					gssOffset++
				}

				// Skip OID
				if gssOffset < len(tokenData) && tokenData[gssOffset] == 0x06 {
					oidLen := int(tokenData[gssOffset+1])
					gssOffset += 2 + oidLen
				}

				// Skip token ID (2 bytes: 0x02 0x00 for AP-REP)
				if gssOffset+2 <= len(tokenData) {
					if tokenData[gssOffset] == 0x02 && tokenData[gssOffset+1] == 0x00 {
						gssOffset += 2
					}
				}

				// Return the AP-REP
				if gssOffset < len(tokenData) {
					return tokenData[gssOffset:]
				}
			}

			// Maybe it's just raw AP-REP (starts with APPLICATION 15 = 0x6f)
			if len(tokenData) > 2 && tokenData[0] == 0x6f {
				return tokenData
			}

			return nil
		}

		// Move to next field
		data = data[offset+fieldLen:]
	}

	return nil
}
