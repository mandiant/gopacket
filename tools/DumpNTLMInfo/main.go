package main

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/flags"
	"gopacket/pkg/ntlm"
	"gopacket/pkg/transport"
	"gopacket/pkg/utf16le"
)

// SMB Constants
const (
	SMB1_HEADER_MAGIC    = "\xffSMB"
	SMB2_HEADER_MAGIC    = "\xfeSMB"
	SMB_COM_NEGOTIATE    = 0x72
	SMB_COM_SESSION_SETUP = 0x73

	// SMB2 Commands
	SMB2_NEGOTIATE     = 0x0000
	SMB2_SESSION_SETUP = 0x0001

	// SMB2 Dialects
	SMB2_DIALECT_002  = 0x0202
	SMB2_DIALECT_21   = 0x0210
	SMB2_DIALECT_30   = 0x0300
	SMB2_DIALECT_302  = 0x0302
	SMB2_DIALECT_311  = 0x0311
	SMB2_DIALECT_WILD = 0x02FF

	// SMB2 Signing
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

	// SMB2 Capabilities
	SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040

	// DCE/RPC
	DCERPC_BIND     = 11
	DCERPC_BIND_ACK = 12
)

var (
	targetIP = flag.String("target-ip", "", "IP Address of the target machine")
	port     = flag.Int("port", 445, "Destination port to connect to SMB/RPC Server")
	protocol = flag.String("protocol", "", "Protocol to use (SMB or RPC)")
)

// FILETIME epoch (Jan 1, 1601) to Unix epoch (Jan 1, 1970) in 100-ns intervals
const EPOCH_DIFF = 116444736000000000

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "gopacket v0.1.0 - Impacket Clone in Go")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Do NTLM authentication and parse information.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [options] target\n", os.Args[0])
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	debug := flag.Bool("debug", false, "Turn DEBUG output ON")
	ts := flag.Bool("ts", false, "Adds timestamp to every logging output")

	flags.CheckHelp()
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	build.Debug = *debug
	build.Timestamp = *ts

	target := flag.Arg(0)
	ip := target
	if *targetIP != "" {
		ip = *targetIP
	}

	// Auto-detect protocol based on port
	proto := strings.ToUpper(*protocol)
	if proto == "" {
		if *port == 135 {
			proto = "RPC"
			logInfo("Port 135 specified; using RPC protocol by default. Use `-protocol SMB` to force SMB protocol.")
		} else {
			proto = "SMB"
			logInfo("Defaulting to SMB protocol.")
		}
	} else if *port == 135 && proto == "SMB" {
		logInfo("Port 135 specified with SMB protocol. Are you sure you don't want `-protocol RPC`?")
	}

	logInfo("Using target: %s, IP: %s, Port: %d, Protocol: %s", target, ip, *port, proto)

	dumper := &DumpNTLM{
		target:   target,
		ip:       ip,
		port:     *port,
		protocol: proto,
		timeout:  60 * time.Second,
	}

	if err := dumper.DisplayInfo(); err != nil {
		logError("%v", err)
		os.Exit(1)
	}
}

type DumpNTLM struct {
	target   string
	ip       string
	port     int
	protocol string
	timeout  time.Duration
}

func (d *DumpNTLM) DisplayInfo() error {
	if d.protocol == "RPC" {
		return d.DisplayRPCInfo()
	}
	return d.DisplaySMBInfo()
}

func (d *DumpNTLM) DisplayRPCInfo() error {
	conn, err := transport.DialTimeout("tcp", fmt.Sprintf("%s:%d", d.ip, d.port), int(d.timeout.Seconds()))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send DCE/RPC Bind with NTLM Type 1 (raw TCP, no NetBIOS)
	bindReq := d.buildRPCBind()
	logDebug("RPC Bind request (%d bytes): %x", len(bindReq), bindReq)
	if _, err := conn.Write(bindReq); err != nil {
		return fmt.Errorf("failed to send bind: %v", err)
	}

	// Receive Bind ACK with NTLM Type 2
	resp, err := d.recvRPC(conn)
	if err != nil {
		return fmt.Errorf("failed to receive bind ack: %v", err)
	}
	logDebug("RPC Bind ACK (%d bytes): %x", len(resp), resp[:min(128, len(resp))])

	// Parse NTLM challenge from response
	ntlmChallenge, maxFrag, err := d.parseRPCBindAck(resp)
	if err != nil {
		return fmt.Errorf("failed to parse bind ack: %v", err)
	}

	d.displayChallengeInfo(ntlmChallenge)
	fmt.Printf("[+] Max Read Size   : %s (%d bytes)\n", convertSize(maxFrag), maxFrag)
	fmt.Printf("[+] Max Write Size  : %s (%d bytes)\n", convertSize(maxFrag), maxFrag)

	return nil
}

func (d *DumpNTLM) recvRPC(conn net.Conn) ([]byte, error) {
	// Read DCE/RPC header first (16 bytes) to get fragment length
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Fragment length is at offset 8-10 (little endian)
	fragLen := int(binary.LittleEndian.Uint16(header[8:10]))
	if fragLen < 16 {
		return nil, fmt.Errorf("invalid fragment length: %d", fragLen)
	}

	// Read the rest of the fragment
	data := make([]byte, fragLen)
	copy(data[:16], header)
	if fragLen > 16 {
		if _, err := io.ReadFull(conn, data[16:]); err != nil {
			return nil, err
		}
	}

	return data, nil
}

func (d *DumpNTLM) DisplaySMBInfo() error {
	// Check if SMBv1 is enabled (separate connection)
	smb1Enabled := d.checkSMB1Enabled()

	// Negotiate SMB session - returns the active connection
	conn, negoResp, err := d.negotiateSMB()
	if err != nil {
		return fmt.Errorf("SMB negotiation failed: %v", err)
	}
	defer conn.Close()

	// Display dialect info
	d.displayDialect(negoResp.dialect, smb1Enabled)
	d.displaySigning(negoResp.securityMode)
	d.displayIO(negoResp.maxReadSize, negoResp.maxWriteSize)
	d.displayTime(negoResp.systemTime, negoResp.bootTime)

	// Get NTLM challenge via session setup (uses same connection)
	ntlmChallenge, err := d.getNTLMChallenge(conn, negoResp)
	if err != nil {
		logDebug("Failed to get NTLM challenge: %v", err)
	} else {
		d.displayChallengeInfo(ntlmChallenge)
	}

	// Test null session (separate connection)
	nullSession := d.testNullSession()
	fmt.Printf("[+] Null Session    : %v\n", nullSession)

	return nil
}

type NegotiateResponse struct {
	dialect      uint16
	securityMode uint16
	maxReadSize  uint32
	maxWriteSize uint32
	systemTime   uint64
	bootTime     uint64
	isSMB1       bool
	secBlob      []byte
}

func (d *DumpNTLM) checkSMB1Enabled() bool {
	conn, err := transport.DialTimeout("tcp", fmt.Sprintf("%s:%d", d.ip, d.port), int(d.timeout.Seconds()))
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send SMB1-only negotiate
	negoReq := d.buildSMB1Negotiate()
	if err := d.sendNetBIOS(conn, negoReq); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := d.recvNetBIOS(conn)
	if err != nil {
		return false
	}

	// Check if response is SMB1
	if len(resp) >= 4 && string(resp[0:4]) == SMB1_HEADER_MAGIC {
		return true
	}
	return false
}

func (d *DumpNTLM) negotiateSMB() (net.Conn, *NegotiateResponse, error) {
	conn, err := transport.DialTimeout("tcp", fmt.Sprintf("%s:%d", d.ip, d.port), int(d.timeout.Seconds()))
	if err != nil {
		return nil, nil, err
	}

	// Send multi-dialect negotiate (SMB1 + SMB2)
	negoReq := d.buildMultiDialectNegotiate()
	if err := d.sendNetBIOS(conn, negoReq); err != nil {
		conn.Close()
		return nil, nil, err
	}

	resp, err := d.recvNetBIOS(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if len(resp) < 4 {
		conn.Close()
		return nil, nil, fmt.Errorf("response too short")
	}

	// Check response type
	if string(resp[0:4]) == SMB2_HEADER_MAGIC {
		negoResp, err := d.parseSMB2NegotiateResponse(resp)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}

		// If we got wildcard dialect, need to do proper SMB2 negotiate on new connection
		if negoResp.dialect == SMB2_DIALECT_WILD {
			conn.Close()

			// New connection for SMB2 negotiate
			conn, err = transport.DialTimeout("tcp", fmt.Sprintf("%s:%d", d.ip, d.port), int(d.timeout.Seconds()))
			if err != nil {
				return nil, nil, err
			}

			// Send proper SMB2 negotiate
			smb2Nego := d.buildSMB2Negotiate()
			if err := d.sendNetBIOS(conn, smb2Nego); err != nil {
				conn.Close()
				return nil, nil, err
			}

			resp, err = d.recvNetBIOS(conn)
			if err != nil {
				conn.Close()
				return nil, nil, err
			}

			negoResp, err = d.parseSMB2NegotiateResponse(resp)
			if err != nil {
				conn.Close()
				return nil, nil, err
			}
			return conn, negoResp, nil
		}

		return conn, negoResp, nil
	} else if string(resp[0:4]) == SMB1_HEADER_MAGIC {
		negoResp, err := d.parseSMB1NegotiateResponse(resp)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		return conn, negoResp, nil
	}

	conn.Close()
	return nil, nil, fmt.Errorf("unknown SMB response")
}

func (d *DumpNTLM) buildSMB1Negotiate() []byte {
	// SMB1 header (32 bytes) + negotiate command
	dialects := []byte("\x02NT LM 0.12\x00")

	header := make([]byte, 32)
	copy(header[0:4], SMB1_HEADER_MAGIC)
	header[4] = SMB_COM_NEGOTIATE
	// Flags1
	header[13] = 0x18 // PATHCASELESS | CANONICALIZED_PATHS
	// Flags2
	binary.LittleEndian.PutUint16(header[14:16], 0xc803) // EXTENDED_SECURITY | NT_STATUS | LONG_NAMES | UNICODE

	// Word count = 0
	// Byte count
	cmd := []byte{0x00}
	cmd = append(cmd, byte(len(dialects)), byte(len(dialects)>>8))
	cmd = append(cmd, dialects...)

	packet := append(header, cmd...)
	return packet
}

func (d *DumpNTLM) buildMultiDialectNegotiate() []byte {
	// SMB1 negotiate with SMB2 dialects to trigger SMB2 response
	dialects := []byte("\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00")

	header := make([]byte, 32)
	copy(header[0:4], SMB1_HEADER_MAGIC)
	header[4] = SMB_COM_NEGOTIATE
	header[13] = 0x18
	binary.LittleEndian.PutUint16(header[14:16], 0xc803)

	cmd := []byte{0x00}
	cmd = append(cmd, byte(len(dialects)), byte(len(dialects)>>8))
	cmd = append(cmd, dialects...)

	return append(header, cmd...)
}

func (d *DumpNTLM) buildSMB2Negotiate() []byte {
	// SMB2 Negotiate Request
	// Header (64 bytes) + Negotiate (36 bytes) + Dialects (6 bytes = 3 dialects * 2)
	dialects := []uint16{SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30}

	header := make([]byte, 64)
	copy(header[0:4], SMB2_HEADER_MAGIC)
	binary.LittleEndian.PutUint16(header[4:6], 64)         // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], SMB2_NEGOTIATE)
	binary.LittleEndian.PutUint16(header[14:16], 1)        // Credits

	// Negotiate Request structure (36 bytes + dialects)
	nego := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(nego[0:2], 36)           // StructureSize
	binary.LittleEndian.PutUint16(nego[2:4], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(nego[4:6], SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	binary.LittleEndian.PutUint32(nego[8:12], SMB2_GLOBAL_CAP_ENCRYPTION)    // Capabilities

	// Client GUID (random)
	for i := 12; i < 28; i++ {
		nego[i] = byte(i) // Pseudo-random GUID
	}

	// Dialects start at offset 36
	for i, dialect := range dialects {
		binary.LittleEndian.PutUint16(nego[36+i*2:38+i*2], dialect)
	}

	return append(header, nego...)
}

func (d *DumpNTLM) parseSMB1NegotiateResponse(data []byte) (*NegotiateResponse, error) {
	if len(data) < 39 {
		return nil, fmt.Errorf("SMB1 response too short")
	}

	resp := &NegotiateResponse{isSMB1: true}

	// Parse parameters
	wordCount := data[32]
	if wordCount < 17 {
		return nil, fmt.Errorf("unexpected word count: %d", wordCount)
	}

	params := data[33:]
	resp.securityMode = uint16(params[2])
	resp.maxReadSize = binary.LittleEndian.Uint32(params[6:10])
	resp.maxWriteSize = resp.maxReadSize

	// System time
	lowTime := binary.LittleEndian.Uint32(params[26:30])
	highTime := binary.LittleEndian.Uint32(params[30:34])
	resp.systemTime = uint64(highTime)<<32 | uint64(lowTime)

	return resp, nil
}

func (d *DumpNTLM) parseSMB2NegotiateResponse(data []byte) (*NegotiateResponse, error) {
	if len(data) < 64+65 {
		return nil, fmt.Errorf("SMB2 response too short")
	}

	resp := &NegotiateResponse{}

	// Parse SMB2 negotiate response (starts at offset 64)
	negoResp := data[64:]
	resp.securityMode = binary.LittleEndian.Uint16(negoResp[2:4])
	resp.dialect = binary.LittleEndian.Uint16(negoResp[4:6])
	resp.maxReadSize = binary.LittleEndian.Uint32(negoResp[28:32])
	resp.maxWriteSize = binary.LittleEndian.Uint32(negoResp[32:36])
	resp.systemTime = binary.LittleEndian.Uint64(negoResp[40:48])
	resp.bootTime = binary.LittleEndian.Uint64(negoResp[48:56])

	// Security buffer
	secBufOffset := binary.LittleEndian.Uint16(negoResp[56:58])
	secBufLen := binary.LittleEndian.Uint16(negoResp[58:60])
	if secBufOffset > 0 && secBufLen > 0 && int(secBufOffset)+int(secBufLen) <= len(data) {
		resp.secBlob = data[secBufOffset : secBufOffset+secBufLen]
	}

	return resp, nil
}

func (d *DumpNTLM) getNTLMChallenge(conn net.Conn, negoResp *NegotiateResponse) ([]byte, error) {
	// Send Session Setup with NTLM Type 1 on existing connection
	sessionReq := d.buildSMB2SessionSetup(negoResp.dialect)
	if err := d.sendNetBIOS(conn, sessionReq); err != nil {
		return nil, fmt.Errorf("failed to send session setup: %v", err)
	}

	resp, err := d.recvNetBIOS(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive session setup response: %v", err)
	}

	// Parse NTLM Type 2 from response
	return d.extractNTLMChallenge(resp)
}

func (d *DumpNTLM) buildSMB2SessionSetup(dialect uint16) []byte {
	// Build NTLM Type 1
	ntlmType1 := d.buildNTLMType1()

	// Wrap in SPNEGO
	spnego := d.wrapInSPNEGO(ntlmType1)

	// SMB2 Header (64 bytes)
	header := make([]byte, 64)
	copy(header[0:4], SMB2_HEADER_MAGIC)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(header[14:16], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(header[18:20], 31) // CreditRequest
	binary.LittleEndian.PutUint64(header[24:32], 1)  // MessageId = 1 (after negotiate which was 0)

	// Session Setup Request (24 bytes fixed structure)
	// StructureSize is 25 which means 24 fixed + 1 byte buffer (per SMB2 spec)
	setup := make([]byte, 24)
	binary.LittleEndian.PutUint16(setup[0:2], 25)   // StructureSize (24 fixed + 1 buffer)
	setup[2] = 0                                     // Flags
	setup[3] = 0x01                                  // SecurityMode = SIGNING_ENABLED
	binary.LittleEndian.PutUint32(setup[4:8], 0)    // Capabilities
	binary.LittleEndian.PutUint32(setup[8:12], 0)   // Channel
	binary.LittleEndian.PutUint16(setup[12:14], 64+24) // SecurityBufferOffset = header + setup
	binary.LittleEndian.PutUint16(setup[14:16], uint16(len(spnego)))
	binary.LittleEndian.PutUint64(setup[16:24], 0) // PreviousSessionId

	packet := append(header, setup...)
	packet = append(packet, spnego...)

	return packet
}

func (d *DumpNTLM) buildNTLMType1() []byte {
	// NTLMSSP Type 1 message
	msg := []byte("NTLMSSP\x00")
	msg = append(msg, 0x01, 0x00, 0x00, 0x00) // Type 1

	// Flags: NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_EXTENDED_SESSIONSECURITY
	flags := uint32(0xe2088297)
	flagBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(flagBytes, flags)
	msg = append(msg, flagBytes...)

	// Domain (empty)
	msg = append(msg, 0x00, 0x00) // DomainLen
	msg = append(msg, 0x00, 0x00) // DomainMaxLen
	msg = append(msg, 0x00, 0x00, 0x00, 0x00) // DomainOffset

	// Workstation (empty)
	msg = append(msg, 0x00, 0x00) // WorkstationLen
	msg = append(msg, 0x00, 0x00) // WorkstationMaxLen
	msg = append(msg, 0x00, 0x00, 0x00, 0x00) // WorkstationOffset

	// Version
	msg = append(msg, 0x06, 0x01, 0x00, 0x00) // 6.1 (Win7)
	msg = append(msg, 0x00, 0x00, 0x00, 0x0f) // Build + NTLM revision

	return msg
}

func (d *DumpNTLM) wrapInSPNEGO(ntlmMsg []byte) []byte {
	// NTLM OID: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// Build mechType
	mechType := append([]byte{0x06, byte(len(ntlmOID))}, ntlmOID...)

	// Build mechTypeList
	mechTypeList := asn1Wrap(0x30, mechType)

	// MechTypes [0]
	mechTypes := asn1Wrap(0xa0, mechTypeList)

	// MechToken [2]
	mechToken := asn1Wrap(0xa2, asn1Wrap(0x04, ntlmMsg))

	// NegTokenInit
	negTokenInit := asn1Wrap(0x30, append(mechTypes, mechToken...))

	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// Application [0]
	app := append(spnegoOID, asn1Wrap(0xa0, negTokenInit)...)

	return asn1Wrap(0x60, app)
}

func asn1Wrap(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		return append([]byte{tag, byte(length)}, data...)
	} else if length < 256 {
		return append([]byte{tag, 0x81, byte(length)}, data...)
	} else {
		return append([]byte{tag, 0x82, byte(length >> 8), byte(length)}, data...)
	}
}

func (d *DumpNTLM) extractNTLMChallenge(data []byte) ([]byte, error) {
	// Check SMB2 status first
	if len(data) >= 12 {
		status := binary.LittleEndian.Uint32(data[8:12])
		logDebug("Session setup response status: 0x%08x", status)
		// STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016 means we got Type 2
		if status != 0xC0000016 && status != 0 {
			logDebug("Response hex (first 128 bytes): %x", data[:min(128, len(data))])
			return nil, fmt.Errorf("session setup failed with status 0x%08x", status)
		}
	}

	// Find NTLMSSP signature in response
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		logDebug("Response hex (first 256 bytes): %x", data[:min(256, len(data))])
		return nil, fmt.Errorf("NTLMSSP not found in response")
	}

	ntlmMsg := data[idx:]
	if len(ntlmMsg) < 56 {
		return nil, fmt.Errorf("NTLM message too short")
	}

	// Verify it's Type 2
	msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("expected NTLM Type 2, got %d", msgType)
	}

	return ntlmMsg, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (d *DumpNTLM) buildNullSessionAuth(dialect uint16, sessionID uint64, ntlmType2 []byte) []byte {
	// Build NTLM Type 3 with empty credentials
	ntlmType3 := d.buildNTLMType3(ntlmType2)

	// Wrap in SPNEGO NegTokenResp
	spnego := d.wrapInSPNEGOResp(ntlmType3)

	// SMB2 Header (64 bytes)
	header := make([]byte, 64)
	copy(header[0:4], SMB2_HEADER_MAGIC)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(header[14:16], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(header[18:20], 31) // CreditRequest
	binary.LittleEndian.PutUint64(header[24:32], 2)  // MessageId = 2
	binary.LittleEndian.PutUint64(header[40:48], sessionID)

	// Session Setup Request (24 bytes fixed structure)
	setup := make([]byte, 24)
	binary.LittleEndian.PutUint16(setup[0:2], 25)   // StructureSize
	setup[2] = 0                                     // Flags
	setup[3] = 0x01                                  // SecurityMode = SIGNING_ENABLED
	binary.LittleEndian.PutUint32(setup[4:8], 0)    // Capabilities
	binary.LittleEndian.PutUint32(setup[8:12], 0)   // Channel
	binary.LittleEndian.PutUint16(setup[12:14], 64+24) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(setup[14:16], uint16(len(spnego)))
	binary.LittleEndian.PutUint64(setup[16:24], 0) // PreviousSessionId

	packet := append(header, setup...)
	packet = append(packet, spnego...)

	return packet
}

func (d *DumpNTLM) buildNTLMType3(ntlmType2 []byte) []byte {
	// Extract negotiateFlags from Type 2
	negotiateFlags := uint32(0xe2088297) // Default flags
	if len(ntlmType2) >= 24 {
		negotiateFlags = binary.LittleEndian.Uint32(ntlmType2[20:24])
	}

	// Adjust flags based on server capabilities
	// Keep EXTENDED_SESSIONSECURITY, NTLM, UNICODE, REQUEST_TARGET
	// Remove flags not supported/required by server
	if negotiateFlags&0x00080000 == 0 { // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		negotiateFlags &^= 0x00080000
	}
	if negotiateFlags&0x20000000 == 0 { // NTLMSSP_NEGOTIATE_128
		negotiateFlags &^= 0x20000000
	}
	if negotiateFlags&0x40000000 == 0 { // NTLMSSP_NEGOTIATE_KEY_EXCH
		negotiateFlags &^= 0x40000000
	}
	if negotiateFlags&0x00000020 == 0 { // NTLMSSP_NEGOTIATE_SEAL
		negotiateFlags &^= 0x00000020
	}
	if negotiateFlags&0x00000010 == 0 { // NTLMSSP_NEGOTIATE_SIGN
		negotiateFlags &^= 0x00000010
	}
	if negotiateFlags&0x00008000 == 0 { // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		negotiateFlags &^= 0x00008000
	}

	// Check if KEY_EXCH is negotiated - need to provide encryptedRandomSessionKey
	hasKeyExch := negotiateFlags&0x40000000 != 0

	// NTLMSSP Type 3 message with empty credentials (null session)
	// Base offset is 64 bytes (fixed header without version)
	baseOffset := uint32(64)

	var encryptedSessionKey []byte
	if hasKeyExch {
		// For null session with KEY_EXCH, generate random session key
		// and encrypt with all-zeros key (since keyExchangeKey is zeros for anonymous)
		randomSessionKey := make([]byte, 16)
		for i := range randomSessionKey {
			randomSessionKey[i] = byte('A' + i%26) // Simple deterministic key for testing
		}
		// Encrypt with RC4 using all-zeros key (keyExchangeKey for anonymous = 0x00*16)
		zeroKey := make([]byte, 16)
		cipher, _ := rc4.NewCipher(zeroKey)
		encryptedSessionKey = make([]byte, 16)
		cipher.XORKeyStream(encryptedSessionKey, randomSessionKey)
	}

	payloadOffset := baseOffset
	if hasKeyExch {
		payloadOffset += 16 // encryptedRandomSessionKey
	}

	msg := make([]byte, payloadOffset)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

	// All fields are empty (null session), so lengths are 0, offsets point to base
	// LmChallengeResponse (offset 12)
	binary.LittleEndian.PutUint16(msg[12:14], 0)              // Len
	binary.LittleEndian.PutUint16(msg[14:16], 0)              // MaxLen
	binary.LittleEndian.PutUint32(msg[16:20], payloadOffset)  // Offset

	// NtChallengeResponse (offset 20)
	binary.LittleEndian.PutUint16(msg[20:22], 0)              // Len
	binary.LittleEndian.PutUint16(msg[22:24], 0)              // MaxLen
	binary.LittleEndian.PutUint32(msg[24:28], payloadOffset)  // Offset

	// DomainName (offset 28)
	binary.LittleEndian.PutUint16(msg[28:30], 0)              // Len
	binary.LittleEndian.PutUint16(msg[30:32], 0)              // MaxLen
	binary.LittleEndian.PutUint32(msg[32:36], payloadOffset)  // Offset

	// UserName (offset 36)
	binary.LittleEndian.PutUint16(msg[36:38], 0)              // Len
	binary.LittleEndian.PutUint16(msg[38:40], 0)              // MaxLen
	binary.LittleEndian.PutUint32(msg[40:44], payloadOffset)  // Offset

	// Workstation (offset 44)
	binary.LittleEndian.PutUint16(msg[44:46], 0)              // Len
	binary.LittleEndian.PutUint16(msg[46:48], 0)              // MaxLen
	binary.LittleEndian.PutUint32(msg[48:52], payloadOffset)  // Offset

	// EncryptedRandomSessionKey (offset 52)
	if hasKeyExch {
		binary.LittleEndian.PutUint16(msg[52:54], 16)         // Len
		binary.LittleEndian.PutUint16(msg[54:56], 16)         // MaxLen
		binary.LittleEndian.PutUint32(msg[56:60], baseOffset) // Offset (right after fixed header)
		copy(msg[64:80], encryptedSessionKey)
	} else {
		binary.LittleEndian.PutUint16(msg[52:54], 0)          // Len
		binary.LittleEndian.PutUint16(msg[54:56], 0)          // MaxLen
		binary.LittleEndian.PutUint32(msg[56:60], payloadOffset) // Offset
	}

	// NegotiateFlags (offset 60)
	binary.LittleEndian.PutUint32(msg[60:64], negotiateFlags)

	return msg
}

func (d *DumpNTLM) wrapInSPNEGOResp(ntlmMsg []byte) []byte {
	// SPNEGO NegTokenResp with responseToken [2]
	responseToken := asn1Wrap(0xa2, asn1Wrap(0x04, ntlmMsg))

	// NegTokenResp
	negTokenResp := asn1Wrap(0x30, responseToken)

	// Application [1] IMPLICIT
	return asn1Wrap(0xa1, negTokenResp)
}

func (d *DumpNTLM) testNullSession() bool {
	// Create new connection for null session test
	conn, negoResp, err := d.negotiateSMB()
	if err != nil {
		logDebug("Null session - negotiation failed: %v", err)
		return false
	}
	defer conn.Close()

	// Send Session Setup with NTLM Type 1
	sessionReq := d.buildSMB2SessionSetup(negoResp.dialect)
	if err := d.sendNetBIOS(conn, sessionReq); err != nil {
		logDebug("Null session - session setup 1 failed: %v", err)
		return false
	}

	resp, err := d.recvNetBIOS(conn)
	if err != nil {
		logDebug("Null session - receive response 1 failed: %v", err)
		return false
	}

	// Extract NTLM Type 2
	ntlmChallenge, err := d.extractNTLMChallenge(resp)
	if err != nil {
		logDebug("Null session - extract challenge failed: %v", err)
		return false
	}

	// Extract session ID from response
	sessionID := uint64(0)
	if len(resp) >= 48 {
		sessionID = binary.LittleEndian.Uint64(resp[40:48])
	}
	logDebug("Null session - session ID: 0x%016x", sessionID)

	// Build and send Session Setup with NTLM Type 3 (null credentials)
	ntlmType3 := d.buildNTLMType3(ntlmChallenge)
	logDebug("Null session - Type 3 len=%d hex=%x", len(ntlmType3), ntlmType3)

	spnego := d.wrapInSPNEGOResp(ntlmType3)
	logDebug("Null session - SPNEGO len=%d hex=%x", len(spnego), spnego)

	sessionReq2 := d.buildNullSessionAuth(negoResp.dialect, sessionID, ntlmChallenge)
	if err := d.sendNetBIOS(conn, sessionReq2); err != nil {
		logDebug("Null session - session setup 2 failed: %v", err)
		return false
	}

	resp2, err := d.recvNetBIOS(conn)
	if err != nil {
		logDebug("Null session - receive response 2 failed: %v", err)
		return false
	}

	// Check SMB2 status
	if len(resp2) >= 12 {
		status := binary.LittleEndian.Uint32(resp2[8:12])
		logDebug("Null session - status: 0x%08x", status)
		// STATUS_SUCCESS = 0x00000000
		return status == 0
	}

	return false
}

func (d *DumpNTLM) displayDialect(dialect uint16, smb1Enabled bool) {
	fmt.Printf("[+] SMBv1 Enabled   : %v\n", smb1Enabled)

	dialectStr := ""
	switch dialect {
	case SMB2_DIALECT_002:
		dialectStr = "SMB 2.0.2"
	case SMB2_DIALECT_21:
		dialectStr = "SMB 2.1"
	case SMB2_DIALECT_30:
		dialectStr = "SMB 3.0"
	case SMB2_DIALECT_302:
		dialectStr = "SMB 3.0.2"
	case SMB2_DIALECT_311:
		dialectStr = "SMB 3.1.1"
	default:
		dialectStr = fmt.Sprintf("0x%04x", dialect)
	}
	fmt.Printf("[+] Prefered Dialect: %s\n", dialectStr)
}

func (d *DumpNTLM) displaySigning(secMode uint16) {
	mode := ""
	if secMode&SMB2_NEGOTIATE_SIGNING_ENABLED != 0 {
		mode = "SIGNING_ENABLED"
	}
	if secMode&SMB2_NEGOTIATE_SIGNING_REQUIRED != 0 {
		mode += " | SIGNING_REQUIRED"
	} else {
		mode += " (not required)"
	}
	fmt.Printf("[+] Server Security : %s\n", mode)
}

func (d *DumpNTLM) displayIO(maxRead, maxWrite uint32) {
	fmt.Printf("[+] Max Read Size   : %s (%d bytes)\n", convertSize(maxRead), maxRead)
	fmt.Printf("[+] Max Write Size  : %s (%d bytes)\n", convertSize(maxWrite), maxWrite)
}

func (d *DumpNTLM) displayTime(systemTime, bootTime uint64) {
	if systemTime != 0 {
		t := filetimeToTime(systemTime)
		fmt.Printf("[+] Current Time    : %s\n", t.UTC().Format("2006-01-02 15:04:05 MST"))
	}
	if bootTime != 0 {
		bt := filetimeToTime(bootTime)
		fmt.Printf("[+] Boot Time       : %s\n", bt.UTC().Format("2006-01-02 15:04:05 MST"))
		if systemTime != 0 {
			uptime := filetimeToTime(systemTime).Sub(bt)
			days := int(uptime.Hours() / 24)
			hours := int(uptime.Hours()) % 24
			mins := int(uptime.Minutes()) % 60
			fmt.Printf("[+] Server Up Time  : %d days, %d:%02d:00\n", days, hours, mins)
		}
	}
}

func (d *DumpNTLM) displayChallengeInfo(ntlmMsg []byte) {
	if len(ntlmMsg) < 56 {
		return
	}

	// Parse Target Info
	targetInfoLen := binary.LittleEndian.Uint16(ntlmMsg[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(ntlmMsg[44:48])

	if targetInfoLen > 0 && int(targetInfoOffset)+int(targetInfoLen) <= len(ntlmMsg) {
		targetInfo := ntlmMsg[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]
		d.parseAVPairs(targetInfo)
	}

	// Parse Version if present (offset 48)
	if len(ntlmMsg) >= 56 {
		version := ntlmMsg[48:56]
		major := version[0]
		minor := version[1]
		build := binary.LittleEndian.Uint16(version[2:4])
		fmt.Printf("[+] OS              : Windows NT %d.%d Build %d\n", major, minor, build)
	}
}

func (d *DumpNTLM) parseAVPairs(data []byte) {
	pairs, ok := ntlm.ParseAvPairs(data)
	if !ok {
		return
	}

	if val, ok := pairs[ntlm.MsvAvNbComputerName]; ok {
		fmt.Printf("[+] Name            : %s\n", utf16le.DecodeToString(val))
	}
	if val, ok := pairs[ntlm.MsvAvNbDomainName]; ok {
		fmt.Printf("[+] Domain          : %s\n", utf16le.DecodeToString(val))
	}
	if val, ok := pairs[ntlm.MsvAvDnsTreeName]; ok {
		fmt.Printf("[+] DNS Tree Name   : %s\n", utf16le.DecodeToString(val))
	}
	if val, ok := pairs[ntlm.MsvAvDnsDomainName]; ok {
		fmt.Printf("[+] DNS Domain Name : %s\n", utf16le.DecodeToString(val))
	}
	if val, ok := pairs[ntlm.MsvAvDnsComputerName]; ok {
		fmt.Printf("[+] DNS Host Name   : %s\n", utf16le.DecodeToString(val))
	}
}

// RPC methods
func (d *DumpNTLM) buildRPCBind() []byte {
	// NTLM Type 1 (simplified for RPC)
	ntlmType1 := d.buildNTLMType1ForRPC()

	// EPM UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa
	epmUUID := []byte{
		0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
		0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
	}
	epmVersion := []byte{0x03, 0x00, 0x00, 0x00}

	// NDR UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
	ndrUUID := []byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	}
	ndrVersion := []byte{0x02, 0x00, 0x00, 0x00}

	// Context item (44 bytes)
	ctxItem := make([]byte, 44)
	binary.LittleEndian.PutUint16(ctxItem[0:2], 0)  // ContextID
	ctxItem[2] = 1                                   // NumTransItems
	ctxItem[3] = 0                                   // Reserved
	copy(ctxItem[4:20], epmUUID)
	copy(ctxItem[20:24], epmVersion)
	copy(ctxItem[24:40], ndrUUID)
	copy(ctxItem[40:44], ndrVersion)

	// Bind PDU body (12 bytes fixed + 44 bytes context item = 56 bytes)
	bind := make([]byte, 12)
	binary.LittleEndian.PutUint16(bind[0:2], 4280)  // MaxXmitFrag
	binary.LittleEndian.PutUint16(bind[2:4], 4280)  // MaxRecvFrag
	binary.LittleEndian.PutUint32(bind[4:8], 0)     // AssocGroup
	bind[8] = 1  // NumCtxItems
	bind[9] = 0  // Reserved
	bind[10] = 0 // Reserved
	bind[11] = 0 // Reserved (align to 4 bytes)
	bind = append(bind, ctxItem...)

	// SEC_TRAILER (8 bytes)
	secTrailer := make([]byte, 8)
	secTrailer[0] = 0x0a // auth_type = NTLMSSP
	secTrailer[1] = 0x05 // auth_level = PKT_INTEGRITY
	secTrailer[2] = 0    // auth_pad_length
	secTrailer[3] = 0    // reserved
	binary.LittleEndian.PutUint32(secTrailer[4:8], 79231) // auth_context_id

	// Total: 16 (header) + 56 (bind body) + 8 (sec_trailer) + len(ntlmType1)
	fragLen := 16 + len(bind) + 8 + len(ntlmType1)
	authLen := len(ntlmType1)

	// RPC Header (16 bytes)
	header := make([]byte, 16)
	header[0] = 5                                            // Version
	header[1] = 0                                            // Minor version
	header[2] = DCERPC_BIND                                  // Packet type
	header[3] = 0x03                                         // Flags (first + last)
	// Data representation: little-endian (0x10), IEEE float (0x00), reserved (0x0000)
	header[4] = 0x10
	header[5] = 0x00
	header[6] = 0x00
	header[7] = 0x00
	binary.LittleEndian.PutUint16(header[8:10], uint16(fragLen))
	binary.LittleEndian.PutUint16(header[10:12], uint16(authLen))
	binary.LittleEndian.PutUint32(header[12:16], 1)          // Call ID

	packet := append(header, bind...)
	packet = append(packet, secTrailer...)
	packet = append(packet, ntlmType1...)

	return packet
}

func (d *DumpNTLM) buildNTLMType1ForRPC() []byte {
	// Simplified NTLM Type 1 message for RPC (no version field)
	// Flags: NEGOTIATE_56 | NEGOTIATE_128 | NEGOTIATE_EXTENDED_SESSIONSECURITY |
	//        NEGOTIATE_NTLM | REQUEST_TARGET | NEGOTIATE_UNICODE
	flags := uint32(0xe0888235)

	msg := make([]byte, 32)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1)     // Type 1
	binary.LittleEndian.PutUint32(msg[12:16], flags)

	// Domain (empty)
	binary.LittleEndian.PutUint16(msg[16:18], 0) // DomainLen
	binary.LittleEndian.PutUint16(msg[18:20], 0) // DomainMaxLen
	binary.LittleEndian.PutUint32(msg[20:24], 0) // DomainOffset

	// Workstation (empty)
	binary.LittleEndian.PutUint16(msg[24:26], 0) // WorkstationLen
	binary.LittleEndian.PutUint16(msg[26:28], 0) // WorkstationMaxLen
	binary.LittleEndian.PutUint32(msg[28:32], 0) // WorkstationOffset

	return msg
}

func (d *DumpNTLM) parseRPCBindAck(data []byte) ([]byte, uint32, error) {
	if len(data) < 24 {
		return nil, 0, fmt.Errorf("bind ack too short")
	}

	// Check packet type
	if data[2] != DCERPC_BIND_ACK {
		return nil, 0, fmt.Errorf("expected bind ack, got %d", data[2])
	}

	maxFrag := binary.LittleEndian.Uint16(data[16:18])
	authLen := binary.LittleEndian.Uint16(data[10:12])

	if authLen == 0 {
		return nil, uint32(maxFrag), fmt.Errorf("no auth data in bind ack")
	}

	// Find NTLMSSP in response
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil, uint32(maxFrag), fmt.Errorf("NTLMSSP not found")
	}

	return data[idx:], uint32(maxFrag), nil
}

func (d *DumpNTLM) sendNetBIOS(conn net.Conn, data []byte) error {
	// NetBIOS session header (4 bytes)
	header := make([]byte, 4)
	header[0] = 0x00 // Session message
	header[1] = byte(len(data) >> 16)
	header[2] = byte(len(data) >> 8)
	header[3] = byte(len(data))

	_, err := conn.Write(append(header, data...))
	return err
}

func (d *DumpNTLM) recvNetBIOS(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		return nil, err
	}

	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length == 0 {
		return nil, fmt.Errorf("empty response")
	}

	data := make([]byte, length)
	total := 0
	for total < length {
		n, err := conn.Read(data[total:])
		if err != nil {
			return nil, err
		}
		total += n
	}

	return data, nil
}

// Utility functions
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// Convert from Windows FILETIME (100-ns since 1601) to Unix time
	usec := (int64(ft) - EPOCH_DIFF) / 10
	return time.Unix(usec/1000000, (usec%1000000)*1000)
}

func convertSize(bytes uint32) string {
	if bytes == 0 {
		return "0B"
	}
	sizes := []string{"B", "KB", "MB", "GB", "TB"}
	i := int(math.Floor(math.Log(float64(bytes)) / math.Log(1024)))
	if i >= len(sizes) {
		i = len(sizes) - 1
	}
	return fmt.Sprintf("%.2f %s", float64(bytes)/math.Pow(1024, float64(i)), sizes[i])
}

func logInfo(format string, args ...interface{}) {
	prefix := "[*] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Printf(prefix+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	prefix := "[-] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Fprintf(os.Stderr, prefix+format+"\n", args...)
}

func logDebug(format string, args ...interface{}) {
	if !build.Debug {
		return
	}
	prefix := "[DEBUG] "
	if build.Timestamp {
		prefix = time.Now().Format("2006-01-02 15:04:05 ") + prefix
	}
	fmt.Printf(prefix+format+"\n", args...)
}
