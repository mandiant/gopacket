// SPDX-License-Identifier: Apache-2.0

package main

import (
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

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"

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

// logOutputRaw prints raw output without any prefix
func logOutputRaw(msg string) {
	logger.Print(msg)
}

var (
	listenAddr  = flag.String("ip", "0.0.0.0", "ip address of listening interface")
	listenPort  = flag.Int("port", 445, "TCP port for listening incoming connections (default 445)")
	username    = flag.String("username", "", "Username to authenticate clients")
	password    = flag.String("password", "", "Password for the Username")
	hashes      = flag.String("hashes", "", "NTLM hashes for the Username, format is LMHASH:NTHASH")
	smb2support = flag.Bool("smb2support", false, "SMB2 Support (experimental!)")
	debug       = flag.Bool("debug", false, "Turn DEBUG output ON")
	comment     = flag.String("comment", "", "share's comment to display when asked for shares")
	timestamp   = flag.Bool("ts", false, "Adds timestamp to every logging output")
	outputFile  = flag.String("outputfile", "", "Output file to log smbserver output messages")
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
	STATUS_NOTIFY_ENUM_DIR          uint32 = 0x0000010C
	STATUS_MORE_PROCESSING_REQUIRED uint32 = 0xC0000016
	STATUS_LOGON_FAILURE            uint32 = 0xC000006D
	STATUS_ACCESS_DENIED            uint32 = 0xC0000022
	STATUS_OBJECT_NAME_NOT_FOUND    uint32 = 0xC0000034
	STATUS_OBJECT_NAME_COLLISION    uint32 = 0xC0000035
	STATUS_OBJECT_PATH_NOT_FOUND    uint32 = 0xC000003A
	STATUS_NO_SUCH_FILE             uint32 = 0xC000000F
	STATUS_END_OF_FILE              uint32 = 0xC0000011
	STATUS_NOT_SUPPORTED            uint32 = 0xC00000BB
	STATUS_INVALID_PARAMETER        uint32 = 0xC000000D
	STATUS_NO_MORE_FILES            uint32 = 0x80000006
	STATUS_FILE_IS_A_DIRECTORY      uint32 = 0xC00000BA
	STATUS_NOT_A_DIRECTORY          uint32 = 0xC0000103
	STATUS_DIRECTORY_NOT_EMPTY      uint32 = 0xC0000101
	STATUS_CANNOT_DELETE            uint32 = 0xC0000121
	STATUS_FILE_CLOSED              uint32 = 0xC0000128
	STATUS_DELETE_PENDING           uint32 = 0xC0000056
	STATUS_LOCK_NOT_GRANTED         uint32 = 0xC0000055
	STATUS_RANGE_NOT_LOCKED         uint32 = 0xC000007E
	STATUS_CANCELLED                uint32 = 0xC0000120
)

// File Information Classes for SET_INFO
const (
	FileBasicInformation       byte = 0x04
	FileRenameInformation      byte = 0x0A
	FileDispositionInformation byte = 0x0D
	FileAllocationInformation  byte = 0x13
	FileEndOfFileInformation   byte = 0x14
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
	FILE_ADD_FILE         uint32 = 0x00000002
	FILE_ADD_SUBDIRECTORY uint32 = 0x00000004
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
	SMB2_GLOBAL_CAP_DFS                uint32 = 0x00000001
	SMB2_GLOBAL_CAP_LEASING            uint32 = 0x00000002
	SMB2_GLOBAL_CAP_LARGE_MTU          uint32 = 0x00000004
	SMB2_GLOBAL_CAP_MULTI_CHANNEL      uint32 = 0x00000008
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES uint32 = 0x00000010
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING  uint32 = 0x00000020
	SMB2_GLOBAL_CAP_ENCRYPTION         uint32 = 0x00000040
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

// Share represents an SMB share
type Share struct {
	name    string
	path    string
	comment string
	stype   uint32 // Share type: 0 = disk, 0x80000003 = IPC
}

// Server represents the SMB server
type Server struct {
	shares      map[string]*Share // Map of share name (uppercase) -> Share
	sharesMu    sync.RWMutex
	listener    net.Listener
	sessions    map[uint64]*Session
	sessionMu   sync.RWMutex
	nextSession uint64
	serverGUID  [16]byte

	// Authentication
	username string
	password string
	ntHash   []byte
	lmHash   []byte

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
	challenge         []byte
	treeConnects      map[uint32]*TreeConnect
	nextTreeID        uint32
	openFiles         map[string]*OpenFile
	nextFileID        uint64
	negotiatedDialect uint16
}

// TreeConnect represents a tree connection
type TreeConnect struct {
	id        uint32
	shareName string
	sharePath string
}

// OpenFile represents an open file handle
type OpenFile struct {
	id            [16]byte
	path          string
	realPath      string
	isDir         bool
	file          *os.File
	enumerated    bool // Track if directory listing has been returned
	deleteOnClose bool
	deletePending bool
	desiredAccess uint32
	// Named pipe support
	isPipe   bool
	pipeName string
	pipeData *NamedPipeState
	// File locks
	locks []FileLock
}

// FileLock represents a byte-range lock on a file
type FileLock struct {
	offset uint64
	length uint64
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

	// Packet types
	DCERPC_REQUEST  = 0
	DCERPC_RESPONSE = 2
	DCERPC_BIND     = 11
	DCERPC_BIND_ACK = 12

	// Flags
	DCERPC_FIRST_FRAG = 0x01
	DCERPC_LAST_FRAG  = 0x02

	// SRVSVC
	SRVSVC_OPNUM_NetrShareEnum = 15
)

// SRVSVC interface UUID: 4B324FC8-1670-01D3-1278-5A47BF6EE188
var SRVSVC_UUID = []byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

// NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
var NDR_UUID = []byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

// AddShare adds a new share to the server
func (s *Server) AddShare(name, path, comment string) {
	s.sharesMu.Lock()
	defer s.sharesMu.Unlock()

	shareName := strings.ToUpper(name)
	s.shares[shareName] = &Share{
		name:    shareName,
		path:    path,
		comment: comment,
		stype:   0x00000000, // STYPE_DISKTREE
	}
}

// GetShare returns a share by name (case-insensitive)
func (s *Server) GetShare(name string) (*Share, bool) {
	s.sharesMu.RLock()
	defer s.sharesMu.RUnlock()

	share, ok := s.shares[strings.ToUpper(name)]
	return share, ok
}

// GetShares returns all shares
func (s *Server) GetShares() []*Share {
	s.sharesMu.RLock()
	defer s.sharesMu.RUnlock()

	shares := make([]*Share, 0, len(s.shares))
	for _, share := range s.shares {
		shares = append(shares, share)
	}
	return shares
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "gopacket v0.1.0 - SMB Server\n\n")
		fmt.Fprintf(os.Stderr, "usage: smbserver [-h] [-comment COMMENT] [-username USERNAME]\n")
		fmt.Fprintf(os.Stderr, "                 [-password PASSWORD] [-hashes LMHASH:NTHASH] [-ts]\n")
		fmt.Fprintf(os.Stderr, "                 [-debug] [-ip INTERFACE_ADDRESS] [-port PORT]\n")
		fmt.Fprintf(os.Stderr, "                 [-smb2support] [-outputfile OUTPUTFILE]\n")
		fmt.Fprintf(os.Stderr, "                 shareName sharePath\n\n")
		fmt.Fprintf(os.Stderr, "This script will launch a SMB Server and add a share specified as an argument.\n")
		fmt.Fprintf(os.Stderr, "You need to be root in order to bind to port 445. For all binding options, run with -h.\n\n")
		fmt.Fprintf(os.Stderr, "positional arguments:\n")
		fmt.Fprintf(os.Stderr, "  shareName             name of the share to add\n")
		fmt.Fprintf(os.Stderr, "  sharePath             path of the share to add\n\n")
		fmt.Fprintf(os.Stderr, "options:\n")
		fmt.Fprintf(os.Stderr, "  -h                    show this help message and exit\n")
		fmt.Fprintf(os.Stderr, "  -comment COMMENT      share's comment to display when asked for shares\n")
		fmt.Fprintf(os.Stderr, "  -username USERNAME    Username to authenticate clients\n")
		fmt.Fprintf(os.Stderr, "  -password PASSWORD    Password for the Username\n")
		fmt.Fprintf(os.Stderr, "  -hashes LMHASH:NTHASH\n")
		fmt.Fprintf(os.Stderr, "                        NTLM hashes for the Username, format is LMHASH:NTHASH\n")
		fmt.Fprintf(os.Stderr, "  -ts                   Adds timestamp to every logging output\n")
		fmt.Fprintf(os.Stderr, "  -debug                Turn DEBUG output ON\n")
		fmt.Fprintf(os.Stderr, "  -ip INTERFACE_ADDRESS\n")
		fmt.Fprintf(os.Stderr, "                        ip address of listening interface (default 0.0.0.0)\n")
		fmt.Fprintf(os.Stderr, "  -port PORT            TCP port for listening incoming connections (default 445)\n")
		fmt.Fprintf(os.Stderr, "  -smb2support          SMB2 Support (experimental!)\n")
		fmt.Fprintf(os.Stderr, "  -outputfile OUTPUTFILE\n")
		fmt.Fprintf(os.Stderr, "                        Output file to log smbserver messages\n")
	}

	// Check for -h anywhere in args (Go's flag stops at positional args)
	flags.CheckHelp()

	flag.Parse()

	if flag.NArg() < 2 {
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

	shareName := flag.Arg(0)
	sharePath := flag.Arg(1)

	// Validate share path
	absPath, err := filepath.Abs(sharePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid share path: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Share path does not exist: %v\n", err)
		os.Exit(1)
	}

	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "[-] Share path must be a directory\n")
		os.Exit(1)
	}

	server := &Server{
		shares:      make(map[string]*Share),
		sessions:    make(map[uint64]*Session),
		smb2Enabled: *smb2support,
		debug:       *debug,
		username:    *username,
		password:    *password,
	}

	// Add the primary share
	server.AddShare(shareName, absPath, *comment)

	// Generate server GUID
	rand.Read(server.serverGUID[:])

	// Parse hashes if provided
	if *hashes != "" {
		parts := strings.Split(*hashes, ":")
		if len(parts) == 2 {
			server.lmHash, _ = hex.DecodeString(parts[0])
			server.ntHash, _ = hex.DecodeString(parts[1])
		}
	} else if server.password != "" {
		// Compute NT hash from password
		server.ntHash = computeNTHash(server.password)
	}

	addr := fmt.Sprintf("%s:%d", *listenAddr, *listenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to listen on %s: %v\n", addr, err)
		os.Exit(1)
	}
	server.listener = listener

	logOutput("[*] SMB Server started on %s\n", addr)
	for name, share := range server.shares {
		logOutput("[*] Share: %s -> %s\n", name, share.path)
	}
	if server.smb2Enabled {
		logOutput("[*] SMB2 support enabled\n")
	}
	if server.username != "" {
		logOutput("[*] Authentication required: %s\n", server.username)
	} else {
		logOutput("[*] Anonymous access enabled\n")
	}
	logOutput("[*] Waiting for connections...\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if *debug {
				fmt.Printf("[DEBUG] Accept error: %v\n", err)
			}
			continue
		}

		go server.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	logOutput("[*] Connection from %s\n", clientAddr)

	session := &Session{
		id:           s.nextSessionID(),
		conn:         conn,
		treeConnects: make(map[uint32]*TreeConnect),
		openFiles:    make(map[string]*OpenFile),
	}

	s.sessionMu.Lock()
	s.sessions[session.id] = session
	s.sessionMu.Unlock()

	defer func() {
		s.sessionMu.Lock()
		delete(s.sessions, session.id)
		s.sessionMu.Unlock()
	}()

	// Read and process SMB packets
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		// Read NetBIOS header (4 bytes)
		nbHeader := make([]byte, 4)
		_, err := io.ReadFull(conn, nbHeader)
		if err != nil {
			if s.debug {
				fmt.Printf("[DEBUG] Read error from %s: %v\n", clientAddr, err)
			}
			return
		}

		// Get packet length from NetBIOS header
		pktLen := int(nbHeader[1])<<16 | int(nbHeader[2])<<8 | int(nbHeader[3])
		if pktLen == 0 || pktLen > 0x100000 {
			if s.debug {
				fmt.Printf("[DEBUG] Invalid packet length from %s: %d\n", clientAddr, pktLen)
			}
			return
		}

		// Read SMB packet
		pkt := make([]byte, pktLen)
		_, err = io.ReadFull(conn, pkt)
		if err != nil {
			if s.debug {
				fmt.Printf("[DEBUG] Read packet error from %s: %v\n", clientAddr, err)
			}
			return
		}

		// Check for SMB1 vs SMB2
		if len(pkt) >= 4 {
			if pkt[0] == 0xFF && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B' {
				// SMB1 - respond with SMB2 negotiate if enabled
				if s.smb2Enabled {
					resp := s.handleSMB1Negotiate(session, pkt)
					if resp != nil {
						s.sendPacket(conn, resp)
					}
				} else {
					// SMB1 not fully supported
					if s.debug {
						fmt.Printf("[DEBUG] SMB1 packet received, SMB2 not enabled\n")
					}
					return
				}
				continue
			} else if pkt[0] == 0xFE && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B' {
				// SMB2
				resp := s.handleSMB2Packet(session, pkt)
				if resp != nil {
					s.sendPacket(conn, resp)
				}
				continue
			}
		}

		if s.debug {
			fmt.Printf("[DEBUG] Unknown packet format from %s\n", clientAddr)
		}
		return
	}
}

func (s *Server) nextSessionID() uint64 {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.nextSession++
	return s.nextSession
}

func (s *Server) sendPacket(conn net.Conn, data []byte) error {
	// Add NetBIOS header
	pktLen := len(data)
	nbHeader := []byte{0x00, byte(pktLen >> 16), byte(pktLen >> 8), byte(pktLen)}

	_, err := conn.Write(append(nbHeader, data...))
	return err
}

func (s *Server) handleSMB1Negotiate(session *Session, pkt []byte) []byte {
	// Respond with SMB2 negotiate response to upgrade
	if s.debug {
		fmt.Printf("[DEBUG] SMB1 Negotiate received, upgrading to SMB2\n")
	}
	// For SMB1 upgrade, use dialect 2.0.2 (most compatible)
	session.negotiatedDialect = SMB2_DIALECT_202
	return s.buildSMB2NegotiateResponse(session, nil)
}

func (s *Server) handleSMB2Packet(session *Session, pkt []byte) []byte {
	if len(pkt) < 64 {
		return nil
	}

	// Parse SMB2 header
	command := binary.LittleEndian.Uint16(pkt[12:14])
	sessionID := binary.LittleEndian.Uint64(pkt[40:48])
	messageID := binary.LittleEndian.Uint64(pkt[24:32])
	treeID := binary.LittleEndian.Uint32(pkt[36:40])
	nextCommand := binary.LittleEndian.Uint32(pkt[20:24])

	if s.debug {
		fmt.Printf("[DEBUG] SMB2 Command: 0x%04x, SessionID: %d, TreeID: %d, NextCommand: %d, PktLen: %d\n", command, sessionID, treeID, nextCommand, len(pkt))
	}

	// Update session ID if set
	if sessionID != 0 {
		session.id = sessionID
	}

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
	case SMB2_FLUSH:
		return s.handleFlush(session, pkt, messageID, treeID)
	case SMB2_READ:
		return s.handleRead(session, pkt, messageID, treeID)
	case SMB2_WRITE:
		return s.handleWrite(session, pkt, messageID, treeID)
	case SMB2_LOCK:
		return s.handleLock(session, pkt, messageID, treeID)
	case SMB2_QUERY_DIRECTORY:
		return s.handleQueryDirectory(session, pkt, messageID, treeID)
	case SMB2_CHANGE_NOTIFY:
		return s.handleChangeNotify(session, pkt, messageID, treeID)
	case SMB2_QUERY_INFO:
		return s.handleQueryInfo(session, pkt, messageID, treeID)
	case SMB2_SET_INFO:
		return s.handleSetInfo(session, pkt, messageID, treeID)
	case SMB2_ECHO:
		return s.handleEcho(session, pkt, messageID, treeID)
	case SMB2_IOCTL:
		return s.handleIoctl(session, pkt, messageID, treeID)
	case SMB2_CANCEL:
		return s.handleCancel(session, pkt, messageID, treeID)
	case SMB2_LOGOFF:
		return s.handleLogoff(session, pkt, messageID, treeID)
	default:
		if s.debug {
			fmt.Printf("[DEBUG] Unhandled SMB2 command: 0x%04x\n", command)
		}
		return s.buildErrorResponse(command, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}
}

func (s *Server) handleNegotiate(session *Session, pkt []byte, messageID uint64) []byte {
	if s.debug {
		fmt.Printf("[DEBUG] SMB2 NEGOTIATE request\n")
	}

	// Parse negotiate request to get client dialects
	// SMB2 NEGOTIATE Request structure:
	// Offset 64: StructureSize (2 bytes)
	// Offset 66: DialectCount (2 bytes)
	// Offset 68: SecurityMode (2 bytes)
	// Offset 70: Reserved (2 bytes)
	// Offset 72: Capabilities (4 bytes)
	// Offset 76: ClientGuid (16 bytes)
	// Offset 92: NegotiateContextOffset/Reserved2 (4 bytes)
	// Offset 96: Dialects array (2 bytes each)

	if len(pkt) < 100 {
		// Too short to have any dialects, use default
		session.negotiatedDialect = SMB2_DIALECT_202
		return s.buildSMB2NegotiateResponse(session, pkt)
	}

	dialectCount := binary.LittleEndian.Uint16(pkt[66:68])

	// Sanity check dialect count
	if dialectCount > 16 || len(pkt) < 96+int(dialectCount)*2 {
		session.negotiatedDialect = SMB2_DIALECT_202
		return s.buildSMB2NegotiateResponse(session, pkt)
	}

	// Parse client dialects and find the best match
	// We support: 2.0.2, 2.1, 3.0, 3.0.2 (not 3.1.1 as that requires preauth contexts)
	clientDialects := make([]uint16, dialectCount)
	for i := uint16(0); i < dialectCount; i++ {
		clientDialects[i] = binary.LittleEndian.Uint16(pkt[96+i*2 : 98+i*2])
	}

	if s.debug {
		fmt.Printf("[DEBUG] Client dialects: %v\n", clientDialects)
	}

	// Select the highest mutually supported dialect
	// Preference order: 3.0.2 > 3.0 > 2.1 > 2.0.2
	supportedDialects := []uint16{SMB2_DIALECT_302, SMB2_DIALECT_30, SMB2_DIALECT_21, SMB2_DIALECT_202}
	selectedDialect := uint16(0)

	for _, supported := range supportedDialects {
		for _, client := range clientDialects {
			if client == supported {
				selectedDialect = supported
				break
			}
		}
		if selectedDialect != 0 {
			break
		}
	}

	// If no match found, use 2.0.2 as fallback or check for wildcard
	if selectedDialect == 0 {
		for _, client := range clientDialects {
			if client == SMB2_DIALECT_WILD {
				selectedDialect = SMB2_DIALECT_202
				break
			}
		}
	}

	if selectedDialect == 0 {
		selectedDialect = SMB2_DIALECT_202
	}

	session.negotiatedDialect = selectedDialect

	if s.debug {
		fmt.Printf("[DEBUG] Selected dialect: 0x%04x\n", selectedDialect)
	}

	return s.buildSMB2NegotiateResponse(session, pkt)
}

func (s *Server) buildSMB2NegotiateResponse(session *Session, pkt []byte) []byte {
	// Build SPNEGO NegTokenInit with NTLM OID
	// NTLM OID: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// Build MechTypeList (sequence of OIDs)
	mechTypeList := append([]byte{0x06, byte(len(ntlmOID))}, ntlmOID...)
	mechTypeListSeq := asn1Wrap(0x30, mechTypeList)

	// Build MechTypes [0] context tag
	mechTypes := asn1Wrap(0xa0, mechTypeListSeq)

	// Build NegTokenInit sequence
	negTokenInit := asn1Wrap(0x30, mechTypes)

	// Wrap in SPNEGO OID application tag
	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	spnegoData := append(spnegoOID, asn1Wrap(0xa0, negTokenInit)...)
	securityBuffer := asn1Wrap(0x60, spnegoData)

	// Calculate response size: 64 (header) + 65 (negotiate response body) + security buffer
	// SecurityBufferOffset is from start of SMB2 header = 64 + 64 = 128 (0x80)
	respLen := 64 + 65 + len(securityBuffer)
	resp := make([]byte, respLen)

	// SMB2 Header
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(resp[6:8], 0)  // CreditCharge
	binary.LittleEndian.PutUint32(resp[8:12], 0) // Status
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_NEGOTIATE)
	binary.LittleEndian.PutUint16(resp[14:16], 1) // CreditResponse
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)

	// Negotiate Response (65 bytes structure size)
	binary.LittleEndian.PutUint16(resp[64:66], 65)                             // StructureSize
	binary.LittleEndian.PutUint16(resp[66:68], SMB2_NEGOTIATE_SIGNING_ENABLED) // SecurityMode (signing enabled but not required)
	binary.LittleEndian.PutUint16(resp[68:70], session.negotiatedDialect)      // DialectRevision
	binary.LittleEndian.PutUint16(resp[70:72], 0)                              // Reserved
	copy(resp[72:88], s.serverGUID[:])                                         // ServerGUID

	// Set capabilities based on dialect
	var capabilities uint32 = 0
	if session.negotiatedDialect >= SMB2_DIALECT_30 {
		// SMB 3.0+ supports large MTU and multi-channel
		capabilities = SMB2_GLOBAL_CAP_LARGE_MTU
	}
	binary.LittleEndian.PutUint32(resp[88:92], capabilities)
	binary.LittleEndian.PutUint32(resp[92:96], 65536)   // MaxTransactSize
	binary.LittleEndian.PutUint32(resp[96:100], 65536)  // MaxReadSize
	binary.LittleEndian.PutUint32(resp[100:104], 65536) // MaxWriteSize
	// SystemTime and ServerStartTime at 104-120
	binary.LittleEndian.PutUint64(resp[104:112], timeToFiletime(time.Now()))  // SystemTime
	binary.LittleEndian.PutUint64(resp[112:120], timeToFiletime(time.Now()))  // ServerStartTime
	binary.LittleEndian.PutUint16(resp[120:122], 128)                         // SecurityBufferOffset (0x80)
	binary.LittleEndian.PutUint16(resp[122:124], uint16(len(securityBuffer))) // SecurityBufferLength
	// NegotiateContextOffset at 124-127 (leave as zero for SMB 2.1)

	// Copy security buffer
	copy(resp[128:], securityBuffer)

	return resp
}

func (s *Server) handleSessionSetup(session *Session, pkt []byte, messageID uint64) []byte {
	if len(pkt) < 64+25 {
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	// Parse Session Setup Request
	secBufOffset := binary.LittleEndian.Uint16(pkt[76:78])
	secBufLen := binary.LittleEndian.Uint16(pkt[78:80])

	if s.debug {
		fmt.Printf("[DEBUG] Session Setup: secBufOffset=%d, secBufLen=%d, pktLen=%d\n",
			secBufOffset, secBufLen, len(pkt))
	}

	if int(secBufOffset)+int(secBufLen) > len(pkt) {
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	securityBuffer := pkt[secBufOffset : secBufOffset+secBufLen]

	if s.debug && len(securityBuffer) > 0 {
		fmt.Printf("[DEBUG] Security buffer first 20 bytes: %x\n", securityBuffer[:min(20, len(securityBuffer))])
	}

	// Parse NTLM message
	return s.handleNTLMAuth(session, securityBuffer, messageID)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) handleNTLMAuth(session *Session, secBuffer []byte, messageID uint64) []byte {
	// Check for SPNEGO wrapper or raw NTLM
	var ntlmMsg []byte

	if len(secBuffer) > 7 && bytes.Equal(secBuffer[0:7], []byte{0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2b}) {
		// SPNEGO - find NTLM inside
		ntlmMsg = s.extractNTLMFromSPNEGO(secBuffer)
	} else if len(secBuffer) > 4 && bytes.Equal(secBuffer[0:4], []byte("NTLM")) {
		ntlmMsg = secBuffer
	} else if len(secBuffer) > 10 {
		// Try to find NTLMSSP signature
		idx := bytes.Index(secBuffer, []byte("NTLMSSP\x00"))
		if idx >= 0 {
			ntlmMsg = secBuffer[idx:]
		}
	}

	if ntlmMsg == nil || len(ntlmMsg) < 12 {
		if s.debug {
			fmt.Printf("[DEBUG] Could not parse NTLM message\n")
		}
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	// Get message type
	msgType := binary.LittleEndian.Uint32(ntlmMsg[8:12])

	switch msgType {
	case 1: // NEGOTIATE
		return s.handleNTLMNegotiate(session, ntlmMsg, messageID)
	case 3: // AUTHENTICATE
		return s.handleNTLMAuthenticate(session, ntlmMsg, messageID)
	default:
		return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}
}

func (s *Server) extractNTLMFromSPNEGO(data []byte) []byte {
	// Simple extraction - find NTLMSSP signature
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx >= 0 {
		return data[idx:]
	}
	return nil
}

func (s *Server) handleNTLMNegotiate(session *Session, ntlmMsg []byte, messageID uint64) []byte {
	// Generate challenge
	session.challenge = make([]byte, 8)
	rand.Read(session.challenge)

	if s.debug {
		fmt.Printf("[DEBUG] NTLM Negotiate received, sending challenge: %x\n", session.challenge)
	}

	// Build NTLM Challenge (Type 2)
	challenge := s.buildNTLMChallenge(session.challenge)

	// Wrap in SPNEGO
	spnegoResp := s.wrapInSPNEGO(challenge, true)

	// Build Session Setup Response with MORE_PROCESSING_REQUIRED
	return s.buildSessionSetupResponse(session, messageID, STATUS_MORE_PROCESSING_REQUIRED, spnegoResp)
}

func (s *Server) buildNTLMChallenge(challenge []byte) []byte {
	targetName := "SERVER"
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
	// MsvAvTimestamp (type 7) - current time
	binary.Write(&targetInfo, binary.LittleEndian, uint16(7))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(8))
	binary.Write(&targetInfo, binary.LittleEndian, timeToFiletime(time.Now()))
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
	// Flags - NTLMSSP negotiate flags (matching Impacket: 0x628a0215)
	// Includes SIGN but not ALWAYS_SIGN or SEAL
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
	// Version (8 bytes at 48-55)
	msg[48] = 6                                     // Major
	msg[49] = 1                                     // Minor
	binary.LittleEndian.PutUint16(msg[50:52], 7600) // Build
	msg[55] = 15                                    // NTLM revision

	// Target name
	copy(msg[56:], targetNameUTF16)
	// Target info
	copy(msg[targetInfoOffset:], targetInfoBytes)

	return msg
}

func (s *Server) handleNTLMAuthenticate(session *Session, ntlmMsg []byte, messageID uint64) []byte {
	// NTLM Type 3 minimum: 64 bytes (can be shorter for anonymous auth)
	if len(ntlmMsg) < 52 {
		if s.debug {
			fmt.Printf("[DEBUG] NTLM Type 3 too short: %d bytes\n", len(ntlmMsg))
		}
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

	// Print captured hash
	s.printCapturedHash(user, domain, session.challenge, lmResponse, ntResponse)

	// Check if authentication required
	if s.username != "" {
		// Validate credentials
		if !s.validateNTLMResponse(user, domain, session.challenge, ntResponse) {
			logOutput("[!] Authentication failed for %s\\%s\n", domain, user)
			return s.buildErrorResponse(SMB2_SESSION_SETUP, messageID, session.id, 0, STATUS_LOGON_FAILURE)
		}
	}

	// Authentication successful (or no auth required)
	session.authenticated = true
	logOutput("[+] Authenticated: %s\\%s\n", domain, user)

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

		logOutput("\n[*] Hashcat format (mode 5600):\n")
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

func (s *Server) validateNTLMResponse(user, domain string, challenge, ntResponse []byte) bool {
	if s.ntHash == nil {
		return true // No auth configured
	}

	if strings.ToLower(user) != strings.ToLower(s.username) {
		return false
	}

	// For NTLMv2, we'd need to compute the expected response
	// This is a simplified check
	return true // Accept for now if username matches
}

func (s *Server) wrapInSPNEGO(ntlmToken []byte, isChallenge bool) []byte {
	// Build SPNEGO NegTokenResp
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
		// No responseToken needed for accept-completed
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
	binary.LittleEndian.PutUint16(resp[14:16], 0x2000) // Credits (match Impacket)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	// Session Setup Response
	binary.LittleEndian.PutUint16(resp[64:66], 9) // StructureSize
	// Set IS_GUEST flag (0x0001) - guest sessions don't require signing
	binary.LittleEndian.PutUint16(resp[66:68], 0x0001) // SessionFlags = IS_GUEST
	binary.LittleEndian.PutUint16(resp[68:70], 72)     // SecurityBufferOffset
	binary.LittleEndian.PutUint16(resp[70:72], uint16(len(secBuffer)))

	copy(resp[72:], secBuffer)

	if s.debug {
		fmt.Printf("[DEBUG] Session Setup Response (status=0x%x, %d bytes): %x\n", status, len(resp), resp)
	}

	return resp
}

func (s *Server) handleTreeConnect(session *Session, pkt []byte, messageID uint64) []byte {
	if len(pkt) < 64+9 {
		return s.buildErrorResponse(SMB2_TREE_CONNECT, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	pathOffset := binary.LittleEndian.Uint16(pkt[68:70])
	pathLen := binary.LittleEndian.Uint16(pkt[70:72])

	if int(pathOffset)+int(pathLen) > len(pkt) {
		return s.buildErrorResponse(SMB2_TREE_CONNECT, messageID, session.id, 0, STATUS_INVALID_PARAMETER)
	}

	pathBytes := pkt[pathOffset : pathOffset+pathLen]
	path := utf16LEDecode(pathBytes)

	if s.debug {
		fmt.Printf("[DEBUG] Tree Connect to: %s\n", path)
	}

	// Extract share name from \\server\share format
	parts := strings.Split(strings.TrimPrefix(path, "\\\\"), "\\")
	var shareName string
	if len(parts) >= 2 {
		shareName = strings.ToUpper(parts[1])
	}

	// Check if share exists
	var sharePath string
	isIPC := shareName == "IPC$"

	if isIPC {
		sharePath = ""
	} else {
		share, ok := s.GetShare(shareName)
		if !ok {
			logOutput("[!] Share not found: %s\n", shareName)
			return s.buildErrorResponse(SMB2_TREE_CONNECT, messageID, session.id, 0, STATUS_OBJECT_NAME_NOT_FOUND)
		}
		sharePath = share.path
	}

	// Create tree connect
	session.nextTreeID++
	treeID := session.nextTreeID

	tc := &TreeConnect{
		id:        treeID,
		shareName: shareName,
		sharePath: sharePath,
	}
	session.treeConnects[treeID] = tc

	logOutput("[+] Tree Connect: %s (TreeID: %d)\n", shareName, treeID)

	return s.buildTreeConnectResponse(session, messageID, treeID, isIPC)
}

func (s *Server) buildTreeConnectResponse(session *Session, messageID uint64, treeID uint32, isIPC bool) []byte {
	resp := make([]byte, 64+16)

	// SMB2 Header
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(resp[6:8], 0)  // CreditCharge
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_TREE_CONNECT)
	binary.LittleEndian.PutUint16(resp[14:16], 32) // CreditResponse
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint32(resp[20:24], 0) // NextCommand
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[32:36], 0) // Reserved
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	// Signature at 48-63 remains zero

	// Tree Connect Response (16 bytes)
	binary.LittleEndian.PutUint16(resp[64:66], 16) // StructureSize

	if isIPC {
		resp[66] = 0x02 // ShareType = PIPE
	} else {
		resp[66] = 0x01 // ShareType = DISK
	}

	resp[67] = 0x00 // Reserved

	// ShareFlags
	binary.LittleEndian.PutUint32(resp[68:72], 0x00000000)

	// Capabilities
	binary.LittleEndian.PutUint32(resp[72:76], 0x00000000)

	// MaximalAccess - FILE_ALL_ACCESS
	binary.LittleEndian.PutUint32(resp[76:80], 0x001f01ff)

	if s.debug {
		fmt.Printf("[DEBUG] Tree Connect Response (%d bytes): %x\n", len(resp), resp)
	}

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
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 4)

	return resp
}

func (s *Server) handleCreate(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+57 {
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Parse CREATE request fields
	// Offset 64: StructureSize (2)
	// Offset 66: SecurityFlags (1)
	// Offset 67: RequestedOplockLevel (1)
	// Offset 68: ImpersonationLevel (4)
	// Offset 72: SmbCreateFlags (8)
	// Offset 80: Reserved (8)
	// Offset 88: DesiredAccess (4)
	// Offset 92: FileAttributes (4)
	// Offset 96: ShareAccess (4)
	// Offset 100: CreateDisposition (4)
	// Offset 104: CreateOptions (4)
	// Offset 108: NameOffset (2)
	// Offset 110: NameLength (2)

	desiredAccess := binary.LittleEndian.Uint32(pkt[88:92])
	// fileAttributes := binary.LittleEndian.Uint32(pkt[92:96])
	// shareAccess := binary.LittleEndian.Uint32(pkt[96:100])
	createDisposition := binary.LittleEndian.Uint32(pkt[100:104])
	createOptions := binary.LittleEndian.Uint32(pkt[104:108])
	nameOffset := binary.LittleEndian.Uint16(pkt[108:110])
	nameLen := binary.LittleEndian.Uint16(pkt[110:112])

	var fileName string
	if nameLen > 0 && int(nameOffset)+int(nameLen) <= len(pkt) {
		fileName = utf16LEDecode(pkt[nameOffset : nameOffset+nameLen])
	}

	tc := session.treeConnects[treeID]
	if tc == nil {
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Check if this is IPC$ (named pipe)
	if tc.shareName == "IPC$" {
		return s.handleCreateNamedPipe(session, fileName, messageID, treeID)
	}

	// Build full path
	fullPath := filepath.Join(tc.sharePath, fileName)

	if s.debug {
		fmt.Printf("[DEBUG] Create: %s -> %s (disposition=%d, options=0x%x, access=0x%x)\n",
			fileName, fullPath, createDisposition, createOptions, desiredAccess)
	}

	// Check if file/dir exists
	info, err := os.Stat(fullPath)
	exists := err == nil

	// Handle create disposition
	var needsCreate bool
	var needsTruncate bool

	switch createDisposition {
	case FILE_SUPERSEDE: // 0 - Delete if exists, then create
		if exists {
			if info.IsDir() {
				os.RemoveAll(fullPath)
			} else {
				os.Remove(fullPath)
			}
		}
		needsCreate = true

	case FILE_OPEN: // 1 - Open existing file, fail if not exists
		if !exists {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
		}

	case FILE_CREATE: // 2 - Create new file, fail if exists
		if exists {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_COLLISION)
		}
		needsCreate = true

	case FILE_OPEN_IF: // 3 - Open if exists, create if not
		if !exists {
			needsCreate = true
		}

	case FILE_OVERWRITE: // 4 - Open and truncate, fail if not exists
		if !exists {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
		}
		needsTruncate = true

	case FILE_OVERWRITE_IF: // 5 - Open and truncate if exists, create if not
		if exists {
			needsTruncate = true
		} else {
			needsCreate = true
		}
	}

	// Check if requesting directory vs file
	wantsDirectory := (createOptions & FILE_DIRECTORY_FILE) != 0
	wantsFile := (createOptions & FILE_NON_DIRECTORY_FILE) != 0

	// Create file or directory if needed
	if needsCreate {
		if wantsDirectory {
			if err := os.MkdirAll(fullPath, 0755); err != nil {
				if s.debug {
					fmt.Printf("[DEBUG] Failed to create directory: %v\n", err)
				}
				return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
			}
			logOutput("[+] Created directory: %s\n", fileName)
		} else {
			// Create parent directories if needed
			parentDir := filepath.Dir(fullPath)
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				if s.debug {
					fmt.Printf("[DEBUG] Failed to create parent directory: %v\n", err)
				}
				return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
			}
			// Create empty file
			f, err := os.Create(fullPath)
			if err != nil {
				if s.debug {
					fmt.Printf("[DEBUG] Failed to create file: %v\n", err)
				}
				return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
			}
			f.Close()
			logOutput("[+] Created file: %s\n", fileName)
		}
		// Re-stat after creation
		info, err = os.Stat(fullPath)
		if err != nil {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
		}
	}

	// Verify file/directory type matches request
	if exists || !needsCreate {
		if wantsDirectory && !info.IsDir() {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_NOT_A_DIRECTORY)
		}
		if wantsFile && info.IsDir() {
			return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_FILE_IS_A_DIRECTORY)
		}
	}

	// Handle truncation
	if needsTruncate && !info.IsDir() {
		if err := os.Truncate(fullPath, 0); err != nil {
			if s.debug {
				fmt.Printf("[DEBUG] Failed to truncate: %v\n", err)
			}
		}
		// Re-stat after truncation
		info, _ = os.Stat(fullPath)
	}

	// Generate file ID
	var fileID [16]byte
	rand.Read(fileID[:])

	// Check for delete-on-close
	deleteOnClose := (createOptions & FILE_DELETE_ON_CLOSE) != 0

	of := &OpenFile{
		id:            fileID,
		path:          fileName,
		realPath:      fullPath,
		isDir:         info.IsDir(),
		deleteOnClose: deleteOnClose,
		desiredAccess: desiredAccess,
	}
	session.openFiles[hex.EncodeToString(fileID[:])] = of

	logOutput("[+] Open: %s\n", fileName)

	return s.buildCreateResponse(session, messageID, treeID, fileID, info)
}

func (s *Server) handleCreateNamedPipe(session *Session, pipeName string, messageID uint64, treeID uint32) []byte {
	// Normalize pipe name (remove leading backslash, case insensitive)
	pipeName = strings.TrimPrefix(pipeName, "\\")
	pipeName = strings.ToLower(pipeName)

	if s.debug {
		fmt.Printf("[DEBUG] Named Pipe Open: %s\n", pipeName)
	}

	// Supported named pipes
	supportedPipes := map[string]bool{
		"srvsvc": true,
	}

	if !supportedPipes[pipeName] {
		if s.debug {
			fmt.Printf("[DEBUG] Unsupported named pipe: %s\n", pipeName)
		}
		return s.buildErrorResponse(SMB2_CREATE, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
	}

	// Generate file ID for pipe
	var fileID [16]byte
	rand.Read(fileID[:])

	of := &OpenFile{
		id:       fileID,
		path:     pipeName,
		isPipe:   true,
		pipeName: pipeName,
		pipeData: &NamedPipeState{},
	}
	session.openFiles[hex.EncodeToString(fileID[:])] = of

	logOutput("[+] Named Pipe Open: %s\n", pipeName)

	return s.buildNamedPipeCreateResponse(session, messageID, treeID, fileID)
}

func (s *Server) buildNamedPipeCreateResponse(session *Session, messageID uint64, treeID uint32, fileID [16]byte) []byte {
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
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	// Create Response
	binary.LittleEndian.PutUint16(resp[64:66], 89) // StructureSize
	resp[66] = 0x00                                // OplockLevel = None
	resp[67] = 0x00                                // Flags

	// File times (use current time)
	now := timeToFiletime(time.Now())
	binary.LittleEndian.PutUint64(resp[72:80], now)
	binary.LittleEndian.PutUint64(resp[80:88], now)
	binary.LittleEndian.PutUint64(resp[88:96], now)
	binary.LittleEndian.PutUint64(resp[96:104], now)

	// AllocationSize and EndOfFile = 0 for pipes
	// FileAttributes = 0x80 (NORMAL)
	binary.LittleEndian.PutUint32(resp[120:124], 0x80)

	// FileId
	copy(resp[128:144], fileID[:])

	return resp
}

func (s *Server) buildCreateResponse(session *Session, messageID uint64, treeID uint32, fileID [16]byte, info os.FileInfo) []byte {
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
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	// Create Response
	binary.LittleEndian.PutUint16(resp[64:66], 89) // StructureSize
	resp[66] = 0x01                                // OplockLevel
	resp[67] = 0x01                                // Flags

	// File times (simplified - use current time)
	now := timeToFiletime(time.Now())
	binary.LittleEndian.PutUint64(resp[72:80], now)                   // CreationTime
	binary.LittleEndian.PutUint64(resp[80:88], now)                   // LastAccessTime
	binary.LittleEndian.PutUint64(resp[88:96], now)                   // LastWriteTime
	binary.LittleEndian.PutUint64(resp[96:104], now)                  // ChangeTime
	binary.LittleEndian.PutUint64(resp[112:120], uint64(info.Size())) // EndOfFile
	binary.LittleEndian.PutUint64(resp[104:112], uint64(info.Size())) // AllocationSize

	// File attributes
	var attrs uint32 = 0x80 // NORMAL
	if info.IsDir() {
		attrs = 0x10 // DIRECTORY
	}
	binary.LittleEndian.PutUint32(resp[120:124], attrs)
	// Reserved2 at 124-127

	// FileId at offset 128 (64 header + 64 in response body)
	copy(resp[128:144], fileID[:])

	if s.debug {
		fmt.Printf("[DEBUG] Create Response - TreeID at offset 36: %d\n", binary.LittleEndian.Uint32(resp[36:40]))
	}

	return resp
}

func (s *Server) handleClose(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+24 {
		return s.buildErrorResponse(SMB2_CLOSE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	fileID := pkt[72:88]
	fileIDStr := hex.EncodeToString(fileID)

	if of, ok := session.openFiles[fileIDStr]; ok {
		// Close the file handle first
		if of.file != nil {
			of.file.Close()
			of.file = nil
		}

		// Handle delete-on-close or delete-pending
		if of.deleteOnClose || of.deletePending {
			if !of.isPipe {
				if of.isDir {
					if err := os.Remove(of.realPath); err != nil {
						if s.debug {
							fmt.Printf("[DEBUG] Failed to delete directory on close: %v\n", err)
						}
					} else {
						logOutput("[+] Deleted directory: %s\n", of.path)
					}
				} else {
					if err := os.Remove(of.realPath); err != nil {
						if s.debug {
							fmt.Printf("[DEBUG] Failed to delete file on close: %v\n", err)
						}
					} else {
						logOutput("[+] Deleted file: %s\n", of.path)
					}
				}
			}
		}

		delete(session.openFiles, fileIDStr)
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
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 60)

	return resp
}

func (s *Server) handleRead(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+49 {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	length := binary.LittleEndian.Uint32(pkt[68:72])
	offset := binary.LittleEndian.Uint64(pkt[72:80])
	fileID := pkt[80:96]
	fileIDStr := hex.EncodeToString(fileID)

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Handle named pipe read (return pending DCE/RPC response)
	if of.isPipe {
		return s.handlePipeRead(session, of, messageID, treeID, length)
	}

	// Open file if not already open
	if of.file == nil {
		f, err := os.Open(of.realPath)
		if err != nil {
			return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
		}
		of.file = f
	}

	// Read data
	data := make([]byte, length)
	of.file.Seek(int64(offset), 0)
	n, err := of.file.Read(data)
	if err != nil && err != io.EOF {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
	}

	if n == 0 {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_END_OF_FILE)
	}

	data = data[:n]

	// Build response
	resp := make([]byte, 64+17+n)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_READ)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	binary.LittleEndian.PutUint16(resp[64:66], 17) // StructureSize
	resp[66] = 0x50                                // DataOffset
	binary.LittleEndian.PutUint32(resp[68:72], uint32(n))
	copy(resp[80:], data)

	return resp
}

func (s *Server) handlePipeRead(session *Session, of *OpenFile, messageID uint64, treeID uint32, maxLength uint32) []byte {
	if of.pipeData == nil || len(of.pipeData.pendingResponse) == 0 {
		return s.buildErrorResponse(SMB2_READ, messageID, session.id, treeID, STATUS_END_OF_FILE)
	}

	data := of.pipeData.pendingResponse
	if uint32(len(data)) > maxLength {
		data = data[:maxLength]
	}

	// Clear pending response
	of.pipeData.pendingResponse = nil

	if s.debug {
		fmt.Printf("[DEBUG] Pipe Read: returning %d bytes\n", len(data))
	}

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
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	binary.LittleEndian.PutUint16(resp[64:66], 17)
	resp[66] = 0x50 // DataOffset (80)
	binary.LittleEndian.PutUint32(resp[68:72], uint32(len(data)))
	copy(resp[80:], data)

	return resp
}

func (s *Server) handleWrite(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+49 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	dataOffset := binary.LittleEndian.Uint16(pkt[66:68])
	length := binary.LittleEndian.Uint32(pkt[68:72])
	offset := binary.LittleEndian.Uint64(pkt[72:80])
	fileID := pkt[80:96]
	fileIDStr := hex.EncodeToString(fileID)

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	if int(dataOffset)+int(length) > len(pkt) {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	data := pkt[dataOffset : dataOffset+uint16(length)]

	// Handle named pipe write (DCE/RPC)
	if of.isPipe {
		return s.handlePipeWrite(session, of, data, messageID, treeID)
	}

	// Open file for writing if not already open
	if of.file == nil {
		f, err := os.OpenFile(of.realPath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
		}
		of.file = f
	}

	of.file.Seek(int64(offset), 0)
	n, err := of.file.Write(data)
	if err != nil {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
	}

	// Build response
	resp := make([]byte, 64+17)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_WRITE)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	binary.LittleEndian.PutUint16(resp[64:66], 17)
	binary.LittleEndian.PutUint32(resp[68:72], uint32(n))

	return resp
}

func (s *Server) handlePipeWrite(session *Session, of *OpenFile, data []byte, messageID uint64, treeID uint32) []byte {
	if len(data) < 16 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Parse DCE/RPC header
	version := data[0]
	versionMinor := data[1]
	packetType := data[2]
	flags := data[3]
	// dataRep := binary.LittleEndian.Uint32(data[4:8])
	fragLen := binary.LittleEndian.Uint16(data[8:10])
	// authLen := binary.LittleEndian.Uint16(data[10:12])
	callID := binary.LittleEndian.Uint32(data[12:16])

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC: version=%d.%d, type=%d, flags=0x%02x, fragLen=%d, callID=%d\n",
			version, versionMinor, packetType, flags, fragLen, callID)
	}

	switch packetType {
	case DCERPC_BIND:
		return s.handleDCERPCBind(session, of, data, messageID, treeID, callID)
	case DCERPC_REQUEST:
		return s.handleDCERPCRequest(session, of, data, messageID, treeID, callID)
	default:
		if s.debug {
			fmt.Printf("[DEBUG] Unsupported DCE/RPC packet type: %d\n", packetType)
		}
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}
}

func (s *Server) handleDCERPCBind(session *Session, of *OpenFile, data []byte, messageID uint64, treeID uint32, callID uint32) []byte {
	if len(data) < 24 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Parse BIND request
	// maxXmitFrag := binary.LittleEndian.Uint16(data[16:18])
	// maxRecvFrag := binary.LittleEndian.Uint16(data[18:20])
	// assocGroup := binary.LittleEndian.Uint32(data[20:24])
	numCtxItems := data[24]

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC BIND: numCtxItems=%d\n", numCtxItems)
	}

	// Parse context items (simplified - assume first context is SRVSVC)
	// Context item starts at offset 28
	var contextID uint16
	if len(data) >= 30 {
		contextID = binary.LittleEndian.Uint16(data[28:30])
	}

	of.pipeData.callID = callID
	of.pipeData.contextID = contextID
	of.pipeData.bound = true

	// Build BIND_ACK response
	bindAck := s.buildDCERPCBindAck(callID, contextID)
	of.pipeData.pendingResponse = bindAck

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC BIND_ACK prepared (%d bytes)\n", len(bindAck))
	}

	// Return SMB2 WRITE response (data was consumed)
	return s.buildWriteResponse(session, messageID, treeID, uint32(len(data)))
}

func (s *Server) buildDCERPCBindAck(callID uint32, contextID uint16) []byte {
	// Build BIND_ACK response
	// Secondary address: "\PIPE\srvsvc" in NDR format
	secAddr := []byte("\\PIPE\\srvsvc")
	secAddrLen := len(secAddr) + 1 // Include null terminator

	// Calculate padding for secondary address (align to 4-byte boundary)
	// The padding is applied after secAddrLen(2) + secAddr + null
	totalSecAddr := 2 + secAddrLen // secAddrLen field + string + null
	secAddrPadding := 0
	if totalSecAddr%4 != 0 {
		secAddrPadding = 4 - (totalSecAddr % 4)
	}

	// Result list: n_results(1) + reserved(3) + result(24)
	// Each result is 24 bytes: result(2) + reason(2) + transfer_syntax(20)
	resultListLen := 4 + 24 // n_results + padding + one result

	headerLen := 24 + totalSecAddr + secAddrPadding + resultListLen
	resp := make([]byte, headerLen)

	// DCE/RPC header (16 bytes)
	resp[0] = DCERPC_VERSION
	resp[1] = DCERPC_VERSION_MINOR
	resp[2] = DCERPC_BIND_ACK
	resp[3] = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG // Flags
	// Data representation (little-endian, ASCII, IEEE float)
	resp[4] = 0x10
	resp[5] = 0x00
	resp[6] = 0x00
	resp[7] = 0x00
	binary.LittleEndian.PutUint16(resp[8:10], uint16(headerLen)) // Frag length
	binary.LittleEndian.PutUint16(resp[10:12], 0)                // Auth length
	binary.LittleEndian.PutUint32(resp[12:16], callID)

	// BIND_ACK specific (8 bytes at offset 16)
	binary.LittleEndian.PutUint16(resp[16:18], 4280)   // Max transmit frag
	binary.LittleEndian.PutUint16(resp[18:20], 4280)   // Max receive frag
	binary.LittleEndian.PutUint32(resp[20:24], 0x53f0) // Assoc group (non-zero)

	// Secondary address (at offset 24)
	offset := 24
	binary.LittleEndian.PutUint16(resp[offset:offset+2], uint16(secAddrLen))
	offset += 2
	copy(resp[offset:], secAddr)
	resp[offset+len(secAddr)] = 0 // Null terminator
	offset += secAddrLen + secAddrPadding

	// Number of results (1 byte + 3 bytes padding for alignment)
	resp[offset] = 1   // n_results
	resp[offset+1] = 0 // reserved
	resp[offset+2] = 0 // reserved
	resp[offset+3] = 0 // reserved
	offset += 4

	// Context result: acceptance (24 bytes)
	binary.LittleEndian.PutUint16(resp[offset:offset+2], 0)   // Result = acceptance
	binary.LittleEndian.PutUint16(resp[offset+2:offset+4], 0) // Reason = not specified
	// Transfer syntax (NDR UUID + version)
	copy(resp[offset+4:offset+20], NDR_UUID)
	binary.LittleEndian.PutUint32(resp[offset+20:offset+24], 2) // NDR version 2.0

	if s.debug {
		fmt.Printf("[DEBUG] BIND_ACK: len=%d, secAddrLen=%d, secAddrPadding=%d\n",
			len(resp), secAddrLen, secAddrPadding)
	}

	return resp
}

func (s *Server) handleDCERPCRequest(session *Session, of *OpenFile, data []byte, messageID uint64, treeID uint32, callID uint32) []byte {
	if len(data) < 24 {
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Parse REQUEST
	// allocHint := binary.LittleEndian.Uint32(data[16:20])
	contextID := binary.LittleEndian.Uint16(data[20:22])
	opnum := binary.LittleEndian.Uint16(data[22:24])

	if s.debug {
		fmt.Printf("[DEBUG] DCE/RPC REQUEST: contextID=%d, opnum=%d, pipe=%s\n", contextID, opnum, of.pipeName)
	}

	var response []byte

	switch of.pipeName {
	case "srvsvc":
		response = s.handleSRVSVCRequest(opnum, data[24:], callID)
	default:
		return s.buildErrorResponse(SMB2_WRITE, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}

	of.pipeData.pendingResponse = response

	return s.buildWriteResponse(session, messageID, treeID, uint32(len(data)))
}

func (s *Server) handleSRVSVCRequest(opnum uint16, stubData []byte, callID uint32) []byte {
	switch opnum {
	case SRVSVC_OPNUM_NetrShareEnum:
		return s.handleNetrShareEnum(stubData, callID)
	default:
		if s.debug {
			fmt.Printf("[DEBUG] Unsupported SRVSVC opnum: %d\n", opnum)
		}
		return s.buildDCERPCFault(callID, 0x1c010002) // nca_op_rng_error
	}
}

func (s *Server) handleNetrShareEnum(stubData []byte, callID uint32) []byte {
	if s.debug {
		fmt.Printf("[DEBUG] NetrShareEnum request\n")
	}

	// Build SHARE_INFO_1 response with all shares
	type shareInfo struct {
		name   string
		stype  uint32
		remark string
	}

	shares := []shareInfo{}

	// Add all disk shares from the server
	for _, share := range s.GetShares() {
		shares = append(shares, shareInfo{
			name:   share.name,
			stype:  share.stype,
			remark: share.comment,
		})
	}

	// Always add IPC$
	shares = append(shares, shareInfo{
		name:   "IPC$",
		stype:  0x80000003, // STYPE_IPC | STYPE_SPECIAL
		remark: "Remote IPC",
	})

	// Build NDR response according to MS-SRVS and NDR encoding rules
	var buf bytes.Buffer

	// SHARE_ENUM_STRUCT:
	// - Level (4 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	// - ShareInfo union (switch_is Level)
	//   - For Level 1: SHARE_INFO_1_CONTAINER*
	//   - First write the union switch value
	binary.Write(&buf, binary.LittleEndian, uint32(1))

	// SHARE_INFO_1_CONTAINER (pointed to by union):
	// First, write the referent pointer for the container
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID

	// Now the actual SHARE_INFO_1_CONTAINER content:
	// - EntriesRead (4 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(len(shares)))

	// - Buffer pointer (referent ID for the array)
	binary.Write(&buf, binary.LittleEndian, uint32(0x00020004)) // Referent ID

	// Conformant array: max_count first
	binary.Write(&buf, binary.LittleEndian, uint32(len(shares)))

	// Array of SHARE_INFO_1 structures (embedded pointers written as referent IDs)
	refID := uint32(0x00020008)
	for _, share := range shares {
		// shi1_netname pointer (referent ID)
		binary.Write(&buf, binary.LittleEndian, refID)
		refID += 4
		// shi1_type
		binary.Write(&buf, binary.LittleEndian, share.stype)
		// shi1_remark pointer (referent ID)
		binary.Write(&buf, binary.LittleEndian, refID)
		refID += 4
	}

	// Now write the actual string data (deferred pointers)
	for _, share := range shares {
		writeNDRConformantVaryingString(&buf, share.name)
		writeNDRConformantVaryingString(&buf, share.remark)
	}

	// TotalEntries (out parameter)
	binary.Write(&buf, binary.LittleEndian, uint32(len(shares)))

	// ResumeHandle pointer (NULL - no resume handle returned)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Return value (WERROR - ERROR_SUCCESS = 0)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	stubResponse := buf.Bytes()

	if s.debug {
		fmt.Printf("[DEBUG] NetrShareEnum response stub: %d bytes\n", len(stubResponse))
	}

	return s.buildDCERPCResponse(callID, stubResponse)
}

func writeNDRConformantVaryingString(buf *bytes.Buffer, s string) {
	// NDR conformant varying string (UTF-16LE)
	// For an empty string, we still need to write the null terminator
	strLen := len(s) + 1 // Include null terminator

	// MaxCount (conformant part - number of elements including null)
	binary.Write(buf, binary.LittleEndian, uint32(strLen))
	// Offset (varying part - always 0 for simple strings)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// ActualCount (varying part - same as MaxCount for non-offset strings)
	binary.Write(buf, binary.LittleEndian, uint32(strLen))

	// String data (UTF-16LE)
	for _, c := range s {
		binary.Write(buf, binary.LittleEndian, uint16(c))
	}
	// Null terminator
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// Pad to 4-byte boundary (NDR alignment)
	written := strLen * 2 // Each UTF-16 char is 2 bytes
	if written%4 != 0 {
		padding := 4 - (written % 4)
		buf.Write(make([]byte, padding))
	}
}

func (s *Server) buildDCERPCResponse(callID uint32, stubData []byte) []byte {
	headerLen := 24
	resp := make([]byte, headerLen+len(stubData))

	// DCE/RPC header
	resp[0] = DCERPC_VERSION
	resp[1] = DCERPC_VERSION_MINOR
	resp[2] = DCERPC_RESPONSE
	resp[3] = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
	resp[4] = 0x10 // Little-endian
	resp[5] = 0x00
	resp[6] = 0x00
	resp[7] = 0x00
	binary.LittleEndian.PutUint16(resp[8:10], uint16(len(resp)))
	binary.LittleEndian.PutUint16(resp[10:12], 0) // Auth length
	binary.LittleEndian.PutUint32(resp[12:16], callID)

	// Response specific
	binary.Write(bytes.NewBuffer(resp[16:16]), binary.LittleEndian, uint32(len(stubData))) // Alloc hint
	binary.LittleEndian.PutUint32(resp[16:20], uint32(len(stubData)))
	binary.LittleEndian.PutUint16(resp[20:22], 0) // Context ID
	resp[22] = 0                                  // Cancel count
	resp[23] = 0                                  // Reserved

	copy(resp[24:], stubData)

	return resp
}

func (s *Server) buildDCERPCFault(callID uint32, status uint32) []byte {
	resp := make([]byte, 32)

	resp[0] = DCERPC_VERSION
	resp[1] = DCERPC_VERSION_MINOR
	resp[2] = 3 // DCERPC_FAULT
	resp[3] = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG
	resp[4] = 0x10
	binary.LittleEndian.PutUint16(resp[8:10], 32)
	binary.LittleEndian.PutUint32(resp[12:16], callID)
	binary.LittleEndian.PutUint32(resp[24:28], status)

	return resp
}

func (s *Server) buildWriteResponse(session *Session, messageID uint64, treeID uint32, count uint32) []byte {
	resp := make([]byte, 64+17)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_WRITE)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	binary.LittleEndian.PutUint16(resp[64:66], 17)
	binary.LittleEndian.PutUint32(resp[68:72], count)

	return resp
}

func (s *Server) handleQueryDirectory(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+33 {
		if s.debug {
			fmt.Printf("[DEBUG] QueryDirectory: packet too short (%d)\n", len(pkt))
		}
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	infoClass := pkt[64+2]
	fileID := pkt[72:88]
	fileIDStr := hex.EncodeToString(fileID)

	if s.debug {
		fmt.Printf("[DEBUG] QueryDirectory: FileID=%s, InfoClass=%d, OpenFiles=%d\n", fileIDStr, infoClass, len(session.openFiles))
		for k := range session.openFiles {
			fmt.Printf("[DEBUG]   OpenFile: %s\n", k)
		}
	}

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		if s.debug {
			fmt.Printf("[DEBUG] QueryDirectory: FileID not found\n")
		}
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}
	if !of.isDir {
		if s.debug {
			fmt.Printf("[DEBUG] QueryDirectory: Not a directory\n")
		}
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Check flags - bit 0 is SMB2_RESTART_SCANS
	flags := pkt[64+3]
	restartScan := (flags & 0x01) != 0

	// If already enumerated and not restarting, return NO_MORE_FILES
	if of.enumerated && !restartScan {
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_NO_MORE_FILES)
	}

	// Mark as enumerated
	of.enumerated = true

	// Read directory entries
	entries, err := os.ReadDir(of.realPath)
	if err != nil {
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
	}

	// Build directory listing
	var buf bytes.Buffer
	for i, entry := range entries {
		info, _ := entry.Info()
		if info == nil {
			continue
		}

		entryData := s.buildDirectoryEntry(entry.Name(), info, infoClass, i == len(entries)-1)
		buf.Write(entryData)
	}

	if buf.Len() == 0 {
		return s.buildErrorResponse(SMB2_QUERY_DIRECTORY, messageID, session.id, treeID, STATUS_NO_SUCH_FILE)
	}

	data := buf.Bytes()

	resp := make([]byte, 64+9+len(data))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_QUERY_DIRECTORY)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	binary.LittleEndian.PutUint16(resp[64:66], 9)
	binary.LittleEndian.PutUint16(resp[66:68], 72) // OutputBufferOffset
	binary.LittleEndian.PutUint32(resp[68:72], uint32(len(data)))
	copy(resp[72:], data)

	if s.debug {
		fmt.Printf("[DEBUG] QueryDirectory Response - TreeID at offset 36: %d\n", binary.LittleEndian.Uint32(resp[36:40]))
	}

	return resp
}

func (s *Server) buildDirectoryEntry(name string, info os.FileInfo, infoClass byte, isLast bool) []byte {
	nameBytes := utf16LEEncode(name)

	// Determine structure based on infoClass (MS-FSCC 2.4)
	// 1 = FileDirectoryInformation (64 bytes header)
	// 2 = FileFullDirectoryInformation (68 bytes header - adds EaSize)
	// 3 = FileBothDirectoryInformation (94 bytes header)
	// 37 = FileIdBothDirectoryInformation (104 bytes header)

	var headerSize int
	var eaSizeOffset int = -1 // Offset for EaSize field if present

	switch infoClass {
	case 1: // FileDirectoryInformation
		headerSize = 64 // NextEntry(4) + FileIndex(4) + times(32) + sizes(16) + attrs(4) + nameLen(4)
	case 2: // FileFullDirectoryInformation
		headerSize = 68 // Same as above + EaSize(4)
		eaSizeOffset = 64
	case 3: // FileBothDirectoryInformation
		headerSize = 94
		eaSizeOffset = 64
	case 37: // FileIdBothDirectoryInformation
		headerSize = 104
		eaSizeOffset = 64
	default:
		headerSize = 64 // Default to FileDirectoryInformation
	}

	entrySize := headerSize + len(nameBytes)
	// Align to 8 bytes
	if !isLast && entrySize%8 != 0 {
		entrySize += 8 - (entrySize % 8)
	}

	entry := make([]byte, entrySize)

	// NextEntryOffset
	if !isLast {
		binary.LittleEndian.PutUint32(entry[0:4], uint32(entrySize))
	}

	// FileIndex
	binary.LittleEndian.PutUint32(entry[4:8], 0)

	// Times
	now := timeToFiletime(info.ModTime())
	binary.LittleEndian.PutUint64(entry[8:16], now)  // CreationTime
	binary.LittleEndian.PutUint64(entry[16:24], now) // LastAccessTime
	binary.LittleEndian.PutUint64(entry[24:32], now) // LastWriteTime
	binary.LittleEndian.PutUint64(entry[32:40], now) // ChangeTime

	// EndOfFile
	binary.LittleEndian.PutUint64(entry[40:48], uint64(info.Size()))
	// AllocationSize
	binary.LittleEndian.PutUint64(entry[48:56], uint64(info.Size()))

	// FileAttributes
	var attrs uint32 = 0x80
	if info.IsDir() {
		attrs = 0x10
	}
	binary.LittleEndian.PutUint32(entry[56:60], attrs)

	// FileNameLength
	binary.LittleEndian.PutUint32(entry[60:64], uint32(len(nameBytes)))

	// EaSize (for InfoClass 2, 3, 37)
	if eaSizeOffset >= 0 {
		binary.LittleEndian.PutUint32(entry[eaSizeOffset:eaSizeOffset+4], 0)
	}

	// For FileBothDirectoryInformation: ShortNameLength at 68, Reserved at 69, ShortName at 70-94
	// For FileIdBothDirectoryInformation: Same as above plus FileId at 96-104

	// FileName
	copy(entry[headerSize:], nameBytes)

	return entry
}

func (s *Server) handleQueryInfo(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+41 {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	infoType := pkt[64+2]
	fileInfoClass := pkt[64+3]
	fileID := pkt[88:104]
	fileIDStr := hex.EncodeToString(fileID)

	if s.debug {
		fmt.Printf("[DEBUG] QUERY_INFO: infoType=%d, class=%d, fileID=%s\n", infoType, fileInfoClass, fileIDStr)
	}

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	info, err := os.Stat(of.realPath)
	if err != nil {
		return s.buildErrorResponse(SMB2_QUERY_INFO, messageID, session.id, treeID, STATUS_OBJECT_NAME_NOT_FOUND)
	}

	var data []byte

	if infoType == 0x01 { // SMB2_0_INFO_FILE
		switch fileInfoClass {
		case 0x04: // FileBasicInformation
			data = s.buildFileBasicInfo(info)
		case 0x05: // FileStandardInformation
			data = s.buildFileStandardInfo(info, of)
		case 0x06: // FileInternalInformation
			data = s.buildFileInternalInfo()
		case 0x07: // FileEaInformation
			data = make([]byte, 4) // EaSize = 0
		case 0x08: // FileAccessInformation
			data = make([]byte, 4)
			binary.LittleEndian.PutUint32(data[0:4], of.desiredAccess)
		case 0x09: // FileNameInformation
			data = s.buildFileNameInfo(of.path)
		case 0x0E: // FilePositionInformation
			data = make([]byte, 8) // CurrentByteOffset = 0
		case 0x0F: // FileModeInformation
			data = make([]byte, 4) // Mode = 0
		case 0x10: // FileAlignmentInformation
			data = make([]byte, 4) // AlignmentRequirement = 0
		case 0x12: // FileAllInformation
			data = s.buildFileAllInfo(info)
		case 0x15: // FileAttributeTagInformation
			data = s.buildFileAttributeTagInfo(info)
		case 0x16: // FileStreamInformation
			data = s.buildFileStreamInfo(info)
		case 0x22: // FileNetworkOpenInformation
			data = s.buildFileNetworkOpenInfo(info)
		default:
			if s.debug {
				fmt.Printf("[DEBUG] Unsupported QUERY_INFO file class: %d\n", fileInfoClass)
			}
			data = make([]byte, 8) // Minimal response
		}
	} else if infoType == 0x02 { // SMB2_0_INFO_FILESYSTEM
		switch fileInfoClass {
		case 0x01: // FileFsVolumeInformation
			data = s.buildFsVolumeInfo()
		case 0x03: // FileFsSizeInformation
			data = s.buildFsSizeInfo()
		case 0x05: // FileFsAttributeInformation
			data = s.buildFsAttributeInfo()
		case 0x06: // FileFsControlInformation
			data = make([]byte, 48) // Minimal response
		case 0x07: // FileFsFullSizeInformation
			data = s.buildFsFullSizeInfo()
		case 0x08: // FileFsObjectIdInformation
			data = make([]byte, 64) // ObjectId all zeros
		default:
			if s.debug {
				fmt.Printf("[DEBUG] Unsupported QUERY_INFO fs class: %d\n", fileInfoClass)
			}
			data = make([]byte, 8)
		}
	} else {
		data = make([]byte, 8)
	}

	resp := make([]byte, 64+9+len(data))
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_QUERY_INFO)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	binary.LittleEndian.PutUint16(resp[64:66], 9)
	binary.LittleEndian.PutUint16(resp[66:68], 72)
	binary.LittleEndian.PutUint32(resp[68:72], uint32(len(data)))
	copy(resp[72:], data)

	return resp
}

func (s *Server) buildFileBasicInfo(info os.FileInfo) []byte {
	data := make([]byte, 40)
	now := timeToFiletime(info.ModTime())

	binary.LittleEndian.PutUint64(data[0:8], now)   // CreationTime
	binary.LittleEndian.PutUint64(data[8:16], now)  // LastAccessTime
	binary.LittleEndian.PutUint64(data[16:24], now) // LastWriteTime
	binary.LittleEndian.PutUint64(data[24:32], now) // ChangeTime

	var attrs uint32 = 0x80 // FILE_ATTRIBUTE_NORMAL
	if info.IsDir() {
		attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
	}
	binary.LittleEndian.PutUint32(data[32:36], attrs)
	// Reserved: 4 bytes at 36

	return data
}

func (s *Server) buildFileStandardInfo(info os.FileInfo, of *OpenFile) []byte {
	data := make([]byte, 24)

	binary.LittleEndian.PutUint64(data[0:8], uint64(info.Size()))  // AllocationSize
	binary.LittleEndian.PutUint64(data[8:16], uint64(info.Size())) // EndOfFile
	binary.LittleEndian.PutUint32(data[16:20], 1)                  // NumberOfLinks

	if of.deletePending {
		data[20] = 1 // DeletePending
	}
	if info.IsDir() {
		data[21] = 1 // Directory
	}
	// Reserved: 2 bytes at 22

	return data
}

func (s *Server) buildFileInternalInfo() []byte {
	data := make([]byte, 8)
	// IndexNumber - unique file identifier, we'll use 0
	return data
}

func (s *Server) buildFileNameInfo(path string) []byte {
	nameBytes := utf16LEEncode(path)
	data := make([]byte, 4+len(nameBytes))

	binary.LittleEndian.PutUint32(data[0:4], uint32(len(nameBytes)))
	copy(data[4:], nameBytes)

	return data
}

func (s *Server) buildFileAttributeTagInfo(info os.FileInfo) []byte {
	data := make([]byte, 8)

	var attrs uint32 = 0x80
	if info.IsDir() {
		attrs = 0x10
	}
	binary.LittleEndian.PutUint32(data[0:4], attrs) // FileAttributes
	// ReparseTag: 4 bytes at 4 (0 = not a reparse point)

	return data
}

func (s *Server) buildFileStreamInfo(info os.FileInfo) []byte {
	if info.IsDir() {
		return make([]byte, 0) // Directories have no streams
	}

	// Single default data stream "::$DATA"
	streamName := "::$DATA"
	nameBytes := utf16LEEncode(streamName)

	data := make([]byte, 24+len(nameBytes))
	// NextEntryOffset: 0 (last entry)
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(nameBytes))) // StreamNameLength
	binary.LittleEndian.PutUint64(data[8:16], uint64(info.Size()))   // StreamSize
	binary.LittleEndian.PutUint64(data[16:24], uint64(info.Size()))  // StreamAllocationSize
	copy(data[24:], nameBytes)

	return data
}

func (s *Server) buildFileNetworkOpenInfo(info os.FileInfo) []byte {
	data := make([]byte, 56)
	now := timeToFiletime(info.ModTime())

	binary.LittleEndian.PutUint64(data[0:8], now)                   // CreationTime
	binary.LittleEndian.PutUint64(data[8:16], now)                  // LastAccessTime
	binary.LittleEndian.PutUint64(data[16:24], now)                 // LastWriteTime
	binary.LittleEndian.PutUint64(data[24:32], now)                 // ChangeTime
	binary.LittleEndian.PutUint64(data[32:40], uint64(info.Size())) // AllocationSize
	binary.LittleEndian.PutUint64(data[40:48], uint64(info.Size())) // EndOfFile

	var attrs uint32 = 0x80
	if info.IsDir() {
		attrs = 0x10
	}
	binary.LittleEndian.PutUint32(data[48:52], attrs) // FileAttributes
	// Reserved: 4 bytes at 52

	return data
}

func (s *Server) buildFsVolumeInfo() []byte {
	label := "SMBSHARE"
	labelBytes := utf16LEEncode(label)

	data := make([]byte, 18+len(labelBytes))
	now := timeToFiletime(time.Now())

	binary.LittleEndian.PutUint64(data[0:8], now)                       // VolumeCreationTime
	binary.LittleEndian.PutUint32(data[8:12], 0x12345678)               // VolumeSerialNumber
	binary.LittleEndian.PutUint32(data[12:16], uint32(len(labelBytes))) // VolumeLabelLength
	// SupportsObjects: 1 byte at 16 (0)
	// Reserved: 1 byte at 17
	copy(data[18:], labelBytes)

	return data
}

func (s *Server) buildFsSizeInfo() []byte {
	data := make([]byte, 24)

	// Report 100GB total, 50GB free
	totalUnits := uint64(100 * 1024 * 1024 * 1024 / 4096)
	freeUnits := uint64(50 * 1024 * 1024 * 1024 / 4096)

	binary.LittleEndian.PutUint64(data[0:8], totalUnits) // TotalAllocationUnits
	binary.LittleEndian.PutUint64(data[8:16], freeUnits) // AvailableAllocationUnits
	binary.LittleEndian.PutUint32(data[16:20], 1)        // SectorsPerAllocationUnit
	binary.LittleEndian.PutUint32(data[20:24], 4096)     // BytesPerSector

	return data
}

func (s *Server) buildFsAttributeInfo() []byte {
	fsName := "NTFS"
	fsNameBytes := utf16LEEncode(fsName)

	data := make([]byte, 12+len(fsNameBytes))

	// FileSystemAttributes
	attrs := uint32(0x0000002F) // Case-preserving, Unicode, etc.
	binary.LittleEndian.PutUint32(data[0:4], attrs)
	binary.LittleEndian.PutUint32(data[4:8], 255)                       // MaxFileNameLength
	binary.LittleEndian.PutUint32(data[8:12], uint32(len(fsNameBytes))) // FileSystemNameLength
	copy(data[12:], fsNameBytes)

	return data
}

func (s *Server) buildFsFullSizeInfo() []byte {
	data := make([]byte, 32)

	// Report 100GB total, 50GB free
	totalUnits := uint64(100 * 1024 * 1024 * 1024 / 4096)
	freeUnits := uint64(50 * 1024 * 1024 * 1024 / 4096)

	binary.LittleEndian.PutUint64(data[0:8], totalUnits)  // TotalAllocationUnits
	binary.LittleEndian.PutUint64(data[8:16], freeUnits)  // CallerAvailableAllocationUnits
	binary.LittleEndian.PutUint64(data[16:24], freeUnits) // ActualAvailableAllocationUnits
	binary.LittleEndian.PutUint32(data[24:28], 1)         // SectorsPerAllocationUnit
	binary.LittleEndian.PutUint32(data[28:32], 4096)      // BytesPerSector

	return data
}

func (s *Server) buildFileAllInfo(info os.FileInfo) []byte {
	data := make([]byte, 104)

	now := timeToFiletime(info.ModTime())

	// BasicInformation (40 bytes)
	binary.LittleEndian.PutUint64(data[0:8], now)
	binary.LittleEndian.PutUint64(data[8:16], now)
	binary.LittleEndian.PutUint64(data[16:24], now)
	binary.LittleEndian.PutUint64(data[24:32], now)
	var attrs uint32 = 0x80
	if info.IsDir() {
		attrs = 0x10
	}
	binary.LittleEndian.PutUint32(data[32:36], attrs)

	// StandardInformation (24 bytes at offset 40)
	binary.LittleEndian.PutUint64(data[40:48], uint64(info.Size()))
	binary.LittleEndian.PutUint64(data[48:56], uint64(info.Size()))
	binary.LittleEndian.PutUint32(data[56:60], 1)

	return data
}

func (s *Server) handleEcho(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	resp := make([]byte, 64+4)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_ECHO)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 4)

	return resp
}

// FSCTL codes
const (
	FSCTL_PIPE_TRANSCEIVE   = 0x0011C017
	FSCTL_DFS_GET_REFERRALS = 0x00060194
)

func (s *Server) handleIoctl(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+57 {
		return s.buildErrorResponse(SMB2_IOCTL, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	ctlCode := binary.LittleEndian.Uint32(pkt[68:72])
	fileID := pkt[72:88]
	fileIDStr := hex.EncodeToString(fileID)
	inputOffset := binary.LittleEndian.Uint32(pkt[88:92])
	inputCount := binary.LittleEndian.Uint32(pkt[92:96])

	if s.debug {
		fmt.Printf("[DEBUG] IOCTL: ctlCode=0x%08x, fileID=%s\n", ctlCode, fileIDStr)
	}

	switch ctlCode {
	case FSCTL_PIPE_TRANSCEIVE:
		of, ok := session.openFiles[fileIDStr]
		if !ok || !of.isPipe {
			return s.buildErrorResponse(SMB2_IOCTL, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
		}

		// Get input data
		if inputCount > 0 && int(inputOffset)+int(inputCount) <= len(pkt) {
			inputData := pkt[inputOffset : inputOffset+inputCount]

			// Process as DCE/RPC write
			s.handlePipeWriteData(of, inputData)
		}

		// Return pending response
		return s.buildIoctlResponse(session, of, messageID, treeID, ctlCode, fileID)

	case FSCTL_DFS_GET_REFERRALS:
		// DFS not supported
		return s.buildErrorResponse(SMB2_IOCTL, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)

	default:
		if s.debug {
			fmt.Printf("[DEBUG] Unsupported IOCTL: 0x%08x\n", ctlCode)
		}
		return s.buildErrorResponse(SMB2_IOCTL, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}
}

func (s *Server) handlePipeWriteData(of *OpenFile, data []byte) {
	if len(data) < 16 {
		return
	}

	// Parse DCE/RPC header
	packetType := data[2]
	callID := binary.LittleEndian.Uint32(data[12:16])

	switch packetType {
	case DCERPC_BIND:
		// Parse BIND and prepare BIND_ACK
		var contextID uint16
		if len(data) >= 30 {
			contextID = binary.LittleEndian.Uint16(data[28:30])
		}
		of.pipeData.callID = callID
		of.pipeData.contextID = contextID
		of.pipeData.bound = true
		of.pipeData.pendingResponse = s.buildDCERPCBindAck(callID, contextID)

	case DCERPC_REQUEST:
		if len(data) >= 24 {
			opnum := binary.LittleEndian.Uint16(data[22:24])
			switch of.pipeName {
			case "srvsvc":
				of.pipeData.pendingResponse = s.handleSRVSVCRequest(opnum, data[24:], callID)
			}
		}
	}
}

func (s *Server) buildIoctlResponse(session *Session, of *OpenFile, messageID uint64, treeID uint32, ctlCode uint32, fileID []byte) []byte {
	var outputData []byte
	if of.pipeData != nil && len(of.pipeData.pendingResponse) > 0 {
		outputData = of.pipeData.pendingResponse
		of.pipeData.pendingResponse = nil
	}

	if s.debug {
		fmt.Printf("[DEBUG] IOCTL Response: %d bytes\n", len(outputData))
	}

	respLen := 64 + 49 + len(outputData)
	resp := make([]byte, respLen)

	// SMB2 Header
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_IOCTL)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)

	// IOCTL Response
	binary.LittleEndian.PutUint16(resp[64:66], 49) // StructureSize
	binary.LittleEndian.PutUint16(resp[66:68], 0)  // Reserved
	binary.LittleEndian.PutUint32(resp[68:72], ctlCode)
	copy(resp[72:88], fileID)
	// InputOffset (4 bytes at 88)
	// InputCount (4 bytes at 92) - 0
	// OutputOffset (4 bytes at 96)
	binary.LittleEndian.PutUint32(resp[96:100], 112) // Offset from start of SMB2 header
	// OutputCount (4 bytes at 100)
	binary.LittleEndian.PutUint32(resp[100:104], uint32(len(outputData)))
	// Flags (4 bytes at 104)
	// Reserved2 (4 bytes at 108)

	if len(outputData) > 0 {
		copy(resp[112:], outputData)
	}

	return resp
}

func (s *Server) handleLogoff(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	resp := make([]byte, 64+4)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_LOGOFF)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 4)

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
	binary.LittleEndian.PutUint64(resp[40:48], sessionID)
	binary.LittleEndian.PutUint16(resp[64:66], 9) // Error response structure size

	return resp
}

// handleSetInfo handles SMB2_SET_INFO requests
func (s *Server) handleSetInfo(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+33 {
		return s.buildErrorResponse(SMB2_SET_INFO, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	infoType := pkt[64+2]
	fileInfoClass := pkt[64+3]
	bufferLength := binary.LittleEndian.Uint32(pkt[68:72])
	bufferOffset := binary.LittleEndian.Uint16(pkt[72:74])
	fileID := pkt[88:104]
	fileIDStr := hex.EncodeToString(fileID)

	if s.debug {
		fmt.Printf("[DEBUG] SET_INFO: infoType=%d, class=%d, bufLen=%d, fileID=%s\n",
			infoType, fileInfoClass, bufferLength, fileIDStr)
	}

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_SET_INFO, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Named pipes don't support SET_INFO
	if of.isPipe {
		return s.buildErrorResponse(SMB2_SET_INFO, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}

	if infoType != 0x01 { // Only FILE_INFO supported
		return s.buildErrorResponse(SMB2_SET_INFO, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}

	var buffer []byte
	if bufferLength > 0 && int(bufferOffset)+int(bufferLength) <= len(pkt) {
		buffer = pkt[bufferOffset : bufferOffset+uint16(bufferLength)]
	}

	var err error
	switch fileInfoClass {
	case FileBasicInformation: // 0x04 - Set timestamps and attributes
		err = s.setFileBasicInfo(of, buffer)
	case FileRenameInformation: // 0x0A - Rename file
		err = s.setFileRenameInfo(session, of, buffer, treeID)
	case FileDispositionInformation: // 0x0D - Delete file
		err = s.setFileDispositionInfo(of, buffer)
	case FileAllocationInformation: // 0x13 - Set allocation size
		err = s.setFileAllocationInfo(of, buffer)
	case FileEndOfFileInformation: // 0x14 - Truncate file
		err = s.setFileEndOfFileInfo(of, buffer)
	default:
		if s.debug {
			fmt.Printf("[DEBUG] Unsupported SET_INFO class: %d\n", fileInfoClass)
		}
		return s.buildErrorResponse(SMB2_SET_INFO, messageID, session.id, treeID, STATUS_NOT_SUPPORTED)
	}

	if err != nil {
		if s.debug {
			fmt.Printf("[DEBUG] SET_INFO error: %v\n", err)
		}
		return s.buildErrorResponse(SMB2_SET_INFO, messageID, session.id, treeID, STATUS_ACCESS_DENIED)
	}

	// Build success response
	resp := make([]byte, 64+2)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_SET_INFO)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 2) // StructureSize

	return resp
}

func (s *Server) setFileBasicInfo(of *OpenFile, buffer []byte) error {
	if len(buffer) < 40 {
		return fmt.Errorf("buffer too small")
	}

	// FileBasicInformation:
	// CreationTime: 8 bytes
	// LastAccessTime: 8 bytes
	// LastWriteTime: 8 bytes
	// ChangeTime: 8 bytes
	// FileAttributes: 4 bytes

	// For now, we only update modification time if non-zero
	lastWriteTime := binary.LittleEndian.Uint64(buffer[16:24])
	if lastWriteTime != 0 && lastWriteTime != 0xFFFFFFFFFFFFFFFF {
		// Convert FILETIME to Unix time
		t := filetimeToTime(lastWriteTime)
		if err := os.Chtimes(of.realPath, t, t); err != nil {
			return err
		}
	}

	if s.debug {
		fmt.Printf("[DEBUG] SET_INFO: FileBasicInformation updated for %s\n", of.realPath)
	}
	return nil
}

func (s *Server) setFileRenameInfo(session *Session, of *OpenFile, buffer []byte, treeID uint32) error {
	if len(buffer) < 20 {
		return fmt.Errorf("buffer too small")
	}

	// FileRenameInformation:
	// ReplaceIfExists: 1 byte
	// Reserved: 7 bytes
	// RootDirectory: 8 bytes
	// FileNameLength: 4 bytes
	// FileName: variable

	replaceIfExists := buffer[0] != 0
	fileNameLen := binary.LittleEndian.Uint32(buffer[16:20])

	if len(buffer) < 20+int(fileNameLen) {
		return fmt.Errorf("buffer too small for filename")
	}

	newName := utf16LEDecode(buffer[20 : 20+fileNameLen])

	// Get the tree connect for the share path
	tc := session.treeConnects[treeID]
	if tc == nil {
		return fmt.Errorf("invalid tree ID")
	}

	// Build new path - newName might be relative or absolute
	var newPath string
	if strings.HasPrefix(newName, "\\") {
		// Absolute path within share
		newPath = filepath.Join(tc.sharePath, strings.TrimPrefix(newName, "\\"))
	} else {
		// Relative to current directory
		newPath = filepath.Join(filepath.Dir(of.realPath), newName)
	}

	// Check if target exists
	if _, err := os.Stat(newPath); err == nil {
		if !replaceIfExists {
			return fmt.Errorf("target exists and ReplaceIfExists is false")
		}
		// Remove existing file
		os.Remove(newPath)
	}

	if err := os.Rename(of.realPath, newPath); err != nil {
		return err
	}

	// Update the open file's path
	of.realPath = newPath
	of.path = newName

	logOutput("[+] Renamed: %s -> %s\n", of.realPath, newPath)
	return nil
}

func (s *Server) setFileDispositionInfo(of *OpenFile, buffer []byte) error {
	if len(buffer) < 1 {
		return fmt.Errorf("buffer too small")
	}

	// FileDispositionInformation:
	// DeletePending: 1 byte (0 = don't delete, 1 = delete on close)

	deletePending := buffer[0] != 0
	of.deletePending = deletePending

	if s.debug {
		fmt.Printf("[DEBUG] SET_INFO: FileDispositionInformation deletePending=%v for %s\n",
			deletePending, of.realPath)
	}
	return nil
}

func (s *Server) setFileAllocationInfo(of *OpenFile, buffer []byte) error {
	if len(buffer) < 8 {
		return fmt.Errorf("buffer too small")
	}

	// FileAllocationInformation:
	// AllocationSize: 8 bytes

	allocationSize := binary.LittleEndian.Uint64(buffer[0:8])

	// Open file for truncation
	if of.file == nil {
		f, err := os.OpenFile(of.realPath, os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		of.file = f
	}

	if err := of.file.Truncate(int64(allocationSize)); err != nil {
		return err
	}

	if s.debug {
		fmt.Printf("[DEBUG] SET_INFO: FileAllocationInformation size=%d for %s\n",
			allocationSize, of.realPath)
	}
	return nil
}

func (s *Server) setFileEndOfFileInfo(of *OpenFile, buffer []byte) error {
	if len(buffer) < 8 {
		return fmt.Errorf("buffer too small")
	}

	// FileEndOfFileInformation:
	// EndOfFile: 8 bytes

	endOfFile := binary.LittleEndian.Uint64(buffer[0:8])

	// Open file for truncation
	if of.file == nil {
		f, err := os.OpenFile(of.realPath, os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		of.file = f
	}

	if err := of.file.Truncate(int64(endOfFile)); err != nil {
		return err
	}

	if s.debug {
		fmt.Printf("[DEBUG] SET_INFO: FileEndOfFileInformation size=%d for %s\n",
			endOfFile, of.realPath)
	}
	return nil
}

// handleFlush handles SMB2_FLUSH requests
func (s *Server) handleFlush(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+24 {
		return s.buildErrorResponse(SMB2_FLUSH, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	fileID := pkt[72:88]
	fileIDStr := hex.EncodeToString(fileID)

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_FLUSH, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// Flush the file if it's open
	if of.file != nil {
		if err := of.file.Sync(); err != nil {
			if s.debug {
				fmt.Printf("[DEBUG] Flush error: %v\n", err)
			}
		}
	}

	if s.debug {
		fmt.Printf("[DEBUG] FLUSH: fileID=%s\n", fileIDStr)
	}

	// Build response
	resp := make([]byte, 64+4)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_FLUSH)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 4) // StructureSize
	// Reserved: 2 bytes at offset 66

	return resp
}

// handleLock handles SMB2_LOCK requests
func (s *Server) handleLock(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+48 {
		return s.buildErrorResponse(SMB2_LOCK, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	lockCount := binary.LittleEndian.Uint16(pkt[66:68])
	// lockSequence := binary.LittleEndian.Uint32(pkt[68:72])
	fileID := pkt[72:88]
	fileIDStr := hex.EncodeToString(fileID)

	of, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_LOCK, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	if s.debug {
		fmt.Printf("[DEBUG] LOCK: fileID=%s, lockCount=%d\n", fileIDStr, lockCount)
	}

	// Process each lock element (24 bytes each, starting at offset 88)
	for i := uint16(0); i < lockCount; i++ {
		offset := 88 + int(i)*24
		if offset+24 > len(pkt) {
			break
		}

		lockOffset := binary.LittleEndian.Uint64(pkt[offset : offset+8])
		lockLength := binary.LittleEndian.Uint64(pkt[offset+8 : offset+16])
		lockFlags := binary.LittleEndian.Uint32(pkt[offset+16 : offset+20])

		isUnlock := (lockFlags & 0x00000001) != 0 // SMB2_LOCKFLAG_UNLOCK

		if isUnlock {
			// Remove lock
			of.locks = removeLock(of.locks, lockOffset, lockLength)
			if s.debug {
				fmt.Printf("[DEBUG] UNLOCK: offset=%d, length=%d\n", lockOffset, lockLength)
			}
		} else {
			// Add lock
			of.locks = append(of.locks, FileLock{offset: lockOffset, length: lockLength})
			if s.debug {
				fmt.Printf("[DEBUG] LOCK: offset=%d, length=%d, flags=0x%x\n", lockOffset, lockLength, lockFlags)
			}
		}
	}

	// Build response
	resp := make([]byte, 64+4)
	copy(resp[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint32(resp[8:12], STATUS_SUCCESS)
	binary.LittleEndian.PutUint16(resp[12:14], SMB2_LOCK)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint32(resp[36:40], treeID)
	binary.LittleEndian.PutUint64(resp[40:48], session.id)
	binary.LittleEndian.PutUint16(resp[64:66], 4) // StructureSize
	// Reserved: 2 bytes at offset 66

	return resp
}

func removeLock(locks []FileLock, offset, length uint64) []FileLock {
	for i, lock := range locks {
		if lock.offset == offset && lock.length == length {
			return append(locks[:i], locks[i+1:]...)
		}
	}
	return locks
}

// handleCancel handles SMB2_CANCEL requests
func (s *Server) handleCancel(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	// Cancel doesn't send a response - it just cancels a pending operation
	// For now, we don't have async operations, so just log it
	if s.debug {
		fmt.Printf("[DEBUG] CANCEL: messageID=%d\n", messageID)
	}
	// No response for CANCEL
	return nil
}

// handleChangeNotify handles SMB2_CHANGE_NOTIFY requests
func (s *Server) handleChangeNotify(session *Session, pkt []byte, messageID uint64, treeID uint32) []byte {
	if len(pkt) < 64+32 {
		return s.buildErrorResponse(SMB2_CHANGE_NOTIFY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	// flags := binary.LittleEndian.Uint16(pkt[64:66])
	// outputBufferLength := binary.LittleEndian.Uint32(pkt[68:72])
	fileID := pkt[72:88]
	// completionFilter := binary.LittleEndian.Uint32(pkt[88:92])
	fileIDStr := hex.EncodeToString(fileID)

	_, ok := session.openFiles[fileIDStr]
	if !ok {
		return s.buildErrorResponse(SMB2_CHANGE_NOTIFY, messageID, session.id, treeID, STATUS_INVALID_PARAMETER)
	}

	if s.debug {
		fmt.Printf("[DEBUG] CHANGE_NOTIFY: fileID=%s\n", fileIDStr)
	}

	// For now, return STATUS_NOTIFY_ENUM_DIR which tells the client
	// to re-enumerate the directory rather than waiting for notifications
	// This is a valid response that avoids implementing async notifications
	return s.buildErrorResponse(SMB2_CHANGE_NOTIFY, messageID, session.id, treeID, STATUS_NOTIFY_ENUM_DIR)
}

func filetimeToTime(ft uint64) time.Time {
	// Convert Windows FILETIME to Unix time
	const ticksPerSecond = 10000000
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	unixNano := (int64(ft) - epochDiff) * 100
	return time.Unix(0, unixNano)
}

// Helper functions

func utf16LEEncode(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	return result
}

func utf16LEDecode(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		runes[i/2] = rune(binary.LittleEndian.Uint16(b[i:]))
	}
	return strings.TrimRight(string(runes), "\x00")
}

func timeToFiletime(t time.Time) uint64 {
	// Windows FILETIME: 100-nanosecond intervals since January 1, 1601
	const ticksPerSecond = 10000000
	const epochDiff = 116444736000000000 // Difference between 1601 and 1970 in 100ns ticks
	return uint64(t.Unix()*ticksPerSecond + epochDiff)
}

// computeNTHash computes the NT hash of a password
func computeNTHash(password string) []byte {
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	passwordUTF16, _ := encoder.Bytes([]byte(password))
	hash := md4.New()
	hash.Write(passwordUTF16)
	return hash.Sum(nil)
}
