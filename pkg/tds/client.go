package tds

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/kerberos"
	"gopacket/pkg/ntlm"
	"gopacket/pkg/transport"
)

// Client represents a TDS/MSSQL client
type Client struct {
	conn       net.Conn
	tlsConn    *tls.Conn
	packetSize int
	remoteName string
	port       int

	// TLS state
	useTLS     bool
	tlsUnique  []byte
	encryptOff bool // server said ENCRYPT_OFF (TLS only for LOGIN7)

	// Session state
	currentDB string
	columns   []ColumnInfo

	// Authentication options
	domain   string
	username string

	// Relay raw packet capture (for SOCKS plugin replay)
	RelayRawChallenge  []byte // Full raw TDS SSPI challenge response
	RelayRawAuthAnswer []byte // Full raw TDS LOGIN_ACK response
}

// NewClient creates a new TDS client
func NewClient(address string, port int, remoteName string) *Client {
	if remoteName == "" {
		remoteName = address
	}
	return &Client{
		packetSize: 32763,
		remoteName: remoteName,
		port:       port,
	}
}

// Connect establishes a TCP connection to the SQL server
func (c *Client) Connect(address string) error {
	conn, err := transport.Dial("tcp", fmt.Sprintf("%s:%d", address, c.port))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	c.conn = conn
	return nil
}

// Close closes the connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// sendTDS sends a TDS packet
func (c *Client) sendTDS(packetType uint8, data []byte) error {
	packetID := uint8(1)

	// Send in chunks if needed
	for len(data) > c.packetSize-8 {
		pkt := &TDSPacket{
			Type:     packetType,
			Status:   TDSStatusNormal,
			PacketID: packetID,
			Data:     data[:c.packetSize-8],
		}
		if err := c.socketSend(pkt.Marshal()); err != nil {
			return err
		}
		data = data[c.packetSize-8:]
		packetID++
	}

	// Send final packet
	pkt := &TDSPacket{
		Type:     packetType,
		Status:   TDSStatusEOM,
		PacketID: packetID,
		Data:     data,
	}
	return c.socketSend(pkt.Marshal())
}

// recvTDS receives a complete TDS response
func (c *Client) recvTDS() (*TDSPacket, error) {
	// Read header
	header := make([]byte, 8)
	if _, err := c.socketRecvFull(header); err != nil {
		return nil, err
	}

	pkt := &TDSPacket{}
	pkt.Type = header[0]
	pkt.Status = header[1]
	pkt.Length = binary.BigEndian.Uint16(header[2:4])
	pkt.SPID = binary.BigEndian.Uint16(header[4:6])
	pkt.PacketID = header[6]
	pkt.Window = header[7]

	// Read data
	if pkt.Length > 8 {
		pkt.Data = make([]byte, pkt.Length-8)
		if _, err := c.socketRecvFull(pkt.Data); err != nil {
			return nil, err
		}
	}

	// Continue reading if not EOM
	for pkt.Status&TDSStatusEOM == 0 {
		if _, err := c.socketRecvFull(header); err != nil {
			return nil, err
		}

		tmpLength := binary.BigEndian.Uint16(header[2:4])
		tmpStatus := header[1]

		if tmpLength > 8 {
			tmpData := make([]byte, tmpLength-8)
			if _, err := c.socketRecvFull(tmpData); err != nil {
				return nil, err
			}
			pkt.Data = append(pkt.Data, tmpData...)
		}

		pkt.Status = tmpStatus
		pkt.Length += tmpLength - 8
	}

	return pkt, nil
}

// socketSend sends data over the socket (plain or TLS)
func (c *Client) socketSend(data []byte) error {
	if c.tlsConn != nil {
		_, err := c.tlsConn.Write(data)
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

// socketRecvFull reads exactly len(buf) bytes
func (c *Client) socketRecvFull(buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		var n int
		var err error
		if c.tlsConn != nil {
			n, err = c.tlsConn.Read(buf[total:])
		} else {
			n, err = c.conn.Read(buf[total:])
		}
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// preLogin performs the TDS PRELOGIN handshake
func (c *Client) preLogin() (*PreLoginPacket, error) {
	prelogin := &PreLoginPacket{
		Version:    []byte{0x08, 0x00, 0x01, 0x55, 0x00, 0x00},
		Encryption: TDSEncryptOff,
		ThreadID:   uint32(rand.Intn(65535)),
		Instance:   "MSSQLServer",
	}

	if err := c.sendTDS(TDSPreLogin, prelogin.Marshal()); err != nil {
		return nil, err
	}

	resp, err := c.recvTDS()
	if err != nil {
		return nil, err
	}

	return ParsePreLoginResponse(resp.Data)
}

// setupTLS sets up TLS encryption for the connection
func (c *Client) setupTLS() error {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	// Wrap the existing connection with TLS
	c.tlsConn = tls.Client(c.conn, config)
	if err := c.tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Get tls-unique for channel binding
	state := c.tlsConn.ConnectionState()
	c.tlsUnique = state.TLSUnique
	c.useTLS = true

	return nil
}

// setupTLSInband sets up TLS using TDS prelogin encapsulation
func (c *Client) setupTLSInband() error {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	}

	// Create a wrapper that encapsulates TLS in TDS packets during handshake
	wrapper := &tdsTransport{
		conn:   c.conn,
		client: c,
	}

	c.tlsConn = tls.Client(wrapper, config)
	if err := c.tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Switch to passthrough mode — after handshake, TLS records go directly
	// to the socket without TDS PRELOGIN wrapping. TDS framing happens
	// inside the TLS tunnel via sendTDS/recvTDS.
	wrapper.passthrough = true

	// TLS limits data fragments to 16KB
	c.packetSize = 16*1024 - 1

	state := c.tlsConn.ConnectionState()
	c.tlsUnique = state.TLSUnique
	c.useTLS = true

	return nil
}

// tdsTransport wraps TLS handshake in TDS packets.
// During handshake, Read/Write wrap TLS records in TDS PRELOGIN packets.
// After handshake (passthrough=true), Read/Write go directly to the socket.
type tdsTransport struct {
	conn        net.Conn
	client      *Client
	buf         []byte
	passthrough bool // set after TLS handshake completes
}

func (t *tdsTransport) Read(p []byte) (int, error) {
	// After handshake, read directly from socket
	if t.passthrough {
		return t.conn.Read(p)
	}

	// If we have buffered data, return it
	if len(t.buf) > 0 {
		n := copy(p, t.buf)
		t.buf = t.buf[n:]
		return n, nil
	}

	// Read TDS packet (handshake mode)
	header := make([]byte, 8)
	total := 0
	for total < 8 {
		n, err := t.conn.Read(header[total:])
		if err != nil {
			return 0, err
		}
		total += n
	}

	length := binary.BigEndian.Uint16(header[2:4])
	if length <= 8 {
		return 0, nil
	}

	data := make([]byte, length-8)
	total = 0
	for total < len(data) {
		n, err := t.conn.Read(data[total:])
		if err != nil {
			return 0, err
		}
		total += n
	}

	n := copy(p, data)
	if n < len(data) {
		t.buf = data[n:]
	}
	return n, nil
}

func (t *tdsTransport) Write(p []byte) (int, error) {
	// After handshake, write directly to socket
	if t.passthrough {
		return t.conn.Write(p)
	}

	// Wrap in TDS PRELOGIN packet (handshake mode)
	pkt := &TDSPacket{
		Type:   TDSPreLogin,
		Status: TDSStatusEOM,
		Data:   p,
	}
	_, err := t.conn.Write(pkt.Marshal())
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *tdsTransport) Close() error {
	return t.conn.Close()
}

func (t *tdsTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *tdsTransport) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

func (t *tdsTransport) SetDeadline(time time.Time) error {
	return t.conn.SetDeadline(time)
}

func (t *tdsTransport) SetReadDeadline(time time.Time) error {
	return t.conn.SetReadDeadline(time)
}

func (t *tdsTransport) SetWriteDeadline(time time.Time) error {
	return t.conn.SetWriteDeadline(time)
}

// generateCBT generates Channel Binding Token from tls-unique
func (c *Client) generateCBT() []byte {
	if len(c.tlsUnique) == 0 {
		return nil
	}

	// gss_channel_bindings_struct
	appData := append([]byte("tls-unique:"), c.tlsUnique...)
	appDataLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(appDataLen, uint32(len(appData)))

	channelBinding := make([]byte, 0, 32+len(appData))
	channelBinding = append(channelBinding, make([]byte, 8)...) // initiator address
	channelBinding = append(channelBinding, make([]byte, 8)...) // acceptor address
	channelBinding = append(channelBinding, appDataLen...)
	channelBinding = append(channelBinding, appData...)

	hash := md5.Sum(channelBinding)
	return hash[:]
}

// Login authenticates with SQL Server using SQL or Windows authentication
func (c *Client) Login(database, username, password, domain string, hashes string, windowsAuth bool) error {
	c.domain = domain
	c.username = username

	// Prelogin
	resp, err := c.preLogin()
	if err != nil {
		return err
	}

	// Setup TLS if required (On=1, Req=3 need full TLS; Off=0 needs TLS for login only)
	if resp.Encryption == TDSEncryptOn || resp.Encryption == TDSEncryptReq || resp.Encryption == TDSEncryptOff {
		if err := c.setupTLSInband(); err != nil {
			return err
		}
	}

	// Build login packet
	login := &LoginPacket{
		TDSVersion:    0x71000001, // TDS 7.1
		PacketSize:    uint32(c.packetSize),
		ClientProgVer: 0x00000007,
		ClientPID:     uint32(rand.Intn(1024)),
		OptionFlags1:  0xe0,
		OptionFlags2:  TDSInitLangFatal | TDSODBCOn,
		HostName:      randomString(8),
		AppName:       randomString(8),
		ServerName:    c.remoteName,
		CltIntName:    randomString(8),
	}

	if database != "" {
		login.Database = database
	}

	if windowsAuth {
		// NTLM authentication
		login.OptionFlags2 |= TDSIntegratedSecurityOn

		// Parse hashes if provided
		var lmHash, ntHash []byte
		if hashes != "" {
			parts := strings.Split(hashes, ":")
			if len(parts) == 2 {
				lmHash = decodeHex(parts[0])
				ntHash = decodeHex(parts[1])
			}
		}

		// Create NTLM negotiate message
		negotiate := ntlm.NewNegotiateMessage(domain, "")
		login.SSPI = negotiate.Marshal()

		// Send login
		if err := c.sendTDS(TDSLogin7, login.Marshal()); err != nil {
			return err
		}

		// Per MS-TDS spec, only the LOGIN7 packet is encrypted when encryption
		// is off. All subsequent traffic (including NTLM challenge) is plaintext.
		if resp.Encryption == TDSEncryptOff {
			c.tlsConn = nil
		}

		// Receive NTLM challenge
		tdsResp, err := c.recvTDS()
		if err != nil {
			return err
		}

		// Parse SSPI challenge
		if len(tdsResp.Data) < 4 {
			return fmt.Errorf("invalid NTLM challenge response")
		}
		challenge := tdsResp.Data[3:] // Skip token header

		// Generate NTLM authenticate message
		cbt := c.generateCBT()
		auth, err := ntlm.CreateAuthenticateMessage(
			challenge, username, password, domain,
			lmHash, ntHash, cbt,
		)
		if err != nil {
			return err
		}

		// Send authenticate (plaintext when encryption is off)
		if err := c.sendTDS(TDSSSPI, auth); err != nil {
			return err
		}

		// Receive final response
		tdsResp, err = c.recvTDS()
		if err != nil {
			return err
		}

		// Check for login success
		return c.checkLoginResponse(tdsResp.Data)

	} else {
		// SQL Server authentication
		login.UserName = username
		login.Password = password

		// Send login
		if err := c.sendTDS(TDSLogin7, login.Marshal()); err != nil {
			return err
		}

		// Per MS-TDS spec, only the LOGIN7 packet is encrypted when encryption
		// is off. The server sends the response in plaintext.
		if resp.Encryption == TDSEncryptOff {
			c.tlsConn = nil
		}

		tdsResp, err := c.recvTDS()
		if err != nil {
			return err
		}

		return c.checkLoginResponse(tdsResp.Data)
	}
}

// KerberosLogin authenticates with Kerberos
func (c *Client) KerberosLogin(database, username, password, domain string, hashes, aesKey, kdcHost string) error {
	c.domain = domain
	c.username = username

	// Prelogin
	resp, err := c.preLogin()
	if err != nil {
		return err
	}

	// Setup TLS if required
	if resp.Encryption == TDSEncryptOn || resp.Encryption == TDSEncryptReq || resp.Encryption == TDSEncryptOff {
		if err := c.setupTLSInband(); err != nil {
			return err
		}
	}

	// Get Kerberos ticket
	spn := fmt.Sprintf("MSSQLSvc/%s:%d", c.remoteName, c.port)
	apReq, err := kerberos.GetAPReq(spn, username, password, domain, hashes, aesKey, kdcHost, c.generateCBT())
	if err != nil {
		return fmt.Errorf("Kerberos authentication failed: %v", err)
	}

	// Build login packet
	login := &LoginPacket{
		TDSVersion:    0x71000001,
		PacketSize:    uint32(c.packetSize),
		ClientProgVer: 0x00000007,
		ClientPID:     uint32(rand.Intn(1024)),
		OptionFlags1:  0xe0,
		OptionFlags2:  TDSInitLangFatal | TDSODBCOn | TDSIntegratedSecurityOn,
		HostName:      randomString(8),
		AppName:       randomString(8),
		ServerName:    c.remoteName,
		CltIntName:    randomString(8),
		SSPI:          apReq,
	}

	if database != "" {
		login.Database = database
	}

	// Send login
	if err := c.sendTDS(TDSLogin7, login.Marshal()); err != nil {
		return err
	}

	// Per MS-TDS spec, only the LOGIN7 packet is encrypted when encryption
	// is off. The server sends the response in plaintext.
	if resp.Encryption == TDSEncryptOff {
		c.tlsConn = nil
	}

	tdsResp, err := c.recvTDS()
	if err != nil {
		return err
	}

	return c.checkLoginResponse(tdsResp.Data)
}

// checkLoginResponse checks if login was successful
func (c *Client) checkLoginResponse(data []byte) error {
	tokens, columns, err := ParseTokens(data, nil)
	if err != nil {
		// Ignore parsing errors, check for login ack
	}
	c.columns = columns

	for _, token := range tokens {
		switch t := token.(type) {
		case *LoginAckToken:
			return nil // Login successful
		case *ErrorToken:
			return fmt.Errorf("SQL error %d: %s", t.Number, t.MsgText)
		case *EnvChangeToken:
			if t.ChangeType == TDSEnvChangeDatabase {
				c.currentDB = t.NewValue
			} else if t.ChangeType == TDSEnvChangePacketSize {
				// Update packet size if changed
			}
		}
	}

	return fmt.Errorf("login failed: no login acknowledgment received")
}

// SQLQuery executes a SQL query and returns results
func (c *Client) SQLQuery(query string) ([]map[string]interface{}, error) {
	c.columns = nil

	// Send query
	queryData := encodeUTF16LE(query + "\r\n")
	if err := c.sendTDS(TDSSQLBatch, queryData); err != nil {
		return nil, err
	}

	// Receive response
	resp, err := c.recvTDS()
	if err != nil {
		return nil, err
	}

	// Parse tokens
	tokens, columns, err := ParseTokens(resp.Data, c.columns)
	if err != nil {
		// Continue even with parsing errors to get partial results
	}
	c.columns = columns

	// Build result rows
	var rows []map[string]interface{}
	var lastError error

	for _, token := range tokens {
		switch t := token.(type) {
		case *ErrorToken:
			lastError = fmt.Errorf("SQL error %d: %s", t.Number, t.MsgText)
		case *RowToken:
			if len(c.columns) > 0 {
				row := make(map[string]interface{})
				for i, val := range t.Values {
					if i < len(c.columns) {
						row[c.columns[i].Name] = val
					}
				}
				rows = append(rows, row)
			}
		case *EnvChangeToken:
			if t.ChangeType == TDSEnvChangeDatabase {
				c.currentDB = t.NewValue
			}
		}
	}

	if lastError != nil && len(rows) == 0 {
		return nil, lastError
	}

	return rows, nil
}

// GetColumns returns the current column metadata
func (c *Client) GetColumns() []ColumnInfo {
	return c.columns
}

// CurrentDB returns the current database name
func (c *Client) CurrentDB() string {
	return c.currentDB
}

// --- Relay support methods ---
// These methods split the NTLM auth flow into relay-compatible steps.

// RelayInit performs the PRELOGIN handshake and sets up TLS, preparing
// the connection for NTLM relay. Call this after Connect().
func (c *Client) RelayInit() error {
	resp, err := c.preLogin()
	if err != nil {
		return fmt.Errorf("prelogin failed: %v", err)
	}

	if build.Debug {
		log.Printf("[D] MSSQL relay: prelogin encryption=%d", resp.Encryption)
	}

	// Setup TLS if required (matches Login() flow)
	if resp.Encryption == TDSEncryptOn || resp.Encryption == TDSEncryptReq || resp.Encryption == TDSEncryptOff {
		if err := c.setupTLSInband(); err != nil {
			return fmt.Errorf("TLS setup failed (encryption=%d): %v", resp.Encryption, err)
		}
	}

	// Track encryption mode for RelaySendNegotiate
	if resp.Encryption == TDSEncryptOff {
		c.encryptOff = true
	}

	return nil
}

// RelaySendNegotiate builds a LOGIN7 packet with the given NTLM Type1 as SSPI,
// sends it, and returns the NTLM Type2 challenge from the server's SSPI response.
func (c *Client) RelaySendNegotiate(ntlmType1 []byte) ([]byte, error) {
	login := &LoginPacket{
		TDSVersion:    0x71000001,
		PacketSize:    uint32(c.packetSize),
		ClientProgVer: 0x00000007,
		ClientPID:     uint32(rand.Intn(1024)),
		OptionFlags1:  0xe0,
		OptionFlags2:  TDSInitLangFatal | TDSODBCOn | TDSIntegratedSecurityOn,
		HostName:      randomString(8),
		AppName:       randomString(8),
		ServerName:    c.remoteName,
		CltIntName:    randomString(8),
		SSPI:          ntlmType1,
	}

	if err := c.sendTDS(TDSLogin7, login.Marshal()); err != nil {
		return nil, err
	}

	// Per MS-TDS spec and Impacket: when encryption is ENCRYPT_OFF,
	// only the LOGIN7 packet itself is encrypted. The server's response
	// (SSPI challenge) is sent as plaintext TDS. Disable TLS before reading.
	if c.encryptOff {
		c.tlsConn = nil
	}

	resp, err := c.recvTDS()
	if err != nil {
		return nil, err
	}

	// Store the raw TDS response for SOCKS plugin replay
	c.RelayRawChallenge = resp.Marshal()

	// The SSPI token starts at offset 3 (token type byte + 2 length bytes)
	if len(resp.Data) < 4 {
		return nil, fmt.Errorf("invalid SSPI challenge response: %d bytes", len(resp.Data))
	}

	// Verify this is an SSPI token (0xED)
	if resp.Data[0] == TDSSSPIToken {
		return resp.Data[3:], nil
	}

	// Sometimes the SSPI is preceded by other tokens — scan for it
	offset := 0
	for offset < len(resp.Data)-3 {
		tokenType := resp.Data[offset]
		if tokenType == TDSSSPIToken {
			tokenLen := int(resp.Data[offset+1]) | int(resp.Data[offset+2])<<8
			if offset+3+tokenLen <= len(resp.Data) {
				return resp.Data[offset+3 : offset+3+tokenLen], nil
			}
			return resp.Data[offset+3:], nil
		}
		// Skip known variable-length tokens
		if offset+3 > len(resp.Data) {
			break
		}
		tokenLen := int(resp.Data[offset+1]) | int(resp.Data[offset+2])<<8
		offset += 3 + tokenLen
	}

	return nil, fmt.Errorf("SSPI challenge token not found in response")
}

// RelayDisableTLSAfterLogin is a no-op — TLS is now disabled inside
// RelaySendNegotiate after sending LOGIN7 (matching Impacket behavior).
func (c *Client) RelayDisableTLSAfterLogin() {
	// No-op: handled in RelaySendNegotiate
}

// RelaySendAuth sends the NTLM Type3 authenticate message as a TDS_SSPI packet,
// and checks for a successful login acknowledgment.
func (c *Client) RelaySendAuth(ntlmType3 []byte) error {
	if err := c.sendTDS(TDSSSPI, ntlmType3); err != nil {
		return err
	}

	resp, err := c.recvTDS()
	if err != nil {
		return err
	}

	// Store the raw TDS LOGIN_ACK response for SOCKS plugin replay
	c.RelayRawAuthAnswer = resp.Marshal()

	return c.checkLoginResponse(resp.Data)
}

// SendTDS is a public wrapper around sendTDS for SOCKS plugin use.
func (c *Client) SendTDS(packetType uint8, data []byte) error {
	return c.sendTDS(packetType, data)
}

// RecvTDS is a public wrapper around recvTDS for SOCKS plugin use.
func (c *Client) RecvTDS() (*TDSPacket, error) {
	return c.recvTDS()
}

// GetPacketSize returns the TDS packet size for framing.
func (c *Client) GetPacketSize() int {
	return c.packetSize
}

// GetConn returns the underlying TCP connection (for SOCKS tunneling).
func (c *Client) GetConn() net.Conn {
	return c.conn
}

// Helper functions

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func decodeHex(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		b[i] = hexVal(s[i*2])<<4 | hexVal(s[i*2+1])
	}
	return b
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
