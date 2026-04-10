// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

// Package dcom implements the DCOM Remote Protocol (MS-DCOM).
package dcom

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/session"
)

// DCOM UUIDs
var (
	// IRemoteSCMActivator - used for object activation
	IID_IRemoteSCMActivator = dcerpc.MustParseUUID("000001A0-0000-0000-C000-000000000046")

	// IRemUnknown - base interface for all DCOM objects
	IID_IRemUnknown = dcerpc.MustParseUUID("00000131-0000-0000-C000-000000000046")

	// IRemUnknown2 - extended version
	IID_IRemUnknown2 = dcerpc.MustParseUUID("00000143-0000-0000-C000-000000000046")

	// IObjectExporter - for OXID resolution and pinging
	IID_IObjectExporter = dcerpc.MustParseUUID("99fcfec4-5260-101b-bbcb-00aa0021347a")

	// IActivationPropertiesIn/Out
	IID_IActivationPropertiesIn  = dcerpc.MustParseUUID("000001A2-0000-0000-C000-000000000046")
	IID_IActivationPropertiesOut = dcerpc.MustParseUUID("000001A3-0000-0000-C000-000000000046")

	// Activation CLSIDs
	CLSID_ActivationPropertiesIn  = dcerpc.MustParseUUID("00000338-0000-0000-C000-000000000046")
	CLSID_ActivationPropertiesOut = dcerpc.MustParseUUID("00000339-0000-0000-C000-000000000046")
	CLSID_InstantiationInfo       = dcerpc.MustParseUUID("000001ab-0000-0000-C000-000000000046")
	CLSID_ActivationContextInfo   = dcerpc.MustParseUUID("000001a5-0000-0000-C000-000000000046")
	CLSID_ServerLocationInfo      = dcerpc.MustParseUUID("000001a4-0000-0000-C000-000000000046")
	CLSID_ScmRequestInfo          = dcerpc.MustParseUUID("000001aa-0000-0000-C000-000000000046")
	CLSID_ScmReplyInfo            = dcerpc.MustParseUUID("000001b6-0000-0000-C000-000000000046")
	CLSID_PropsOutInfo            = dcerpc.MustParseUUID("00000339-0000-0000-C000-000000000046")
)

// OBJREF flags
const (
	FLAGS_OBJREF_STANDARD = 0x00000001
	FLAGS_OBJREF_HANDLER  = 0x00000002
	FLAGS_OBJREF_CUSTOM   = 0x00000004
	FLAGS_OBJREF_EXTENDED = 0x00000008
)

// OBJREF signature
const OBJREF_SIGNATURE = 0x574F454D // "MEOW"

// Protocol sequence constants
const (
	NCACN_IP_TCP = 7 // TCP/IP
)

// COMVERSION represents the DCOM protocol version
type COMVERSION struct {
	MajorVersion uint16
	MinorVersion uint16
}

// ORPCTHIS is the header for DCOM calls (client to server)
type ORPCTHIS struct {
	Version    COMVERSION
	Flags      uint32
	Reserved1  uint32
	CID        [16]byte // Causality ID (GUID)
	Extensions []byte   // ORPC_EXTENT_ARRAY (optional)
}

// Marshal serializes ORPCTHIS to bytes
func (o *ORPCTHIS) Marshal() []byte {
	buf := new(bytes.Buffer)

	// COMVERSION
	binary.Write(buf, binary.LittleEndian, o.Version.MajorVersion)
	binary.Write(buf, binary.LittleEndian, o.Version.MinorVersion)

	// Flags
	binary.Write(buf, binary.LittleEndian, o.Flags)

	// Reserved1
	binary.Write(buf, binary.LittleEndian, o.Reserved1)

	// CID (causality ID)
	buf.Write(o.CID[:])

	// Extensions pointer (NULL if no extensions)
	if len(o.Extensions) == 0 {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pointer
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Referent ID
		buf.Write(o.Extensions)
	}

	return buf.Bytes()
}

// ORPCTHAT is the header for DCOM responses (server to client)
type ORPCTHAT struct {
	Flags      uint32
	Extensions []byte
}

// Unmarshal deserializes ORPCTHAT from bytes
func (o *ORPCTHAT) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("ORPCTHAT too short")
	}

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &o.Flags)

	var extPtr uint32
	binary.Read(r, binary.LittleEndian, &extPtr)

	// If extensions pointer is non-null, read extensions
	if extPtr != 0 {
		// Skip extension parsing for now - they're optional
	}

	return nil
}

// STDOBJREF is a standard object reference
type STDOBJREF struct {
	Flags       uint32
	CPublicRefs uint32
	OXID        uint64   // Object Exporter ID
	OID         uint64   // Object ID
	IPID        [16]byte // Interface Pointer ID
}

// OBJREF represents a marshaled object reference
type OBJREF struct {
	Signature uint32
	Flags     uint32
	IID       [16]byte
	Data      []byte // Type-specific data (STDOBJREF, OBJREF_CUSTOM, etc.)
}

// Unmarshal deserializes OBJREF from bytes
func (o *OBJREF) Unmarshal(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("OBJREF too short")
	}

	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &o.Signature)
	binary.Read(r, binary.LittleEndian, &o.Flags)
	r.Read(o.IID[:])

	if o.Signature != OBJREF_SIGNATURE {
		return fmt.Errorf("invalid OBJREF signature: 0x%x", o.Signature)
	}

	o.Data = data[24:]
	return nil
}

// DCOMConnection represents a connection to a DCOM server
type DCOMConnection struct {
	target          string
	creds           *session.Credentials
	rpcClient       *dcerpc.Client
	transport       *dcerpc.TCPTransport
	oxidPort        int
	interfaces      map[string]*Interface             // IPID -> Interface
	ifaceClients    map[[16]byte]*dcerpc.Client       // IID -> RPC client (separate connection per interface)
	ifaceTransports map[[16]byte]*dcerpc.TCPTransport // IID -> TCP transport
}

// Interface represents a DCOM interface instance
type Interface struct {
	IPID        [16]byte
	IID         [16]byte
	OXID        uint64
	OID         uint64
	StringBinds []string
	Connection  *DCOMConnection
	Client      *dcerpc.Client // The RPC client this interface was obtained on (for IPID-bound calls)
}

// NewDCOMConnection creates a new DCOM connection to the target
func NewDCOMConnection(target string, creds *session.Credentials) *DCOMConnection {
	return &DCOMConnection{
		target:          target,
		creds:           creds,
		interfaces:      make(map[string]*Interface),
		ifaceClients:    make(map[[16]byte]*dcerpc.Client),
		ifaceTransports: make(map[[16]byte]*dcerpc.TCPTransport),
	}
}

// Connect establishes the DCOM connection
func (d *DCOMConnection) Connect() error {
	// Connect to port 135 (endpoint mapper / DCOM activation)
	transport, err := dcerpc.DialTCP(d.target, 135)
	if err != nil {
		return fmt.Errorf("failed to connect to port 135: %v", err)
	}
	d.transport = transport

	// Create RPC client
	d.rpcClient = dcerpc.NewClientTCP(transport)

	// Bind to IRemoteSCMActivator with authentication
	if err := d.rpcClient.BindAuth(IID_IRemoteSCMActivator, 0, 0, d.creds); err != nil {
		return fmt.Errorf("failed to bind IRemoteSCMActivator: %v", err)
	}

	return nil
}

// Close closes the DCOM connection
func (d *DCOMConnection) Close() error {
	// Close all interface-specific connections
	for _, transport := range d.ifaceTransports {
		if transport != nil {
			transport.Close()
		}
	}
	if d.transport != nil {
		return d.transport.Close()
	}
	return nil
}

// ConnectToOXID establishes a connection to the object exporter on the given port
func (d *DCOMConnection) ConnectToOXID(port int) error {
	d.oxidPort = port
	return nil
}

// BindInterface binds to a specific interface on the OXID port.
// Creates a new TCP connection and performs fresh authentication for each interface.
// This avoids ALTER_CONTEXT issues with security context association.
func (d *DCOMConnection) BindInterface(iid [16]byte) error {
	if d.oxidPort == 0 {
		return fmt.Errorf("OXID port not set")
	}

	fmt.Printf("[D] BindInterface: iid=%x\n", iid)

	// Check if we already have a connection for this interface
	if _, exists := d.ifaceClients[iid]; exists {
		fmt.Printf("[D] BindInterface: already have connection for this interface\n")
		return nil
	}

	// Create new connection for this interface
	transport, err := dcerpc.DialTCP(d.target, d.oxidPort)
	if err != nil {
		return fmt.Errorf("failed to connect to port %d: %v", d.oxidPort, err)
	}

	// Create RPC client
	client := dcerpc.NewClientTCP(transport)

	// Bind to the interface with authentication
	if err := client.BindAuth(iid, 0, 0, d.creds); err != nil {
		transport.Close()
		return fmt.Errorf("failed to bind interface: %v", err)
	}

	// Store the connection
	d.ifaceClients[iid] = client
	d.ifaceTransports[iid] = transport

	fmt.Printf("[D] BindInterface: created new connection for interface\n")
	return nil
}

// BindInterfaces binds to multiple interfaces on a new connection.
// This allows binding IWbemLevel1Login and IWbemServices simultaneously.
func (d *DCOMConnection) BindInterfaces(iids [][16]byte) error {
	if d.oxidPort == 0 {
		return fmt.Errorf("OXID port not set")
	}

	// Create bindings list
	var bindings []dcerpc.InterfaceBinding
	for _, iid := range iids {
		bindings = append(bindings, dcerpc.InterfaceBinding{
			InterfaceUUID: iid,
			Major:         0,
			Minor:         0,
		})
	}

	// Create new connection
	transport, err := dcerpc.DialTCP(d.target, d.oxidPort)
	if err != nil {
		return fmt.Errorf("failed to connect to port %d: %v", d.oxidPort, err)
	}

	// Create RPC client
	client := dcerpc.NewClientTCP(transport)

	// Bind to the interfaces with authentication
	if err := client.BindAuthMulti(bindings, d.creds); err != nil {
		transport.Close()
		return fmt.Errorf("failed to bind interfaces: %v", err)
	}

	// Store the connection for ALL bound interfaces
	for _, iid := range iids {
		d.ifaceClients[iid] = client
		d.ifaceTransports[iid] = transport
	}

	fmt.Printf("[D] BindInterfaces: bound %d interfaces to new connection\n", len(iids))
	return nil
}

// GetInterfaceClient returns the RPC client for a specific interface
func (d *DCOMConnection) GetInterfaceClient(iid [16]byte) *dcerpc.Client {
	if client, exists := d.ifaceClients[iid]; exists {
		return client
	}
	// Fallback to the main RPC client (for activation calls on port 135)
	return d.rpcClient
}

// CoCreateInstanceEx activates a COM object on the server
func (d *DCOMConnection) CoCreateInstanceEx(clsid, iid [16]byte) (*Interface, error) {
	activator := &RemoteSCMActivator{conn: d}
	return activator.RemoteCreateInstance(clsid, iid)
}

// GetRPCClient returns the underlying RPC client
func (d *DCOMConnection) GetRPCClient() *dcerpc.Client {
	return d.rpcClient
}

// GenerateCausalityID generates a new causality ID (GUID)
func GenerateCausalityID() [16]byte {
	// Simple random GUID generation
	var cid [16]byte
	// Using a fixed pattern for now - should use crypto/rand in production
	copy(cid[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	return cid
}

// NewORPCTHIS creates a new ORPCTHIS header for object calls (flags=0)
func NewORPCTHIS() *ORPCTHIS {
	return &ORPCTHIS{
		Version: COMVERSION{
			MajorVersion: 5,
			MinorVersion: 7,
		},
		Flags:     0, // Flags=0 for object calls
		Reserved1: 0,
		CID:       GenerateCausalityID(),
	}
}

// NewORPCTHISForActivation creates a new ORPCTHIS header for activation (flags=1)
func NewORPCTHISForActivation() *ORPCTHIS {
	return &ORPCTHIS{
		Version: COMVERSION{
			MajorVersion: 5,
			MinorVersion: 7,
		},
		Flags:     1, // Flags=1 for activation
		Reserved1: 0,
		CID:       GenerateCausalityID(),
	}
}
