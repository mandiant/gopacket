package dcom

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"gopacket/pkg/dcerpc"
)

// IRemUnknown operation numbers
const (
	OpRemQueryInterface = 3
	OpRemAddRef         = 4
	OpRemRelease        = 5
)

// IRemUnknown2 operation numbers
const (
	OpRemQueryInterface2 = 6
)

// REMQIRESULT contains the result of a QueryInterface call
type REMQIRESULT struct {
	HRESULT uint32
	Std     STDOBJREF
}

// Call makes an ORPC call on this interface
func (i *Interface) Call(opnum uint16, payload []byte) ([]byte, error) {
	// Build ORPC request
	buf := new(bytes.Buffer)

	// ORPCTHIS header
	orpcThis := NewORPCTHIS()
	buf.Write(orpcThis.Marshal())

	// Payload
	buf.Write(payload)

	fmt.Printf("[D] Interface.Call: opnum=%d, IPID=%x, IID=%x\n", opnum, i.IPID, i.IID)

	// Use the specific client this interface was obtained on, if set.
	// IPIDs are tied to the security context where they were created.
	var client *dcerpc.Client
	if i.Client != nil {
		client = i.Client
	} else {
		// Fallback to IID-based client lookup
		client = i.Connection.GetInterfaceClient(i.IID)
		// Remember this client for future calls and for derived interfaces
		if client != nil {
			i.Client = client
		}
	}
	if client == nil {
		return nil, fmt.Errorf("no client for interface %x", i.IID)
	}

	// Set the correct presentation context ID for this interface
	if ctxID, ok := client.GetContextID(i.IID); ok {
		client.ContextID = ctxID
	} else {
		fmt.Printf("[D] Interface.Call: Warning - Context ID not found for IID %x, using current %d\n", i.IID, client.ContextID)
	}

	// Make the RPC call with IPID for DCOM object dispatch
	return client.CallAuthDCOM(opnum, buf.Bytes(), i.IPID)
}

// RemQueryInterface queries for additional interfaces on the object
func (i *Interface) RemQueryInterface(iid [16]byte) (*Interface, error) {
	// Need to connect to the object's OXID resolver first
	// to establish communication with the object

	buf := new(bytes.Buffer)

	// ORPCTHIS header
	orpcThis := NewORPCTHIS()
	buf.Write(orpcThis.Marshal())

	// IPID of this interface
	buf.Write(i.IPID[:])

	// cRefs (4) - requested reference count
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// cIids (2) - number of IIDs to query
	binary.Write(buf, binary.LittleEndian, uint16(1))

	// padding
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// iids array pointer
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))

	// iids array data
	buf.Write(iid[:])

	// TODO: This needs to be called on a connection to the object's OXID
	// For now, we'll use the main connection
	resp, err := i.Connection.rpcClient.CallAuth(OpRemQueryInterface, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("RemQueryInterface failed: %v", err)
	}

	return parseQueryInterfaceResponse(resp, i.Connection, iid)
}

// RemAddRef increments the reference count
func (i *Interface) RemAddRef(count uint32) error {
	buf := new(bytes.Buffer)

	// cInterfaceRefs (2)
	binary.Write(buf, binary.LittleEndian, uint16(1))
	// padding
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// REMINTERFACEREF conformant array - just conformance + elements, no pointer
	binary.Write(buf, binary.LittleEndian, uint32(1)) // conformance (max_count)

	// REMINTERFACEREF: ipid (16) + cPublicRefs (4) + cPrivateRefs (4)
	buf.Write(i.IPID[:])
	binary.Write(buf, binary.LittleEndian, count)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	_, err := i.Call(OpRemAddRef, buf.Bytes())
	return err
}

// RemRelease decrements the reference count
func (i *Interface) RemRelease() error {
	buf := new(bytes.Buffer)

	// cInterfaceRefs (2)
	binary.Write(buf, binary.LittleEndian, uint16(1))
	// padding
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// REMINTERFACEREF conformant array - just conformance + elements, no pointer
	binary.Write(buf, binary.LittleEndian, uint32(1)) // conformance (max_count)

	// REMINTERFACEREF structure
	buf.Write(i.IPID[:])
	binary.Write(buf, binary.LittleEndian, uint32(1)) // cPublicRefs
	binary.Write(buf, binary.LittleEndian, uint32(0)) // cPrivateRefs

	_, err := i.Call(OpRemRelease, buf.Bytes())
	return err
}

// parseQueryInterfaceResponse parses the RemQueryInterface response
func parseQueryInterfaceResponse(resp []byte, conn *DCOMConnection, requestedIID [16]byte) (*Interface, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	r := bytes.NewReader(resp)

	// ORPCTHAT header
	var orpcThat ORPCTHAT
	orpcThatData := make([]byte, 8)
	r.Read(orpcThatData)
	orpcThat.Unmarshal(orpcThatData)

	// ppQIResults pointer
	var ptrResults uint32
	binary.Read(r, binary.LittleEndian, &ptrResults)

	// Check HRESULT
	// Skip to end for now to get HRESULT
	remaining := resp[r.Len():]
	if len(remaining) >= 4 {
		hresult := binary.LittleEndian.Uint32(remaining[len(remaining)-4:])
		if hresult != 0 && hresult != 0x00000001 {
			return nil, fmt.Errorf("QueryInterface failed with HRESULT: 0x%08x", hresult)
		}
	}

	// Search for OBJREF in response
	for i := 0; i < len(resp)-44; i++ {
		sig := binary.LittleEndian.Uint32(resp[i:])
		if sig == OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(resp[i+4:])
			if flags == FLAGS_OBJREF_STANDARD {
				iface, err := parseStdObjRef(resp[i:], conn)
				if err == nil {
					iface.IID = requestedIID
					return iface, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("could not find interface in response")
}

// ConnectToInterface connects to a DCOM interface at a specific address
func ConnectToInterface(target string, port int, creds *dcerpc.AuthHandler, iface *Interface) (*dcerpc.Client, error) {
	transport, err := dcerpc.DialTCP(target, port)
	if err != nil {
		return nil, err
	}

	client := dcerpc.NewClientTCP(transport)

	// Bind to IRemUnknown2
	// The binding uses the IPID from the interface
	if err := client.Bind(IID_IRemUnknown2, 0, 0); err != nil {
		return nil, err
	}

	return client, nil
}
