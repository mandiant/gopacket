// SPDX-License-Identifier: Apache-2.0

package wmi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/dcom"
	"gopacket/pkg/utf16le"
)

// IWbemLevel1Login wraps the WMI login interface
type IWbemLevel1Login struct {
	iface *dcom.Interface
}

// NewIWbemLevel1Login creates a new IWbemLevel1Login from a DCOM interface
func NewIWbemLevel1Login(iface *dcom.Interface) *IWbemLevel1Login {
	return &IWbemLevel1Login{iface: iface}
}

// NTLMLogin logs into WMI and returns an IWbemServices interface.
// The namespace is typically "//./root/cimv2" for standard WMI operations.
func (l *IWbemLevel1Login) NTLMLogin(namespace string) (*IWbemServices, error) {
	// Bind to IWbemLevel1Login on the OXID connection
	if err := l.iface.Connection.BindInterface(IID_IWbemLevel1Login); err != nil {
		return nil, fmt.Errorf("failed to bind IWbemLevel1Login: %v", err)
	}

	buf := new(bytes.Buffer)

	// wszNetworkResource - LPWSTR (pointer + string)
	namespaceUTF16 := utf16le.EncodeStringToBytes(namespace)
	// Pointer (non-null)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
	// Conformance (max count)
	binary.Write(buf, binary.LittleEndian, uint32(len(namespace)+1))
	// Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Actual count
	binary.Write(buf, binary.LittleEndian, uint32(len(namespace)+1))
	// String data
	buf.Write(namespaceUTF16)
	buf.Write([]byte{0, 0}) // Null terminator
	// Pad to 4-byte boundary
	if (len(namespaceUTF16)+2)%4 != 0 {
		buf.Write(make([]byte, 4-(len(namespaceUTF16)+2)%4))
	}

	// wszPreferredLocale - LPWSTR (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lFlags - LONG
	binary.Write(buf, binary.LittleEndian, int32(0))

	// pCtx - PMInterfacePointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Call the RPC (Interface.Call adds ORPCTHIS)
	resp, err := l.iface.Call(OpIWbemLevel1Login_NTLMLogin, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("NTLMLogin RPC failed: %v", err)
	}

	// Parse response - pass the client that was used for NTLMLogin
	// The returned IWbemServices IPID is tied to this client's security context
	return parseNTLMLoginResponse(resp, l.iface.Connection, l.iface.Client)
}

// parseNTLMLoginResponse parses the NTLMLogin response
func parseNTLMLoginResponse(resp []byte, conn *dcom.DCOMConnection, client *dcerpc.Client) (*IWbemServices, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Check HRESULT at end of response
	if len(resp) >= 4 {
		hresult := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if hresult != 0 {
			return nil, fmt.Errorf("NTLMLogin failed with HRESULT: 0x%08x", hresult)
		}
	}

	// Search for OBJREF signature in response to find the IWbemServices interface
	for i := 0; i < len(resp)-44; i++ {
		sig := binary.LittleEndian.Uint32(resp[i:])
		if sig == dcom.OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(resp[i+4:])
			fmt.Printf("[D] parseNTLMLoginResponse: Found OBJREF at offset %d, flags=0x%x\n", i, flags)
			if flags == dcom.FLAGS_OBJREF_STANDARD {
				iface, err := parseStdObjRef(resp[i:], conn)
				if err == nil {
					iface.IID = IID_IWbemServices
					// Set the client - the IPID is tied to this client's security context
					iface.Client = client
					return &IWbemServices{iface: iface}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("could not find IWbemServices interface in response")
}

// parseStdObjRef parses a standard OBJREF and returns an Interface
func parseStdObjRef(data []byte, conn *dcom.DCOMConnection) (*dcom.Interface, error) {
	if len(data) < 68 {
		return nil, fmt.Errorf("STDOBJREF too short")
	}

	// Skip OBJREF header (24 bytes)
	data = data[24:]

	iface := &dcom.Interface{
		Connection: conn,
	}

	r := bytes.NewReader(data)

	// STDOBJREF
	var flags, cPublicRefs uint32
	binary.Read(r, binary.LittleEndian, &flags)
	binary.Read(r, binary.LittleEndian, &cPublicRefs)
	binary.Read(r, binary.LittleEndian, &iface.OXID)
	binary.Read(r, binary.LittleEndian, &iface.OID)
	r.Read(iface.IPID[:])

	fmt.Printf("[D] parseStdObjRef: IPID=%x, OXID=%016x, OID=%016x\n", iface.IPID, iface.OXID, iface.OID)

	return iface, nil
}

// Release releases the IWbemLevel1Login interface
func (l *IWbemLevel1Login) Release() error {
	return l.iface.RemRelease()
}
