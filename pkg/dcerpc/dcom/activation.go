// SPDX-License-Identifier: Apache-2.0

package dcom

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// RemoteSCMActivator implements the IRemoteSCMActivator interface
// for activating COM objects remotely.
type RemoteSCMActivator struct {
	conn *DCOMConnection
}

// OpNum for IRemoteSCMActivator
const (
	OpRemoteGetClassObject = 3
	OpRemoteCreateInstance = 4
)

// RemoteCreateInstance activates a COM class and returns an interface pointer.
// This is the Go equivalent of CoCreateInstanceEx.
func (s *RemoteSCMActivator) RemoteCreateInstance(clsid, iid [16]byte) (*Interface, error) {
	// Build the request
	buf := new(bytes.Buffer)

	// ORPCTHIS header (flags=1 for activation)
	orpcThis := NewORPCTHISForActivation()
	buf.Write(orpcThis.Marshal())

	// pUnkOuter - PMInterfacePointer (NULL)
	// NULL pointer in NDR
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pActProperties (PMInterfacePointer) - contains the activation blob
	actBlob := buildActivationBlob(clsid, iid)

	// PMInterfacePointer (non-NULL):
	// - Pointer referent ID (4)
	// - ulCntData (4)
	// - conformant array max count (4)
	// - abData (variable)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))   // Referent ID
	binary.Write(buf, binary.LittleEndian, uint32(len(actBlob))) // ulCntData
	binary.Write(buf, binary.LittleEndian, uint32(len(actBlob))) // Conformant max count
	buf.Write(actBlob)

	// Call the RPC
	resp, err := s.conn.rpcClient.CallAuth(OpRemoteCreateInstance, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("RemoteCreateInstance RPC failed: %v", err)
	}

	// Parse the response
	return parseActivationResponse(resp, s.conn, iid)
}

// buildActivationBlob builds the OBJREF_CUSTOM containing activation properties
func buildActivationBlob(clsid, iid [16]byte) []byte {
	// Build the properties with TypeSerialization1 headers
	instantiationInfo := buildInstantiationInfoTS1(clsid, iid)
	activationContextInfo := buildActivationContextInfoTS1()
	locationInfo := buildLocationInfoTS1()
	scmRequestInfo := buildScmRequestInfoTS1()

	// Pad each to 8-byte alignment
	instantiationInfo = padToAlign(instantiationInfo, 8, 0xFA)
	activationContextInfo = padToAlign(activationContextInfo, 8, 0xFA)
	// locationInfo doesn't need padding (already 32 bytes)
	scmRequestInfo = padToAlign(scmRequestInfo, 8, 0xFA)

	properties := make([]byte, 0)
	properties = append(properties, instantiationInfo...)
	properties = append(properties, activationContextInfo...)
	properties = append(properties, locationInfo...)
	properties = append(properties, scmRequestInfo...)

	// Build CustomHeader with TypeSerialization1
	customHeader := buildCustomHeaderTS1(
		len(instantiationInfo),
		len(activationContextInfo),
		len(locationInfo),
		len(scmRequestInfo),
	)

	// Calculate total sizes
	headerSize := len(customHeader)
	totalSize := headerSize + len(properties)

	// Build ACTIVATION_BLOB
	actBlob := new(bytes.Buffer)
	binary.Write(actBlob, binary.LittleEndian, uint32(totalSize)) // dwSize
	binary.Write(actBlob, binary.LittleEndian, uint32(0))         // dwReserved
	actBlob.Write(customHeader)
	actBlob.Write(properties)

	// Build OBJREF_CUSTOM wrapper
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(OBJREF_SIGNATURE))
	binary.Write(buf, binary.LittleEndian, uint32(FLAGS_OBJREF_CUSTOM))
	buf.Write(IID_IActivationPropertiesIn[:])
	buf.Write(CLSID_ActivationPropertiesIn[:])
	binary.Write(buf, binary.LittleEndian, uint32(0))                      // extension
	binary.Write(buf, binary.LittleEndian, uint32(len(actBlob.Bytes())+8)) // ObjectReferenceSize
	buf.Write(actBlob.Bytes())

	return buf.Bytes()
}

// writeTS1Header writes a TypeSerialization1 header (CommonHeader + PrivateHeader)
func writeTS1Header(buf *bytes.Buffer, objectLen int) {
	// CommonHeader (8 bytes)
	buf.WriteByte(0x01)                                        // Version = 1
	buf.WriteByte(0x10)                                        // Endianness = 0x10 (little-endian)
	binary.Write(buf, binary.LittleEndian, uint16(8))          // CommonHeaderLength = 8
	binary.Write(buf, binary.LittleEndian, uint32(0xcccccccc)) // Filler

	// PrivateHeader (8 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(objectLen))  // ObjectBufferLength
	binary.Write(buf, binary.LittleEndian, uint32(0xcccccccc)) // Filler
}

// buildCustomHeaderTS1 builds the CustomHeader with TypeSerialization1 wrapper
func buildCustomHeaderTS1(size0, size1, size2, size3 int) []byte {
	// Calculate the inner header data first to get ObjectBufferLength
	inner := new(bytes.Buffer)

	// totalSize placeholder (will be fixed by caller)
	binary.Write(inner, binary.LittleEndian, uint32(0)) // placeholder
	// headerSize placeholder
	binary.Write(inner, binary.LittleEndian, uint32(0)) // placeholder
	// dwReserved
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// destCtx = 2
	binary.Write(inner, binary.LittleEndian, uint32(2))
	// cIfs = 4
	binary.Write(inner, binary.LittleEndian, uint32(4))
	// classInfoClsid (16 bytes of zeros)
	inner.Write(make([]byte, 16))
	// pclsid pointer (referent ID)
	binary.Write(inner, binary.LittleEndian, uint32(0x000037b4))
	// pSizes pointer (referent ID)
	binary.Write(inner, binary.LittleEndian, uint32(0x00005ce5))
	// pdwReserved = NULL
	binary.Write(inner, binary.LittleEndian, uint32(0))

	// Referent data for pclsid (conformant array of 4 CLSIDs)
	binary.Write(inner, binary.LittleEndian, uint32(4)) // max count
	inner.Write(CLSID_InstantiationInfo[:])
	inner.Write(CLSID_ActivationContextInfo[:])
	inner.Write(CLSID_ServerLocationInfo[:])
	inner.Write(CLSID_ScmRequestInfo[:])

	// Referent data for pSizes (conformant array of 4 DWORDs)
	binary.Write(inner, binary.LittleEndian, uint32(4)) // max count
	binary.Write(inner, binary.LittleEndian, uint32(size0))
	binary.Write(inner, binary.LittleEndian, uint32(size1))
	binary.Write(inner, binary.LittleEndian, uint32(size2))
	binary.Write(inner, binary.LittleEndian, uint32(size3))

	// Build final with TS1 header
	buf := new(bytes.Buffer)
	writeTS1Header(buf, len(inner.Bytes()))
	buf.Write(inner.Bytes())

	// Fix totalSize and headerSize in the header
	data := buf.Bytes()
	headerSize := len(data)
	totalSize := headerSize + size0 + size1 + size2 + size3

	// totalSize is at offset 16 (after TS1 headers)
	binary.LittleEndian.PutUint32(data[16:], uint32(totalSize))
	// headerSize is at offset 20
	binary.LittleEndian.PutUint32(data[20:], uint32(headerSize))

	return data
}

// buildInstantiationInfoTS1 builds the InstantiationInfoData with TypeSerialization1 header
func buildInstantiationInfoTS1(clsid, iid [16]byte) []byte {
	inner := new(bytes.Buffer)

	// classId (16)
	inner.Write(clsid[:])
	// classCtx (4) = 0 (default)
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// actvflags (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// fIsSurrogate (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// cIID (4) = 1
	binary.Write(inner, binary.LittleEndian, uint32(1))
	// instFlag (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// pIID pointer (referent ID)
	binary.Write(inner, binary.LittleEndian, uint32(0x0000612b))
	// thisSize (4) - placeholder
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// clientCOMVersion
	binary.Write(inner, binary.LittleEndian, uint16(5)) // major
	binary.Write(inner, binary.LittleEndian, uint16(7)) // minor

	// Referent data for pIID (conformant array of 1 IID)
	binary.Write(inner, binary.LittleEndian, uint32(1)) // max count
	inner.Write(iid[:])

	// Build with TS1 header
	buf := new(bytes.Buffer)
	writeTS1Header(buf, len(inner.Bytes()))
	buf.Write(inner.Bytes())

	// Fix thisSize (at offset 16 + 32 = 48)
	data := buf.Bytes()
	// thisSize should be the total padded size
	// We'll set it after padding in the caller

	return data
}

// buildActivationContextInfoTS1 builds the ActivationContextInfoData with TypeSerialization1 header
func buildActivationContextInfoTS1() []byte {
	inner := new(bytes.Buffer)

	// clientOK (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// bReserved (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// dwReserved (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// Reserved2 (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// pIFDClientCtx (4) = NULL
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// pIFDPrototypeCtx (4) = NULL
	binary.Write(inner, binary.LittleEndian, uint32(0))

	buf := new(bytes.Buffer)
	writeTS1Header(buf, len(inner.Bytes()))
	buf.Write(inner.Bytes())

	return buf.Bytes()
}

// buildLocationInfoTS1 builds the LocationInfoData with TypeSerialization1 header
func buildLocationInfoTS1() []byte {
	inner := new(bytes.Buffer)

	// machineName pointer (4) = NULL
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// processId (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// apartmentId (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// contextId (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))

	buf := new(bytes.Buffer)
	writeTS1Header(buf, len(inner.Bytes()))
	buf.Write(inner.Bytes())

	return buf.Bytes()
}

// buildScmRequestInfoTS1 builds the ScmRequestInfoData with TypeSerialization1 header
func buildScmRequestInfoTS1() []byte {
	inner := new(bytes.Buffer)

	// pdwReserved (4) = NULL
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// remoteRequest pointer (referent ID)
	binary.Write(inner, binary.LittleEndian, uint32(0x0000bbec))

	// Referent data for remoteRequest (customREMOTE_REQUEST_SCM_INFO):
	// ClientImpLevel (4) = 0
	binary.Write(inner, binary.LittleEndian, uint32(0))
	// cRequestedProtseqs (2) = 1
	binary.Write(inner, binary.LittleEndian, uint16(1))
	// Padding for alignment
	binary.Write(inner, binary.LittleEndian, uint16(0xaaaa))
	// pRequestedProtseqs pointer (referent ID)
	binary.Write(inner, binary.LittleEndian, uint32(0x0000b82a))

	// Referent data for pRequestedProtseqs (conformant array)
	binary.Write(inner, binary.LittleEndian, uint32(1))            // max count
	binary.Write(inner, binary.LittleEndian, uint16(NCACN_IP_TCP)) // protocol = 7

	buf := new(bytes.Buffer)
	writeTS1Header(buf, len(inner.Bytes()))
	buf.Write(inner.Bytes())

	return buf.Bytes()
}

// padToAlign pads data to alignment boundary with specified fill byte
func padToAlign(data []byte, align int, fill byte) []byte {
	pad := (align - (len(data) % align)) % align
	for i := 0; i < pad; i++ {
		data = append(data, fill)
	}
	return data
}

// parseActivationResponse parses the response from RemoteCreateInstance
func parseActivationResponse(resp []byte, conn *DCOMConnection, requestedIID [16]byte) (*Interface, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Check HRESULT at end of response
	if len(resp) >= 4 {
		hresult := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if hresult != 0 && hresult != 0x00000001 {
			return nil, fmt.Errorf("activation failed with HRESULT: 0x%08x", hresult)
		}
	}

	// Find OBJREF_CUSTOM in response (IActivationPropertiesOut)
	var actBlobData []byte
	for i := 0; i < len(resp)-44; i++ {
		sig := binary.LittleEndian.Uint32(resp[i:])
		if sig == OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(resp[i+4:])
			if flags == FLAGS_OBJREF_CUSTOM {
				// Found OBJREF_CUSTOM - extract the activation blob
				// Skip signature (4) + flags (4) + iid (16) + clsid (16) + extension (4)
				offset := i + 4 + 4 + 16 + 16 + 4
				if offset+4 <= len(resp) {
					objRefSize := binary.LittleEndian.Uint32(resp[offset:])
					offset += 4
					// pObjectData size is ObjectReferenceSize - 8 (size excludes signature+flags)
					dataSize := int(objRefSize) - 8
					if dataSize > 0 && offset+dataSize <= len(resp) {
						actBlobData = resp[offset : offset+dataSize]
						break
					}
				}
			}
		}
	}

	if actBlobData == nil {
		return nil, fmt.Errorf("could not find activation blob in response")
	}

	// Parse ACTIVATION_BLOB to extract string bindings and interface data
	return parseActivationBlob(actBlobData, conn, requestedIID)
}

// parseActivationBlob extracts interface info from the activation blob
func parseActivationBlob(data []byte, conn *DCOMConnection, requestedIID [16]byte) (*Interface, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("activation blob too short")
	}

	// ACTIVATION_BLOB: dwSize (4) + dwReserved (4) + CustomHeader + Properties
	// dwSize := binary.LittleEndian.Uint32(data[0:])

	// Skip to CustomHeader (after TypeSerialization1 headers at offset 8)
	// CustomHeader starts after dwSize + dwReserved + TS1 headers (16 bytes)
	offset := 8

	// Check for TypeSerialization1 header
	if offset+16 <= len(data) {
		if data[offset] == 0x01 && data[offset+1] == 0x10 {
			// Skip TS1 header (16 bytes)
			offset += 16
		}
	}

	// Now we're in CustomHeader
	if offset+24 > len(data) {
		return nil, fmt.Errorf("cannot read CustomHeader")
	}

	totalSize := binary.LittleEndian.Uint32(data[offset:])
	headerSize := binary.LittleEndian.Uint32(data[offset+4:])
	// dwReserved at offset+8
	// destCtx at offset+12
	cIfs := binary.LittleEndian.Uint32(data[offset+16:])

	_ = totalSize
	_ = cIfs

	// Skip to property sizes array to find where ScmReplyInfo starts
	// This is complex - for now, scan for the string bindings pattern

	// Look for string bindings in the response
	// Format: wTowerId (2) + wSecurityOffset (2) + aStringArray
	// TCP bindings start with 0x07 0x00 (ncacn_ip_tcp)

	var stringBindings []string
	var port int

	for i := 0; i < len(data)-10; i++ {
		// Look for ncacn_ip_tcp binding (0x0007)
		if binary.LittleEndian.Uint16(data[i:]) == 0x0007 {
			// Found a potential TCP binding
			// Next is the network address as null-terminated UTF-16
			addr := ""
			j := i + 2
			for j < len(data)-1 {
				c := binary.LittleEndian.Uint16(data[j:])
				if c == 0 {
					break
				}
				addr += string(rune(c))
				j += 2
			}
			if addr != "" {
				stringBindings = append(stringBindings, addr)
				// Extract port if present [port]
				if idx := indexOf(addr, "["); idx >= 0 {
					endIdx := indexOf(addr[idx:], "]")
					if endIdx > 0 {
						fmt.Sscanf(addr[idx+1:idx+endIdx], "%d", &port)
					}
				}
			}
		}
	}

	// Look for IPID in the response - it's typically in the ScmReplyInfo
	// Search for a 16-byte GUID pattern that looks like an IPID
	var ipid [16]byte
	var oxid uint64
	var oid uint64

	// Search for STDOBJREF pattern in PropsOutInfo
	for i := 0; i < len(data)-44; i++ {
		sig := binary.LittleEndian.Uint32(data[i:])
		if sig == OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(data[i+4:])
			if flags == FLAGS_OBJREF_STANDARD {
				// Found a STDOBJREF
				stdOffset := i + 24 // After OBJREF header
				if stdOffset+44 <= len(data) {
					// STDOBJREF: flags (4) + cPublicRefs (4) + oxid (8) + oid (8) + ipid (16)
					oxid = binary.LittleEndian.Uint64(data[stdOffset+8:])
					oid = binary.LittleEndian.Uint64(data[stdOffset+16:])
					copy(ipid[:], data[stdOffset+24:stdOffset+40])
					break
				}
			}
		}
	}

	// Create interface - we'll need to connect to the OXID port
	iface := &Interface{
		IPID:        ipid,
		IID:         requestedIID,
		OXID:        oxid,
		OID:         oid,
		StringBinds: stringBindings,
		Connection:  conn,
	}

	// If we found a port, connect to the OXID
	if port > 0 {
		if err := conn.ConnectToOXID(port); err != nil {
			return nil, fmt.Errorf("failed to connect to OXID on port %d: %v", port, err)
		}
	}

	// Store the interface in the connection's registry
	if headerSize > 0 { // valid header
		return iface, nil
	}

	return iface, nil
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// parseStdObjRef parses a standard OBJREF and returns an Interface
func parseStdObjRef(data []byte, conn *DCOMConnection) (*Interface, error) {
	if len(data) < 68 { // 24 (OBJREF header) + 44 (STDOBJREF)
		return nil, fmt.Errorf("STDOBJREF too short")
	}

	// Skip OBJREF header (24 bytes)
	data = data[24:]

	iface := &Interface{
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

	// After STDOBJREF comes DUALSTRINGARRAY with string bindings
	// Skip parsing those for now

	return iface, nil
}
