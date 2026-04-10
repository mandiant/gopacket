// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package wmi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"gopacket/pkg/dcerpc/dcom"
	"gopacket/pkg/utf16le"
)

// IWbemServices wraps the WMI services interface
type IWbemServices struct {
	iface *dcom.Interface
}

// NewIWbemServices creates a new IWbemServices from a DCOM interface
func NewIWbemServices(iface *dcom.Interface) *IWbemServices {
	return &IWbemServices{iface: iface}
}

// GetObject retrieves a WMI class or instance object.
// For Win32_Process execution, use path "Win32_Process".
func (s *IWbemServices) GetObject(objectPath string) (*IWbemClassObject, error) {
	// Note: In DCOM, object calls are routed via IPID, not presentation context

	buf := new(bytes.Buffer)

	// strObjectPath - BSTR (Interface.Call adds ORPCTHIS)
	writeBSTR(buf, objectPath)

	// lFlags - LONG
	binary.Write(buf, binary.LittleEndian, int32(0))

	// pCtx - PMInterfacePointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ppObject - PMInterfacePointer (out - pass NULL pointer)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ppCallResult - PMInterfacePointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Call the RPC
	resp, err := s.iface.Call(OpIWbemServices_GetObject, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("GetObject RPC failed: %v", err)
	}

	return parseGetObjectResponse(resp, s.iface.Connection)
}

// ExecMethod executes a method on a WMI class or instance.
// For Win32_Process.Create:
//   - objectPath: "Win32_Process"
//   - methodName: "Create"
//   - inParams: serialized method parameters
func (s *IWbemServices) ExecMethod(objectPath, methodName string, inParams []byte) (*ExecMethodResult, error) {
	// The IWbemServices IPID was obtained via NTLMLogin.
	// Note: AlterContext method not yet implemented on Client; once available,
	// callers should alter to IID_IWbemServices on existing clients.

	buf := new(bytes.Buffer)

	// strObjectPath - BSTR (Interface.Call adds ORPCTHIS)
	writeBSTR(buf, objectPath)

	// strMethodName - BSTR
	writeBSTR(buf, methodName)

	// lFlags - LONG
	binary.Write(buf, binary.LittleEndian, int32(0))

	// pCtx - PMInterfacePointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pInParams - PMInterfacePointer
	if len(inParams) > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Pointer
		binary.Write(buf, binary.LittleEndian, uint32(len(inParams)))
		buf.Write(inParams)
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL
	}

	// ppOutParams - PPMInterfacePointer (out)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// ppCallResult - PPMInterfacePointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Call the RPC
	resp, err := s.iface.Call(OpIWbemServices_ExecMethod, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ExecMethod RPC failed: %v", err)
	}

	return parseExecMethodResponse(resp)
}

// ExecMethodResult contains the result of ExecMethod
type ExecMethodResult struct {
	ReturnValue int32
	ProcessId   uint32
	OutParams   []byte
}

// writeBSTR writes a BSTR to the buffer
func writeBSTR(buf *bytes.Buffer, s string) {
	if s == "" {
		// NULL BSTR
		binary.Write(buf, binary.LittleEndian, uint32(0))
		return
	}

	// BSTR structure in NDR:
	// MaxCount (4) + Offset (4) + ActualCount (4) + data (UTF-16LE) + padding
	strUTF16 := utf16le.EncodeStringToBytes(s)
	charCount := len(s) // Character count (not byte count)

	// Pointer (non-null)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
	// MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(charCount))
	// Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// ActualCount
	binary.Write(buf, binary.LittleEndian, uint32(charCount))
	// String data (without null terminator for BSTR)
	buf.Write(strUTF16)
	// Pad to 4-byte boundary
	if len(strUTF16)%4 != 0 {
		buf.Write(make([]byte, 4-len(strUTF16)%4))
	}
}

// parseGetObjectResponse parses the GetObject response
func parseGetObjectResponse(resp []byte, conn *dcom.DCOMConnection) (*IWbemClassObject, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Check HRESULT at end
	if len(resp) >= 4 {
		hresult := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if hresult != 0 && hresult != WBEM_S_NO_ERROR {
			return nil, fmt.Errorf("GetObject failed with HRESULT: 0x%08x", hresult)
		}
	}

	// Search for OBJREF_CUSTOM containing the WMI object
	for i := 0; i < len(resp)-24; i++ {
		sig := binary.LittleEndian.Uint32(resp[i:])
		if sig == dcom.OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(resp[i+4:])
			if flags == dcom.FLAGS_OBJREF_CUSTOM {
				// Found OBJREF_CUSTOM - extract the WMI object data
				obj, err := parseObjRefCustom(resp[i:])
				if err == nil {
					return obj, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("could not find WMI object in response")
}

// parseExecMethodResponse parses the ExecMethod response
func parseExecMethodResponse(resp []byte) (*ExecMethodResult, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Check HRESULT at end
	if len(resp) >= 4 {
		hresult := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if hresult != 0 && hresult != WBEM_S_NO_ERROR {
			return nil, fmt.Errorf("ExecMethod failed with HRESULT: 0x%08x", hresult)
		}
	}

	result := &ExecMethodResult{}

	// Parse out params to get ReturnValue and ProcessId
	// The response contains an OBJREF_CUSTOM with the output parameters
	for i := 0; i < len(resp)-24; i++ {
		sig := binary.LittleEndian.Uint32(resp[i:])
		if sig == dcom.OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(resp[i+4:])
			if flags == dcom.FLAGS_OBJREF_CUSTOM {
				result.OutParams = resp[i:]
				// Try to extract ReturnValue and ProcessId
				// This is simplified - full parsing would need WMIO decoder
				break
			}
		}
	}

	return result, nil
}

// parseObjRefCustom parses an OBJREF_CUSTOM containing WMI object data
func parseObjRefCustom(data []byte) (*IWbemClassObject, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("OBJREF_CUSTOM too short")
	}

	// OBJREF_CUSTOM:
	// signature (4)
	// flags (4)
	// iid (16)
	// clsid (16)
	// extension (4)
	// reserved (4)
	// ObjectReferenceSize (4)
	// pObjectData (variable)

	r := bytes.NewReader(data)

	var signature, flags uint32
	binary.Read(r, binary.LittleEndian, &signature)
	binary.Read(r, binary.LittleEndian, &flags)

	if signature != dcom.OBJREF_SIGNATURE || flags != dcom.FLAGS_OBJREF_CUSTOM {
		return nil, fmt.Errorf("not an OBJREF_CUSTOM")
	}

	// Skip IID and CLSID
	r.Seek(32, 1) // Skip 32 bytes

	var extension, reserved, size uint32
	binary.Read(r, binary.LittleEndian, &extension)
	binary.Read(r, binary.LittleEndian, &reserved)
	binary.Read(r, binary.LittleEndian, &size)

	// Read object data
	objData := make([]byte, size)
	r.Read(objData)

	return &IWbemClassObject{
		data: objData,
	}, nil
}

// Release releases the IWbemServices interface
func (s *IWbemServices) Release() error {
	return s.iface.RemRelease()
}

// GetInterface returns the underlying DCOM interface
func (s *IWbemServices) GetInterface() *dcom.Interface {
	return s.iface
}
