// Package oaut implements OLE Automation interfaces (IDispatch)
package oaut

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/dcom"
)

// IDispatch UUID
var IID_IDispatch = dcerpc.MustParseUUID("00020400-0000-0000-C000-000000000046")

// IDispatch operation numbers
const (
	OpGetTypeInfoCount = 3
	OpGetTypeInfo      = 4
	OpGetIDsOfNames    = 5
	OpInvoke           = 6
)

// Invoke flags
const (
	CYCLELOGGING        = 0x00000000
	CYCLELOGGING_2      = 0x00000000
	CYCLELOGGING_3      = 0x00000000
	DISPATCH_METHOD     = 0x00000001
	DISPATCH_PROPERTYGET = 0x00000002
	DISPATCH_PROPERTYPUT = 0x00000004
	DISPATCH_PROPERTYPUTREF = 0x00000008
)

// VARIANT types (VT_*)
const (
	VT_EMPTY    = 0
	VT_NULL     = 1
	VT_I2       = 2
	VT_I4       = 3
	VT_R4       = 4
	VT_R8       = 5
	VT_CY       = 6
	VT_DATE     = 7
	VT_BSTR     = 8
	VT_DISPATCH = 9
	VT_ERROR    = 10
	VT_BOOL     = 11
	VT_VARIANT  = 12
	VT_UNKNOWN  = 13
	VT_DECIMAL  = 14
	VT_I1       = 16
	VT_UI1      = 17
	VT_UI2      = 18
	VT_UI4      = 19
	VT_I8       = 20
	VT_UI8      = 21
	VT_INT      = 22
	VT_UINT     = 23
	VT_VOID     = 24
	VT_HRESULT  = 25
	VT_PTR      = 26
	VT_SAFEARRAY = 27
	VT_CARRAY   = 28
	VT_USERDEFINED = 29
	VT_LPSTR    = 30
	VT_LPWSTR   = 31
	VT_RECORD   = 36
	VT_INT_PTR  = 37
	VT_UINT_PTR = 38
	VT_ARRAY    = 0x2000
	VT_BYREF    = 0x4000
)

// IDispatch wraps a DCOM Interface for IDispatch calls
type IDispatch struct {
	iface *dcom.Interface
}

// NewIDispatch creates an IDispatch wrapper from a DCOM interface
func NewIDispatch(iface *dcom.Interface) *IDispatch {
	return &IDispatch{iface: iface}
}

// GetInterface returns the underlying DCOM interface
func (d *IDispatch) GetInterface() *dcom.Interface {
	return d.iface
}

// GetIDsOfNames retrieves dispatch IDs for method/property names
func (d *IDispatch) GetIDsOfNames(names []string) ([]int32, error) {
	buf := new(bytes.Buffer)

	// riid - must be IID_NULL (all zeros)
	buf.Write(make([]byte, 16))

	// rgszNames - array of LPOLESTR (pointer to conformant array)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // referent ID

	// cNames
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// lcid (locale ID) - use 0x409 for English
	binary.Write(buf, binary.LittleEndian, uint32(0x409))

	// Now write the conformant array of LPOLESTR
	// MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// Array of pointers to strings
	for i := range names {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000+uint32(i+1))) // referent IDs
	}

	// Now write each string
	for _, name := range names {
		writeBSTR(buf, name)
	}

	resp, err := d.iface.Call(OpGetIDsOfNames, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("GetIDsOfNames failed: %v", err)
	}

	return parseGetIDsOfNamesResponse(resp, len(names))
}

// Invoke calls a method or accesses a property on the dispatch interface
func (d *IDispatch) Invoke(dispID int32, lcid uint32, flags uint16, params *DISPPARAMS) (*VARIANT, error) {
	buf := new(bytes.Buffer)

	// dispIdMember
	binary.Write(buf, binary.LittleEndian, dispID)

	// riid - must be IID_NULL
	buf.Write(make([]byte, 16))

	// lcid
	binary.Write(buf, binary.LittleEndian, lcid)

	// dwFlags
	binary.Write(buf, binary.LittleEndian, uint32(flags))

	// pDispParams
	params.Marshal(buf)

	// cVarRef (number of arguments passed by reference)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// rgVarRefIdx - pointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// rgVarRef - pointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := d.iface.Call(OpInvoke, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Invoke failed: %v", err)
	}

	return parseInvokeResponse(resp)
}

// DISPPARAMS contains parameters for IDispatch::Invoke
type DISPPARAMS struct {
	Args         []*VARIANT
	NamedArgs    []int32
}

// Marshal serializes DISPPARAMS
func (p *DISPPARAMS) Marshal(buf *bytes.Buffer) {
	// pDispParams pointer (unique)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000))

	// cArgs
	binary.Write(buf, binary.LittleEndian, uint32(len(p.Args)))

	// cNamedArgs
	binary.Write(buf, binary.LittleEndian, uint32(len(p.NamedArgs)))

	// rgvarg pointer
	if len(p.Args) > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020001))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	// rgdispidNamedArgs pointer
	if len(p.NamedArgs) > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020002))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	// Write rgvarg array (in reverse order per DCOM convention)
	if len(p.Args) > 0 {
		// Conformance
		binary.Write(buf, binary.LittleEndian, uint32(len(p.Args)))
		// Arguments in reverse order
		for i := len(p.Args) - 1; i >= 0; i-- {
			p.Args[i].Marshal(buf)
		}
	}

	// Write rgdispidNamedArgs array
	if len(p.NamedArgs) > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(len(p.NamedArgs)))
		for _, id := range p.NamedArgs {
			binary.Write(buf, binary.LittleEndian, id)
		}
	}
}

// VARIANT represents an OLE VARIANT value
type VARIANT struct {
	VT    uint16
	Value interface{}
}

// NewVariantBSTR creates a BSTR variant
func NewVariantBSTR(s string) *VARIANT {
	return &VARIANT{VT: VT_BSTR, Value: s}
}

// NewVariantI4 creates an I4 (int32) variant
func NewVariantI4(v int32) *VARIANT {
	return &VARIANT{VT: VT_I4, Value: v}
}

// NewVariantEmpty creates an empty variant
func NewVariantEmpty() *VARIANT {
	return &VARIANT{VT: VT_EMPTY, Value: nil}
}

// NewVariantDispatch creates a dispatch variant from an IDispatch interface
func NewVariantDispatch(disp *IDispatch) *VARIANT {
	return &VARIANT{VT: VT_DISPATCH, Value: disp}
}

// Marshal serializes a VARIANT
func (v *VARIANT) Marshal(buf *bytes.Buffer) {
	// clSize (wire size - we'll use 5 DWORDS = 20 bytes for most types)
	binary.Write(buf, binary.LittleEndian, uint32(5))

	// reserved1, reserved2, reserved3
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// vt
	binary.Write(buf, binary.LittleEndian, v.VT)

	// wReserved1, wReserved2, wReserved3
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// Value based on type
	switch v.VT {
	case VT_EMPTY, VT_NULL:
		binary.Write(buf, binary.LittleEndian, uint64(0))

	case VT_I4, VT_INT:
		val := v.Value.(int32)
		binary.Write(buf, binary.LittleEndian, val)
		binary.Write(buf, binary.LittleEndian, uint32(0)) // padding

	case VT_BSTR:
		s := v.Value.(string)
		// BSTR pointer
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
		// Actual BSTR data will follow
		writeBSTRData(buf, s)

	case VT_DISPATCH:
		// For dispatch, we write the MInterfacePointer
		disp := v.Value.(*IDispatch)
		if disp != nil && disp.iface != nil {
			// Write interface pointer - this is complex, simplified version
			binary.Write(buf, binary.LittleEndian, uint32(0x00020000))
			// TODO: Write OBJREF for the interface
		} else {
			binary.Write(buf, binary.LittleEndian, uint64(0))
		}

	default:
		// For other types, write zeros
		binary.Write(buf, binary.LittleEndian, uint64(0))
	}
}

// writeBSTR writes a BSTR (length-prefixed UTF-16LE string) with NDR conformant array header
func writeBSTR(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	byteLen := len(utf16Chars) * 2

	// MaxCount (in bytes)
	binary.Write(buf, binary.LittleEndian, uint32(byteLen))
	// Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// ActualCount (in bytes)
	binary.Write(buf, binary.LittleEndian, uint32(byteLen))

	// String data
	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}

// writeBSTRData writes just the BSTR data (for VARIANT)
func writeBSTRData(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	byteLen := uint32(len(utf16Chars) * 2)

	// BSTR: length prefix (in bytes) + UTF-16LE data + null terminator
	// Wire format: MaxCount, Offset, ActualCount, Length, Data
	binary.Write(buf, binary.LittleEndian, byteLen+4) // MaxCount (includes length field)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, byteLen+4) // ActualCount

	// Length prefix for BSTR
	binary.Write(buf, binary.LittleEndian, byteLen)

	// String data
	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Null terminator
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}

// parseGetIDsOfNamesResponse parses the response from GetIDsOfNames
func parseGetIDsOfNamesResponse(resp []byte, count int) ([]int32, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	r := bytes.NewReader(resp)

	// Skip ORPCTHAT (8 bytes)
	r.Seek(8, 0)

	// rgDispId pointer
	var ptr uint32
	binary.Read(r, binary.LittleEndian, &ptr)

	// HRESULT at end
	hresult := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if hresult != 0 {
		return nil, fmt.Errorf("GetIDsOfNames returned HRESULT: 0x%08x", hresult)
	}

	// Find the dispatch IDs in the response
	// They should be after the pointer, as a conformant array
	ids := make([]int32, count)

	// Skip to conformance (after pointer)
	pos := 12
	if pos+4 > len(resp)-4 {
		return nil, fmt.Errorf("cannot read conformance")
	}
	// conformance := binary.LittleEndian.Uint32(resp[pos:])
	pos += 4

	// Read dispatch IDs
	for i := 0; i < count && pos+4 <= len(resp)-4; i++ {
		ids[i] = int32(binary.LittleEndian.Uint32(resp[pos:]))
		pos += 4
	}

	return ids, nil
}

// parseInvokeResponse parses the response from Invoke
func parseInvokeResponse(resp []byte) (*VARIANT, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// HRESULT at end
	hresult := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if hresult != 0 && hresult != 0x80020003 { // DISP_E_MEMBERNOTFOUND is sometimes OK
		return nil, fmt.Errorf("Invoke returned HRESULT: 0x%08x", hresult)
	}

	// For now, return empty variant - parsing the return value is complex
	return NewVariantEmpty(), nil
}

// GetDispatchFromVariant extracts an IDispatch interface from a VARIANT response
func GetDispatchFromVariant(resp []byte, conn *dcom.DCOMConnection) (*IDispatch, error) {
	// Search for OBJREF in response
	for i := 0; i < len(resp)-44; i++ {
		sig := binary.LittleEndian.Uint32(resp[i:])
		if sig == dcom.OBJREF_SIGNATURE {
			flags := binary.LittleEndian.Uint32(resp[i+4:])
			if flags == dcom.FLAGS_OBJREF_STANDARD {
				iface, err := parseStdObjRef(resp[i:], conn)
				if err == nil {
					return NewIDispatch(iface), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no IDispatch interface found in response")
}

// parseStdObjRef parses a standard OBJREF and returns an Interface
func parseStdObjRef(data []byte, conn *dcom.DCOMConnection) (*dcom.Interface, error) {
	if len(data) < 44 {
		return nil, fmt.Errorf("OBJREF_STANDARD too short")
	}

	r := bytes.NewReader(data)

	// Skip signature and flags
	r.Seek(8, 0)

	// IID
	var iid [16]byte
	r.Read(iid[:])

	// STDOBJREF
	var std dcom.STDOBJREF
	binary.Read(r, binary.LittleEndian, &std.Flags)
	binary.Read(r, binary.LittleEndian, &std.CPublicRefs)
	binary.Read(r, binary.LittleEndian, &std.OXID)
	binary.Read(r, binary.LittleEndian, &std.OID)
	r.Read(std.IPID[:])

	return &dcom.Interface{
		IPID:       std.IPID,
		IID:        iid,
		OXID:       std.OXID,
		OID:        std.OID,
		Connection: conn,
	}, nil
}
