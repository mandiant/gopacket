// SPDX-License-Identifier: Apache-2.0

// Package wmi implements the WMI Remote Protocol (MS-WMI).
package wmi

import (
	"gopacket/pkg/dcerpc"
)

// WMI UUIDs
var (
	// CLSID for WbemLevel1Login - the entry point for WMI
	CLSID_WbemLevel1Login = dcerpc.MustParseUUID("8BC3F05E-D86B-11D0-A075-00C04FB68820")

	// IID for IWbemLevel1Login interface
	IID_IWbemLevel1Login = dcerpc.MustParseUUID("F309AD18-D86A-11d0-A075-00C04FB68820")

	// IID for IWbemServices interface
	IID_IWbemServices = dcerpc.MustParseUUID("9556DC99-828C-11CF-A37E-00AA003240C7")

	// IID for IWbemClassObject interface
	IID_IWbemClassObject = dcerpc.MustParseUUID("DC12A681-737F-11CF-884D-00AA004B2E24")

	// IID for IEnumWbemClassObject interface
	IID_IEnumWbemClassObject = dcerpc.MustParseUUID("027947e1-d731-11ce-a357-000000000001")
)

// WMI operation numbers
const (
	// IWbemLevel1Login operations
	OpIWbemLevel1Login_NTLMLogin = 6

	// IWbemServices operations
	OpIWbemServices_OpenNamespace = 3
	OpIWbemServices_GetObject     = 6
	OpIWbemServices_ExecQuery     = 20
	OpIWbemServices_ExecMethod    = 24
)

// WBEM flags
const (
	WBEM_FLAG_RETURN_WBEM_COMPLETE   = 0x00000000
	WBEM_FLAG_RETURN_IMMEDIATELY     = 0x00000010
	WBEM_FLAG_FORWARD_ONLY           = 0x00000020
	WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x00020000
)

// WBEM status codes
const (
	WBEM_S_NO_ERROR          = 0x00000000
	WBEM_S_FALSE             = 0x00000001
	WBEM_E_FAILED            = 0x80041001
	WBEM_E_NOT_FOUND         = 0x80041002
	WBEM_E_ACCESS_DENIED     = 0x80041003
	WBEM_E_INVALID_NAMESPACE = 0x8004100E
	WBEM_E_INVALID_CLASS     = 0x80041010
)

// WMIO constants
const (
	WMIO_SIGNATURE = 0x12345678
)

// CIM types
const (
	CIM_TYPE_SINT8     = 16
	CIM_TYPE_UINT8     = 17
	CIM_TYPE_SINT16    = 2
	CIM_TYPE_UINT16    = 18
	CIM_TYPE_SINT32    = 3
	CIM_TYPE_UINT32    = 19
	CIM_TYPE_SINT64    = 20
	CIM_TYPE_UINT64    = 21
	CIM_TYPE_REAL32    = 4
	CIM_TYPE_REAL64    = 5
	CIM_TYPE_BOOLEAN   = 11
	CIM_TYPE_STRING    = 8
	CIM_TYPE_DATETIME  = 101
	CIM_TYPE_REFERENCE = 102
	CIM_TYPE_CHAR16    = 103
	CIM_TYPE_OBJECT    = 13
	CIM_ARRAY_FLAG     = 0x2000
)
