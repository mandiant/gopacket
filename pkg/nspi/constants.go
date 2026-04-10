// SPDX-License-Identifier: Apache-2.0

// Package nspi implements MS-NSPI (Name Service Provider Interface) protocol
// for querying Exchange address books via RPC over HTTP v2.
// This is a modular library that can be used by multiple tools.
package nspi

import (
	"github.com/google/uuid"
)

// NSPI interface UUID
var MSRPC_UUID_NSPI = uuid.MustParse("F5CC5A18-4264-101A-8C59-08002B2F8426")

// UUIDToMSRPC converts a google/uuid.UUID (RFC 4122, big-endian) to
// MS-RPC mixed-endian wire format: Data1(LE), Data2(LE), Data3(LE), Data4(BE)
func UUIDToMSRPC(u uuid.UUID) [16]byte {
	b := u[:]
	var result [16]byte
	// Data1: uint32 LE
	result[0] = b[3]
	result[1] = b[2]
	result[2] = b[1]
	result[3] = b[0]
	// Data2: uint16 LE
	result[4] = b[5]
	result[5] = b[4]
	// Data3: uint16 LE
	result[6] = b[7]
	result[7] = b[6]
	// Data4: 8 bytes as-is
	copy(result[8:], b[8:])
	return result
}

// Interface version
const (
	NSPI_VERSION_MAJOR = 56
	NSPI_VERSION_MINOR = 0
)

// Property type values (2.2.1)
const (
	PtypEmbeddedTable = 0x0000000D
	PtypNull          = 0x00000001
	PtypUnspecified   = 0x00000000
	PtypInteger16     = 0x00000002
	PtypInteger32     = 0x00000003
	PtypFloating32    = 0x00000004
	PtypFloating64    = 0x00000005
	PtypCurrency      = 0x00000006
	PtypFloatingTime  = 0x00000007
	PtypErrorCode     = 0x0000000A
	PtypBoolean       = 0x0000000B
	PtypInteger64     = 0x00000014
	PtypString8       = 0x0000001E
	PtypString        = 0x0000001F
	PtypTime          = 0x00000040
	PtypGuid          = 0x00000048
	PtypBinary        = 0x00000102
	PtypMultipleInt16 = 0x00001002
	PtypMultipleInt32 = 0x00001003
	PtypMultipleStr8  = 0x0000101E
	PtypMultipleStr   = 0x0000101F
	PtypMultipleTime  = 0x00001040
	PtypMultipleGuid  = 0x00001048
	PtypMultipleBin   = 0x00001102
)

// Display Type Values (2.2.3)
const (
	DT_MAILUSER         = 0x00000000
	DT_DISTLIST         = 0x00000001
	DT_FORUM            = 0x00000002
	DT_AGENT            = 0x00000003
	DT_ORGANIZATION     = 0x00000004
	DT_PRIVATE_DISTLIST = 0x00000005
	DT_REMOTE_MAILUSER  = 0x00000006
	DT_CONTAINER        = 0x00000100
	DT_TEMPLATE         = 0x00000101
	DT_ADDRESS_TEMPLATE = 0x00000102
	DT_SEARCH           = 0x00000200
)

// Default Language Code Identifier (2.2.4)
const NSPI_DEFAULT_LOCALE = 0x00000409

// Required Codepages (2.2.5)
const (
	CP_TELETEX    = 0x00004F25
	CP_WINUNICODE = 0x000004B0
)

// Comparison Flags (2.2.6.1)
const (
	NORM_IGNORECASE     = 1 << 0
	NORM_IGNORENONSPACE = 1 << 1
	NORM_IGNORESYMBOLS  = 1 << 2
	SORT_STRINGSORT     = 1 << 12
	NORM_IGNOREKANATYPE = 1 << 16
	NORM_IGNOREWIDTH    = 1 << 17
)

// Permanent Entry ID GUID (2.2.7)
var GUID_NSPI = uuid.MustParse("C840A7DC-42C0-1A10-B4B9-08002B2FE182")

// Positioning Minimal Entry IDs (2.2.8)
const (
	MID_BEGINNING_OF_TABLE = 0x00000000
	MID_END_OF_TABLE       = 0x00000002
	MID_CURRENT            = 0x00000001
)

// Ambiguous Name Resolution Minimal Entry IDs (2.2.9)
const (
	MID_UNRESOLVED = 0x00000000
	MID_AMBIGUOUS  = 0x00000001
	MID_RESOLVED   = 0x00000002
)

// Table Sort Orders (2.2.10)
const (
	SortTypeDisplayName         = 0
	SortTypePhoneticDisplayName = 0x00000003
	SortTypeDisplayName_RO      = 0x000003E8
	SortTypeDisplayName_W       = 0x000003E9
)

// NspiBind Flags (2.2.11)
const (
	FAnonymousLogin = 0x00000020
)

// Retrieve Property Flags (2.2.12)
const (
	FSkipObjects = 0x00000001
	FEphID       = 0x00000002
)

// NspiGetSpecialTable Flags (2.2.13)
const (
	NspiAddressCreationTemplates = 0x00000002
	NspiUnicodeStrings           = 0x00000004
)

// NspiQueryColumns Flags (2.2.14)
const (
	NspiUnicodeProptypes = 0x80000000
)

// NspiGetIDsFromNames Flags (2.2.15)
const (
	NspiVerifyNames = 0x00000002
)

// NspiGetTemplateInfo Flags (2.2.16)
const (
	TI_TEMPLATE          = 0x00000001
	TI_SCRIPT            = 0x00000004
	TI_EMT               = 0x00000010
	TI_HELPFILE_NAME     = 0x00000020
	TI_HELPFILE_CONTENTS = 0x00000040
)

// NspiModLinkAtt Flags (2.2.17)
const (
	FDelete = 0x00000001
)

// NSPI Operation Numbers
const (
	OP_NspiBind            = 0
	OP_NspiUnbind          = 1
	OP_NspiUpdateStat      = 2
	OP_NspiQueryRows       = 3
	OP_NspiSeekEntries     = 4
	OP_NspiGetMatches      = 5
	OP_NspiResortRestrict  = 6
	OP_NspiDNToMId         = 7
	OP_NspiGetPropList     = 8
	OP_NspiGetProps        = 9
	OP_NspiCompareMIds     = 10
	OP_NspiModProps        = 11
	OP_NspiGetSpecialTable = 12
	OP_NspiGetTemplateInfo = 13
	OP_NspiModLinkAtt      = 14
	OP_NspiQueryColumns    = 16
	OP_NspiResolveNames    = 19
	OP_NspiResolveNamesW   = 20
)
