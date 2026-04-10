// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package tds

// MC-SQLR Constants (SQL Server Resolution Protocol)
const (
	SQLRPort          = 1434
	SQLRClntBcastEx   = 0x02
	SQLRClntUcastEx   = 0x03
	SQLRClntUcastInst = 0x04
	SQLRClntUcastDAC  = 0x0f
)

// TDS Packet Types
const (
	TDSSQLBatch     = 1
	TDSPreTDSLogin  = 2
	TDSRPC          = 3
	TDSTabular      = 4
	TDSAttention    = 6
	TDSBulkLoadData = 7
	TDSTransaction  = 14
	TDSLogin7       = 16
	TDSSSPI         = 17
	TDSPreLogin     = 18
)

// TDS Status
const (
	TDSStatusNormal          = 0
	TDSStatusEOM             = 1
	TDSStatusResetConnection = 8
	TDSStatusResetSkiptrans  = 16
)

// TDS Encryption
const (
	TDSEncryptOff    = 0
	TDSEncryptOn     = 1
	TDSEncryptNotSup = 2
	TDSEncryptReq    = 3
)

// Option Flags
const (
	TDSIntegratedSecurityOn = 0x80
	TDSInitLangFatal        = 0x01
	TDSODBCOn               = 0x02
)

// Token Types
const (
	TDSAltMetadataToken  = 0x88
	TDSAltRowToken       = 0xD3
	TDSColMetadataToken  = 0x81
	TDSColInfoToken      = 0xA5
	TDSDoneToken         = 0xFD
	TDSDoneProcToken     = 0xFE
	TDSDoneInProcToken   = 0xFF
	TDSEnvChangeToken    = 0xE3
	TDSErrorToken        = 0xAA
	TDSInfoToken         = 0xAB
	TDSLoginAckToken     = 0xAD
	TDSNBCRowToken       = 0xD2
	TDSOffsetToken       = 0x78
	TDSOrderToken        = 0xA9
	TDSReturnStatusToken = 0x79
	TDSReturnValueToken  = 0xAC
	TDSRowToken          = 0xD1
	TDSSSPIToken         = 0xED
	TDSTabNameToken      = 0xA4
)

// ENVCHANGE Types
const (
	TDSEnvChangeDatabase    = 1
	TDSEnvChangeLanguage    = 2
	TDSEnvChangeCharset     = 3
	TDSEnvChangePacketSize  = 4
	TDSEnvChangeUnicode     = 5
	TDSEnvChangeUnicodeDS   = 6
	TDSEnvChangeCollation   = 7
	TDSEnvChangeTransStart  = 8
	TDSEnvChangeTransCommit = 9
	TDSEnvChangeRollback    = 10
	TDSEnvChangeDTC         = 11
)

// Column Types - Fixed Length
const (
	TDSNullType     = 0x1F
	TDSInt1Type     = 0x30
	TDSBitType      = 0x32
	TDSInt2Type     = 0x34
	TDSInt4Type     = 0x38
	TDSDateTim4Type = 0x3A
	TDSFlt4Type     = 0x3B
	TDSMoneyType    = 0x3C
	TDSDateTimeType = 0x3D
	TDSFlt8Type     = 0x3E
	TDSMoney4Type   = 0x7A
	TDSInt8Type     = 0x7F
)

// Column Types - Variable Length
const (
	TDSGuidType            = 0x24
	TDSIntNType            = 0x26
	TDSDecimalType         = 0x37
	TDSNumericType         = 0x3F
	TDSBitNType            = 0x68
	TDSDecimalNType        = 0x6A
	TDSNumericNType        = 0x6C
	TDSFltNType            = 0x6D
	TDSMoneyNType          = 0x6E
	TDSDateTimNType        = 0x6F
	TDSDateNType           = 0x28
	TDSTimeNType           = 0x29
	TDSDateTime2NType      = 0x2A
	TDSDateTimeOffsetNType = 0x2B
	TDSCharType            = 0x2F
	TDSVarCharType         = 0x27
	TDSBinaryType          = 0x2D
	TDSVarBinaryType       = 0x25
	TDSBigVarBinType       = 0xA5
	TDSBigVarChrType       = 0xA7
	TDSBigBinaryType       = 0xAD
	TDSBigCharType         = 0xAF
	TDSNVarCharType        = 0xE7
	TDSNCharType           = 0xEF
	TDSXMLType             = 0xF1
	TDSUDTType             = 0xF0
	TDSTextType            = 0x23
	TDSImageType           = 0x22
	TDSNTextType           = 0x63
	TDSSSVariantType       = 0x62
)
