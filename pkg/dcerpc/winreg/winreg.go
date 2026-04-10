// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package winreg

// MS-RRP (Windows Remote Registry Protocol)
// UUID: 338CD001-2244-31F1-AAAA-900038001003 v1.0

var UUID = [16]byte{
	0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31,
	0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03,
}

const MajorVersion = 1
const MinorVersion = 0

// Operation numbers (MS-RRP 3.1.5)
const (
	OpOpenClassesRoot             = 0
	OpOpenCurrentUser             = 1
	OpOpenLocalMachine            = 2
	OpOpenPerformanceData         = 3
	OpOpenUsers                   = 4
	OpBaseRegCloseKey             = 5
	OpBaseRegCreateKey            = 6
	OpBaseRegDeleteKey            = 7
	OpBaseRegDeleteValue          = 8
	OpBaseRegEnumKey              = 9
	OpBaseRegEnumValue            = 10
	OpBaseRegFlushKey             = 11
	OpBaseRegGetKeySecurity       = 12
	OpBaseRegLoadKey              = 13
	OpBaseRegOpenKey              = 15
	OpBaseRegQueryInfoKey         = 16
	OpBaseRegQueryValue           = 17
	OpBaseRegReplaceKey           = 18
	OpBaseRegRestoreKey           = 19
	OpBaseRegSaveKey              = 20
	OpBaseRegSetKeySecurity       = 21
	OpBaseRegSetValue             = 22
	OpBaseRegUnLoadKey            = 23
	OpBaseRegGetVersion           = 26
	OpOpenCurrentConfig           = 27
	OpBaseRegQueryMultipleValues  = 29
	OpBaseRegSaveKeyEx            = 31
	OpOpenPerformanceText         = 32
	OpOpenPerformanceNlsText      = 33
	OpBaseRegQueryMultipleValues2 = 34
	OpBaseRegDeleteKeyEx          = 35
)

// REGSAM - Registry security access mask (MS-RRP 2.2.3)
const (
	KEY_QUERY_VALUE        = 0x00000001
	KEY_SET_VALUE          = 0x00000002
	KEY_CREATE_SUB_KEY     = 0x00000004
	KEY_ENUMERATE_SUB_KEYS = 0x00000008
	KEY_NOTIFY             = 0x00000010
	KEY_CREATE_LINK        = 0x00000020
	KEY_WOW64_64KEY        = 0x00000100
	KEY_WOW64_32KEY        = 0x00000200
	KEY_READ               = 0x00020019
	KEY_WRITE              = 0x00020006
	KEY_EXECUTE            = 0x00020019
	KEY_ALL_ACCESS         = 0x000F003F
	MAXIMUM_ALLOWED        = 0x02000000
)

// REG value types (MS-RRP 2.2.6)
const (
	REG_NONE                       = 0
	REG_SZ                         = 1
	REG_EXPAND_SZ                  = 2
	REG_BINARY                     = 3
	REG_DWORD                      = 4
	REG_DWORD_BIG_ENDIAN           = 5
	REG_LINK                       = 6
	REG_MULTI_SZ                   = 7
	REG_RESOURCE_LIST              = 8
	REG_FULL_RESOURCE_DESCRIPTOR   = 9
	REG_RESOURCE_REQUIREMENTS_LIST = 10
	REG_QWORD                      = 11
)

// Error codes (MS-RRP 2.2.7)
const (
	ERROR_SUCCESS             = 0
	ERROR_FILE_NOT_FOUND      = 2
	ERROR_ACCESS_DENIED       = 5
	ERROR_INVALID_HANDLE      = 6
	ERROR_OUTOFMEMORY         = 14
	ERROR_INVALID_PARAMETER   = 87
	ERROR_INSUFFICIENT_BUFFER = 122
	ERROR_MORE_DATA           = 234
	ERROR_NO_MORE_ITEMS       = 259
	ERROR_KEY_DELETED         = 1018
)
