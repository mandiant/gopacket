// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package netlogon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

// MS-NRPC (Netlogon Remote Protocol)
// UUID: 12345678-1234-ABCD-EF00-01234567CFFB v1.0

var UUID = [16]byte{
	0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB,
	0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0xCF, 0xFB,
}

const MajorVersion = 1
const MinorVersion = 0

// Opnums
const (
	OpDsrGetDcNameEx = 27
)

// DS_FLAG constants for DsrGetDcNameEx Flags parameter
const (
	DS_FORCE_REDISCOVERY = 0x00000001
	DS_RETURN_DNS_NAME   = 0x40000000
	DS_RETURN_FLAT_NAME  = 0x80000000
	DS_IS_FLAT_NAME      = 0x00008000
	DS_IS_DNS_NAME       = 0x00020000
)

// DomainControllerInfo holds the result from DsrGetDcNameEx
type DomainControllerInfo struct {
	DomainControllerName        string
	DomainControllerAddress     string
	DomainControllerAddressType uint32
	DomainGUID                  [16]byte
	DomainName                  string
	DnsForestName               string
	Flags                       uint32
	DcSiteName                  string
	ClientSiteName              string
}

// DsrGetDcNameEx calls Opnum 27 to locate a domain controller.
// Pass empty strings for parameters you want to be NULL.
// With domainName="" and flags=0, returns info about the current domain including
// DnsForestName which identifies the forest root.
func DsrGetDcNameEx(client *dcerpc.Client, computerName, domainName string, flags uint32) (*DomainControllerInfo, error) {
	buf := new(bytes.Buffer)

	// Parameter 1: ComputerName (PLOGONSRV_HANDLE = unique pointer to wchar_t string)
	if computerName != "" {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // non-NULL referent
		writeWideString(buf, computerName)
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL
	}

	// Parameter 2: DomainName (unique pointer to wchar_t string)
	if domainName != "" {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020004)) // non-NULL referent
		writeWideString(buf, domainName)
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL
	}

	// Parameter 3: DomainGuid (unique pointer to GUID, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Parameter 4: SiteName (unique pointer to wchar_t string, NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Parameter 5: Flags (ULONG)
	binary.Write(buf, binary.LittleEndian, flags)

	resp, err := client.Call(OpDsrGetDcNameEx, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("DsrGetDcNameEx call failed: %v", err)
	}

	return parseDCInfoResponse(resp)
}

func parseDCInfoResponse(resp []byte) (*DomainControllerInfo, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short (%d bytes)", len(resp))
	}

	// ReturnValue is at the end (4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		return nil, fmt.Errorf("DsrGetDcNameEx failed: 0x%08x", retVal)
	}

	offset := 0

	// Unique pointer to DOMAIN_CONTROLLER_INFOW
	dcInfoPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if dcInfoPtr == 0 {
		return nil, fmt.Errorf("NULL DomainControllerInfo returned")
	}

	info := &DomainControllerInfo{}

	// DOMAIN_CONTROLLER_INFOW fixed part (48 bytes):
	//   DomainControllerName pointer (4)
	//   DomainControllerAddress pointer (4)
	//   DomainControllerAddressType (4)
	//   DomainGuid (16)
	//   DomainName pointer (4)
	//   DnsForestName pointer (4)
	//   Flags (4)
	//   DcSiteName pointer (4)
	//   ClientSiteName pointer (4)

	endData := len(resp) - 4 // exclude ReturnValue
	if offset+48 > endData {
		return nil, fmt.Errorf("response too short for DOMAIN_CONTROLLER_INFOW")
	}

	dcNamePtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	dcAddrPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	info.DomainControllerAddressType = binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	copy(info.DomainGUID[:], resp[offset:offset+16])
	offset += 16
	domNamePtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	forestNamePtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	info.Flags = binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	dcSitePtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4
	clientSitePtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	// Read deferred string data in order of pointer fields
	readStr := func(ptr uint32) string {
		if ptr == 0 || offset+12 > endData {
			return ""
		}
		_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
		offset += 4
		_ = binary.LittleEndian.Uint32(resp[offset:]) // Offset
		offset += 4
		actualCount := binary.LittleEndian.Uint32(resp[offset:])
		offset += 4

		dataLen := int(actualCount) * 2
		if offset+dataLen > endData {
			return ""
		}
		s := readUTF16(resp[offset:], int(actualCount))
		offset += dataLen
		// Align to 4 bytes
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
		return s
	}

	info.DomainControllerName = stripLeadingBackslashes(readStr(dcNamePtr))
	info.DomainControllerAddress = stripLeadingBackslashes(readStr(dcAddrPtr))
	info.DomainName = readStr(domNamePtr)
	info.DnsForestName = readStr(forestNamePtr)
	info.DcSiteName = readStr(dcSitePtr)
	info.ClientSiteName = readStr(clientSitePtr)

	return info, nil
}

// stripLeadingBackslashes removes leading \\ from DC names/addresses
func stripLeadingBackslashes(s string) string {
	return strings.TrimLeft(s, "\\")
}

func writeWideString(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // null terminator
	charCount := uint32(len(utf16Chars))

	binary.Write(buf, binary.LittleEndian, charCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, charCount) // ActualCount

	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}

func readUTF16(data []byte, charCount int) string {
	if len(data) < charCount*2 {
		charCount = len(data) / 2
	}
	u16s := make([]uint16, charCount)
	for i := 0; i < charCount; i++ {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}
