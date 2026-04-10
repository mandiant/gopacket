// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package drsuapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/utf16le"
)

// CrackedName represents a single result from DsCrackNames
type CrackedName struct {
	Status    uint32
	DNSDomain string
	Name      string
}

// DsCrackNames translates names from one format to another.
// This is used to get the domain DN from the domain DNS name.
func DsCrackNames(client *dcerpc.Client, hBind []byte, formatOffered, formatDesired uint32, names []string) ([]CrackedName, error) {
	buf := new(bytes.Buffer)

	// [in, ref] DRS_HANDLE hDrs (context handle - 20 bytes)
	if build.Debug {
		log.Printf("[D] DsCrackNames: handle=%x, formatOffered=%d, formatDesired=%d, names=%v",
			hBind, formatOffered, formatDesired, names)
	}
	buf.Write(hBind)

	// [in] DWORD dwInVersion - must be 1
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// [in, ref, switch_is(dwInVersion)] DRS_MSG_CRACKREQ* pmsgIn
	// DRS_MSG_CRACKREQ is an NDR UNION with embedded tag
	binary.Write(buf, binary.LittleEndian, uint32(1)) // Union tag (same as dwInVersion)

	// DRS_MSG_CRACKREQ_V1 structure (not itself conformant):
	//   CodePage, LocaleId, dwFlags, formatOffered, formatDesired, cNames, rpNames
	// rpNames is WCHAR** - pointer to conformant array of string pointers

	// Structure fixed fields
	binary.Write(buf, binary.LittleEndian, uint32(0))                // CodePage (0 = default)
	binary.Write(buf, binary.LittleEndian, uint32(0))                // LocaleId (0 = default)
	binary.Write(buf, binary.LittleEndian, uint32(DS_NAME_NO_FLAGS)) // dwFlags
	binary.Write(buf, binary.LittleEndian, formatOffered)            // formatOffered
	binary.Write(buf, binary.LittleEndian, formatDesired)            // formatDesired
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))       // cNames

	// rpNames - referent ID for the outer pointer (array pointer)
	binary.Write(buf, binary.LittleEndian, uint32(0x00020004)) // Referent ID

	// --- Deferred data for rpNames pointer ---
	// Conformant array: MaxCount (comes with the array data)
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// Array of string pointers (each string is accessed via pointer)
	for i := range names {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020008+uint32(i)*4)) // Referent IDs
	}

	// --- Deferred data for each string pointer ---
	for _, name := range names {
		writeUnicodeString(buf, name)
	}

	if build.Debug {
		log.Printf("[D] DsCrackNames request payload (%d bytes): %x", buf.Len(), buf.Bytes())
	}

	// Call DsCrackNames (OpNum 12)
	var resp []byte
	var err error
	if client.Authenticated {
		resp, err = client.CallAuthAuto(OpDsCrackNames, buf.Bytes())
	} else {
		resp, err = client.Call(OpDsCrackNames, buf.Bytes())
	}
	if err != nil {
		return nil, err
	}

	return parseCrackNamesResponse(resp)
}

func writeUnicodeString(buf *bytes.Buffer, s string) {
	encoded := utf16le.EncodeStringToBytes(s)
	charCount := len(encoded)/2 + 1 // Include null terminator

	// Conformant varying string:
	// MaxCount, Offset, ActualCount, Data, Null
	binary.Write(buf, binary.LittleEndian, uint32(charCount)) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))         // Offset
	binary.Write(buf, binary.LittleEndian, uint32(charCount)) // ActualCount
	buf.Write(encoded)
	buf.Write([]byte{0, 0}) // Null terminator (UTF-16)

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4))
	}
}

func parseCrackNamesResponse(resp []byte) ([]CrackedName, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	if build.Debug {
		log.Printf("[D] DsCrackNames raw response (%d bytes): %x", len(resp), resp)
	}

	r := bytes.NewReader(resp)

	// [out, ref] DWORD* pdwOutVersion
	var outVersion uint32
	binary.Read(r, binary.LittleEndian, &outVersion)

	if build.Debug {
		log.Printf("[D] DsCrackNames response version: %d", outVersion)
	}

	// [out, ref, switch_is(*pdwOutVersion)] DRS_MSG_CRACKREPLY* pmsgOut
	// DRS_MSG_CRACKREPLY is an NDR union with embedded tag
	var unionTag uint32
	binary.Read(r, binary.LittleEndian, &unionTag)

	if build.Debug {
		log.Printf("[D] DsCrackNames reply union tag: %d", unionTag)
	}

	// DRS_MSG_CRACKREPLY_V1 contains a pointer to DS_NAME_RESULTW
	// DS_NAME_RESULTW* (pointer)
	var ptrResult uint32
	binary.Read(r, binary.LittleEndian, &ptrResult)

	if ptrResult == 0 {
		return nil, fmt.Errorf("null result pointer")
	}

	// DS_NAME_RESULTW structure
	// cItems, rItems (pointer)
	var cItems uint32
	binary.Read(r, binary.LittleEndian, &cItems)

	var ptrItems uint32
	binary.Read(r, binary.LittleEndian, &ptrItems)

	if ptrItems == 0 || cItems == 0 {
		return nil, fmt.Errorf("no items in result")
	}

	// Conformant array MaxCount
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	results := make([]CrackedName, cItems)

	// Read array of DS_NAME_RESULT_ITEMW structures
	// Each item: Status, pDomain (ptr), pName (ptr)
	type itemHeader struct {
		Status    uint32
		PtrDomain uint32
		PtrName   uint32
	}

	headers := make([]itemHeader, cItems)
	for i := uint32(0); i < cItems; i++ {
		binary.Read(r, binary.LittleEndian, &headers[i].Status)
		binary.Read(r, binary.LittleEndian, &headers[i].PtrDomain)
		binary.Read(r, binary.LittleEndian, &headers[i].PtrName)
		results[i].Status = headers[i].Status
	}

	// Read deferred string data
	for i := uint32(0); i < cItems; i++ {
		if headers[i].PtrDomain != 0 {
			results[i].DNSDomain = readUnicodeString(r)
		}
		if headers[i].PtrName != 0 {
			results[i].Name = readUnicodeString(r)
		}
		if build.Debug {
			log.Printf("[D] DsCrackNames result[%d]: status=%d, domain=%q, name=%q",
				i, results[i].Status, results[i].DNSDomain, results[i].Name)
		}
	}

	return results, nil
}

func readUnicodeString(r *bytes.Reader) string {
	var maxCount, offset, actualCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	binary.Read(r, binary.LittleEndian, &offset)
	binary.Read(r, binary.LittleEndian, &actualCount)

	if actualCount == 0 {
		return ""
	}

	// Read UTF-16LE data (actualCount includes null terminator)
	data := make([]byte, actualCount*2)
	r.Read(data)

	// Skip padding to 4-byte boundary
	totalRead := 12 + int(actualCount*2)
	if totalRead%4 != 0 {
		r.Seek(int64(4-totalRead%4), 1)
	}

	// Remove null terminator and decode
	if len(data) >= 2 {
		data = data[:len(data)-2] // Remove null terminator
	}
	return utf16le.DecodeToString(data)
}

// GetDomainDN converts a DNS domain name to a distinguished name.
// For example: "corp.local" -> "DC=corp,DC=local"
func GetDomainDN(client *dcerpc.Client, hBind []byte, domainDNS string) (string, error) {
	// Try DsCrackNames first
	results, err := DsCrackNames(client, hBind, DS_DNS_DOMAIN_NAME, DS_FQDN_1779_NAME, []string{domainDNS})
	if err == nil && len(results) > 0 && results[0].Status == DS_NAME_NO_ERROR {
		return results[0].Name, nil
	}

	// Fallback: construct DN from domain name parts
	// corp.local -> DC=corp,DC=local
	if build.Debug && err != nil {
		log.Printf("[D] DsCrackNames failed (%v), constructing DN from domain name", err)
	}

	return DomainDNSToLDAP(domainDNS), nil
}

// DomainDNSToLDAP converts a DNS domain name to LDAP DN format.
// Example: "corp.local" -> "DC=corp,DC=local"
func DomainDNSToLDAP(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		if part != "" {
			dnParts = append(dnParts, "DC="+part)
		}
	}
	return strings.Join(dnParts, ",")
}
