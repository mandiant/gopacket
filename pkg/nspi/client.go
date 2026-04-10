// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package nspi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"unicode/utf16"

	"gopacket/internal/build"
	"gopacket/pkg/mapi"
	"gopacket/pkg/rpch"
	"gopacket/pkg/session"

	"github.com/google/uuid"
)

// Client is an NSPI protocol client
type Client struct {
	Transport *rpch.AuthTransport
	Handler   ContextHandle
	Stat      *STAT
	CallID    uint32

	// Address book hierarchy (map for lookup, slice for insertion order)
	HTable      map[int32]*AddressBookEntry
	HTableOrder []int32

	// Cached properties list
	Properties []PropertyTag

	// Any existing container ID for queries
	AnyExistingContainerID int32

	// Kerberos authentication
	useKerberos bool
	kerbCreds   *session.Credentials
}

// NewClient creates a new NSPI client
func NewClient(remoteName, rpcHostname string) *Client {
	transport := rpch.NewAuthTransport(remoteName)
	transport.RPCHostname = rpcHostname

	return &Client{
		Transport:              transport,
		Stat:                   NewSTAT(),
		CallID:                 1,
		HTable:                 make(map[int32]*AddressBookEntry),
		AnyExistingContainerID: -1,
	}
}

// SetKerberosConfig enables Kerberos authentication for this client
func (c *Client) SetKerberosConfig(useKerberos bool, creds *session.Credentials) {
	c.useKerberos = useKerberos
	c.kerbCreds = creds
}

// SetCredentials sets authentication credentials
func (c *Client) SetCredentials(username, password, domain string, hashes string) {
	var lmhash, nthash string
	if hashes != "" {
		parts := strings.Split(hashes, ":")
		if len(parts) == 2 {
			lmhash = parts[0]
			nthash = parts[1]
		}
	}
	c.Transport.SetCredentials(username, password, domain, lmhash, nthash)
}

// Connect establishes the RPC over HTTP connection and binds to NSPI
func (c *Client) Connect() error {
	// Connect transport - use Kerberos or NTLM
	if c.useKerberos && c.kerbCreds != nil {
		if err := c.Transport.ConnectWithKerberos(c.kerbCreds); err != nil {
			return fmt.Errorf("transport connect failed: %v", err)
		}
	} else {
		if err := c.Transport.ConnectWithNTLM(); err != nil {
			return fmt.Errorf("transport connect failed: %v", err)
		}
	}

	// Bind to NSPI interface
	// Convert UUID from RFC 4122 (big-endian) to MS-RPC (mixed-endian) wire format
	uuidBytes := UUIDToMSRPC(MSRPC_UUID_NSPI)

	if err := c.Transport.RPCBind(uuidBytes, NSPI_VERSION_MAJOR, NSPI_VERSION_MINOR); err != nil {
		return fmt.Errorf("RPC bind failed: %v", err)
	}

	// NspiBind
	if err := c.bind(); err != nil {
		return fmt.Errorf("NSPI bind failed: %v", err)
	}

	return nil
}

// bind performs NspiBind operation
func (c *Client) bind() error {
	buf := new(bytes.Buffer)

	// dwFlags (DWORD)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pStat (STAT)
	buf.Write(c.Stat.Marshal())

	// pServerGuid - [in, out, unique] FlatUID_r* - non-null pointer to all-zero GUID
	binary.Write(buf, binary.LittleEndian, uint32(1)) // non-null referent
	buf.Write(make([]byte, 16))                       // FlatUID_r (16 zero bytes)

	if build.Debug {
		data := buf.Bytes()
		log.Printf("[D] NSPI: Bind request (%d bytes): %x", len(data), data)
	}

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiBind, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return err
	}

	if build.Debug {
		log.Printf("[D] NSPI: Bind response stub (%d bytes): %x", len(resp), resp)
	}

	if len(resp) < 28 {
		return fmt.Errorf("response too short: %d", len(resp))
	}

	// NspiBindResponse format (IDL parameter order):
	//   pServerGuid (PFlatUID_r, pointer: 4 byte referent + 16 byte data if non-null)
	//   contextHandle (handle_t, 20 bytes)
	//   ErrorCode (DWORD, 4 bytes)
	offset := 0

	// Skip pServerGuid pointer
	ppRef := binary.LittleEndian.Uint32(resp[offset : offset+4])
	offset += 4
	if ppRef != 0 {
		// Non-null pointer: skip 16 bytes of FlatUID_r data
		offset += 16
	}

	// Parse context handle (20 bytes)
	if offset+20 > len(resp) {
		return fmt.Errorf("response too short for context handle")
	}
	if err := c.Handler.Unmarshal(resp[offset : offset+20]); err != nil {
		return fmt.Errorf("failed to parse context handle: %v", err)
	}
	offset += 20

	if offset+4 > len(resp) {
		return fmt.Errorf("response too short for error code")
	}

	// Return value (4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[offset : offset+4])
	if retVal != 0 {
		if msg, ok := mapi.ErrorMessages[retVal]; ok {
			return fmt.Errorf("NspiBind failed: %s (0x%08x)", msg, retVal)
		}
		return fmt.Errorf("NspiBind failed: 0x%08x", retVal)
	}

	if build.Debug {
		log.Printf("[D] NSPI: Bind successful, handle: %x", c.Handler.UUID)
	}

	return nil
}

// Unbind performs NspiUnbind operation
func (c *Client) Unbind() error {
	buf := new(bytes.Buffer)

	// contextHandle
	buf.Write(c.Handler.Marshal())

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiUnbind, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return err
	}

	if len(resp) >= 4 {
		retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if retVal != 1 { // 1 = success for unbind
			return fmt.Errorf("NspiUnbind unexpected return: %d", retVal)
		}
	}

	return nil
}

// Disconnect closes the connection
func (c *Client) Disconnect() error {
	if !c.Handler.IsNull() {
		c.Unbind()
	}
	return c.Transport.Close()
}

// UpdateStat performs NspiUpdateStat operation
func (c *Client) UpdateStat(containerID int32) error {
	c.Stat.ContainerID = uint32(intToDword(containerID))

	buf := new(bytes.Buffer)

	// contextHandle
	buf.Write(c.Handler.Marshal())

	// Reserved
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pStat
	buf.Write(c.Stat.Marshal())

	// plDelta - pointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiUpdateStat, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return err
	}

	if len(resp) < 40 {
		return fmt.Errorf("response too short")
	}

	// Parse updated STAT
	if err := c.Stat.Unmarshal(resp[:36]); err != nil {
		return err
	}

	if build.Debug {
		log.Printf("[D] NSPI: UpdateStat response (%d bytes): ContainerID=%d CurrentRec=%d TotalRecs=%d NumPos=%d",
			len(resp), c.Stat.ContainerID, c.Stat.CurrentRec, c.Stat.TotalRecs, c.Stat.NumPos)
	}

	// Return value
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		if msg, ok := mapi.ErrorMessages[retVal]; ok {
			return fmt.Errorf("NspiUpdateStat failed: %s (0x%08x)", msg, retVal)
		}
		return fmt.Errorf("NspiUpdateStat failed: 0x%08x", retVal)
	}

	return nil
}

// GetSpecialTable performs NspiGetSpecialTable operation to get address book hierarchy
func (c *Client) GetSpecialTable() error {
	buf := new(bytes.Buffer)

	// contextHandle
	buf.Write(c.Handler.Marshal())

	// dwFlags
	binary.Write(buf, binary.LittleEndian, uint32(NspiUnicodeStrings))

	// pStat - PSTAT is a POINTER to STAT, inline with referent ID
	binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // non-null referent
	buf.Write(c.Stat.Marshal())

	// lpVersion - LPDWORD pointer (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	if build.Debug {
		data := buf.Bytes()
		log.Printf("[D] NSPI: GetSpecialTable request (%d bytes): %x", len(data), data)
	}

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiGetSpecialTable, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return err
	}

	if len(resp) < 8 {
		return fmt.Errorf("response too short")
	}

	// Parse response
	// Format: [lpVersion DWORD][ppRows PropertyRowSet_r][ReturnValue DWORD]
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		if msg, ok := mapi.ErrorMessages[retVal]; ok {
			return fmt.Errorf("NspiGetSpecialTable failed: %s (0x%08x)", msg, retVal)
		}
		return fmt.Errorf("NspiGetSpecialTable failed: 0x%08x", retVal)
	}

	// Response format: [lpVersion DWORD][ppRows referent DWORD][PropertyRowSet_r data...][ErrorCode DWORD]
	// Skip lpVersion (4 bytes) and ppRows pointer referent (4 bytes)
	if len(resp) < 12 {
		return fmt.Errorf("response too short for lpVersion + ppRows")
	}

	// Check ppRows referent
	ppRef := binary.LittleEndian.Uint32(resp[4:8])
	if ppRef == 0 {
		// Null pointer - no data
		return fmt.Errorf("server returned null ppRows")
	}

	// Parse the PropertyRowSet starting after lpVersion(4) + ppRows referent(4)
	hierarchyData := resp[8 : len(resp)-4]

	if build.Debug {
		log.Printf("[D] NSPI: GetSpecialTable response size: %d bytes (hierarchy data: %d bytes)",
			len(resp), len(hierarchyData))
		// Dump first 32 bytes of response to understand structure
		end := len(resp)
		if end > 64 {
			end = 64
		}
		log.Printf("[D] NSPI: GetSpecialTable resp head: %x", resp[:end])
	}

	c.parseHierarchyTable(hierarchyData)

	return nil
}

// parseHierarchyTable parses the address book hierarchy from GetSpecialTable response
func (c *Client) parseHierarchyTable(data []byte) {
	c.HTable = make(map[int32]*AddressBookEntry)
	c.HTableOrder = nil

	// The hierarchy table is a PropertyRowSet_r with properties:
	// PR_DISPLAY_NAME (0x3001001F), PR_ENTRYID (0x0FFF0102),
	// PR_CONTAINER_FLAGS (0x36000003), PR_DEPTH (0x30050003),
	// PR_EMS_AB_CONTAINERID (0xFFFD0003), PR_EMS_AB_PARENT_ENTRYID (0xFFFC0102),
	// PR_EMS_AB_IS_MASTER (0xFFFB000B)
	// These are NOT specified by us - the server sends them with their actual tags
	// embedded in each PropertyValue_r's ulPropTag field.

	// Parse using the NDR parser - we don't pass propTags since the server
	// includes ulPropTag in each PropertyValue_r
	rowSet, err := ParsePropertyRowSet(data, nil)
	if err != nil {
		if build.Debug {
			log.Printf("[D] NSPI: Error parsing hierarchy table: %v", err)
		}
		// Fallback to default GAL only
		c.HTable[0] = &AddressBookEntry{
			MId:   0,
			Name:  "Default Global Address List",
			Flags: mapi.AB_RECIPIENTS | mapi.AB_SUBCONTAINERS,
			Depth: 0,
		}
		return
	}

	if build.Debug {
		log.Printf("[D] NSPI: Hierarchy table has %d rows", len(rowSet.Rows))
	}

	for _, row := range rowSet.Rows {
		props := SimplifyPropertyRow(&row)

		entry := &AddressBookEntry{
			Properties: props,
		}

		// Extract MId from PR_EMS_AB_CONTAINERID (0xFFFD0003)
		if v, ok := props[PropertyTag(mapi.PR_EMS_AB_CONTAINERID)]; ok {
			if mid, ok := v.(int32); ok {
				entry.MId = mid
			}
		}

		// Extract display name from PR_DISPLAY_NAME (0x3001001F)
		if v, ok := props[PropertyTag(mapi.PR_DISPLAY_NAME)]; ok {
			if name, ok := v.(string); ok {
				entry.Name = name
			}
		}

		// For MId 0 (GAL), override name
		if entry.MId == 0 {
			entry.Name = "Default Global Address List"
		}

		// Extract GUID from PR_ENTRYID (0x0FFF0102)
		if v, ok := props[PropertyTag(mapi.PR_ENTRYID)]; ok {
			if bin, ok := v.(BinaryObject); ok {
				entry.GUID = GetGUIDFromDN([]byte(bin))
			}
		}

		// Extract container flags from PR_CONTAINER_FLAGS (0x36000003)
		if v, ok := props[PropertyTag(mapi.PR_CONTAINER_FLAGS)]; ok {
			if flags, ok := v.(int32); ok {
				entry.Flags = uint32(flags)
			}
		}

		// Extract depth from PR_DEPTH (0x30050003)
		if v, ok := props[PropertyTag(mapi.PR_DEPTH)]; ok {
			if depth, ok := v.(int32); ok {
				entry.Depth = uint32(depth)
			}
		}

		// Extract is_master from PR_EMS_AB_IS_MASTER (0xFFFB000B)
		if v, ok := props[PropertyTag(mapi.PR_EMS_AB_IS_MASTER)]; ok {
			if master, ok := v.(bool); ok {
				entry.IsMaster = master
			}
		}

		// Extract parent GUID from PR_EMS_AB_PARENT_ENTRYID (0xFFFC0102)
		if v, ok := props[PropertyTag(mapi.PR_EMS_AB_PARENT_ENTRYID)]; ok {
			if bin, ok := v.(BinaryObject); ok {
				entry.ParentGUID = GetGUIDFromDN([]byte(bin))
			}
		}

		c.HTable[entry.MId] = entry
		c.HTableOrder = append(c.HTableOrder, entry.MId)

		if build.Debug {
			guidStr := "None"
			if entry.GUID != nil {
				guidStr = FormatGUID(entry.GUID)
			}
			log.Printf("[D] NSPI: Hierarchy entry MId=%d name=%q guid=%s depth=%d flags=0x%x",
				entry.MId, entry.Name, guidStr, entry.Depth, entry.Flags)
		}
	}

	// Ensure GAL entry exists at MId 0
	if _, ok := c.HTable[0]; !ok {
		c.HTable[0] = &AddressBookEntry{
			MId:   0,
			Name:  "Default Global Address List",
			Flags: mapi.AB_RECIPIENTS | mapi.AB_SUBCONTAINERS,
			Depth: 0,
		}
		c.HTableOrder = append(c.HTableOrder, 0)
	}

	if build.Debug {
		log.Printf("[D] NSPI: Parsed hierarchy table, found %d entries", len(c.HTable))
	}
}

// QueryColumns performs NspiQueryColumns operation to get available properties
func (c *Client) QueryColumns() ([]PropertyTag, error) {
	buf := new(bytes.Buffer)

	// contextHandle
	buf.Write(c.Handler.Marshal())

	// Reserved
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// dwFlags
	binary.Write(buf, binary.LittleEndian, uint32(NspiUnicodeProptypes))

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiQueryColumns, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return nil, err
	}

	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Return value
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		if msg, ok := mapi.ErrorMessages[retVal]; ok {
			return nil, fmt.Errorf("NspiQueryColumns failed: %s (0x%08x)", msg, retVal)
		}
		return nil, fmt.Errorf("NspiQueryColumns failed: 0x%08x", retVal)
	}

	// Parse property tags from response
	// Skip the pointer reference
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short for property array")
	}

	// cValues at offset after pointer ref
	offset := 4 // Skip pointer ref
	cValues := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	var props []PropertyTag
	for i := uint32(0); i < cValues && offset+4 <= len(resp)-4; i++ {
		tag := PropertyTag(binary.LittleEndian.Uint32(resp[offset:]))
		// Skip PtypEmbeddedTable to reduce traffic
		if tag.Type() != PtypEmbeddedTable {
			props = append(props, tag)
		}
		offset += 4
	}

	c.Properties = props

	if build.Debug {
		log.Printf("[D] NSPI: QueryColumns returned %d properties", len(props))
	}

	return props, nil
}

// queryRowsSingle performs a single NspiQueryRows RPC call (no pagination)
func (c *Client) queryRowsSingle(count uint32, propTags []PropertyTag, eTable []uint32) (*PropertyRowSet, error) {
	buf := new(bytes.Buffer)

	// contextHandle
	buf.Write(c.Handler.Marshal())

	// dwFlags - use FSkipObjects (matching Impacket) to get permanent entry IDs
	binary.Write(buf, binary.LittleEndian, uint32(FSkipObjects))

	// pStat
	buf.Write(c.Stat.Marshal())

	// dwETableCount and lpETable
	if len(eTable) > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(len(eTable)))
		// Pointer referent (non-null)
		binary.Write(buf, binary.LittleEndian, uint32(1))
		// Conformant array: MaxCount
		binary.Write(buf, binary.LittleEndian, uint32(len(eTable)))
		for _, mid := range eTable {
			binary.Write(buf, binary.LittleEndian, mid)
		}
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0))
		// NULL pointer
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	// Count
	binary.Write(buf, binary.LittleEndian, count)

	// pPropTags
	if len(propTags) > 0 {
		// Pointer ref
		binary.Write(buf, binary.LittleEndian, uint32(1))
		// Property tag array
		pta := PropertyTagArray{Values: propTags}
		buf.Write(pta.MarshalNDR())
	} else {
		// NULL pointer
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiQueryRows, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return nil, err
	}

	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Return value (last 4 bytes)
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		if msg, ok := mapi.ErrorMessages[retVal]; ok {
			return nil, fmt.Errorf("NspiQueryRows failed: %s (0x%08x)", msg, retVal)
		}
		return nil, fmt.Errorf("NspiQueryRows failed: 0x%08x", retVal)
	}

	// Parse response: [pStat(36)][ppRows referent(4)][PropertyRowSet_r(variable)][ReturnValue(4)]
	if len(resp) < 44 {
		return nil, fmt.Errorf("response too short for STAT + ppRows")
	}

	// Update STAT from response
	c.Stat.Unmarshal(resp[:36])

	if build.Debug {
		log.Printf("[D] NSPI: QueryRows response: CurrentRec=%d NumPos=%d TotalRecs=%d",
			c.Stat.CurrentRec, c.Stat.NumPos, c.Stat.TotalRecs)
	}

	// Skip ppRows pointer referent (4 bytes)
	ppRowsRef := binary.LittleEndian.Uint32(resp[36:40])
	if ppRowsRef == 0 {
		// Null pointer - no rows
		return &PropertyRowSet{}, nil
	}

	// Parse PropertyRowSet from the data after STAT + ppRows referent
	rowData := resp[40 : len(resp)-4]
	rowSet, err := ParsePropertyRowSet(rowData, propTags)
	if err != nil {
		if build.Debug {
			log.Printf("[D] NSPI: Warning parsing rows: %v", err)
		}
		return &PropertyRowSet{}, nil
	}

	return rowSet, nil
}

// QueryRows performs NspiQueryRows with pagination until MID_END_OF_TABLE
func (c *Client) QueryRows(containerID int32, count uint32, propTags []PropertyTag) (*PropertyRowSet, error) {
	// Update stat for container
	c.Stat.ContainerID = uint32(intToDword(containerID))
	c.Stat.CurrentRec = MID_BEGINNING_OF_TABLE
	c.Stat.Delta = 0
	c.Stat.NumPos = 0

	allRows := &PropertyRowSet{}

	for {
		rowSet, err := c.queryRowsSingle(count, propTags, nil)
		if err != nil {
			return nil, err
		}

		if rowSet != nil && len(rowSet.Rows) > 0 {
			allRows.Rows = append(allRows.Rows, rowSet.Rows...)
		}

		// Check if we've reached the end of the table
		if c.Stat.CurrentRec == MID_END_OF_TABLE {
			break
		}

		// Safety: if no rows returned, stop
		if rowSet == nil || len(rowSet.Rows) == 0 {
			break
		}
	}

	return allRows, nil
}

// QueryRowsExplicit performs NspiQueryRows with an explicit table (lpETable)
func (c *Client) QueryRowsExplicit(containerID int32, count uint32, propTags []PropertyTag, eTable []uint32) (*PropertyRowSet, error) {
	c.Stat.ContainerID = uint32(intToDword(containerID))

	return c.queryRowsSingle(count, propTags, eTable)
}

// QueryRowsWithCallback performs paginated QueryRows and calls the callback for each batch.
// This is used for two-phase queries where we first get MIds then fetch full properties.
func (c *Client) QueryRowsWithCallback(containerID int32, count uint32, propTags []PropertyTag, callback func(*PropertyRowSet) error) error {
	c.Stat.ContainerID = uint32(intToDword(containerID))
	c.Stat.CurrentRec = MID_BEGINNING_OF_TABLE
	c.Stat.Delta = 0
	c.Stat.NumPos = 0

	for {
		rowSet, err := c.queryRowsSingle(count, propTags, nil)
		if err != nil {
			return err
		}

		if rowSet != nil && len(rowSet.Rows) > 0 {
			if err := callback(rowSet); err != nil {
				return err
			}
		}

		if c.Stat.CurrentRec == MID_END_OF_TABLE {
			break
		}

		if rowSet == nil || len(rowSet.Rows) == 0 {
			break
		}
	}

	return nil
}

// ResolveNamesW performs NspiResolveNamesW operation for GUID lookups
func (c *Client) ResolveNamesW(names []string, propTags []PropertyTag) (*PropertyRowSet, error) {
	buf := new(bytes.Buffer)

	// contextHandle
	buf.Write(c.Handler.Marshal())

	// Reserved
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// pStat
	buf.Write(c.Stat.Marshal())

	// pPropTags
	if len(propTags) > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(1)) // Pointer ref
		pta := PropertyTagArray{Values: propTags}
		buf.Write(pta.MarshalNDR())
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	// paStr - WStringsArray_r
	// cValues
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// Conformant array MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(len(names)))

	// Array of LPWSTR pointers (referent IDs)
	for i := range names {
		binary.Write(buf, binary.LittleEndian, uint32(i+1)) // non-null referent
	}

	// Deferred string data
	for _, name := range names {
		u16 := utf16.Encode([]rune(name + "\x00"))
		// MaxCount, Offset, ActualCount
		binary.Write(buf, binary.LittleEndian, uint32(len(u16)))
		binary.Write(buf, binary.LittleEndian, uint32(0))
		binary.Write(buf, binary.LittleEndian, uint32(len(u16)))
		for _, c := range u16 {
			binary.Write(buf, binary.LittleEndian, c)
		}
		// Align to 4 bytes
		padLen := (len(u16) * 2) % 4
		if padLen != 0 {
			pad := make([]byte, 4-padLen)
			buf.Write(pad)
		}
	}

	// Send request
	resp, err := c.Transport.RPCCall(OP_NspiResolveNamesW, buf.Bytes(), c.CallID)
	c.CallID++
	if err != nil {
		return nil, err
	}

	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Return value
	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != 0 {
		if msg, ok := mapi.ErrorMessages[retVal]; ok {
			return nil, fmt.Errorf("NspiResolveNamesW failed: %s (0x%08x)", msg, retVal)
		}
		return nil, fmt.Errorf("NspiResolveNamesW failed: 0x%08x", retVal)
	}

	// Response format varies between server versions:
	//   [pStat(36)][ppMIds][ppRows][ReturnValue(4)], or
	//   [codePage DWORD][ppMIds][ppRows][ReturnValue] for ResolveNamesW.
	// We locate ppRows by scanning for the PropertyRowSet pointer.

	// Response format: ppMIds(PropertyTagArray_r**) + ppRows(PropertyRowSet_r**) + ReturnValue(4)
	//
	// ppMIds: referent(4) + if non-null: MaxCount(4) + cValues(4) + Offset(4) + ActualCount(4) + aulPropTag[ActualCount]
	// ppRows: referent(4) + if non-null: PropertyRowSet_r data
	offset := 0

	// Read ppMIds pointer referent
	if offset+4 > len(resp)-4 {
		return &PropertyRowSet{}, nil
	}
	midsPtr := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if midsPtr != 0 {
		// PropertyTagArray_r is a conformant-varying structure:
		// MaxCount(4) + cValues(4) + Offset(4) + ActualCount(4) + elements
		if offset+16 > len(resp)-4 {
			return &PropertyRowSet{}, nil
		}
		_ = binary.LittleEndian.Uint32(resp[offset:]) // MaxCount
		offset += 4
		_ = binary.LittleEndian.Uint32(resp[offset:]) // cValues
		offset += 4
		_ = binary.LittleEndian.Uint32(resp[offset:]) // Offset
		offset += 4
		actualCount := binary.LittleEndian.Uint32(resp[offset:]) // ActualCount
		offset += 4
		// Skip the MId array
		offset += int(actualCount) * 4
	}

	// Read ppRows pointer referent
	if offset+4 > len(resp)-4 {
		return &PropertyRowSet{}, nil
	}
	ppRowsRef := binary.LittleEndian.Uint32(resp[offset:])
	offset += 4

	if ppRowsRef == 0 {
		return &PropertyRowSet{}, nil
	}

	// Parse PropertyRowSet from the data after ppRows referent
	rowData := resp[offset : len(resp)-4]
	rowSet, err := ParsePropertyRowSet(rowData, propTags)
	if err != nil {
		if build.Debug {
			log.Printf("[D] NSPI: Warning parsing ResolveNamesW rows: %v", err)
		}
		return &PropertyRowSet{}, nil
	}

	return rowSet, nil
}

// LoadHTableContainerID finds an existing container ID for queries
func (c *Client) LoadHTableContainerID() error {
	if c.AnyExistingContainerID != -1 {
		return nil
	}

	if len(c.HTable) == 0 {
		if err := c.GetSpecialTable(); err != nil {
			return err
		}
	}

	for mid := range c.HTable {
		if err := c.UpdateStat(mid); err != nil {
			continue
		}

		if c.Stat.CurrentRec > 0 {
			c.AnyExistingContainerID = int32(intToDword(mid))
			return nil
		}
	}

	// Default to GAL (MId 0)
	c.AnyExistingContainerID = 0
	return nil
}

// intToDword converts an int32 to uint32 preserving negative values
func intToDword(n int32) uint32 {
	if n >= 0 {
		return uint32(n)
	}
	return uint32(int64(n) + (1 << 32))
}

// GetGUIDFromDN extracts GUID from an NSPI PermanentEntryID
func GetGUIDFromDN(entryID []byte) []byte {
	// PermanentEntryID format:
	// 4 bytes: ID type (flags)
	// 16 bytes: Provider GUID (GUID_NSPI)
	// 4 bytes: R1 (version)
	// 4 bytes: R2 (display type)
	// Then DN string (null-terminated)
	//
	// For the hierarchy table, the GUID we want is encoded in the DN.
	// But for the NSPI format, the entry ID structure is:
	// 4 bytes: flags (0x00000000)
	// 16 bytes: provider UID (GUID_NSPI)
	// 4 bytes: version (0x00000001)
	// 4 bytes: display type
	// Variable: Distinguished Name (null-terminated string)

	if len(entryID) < 28 {
		return nil
	}

	// Check if this is an NSPI permanent entry ID
	providerGUID := entryID[4:20]
	expectedGUID := guidToBytes(GUID_NSPI)
	if !bytes.Equal(providerGUID, expectedGUID) {
		return nil
	}

	// Extract the DN after the fixed header
	dn := string(entryID[28:])
	dn = strings.TrimRight(dn, "\x00")

	// The DN contains the GUID. Try to extract it.
	// Format: /o=.../ou=.../cn=<hex guid>
	// or /guid=<hex guid>
	if idx := strings.LastIndex(dn, "/cn="); idx >= 0 {
		guidHex := dn[idx+4:]
		guidHex = strings.TrimRight(guidHex, "\x00")
		if guidBytes, err := hex.DecodeString(guidHex); err == nil && len(guidBytes) == 16 {
			return guidBytes
		}
	}
	if idx := strings.LastIndex(dn, "/guid="); idx >= 0 {
		guidHex := dn[idx+6:]
		guidHex = strings.TrimRight(guidHex, "\x00")
		if guidBytes, err := hex.DecodeString(guidHex); err == nil && len(guidBytes) == 16 {
			return guidBytes
		}
	}

	return nil
}

// guidToBytes converts a uuid.UUID to its binary representation in little-endian format
func guidToBytes(g uuid.UUID) []byte {
	// uuid.UUID stores as big-endian RFC 4122 format
	// MS GUID uses mixed-endian: first 3 fields are LE, last 2 are BE
	b := g[:]
	result := make([]byte, 16)
	// Data1 (4 bytes LE)
	result[0] = b[3]
	result[1] = b[2]
	result[2] = b[1]
	result[3] = b[0]
	// Data2 (2 bytes LE)
	result[4] = b[5]
	result[5] = b[4]
	// Data3 (2 bytes LE)
	result[6] = b[7]
	result[7] = b[6]
	// Data4 (8 bytes, kept as-is)
	copy(result[8:], b[8:])
	return result
}

// GetDNFromGUID creates a minimal DN from a GUID for ResolveNames lookup
func GetDNFromGUID(guidStr string) string {
	// Parse GUID
	g, err := uuid.Parse(guidStr)
	if err != nil {
		return ""
	}

	// Convert to binary (MS mixed-endian format) then hex
	guidBytes := guidToBytes(g)
	guidHex := hex.EncodeToString(guidBytes)

	// Format: /guid=<hex>
	return fmt.Sprintf("/guid=%s", guidHex)
}
