// SPDX-License-Identifier: Apache-2.0

package epmapper

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"sort"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/header"
)

// Endpoint Mapper UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa
var UUID = [16]byte{
	0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
	0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
}

const (
	MajorVersion = 3
	MinorVersion = 0

	OpEptLookup = 2
	OpEptMap    = 3
)

// Inquiry types for ept_lookup
const (
	RPC_C_EP_ALL_ELTS      = 0
	RPC_C_EP_MATCH_BY_IF   = 1
	RPC_C_EP_MATCH_BY_OBJ  = 2
	RPC_C_EP_MATCH_BY_BOTH = 3
)

// Version options
const (
	RPC_C_VERS_ALL        = 1
	RPC_C_VERS_COMPATIBLE = 2
	RPC_C_VERS_EXACT      = 3
	RPC_C_VERS_MAJOR_ONLY = 4
	RPC_C_VERS_UPTO       = 5
)

// Tower floor protocol identifiers
const (
	ProtocolDCERPC    = 0x0B // DCE/RPC
	ProtocolUUID      = 0x0D // UUID
	ProtocolTCP       = 0x07 // TCP
	ProtocolUDP       = 0x08 // UDP
	ProtocolIP        = 0x09 // IP
	ProtocolNamedPipe = 0x0F // Named Pipe
	ProtocolLRPC      = 0x10 // LRPC (Local RPC)
	ProtocolNetBIOS   = 0x11 // NetBIOS
	ProtocolSMB       = 0x12 // SMB (NetBIOS Name)
	ProtocolHTTP      = 0x1F // HTTP
)

// Endpoint represents a discovered RPC endpoint
type Endpoint struct {
	UUID       string
	Version    string
	Annotation string
	Protocol   string
	Provider   string
	Bindings   []string
}

// EpmClient is a client for the Endpoint Mapper
type EpmClient struct {
	client *dcerpc.Client
}

// NewEpmClient creates a new Endpoint Mapper client
func NewEpmClient(client *dcerpc.Client) *EpmClient {
	return &EpmClient{client: client}
}

// Lookup enumerates all RPC endpoints
func (e *EpmClient) Lookup() ([]Endpoint, error) {
	var entries []rawEntry
	entryHandle := make([]byte, 20) // Context handle, initially zero

	for {
		// Build ept_lookup request
		payload := buildEptLookupRequest(entryHandle)

		resp, err := e.client.Call(OpEptLookup, payload)
		if err != nil {
			return nil, fmt.Errorf("ept_lookup call failed: %v", err)
		}

		// Parse response
		newEntries, newHandle, status, err := parseEptLookupResponse(resp)
		if err != nil {
			return nil, err
		}

		entries = append(entries, newEntries...)
		copy(entryHandle, newHandle)

		if build.Debug {
			log.Printf("[D] EPM: Got %d entries this batch, status=0x%08x", len(newEntries), status)
		}

		// Stop conditions:
		// - EPT_S_NOT_REGISTERED (0x16c9a0d6) = no more entries
		// - No entries returned
		// - Got fewer entries than max_ents (500) = server returned everything
		// - Any non-zero status other than 0x16c9a0d6
		if status == 0x16c9a0d6 || len(newEntries) == 0 {
			break
		}
		if len(newEntries) < 500 {
			break
		}
		if status != 0 {
			break
		}
	}

	// Group entries by UUID
	return groupEndpoints(entries), nil
}

type rawEntry struct {
	uuid       string
	version    string
	annotation string
	binding    string
}

func buildEptLookupRequest(entryHandle []byte) []byte {
	buf := new(bytes.Buffer)

	// inquiry_type: RPC_C_EP_ALL_ELTS (0) - enumerate all
	binary.Write(buf, binary.LittleEndian, uint32(RPC_C_EP_ALL_ELTS))

	// object: NULL pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Ifid: NULL pointer (match all interfaces)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// vers_option: RPC_C_VERS_ALL
	binary.Write(buf, binary.LittleEndian, uint32(RPC_C_VERS_ALL))

	// entry_handle (20 bytes context handle)
	buf.Write(entryHandle)

	// max_ents: number of entries to return
	binary.Write(buf, binary.LittleEndian, uint32(500))

	return buf.Bytes()
}

func parseEptLookupResponse(resp []byte) ([]rawEntry, []byte, uint32, error) {
	if len(resp) < 32 {
		return nil, nil, 0, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	if build.Debug {
		log.Printf("[D] EPM: Response length: %d bytes", len(resp))
	}

	r := bytes.NewReader(resp)

	// entry_handle (20 bytes)
	entryHandle := make([]byte, 20)
	r.Read(entryHandle)

	// num_ents
	var numEnts uint32
	binary.Read(r, binary.LittleEndian, &numEnts)

	if build.Debug {
		log.Printf("[D] EPM: Lookup returned %d entries", numEnts)
	}

	var entries []rawEntry

	if numEnts > 0 {
		// Conformant varying array header: max_count, offset, actual_count
		var maxCount, arrOffset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &arrOffset)
		binary.Read(r, binary.LittleEndian, &actualCount)

		if build.Debug {
			log.Printf("[D] EPM: Array header: maxCount=%d, offset=%d, actualCount=%d", maxCount, arrOffset, actualCount)
		}

		// ept_entry_t NDR layout (per entry, inline in array):
		// - UUID object (16 bytes)
		// - twr_p_t tower (4 bytes - pointer referent ID, deferred)
		// - annotation (NDRUniVaryingArray - inline varying array):
		//   - offset (4 bytes)
		//   - actual_count (4 bytes)
		//   - data (actual_count bytes)
		//   - padding to 4-byte alignment
		//
		// Tower data is DEFERRED - comes after ALL entry structures

		type entryInfo struct {
			towerPtr   uint32
			annotation string
		}
		entryInfos := make([]entryInfo, actualCount)

		for i := uint32(0); i < actualCount; i++ {
			// UUID object (16 bytes) - skip, we get UUID from tower
			r.Seek(16, 1)

			// Tower pointer referent ID
			var towerPtr uint32
			binary.Read(r, binary.LittleEndian, &towerPtr)
			entryInfos[i].towerPtr = towerPtr

			// Annotation (varying array: offset + actual_count + data + padding)
			var annotOffset, annotActual uint32
			binary.Read(r, binary.LittleEndian, &annotOffset)
			binary.Read(r, binary.LittleEndian, &annotActual)

			if annotActual > 0 {
				data := make([]byte, annotActual)
				r.Read(data)
				// Remove null terminator
				if len(data) > 0 && data[len(data)-1] == 0 {
					data = data[:len(data)-1]
				}
				entryInfos[i].annotation = string(data)

				// Align to 4 bytes
				if annotActual%4 != 0 {
					r.Seek(int64(4-(annotActual%4)), 1)
				}
			}

			if build.Debug && i < 3 {
				pos, _ := r.Seek(0, 1)
				log.Printf("[D] EPM: Entry[%d]: towerPtr=%d, annot=%q, pos=%d",
					i, towerPtr, entryInfos[i].annotation, pos)
			}
		}

		if build.Debug {
			pos, _ := r.Seek(0, 1)
			log.Printf("[D] EPM: Position after all entries: %d, remaining: %d bytes", pos, len(resp)-int(pos))
		}

		// Now read deferred tower data (one per entry with non-null tower pointer)
		for i := uint32(0); i < actualCount; i++ {
			entry := rawEntry{
				annotation: entryInfos[i].annotation,
			}

			if entryInfos[i].towerPtr != 0 {
				entry.uuid, entry.version, entry.binding = parseTower(r)

				if build.Debug && i < 3 {
					log.Printf("[D] EPM: Tower[%d]: uuid=%s, ver=%s, binding=%s",
						i, entry.uuid, entry.version, entry.binding)
				}
			}

			entries = append(entries, entry)
		}
	}

	// Read status - it follows the entry/tower data
	var status uint32
	binary.Read(r, binary.LittleEndian, &status)

	if build.Debug {
		pos, _ := r.Seek(0, 1)
		log.Printf("[D] EPM: Status=0x%08x, position after status: %d, total: %d", status, pos, len(resp))
		log.Printf("[D] EPM: Handle: %x", entryHandle)
	}

	return entries, entryHandle, status, nil
}

func parseTower(r *bytes.Reader) (string, string, string) {
	// Tower: max_count (conformant array)
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// tower_length
	var towerLen uint32
	binary.Read(r, binary.LittleEndian, &towerLen)

	if towerLen == 0 {
		return "", "", ""
	}

	// Number of floors
	var numFloors uint16
	binary.Read(r, binary.LittleEndian, &numFloors)

	var uuid string
	var version string
	var protocol string     // e.g. "ncacn_ip_tcp", "ncacn_np", "ncalrpc"
	var portStr string      // e.g. "49671"
	var ipAddr string       // e.g. "192.0.2.10"
	var pipeName string     // e.g. "\\pipe\\lsass"
	var nbName string       // e.g. "DC01"
	var lrpcName string     // e.g. "NETLOGON_LRPC"
	var unknownProto string // For unrecognized protocols
	uuidFloor := 0          // Track which UUID floor we're on

	for i := uint16(0); i < numFloors; i++ {
		var lhsLen uint16
		binary.Read(r, binary.LittleEndian, &lhsLen)

		lhsData := make([]byte, lhsLen)
		r.Read(lhsData)

		var rhsLen uint16
		binary.Read(r, binary.LittleEndian, &rhsLen)

		rhsData := make([]byte, rhsLen)
		r.Read(rhsData)

		if lhsLen >= 1 {
			switch lhsData[0] {
			case ProtocolUUID:
				if lhsLen >= 19 {
					uuidFloor++
					// Floor 1 = interface UUID, Floor 2 = transfer syntax (skip)
					if uuidFloor == 1 {
						uuid = formatUUID(lhsData[1:17])
						ver := binary.LittleEndian.Uint16(lhsData[17:19])
						minorVer := uint16(0)
						if rhsLen >= 2 {
							minorVer = binary.LittleEndian.Uint16(rhsData)
						}
						version = fmt.Sprintf("v%d.%d", ver, minorVer)
					}
				}
			case ProtocolTCP:
				protocol = "ncacn_ip_tcp"
				if rhsLen >= 2 {
					portStr = fmt.Sprintf("%d", binary.BigEndian.Uint16(rhsData))
				}
			case ProtocolUDP:
				protocol = "ncadg_ip_udp"
				if rhsLen >= 2 {
					portStr = fmt.Sprintf("%d", binary.BigEndian.Uint16(rhsData))
				}
			case ProtocolIP:
				if rhsLen >= 4 {
					ipAddr = fmt.Sprintf("%d.%d.%d.%d", rhsData[0], rhsData[1], rhsData[2], rhsData[3])
				}
			case ProtocolNamedPipe:
				protocol = "ncacn_np"
				if rhsLen > 0 {
					pipeName = string(rhsData[:rhsLen-1]) // Remove null terminator
				}
			case ProtocolNetBIOS:
				if rhsLen > 0 {
					nbName = string(rhsData[:rhsLen-1])
				}
			case ProtocolLRPC:
				protocol = "ncalrpc"
				if rhsLen > 0 {
					lrpcName = string(rhsData[:rhsLen-1])
				}
			case ProtocolHTTP:
				protocol = "ncacn_http"
				if rhsLen >= 2 {
					portStr = fmt.Sprintf("%d", binary.BigEndian.Uint16(rhsData))
				}
			default:
				if lhsData[0] != ProtocolDCERPC && protocol == "" {
					unknownProto = fmt.Sprintf("unknown_proto_0x%02x", lhsData[0])
					if rhsLen >= 2 {
						portStr = fmt.Sprintf("%d", binary.BigEndian.Uint16(rhsData))
					}
				}
			}
		}
	}

	// Build binding string
	var binding string
	switch protocol {
	case "ncacn_ip_tcp":
		if ipAddr != "" && ipAddr != "0.0.0.0" {
			binding = fmt.Sprintf("ncacn_ip_tcp:%s[%s]", ipAddr, portStr)
		} else {
			binding = fmt.Sprintf("ncacn_ip_tcp:%s", portStr)
		}
	case "ncadg_ip_udp":
		if ipAddr != "" && ipAddr != "0.0.0.0" {
			binding = fmt.Sprintf("ncadg_ip_udp:%s[%s]", ipAddr, portStr)
		} else {
			binding = fmt.Sprintf("ncadg_ip_udp:%s", portStr)
		}
	case "ncacn_np":
		if nbName != "" {
			binding = fmt.Sprintf("ncacn_np:%s[%s]", nbName, pipeName)
		} else {
			binding = fmt.Sprintf("ncacn_np:[%s]", pipeName)
		}
	case "ncalrpc":
		binding = fmt.Sprintf("ncalrpc:[%s]", lrpcName)
	case "ncacn_http":
		if ipAddr != "" && ipAddr != "0.0.0.0" {
			binding = fmt.Sprintf("ncacn_http:%s[%s]", ipAddr, portStr)
		} else {
			binding = fmt.Sprintf("ncacn_http:%s", portStr)
		}
	default:
		if unknownProto != "" {
			binding = fmt.Sprintf("%s:[%s]", unknownProto, portStr)
		}
	}

	// Align to 4 bytes
	pos, _ := r.Seek(0, 1) // Get current position
	if pos%4 != 0 {
		r.Seek(int64(4-(pos%4)), 1)
	}

	return uuid, version, binding
}

func formatUUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(data[0:4]),
		binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]),
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

// Known RPC protocols by UUID
var knownProtocols = map[string]string{
	"00000000-0000-0000-C000-000000000046": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"00000131-0000-0000-C000-000000000046": "[MS-DCOM]: Distributed Component Object Model (DCOM) Remote",
	"00000134-0000-0000-C000-000000000046": "[MS-DCOM]: Distributed Component Object Model (DCOM)",
	"00000143-0000-0000-C000-000000000046": "[MS-DCOM]: Distributed Component Object Model (DCOM) Remote",
	"000001A0-0000-0000-C000-000000000046": "[MS-DCOM]: Distributed Component Object Model (DCOM) Remote",
	"00020400-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"00020401-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"00020402-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"00020403-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"00020404-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"00020411-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"00020412-0000-0000-C000-000000000046": "[MS-OAUT]: OLE Automation Protocol",
	"004C6A2B-0C19-4C69-9F5C-A269B2560DB9": "[MS-UAMG]: Update Agent Management Protocol",
	"01454B97-C6A5-4685-BEA8-9779C88AB990": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"0188401C-247A-4FED-99C6-BF14119D7055": "[MC-MQAC]: Message Queuing (MSMQ):",
	"0188AC2F-ECB3-4173-9779-635CA2039C72": "[MC-MQAC]: Message Queuing (MSMQ):",
	"0191775E-BCFF-445A-B4F4-3BDDA54E2816": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"01954E6B-9254-4E6E-808C-C9E05D007696": "[MS-SCMP]: Shadow Copy Management Protocol",
	"027947E1-D731-11CE-A357-000000000001": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"0316560B-5DB4-4ED9-BBB5-213436DDC0D9": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"0344CDDA-151E-4CBF-82DA-66AE61E97754": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"034634FD-BA3F-11D1-856A-00A0C944138C": "[MS-TSRAP]: Telnet Server Remote Administration Protocol",
	"038374FF-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837502-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837506-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"0383750B-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837510-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837512-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837514-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837516-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"0383751A-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837520-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837524-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837533-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837534-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"0383753A-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"0383753D-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837541-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837543-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"03837544-098B-11D8-9414-505054503030": "[MS-PLA]: Performance Logs and Alerts Protocol",
	"04C6895D-EAF2-4034-97F3-311DE9BE413A": "[MS-UAMG]: Update Agent Management Protocol",
	"04D55210-B6AC-4248-9E69-2A569D1D2AB6": "[MS-CSVP]: Failover Cluster:",
	"070669EB-B52F-11D1-9270-00C04FBBBFB3": "[MS-ADTG]: Remote Data Services (RDS) Transport Protocol",
	"0716CAF8-7D05-4A46-8099-77594BE91394": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"0770687E-9F36-4D6F-8778-599D188461C9": "[MS-FSRM]: File Server Resource Manager Protocol",
	"07E5C822-F00C-47A1-8FCE-B244DA56FD06": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"07F7438C-7709-4CA5-B518-91279288134E": "[MS-UAMG]: Update Agent Management Protocol",
	"0818A8EF-9BA9-40D8-A6F9-E22833CC771E": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"081E7188-C080-4FF3-9238-29F66D6CABFD": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"08A90F5F-0702-48D6-B45F-02A9885A9768": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"09829352-87C2-418D-8D79-4133969A489D": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"0AC13689-3134-47C6-A17C-4669216801BE": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"0B1C2170-5732-4E0E-8CD3-D9B16F3B84D7": "[MS-RAA]: Remote Authorization API Protocol",
	"0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1": "[MS-PAN]: Print System Asynchronous Notification Protocol",
	"0BB8531D-7E8D-424F-986C-A0B8F60A3E7B": "[MS-UAMG]: Update Agent Management Protocol",
	"0D521700-A372-4BEF-828B-3D00C10ADEBD": "[MS-UAMG]: Update Agent Management Protocol",
	"0DD8A158-EBE6-4008-A1D9-B7ECC8F1104B": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"0E3D6630-B46B-11D1-9D2D-006008B0E5CA": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"0E3D6631-B46B-11D1-9D2D-006008B0E5CA": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"0EAC4842-8763-11CF-A743-00AA00A3F00D": "[MS-ADTG]: Remote Data Services (RDS) Transport Protocol",
	"0FB15084-AF41-11CE-BD2B-204C4F4F5020": "[MC-MQAC]: Message Queuing (MSMQ):",
	"100DA538-3F4A-45AB-B852-709148152789": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"1088A980-EAE5-11D0-8D9B-00A02453C337": "[MS-MQQP]: Message Queuing (MSMQ):",
	"10C5E575-7984-4E81-A56B-431F5F92AE42": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"112B1DFF-D9DC-41F7-869F-D67FEE7CB591": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"112EDA6B-95B3-476F-9D90-AEE82C6B8181": "[MS-UAMG]: Update Agent Management Protocol",
	"118610B7-8D94-4030-B5B8-500889788E4E": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"11899A43-2B68-4A76-92E3-A3D6AD8C26CE": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"11942D87-A1DE-4E7F-83FB-A840D9C5928D": "[MS-CSVP]: Failover Cluster:",
	"12108A88-6858-4467-B92F-E6CF4568DFB6": "[MS-CSVP]: Failover Cluster:",
	"12345678-1234-ABCD-EF00-0123456789AB": "[MS-RPRN]: Print System Remote Protocol",
	"12345678-1234-ABCD-EF00-01234567CFFB": "[MS-NRPC]: Netlogon Remote Protocol",
	"12345778-1234-ABCD-EF00-0123456789AB": "[MS-LSAT]: Local Security Authority (Translation Methods) Remote",
	"12345778-1234-ABCD-EF00-0123456789AC": "[MS-SAMR]: Security Account Manager (SAM) Remote Protocol",
	"1257B580-CE2F-4109-82D6-A9459D0BF6BC": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"12937789-E247-4917-9C20-F3EE9C7EE783": "[MS-FSRM]: File Server Resource Manager Protocol",
	"12A30900-7300-11D2-B0E6-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"135698D2-3A37-4D26-99DF-E2BB6AE3AC61": "[MS-DMRP]: Disk Management Remote Protocol",
	"1396DE6F-A794-4B11-B93F-6B69A5B47BAE": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"13B50BFF-290A-47DD-8558-B7C58DB1A71A": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"144FE9B0-D23D-4A8B-8634-FB4457533B7A": "[MS-UAMG]: Update Agent Management Protocol",
	"14A8831C-BC82-11D2-8A64-0008C7457E5D": "[MS-EERR]: ExtendedError Remote Data Structure",
	"14FBE036-3ED7-4E10-90E9-A5FF991AFF01": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"1518B460-6518-4172-940F-C75883B24CEB": "[MS-UAMG]: Update Agent Management Protocol",
	"152EA2A8-70DC-4C59-8B2A-32AA3CA0DCAC": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"1544F5E0-613C-11D1-93DF-00C04FD7BD09": "[MS-OXABREF]: Address Book Name Service Provider Interface (NSPI) Referral Protocol",
	"1568A795-3924-4118-B74B-68D8F0FA5DAF": "[MS-FSRM]: File Server Resource Manager Protocol",
	"15A81350-497D-4ABA-80E9-D4DBCC5521FE": "[MS-FSRM]: File Server Resource Manager Protocol",
	"15FC031C-0652-4306-B2C3-F558B8F837E2": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"16A18E86-7F6E-4C20-AD89-4FFC0DB7A96A": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"17FDD703-1827-4E34-79D4-24A55C53BB37": "[MS-MSRP]: Messenger Service Remote Protocol",
	"1822A95E-1C2B-4D02-AB25-CC116DD9DBDE": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"182C40FA-32E4-11D0-818B-00A0C9231C29": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"18F70770-8E64-11CF-9AF1-0020AF6E72F4": "[MS-DCOM]: Distributed Component Object Model (DCOM)",
	"1995785D-2A1E-492F-8923-E621EACA39D9": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"1A1BB35F-ABB8-451C-A1AE-33D98F1BEF4A": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"1A9134DD-7B39-45BA-AD88-44D01CA47F28": "[MS-MQRR]: Message Queuing (MSMQ):",
	"1A927394-352E-4553-AE3F-7CF4AAFCA620": "[MS-WDSC]: Windows Deployment Services Control Protocol",
	"1B1C4D1C-ABC4-4D3A-8C22-547FBA3AA8A0": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"1BB617B8-3886-49DC-AF82-A6C90FA35DDA": "[MS-FSRM]: File Server Resource Manager Protocol",
	"1BE2275A-B315-4F70-9E44-879B3A2A53F2": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"1C1C45EE-4395-11D2-B60B-00104B703EFD": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"1C60A923-2D86-46AA-928A-E7F3E37577AF": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"1D118904-94B3-4A64-9FA6-ED432666A7B9": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"1E062B84-E5E6-4B4B-8A25-67B81E8F13E8": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"1F7B1697-ECB2-4CBB-8A0E-75C427F4A6F0": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"1FF70682-0A51-30E8-076D-740BE8CEE98B": "[MS-TSCH]: Task Scheduler Service Remoting Protocol",
	"205BEBF8-DD93-452A-95A6-32B566B35828": "[MS-FSRM]: File Server Resource Manager Protocol",
	"20610036-FA22-11CF-9823-00A0C911E5DF": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"20D15747-6C48-4254-A358-65039FD8C63C": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"214A0F28-B737-4026-B847-4F9E37D79529": "[MS-SCMP]: Shadow Copy Management Protocol",
	"21546AE8-4DA5-445E-987F-627FEA39C5E8": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"22BCEF93-4A3F-4183-89F9-2F8B8A628AEE": "[MS-FSRM]: File Server Resource Manager Protocol",
	"22E5386D-8B12-4BF0-B0EC-6A1EA419E366": "[MS-LREC]: Live Remote Event Capture (LREC) Protocol",
	"23857E3C-02BA-44A3-9423-B1C900805F37": "[MS-UAMG]: Update Agent Management Protocol",
	"23C9DD26-2355-4FE2-84DE-F779A238ADBD": "[MS-COMT]: Component Object Model Plus (COM+) Tracker Service",
	"27B899FE-6FFA-4481-A184-D3DAADE8A02B": "[MS-FSRM]: File Server Resource Manager Protocol",
	"27E94B0D-5139-49A2-9A61-93522DC54652": "[MS-UAMG]: Update Agent Management Protocol",
	"28BC8D5E-CA4B-4F54-973C-ED9622D2B3AC": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"2931C32C-F731-4C56-9FEB-3D5F1C5E72BF": "[MS-CSVP]: Failover Cluster:",
	"29822AB7-F302-11D0-9953-00C04FD919C1": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"29822AB8-F302-11D0-9953-00C04FD919C1": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"2A3EB639-D134-422D-90D8-AAA1B5216202": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"2ABD757F-2851-4997-9A13-47D2A885D6CA": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"2C9273E0-1DC3-11D3-B364-00105A1F8177": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"2CE0C5B0-6E67-11D2-B0E6-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"2D9915FB-9D42-4328-B782-1B46819FAB9E": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"2DBE63C4-B340-48A0-A5B0-158E07FC567E": "[MS-FSRM]: File Server Resource Manager Protocol",
	"2F5F6520-CA46-1067-B319-00DD010662DA": "[MS-TRP]: Telephony Remote Protocol",
	"2F5F6521-CA47-1068-B319-00DD010662DB": "[MS-TRP]: Telephony Remote Protocol",
	"300F3532-38CC-11D0-A3F0-0020AF6B0ADD": "[MS-DLTW]: Distributed Link Tracking:",
	"312CC019-D5CD-4CA7-8C10-9E0A661F147E": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"31A83EA0-C0E4-4A2C-8A01-353CC2A4C60A": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"326AF66F-2AC0-4F68-BF8C-4759F054FA29": "[MS-FSRM]: File Server Resource Manager Protocol",
	"338CD001-2244-31F1-AAAA-900038001003": "[MS-RRP]: Windows Remote Registry Protocol",
	"33B6D07E-F27D-42FA-B2D7-BF82E11E9374": "[MC-MQAC]: Message Queuing (MSMQ):",
	"345B026B-5802-4E38-AC75-795E08B0B83F": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"348A0821-69BB-4889-A101-6A9BDE6FA720": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"367ABB81-9844-35F1-AD32-98F038001003": "[MS-SCMR]: Service Control Manager Remote Protocol",
	"370AF178-7758-4DAD-8146-7391F6E18585": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"377F739D-9647-4B8E-97D2-5FFCE6D759CD": "[MS-FSRM]: File Server Resource Manager Protocol",
	"378E52B0-C0A9-11CF-822D-00AA0051E40F": "[MS-TSCH]: Task Scheduler Service Remoting Protocol",
	"3858C0D5-0F35-4BF5-9714-69874963BC36": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"38A0A9AB-7CC8-4693-AC07-1F28BD03C3DA": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"38E87280-715C-4C7D-A280-EA1651A19FEF": "[MS-FSRM]: File Server Resource Manager Protocol",
	"3919286A-B10C-11D0-9BA8-00C04FD92EF5": "[MS-DSSP]: Directory Services Setup Remote Protocol",
	"39322A2D-38EE-4D0D-8095-421A80849A82": "[MS-FSRM]: File Server Resource Manager Protocol",
	"39CE96FE-F4C5-4484-A143-4C2D5D324229": "[MC-MQAC]: Message Queuing (MSMQ):",
	"3A410F21-553F-11D1-8E5E-00A0C92C9D5D": "[MS-DMRP]: Disk Management Remote Protocol",
	"3A56BFB8-576C-43F7-9335-FE4838FD7E37": "[MS-UAMG]: Update Agent Management Protocol",
	"3B69D7F5-9D94-4648-91CA-79939BA263BF": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"3BBED8D9-2C9A-4B21-8936-ACB2F995BE6C": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"3C3A70A7-A468-49B9-8ADA-28E11FCCAD5D": "[MS-RAI]: Remote Assistance Initiation Protocol",
	"3C73848A-A679-40C5-B101-C963E67F9949": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"3C745A97-F375-4150-BE17-5950F694C699": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"3CFEE98C-FB4B-44C6-BD98-A1DB14ABCA3F": "[MS-CSVP]: Failover Cluster:",
	"3DDE7C30-165D-11D1-AB8F-00805F14DB40": "[MS-BKRP]: BackupKey Remote Protocol",
	"3F3B1B86-DBBE-11D1-9DA6-00805F85CFE3": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"3F99B900-4D87-101B-99B7-AA0004007F07": "[MS-SQL]: TDS (SQL Server)",
	"40CC8569-6D23-4005-9958-E37F08AE192B": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"40F73C8B-687D-4A13-8D96-3D7F2E683936": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"41208EE0-E970-11D1-9B9E-00E02C064C39": "[MS-MQMR]: Message Queuing (MSMQ):",
	"4142DD5D-3472-4370-8641-DE7856431FB0": "[MS-CSVP]: Failover Cluster:",
	"4173AC41-172D-4D52-963C-FDC7E415F717": "[MS-FSRM]: File Server Resource Manager Protocol",
	"423EC01E-2E35-11D2-B604-00104B703EFD": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"426677D5-018C-485C-8A51-20B86D00BDC4": "[MS-FSRM]: File Server Resource Manager Protocol",
	"42DC3511-61D5-48AE-B6DC-59FC00C0A8D6": "[MS-FSRM]: File Server Resource Manager Protocol",
	"442931D5-E522-4E64-A181-74E98A4E1748": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"44ACA674-E8FC-11D0-A07C-00C04FB68820": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"44ACA675-E8FC-11D0-A07C-00C04FB68820": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"44E265DD-7DAF-42CD-8560-3CDB6E7A2729": "[MS-TSGU]: Terminal Services Gateway Server Protocol",
	"450386DB-7409-4667-935E-384DBBEE2A9E": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"456129E2-1078-11D2-B0F9-00805FC73204": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"45F52C28-7F9F-101A-B52B-08002B2EFABE": "[MS-RAIW]: Remote Administrative Interface:",
	"46297823-9940-4C09-AED9-CD3EA6D05968": "[MS-UAMG]: Update Agent Management Protocol",
	"4639DB2A-BFC5-11D2-9318-00C04FBBBFB3": "[MS-ADTG]: Remote Data Services (RDS) Transport Protocol",
	"47782152-D16C-4229-B4E1-0DDFE308B9F6": "[MS-FSRM]: File Server Resource Manager Protocol",
	"47CDE9A1-0BF6-11D2-8016-00C04FB9988E": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"481E06CF-AB04-4498-8FFE-124A0A34296D": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"4846CB01-D430-494F-ABB4-B1054999FB09": "[MS-FSRM]: File Server Resource Manager Protocol",
	"484809D6-4239-471B-B5BC-61DF8C23AC48": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"491260B5-05C9-40D9-B7F2-1F7BDAE0927F": "[MS-CSVP]: Failover Cluster:",
	"497D95A6-2D27-4BF5-9BBD-A6046957133C": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"49EBD502-4A96-41BD-9E3E-4C5057F4250C": "[MS-UAMG]: Update Agent Management Protocol",
	"4A2F5C31-CFD9-410E-B7FB-29A653973A0F": "[MS-UAMG]: Update Agent Management Protocol",
	"4A6B0E15-2E38-11D1-9965-00C04FBBB345": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"4A6B0E16-2E38-11D1-9965-00C04FBBB345": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"4A73FEE4-4102-4FCC-9FFB-38614F9EE768": "[MS-FSRM]: File Server Resource Manager Protocol",
	"4AFC3636-DB01-4052-80C3-03BBCB8D3C69": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"4B324FC8-1670-01D3-1278-5A47BF6EE188": "[MS-SRVS]: Server Service Remote Protocol",
	"4BB8AB1D-9EF9-4100-8EB6-DD4B4E418B72": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"4BDAFC52-FE6A-11D2-93F8-00105A11164A": "[MS-DMRP]: Disk Management Remote Protocol",
	"4C8F96C3-5D94-4F37-A4F4-F56AB463546F": "[MS-FSRM]: File Server Resource Manager Protocol",
	"4CBDCB2D-1589-4BEB-BD1C-3E582FF0ADD0": "[MS-UAMG]: Update Agent Management Protocol",
	"4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57": "[MS-DCOM]: Distributed Component Object Model (DCOM) Remote",
	"4DA1C422-943D-11D1-ACAE-00C04FC2AA3F": "[MS-DLTM]: Distributed Link Tracking:",
	"4DAA0135-E1D1-40F1-AAA5-3CC1E53221C3": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"4DBCEE9A-6343-4651-B85F-5E75D74D983C": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"4DFA1DF3-8900-4BC7-BBB5-D1A458C52410": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"4E14FB9F-2E22-11D1-9964-00C04FBBB345": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"4E65A71E-4EDE-4886-BE67-3C90A08D1F29": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"4E6CDCC9-FB25-4FD5-9CC5-C9F4B6559CEC": "[MS-COMT]: Component Object Model Plus (COM+) Tracker Service",
	"4E934F30-341A-11D1-8FB1-00A024CB6019": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"4F7CA01C-A9E5-45B6-B142-2332A1339C1D": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"4FC742E0-4A10-11CF-8273-00AA004AE673": "[MS-DFSNM]: Distributed File System (DFS):",
	"503626A3-8E14-4729-9355-0FE664BD2321": "[MS-UAMG]: Update Agent Management Protocol",
	"50ABC2A4-574D-40B3-9D66-EE4FD5FBA076": "[MS-DNSP]: Domain Name Service (DNS) Server Management",
	"515C1277-2C81-440E-8FCF-367921ED4F59": "[MS-FSRM]: File Server Resource Manager Protocol",
	"5261574A-4572-206E-B268-6B199213B4E4": "[MS-OXCRPC]: Wire Format Protocol",
	"52BA97E7-9364-4134-B9CB-F8415213BDD8": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"52C80B95-C1AD-4240-8D89-72E9FA84025E": "[MC-CCFG]: Server Cluster:",
	"538684E0-BA3D-4BC0-ACA9-164AFF85C2A9": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"53B46B02-C73B-4A3E-8DEE-B16B80672FC0": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"541679AB-2E5F-11D3-B34E-00104BCC4B4A": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"5422FD3A-D4B8-4CEF-A12E-E87D4CA22E90": "[MS-WCCE]: Windows Client Certificate Enrollment Protocol",
	"54A2CB2D-9A0C-48B6-8A50-9ABB69EE2D02": "[MS-UAMG]: Update Agent Management Protocol",
	"56E65EA5-CDFF-4391-BA76-006E42C2D746": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"592381E5-8D3C-42E9-B7DE-4E77A1F75AE4": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"59602EB6-57B0-4FD8-AA4B-EBF06971FE15": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"5A7B91F8-FF00-11D0-A9B2-00C04FB6E6FC": "[MS-MSRP]: Messenger Service Remote Protocol",
	"5B5A68E6-8B9F-45E1-8199-A95FFCCDFFFF": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"5B821720-F63B-11D0-AAD2-00C04FC324DB": "[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP)",
	"5CA4A760-EBB1-11CF-8611-00A0245420ED": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"5F6325D3-CE88-4733-84C1-2D6AEFC5EA07": "[MS-FSRM]: File Server Resource Manager Protocol",
	"5FF9BDF6-BD91-4D8B-A614-D6317ACC8DD8": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"6050B110-CE87-4126-A114-50AEFCFC95F8": "[MS-DCOM]: Distributed Component Object Model (DCOM)",
	"6099FC12-3EFF-11D0-ABD0-00C04FD91A4E": "[MS-FAX]: Fax Server and Client Remote Protocol",
	"6139D8A4-E508-4EBB-BAC7-D7F275145897": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"615C4269-7A48-43BD-96B7-BF6CA27D6C3E": "[MS-UAMG]: Update Agent Management Protocol",
	"640038F1-D626-40D8-B52B-09660601D045": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"64C478FB-F9B0-4695-8A7F-439AC94326D3": "[MC-MQAC]: Message Queuing (MSMQ):",
	"64FF8CCC-B287-4DAE-B08A-A72CBF45F453": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"6619A740-8154-43BE-A186-0319578E02DB": "[MS-IOI]: IManagedObject Interface Protocol",
	"66A2DB1B-D706-11D0-A37B-00C04FC9DA04": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"66A2DB20-D706-11D0-A37B-00C04FC9DA04": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"66A2DB21-D706-11D0-A37B-00C04FC9DA04": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"66A2DB22-D706-11D0-A37B-00C04FC9DA04": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"66C9B082-7794-4948-839A-D8A5A616378F": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"673425BF-C082-4C7C-BDFD-569464B8E0CE": "[MS-UAMG]: Update Agent Management Protocol",
	"674B6698-EE92-11D0-AD71-00C04FD8FDFF": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"6788FAF9-214E-4B85-BA59-266953616E09": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"67E08FC2-2984-4B62-B92E-FC1AAE64BBBB": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"6879CAF9-6617-4484-8719-71C3D8645F94": "[MS-FSRM]: File Server Resource Manager Protocol",
	"69AB7050-3059-11D1-8FAF-00A024CB6019": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"6A92B07A-D821-4682-B423-5C805022CC4D": "[MS-UAMG]: Update Agent Management Protocol",
	"6AEA6B26-0680-411D-8877-A148DF3087D5": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"6B5BDD1E-528C-422C-AF8C-A4079BE4FE48": "[MS-FASP]: Firewall and Advanced Security Protocol",
	"6BFFD098-A112-3610-9833-012892020162": "[MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary",
	"6BFFD098-A112-3610-9833-46C3F874532D": "[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP)",
	"6BFFD098-A112-3610-9833-46C3F87E345A": "[MS-WKST]: Workstation Service Remote Protocol",
	"6C935649-30A6-4211-8687-C4C83E5FE1C7": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"6CD6408A-AE60-463B-9EF1-E117534D69DC": "[MS-FSRM]: File Server Resource Manager Protocol",
	"6E6F6B40-977C-4069-BDDD-AC710059F8C0": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"6F4DBFFF-6920-4821-A6C3-B7E94C1FD60C": "[MS-FSRM]: File Server Resource Manager Protocol",
	"703E6B03-7AD1-4DED-BA0D-E90496EBC5DE": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"708CCA10-9569-11D1-B2A5-0060977D8118": "[MS-MQDS]: Message Queuing (MSMQ):",
	"70B51430-B6CA-11D0-B9B9-00A0C922E750": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"70CF5C82-8642-42BB-9DBC-0CFD263C6C4F": "[MS-UAMG]: Update Agent Management Protocol",
	"72AE6713-DCBB-4A03-B36B-371F6AC6B53D": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"7366EA16-7A1A-4EA2-B042-973D3E9CD99B": "[MS-UAMG]: Update Agent Management Protocol",
	"75C8F324-F715-4FE3-A28E-F9011B61A4A1": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"76B3B17E-AED6-4DA5-85F0-83587F81ABE3": "[MS-UAMG]: Update Agent Management Protocol",
	"76D12B80-3467-11D3-91FF-0090272F9EA3": "[MS-MQMP]: Message Queuing (MSMQ):",
	"76F03F96-CDFD-44FC-A22C-64950A001209": "[MS-PAR]: Print System Asynchronous Remote Protocol",
	"76F226C3-EC14-4325-8A99-6A46348418AF": "[MS-PAN]: Print System Asynchronous Notification Protocol",
	"77DF7A80-F298-11D0-8358-00A024C480A8": "[MS-MQDS]: Message Queuing (MSMQ):",
	"784B693D-95F3-420B-8126-365C098659F2": "[MS-OCSPA]: Microsoft OCSP Administration Protocol",
	"7883CA1C-1112-4447-84C3-52FBEB38069D": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"7A2323C7-9EBE-494A-A33C-3CC329A18E1D": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"7C44D7D4-31D5-424C-BD5E-2B3E1F323D22": "[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol",
	"7C4E1804-E342-483D-A43E-A850CFCC8D18": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"7C857801-7381-11CF-884D-00AA004B2E24": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"7C907864-346C-4AEB-8F3F-57DA289F969F": "[MS-UAMG]: Update Agent Management Protocol",
	"7D07F313-A53F-459A-BB12-012C15B1846E": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"7F43B400-1A0E-4D57-BBC9-6B0C65F7A889": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"7FB7EA43-2D76-4EA8-8CD9-3DECC270295E": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"7FBE7759-5760-444D-B8A5-5E7AB9A84CCE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"7FE0D935-DDA6-443F-85D0-1CFB58FE41DD": "[MS-CSRA]: Certificate Services Remote Administration Protocol",
	"811109BF-A4E1-11D1-AB54-00A0C91E9B45": "[MS-RAIW]: Remote Administrative Interface:",
	"8165B19E-8D3A-4D0B-80C8-97DE310DB583": "[MS-IOI]: IManagedObject Interface Protocol",
	"816858A4-260D-4260-933A-2585F1ABC76B": "[MS-UAMG]: Update Agent Management Protocol",
	"81DDC1B8-9D35-47A6-B471-5B80F519223B": "[MS-UAMG]: Update Agent Management Protocol",
	"81FE3594-2495-4C91-95BB-EB5785614EC7": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"82273FDC-E32A-18C3-3F78-827929DC23EA": "[MS-EVEN]: EventLog Remoting Protocol",
	"8276702F-2532-4839-89BF-4872609A2EA4": "[MS-FSRM]: File Server Resource Manager Protocol",
	"8298D101-F992-43B7-8ECA-5052D885B995": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"82AD4280-036B-11CF-972C-00AA006887B0": "[MS-IRP]: Internet Information Services (IIS) Inetinfo Remote",
	"8326CD1D-CF59-4936-B786-5EFC08798E25": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"832A32F7-B3EA-4B8C-B260-9A2923001184": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"833E4010-AFF7-4AC3-AAC2-9F24C1457BCE": "[MS-RAI]: Remote Assistance Initiation Protocol",
	"833E4100-AFF7-4AC3-AAC2-9F24C1457BCE": "[MS-RAI]: Remote Assistance Initiation Protocol",
	"833E41AA-AFF7-4AC3-AAC2-9F24C1457BCE": "[MS-RAI]: Remote Assistance Initiation Protocol",
	"833E4200-AFF7-4AC3-AAC2-9F24C1457BCE": "[MS-RAI]: Remote Assistance Initiation Protocol",
	"83BFB87F-43FB-4903-BAA6-127F01029EEC": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"83E05BD5-AEC1-4E58-AE50-E819C7296F67": "[MS-RAINPS]: Remote Administrative Interface:",
	"85713FA1-7796-4FA2-BE3B-E2D6124DD373": "[MS-UAMG]: Update Agent Management Protocol",
	"85923CA7-1B6B-4E83-A2E4-F5BA3BFBB8A3": "[MS-CSVP]: Failover Cluster:",
	"866A78BC-A2FB-4AC4-94D5-DB3041B4ED75": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"86D35949-83C9-4044-B424-DB363231FD0C": "[MS-TSCH]: Task Scheduler Service Remoting Protocol",
	"879C8BBE-41B0-11D1-BE11-00C04FB6BF70": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"88143FD0-C28D-4B2B-8FEF-8D882F6A9390": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"88306BB2-E71F-478C-86A2-79DA200A0F11": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"883343F1-CEED-4E3A-8C1B-F0DADFCE281E": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"88E7AC6D-C561-4F03-9A60-39DD768F867D": "[MS-CSVP]: Failover Cluster:",
	"894DE0C0-0D55-11D3-A322-00C04FA321A1": "[MS-RSP]: Remote Shutdown Protocol",
	"895A2C86-270D-489D-A6C0-DC2A9B35280E": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"897E2E5F-93F3-4376-9C9C-FD2277495C27": "[MS-FRS2]: Distributed File System Replication Protocol",
	"8AD608A4-6C16-4405-8879-B27910A68995": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"8BB68C7D-19D8-4FFB-809E-BE4FC1734014": "[MS-FSRM]: File Server Resource Manager Protocol",
	"8BC3F05E-D86B-11D0-A075-00C04FB68820": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"8BED2C68-A5FB-4B28-8581-A0DC5267419F": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"8C58F6B3-4736-432A-891D-389DE3505C7C": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"8D7AE740-B9C5-49FC-A11E-89171907CB86": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"8DA03F40-3419-11D1-8FB1-00A024CB6019": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"8DB2180E-BD29-11D1-8B7E-00C04FD7A924": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"8DD04909-0E34-4D55-AFAA-89E1F1A1BBB9": "[MS-FSRM]: File Server Resource Manager Protocol",
	"8F09F000-B7ED-11CE-BBD2-00001A181CAD": "[MS-RRASM]: Routing and Remote Access Server (RRAS) Management",
	"8F45ABF1-F9AE-4B95-A933-F0F66E5056EA": "[MS-UAMG]: Update Agent Management Protocol",
	"8F4B2F5D-EC15-4357-992F-473EF10975B9": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"8F6D760F-F0CB-4D69-B5F6-848B33E9BDC6": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"8FB6D884-2388-11D0-8C35-00C04FDA2795": "[MS-W32T]: W32Time Remote Protocol",
	"9009D654-250B-4E0D-9AB0-ACB63134F69F": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"90681B1D-6A7F-48E8-9061-31B7AA125322": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"906B0CE0-C70B-1067-B317-00DD010662DA": "[MS-CMPO]: MSDTC Connection Manager:",
	"918EFD1E-B5D8-4C90-8540-AEB9BDC56F9D": "[MS-UAMG]: Update Agent Management Protocol",
	"91AE6020-9E3C-11CF-8D7C-00AA00C091BE": "[MS-ICPR]: ICertPassage Remote Protocol",
	"91CAF7B0-EB23-49ED-9937-C52D817F46F7": "[MS-UAMG]: Update Agent Management Protocol",
	"943991A5-B3FE-41FA-9696-7F7B656EE34B": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"9556DC99-828C-11CF-A37E-00AA003240C7": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"958F92D8-DA20-467A-BBE3-65E7E9B4EDCF": "[MS-TSGU]: Terminal Services Gateway Server Management Interface",
	"96DEB3B5-8B91-4A2A-9D93-80A35D8AA847": "[MS-FSRM]: File Server Resource Manager Protocol",
	"971668DC-C3FE-4EA1-9643-0C7230F494A1": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"97199110-DB2E-11D1-A251-0000F805CA53": "[MS-COM]: Component Object Model Plus (COM+) Protocol",
	"9723F420-9355-42DE-AB66-E31BB15BEEAC": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"98315903-7BE5-11D2-ADC1-00A02463D6E7": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"9882F547-CFC3-420B-9750-00DFBEC50662": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"99CC098F-A48A-4E9C-8E58-965C0AFC19D5": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"99FCFEC4-5260-101B-BBCB-00AA0021347A": "[MS-DCOM]: Distributed Component Object Model (DCOM) Remote",
	"9A2BF113-A329-44CC-809A-5C00FCE8DA40": "[MS-FSRM]: File Server Resource Manager Protocol",
	"9A653086-174F-11D2-B5F9-00104B703EFD": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"9AA58360-CE33-4F92-B658-ED24B14425B8": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"9B0353AA-0E52-44FF-B8B0-1F7FA0437F88": "[MS-UAMG]: Update Agent Management Protocol",
	"9BE77978-73ED-4A9A-87FD-13F09FEC1B13": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"9CBE50CA-F2D2-4BF4-ACE1-96896B729625": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"A0E8F27A-888C-11D1-B763-00C04FB926AF": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"A2EFAB31-295E-46BB-B976-E86D58B52E8B": "[MS-FSRM]: File Server Resource Manager Protocol",
	"A359DEC5-E813-4834-8A2A-BA7F1D777D76": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"A35AF600-9CF4-11CD-A076-08002B2BD711": "[MS-RDPESC]: Remote Desktop Protocol:",
	"A376DD5E-09D4-427F-AF7C-FED5B6E1C1D6": "[MS-UAMG]: Update Agent Management Protocol",
	"A4F1DB00-CA47-1067-B31F-00DD010662DA": "[MS-OXCRPC]: Wire Format Protocol",
	"A5ECFC73-0013-4A9E-951C-59BF9735FDDA": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"A6D3E32B-9814-4409-8DE3-CFA673E6D3DE": "[MS-CSVP]: Failover Cluster:",
	"A7F04F3C-A290-435B-AADF-A116C3357A5C": "[MS-UAMG]: Update Agent Management Protocol",
	"A8927A41-D3CE-11D1-8472-006008B0E5CA": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"A8E0653C-2744-4389-A61D-7373DF8B2292": "[MS-FSRVP]: File Server Remote VSS Protocol",
	"AD55F10B-5F11-4BE7-94EF-D9EE2E470DED": "[MS-FSRM]: File Server Resource Manager Protocol",
	"ADA4E6FB-E025-401E-A5D0-C3134A281F07": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"AE1C7110-2F60-11D3-8A39-00C04F72D8E3": "[MS-SCMP]: Shadow Copy Management Protocol",
	"AE33069B-A2A8-46EE-A235-DDFD339BE281": "[MS-PAN]: Print System Asynchronous Notification Protocol",
	"AFA8BD80-7D8A-11C9-BEF4-08002B102989": "[MS-RPCE]: Remote Management Interface",
	"AFC052C2-5315-45AB-841B-C6DB0E120148": "[MS-FSRM]: File Server Resource Manager Protocol",
	"AFC07E2E-311C-4435-808C-C483FFEEC7C9": "[MS-CAPR]: Central Access Policy Identifier (ID) Retrieval Protocol",
	"B0076FEC-A921-4034-A8BA-090BC6D03BDE": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"B057DC50-3059-11D1-8FAF-00A024CB6019": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"B06A64E3-814E-4FF9-AFAC-597AD32517C7": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"B07FEDD4-1682-4440-9189-A39B55194DC5": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"B0D1AC4B-F87A-49B2-938F-D439248575B2": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"B196B284-BAB4-101A-B69C-00AA00341D07": "[MC-MQAC]: Message Queuing (MSMQ):",
	"B196B285-BAB4-101A-B69C-00AA00341D07": "[MC-MQAC]: Message Queuing (MSMQ):",
	"B196B286-BAB4-101A-B69C-00AA00341D07": "[MC-MQAC]: Message Queuing (MSMQ):",
	"B196B287-BAB4-101A-B69C-00AA00341D07": "[MC-MQAC]: Message Queuing (MSMQ):",
	"B383CD1A-5CE9-4504-9F63-764B1236F191": "[MS-UAMG]: Update Agent Management Protocol",
	"B481498C-8354-45F9-84A0-0BDD2832A91F": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"B4FA8E86-2517-4A88-BD67-75447219EEE4": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"B60040E0-BCF3-11D1-861D-0080C729264D": "[MS-COMT]: Component Object Model Plus (COM+) Tracker Service",
	"B6B22DA8-F903-4BE7-B492-C09D875AC9DA": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"B7D381EE-8860-47A1-8AF4-1F33B2B1F325": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"B80F3C42-60E0-4AE0-9007-F52852D3DBED": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"B9785960-524F-11DF-8B6D-83DCDED72085": "[MS-GKDI]: Group Key Distribution Protocol",
	"B97DB8B2-4C63-11CF-BFF6-08002BE23F2F": "[MS-CMRP]: Failover Cluster:",
	"BB36EA26-6318-4B8C-8592-F72DD602E7A5": "[MS-FSRM]: File Server Resource Manager Protocol",
	"BB39332C-BFEE-4380-AD8A-BADC8AFF5BB6": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"BB39E296-AD26-42C5-9890-5325333BB11E": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"BBA9CB76-EB0C-462C-AA1B-5D8C34415701": "[MS-ADTS]: Active Directory Technical Specification",
	"BC5513C8-B3B8-4BF7-A4D4-361C0D8C88BA": "[MS-UAMG]: Update Agent Management Protocol",
	"BC681469-9DD9-4BF4-9B3D-709F69EFE431": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"BD0C73BC-805B-4043-9C30-9A28D64DD7D2": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"BDE95FDF-EEE0-45DE-9E12-E5A61CD0D4FE": "[MS-TSTS]: Terminal Services Terminal Server Runtime Interface",
	"BE56A644-AF0E-4E0E-A311-C1D8E695CBFF": "[MS-UAMG]: Update Agent Management Protocol",
	"BE5F0241-E489-4957-8CC4-A452FCF3E23E": "[MC-MQAC]: Message Queuing (MSMQ):",
	"BEE7CE02-DF77-4515-9389-78F01C5AFC1A": "[MS-FSRM]: File Server Resource Manager Protocol",
	"C10A76D8-1FE4-4C2F-B70D-665265215259": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"C1C2F21A-D2F4-4902-B5C6-8A081C19A890": "[MS-UAMG]: Update Agent Management Protocol",
	"C2BE6970-DF9E-11D1-8B87-00C04FD7A924": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"C2BFB780-4539-4132-AB8C-0A8772013AB6": "[MS-UAMG]: Update Agent Management Protocol",
	"C323BE28-E546-4C23-A81B-D6AD8D8FAC7B": "[MS-RAINPS]: Remote Administrative Interface:",
	"C3FCC19E-A970-11D2-8B5A-00A0C9B7C9C4": "[MS-IOI]: IManagedObject Interface Protocol",
	"C49E32C6-BC8B-11D2-85D4-00105A1F8304": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"C49E32C7-BC8B-11D2-85D4-00105A1F8304": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"C4B0C7D9-ABE0-4733-A1E1-9FDEDF260C7A": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"C5C04795-321C-4014-8FD6-D44658799393": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"C5CEBEE2-9DF5-4CDD-A08C-C2471BC144B4": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"C681D488-D850-11D0-8C52-00C04FD90F7E": "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol",
	"C726744E-5735-4F08-8286-C510EE638FB6": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"C72B09DB-4D53-4F41-8DCC-2D752AB56F7C": "[MS-CSVP]: Failover Cluster:",
	"C8550BFF-5281-4B1E-AC34-99B6FA38464D": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"C97AD11B-F257-420B-9D9F-377F733F6F68": "[MS-UAMG]: Update Agent Management Protocol",
	"CB0DF960-16F5-4495-9079-3F9360D831DF": "[MS-FSRM]: File Server Resource Manager Protocol",
	"CCD8C074-D0E5-4A40-92B4-D074FAA6BA28": "[MS-SWN]: Service Witness Protocol",
	"CEB5D7B4-3964-4F71-AC17-4BF57A379D87": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"CFADAC84-E12C-11D1-B34C-00C04F990D54": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"CFE36CBA-1949-4E74-A14F-F1D580CEAF13": "[MS-FSRM]: File Server Resource Manager Protocol",
	"D02E4BE0-3419-11D1-8FB1-00A024CB6019": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"D049B186-814F-11D1-9A3C-00C04FC9B232": "[MS-FRS1]: File Replication Service Protocol",
	"D2D79DF5-3400-11D0-B40B-00AA005FF586": "[MS-DMRP]: Disk Management Remote Protocol",
	"D2D79DF7-3400-11D0-B40B-00AA005FF586": "[MS-DMRP]: Disk Management Remote Protocol",
	"D2DC89DA-EE91-48A0-85D8-CC72A56F7D04": "[MS-FSRM]: File Server Resource Manager Protocol",
	"D3766938-9FB7-4392-AF2F-2CE8749DBBD0": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"D40CFF62-E08C-4498-941A-01E25F0FD33C": "[MS-UAMG]: Update Agent Management Protocol",
	"D4781CD6-E5D3-44DF-AD94-930EFE48A887": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"D5D23B6D-5A55-4492-9889-397A3C2D2DBC": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"D6105110-8917-41A5-AA32-8E0AA2933DC9": "[MS-CSVP]: Failover Cluster:",
	"D61A27C6-8F53-11D0-BFA0-00A024151983": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"D646567D-26AE-4CAA-9F84-4E0AAD207FCA": "[MS-FSRM]: File Server Resource Manager Protocol",
	"D68168C9-82A2-4F85-B6E9-74707C49A58F": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"D6BD6D63-E8CB-4905-AB34-8A278C93197A": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"D6C7CD8F-BB8D-4F96-B591-D3A5F1320269": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"D71B2CAE-33E8-4567-AE96-3CCF31620BE2": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"D7AB3341-C9D3-11D1-BB47-0080C7C5A2C0": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E072-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E073-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E074-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E075-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E076-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E077-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E078-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E079-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E07A-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E07B-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E07C-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E07D-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E07E-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E07F-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E080-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E081-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E082-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E083-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E084-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E085-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D7D6E086-DCCD-11D0-AA4B-0060970DEBAE": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D8CC81D9-46B8-4FA4-BFA5-4AA9DEC9B638": "[MS-FSRM]: File Server Resource Manager Protocol",
	"D95AFE70-A6D5-4259-822E-2C84DA1DDB0D": "[MS-RSP]: Remote Shutdown Protocol",
	"D9933BE0-A567-11D2-B0F3-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"D99BDAAE-B13A-4178-9FDB-E27F16B4603E": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"D99E6E70-FC88-11D0-B498-00A0C90312F3": "[MS-WCCE]: Windows Client Certificate Enrollment Protocol",
	"D99E6E71-FC88-11D0-B498-00A0C90312F3": "[MS-CSRA]: Certificate Services Remote Administration Protocol",
	"D9A59339-E245-4DBD-9686-4D5763E39624": "[MS-UAMG]: Update Agent Management Protocol",
	"DA5A86C5-12C2-4943-AB30-7F74A813D853": "[MS-PCQ]: Performance Counter Query Protocol",
	"DB90832F-6910-4D46-9F5E-9FD6BFA73903": "[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol",
	"DC12A681-737F-11CF-884D-00AA004B2E24": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"DD6F0A28-248F-4DD3-AFE9-71AED8F685C4": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"DDE02280-12B3-4E0B-937B-6747F6ACB286": "[MS-UAMG]: Update Agent Management Protocol",
	"DE095DB1-5368-4D11-81F6-EFEF619B7BCF": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"DEB01010-3A37-4D26-99DF-E2BB6AE3AC61": "[MS-DMRP]: Disk Management Remote Protocol",
	"DF1941C5-FE89-4E79-BF10-463657ACF44D": "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol",
	"E0393303-90D4-4A97-AB71-E9B671EE2729": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"E1010359-3E5D-4ECD-9FE4-EF48622FDF30": "[MS-FSRM]: File Server Resource Manager Protocol",
	"E141FD54-B79E-4938-A6BB-D523C3D49FF1": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"E1568352-586D-43E4-933F-8E6DC4DE317A": "[MS-CSVP]: Failover Cluster:",
	"E1AF8308-5D1F-11C9-91A4-08002B14A0FA": "[MS-RPCE]: Endpoint Mapper",
	"E2842C88-07C3-4EB0-B1A9-D3D95E76FEF2": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"E33C0CC4-0482-101A-BC0C-02608C6BA218": "[MS-RPCL]: Remote Procedure Call Location Services Extensions",
	"E3514235-4B06-11D1-AB04-00C04FC2DCD2": "[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol",
	"E3C9B851-C442-432B-8FC6-A7FAAFC09D3B": "[MS-CSVP]: Failover Cluster:",
	"E3D0D746-D2AF-40FD-8A7A-0D7078BB7092": "[MS-BPAU]: Background Intelligent Transfer Service (BITS) Peer-",
	"E645744B-CAE5-4712-ACAF-13057F7195AF": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"E65E8028-83E8-491B-9AF7-AAF6BD51A0CE": "[MS-DFSRH]: DFS Replication Helper Protocol",
	"E7927575-5CC3-403B-822E-328A6B904BEE": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"E7A4D634-7942-4DD9-A111-82228BA33901": "[MS-UAMG]: Update Agent Management Protocol",
	"E8BCFFAC-B864-4574-B2E8-F1FB21DFDC18": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"E8FB8620-588F-11D2-9D61-00C04F79C5FE": "[MS-IISS]: Internet Information Services (IIS) ServiceControl",
	"E946D148-BD67-4178-8E22-1C44925ED710": "[MS-FSRM]: File Server Resource Manager Protocol",
	"EA0A3165-4834-11D2-A6F8-00C04FA346CC": "[MS-FAX]: Fax Server and Client Remote Protocol",
	"EAFE4895-A929-41EA-B14D-613E23F62B71": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"EBA96B0E-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B0F-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B10-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B11-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B12-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B13-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B14-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B15-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B16-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B17-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B18-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B19-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B1A-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B1B-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B1C-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B1D-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B1E-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B1F-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B20-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B21-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B22-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B23-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EBA96B24-2168-11D3-898C-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"ED35F7A1-5024-4E7B-A44D-07DDAF4B524D": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"ED8BFE40-A60B-42EA-9652-817DFCFA23EC": "[MS-UAMG]: Update Agent Management Protocol",
	"EDE0150F-E9A3-419C-877C-01FE5D24C5D3": "[MS-FSRM]: File Server Resource Manager Protocol",
	"EE2D5DED-6236-4169-931D-B9778CE03DC6": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"EE321ECB-D95E-48E9-907C-C7685A013235": "[MS-FSRM]: File Server Resource Manager Protocol",
	"EF0574E0-06D8-11D3-B100-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"EF13D885-642C-4709-99EC-B89561C6BC69": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"EFF90582-2DDC-480F-A06D-60F3FBC362C3": "[MS-UAMG]: Update Agent Management Protocol",
	"F093FE3D-8131-4B73-A742-EF54C20B337B": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"F120A684-B926-447F-9DF4-C966CB785648": "[MS-RAI]: Remote Assistance Initiation Protocol",
	"F131EA3E-B7BE-480E-A60D-51CB2785779E": "[MS-COMA]: Component Object Model Plus (COM+) Remote",
	"F1D6C29C-8FBE-4691-8724-F6D8DEAEAFC8": "[MS-CSVP]: Failover Cluster:",
	"F1E9C5B2-F59B-11D2-B362-00105A1F8177": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"F309AD18-D86A-11D0-A075-00C04FB68820": "[MS-WMI]: Windows Management Instrumentation Remote Protocol",
	"F31931A9-832D-481C-9503-887A0E6A79F0": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"F3637E80-5B22-4A2B-A637-BBB642B41CFC": "[MS-FSRM]: File Server Resource Manager Protocol",
	"F411D4FD-14BE-4260-8C40-03B7C95E608A": "[MS-FSRM]: File Server Resource Manager Protocol",
	"F4A07D63-2E25-11D1-9964-00C04FBBB345": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"F5CC59B4-4264-101A-8C59-08002B2F8426": "[MS-FRS1]: File Replication Service Protocol",
	"F5CC5A18-4264-101A-8C59-08002B2F8426": "[MS-NSPI]: Name Service Provider Interface (NSPI) Protocol",
	"F612954D-3B0B-4C56-9563-227B7BE624B4": "[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW",
	"F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C": "[MS-EVEN6]: EventLog Remoting Protocol",
	"F72B9031-2F0C-43E8-924E-E6052CDC493F": "[MC-MQAC]: Message Queuing (MSMQ):",
	"F76FBF3B-8DDD-4B42-B05A-CB1C3FF1FEE8": "[MS-FSRM]: File Server Resource Manager Protocol",
	"F82E5729-6ABA-4740-BFC7-C7F58F75FB7B": "[MS-FSRM]: File Server Resource Manager Protocol",
	"F89AC270-D4EB-11D1-B682-00805FC79216": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"FA7660F6-7B3F-4237-A8BF-ED0AD0DCBBD9": "[MC-IISA]: Internet Information Services (IIS) Application Host COM",
	"FA7DF749-66E7-4986-A27F-E2F04AE53772": "[MS-SCMP]: Shadow Copy Management Protocol",
	"FB2B72A0-7A68-11D1-88F9-0080C7D771BF": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"FB2B72A1-7A68-11D1-88F9-0080C7D771BF": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"FBC1D17D-C498-43A0-81AF-423DDD530AF6": "[MS-COMEV]: Component Object Model Plus (COM+) Event System",
	"FC5D23E8-A88B-41A5-8DE0-2D2F73C5A630": "[MS-VDS]: Virtual Disk Service (VDS) Protocol",
	"FC910418-55CA-45EF-B264-83D4CE7D30E0": "[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol",
	"FD174A80-89CF-11D2-B0F2-00E02C074F6B": "[MC-MQAC]: Message Queuing (MSMQ):",
	"FDB3A030-065F-11D1-BB9B-00A024EA5525": "[MS-MQMP]: Message Queuing (MSMQ):",
	"FDF8A2B9-02DE-47F4-BC26-AA85AB5E5267": "[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card",
	"FE7F99F9-1DFB-4AFB-9D00-6A8DD0AABF2C": "[MS-ISTM]: iSCSI Software Target Management Protocol",
	"FF4FA04E-5A94-4BDA-A3A0-D5B4D3C52EBA": "[MS-FSRM]: File Server Resource Manager Protocol",
}

// Known providers by UUID (maps interface UUID to hosting DLL/EXE)
var knownProviders = map[string]string{
	"00000002-0001-0000-C000-000000000069": "kdcsvc.dll",
	"00000136-0000-0000-C000-000000000046": "rpcss.dll",
	"000001A0-0000-0000-C000-000000000046": "rpcss.dll",
	"00645E6C-FC9F-4A0C-9896-F00B66297798": "icardagt.exe",
	"048CF666-AB42-42B4-8975-1357018DECB3": "ws2_32.dll",
	"04EEB297-CBF4-466B-8A2A-BFD6A2F10BBA": "efssvc.dll",
	"05EBB278-E114-4EC1-A5A3-096153F300E4": "tsgqec.dll",
	"06BBA54A-BE05-49F9-B0A0-30F790261023": "wscsvc.dll",
	"0767A036-0D22-48AA-BA69-B619480F38CB": "pcasvc.dll",
	"0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53": "schedsvc.dll",
	"0B0A6584-9E0F-11CF-A3CF-00805F68CB1B": "rpcss.dll",
	"0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1": "spoolsv.exe",
	"0C821D64-A3FC-11D1-BB7A-0080C75E4EC1": "irftp.exe",
	"0D72A7D4-6148-11D1-B4AA-00C04FB66EA0": "cryptsvc.dll",
	"1088A980-EAE5-11D0-8D9B-00A02453C337": "mqqm.dll",
	"11220835-5B26-4D94-AE86-C3E475A809DE": "lsasrv.dll",
	"11899A43-2B68-4A76-92E3-A3D6AD8C26CE": "lsm.exe",
	"11F25515-C879-400A-989E-B074D5F092FE": "lsm.exe",
	"12345678-1234-ABCD-EF00-0123456789AB": "spoolsv.exe",
	"12345678-1234-ABCD-EF00-01234567CFFB": "netlogon.dll",
	"12345778-1234-ABCD-EF00-0123456789AB": "lsasrv.dll",
	"12345778-1234-ABCD-EF00-0123456789AC": "samsrv.dll",
	"12B81E99-F207-4A4C-85D3-77B42F76FD14": "seclogon.dll",
	"12D4B7C8-77D5-11D1-8C24-00C04FA3080D": "lserver.dll",
	"12E65DD8-887F-41EF-91BF-8D816C42C2E7": "winlogon.exe",
	"130CEEFB-E466-11D1-B78B-00C04FA32883": "ismip.dll",
	"15CD3850-28CA-11CE-A4E8-00AA006116CB": "PeerDistSvc.dll",
	"16E0CF3A-A604-11D0-96B1-00A0C91ECE30": "ntdsbsrv.dll",
	"17FDD703-1827-4E34-79D4-24A55C53BB37": "msgsvc.dll",
	"18F70770-8E64-11CF-9AF1-0020AF6E72F4": "ole32.dll",
	"1A9134DD-7B39-45BA-AD88-44D01CA47F28": "mqqm.dll",
	"1A927394-352E-4553-AE3F-7CF4AAFCA620": "wdssrv.dll",
	"1AA5E974-6282-4E8D-9C96-40186E89D280": "scss.exe",
	"1BDDB2A6-C0C3-41BE-8703-DDBDF4F0E80A": "dot3svc.dll",
	"1CBCAD78-DF0B-4934-B558-87839EA501C9": "lsasrv.dll",
	"1D55B526-C137-46C5-AB79-638F2A68E869": "rpcss.dll",
	"1DFCE5A8-DD8A-4E33-AACE-F603922FD9E7": "wpcsvc.dll",
	"1E665584-40FE-4450-8F6E-802362399694": "lsm.exe",
	"1F260487-BA29-4F13-928A-BBD29761B083": "termsrv.dll",
	"1FE1AF83-C95D-9111-A408-002B14A0FA03": "rpcss.dll",
	"1FF70682-0A51-30E8-076D-740BE8CEE98B": "taskcomp.dll",
	"201EF99A-7FA0-444C-9399-19BA84F12A1A": "appinfo.dll",
	"20610036-FA22-11CF-9823-00A0C911E5DF": "rasmans.dll",
	"209BB240-B919-11D1-BBB6-0080C75E4EC1": "irmon.dll",
	"22716894-FD8E-4462-9783-09E6D9531F16": "ubpm.dll",
	"24019106-A203-4642-B88D-82DAE9158929": "authui.dll",
	"25952C5D-7976-4AA1-A3CB-C35F7AE79D1B": "wlansvc.dll",
	"266F33B4-C7C1-4BD1-8F52-DDB8F2214EA9": "wlansvc.dll",
	"2ACB9D68-B434-4B3E-B966-E06B4B3A84CB": "bthserv.dll",
	"2C9A33D5-F1DB-472D-8464-42B8B0C76C38": "tbssvc.dll",
	"2EB08E3E-639F-4FBA-97B1-14F878961076": "gpsvc.dll",
	"2F59A331-BF7D-48CB-9E5C-7C090D76E8B8": "termsrv.dll",
	"2F5F3220-C126-1076-B549-074D078619DA": "netdde.exe",
	"2F5F6520-CA46-1067-B319-00DD010662DA": "tapisrv.dll",
	"2FB92682-6599-42DC-AE13-BD2CA89BD11C": "MPSSVC.dll",
	"300F3532-38CC-11D0-A3F0-0020AF6B0ADD": "trkwks.dll",
	"30ADC50C-5CBC-46CE-9A0E-91914789E23C": "nrpsrv.dll",
	"30B044A5-A225-43F0-B3A4-E060DF91F9C1": "certprop.dll",
	"326731E3-C1C0-4A69-AE20-7D9044A4EA5C": "profsvc.dll",
	"333A2276-0000-0000-0D00-00809C000000": "rpcrt4.dll",
	"33511F95-5B84-4DCC-B6CC-3F4B21DA53E1": "ubpm.dll",
	"3357951C-A1D1-47DB-A278-AB945D063D03": "LBService.dll",
	"338CD001-2244-31F1-AAAA-900038001003": "regsvc.dll",
	"342CFD40-3C6C-11CE-A893-08002B2E9C6D": "llssrv.exe",
	"3473DD4D-2E88-4006-9CBA-22570909DD10": "winhttp.dll",
	"367ABB81-9844-35F1-AD32-98F038001003": "services.exe",
	"369CE4F0-0FDC-11D3-BDE8-00C04F8EEE78": "profmap.dll",
	"378E52B0-C0A9-11CF-822D-00AA0051E40F": "taskcomp.dll",
	"3919286A-B10C-11D0-9BA8-00C04FD92EF5": "lsasrv.dll",
	"3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5": "dhcpcsvc.dll",
	"3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6": "dhcpcsvc6.dll",
	"3CA78105-A3A3-4A68-B458-1A606BAB8FD6": "mpnotify.exe",
	"3D267954-EEB7-11D1-B94E-00C04FA3080D": "lserver.dll",
	"3DDE7C30-165D-11D1-AB8F-00805F14DB40": "services.exe",
	"3F31C91E-2545-4B7B-9311-9529E8BFFEF6": "p2psvc.dll",
	"3FAF4738-3A21-4307-B46C-FDDA9BB8C0D5": "audiosrv.dll",
	"41208EE0-E970-11D1-9B9E-00E02C064C39": "mqqm.dll",
	"412F241E-C12A-11CE-ABFF-0020AF6E7A17": "rpcss.dll",
	"45776B01-5956-4485-9F80-F428F7D60129": "dnsrslvr.dll",
	"45F52C28-7F9F-101A-B52B-08002B2EFABE": "WINS.EXE",
	"46EA9280-5BBF-445E-831D-41D0F60F503A": "ifssvc.exe",
	"4825EA41-51E3-4C2A-8406-8F2D2698395F": "userenv.dll",
	"484809D6-4239-471B-B5BC-61DF8C23AC48": "lsm.exe",
	"497D95A6-2D27-4BF5-9BBD-A6046957133C": "termsrv.dll",
	"4A452661-8290-4B36-8FBE-7F4093A94978": "spoolsv.exe",
	"4A51DCF2-5C3A-4DD2-84DB-C3802EE7F9B7": "ntdsai.dll",
	"4A72BFE1-9294-11DA-A72B-0800200C9A66": "rdpinit.exe",
	"4B112204-0E19-11D3-B42B-0000F81FEB9F": "ssdpsrv.dll",
	"4B324FC8-1670-01D3-1278-5A47BF6EE188": "srvsvc.dll",
	"4BE96A0F-9F52-4729-A51D-C70610F118B0": "wbiosrvc.dll",
	"4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57": "rpcss.dll",
	"4DA1C422-943D-11D1-ACAE-00C04FC2AA3F": "trksvr.dll",
	"4F32ADC8-6052-4A04-8701-293CCF2096F0": "sspisrv.dll",
	"4F82F460-0E21-11CF-909E-00805F48A135": "nntpsvc.dll",
	"4F83DA7C-D2E8-9811-0700-C04F8EC85002": "sfc.dll",
	"4FC742E0-4A10-11CF-8273-00AA004AE673": "dfssvc.exe",
	"506C3B0E-4BD1-4C56-88C0-49A20ED4B539": "milcore.dll",
	"50ABC2A4-574D-40B3-9D66-EE4FD5FBA076": "dns.exe",
	"51C82175-844E-4750-B0D8-EC255555BC06": "SLsvc.exe",
	"5267AABA-4F49-4653-8E26-D1E11F3F2AD9": "termsrv.dll",
	"52D9F704-D3C6-4748-AD11-2550209E80AF": "IMEPADSM.DLL",
	"552D076A-CB29-4E44-8B6A-D15E59E2C0AF": "iphlpsvc.dll",
	"57674CD0-5200-11CE-A897-08002B2E9C6D": "llssrv.exe",
	"58E604E8-9ADB-4D2E-A464-3B0683FB1480": "appinfo.dll",
	"590B8BB3-4EF6-4CA4-83CF-BE06C4078674": "PSIService.exe",
	"5A7B91F8-FF00-11D0-A9B2-00C04FB636FC": "msgsvc.dll",
	"5A7B91F8-FF00-11D0-A9B2-00C04FB6E6FC": "msgsvc.dll",
	"5B5B3580-B0E0-11D1-B92D-0060081E87F0": "mqqm.dll",
	"5B821720-F63B-11D0-AAD2-00C04FC324DB": "dhcpssvc.dll",
	"5CA4A760-EBB1-11CF-8611-00A0245420ED": "termsrv.dll",
	"5CBE92CB-F4BE-45C9-9FC9-33E73E557B20": "lsasrv.dll",
	"5F54CE7D-5B79-4175-8584-CB65313A0E98": "appinfo.dll",
	"6099FC12-3EFF-11D0-ABD0-00C04FD91A4E": "FXSAPI.dll",
	"621DFF68-3C39-4C6C-AAE3-E68E2C6503AD": "wzcsvc.dll",
	"629B9F66-556C-11D1-8DD2-00AA004ABD5E": "sens.dll",
	"63FBE424-2029-11D1-8DB8-00AA004ABD5E": "Sens.dll",
	"647D4452-9F33-4A18-B2BE-C5C0E920E94E": "pla.dll",
	"64FE0B7F-9EF5-4553-A7DB-9A1975777554": "rpcss.dll",
	"654976DF-1498-4056-A15E-CB4E87584BD8": "emdmgmt.dll",
	"65A93890-FAB9-43A3-B2A5-1E330AC28F11": "dnsrslvr.dll",
	"68B58241-C259-4F03-A2E5-A2651DCBC930": "cryptsvc.dll",
	"68DCD486-669E-11D1-AB0C-00C04FC2DCD2": "ismserv.exe",
	"69510FA1-2F99-4EEB-A4FF-AF259F0F9749": "wecsvc.dll",
	"69C09EA0-4A09-101B-AE4B-08002B349A02": "ole32.dll",
	"6AF13C8B-0844-4C83-9064-1892BA825527": "tssdis.exe",
	"6B5BDD1E-528C-422C-AF8C-A4079BE4FE48": "FwRemoteSvr.dll",
	"6BFFD098-A112-3610-9833-012892020162": "browser.dll",
	"6BFFD098-A112-3610-9833-46C3F874532D": "dhcpssvc.dll",
	"6BFFD098-A112-3610-9833-46C3F87E345A": "wkssvc.dll",
	"6C9B7B96-45A8-4CCA-9EB3-E21CCF8B5A89": "umpo.dll",
	"6D9FE472-30F1-4708-8FA8-678362B96155": "wimserv.exe",
	"6E17AAA0-1A47-11D1-98BD-0000F875292E": "clussvc.exe",
	"6F201A55-A24D-495F-AAC9-2F4FCE34DF98": "iphlpsvc.dll",
	"6F201A55-A24D-495F-AAC9-2F4FCE34DF99": "IPHLPAPI.DLL",
	"708CCA10-9569-11D1-B2A5-0060977D8118": "mqdssrv.dll",
	"7212A04B-B463-402E-9649-2BA477394676": "umrdp.dll",
	"76D12B80-3467-11D3-91FF-0090272F9EA3": "mqqm.dll",
	"76F03F96-CDFD-44FC-A22C-64950A001209": "spoolsv.exe",
	"76F226C3-EC14-4325-8A99-6A46348418AE": "winlogon.exe",
	"76F226C3-EC14-4325-8A99-6A46348418AF": "winlogon.exe",
	"77850D46-851D-43B6-9398-290161F0CAE6": "SeVA.dll",
	"77DF7A80-F298-11D0-8358-00A024C480A8": "mqdssrv.dll",
	"7AF5BBD0-6063-11D1-AE2A-0080C75E4EC1": "irmon.dll",
	"7C44D7D4-31D5-424C-BD5E-2B3E1F323D22": "ntdsai.dll",
	"7D814569-35B3-4850-BB32-83035FCEBF6E": "ias.dll",
	"7E048D38-AC08-4FF1-8E6B-F35DBAB88D4A": "mqqm.dll",
	"7EA70BCF-48AF-4F6A-8968-6A440754D5FA": "nsisvc.dll",
	"7F9D11BF-7FB9-436B-A812-B2D50C5D4C03": "MPSSVC.dll",
	"811109BF-A4E1-11D1-AB54-00A0C91E9B45": "WINS.EXE",
	"8174BB16-571B-4C38-8386-1102B449044A": "p2psvc.dll",
	"81EE95A8-882E-4615-888A-53344CA149E4": "vpnikeapi.dll",
	"82273FDC-E32A-18C3-3F78-827929DC23EA": "wevtsvc.dll",
	"827BFCC4-38B4-4ACD-92E4-21E1506B85FB": "SLsvc.exe",
	"82AD4280-036B-11CF-972C-00AA006887B0": "infocomm.dll",
	"83DA4C30-EA3A-11CF-9CC1-08003601E506": "nfsclnt.exe",
	"83DA7C00-E84F-11D2-9807-00C04F8EC850": "sfc_os.dll",
	"86D35949-83C9-4044-B424-DB363231FD0C": "schedsvc.dll",
	"873F99B9-1B4D-9910-B7AA-0004007F0701": "ssmsrp70.dll",
	"88143FD0-C28D-4B2B-8FEF-8D882F6A9390": "lsm.exe",
	"8833D1D0-965F-4216-B3E9-FBE58CAD3100": "SCardSvr.dll",
	"894DE0C0-0D55-11D3-A322-00C04FA321A1": "wininit.exe",
	"89759FCE-5A25-4086-8967-DE12F39A60B5": "tssdjet.dll",
	"897E2E5F-93F3-4376-9C9C-FD2277495C27": "dfsrmig.exe",
	"8A7B5006-CC13-11DB-9705-005056C00008": "appidsvc.dll",
	"8C7A6DE0-788D-11D0-9EDF-444553540000": "wiaservc.dll",
	"8C7DAF44-B6DC-11D1-9A4C-0020AF6E7C57": "appmgmts.dll",
	"8CFB5D70-31A4-11CF-A7D8-00805F48A135": "smtpsvc.dll",
	"8D0FFE72-D252-11D0-BF8F-00C04FD9126B": "cryptsvc.dll",
	"8D9F4E40-A03D-11CE-8F69-08003E30051B": "services.exe",
	"8F09F000-B7ED-11CE-BBD2-00001A181CAD": "mprdim.dll",
	"8F1ACDC1-754D-43EB-9629-AA1620928E65": "IMEPADSM.DLL",
	"8FB6D884-2388-11D0-8C35-00C04FDA2795": "w32time.dll",
	"906B0CE0-C70B-1067-B317-00DD010662DA": "msdtcprx.dll",
	"91AE6020-9E3C-11CF-8D7C-00AA00C091BE": "certsrv.exe",
	"93149CA2-973B-11D1-8C39-00C04FB984F9": "scecli.dll",
	"9435CC56-1D9C-4924-AC7D-B60A2C3520E1": "sppsvc.exe",
	"95958C94-A424-4055-B62B-B7F4D5C47770": "winlogon.exe",
	"975201B0-59CA-11D0-A8D5-00A0C90D8051": "rpcss.dll",
	"98716D03-89AC-44C7-BB8C-285824E51C4A": "srvsvc.dll",
	"98E96949-BC59-47F1-92D1-8C25B46F85C7": "wlanext.exe",
	"98FE2C90-A542-11D0-A4EF-00A0C9062910": "advapi32.dll",
	"99FCFEC4-5260-101B-BBCB-00AA0021347A": "rpcss.dll",
	"9B3195FE-D603-43D1-A0D5-9072D7CDE122": "tssdjet.dll",
	"9B8699AE-0E44-47B1-8E7F-86A461D7ECDC": "rpcss.dll",
	"9D420415-B8FB-4F4A-8C53-4502EAD30CA9": "PlaySndSrv.dll",
	"9F3A53E6-CBB1-4E54-878E-AF9F823AA3F1": "MpRtMon.dll",
	"A002B3A0-C9B7-11D1-AE88-0080C75E4EC1": "wlnotify.dll",
	"A00C021C-2BE2-11D2-B678-0000F87A8F8E": "ntfrs.exe",
	"A0BC4698-B8D7-4330-A28F-7709E18B6108": "Sens.dll",
	"A2C45F7C-7D32-46AD-96F5-ADAFB486BE74": "services.exe",
	"A2D47257-12F7-4BEB-8981-0EBFA935C407": "p2psvc.dll",
	"A398E520-D59A-4BDD-AA7A-3C1E0303A511": "IKEEXT.DLL",
	"AA177641-FC9B-41BD-80FF-F964A701596F": "tssdis.exe",
	"AA411582-9BDF-48FB-B42B-FAA1EEE33949": "nlasvc.dll",
	"ACE1C026-8B3F-4711-8918-F345D17F5BFF": "lsasrv.dll",
	"AE33069B-A2A8-46EE-A235-DDFD339BE281": "spoolsv.exe",
	"AE55C4C0-64CE-11DD-AD8B-0800200C9A66": "bdesvc.dll",
	"AFA8BD80-7D8A-11C9-BEF4-08002B102989": "rpcrt4.dll",
	"B15B2F9F-903C-4671-8DC0-772C54214068": "pwmig.dll",
	"B253C301-78A2-4270-A91F-660DEE069F4C": "rdpcore.dll",
	"B25A52BF-E5DD-4F4A-AEA6-8CA7272A0E86": "keyiso.dll",
	"B58AA02E-2884-4E97-8176-4EE06D794184": "sysmain.dll",
	"B97DB8B2-4C63-11CF-BFF6-08002BE23F2F": "clussvc.exe",
	"B9E79E60-3D52-11CE-AAA1-00006901293F": "rpcss.dll",
	"BB8B98E8-84DD-45E7-9F34-C3FB6155EEED": "vaultsvc.dll",
	"BDE95FDF-EEE0-45DE-9E12-E5A61CD0D4FE": "termsrv.dll",
	"BFA951D1-2F0E-11D3-BFD1-00C04FA3490A": "aqueue.dll",
	"C0E9671E-33C6-4438-9464-56B2E1B1C7B4": "wbiosrvc.dll",
	"C100BEAB-D33A-4A4B-BF23-BBEF4663D017": "wcncsvc.dll",
	"C100BEAC-D33A-4A4B-BF23-BBEF4663D017": "wcncsvc.dll",
	"C13D3372-CC20-4449-9B23-8CC8271B3885": "rpcrt4.dll",
	"C33B9F46-2088-4DBC-97E3-6125F127661C": "nlasvc.dll",
	"C386CA3E-9061-4A72-821E-498D83BE188F": "audiosrv.dll",
	"C3F42C6E-D4CC-4E5A-938B-9C5E8A5D8C2E": "wlanmsm.dll",
	"C421ADCE-A0B2-480D-8418-984495B32D5F": "SLsvc.exe",
	"C503F532-443A-4C69-8300-CCD1FBDB3839": "MpSvc.dll",
	"C681D488-D850-11D0-8C52-00C04FD90F7E": "lsasrv.dll",
	"C6B5235A-E413-481D-9AC8-31681B1FAAF5": "SCardSvr.dll",
	"C6F3EE72-CE7E-11D1-B71E-00C04FC3111A": "rpcss.dll",
	"C80066A8-7579-44FC-B9B2-8466930791B0": "umrdp.dll",
	"C8CB7687-E6D3-11D2-A958-00C04F682E16": "WebClnt.dll",
	"C9378FF1-16F7-11D0-A0B2-00AA0061426A": "pstorsvc.dll",
	"C9AC6DB5-82B7-4E55-AE8A-E464ED7B4277": "sysntfy.dll",
	"CB407BBF-C14F-4CD9-8F55-CBB08146598C": "IMJPDCT.EXE",
	"D049B186-814F-11D1-9A3C-00C04FC9B232": "ntfrs.exe",
	"D2D79DFA-3400-11D0-B40B-00AA005FF586": "dmadmin.exe",
	"D335B8F6-CB31-11D0-B0F9-006097BA4E54": "polagent.dll",
	"D3FBB514-0E3B-11CB-8FAD-08002B1D29C3": "locator.exe",
	"D4254F95-08C3-4FCC-B2A6-0B651377A29C": "wwansvc.dll",
	"D4254F95-08C3-4FCC-B2A6-0B651377A29D": "wwansvc.dll",
	"D674A233-5829-49DD-90F0-60CF9CEB7129": "ipnathlp.dll",
	"D6D70EF0-0E3B-11CB-ACC3-08002B1D29C3": "locator.exe",
	"D6D70EF0-0E3B-11CB-ACC3-08002B1D29C4": "locator.exe",
	"D95AFE70-A6D5-4259-822E-2C84DA1DDB0D": "wininit.exe",
	"DA5A86C5-12C2-4943-AB30-7F74A813D853": "regsvc.dll",
	"DD490425-5325-4565-B774-7E27D6C09C24": "BFE.DLL",
	"DE3B9BC8-BEF7-4578-A0DE-F089048442DB": "audiodg.exe",
	"DE79FC6C-DC6F-43C7-A48E-63BBC8D4009D": "rdpclip.exe",
	"DF1941C5-FE89-4E79-BF10-463657ACF44D": "efssvc.dll",
	"E1AF8308-5D1F-11C9-91A4-08002B14A0FA": "rpcss.dll",
	"E248D0B8-BF15-11CF-8C5E-08002BB49649": "clussvc.exe",
	"E33C0CC4-0482-101A-BC0C-02608C6BA218": "locator.exe",
	"E3514235-4B06-11D1-AB04-00C04FC2DCD2": "ntdsai.dll",
	"E3D0D746-D2AF-40FD-8A7A-0D7078BB7092": "qmgr.dll",
	"E60C73E6-88F9-11CF-9AF1-0020AF6E72F4": "rpcss.dll",
	"E76EA56D-453F-11CF-BFEC-08002BE23F2F": "resrcmon.exe",
	"EA0A3165-4834-11D2-A6F8-00C04FA346CC": "FXSSVC.exe",
	"EC02CAE0-B9E0-11D2-BE62-0020AFEDDF63": "mq1repl.dll",
	"ECD85155-CC3A-4F10-AAD5-9A9A2BF2EF0C": "termsrv.dll",
	"ECEC0D70-A603-11D0-96B1-00A0C91ECE30": "ntdsbsrv.dll",
	"ED8F09F0-CEB7-BB11-D200-001A181CAD00": "mprdim.dll",
	"F1EC59AB-4CA9-4C30-B2D0-54EF1DB441B7": "iertutil.dll",
	"F3190C53-4E0C-491A-AAD3-2A7CEB7E25D4": "vpnikeapi.dll",
	"F50AAC00-C7F3-428E-A022-A6B71BFB9D43": "cryptsvc.dll",
	"F5CC59B4-4264-101A-8C59-08002B2F8426": "ntfrs.exe",
	"F5CC5A18-4264-101A-8C59-08002B2F8426": "ntdsai.dll",
	"F5CC5A7C-4264-101A-8C59-08002B2F8426": "ntdsa.dll",
	"F61C406F-BD60-4194-9565-BFEDD5256F70": "p2phost.exe",
	"F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C": "wevtsvc.dll",
	"FA4FEBC0-4591-11CE-95E5-00AA0051E510": "autmgr32.exe",
	"FB8A0729-2D04-4658-BE93-27B4AD553FAC": "lsass.exe",
	"FC13257D-5567-4DEA-898D-C6F9C48415A0": "mqqm.dll",
	"FD6BB951-C830-4734-BF2C-18BA6EC7AB49": "iscsiexe.dll",
	"FD7A0523-DC70-43DD-9B2E-9C5ED48225B1": "appinfo.dll",
	"FDB3A030-065F-11D1-BB9B-00A024EA5525": "mqqm.dll",
	"FFE561B8-BF15-11CF-8C5E-08002BB49649": "clussvc.exe",
}

// KnownUUIDs returns a sorted list of all known protocol UUIDs.
func KnownUUIDs() []string {
	uuids := make([]string, 0, len(knownProtocols))
	for k := range knownProtocols {
		uuids = append(uuids, k)
	}
	sort.Strings(uuids)
	return uuids
}

// LookupProtocol returns the protocol description for a given UUID, or "N/A" if unknown.
func LookupProtocol(uuid string) string {
	if p, ok := knownProtocols[uuid]; ok {
		return p
	}
	return "N/A"
}

// LookupProvider returns the provider for a given UUID, or "N/A" if unknown.
func LookupProvider(uuid string) string {
	if p, ok := knownProviders[uuid]; ok {
		return p
	}
	return "N/A"
}

func groupEndpoints(entries []rawEntry) []Endpoint {
	// Group by UUID
	groups := make(map[string]*Endpoint)
	order := []string{}

	for _, e := range entries {
		key := e.uuid + e.version
		if _, exists := groups[key]; !exists {
			groups[key] = &Endpoint{
				UUID:       e.uuid,
				Version:    e.version,
				Annotation: e.annotation,
				Protocol:   LookupProtocol(e.uuid),
				Provider:   LookupProvider(e.uuid),
				Bindings:   []string{},
			}
			order = append(order, key)
		}
		if e.binding != "" {
			groups[key].Bindings = append(groups[key].Bindings, e.binding)
		}
	}

	// Return in order
	var result []Endpoint
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

// MapTCPEndpoint queries the endpoint mapper for the TCP port of the given interface.
func MapTCPEndpoint(host string, interfaceUUID [16]byte, interfaceVer uint16) (int, error) {
	// Connect to endpoint mapper on port 135
	transport, err := dcerpc.DialTCP(host, 135)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to endpoint mapper: %v", err)
	}
	defer transport.Close()

	client := dcerpc.NewClientTCP(transport)

	// Bind to endpoint mapper
	if err := client.Bind(UUID, MajorVersion, MinorVersion); err != nil {
		return 0, fmt.Errorf("failed to bind to endpoint mapper: %v", err)
	}

	// Build ept_map request
	// The request contains a "map tower" that specifies what we're looking for
	payload := buildEptMapRequest(interfaceUUID, interfaceVer)

	if build.Debug {
		log.Printf("[D] EPM: Sending ept_map request for interface %x", interfaceUUID)
	}

	resp, err := client.Call(OpEptMap, payload)
	if err != nil {
		return 0, fmt.Errorf("ept_map call failed: %v", err)
	}

	// Parse the response to extract the TCP port
	port, err := parseEptMapResponse(resp)
	if err != nil {
		return 0, err
	}

	if build.Debug {
		log.Printf("[D] EPM: Found endpoint on port %d", port)
	}

	return port, nil
}

// buildEptMapRequest constructs the ept_map request payload.
func buildEptMapRequest(interfaceUUID [16]byte, interfaceVer uint16) []byte {
	buf := new(bytes.Buffer)

	// [in] handle_t h - implicit
	// [in] UUID* object - NULL pointer (referent ID = 0)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// [in] twr_p_t map_tower
	// Build a tower requesting the interface over TCP/IP
	tower := buildTower(interfaceUUID, interfaceVer)

	// Tower pointer (referent ID, non-null)
	binary.Write(buf, binary.LittleEndian, uint32(1))

	// Tower is a conformant structure: max_count + actual tower data
	// twr_t: tower_length (uint32) + tower_octet_string[]
	towerLen := uint32(len(tower))
	binary.Write(buf, binary.LittleEndian, towerLen) // max_count (conformant array)
	binary.Write(buf, binary.LittleEndian, towerLen) // tower_length field
	buf.Write(tower)

	// Align to 4 bytes after tower
	if len(tower)%4 != 0 {
		buf.Write(make([]byte, 4-(len(tower)%4)))
	}

	// [in, out] ept_lookup_handle_t* entry_handle - zeroed context handle
	buf.Write(make([]byte, 20))

	// [in] unsigned32 max_towers
	binary.Write(buf, binary.LittleEndian, uint32(4))

	return buf.Bytes()
}

// buildTower constructs an RPC tower for the interface over TCP/IP.
func buildTower(interfaceUUID [16]byte, interfaceVer uint16) []byte {
	buf := new(bytes.Buffer)

	// Number of floors (5 for TCP/IP)
	binary.Write(buf, binary.LittleEndian, uint16(5))

	// Floor 1: Interface UUID
	// LHS: protocol identifier (0x0D) + UUID + version
	floor1LHS := new(bytes.Buffer)
	floor1LHS.WriteByte(ProtocolUUID)
	floor1LHS.Write(interfaceUUID[:])
	binary.Write(floor1LHS, binary.LittleEndian, interfaceVer)
	// LHS length
	binary.Write(buf, binary.LittleEndian, uint16(floor1LHS.Len()))
	buf.Write(floor1LHS.Bytes())
	// RHS: minor version
	binary.Write(buf, binary.LittleEndian, uint16(2)) // RHS length
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Minor version

	// Floor 2: Transfer Syntax (NDR)
	floor2LHS := new(bytes.Buffer)
	floor2LHS.WriteByte(ProtocolUUID)
	floor2LHS.Write(header.TransferSyntaxNDR[:])
	binary.Write(floor2LHS, binary.LittleEndian, uint16(2)) // NDR version
	binary.Write(buf, binary.LittleEndian, uint16(floor2LHS.Len()))
	buf.Write(floor2LHS.Bytes())
	binary.Write(buf, binary.LittleEndian, uint16(2)) // RHS length
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Minor version

	// Floor 3: RPC Protocol
	binary.Write(buf, binary.LittleEndian, uint16(1)) // LHS length
	buf.WriteByte(ProtocolDCERPC)
	binary.Write(buf, binary.LittleEndian, uint16(2)) // RHS length
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Minor version

	// Floor 4: TCP (port will be returned)
	binary.Write(buf, binary.LittleEndian, uint16(1)) // LHS length
	buf.WriteByte(ProtocolTCP)
	binary.Write(buf, binary.LittleEndian, uint16(2)) // RHS length
	binary.Write(buf, binary.LittleEndian, uint16(0)) // Port (0 = any)

	// Floor 5: IP Address
	binary.Write(buf, binary.LittleEndian, uint16(1)) // LHS length
	buf.WriteByte(ProtocolIP)
	binary.Write(buf, binary.LittleEndian, uint16(4)) // RHS length
	buf.Write([]byte{0, 0, 0, 0})                     // IP (0.0.0.0 = any)

	return buf.Bytes()
}

// parseEptMapResponse extracts the TCP port from the ept_map response.
func parseEptMapResponse(resp []byte) (int, error) {
	if len(resp) < 28 {
		return 0, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	r := bytes.NewReader(resp)

	// Skip entry_handle (20 bytes)
	r.Seek(20, 0)

	// num_towers
	var numTowers uint32
	binary.Read(r, binary.LittleEndian, &numTowers)

	if numTowers == 0 {
		return 0, fmt.Errorf("no endpoints returned")
	}

	if build.Debug {
		log.Printf("[D] EPM: Response contains %d tower(s)", numTowers)
	}

	// Skip max_count and offset for conformant array
	r.Seek(8, 1) // Skip max_count (4) + offset (4)

	// Read actual_count
	var actualCount uint32
	binary.Read(r, binary.LittleEndian, &actualCount)

	if actualCount == 0 {
		return 0, fmt.Errorf("no tower entries")
	}

	// Read tower pointers (one per actualCount entry)
	towerPtrs := make([]uint32, actualCount)
	for i := uint32(0); i < actualCount; i++ {
		binary.Read(r, binary.LittleEndian, &towerPtrs[i])
	}

	if towerPtrs[0] == 0 {
		return 0, fmt.Errorf("null tower pointer")
	}

	// Deferred tower data follows the pointer array.
	// Each tower: max_count (4) + tower_length (4) + tower_data[]

	// Tower: max_count (conformant array size)
	var towerMaxCount uint32
	binary.Read(r, binary.LittleEndian, &towerMaxCount)

	// Tower: tower_length field
	var towerLen uint32
	binary.Read(r, binary.LittleEndian, &towerLen)

	if towerLen == 0 {
		return 0, fmt.Errorf("empty tower")
	}

	// Read number of floors
	var numFloors uint16
	binary.Read(r, binary.LittleEndian, &numFloors)

	if build.Debug {
		log.Printf("[D] EPM: Tower has %d floors", numFloors)
	}

	// Parse floors to find TCP port
	for i := 0; i < int(numFloors); i++ {
		var lhsLen uint16
		binary.Read(r, binary.LittleEndian, &lhsLen)

		lhsData := make([]byte, lhsLen)
		r.Read(lhsData)

		var rhsLen uint16
		binary.Read(r, binary.LittleEndian, &rhsLen)

		rhsData := make([]byte, rhsLen)
		r.Read(rhsData)

		// Check if this is the TCP floor
		if lhsLen == 1 && lhsData[0] == ProtocolTCP && rhsLen == 2 {
			port := int(binary.BigEndian.Uint16(rhsData))
			return port, nil
		}
	}

	return 0, fmt.Errorf("TCP port not found in tower")
}
