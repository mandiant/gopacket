package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"gopacket/pkg/dcerpc/epmapper"
	"gopacket/pkg/transport"

)

// MGMT interface UUID: afa8bd80-7d8a-11c9-bef4-08002b102989
var mgmtUUID = dcerpc.MustParseUUID("afa8bd80-7d8a-11c9-bef4-08002b102989")

const (
	mgmtMajorVersion = 1
	mgmtMinorVersion = 0
	opInqIfIDs       = 0
)

var (
	bruteUUIDs  = flag.Bool("brute-uuids", false, "Bruteforce UUIDs even if MGMT interface works")
	bruteOpnums = flag.Bool("brute-opnums", false, "Bruteforce opnums for each discovered UUID")
	bruteVers   = flag.Bool("brute-versions", false, "Bruteforce versions for each discovered UUID")
	opnumMax    = flag.Int("opnum-max", 64, "Max opnum to try when bruteforcing opnums")
	versionMax  = flag.Int("version-max", 64, "Max major version to try when bruteforcing versions")
	singleUUID  = flag.String("uuid", "", "Test a single UUID instead of all known UUIDs")
	debug       = flag.Bool("debug", false, "Turn DEBUG output ON")
)

type stringBinding struct {
	protocol string
	host     string
	endpoint string
}

func parseStringBinding(s string) (stringBinding, error) {
	// Format: protocol:host[endpoint]
	// e.g. ncacn_ip_tcp:192.168.0.1[135]
	colonIdx := strings.Index(s, ":")
	if colonIdx == -1 {
		return stringBinding{}, fmt.Errorf("invalid string binding %q: missing ':'", s)
	}

	proto := s[:colonIdx]
	rest := s[colonIdx+1:]

	var host, endpoint string
	bracketIdx := strings.Index(rest, "[")
	if bracketIdx == -1 {
		host = rest
	} else {
		host = rest[:bracketIdx]
		endBracket := strings.Index(rest, "]")
		if endBracket == -1 {
			return stringBinding{}, fmt.Errorf("invalid string binding %q: missing ']'", s)
		}
		endpoint = rest[bracketIdx+1 : endBracket]
	}

	return stringBinding{protocol: proto, host: host, endpoint: endpoint}, nil
}

type ifaceResult struct {
	uuid    string
	version string
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `gopacket v0.1.0 - rpcmap

Scans for listening MSRPC interfaces. Tries the MGMT interface first,
falls back to UUID bruteforce if MGMT is not available.

Usage: %s [options] string_binding

String Binding Format:
  ncacn_ip_tcp:host[port]    TCP transport
  ncacn_np:host[\pipe\name]  Named pipe transport (SMB)

Options:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  %s 'ncacn_ip_tcp:192.168.1.10[135]'
  %s -brute-uuids 'ncacn_ip_tcp:192.168.1.10[135]'
  %s -uuid 12345778-1234-abcd-ef00-0123456789ac 'ncacn_ip_tcp:192.168.1.10[135]'
`, os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("gopacket v0.1.0 - rpcmap")
	fmt.Println()

	if *debug {
		build.Debug = true
	}

	binding, err := parseStringBinding(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	if binding.protocol != "ncacn_ip_tcp" {
		fmt.Fprintf(os.Stderr, "[-] Only ncacn_ip_tcp transport is currently supported\n")
		os.Exit(1)
	}

	if binding.endpoint == "" {
		binding.endpoint = "135"
	}

	addr := net.JoinHostPort(binding.host, binding.endpoint)
	fmt.Printf("[*] Trying to connect to %s...\n", addr)

	mgmtWorked := false
	if !*bruteUUIDs {
		mgmtWorked = tryMGMT(binding.host, addr)
	}

	if !mgmtWorked || *bruteUUIDs {
		if *bruteUUIDs && mgmtWorked {
			fmt.Println()
			fmt.Println("[*] Bruteforcing UUIDs as requested...")
		} else if !mgmtWorked {
			fmt.Println("[*] MGMT interface not available, falling back to UUID bruteforce...")
		}
		bruteforceUUIDs(addr)
	}
}

func tryMGMT(host, addr string) bool {
	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to connect to %s: %v\n", addr, err)
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	transport := dcerpc.NewTCPTransport(conn)
	client := dcerpc.NewClientTCP(transport)

	// Try binding to MGMT interface
	err = client.Bind(mgmtUUID, mgmtMajorVersion, mgmtMinorVersion)
	if err != nil {
		if build.Debug {
			fmt.Printf("[D] MGMT bind failed: %v\n", err)
		}
		return false
	}

	fmt.Println("[*] Bound to MGMT interface, querying remote interface list...")
	fmt.Println()

	// Call inq_if_ids (opnum 0, empty stub)
	resp, err := client.Call(opInqIfIDs, []byte{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] inq_if_ids call failed: %v\n", err)
		return false
	}

	ifaces := parseIfIDVector(resp)

	// Add the MGMT interface itself (it won't list itself)
	ifaces = append(ifaces, ifaceResult{
		uuid:    "AFA8BD80-7D8A-11C9-BEF4-08002B102989",
		version: "v1.0",
	})

	// Sort by UUID to match Impacket output
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].uuid < ifaces[j].uuid
	})

	for _, iface := range ifaces {
		printIface(iface)
		if *bruteOpnums {
			bruteforceOpnums(addr, iface)
		}
	}

	fmt.Printf("[*] Received %d interfaces from MGMT.\n", len(ifaces))
	return true
}

func parseIfIDVector(data []byte) []ifaceResult {
	if len(data) < 8 {
		return nil
	}

	// NDR response for inq_if_ids:
	// [referent_id:4][count:4][max_count:4]
	// then count * [referent_id:4] (pointer array)
	// then count * [uuid:16 + ver_major:2 + ver_minor:2] (deferred data)
	// then [status:4]

	offset := 0

	// Read referent ID for the if_id_vector pointer
	if offset+4 > len(data) {
		return nil
	}
	offset += 4 // skip referent ID

	// Read count
	if offset+4 > len(data) {
		return nil
	}
	count := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if count == 0 || count > 1000 {
		return nil
	}

	// Read max_count (conformant array)
	if offset+4 > len(data) {
		return nil
	}
	offset += 4 // skip max_count

	// Read referent IDs for each pointer in the array
	if offset+int(count)*4 > len(data) {
		return nil
	}
	offset += int(count) * 4 // skip referent IDs

	// Now read the deferred data: each entry is uuid(16) + ver_major(2) + ver_minor(2) = 20 bytes
	var results []ifaceResult
	for i := 0; i < int(count); i++ {
		if offset+20 > len(data) {
			break
		}

		var uuid [16]byte
		copy(uuid[:], data[offset:offset+16])
		offset += 16

		major := binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		minor := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		uuidStr := strings.ToUpper(dcerpc.FormatUUID(uuid))
		results = append(results, ifaceResult{
			uuid:    uuidStr,
			version: fmt.Sprintf("v%d.%d", major, minor),
		})
	}

	return results
}

func printIface(iface ifaceResult) {
	protocol := epmapper.LookupProtocol(iface.uuid)
	provider := epmapper.LookupProvider(iface.uuid)
	fmt.Printf("Protocol: %s\n", protocol)
	fmt.Printf("Provider: %s\n", provider)
	fmt.Printf("UUID    : %s %s\n", iface.uuid, iface.version)
	fmt.Println()
}

func bruteforceUUIDs(addr string) {
	var uuids []string
	if *singleUUID != "" {
		uuids = []string{strings.ToUpper(*singleUUID)}
	} else {
		uuids = epmapper.KnownUUIDs()
	}

	found := 0
	for _, uuidStr := range uuids {
		if *bruteVers {
			for ver := 0; ver <= *versionMax; ver++ {
				if tryBindUUID(addr, uuidStr, uint16(ver), 0) {
					iface := ifaceResult{
						uuid:    uuidStr,
						version: fmt.Sprintf("v%d.0", ver),
					}
					printIface(iface)
					found++
					if *bruteOpnums {
						bruteforceOpnums(addr, iface)
					}
				}
			}
		} else {
			// Try version 1.0 by default (most common)
			if tryBindUUID(addr, uuidStr, 1, 0) {
				iface := ifaceResult{
					uuid:    uuidStr,
					version: "v1.0",
				}
				printIface(iface)
				found++
				if *bruteOpnums {
					bruteforceOpnums(addr, iface)
				}
			}
		}
	}

	fmt.Printf("[*] Found %d UUID(s) via bruteforce.\n", found)
}

func tryBindUUID(addr, uuidStr string, major, minor uint16) bool {
	uuid, err := dcerpc.ParseUUID(uuidStr)
	if err != nil {
		if build.Debug {
			fmt.Printf("[D] Invalid UUID %s: %v\n", uuidStr, err)
		}
		return false
	}

	// Each attempt uses a fresh TCP connection (matching Impacket behavior)
	conn, err := transport.DialTimeout("tcp", addr, 5)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	transport := dcerpc.NewTCPTransport(conn)
	client := dcerpc.NewClientTCP(transport)

	err = client.Bind(uuid, major, minor)
	return err == nil
}

func bruteforceOpnums(addr string, iface ifaceResult) {
	uuid, err := dcerpc.ParseUUID(iface.uuid)
	if err != nil {
		return
	}

	// Parse version
	var major, minor uint16
	fmt.Sscanf(iface.version, "v%d.%d", &major, &minor)

	for opnum := 0; opnum <= *opnumMax; opnum++ {
		// Each opnum test needs a fresh connection + bind
		conn, err := transport.DialTimeout("tcp", addr, 5)
		if err != nil {
			break
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		transport := dcerpc.NewTCPTransport(conn)
		client := dcerpc.NewClientTCP(transport)

		err = client.Bind(uuid, major, minor)
		if err != nil {
			conn.Close()
			break
		}

		// Try calling the opnum with empty stub data
		_, err = client.Call(uint16(opnum), []byte{})
		conn.Close()

		if err != nil {
			// Check if it's an RPC Fault with nca_s_op_rng_error (0x1c010002)
			// That means the opnum doesn't exist
			if strings.Contains(err.Error(), "0x1c010002") {
				// No more opnums
				fmt.Printf("[*] UUID %s %s: opnums 0-%d accessible\n", iface.uuid, iface.version, opnum-1)
				return
			}
			// Other fault = opnum exists but call failed (expected with empty stub)
			fmt.Printf("  [*] Opnum %d: exists (fault: %v)\n", opnum, err)
		} else {
			fmt.Printf("  [*] Opnum %d: success\n", opnum)
		}
	}
}
