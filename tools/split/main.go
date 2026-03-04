package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Supported datalink types
const (
	DLT_EN10MB    = 1   // Ethernet
	DLT_LINUX_SLL = 113 // Linux cooked capture
)

// Connection represents a TCP connection between two peers
type Connection struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// Key returns a unique key for this connection (order-independent)
func (c Connection) Key() string {
	// Normalize so that the same connection in either direction has the same key
	if c.SrcIP < c.DstIP || (c.SrcIP == c.DstIP && c.SrcPort < c.DstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", c.DstIP, c.DstPort, c.SrcIP, c.SrcPort)
}

// Filename returns the output filename for this connection
func (c Connection) Filename() string {
	return fmt.Sprintf("%s.%d-%s.%d.pcap", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
}

// ConnectionWriter holds the file and writer for a connection
type ConnectionWriter struct {
	file   *os.File
	writer *pcapgo.Writer
}

func main() {
	fmt.Println("gopacket v0.1.0 - split")
	fmt.Println()
	fmt.Println("[!] This tool is deprecated and may be removed in future versions.")
	fmt.Println()

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Pcap dump splitter - splits a pcap file by TCP connections\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <filename>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	if err := splitPcap(filename); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}

func splitPcap(filename string) error {
	// Open the pcap file
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("failed to open pcap file: %v", err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	fmt.Printf("Reading from %s: linktype=%d (%s)\n", filename, linkType, linkType.String())

	// Validate supported datalink types
	switch int(linkType) {
	case DLT_EN10MB:
		// Ethernet - supported
	case DLT_LINUX_SLL:
		// Linux cooked capture - supported
	default:
		return fmt.Errorf("datalink type not supported: %d (%s)", linkType, linkType.String())
	}

	// Set BPF filter for TCP packets
	if err := handle.SetBPFFilter("ip proto \\tcp"); err != nil {
		// Try without escape
		if err := handle.SetBPFFilter("tcp"); err != nil {
			return fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	// Map to track connections and their writers
	connections := make(map[string]*ConnectionWriter)
	defer func() {
		// Close all connection files
		for _, cw := range connections {
			cw.file.Close()
		}
	}()

	// Get snapshot length for writers
	snapLen := handle.SnapLen()

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Get IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Get TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		// Build connection info
		conn := Connection{
			SrcIP:   ip.SrcIP.String(),
			SrcPort: uint16(tcp.SrcPort),
			DstIP:   ip.DstIP.String(),
			DstPort: uint16(tcp.DstPort),
		}

		key := conn.Key()

		// Create writer if this is a new connection
		if _, exists := connections[key]; !exists {
			fn := conn.Filename()
			fmt.Printf("Found a new connection, storing into: %s\n", fn)

			file, err := os.Create(fn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Can't write packet to: %s (%v)\n", fn, err)
				continue
			}

			writer := pcapgo.NewWriter(file)
			if err := writer.WriteFileHeader(uint32(snapLen), linkType); err != nil {
				file.Close()
				fmt.Fprintf(os.Stderr, "Can't write pcap header to: %s (%v)\n", fn, err)
				continue
			}

			connections[key] = &ConnectionWriter{
				file:   file,
				writer: writer,
			}
		}

		// Write packet to the appropriate file
		cw := connections[key]
		ci := packet.Metadata().CaptureInfo
		if err := cw.writer.WritePacket(ci, packet.Data()); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing packet: %v\n", err)
		}
	}

	fmt.Printf("\n[*] Split into %d connection files\n", len(connections))
	return nil
}
