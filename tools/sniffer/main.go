// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Protocol name to number mapping
var protoMap = map[string]int{
	"icmp":   1,
	"igmp":   2,
	"tcp":    6,
	"udp":    17,
	"gre":    47,
	"icmpv6": 58,
	"ospf":   89,
	"sctp":   132,
}

func main() {
	fmt.Println("gopacket v0.1.0 - sniffer")
	fmt.Println()

	// Default protocols if none specified
	protocols := []string{"icmp", "tcp", "udp"}
	if len(os.Args) > 1 {
		protocols = os.Args[1:]
	} else {
		fmt.Printf("Using default set of protocols. A list of protocols can be supplied from the command line, eg.: %s <proto1> [proto2] ...\n", os.Args[0])
	}

	// Open raw sockets for each protocol
	var sockets []int
	var validProtos []string

	for _, proto := range protocols {
		protoLower := strings.ToLower(proto)
		protoNum, ok := protoMap[protoLower]
		if !ok {
			fmt.Printf("Ignoring unknown protocol: %s\n", proto)
			continue
		}

		// Create raw socket
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protoNum)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error creating socket for %s: %v\n", proto, err)
			fmt.Fprintf(os.Stderr, "    (requires root/CAP_NET_RAW)\n")
			continue
		}

		// Set IP_HDRINCL to include IP headers
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error setting IP_HDRINCL for %s: %v\n", proto, err)
			syscall.Close(fd)
			continue
		}

		sockets = append(sockets, fd)
		validProtos = append(validProtos, protoLower)
	}

	if len(sockets) == 0 {
		fmt.Fprintln(os.Stderr, "[-] There are no protocols available.")
		os.Exit(1)
	}

	// Cleanup on exit
	defer func() {
		for _, fd := range sockets {
			syscall.Close(fd)
		}
	}()

	fmt.Printf("Listening on protocols: %v\n", validProtos)
	fmt.Println()

	// Use goroutines to read from each socket
	packets := make(chan packetData, 100)
	for i, fd := range sockets {
		go readSocket(fd, validProtos[i], packets)
	}

	// Process packets
	for pkt := range packets {
		printPacket(pkt.proto, pkt.data)
	}
}

type packetData struct {
	proto string
	data  []byte
}

func readSocket(fd int, proto string, out chan<- packetData) {
	buf := make([]byte, 65535)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			out <- packetData{proto: proto, data: data}
		}
	}
}

func printPacket(proto string, data []byte) {
	// Decode as IP packet
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)

	var output strings.Builder

	// IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		output.WriteString(fmt.Sprintf("IP: %s -> %s (proto: %d, len: %d, ttl: %d, id: %d)\n",
			ip.SrcIP, ip.DstIP, ip.Protocol, ip.Length, ip.TTL, ip.Id))
	}

	// TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flags := getTCPFlags(tcp)
		output.WriteString(fmt.Sprintf("  TCP: %d -> %d (seq: %d, ack: %d, flags: %s, win: %d)\n",
			tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, flags, tcp.Window))
	}

	// UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		output.WriteString(fmt.Sprintf("  UDP: %d -> %d (len: %d)\n",
			udp.SrcPort, udp.DstPort, udp.Length))
	}

	// ICMP layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		output.WriteString(fmt.Sprintf("  ICMP: type=%d, code=%d, id=%d, seq=%d\n",
			icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq))
	}

	// GRE layer
	if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
		gre := greLayer.(*layers.GRE)
		output.WriteString(fmt.Sprintf("  GRE: protocol=0x%04x\n", uint16(gre.Protocol)))
	}

	// SCTP layer
	if sctpLayer := packet.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		sctp := sctpLayer.(*layers.SCTP)
		output.WriteString(fmt.Sprintf("  SCTP: %d -> %d\n", sctp.SrcPort, sctp.DstPort))
	}

	// Application payload
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			showLen := len(payload)
			if showLen > 64 {
				showLen = 64
			}
			// Check if printable
			if isPrintable(payload[:showLen]) {
				output.WriteString(fmt.Sprintf("  Data (%d bytes): %q\n", len(payload), payload[:showLen]))
			} else {
				output.WriteString(fmt.Sprintf("  Data (%d bytes): [binary]\n", len(payload)))
			}
		}
	}

	if output.Len() > 0 {
		fmt.Print(output.String())
		fmt.Println()
	}
}

func getTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "S")
	}
	if tcp.ACK {
		flags = append(flags, "A")
	}
	if tcp.FIN {
		flags = append(flags, "F")
	}
	if tcp.RST {
		flags = append(flags, "R")
	}
	if tcp.PSH {
		flags = append(flags, "P")
	}
	if tcp.URG {
		flags = append(flags, "U")
	}
	if len(flags) == 0 {
		return "."
	}
	return strings.Join(flags, "")
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			if b != '\n' && b != '\r' && b != '\t' {
				return false
			}
		}
	}
	return true
}

// Resolve protocol name to number (for extensibility)
func getProtoByName(name string) (int, error) {
	if num, ok := protoMap[strings.ToLower(name)]; ok {
		return num, nil
	}
	// Try system lookup
	if proto, err := net.LookupPort("ip", name); err == nil {
		return proto, nil
	}
	return 0, fmt.Errorf("unknown protocol: %s", name)
}
