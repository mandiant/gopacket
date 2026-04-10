// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Supported datalink types
const (
	DLT_EN10MB    = 1   // Ethernet
	DLT_LINUX_SLL = 113 // Linux cooked capture
)

var (
	ifaceName  = flag.String("i", "", "Interface to sniff on (skip interactive selection)")
	listIfaces = flag.Bool("l", false, "List available interfaces and exit")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `gopacket v0.1.0 - sniff

Simple packet sniffer using pcap.

Usage: %s [options] [BPF filter]

Options:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  %s                     # Interactive interface selection, capture all
  %s -i eth0             # Capture all packets on eth0
  %s -i eth0 tcp port 80 # Capture HTTP traffic on eth0
  %s -l                  # List available interfaces

Note: Requires root/CAP_NET_RAW privileges.
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	fmt.Println("gopacket v0.1.0 - sniff")
	fmt.Println()

	// List interfaces mode
	if *listIfaces {
		listInterfaces()
		return
	}

	// Collect BPF filter from remaining arguments
	filter := strings.Join(flag.Args(), " ")

	if err := runSniffer(*ifaceName, filter); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}

func listInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Available interfaces:")
	for i, dev := range devices {
		desc := dev.Name
		if dev.Description != "" {
			desc = fmt.Sprintf("%s (%s)", dev.Name, dev.Description)
		}
		var addrs []string
		for _, addr := range dev.Addresses {
			addrs = append(addrs, addr.IP.String())
		}
		if len(addrs) > 0 {
			desc = fmt.Sprintf("%s [%s]", desc, strings.Join(addrs, ", "))
		}
		fmt.Printf("%d - %s\n", i, desc)
	}
}

func runSniffer(specifiedIface, filter string) error {
	// Get interface to sniff on
	var iface string
	var err error
	if specifiedIface != "" {
		iface = specifiedIface
	} else {
		iface, err = getInterface()
		if err != nil {
			return err
		}
	}

	// Open interface for capturing
	// snaplen=1500, promisc=false, timeout=100ms
	handle, err := pcap.OpenLive(iface, 1500, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface, err)
	}
	defer handle.Close()

	// Validate datalink type
	linkType := handle.LinkType()
	switch int(linkType) {
	case DLT_EN10MB, DLT_LINUX_SLL:
		// Supported
	default:
		return fmt.Errorf("datalink type not supported: %d (%s)", linkType, linkType.String())
	}

	// Set BPF filter if provided
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("failed to set BPF filter '%s': %v", filter, err)
		}
	}

	// Get network info
	netAddr, maskAddr := getNetworkInfo(iface)

	fmt.Printf("Listening on %s: net=%s, mask=%s, linktype=%d\n",
		iface, netAddr, maskAddr, linkType)
	fmt.Println()

	// Start packet capture
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacket(packet)
	}

	return nil
}

func getInterface() (string, error) {
	// Find all available interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("failed to find interfaces: %v", err)
	}

	if len(devices) == 0 {
		return "", fmt.Errorf("you don't have enough permissions to open any interface on this system")
	}

	// Filter to only interfaces that are up and have addresses
	var validDevices []pcap.Interface
	for _, dev := range devices {
		// Skip loopback for default selection, but still list it
		validDevices = append(validDevices, dev)
	}

	if len(validDevices) == 0 {
		return "", fmt.Errorf("no usable interfaces found")
	}

	// Only one interface, use it
	if len(validDevices) == 1 {
		fmt.Println("Only one interface present, defaulting to it.")
		return validDevices[0].Name, nil
	}

	// List interfaces and ask user to choose
	for i, dev := range validDevices {
		desc := dev.Name
		if dev.Description != "" {
			desc = fmt.Sprintf("%s (%s)", dev.Name, dev.Description)
		}
		// Show addresses if available
		var addrs []string
		for _, addr := range dev.Addresses {
			addrs = append(addrs, addr.IP.String())
		}
		if len(addrs) > 0 {
			desc = fmt.Sprintf("%s [%s]", desc, strings.Join(addrs, ", "))
		}
		fmt.Printf("%d - %s\n", i, desc)
	}

	// Read user selection
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Please select an interface: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %v", err)
	}

	input = strings.TrimSpace(input)
	idx, err := strconv.Atoi(input)
	if err != nil || idx < 0 || idx >= len(validDevices) {
		return "", fmt.Errorf("invalid interface selection: %s", input)
	}

	return validDevices[idx].Name, nil
}

func getNetworkInfo(ifaceName string) (string, string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "unknown", "unknown"
	}

	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		return "unknown", "unknown"
	}

	// Get first IPv4 address
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				return ipnet.IP.String(), net.IP(ipnet.Mask).String()
			}
		}
	}

	return "unknown", "unknown"
}

func printPacket(packet gopacket.Packet) {
	// Build a human-readable representation similar to Impacket's output
	var output strings.Builder

	// Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		output.WriteString(fmt.Sprintf("Ether: %s -> %s (type: 0x%04x)\n",
			eth.SrcMAC, eth.DstMAC, uint16(eth.EthernetType)))
	}

	// Linux SLL layer
	if sllLayer := packet.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
		sll := sllLayer.(*layers.LinuxSLL)
		output.WriteString(fmt.Sprintf("Linux SLL: type=%d, protocol=0x%04x\n",
			sll.PacketType, uint16(sll.EthernetType)))
	}

	// IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		output.WriteString(fmt.Sprintf("  IP: %s -> %s (proto: %d, len: %d, ttl: %d, id: %d)\n",
			ip.SrcIP, ip.DstIP, ip.Protocol, ip.Length, ip.TTL, ip.Id))
	}

	// IPv6 layer
	if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		output.WriteString(fmt.Sprintf("  IPv6: %s -> %s (next: %d, len: %d, hop: %d)\n",
			ip6.SrcIP, ip6.DstIP, ip6.NextHeader, ip6.Length, ip6.HopLimit))
	}

	// TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flags := getTCPFlags(tcp)
		output.WriteString(fmt.Sprintf("    TCP: %d -> %d (seq: %d, ack: %d, flags: %s, win: %d)\n",
			tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, flags, tcp.Window))
	}

	// UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		output.WriteString(fmt.Sprintf("    UDP: %d -> %d (len: %d)\n",
			udp.SrcPort, udp.DstPort, udp.Length))
	}

	// ICMP layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		output.WriteString(fmt.Sprintf("    ICMP: type=%d, code=%d, id=%d, seq=%d\n",
			icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq))
	}

	// ICMPv6 layer
	if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6 := icmp6Layer.(*layers.ICMPv6)
		output.WriteString(fmt.Sprintf("    ICMPv6: type=%d, code=%d\n",
			icmp6.TypeCode.Type(), icmp6.TypeCode.Code()))
	}

	// ARP layer
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		output.WriteString(fmt.Sprintf("  ARP: op=%d, sender=%s (%s), target=%s (%s)\n",
			arp.Operation,
			net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.SourceProtAddress),
			net.HardwareAddr(arp.DstHwAddress), net.IP(arp.DstProtAddress)))
	}

	// DNS layer
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		output.WriteString(fmt.Sprintf("      DNS: id=%d, qr=%v, questions=%d, answers=%d\n",
			dns.ID, dns.QR, len(dns.Questions), len(dns.Answers)))
	}

	// Application payload
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			// Show first 64 bytes of payload
			showLen := len(payload)
			if showLen > 64 {
				showLen = 64
			}
			output.WriteString(fmt.Sprintf("      Data (%d bytes): %q\n", len(payload), payload[:showLen]))
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
