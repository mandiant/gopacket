package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	payloadSize = 156
	protocolICMP = 1
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "gopacket v0.1.0 - ping\n\n")
		fmt.Fprintf(os.Stderr, "Simple ICMP ping using raw sockets.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <src ip> <dst ip>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nNote: Requires root/CAP_NET_RAW privileges.\n")
		os.Exit(1)
	}

	srcIP := os.Args[1]
	dstIP := os.Args[2]

	// Validate IP addresses
	src := net.ParseIP(srcIP)
	if src == nil || src.To4() == nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid source IPv4 address: %s\n", srcIP)
		os.Exit(1)
	}

	dst := net.ParseIP(dstIP)
	if dst == nil || dst.To4() == nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid destination IPv4 address: %s\n", dstIP)
		os.Exit(1)
	}

	// Open raw ICMP socket
	conn, err := icmp.ListenPacket("ip4:icmp", srcIP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open raw socket: %v\n", err)
		fmt.Fprintf(os.Stderr, "    (Try running with sudo or as root)\n")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("PING %s from %s: %d data bytes\n", dstIP, srcIP, payloadSize)

	// Create payload
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = 'A'
	}

	seqID := 0
	for {
		seqID++

		// Build ICMP echo request
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  seqID,
				Data: payload,
			},
		}

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to marshal ICMP message: %v\n", err)
			continue
		}

		// Send the packet
		start := time.Now()
		_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: dst})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to send ICMP packet: %v\n", err)
			continue
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		// Wait for reply
		reply := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("Request timeout for icmp_seq %d\n", seqID)
			} else {
				fmt.Fprintf(os.Stderr, "[-] Read error: %v\n", err)
			}
			time.Sleep(1 * time.Second)
			continue
		}

		duration := time.Since(start)

		// Parse the reply
		rm, err := icmp.ParseMessage(protocolICMP, reply[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to parse ICMP reply: %v\n", err)
			continue
		}

		// Check if it's an echo reply
		if rm.Type == ipv4.ICMPTypeEchoReply {
			echo, ok := rm.Body.(*icmp.Echo)
			if ok {
				fmt.Printf("%d bytes from %s: icmp_seq=%d time=%.3f ms\n",
					n, peer.String(), echo.Seq, float64(duration.Microseconds())/1000.0)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

// calculateChecksum computes the ICMP checksum
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}

	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}
