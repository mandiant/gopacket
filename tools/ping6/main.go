// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	payloadSize    = 156
	protocolICMPv6 = 58
)

func main() {
	fmt.Println("gopacket v0.1.0 - ping6")
	fmt.Println()

	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Simple ICMPv6 ping using raw sockets.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <src ip> <dst ip>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nNote: Requires root/CAP_NET_RAW privileges.\n")
		os.Exit(1)
	}

	srcIP := os.Args[1]
	dstIP := os.Args[2]

	// Validate IP addresses
	src := net.ParseIP(srcIP)
	if src == nil || src.To4() != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid source IPv6 address: %s\n", srcIP)
		os.Exit(1)
	}

	dst := net.ParseIP(dstIP)
	if dst == nil || dst.To4() != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid destination IPv6 address: %s\n", dstIP)
		os.Exit(1)
	}

	// Open raw ICMPv6 socket
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", srcIP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open raw socket: %v\n", err)
		fmt.Fprintf(os.Stderr, "    (Try running with sudo or as root)\n")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("PING %s %d data bytes\n", dstIP, payloadSize)

	// Create payload
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = 'A'
	}

	seqID := 0
	for {
		seqID++

		// Build ICMPv6 echo request
		msg := icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  seqID,
				Data: payload,
			},
		}

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to marshal ICMPv6 message: %v\n", err)
			continue
		}

		// Send the packet
		start := time.Now()
		_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: dst})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to send ICMPv6 packet: %v\n", err)
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
		rm, err := icmp.ParseMessage(protocolICMPv6, reply[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to parse ICMPv6 reply: %v\n", err)
			continue
		}

		// Check if it's an echo reply
		if rm.Type == ipv6.ICMPTypeEchoReply {
			echo, ok := rm.Body.(*icmp.Echo)
			if ok {
				// Calculate reply size (subtract ICMP header)
				replySize := n - 4
				fmt.Printf("%d bytes from %s: icmp_seq=%d time=%.3f ms\n",
					replySize, peer.String(), echo.Seq, float64(duration.Microseconds())/1000.0)
			}
		}

		time.Sleep(1 * time.Second)
	}
}
