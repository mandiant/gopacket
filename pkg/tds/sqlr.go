// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package tds

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SQLRInstance represents a discovered SQL Server instance
type SQLRInstance struct {
	ServerName   string
	InstanceName string
	IsClustered  string
	Version      string
	TCP          string
	NamedPipe    string
}

// GetInstances queries the SQL Server Browser service for instances
func GetInstances(server string, timeout time.Duration) ([]SQLRInstance, error) {
	// Create UDP connection
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", server, SQLRPort))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send CLNT_UCAST_EX request
	request := []byte{SQLRClntUcastEx}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return parseInstanceResponse(buf[:n])
}

// GetInstancePort queries for a specific instance's port
func GetInstancePort(server, instance string, timeout time.Duration) (int, error) {
	// Create UDP connection
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", server, SQLRPort))
	if err != nil {
		return 0, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Send CLNT_UCAST_INST request
	request := append([]byte{SQLRClntUcastInst}, []byte(instance)...)
	request = append(request, 0x00) // Null terminator
	if _, err := conn.Write(request); err != nil {
		return 0, err
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	// Read response
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}

	instances, err := parseInstanceResponse(buf[:n])
	if err != nil {
		return 0, err
	}

	for _, inst := range instances {
		if strings.EqualFold(inst.InstanceName, instance) {
			var port int
			fmt.Sscanf(inst.TCP, "%d", &port)
			return port, nil
		}
	}

	return 0, fmt.Errorf("instance %s not found", instance)
}

// parseInstanceResponse parses the SQL Server Browser response
func parseInstanceResponse(data []byte) ([]SQLRInstance, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("response too short")
	}

	// Check response type
	if data[0] != 0x05 {
		return nil, fmt.Errorf("unexpected response type: 0x%02x", data[0])
	}

	// Get length
	// length := binary.LittleEndian.Uint16(data[1:3])
	payload := data[3:]

	// Split by double semicolon
	entries := strings.Split(string(payload), ";;")

	var instances []SQLRInstance
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		inst := SQLRInstance{}
		fields := strings.Split(entry, ";")

		for i := 0; i < len(fields)-1; i += 2 {
			key := fields[i]
			value := fields[i+1]

			switch key {
			case "ServerName":
				inst.ServerName = value
			case "InstanceName":
				inst.InstanceName = value
			case "IsClustered":
				inst.IsClustered = value
			case "Version":
				inst.Version = value
			case "tcp":
				inst.TCP = value
			case "np":
				inst.NamedPipe = value
			}
		}

		if inst.ServerName != "" || inst.InstanceName != "" {
			instances = append(instances, inst)
		}
	}

	return instances, nil
}
