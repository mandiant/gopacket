// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package relay

import (
	"fmt"
	"log"

	"gopacket/internal/build"
)

// RelayPipeTransport implements dcerpc.Transport over a raw SMB2 relay pipe.
// Uses SMB2 WRITE + READ for pipe communication (more compatible than IOCTL).
type RelayPipeTransport struct {
	client   *SMBRelayClient
	fileID   [16]byte
	writeBuf []byte
	readBuf  []byte
	readOff  int
}

// NewRelayPipeTransport creates a transport adapter for the given pipe.
func NewRelayPipeTransport(client *SMBRelayClient, fileID [16]byte) *RelayPipeTransport {
	return &RelayPipeTransport{
		client: client,
		fileID: fileID,
	}
}

// Write buffers data for the next send operation.
func (t *RelayPipeTransport) Write(b []byte) (int, error) {
	t.writeBuf = append(t.writeBuf, b...)
	if build.Debug {
		log.Printf("[D] RelayPipe: buffered %d bytes (total: %d)", len(b), len(t.writeBuf))
	}
	return len(b), nil
}

// Read sends buffered write data via SMB2 WRITE, then reads response via SMB2 READ.
func (t *RelayPipeTransport) Read(b []byte) (int, error) {
	// If we have buffered write data, send it via SMB2 WRITE first
	if len(t.writeBuf) > 0 {
		if build.Debug {
			log.Printf("[D] RelayPipe: writing %d bytes to pipe", len(t.writeBuf))
		}
		if err := t.client.WritePipe(t.fileID, t.writeBuf); err != nil {
			t.writeBuf = nil
			return 0, fmt.Errorf("write pipe failed: %v", err)
		}
		t.writeBuf = nil

		// Read response via SMB2 READ
		if build.Debug {
			log.Printf("[D] RelayPipe: reading response from pipe")
		}
		data, err := t.client.ReadPipe(t.fileID, 65536)
		if err != nil {
			return 0, fmt.Errorf("read pipe failed: %v", err)
		}
		t.readBuf = data
		t.readOff = 0
	}

	// Return data from the read buffer
	if t.readOff < len(t.readBuf) {
		n := copy(b, t.readBuf[t.readOff:])
		t.readOff += n
		if build.Debug {
			log.Printf("[D] RelayPipe: read returned %d bytes", n)
		}
		return n, nil
	}

	// No buffered data - need to read more from the pipe (overflow)
	if build.Debug {
		log.Printf("[D] RelayPipe: reading overflow via SMB2 READ")
	}
	data, err := t.client.ReadPipe(t.fileID, 65536)
	if err != nil {
		return 0, err
	}
	t.readBuf = data
	t.readOff = 0
	n := copy(b, t.readBuf)
	t.readOff += n
	return n, nil
}

// Close closes the pipe handle.
func (t *RelayPipeTransport) Close() error {
	return t.client.ClosePipe(t.fileID)
}
