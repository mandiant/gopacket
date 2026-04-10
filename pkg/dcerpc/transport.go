// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package dcerpc

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"gopacket/internal/build"
	"gopacket/pkg/thirdparty/smb2"
	"gopacket/pkg/transport"
	"log"
)

// Transport abstracts the underlying connection for DCE/RPC.
type Transport interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
}

// PipeTransport wraps an SMB2 named pipe using FSCTL_PIPE_TRANSCEIVE.
// This provides atomic request/response handling for DCE/RPC over named pipes.
type PipeTransport struct {
	Pipe       *smb2.File
	writeBuf   []byte // Buffers written data until Read() triggers Transact
	readBuf    []byte // Buffers response data from Transact
	readOffset int    // Current offset into readBuf
	maxOutput  int    // Maximum response size
}

func NewPipeTransport(pipe *smb2.File) *PipeTransport {
	return &PipeTransport{
		Pipe:      pipe,
		maxOutput: 65535, // Default max output size
	}
}

func (p *PipeTransport) Read(b []byte) (int, error) {
	// If we have buffered write data, perform the Transact now
	if len(p.writeBuf) > 0 {
		if build.Debug {
			log.Printf("[D] Pipe: Transact with %d bytes input", len(p.writeBuf))
		}
		output, err := p.Pipe.Transact(p.writeBuf, p.maxOutput)
		p.writeBuf = nil // Clear the write buffer
		if err != nil {
			// Handle buffer overflow - there's more data to read
			errMsg := fmt.Sprintf("%v", err)
			if strings.Contains(errMsg, "Buffer Overflow") || strings.Contains(errMsg, "STATUS_BUFFER_OVERFLOW") {
				p.readBuf = output
				p.readOffset = 0
				// Fall through to return available data
			} else {
				return 0, err
			}
		} else {
			p.readBuf = output
			p.readOffset = 0
		}
	}

	// Return data from the read buffer
	if p.readOffset < len(p.readBuf) {
		n := copy(b, p.readBuf[p.readOffset:])
		p.readOffset += n
		if build.Debug {
			log.Printf("[D] Pipe: Read returned %d bytes", n)
		}
		return n, nil
	}

	// No buffered data, need to read more from the pipe
	// This happens when DCE/RPC response is larger than single transact output
	if build.Debug {
		log.Printf("[D] Pipe: Reading additional data via SMB2_READ")
	}

	// Read into a large temporary buffer so we don't lose data when the
	// caller's buffer is smaller than the SMB2_READ response
	tmp := make([]byte, p.maxOutput)
	n, err := p.Pipe.Read(tmp)
	if n > 0 {
		// Buffer the data, then copy what fits into the caller's buffer
		p.readBuf = tmp[:n]
		p.readOffset = 0
		copied := copy(b, p.readBuf[p.readOffset:])
		p.readOffset += copied
		if build.Debug {
			log.Printf("[D] Pipe: SMB2_READ got %d bytes, returned %d to caller", n, copied)
		}
		return copied, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (p *PipeTransport) Write(b []byte) (int, error) {
	// Buffer the write data for the next Transact
	p.writeBuf = append(p.writeBuf, b...)
	if build.Debug {
		log.Printf("[D] Pipe: Buffered %d bytes for transact (total: %d)", len(b), len(p.writeBuf))
	}
	return len(b), nil
}

func (p *PipeTransport) Close() error {
	return p.Pipe.Close()
}

// TCPTransport wraps a raw TCP connection for ncacn_ip_tcp.
type TCPTransport struct {
	Conn net.Conn
}

func NewTCPTransport(conn net.Conn) *TCPTransport {
	return &TCPTransport{Conn: conn}
}

func (t *TCPTransport) Read(b []byte) (int, error) {
	return t.Conn.Read(b)
}

func (t *TCPTransport) Write(b []byte) (int, error) {
	return t.Conn.Write(b)
}

func (t *TCPTransport) Close() error {
	return t.Conn.Close()
}

// DialTCP connects to a remote host:port and returns a TCPTransport.
func DialTCP(host string, port int) (*TCPTransport, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	if build.Debug {
		log.Printf("[D] RPC: Dialing TCP %s", addr)
	}
	conn, err := transport.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// Set read/write deadlines to prevent hanging
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return NewTCPTransport(conn), nil
}

// readFull reads exactly len(buf) bytes from transport, handling partial reads.
func readFull(t Transport, buf []byte) error {
	offset := 0
	for offset < len(buf) {
		n, err := t.Read(buf[offset:])
		offset += n

		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}

			errMsg := fmt.Sprintf("%v", err)

			// Handle "Buffer Overflow" which just means "More Data" for pipes
			if strings.Contains(errMsg, "Buffer Overflow") {
				continue
			}

			return err
		}
	}

	if build.Debug && len(buf) >= 4 {
		log.Printf("[D] RPC Read (%d bytes): %x", len(buf), buf)
	}

	return nil
}
