// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

/*
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// libc_dial connects via libc's getaddrinfo + connect, which ARE hookable by LD_PRELOAD.
// Returns the file descriptor on success, or -1 (getaddrinfo fail) / -2 (connect fail) on error.
int libc_dial(const char *host, const char *port, int timeout_sec) {
    struct addrinfo hints, *res, *p;
    int sockfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;

        // Set connect timeout via SO_SNDTIMEO (Linux honors this for connect())
        if (timeout_sec > 0) {
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (p == NULL) return -2;

    // Clear the send timeout so it doesn't affect subsequent writes
    if (timeout_sec > 0) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    return sockfd;
}
*/
import "C"

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"unsafe"
)

// DefaultTimeout is the default connect timeout in seconds.
const DefaultTimeout = 30

// Dial connects to the address on the named network using libc's connect(),
// which is hookable by LD_PRELOAD-based proxies like proxychains.
// The address must be in "host:port" format.
func Dial(network, address string) (net.Conn, error) {
	return DialTimeout(network, address, DefaultTimeout)
}

// DialTimeout connects using libc's connect() with the given timeout in seconds.
func DialTimeout(network, address string, timeoutSec int) (net.Conn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}

	cHost := C.CString(host)
	cPort := C.CString(port)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPort))

	fd := C.libc_dial(cHost, cPort, C.int(timeoutSec))
	if fd == -1 {
		return nil, fmt.Errorf("getaddrinfo failed for %s", address)
	}
	if fd == -2 {
		return nil, fmt.Errorf("connect failed for %s", address)
	}

	// Convert C file descriptor to Go net.Conn
	f := os.NewFile(uintptr(fd), fmt.Sprintf("tcp:%s", address))
	conn, err := net.FileConn(f)
	f.Close() // FileConn dups the fd, so close the original
	if err != nil {
		return nil, fmt.Errorf("FileConn failed: %w", err)
	}
	return conn, nil
}

// DialTLS connects via libc then wraps the connection in TLS.
func DialTLS(network, address string, config *tls.Config) (*tls.Conn, error) {
	rawConn, err := Dial(network, address)
	if err != nil {
		return nil, err
	}
	host, _, _ := splitHostPort(address)
	if config.ServerName == "" {
		config = config.Clone()
		config.ServerName = host
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// Dialer provides a way to establish connections via libc.
type Dialer struct {
	TimeoutSec int
}

// Dial establishes a TCP connection to the specified address using libc's connect().
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	timeout := d.TimeoutSec
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return DialTimeout(network, address, timeout)
}
