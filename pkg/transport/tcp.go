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

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultTimeout is the default connect timeout in seconds.
const DefaultTimeout = 30

// Dial opens a TCP connection. Routes through the configured proxy if one was
// set via Configure; otherwise uses the platform's direct dialer (libc
// connect() on Unix/cgo, net.Dialer elsewhere).
func Dial(network, address string) (net.Conn, error) {
	return DialTimeout(network, address, DefaultTimeout)
}

// DialTimeout is Dial with an explicit connect timeout in seconds.
// A non-positive timeoutSec is normalized to DefaultTimeout so the direct and
// proxy branches behave consistently.
func DialTimeout(network, address string, timeoutSec int) (net.Conn, error) {
	if timeoutSec <= 0 {
		timeoutSec = DefaultTimeout
	}
	if h := proxyHolder.Load(); h != nil {
		if strings.HasPrefix(network, "udp") {
			return nil, ErrUDPUnderProxy
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
		defer cancel()
		return h.cd.DialContext(ctx, network, address)
	}
	return directDial(network, address, timeoutSec)
}

// DialTLS opens a TCP connection (via proxy if configured) and wraps it in TLS.
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

// Dialer is a value-typed dialer suitable for APIs that expect a struct with a
// Dial method (e.g. pkg/smb, pkg/ldap). Respects the configured proxy.
type Dialer struct {
	TimeoutSec int
}

// Dial establishes a TCP connection to address. Routes through the proxy if configured.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return DialTimeout(network, address, d.TimeoutSec)
}

// ContextDialer is the value-typed counterpart of Dialer for APIs that expect
// a DialContext method (e.g. github.com/oiweiwei/go-msrpc/dcerpc.WithDialer,
// net/http.Transport.DialContext). Respects the configured proxy. The zero
// value works.
type ContextDialer struct{}

// DialContext routes through the configured proxy if set, honoring ctx.
func (ContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address)
}

func splitHostPort(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		if !strings.Contains(address, ":") {
			return address, "", fmt.Errorf("missing port in address: %s", address)
		}
		return "", "", fmt.Errorf("invalid address %q: %w", address, err)
	}
	return host, port, nil
}
