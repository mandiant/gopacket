package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return proxy.Dial(ctx, network, fmt.Sprintf("%s:%s", host, port))
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
