package transport

import (
	"fmt"
	"net"
	"strings"
)

func splitHostPort(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		// Try treating the whole thing as a host (no port)
		if !strings.Contains(address, ":") {
			return address, "", fmt.Errorf("missing port in address: %s", address)
		}
		return "", "", fmt.Errorf("invalid address %q: %w", address, err)
	}
	return host, port, nil
}
