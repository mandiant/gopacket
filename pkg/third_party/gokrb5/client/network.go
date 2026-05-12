package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/iana/errorcode"
	"github.com/mandiant/gopacket/pkg/third_party/gokrb5/messages"
)

// DirectDialer is a KDCDialer that uses net.DialTimeout directly. Restores the
// pre-fork behavior; intended only for callers that explicitly do not want
// their KDC traffic routed through a transport layer (e.g. unit tests).
type DirectDialer struct{}

func (DirectDialer) Dial(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, 5*time.Second)
}

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		//1 means we should always use TCP
		rb, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %v", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		//Try UDP first, TCP second
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}
	return rb, nil
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return r, err
	}
	r, err = cl.dialSendUDP(kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialSendUDP establishes a UDP connection to a KDC via the injected dialer.
// The dialer receives the address verbatim (no local net.ResolveUDPAddr) so
// hostname resolution can be deferred to a SOCKS5 proxy when set.
func (cl *Client) dialSendUDP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		conn, err := cl.dialer.Dial("udp", kdcs[i])
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing UDP connection to %s: %v", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			conn.Close()
			continue
		}
		rb, err := sendUDP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendUDP sends bytes to connection over UDP. Uses the net.Conn Read/Write
// contract directly rather than the *net.UDPConn type assertion, so custom
// dialers returning any connected-UDP conn work without panic.
func sendUDP(conn net.Conn, b []byte) ([]byte, error) {
	var r []byte
	defer conn.Close()
	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %v", conn.RemoteAddr().String(), err)
	}
	// Max UDP payload — UDP datagrams larger than the buffer are silently
	// truncated by conn.Read. 65535 covers the protocol-max datagram so a
	// large KRB-ERROR or AS-REP cannot be silently mangled if UDP is ever
	// re-enabled.
	udpbuf := make([]byte, 65535)
	n, err := conn.Read(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %v", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return r, err
	}
	r, err = cl.dialSendTCP(kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialSendTCP establishes a TCP connection to a KDC via the injected dialer.
// The dialer receives the address verbatim (no local net.ResolveTCPAddr) so
// hostname resolution can be deferred to a SOCKS5 proxy when set.
func (cl *Client) dialSendTCP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		conn, err := cl.dialer.Dial("tcp", kdcs[i])
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing TCP connection to %s: %v", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			conn.Close()
			continue
		}
		rb, err := sendTCP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn net.Conn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	// io.ReadFull, not conn.Read: the 4-byte length header can arrive in
	// fragments over a SOCKS5 tunnel or any conn that doesn't fill on first
	// read. A short read here desyncs the stream and produces a corrupt length.
	sh := make([]byte, 4, 4)
	_, err = io.ReadFull(conn, sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	// Bound the allocation. A hostile or garbage 4-byte length prefix can
	// otherwise demand up to 4 GiB and OOM the process. Real KRB messages
	// (including PAC-bearing TGS responses) sit well under a megabyte; this
	// cap is generous but finite. Anything larger is almost certainly an
	// attacker-controlled proxy spewing HTML/junk into the framed stream.
	const maxKRBResponseBytes = 10 * 1024 * 1024
	if s > maxKRBResponseBytes {
		return r, fmt.Errorf("KDC response size %d exceeds %d-byte cap; refusing to allocate", s, maxKRBResponseBytes)
	}

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
