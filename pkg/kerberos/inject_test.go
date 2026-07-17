package kerberos

import (
	"context"
	"net"
	"testing"
	"time"
)

type recordingDialer struct {
	called           bool
	ctx              context.Context
	network, address string
	conn             net.Conn
	err              error
}

func (r *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r.called = true
	r.ctx = ctx
	r.network = network
	r.address = address
	return r.conn, r.err
}

func TestContextKDCDialerForwardsWithTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rd := &recordingDialer{conn: a}
	ad := contextKDCDialer{d: rd}

	got, err := ad.Dial("tcp", "kdc:88")
	if err != nil {
		t.Fatalf("Dial err: %v", err)
	}
	if got != a {
		t.Fatalf("Dial returned %v, want forwarded conn", got)
	}
	if !rd.called || rd.network != "tcp" || rd.address != "kdc:88" {
		t.Fatalf("forwarded (%q,%q) called=%v, want (tcp,kdc:88) true", rd.network, rd.address, rd.called)
	}
	dl, ok := rd.ctx.Deadline()
	if !ok {
		t.Fatalf("expected a KDC connect deadline")
	}
	if d := time.Until(dl); d <= 9*time.Second || d > 10*time.Second {
		t.Fatalf("KDC deadline %v, want ~10s", d)
	}
}

func TestWithKDCDialerSetsDialer(t *testing.T) {
	rd := &recordingDialer{}
	var kc kdcConfig
	WithKDCDialer(rd)(&kc)
	if kc.dialer == nil {
		t.Fatalf("WithKDCDialer did not set the dialer")
	}
}
