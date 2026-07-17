package smb

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
)

// recordingDialer captures the last DialContext call and returns a canned conn.
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

func TestSocketDialerDefaultsToContextDialer(t *testing.T) {
	c := NewClient(session.Target{}, &session.Credentials{})
	if _, ok := c.socketDialer().(transport.ContextDialer); !ok {
		t.Fatalf("default socketDialer = %T, want transport.ContextDialer", c.socketDialer())
	}
}

func TestWithConnShortCircuitsDial(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rd := &recordingDialer{}
	c := NewClient(session.Target{Host: "h"}, &session.Credentials{}, WithConn(a), WithDialer(rd))

	got, err := c.dialConn(context.Background(), "h:445")
	if err != nil {
		t.Fatalf("dialConn err: %v", err)
	}
	if got != a {
		t.Fatalf("dialConn returned %v, want injected conn", got)
	}
	if rd.called {
		t.Fatalf("dialer must not be called when a conn is injected")
	}
}

func TestDialConnUsesInjectedDialerWithDefaultTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rd := &recordingDialer{conn: a}
	c := NewClient(session.Target{Host: "h"}, &session.Credentials{}, WithDialer(rd))

	got, err := c.dialConn(context.Background(), "h:445")
	if err != nil {
		t.Fatalf("dialConn err: %v", err)
	}
	if got != a {
		t.Fatalf("dialConn returned %v, want dialer conn", got)
	}
	if !rd.called || rd.network != "tcp" || rd.address != "h:445" {
		t.Fatalf("dialer got (%q,%q) called=%v, want (tcp,h:445) true", rd.network, rd.address, rd.called)
	}
	dl, ok := rd.ctx.Deadline()
	if !ok {
		t.Fatalf("expected a connect deadline on the context")
	}
	if d := time.Until(dl); d <= 29*time.Second || d > 30*time.Second {
		t.Fatalf("connect deadline %v, want ~30s", d)
	}
}

func TestCloseConnIfOwnedRespectsOwnership(t *testing.T) {
	// Injected conn (ownsConn == false): closeConnIfOwned must NOT close it.
	inA, inB := net.Pipe()
	defer inA.Close()
	defer inB.Close()
	injected := NewClient(session.Target{Host: "h"}, &session.Credentials{}, WithConn(inA))
	got, err := injected.dialConn(context.Background(), "h:445")
	if err != nil {
		t.Fatalf("dialConn err: %v", err)
	}
	injected.conn = got // mirror what Connect() does before the login-failure branch
	injected.closeConnIfOwned()
	// A caller-supplied conn must still be usable afterwards.
	if err := inA.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("injected conn closed by closeConnIfOwned: %v", err)
	}

	// Dialed conn (ownsConn == true): closeConnIfOwned must close it.
	dlA, dlB := net.Pipe()
	defer dlB.Close()
	dialed := NewClient(session.Target{Host: "h"}, &session.Credentials{}, WithDialer(&recordingDialer{conn: dlA}))
	got, err = dialed.dialConn(context.Background(), "h:445")
	if err != nil {
		t.Fatalf("dialConn err: %v", err)
	}
	dialed.conn = got
	dialed.closeConnIfOwned()
	if err := dlA.SetDeadline(time.Now().Add(time.Second)); err == nil {
		t.Fatalf("dialed conn not closed by closeConnIfOwned")
	}
}

func TestDialConnSetsOwnsConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Injected conn: client must NOT own it.
	injected := NewClient(session.Target{Host: "h"}, &session.Credentials{}, WithConn(a))
	if _, err := injected.dialConn(context.Background(), "h:445"); err != nil {
		t.Fatalf("dialConn err: %v", err)
	}
	if injected.ownsConn {
		t.Fatalf("ownsConn = true for an injected conn, want false")
	}

	// Dialed conn: client owns it.
	dialed := NewClient(session.Target{Host: "h"}, &session.Credentials{}, WithDialer(&recordingDialer{conn: a}))
	if _, err := dialed.dialConn(context.Background(), "h:445"); err != nil {
		t.Fatalf("dialConn err: %v", err)
	}
	if !dialed.ownsConn {
		t.Fatalf("ownsConn = false for a dialed conn, want true")
	}
}
