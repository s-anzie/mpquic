package quic

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/wire"
)

// ExperimentalSourcePath owns a dedicated client UDP transport to one accepted
// source generation. Close it after use. The source cannot replace path 0.
type ExperimentalSourcePath struct {
	path      *Path
	transport *Transport
	socket    *sourceDestinationConn
}

func (p *ExperimentalSourcePath) Close() error {
	p.socket.active.Store(false)
	p.socket.Close()
	_ = p.path.Close()
	return p.transport.Close()
}

// ID returns the dedicated multipath identifier.
func (p *ExperimentalSourcePath) ID() uint64 { return p.path.ID() }

// sourceDestinationConn pins both directions to the explicitly accepted worker.
// The ordinary path scheduler still addresses the primary; this dedicated
// transport maps that destination to the worker and accepts no other endpoint.
type sourceDestinationConn struct {
	net.PacketConn
	primary, worker netip.AddrPort
	expires         time.Time
	active          atomic.Bool
}

func (s *sourceDestinationConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	u, ok := addr.(*net.UDPAddr)
	if !ok || (u.AddrPort() != s.primary && u.AddrPort() != s.worker) || !s.active.Load() || !time.Now().Before(s.expires) {
		return 0, ErrExperimentalSourceOffer
	}
	return s.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(s.worker))
}

func (s *sourceDestinationConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := s.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if !s.active.Load() || !time.Now().Before(s.expires) {
			return 0, nil, ErrExperimentalSourceOffer
		}
		u, ok := addr.(*net.UDPAddr)
		if ok && u.AddrPort() == s.worker {
			return n, addr, nil
		}
	}
}

// ProbeExperimentalSource binds an already accepted generation to a fresh path
// and completes QUIC PATH_CHALLENGE/PATH_RESPONSE at the advertised worker UDP
// endpoint. The server must prepare its relay first. udp must be dedicated and
// unused; ownership transfers to the returned path, or it is closed on failure.
// No DNS lookup is performed. Caller acceptance policy precedes all probes.
func (c *Conn) ProbeExperimentalSource(ctx context.Context, id, generation uint64, udp *net.UDPConn) (_ *ExperimentalSourcePath, err error) {
	if udp == nil {
		return nil, ErrExperimentalSourceOffer
	}
	defer func() {
		if err != nil {
			udp.Close()
		}
	}()
	offers, err := c.ExperimentalSourceOffers(ctx)
	if err != nil {
		return nil, err
	}
	var offer ExperimentalSourceOffer
	for _, o := range offers {
		if o.ID == id && o.Generation == generation && o.Accepted && o.PathID == 0 {
			offer = o
			break
		}
	}
	primary, ok := c.RemoteAddr().(*net.UDPAddr)
	if offer.ID == 0 || !ok {
		return nil, ErrExperimentalSourceOffer
	}
	s := &sourceDestinationConn{PacketConn: udp, primary: primary.AddrPort(), worker: offer.Address, expires: offer.ExpiresAt}
	s.active.Store(true)
	tr := &Transport{Conn: s, ConnectionIDLength: c.srcConnIDLen}
	path, err := c.AddPath(tr)
	if err != nil {
		tr.Close()
		return nil, err
	}
	result := &ExperimentalSourcePath{path: path, transport: tr, socket: s}
	defer func() {
		if err != nil {
			result.Close()
		}
	}()
	err = (&ExperimentalCloneWriter{conn: c}).onLoop(ctx, func() error {
		e := c.experimentalSources.entries[id]
		if !e.accepted || e.frame.Generation != generation || e.pathID != 0 || e.frame.Address != offer.Address || !e.expires.After(time.Now()) {
			return ErrExperimentalSourceOffer
		}
		e.pathID, e.clientPath = path.ID(), result
		c.experimentalSources.entries[id] = e
		c.queueControlFrame(&wire.ExperimentalSourceAcceptFrame{ID: id, Generation: generation, PathID: path.ID()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = path.Probe(ctx); err != nil {
		return nil, err
	}
	// Withdrawal can race the final response.
	err = (&ExperimentalCloneWriter{conn: c}).onLoop(ctx, func() error {
		e := c.experimentalSources.entries[id]
		if e.clientPath != result || e.frame.Generation != generation || !e.expires.After(time.Now()) {
			return ErrExperimentalSourceOffer
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
