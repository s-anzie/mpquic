package quic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// ExperimentalSourceRelayALPN separates opaque packet forwarding from key jobs.
const ExperimentalSourceRelayALPN = "mpquic-clone-relay/1"

func checkSourceRelayTLS(c *tls.Conn, pin [32]byte) error {
	if c == nil {
		return ErrExperimentalSourceOffer
	}
	s := c.ConnectionState()
	if !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != ExperimentalSourceRelayALPN || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || sha256.Sum256(s.PeerCertificates[0].Raw) != pin {
		return ErrExperimentalSourceOffer
	}
	return nil
}

type sourceRelayPacket struct {
	address netip.AddrPort
	data    []byte
}

func writeSourceRelayPacket(c *tls.Conn, p sourceRelayPacket) error {
	if !p.address.IsValid() || p.address.Port() == 0 || len(p.data) == 0 || len(p.data) > 1452 {
		return ErrExperimentalSourceOffer
	}
	ip := p.address.Addr().As16()
	b := append([]byte(nil), ip[:]...)
	b = binary.BigEndian.AppendUint16(b, p.address.Port())
	b = append(b, p.data...)
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	return writeCloneRecord(c, b)
}

func readSourceRelayPacket(c *tls.Conn) (sourceRelayPacket, error) {
	b, err := readCloneRecord(c, 1470)
	if err != nil {
		return sourceRelayPacket{}, err
	}
	if len(b) <= 18 {
		return sourceRelayPacket{}, ErrExperimentalSourceOffer
	}
	ip := netip.AddrFrom16([16]byte(b[:16])).Unmap()
	addr := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[16:18]))
	if ip.IsUnspecified() || ip.IsMulticast() || addr.Port() == 0 {
		return sourceRelayPacket{}, ErrExperimentalSourceOffer
	}
	return sourceRelayPacket{addr, b[18:]}, nil
}

// ServeExperimentalSourceRelay forwards opaque QUIC datagrams over dedicated
// mutual TLS. It owns reads on udp; ServeExperimentalCloneWorker may concurrently
// send using the same socket. No receive keys leave the primary. Destination
// policy is mandatory for both directions. The caller retains ownership of udp.
func ServeExperimentalSourceRelay(ctx context.Context, control *tls.Conn, primaryPin [32]byte, udp *net.UDPConn, allow func(netip.AddrPort) bool) error {
	if err := checkSourceRelayTLS(control, primaryPin); err != nil {
		return err
	}
	defer control.Close()
	if udp == nil || allow == nil {
		return ErrExperimentalSourceOffer
	}
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	done := make(chan error, 1)
	go func() {
		for {
			p, err := readSourceRelayPacket(control)
			if err == nil && !allow(p.address) {
				err = ErrExperimentalSourceOffer
			}
			if err == nil {
				_, err = udp.WriteToUDPAddrPort(p.data, p.address)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	// Bounded UDP reads let a failed control channel stop this goroutine.
	defer udp.SetReadDeadline(time.Time{})
	buf := make([]byte, 1453)
	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}
		n, addr, err := udp.ReadFromUDPAddrPort(buf)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			return err
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if n == 0 || n > 1452 || buf[0]&0x80 != 0 || !allow(addr) {
			continue
		}
		if err := writeSourceRelayPacket(control, sourceRelayPacket{addr, buf[:n]}); err != nil {
			return err
		}
	}
}

type experimentalSourceRelay struct {
	conn           *Conn
	id, generation uint64
	control        *tls.Conn
	workerPin      [32]byte
	queue          chan sourceRelayPacket
}

// PrepareExperimentalSource attaches a dedicated authenticated forwarding channel
// to an announced generation before the client probes it. The worker must run
// ServeExperimentalSourceRelay on the advertised UDP socket. This method takes
// ownership of control on success; channel failure closes the QUIC connection.
func (c *Conn) PrepareExperimentalSource(ctx context.Context, id, generation uint64, control *tls.Conn, workerPin [32]byte) error {
	if err := checkSourceRelayTLS(control, workerPin); err != nil {
		return err
	}
	r := &experimentalSourceRelay{conn: c, id: id, generation: generation, control: control, workerPin: workerPin, queue: make(chan sourceRelayPacket, 64)}
	err := (&ExperimentalCloneWriter{conn: c}).onLoop(ctx, func() error {
		if c.perspective != protocol.PerspectiveServer || !c.sourceOffersNegotiated() || c.experimentalSources == nil {
			return ErrExperimentalSourceOffer
		}
		e, ok := c.experimentalSources.entries[id]
		if !ok || e.frame.Generation != generation || !e.expires.After(time.Now()) || e.frame.TTL == 0 || e.relay != nil {
			return ErrExperimentalSourceOffer
		}
		for _, other := range c.experimentalSources.entries {
			if other.relay != nil && other.relay.control == control {
				return ErrExperimentalSourceOffer
			}
		}
		e.relay = r
		c.experimentalSources.entries[id] = e
		if e.pathID != 0 {
			c.multipath.paths[e.pathID].experimentalRelay = r
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			control.Close()
			c.CloseWithError(0x100, "experimental source preparation canceled")
		}
		return err
	}
	go r.run()
	return nil
}

func (r *experimentalSourceRelay) current(pathID uint64) bool {
	e := r.conn.experimentalSources.entries[r.id]
	return e.relay == r && e.frame.Generation == r.generation && e.pathID == pathID && e.accepted && e.frame.TTL > 0 && e.expires.After(time.Now())
}

func (r *experimentalSourceRelay) run() {
	defer r.control.Close()
	defer r.conn.CloseWithError(0x100, "experimental source relay stopped")
	stop := context.AfterFunc(r.conn.ctx, func() { r.control.Close() })
	defer stop()
	go func() {
		defer r.control.Close()
		for {
			select {
			case <-r.conn.ctx.Done():
				return
			case p := <-r.queue:
				if err := writeSourceRelayPacket(r.control, p); err != nil {
					return
				}
			}
		}
	}()
	for {
		p, err := readSourceRelayPacket(r.control)
		if err != nil {
			return
		}
		if p.data[0]&0x80 != 0 {
			continue
		}
		// Admission and teardown share the connection loop. Never enqueue a
		// pooled buffer after the connection has stopped receiving packets.
		if err := (&ExperimentalCloneWriter{conn: r.conn}).onLoop(r.conn.ctx, func() error {
			r.conn.receivedPacketMx.Lock()
			defer r.conn.receivedPacketMx.Unlock()
			if r.conn.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets {
				return nil
			}
			b := getPacketBuffer()
			b.Data = append(b.Data, p.data...)
			r.conn.receivedPackets.PushBack(receivedPacket{buffer: b, data: b.Data, remoteAddr: net.UDPAddrFromAddrPort(p.address), rcvTime: monotime.Now(), ecn: protocol.ECNUnsupported, experimentalRelay: r})
			select {
			case r.conn.notifyReceivedPacket <- struct{}{}:
			default:
			}
			return nil
		}); err != nil {
			return
		}
	}
}

func (c *Conn) experimentalSourceReady(s ExperimentalCloneSource) bool {
	if !c.sourceOffersNegotiated() {
		return s.SourceID == 0 && s.Generation == 0
	}
	if c.experimentalSources == nil {
		return false
	}
	e := c.experimentalSources.entries[s.SourceID]
	return e.frame.Generation == s.Generation && e.relay != nil && e.relay.workerPin == s.CertificateSHA256 && e.relay.current(s.PathID)
}

func (c *Conn) acceptExperimentalRelayPacket(id uint64, packet receivedPacket) bool {
	if c.perspective == protocol.PerspectiveClient && c.experimentalSources != nil && id != 0 {
		for _, e := range c.experimentalSources.entries {
			if e.pathID == id {
				u, ok := packet.remoteAddr.(*net.UDPAddr)
				return ok && e.accepted && e.expires.After(time.Now()) && u.AddrPort() == e.frame.Address
			}
		}
	}
	if packet.experimentalRelay != nil {
		return id != 0 && packet.experimentalRelay.conn == c && packet.experimentalRelay.current(id)
	}
	if c.multipath != nil {
		if p := c.multipath.paths[id]; p != nil && p.experimentalRelay != nil {
			return false
		}
	}
	if c.perspective == protocol.PerspectiveServer && c.experimentalSources != nil && id != 0 {
		for _, e := range c.experimentalSources.entries {
			if e.pathID == id {
				return false
			}
		}
	}
	return true
}

func (c *Conn) writeExperimentalPath(id uint64, data []byte, addr net.Addr, info packetInfo) error {
	p := c.multipath.paths[id]
	if p == nil || p.experimentalRelay == nil {
		return c.conn.WriteTo(data, addr, info)
	}
	r := p.experimentalRelay
	if !r.current(id) {
		return ErrExperimentalSourceOffer
	}
	u, ok := addr.(*net.UDPAddr)
	if !ok {
		return ErrExperimentalSourceOffer
	}
	select {
	case r.queue <- sourceRelayPacket{u.AddrPort(), append([]byte(nil), data...)}:
		return nil
	default:
		return errors.New("experimental source relay queue full")
	}
}
