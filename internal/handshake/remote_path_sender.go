package handshake

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/quic-go/quic-go/internal/protocol"
)

type remoteDatagramWriter interface {
	SetWriteDeadline(time.Time) error
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

type remoteUDPBatchWriter struct {
	*net.UDPConn
	batch *ipv4.PacketConn
}

func (w *remoteUDPBatchWriter) writeBatch(packets [][]byte, addr *net.UDPAddr) error {
	messages := make([]ipv4.Message, len(packets))
	for i, p := range packets {
		messages[i] = ipv4.Message{Buffers: [][]byte{p}, Addr: addr}
	}
	for len(messages) > 0 {
		n, err := w.batch.WriteBatch(messages, 0)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(messages) {
			return io.ErrShortWrite
		}
		messages = messages[n:]
	}
	return nil
}

// RemotePathSender serializes protected UDP writes with worker-side quiescence.
// It requires a dedicated socket and an already validated destination. The
// caller still supplies congestion, pacing, anti-amplification and loss control.
// The experimental worker runtime provides these controls. Do not copy it.
type RemotePathSender struct {
	mu      sync.Mutex
	self    *RemotePathSender
	conn    remoteDatagramWriter
	addr    *net.UDPAddr
	current *RemoteSealer
	path    uint64
	epoch   protocol.KeyPhase
	end     protocol.PacketNumber
	cid     protocol.ConnectionID
	version protocol.Version
	suite   uint16
	hpHash  [32]byte
	closed  bool
}

func (*RemotePathSender) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted remote sender]")
}

// RemoteSendBoundary is a local worker drain result, not proof of delivery.
// End is the exclusive end of the burned reservation, including unused numbers.
type RemoteSendBoundary struct {
	PathID uint64
	Epoch  protocol.KeyPhase
	End    protocol.PacketNumber
}

// NewRemotePathSender takes exclusive ownership of a fresh imported sealer.
// The caller retains socket ownership, but must not use it for parallel writes.
func NewRemotePathSender(p *RemoteSealer, conn *net.UDPConn, addr *net.UDPAddr) (*RemotePathSender, error) {
	if p == nil || conn == nil || addr == nil {
		return nil, ErrRemoteSealer
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.closed || p.owned || p.used || p.aead == nil {
		return nil, ErrRemoteSealer
	}
	copyAddr := *addr
	copyAddr.IP = append(net.IP(nil), addr.IP...)
	s := &RemotePathSender{conn: &remoteUDPBatchWriter{UDPConn: conn, batch: ipv4.NewPacketConn(conn)}, addr: &copyAddr, current: p, path: p.path,
		epoch: p.epoch, end: p.end, cid: p.cid, version: p.version, suite: p.suite.ID,
		hpHash: sha256.Sum256(p.keys.hp[:])}
	p.owned = true
	s.self = s
	return s, nil
}

// WritePayload consumes a number even if the UDP write fails. A successful
// return only means the local socket accepted the datagram, never client ACK.
func (s *RemotePathSender) WritePayload(payload []byte) (protocol.PacketNumber, error) {
	return s.WritePayloads([][]byte{payload})
}

// WritePayloads commits a paced group with one bounded UDP batch. Every number
// is consumed before the syscall; partial writes never permit number reuse.
func (s *RemotePathSender) WritePayloads(payloads [][]byte) (protocol.PacketNumber, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || s.current == nil {
		return 0, ErrRemoteSealer
	}
	p := s.current
	p.mu.Lock()
	packets := make([][]byte, len(payloads))
	var pn protocol.PacketNumber
	var err error
	if len(payloads) == 0 || len(payloads) > 64 {
		p.mu.Unlock()
		return 0, ErrRemoteSealer
	}
	for i, payload := range payloads {
		packets[i], pn, err = p.sealPacketLocked(payload)
		if err != nil {
			break
		}
	}
	p.mu.Unlock()
	if err != nil {
		return pn, err
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return pn, err
	}
	if batch, ok := s.conn.(interface {
		writeBatch([][]byte, *net.UDPAddr) error
	}); ok && len(packets) > 1 {
		return pn, batch.writeBatch(packets, s.addr)
	}
	for _, packet := range packets {
		n, e := s.conn.WriteToUDP(packet, s.addr)
		if e != nil {
			return pn, e
		}
		if n != len(packet) {
			return pn, io.ErrShortWrite
		}
	}
	return pn, err
}

// Pause waits for an in-progress UDP write, destroys the active sealer and
// burns the rest of its window. Repeated calls return the same boundary.
// Packets already accepted by the network can still arrive after Pause returns.
func (s *RemotePathSender) Pause() (RemoteSendBoundary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed {
		return RemoteSendBoundary{}, ErrRemoteSealer
	}
	s.pauseLocked()
	return RemoteSendBoundary{PathID: s.path, Epoch: s.epoch, End: s.end}, nil
}

func (s *RemotePathSender) pauseLocked() {
	if s.current != nil {
		s.current.Close()
		s.current = nil
	}
}

// Resume accepts only a fresh, non-overlapping window after Pause. The fixed
// header-protection key binds it to the same connection's sending direction.
// Full epoch numbers cannot go backwards, even when their wire bits wrap.
// This in-memory fence does not replace authenticated restart fencing.
func (s *RemotePathSender) Resume(p *RemoteSealer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || s.current != nil || p == nil {
		return ErrRemoteSealer
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.closed || p.owned || p.used || p.aead == nil ||
		p.path != s.path || p.cid != s.cid || p.version != s.version || p.suite.ID != s.suite ||
		p.epoch < s.epoch || p.next < s.end || sha256.Sum256(p.keys.hp[:]) != s.hpHash {
		return ErrRemoteSealer
	}
	p.owned = true
	s.current, s.epoch, s.end = p, p.epoch, p.end
	return nil
}

// Close permanently fences this sender, without closing its caller-owned socket.
func (s *RemotePathSender) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s {
		return
	}
	s.pauseLocked()
	s.closed = true
}
