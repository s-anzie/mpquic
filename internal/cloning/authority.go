// Package cloning contains experimental coordination primitives for a distributed
// server endpoint. It is not yet connected to QUIC packet emission.
package cloning

import (
	"errors"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
)

var (
	ErrClosed = errors.New("cloning authority closed")
	ErrPath   = errors.New("invalid, retired, or foreign path grant")
	ErrLimit  = errors.New("cloning reservation exceeds limit")
	ErrStream = errors.New("invalid, unknown, or finalized stream")
)

// Authority serializes reservations for one server-side connection. Its zero
// value is not usable. It must not be copied after construction. An instance
// must never be recreated for an existing
// connection: its monotonic counters are safety-critical, not a cache.
// Owner labels are not authentication; a future RPC adapter must authenticate
// participants before handing out grants or accepting requests.
type Authority struct {
	mu              sync.Mutex
	closed          bool
	lastPath        uint64
	connectionLimit uint64
	reserved        uint64
	streams         map[protocol.StreamID]*stream
	paths           map[*Path]struct{}
}

// Path is an opaque, process-local grant. Copying it is unsupported. Retiring a
// grant prevents further reservations through it; it cannot recall numbers or
// data already handed to a remote sender.
type Path struct {
	authority        *Authority
	id               uint64
	owner            string
	retired          bool
	nextPacketNumber uint64
}

type stream struct {
	limit uint64
	next  uint64
	final bool
}

// Range identifies a new, non-overlapping portion of a stream. Reservations
// consume flow-control credit permanently. Retransmission must reuse the same
// offsets and bytes, not request another range or refund the original credit.
type Range struct {
	StreamID protocol.StreamID
	Offset   uint64
	Length   uint64
}

func NewAuthority(connectionLimit uint64) (*Authority, error) {
	if connectionLimit > uint64(protocol.MaxByteCount) {
		return nil, ErrLimit
	}
	return &Authority{connectionLimit: connectionLimit, streams: make(map[protocol.StreamID]*stream), paths: make(map[*Path]struct{})}, nil
}

// GrantPath reserves a fresh, increasing, nonzero path ID for one worker.
// Path zero remains owned by the primary QUIC endpoint. The caller must obtain
// IDs from client path establishment; this method does not create network paths.
// It must run before the first server packet on that path, including validation
// packets. Attaching to a used packet number space requires a future bootstrap
// API that imports its high-water mark, not a new zero-based grant.
func (a *Authority) GrantPath(id uint64, owner string) (*Path, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	if owner == "" || id == 0 || id > protocol.MaxPathID || id <= a.lastPath {
		return nil, ErrPath
	}
	a.lastPath = id
	p := &Path{authority: a, id: id, owner: owner}
	a.paths[p] = struct{}{}
	return p, nil
}

func (a *Authority) checkPath(p *Path) error {
	if a.closed {
		return ErrClosed
	}
	if p == nil || p.authority != a || p.retired {
		return ErrPath
	}
	if _, ok := a.paths[p]; !ok {
		return ErrPath
	}
	return nil
}

func (a *Authority) RetirePath(p *Path) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkPath(p); err != nil {
		return err
	}
	p.retired = true
	return nil
}

// NextPacketNumber never rolls back, including after a failed send or key
// update. Actual integration must make this the worker's only number source.
func (a *Authority) NextPacketNumber(p *Path) (protocol.PacketNumber, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkPath(p); err != nil {
		return 0, err
	}
	if p.nextPacketNumber > uint64(protocol.MaxPathAndPacketNumber) {
		return 0, ErrLimit
	}
	pn := p.nextPacketNumber
	p.nextPacketNumber++
	return protocol.PacketNumber(pn), nil
}

// RegisterStream starts accounting before any bytes are emitted on this stream.
// It does not open a QUIC stream or grant MAX_STREAMS credit. Only streams on
// which the server is allowed to send may be registered.
func (a *Authority) RegisterStream(id protocol.StreamID, limit uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if id < 0 || id > protocol.MaxStreamID || id%4 == 2 || a.streams[id] != nil {
		return ErrStream
	}
	if limit > uint64(protocol.MaxByteCount) {
		return ErrLimit
	}
	a.streams[id] = &stream{limit: limit}
	return nil
}

// Reserve assigns contiguous offsets from a single shared high-water mark.
// Failed reservations do not change offsets or connection credit.
func (a *Authority) Reserve(p *Path, id protocol.StreamID, length uint64) (Range, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkPath(p); err != nil {
		return Range{}, err
	}
	s := a.streams[id]
	if s == nil || s.final {
		return Range{}, ErrStream
	}
	if length == 0 || length > s.limit-s.next || length > a.connectionLimit-a.reserved {
		return Range{}, ErrLimit
	}
	r := Range{StreamID: id, Offset: s.next, Length: length}
	s.next += length
	a.reserved += length
	return r, nil
}

// UpdateLimits accepts only monotonic limits from the primary endpoint's
// authenticated QUIC control state. It is not an application credit override.
func (a *Authority) UpdateLimits(id protocol.StreamID, streamLimit, connectionLimit uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	s := a.streams[id]
	if s == nil {
		return ErrStream
	}
	if streamLimit < s.limit || connectionLimit < a.connectionLimit || streamLimit > uint64(protocol.MaxByteCount) || connectionLimit > uint64(protocol.MaxByteCount) {
		return ErrLimit
	}
	s.limit, a.connectionLimit = streamLimit, connectionLimit
	return nil
}

// Finalize fixes the logical final size. It does not mean all reserved bytes
// were sent or acknowledged, and does not itself emit a FIN frame.
func (a *Authority) Finalize(id protocol.StreamID) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0, ErrClosed
	}
	s := a.streams[id]
	if s == nil {
		return 0, ErrStream
	}
	s.final = true
	return s.next, nil
}

func (a *Authority) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
}
