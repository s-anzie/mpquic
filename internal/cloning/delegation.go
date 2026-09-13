package cloning

import (
	"crypto/sha256"
	"errors"
	"math/bits"
	"slices"

	"github.com/quic-go/quic-go/internal/protocol"
)

var ErrAttempt = errors.New("invalid, obsolete, or canceled delegation attempt")

const (
	MaxDelegationBytes        = 64 << 10
	MaxPendingDelegations     = 256
	MaxPendingDelegationBytes = 8 << 20
)

// Attempt is an immutable process-local handle, not an authenticated RPC token.
// Copies are safe: all delivery state belongs to the authority.
type Attempt struct {
	authority  *Authority
	rangeState *delegation
	generation uint64
	path       *Path
}

type Descriptor struct {
	ID         uint64
	Generation uint64
	PathID     uint64
	Range      Range
	SHA256     [32]byte
}

type delegation struct {
	id         uint64
	rangeInfo  Range
	digest     [32]byte
	data       []byte
	ackBits    []uint64
	acked      uint64
	generation uint64
	retryable  bool
	done       bool
	canceled   bool
}

// DelegatePrimary is called only by the locked live stream adapter. It couples
// content retention and range reservation in one transaction. The adapter must
// advance its own offsets and counters before releasing its locks.
func (a *Authority) DelegatePrimary(path *Path, id protocol.StreamID, offset, limit uint64, data []byte, connectionLimit uint64) (*Attempt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkPath(path); err != nil {
		return nil, err
	}
	n := uint64(len(data))
	if n == 0 || n > MaxDelegationBytes || len(a.delegations) >= MaxPendingDelegations || n > MaxPendingDelegationBytes-a.delegatedBytes || a.nextDelegation == ^uint64(0) {
		return nil, ErrLimit
	}
	// Retain an immutable copy: a failed or retired source must not be the only
	// holder of bytes needed for retransmission. Caller must not mutate during copy.
	d := &delegation{data: slices.Clone(data), ackBits: make([]uint64, (n+63)/64), generation: 1}
	d.digest = sha256.Sum256(d.data)
	if err := a.accountPrimary(id, offset, limit, n, connectionLimit); err != nil {
		return nil, err
	}
	a.nextDelegation++
	d.id, d.rangeInfo = a.nextDelegation, Range{StreamID: id, Offset: offset, Length: n}
	if a.delegations == nil {
		a.delegations = make(map[uint64]*delegation)
	}
	a.delegations[d.id] = d
	a.delegatedBytes += n
	return &Attempt{authority: a, rangeState: d, generation: 1, path: path}, nil
}

func (a *Authority) checkAttempt(t *Attempt) (*delegation, error) {
	if a.closed {
		return nil, ErrClosed
	}
	if t == nil || t.authority != a || t.rangeState == nil || t.generation == 0 || t.generation > t.rangeState.generation {
		return nil, ErrAttempt
	}
	d := t.rangeState
	if d.canceled {
		return nil, ErrAttempt
	}
	if !d.done && a.delegations[d.id] != d {
		return nil, ErrAttempt
	}
	return d, nil
}

func (a *Authority) ReadAttempt(t *Attempt) (Descriptor, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.checkAttempt(t)
	if err != nil {
		return Descriptor{}, nil, err
	}
	if d.done || d.retryable || t.generation != d.generation {
		return Descriptor{}, nil, ErrAttempt
	}
	if err := a.checkPath(t.path); err != nil {
		return Descriptor{}, nil, err
	}
	return Descriptor{ID: d.id, Generation: t.generation, PathID: t.path.id, Range: d.rangeInfo, SHA256: d.digest}, slices.Clone(d.data), nil
}

func (a *Authority) MarkLost(t *Attempt) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.checkAttempt(t)
	if err != nil {
		return err
	}
	if !d.done && t.generation == d.generation {
		d.retryable = true
	}
	return nil
}

// Retry preserves content and offsets and consumes no additional flow credit.
// A retired source is sufficient reason to retry; an obsolete attempt cannot
// replace a newer assignment. Previously issued bytes cannot be recalled.
func (a *Authority) Retry(t *Attempt, path *Path) (*Attempt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.checkAttempt(t)
	if err != nil {
		return nil, err
	}
	if d.done || t.generation != d.generation || (!d.retryable && !t.path.retired) || d.generation == ^uint64(0) {
		return nil, ErrAttempt
	}
	if err := a.checkPath(path); err != nil {
		return nil, err
	}
	d.generation++
	d.retryable = false
	return &Attempt{authority: a, rangeState: d, generation: d.generation, path: path}, nil
}

// Acknowledge records a byte interval proven delivered by authenticated QUIC
// packet acknowledgments. A worker's unverified success message is NOT such
// proof. Late ACKs from old attempts still count; overlapping intervals count once.
// The bool is true only for the transition to complete delivery.
func (a *Authority) Acknowledge(t *Attempt, offset, length uint64) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.checkAttempt(t)
	if err != nil {
		return false, err
	}
	if offset < d.rangeInfo.Offset {
		return false, ErrAttempt
	}
	start := offset - d.rangeInfo.Offset
	if length == 0 || start > d.rangeInfo.Length || length > d.rangeInfo.Length-start {
		return false, ErrAttempt
	}
	if d.done {
		return false, nil
	}
	end := start + length
	for start < end {
		word, shift := start/64, start%64
		n := min(end-start, 64-shift)
		mask := (^uint64(0) >> (64 - n)) << shift
		d.acked += uint64(bits.OnesCount64(mask &^ d.ackBits[word]))
		d.ackBits[word] |= mask
		start += n
	}
	if d.acked != d.rangeInfo.Length {
		return false, nil
	}
	a.releaseDelegation(d, false)
	return true, nil
}

func (a *Authority) releaseDelegation(d *delegation, canceled bool) {
	delete(a.delegations, d.id)
	a.delegatedBytes -= uint64(len(d.data))
	d.data, d.ackBits = nil, nil
	d.done, d.canceled = !canceled, canceled
}

// CancelStream releases retained payload, never previously consumed flow credit.
func (a *Authority) CancelStream(id protocol.StreamID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || id < 0 || id > protocol.MaxStreamID || id%4 == 2 {
		return
	}
	if a.canceledStreams == nil {
		a.canceledStreams = make(map[protocol.StreamID]bool)
	}
	a.canceledStreams[id] = true
	for _, d := range a.delegations {
		if d.rangeInfo.StreamID == id {
			a.releaseDelegation(d, true)
		}
	}
}
