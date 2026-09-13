package cloning

import "github.com/quic-go/quic-go/internal/protocol"

// BindPrimary imports connection-wide credit already consumed, including bytes
// reserved by TryWriteAll and bytes of streams no longer in the live stream map.
// The caller serializes this with all connection send-credit operations.
func (a *Authority) BindPrimary(limit, used uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if a.primaryBound || len(a.streams) != 0 || a.reserved != 0 {
		return ErrStream
	}
	if used > limit || limit > uint64(protocol.MaxByteCount) {
		return ErrLimit
	}
	a.connectionLimit, a.reserved, a.primaryBound = limit, used, true
	a.primaryInitialUsed = used
	return nil
}

// AccountPrimary imports a stream lazily and authorizes its next reservation.
// Imported offsets are already included in the connection total, so only length
// consumes new credit. Offset must be the live flow controller's high-water mark,
// not the application buffer length or the amount acknowledged by the peer.
func (a *Authority) AccountPrimary(id protocol.StreamID, offset, limit, length, connectionLimit uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.accountPrimary(id, offset, limit, length, connectionLimit)
}

func (a *Authority) accountPrimary(id protocol.StreamID, offset, limit, length, connectionLimit uint64) error {
	if a.closed {
		return ErrClosed
	}
	if !a.primaryBound || id < 0 || id > protocol.MaxStreamID || id%4 == 2 || a.canceledStreams[id] {
		return ErrStream
	}
	if offset > limit || limit > uint64(protocol.MaxByteCount) || connectionLimit < a.connectionLimit || connectionLimit > uint64(protocol.MaxByteCount) {
		return ErrLimit
	}
	s := a.streams[id]
	if s == nil && offset > a.primaryInitialUsed-a.primaryImported {
		return ErrLimit
	}
	if s != nil && (s.next != offset || s.limit > limit || s.final && length != 0) {
		return ErrStream
	}
	if length > limit-offset || length > connectionLimit-a.reserved {
		return ErrLimit
	}
	if s == nil {
		s = &stream{}
		a.streams[id] = s
		a.primaryImported += offset
	}
	s.next, s.limit = offset+length, limit
	a.reserved += length
	a.connectionLimit = connectionLimit
	return nil
}

// PrimaryState is an internal diagnostic view, not a resumable snapshot.
func (a *Authority) PrimaryState(id protocol.StreamID) (offset, total uint64, final bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.streams[id]
	if s == nil {
		return 0, a.reserved, false, ErrStream
	}
	return s.next, a.reserved, s.final, nil
}
