package quic

import (
	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
)

// clonedRange is an internal bridge between retained delegated data and the
// live stream lifecycle. It does not transmit packets or trust worker receipts.
type clonedRange struct {
	stream    *SendStream
	authority *cloning.Authority
	attempt   *cloning.Attempt
}

func (s *SendStream) delegateCloningRange(path *cloning.Path, data []byte) (*clonedRange, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.shutdownErr != nil {
		return nil, s.shutdownErr
	}
	if s.resetErr != nil {
		return nil, s.resetErr
	}
	if s.finishedWriting {
		return nil, cloning.ErrStream
	}
	// Partial reliable reset requires per-range reliable-prefix ownership; do
	// not pretend ordinary cancellation implements that distributed lifecycle.
	if s.supportsResetStreamAt {
		return nil, cloning.ErrDelegationNotReady
	}
	if len(s.dataForWriting) != 0 || s.nextFrame != nil {
		return nil, ErrWouldBlock
	}
	fc := s.flowController
	c := fc.connection
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	if c.cloningAuthority == nil {
		return nil, errCloningNotReady
	}
	n := protocol.ByteCount(len(data))
	if n == 0 || n > cloning.MaxDelegationBytes {
		return nil, cloning.ErrLimit
	}
	if s.writeOffset != fc.bytesSent || fc.bytesSent > fc.sendWindow || c.bytesSent > c.sendWindow || n > min(fc.sendWindow-fc.bytesSent, c.sendWindow-c.bytesSent) {
		return nil, ErrWouldBlock
	}
	attempt, err := c.cloningAuthority.DelegatePrimary(path, s.streamID, uint64(s.writeOffset), uint64(fc.sendWindow), data, uint64(c.sendWindow))
	if err != nil {
		return nil, err
	}
	// No fallible operations follow the authority commit while these locks are held.
	fc.bytesSent += n
	c.bytesSent += n
	s.writeOffset += n
	s.numOutstandingFrames++ // one delivery obligation, regardless of packet count
	return &clonedRange{stream: s, authority: c.cloningAuthority, attempt: attempt}, nil
}

func (r *clonedRange) read() (cloning.Descriptor, []byte, error) {
	return r.authority.ReadAttempt(r.attempt)
}

func (r *clonedRange) lost() error { return r.authority.MarkLost(r.attempt) }

func (r *clonedRange) retry(path *cloning.Path) (*clonedRange, error) {
	attempt, err := r.authority.Retry(r.attempt, path)
	if err != nil {
		return nil, err
	}
	return &clonedRange{stream: r.stream, authority: r.authority, attempt: attempt}, nil
}

// acknowledge must only be called with delivery evidence from the QUIC ACK
// handler for the corresponding packet. No network/RPC adapter calls it yet.
func (r *clonedRange) acknowledge(offset, length uint64) error {
	s := r.stream
	s.mutex.Lock()
	done, err := r.authority.Acknowledge(r.attempt, offset, length)
	if err != nil || !done {
		s.mutex.Unlock()
		return err
	}
	s.numOutstandingFrames--
	completed := s.isNewlyCompleted()
	s.mutex.Unlock()
	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
	return nil
}

func (c *connectionFlowController) cancelCloningStream(id protocol.StreamID) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	if c.cloningAuthority != nil {
		c.cloningAuthority.CancelStream(id)
	}
}
