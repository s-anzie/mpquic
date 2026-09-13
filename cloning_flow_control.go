package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
)

func (c *connectionFlowController) bindCloningAuthority(a *cloning.Authority, fail func(error)) error {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	if err := a.BindPrimary(uint64(c.sendWindow), uint64(c.bytesSent)); err != nil {
		return err
	}
	c.cloningAuthority, c.cloningFailure = a, fail
	return nil
}

// Called with the SendStream lock held. Lock order is stream -> connection
// send-side -> authority; activation never acquires a stream lock in reverse.
func (c *connectionFlowController) reserveStream(s *streamFlowController, n protocol.ByteCount, limiter func(int) int) (added protocol.ByteCount, limited, ok bool) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	if n < 0 || s.bytesSent > s.sendWindow || c.bytesSent > c.sendWindow {
		return 0, false, false
	}
	available := min(s.sendWindow-s.bytesSent, c.sendWindow-c.bytesSent)
	if limiter == nil {
		if n > available {
			return 0, false, false
		}
	} else {
		n = min(n, available)
		if n == 0 {
			return 0, false, false
		}
		approved := min(max(protocol.ByteCount(limiter(int(n))), 0), n)
		limited, n = approved < n, approved
	}
	if c.cloningAuthority != nil {
		if err := c.cloningAuthority.AccountPrimary(s.streamID, uint64(s.bytesSent), uint64(s.sendWindow), uint64(n), uint64(c.sendWindow)); err != nil {
			c.failCloningAccounting(err)
			return 0, false, false
		}
	}
	s.bytesSent += n
	c.bytesSent += n
	return n, limited, true
}

func (c *connectionFlowController) failCloningAccounting(err error) {
	if c.cloningFailure != nil {
		c.cloningFailure(fmt.Errorf("cloning stream accounting: %w", err))
	}
}

// A FIN finalizes only after all its bytes have consumed credit. Retransmissions
// bypass this reservation path and retain their original offsets.
func (c *connectionFlowController) finalizeCloningStream(s *streamFlowController, offset protocol.ByteCount) bool {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	if c.cloningAuthority == nil {
		return true
	}
	if offset != s.bytesSent {
		c.failCloningAccounting(cloning.ErrStream)
		return false
	}
	if err := c.cloningAuthority.AccountPrimary(s.streamID, uint64(offset), uint64(s.sendWindow), 0, uint64(c.sendWindow)); err != nil {
		c.failCloningAccounting(err)
		return false
	}
	_, err := c.cloningAuthority.Finalize(s.streamID)
	if err != nil {
		c.failCloningAccounting(err)
		return false
	}
	return true
}
