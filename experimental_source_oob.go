package quic

import (
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// Preserve UDP batching and ancillary data without relaxing source pinning.
// The fallback wrapper remains available for arbitrary user PacketConns.
type experimentalSourceOOB struct {
	*sourceDestinationConn
	oob   OOBCapablePacketConn
	batch interface {
		ReadBatch([]ipv4.Message, int) (int, error)
	}
}

func wrapExperimentalSource(s *sourceDestinationConn) net.PacketConn {
	oob, ok := s.PacketConn.(OOBCapablePacketConn)
	if !ok {
		return s
	}
	b, ok := s.PacketConn.(interface {
		ReadBatch([]ipv4.Message, int) (int, error)
	})
	if !ok {
		if _, ok := s.PacketConn.(net.Conn); !ok {
			return s
		}
		b = ipv4.NewPacketConn(s.PacketConn)
	}
	return &experimentalSourceOOB{sourceDestinationConn: s, oob: oob, batch: b}
}

func (s *experimentalSourceOOB) SyscallConn() (syscall.RawConn, error) { return s.oob.SyscallConn() }
func (s *experimentalSourceOOB) SetReadBuffer(n int) error             { return s.oob.SetReadBuffer(n) }
func (s *experimentalSourceOOB) SetWriteBuffer(n int) error {
	if c, ok := s.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return c.SetWriteBuffer(n)
	}
	return nil
}
func (s *experimentalSourceOOB) accepts(addr net.Addr) bool {
	u, ok := addr.(*net.UDPAddr)
	return ok && s.active.Load() && time.Now().Before(s.expires) && u.AddrPort() == s.worker
}
func (s *experimentalSourceOOB) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	for {
		n, on, flags, a, err := s.oob.ReadMsgUDP(b, oob)
		if err != nil {
			if isPathSendError(err) {
				continue
			}
			return n, on, flags, a, err
		}
		if s.accepts(a) {
			return n, on, flags, a, nil
		}
	}
}
func (s *experimentalSourceOOB) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	for {
		n, err := s.batch.ReadBatch(messages, flags)
		if err != nil && n == 0 {
			if isPathSendError(err) {
				continue
			}
			return n, err
		}
		kept := 0
		for i := 0; i < n; i++ {
			if !s.accepts(messages[i].Addr) {
				continue
			}
			if kept != i {
				// Keep the caller's buffer ownership aligned with each slot.
				copy(messages[kept].Buffers[0], messages[i].Buffers[0][:messages[i].N])
				copy(messages[kept].OOB, messages[i].OOB[:messages[i].NN])
				messages[kept].N, messages[kept].NN, messages[kept].Flags, messages[kept].Addr = messages[i].N, messages[i].NN, messages[i].Flags, messages[i].Addr
			}
			kept++
		}
		if kept > 0 {
			return kept, err
		}
	}
}
func (s *experimentalSourceOOB) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	if !s.active.Load() || !time.Now().Before(s.expires) {
		return 0, 0, errors.Join(ErrExperimentalSourceOffer, syscall.ENETDOWN)
	}
	if addr == nil || (addr.AddrPort() != s.primary && addr.AddrPort() != s.worker) {
		return 0, 0, ErrExperimentalSourceOffer
	}
	return s.oob.WriteMsgUDP(b, oob, net.UDPAddrFromAddrPort(s.worker))
}

func (*experimentalSourceOOB) receiveBatchSize() int { return 64 }
