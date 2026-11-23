package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	pathID  uint64
	write   func([]byte, uint16) error
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
	// onWriteError may isolate a failed path while keeping the queue drainable.
	// It must not block or access connection-loop-owned state.
	onWriteError     func(error) bool
	onPathWriteError func(uint64, error) bool
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	h.enqueue(queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn})
}

func (h *sendQueue) enqueue(e queueEntry) {
	select {
	case h.queue <- e:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
		e.buf.Release()
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	var failed bool
	failedPaths := make(map[uint64]bool)
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			if (e.pathID == 0 && !failed) || (e.pathID != 0 && !failedPaths[e.pathID]) {
				var err error
				if e.write != nil {
					err = e.write(e.buf.Data, e.gsoSize)
				} else {
					err = h.conn.Write(e.buf.Data, e.gsoSize, e.ecn)
				}
				// Oversized datagrams are handled by path MTU discovery.
				if err != nil && !isSendMsgSizeErr(err) {
					handled := false
					if e.pathID == 0 && h.onWriteError != nil {
						handled = h.onWriteError(err)
					} else if e.pathID != 0 && h.onPathWriteError != nil {
						handled = h.onPathWriteError(e.pathID, err)
					}
					if !handled {
						e.buf.Release()
						return err
					}
					if e.pathID == 0 {
						failed = true
					} else {
						failedPaths[e.pathID] = true
					}
				}
			}
			e.buf.Release()
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
