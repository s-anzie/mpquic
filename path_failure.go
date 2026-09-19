package quic

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

func isPathSendError(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.ECONNREFUSED)
}

func (c *Conn) newConnectionSendQueue() sender {
	q := newSendQueue(c.conn).(*sendQueue)
	if c.config != nil && c.config.EnableMultipath {
		if c.pathSendErrors == nil {
			c.pathSendErrors = make(chan error, 1)
		}
		q.onWriteError = func(err error) bool {
			if !isPathSendError(err) {
				return false
			}
			select {
			case c.pathSendErrors <- err:
			default:
			}
			c.scheduleSending()
			return true
		}
	}
	return q
}

// Called only on the connection loop. Do not treat unvalidated candidates as
// survivors: otherwise a failed handshake could be kept alive indefinitely.
func (c *Conn) hasValidatedPathExcept(excluded uint64) bool {
	if excluded != 0 && !c.multipath.isPathAbandoned(0) {
		return true
	}
	if c.perspective == protocol.PerspectiveServer {
		for id, p := range c.multipath.paths {
			if id != excluded && !p.abandoned && p.serverValidated && p.remoteAddr != nil {
				// A worker can fail before its coalesced notification is processed.
				// Such a path is not a survivor, even while local CID cleanup waits.
				if p.cloningGrant != nil && p.cloningAuthority.WorkerFailure(p.cloningGrant) != nil {
					continue
				}
				return true
			}
		}
		return false
	}
	pm := c.pathManagerOutgoing.Load()
	if pm == nil {
		return false
	}
	pm.mx.Lock()
	defer pm.mx.Unlock()
	for id, p := range pm.paths {
		if uint64(id) != excluded && p.isValidated && !c.multipath.isPathAbandoned(uint64(id)) {
			return true
		}
	}
	return false
}

func (c *Conn) requeueInitialPathPackets() {
	// Preserve packet-number history for delayed ACKs; return outstanding frames
	// to their owners so they can be retransmitted on a surviving path.
	for c.sentPacketHandler.QueueProbePacket(protocol.Encryption1RTT) {
	}
}

func (c *Conn) handlePathSendError(id uint64, err error) error {
	if !c.multipathEnabled || !c.handshakeConfirmed || !isPathSendError(err) {
		return err
	}
	return c.abandonFailedPath(id, err)
}

// abandonFailedPath runs on the connection loop for either a socket failure or
// a failed cloning control channel. Preserve other validated paths and notify
// the peer instead of leaving local CID and recovery state partially retired.
func (c *Conn) abandonFailedPath(id uint64, cause error) error {
	if c.multipath.isPathAbandoned(id) {
		return nil
	}
	if !c.hasValidatedPathExcept(id) {
		return &qerr.TransportError{ErrorCode: qerr.NoViablePathError,
			ErrorMessage: fmt.Sprintf("path %d failed with no validated alternative: %v", id, cause)}
	}
	if err := c.multipath.markPathAbandoned(id); err != nil {
		return err
	}
	if id == 0 {
		c.requeueInitialPathPackets()
	}
	c.receivedPacketHandler.AbandonPath(id)
	c.connIDGenerator.AbandonPath(pathID(id))
	c.connIDManager.AbandonPath(pathID(id))
	c.queueControlFrame(&wire.PathAbandonFrame{PathID: id})
	c.scheduleSending()
	return nil
}

// Detach only this connection before closing a discovery-owned transport.
// Removing the generator entry on the connection loop prevents later CID
// replenishment from registering the connection again on the retired socket.
func (c *Conn) detachDiscoveredTransport(tr *Transport) {
	done := make(chan struct{})
	action := func() {
		delete(c.connIDGenerator.connRunners, (*packetHandlerMap)(tr))
		tr.mutex.Lock()
		for id, handler := range tr.handlers {
			if handler == c {
				delete(tr.handlers, id)
			}
		}
		tr.mutex.Unlock()
		close(done)
	}
	select {
	case c.multipathActions <- action:
		c.scheduleSending()
	case <-c.Context().Done():
		return
	}
	select {
	case <-done:
	case <-c.Context().Done():
	}
}
