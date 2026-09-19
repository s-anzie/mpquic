package quic

import (
	"context"
	"errors"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

var errCloningNotReady = errors.New("cloning requires a confirmed multipath server connection")

// prepareCloningAuthority is an internal staging hook, not a public cloning API.
// It enables packet-number authority and primary stream credit accounting.
// Remote stream reservations stay blocked until worker ranges can also advance
// live stream offsets and acquire a retransmission owner.
// The switch and every later import run on the same loop as packet packing.
func (c *Conn) prepareCloningAuthority() error {
	result := make(chan error, 1)
	select {
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	case c.multipathActions <- func() { result <- c.prepareCloningAuthorityOnLoop() }:
		c.scheduleSending()
	}
	select {
	case err := <-result:
		return err
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
}

// forwardCloningPathACK runs only after ordinary QUIC sent-history validation.
// The ACK's path ID (not the packet's arrival path) selects its control channel.
// This is control forwarding, not remote packet-history or sender handoff.
func (c *Conn) forwardCloningPathACK(f *wire.AckFrame) error {
	a := c.multipath.cloningAuthority
	if a == nil || f.PathID == nil || *f.PathID == 0 {
		return nil
	}
	p := c.multipath.paths[*f.PathID]
	if p == nil || p.abandoned || p.cloningGrant == nil {
		return nil
	}
	err := a.ForwardPathACK(p.cloningGrant, f)
	if errors.Is(err, cloning.ErrWorkerBusy) || errors.Is(err, cloning.ErrPath) {
		return c.abandonFailedPath(*f.PathID, err)
	}
	return err
}

// handleCloningWorkerFailures runs on the connection loop, including when no
// packets arrive. Coalesced wakeups cannot lose failures because each grant
// retains its terminal state until the corresponding path is abandoned.
func (c *Conn) handleCloningWorkerFailures() error {
	a := c.multipath.cloningAuthority
	if a == nil {
		return nil
	}
	for id, p := range c.multipath.paths {
		if p.abandoned || p.cloningGrant == nil {
			continue
		}
		if cause := a.WorkerFailure(p.cloningGrant); cause != nil {
			if err := c.abandonFailedPath(id, cause); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Conn) prepareCloningAuthorityOnLoop() error {
	if c.perspective != protocol.PerspectiveServer || !c.multipathEnabled || !c.handshakeConfirmed {
		return errCloningNotReady
	}
	if c.multipath.cloningAuthority != nil {
		return nil
	}
	a, err := cloning.NewAuthority(0)
	if err != nil {
		return err
	}
	// Build all grants before publishing the authority. A failed import must
	// leave the connection using its original allocators with no partial switch.
	grants := make(map[uint64]*cloning.Path)
	for id, p := range c.multipath.paths {
		if id == 0 {
			continue
		}
		grant, err := a.ImportPath(id, uint64(p.packetNumberSpace.nextPacketNumber), "primary")
		if err != nil {
			a.Close()
			return err
		}
		if p.abandoned {
			_ = a.RetirePath(grant)
		}
		grants[id] = grant
	}
	if c.connFlowController == nil {
		a.Close()
		return errCloningNotReady
	}
	if err := c.connFlowController.bindCloningAuthority(a, c.destroyImpl); err != nil {
		a.Close()
		return err
	}
	for id, grant := range grants {
		p := c.multipath.paths[id]
		p.cloningGrant, p.cloningAuthority = grant, a
	}
	c.multipath.cloningAuthority = a
	c.cloningWorkerEvents = a.WorkerEvents()
	return nil
}
