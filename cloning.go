package quic

import (
	"context"
	"errors"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
)

var errCloningNotReady = errors.New("cloning requires a confirmed multipath server connection")

// prepareCloningAuthority is an internal staging hook, not a public cloning API.
// It enables packet-number authority only. Stream reservations remain blocked
// with zero credit until the shared stream/flow-control adapter is implemented.
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
	for id, grant := range grants {
		p := c.multipath.paths[id]
		p.cloningGrant, p.cloningAuthority = grant, a
	}
	c.multipath.cloningAuthority = a
	return nil
}
