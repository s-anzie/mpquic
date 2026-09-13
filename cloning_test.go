package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestCloningAuthorityImportsAndOwnsPacketNumbers(t *testing.T) {
	c := &Conn{connFlowController: &connectionFlowController{}, multipath: newMultipathState(8), perspective: protocol.PerspectiveServer,
		multipathEnabled: true, handshakeConfirmed: true}
	for _, id := range []uint64{3, 1} {
		for range 5 {
			_, _, err := c.multipath.allocatePacketNumber(id)
			require.NoError(t, err)
		}
	}
	require.NoError(t, c.prepareCloningAuthorityOnLoop())
	a := c.multipath.cloningAuthority
	require.NoError(t, c.prepareCloningAuthorityOnLoop())
	require.Same(t, a, c.multipath.cloningAuthority)
	for _, id := range []uint64{1, 3, 2, 4} {
		pn, _, err := c.multipath.allocatePacketNumber(id)
		require.NoError(t, err)
		if id == 1 || id == 3 {
			require.Equal(t, protocol.PacketNumber(5), pn)
		} else {
			require.Zero(t, pn)
		}
		grant := c.multipath.paths[id].cloningGrant
		require.NotNil(t, grant)
		// An allocation by the authority advances the real packet packer's source.
		reserved, err := a.NextPacketNumber(grant)
		require.NoError(t, err)
		next, _, err := c.multipath.allocatePacketNumber(id)
		require.NoError(t, err)
		require.Equal(t, reserved+1, next)
		helperNext, err := c.multipath.nextPacketNumber(id)
		require.NoError(t, err)
		require.Equal(t, next+1, helperNext)
	}
	require.NoError(t, c.multipath.markPathAbandoned(1))
	_, _, err := c.multipath.allocatePacketNumber(1)
	require.ErrorIs(t, err, cloning.ErrPath)
	_, err = a.NextPacketNumber(c.multipath.paths[1].cloningGrant)
	require.ErrorIs(t, err, cloning.ErrPath)
	a.Close()
	_, _, err = c.multipath.allocatePacketNumber(3)
	require.ErrorIs(t, err, cloning.ErrClosed)
}

func TestCloningAuthorityActivationGuardsAndAtomicImport(t *testing.T) {
	c := &Conn{connFlowController: &connectionFlowController{}, multipath: newMultipathState(4), perspective: protocol.PerspectiveClient}
	require.ErrorIs(t, c.prepareCloningAuthorityOnLoop(), errCloningNotReady)
	c.perspective = protocol.PerspectiveServer
	require.ErrorIs(t, c.prepareCloningAuthorityOnLoop(), errCloningNotReady)
	c.multipathEnabled = true
	require.ErrorIs(t, c.prepareCloningAuthorityOnLoop(), errCloningNotReady)
	c.handshakeConfirmed = true
	p, err := c.multipath.path(1)
	require.NoError(t, err)
	p.packetNumberSpace.nextPacketNumber = -1
	require.Error(t, c.prepareCloningAuthorityOnLoop())
	require.Nil(t, c.multipath.cloningAuthority)
	require.Nil(t, p.cloningGrant)
	p.packetNumberSpace.nextPacketNumber = protocol.MaxPathAndPacketNumber + 1
	require.NoError(t, c.prepareCloningAuthorityOnLoop())
	_, _, err = c.multipath.allocatePacketNumber(1)
	require.ErrorIs(t, err, cloning.ErrLimit, "an exhausted space must not restart")
}

func onCloningConnectionLoop(t *testing.T, c *Conn, action func()) {
	t.Helper()
	done := make(chan struct{})
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case c.multipathActions <- func() { action(); close(done) }:
		c.scheduleSending()
	case <-timer.C:
		t.Fatal("connection action timed out")
	case <-c.Context().Done():
		t.Fatal("connection closed before action")
	}
	select {
	case <-done:
	case <-timer.C:
		t.Fatal("connection action timed out")
	case <-c.Context().Done():
		t.Fatal("connection closed before action completed")
	}
}
