package cloning

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestPacketWindowsExclusiveAndMonotonic(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	p, err := a.ImportPath(1, 123, "worker")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(p, 0)
	require.ErrorIs(t, err, ErrLimit)
	pn, err := a.NextPacketNumber(p)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(123), pn)
	var wg sync.WaitGroup
	starts := make(chan protocol.PacketNumber, 16)
	for range 16 {
		wg.Go(func() {
			_, first, err := a.ReservePacketWindow(p, 64)
			if err != nil {
				t.Error(err)
				return
			}
			starts <- first
		})
	}
	wg.Wait()
	close(starts)
	seen := make(map[protocol.PacketNumber]bool)
	for first := range starts {
		require.False(t, seen[first])
		seen[first] = true
		require.Zero(t, (first-124)%64)
	}
	require.Len(t, seen, 16)
	_, err = a.NextPacketNumber(p)
	require.ErrorIs(t, err, ErrPath)
	require.NoError(t, a.RetirePath(p))
	_, _, err = a.ReservePacketWindow(p, 1)
	require.ErrorIs(t, err, ErrPath)
}

func TestPacketWindowExhaustion(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	p, err := a.ImportPath(1, uint64(protocol.MaxPathAndPacketNumber), "worker")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(p, 2)
	require.ErrorIs(t, err, ErrLimit)
	_, pn, err := a.ReservePacketWindow(p, 1)
	require.NoError(t, err)
	require.Equal(t, protocol.MaxPathAndPacketNumber, pn)
	_, _, err = a.ReservePacketWindow(p, 1)
	require.ErrorIs(t, err, ErrLimit)
}
