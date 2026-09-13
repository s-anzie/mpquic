package cloning

import (
	"sort"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestExclusivePathOwnershipAndPacketNumbers(t *testing.T) {
	a, err := NewAuthority(100)
	require.NoError(t, err)
	_, err = a.GrantPath(0, "primary")
	require.ErrorIs(t, err, ErrPath)
	p, err := a.GrantPath(1, "source-a")
	require.NoError(t, err)
	_, err = a.GrantPath(1, "source-b")
	require.ErrorIs(t, err, ErrPath)
	for i := range 10 {
		pn, err := a.NextPacketNumber(p)
		require.NoError(t, err)
		require.Equal(t, protocol.PacketNumber(i), pn)
	}
	copy := *p
	_, err = a.NextPacketNumber(&copy)
	require.ErrorIs(t, err, ErrPath, "copying a grant must not duplicate a number source")
	other, err := NewAuthority(100)
	require.NoError(t, err)
	_, err = other.NextPacketNumber(p)
	require.ErrorIs(t, err, ErrPath)
	require.NoError(t, a.RetirePath(p))
	_, err = a.NextPacketNumber(p)
	require.ErrorIs(t, err, ErrPath)
	_, err = a.GrantPath(1, "replacement")
	require.ErrorIs(t, err, ErrPath, "retired path IDs cannot be reassigned")
	next, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	pn, err := a.NextPacketNumber(next)
	require.NoError(t, err)
	require.Zero(t, pn, "a fresh path has an independent packet number space")
}

func TestRangesShareConnectionCreditAndFinalSize(t *testing.T) {
	a, err := NewAuthority(12)
	require.NoError(t, err)
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	q, err := a.GrantPath(2, "b")
	require.NoError(t, err)
	require.NoError(t, a.RegisterStream(0, 8))
	require.NoError(t, a.RegisterStream(3, 12))
	x, err := a.Reserve(p, 0, 5)
	require.NoError(t, err)
	require.Equal(t, Range{StreamID: 0, Offset: 0, Length: 5}, x)
	_, err = a.Reserve(q, 0, 4)
	require.ErrorIs(t, err, ErrLimit)
	x, err = a.Reserve(q, 0, 3)
	require.NoError(t, err)
	require.Equal(t, uint64(5), x.Offset)
	_, err = a.Reserve(q, 3, 5)
	require.ErrorIs(t, err, ErrLimit, "connection limit spans all streams and workers")
	x, err = a.Reserve(q, 3, 4)
	require.NoError(t, err)
	require.Zero(t, x.Offset)
	require.NoError(t, a.UpdateLimits(0, 10, 14))
	x, err = a.Reserve(p, 0, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(8), x.Offset)
	final, err := a.Finalize(0)
	require.NoError(t, err)
	require.Equal(t, uint64(10), final)
	_, err = a.Reserve(q, 0, 1)
	require.ErrorIs(t, err, ErrStream)
	again, err := a.Finalize(0)
	require.NoError(t, err)
	require.Equal(t, final, again)
	require.NoError(t, a.RetirePath(p))
	_, err = a.Reserve(q, 3, 1)
	require.ErrorIs(t, err, ErrLimit, "retirement must not refund reserved credit")
}

func TestConcurrentReservationsDoNotOverlap(t *testing.T) {
	a, err := NewAuthority(1000)
	require.NoError(t, err)
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	require.NoError(t, a.RegisterStream(0, 1000))
	var wg sync.WaitGroup
	numbers := make(chan uint64, 1000)
	offsets := make(chan uint64, 1000)
	errors := make(chan error, 2000)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				pn, err := a.NextPacketNumber(p)
				if err != nil {
					errors <- err
				} else {
					numbers <- uint64(pn)
				}
				r, err := a.Reserve(p, 0, 1)
				if err != nil {
					errors <- err
				} else {
					offsets <- r.Offset
				}
			}
		}()
	}
	wg.Wait()
	close(numbers)
	close(offsets)
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	for _, values := range []chan uint64{numbers, offsets} {
		var sorted []uint64
		for n := range values {
			sorted = append(sorted, n)
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		require.Len(t, sorted, 1000)
		for i, n := range sorted {
			require.Equal(t, uint64(i), n)
		}
	}
}

func TestLimitsAndTerminalClosure(t *testing.T) {
	_, err := NewAuthority(^uint64(0))
	require.ErrorIs(t, err, ErrLimit)
	a, err := NewAuthority(uint64(protocol.MaxByteCount))
	require.NoError(t, err)
	p, err := a.GrantPath(protocol.MaxPathID, "last")
	require.NoError(t, err)
	p.nextPacketNumber = uint64(protocol.MaxPathAndPacketNumber)
	pn, err := a.NextPacketNumber(p)
	require.NoError(t, err)
	require.Equal(t, protocol.MaxPathAndPacketNumber, pn)
	_, err = a.NextPacketNumber(p)
	require.ErrorIs(t, err, ErrLimit)
	require.ErrorIs(t, a.RegisterStream(2, 10), ErrStream)
	require.ErrorIs(t, a.RegisterStream(-1, 10), ErrStream)
	require.NoError(t, a.RegisterStream(0, uint64(protocol.MaxByteCount)))
	_, err = a.Reserve(p, 0, ^uint64(0))
	require.ErrorIs(t, err, ErrLimit)
	_, err = a.Reserve(p, 0, uint64(protocol.MaxByteCount))
	require.NoError(t, err)
	_, err = a.Reserve(p, 0, 1)
	require.ErrorIs(t, err, ErrLimit)
	require.ErrorIs(t, a.UpdateLimits(0, 10, 10), ErrLimit)
	a.Close()
	_, err = a.Reserve(p, 0, 1)
	require.ErrorIs(t, err, ErrClosed)
	_, err = a.NextPacketNumber(p)
	require.ErrorIs(t, err, ErrClosed)
	_, err = a.Finalize(0)
	require.ErrorIs(t, err, ErrClosed)
	a.Close()
}
