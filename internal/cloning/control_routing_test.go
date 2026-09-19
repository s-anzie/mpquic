package cloning

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestWorkerControlACKSnapshotAndDirection(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, client, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	id := uint64(1)
	f := &wire.AckFrame{PathID: &id, DelayTime: 321 * time.Microsecond, ECT0: 10, ECT1: 20, ECNCE: 30,
		AckRanges: []wire.AckRange{{Smallest: 8, Largest: 10}, {Smallest: 2, Largest: 5}}}
	require.NoError(t, a.ForwardPathACK(p, f))
	id, f.DelayTime, f.ECT0 = 2, 0, 0
	f.AckRanges[0].Largest = 999
	workerTestRead(t, client, 1, controlWelcome)
	body := workerTestRead(t, client, 2, controlPathACK)
	want := []uint64{1, uint64(321 * time.Microsecond), 10, 20, 30, 2, 8, 10, 2, 5}
	require.Len(t, body, 8*len(want))
	for i, v := range want {
		require.Equal(t, v, binary.BigEndian.Uint64(body[8*i:]))
	}
	// A primary-to-worker kind is forbidden in the reverse direction, even on
	// a mutually authenticated channel. A short ACK-shaped claim cannot deliver.
	require.NoError(t, writeControlMessage(client, controlPathACK, 1, nil))
	waitWorker(t, w)
	require.ErrorIs(t, w.Err(), ErrWorkerProtocol)
	require.Zero(t, a.reserved)
}

func TestWorkerControlACKAdmission(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, _, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	id := uint64(1)
	for _, frame := range []*wire.AckFrame{
		nil, {}, {PathID: &id},
		{PathID: &id, DelayTime: -1, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}},
		{PathID: &id, ECT0: ^uint64(0), AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}},
		{PathID: &id, AckRanges: []wire.AckRange{{Smallest: -1, Largest: 0}}},
		{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 2, Largest: 1}}},
		{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: protocol.MaxPathAndPacketNumber + 1}}},
		{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}, {Smallest: 0, Largest: 1}}},
	} {
		require.ErrorIs(t, a.ForwardPathACK(p, frame), ErrWorkerProtocol)
	}
	other := uint64(2)
	require.ErrorIs(t, a.ForwardPathACK(p, &wire.AckFrame{PathID: &other, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}), ErrWorkerProtocol)
	copy := *p
	require.ErrorIs(t, a.ForwardPathACK(&copy, nil), ErrPath)
	require.Empty(t, w.controls)
	boundary := &wire.AckFrame{PathID: &id, AckRanges: make([]wire.AckRange, MaxWorkerACKRanges)}
	for i := range boundary.AckRanges {
		pn := protocol.PacketNumber(2 * (len(boundary.AckRanges) - i))
		boundary.AckRanges[i] = wire.AckRange{Smallest: pn, Largest: pn}
	}
	require.NoError(t, a.ForwardPathACK(p, boundary))
	require.Len(t, w.controls, 1)
	w.Close()
	waitWorker(t, w)
}

func TestWorkerControlACKBoundsRetireWithoutRefund(t *testing.T) {
	for _, excessiveRanges := range []bool{false, true} {
		t.Run(map[bool]string{false: "queue", true: "ranges"}[excessiveRanges], func(t *testing.T) {
			sc, cc, pin := workerTestTLS(t)
			server, _, handshake := workerTestTransport(t, cc, false)
			a, p := workerTestAuthority(t)
			w, err := a.BindWorker(t.Context(), server, sc, p, pin)
			require.NoError(t, err)
			require.NoError(t, <-handshake)
			attempt, err := a.DelegatePrimary(p, 3, 0, 100, []byte("retained"), 1<<20)
			require.NoError(t, err)
			id := uint64(1)
			frame := &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
			if excessiveRanges {
				frame.AckRanges = make([]wire.AckRange, MaxWorkerACKRanges+1)
				for i := range frame.AckRanges {
					pn := protocol.PacketNumber(2 * (len(frame.AckRanges) - i))
					frame.AckRanges[i] = wire.AckRange{Smallest: pn, Largest: pn}
				}
			} else {
				for range MaxWorkerControlQueue {
					require.NoError(t, a.ForwardPathACK(p, frame))
				}
			}
			require.ErrorIs(t, a.ForwardPathACK(p, frame), ErrWorkerBusy)
			waitWorker(t, w)
			require.Empty(t, w.controls)
			require.Equal(t, uint64(8), a.reserved)
			require.Zero(t, attempt.rangeState.acked)
			q, err := a.GrantPath(2, "replacement")
			require.NoError(t, err)
			_, err = a.Retry(attempt, q)
			require.NoError(t, err)
		})
	}
}

func TestWorkerControlCancellationReachesPreviousOwners(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, client, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	attempt, err := a.DelegatePrimary(p, 3, 0, 100, []byte("data"), 1<<20)
	require.NoError(t, err)
	require.NoError(t, w.Queue(attempt))
	w.failed(1, 1) // previous owner no longer appears in the pending map
	require.Empty(t, w.pending)
	a.CancelStream(7) // ordinary/unknown stream does not produce a control message
	a.CancelStream(3)
	a.CancelStream(3)
	workerTestRead(t, client, 1, controlWelcome)
	require.Equal(t, uint64(3), binary.BigEndian.Uint64(workerTestRead(t, client, 2, controlCancelStream)))
	require.Empty(t, w.controls, "duplicate cancellation must not enqueue another message")
	w.Close()
	waitWorker(t, w)
}

func TestWorkerControlCancellationOverflowAndConcurrentClose(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, _, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	id := uint64(1)
	frame := &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
	for range MaxWorkerControlQueue {
		require.NoError(t, a.ForwardPathACK(p, frame))
	}
	_, err = a.DelegatePrimary(p, 3, 0, 100, []byte("data"), 1<<20)
	require.NoError(t, err)
	a.CancelStream(3)
	waitWorker(t, w)
	require.ErrorIs(t, w.Err(), ErrWorkerBusy)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _ = a.ForwardPathACK(p, frame); a.CancelStream(3); w.Close() })
	}
	wg.Wait()
	require.Zero(t, a.workerCount)
}

func TestWorkerControlConcurrentRoutingAndCancellation(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, _, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	_, err = a.DelegatePrimary(p, 3, 0, 100, []byte("data"), 1<<20)
	require.NoError(t, err)
	id := uint64(1)
	frame := &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _ = a.ForwardPathACK(p, frame); a.CancelStream(3); w.Close() })
	}
	wg.Wait()
	waitWorker(t, w)
	require.Zero(t, a.workerCount)
	require.Zero(t, a.delegatedBytes)
	require.Equal(t, uint64(4), a.reserved)
}
