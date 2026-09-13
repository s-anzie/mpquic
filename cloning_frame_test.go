package quic

import (
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestCloningFramePacketEvidence(t *testing.T) {
	s, a, p, sender := setupClonedStream(t)
	r, err := s.delegateCloningRange(p, []byte("abcdefgh"))
	require.NoError(t, err)
	first, err := r.frame(1, 0, 3)
	require.NoError(t, err)
	second, err := r.frame(1, 3, 5)
	require.NoError(t, err)
	require.Equal(t, []byte("defgh"), second.Frame.Data)
	require.False(t, second.Frame.Fin)
	require.NoError(t, s.Close())
	fin, _, _ := s.popStreamFrame(128, protocol.Version1)
	fin.Handler.OnAcked(fin.Frame)
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 0, now, 100, true, nil, []ackhandler.StreamFrame{first}))
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 1, now, 100, true, nil, []ackhandler.StreamFrame{second}))
	// The same packet number on another path cannot acknowledge these bytes.
	require.NoError(t, state.recordSentApplicationPacketWithSize(2, 1, now, 100, true, nil, nil))
	otherPath := uint64(2)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{PathID: &otherPath, AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}))
	require.Equal(t, int64(1), s.numOutstandingFrames)
	pathID := uint64(1)
	ack := func(pn protocol.PacketNumber) error {
		return state.handlePathAck(&wire.AckFrame{PathID: &pathID, AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}})
	}
	// An unsent packet is not delivery evidence.
	require.Error(t, ack(2))
	require.Equal(t, int64(1), s.numOutstandingFrames)
	require.NoError(t, ack(1))
	require.NoError(t, ack(1))
	require.False(t, s.completed)
	sender.EXPECT().onStreamCompleted(protocol.StreamID(3)).Times(1)
	require.NoError(t, ack(0))
	require.True(t, s.completed)
	require.Zero(t, s.numOutstandingFrames)
	_, total, _, err := a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, uint64(8), total)
}

func TestCloningFrameLossAndCrossPathRetry(t *testing.T) {
	s, a, p, _ := setupClonedStream(t)
	r, err := s.delegateCloningRange(p, []byte("abcdefgh"))
	require.NoError(t, err)
	f, err := r.frame(1, 0, 8)
	require.NoError(t, err)
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 0, now.Add(-time.Second), 100, true, nil, []ackhandler.StreamFrame{f}))
	state.paths[1].packetNumberSpace.largestAcknowledged = 1
	_, lost := state.detectLostPathPackets(now, time.Second)
	require.True(t, lost)
	require.Equal(t, int64(1), s.numOutstandingFrames)
	q, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	retry, err := r.retry(q)
	require.NoError(t, err)
	_, err = r.frame(1, 0, 8)
	require.ErrorIs(t, err, cloning.ErrAttempt)
	replacement, err := retry.frame(2, 0, 8)
	require.NoError(t, err)
	require.Equal(t, f.Frame.Data, replacement.Frame.Data)
	require.NoError(t, state.recordSentApplicationPacketWithSize(2, 0, now, 100, true, nil, []ackhandler.StreamFrame{replacement}))
	pathID := uint64(2)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{PathID: &pathID, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}))
	require.Zero(t, s.numOutstandingFrames)
	// Delayed callbacks from the old attempt cannot decrement twice.
	f.Handler.OnLost(f.Frame)
	f.Handler.OnAcked(f.Frame)
	require.Zero(t, s.numOutstandingFrames)
	_, total, _, err := a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, uint64(8), total)
}

func TestCloningFrameAdmissionAndImmutableEvidence(t *testing.T) {
	s, _, p, _ := setupClonedStream(t)
	r, err := s.delegateCloningRange(p, []byte("abcdefgh"))
	require.NoError(t, err)
	for _, interval := range [][2]uint64{{0, 0}, {8, 1}, {1, 8}, {0, ^uint64(0)}, {^uint64(0), 1}} {
		_, err := r.frame(1, interval[0], interval[1])
		require.ErrorIs(t, err, cloning.ErrLimit)
	}
	_, err = r.frame(2, 0, 1)
	require.ErrorIs(t, err, cloning.ErrPath)
	f, err := r.frame(1, 0, 3)
	require.NoError(t, err)
	f.Frame.Data[0] = 'X'
	_, data, err := r.read()
	require.NoError(t, err)
	require.Equal(t, []byte("abcdefgh"), data)
	// Callback arguments cannot expand the captured three-byte interval.
	f.Handler.OnAcked(&wire.StreamFrame{StreamID: 999, Data: make([]byte, 100)})
	require.Equal(t, int64(1), s.numOutstandingFrames)
	rest, err := r.frame(1, 3, 5)
	require.NoError(t, err)
	rest.Handler.OnAcked(nil)
	require.Zero(t, s.numOutstandingFrames)
}

func TestCloningFrameCallbacksAfterCancel(t *testing.T) {
	s, _, p, _ := setupClonedStream(t)
	r, err := s.delegateCloningRange(p, []byte("data"))
	require.NoError(t, err)
	f, err := r.frame(1, 0, 4)
	require.NoError(t, err)
	s.CancelWrite(42)
	before := s.numOutstandingFrames
	f.Handler.OnAcked(f.Frame)
	f.Handler.OnLost(f.Frame)
	require.Equal(t, before, s.numOutstandingFrames)
}

func TestCloningFrameAbsoluteOffset(t *testing.T) {
	s, _, p, _ := setupClonedStream(t)
	require.NoError(t, s.TryWriteAll([]byte("prefix")))
	ordinary, _, _ := s.popStreamFrame(128, protocol.Version1)
	ordinary.Handler.OnAcked(ordinary.Frame)
	r, err := s.delegateCloningRange(p, []byte("data"))
	require.NoError(t, err)
	_, err = r.frame(1, 5, 1)
	require.ErrorIs(t, err, cloning.ErrLimit)
	f, err := r.frame(1, 7, 3)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(7), f.Frame.Offset)
	require.Equal(t, []byte("ata"), f.Frame.Data)
	f.Handler.OnAcked(f.Frame)
	require.Equal(t, int64(1), s.numOutstandingFrames)
	first, err := r.frame(1, 6, 1)
	require.NoError(t, err)
	first.Handler.OnAcked(first.Frame)
	require.Zero(t, s.numOutstandingFrames)
}

func TestCloningFrameConcurrentDuplicateCallbacks(t *testing.T) {
	s, _, p, _ := setupClonedStream(t)
	r, err := s.delegateCloningRange(p, []byte("data"))
	require.NoError(t, err)
	f, err := r.frame(1, 0, 4)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			f.Handler.OnLost(nil)
			f.Handler.OnAcked(nil)
		})
	}
	wg.Wait()
	require.Zero(t, s.numOutstandingFrames)
}
