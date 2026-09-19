package cloning

import (
	"sync"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func historyFixture(t *testing.T) (*Authority, *Path, *Attempt) {
	t.Helper()
	a, err := NewAuthority(0)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	require.NoError(t, a.BindPrimary(1000, 0))
	p, err := a.GrantPath(1, "source")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(p, 4)
	require.NoError(t, err)
	attempt, err := a.DelegatePrimary(p, 0, 0, 1000, []byte("abcdefgh"), 1000)
	require.NoError(t, err)
	return a, p, attempt
}

func historyACK(path uint64, ranges ...wire.AckRange) *wire.AckFrame {
	return &wire.AckFrame{PathID: &path, AckRanges: ranges}
}

func TestRemoteHistoryACKLossAndLateDelivery(t *testing.T) {
	a, p, attempt := historyFixture(t)
	require.NoError(t, a.RecordRemotePacket(p, 0, []PacketFragment{{attempt, 0, 4}}))
	require.NoError(t, a.RecordRemotePacket(p, 1, []PacketFragment{{attempt, 4, 4}}))
	completed, err := a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 0, Largest: 0}))
	require.NoError(t, err)
	require.Empty(t, completed)
	require.Equal(t, uint64(4), attempt.rangeState.acked)
	require.NoError(t, a.MarkRemotePacketLost(p, 1))
	q, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(q, 1)
	require.NoError(t, err)
	retry, err := a.Retry(attempt, q)
	require.NoError(t, err)
	require.NoError(t, a.RecordRemotePacket(q, 0, []PacketFragment{{retry, 0, 8}}))
	require.NoError(t, a.MarkRemotePacketLost(p, 1))
	require.False(t, retry.rangeState.retryable, "duplicate old loss cannot invalidate replacement")
	require.NoError(t, a.RetirePath(p))
	completed, err = a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 1, Largest: 1}))
	require.NoError(t, err)
	require.Equal(t, []uint64{attempt.rangeState.id}, completed)
	completed, err = a.AcknowledgeRemotePackets(q, historyACK(2, wire.AckRange{Smallest: 0, Largest: 0}))
	require.NoError(t, err)
	require.Empty(t, completed)
	_, credit, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(8), credit)
	require.Zero(t, a.delegatedBytes)
}

func TestRemoteHistoryRejectsWholeInvalidACK(t *testing.T) {
	a, p, attempt := historyFixture(t)
	require.NoError(t, a.RecordRemotePacket(p, 2, []PacketFragment{{attempt, 0, 8}}))
	for name, frame := range map[string]*wire.AckFrame{
		"reserved but not planned": historyACK(1, wire.AckRange{Smallest: 0, Largest: 2}),
		"valid range then unsent":  historyACK(1, wire.AckRange{Smallest: 2, Largest: 2}, wire.AckRange{Smallest: 0, Largest: 0}),
		"other path":               historyACK(2, wire.AckRange{Smallest: 2, Largest: 2}),
		"huge range":               historyACK(1, wire.AckRange{Smallest: 0, Largest: protocol.MaxPathAndPacketNumber}),
		"negative":                 historyACK(1, wire.AckRange{Smallest: -1, Largest: 2}),
		"overlapping":              historyACK(1, wire.AckRange{Smallest: 2, Largest: 2}, wire.AckRange{Smallest: 2, Largest: 2}),
		"nil":                      nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := a.AcknowledgeRemotePackets(p, frame)
			require.ErrorIs(t, err, ErrPacketHistory)
			require.Zero(t, attempt.rangeState.acked)
			require.False(t, p.remotePackets[2].acked)
		})
	}
	completed, err := a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 2, Largest: 2}))
	require.NoError(t, err)
	require.Len(t, completed, 1)
}

func TestRemoteHistoryRegistrationAndRetention(t *testing.T) {
	a, p, attempt := historyFixture(t)
	require.ErrorIs(t, a.RecordRemotePacket(p, 4, nil), ErrPacketHistory)
	require.ErrorIs(t, a.RecordRemotePacket(p, 0, []PacketFragment{{attempt, 0, 9}}), ErrAttempt)
	require.Zero(t, a.remotePacketCount)
	fragments := []PacketFragment{{attempt, 0, 8}}
	require.NoError(t, a.RecordRemotePacket(p, 0, fragments))
	fragments[0].Length = 1
	require.Equal(t, uint64(8), p.remotePackets[0].fragments[0].Length)
	require.ErrorIs(t, a.RecordRemotePacket(p, 0, nil), ErrPacketHistory)
	require.ErrorIs(t, a.ForgetRemotePacketsBefore(p, 1), ErrPacketHistory)
	require.Zero(t, p.remoteFloor)
	require.NoError(t, a.MarkRemotePacketLost(p, 0))
	require.NoError(t, a.ForgetRemotePacketsBefore(p, 2))
	require.Zero(t, a.remotePacketCount)
	require.ErrorIs(t, a.RecordRemotePacket(p, 1, nil), ErrPacketHistory)
	require.ErrorIs(t, a.ForgetRemotePacketsBefore(p, 1), ErrPacketHistory)
	completed, err := a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 0, Largest: 1}))
	require.NoError(t, err)
	require.Empty(t, completed)
	require.Zero(t, attempt.rangeState.acked, "forgotten ACK cannot release retained bytes")
	require.NoError(t, a.RecordRemotePacket(p, 2, nil)) // control-only plan
	a.Close()
	require.Zero(t, a.remotePacketCount)
	require.Empty(t, p.remotePackets)
	_, err = a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 2, Largest: 2}))
	require.ErrorIs(t, err, ErrClosed)
}

func TestRemoteHistoryCancellationAndConcurrentACK(t *testing.T) {
	a, p, attempt := historyFixture(t)
	require.NoError(t, a.RecordRemotePacket(p, 0, []PacketFragment{{attempt, 0, 8}}))
	var wg sync.WaitGroup
	results := make(chan []uint64, 16)
	for range 16 {
		wg.Go(func() {
			completed, err := a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 0, Largest: 0}))
			if err != nil {
				t.Error(err)
			}
			results <- completed
		})
	}
	wg.Wait()
	close(results)
	count := 0
	for completed := range results {
		count += len(completed)
	}
	require.Equal(t, 1, count)
	other, err := a.DelegatePrimary(p, 0, 8, 1000, []byte("ijkl"), 1000)
	require.NoError(t, err)
	require.NoError(t, a.RecordRemotePacket(p, 1, []PacketFragment{{other, 8, 4}}))
	a.CancelStream(0)
	completed, err := a.AcknowledgeRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 1, Largest: 1}))
	require.NoError(t, err)
	require.Empty(t, completed)
	require.NoError(t, a.MarkRemotePacketLost(p, 1))
}

func TestRemoteHistoryGlobalCapacity(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	defer a.Close()
	p, err := a.GrantPath(1, "source")
	require.NoError(t, err)
	for range MaxRemoteHistoryPackets / MaxRemotePacketWindow {
		_, start, err := a.ReservePacketWindow(p, MaxRemotePacketWindow)
		require.NoError(t, err)
		for j := range MaxRemotePacketWindow {
			require.NoError(t, a.RecordRemotePacket(p, start+protocol.PacketNumber(j), nil))
		}
	}
	q, err := a.GrantPath(2, "other")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(q, 1)
	require.NoError(t, err)
	require.ErrorIs(t, a.RecordRemotePacket(q, 0, nil), ErrLimit)
	require.NoError(t, a.MarkRemotePacketLost(p, 0))
	require.NoError(t, a.ForgetRemotePacketsBefore(p, 1))
	require.NoError(t, a.RecordRemotePacket(q, 0, nil))
}

func TestRemoteStreamPacketUsesRetainedBytes(t *testing.T) {
	a, p, attempt := historyFixture(t)
	for i, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		pn := protocol.PacketNumber(i)
		payload, err := a.PrepareRemoteStreamPacket(p, pn, []PacketFragment{{attempt, 2, 4}}, version)
		require.NoError(t, err)
		frame := wire.StreamFrame{StreamID: 0, Offset: 2, Data: []byte("cdef"), DataLenPresent: true}
		want, err := frame.Append(nil, version)
		require.NoError(t, err)
		require.Equal(t, want, payload)
		payload[len(payload)-1] ^= 1
		_, data, err := a.ReadAttempt(attempt)
		require.NoError(t, err)
		require.Equal(t, []byte("abcdefgh"), data)
	}
	_, err := a.PrepareRemoteStreamPacket(p, 2, nil, protocol.Version1)
	require.ErrorIs(t, err, ErrPacketHistory)
	_, err = a.PrepareRemoteStreamPacket(p, 2, []PacketFragment{{attempt, 0, 9}}, protocol.Version1)
	require.ErrorIs(t, err, ErrAttempt)
	require.Nil(t, p.remotePackets[2])
}

func TestRemoteStreamPacketOversizeIsAtomic(t *testing.T) {
	a, p, _ := historyFixture(t)
	big, err := a.DelegatePrimary(p, 3, 0, 10000, make([]byte, 4096), 10000)
	require.NoError(t, err)
	_, err = a.PrepareRemoteStreamPacket(p, 0, []PacketFragment{{big, 0, 4096}}, protocol.Version1)
	require.ErrorIs(t, err, ErrLimit)
	require.Empty(t, p.remotePackets)
	require.Zero(t, a.remotePacketCount)
	// Header overhead also counts; a payload of this size alone would fit.
	_, err = a.PrepareRemoteStreamPacket(p, 0, []PacketFragment{{big, 0, uint64(protocol.MaxPacketBufferSize) - 41}}, protocol.Version1)
	require.ErrorIs(t, err, ErrLimit)
	require.Empty(t, p.remotePackets)
	_, err = a.PrepareRemoteStreamPacket(p, 0, []PacketFragment{{big, 0, 100}}, protocol.Version1)
	require.NoError(t, err)
}

func TestRemoteHistoryRejectsPrimaryNumbersAndCopiedGrant(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	defer a.Close()
	p, err := a.ImportPath(1, 123, "source")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(p, 2)
	require.NoError(t, err)
	require.ErrorIs(t, a.RecordRemotePacket(p, 122, nil), ErrPacketHistory)
	copyGrant := *p
	require.ErrorIs(t, a.RecordRemotePacket(&copyGrant, 123, nil), ErrPath)
	require.NoError(t, a.RecordRemotePacket(p, 123, nil))
	_, err = a.AcknowledgeRemotePackets(&copyGrant, historyACK(1, wire.AckRange{Smallest: 123, Largest: 123}))
	require.ErrorIs(t, err, ErrPath)
}
