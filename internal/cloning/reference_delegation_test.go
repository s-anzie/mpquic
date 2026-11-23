package cloning

import (
	"crypto/sha256"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func referenceFixture(t *testing.T) (*Authority, *Path, *Attempt) {
	t.Helper()
	a, err := NewAuthority(0)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	require.NoError(t, a.BindPrimary(1000, 100))
	p, err := a.GrantPath(1, "source")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(p, 4)
	require.NoError(t, err)
	attempt, err := a.DelegatePrimaryReference(p, 0, 100, 1000, 130, sha256.Sum256(make([]byte, 130)), 1000)
	require.NoError(t, err)
	return a, p, attempt
}

func TestReferenceDelegationRetryAndLateACK(t *testing.T) {
	a, p, first := referenceFixture(t)
	desc, data, err := a.ReadAttempt(first)
	require.NoError(t, err)
	require.Nil(t, data)
	require.Nil(t, first.rangeState.data)
	require.True(t, first.rangeState.reference)
	require.Equal(t, Range{StreamID: 0, Offset: 100, Length: 130}, desc.Range)
	require.Equal(t, sha256.Sum256(make([]byte, 130)), desc.SHA256)
	require.Equal(t, uint64(130), a.delegatedBytes)
	fragments := []PacketFragment{{first, 100, 130}}
	require.NoError(t, a.PrepareRemoteReferencePacket(p, 0, fragments))
	fragments[0].Length = 1
	require.Equal(t, uint64(130), p.remotePackets[0].fragments[0].Length)
	require.NoError(t, a.AdmitRemotePacket(p, 0))
	require.NoError(t, a.MarkRemotePacketLost(p, 0))
	q, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(q, 1)
	require.NoError(t, err)
	retry, err := a.Retry(first, q)
	require.NoError(t, err)
	next, data, err := a.ReadAttempt(retry)
	require.NoError(t, err)
	require.Nil(t, data)
	require.Equal(t, desc.ID, next.ID)
	require.Equal(t, desc.Range, next.Range)
	require.Equal(t, desc.SHA256, next.SHA256)
	require.Equal(t, uint64(2), next.Generation)
	require.Equal(t, uint64(2), next.PathID)
	offset, total, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(230), offset)
	require.Equal(t, uint64(230), total)
	require.Equal(t, uint64(130), a.delegatedBytes)
	_, _, err = a.ReadAttempt(first)
	require.ErrorIs(t, err, ErrAttempt)
	require.NoError(t, a.PrepareRemoteReferencePacket(q, 0, []PacketFragment{{retry, 100, 130}}))
	require.NoError(t, a.AdmitRemotePacket(q, 0))
	require.NoError(t, a.RetirePath(p))
	completed, err := a.AcknowledgeDispatchedRemotePackets(p, historyACK(1, wire.AckRange{Smallest: 0, Largest: 0}))
	require.NoError(t, err)
	require.Equal(t, []uint64{desc.ID}, completed)
	completed, err = a.AcknowledgeDispatchedRemotePackets(q, historyACK(2, wire.AckRange{Smallest: 0, Largest: 0}))
	require.NoError(t, err)
	require.Empty(t, completed)
	require.Zero(t, a.delegatedBytes)
	require.Empty(t, a.delegations)
}

func TestReferencePacketPreparationRejectsWrongModeAtomically(t *testing.T) {
	a, p, ref := referenceFixture(t)
	retained, err := a.DelegatePrimary(p, 0, 230, 1000, []byte("abc"), 1000)
	require.NoError(t, err)
	reference := PacketFragment{ref, 100, 130}
	bytes := PacketFragment{retained, 230, 3}
	for _, fragments := range [][]PacketFragment{{reference}, {bytes, reference}, {reference, bytes}} {
		payload, err := a.PrepareRemoteStreamPacket(p, 0, fragments, protocol.Version1)
		require.ErrorIs(t, err, ErrPacketHistory)
		require.Nil(t, payload)
		require.Empty(t, p.remotePackets)
		require.Zero(t, a.remotePacketCount)
	}
	for _, fragments := range [][]PacketFragment{nil, {bytes}, {reference, bytes}, {bytes, reference}} {
		require.ErrorIs(t, a.PrepareRemoteReferencePacket(p, 0, fragments), ErrPacketHistory)
		require.Empty(t, p.remotePackets)
		require.Zero(t, a.remotePacketCount)
	}
	require.Equal(t, uint64(133), a.delegatedBytes)
	require.Equal(t, uint64(233), a.reserved)
	require.NoError(t, a.PrepareRemoteReferencePacket(p, 0, []PacketFragment{reference}))
	_, err = a.PrepareRemoteStreamPacket(p, 1, []PacketFragment{bytes}, protocol.Version1)
	require.NoError(t, err)
}

func TestReferencePacketBounds(t *testing.T) {
	a, p, ref := referenceFixture(t)
	for _, interval := range [][2]uint64{{100, 0}, {99, 130}, {100, 129}, {101, 129}, {100, 131}, {230, 1}, {100, ^uint64(0)}} {
		fragments := []PacketFragment{{ref, interval[0], interval[1]}}
		require.ErrorIs(t, a.PrepareRemoteReferencePacket(p, 0, fragments), ErrAttempt)
		require.ErrorIs(t, a.RecordRemotePacket(p, 0, fragments), ErrAttempt)
		require.Empty(t, p.remotePackets)
		require.Zero(t, a.remotePacketCount)
	}
	full := []PacketFragment{{ref, 100, 130}}
	require.ErrorIs(t, a.PrepareRemoteReferencePacket(p, 4, full), ErrPacketHistory)
	require.ErrorIs(t, a.PrepareRemoteReferencePacket(p, -1, full), ErrPacketHistory)
	require.ErrorIs(t, a.PrepareRemoteReferencePacket(nil, 0, full), ErrPath)
	q, err := a.GrantPath(2, "other")
	require.NoError(t, err)
	_, _, err = a.ReservePacketWindow(q, 1)
	require.NoError(t, err)
	require.ErrorIs(t, a.PrepareRemoteReferencePacket(q, 0, full), ErrAttempt)
	many := make([]PacketFragment, MaxRemotePacketFragments+1)
	for i := range many {
		many[i] = full[0]
	}
	require.ErrorIs(t, a.PrepareRemoteReferencePacket(p, 0, many), ErrLimit)
	require.NoError(t, a.PrepareRemoteReferencePacket(p, 0, full))
	require.ErrorIs(t, a.PrepareRemoteReferencePacket(p, 0, full), ErrPacketHistory)
	require.Equal(t, 1, a.remotePacketCount)
}

func TestReferenceDelegationBoundsAreAtomic(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		offset, limit, length, connection uint64
		want                              error
	}{
		{"empty", 230, 1000, 0, 1000, ErrLimit},
		{"oversize", 230, 100000, MaxDelegationBytes + 1, 100000, ErrLimit},
		{"length overflow", 230, 1000, ^uint64(0), 1000, ErrLimit},
		{"offset overflow", ^uint64(0), 1000, 1, 1000, ErrLimit},
		{"stream credit", 230, 1000, 771, 2000, ErrLimit},
		{"connection credit", 230, 2000, 771, 1000, ErrLimit},
		{"offset mismatch", 229, 1000, 1, 1000, ErrStream},
		{"invalid limit", 230, ^uint64(0), 1, 1000, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, p, _ := referenceFixture(t)
			_, err := a.DelegatePrimaryReference(p, 0, tc.offset, tc.limit, tc.length, [32]byte{}, tc.connection)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, uint64(230), a.streams[0].next)
			require.Equal(t, uint64(230), a.reserved)
			require.Equal(t, uint64(1000), a.connectionLimit)
			require.Equal(t, uint64(130), a.delegatedBytes)
			require.Equal(t, uint64(1), a.nextDelegation)
			require.Len(t, a.delegations, 1)
		})
	}
}

func TestReferenceAndRetainedDelegationsShareBudget(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	const limit = uint64(protocol.MaxByteCount)
	require.NoError(t, a.BindPrimary(limit, 0))
	p, err := a.GrantPath(1, "source")
	require.NoError(t, err)
	var first *Attempt
	for i := range MaxPendingDelegationBytes / MaxDelegationBytes {
		offset := uint64(i * MaxDelegationBytes)
		var attempt *Attempt
		if i%2 == 0 {
			attempt, err = a.DelegatePrimaryReference(p, 0, offset, limit, MaxDelegationBytes, [32]byte{}, limit)
		} else {
			attempt, err = a.DelegatePrimary(p, 0, offset, limit, make([]byte, MaxDelegationBytes), limit)
		}
		require.NoError(t, err)
		if i == 0 {
			first = attempt
		}
	}
	require.Equal(t, uint64(MaxPendingDelegationBytes), a.delegatedBytes)
	_, err = a.DelegatePrimaryReference(p, 0, MaxPendingDelegationBytes, limit, 1, [32]byte{}, limit)
	require.ErrorIs(t, err, ErrLimit)
	_, err = a.DelegatePrimary(p, 0, MaxPendingDelegationBytes, limit, []byte{1}, limit)
	require.ErrorIs(t, err, ErrLimit)
	done, err := a.Acknowledge(first, 0, MaxDelegationBytes)
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, uint64(MaxPendingDelegationBytes-MaxDelegationBytes), a.delegatedBytes)
	_, err = a.DelegatePrimaryReference(p, 0, MaxPendingDelegationBytes, limit, MaxDelegationBytes, [32]byte{}, limit)
	require.NoError(t, err)
	a.CancelStream(0)
	require.Zero(t, a.delegatedBytes)
	require.Empty(t, a.delegations)
	require.Equal(t, uint64(MaxPendingDelegationBytes+MaxDelegationBytes), a.reserved)
	_, err = a.DelegatePrimaryReference(p, 0, a.reserved, limit, 1, [32]byte{}, limit)
	require.ErrorIs(t, err, ErrStream)
	_, err = a.DelegatePrimaryReference(p, 3, 0, limit, 1, [32]byte{}, limit)
	require.NoError(t, err)
	a.Close()
	require.Zero(t, a.delegatedBytes)
}

func TestReferenceDelegationEntryLimitAndPartialACK(t *testing.T) {
	a, p, first := referenceFixture(t)
	for _, interval := range [][2]uint64{{99, 1}, {100, 0}, {230, 1}, {101, ^uint64(0)}} {
		done, err := a.Acknowledge(first, interval[0], interval[1])
		require.ErrorIs(t, err, ErrAttempt)
		require.False(t, done)
		require.Zero(t, first.rangeState.acked)
	}
	for i := 1; i < MaxPendingDelegations; i++ {
		_, err := a.DelegatePrimaryReference(p, 0, uint64(229+i), 1000, 1, [32]byte{}, 1000)
		require.NoError(t, err)
	}
	_, err := a.DelegatePrimaryReference(p, 0, 229+MaxPendingDelegations, 1000, 1, [32]byte{}, 1000)
	require.ErrorIs(t, err, ErrLimit)
	before := a.delegatedBytes
	done, err := a.Acknowledge(first, 100, 70)
	require.NoError(t, err)
	require.False(t, done)
	done, err = a.Acknowledge(first, 150, 79)
	require.NoError(t, err)
	require.False(t, done)
	require.Equal(t, before, a.delegatedBytes)
	done, err = a.Acknowledge(first, 229, 1)
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, before-130, a.delegatedBytes)
	_, err = a.DelegatePrimaryReference(p, 0, 229+MaxPendingDelegations, 1000, 1, [32]byte{}, 1000)
	require.NoError(t, err)
	require.NoError(t, a.RetirePath(p))
	_, err = a.DelegatePrimaryReference(p, 3, 0, 1000, 1, [32]byte{}, 1000)
	require.ErrorIs(t, err, ErrPath)
	a.Close()
	_, err = a.DelegatePrimaryReference(p, 3, 0, 1000, 1, [32]byte{}, 1000)
	require.ErrorIs(t, err, ErrClosed)
	require.Zero(t, a.delegatedBytes)
}
