package cloning

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestDelegationPreservesBytesAndAcceptsLatePartialACKs(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, a.BindPrimary(1000, 100))
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	q, err := a.GrantPath(2, "b")
	require.NoError(t, err)
	payload := bytes.Repeat([]byte{7}, 130)
	original := bytes.Clone(payload)
	first, err := a.DelegatePrimary(p, 0, 100, 1000, payload, 1000)
	require.NoError(t, err)
	payload[0] = 99
	desc, data, err := a.ReadAttempt(first)
	require.NoError(t, err)
	require.Equal(t, original, data)
	require.Equal(t, sha256.Sum256(original), desc.SHA256)
	data[1] = 99
	_, data, err = a.ReadAttempt(first)
	require.NoError(t, err)
	require.Equal(t, original, data, "readers cannot mutate retained content")
	done, err := a.Acknowledge(first, 100, 70)
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, a.MarkLost(first))
	second, err := a.Retry(first, q)
	require.NoError(t, err)
	desc2, data, err := a.ReadAttempt(second)
	require.NoError(t, err)
	require.Equal(t, desc.Range, desc2.Range)
	require.Equal(t, desc.ID, desc2.ID)
	require.Equal(t, desc.SHA256, desc2.SHA256)
	require.Equal(t, uint64(2), desc2.PathID)
	require.Equal(t, original, data)
	_, _, err = a.ReadAttempt(first)
	require.ErrorIs(t, err, ErrAttempt)
	require.NoError(t, a.MarkLost(first)) // stale loss must not invalidate the new attempt
	_, _, err = a.ReadAttempt(second)
	require.NoError(t, err)
	done, err = a.Acknowledge(second, 150, 79) // overlaps the first ACK, leaves one byte
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, a.RetirePath(p))
	done, err = a.Acknowledge(first, 229, 1) // late ACK from the retired original source
	require.NoError(t, err)
	require.True(t, done)
	done, err = a.Acknowledge(second, 100, 130)
	require.NoError(t, err)
	require.False(t, done, "completion notification is exactly once")
	require.Empty(t, a.delegations)
	require.Zero(t, a.delegatedBytes)
	require.Nil(t, first.rangeState.data)
	_, total, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(230), total)
}

func TestDelegationCapacityAndCancellationDoNotRefundCredit(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, a.BindPrimary(1000, 0))
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	var first *Attempt
	for i := range MaxPendingDelegations {
		attempt, err := a.DelegatePrimary(p, 0, uint64(i), 1000, []byte{1}, 1000)
		require.NoError(t, err)
		if i == 0 {
			first = attempt
		}
	}
	_, err = a.DelegatePrimary(p, 0, MaxPendingDelegations, 1000, []byte{1}, 1000)
	require.ErrorIs(t, err, ErrLimit)
	offset, total, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(MaxPendingDelegations), offset)
	require.Equal(t, offset, total)
	a.CancelStream(0)
	require.Empty(t, a.delegations)
	require.Zero(t, a.delegatedBytes)
	_, err = a.Acknowledge(first, 0, 1)
	require.ErrorIs(t, err, ErrAttempt)
	_, err = a.Retry(first, p)
	require.ErrorIs(t, err, ErrAttempt)
	_, totalAfter, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, total, totalAfter)
	_, err = a.DelegatePrimary(p, 0, offset, 1000, []byte{1}, 1000)
	require.ErrorIs(t, err, ErrStream, "cancellation must also reject new assignments")
	// A separate live stream can use freed retention capacity, not refunded credit.
	attempt, err := a.DelegatePrimary(p, 3, 0, 1000, []byte{2}, 1000)
	require.NoError(t, err)
	a.Close()
	require.Zero(t, a.delegatedBytes)
	_, _, err = a.ReadAttempt(attempt)
	require.ErrorIs(t, err, ErrClosed)
}

func TestDelegationRejectsInvalidACKAndForeignAttempt(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, a.BindPrimary(100, 0))
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	attempt, err := a.DelegatePrimary(p, 0, 0, 100, []byte("hello"), 100)
	require.NoError(t, err)
	for _, interval := range [][2]uint64{{0, 0}, {0, 6}, {6, 1}, {1, ^uint64(0)}} {
		_, err := a.Acknowledge(attempt, interval[0], interval[1])
		require.ErrorIs(t, err, ErrAttempt)
	}
	other, err := NewAuthority(0)
	require.NoError(t, err)
	_, err = other.Acknowledge(attempt, 0, 5)
	require.ErrorIs(t, err, ErrAttempt)
	_, err = a.Retry(attempt, p)
	require.ErrorIs(t, err, ErrAttempt, "a healthy attempt cannot be replaced arbitrarily")
	require.NoError(t, a.RetirePath(p))
	q, err := a.GrantPath(2, "b")
	require.NoError(t, err)
	_, err = a.Retry(attempt, q)
	require.NoError(t, err, "retirement permits recovery without a loss notification")
}

func TestDelegationPayloadBudgetIsIndependentOfEntryBudget(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, a.BindPrimary(uint64(protocol.MaxByteCount), 0))
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	payload := make([]byte, MaxDelegationBytes)
	for i := range MaxPendingDelegationBytes / MaxDelegationBytes {
		_, err := a.DelegatePrimary(p, 0, uint64(i*MaxDelegationBytes), uint64(protocol.MaxByteCount), payload, uint64(protocol.MaxByteCount))
		require.NoError(t, err)
	}
	require.Less(t, len(a.delegations), MaxPendingDelegations)
	_, err = a.DelegatePrimary(p, 0, MaxPendingDelegationBytes, uint64(protocol.MaxByteCount), []byte{1}, uint64(protocol.MaxByteCount))
	require.ErrorIs(t, err, ErrLimit)
	require.Equal(t, uint64(MaxPendingDelegationBytes), a.reserved)
	a.Close()
	require.Zero(t, a.delegatedBytes)
	require.Empty(t, a.delegations)
}

func TestDelegationConcurrentDuplicateACKCompletesOnce(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, a.BindPrimary(256, 0))
	p, err := a.GrantPath(1, "a")
	require.NoError(t, err)
	attempt, err := a.DelegatePrimary(p, 0, 0, 256, make([]byte, 256), 256)
	require.NoError(t, err)
	var wg sync.WaitGroup
	var completions atomic.Int64
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done, err := a.Acknowledge(attempt, 0, 256)
			if err != nil {
				t.Error(err)
			}
			if done {
				completions.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int64(1), completions.Load())
	require.Zero(t, a.delegatedBytes)
}
