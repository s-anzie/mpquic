package cloning

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestPrimaryAccountingIsAtomicAndDoesNotEnableDelegation(t *testing.T) {
	a, err := NewAuthority(0)
	require.NoError(t, err)
	p, err := a.GrantPath(1, "primary")
	require.NoError(t, err)
	require.NoError(t, a.BindPrimary(100, 60))
	require.ErrorIs(t, a.BindPrimary(100, 0), ErrStream)
	require.NoError(t, a.AccountPrimary(0, 20, 50, 10, 100))
	require.ErrorIs(t, a.AccountPrimary(0, 20, 50, 1, 100), ErrStream)
	require.ErrorIs(t, a.AccountPrimary(3, 40, 100, 31, 100), ErrLimit)
	offset, total, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(30), offset)
	require.Equal(t, uint64(70), total)
	_, _, _, err = a.PrimaryState(3)
	require.ErrorIs(t, err, ErrStream, "failed import must not publish a stream")
	_, err = a.Reserve(p, 0, 1)
	require.ErrorIs(t, err, ErrDelegationNotReady)
	require.NoError(t, a.AccountPrimary(3, 40, 100, 30, 100))
	require.ErrorIs(t, a.AccountPrimary(7, 1, 100, 0, 100), ErrLimit, "imports must not invent pre-activation bytes")
	_, err = a.Finalize(0)
	require.NoError(t, err)
	require.NoError(t, a.AccountPrimary(0, 30, 50, 0, 100))
	require.ErrorIs(t, a.AccountPrimary(0, 30, 50, 1, 101), ErrStream)
	require.ErrorIs(t, a.AccountPrimary(3, 70, uint64(protocol.MaxByteCount), ^uint64(0), 100), ErrLimit)
	a.Close()
	require.ErrorIs(t, a.AccountPrimary(3, 70, 100, 0, 100), ErrClosed)
}
