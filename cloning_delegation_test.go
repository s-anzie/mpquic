package quic

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupClonedStream(t *testing.T) (*SendStream, *cloning.Authority, *cloning.Path, *MockStreamSender) {
	t.Helper()
	fc := newTestStreamFlowControllerWithSendWindow(3, 4096)
	sender := NewMockStreamSender(gomock.NewController(t))
	sender.EXPECT().onHasStreamData(gomock.Any(), gomock.Any()).AnyTimes()
	sender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	s := newSendStream(context.Background(), 3, sender, fc, false)
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, fc.connection.bindCloningAuthority(a, func(err error) { t.Error(err) }))
	p, err := a.GrantPath(1, "source")
	require.NoError(t, err)
	return s, a, p, sender
}

func TestCloningDelegationAdvancesLiveStreamAndWaitsForAllBytes(t *testing.T) {
	s, a, p, sender := setupClonedStream(t)
	r, err := s.delegateCloningRange(p, []byte("delegated"))
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(9), s.writeOffset)
	require.Equal(t, int64(1), s.numOutstandingFrames)
	require.NoError(t, s.TryWriteAll([]byte("tail")))
	require.NoError(t, s.Close())
	frame, _, _ := s.popStreamFrame(128, protocol.Version1)
	require.Equal(t, protocol.ByteCount(9), frame.Frame.Offset)
	require.Equal(t, []byte("tail"), frame.Frame.Data)
	require.True(t, frame.Frame.Fin)
	frame.Handler.OnAcked(frame.Frame)
	require.False(t, s.completed, "FIN ACK cannot discard delegated bytes")
	require.NoError(t, r.acknowledge(0, 4))
	require.NoError(t, r.lost())
	q, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	retry, err := r.retry(q)
	require.NoError(t, err)
	_, bytes, err := retry.read()
	require.NoError(t, err)
	require.Equal(t, []byte("delegated"), bytes)
	sender.EXPECT().onStreamCompleted(protocol.StreamID(3)).Times(1)
	require.NoError(t, retry.acknowledge(4, 5))
	require.True(t, s.completed)
	require.Zero(t, s.numOutstandingFrames)
	require.NoError(t, r.acknowledge(0, 9))
	_, total, _, err := a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, uint64(13), total)
}

func TestCloningDelegationCancellationAndAdmission(t *testing.T) {
	for _, mode := range []string{"cancel", "stop", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			s, a, p, _ := setupClonedStream(t)
			require.NoError(t, s.TryWriteAll([]byte("queued")))
			_, err := s.delegateCloningRange(p, []byte("blocked"))
			require.ErrorIs(t, err, ErrWouldBlock)
			frame, _, _ := s.popStreamFrame(128, protocol.Version1)
			frame.Handler.OnAcked(frame.Frame)
			s.supportsResetStreamAt = true
			_, err = s.delegateCloningRange(p, []byte("blocked"))
			require.ErrorIs(t, err, cloning.ErrDelegationNotReady)
			s.supportsResetStreamAt = false
			r, err := s.delegateCloningRange(p, []byte("data"))
			require.NoError(t, err)
			switch mode {
			case "cancel":
				s.CancelWrite(42)
			case "stop":
				s.handleStopSendingFrame(&wire.StopSendingFrame{StreamID: 3, ErrorCode: 42})
			case "shutdown":
				s.closeForShutdown(context.Canceled)
			}
			require.ErrorIs(t, r.acknowledge(6, 4), cloning.ErrAttempt)
			_, _, err = r.read()
			require.ErrorIs(t, err, cloning.ErrAttempt)
			_, total, _, err := a.PrimaryState(3)
			require.NoError(t, err)
			require.Equal(t, uint64(10), total, "cancellation never refunds credit")
		})
	}
}
