package quic

import (
	"context"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestCloningFlowControlImportsSharedCredit(t *testing.T) {
	c := &connectionFlowController{sendWindow: 12}
	s := &streamFlowController{connection: c, streamID: 0, sendWindow: 10}
	other := &streamFlowController{connection: c, streamID: 3, sendWindow: 10}
	require.True(t, s.TryAddBytesSent(5))
	require.True(t, other.TryAddBytesSent(3))
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, c.bindCloningAuthority(a, func(err error) { t.Error(err) }))
	require.True(t, s.TryAddBytesSent(2))
	offset, total, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(7), offset)
	require.Equal(t, uint64(10), total, "imported bytes must not be charged twice")
	require.False(t, other.TryAddBytesSent(3))
	require.True(t, other.TryAddBytesSent(2))
	_, total, _, err = a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, uint64(12), total)
	c.UpdateSendWindow(16)
	s.UpdateSendWindow(14)
	added, limited := s.AddBytesSentWithLimiter(4, func(n int) int { return n / 2 })
	require.Equal(t, protocol.ByteCount(2), added)
	require.True(t, limited)
	require.True(t, c.finalizeCloningStream(s, 9))
	offset, total, final, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(9), offset)
	require.Equal(t, uint64(14), total)
	require.True(t, final)
}

func TestCloningFlowControlPreservesBufferedReservations(t *testing.T) {
	fc := newTestStreamFlowControllerWithSendWindow(3, 4096)
	str := newSendStream(context.Background(), 3, nil, fc, false)
	_, _, err := str.tryWriteAll(make([]byte, 1024))
	require.NoError(t, err)
	require.Zero(t, str.writeOffset)
	require.Equal(t, protocol.ByteCount(1024), fc.bytesSent)
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, fc.connection.bindCloningAuthority(a, func(err error) { t.Error(err) }))
	var sent protocol.ByteCount
	for sent < 1024 {
		frame, _, _ := str.popStreamFrame(128, protocol.Version1)
		require.NotNil(t, frame.Frame)
		require.Equal(t, sent, frame.Frame.Offset)
		sent += frame.Frame.DataLen()
		frame.Frame.PutBack()
	}
	require.Equal(t, protocol.ByteCount(1024), fc.connection.bytesSent)
	_, _, err = str.tryWriteAll(make([]byte, 17))
	require.NoError(t, err)
	str.finishedWriting = true
	frame, _, _ := str.popStreamFrame(128, protocol.Version1)
	require.True(t, frame.Frame.Fin)
	require.Equal(t, protocol.ByteCount(1024), frame.Frame.Offset)
	frame.Frame.PutBack()
	offset, total, final, err := a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, uint64(1041), offset)
	require.Equal(t, offset, total)
	require.True(t, final)
	str.retransmissionQueue = []*wire.StreamFrame{{StreamID: 3, Offset: 0, Data: []byte("data"), DataLenPresent: true}}
	retransmission, _ := str.popRetransmissionFrame(128, protocol.Version1)
	require.Equal(t, protocol.ByteCount(0), retransmission.Frame.Offset)
	retransmission.Frame.PutBack()
	_, retriedTotal, _, err := a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, total, retriedTotal, "retransmissions do not reserve new stream bytes")
}

func TestCloningFlowControlFailsClosedOnOffsetMismatch(t *testing.T) {
	fc := newTestStreamFlowControllerWithSendWindow(3, 100)
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	var failure error
	require.NoError(t, fc.connection.bindCloningAuthority(a, func(err error) { failure = err }))
	require.True(t, fc.TryAddBytesSent(5))
	// Simulate an inconsistent adapter: no packet may be authorized at a stale offset.
	fc.bytesSent = 0
	require.False(t, fc.TryAddBytesSent(1))
	require.ErrorIs(t, failure, cloning.ErrStream)
	require.Equal(t, protocol.ByteCount(5), fc.connection.bytesSent)
	failure = nil
	require.False(t, fc.connection.TryAddBytesSent(1))
	require.ErrorIs(t, failure, cloning.ErrStream, "anonymous credit updates would bypass stream ownership")
}

func TestCloningFlowControlConcurrentStreamsAcrossActivation(t *testing.T) {
	c := &connectionFlowController{sendWindow: 1000}
	ready := make(chan struct{}, 10)
	resume := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := &streamFlowController{connection: c, streamID: protocol.StreamID(4*i + 1), sendWindow: 100}
			for range 50 {
				if !s.TryAddBytesSent(1) {
					t.Error("prefix reservation failed")
				}
			}
			ready <- struct{}{}
			<-resume
			for range 50 {
				if !s.TryAddBytesSent(1) {
					t.Error("suffix reservation failed")
				}
			}
		}()
	}
	for range 10 {
		<-ready
	}
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	require.NoError(t, c.bindCloningAuthority(a, func(err error) { t.Error(err) }))
	close(resume)
	wg.Wait()
	for i := range 10 {
		offset, total, _, err := a.PrimaryState(protocol.StreamID(4*i + 1))
		require.NoError(t, err)
		require.Equal(t, uint64(100), offset)
		require.Equal(t, uint64(1000), total)
	}
}
