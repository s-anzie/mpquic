package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func TestExperimentalBatchReservesCreditBeforeKeys(t *testing.T) {
	c, err := NewExperimentalWorkerController(1452, 25*time.Millisecond)
	require.NoError(t, err)
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	n, err := c.reserveBatch(ctx, 64, 1452)
	require.NoError(t, err)
	require.Positive(t, n)
	require.LessOrEqual(t, int64(n*1452), c.Snapshot().CongestionWindow)
	// No ACKs arrive during the lease. All approved packets must nevertheless
	// drain, so a pending key transition cannot deadlock behind this window.
	for i := range n {
		require.NoError(t, c.WaitSend(ctx, 1452))
		require.NoError(t, c.OnSent(int64(i), 1452, monotime.Now()))
	}
	blocked, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	_, err = c.reserveBatch(blocked, 64, 1452)
	stop()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, c.OnACK([]ExperimentalWorkerACKRange{{Smallest: 0, Largest: int64(n - 1)}}, 0, monotime.Now()))
	n, err = c.reserveBatch(ctx, 64, 1452)
	require.NoError(t, err)
	require.Positive(t, n)
	c.cancelBatch()
	require.Zero(t, c.Snapshot().Retained, "ACKed history must not grow with transfer length")
}

func TestExperimentalBatchRespectsHistoryCapacity(t *testing.T) {
	c, err := NewExperimentalWorkerController(1452, 25*time.Millisecond)
	require.NoError(t, err)
	defer c.Close()
	for range experimentalWorkerHistoryLimit - 1 {
		c.packets = append(c.packets, experimentalWorkerPacket{lost: true, pending: true})
	}
	n, err := c.reserveBatch(t.Context(), 64, 1452)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	c.cancelBatch()
	_, err = c.reserveBatch(t.Context(), experimentalCloneBatchPackets+1, 1452)
	require.ErrorIs(t, err, ErrExperimentalWorkerController)
}

func TestExperimentalSourceBatchPinsPeerAndPreservesBuffers(t *testing.T) {
	client, worker, other := experimentalUDP(t), experimentalUDP(t), experimentalUDP(t)
	defer client.Close()
	defer worker.Close()
	defer other.Close()
	s := &sourceDestinationConn{PacketConn: client, primary: other.LocalAddr().(*net.UDPAddr).AddrPort(), worker: worker.LocalAddr().(*net.UDPAddr).AddrPort(), expires: time.Now().Add(time.Minute)}
	s.active.Store(true)
	c, ok := wrapExperimentalSource(s).(*experimentalSourceOOB)
	require.True(t, ok)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err := other.WriteToUDP([]byte("untrusted"), client.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	for _, p := range []string{"first", "second"} {
		_, err = worker.WriteToUDP([]byte(p), client.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
	}
	m := make([]ipv4.Message, 4)
	ptrs := make([]*byte, len(m))
	for i := range m {
		m[i].Buffers = [][]byte{make([]byte, 128)}
		m[i].OOB = make([]byte, 128)
		ptrs[i] = &m[i].Buffers[0][0]
	}
	var got []string
	for len(got) < 2 {
		n, e := c.ReadBatch(m, 0)
		require.NoError(t, e)
		for i := 0; i < n; i++ {
			require.Equal(t, ptrs[i], &m[i].Buffers[0][0])
			got = append(got, string(m[i].Buffers[0][:m[i].N]))
		}
	}
	require.Equal(t, []string{"first", "second"}, got)
	_, _, err = c.WriteMsgUDP([]byte("mapped"), nil, other.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	require.NoError(t, worker.SetReadDeadline(time.Now().Add(time.Second)))
	b := make([]byte, 32)
	n, _, err := worker.ReadFromUDP(b)
	require.NoError(t, err)
	require.Equal(t, "mapped", string(b[:n]))
	_, _, err = c.WriteMsgUDP([]byte("wrong"), nil, client.LocalAddr().(*net.UDPAddr))
	require.ErrorIs(t, err, ErrExperimentalSourceOffer)
}

func TestMultipathACKOnlyHistoryIsBounded(t *testing.T) {
	s := newMultipathState(2)
	for i := range 10000 {
		require.NoError(t, s.recordSentApplicationPacketWithSize(1, protocol.PacketNumber(i), monotime.Now(), 50, false, nil, nil))
	}
	require.Empty(t, s.paths[1].sentPackets)
	require.EqualValues(t, 9999, s.paths[1].largestSent)
	require.True(t, s.nextPathProbeLossTime(time.Second).IsZero())
}

func TestExperimentalWorkerACKCoalescing(t *testing.T) {
	r := &experimentalSourceRelay{ackWake: make(chan struct{}, 1)}
	require.NoError(t, r.queueWorkerACK(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 20}}, DelayTime: time.Millisecond}))
	require.NoError(t, r.queueWorkerACK(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 9}}, DelayTime: time.Second}))
	require.Equal(t, []ExperimentalWorkerACKRange{{Smallest: 0, Largest: 20}}, r.acks)
	require.Equal(t, time.Millisecond, r.ackDelay)
	require.Len(t, r.ackWake, 1)
	require.NoError(t, r.queueWorkerACK(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 25, Largest: 30}}, DelayTime: 2 * time.Millisecond}))
	require.Len(t, r.acks, 2)
	require.Equal(t, 2*time.Millisecond, r.ackDelay)
}

func TestExperimentalLateWorkerLossRetiresHistoryWithoutRetryMapping(t *testing.T) {
	m, a, grant, attempt, _, _ := cloningRecoveryFixture(t)
	require.NoError(t, a.RecordRemotePacket(grant, 1, []cloning.PacketFragment{{Attempt: attempt, Offset: 0, Length: 8}}))
	require.NoError(t, m.recordCloningPacket(1, 1, monotime.Now(), 1200))
	p := m.paths[1]
	require.Empty(t, p.experimentalPacketRanges)
	require.Error(t, a.ForgetRemotePacketsBefore(grant, 2))
	p.recordExperimentalWorkerLoss(0)
	require.Contains(t, p.sentPackets, protocol.PacketNumber(0), "worker cannot retire primary-owned packets")
	p.recordExperimentalWorkerLoss(1)
	require.NoError(t, a.ForgetRemotePacketsBefore(grant, 2))
	require.NotContains(t, p.sentPackets, protocol.PacketNumber(1))
	require.Equal(t, protocol.ByteCount(1200), p.bytesInFlight)
	p.recordExperimentalWorkerLoss(1)
	require.Equal(t, protocol.ByteCount(1200), p.bytesInFlight)
}

func TestExperimentalReceiveQueueMatchesBoundedFlight(t *testing.T) {
	for _, tc := range []struct {
		config Config
		limit  int
	}{
		{Config{}, protocol.MaxConnUnprocessedPackets},
		{Config{EnableMultipath: true}, 4 * protocol.MaxConnUnprocessedPackets},
		{Config{EnableMultipath: true, EnableExperimentalSourceOffers: true}, experimentalCloneFlightPackets},
	} {
		c := &Conn{config: &tc.config}
		limit := tc.limit
		for range limit {
			c.handlePacket(receivedPacket{data: []byte{1}})
		}
		require.Equal(t, limit, c.receivedPackets.Len())
		require.Zero(t, c.connStats.ReceiveQueueDrops.Load())
		// The rejected datagram must return its buffer instead of leaking one for
		// every queue overflow. Also support another owner of a coalesced buffer.
		b := getPacketBuffer()
		b.Split()
		c.handlePacket(receivedPacket{data: []byte{1}, buffer: b})
		require.Equal(t, 1, b.refCount)
		b.Release()
		require.EqualValues(t, 1, c.connStats.ReceiveQueueDrops.Load())
		require.Equal(t, limit, c.receivedPackets.Len())
	}
}

func TestExperimentalRecoveryTimerPreservesPrimaryHandoffPackets(t *testing.T) {
	m, a, grant, attempt, handler, _ := cloningRecoveryFixture(t)
	p := m.paths[1]
	p.experimentalWorkerControlled = true
	now := monotime.Now()
	require.NoError(t, a.RecordRemotePacket(grant, 1, []cloning.PacketFragment{{Attempt: attempt, Offset: 0, Length: 8}}))
	require.NoError(t, m.recordCloningPacket(1, 1, now, 1200))
	p.packetNumberSpace.largestAcknowledged = 1
	require.False(t, m.nextPathProbeLossTime(time.Millisecond).IsZero())
	_, lost := m.detectLostPathPackets(now.Add(time.Second), time.Millisecond)
	require.True(t, lost)
	require.Equal(t, 1, handler.lost)
	require.NotContains(t, p.sentPackets, protocol.PacketNumber(0))
	require.Contains(t, p.sentPackets, protocol.PacketNumber(1))
	require.True(t, m.nextPathProbeLossTime(time.Millisecond).IsZero())
}
