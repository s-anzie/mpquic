package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// TestCongestionStatsPublished: the congestion window, its peak and the
// controller's state reach the connection's stats (Mycelium instrumentation)
// at construction, after an ACK frame and after a loss.
func TestCongestionStatsPublished(t *testing.T) {
	var stats utils.ConnectionStats
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &stats, false, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	initial := uint64(sph.congestion.GetCongestionWindow())
	require.NotZero(t, initial)
	require.Equal(t, initial, stats.CongestionWindow.Load(), "published at construction")
	require.Equal(t, initial, stats.MaxCongestionWindow.Load())
	require.EqualValues(t, 0, stats.CongestionState.Load(), "slow start at construction")

	var packets packetTracker
	now := monotime.Now()
	var pns []protocol.PacketNumber
	for range 32 { // fills the initial window: the controller only grows a window it is limited by
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		pns = append(pns, pn)
	}
	// Acknowledging every packet grows the window (slow start).
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns...)}, protocol.Encryption1RTT, now.Add(10e6))
	require.NoError(t, err)
	grown := uint64(sph.congestion.GetCongestionWindow())
	require.Greater(t, grown, initial)
	require.Equal(t, grown, stats.CongestionWindow.Load(), "published after the ACK")
	require.Equal(t, grown, stats.MaxCongestionWindow.Load())

	// Packets 10..19 sent; acknowledging only the last three declares the first
	// ones lost (packet-threshold loss detection): the window is cut, the
	// controller enters recovery, the peak keeps the grown window.
	pns = pns[:0]
	for range 10 {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(now.Add(20e6), pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		pns = append(pns, pn)
	}
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[7], pns[8], pns[9])}, protocol.Encryption1RTT, now.Add(30e6))
	require.NoError(t, err)
	require.NotZero(t, stats.PacketsLost.Load(), "losses declared")
	cut := uint64(sph.congestion.GetCongestionWindow())
	require.Less(t, cut, grown)
	require.Equal(t, cut, stats.CongestionWindow.Load(), "published after the loss")
	require.Equal(t, grown, stats.MaxCongestionWindow.Load(), "peak kept")
	require.EqualValues(t, 2, stats.CongestionState.Load(), "recovery after the cut")
	require.True(t, sph.congestion.InRecovery())
}
