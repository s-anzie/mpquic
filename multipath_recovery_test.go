package quic

import (
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestMultipathRecoveryRequiresAcknowledgmentEvidence(t *testing.T) {
	s := newMultipathState(3)
	s.configurePathCongestion(1200, &utils.ConnectionStats{})
	now := monotime.Now()
	h := &multipathTestFrameHandler{}
	require.NoError(t, s.recordSentApplicationPacketWithSize(1, 1, now, 1200, true,
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: h}}, nil))
	p := s.paths[1]
	p.lossDelay = time.Millisecond
	window := p.congestion.GetCongestionWindow()
	_, lost := s.detectLostPathPackets(now.Add(time.Second), time.Second)
	require.False(t, lost)
	require.Zero(t, h.lost)
	require.Equal(t, protocol.ByteCount(1200), p.bytesInFlight)
	require.Equal(t, window, p.congestion.GetCongestionWindow())
	pto := p.probeTimeout(time.Second)
	require.Equal(t, now.Add(p.rttStats.PTO(true)), pto)
	require.Equal(t, pto, s.nextPathProbeLossTime(time.Second))
	p.lastPTO, p.ptoCount = pto, 1
	require.Equal(t, pto.Add(2*p.rttStats.PTO(true)), p.probeTimeout(time.Second))
	// Evidence on a different path must not declare this packet lost.
	require.NoError(t, s.recordSentApplicationPacketWithSize(2, 2, now, 1200, true, nil, nil))
	id := uint64(2)
	require.NoError(t, s.handlePathAck(&wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}, now.Add(time.Millisecond)))
	_, lost = s.detectLostPathPackets(now.Add(time.Second), time.Second)
	require.False(t, lost)
	// Acknowledging a later packet on this path enables time-threshold loss.
	require.NoError(t, s.recordSentApplicationPacketWithSize(1, 2, now, 1200, true, nil, nil))
	id = 1
	require.NoError(t, s.handlePathAck(&wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}, now.Add(10*time.Millisecond)))
	require.Zero(t, p.ptoCount)
	_, lost = s.detectLostPathPackets(now.Add(time.Second), time.Second)
	require.True(t, lost)
	require.Equal(t, 1, h.lost)
	require.Zero(t, p.bytesInFlight)
}

func TestMultipathRecoveryDoesNotArmPTOForAckOnlyOrAbandonedPath(t *testing.T) {
	s := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, s.recordSentApplicationPacketWithSize(1, 0, now, 100, false, nil, nil))
	require.True(t, s.nextPathProbeLossTime(time.Second).IsZero())
	require.NoError(t, s.recordSentApplicationPacketWithSize(1, 1, now, 1200, true, nil, nil))
	require.False(t, s.nextPathProbeLossTime(time.Second).IsZero())
	require.NoError(t, s.markPathAbandoned(1))
	require.True(t, s.nextPathProbeLossTime(time.Second).IsZero())
}

func TestMultipathRecoverySendsOneProbeWithoutDiscardingFlight(t *testing.T) {
	ctrl := gomock.NewController(t)
	packer := NewMockPacker(ctrl)
	conn := NewMockSendConn(ctrl)
	c := &Conn{multipath: newMultipathState(3), multipathEnabled: true,
		perspective: protocol.PerspectiveServer, packer: packer, conn: conn,
		logger: utils.DefaultLogger, connIDManager: &connIDManager{}}
	now := monotime.Now()
	require.NoError(t, c.multipath.recordSentApplicationPacketWithSize(1, 0, now, 1200, true, nil, nil))
	p := c.multipath.paths[1]
	p.serverValidated = true
	p.remoteAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	buf := getPacketBuffer()
	buf.Data = append(buf.Data, 1, 2, 3)
	frames := []ackhandler.Frame{{Frame: &wire.PingFrame{}}}
	packer.EXPECT().PackPathProbePacket(protocol.ConnectionID{}, frames, gomock.Any()).Return(
		shortHeaderPacket{PathID: 1, PacketNumber: 1, Length: 3, Frames: frames, IsPathProbePacket: true}, buf, nil)
	conn.EXPECT().WriteTo([]byte{1, 2, 3}, p.remoteAddr, p.packetInfo).Return(nil)
	require.NoError(t, c.sendMultipathRecoveryProbes(now.Add(time.Second)))
	require.True(t, c.multipath.hasOutstandingPacket(1, 0))
	require.True(t, c.multipath.hasOutstandingPacket(1, 1))
	require.False(t, p.sentPackets[1].isProbe, "recovery PING must not enter validation retry handling")
	require.Equal(t, uint(1), p.ptoCount)
	// A second call at the same time must not send another probe.
	require.NoError(t, c.sendMultipathRecoveryProbes(now.Add(time.Second)))
	require.Equal(t, now.Add(3*time.Second), p.probeTimeout(time.Second))
}
