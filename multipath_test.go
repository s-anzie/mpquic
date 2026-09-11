package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestMultipathStateMaxPathID(t *testing.T) {
	state := newMultipathState(3)
	state.setPeerInitialMaxPathID(1)
	require.Equal(t, uint64(1), state.peerMaxPathID)

	require.NoError(t, state.handleMaxPathID(&wire.MaxPathIDFrame{MaximumPathID: 2}))
	require.Equal(t, uint64(2), state.peerMaxPathID)
	require.NoError(t, state.handleMaxPathID(&wire.MaxPathIDFrame{MaximumPathID: 1}))
	require.Equal(t, uint64(2), state.peerMaxPathID)

	err := state.handleMaxPathID(&wire.MaxPathIDFrame{MaximumPathID: 0})
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
}

func TestMultipathStatePathStatusIsMonotonic(t *testing.T) {
	state := newMultipathState(3)
	require.NoError(t, state.handlePathStatus(1, 2, false))
	require.NoError(t, state.handlePathStatus(1, 1, true))

	path := state.paths[1]
	require.True(t, path.hasStatus)
	require.Equal(t, uint64(2), path.statusSequence)
	require.False(t, path.statusBackup)
}

func TestMultipathStatePathStatusSequence(t *testing.T) {
	state := newMultipathState(3)

	frame, err := state.nextPathStatusFrame(1, false)
	require.NoError(t, err)
	require.Equal(t, &wire.PathStatusAvailableFrame{PathID: 1, SequenceNumber: 0}, frame)

	frame, err = state.nextPathStatusFrame(1, true)
	require.NoError(t, err)
	require.Equal(t, &wire.PathStatusBackupFrame{PathID: 1, SequenceNumber: 1}, frame)

	frame, err = state.nextPathStatusFrame(2, false)
	require.NoError(t, err)
	require.Equal(t, &wire.PathStatusAvailableFrame{PathID: 2, SequenceNumber: 0}, frame)
}

func TestMultipathStatePathConnectionIDSequences(t *testing.T) {
	state := newMultipathState(3)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	require.NoError(t, state.handlePathNewConnectionID(&wire.PathNewConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 0,
		ConnectionID:   connID,
	}))
	require.Equal(t, uint64(1), state.paths[1].nextConnectionIDSequence)
	require.NoError(t, state.handlePathRetireConnectionID(&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0}))

	err := state.handlePathRetireConnectionID(&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 1})
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
}

func TestMultipathStateIgnoresFramesForAbandonedPath(t *testing.T) {
	state := newMultipathState(3)
	require.NoError(t, state.markPathAbandoned(1))

	require.NoError(t, state.handlePathStatus(1, 4, true))
	require.NoError(t, state.handlePathNewConnectionID(&wire.PathNewConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 0,
		ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}))
	require.NoError(t, state.handlePathRetireConnectionID(&wire.PathRetireConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 99,
	}))
	require.NoError(t, state.handlePathCIDsBlocked(&wire.PathCIDsBlockedFrame{
		PathID:             1,
		NextSequenceNumber: 99,
	}))

	path := state.paths[1]
	require.Empty(t, path.connectionIDs)
	require.False(t, path.hasStatus)
}

func TestMultipathStateAcceptsReorderedRetirePriorTo(t *testing.T) {
	state := newMultipathState(3)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	// A higher sequence number can arrive before the connection IDs covered by
	// Retire Prior To. Those older sequence numbers are retired implicitly.
	require.NoError(t, state.handlePathNewConnectionID(&wire.PathNewConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 4,
		RetirePriorTo:  3,
		ConnectionID:   connID,
	}))
	require.Equal(t, uint64(3), state.paths[1].highestRetiredConnectionID)
	require.Equal(t, uint64(5), state.paths[1].nextConnectionIDSequence)

	// A delayed frame for a sequence below the threshold is silently ignored.
	require.NoError(t, state.handlePathNewConnectionID(&wire.PathNewConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 1,
		RetirePriorTo:  0,
		ConnectionID:   protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
	}))
	require.NotContains(t, state.paths[1].connectionIDs, uint64(1))
}

func TestMultipathStateBindsConnectionIDsToOnePath(t *testing.T) {
	state := newMultipathState(3)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	require.NoError(t, state.handlePathNewConnectionID(&wire.PathNewConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 0,
		ConnectionID:   connID,
	}))
	pathID, ok := state.pathIDForConnectionID(connID)
	require.True(t, ok)
	require.Equal(t, uint64(1), pathID)

	err := state.handlePathNewConnectionID(&wire.PathNewConnectionIDFrame{
		PathID:         2,
		SequenceNumber: 0,
		ConnectionID:   connID,
	})
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)

	require.NoError(t, state.handlePathRetireConnectionID(&wire.PathRetireConnectionIDFrame{
		PathID:         1,
		SequenceNumber: 0,
	}))
	_, ok = state.pathIDForConnectionID(connID)
	require.False(t, ok)
}

func TestMultipathStatePathAbandonIsIdempotent(t *testing.T) {
	state := newMultipathState(3)
	f := &wire.PathAbandonFrame{PathID: 1, ErrorCode: 0}

	echo, err := state.handlePathAbandon(f)
	require.NoError(t, err)
	require.True(t, echo)
	echo, err = state.handlePathAbandon(f)
	require.NoError(t, err)
	require.False(t, echo)
}

func TestMultipathStateAllowsInitialPathAbandon(t *testing.T) {
	state := newMultipathState(3)
	echo, err := state.handlePathAbandon(&wire.PathAbandonFrame{PathID: 0})
	require.NoError(t, err)
	require.True(t, echo)
	require.True(t, state.isPathAbandoned(0))
	require.False(t, state.hasUsablePathExcept(0))
	require.NoError(t, state.markPathAbandoned(0))
}

func TestMultipathStateKeepsImplicitInitialPathUsable(t *testing.T) {
	state := newMultipathState(3)
	echo, err := state.handlePathAbandon(&wire.PathAbandonFrame{PathID: 1})
	require.NoError(t, err)
	require.True(t, echo)
	require.True(t, state.hasUsablePathExcept(1))
}

func TestMultipathStateAcceptsInitialPathCIDsBlocked(t *testing.T) {
	state := newMultipathState(3)
	require.NoError(t, state.handlePathCIDsBlocked(&wire.PathCIDsBlockedFrame{
		PathID:             0,
		NextSequenceNumber: 42,
	}))
}

func TestMultipathStateUsesAnIndependentPacketNumberSpacePerPath(t *testing.T) {
	state := newMultipathState(3)

	pathZeroPN, err := state.nextPacketNumber(0)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0), pathZeroPN)
	pathZeroPN, err = state.nextPacketNumber(0)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(1), pathZeroPN)

	pathOnePN, err := state.nextPacketNumber(1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0), pathOnePN)

	require.NoError(t, state.observeReceivedPacketNumber(0, 9))
	require.NoError(t, state.observeReceivedPacketNumber(0, 4))
	require.NoError(t, state.observeAcknowledgedPacketNumber(0, 7))
	require.Equal(t, protocol.PacketNumber(9), state.paths[0].packetNumberSpace.largestReceived)
	require.Equal(t, protocol.PacketNumber(7), state.paths[0].packetNumberSpace.largestAcknowledged)
	require.Equal(t, protocol.InvalidPacketNumber, state.paths[1].packetNumberSpace.largestReceived)
}

func TestMultipathStateRejectsPacketNumberOverflow(t *testing.T) {
	state := newMultipathState(0)
	path, err := state.path(0)
	require.NoError(t, err)
	path.packetNumberSpace.nextPacketNumber = protocol.MaxPathAndPacketNumber + 1

	_, err = state.nextPacketNumber(0)
	require.Error(t, err)
	require.NoError(t, state.observeReceivedPacketNumber(0, protocol.MaxPathAndPacketNumber))
	require.Error(t, state.observeReceivedPacketNumber(0, protocol.MaxPathAndPacketNumber+1))
}

func TestMultipathStateHandlesPathAckPerPath(t *testing.T) {
	state := newMultipathState(3)
	require.NoError(t, state.recordSentPacket(1, 9, monotime.Now()))
	pathID := uint64(1)
	ack := &wire.AckFrame{
		PathID:    &pathID,
		AckRanges: []wire.AckRange{{Smallest: 4, Largest: 9}},
		DelayTime: 0,
		ECT0:      0,
		ECT1:      0,
		ECNCE:     0,
	}

	require.NoError(t, state.handlePathAck(ack))
	require.Equal(t, protocol.PacketNumber(9), state.paths[1].packetNumberSpace.largestAcknowledged)

	_, err := state.handlePathAbandon(&wire.PathAbandonFrame{PathID: 1})
	require.NoError(t, err)
	ack.AckRanges[0].Largest = 20
	require.NoError(t, state.handlePathAck(ack))
	require.Equal(t, protocol.PacketNumber(9), state.paths[1].packetNumberSpace.largestAcknowledged)
}

func TestMultipathStateRejectsPathAckForUnsentPacket(t *testing.T) {
	state := newMultipathState(3)
	require.NoError(t, state.recordSentPacket(1, 3, monotime.Now()))
	pathID := uint64(1)
	err := state.handlePathAck(&wire.AckFrame{
		PathID:    &pathID,
		AckRanges: []wire.AckRange{{Smallest: 4, Largest: 4}},
	})
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
}

func TestMultipathStateAcknowledgesPacketRanges(t *testing.T) {
	state := newMultipathState(3)
	now := monotime.Now()
	for _, packetNumber := range []protocol.PacketNumber{4, 5, 7, 9} {
		require.NoError(t, state.recordSentPacket(1, packetNumber, now))
	}

	pathID := uint64(1)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{
		PathID: &pathID,
		AckRanges: []wire.AckRange{
			{Smallest: 9, Largest: 9},
			{Smallest: 4, Largest: 5},
		},
	}))
	require.False(t, state.hasOutstandingPacket(1, 4))
	require.False(t, state.hasOutstandingPacket(1, 5))
	require.True(t, state.hasOutstandingPacket(1, 7))
	require.False(t, state.hasOutstandingPacket(1, 9))
}

func TestMultipathStateTracksPerPathRTTAndLossDelay(t *testing.T) {
	state := newMultipathState(3)
	sentAt := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 1, sentAt, 1200, true, nil, nil))

	pathID := uint64(1)
	receivedAt := sentAt.Add(100 * time.Millisecond)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{
		PathID:    &pathID,
		AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: 10 * time.Millisecond,
	}, receivedAt))

	require.Equal(t, 90*time.Millisecond, state.paths[1].latestRTT)
	require.Equal(t, 90*time.Millisecond, state.paths[1].smoothedRTT)
	require.Equal(t, 101250*time.Microsecond, state.paths[1].lossDelay)
}

func TestMultipathStateUsesPathLossDelay(t *testing.T) {
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentPacket(1, 1, now.Add(-200*time.Millisecond)))
	require.NoError(t, state.recordSentPacket(2, 1, now.Add(-200*time.Millisecond)))
	state.paths[1].lossDelay = 100 * time.Millisecond

	require.Equal(t, now.Add(-100*time.Millisecond), state.nextPathProbeLossTime(time.Second))
	lost := state.detectLostPathProbes(now, time.Second)
	require.Equal(t, []uint64{1}, lost)
	require.True(t, state.hasOutstandingPacket(2, 1))
}

func TestMultipathStateReportsLostPathsInIDOrder(t *testing.T) {
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentPacket(2, 1, now.Add(-time.Second)))
	require.NoError(t, state.recordSentPacket(1, 1, now.Add(-time.Second)))
	require.Equal(t, []uint64{1, 2}, state.detectLostPathProbes(now, time.Second))
}

func TestMultipathStateDoesNotKeepLossTimerForAbandonedPath(t *testing.T) {
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentPacket(1, 1, now.Add(-time.Second)))
	require.NoError(t, state.markPathAbandoned(1))
	require.True(t, state.nextPathProbeLossTime(time.Second).IsZero())
}

func TestMultipathStateReportsNextPathPacingTime(t *testing.T) {
	state := newMultipathState(3)
	var connStats utils.ConnectionStats
	state.configurePathCongestion(protocol.ByteCount(protocol.InitialPacketSize), &connStats)
	now := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 1, now, 1200, true, nil, nil))

	deadline, ok := state.nextPathPacingTime()
	require.True(t, ok)
	require.Zero(t, deadline)

	require.NoError(t, state.markPathAbandoned(1))
	_, ok = state.nextPathPacingTime()
	require.False(t, ok)
}

func TestMultipathStateSynchronizesPathMaximumDatagramSize(t *testing.T) {
	state := newMultipathState(3)
	var connStats utils.ConnectionStats
	state.configurePathCongestion(protocol.ByteCount(protocol.InitialPacketSize), &connStats)
	path, err := state.path(1)
	require.NoError(t, err)

	state.setMaxDatagramSize(1400)
	require.Equal(t, protocol.ByteCount(1400), state.maxDatagramSize)
	require.NotNil(t, path.congestion)

	path, err = state.path(2)
	require.NoError(t, err)
	require.NotNil(t, path.congestion)
	require.Equal(t, protocol.ByteCount(1400), state.maxDatagramSize)
}

func TestMultipathStateFeedsRTTIntoPathCongestionController(t *testing.T) {
	state := newMultipathState(3)
	var connStats utils.ConnectionStats
	state.configurePathCongestion(protocol.ByteCount(protocol.InitialPacketSize), &connStats)
	state.setMaxAckDelay(40 * time.Millisecond)
	sentAt := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 1, sentAt, 1200, true, nil, nil))

	pathID := uint64(1)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{
		PathID:    &pathID,
		AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
	}, sentAt.Add(100*time.Millisecond)))

	require.True(t, state.paths[1].rttStats.HasMeasurement())
	require.Equal(t, 40*time.Millisecond, state.paths[1].rttStats.MaxAckDelay())
	require.Equal(t, state.paths[1].rttStats.LatestRTT(), state.paths[1].latestRTT)
	require.Equal(t, state.paths[1].rttStats.SmoothedRTT(), state.paths[1].smoothedRTT)
}

type multipathTestFrameHandler struct {
	acked int
	lost  int
}

func (h *multipathTestFrameHandler) OnAcked(wire.Frame) { h.acked++ }
func (h *multipathTestFrameHandler) OnLost(wire.Frame)  { h.lost++ }

func TestMultipathStateAcknowledgesAndDetectsLostApplicationFrames(t *testing.T) {
	state := newMultipathState(3)
	handler := &multipathTestFrameHandler{}
	frame := &wire.PingFrame{}
	now := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacket(
		1,
		4,
		now,
		[]ackhandler.Frame{{Frame: frame, Handler: handler}},
		nil,
	))

	pathID := uint64(1)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{
		PathID:    &pathID,
		AckRanges: []wire.AckRange{{Smallest: 4, Largest: 4}},
	}))
	require.Equal(t, 1, handler.acked)
	require.Zero(t, handler.lost)

	require.NoError(t, state.recordSentApplicationPacket(
		1,
		5,
		now.Add(-time.Second),
		[]ackhandler.Frame{{Frame: frame, Handler: handler}},
		nil,
	))
	require.Empty(t, state.detectLostPathProbes(now, time.Second))
	require.Equal(t, 1, handler.lost)
}

func TestMultipathStateReportsApplicationLossWithoutProbeLoss(t *testing.T) {
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacket(
		1,
		4,
		now.Add(-time.Second),
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}}},
		nil,
	))

	lostPaths, lostPackets := state.detectLostPathPackets(now, time.Second)
	require.Empty(t, lostPaths)
	require.True(t, lostPackets)
}

func TestMultipathStateUsesIndependentPathCongestionControllers(t *testing.T) {
	state := newMultipathState(3)
	var connStats utils.ConnectionStats
	state.configurePathCongestion(protocol.ByteCount(protocol.InitialPacketSize), &connStats)

	now := monotime.Now()
	require.NoError(t, state.recordSentApplicationPacketWithSize(1, 1, now, 1200, true, nil, nil))
	require.NoError(t, state.recordSentApplicationPacketWithSize(2, 1, now, 1200, true, nil, nil))
	require.Equal(t, protocol.ByteCount(1200), state.paths[1].bytesInFlight)
	require.Equal(t, protocol.ByteCount(1200), state.paths[2].bytesInFlight)
	require.NotSame(t, state.paths[1].congestion, state.paths[2].congestion)

	pathID := uint64(1)
	require.NoError(t, state.handlePathAck(&wire.AckFrame{
		PathID:    &pathID,
		AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
	}, now.Add(time.Millisecond)))
	require.Zero(t, state.paths[1].bytesInFlight)
	require.Equal(t, protocol.ByteCount(1200), state.paths[2].bytesInFlight)

	require.Empty(t, state.detectLostPathProbes(now.Add(time.Second), time.Second))
	require.Zero(t, state.paths[2].bytesInFlight)
}

func TestMultipathStateAllocatesIndependentPacketNumbers(t *testing.T) {
	state := newMultipathState(3)
	pn, pnLen, err := state.allocatePacketNumber(1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0), pn)
	require.Equal(t, protocol.PacketNumberLen2, pnLen)
	pn, _, err = state.allocatePacketNumber(2)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0), pn)
}

func TestMultipathStateDetectsLostPathProbes(t *testing.T) {
	state := newMultipathState(3)
	now := monotime.Now()
	require.NoError(t, state.recordSentPacket(1, 0, now.Add(-time.Second)))
	require.NoError(t, state.recordSentPacket(2, 0, now))
	require.False(t, state.nextPathProbeLossTime(time.Second).IsZero())
	require.Equal(t, []uint64{1}, state.detectLostPathProbes(now, time.Second))
	require.False(t, state.hasOutstandingPacket(1, 0))
	require.True(t, state.hasOutstandingPacket(2, 0))
}
