package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
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
