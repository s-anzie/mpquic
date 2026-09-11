package quic

import (
	"testing"

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
