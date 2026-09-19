package quic

import (
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func cloningRecoveryFixture(t *testing.T) (*multipathState, *cloning.Authority, *cloning.Path, *cloning.Attempt, *multipathTestFrameHandler, *[]uint64) {
	t.Helper()
	m := newMultipathState(3)
	m.configurePathCongestion(1200, &utils.ConnectionStats{})
	h := &multipathTestFrameHandler{}
	require.NoError(t, m.recordSentApplicationPacketWithSize(1, 0, monotime.Now(), 1200, true,
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: h}}, nil))
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	require.NoError(t, a.BindPrimary(1000, 0))
	g, err := a.ImportPath(1, 1, "remote")
	require.NoError(t, err)
	p := m.paths[1]
	p.cloningAuthority, p.cloningGrant, p.packetNumberSpace.nextPacketNumber = a, g, 1
	_, _, err = a.ReservePacketWindow(g, 4)
	require.NoError(t, err)
	var completed []uint64
	require.NoError(t, m.attachCloningRecovery(1, a, g, func(ids []uint64) { completed = append(completed, ids...) }))
	attempt, err := a.DelegatePrimary(g, 0, 0, 1000, []byte("abcdefgh"), 1000)
	require.NoError(t, err)
	return m, a, g, attempt, h, &completed
}

func cloningRecoveryACK(first, last protocol.PacketNumber) *wire.AckFrame {
	id := uint64(1)
	return &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: first, Largest: last}}}
}

func TestCloningRecoveryMixedPrimaryAndRemoteACK(t *testing.T) {
	m, a, g, attempt, h, completed := cloningRecoveryFixture(t)
	now := monotime.Now()
	for pn := protocol.PacketNumber(1); pn <= 2; pn++ {
		require.NoError(t, a.RecordRemotePacket(g, pn, []cloning.PacketFragment{{Attempt: attempt, Offset: uint64(pn-1) * 4, Length: 4}}))
		require.NoError(t, m.recordCloningPacket(1, pn, now, 1200))
	}
	require.Equal(t, protocol.ByteCount(3600), m.paths[1].bytesInFlight)
	require.Empty(t, *completed)
	require.NoError(t, m.handlePathAck(cloningRecoveryACK(0, 2), now.Add(10*time.Millisecond)))
	require.Equal(t, 1, h.acked)
	require.Len(t, *completed, 1)
	require.Zero(t, m.paths[1].bytesInFlight)
	require.Empty(t, m.paths[1].sentPackets)
	require.NoError(t, m.handlePathAck(cloningRecoveryACK(0, 2), now.Add(20*time.Millisecond)))
	require.Equal(t, 1, h.acked)
	require.Len(t, *completed, 1)
	_, used, _, err := a.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(8), used)
}

func TestCloningRecoveryRejectsPlannedButUndispatchedPacketAtomically(t *testing.T) {
	m, a, g, attempt, h, completed := cloningRecoveryFixture(t)
	for pn := protocol.PacketNumber(1); pn <= 2; pn++ {
		require.NoError(t, a.RecordRemotePacket(g, pn, []cloning.PacketFragment{{Attempt: attempt, Offset: uint64(pn-1) * 4, Length: 4}}))
	}
	require.NoError(t, m.recordCloningPacket(1, 2, monotime.Now(), 1200))
	err := m.handlePathAck(cloningRecoveryACK(0, 2))
	var transportError *qerr.TransportError
	require.ErrorAs(t, err, &transportError)
	require.Equal(t, qerr.ProtocolViolation, transportError.ErrorCode)
	require.Zero(t, h.acked)
	require.Empty(t, *completed)
	require.Equal(t, protocol.ByteCount(2400), m.paths[1].bytesInFlight)
	require.Equal(t, protocol.InvalidPacketNumber, m.paths[1].packetNumberSpace.largestAcknowledged)
	_, _, err = a.ReadAttempt(attempt)
	require.NoError(t, err)
}

func TestCloningRecoveryLossRetryAndLateACK(t *testing.T) {
	m, a, g, attempt, _, completed := cloningRecoveryFixture(t)
	now := monotime.Now()
	require.NoError(t, a.RecordRemotePacket(g, 1, []cloning.PacketFragment{{Attempt: attempt, Offset: 0, Length: 8}}))
	require.NoError(t, a.RecordRemotePacket(g, 2, nil))
	require.NoError(t, m.recordCloningPacket(1, 1, now, 1200))
	require.NoError(t, m.recordCloningPacket(1, 2, now, 1200))
	require.NoError(t, m.handlePathAck(cloningRecoveryACK(2, 2), now.Add(time.Millisecond)))
	_, lost := m.detectLostPathPackets(now.Add(time.Second), time.Second)
	require.True(t, lost)
	require.Zero(t, m.paths[1].bytesInFlight)
	other, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	_, err = a.Retry(attempt, other)
	require.NoError(t, err)
	require.NoError(t, m.handlePathAck(cloningRecoveryACK(1, 1), now.Add(2*time.Second)))
	require.Len(t, *completed, 1)
	require.Zero(t, m.paths[1].bytesInFlight, "late ACK must not charge congestion twice")
}

func TestCloningRecoveryAdmissionAndPrimarySendIsolation(t *testing.T) {
	m, a, g, attempt, _, _ := cloningRecoveryFixture(t)
	p := m.paths[1]
	require.NoError(t, a.RecordRemotePacket(g, 1, []cloning.PacketFragment{{Attempt: attempt, Offset: 0, Length: 8}}))
	inFlight := p.bytesInFlight
	p.bytesInFlight = p.congestion.GetCongestionWindow()
	require.ErrorIs(t, m.recordCloningPacket(1, 1, monotime.Now(), 1200), errCloningRecoveryBlocked)
	p.bytesInFlight = inFlight
	require.NoError(t, m.recordCloningPacket(1, 1, monotime.Now(), 1200))
	require.ErrorIs(t, m.recordCloningPacket(1, 1, monotime.Now(), 1200), errCloningRecoveryBlocked)
	_, err := a.NextPacketNumber(g)
	require.ErrorIs(t, err, cloning.ErrPath)
	p.serverValidated, p.remoteAddr = true, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	c := &Conn{perspective: protocol.PerspectiveServer, multipath: m}
	_, _, selected := c.nextServerApplicationPath(monotime.Now())
	require.False(t, selected, "primary must not schedule application packets on the delegated path")
	// No CID manager / packer is configured: a local PTO send would panic.
	require.NoError(t, c.sendMultipathRecoveryProbes(monotime.Now().Add(time.Hour)))
	require.Greater(t, p.ptoCount, uint(0))
}

func TestCloningRecoveryAttachmentIsFailClosed(t *testing.T) {
	m, a, g, _, _, _ := cloningRecoveryFixture(t)
	p := m.paths[1]
	require.ErrorIs(t, m.attachCloningRecovery(1, a, g, func([]uint64) {}), errCloningRecoveryBlocked)
	p.cloningRecovery = nil
	p.packetNumberSpace.nextPacketNumber++
	require.ErrorIs(t, m.attachCloningRecovery(1, a, g, func([]uint64) {}), errCloningRecoveryBlocked)
	require.Nil(t, p.cloningRecovery)
	p.packetNumberSpace.nextPacketNumber--
	require.ErrorIs(t, m.attachCloningRecovery(1, a, g, nil), errCloningRecoveryBlocked)
	require.ErrorIs(t, m.attachCloningRecovery(0, a, g, func([]uint64) {}), errCloningRecoveryBlocked)
	require.NoError(t, a.ForgetRemotePacketsBefore(g, 2))
	boundary, err := a.RemotePacketStart(g)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(1), boundary, "retention must not move the handoff boundary")
	require.NoError(t, m.attachCloningRecovery(1, a, g, func([]uint64) {}))
}
