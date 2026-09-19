package quic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// No live sender runs in this fixture. Its pre-handoff packet history lets us
// exercise the real frame parser / ACK ingestion followed by worker TLS routing.
// It does not simulate remote packet protection or claim a UDP cloning transfer.
func newCloningControlConnection(t *testing.T) *Conn {
	t.Helper()
	c := newServerTestConnection(t, nil, &Config{EnableMultipath: true}, false).conn
	c.multipath = newMultipathState(4)
	c.multipathEnabled, c.handshakeConfirmed = true, true
	c.frameParser.SetMultipath(true)
	for _, id := range []uint64{1, 2} {
		pn, _, err := c.multipath.allocatePacketNumber(id)
		require.NoError(t, err)
		require.NoError(t, c.multipath.recordSentApplicationPacket(id, pn, monotime.Now(), nil, nil))
	}
	require.NoError(t, c.prepareCloningAuthorityOnLoop())
	t.Cleanup(c.multipath.cloningAuthority.Close)
	return c
}

func bindCloningControlTestWorker(t *testing.T, c *Conn, id uint64) (*cloning.WorkerControl, *tls.Conn) {
	t.Helper()
	sc := testdata.GetTLSConfig()
	sc.ClientAuth, sc.ClientCAs, sc.NextProtos = tls.RequireAndVerifyClientCert, testdata.GetRootCA(), []string{cloning.WorkerControlALPN}
	cc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: testdata.GetRootCA(), ServerName: "localhost", Certificates: sc.Certificates, NextProtos: sc.NextProtos}
	server, rawClient := net.Pipe()
	t.Cleanup(func() { _ = rawClient.Close(); _ = server.Close() })
	client := tls.Client(rawClient, cc)
	handshake := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		handshake <- client.HandshakeContext(ctx)
	}()
	w, err := c.multipath.cloningAuthority.BindWorker(t.Context(), server, sc, c.multipath.paths[id].cloningGrant, sha256.Sum256(cc.Certificates[0].Certificate[0]))
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	t.Cleanup(func() {
		w.Close()
		select {
		case <-w.Done():
		case <-time.After(3 * time.Second):
			t.Error("worker did not exit")
		}
	})
	return w, client
}

func readCloningControlTestMessage(t *testing.T, client *tls.Conn, sequence uint64, kind byte) []byte {
	t.Helper()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	var prefix [4]byte
	_, err := io.ReadFull(client, prefix[:])
	require.NoError(t, err)
	n := binary.BigEndian.Uint32(prefix[:])
	require.GreaterOrEqual(t, n, uint32(9))
	require.LessOrEqual(t, n, uint32(9+48+16*cloning.MaxWorkerACKRanges))
	body := make([]byte, n)
	_, err = io.ReadFull(client, body)
	require.NoError(t, err)
	require.Equal(t, kind, body[0])
	require.Equal(t, sequence, binary.BigEndian.Uint64(body[1:9]))
	return body[9:]
}

func TestCloningControlRoutesACKByAcknowledgedPath(t *testing.T) {
	c := newCloningControlConnection(t)
	_, first := bindCloningControlTestWorker(t, c, 1)
	_, second := bindCloningControlTestWorker(t, c, 2)
	readCloningControlTestMessage(t, first, 1, 1) // welcome
	readCloningControlTestMessage(t, second, 1, 1)
	for _, path := range []uint64{1, 2} {
		frame := &wire.AckFrame{PathID: &path, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
		data, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		arrivalPath := uint64(3) - path
		_, _, _, err = c.handleFramesForPath(data, protocol.ConnectionID{}, arrivalPath, protocol.Encryption1RTT, nil, monotime.Now())
		require.NoError(t, err)
		client := first
		if path == 2 {
			client = second
		}
		body := readCloningControlTestMessage(t, client, 2, 6) // forwarded PATH_ACK
		require.Equal(t, path, binary.BigEndian.Uint64(body))
		require.Equal(t, uint64(1), binary.BigEndian.Uint64(body[40:]))
		require.Zero(t, binary.BigEndian.Uint64(body[48:]))
		require.Empty(t, c.multipath.paths[path].sentPackets)
	}
}

func TestCloningControlDoesNotForwardInvalidClientACK(t *testing.T) {
	c := newCloningControlConnection(t)
	_, client := bindCloningControlTestWorker(t, c, 1)
	readCloningControlTestMessage(t, client, 1, 1)
	id := uint64(1)
	frame := &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
	data, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = c.handleFramesForPath(data, protocol.ConnectionID{}, 0, protocol.Encryption1RTT, nil, monotime.Now())
	var transportError *qerr.TransportError
	require.ErrorAs(t, err, &transportError)
	require.Equal(t, qerr.ProtocolViolation, transportError.ErrorCode)
	frame.AckRanges[0] = wire.AckRange{Smallest: 0, Largest: 0}
	data, err = frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = c.handleFramesForPath(data, protocol.ConnectionID{}, 0, protocol.EncryptionHandshake, nil, monotime.Now())
	require.Error(t, err, "PATH_ACK cannot arrive at the Handshake encryption level")
	// The only notification after welcome must be the valid ACK below.
	_, _, _, err = c.handleFramesForPath(data, protocol.ConnectionID{}, 0, protocol.Encryption1RTT, nil, monotime.Now())
	require.NoError(t, err)
	body := readCloningControlTestMessage(t, client, 2, 6)
	require.Zero(t, binary.BigEndian.Uint64(body[56:]))
}

func TestCloningControlOverflowRetiresOnlyAffectedPath(t *testing.T) {
	c := newCloningControlConnection(t)
	w, _ := bindCloningControlTestWorker(t, c, 1) // no welcome read: deterministic backpressure
	id := uint64(1)
	frame := &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
	for range cloning.MaxWorkerControlQueue + 1 {
		require.NoError(t, c.handleAckFrame(frame, protocol.Encryption1RTT, monotime.Now()))
	}
	select {
	case <-w.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("saturated worker did not exit")
	}
	require.ErrorIs(t, w.Err(), cloning.ErrWorkerBusy)
	require.True(t, c.multipath.isPathAbandoned(1))
	require.False(t, c.multipath.isPathAbandoned(0))
	require.False(t, c.multipath.isPathAbandoned(2))
	require.True(t, c.connIDGenerator.abandonedPaths[1])
	require.True(t, c.connIDManager.abandonedPaths[1])
	require.Contains(t, c.framer.controlFrames, &wire.PathAbandonFrame{PathID: 1})
	require.NoError(t, c.Context().Err())
	// Late ACKs on the retired path are ignored rather than reopening it.
	require.NoError(t, c.handleAckFrame(frame, protocol.Encryption1RTT, monotime.Now()))
}

func TestCloningControlFailureWithoutAlternative(t *testing.T) {
	c := newCloningControlConnection(t)
	w, _ := bindCloningControlTestWorker(t, c, 1)
	require.NoError(t, c.multipath.markPathAbandoned(0))
	w.Close()
	id := uint64(1)
	err := c.handleAckFrame(&wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}, protocol.Encryption1RTT, monotime.Now())
	var transportError *qerr.TransportError
	require.ErrorAs(t, err, &transportError)
	require.Equal(t, qerr.NoViablePathError, transportError.ErrorCode)
}

func TestCloningControlCoalescedFailuresWithoutACK(t *testing.T) {
	c := newCloningControlConnection(t)
	first, _ := bindCloningControlTestWorker(t, c, 1)
	second, _ := bindCloningControlTestWorker(t, c, 2)
	first.Close()
	second.Close()
	select {
	case <-c.cloningWorkerEvents:
	default:
		t.Fatal("worker shutdown did not wake the connection loop")
	}
	require.NoError(t, c.handleCloningWorkerFailures())
	require.True(t, c.multipath.isPathAbandoned(1))
	require.True(t, c.multipath.isPathAbandoned(2))
	require.False(t, c.multipath.isPathAbandoned(0))
	require.Contains(t, c.framer.controlFrames, &wire.PathAbandonFrame{PathID: 1})
	require.Contains(t, c.framer.controlFrames, &wire.PathAbandonFrame{PathID: 2})
	require.NoError(t, c.handleCloningWorkerFailures(), "repeated wakeups are idempotent")
}

func TestCloningControlFailedWorkerIsNotAValidatedSurvivor(t *testing.T) {
	c := newCloningControlConnection(t)
	first, _ := bindCloningControlTestWorker(t, c, 1)
	second, _ := bindCloningControlTestWorker(t, c, 2)
	for _, id := range []uint64{1, 2} {
		c.multipath.paths[id].serverValidated = true
		c.multipath.paths[id].remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	}
	require.NoError(t, c.multipath.markPathAbandoned(0))
	require.True(t, c.hasValidatedPathExcept(1))
	second.Close()
	require.False(t, c.hasValidatedPathExcept(1), "failure is visible before connection-loop cleanup")
	first.Close()
	var transportError *qerr.TransportError
	require.ErrorAs(t, c.handleCloningWorkerFailures(), &transportError)
	require.Equal(t, qerr.NoViablePathError, transportError.ErrorCode)
}
