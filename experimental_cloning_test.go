package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

func experimentalUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestExperimentalCloneRecordBounds(t *testing.T) {
	var buf bytes.Buffer
	want := bytes.Repeat([]byte{7}, 512)
	require.NoError(t, writeCloneRecord(&buf, want))
	got, err := readCloneRecord(bytes.NewReader(buf.Bytes()), 512)
	require.NoError(t, err)
	require.Equal(t, want, got)
	_, err = readCloneRecord(bytes.NewReader(buf.Bytes()), 511)
	require.Error(t, err)
	for _, data := range [][]byte{{}, {0}, {0, 0}, {255, 255}, {0, 2, 1}} {
		_, err := readCloneRecord(bytes.NewReader(data), 1500)
		require.Error(t, err)
	}
	require.Error(t, writeCloneRecord(&buf, nil))
	require.Error(t, writeCloneRecord(&buf, make([]byte, 1501)))
}

func experimentalWorkerTLS(t *testing.T, ctx context.Context, alpn ...string) (*tls.Conn, *tls.Conn, [32]byte) {
	t.Helper()
	sc := testdata.GetTLSConfig()
	sc.ClientAuth, sc.ClientCAs, sc.NextProtos = tls.RequireAndVerifyClientCert, testdata.GetRootCA(), []string{ExperimentalCloningALPN}
	if len(alpn) != 0 {
		sc.NextProtos = alpn
	}
	cc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: sc.Certificates, RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: sc.NextProtos}
	l, r := net.Pipe()
	t.Cleanup(func() { l.Close(); r.Close() })
	s, c := tls.Server(l, sc), tls.Client(r, cc)
	done := make(chan error, 1)
	go func() { done <- s.HandshakeContext(ctx) }()
	require.NoError(t, c.HandshakeContext(ctx))
	require.NoError(t, <-done)
	return c, s, sha256.Sum256(sc.Certificates[0].Certificate[0])
}

type experimentalDropConn struct {
	net.PacketConn
	workerPort atomic.Int64
	dropped    atomic.Bool
}

func (c *experimentalDropConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if udp, ok := addr.(*net.UDPAddr); ok && int64(udp.Port) == c.workerPort.Load() && c.dropped.CompareAndSwap(false, true) {
			continue
		}
		return n, addr, nil
	}
}

func TestExperimentalCloningLiveConnection(t *testing.T) {
	testExperimentalCloningLive(t, false, false, false)
}
func TestExperimentalCloningLivePacketLoss(t *testing.T) {
	testExperimentalCloningLive(t, true, false, false)
}
func TestExperimentalCloningWorkerFailureClosesConnection(t *testing.T) {
	testExperimentalCloningLive(t, false, true, false)
}

func TestExperimentalCloningConcurrentClose(t *testing.T) {
	testExperimentalCloningLive(t, false, false, true)
}

func TestExperimentalCloningKeyRotation(t *testing.T) {
	reset := handshake.SetKeyUpdateInterval(20)
	defer reset()
	testExperimentalCloningLive(t, false, false, false, true)
}

func TestExperimentalCloningAutomaticKeyRotation(t *testing.T) {
	reset := handshake.SetKeyUpdateInterval(20)
	defer reset()
	testExperimentalCloningLive(t, false, false, false)
}

func TestExperimentalCloningDirectSources(t *testing.T) {
	testExperimentalCloningLive(t, false, false, false, false, true)
}

func TestExperimentalCloningDirectSourcesWorkerFailure(t *testing.T) {
	testExperimentalCloningLive(t, false, true, false, false, true)
}

func TestExperimentalCloningDirectSourcesKeyRotation(t *testing.T) {
	reset := handshake.SetKeyUpdateInterval(20)
	defer reset()
	testExperimentalCloningLive(t, false, false, false, true, true)
}

func testExperimentalCloningLive(t *testing.T, dropPacket, failWorker, interrupt bool, rotation ...bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cfg := &Config{EnableMultipath: true, MaxPathID: 4}
	direct := len(rotation) > 1 && rotation[1]
	cfg.EnableExperimentalSourceOffers = direct
	st := &Transport{Conn: experimentalUDP(t), ConnectionIDLength: 8}
	defer st.Close()
	listener, err := st.Listen(testdata.GetTLSConfig(), cfg)
	require.NoError(t, err)
	defer listener.Close()
	ct := &Transport{Conn: experimentalUDP(t), ConnectionIDLength: 8}
	defer ct.Close()
	client, err := ct.Dial(ctx, listener.Addr(), &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: testdata.GetTLSConfig().NextProtos}, cfg)
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")
	warmRead := make(chan error, 1)
	go func() {
		s, err := client.AcceptUniStream(ctx)
		if err == nil {
			_, err = io.Copy(io.Discard, s)
		}
		warmRead <- err
	}()
	warm, err := server.OpenUniStreamSync(ctx)
	require.NoError(t, err)
	_, err = warm.Write(make([]byte, 512<<10))
	require.NoError(t, err)
	require.NoError(t, warm.Close())
	require.NoError(t, <-warmRead)
	var sources []ExperimentalCloneSource
	var drop *experimentalDropConn
	var firstWorker *net.UDPConn
	workerDone := make([]chan error, 0, 2)
	for i := range 2 {
		var pc net.PacketConn = experimentalUDP(t)
		if dropPacket && i == 0 {
			drop = &experimentalDropConn{PacketConn: pc}
			pc = drop
		}
		primaryControl, workerControl, pin := experimentalWorkerTLS(t, ctx)
		udp := experimentalUDP(t)
		if direct {
			udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(i+2))})
			require.NoError(t, err)
			defer udp.Close()
		}
		var path *Path
		source := ExperimentalCloneSource{Control: primaryControl, CertificateSHA256: pin}
		if direct {
			id := uint64(i + 1)
			address := udp.LocalAddr().(*net.UDPAddr).AddrPort()
			require.NoError(t, server.AnnounceExperimentalSource(ctx, id, 1, address, time.Minute))
			relayPrimary, relayWorker, relayPin := experimentalWorkerTLS(t, ctx, ExperimentalSourceRelayALPN)
			go func() {
				_ = ServeExperimentalSourceRelay(ctx, relayWorker, relayPin, udp, func(addr netip.AddrPort) bool { return addr == pc.LocalAddr().(*net.UDPAddr).AddrPort() })
			}()
			require.NoError(t, server.PrepareExperimentalSource(ctx, id, 1, relayPrimary, relayPin))
			require.Eventually(t, func() bool {
				return client.AcceptExperimentalSource(ctx, id, 1, func(o ExperimentalSourceOffer) bool { return o.Address == address }) == nil
			}, time.Second, time.Millisecond)
			directPath, err := client.ProbeExperimentalSource(ctx, id, 1, pc.(*net.UDPConn))
			require.NoError(t, err)
			defer directPath.Close()
			path = directPath.path
			source.SourceID, source.Generation = id, 1
		} else {
			tr := &Transport{Conn: pc, ConnectionIDLength: 8}
			defer tr.Close()
			path, err = client.AddPath(tr)
			require.NoError(t, err)
			require.NoError(t, path.Probe(ctx))
		}
		if i == 0 {
			firstWorker = udp
			if drop != nil {
				drop.workerPort.Store(int64(udp.LocalAddr().(*net.UDPAddr).Port))
			}
		}
		done := make(chan error, 1)
		workerDone = append(workerDone, done)
		go func() {
			done <- ServeExperimentalCloneWorker(ctx, workerControl, pin, udp, func(addr netip.AddrPort) bool { return addr.Addr().IsLoopback() })
		}()
		source.PathID = path.ID()
		sources = append(sources, source)
	}
	stream, err := server.OpenUniStreamSync(ctx)
	require.NoError(t, err)
	if direct {
		bad := append([]ExperimentalCloneSource(nil), sources...)
		bad[0].SourceID = 999
		_, err := server.NewExperimentalCloneWriter(ctx, stream, bad)
		require.ErrorIs(t, err, ErrExperimentalCloningNotReady)
	}
	var writer *ExperimentalCloneWriter
	for {
		writer, err = server.NewExperimentalCloneWriter(ctx, stream, sources)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, ErrExperimentalCloningNotReady)
		require.NoError(t, waitCloneTick(ctx, server.ctx, time.Millisecond))
	}
	defer writer.Close()
	if interrupt {
		writer.mu.Lock()
		closed := make(chan struct{})
		go func() { writer.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			writer.mu.Unlock()
			t.Fatal("Close waited for writer lock")
		}
		writer.mu.Unlock()
		_, err := writer.WriteContext(ctx, []byte{1})
		require.ErrorIs(t, err, net.ErrClosed)
		return
	}
	data := bytes.Repeat([]byte("distinct-source-content"), 4096)
	readDone := make(chan error, 1)
	go func() {
		s, err := client.AcceptUniStream(ctx)
		if err != nil {
			readDone <- err
			return
		}
		got, err := io.ReadAll(s)
		if err == nil && !bytes.Equal(data, got) {
			err = io.ErrUnexpectedEOF
		}
		readDone <- err
	}()
	if failWorker {
		require.NoError(t, firstWorker.Close())
	}
	// Exercise a second call after coalesced delivery wakeups from the first.
	// A stale notification must not complete a new range prematurely.
	cut := len(data) / 2
	n, err := writer.WriteContext(ctx, data[:cut])
	if err == nil && len(rotation) > 0 && rotation[0] {
		err = writer.RotateKeys(ctx)
	}
	if err == nil {
		var rest int
		rest, err = writer.WriteContext(ctx, data[cut:])
		n += rest
	}
	if failWorker {
		require.Error(t, err)
		require.Zero(t, n)
		select {
		case <-server.ctx.Done():
		case <-ctx.Done():
			t.Fatal("worker failure did not close connection")
		}
		return
	}
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	server.connFlowController.sendMutex.Lock()
	used := server.connFlowController.bytesSent
	server.connFlowController.sendMutex.Unlock()
	require.EqualValues(t, (512<<10)+len(data), used, "retries must not charge unique-byte flow credit twice")
	stream.mutex.Lock()
	outstanding := stream.numOutstandingFrames
	stream.mutex.Unlock()
	require.Zero(t, outstanding, "client ACK must discharge the live stream obligation")
	require.NoError(t, stream.Close())
	require.NoError(t, <-readDone)
	require.Greater(t, writer.sequences[0], uint64(0))
	require.Greater(t, writer.sequences[1], uint64(0))
	if len(rotation) > 0 && rotation[0] {
		stats := writer.Stats()
		for _, stat := range stats {
			require.Greater(t, stat.KeyRotations, uint64(0))
			t.Logf("path %d: epoch %d, rotations %d", stat.PathID, stat.LastKeyEpoch, stat.KeyRotations)
		}
	}
	if drop != nil {
		require.True(t, drop.dropped.Load())
		require.Greater(t, writer.sequences[0], uint64(48))
	}
	t.Logf("live QUIC transfer: %d bytes, worker packets %v", n, writer.sequences)
	require.NoError(t, writer.Close())
	for _, done := range workerDone {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
