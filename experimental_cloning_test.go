package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/wire"
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
	onDrop     func()
}

func (c *experimentalDropConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if udp, ok := addr.(*net.UDPAddr); ok && n > 1000 && n < 1150 && int64(udp.Port) == c.workerPort.Load() && c.dropped.CompareAndSwap(false, true) {
			if c.onDrop != nil {
				c.onDrop()
			}
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

func TestExperimentalCloningAutonomousSources(t *testing.T) {
	testExperimentalCloningLive(t, false, false, false, false, true, true)
}

func TestExperimentalCloningSourceLocalObject(t *testing.T) {
	testExperimentalCloningLive(t, false, false, false, false, true, true, true)
}

func TestExperimentalCloningSourceLocalObjectFailover(t *testing.T) {
	testExperimentalCloningLive(t, false, true, false, false, true, true, true)
}

func TestExperimentalCloningSourceLocalObjectRotation(t *testing.T) {
	reset := handshake.SetKeyUpdateInterval(20)
	defer reset()
	testExperimentalCloningLive(t, false, false, false, false, true, true, true)
}

func TestExperimentalCloningAutonomousLoss(t *testing.T) {
	testExperimentalCloningLive(t, true, false, false, false, true, true)
}

func TestExperimentalCloningAddReplacementDuringWrite(t *testing.T) {
	testExperimentalCloningLive(t, false, true, false, false, true, true, true, true)
}

func TestExperimentalCloningCorruptSourceFailover(t *testing.T) {
	testExperimentalCloningLive(t, false, false, false, false, true, true, true, false, true)
}

func TestExperimentalCloningLostDrainReceipt(t *testing.T) {
	reset := handshake.SetKeyUpdateInterval(20)
	defer reset()
	testExperimentalCloningLive(t, false, false, false, false, true, true, false, false, false, true)
}

func TestExperimentalCloningWithdrawSourceDuringTransfer(t *testing.T) {
	testExperimentalCloningLive(t, false, false, false, false, true, true, true, false, false, false, true)
}

func TestExperimentalCloningExpiredAutonomousSource(t *testing.T) {
	for _, object := range []bool{false, true} {
		t.Run(map[bool]string{false: "bytes", true: "object"}[object], func(t *testing.T) {
			testExperimentalCloningLiveWithRecovery(t, experimentalRecoveryTest{expire: true}, true, false, false, false, true, true, object)
		})
	}
}

func TestExperimentalCloningFlowBlockedRecovery(t *testing.T) {
	for _, connectionWindow := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "connection"}[connectionWindow], func(t *testing.T) {
			for _, object := range []bool{false, true} {
				t.Run(map[bool]string{false: "bytes", true: "object"}[object], func(t *testing.T) {
					testExperimentalCloningLiveWithRecovery(t, experimentalRecoveryTest{smallWindow: true, connectionWindow: connectionWindow}, true, false, false, false, true, true, object)
				})
			}
		})
	}
}

func TestExperimentalCloningFlowBlockedRecoveryDelayedProbe(t *testing.T) {
	testExperimentalCloningLiveWithRecovery(t, experimentalRecoveryTest{smallWindow: true, reprobe: true}, true, false, false, false, true, true, true)
}

func TestExperimentalCloningDelayedValidationDuplicate(t *testing.T) {
	for _, kind := range []string{"exact", "changed-address", "unvalidated"} {
		t.Run(kind, func(t *testing.T) {
			testExperimentalCloningLiveWithRecovery(t, experimentalRecoveryTest{smallWindow: true, duplicate: kind}, true, false, false, false, true, true, true)
		})
	}
}

type experimentalRecoveryTest struct {
	expire, smallWindow, connectionWindow, reprobe bool
	duplicate                                      string
}

func dropExperimentalDrainReceipt(control *tls.Conn, pin [32]byte, udp *net.UDPConn) error {
	defer control.Close()
	meta, err := readCloneRecord(control, 1200)
	if err != nil {
		return err
	}
	var job experimentalCloneJob
	if err := json.Unmarshal(meta, &job); err != nil {
		return err
	}
	if job.Prepare {
		if _, err := control.Write(binary.BigEndian.AppendUint16(nil, uint16(min(job.Count, 4)))); err != nil {
			return err
		}
		meta, err = readCloneRecord(control, 1200)
		if err != nil {
			return err
		}
		job = experimentalCloneJob{}
		if err = json.Unmarshal(meta, &job); err != nil {
			return err
		}
	}
	sealer, err := handshake.ReadRemoteSealer(control, pin, job.Path, protocol.KeyPhase(job.Epoch), protocol.ParseConnectionID(job.CID))
	if err != nil {
		return err
	}
	defer sealer.Close()
	payload, err := readCloneRecord(control, 1200)
	if err != nil {
		return err
	}
	packet, _, err := sealer.SealPacket(payload)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddrPort(job.Destination)
	if err != nil {
		return err
	}
	_, err = udp.WriteToUDPAddrPort(packet, addr)
	// Deliberately lose the only drain receipt after actual emission.
	return err
}

func testExperimentalCloningLive(t *testing.T, dropPacket, failWorker, interrupt bool, rotation ...bool) {
	t.Helper()
	testExperimentalCloningLiveWithRecovery(t, experimentalRecoveryTest{}, dropPacket, failWorker, interrupt, rotation...)
}

func testExperimentalCloningLiveWithRecovery(t *testing.T, recovery experimentalRecoveryTest, dropPacket, failWorker, interrupt bool, rotation ...bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cfg := &Config{EnableMultipath: true, MaxPathID: 4}
	if recovery.smallWindow {
		if recovery.connectionWindow {
			cfg.InitialConnectionReceiveWindow, cfg.MaxConnectionReceiveWindow = 4000, 4000
		} else {
			cfg.InitialStreamReceiveWindow, cfg.MaxStreamReceiveWindow = 4000, 4000
		}
	}
	direct := len(rotation) > 1 && rotation[1]
	autonomous := len(rotation) > 2 && rotation[2]
	object := len(rotation) > 3 && rotation[3]
	dynamic := len(rotation) > 4 && rotation[4]
	corrupt := len(rotation) > 5 && rotation[5]
	uncertain := len(rotation) > 6 && rotation[6]
	withdraw := len(rotation) > 7 && rotation[7]
	data := bytes.Repeat([]byte("distinct-source-content"), 4096)
	if recovery.expire {
		// One lost range in the first write: no new admission can discover expiry.
		data = data[:2000]
	}
	if recovery.reprobe || recovery.duplicate != "" {
		data = data[:8000]
	}
	manifest, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	var controllers []*ExperimentalWorkerController
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
	expiryDone := make(chan error, 1)
	var firstWorker *net.UDPConn
	workerDone := make([]chan error, 0, 2)
	for i := range 2 {
		var pc net.PacketConn = experimentalUDP(t)
		if dropPacket && i == 0 {
			drop = &experimentalDropConn{PacketConn: pc}
			pc = drop
			if recovery.expire {
				drop.onDrop = func() {
					// Expire on the authority loop before the dropped packet can
					// generate a worker retry. Keep both TLS channels healthy.
					expiryDone <- (&ExperimentalCloneWriter{conn: server}).onLoop(ctx, func() error {
						e := server.experimentalSources.entries[1]
						e.expires = time.Now().Add(-time.Second)
						server.experimentalSources.entries[1] = e
						return nil
					})
				}
			}
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
		options := &ExperimentalCloneWorkerOptions{Objects: ExperimentalCloneObjectResolverFunc(func(id ExperimentalCloneObjectID) (io.ReaderAt, error) {
			if id != manifest.ID() {
				return nil, io.EOF
			}
			if corrupt && i == 0 {
				bad := append([]byte(nil), data...)
				bad[0] ^= 1
				return bytes.NewReader(bad), nil
			}
			return bytes.NewReader(data), nil
		})}
		if autonomous {
			options.Controller, err = NewExperimentalWorkerController(1452, 25*time.Millisecond)
			require.NoError(t, err)
			controllers = append(controllers, options.Controller)
			source.Autonomous = true
		}
		if direct {
			id := uint64(i + 1)
			address := udp.LocalAddr().(*net.UDPAddr).AddrPort()
			require.NoError(t, server.AnnounceExperimentalSource(ctx, id, 1, address, time.Minute))
			relayPrimary, relayWorker, relayPin := experimentalWorkerTLS(t, ctx, ExperimentalSourceRelayALPN)
			go func() {
				_ = ServeExperimentalSourceRelay(ctx, relayWorker, relayPin, udp, func(addr netip.AddrPort) bool { return addr == pc.LocalAddr().(*net.UDPAddr).AddrPort() }, options)
			}()
			require.NoError(t, server.PrepareExperimentalSource(ctx, id, 1, relayPrimary, relayPin))
			require.Eventually(t, func() bool {
				return client.AcceptExperimentalSource(ctx, id, 1, func(o ExperimentalSourceOffer) bool { return o.Address == address }) == nil
			}, time.Second, time.Millisecond)
			directPath, err := client.ProbeExperimentalSource(ctx, id, 1, pc)
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
			if uncertain && i == 0 {
				done <- dropExperimentalDrainReceipt(workerControl, pin, udp)
				return
			}
			done <- ServeExperimentalCloneWorker(ctx, workerControl, pin, udp, func(addr netip.AddrPort) bool { return addr.Addr().IsLoopback() }, options)
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
	initialSources := sources
	if dynamic {
		initialSources = sources[:1]
	}
	for {
		writer, err = server.NewExperimentalCloneWriter(ctx, stream, initialSources)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, ErrExperimentalCloningNotReady)
		require.NoError(t, waitCloneTick(ctx, server.ctx, time.Millisecond))
	}
	defer writer.Close()
	var replacementDone chan error
	if dynamic {
		replacementDone = make(chan error, 1)
		go func() {
			for {
				retired := false
				if err := (&ExperimentalCloneWriter{conn: server}).onLoop(ctx, func() error { retired = server.multipath.isPathAbandoned(sources[0].PathID); return nil }); err != nil {
					replacementDone <- err
					return
				}
				if retired {
					replacementDone <- writer.AddSource(ctx, sources[1])
					return
				}
				if err := waitCloneTick(ctx, server.ctx, time.Millisecond); err != nil {
					replacementDone <- err
					return
				}
			}
		}()
	}
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
	writeCtx := ctx
	if recovery.expire || recovery.smallWindow {
		var stopWrite context.CancelFunc
		writeCtx, stopWrite = context.WithTimeout(ctx, 5*time.Second)
		defer stopWrite()
	}
	// Exercise a second call after coalesced delivery wakeups from the first.
	// A stale notification must not complete a new range prematurely.
	cut := len(data) / 2
	if object {
		cut = cut / 1000 * 1000
	}
	var n int
	if object {
		if withdraw || recovery.expire || recovery.reprobe || recovery.duplicate != "" {
			n, err = writer.WriteObjectRange(writeCtx, manifest, 0, int64(cut))
		} else {
			n, err = writer.WriteObject(writeCtx, manifest)
		}
	} else {
		n, err = writer.WriteContext(writeCtx, data[:cut])
	}
	var expectedRetiredPath uint64
	if err == nil && recovery.duplicate != "" {
		require.NoError(t, writer.onLoop(ctx, func() error {
			for i := len(sources) - 1; i >= 0; i-- {
				source := sources[i]
				p := server.multipath.paths[source.PathID]
				if p.abandoned || p.cloningRecovery == nil {
					continue
				}
				previous, ok := server.experimentalPathChallenges[source.PathID]
				if !ok {
					return fmt.Errorf("initial validation response not remembered for path %d", source.PathID)
				}
				addr := net.UDPAddrFromAddrPort(previous.address)
				if recovery.duplicate == "changed-address" {
					addr.Port = addr.Port%65535 + 1
				}
				if recovery.duplicate == "unvalidated" {
					p.serverValidated = false
				}
				retire := recovery.duplicate != "exact"
				nextPN, largestSent := p.packetNumberSpace.nextPacketNumber, p.largestSent
				for range 2 {
					if err := server.sendMultipathPathResponse(source.PathID, &wire.PathChallengeFrame{Data: previous.data}, monotime.Now(), addr, p.packetInfo); err != nil {
						return err
					}
					if p.abandoned != retire || p.cloningAuthority.IsRetiredPath(p.cloningGrant) != retire {
						return fmt.Errorf("%s challenge: path %d retired=%v, want %v", recovery.duplicate, source.PathID, p.abandoned, retire)
					}
					if nextPN != p.packetNumberSpace.nextPacketNumber || largestSent != p.largestSent {
						return fmt.Errorf("challenge emitted a primary packet after worker handoff")
					}
				}
				if retire {
					expectedRetiredPath = source.PathID
				}
				return nil
			}
			return fmt.Errorf("no delegated path available to test late challenge")
		}))
	}
	if err == nil && recovery.reprobe {
		// A lost validation probe can be requeued after Probe has returned.
		// Deliver that real challenge only after worker handoff is complete.
		var reprobePath pathID
		require.NoError(t, writer.onLoop(ctx, func() error {
			for _, source := range sources {
				p := server.multipath.paths[source.PathID]
				if !p.abandoned && p.cloningRecovery != nil {
					reprobePath = pathID(source.PathID)
					break
				}
			}
			return nil
		}))
		require.NotZero(t, reprobePath)
		expectedRetiredPath = uint64(reprobePath)
		client.pathManagerOutgoing.Load().requeueProbe(reprobePath)
		require.Eventually(t, func() bool {
			retired := false
			loopErr := writer.onLoop(ctx, func() error {
				retired = server.multipath.isPathAbandoned(uint64(reprobePath))
				return nil
			})
			return loopErr == nil && retired
		}, time.Second, time.Millisecond)
	}
	if err == nil && (recovery.expire || recovery.reprobe || recovery.duplicate != "") && object {
		var rest int
		rest, err = writer.WriteObjectRange(writeCtx, manifest, int64(cut), int64(len(data)-cut))
		n += rest
	}
	if err == nil && withdraw {
		err = server.AnnounceExperimentalSource(ctx, sources[0].SourceID, 2, netip.AddrPort{}, 0)
		if err == nil {
			var rest int
			rest, err = writer.WriteObjectRange(writeCtx, manifest, int64(cut), int64(len(data)-cut))
			n += rest
		}
	}
	if err == nil && len(rotation) > 0 && rotation[0] {
		err = writer.RotateKeys(ctx)
	}
	if err == nil && !object {
		var rest int
		rest, err = writer.WriteContext(writeCtx, data[cut:])
		n += rest
	}
	if failWorker && !direct {
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
	if recovery.expire {
		require.NoError(t, <-expiryDone)
	}
	if direct && (failWorker || corrupt || uncertain || withdraw || recovery.expire) {
		require.True(t, writer.failed[0])
		fenced := false
		require.NoError(t, writer.onLoop(ctx, func() error {
			f := server.experimentalFences[sources[0].PathID]
			fenced = f != nil && f.acknowledged
			return nil
		}))
		require.True(t, fenced, "reassignment requires the client's semantic retirement acknowledgment")
		require.NoError(t, client.Context().Err())
		require.NoError(t, server.Context().Err())
	}
	if recovery.smallWindow {
		if !recovery.reprobe && recovery.duplicate == "" {
			require.Equal(t, []bool{false, false}, writer.failed, "flow-blocked recovery must not discard healthy sources")
		}
		// Fresh validation challenges can legitimately retire delegated paths.
		// Recovery must keep the connection alive and fence every retired source
		// before completing the write, rather than guarantee no path changes.
		require.NoError(t, writer.onLoop(ctx, func() error {
			for i, failed := range writer.failed {
				if !failed {
					continue
				}
				p := server.multipath.paths[sources[i].PathID]
				f := server.experimentalFences[sources[i].PathID]
				if !p.abandoned || !p.cloningAuthority.IsRetiredPath(p.cloningGrant) || f == nil || !f.acknowledged {
					return fmt.Errorf("source %d reassigned without permanent retirement and semantic client fence", i)
				}
			}
			if expectedRetiredPath != 0 {
				f := server.experimentalFences[expectedRetiredPath]
				if f == nil || !f.acknowledged {
					return fmt.Errorf("revalidation retirement was not fenced")
				}
			}
			return nil
		}))
		require.NoError(t, server.Context().Err())
		require.NoError(t, client.Context().Err())
	}
	if replacementDone != nil {
		require.NoError(t, <-replacementDone)
	}
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
	if autonomous {
		require.Greater(t, controllers[len(controllers)-1].Snapshot().Sent, uint64(0))
	}
	if !failWorker && !corrupt && !uncertain {
		require.Greater(t, writer.sequences[0], uint64(0))
	}
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
		if !recovery.expire && !recovery.smallWindow {
			require.Greater(t, writer.sequences[0], uint64(48))
		}
		if autonomous && !recovery.expire {
			stats := controllers[0].Snapshot()
			// A retired source recovers through the checked semantic fence;
			// otherwise the worker must have requested recovery of the loss.
			require.True(t, stats.Lost+stats.PTOs > 0 || recovery.smallWindow && writer.failed[0], "dropped data requires worker recovery or fenced source retirement")
		}
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
