package cloning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func workerTestTLS(t *testing.T) (*tls.Config, *tls.Config, [32]byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"primary.test"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, key)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	}
	server, worker := leaf(2, x509.ExtKeyUsageServerAuth), leaf(3, x509.ExtKeyUsageClientAuth)
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{WorkerControlALPN}},
		&tls.Config{Certificates: []tls.Certificate{worker}, RootCAs: roots, ServerName: "primary.test", MinVersion: tls.VersionTLS13, NextProtos: []string{WorkerControlALPN}}, sha256.Sum256(worker.Certificate[0])
}

// TCP exercises the reference control channel over actual loopback sockets;
// net.Pipe gives deterministic backpressure for queue saturation tests.
func workerTestTransport(t *testing.T, clientConfig *tls.Config, tcp bool) (net.Conn, *tls.Conn, <-chan error) {
	t.Helper()
	var server, client net.Conn
	if tcp {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		client, err = net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		server, err = listener.Accept()
		require.NoError(t, err)
	} else {
		server, client = net.Pipe()
	}
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	clientTLS := tls.Client(client, clientConfig)
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		result <- clientTLS.HandshakeContext(ctx)
	}()
	return server, clientTLS, result
}

func workerTestAuthority(t *testing.T) (*Authority, *Path) {
	t.Helper()
	a, err := NewAuthority(0)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	require.NoError(t, a.BindPrimary(1<<20, 0))
	p, err := a.GrantPath(1, "source-label-not-an-identity")
	require.NoError(t, err)
	return a, p
}

func workerTestRead(t *testing.T, c *tls.Conn, seq uint64, kind byte) []byte {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
	got, body, err := readControlMessage(c, seq, controlHeaderSize+80+MaxDelegationBytes)
	require.NoError(t, err)
	require.Equal(t, kind, got)
	return body
}

func waitWorker(t *testing.T, w *WorkerControl) {
	t.Helper()
	select {
	case <-w.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("worker goroutines did not exit")
	}
}

func TestWorkerControlTLSAssignmentFailureAndRetirement(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, client, handshake := workerTestTransport(t, cc, true)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(workerTestRead(t, client, 1, controlWelcome)))
	payload := []byte("a distinct source portion")
	attempt, err := a.DelegatePrimary(p, 3, 0, 1000, payload, 1<<20)
	require.NoError(t, err)
	require.NoError(t, w.Queue(attempt))
	body := workerTestRead(t, client, 2, controlAssignment)
	values := []uint64{1, 1, 1, 3, 0, uint64(len(payload))}
	for i, want := range values {
		require.Equal(t, want, binary.BigEndian.Uint64(body[i*8:]))
	}
	digest := sha256.Sum256(payload)
	require.Equal(t, digest[:], body[48:80])
	require.Equal(t, payload, body[80:])
	// Reading an assignment never constitutes QUIC delivery evidence.
	a.mu.Lock()
	require.Zero(t, attempt.rangeState.acked)
	a.mu.Unlock()
	failure := binary.BigEndian.AppendUint64(nil, 1)
	failure = binary.BigEndian.AppendUint64(failure, 1)
	require.NoError(t, writeControlMessage(client, controlFailed, 1, failure))
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return attempt.rangeState.retryable
	}, time.Second, time.Millisecond)
	q, err := a.GrantPath(2, "replacement")
	require.NoError(t, err)
	retry, err := a.Retry(attempt, q)
	require.NoError(t, err)
	require.ErrorIs(t, w.Queue(retry), ErrAttempt)
	// A late repeated failure cannot invalidate the replacement generation.
	require.NoError(t, writeControlMessage(client, controlFailed, 2, failure))
	require.NoError(t, writeControlMessage(client, controlStopped, 3, nil))
	waitWorker(t, w)
	require.ErrorIs(t, w.Err(), ErrWorkerStopped)
	_, restored, err := a.ReadAttempt(retry)
	require.NoError(t, err)
	require.Equal(t, payload, restored)
	_, err = a.NextPacketNumber(p)
	require.ErrorIs(t, err, ErrPath)
	_, total, _, err := a.PrimaryState(3)
	require.NoError(t, err)
	require.Equal(t, uint64(len(payload)), total)
}

func TestWorkerControlRejectsIdentityAndProtocol(t *testing.T) {
	for _, mode := range []string{"wrong-pin", "unverified", "no-certificate", "wrong-alpn", "legacy-alpn", "tls12", "config-callback"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc, pin := workerTestTLS(t)
			switch mode {
			case "wrong-pin":
				pin[0] ^= 1
			case "unverified":
				sc.ClientAuth = tls.RequireAnyClientCert
			case "no-certificate":
				sc.ClientAuth = tls.NoClientCert
				cc.Certificates = nil
			case "wrong-alpn":
				sc.NextProtos, cc.NextProtos = []string{"other"}, []string{"other"}
			case "legacy-alpn":
				sc.NextProtos, cc.NextProtos = []string{"mpquic-worker-control/1"}, []string{"mpquic-worker-control/1"}
			case "tls12":
				sc.MinVersion, sc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
				cc.MinVersion, cc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			case "config-callback":
				sc.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
			}
			server, _, handshake := workerTestTransport(t, cc, false)
			a, p := workerTestAuthority(t)
			_, err := a.BindWorker(t.Context(), server, sc, p, pin)
			require.ErrorIs(t, err, ErrWorkerIdentity)
			<-handshake
			require.Nil(t, p.worker, "failed authentication must not bind the path")
			_, err = a.NextPacketNumber(p)
			require.NoError(t, err)
		})
	}
}

func TestWorkerControlRejectsReplayAndDeliveryClaims(t *testing.T) {
	for _, mode := range []string{"replay", "gap", "delivered", "cancel-command", "oversized", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc, pin := workerTestTLS(t)
			server, client, handshake := workerTestTransport(t, cc, false)
			a, p := workerTestAuthority(t)
			w, err := a.BindWorker(t.Context(), server, sc, p, pin)
			require.NoError(t, err)
			require.NoError(t, <-handshake)
			workerTestRead(t, client, 1, controlWelcome)
			attempt, err := a.DelegatePrimary(p, 3, 0, 1000, []byte("pending"), 1<<20)
			require.NoError(t, err)
			switch mode {
			case "replay":
				require.NoError(t, writeControlMessage(client, controlHeartbeat, 1, nil))
				require.NoError(t, writeControlMessage(client, controlHeartbeat, 1, nil))
			case "gap":
				require.NoError(t, writeControlMessage(client, controlHeartbeat, 2, nil))
			case "delivered":
				require.NoError(t, writeControlMessage(client, 6, 1, nil))
			case "cancel-command":
				require.NoError(t, writeControlMessage(client, controlCancelStream, 1, binary.BigEndian.AppendUint64(nil, 3)))
			case "oversized":
				_, err := client.Write(binary.BigEndian.AppendUint32(nil, ^uint32(0)))
				require.NoError(t, err)
			case "malformed":
				require.NoError(t, writeControlMessage(client, controlFailed, 1, []byte{1}))
			}
			waitWorker(t, w)
			require.ErrorIs(t, w.Err(), ErrWorkerProtocol)
			require.Zero(t, attempt.rangeState.acked)
			require.False(t, attempt.rangeState.done)
			require.True(t, p.retired)
		})
	}
}

func TestWorkerControlBoundedQueueAndClose(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, _, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	// The peer does not read the welcome, blocking the writer before dequeue.
	for i := range MaxWorkerQueue + 1 {
		attempt, err := a.DelegatePrimary(p, 3, uint64(i), 1000, []byte{byte(i)}, 1<<20)
		require.NoError(t, err)
		err = w.Queue(attempt)
		if i < MaxWorkerQueue {
			require.NoError(t, err)
			require.ErrorIs(t, w.Queue(attempt), ErrAttempt)
		} else {
			require.ErrorIs(t, err, ErrWorkerBusy)
			_, _, err = a.ReadAttempt(attempt)
			require.NoError(t, err, "queue failure preserves the reservation")
		}
	}
	a.Close()
	waitWorker(t, w)
	require.Empty(t, w.queue)
	require.Empty(t, w.pending)
	require.Zero(t, a.delegatedBytes)
}

func TestWorkerControlRetireDisconnectAndCancellation(t *testing.T) {
	for _, mode := range []string{"retire", "disconnect", "context"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc, pin := workerTestTLS(t)
			server, client, handshake := workerTestTransport(t, cc, false)
			a, p := workerTestAuthority(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			w, err := a.BindWorker(ctx, server, sc, p, pin)
			require.NoError(t, err)
			require.NoError(t, <-handshake)
			switch mode {
			case "retire":
				require.NoError(t, a.RetirePath(p))
			case "disconnect":
				require.NoError(t, client.NetConn().Close())
			case "context":
				cancel()
			}
			waitWorker(t, w)
			require.True(t, p.retired)
			server2, _, handshake2 := workerTestTransport(t, cc, false)
			_, err = a.BindWorker(t.Context(), server2, sc, p, pin)
			require.ErrorIs(t, err, ErrPath, "reconnect never resurrects a path")
			<-handshake2
		})
	}
}

func TestWorkerControlConcurrentQueueAndClose(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	server, _, handshake := workerTestTransport(t, cc, false)
	a, p := workerTestAuthority(t)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	attempt, err := a.DelegatePrimary(p, 3, 0, 1000, []byte("data"), 1<<20)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _ = w.Queue(attempt); w.Close() })
	}
	wg.Wait()
	waitWorker(t, w)
}

func TestWorkerControlCodecBoundsAndTruncation(t *testing.T) {
	for _, size := range []uint32{0, 8, maxWorkerMessage + 1, ^uint32(0)} {
		_, _, err := readControlMessage(bytes.NewReader(binary.BigEndian.AppendUint32(nil, size)), 1, maxWorkerMessage)
		require.ErrorIs(t, err, ErrWorkerProtocol)
	}
	var buf bytes.Buffer
	require.NoError(t, writeControlMessage(&buf, controlHeartbeat, 1, nil))
	encoded := bytes.Clone(buf.Bytes())
	for n := range len(encoded) {
		_, _, err := readControlMessage(bytes.NewReader(encoded[:n]), 1, maxWorkerMessage)
		require.Error(t, err)
	}
	_, _, err := readControlMessage(bytes.NewReader(encoded), 2, maxWorkerMessage)
	require.ErrorIs(t, err, ErrWorkerProtocol)
	require.ErrorIs(t, writeControlMessage(io.Discard, controlHeartbeat, 0, nil), ErrWorkerProtocol)
	require.ErrorIs(t, writeControlMessage(io.Discard, controlAssignment, 1, make([]byte, MaxDelegationBytes+81)), ErrWorkerProtocol)
}

func TestWorkerControlBindingIsExclusive(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	a, p := workerTestAuthority(t)
	server, client, handshake := workerTestTransport(t, cc, false)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	workerTestRead(t, client, 1, controlWelcome)
	copy := *w
	copy.Close()
	require.Nil(t, w.Err(), "a copied handle must not stop the registered channel")
	server2, _, handshake2 := workerTestTransport(t, cc, false)
	_, err = a.BindWorker(t.Context(), server2, sc, p, pin)
	require.ErrorIs(t, err, ErrPath)
	<-handshake2
	// Rejecting a second authenticated connection does not stop the first one.
	require.NoError(t, writeControlMessage(client, controlHeartbeat, 1, nil))
	require.Nil(t, w.Err())
	w.Close()
	waitWorker(t, w)
}

type workerTestDeadlineConn struct {
	net.Conn
	read, write bool
}

func (c workerTestDeadlineConn) SetReadDeadline(deadline time.Time) error {
	if c.read {
		deadline = time.Now().Add(100 * time.Millisecond)
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c workerTestDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if c.write {
		deadline = time.Now().Add(100 * time.Millisecond)
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestWorkerControlTimeoutRetiresPath(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(map[bool]string{false: "blocked-writer", true: "idle-reader"}[read], func(t *testing.T) {
			sc, cc, pin := workerTestTLS(t)
			server, client, handshake := workerTestTransport(t, cc, false)
			a, p := workerTestAuthority(t)
			w, err := a.BindWorker(t.Context(), workerTestDeadlineConn{Conn: server, read: read, write: !read}, sc, p, pin)
			require.NoError(t, err)
			require.NoError(t, <-handshake)
			if read {
				workerTestRead(t, client, 1, controlWelcome)
			}
			waitWorker(t, w)
			var timeout net.Error
			require.True(t, errors.As(w.Err(), &timeout))
			require.True(t, timeout.Timeout())
			require.True(t, p.retired)
		})
	}
}

func TestWorkerControlSkipsCanceledQueueAndUnsolicitedFailure(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	a, p := workerTestAuthority(t)
	server, client, handshake := workerTestTransport(t, cc, false)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err)
	require.NoError(t, <-handshake)
	first, err := a.DelegatePrimary(p, 3, 0, 1000, []byte("canceled"), 1<<20)
	require.NoError(t, err)
	require.NoError(t, w.Queue(first))
	a.CancelStream(3)
	second, err := a.DelegatePrimary(p, 7, 0, 1000, []byte("live"), 1<<20)
	require.NoError(t, err)
	require.NoError(t, w.Queue(second))
	a.mu.Lock()
	require.Len(t, w.pending, 1, "terminal metadata is pruned on admission")
	a.mu.Unlock()
	workerTestRead(t, client, 1, controlWelcome)
	require.Equal(t, uint64(3), binary.BigEndian.Uint64(workerTestRead(t, client, 2, controlCancelStream)))
	body := workerTestRead(t, client, 3, controlAssignment)
	require.Equal(t, uint64(2), binary.BigEndian.Uint64(body))
	require.Equal(t, []byte("live"), body[80:])
	unoffered, err := a.DelegatePrimary(p, 11, 0, 1000, []byte("private"), 1<<20)
	require.NoError(t, err)
	for i, values := range [][2]uint64{{1, 1}, {2, 2}, {3, 1}} {
		failure := binary.BigEndian.AppendUint64(nil, values[0])
		failure = binary.BigEndian.AppendUint64(failure, values[1])
		require.NoError(t, writeControlMessage(client, controlFailed, uint64(i+1), failure))
	}
	require.NoError(t, writeControlMessage(client, controlStopped, 4, nil))
	waitWorker(t, w)
	require.False(t, second.rangeState.retryable, "wrong generation cannot report failure")
	require.False(t, unoffered.rangeState.retryable, "unoffered range cannot report failure")
	require.Zero(t, second.rangeState.acked)
}

func TestWorkerControlRequiresTrustedCertificate(t *testing.T) {
	sc, cc, _ := workerTestTLS(t)
	_, foreign, foreignPin := workerTestTLS(t)
	// The expected fingerprint alone is insufficient without a verified CA chain.
	cc.Certificates = foreign.Certificates
	server, _, handshake := workerTestTransport(t, cc, true)
	a, p := workerTestAuthority(t)
	_, err := a.BindWorker(t.Context(), server, sc, p, foreignPin)
	require.Error(t, err)
	var unknownCA x509.UnknownAuthorityError
	require.True(t, errors.As(err, &unknownCA), "must reject the untrusted chain, not merely time out: %v", err)
	<-handshake
	require.Nil(t, p.worker)
}

func TestWorkerControlHandshakeCancellation(t *testing.T) {
	sc, _, pin := workerTestTLS(t)
	server, client := net.Pipe()
	defer client.Close()
	a, p := workerTestAuthority(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := a.BindWorker(ctx, server, sc, p, pin)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, p.worker)
}

func FuzzWorkerControlMessage(f *testing.F) {
	var valid bytes.Buffer
	_ = writeControlMessage(&valid, controlHeartbeat, 1, nil)
	f.Add(valid.Bytes())
	f.Add([]byte{255, 255, 255, 255})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, body, err := readControlMessage(bytes.NewReader(data), 1, maxWorkerMessage)
		if err == nil && len(body) > maxWorkerMessage-controlHeaderSize {
			t.Fatal("decoder exceeded its allocation bound")
		}
	})
}

func TestWorkerControlActiveChannelLimit(t *testing.T) {
	sc, cc, pin := workerTestTLS(t)
	a, p := workerTestAuthority(t)
	var workers []*WorkerControl
	for i := range MaxWorkerControls {
		if i > 0 {
			var err error
			p, err = a.GrantPath(uint64(i+1), "source")
			require.NoError(t, err)
		}
		server, _, handshake := workerTestTransport(t, cc, false)
		w, err := a.BindWorker(t.Context(), server, sc, p, pin)
		require.NoError(t, err)
		require.NoError(t, <-handshake)
		workers = append(workers, w)
	}
	p, err := a.GrantPath(MaxWorkerControls+1, "waiting")
	require.NoError(t, err)
	server, _, handshake := workerTestTransport(t, cc, false)
	_, err = a.BindWorker(t.Context(), server, sc, p, pin)
	require.ErrorIs(t, err, ErrWorkerBusy)
	<-handshake
	workers[0].Close()
	waitWorker(t, workers[0])
	server, _, handshake = workerTestTransport(t, cc, false)
	w, err := a.BindWorker(t.Context(), server, sc, p, pin)
	require.NoError(t, err, "closing a channel releases capacity, not its path ID")
	require.NoError(t, <-handshake)
	workers = append(workers, w)
	a.Close()
	for _, worker := range workers {
		waitWorker(t, worker)
	}
	require.Zero(t, a.workerCount)
}
