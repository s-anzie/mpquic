package handshake

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func remoteUDPSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRemotePathSenderPauseResume(t *testing.T) {
	primary, _, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	cid := protocol.ParseConnectionID([]byte("cid"))
	fresh := func() *RemoteSealer {
		p, err := primary.prepareRemoteSealer(authority, grant, 4, cid)
		require.NoError(t, err)
		return transferRemote(t, p)
	}
	first := fresh()
	source, destination := remoteUDPSocket(t), remoteUDPSocket(t)
	sender, err := NewRemotePathSender(first, source, destination.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(sender.Close)
	_, _, err = first.SealPacket([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer, "adopted material must not bypass sender quiescence")
	_, err = NewRemotePathSender(first, source, destination.LocalAddr().(*net.UDPAddr))
	require.ErrorIs(t, err, ErrRemoteSealer)
	pn, err := sender.WritePayload([]byte{1})
	require.NoError(t, err)
	require.Zero(t, pn)
	require.NoError(t, destination.SetReadDeadline(time.Now().Add(time.Second)))
	_, _, err = destination.ReadFromUDP(make([]byte, 1500))
	require.NoError(t, err)
	boundary, err := sender.Pause()
	require.NoError(t, err)
	require.Equal(t, RemoteSendBoundary{PathID: 1, Epoch: 0, End: 4}, boundary)
	again, err := sender.Pause()
	require.NoError(t, err)
	require.Equal(t, boundary, again)
	require.Equal(t, remoteSendKeys{}, first.keys)
	_, err = sender.WritePayload([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer)
	primary.rollKeys()
	next := fresh()
	require.NoError(t, sender.Resume(next))
	pn, err = sender.WritePayload([]byte{1})
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(4), pn)
	_, err = sender.Pause()
	require.NoError(t, err)
	for name, mutate := range map[string]func(*RemoteSealer){
		"older epoch":        func(p *RemoteSealer) { p.epoch = 0 },
		"overlapping window": func(p *RemoteSealer) { p.next = 7 },
		"other path":         func(p *RemoteSealer) { p.path++ },
		"other CID":          func(p *RemoteSealer) { p.cid = protocol.ParseConnectionID([]byte("other")) },
		"other connection":   func(p *RemoteSealer) { p.keys.hp[0] ^= 1 },
		"already used":       func(p *RemoteSealer) { _, _, err := p.SealPacket([]byte{1}); require.NoError(t, err) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fresh()
			mutate(candidate)
			require.ErrorIs(t, sender.Resume(candidate), ErrRemoteSealer)
			candidate.Close()
		})
	}
	// A same-epoch refill is valid, with gaps left by rejected/burned windows.
	require.NoError(t, sender.Resume(fresh()))
	sender.Close()
	require.ErrorIs(t, sender.Resume(fresh()), ErrRemoteSealer)
	_, err = sender.WritePayload([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer)
}

func TestRemotePathSenderConcurrentPause(t *testing.T) {
	primary, _, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	p, err := primary.prepareRemoteSealer(authority, grant, 64, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	worker := transferRemote(t, p)
	source, destination := remoteUDPSocket(t), remoteUDPSocket(t)
	sender, err := NewRemotePathSender(worker, source, destination.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer sender.Close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() { <-start; _, _ = sender.WritePayload([]byte{1}) })
	}
	close(start)
	boundary, err := sender.Pause()
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(64), boundary.End)
	wg.Wait()
	require.True(t, worker.closed)
	require.Equal(t, remoteSendKeys{}, worker.keys)
	_, err = sender.WritePayload([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer)
}

func TestRemotePathSenderFailedWriteBurnsNumber(t *testing.T) {
	primary, _, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	p, err := primary.prepareRemoteSealer(authority, grant, 2, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	worker := transferRemote(t, p)
	source, destination := remoteUDPSocket(t), remoteUDPSocket(t)
	sender, err := NewRemotePathSender(worker, source, destination.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer sender.Close()
	require.NoError(t, source.Close())
	_, err = sender.WritePayload([]byte{1})
	require.Error(t, err)
	require.Equal(t, protocol.PacketNumber(1), worker.next)
	_, err = sender.WritePayload([]byte{1})
	require.Error(t, err)
	require.Equal(t, protocol.PacketNumber(2), worker.next)
}

type blockedRemoteWrite struct {
	started chan struct{}
	release chan struct{}
}

func (*blockedRemoteWrite) SetWriteDeadline(time.Time) error { return nil }
func (w *blockedRemoteWrite) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	close(w.started)
	<-w.release
	return len(b), nil
}

func TestRemotePathSenderPauseWaitsForWrite(t *testing.T) {
	primary, _, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	p, err := primary.prepareRemoteSealer(authority, grant, 2, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	source, destination := remoteUDPSocket(t), remoteUDPSocket(t)
	sender, err := NewRemotePathSender(transferRemote(t, p), source, destination.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	w := &blockedRemoteWrite{started: make(chan struct{}), release: make(chan struct{})}
	sender.conn = w
	writeDone, pauseDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := sender.WritePayload([]byte{1}); writeDone <- err }()
	<-w.started
	go func() { _, err := sender.Pause(); pauseDone <- err }()
	select {
	case err := <-pauseDone:
		t.Errorf("pause completed before pending write: %v", err)
		close(w.release)
		<-writeDone
		sender.Close()
		return
	case <-time.After(10 * time.Millisecond):
	}
	close(w.release)
	require.NoError(t, <-writeDone)
	require.NoError(t, <-pauseDone)
	_, err = sender.WritePayload([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer)
	sender.Close()
}
