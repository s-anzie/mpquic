package handshake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func remoteTLS(t *testing.T) (*tls.Conn, *tls.Conn, [32]byte) {
	t.Helper()
	sc := testdata.GetTLSConfig()
	sc.ClientAuth, sc.ClientCAs, sc.NextProtos = tls.RequireAndVerifyClientCert, testdata.GetRootCA(), []string{RemoteSealerALPN}
	cc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: sc.Certificates, RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: sc.NextProtos}
	l, r := net.Pipe()
	t.Cleanup(func() { _ = l.Close(); _ = r.Close() })
	s, c := tls.Server(l, sc), tls.Client(r, cc)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.HandshakeContext(ctx) }()
	require.NoError(t, s.HandshakeContext(ctx))
	require.NoError(t, <-done)
	return s, c, sha256.Sum256(sc.Certificates[0].Certificate[0])
}

func transferRemote(t *testing.T, p *RemoteSealer) *RemoteSealer {
	t.Helper()
	s, c, pin := remoteTLS(t)
	done := make(chan error, 1)
	go func() { done <- p.WriteTLS(s, pin) }()
	worker, err := ReadRemoteSealer(c, pin, p.path, p.epoch, p.cid)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.ErrorIs(t, p.WriteTLS(s, pin), ErrRemoteSealer)
	t.Cleanup(worker.Close)
	return worker
}

func remoteTestEndpoints(t *testing.T, suite cipherSuite, version protocol.Version) (*updatableAEAD, *updatableAEAD, *cloning.Authority) {
	t.Helper()
	secret := bytes.Repeat([]byte{0x42}, suite.Hash.Size())
	s := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, version)
	c := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, version)
	s.SetWriteKey(suite, secret)
	s.SetReadKey(suite, secret)
	c.SetReadKey(suite, secret)
	c.SetWriteKey(suite, secret)
	s.SetMultipath(true)
	c.SetMultipath(true)
	s.SetHandshakeConfirmed()
	c.SetHandshakeConfirmed()
	a, err := cloning.NewAuthority(0)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	return s, c, a
}

func TestRemoteSealerTLSAndTwoUDPSourcePaths(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, suite := range cipherSuites {
			t.Run(fmt.Sprintf("%s/%x", version, suite.ID), func(t *testing.T) {
				s, c, a := remoteTestEndpoints(t, suite, version)
				destination, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				defer destination.Close()
				var previousSource string
				for _, path := range []uint64{1, 2} {
					// A real multipath receiver maps distinct destination CIDs to
					// path-specific packet-number spaces within one connection.
					cid := protocol.ParseConnectionID([]byte{'c', 'l', 'i', 'e', 'n', 't', 0, byte(path)})
					grant, err := a.GrantPath(path, "worker")
					require.NoError(t, err)
					prepared, err := s.prepareRemoteSealer(a, grant, 2, cid)
					require.NoError(t, err)
					worker := transferRemote(t, prepared)
					source, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					require.NoError(t, err)
					defer source.Close()
					require.NotEqual(t, previousSource, source.LocalAddr().String())
					previousSource = source.LocalAddr().String()
					for i := range 2 {
						fragment := &wire.StreamFrame{StreamID: 3, Offset: protocol.ByteCount((path-1)*8 + uint64(i)*4), Data: []byte{byte(path), byte(i), 3, 4}, DataLenPresent: true}
						plain, err := fragment.Append(nil, version)
						require.NoError(t, err)
						packet, pn, err := worker.SealPacket(plain)
						require.NoError(t, err)
						require.Equal(t, protocol.PacketNumber(i), pn)
						_, err = source.WriteToUDP(packet, destination.LocalAddr().(*net.UDPAddr))
						require.NoError(t, err)
						require.NoError(t, destination.SetReadDeadline(time.Now().Add(time.Second)))
						buf := make([]byte, 1500)
						n, sender, err := destination.ReadFromUDP(buf)
						require.NoError(t, err)
						require.Equal(t, source.LocalAddr().String(), sender.String())
						packet = buf[:n]
						offset := 1 + cid.Len()
						c.DecryptHeader(packet[offset+4:offset+20], &packet[0], packet[offset:offset+4])
						length, wirePN, _, phase, err := wire.ParseShortHeader(packet, cid.Len())
						require.NoError(t, err)
						require.Equal(t, pn, wirePN)
						require.NoError(t, c.SetPathID(path))
						opened, err := c.Open(nil, packet[length:], monotime.Now(), pn, phase, packet[:length])
						require.NoError(t, err)
						require.Equal(t, plain, opened)
					}
					_, _, err = worker.SealPacket([]byte{1})
					require.ErrorIs(t, err, ErrRemoteSealer)
					_, err = a.NextPacketNumber(grant)
					require.ErrorIs(t, err, cloning.ErrPath)
				}
				require.Equal(t, uint64(4), s.numSentWithCurrentKey)
			})
		}
	}
}

func TestRemoteSealerAccountingAndEpochs(t *testing.T) {
	s, c, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	g, err := a.ImportPath(1, 40, "worker")
	require.NoError(t, err)
	cid := protocol.ParseConnectionID([]byte("cid"))
	first, err := s.prepareRemoteSealer(a, g, 2, cid)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(40), first.next)
	worker := transferRemote(t, first)
	originalHP := worker.keys.hp
	s.rollKeys()
	c.rollKeys()
	second, err := s.prepareRemoteSealer(a, g, 1, cid)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(42), second.next)
	updated := transferRemote(t, second)
	require.Equal(t, originalHP, updated.keys.hp)
	require.NotEqual(t, worker.keys.key, updated.keys.key)
	packet, pn, err := updated.SealPacket([]byte{1})
	require.NoError(t, err)
	offset := 1 + cid.Len()
	c.DecryptHeader(packet[offset+4:offset+20], &packet[0], packet[offset:offset+4])
	length, _, _, phase, err := wire.ParseShortHeader(packet, cid.Len())
	require.NoError(t, err)
	require.Equal(t, protocol.KeyPhaseOne, phase)
	require.NoError(t, c.SetPathID(1))
	opened, err := c.Open(nil, packet[length:], monotime.Now(), pn, phase, packet[:length])
	require.NoError(t, err)
	require.Equal(t, []byte{1}, opened)
	s.numSentWithCurrentKey = 1 << 23
	_, err = s.prepareRemoteSealer(a, g, 1, cid)
	require.ErrorIs(t, err, ErrRemoteSealer)
	require.Equal(t, "[redacted remote sealer]", fmt.Sprintf("%+v", updated))
	updated.Close()
	_, _, err = updated.SealPacket([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer)
}

func TestRemoteSealerConcurrentWindowConsumption(t *testing.T) {
	s, _, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	g, err := a.GrantPath(1, "worker")
	require.NoError(t, err)
	p, err := s.prepareRemoteSealer(a, g, 64, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	w := transferRemote(t, p)
	var wg sync.WaitGroup
	results := make(chan protocol.PacketNumber, 64)
	for range 64 {
		wg.Go(func() {
			_, pn, err := w.SealPacket([]byte{1})
			if err != nil {
				t.Error(err)
				return
			}
			results <- pn
		})
	}
	wg.Wait()
	close(results)
	seen := make(map[protocol.PacketNumber]bool)
	for pn := range results {
		require.False(t, seen[pn])
		seen[pn] = true
	}
	require.Len(t, seen, 64)
}

func TestRemoteSealerRejectsWrongTLSIdentityAndContext(t *testing.T) {
	s, _, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	g, err := a.GrantPath(1, "worker")
	require.NoError(t, err)
	p, err := s.prepareRemoteSealer(a, g, 1, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	server, client, pin := remoteTLS(t)
	wrong := pin
	wrong[0] ^= 1
	require.ErrorIs(t, p.WriteTLS(server, wrong), ErrRemoteSealer)
	_, err = ReadRemoteSealer(client, wrong, 1, 0, p.cid)
	require.ErrorIs(t, err, ErrRemoteSealer)
	done := make(chan error, 1)
	go func() { done <- p.WriteTLS(server, pin) }()
	_, err = ReadRemoteSealer(client, pin, 2, 0, p.cid)
	require.ErrorIs(t, err, ErrRemoteSealer)
	require.NoError(t, <-done)
	require.True(t, p.closed)
	require.Equal(t, remoteSendKeys{}, p.keys)
	_, _, err = p.SealPacket([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer)
	for _, data := range [][]byte{nil, make([]byte, 134), make([]byte, 135), make([]byte, 136)} {
		_, err := decodeRemoteSealer(data, 1, 0)
		require.ErrorIs(t, err, ErrRemoteSealer)
	}
}

func TestRemoteSealerFailedBootstrapBurnsWindow(t *testing.T) {
	s, _, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	g, err := a.GrantPath(1, "worker")
	require.NoError(t, err)
	cid := protocol.ParseConnectionID([]byte("cid"))
	p, err := s.prepareRemoteSealer(a, g, 2, cid)
	require.NoError(t, err)
	server, client, pin := remoteTLS(t)
	require.NoError(t, client.NetConn().Close())
	require.Error(t, p.WriteTLS(server, pin))
	require.True(t, p.closed)
	require.Equal(t, remoteSendKeys{}, p.keys)
	require.ErrorIs(t, p.WriteTLS(server, pin), ErrRemoteSealer)
	next, err := s.prepareRemoteSealer(a, g, 1, cid)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(2), next.next)
	require.Equal(t, uint64(3), s.numSentWithCurrentKey)
}

func TestRemoteSealerBindingAndPayloadGuards(t *testing.T) {
	for _, mode := range []string{"cid", "epoch"} {
		t.Run(mode, func(t *testing.T) {
			s, _, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
			g, err := a.GrantPath(1, "worker")
			require.NoError(t, err)
			cid := protocol.ParseConnectionID([]byte("cid"))
			p, err := s.prepareRemoteSealer(a, g, 1, cid)
			require.NoError(t, err)
			server, client, pin := remoteTLS(t)
			epoch := protocol.KeyPhase(0)
			if mode == "cid" {
				cid = protocol.ParseConnectionID([]byte("other"))
			} else {
				epoch = 1
			}
			done := make(chan error, 1)
			go func() { done <- p.WriteTLS(server, pin) }()
			_, err = ReadRemoteSealer(client, pin, 1, epoch, cid)
			require.ErrorIs(t, err, ErrRemoteSealer)
			require.NoError(t, <-done)
		})
	}
	s, _, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	g, err := a.GrantPath(1, "worker")
	require.NoError(t, err)
	cid := protocol.ParseConnectionID([]byte("cid"))
	for _, count := range []uint64{0, 65, ^uint64(0)} {
		_, err := s.prepareRemoteSealer(a, g, count, cid)
		require.ErrorIs(t, err, ErrRemoteSealer)
	}
	require.Zero(t, s.numSentWithCurrentKey)
	p, err := s.prepareRemoteSealer(a, g, 1, cid)
	require.NoError(t, err)
	_, _, err = p.SealPacket([]byte{1})
	require.ErrorIs(t, err, ErrRemoteSealer, "the exporting primary cannot use the remote window")
	w := transferRemote(t, p)
	_, _, err = w.SealPacket(nil)
	require.ErrorIs(t, err, ErrRemoteSealer)
	_, _, err = w.SealPacket(make([]byte, 1500))
	require.ErrorIs(t, err, ErrRemoteSealer)
	_, pn, err := w.SealPacket([]byte{1})
	require.NoError(t, err)
	require.Zero(t, pn)
}

func FuzzRemoteSealerDecode(f *testing.F) {
	b := make([]byte, remoteSealerSize)
	binary.BigEndian.PutUint16(b[:2], tls.TLS_AES_128_GCM_SHA256)
	binary.BigEndian.PutUint32(b[2:6], uint32(protocol.Version1))
	binary.BigEndian.PutUint64(b[14:22], 1)
	binary.BigEndian.PutUint64(b[30:38], 1)
	b[38] = 1
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := decodeRemoteSealer(b, 1, 0)
		if err != nil {
			return
		}
		defer p.Close()
		if p.end-p.next > cloning.MaxRemotePacketWindow || p.path != 1 || p.epoch != 0 {
			t.Fatal("invalid accepted window")
		}
		_, _, err = p.SealPacket([]byte{1})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestRemoteSealerRetirementBeforeExport(t *testing.T) {
	s, _, a := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	g, err := a.GrantPath(1, "worker")
	require.NoError(t, err)
	p, err := s.prepareRemoteSealer(a, g, 1, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	require.NoError(t, a.RetirePath(g))
	server, _, pin := remoteTLS(t)
	require.ErrorIs(t, p.WriteTLS(server, pin), cloning.ErrPath)
	require.True(t, p.closed)
	require.Equal(t, remoteSendKeys{}, p.keys)
}
