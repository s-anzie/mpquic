package quic

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestExperimentalSourceRelayBinding(t *testing.T) {
	c := &Conn{perspective: protocol.PerspectiveServer, multipath: newMultipathState(2), experimentalSources: &experimentalSourceRegistry{entries: make(map[uint64]experimentalSourceEntry)}}
	r := &experimentalSourceRelay{conn: c, id: 1, generation: 1}
	e := experimentalSourceEntry{frame: wire.ExperimentalSourceOfferFrame{ID: 1, Generation: 1, TTL: 60, Address: netip.MustParseAddrPort("127.0.0.2:4433")}, expires: time.Now().Add(time.Minute), pathID: 1, accepted: true, relay: r}
	c.experimentalSources.entries[1] = e
	p, err := c.multipath.path(1)
	require.NoError(t, err)
	p.experimentalRelay = r
	require.True(t, c.acceptExperimentalRelayPacket(1, receivedPacket{experimentalRelay: r}))
	require.False(t, c.acceptExperimentalRelayPacket(0, receivedPacket{experimentalRelay: r}))
	require.False(t, c.acceptExperimentalRelayPacket(2, receivedPacket{experimentalRelay: r}))
	require.False(t, c.acceptExperimentalRelayPacket(1, receivedPacket{}), "primary socket cannot validate a worker route")
	require.False(t, c.acceptExperimentalRelayPacket(1, receivedPacket{experimentalRelay: &experimentalSourceRelay{conn: c, id: 1, generation: 1}}))
	e.expires = time.Now().Add(-time.Second)
	c.experimentalSources.entries[1] = e
	require.False(t, c.acceptExperimentalRelayPacket(1, receivedPacket{experimentalRelay: r}))
	e.expires = time.Now().Add(time.Minute)
	c.experimentalSources.entries[1] = e
	c.perspective = protocol.PerspectiveClient
	require.True(t, c.acceptExperimentalRelayPacket(1, receivedPacket{remoteAddr: net.UDPAddrFromAddrPort(e.frame.Address)}))
	require.False(t, c.acceptExperimentalRelayPacket(1, receivedPacket{remoteAddr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.3:4433"))}))
}

func TestExperimentalSourceRelayTLSSeparation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	job, _, pin := experimentalWorkerTLS(t, ctx)
	require.Error(t, checkSourceRelayTLS(job, pin))
	relay, _, pin := experimentalWorkerTLS(t, ctx, ExperimentalSourceRelayALPN)
	require.NoError(t, checkSourceRelayTLS(relay, pin))
	pin[0] ^= 1
	require.Error(t, checkSourceRelayTLS(relay, pin))
}

func TestExperimentalSourceUnreachableDoesNotValidate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cfg := &Config{EnableMultipath: true, MaxPathID: 2, EnableExperimentalSourceOffers: true, DisableAutomaticPathDiscovery: true}
	st := &Transport{Conn: experimentalUDP(t), ConnectionIDLength: 8}
	defer st.Close()
	l, err := st.Listen(testdata.GetTLSConfig(), cfg)
	require.NoError(t, err)
	defer l.Close()
	ct := &Transport{Conn: experimentalUDP(t), ConnectionIDLength: 8}
	defer ct.Close()
	client, err := ct.Dial(ctx, l.Addr(), &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost"}, cfg)
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := l.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")
	blackhole := experimentalUDP(t)
	addr := blackhole.LocalAddr().(*net.UDPAddr).AddrPort()
	require.NoError(t, server.AnnounceExperimentalSource(ctx, 1, 1, addr, time.Minute))
	require.Eventually(t, func() bool {
		o, err := client.ExperimentalSourceOffers(ctx)
		return err == nil && len(o) == 1
	}, time.Second, time.Millisecond)
	_, err = client.ProbeExperimentalSource(ctx, 1, 1, experimentalUDP(t))
	require.ErrorIs(t, err, ErrExperimentalSourceOffer, "unaccepted offers must not probe")
	require.NoError(t, blackhole.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
	_, _, err = blackhole.ReadFrom(make([]byte, 1500))
	require.Error(t, err, "no packet may be sent before consent")
	require.NoError(t, client.AcceptExperimentalSource(ctx, 1, 1, func(o ExperimentalSourceOffer) bool { return o.Address == addr }))
	probeCtx, stop := context.WithTimeout(ctx, 250*time.Millisecond)
	defer stop()
	path, err := client.ProbeExperimentalSource(probeCtx, 1, 1, experimentalUDP(t))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, path)
	require.NoError(t, (&ExperimentalCloneWriter{conn: server}).onLoop(ctx, func() error {
		for id, p := range server.multipath.paths {
			if id != 0 {
				require.False(t, p.serverValidated)
				require.Zero(t, p.serverProbeBytesSent)
			}
		}
		return nil
	}))
}
