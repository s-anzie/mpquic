package quic

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceOfferRegistryOrderingExpiryAndBounds(t *testing.T) {
	r := &experimentalSourceRegistry{}
	now := time.Now()
	f := wire.ExperimentalSourceOfferFrame{ID: 1, Generation: 2, TTL: 60, Address: netip.MustParseAddrPort("192.0.2.1:443")}
	require.NoError(t, r.apply(f, now))
	require.NoError(t, r.apply(f, now.Add(time.Minute)))
	require.Equal(t, now.Add(time.Minute), r.entries[1].expires)
	stale := f
	stale.Generation = 1
	stale.TTL = 3600
	require.NoError(t, r.apply(stale, now))
	conflict := f
	conflict.TTL = 30
	require.Error(t, r.apply(conflict, now))
	require.NoError(t, r.apply(wire.ExperimentalSourceOfferFrame{ID: 1, Generation: 3}, now))
	f.Generation = 4
	require.Error(t, r.apply(f, now), "withdrawal is permanent")
	for id := uint64(2); id <= 32; id++ {
		f.ID = id
		require.NoError(t, r.apply(f, now))
	}
	f.ID = 33
	require.Error(t, r.apply(f, now))
}

func TestSourceOfferLiveNegotiation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cfg := &Config{EnableMultipath: true, EnableExperimentalSourceOffers: enabled, MaxPathID: 2, DisableAutomaticPathDiscovery: true}
			st := &Transport{Conn: experimentalUDP(t), ConnectionIDLength: 8}
			defer st.Close()
			listener, err := st.Listen(testdata.GetTLSConfig(), cfg)
			require.NoError(t, err)
			defer listener.Close()
			ct := &Transport{Conn: experimentalUDP(t), ConnectionIDLength: 8}
			defer ct.Close()
			cc := cfg.Clone()
			cc.EnableExperimentalSourceOffers = true
			client, err := ct.Dial(ctx, listener.Addr(), &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost"}, cc)
			require.NoError(t, err)
			defer client.CloseWithError(0, "")
			server, err := listener.Accept(ctx)
			require.NoError(t, err)
			defer server.CloseWithError(0, "")
			addr := netip.MustParseAddrPort("192.0.2.123:4433")
			err = server.AnnounceExperimentalSource(ctx, 1, 1, addr, time.Minute)
			if !enabled {
				require.ErrorIs(t, err, ErrExperimentalSourceOffer)
				_, err = client.ExperimentalSourceOffers(ctx)
				require.ErrorIs(t, err, ErrExperimentalSourceOffer)
				return
			}
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				offers, err := client.ExperimentalSourceOffers(ctx)
				return err == nil && len(offers) == 1 && offers[0].Address == addr
			}, time.Second, 5*time.Millisecond)
			require.ErrorIs(t, client.AnnounceExperimentalSource(ctx, 2, 1, addr, time.Minute), ErrExperimentalSourceOffer)
			require.ErrorIs(t, server.AnnounceExperimentalSource(ctx, 1, 1, addr, time.Minute), ErrExperimentalSourceOffer)
			require.NoError(t, server.AnnounceExperimentalSource(ctx, 1, 2, netip.AddrPort{}, 0))
			require.Eventually(t, func() bool {
				offers, err := client.ExperimentalSourceOffers(ctx)
				return err == nil && len(offers) == 0
			}, time.Second, 5*time.Millisecond)
			onCloningConnectionLoop(t, client, func() {
				for _, p := range client.multipath.paths {
					assert.Nil(t, p.remoteAddr, "offers must not probe preprovisioned path IDs")
				}
			})
			// Both APIs leave application stream allocation untouched.
			s, err := server.OpenUniStream()
			require.NoError(t, err)
			require.Equal(t, protocol.StreamID(3), s.StreamID())
		})
	}
}
