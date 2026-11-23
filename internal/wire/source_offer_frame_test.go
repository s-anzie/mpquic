package wire

import (
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestExperimentalSourceOfferWire(t *testing.T) {
	for _, address := range []string{"192.0.2.1:443", "[2001:db8::1]:443", ""} {
		f := &ExperimentalSourceOfferFrame{ID: 1, Generation: 2}
		if address != "" {
			f.Address = netip.MustParseAddrPort(address)
			f.TTL = 60
		}
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.EqualValues(t, len(b), f.Length(protocol.Version1))
		parser := NewFrameParser(false, false, false)
		_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
		require.Error(t, err)
		parser.SetExperimentalSourceOffers(true)
		for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
			_, _, err = parser.ParseType(b, level)
			require.Error(t, err)
		}
		typ, n, err := parser.ParseType(b, protocol.Encryption1RTT)
		require.NoError(t, err)
		got, l, err := parser.ParseLessCommonFrame(typ, b[n:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, f, got)
		require.Equal(t, len(b), n+l)
		for i := 0; i < 38; i++ {
			_, _, err := parseExperimentalSourceOfferFrame(b[n : n+i])
			require.Error(t, err)
		}
	}
}

func TestExperimentalSourceOfferTransportParameter(t *testing.T) {
	p := &TransportParameters{ExperimentalSourceOffers: true, ActiveConnectionIDLimit: 2}
	var parsed TransportParameters
	require.NoError(t, parsed.Unmarshal(p.Marshal(protocol.PerspectiveClient), protocol.PerspectiveClient))
	require.True(t, parsed.ExperimentalSourceOffers)
	for _, value := range []uint64{0, 1, 2, 4} {
		b := p.marshalVarintParam(nil, experimentalSourceOffersParameterID, value)
		require.Error(t, parsed.Unmarshal(b, protocol.PerspectiveClient))
	}
}

func TestExperimentalSourceOfferInvalidFields(t *testing.T) {
	valid := ExperimentalSourceOfferFrame{ID: 1, Generation: 1, TTL: 60, Address: netip.MustParseAddrPort("192.0.2.1:443")}
	for _, mutate := range []func(*ExperimentalSourceOfferFrame){
		func(f *ExperimentalSourceOfferFrame) { f.ID = 0 },
		func(f *ExperimentalSourceOfferFrame) { f.Generation = 0 },
		func(f *ExperimentalSourceOfferFrame) { f.TTL = 3601 },
		func(f *ExperimentalSourceOfferFrame) { f.TTL = 0 },
		func(f *ExperimentalSourceOfferFrame) { f.Address = netip.MustParseAddrPort("0.0.0.0:443") },
		func(f *ExperimentalSourceOfferFrame) { f.Address = netip.MustParseAddrPort("224.0.0.1:443") },
		func(f *ExperimentalSourceOfferFrame) { f.Address = netip.MustParseAddrPort("[fe80::1%eth0]:443") },
		func(f *ExperimentalSourceOfferFrame) { f.Address = netip.MustParseAddrPort("192.0.2.1:0") },
	} {
		f := valid
		mutate(&f)
		_, err := f.Append(nil, protocol.Version1)
		require.Error(t, err)
	}
	b, err := valid.Append(nil, protocol.Version1)
	require.NoError(t, err)
	body := append([]byte(nil), b[len(b)-38:]...)
	clear(body[16:20]) // withdrawal with a nonempty endpoint is noncanonical
	_, _, err = parseExperimentalSourceOfferFrame(body)
	require.Error(t, err)
}

func FuzzExperimentalSourceOffer(f *testing.F) {
	b, _ := (&ExperimentalSourceOfferFrame{ID: 1, Generation: 1, TTL: 60, Address: netip.MustParseAddrPort("192.0.2.1:443")}).Append(nil, protocol.Version1)
	f.Add(b[len(b)-38:])
	f.Fuzz(func(t *testing.T, b []byte) {
		offer, n, err := parseExperimentalSourceOfferFrame(b)
		if err != nil {
			return
		}
		require.Equal(t, 38, n)
		require.True(t, offer.valid())
		_, err = offer.Append(nil, protocol.Version1)
		require.NoError(t, err)
	})
}
