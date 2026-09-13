package quic

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEligiblePathAddresses(t *testing.T) {
	addresses := []net.IP{
		net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.2"),
		net.ParseIP("127.0.0.1"), net.ParseIP("169.254.1.1"), net.ParseIP("224.0.0.1"),
		net.ParseIP("::"), net.ParseIP("fe80::1"), net.ParseIP("2001:db8::1"), nil,
	}
	got := eligiblePathAddresses(addresses, net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.1"))
	require.Len(t, got, 1)
	require.True(t, got[0].Equal(net.ParseIP("192.0.2.2")))
	got = eligiblePathAddresses(addresses, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::3"))
	require.Len(t, got, 1)
	require.True(t, got[0].Equal(net.ParseIP("2001:db8::1")))
}

func TestPathDiscoveryConfigPropagation(t *testing.T) {
	var calls int
	config := &Config{DisableAutomaticPathDiscovery: true, PathDiscoveryAddresses: func() ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}}
	for _, copy := range []*Config{config.Clone(), populateConfig(config)} {
		require.True(t, copy.DisableAutomaticPathDiscovery)
		ips, err := copy.PathDiscoveryAddresses()
		require.NoError(t, err)
		require.Len(t, ips, 1)
	}
	require.Equal(t, 2, calls)
}
