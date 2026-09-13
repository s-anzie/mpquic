package quic

import (
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/stretchr/testify/require"
)

func TestMultipathServerRequiresMatchingResponse(t *testing.T) {
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	p := &multipathPathState{serverChallenge: challenge}
	p.validateServerResponse(challenge)
	require.False(t, p.serverValidated, "unsolicited responses must not validate an address")
	p.serverChallengePending = true
	p.validateServerResponse([8]byte{9})
	require.False(t, p.serverValidated)
	require.True(t, p.serverChallengePending)
	p.validateServerResponse(challenge)
	require.True(t, p.serverValidated)
	require.False(t, p.serverChallengePending)
	p.serverValidated = false
	p.serverChallengePending = true
	p.abandoned = true
	p.validateServerResponse(challenge)
	require.False(t, p.serverValidated, "late responses must not revive abandoned paths")
}

func TestMultipathServerDoesNotScheduleUnvalidatedOrAbandonedPaths(t *testing.T) {
	for _, abandoned := range []bool{false, true} {
		c := &Conn{multipath: newMultipathState(1)}
		p, err := c.multipath.path(1)
		require.NoError(t, err)
		p.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
		p.serverValidated = abandoned
		p.abandoned = abandoned
		_, _, ok := c.nextServerApplicationPath(monotime.Now())
		require.False(t, ok)
	}
}
