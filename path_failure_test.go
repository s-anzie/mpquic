package quic

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/stretchr/testify/require"
)

func TestPathSendErrorClassification(t *testing.T) {
	for _, err := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EADDRNOTAVAIL, syscall.ECONNREFUSED} {
		require.True(t, isPathSendError(&net.OpError{Op: "write", Net: "udp", Err: err}))
	}
	require.False(t, isPathSendError(syscall.EPERM))
	require.False(t, isPathSendError(errors.New("internal error")))
}

func TestPathFailureRequiresValidatedSurvivor(t *testing.T) {
	c := &Conn{multipath: newMultipathState(4), multipathEnabled: true, handshakeConfirmed: true,
		perspective: protocol.PerspectiveServer}
	p, err := c.multipath.path(1)
	require.NoError(t, err)
	p.remoteAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	require.False(t, c.hasValidatedPathExcept(0))
	var transportError *qerr.TransportError
	require.ErrorAs(t, c.handlePathSendError(0, syscall.ENETUNREACH), &transportError)
	require.Equal(t, qerr.NoViablePathError, transportError.ErrorCode)
	p.serverValidated = true
	require.True(t, c.hasValidatedPathExcept(0))
	c.multipathEnabled = false
	require.ErrorIs(t, c.handlePathSendError(0, syscall.ENETUNREACH), syscall.ENETUNREACH)
}
