//go:build linux

package handshake

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func TestRemoteGSOPreservesDatagramBoundaries(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "gso", true: "fallback"}[disabled], func(t *testing.T) {
			source, destination := remoteUDPSocket(t), remoteUDPSocket(t)
			w := &remoteUDPBatchWriter{UDPConn: source, batch: ipv4.NewPacketConn(source), writeMsg: source.WriteMsgUDP, gsoDisabled: disabled}
			packets := make([][]byte, 64)
			for i := range packets {
				packets[i] = bytes.Repeat([]byte{byte(i)}, 1100)
			}
			packets[63] = []byte("short final datagram")
			require.NoError(t, destination.SetReadDeadline(time.Now().Add(time.Second)))
			require.NoError(t, w.writeBatch(packets, destination.LocalAddr().(*net.UDPAddr)))
			for _, expected := range packets {
				b := make([]byte, 1500)
				n, _, err := destination.ReadFromUDP(b)
				require.NoError(t, err)
				require.Equal(t, expected, b[:n])
			}
		})
	}
}

func TestRemoteGSOFallbackAndUncertainWrite(t *testing.T) {
	source, destination := remoteUDPSocket(t), remoteUDPSocket(t)
	calls := 0
	w := &remoteUDPBatchWriter{UDPConn: source, batch: ipv4.NewPacketConn(source), writeMsg: func([]byte, []byte, *net.UDPAddr) (int, int, error) { calls++; return 0, 0, unix.EIO }}
	packets := [][]byte{[]byte("one"), []byte("two")}
	require.NoError(t, w.writeBatch(packets, destination.LocalAddr().(*net.UDPAddr)))
	require.True(t, w.gsoDisabled)
	require.Equal(t, 1, calls)
	require.NoError(t, destination.SetReadDeadline(time.Now().Add(time.Second)))
	for _, expected := range packets {
		b := make([]byte, 1500)
		n, _, err := destination.ReadFromUDP(b)
		require.NoError(t, err)
		require.Equal(t, expected, b[:n])
	}
	// A partial or otherwise uncertain write must fail rather than replaying.
	w.gsoDisabled = false
	w.writeMsg = func([]byte, []byte, *net.UDPAddr) (int, int, error) { return 1, 0, nil }
	require.ErrorIs(t, w.writeBatch(packets, destination.LocalAddr().(*net.UDPAddr)), io.ErrShortWrite)
	require.False(t, w.gsoDisabled)
	w.writeMsg = func([]byte, []byte, *net.UDPAddr) (int, int, error) { return 1, 0, unix.EIO }
	require.ErrorIs(t, w.writeBatch(packets, destination.LocalAddr().(*net.UDPAddr)), unix.EIO)
}
