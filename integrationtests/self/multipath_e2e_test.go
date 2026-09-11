package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestMultipathEndToEnd(t *testing.T) {
	const maxPathID = 1
	mpConfig := getQuicConfig(&quic.Config{
		EnableMultipath: true,
		MaxPathID:       maxPathID,
	})

	serverTransport := &quic.Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: 8,
	}
	defer serverTransport.Close()
	listener, err := serverTransport.Listen(getTLSConfig(), mpConfig.Clone())
	require.NoError(t, err)
	defer listener.Close()

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 8}
	defer tr1.Close()
	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 8}
	defer tr2.Close()

	var path1Packets, path2Packets atomic.Int64
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: listener.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, from, to net.Addr, _ []byte) time.Duration {
			var port int
			switch dir {
			case quicproxy.DirectionIncoming:
				port = from.(*net.UDPAddr).Port
			case quicproxy.DirectionOutgoing:
				port = to.(*net.UDPAddr).Port
			}
			switch port {
			case tr1.Conn.LocalAddr().(*net.UDPAddr).Port:
				path1Packets.Add(1)
			case tr2.Conn.LocalAddr().(*net.UDPAddr).Port:
				path2Packets.Add(1)
			}
			return 0
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := tr1.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), mpConfig.Clone())
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")

	path, err := client.AddPath(tr2)
	require.NoError(t, err)
	require.ErrorIs(t, path.Switch(), quic.ErrPathNotValidated)
	require.NoError(t, path.Probe(ctx))
	require.NotZero(t, path2Packets.Load(), "the secondary path must carry validation traffic")

	payload := bytes.Repeat([]byte("multipath end-to-end payload"), 4096)
	stream, err := client.OpenUniStream()
	require.NoError(t, err)
	serverData := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		incoming, err := server.AcceptUniStream(ctx)
		if err != nil {
			serverErr <- fmt.Errorf("accepting multipath stream: %w", err)
			return
		}
		data, err := io.ReadAll(incoming)
		if err != nil {
			serverErr <- fmt.Errorf("reading multipath stream: %w", err)
			return
		}
		serverData <- data
	}()

	path2BeforeData := path2Packets.Load()
	path1BeforeData := path1Packets.Load()
	_, err = stream.Write(payload)
	require.NoError(t, err)
	require.NoError(t, stream.Close())

	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case data := <-serverData:
		require.True(t, bytes.Equal(payload, data))
	case <-ctx.Done():
		t.Fatal("timed out waiting for multipath stream data")
	}
	require.Greater(t, path2Packets.Load(), path2BeforeData, "application data must use the validated secondary path")
	require.Greater(t, path1Packets.Load(), path1BeforeData, "application data must also use the initial path")

	require.NoError(t, path.Close())
	fallbackPayload := []byte("fallback after path close")
	fallbackData := make(chan []byte, 1)
	fallbackErr := make(chan error, 1)
	go func() {
		incoming, err := server.AcceptUniStream(ctx)
		if err != nil {
			fallbackErr <- fmt.Errorf("accepting fallback stream: %w", err)
			return
		}
		data, err := io.ReadAll(incoming)
		if err != nil {
			fallbackErr <- fmt.Errorf("reading fallback stream: %w", err)
			return
		}
		fallbackData <- data
	}()
	stream, err = client.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write(fallbackPayload)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	select {
	case err := <-fallbackErr:
		require.NoError(t, err)
	case data := <-fallbackData:
		require.Equal(t, fallbackPayload, data)
	case <-ctx.Done():
		t.Fatal("timed out waiting for fallback stream data")
	}
}
