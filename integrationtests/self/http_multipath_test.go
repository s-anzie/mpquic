package self_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/stretchr/testify/require"
)

// TestHTTP3Multipath exercises HTTP request and response streams on a negotiated
// multipath connection, then reuses the connection after closing the second path.
func TestHTTP3Multipath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config := getQuicConfig(&quic.Config{
		Versions: []quic.Version{version}, EnableMultipath: true, MaxPathID: 1,
	})
	serverTransport := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 8}
	defer serverTransport.Close()
	tlsConfig := getTLSConfig()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	listener, err := serverTransport.Listen(tlsConfig, config.Clone())
	require.NoError(t, err)
	defer listener.Close()
	initial := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 8}
	defer initial.Close()
	secondary := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 8}
	defer secondary.Close()
	// Count UDP payload bytes by direction and client socket. These include
	// protocol overhead and retransmissions, and are not application-byte counts.
	var traffic [2][2]atomic.Int64
	proxy := quicproxy.Proxy{
		Conn: newUDPConnLocalhost(t), ServerAddr: listener.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, from, to net.Addr, packet []byte) time.Duration {
			direction, addr := 0, from
			if dir == quicproxy.DirectionOutgoing {
				direction, addr = 1, to
			}
			path := 0
			if addr.String() == secondary.Conn.LocalAddr().String() {
				path = 1
			}
			traffic[direction][path].Add(int64(len(packet)))
			return 0
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientTLS := getTLSClientConfig()
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	client, err := initial.Dial(ctx, proxy.LocalAddr(), clientTLS, config.Clone())
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")
	for _, conn := range []*quic.Conn{client, server} {
		state := conn.ConnectionState()
		require.True(t, state.SupportsMultipath.Local && state.SupportsMultipath.Remote)
		require.Equal(t, http3.NextProtoH3, state.TLS.NegotiatedProtocol)
		require.Equal(t, version, state.Version)
	}
	path, err := client.AddPath(secondary)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))

	payload := GeneratePRData(4 * 1024 * 1024)
	h3server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "invalid request payload", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h3server.ServeQUICConn(server)
	}()
	defer func() {
		_ = h3server.Close()
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("HTTP/3 server did not stop")
		}
	}()
	h3transport := &http3.Transport{}
	defer h3transport.Close()
	httpClient := &http.Client{Transport: h3transport.NewClientConn(client)}
	exchange := func() {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/echo", bytes.NewReader(payload))
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, 3, resp.ProtoMajor)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, payload, body)
	}
	var before [2][2]int64
	for d := range 2 {
		for p := range 2 {
			before[d][p] = traffic[d][p].Load()
		}
	}
	exchange()
	for d, label := range []string{"client-to-server", "server-to-client"} {
		for p := range 2 {
			delta := traffic[d][p].Load() - before[d][p]
			t.Logf("%s path %d: %d UDP payload bytes", label, p, delta)
			if d == 0 {
				require.Greater(t, delta, int64(64*1024), "both paths must carry substantial upload traffic")
			}
		}
	}
	require.NoError(t, path.Close())
	exchange()
}
