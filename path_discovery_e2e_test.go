package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/stretchr/testify/require"
)

type discoveryTestSocket struct {
	*net.UDPConn
	secondaryBytes atomic.Int64
	secondaryPort  atomic.Int32
}

func (s *discoveryTestSocket) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	n, m, err := s.UDPConn.WriteMsgUDP(b, oob, addr)
	if err == nil && addr.IP.Equal(net.ParseIP("127.0.0.2")) {
		s.secondaryBytes.Add(int64(n))
		s.secondaryPort.Store(int32(addr.Port))
	}
	return n, m, err
}

func TestQUICAutomaticPathDiscovery(t *testing.T) {
	for _, mode := range []string{"dial-addr", "dial-early", "transport", "disabled", "unsupported-peer"} {
		t.Run(mode, func(t *testing.T) {
			probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
			if err != nil {
				t.Skip("secondary loopback unavailable")
			}
			probe.Close()
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			require.NoError(t, err)
			defer udp.Close()
			socket := &discoveryTestSocket{UDPConn: udp}
			serverTransport := &Transport{Conn: socket}
			defer serverTransport.Close()
			serverTLS := testdata.GetTLSConfig()
			serverTLS.NextProtos = []string{"discovery-test"}
			var serverScans atomic.Int64
			listener, err := serverTransport.Listen(serverTLS, &Config{
				EnableMultipath: mode != "unsupported-peer", MaxPathID: 4,
				PathDiscoveryAddresses: func() ([]net.IP, error) { serverScans.Add(1); return nil, nil },
			})
			require.NoError(t, err)
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var scans atomic.Int64
			config := &Config{EnableMultipath: true, MaxPathID: 4, DisableAutomaticPathDiscovery: mode == "disabled",
				PathDiscoveryAddresses: func() ([]net.IP, error) {
					scans.Add(1)
					return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}, nil
				},
			}
			clientTLS := &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: serverTLS.NextProtos}
			var client *Conn
			switch mode {
			case "transport":
				local, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
				require.NoError(t, listenErr)
				defer local.Close()
				tr := &Transport{Conn: local}
				defer tr.Close()
				client, err = tr.Dial(ctx, listener.Addr(), clientTLS, config)
			case "dial-early":
				client, err = DialAddrEarly(ctx, listener.Addr().String(), clientTLS, config)
			default:
				client, err = DialAddr(ctx, listener.Addr().String(), clientTLS, config)
			}
			require.NoError(t, err)
			defer client.CloseWithError(0, "")
			server, err := listener.Accept(ctx)
			require.NoError(t, err)
			defer server.CloseWithError(0, "")
			payload := bytes.Repeat([]byte("QUIC automatic discovery"), 32768)
			transfer := func() {
				stream, err := server.OpenUniStream()
				require.NoError(t, err)
				written := make(chan error, 1)
				go func() {
					_, err := stream.Write(payload)
					if err == nil {
						err = stream.Close()
					}
					written <- err
				}()
				incoming, err := client.AcceptUniStream(ctx)
				require.NoError(t, err)
				body, err := io.ReadAll(incoming)
				require.NoError(t, err)
				require.Equal(t, payload, body)
				require.NoError(t, <-written)
			}
			transfer()
			if mode == "disabled" || mode == "unsupported-peer" {
				require.Zero(t, scans.Load())
				require.Zero(t, socket.secondaryBytes.Load())
			} else {
				deadline := time.Now().Add(5 * time.Second)
				for socket.secondaryBytes.Load() < 65536 && time.Now().Before(deadline) {
					transfer()
				}
				require.Greater(t, socket.secondaryBytes.Load(), int64(65536))
			}
			require.Zero(t, serverScans.Load(), "servers never initiate discovery")
			require.NoError(t, client.CloseWithError(0, ""))
			if port := socket.secondaryPort.Load(); port != 0 {
				// Closing the connection must release discovery-owned sockets.
				replacement, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: int(port)})
				require.NoError(t, err)
				replacement.Close()
			}
		})
	}
}
