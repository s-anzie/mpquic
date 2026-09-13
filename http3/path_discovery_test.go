package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestTransportMultipathConfiguration(t *testing.T) {
	for _, maxPathID := range []uint64{0, 2} {
		config := &quic.Config{MaxPathID: maxPathID}
		transport := &Transport{EnableMultipath: true, QUICConfig: config}
		require.NoError(t, transport.init())
		t.Cleanup(func() { require.NoError(t, transport.Close()) })
		require.False(t, config.EnableMultipath, "do not mutate the caller's configuration")
		require.Equal(t, maxPathID, config.MaxPathID)
		require.True(t, transport.QUICConfig.EnableMultipath)
		if maxPathID == 0 {
			require.Equal(t, uint64(4), transport.QUICConfig.MaxPathID)
		} else {
			require.Equal(t, maxPathID, transport.QUICConfig.MaxPathID)
		}
	}
}

type discoveryTestSocket struct {
	*net.UDPConn
	secondaryBytes atomic.Int64
	secondaryPort  atomic.Int32
}

func (s *discoveryTestSocket) WriteMsgUDP(data, oob []byte, addr *net.UDPAddr) (int, int, error) {
	n, oobn, err := s.UDPConn.WriteMsgUDP(data, oob, addr)
	if err == nil && addr.IP.Equal(net.ParseIP("127.0.0.2")) {
		s.secondaryPort.Store(int32(addr.Port))
		s.secondaryBytes.Add(int64(n))
	}
	return n, oobn, err
}

func TestHTTP3AutomaticPathDiscovery(t *testing.T) {
	for _, name := range []string{"multipath", "quic-config", "custom-dial", "unsupported-peer"} {
		t.Run(name, func(t *testing.T) {
			enabled := name != "unsupported-peer"
			// Supply a deterministic interface inventory; all QUIC traffic still
			// traverses real UDP sockets and the ordinary HTTP/3 dialer.
			probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
			if err != nil {
				t.Skip("secondary loopback address unavailable")
			}
			_ = probe.Close()
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			require.NoError(t, err)
			defer udp.Close()
			socket := &discoveryTestSocket{UDPConn: udp}
			payload := bytes.Repeat([]byte("automatic HTTP/3 multipath\n"), 16384)
			server := &Server{
				TLSConfig:  getTLSConfig(),
				QUICConfig: &quic.Config{EnableMultipath: enabled, MaxPathID: 4},
				Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }),
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(socket) }()
			defer func() { _ = server.Close(); <-done }()
			var available atomic.Bool
			var inventoryError atomic.Bool
			var scans atomic.Int64
			transport := &Transport{EnableMultipath: true, TLSClientConfig: getTLSClientConfig(),
				QUICConfig: &quic.Config{PathDiscoveryAddresses: func() ([]net.IP, error) {
					scans.Add(1)
					if inventoryError.Load() {
						return nil, errors.New("temporary interface inventory failure")
					}
					if available.Load() {
						return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}, nil
					}
					return nil, nil
				}},
			}
			if name == "quic-config" {
				transport.EnableMultipath = false
				transport.QUICConfig.EnableMultipath = true
				transport.QUICConfig.MaxPathID = 4
			}
			defer transport.Close()
			if name == "custom-dial" {
				transport.Dial = quic.DialAddrEarly
			}
			client := &http.Client{Transport: transport}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			request := func() {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+udp.LocalAddr().String()+"/data", nil)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				require.NoError(t, err)
				require.Equal(t, 3, resp.ProtoMajor)
				require.Equal(t, payload, body)
			}
			request()
			transport.mutex.Lock()
			originalConn := transport.clients[udp.LocalAddr().String()].conn
			transport.mutex.Unlock()
			if enabled {
				// Discover an address that appears after the first request.
				require.Zero(t, socket.secondaryBytes.Load())
				available.Store(true)
				deadline := time.Now().Add(8 * time.Second)
				for socket.secondaryBytes.Load() < 64*1024 && time.Now().Before(deadline) {
					request()
				}
				require.Greater(t, socket.secondaryBytes.Load(), int64(64*1024))
				// A failed inventory must not remove a working path.
				inventoryError.Store(true)
				previous := scans.Load()
				require.Eventually(t, func() bool { return scans.Load() > previous }, 5*time.Second, 20*time.Millisecond)
				before := socket.secondaryBytes.Load()
				request()
				require.Greater(t, socket.secondaryBytes.Load(), before)
				available.Store(false)
				inventoryError.Store(false)
				// Rebinding the exact endpoint proves the removed path's socket
				// was closed, not merely that an inventory scan started.
				require.Eventually(t, func() bool {
					addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: int(socket.secondaryPort.Load())}
					replacement, err := net.ListenUDP("udp4", addr)
					if err != nil {
						return false
					}
					_ = replacement.Close()
					return true
				}, 5*time.Second, 20*time.Millisecond)
				request()
			} else {
				require.Zero(t, scans.Load(), "do not discover paths for a peer without multipath")
				require.Zero(t, socket.secondaryBytes.Load())
			}
			require.NoError(t, originalConn.Context().Err(), "removing a path must not close the connection")
			transport.mutex.Lock()
			currentConn := transport.clients[udp.LocalAddr().String()].conn
			transport.mutex.Unlock()
			require.Same(t, originalConn, currentConn, "HTTP/3 must not silently redial")
			if name == "quic-config" {
				// A connection evicted from the request pool can remain alive.
				// Closing the transport must still stop its discovery watcher.
				hostname := udp.LocalAddr().String()
				transport.mutex.Lock()
				conn := transport.clients[hostname].conn
				transport.mutex.Unlock()
				defer conn.CloseWithError(0, "")
				transport.removeClient(hostname)
			}
			start := time.Now()
			require.NoError(t, transport.Close()) // Joins discovery and closes its sockets.
			require.Less(t, time.Since(start), 3*time.Second)
		})
	}
}
