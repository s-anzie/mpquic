// Command multiinterface validates automatic discovery over isolated OS interfaces.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/internal/testdata"
)

var block = make([]byte, 64*1024)

func writePayload(w io.Writer, size int64) error {
	for size > 0 {
		n := min(size, int64(len(block)))
		written, err := w.Write(block[:n])
		if err != nil {
			return err
		}
		if int64(written) != n {
			return io.ErrShortWrite
		}
		size -= n
	}
	return nil
}

type connectionKey struct{}

type linkStat struct {
	Name  string `json:"ifname"`
	Stats struct {
		RX struct {
			Bytes int64 `json:"bytes"`
		} `json:"rx"`
		TX struct {
			Bytes int64 `json:"bytes"`
		} `json:"tx"`
	} `json:"stats64"`
}

func counters() (map[string][2]int64, error) {
	out, err := exec.Command("ip", "-j", "-s", "link", "show").Output()
	if err != nil {
		return nil, err
	}
	var links []linkStat
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, err
	}
	result := make(map[string][2]int64)
	for _, link := range links {
		if strings.HasPrefix(link.Name, "mpq-c") {
			result[link.Name] = [2]int64{link.Stats.RX.Bytes, link.Stats.TX.Bytes}
		}
	}
	return result, nil
}

func run() error {
	role := flag.String("role", "client", "client or server")
	protocol := flag.String("protocol", "quic", "quic or http3")
	address := flag.String("address", "10.66.0.1:4433", "server address")
	multipath := flag.Bool("multipath", true, "negotiate multipath")
	size := flag.Int64("bytes", 64<<20, "application bytes per transfer")
	cut := flag.String("cut", "", "test interface to disable at one quarter of the transfer")
	deadline := flag.Duration("timeout", 150*time.Second, "client deadline")
	flag.Parse()
	for i := range block {
		block[i] = byte(i*31 + 7)
	}
	config := &quic.Config{EnableMultipath: *multipath, MaxPathID: 4, MaxIdleTimeout: 15 * time.Second}
	tlsConfig := testdata.GetTLSConfig()
	tlsConfig.NextProtos = []string{"multiinterface-test"}
	if *protocol == "http3" {
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
	}
	if *role == "server" {
		if *protocol == "http3" {
			var ids atomic.Int64
			server := &http3.Server{Addr: *address, TLSConfig: tlsConfig, QUICConfig: config,
				ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
					return context.WithValue(ctx, connectionKey{}, strconv.FormatInt(ids.Add(1), 10))
				},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Connection-ID", r.Context().Value(connectionKey{}).(string))
					n := *size
					if r.URL.Path == "/check" {
						n = 1024
					}
					w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
					_ = writePayload(w, n)
				}),
			}
			fmt.Println("READY")
			return server.ListenAndServe()
		}
		listener, err := quic.ListenAddr(*address, tlsConfig, config)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Println("READY")
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return err
			}
			go func() {
				defer conn.CloseWithError(0, "")
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						var request [1]byte
						if _, err := io.ReadFull(stream, request[:]); err != nil {
							stream.CancelWrite(1)
							return
						}
						n := *size
						if request[0] == 0 {
							n = 1024
						}
						if err := writePayload(stream, n); err != nil {
							stream.CancelWrite(1)
							return
						}
						_ = stream.Close()
					}()
				}
			}()
		}
	}
	if *cut != "" && *cut != "mpq-ca" && *cut != "mpq-cb" {
		return fmt.Errorf("refusing to modify non-test interface %q", *cut)
	}
	if *cut != "" {
		current, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			return err
		}
		host := os.Getenv("MPQUIC_HOST_NETNS")
		if host == "" || current == host {
			return fmt.Errorf("interface failure injection requires an isolated network namespace")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *deadline)
	defer cancel()
	clientTLS := &tls.Config{RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: tlsConfig.NextProtos}
	var fetch func(bool) (io.ReadCloser, string, error)
	if *protocol == "http3" {
		transport := &http3.Transport{TLSClientConfig: clientTLS, QUICConfig: config}
		defer transport.Close()
		client := &http.Client{Transport: transport}
		fetch = func(check bool) (io.ReadCloser, string, error) {
			path := "/data"
			if check {
				path = "/check"
			}
			req, err := http.NewRequestWithContext(ctx, "GET", "https://"+*address+path, nil)
			if err != nil {
				return nil, "", err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, "", err
			}
			if resp.StatusCode != 200 || resp.ProtoMajor != 3 {
				resp.Body.Close()
				return nil, "", fmt.Errorf("unexpected response: %s", resp.Status)
			}
			return resp.Body, resp.Header.Get("X-Connection-ID"), nil
		}
	} else {
		conn, err := quic.DialAddr(ctx, *address, clientTLS, config)
		if err != nil {
			return err
		}
		defer conn.CloseWithError(0, "")
		fetch = func(check bool) (io.ReadCloser, string, error) {
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				return nil, "", err
			}
			_ = stream.SetReadDeadline(time.Now().Add(*deadline))
			request := byte(1)
			if check {
				request = 0
			}
			if _, err := stream.Write([]byte{request}); err != nil {
				return nil, "", err
			}
			_ = stream.Close()
			return io.NopCloser(stream), "same-quic-connection", nil
		}
	}
	// Establish the connection, then allow the immediate OS inventory and probes.
	check, connectionID, err := fetch(true)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, check)
	check.Close()
	if err != nil {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	before, err := counters()
	if err != nil {
		return err
	}
	expected := sha256.New()
	if err := writePayload(expected, *size); err != nil {
		return err
	}
	started := time.Now()
	reader, dataID, err := fetch(false)
	if err != nil {
		return err
	}
	defer reader.Close()
	hash := sha256.New()
	var received int64
	cutAt := float64(-1)
	buffer := make([]byte, 64*1024)
	var readErr error
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			hash.Write(buffer[:n])
			received += int64(n)
		}
		if *cut != "" && cutAt < 0 && received >= *size/4 {
			output, cutErr := exec.Command("ip", "link", "set", "dev", *cut, "down").CombinedOutput()
			if cutErr != nil {
				return fmt.Errorf("cut: %w: %s", cutErr, output)
			}
			cutAt = time.Since(started).Seconds()
		}
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
	}
	elapsed := time.Since(started).Seconds()
	after, err := counters()
	if err != nil {
		return err
	}
	delta := make(map[string][2]int64)
	for name, value := range after {
		previous := before[name]
		delta[name] = [2]int64{value[0] - previous[0], value[1] - previous[1]}
	}
	integrity := received == *size && hex.EncodeToString(hash.Sum(nil)) == hex.EncodeToString(expected.Sum(nil))
	pathTrafficOK := !*multipath || (delta["mpq-ca"][0] > 65536 && delta["mpq-cb"][0] > 65536)
	followupOK := false
	if readErr == nil {
		followup, followupID, err := fetch(true)
		if err == nil {
			n, err := io.Copy(io.Discard, followup)
			followup.Close()
			followupOK = err == nil && n == 1024 && followupID == connectionID && dataID == connectionID
		}
	}
	report := map[string]any{"protocol": *protocol, "multipath": *multipath, "requested_bytes": *size, "received_bytes": received,
		"seconds": elapsed, "mbps": float64(received) * 8 / elapsed / 1e6, "sha256_ok": integrity, "same_connection_followup_ok": followupOK,
		"cut_interface": *cut, "cut_at_seconds": cutAt, "interface_bytes_rx_tx": delta, "path_traffic_ok": pathTrafficOK}
	if readErr != nil {
		report["error"] = readErr.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if !integrity || !followupOK || !pathTrafficOK || readErr != nil {
		return fmt.Errorf("transfer validation failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
