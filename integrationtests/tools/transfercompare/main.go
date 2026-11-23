// Command transfercompare compares raw QUIC transport architectures on loopback.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

type countedUDP struct {
	*net.UDPConn
	batch   *ipv4.PacketConn
	bytes   atomic.Uint64
	packets atomic.Uint64
}

func newUDP(ip string) (*countedUDP, error) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		return nil, err
	}
	return &countedUDP{UDPConn: u, batch: ipv4.NewPacketConn(u)}, nil
}

// Retain UDP offloads and batched reception while counting each client socket.
func (u *countedUDP) ReadBatch(m []ipv4.Message, flags int) (int, error) {
	n, err := u.batch.ReadBatch(m, flags)
	for i := 0; i < n; i++ {
		u.bytes.Add(uint64(m[i].N))
		u.packets.Add(1)
	}
	return n, err
}
func (u *countedUDP) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := u.UDPConn.ReadFrom(b)
	if err == nil {
		u.bytes.Add(uint64(n))
		u.packets.Add(1)
	}
	return n, a, err
}

type workerConfig struct {
	Certificate, PrivateKey, PrimaryCertificate []byte
	File, Destination, IP                       string
	ObjectID                                    quic.ExperimentalCloneObjectID
}
type ready struct {
	UDP, Relay, Jobs string
	PID              int
}
type pathResult struct {
	Address             string
	UDPBytes, Datagrams uint64
}
type result struct {
	Mode           string                              `json:"mode"`
	Bytes          int64                               `json:"bytes"`
	Seconds        float64                             `json:"seconds"`
	MbitPerSecond  float64                             `json:"mbit_per_second"`
	MiBPerSecond   float64                             `json:"mib_per_second"`
	SHA256         string                              `json:"sha256,omitempty"`
	SHA256Verified bool                                `json:"sha256_verified"`
	Paths          []pathResult                        `json:"client_sockets"`
	Sources        []quic.ExperimentalCloneSourceStats `json:"sources,omitempty"`
	WorkerPIDs     []int                               `json:"worker_pids,omitempty"`
	GoVersion      string                              `json:"go_version"`
	GOMAXPROCS     int                                 `json:"gomaxprocs"`
}

var cpuProfile string
var verifySHA256 bool

func main() {
	mode := flag.String("mode", "single", "single, multipath, or multisource")
	size := flag.Int64("bytes", 1<<30, "verified application bytes")
	deadline := flag.Duration("timeout", 30*time.Minute, "whole-run deadline")
	worker := flag.Bool("worker", false, "internal worker subprocess")
	flag.StringVar(&cpuProfile, "cpuprofile", "", "optional primary/client CPU profile during transfer")
	flag.BoolVar(&verifySHA256, "verify-sha256", true, "verify the complete received content with SHA-256")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), *deadline)
	defer cancel()
	var err error
	if *worker {
		err = serveWorker(ctx)
	} else {
		err = run(ctx, *mode, *size)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func roots(cert tls.Certificate) (*x509.CertPool, error) {
	p, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	r := x509.NewCertPool()
	r.AddCert(p)
	return r, nil
}

func sourceFile(size int64) (*os.File, string, error) {
	f, err := os.CreateTemp("", "mpquic-compare-source-*")
	if err != nil {
		return nil, "", err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte(i*31 + 7)
	}
	for left := size; left > 0; {
		n := min(left, int64(len(block)))
		if _, err := f.Write(block[:n]); err != nil {
			return nil, "", err
		}
		h.Write(block[:n])
		left -= n
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, "", err
	}
	ok = true
	return f, hex.EncodeToString(h.Sum(nil)), nil
}

func run(ctx context.Context, mode string, size int64) error {
	if size <= 0 || size > 2_097_152_000 || (mode != "single" && mode != "multipath" && mode != "multisource") {
		return errors.New("invalid mode or size")
	}
	cert, err := identity(1)
	if err != nil {
		return err
	}
	pool, err := roots(cert)
	if err != nil {
		return err
	}
	file, expected, err := sourceFile(size)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	su, err := newUDP("127.0.0.1")
	if err != nil {
		return err
	}
	defer su.Close()
	st := &quic.Transport{Conn: su, ConnectionIDLength: 8}
	defer st.Close()
	cfg := &quic.Config{EnableMultipath: mode != "single", MaxPathID: 4, EnableExperimentalSourceOffers: mode == "multisource", DisableAutomaticPathDiscovery: true, MaxIdleTimeout: time.Minute}
	l, err := st.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"transfer-compare/1"}}, cfg)
	if err != nil {
		return err
	}
	defer l.Close()
	cu, err := newUDP("127.0.0.1")
	if err != nil {
		return err
	}
	defer cu.Close()
	ct := &quic.Transport{Conn: cu, ConnectionIDLength: 8}
	defer ct.Close()
	client, err := ct.Dial(ctx, l.Addr(), &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{"transfer-compare/1"}}, cfg)
	if err != nil {
		return err
	}
	defer client.CloseWithError(0, "done")
	stopDeadline := context.AfterFunc(ctx, func() { client.CloseWithError(1, "benchmark deadline") })
	defer stopDeadline()
	server, err := l.Accept(ctx)
	if err != nil {
		return err
	}
	defer server.CloseWithError(0, "done")
	sockets := []*countedUDP{cu}
	// Identical untimed warm-up completes the initial key transition.
	warmDone := make(chan error, 1)
	go func() {
		s, e := client.AcceptUniStream(ctx)
		if e == nil {
			_, e = io.Copy(io.Discard, s)
		}
		warmDone <- e
	}()
	warm, err := server.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err = warm.Write(make([]byte, 512<<10)); err != nil {
		return err
	}
	if err = warm.Close(); err != nil {
		return err
	}
	if err = <-warmDone; err != nil {
		return err
	}
	if mode == "multipath" {
		u, e := newUDP("127.0.0.1")
		if e != nil {
			return e
		}
		defer u.Close()
		sockets = append(sockets, u)
		tr := &quic.Transport{Conn: u, ConnectionIDLength: 8}
		defer tr.Close()
		p, e := client.AddPath(tr)
		if e != nil {
			return e
		}
		defer p.Close()
		if e = p.Probe(ctx); e != nil {
			return e
		}
	}
	var manifest quic.ExperimentalCloneObjectManifest
	var sources []quic.ExperimentalCloneSource
	var pids []int
	if mode == "multisource" {
		manifest, err = quic.BuildExperimentalCloneObjectManifest(file, size)
		if err != nil {
			return err
		}
		for i := range 2 {
			f := file
			if i == 1 {
				f, _, err = sourceFile(size)
				if err != nil {
					return err
				}
				defer os.Remove(f.Name())
				defer f.Close()
			}
			u, e := newUDP("127.0.0.1")
			if e != nil {
				return e
			}
			defer u.Close()
			sockets = append(sockets, u)
			wc, e := identity(int64(i + 2))
			if e != nil {
				return e
			}
			key, e := x509.MarshalPKCS8PrivateKey(wc.PrivateKey)
			if e != nil {
				return e
			}
			config := workerConfig{Certificate: wc.Certificate[0], PrivateKey: key, PrimaryCertificate: cert.Certificate[0], File: f.Name(), Destination: u.LocalAddr().String(), IP: fmt.Sprintf("127.0.0.%d", i+2), ObjectID: manifest.ID()}
			r, stop, e := startWorker(ctx, config)
			if e != nil {
				return e
			}
			defer stop()
			pids = append(pids, r.PID)
			wp, e := roots(wc)
			if e != nil {
				return e
			}
			dial := func(address, alpn string) (*tls.Conn, error) {
				d := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: wp, Certificates: []tls.Certificate{cert}, ServerName: "localhost", NextProtos: []string{alpn}}}
				c, e := d.DialContext(ctx, "tcp", address)
				if e != nil {
					return nil, e
				}
				return c.(*tls.Conn), nil
			}
			id := uint64(i + 1)
			address, e := netip.ParseAddrPort(r.UDP)
			if e != nil {
				return e
			}
			pin := sha256.Sum256(wc.Certificate[0])
			if e = server.AnnounceExperimentalSource(ctx, id, 1, address, time.Hour); e != nil {
				return e
			}
			relay, e := dial(r.Relay, quic.ExperimentalSourceRelayALPN)
			if e != nil {
				return e
			}
			defer relay.Close()
			if e = server.PrepareExperimentalSource(ctx, id, 1, relay, pin); e != nil {
				return e
			}
			for {
				e = client.AcceptExperimentalSource(ctx, id, 1, func(o quic.ExperimentalSourceOffer) bool { return o.Address == address })
				if e == nil {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Millisecond):
				}
			}
			p, e := client.ProbeExperimentalSource(ctx, id, 1, u)
			if e != nil {
				return e
			}
			defer p.Close()
			control, e := dial(r.Jobs, quic.ExperimentalCloningALPN)
			if e != nil {
				return e
			}
			defer control.Close()
			sources = append(sources, quic.ExperimentalCloneSource{PathID: p.ID(), SourceID: id, Generation: 1, Control: control, CertificateSHA256: pin, Autonomous: true})
		}
	}
	stream, err := server.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	var writer *quic.ExperimentalCloneWriter
	if mode == "multisource" {
		for {
			writer, err = server.NewExperimentalCloneWriter(ctx, stream, sources)
			if err == nil {
				break
			}
			if !errors.Is(err, quic.ErrExperimentalCloningNotReady) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		defer writer.Close()
	}
	// Let validation control packets settle before taking counter baselines.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}
	base := make([]pathResult, len(sockets))
	for i, u := range sockets {
		base[i] = pathResult{Address: u.LocalAddr().String(), UDPBytes: u.bytes.Load(), Datagrams: u.packets.Load()}
	}
	var received atomic.Int64
	done := make(chan error, 1)
	go func() {
		s, e := client.AcceptUniStream(ctx)
		if e != nil {
			done <- e
			return
		}
		h := sha256.New()
		b := make([]byte, 64<<10)
		for {
			n, re := s.Read(b)
			if n > 0 {
				if verifySHA256 {
					h.Write(b[:n])
				}
				received.Add(int64(n))
			}
			if re == io.EOF {
				break
			}
			if re != nil {
				done <- re
				return
			}
		}
		if received.Load() != size || (verifySHA256 && hex.EncodeToString(h.Sum(nil)) != expected) {
			done <- errors.New("content mismatch")
			return
		}
		done <- nil
	}()
	if cpuProfile != "" {
		profile, e := os.Create(cpuProfile)
		if e != nil {
			return e
		}
		defer profile.Close()
		if e = pprof.StartCPUProfile(profile); e != nil {
			return e
		}
		defer pprof.StopCPUProfile()
	}
	start := time.Now()
	progressDone := make(chan struct{})
	defer close(progressDone)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-t.C:
				fmt.Fprintf(os.Stderr, "progress mode=%s received=%d elapsed=%s\n", mode, received.Load(), time.Since(start).Round(time.Second))
			}
		}
	}()
	if writer != nil {
		_, err = writer.WriteObject(ctx, manifest)
	} else {
		_, err = io.CopyBuffer(stream, io.LimitReader(file, size), make([]byte, 64<<10))
	}
	if err != nil {
		return err
	}
	if err = stream.Close(); err != nil {
		return err
	}
	if err = <-done; err != nil {
		return err
	}
	elapsed := time.Since(start)
	r := result{Mode: mode, Bytes: size, Seconds: elapsed.Seconds(), MbitPerSecond: float64(size) * 8 / elapsed.Seconds() / 1e6, MiBPerSecond: float64(size) / elapsed.Seconds() / (1 << 20), SHA256: expected, WorkerPIDs: pids, GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0)}
	r.SHA256Verified = verifySHA256
	if !verifySHA256 {
		r.SHA256 = ""
	}
	for i, u := range sockets {
		r.Paths = append(r.Paths, pathResult{Address: base[i].Address, UDPBytes: u.bytes.Load() - base[i].UDPBytes, Datagrams: u.packets.Load() - base[i].Datagrams})
	}
	if writer != nil {
		r.Sources = writer.Stats()
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}

func startWorker(ctx context.Context, config workerConfig) (ready, func(), error) {
	exe, err := os.Executable()
	if err != nil {
		return ready{}, nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "-worker", "-timeout", "45m")
	in, err := cmd.StdinPipe()
	if err != nil {
		return ready{}, nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return ready{}, nil, err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return ready{}, nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	if err = json.NewEncoder(in).Encode(config); err != nil {
		stop()
		return ready{}, nil, err
	}
	in.Close()
	var r ready
	if err = json.NewDecoder(out).Decode(&r); err != nil {
		stop()
		return ready{}, nil, err
	}
	return r, stop, nil
}

func serveWorker(ctx context.Context) error {
	var c workerConfig
	if err := json.NewDecoder(os.Stdin).Decode(&c); err != nil {
		return err
	}
	key, err := x509.ParsePKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	cert := tls.Certificate{Certificate: [][]byte{c.Certificate}, PrivateKey: key}
	pool, err := roots(tls.Certificate{Certificate: [][]byte{c.PrimaryCertificate}})
	if err != nil {
		return err
	}
	pin := sha256.Sum256(c.PrimaryCertificate)
	f, err := os.Open(c.File)
	if err != nil {
		return err
	}
	defer f.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(c.IP)})
	if err != nil {
		return err
	}
	defer u.Close()
	relay, err := net.Listen("tcp4", c.IP+":0")
	if err != nil {
		return err
	}
	defer relay.Close()
	jobs, err := net.Listen("tcp4", c.IP+":0")
	if err != nil {
		return err
	}
	defer jobs.Close()
	dest, err := netip.ParseAddrPort(c.Destination)
	if err != nil {
		return err
	}
	controller, err := quic.NewExperimentalWorkerController(1452, 25*time.Millisecond)
	if err != nil {
		return err
	}
	options := &quic.ExperimentalCloneWorkerOptions{Controller: controller, Objects: quic.ExperimentalCloneObjectResolverFunc(func(id quic.ExperimentalCloneObjectID) (io.ReaderAt, error) {
		if id != c.ObjectID {
			return nil, errors.New("unknown object")
		}
		return f, nil
	})}
	accept := func(l net.Listener, alpn string) (*tls.Conn, error) {
		raw, e := l.Accept()
		if e != nil {
			return nil, e
		}
		tc := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, NextProtos: []string{alpn}})
		if e = tc.HandshakeContext(ctx); e != nil {
			tc.Close()
			return nil, e
		}
		return tc, nil
	}
	done := make(chan error, 2)
	allow := func(a netip.AddrPort) bool { return a == dest }
	go func() {
		tc, e := accept(relay, quic.ExperimentalSourceRelayALPN)
		if e == nil {
			e = quic.ServeExperimentalSourceRelay(ctx, tc, pin, u, allow, options)
		}
		done <- e
	}()
	go func() {
		tc, e := accept(jobs, quic.ExperimentalCloningALPN)
		if e == nil {
			e = quic.ServeExperimentalCloneWorker(ctx, tc, pin, u, allow, options)
		}
		done <- e
	}()
	if err = json.NewEncoder(os.Stdout).Encode(ready{UDP: u.LocalAddr().String(), Relay: relay.Addr().String(), Jobs: jobs.Addr().String(), PID: os.Getpid()}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
