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
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

var distributedRole, bindIP, secondBindIP, serverAddress, stateDir, objectPath, workerHosts, workerIPs string

func init() {
	flag.StringVar(&distributedRole, "role", "", "distributed role: identity, object, server, client")
	flag.StringVar(&bindIP, "bind", "127.0.0.1", "local IPv4 address")
	flag.StringVar(&secondBindIP, "second-bind", "", "optional second local IPv4 address")
	flag.StringVar(&serverAddress, "server", "", "primary server UDP address")
	flag.StringVar(&stateDir, "state-dir", "", "experiment TLS identity directory")
	flag.StringVar(&objectPath, "object", "", "node-local source object path")
	flag.StringVar(&workerHosts, "worker-hosts", ",", "two comma-separated OAR worker hosts; empty means local")
	flag.StringVar(&workerIPs, "worker-ips", "", "two comma-separated source IPv4 addresses")
}

type distributedMessage struct {
	Kind, Mode, Expected, Address string
	Size                          int64
	Destinations                  []string
	ID, PathID                    uint64
	Seconds                       float64
	Bytes                         int64
	SHA256                        string
	Stats                         *result
}

func remoteWorkerCommand(ctx context.Context, host, exe string) *exec.Cmd {
	// oarsh inherits OAR_JOB_ID. The command contains only quoted arguments.
	args := []string{"env", "GOMAXPROCS=" + strconv.Itoa(runtime.GOMAXPROCS(0)), exe, "-worker", "-timeout", "45m"}
	for i := range args {
		args[i] = "'" + strings.ReplaceAll(args[i], "'", "'"+string(rune(34))+"'"+string(rune(34))+"'") + "'"
	}
	return exec.CommandContext(ctx, "oarsh", host, strings.Join(args, " "))
}

func experimentIdentity() (tls.Certificate, error) {
	der, err := os.ReadFile(filepath.Join(stateDir, "cert.der"))
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := os.ReadFile(filepath.Join(stateDir, "key.der"))
	if err != nil {
		return tls.Certificate{}, err
	}
	k, err := x509.ParsePKCS8PrivateKey(key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, err
}

func distributedConfig(mode string) *quic.Config {
	return &quic.Config{EnableMultipath: mode != "single", MaxPathID: 4,
		EnableExperimentalSourceOffers: mode == "multisource",
		DisableAutomaticPathDiscovery:  true, MaxIdleTimeout: time.Minute}
}

func runDistributed(ctx context.Context, mode string, size int64) error {
	if size <= 0 || size > 2_097_152_000 {
		return errors.New("invalid object size")
	}
	switch distributedRole {
	case "identity":
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return err
		}
		c, err := identity(1)
		if err != nil {
			return err
		}
		key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(stateDir, "key.der"), key, 0600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(stateDir, "cert.der"), c.Certificate[0], 0644)
	case "object":
		f, digest, err := sourceFile(size)
		if err != nil {
			return err
		}
		f.Close()
		if err = os.Rename(f.Name(), objectPath); err != nil {
			os.Remove(f.Name())
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"bytes": size, "sha256": digest})
	}
	if mode != "single" && mode != "multipath" && mode != "multisource" {
		return errors.New("invalid mode")
	}
	if distributedRole == "server" {
		return distributedServer(ctx, mode, size)
	}
	if distributedRole == "client" {
		return distributedClient(ctx, mode, size)
	}
	return errors.New("invalid distributed role")
}

func distributedServer(ctx context.Context, mode string, size int64) error {
	cert, err := experimentIdentity()
	if err != nil {
		return err
	}
	f, err := os.Open(objectPath)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() < size || (mode == "multisource" && stat.Size() != size) {
		return errors.New("source object size does not match the requested transfer")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(f, 0, size)); err != nil {
		return err
	}
	expected := hex.EncodeToString(h.Sum(nil))
	var manifest quic.ExperimentalCloneObjectManifest
	if mode == "multisource" {
		manifest, err = quic.BuildExperimentalCloneObjectManifest(f, size)
		if err != nil {
			return err
		}
	}
	addr, err := net.ResolveUDPAddr("udp4", serverAddress)
	if err != nil {
		return err
	}
	u, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer u.Close()
	tr := &quic.Transport{Conn: u, ConnectionIDLength: 8}
	defer tr.Close()
	listener, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"transfer-distributed/1"}}, distributedConfig(mode))
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"listening": listener.Addr().String(), "pid": os.Getpid()}); err != nil {
		return err
	}
	c, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	defer c.CloseWithError(0, "done")
	stop := context.AfterFunc(ctx, func() { c.CloseWithError(1, "deadline") })
	defer stop()
	control, err := c.AcceptStream(ctx)
	if err != nil {
		return err
	}
	enc, dec := json.NewEncoder(control), json.NewDecoder(control)
	var request distributedMessage
	if err = dec.Decode(&request); err != nil {
		return err
	}
	if request.Mode != mode || request.Size != size {
		return errors.New("client/server configuration mismatch")
	}
	warm, err := c.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err = warm.Write(make([]byte, 512<<10)); err != nil {
		return err
	}
	if err = warm.Close(); err != nil {
		return err
	}
	if err = enc.Encode(distributedMessage{Kind: "warm"}); err != nil {
		return err
	}
	if err = dec.Decode(&request); err != nil {
		return err
	}
	if request.Kind != "paths-ready" {
		return errors.New("missing client paths")
	}
	var sources []quic.ExperimentalCloneSource
	if mode == "multisource" {
		hosts, ips := strings.Split(workerHosts, ","), strings.Split(workerIPs, ",")
		if len(hosts) != 2 || len(ips) != 2 || len(request.Destinations) != 2 {
			return errors.New("exactly two sources and client destinations required")
		}
		for i := range 2 {
			wc, e := identity(int64(i + 2))
			if e != nil {
				return e
			}
			key, e := x509.MarshalPKCS8PrivateKey(wc.PrivateKey)
			if e != nil {
				return e
			}
			config := workerConfig{Certificate: wc.Certificate[0], PrivateKey: key, PrimaryCertificate: cert.Certificate[0],
				File: objectPath, Destination: request.Destinations[i], IP: ips[i], ObjectID: manifest.ID()}
			r, stopWorker, e := startWorkerOnHost(ctx, config, hosts[i])
			if e != nil {
				return e
			}
			defer stopWorker()
			pool, e := roots(wc)
			if e != nil {
				return e
			}
			dial := func(address, alpn string) (*tls.Conn, error) {
				d := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "localhost", NextProtos: []string{alpn}}}
				conn, e := d.DialContext(ctx, "tcp", address)
				if e != nil {
					return nil, e
				}
				return conn.(*tls.Conn), nil
			}
			id := uint64(i + 1)
			address, e := netip.ParseAddrPort(r.UDP)
			if e != nil {
				return e
			}
			pin := sha256.Sum256(wc.Certificate[0])
			if e = c.AnnounceExperimentalSource(ctx, id, 1, address, time.Hour); e != nil {
				return e
			}
			relay, e := dial(r.Relay, quic.ExperimentalSourceRelayALPN)
			if e != nil {
				return e
			}
			defer relay.Close()
			if e = c.PrepareExperimentalSource(ctx, id, 1, relay, pin); e != nil {
				return e
			}
			if e = enc.Encode(distributedMessage{Kind: "source", ID: id, Address: r.UDP}); e != nil {
				return e
			}
			var ack distributedMessage
			if e = dec.Decode(&ack); e != nil {
				return e
			}
			if ack.Kind != "source-ready" || ack.ID != id {
				return errors.New("invalid source acknowledgement")
			}
			jobs, e := dial(r.Jobs, quic.ExperimentalCloningALPN)
			if e != nil {
				return e
			}
			defer jobs.Close()
			sources = append(sources, quic.ExperimentalCloneSource{PathID: ack.PathID, SourceID: id, Generation: 1, Control: jobs, CertificateSHA256: pin, Autonomous: true})
		}
	}
	stream, err := c.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	var writer *quic.ExperimentalCloneWriter
	if mode == "multisource" {
		for {
			writer, err = c.NewExperimentalCloneWriter(ctx, stream, sources)
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
	if err = enc.Encode(distributedMessage{Kind: "ready", Expected: expected}); err != nil {
		return err
	}
	if err = dec.Decode(&request); err != nil {
		return err
	}
	if request.Kind != "start" {
		return errors.New("missing start")
	}
	base := c.ConnectionStats().ReceiveQueueDrops
	start := time.Now()
	if writer != nil {
		_, err = writer.WriteObject(ctx, manifest)
	} else {
		_, err = io.CopyBuffer(stream, io.NewSectionReader(f, 0, size), make([]byte, 64<<10))
	}
	if err != nil {
		return err
	}
	if err = stream.Close(); err != nil {
		return err
	}
	if err = dec.Decode(&request); err != nil {
		return err
	}
	if request.Kind != "received" || request.Bytes != size || (request.SHA256 != "" && request.SHA256 != expected) {
		return errors.New("invalid transfer receipt")
	}
	r := result{Mode: mode, Bytes: size, Seconds: time.Since(start).Seconds(), PrimaryQueueDrops: c.ConnectionStats().ReceiveQueueDrops - base}
	if writer != nil {
		r.Sources = writer.Stats()
	}
	if err = enc.Encode(distributedMessage{Kind: "stats", Stats: &r}); err != nil {
		return err
	}
	if err = dec.Decode(&request); err != nil {
		return err
	}
	if request.Kind != "finished" {
		return errors.New("missing final receipt")
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}

func distributedClient(ctx context.Context, mode string, size int64) error {
	if secondBindIP == "" {
		secondBindIP = bindIP
	}
	der, err := os.ReadFile(filepath.Join(stateDir, "cert.der"))
	if err != nil {
		return err
	}
	pool, err := roots(tls.Certificate{Certificate: [][]byte{der}})
	if err != nil {
		return err
	}
	u, err := newUDP(bindIP)
	if err != nil {
		return err
	}
	defer u.Close()
	tr := &quic.Transport{Conn: u, ConnectionIDLength: 8}
	defer tr.Close()
	address, err := net.ResolveUDPAddr("udp4", serverAddress)
	if err != nil {
		return err
	}
	c, err := tr.Dial(ctx, address, &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{"transfer-distributed/1"}}, distributedConfig(mode))
	if err != nil {
		return err
	}
	defer c.CloseWithError(0, "done")
	stop := context.AfterFunc(ctx, func() { c.CloseWithError(1, "deadline") })
	defer stop()
	control, err := c.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	enc, dec := json.NewEncoder(control), json.NewDecoder(control)
	if err = enc.Encode(distributedMessage{Kind: "hello", Mode: mode, Size: size}); err != nil {
		return err
	}
	warm, err := c.AcceptUniStream(ctx)
	if err != nil {
		return err
	}
	if _, err = io.Copy(io.Discard, warm); err != nil {
		return err
	}
	var message distributedMessage
	if err = dec.Decode(&message); err != nil {
		return err
	}
	if message.Kind != "warm" {
		return errors.New("missing warm-up")
	}
	sockets := []*countedUDP{u}
	request := distributedMessage{Kind: "paths-ready"}
	if mode == "multipath" {
		extra, e := newUDP(secondBindIP)
		if e != nil {
			return e
		}
		defer extra.Close()
		sockets = append(sockets, extra)
		pt := &quic.Transport{Conn: extra, ConnectionIDLength: 8}
		defer pt.Close()
		p, e := c.AddPath(pt)
		if e != nil {
			return e
		}
		defer p.Close()
		if e = p.Probe(ctx); e != nil {
			return e
		}
	}
	if mode == "multisource" {
		for i := range 2 {
			ip := bindIP
			if i == 1 {
				ip = secondBindIP
			}
			extra, e := newUDP(ip)
			if e != nil {
				return e
			}
			defer extra.Close()
			sockets = append(sockets, extra)
			request.Destinations = append(request.Destinations, extra.LocalAddr().String())
		}
	}
	if err = enc.Encode(request); err != nil {
		return err
	}
	if mode == "multisource" {
		for i := range 2 {
			if err = dec.Decode(&message); err != nil {
				return err
			}
			if message.Kind != "source" {
				return errors.New("missing source offer")
			}
			a, e := netip.ParseAddrPort(message.Address)
			if e != nil {
				return e
			}
			for {
				e = c.AcceptExperimentalSource(ctx, message.ID, 1, func(o quic.ExperimentalSourceOffer) bool { return o.Address == a })
				if e == nil {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Millisecond):
				}
			}
			p, e := c.ProbeExperimentalSource(ctx, message.ID, 1, sockets[i+1])
			if e != nil {
				return e
			}
			defer p.Close()
			if e = enc.Encode(distributedMessage{Kind: "source-ready", ID: message.ID, PathID: p.ID()}); e != nil {
				return e
			}
		}
	}
	if err = dec.Decode(&message); err != nil {
		return err
	}
	if message.Kind != "ready" {
		return errors.New("server not ready")
	}
	expected := message.Expected
	time.Sleep(100 * time.Millisecond)
	base := make([]pathResult, len(sockets))
	for i, u := range sockets {
		base[i] = pathResult{Address: u.LocalAddr().String(), UDPBytes: u.bytes.Load(), Datagrams: u.packets.Load()}
	}
	drops := c.ConnectionStats().ReceiveQueueDrops
	start := time.Now()
	if err = enc.Encode(distributedMessage{Kind: "start"}); err != nil {
		return err
	}
	stream, err := c.AcceptUniStream(ctx)
	if err != nil {
		return err
	}
	h := sha256.New()
	var sink io.Writer = io.Discard
	if verifySHA256 {
		sink = h
	}
	n, err := io.CopyBuffer(sink, stream, make([]byte, 64<<10))
	if err != nil {
		return err
	}
	elapsed := time.Since(start)
	digest := ""
	if verifySHA256 {
		digest = hex.EncodeToString(h.Sum(nil))
	}
	if n != size || (verifySHA256 && digest != expected) {
		return errors.New("content mismatch")
	}
	r := result{Mode: mode, Bytes: n, Seconds: elapsed.Seconds(), MbitPerSecond: float64(n) * 8 / elapsed.Seconds() / 1e6, MiBPerSecond: float64(n) / elapsed.Seconds() / (1 << 20),
		SHA256: digest, SHA256Verified: verifySHA256, SourceSHA256Verification: "not-applicable", GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0), ClientQueueDrops: c.ConnectionStats().ReceiveQueueDrops - drops}
	if mode == "multisource" {
		r.SourceSHA256Verification = sourceSHA256Verification
	}
	for i, u := range sockets {
		r.Paths = append(r.Paths, pathResult{Address: base[i].Address, UDPBytes: u.bytes.Load() - base[i].UDPBytes, Datagrams: u.packets.Load() - base[i].Datagrams})
	}
	if err = enc.Encode(distributedMessage{Kind: "received", Bytes: n, SHA256: digest}); err != nil {
		return err
	}
	if err = dec.Decode(&message); err != nil {
		return err
	}
	if message.Kind != "stats" || message.Stats == nil {
		return errors.New("missing server statistics")
	}
	r.PrimaryQueueDrops = message.Stats.PrimaryQueueDrops
	r.Sources = message.Stats.Sources
	if err = enc.Encode(distributedMessage{Kind: "finished"}); err != nil {
		return err
	}
	// Ensure the final control receipt is delivered before closing the connection.
	select {
	case <-c.Context().Done():
	case <-ctx.Done():
		return ctx.Err()
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}
