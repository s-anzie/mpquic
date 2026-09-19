// Command cloning runs a loopback-only experimental QUIC cloning laboratory.
// All endpoints use real sockets; identities are generated in memory per run.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

func main() {
	size := flag.Int("bytes", 64<<10, "application bytes (1..67108864)")
	timeout := flag.Duration("timeout", 60*time.Second, "total laboratory deadline")
	flag.Parse()
	if *size <= 0 || *size > 64<<20 {
		fmt.Fprintln(os.Stderr, "invalid byte count")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := run(ctx, *size); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func identity(serial int64) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "clone-lab"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func udp() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func run(ctx context.Context, size int) error {
	primaryCert, err := identity(1)
	if err != nil {
		return err
	}
	workerCert, err := identity(2)
	if err != nil {
		return err
	}
	primaryRoots, workerRoots := x509.NewCertPool(), x509.NewCertPool()
	for i, cert := range []tls.Certificate{primaryCert, workerCert} {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		if i == 0 {
			primaryRoots.AddCert(parsed)
		} else {
			workerRoots.AddCert(parsed)
		}
	}
	primaryPin := sha256.Sum256(primaryCert.Certificate[0])
	workerPin := sha256.Sum256(workerCert.Certificate[0])
	serverUDP, err := udp()
	if err != nil {
		return err
	}
	defer serverUDP.Close()
	st := &quic.Transport{Conn: serverUDP, ConnectionIDLength: 8}
	defer st.Close()
	config := &quic.Config{EnableMultipath: true, MaxPathID: 4}
	listener, err := st.Listen(&tls.Config{Certificates: []tls.Certificate{primaryCert}, NextProtos: []string{"clone-lab/1"}}, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	clientUDP, err := udp()
	if err != nil {
		return err
	}
	defer clientUDP.Close()
	ct := &quic.Transport{Conn: clientUDP, ConnectionIDLength: 8}
	defer ct.Close()
	client, err := ct.Dial(ctx, listener.Addr(), &tls.Config{RootCAs: primaryRoots, ServerName: "localhost", NextProtos: []string{"clone-lab/1"}}, config)
	if err != nil {
		return err
	}
	defer client.CloseWithError(0, "lab complete")
	server, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	defer server.CloseWithError(0, "lab complete")
	// Complete the normal initial key transition before exporting any send keys.
	warmDone := make(chan error, 1)
	go func() {
		s, err := client.AcceptUniStream(ctx)
		if err == nil {
			_, err = io.Copy(io.Discard, s)
		}
		warmDone <- err
	}()
	warm, err := server.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := warm.Write(make([]byte, 512<<10)); err != nil {
		return err
	}
	if err := warm.Close(); err != nil {
		return err
	}
	if err := <-warmDone; err != nil {
		return err
	}
	fmt.Println("primary warm-up: 524288 bytes (excluded from cloned-transfer statistics)")
	var sources []quic.ExperimentalCloneSource
	for range 2 {
		pathUDP, err := udp()
		if err != nil {
			return err
		}
		defer pathUDP.Close()
		tr := &quic.Transport{Conn: pathUDP, ConnectionIDLength: 8}
		defer tr.Close()
		path, err := client.AddPath(tr)
		if err != nil {
			return err
		}
		if err := path.Probe(ctx); err != nil {
			return err
		}
		workerUDP, err := udp()
		if err != nil {
			return err
		}
		defer workerUDP.Close()
		tcp, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer tcp.Close()
		destination := pathUDP.LocalAddr().(*net.UDPAddr).AddrPort()
		workerErrors := make(chan error, 1)
		go func() {
			raw, err := tcp.Accept()
			if err != nil {
				workerErrors <- err
				return
			}
			tlsConn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{workerCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: primaryRoots, NextProtos: []string{quic.ExperimentalCloningALPN}})
			defer tlsConn.Close()
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				workerErrors <- err
				return
			}
			workerErrors <- quic.ServeExperimentalCloneWorker(ctx, tlsConn, primaryPin, workerUDP, func(addr netip.AddrPort) bool { return addr == destination })
		}()
		dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: workerRoots, Certificates: []tls.Certificate{primaryCert}, ServerName: "localhost", NextProtos: []string{quic.ExperimentalCloningALPN}}}
		control, err := dialer.DialContext(ctx, "tcp", tcp.Addr().String())
		if err != nil {
			return err
		}
		defer control.Close()
		sources = append(sources, quic.ExperimentalCloneSource{PathID: path.ID(), Control: control.(*tls.Conn), CertificateSHA256: workerPin})
		fmt.Printf("worker path=%d source=%s destination=%s\n", path.ID(), workerUDP.LocalAddr(), destination)
	}
	stream, err := server.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	var writer *quic.ExperimentalCloneWriter
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
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	readDone := make(chan error, 1)
	go func() {
		s, err := client.AcceptUniStream(ctx)
		if err != nil {
			readDone <- err
			return
		}
		got, err := io.ReadAll(s)
		if err == nil && !bytes.Equal(got, data) {
			err = errors.New("content mismatch")
		}
		readDone <- err
	}()
	start := time.Now()
	n, err := writer.WriteContext(ctx, data)
	if err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	if err := <-readDone; err != nil {
		return err
	}
	elapsed := time.Since(start)
	fmt.Printf("verified bytes=%d elapsed=%s throughput=%.3f Mbit/s sha256=%x\n", n, elapsed.Round(time.Millisecond), float64(n)*8/elapsed.Seconds()/1e6, sha256.Sum256(data))
	for _, stat := range writer.Stats() {
		fmt.Printf("path=%d worker_packets=%d\n", stat.PathID, stat.Packets)
	}
	fmt.Println("Experimental loopback lab only; one QUIC connection, two worker UDP sources. Not HTTP/3 or production-ready.")
	return nil
}
