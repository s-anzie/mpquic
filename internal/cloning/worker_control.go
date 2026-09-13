package cloning

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const (
	WorkerControlALPN = "mpquic-worker-control/1"
	MaxWorkerQueue    = 16
	MaxWorkerControls = 16
	workerIOTimeout   = 5 * time.Second
	workerIdleTimeout = 30 * time.Second

	controlWelcome    byte = 1
	controlAssignment byte = 2
	controlFailed     byte = 3
	controlStopped    byte = 4
	controlHeartbeat  byte = 5
	controlHeaderSize      = 9                      // kind and per-direction sequence number
	maxWorkerMessage       = controlHeaderSize + 16 // failure: range ID and generation
)

var (
	ErrWorkerIdentity = errors.New("worker TLS identity or protocol not authorized")
	ErrWorkerProtocol = errors.New("invalid worker control message")
	ErrWorkerBusy     = errors.New("worker control queue full")
	ErrWorkerStopped  = errors.New("worker control session stopped")
)

// WorkerControl is an experimental, one-path control channel, not a QUIC packet
// sender or a copy of the connection. All mutable fields below are protected by
// authority.mu. The TLS connection has one reader and one writer. A channel
// failure permanently retires its path; it never restores counters or refunds
// credit. Already issued bytes cannot be recalled from a remote worker. The
// handle must not be copied after construction.
type WorkerControl struct {
	authority *Authority
	path      *Path
	conn      *tls.Conn
	queue     chan *Attempt
	pending   map[uint64]*Attempt
	done      chan struct{}
	exited    chan struct{}
	closed    bool
	err       error
}

// BindWorker takes exclusive ownership of a dedicated raw connection, even on
// failure, and performs a server-side mutual TLS handshake. The caller supplies
// a server configuration with RequireAndVerifyClientCert and the expected leaf
// certificate fingerprint from trusted policy, NOT from a worker message.
// The path must already be client-established and reserved for this worker.
// This method does not transfer the primary's live packet sender or TLS keys.
// It must not be used to attach a worker while another sender owns that path.
// The caller also bounds concurrent handshakes at the listener level.
func (a *Authority) BindWorker(ctx context.Context, raw net.Conn, config *tls.Config, path *Path, expected [32]byte) (*WorkerControl, error) {
	if raw == nil {
		return nil, ErrWorkerIdentity
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	// Do not allow a ClientHello callback to replace the checked authentication
	// policy. The caller can select a configuration before binding the channel.
	if config == nil || config.ClientAuth != tls.RequireAndVerifyClientCert || config.GetConfigForClient != nil {
		return nil, ErrWorkerIdentity
	}
	conn := tls.Server(raw, config.Clone())
	handshakeCtx, cancel := context.WithTimeout(ctx, workerIOTimeout)
	defer cancel()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.DidResume || state.NegotiatedProtocol != WorkerControlALPN || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != expected {
		return nil, ErrWorkerIdentity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if err := a.checkPath(path); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	if path.worker != nil {
		a.mu.Unlock()
		return nil, ErrPath
	}
	if a.workerCount >= MaxWorkerControls {
		a.mu.Unlock()
		return nil, ErrWorkerBusy
	}
	w := &WorkerControl{authority: a, path: path, conn: conn, queue: make(chan *Attempt, MaxWorkerQueue), pending: make(map[uint64]*Attempt), done: make(chan struct{}), exited: make(chan struct{})}
	path.worker = w
	a.workerCount++
	a.mu.Unlock()
	success = true
	readerDone, writerDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(readerDone); w.readLoop() }()
	go func() { defer close(writerDone); w.writeLoop() }()
	go func() {
		select {
		case <-ctx.Done():
			w.stop(ctx.Err())
		case <-w.done:
		}
		<-readerDone
		<-writerDone
		close(w.exited)
	}()
	return w, nil
}

// Queue offers an already reserved range without blocking the connection loop.
// Admission does not mean sent or delivered. On ErrWorkerBusy the caller keeps
// the existing reservation and may retry admission; it must not reserve again.
func (w *WorkerControl) Queue(t *Attempt) error {
	a := w.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if w.closed || w.path.worker != w {
		return ErrWorkerStopped
	}
	if err := a.checkPath(w.path); err != nil {
		return err
	}
	if !w.currentAttempt(t) {
		return ErrAttempt
	}
	// Drop terminal metadata so a long-lived path cannot accumulate references.
	for id, previous := range w.pending {
		if !w.currentAttempt(previous) {
			delete(w.pending, id)
		}
	}
	id := t.rangeState.id
	if w.pending[id] != nil {
		return ErrAttempt
	}
	if len(w.pending) >= MaxPendingDelegations {
		return ErrWorkerBusy
	}
	select {
	case w.queue <- t:
		w.pending[id] = t
		return nil
	default:
		return ErrWorkerBusy
	}
}

// currentAttempt requires authority.mu and does not copy retained payload.
func (w *WorkerControl) currentAttempt(t *Attempt) bool {
	d, err := w.authority.checkAttempt(t)
	return err == nil && t.path == w.path && !d.done && !d.retryable && t.generation == d.generation
}

func (w *WorkerControl) Done() <-chan struct{} { return w.exited }

func (w *WorkerControl) Err() error {
	w.authority.mu.Lock()
	defer w.authority.mu.Unlock()
	return w.err
}

func (w *WorkerControl) Close() { w.stop(ErrWorkerStopped) }

func (w *WorkerControl) stop(err error) {
	w.authority.mu.Lock()
	if w.closed || w.path.worker != w {
		w.authority.mu.Unlock()
		return
	}
	w.closed, w.err, w.path.retired = true, err, true
	w.path.worker = nil
	w.authority.workerCount--
	w.pending = nil
drain:
	for {
		select {
		case <-w.queue:
		default:
			break drain
		}
	}
	close(w.done)
	w.authority.mu.Unlock()
	// Abort the underlying transport to interrupt both I/O directions without
	// waiting for a TLS close-notify write to an unresponsive peer.
	_ = w.conn.NetConn().Close()
}

func (w *WorkerControl) readLoop() {
	for sequence := uint64(1); ; sequence++ {
		if sequence == 0 {
			w.stop(ErrWorkerProtocol)
			return
		}
		if err := w.conn.SetReadDeadline(time.Now().Add(workerIdleTimeout)); err != nil {
			w.stop(err)
			return
		}
		kind, body, err := readControlMessage(w.conn, sequence, maxWorkerMessage)
		if err != nil {
			w.stop(err)
			return
		}
		switch {
		case kind == controlHeartbeat && len(body) == 0:
		case kind == controlStopped && len(body) == 0:
			w.Close()
			return
		case kind == controlFailed && len(body) == 16:
			w.failed(binary.BigEndian.Uint64(body), binary.BigEndian.Uint64(body[8:]))
		default:
			// In particular there is no worker-to-primary "delivered" operation.
			w.stop(ErrWorkerProtocol)
			return
		}
	}
}

func (w *WorkerControl) failed(id, generation uint64) {
	a := w.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if w.closed || a.checkPath(w.path) != nil {
		return
	}
	t := w.pending[id]
	if t == nil || t.generation != generation {
		return // duplicate, unknown or obsolete failure is not a state transition
	}
	if w.currentAttempt(t) {
		t.rangeState.retryable = true
	}
	delete(w.pending, id)
}

func (w *WorkerControl) writeLoop() {
	sequence := uint64(1)
	if err := w.write(controlWelcome, sequence, binary.BigEndian.AppendUint64(nil, w.path.id)); err != nil {
		w.stop(err)
		return
	}
	for {
		select {
		case <-w.done:
			return
		case t := <-w.queue:
			d, data, err := w.authority.ReadAttempt(t)
			if err != nil {
				continue // canceled, retried or retired while waiting in the queue
			}
			sequence++
			if sequence == 0 {
				w.stop(ErrWorkerProtocol)
				return
			}
			body := make([]byte, 0, 80+len(data))
			for _, value := range []uint64{d.ID, d.Generation, d.PathID, uint64(d.Range.StreamID), d.Range.Offset, d.Range.Length} {
				body = binary.BigEndian.AppendUint64(body, value)
			}
			body = append(body, d.SHA256[:]...)
			body = append(body, data...)
			if err := w.write(controlAssignment, sequence, body); err != nil {
				w.stop(err)
				return
			}
		}
	}
}

func (w *WorkerControl) write(kind byte, sequence uint64, body []byte) error {
	if err := w.conn.SetWriteDeadline(time.Now().Add(workerIOTimeout)); err != nil {
		return err
	}
	return writeControlMessage(w.conn, kind, sequence, body)
}

// Length is checked before allocation. TLS protects this dedicated channel;
// strict per-direction sequencing also rejects application-level replay/gaps.
func readControlMessage(r io.Reader, expected uint64, maximum uint32) (byte, []byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n < controlHeaderSize || n > maximum {
		return 0, nil, ErrWorkerProtocol
	}
	buf := make([]byte, int(n))
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	if expected == 0 || binary.BigEndian.Uint64(buf[1:9]) != expected {
		return 0, nil, ErrWorkerProtocol
	}
	return buf[0], buf[9:], nil
}

func writeControlMessage(w io.Writer, kind byte, sequence uint64, body []byte) error {
	if sequence == 0 || len(body) > 80+MaxDelegationBytes {
		return ErrWorkerProtocol
	}
	buf := make([]byte, 0, 4+controlHeaderSize+len(body))
	buf = binary.BigEndian.AppendUint32(buf, uint32(controlHeaderSize+len(body)))
	buf = append(buf, kind)
	buf = binary.BigEndian.AppendUint64(buf, sequence)
	buf = append(buf, body...)
	n, err := w.Write(buf)
	if err == nil && n != len(buf) {
		return io.ErrShortWrite
	}
	return err
}
