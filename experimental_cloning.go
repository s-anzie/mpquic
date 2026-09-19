package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// ExperimentalCloningALPN is for dedicated, mutually authenticated worker TLS
// channels. This prototype is not a standardized multipath extension.
const ExperimentalCloningALPN = handshake.ExperimentalRemoteALPN

var ErrExperimentalCloningNotReady = errors.New("experimental cloning requires warmed-up confirmed multipath, validated paths and an idle stream")

// ExperimentalCloneSource binds one already validated client path to one trusted
// worker. Control must have completed mutual TLS with ExperimentalCloningALPN.
// CertificateSHA256 is the expected worker leaf fingerprint from trusted policy.
// The writer takes exclusive ownership of Control on successful construction.
type ExperimentalCloneSource struct {
	PathID            uint64
	Control           *tls.Conn
	CertificateSHA256 [32]byte
}

// ExperimentalCloneSourceStats counts locally drained worker packets, including
// retransmissions. It is not an application-byte or client-delivery counter.
type ExperimentalCloneSourceStats struct {
	PathID  uint64
	Packets uint64
}

func (w *ExperimentalCloneWriter) Stats() []ExperimentalCloneSourceStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	stats := make([]ExperimentalCloneSourceStats, len(w.sources))
	for i, source := range w.sources {
		stats[i] = ExperimentalCloneSourceStats{PathID: source.PathID, Packets: w.sequences[i]}
	}
	return stats
}

// ExperimentalCloneWriter sends retained stream portions through trusted workers.
// It serializes single-packet leases and waits for authenticated QUIC ACKs.
// This is a private-network prototype: no source advertisement/NAT traversal,
// transparent worker failover, or HTTP/3 integration. Uncertain coordination or
// peer key update during a lease closes the WHOLE connection. Do not use in production.
type ExperimentalCloneWriter struct {
	mu        sync.Mutex
	conn      *Conn
	stream    *SendStream
	sources   []ExperimentalCloneSource
	sequences []uint64
	crypto    handshake.ExperimentalRemoteCrypto
	pending   map[uint64]*clonedRange // connection-loop owned
	delivered chan struct{}
	next      int
	closed    atomic.Bool
	closeOnce sync.Once
}

// NewExperimentalCloneWriter requires the initial key update to have completed;
// first exchange ordinary stream traffic and retry readiness with a bounded ctx.
// It supports one writer per server connection, on one caller-owned send stream.
// Sources must be opted into by the client out of band on a private network.
func (c *Conn) NewExperimentalCloneWriter(ctx context.Context, stream *SendStream, sources []ExperimentalCloneSource) (*ExperimentalCloneWriter, error) {
	if stream == nil || len(sources) == 0 || len(sources) > 8 {
		return nil, ErrExperimentalCloningNotReady
	}
	seen := make(map[uint64]bool)
	channels := make(map[*tls.Conn]bool)
	for _, s := range sources {
		if s.PathID == 0 || seen[s.PathID] || channels[s.Control] {
			return nil, ErrExperimentalCloningNotReady
		}
		if err := handshake.CheckRemoteTLS(s.Control, s.CertificateSHA256); err != nil {
			return nil, err
		}
		seen[s.PathID], channels[s.Control] = true, true
	}
	w := &ExperimentalCloneWriter{conn: c, stream: stream, sources: append([]ExperimentalCloneSource(nil), sources...), sequences: make([]uint64, len(sources)), pending: make(map[uint64]*clonedRange), delivered: make(chan struct{}, 1)}
	err := w.onLoop(ctx, func() error {
		cs, ok := c.cryptoStreamHandler.(handshake.ExperimentalRemoteCrypto)
		if !ok || !cs.ExperimentalRemoteReady() || c.experimentalCloneActive || c.perspective != protocol.PerspectiveServer || stream.flowController.connection != c.connFlowController || stream.supportsResetStreamAt {
			return ErrExperimentalCloningNotReady
		}
		stream.mutex.Lock()
		idle := stream.shutdownErr == nil && stream.resetErr == nil && !stream.finishedWriting && len(stream.dataForWriting) == 0 && stream.nextFrame == nil
		stream.mutex.Unlock()
		if !idle {
			return ErrExperimentalCloningNotReady
		}
		for _, s := range sources {
			p := c.multipath.paths[s.PathID]
			if p == nil || p.abandoned || !p.serverValidated || p.remoteAddr == nil || p.cloningRecovery != nil {
				return ErrExperimentalCloningNotReady
			}
			if _, ok := c.connIDManager.GetConnIDForPath(pathID(s.PathID)); !ok {
				return ErrExperimentalCloningNotReady
			}
		}
		if err := c.prepareCloningAuthorityOnLoop(); err != nil {
			return err
		}
		c.experimentalCloneActive, w.crypto = true, cs
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			// Admission may have won the race with context cancellation.
			c.CloseWithError(0x100, "experimental cloning initialization canceled")
		}
		return nil, err
	}
	return w, nil
}

func (w *ExperimentalCloneWriter) onLoop(ctx context.Context, action func() error) error {
	result := make(chan error, 1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.conn.ctx.Done():
		return context.Cause(w.conn.ctx)
	case w.conn.multipathActions <- func() {
		if err := ctx.Err(); err != nil {
			result <- err
		} else {
			result <- action()
		}
	}:
		w.conn.scheduleSending()
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-w.conn.ctx.Done():
		return context.Cause(w.conn.ctx)
	}
}

// WriteContext waits for delivery, not just worker dispatch. Calls are serialized.
// Close the original stream after success to send its FIN through the primary.
// Use ctx for deadlines; the stream's ordinary write deadline is not consulted.
func (w *ExperimentalCloneWriter) WriteContext(ctx context.Context, data []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return 0, net.ErrClosed
	}
	select {
	case w.stream.writeOnce <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-w.conn.ctx.Done():
		return 0, context.Cause(w.conn.ctx)
	}
	defer func() { <-w.stream.writeOnce }()
	defer func() {
		if err != nil {
			w.fail()
		}
	}()
	for n < len(data) {
		chunk := data[n:min(n+1000, len(data))]
		index := w.next % len(w.sources)
		w.next++
		var rangeID uint64
		for {
			err = w.onLoop(ctx, func() error {
				r, e := w.stream.delegateCloningRange(w.conn.multipath.paths[w.sources[index].PathID].cloningGrant, chunk)
				if e == nil {
					desc, _, readErr := r.read()
					if readErr != nil {
						return readErr
					}
					rangeID = desc.ID
					w.pending[desc.ID] = r
				}
				return e
			})
			if !errors.Is(err, ErrWouldBlock) {
				break
			}
			if err = waitCloneTick(ctx, w.conn.ctx, 5*time.Millisecond); err != nil {
				return n, err
			}
		}
		if err != nil {
			return n, err
		}
		for tries := 0; ; tries++ {
			if tries == 8 {
				return n, errors.New("experimental clone delivery retry limit")
			}
			if err = w.dispatch(ctx, index, rangeID); err != nil {
				return n, err
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-w.delivered:
				timer.Stop()
				n += len(chunk)
			case <-ctx.Done():
				timer.Stop()
				return n, ctx.Err()
			case <-w.conn.ctx.Done():
				timer.Stop()
				return n, context.Cause(w.conn.ctx)
			case <-timer.C:
				continue // retransmit identical bytes with a fresh PN
			}
			break
		}
	}
	return n, nil
}

func waitCloneTick(ctx, connection context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connection.Done():
		return context.Cause(connection)
	case <-t.C:
		return nil
	}
}

func (w *ExperimentalCloneWriter) completed(ids []uint64) {
	for _, id := range ids {
		r := w.pending[id]
		if r == nil {
			continue
		}
		delete(w.pending, id)
		s := r.stream
		s.mutex.Lock()
		if s.resetErr == nil && s.shutdownErr == nil {
			s.numOutstandingFrames--
		}
		done := s.isNewlyCompleted()
		s.mutex.Unlock()
		if done {
			s.sender.onStreamCompleted(s.streamID)
		}
		select {
		case w.delivered <- struct{}{}:
		default:
		}
	}
	for _, p := range w.conn.multipath.paths {
		if p.cloningRecovery != nil {
			_ = p.cloningAuthority.ForgetRemotePacketsBefore(p.cloningGrant, p.packetNumberSpace.largestAcknowledged+1)
		}
	}
}

type experimentalCloneJob struct {
	Sequence    uint64
	Path        uint64
	Epoch       uint64
	PN          protocol.PacketNumber
	CID         []byte
	Destination string
}

func (w *ExperimentalCloneWriter) dispatch(ctx context.Context, index int, rangeID uint64) error {
	source := w.sources[index]
	var snapshot *handshake.RemoteSealer
	defer func() {
		if snapshot != nil {
			snapshot.Close()
		}
	}()
	var payload []byte
	job := experimentalCloneJob{Path: source.PathID, Sequence: w.sequences[index] + 1}
	for {
		err := w.onLoop(ctx, func() error {
			r := w.pending[rangeID]
			if r == nil {
				return nil
			} // ACK won the race with the retry timer
			p := w.conn.multipath.paths[source.PathID]
			if p.abandoned || !p.serverValidated {
				return ErrExperimentalCloningNotReady
			}
			if !w.conn.multipath.canSendOnPath(source.PathID, monotime.Now()) {
				return ErrWouldBlock
			}
			cid, ok := w.conn.connIDManager.GetConnIDForPath(pathID(source.PathID))
			if !ok {
				return ErrExperimentalCloningNotReady
			}
			desc, _, err := r.read()
			if errors.Is(err, cloning.ErrAttempt) {
				r, err = r.retry(p.cloningGrant)
				if err == nil {
					desc, _, err = r.read()
					w.pending[desc.ID] = r
				}
			}
			if err != nil {
				return err
			}
			snapshot, job.Epoch, job.PN, err = w.crypto.AcquireExperimentalRemote(w.conn.multipath.cloningAuthority, p.cloningGrant, cid)
			if err != nil {
				return err
			}
			if p.cloningRecovery == nil {
				if err := w.conn.multipath.attachCloningRecovery(source.PathID, w.conn.multipath.cloningAuthority, p.cloningGrant, w.completed); err != nil {
					return err
				}
			}
			payload, err = w.conn.multipath.cloningAuthority.PrepareRemoteStreamPacket(p.cloningGrant, job.PN,
				[]cloning.PacketFragment{{Attempt: r.attempt, Offset: desc.Range.Offset, Length: desc.Range.Length}}, w.conn.version)
			if err != nil {
				return err
			}
			size := protocol.ByteCount(1 + cid.Len() + 4 + 16 + len(payload))
			if err := w.conn.multipath.recordCloningPacket(source.PathID, job.PN, monotime.Now(), size); err != nil {
				return err
			}
			job.CID, job.Destination = cid.Bytes(), p.remoteAddr.String()
			return nil
		})
		if !errors.Is(err, ErrWouldBlock) {
			if err != nil {
				return err
			}
			break
		}
		if err := waitCloneTick(ctx, w.conn.ctx, 5*time.Millisecond); err != nil {
			return err
		}
	}
	if snapshot == nil {
		return nil
	}
	stop := context.AfterFunc(ctx, func() { source.Control.Close() })
	defer stop()
	stopConnection := context.AfterFunc(w.conn.ctx, func() { source.Control.Close() })
	defer stopConnection()
	if err := source.Control.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	meta, err := json.Marshal(job)
	if err != nil {
		return err
	}
	if err := writeCloneRecord(source.Control, meta); err != nil {
		return err
	}
	if err := snapshot.WriteTLS(source.Control, source.CertificateSHA256); err != nil {
		return err
	}
	if err := writeCloneRecord(source.Control, payload); err != nil {
		return err
	}
	var receipt [8]byte
	if _, err := io.ReadFull(source.Control, receipt[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint64(receipt[:]) != job.Sequence {
		return errors.New("invalid experimental worker drain receipt")
	}
	w.sequences[index] = job.Sequence
	return w.onLoop(ctx, func() error { return w.crypto.ReleaseExperimentalRemote(snapshot) })
}

func writeCloneRecord(w io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > 1500 {
		return errors.New("invalid experimental clone record size")
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
	b = append(b, data...)
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func readCloneRecord(r io.Reader, limit uint16) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(h[:])
	if n == 0 || n > limit {
		return nil, errors.New("invalid experimental clone record size")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func (w *ExperimentalCloneWriter) fail() {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		for _, s := range w.sources {
			s.Control.Close()
		}
		w.conn.CloseWithError(0x100, "experimental cloning stopped")
	})
}

// Close stops the prototype and closes the whole connection. Send and receive
// any final application confirmation before calling Close.
func (w *ExperimentalCloneWriter) Close() error {
	w.fail()
	return nil
}

// ServeExperimentalCloneWorker owns a preauthenticated TLS channel until exit.
// udp must be dedicated to this path. allowDestination is mandatory policy from
// the worker operator, not from an untrusted request. The caller owns udp.
// A drain receipt confirms only that the one-packet key window was exhausted and
// closed; it is never proof that the QUIC client received the data.
func ServeExperimentalCloneWorker(ctx context.Context, control *tls.Conn, primaryCertificateSHA256 [32]byte, udp *net.UDPConn, allowDestination func(netip.AddrPort) bool) error {
	if control != nil {
		defer control.Close()
	}
	if err := handshake.CheckRemoteTLS(control, primaryCertificateSHA256); err != nil {
		return err
	}
	if udp == nil || allowDestination == nil {
		return ErrExperimentalCloningNotReady
	}
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	var sender *handshake.RemotePathSender
	defer func() {
		if sender != nil {
			sender.Close()
		}
	}()
	var destination netip.AddrPort
	for sequence := uint64(1); sequence != 0; sequence++ {
		if err := control.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return err
		}
		meta, err := readCloneRecord(control, 512)
		if err != nil {
			return err
		}
		var job experimentalCloneJob
		if err := json.Unmarshal(meta, &job); err != nil {
			return err
		}
		addr, err := netip.ParseAddrPort(job.Destination)
		if err != nil || !addr.IsValid() || !allowDestination(addr) || job.Sequence != sequence || (sender != nil && addr != destination) {
			return ErrExperimentalCloningNotReady
		}
		if len(job.CID) == 0 || len(job.CID) > 20 {
			return ErrExperimentalCloningNotReady
		}
		cid := protocol.ParseConnectionID(job.CID)
		sealer, err := handshake.ReadRemoteSealer(control, primaryCertificateSHA256, job.Path, protocol.KeyPhase(job.Epoch), cid)
		if err != nil {
			return err
		}
		if err := sealer.ValidateExperimentalWindow(job.PN); err != nil {
			sealer.Close()
			return err
		}
		payload, err := readCloneRecord(control, 1200)
		if err != nil {
			sealer.Close()
			return err
		}
		if sender == nil {
			sender, err = handshake.NewRemotePathSender(sealer, udp, net.UDPAddrFromAddrPort(addr))
			destination = addr
		} else {
			err = sender.Resume(sealer)
		}
		if err != nil {
			sealer.Close()
			return err
		}
		pn, err := sender.WritePayload(payload)
		if err != nil {
			return err
		}
		boundary, err := sender.Pause()
		if err != nil || pn != job.PN || boundary.End != pn+1 {
			return ErrExperimentalCloningNotReady
		}
		if _, err := control.Write(binary.BigEndian.AppendUint64(nil, sequence)); err != nil {
			return err
		}
	}
	return errors.New("experimental worker sequence exhausted")
}
