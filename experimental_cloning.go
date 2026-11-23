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
	"github.com/quic-go/quic-go/internal/wire"
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
	PathID               uint64
	SourceID, Generation uint64
	Control              *tls.Conn
	CertificateSHA256    [32]byte
	Autonomous           bool
}

// ExperimentalCloneSourceStats counts locally drained worker packets, including
// retransmissions. It is not an application-byte or client-delivery counter.
type ExperimentalCloneSourceStats struct {
	PathID       uint64
	Packets      uint64
	LastKeyEpoch uint64
	KeyRotations uint64
}

func (w *ExperimentalCloneWriter) Stats() []ExperimentalCloneSourceStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	stats := make([]ExperimentalCloneSourceStats, len(w.sources))
	for i, source := range w.sources {
		stats[i] = ExperimentalCloneSourceStats{PathID: source.PathID, Packets: w.sequences[i], LastKeyEpoch: w.epochs[i], KeyRotations: w.rotations[i]}
	}
	return stats
}

// ExperimentalCloneWriter sends retained stream portions through trusted workers.
// It serializes single-packet leases and waits for authenticated QUIC ACKs.
// This is a private-network prototype: no automatic NAT traversal or HTTP/3
// integration. Negotiated sources recover through permanent path retirement
// and client fencing. Failed fencing or application cancellation closes the
// whole connection. Workers share one trust domain. Do not use in production.
type ExperimentalCloneWriter struct {
	mu          sync.Mutex
	sourceMutex sync.Mutex
	conn        *Conn
	stream      *SendStream
	sources     []ExperimentalCloneSource
	sequences   []uint64
	epochs      []uint64
	rotations   []uint64
	failed      []bool
	additions   chan experimentalSourceAddition
	assignments map[uint64]int                    // connection-loop owned
	objects     map[uint64]*experimentalObjectJob // connection-loop owned
	crypto      handshake.ExperimentalRemoteCrypto
	pending     map[uint64]*clonedRange // connection-loop owned
	delivered   chan struct{}
	next        int
	closed      atomic.Bool
	closeOnce   sync.Once
}

// NewExperimentalCloneWriter requires the initial key update to have completed;
// first exchange ordinary stream traffic and retry readiness with a bounded ctx.
// It supports one writer per server connection, on one caller-owned send stream.
// With source offers negotiated, sources must name an accepted generation and
// its directly validated relay path. Without negotiation, legacy private-network
// paths still require client consent out of band.
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
	w.epochs, w.rotations = make([]uint64, len(sources)), make([]uint64, len(sources))
	w.failed, w.additions, w.assignments = make([]bool, len(sources)), make(chan experimentalSourceAddition, 8), make(map[uint64]int)
	w.objects = make(map[uint64]*experimentalObjectJob)
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
			if !c.experimentalSourceReady(s) {
				return ErrExperimentalCloningNotReady
			}
		}
		if err := c.prepareCloningAuthorityOnLoop(); err != nil {
			return err
		}
		for _, s := range sources {
			if s.Autonomous {
				if !c.sourceOffersNegotiated() {
					return ErrExperimentalSourceOffer
				}
				p := c.multipath.paths[s.PathID]
				p.experimentalWorkerControlled = true
				p.experimentalPacketRanges, p.experimentalRetryRanges = make(map[protocol.PacketNumber]uint64), make(map[uint64]bool)
			}
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
	return w.writeContent(ctx, data, nil, 0, len(data))
}

// WriteObject transmits verified chunks read at the workers. The primary needs
// only an authenticated manifest, never the object's content or file handle.
func (w *ExperimentalCloneWriter) WriteObject(ctx context.Context, manifest ExperimentalCloneObjectManifest) (int, error) {
	return w.WriteObjectRange(ctx, manifest, 0, manifest.Size())
}

// WriteObjectRange appends a chunk-aligned portion of an immutable object to the
// stream. The final portion may end at the object's non-aligned end.
func (w *ExperimentalCloneWriter) WriteObjectRange(ctx context.Context, manifest ExperimentalCloneObjectManifest, offset, length int64) (int, error) {
	if err := manifest.Validate(); err != nil {
		return 0, err
	}
	if offset < 0 || length < 0 || offset > manifest.Size() || length > manifest.Size()-offset || offset%1000 != 0 || length%1000 != 0 && offset+length != manifest.Size() {
		return 0, ErrExperimentalSourceOffer
	}
	return w.writeContent(ctx, nil, &manifest, int(offset), int(length))
}

func (w *ExperimentalCloneWriter) writeContent(ctx context.Context, data []byte, manifest *ExperimentalCloneObjectManifest, objectOffset, length int) (n int, err error) {
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
	type flight struct {
		id                 uint64
		end, source, tries int
		sent               time.Time
		done               bool
	}
	var flights []*flight
	queued := 0
	for n < length {
		admissionBlocked := false
		// Bound pending data or object descriptors independently of flow credit.
		for queued < length && len(flights) < 8 {
			chunkLength := min(1000, length-queued)
			index, selectErr := w.chooseSource(ctx, w.next%len(w.sources))
			if selectErr != nil {
				return n, selectErr
			}
			w.next++
			var rangeID uint64
			for {
				err = w.onLoop(ctx, func() error {
					var r *clonedRange
					var e error
					grant := w.conn.multipath.paths[w.sources[index].PathID].cloningGrant
					if manifest == nil {
						r, e = w.stream.delegateCloningRange(grant, data[queued:queued+chunkLength])
					} else {
						r, e = w.stream.delegateCloningReference(grant, uint64(chunkLength), manifest.hashes[(objectOffset+queued)/1000])
					}
					if e == nil {
						desc, _, readErr := r.read()
						if readErr != nil {
							return readErr
						}
						rangeID = desc.ID
						w.pending[desc.ID] = r
						w.assignments[desc.ID] = index
						if manifest != nil {
							id := manifest.ID()
							hash := desc.SHA256
							w.objects[desc.ID] = &experimentalObjectJob{ID: id[:], Hash: hash[:], Size: manifest.Size(), Offset: int64(objectOffset + queued), StreamID: int64(desc.Range.StreamID), StreamOffset: int64(desc.Range.Offset)}
						}
					}
					return e
				})
				if errors.Is(err, cloning.ErrPath) && w.conn.sourceOffersNegotiated() {
					index, err = w.chooseSource(ctx, (index+1)%len(w.sources))
					if err != nil {
						return n, err
					}
					continue
				}
				break
			}
			if errors.Is(err, ErrWouldBlock) {
				// Missing earlier bytes can prevent the peer from releasing
				// credit. Service their recovery before attempting admission again.
				admissionBlocked = true
				break
			}
			if err != nil {
				return n, err
			}
			if index, err = w.sendRange(ctx, index, rangeID); err != nil {
				return n, err
			}
			queued += chunkLength
			flights = append(flights, &flight{id: rangeID, end: queued, source: index, tries: 1, sent: time.Now()})
		}
		// Completion notifications are coalesced wakeups only. The loop-owned
		// ledger is authoritative, including out-of-order and late ACKs.
		err = w.onLoop(ctx, func() error {
			for _, f := range flights {
				f.done = w.pending[f.id] == nil
			}
			return nil
		})
		if err != nil {
			return n, err
		}
		for len(flights) > 0 && flights[0].done {
			n = flights[0].end
			flights = flights[1:]
		}
		for _, f := range flights {
			if f.done {
				continue
			}
			retry := time.Since(f.sent) >= time.Second
			if w.sources[f.source].Autonomous {
				if err = w.onLoop(ctx, func() error {
					source := w.sources[f.source]
					p := w.conn.multipath.paths[source.PathID]
					// Expired sources stop forwarding worker retry requests. Let
					// source selection fence them even with no fresh work to admit.
					retry = p == nil || p.abandoned || !w.conn.experimentalSourceReady(source)
					if p != nil {
						retry = retry || p.experimentalRetryRanges[f.id]
						delete(p.experimentalRetryRanges, f.id)
					}
					return nil
				}); err != nil {
					return n, err
				}
			}
			if !retry {
				continue
			}
			if f.tries == 8 {
				if !w.conn.sourceOffersNegotiated() {
					return n, errors.New("experimental clone delivery retry limit")
				}
				if err := w.fenceSource(ctx, f.source, nil); err != nil {
					return n, err
				}
				f.tries = 0
			}
			if f.source, err = w.sendRange(ctx, f.source, f.id); err != nil {
				return n, err
			}
			f.tries++
			f.sent = time.Now()
		}
		if n == length {
			break
		}
		if !admissionBlocked && queued < length && len(flights) < 8 {
			continue
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-w.delivered:
		case <-ctx.Done():
			timer.Stop()
			return n, ctx.Err()
		case <-w.conn.ctx.Done():
			timer.Stop()
			return n, context.Cause(w.conn.ctx)
		case <-timer.C:
		}
		timer.Stop()
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
		delete(w.assignments, id)
		delete(w.objects, id)
		for _, p := range w.conn.multipath.paths {
			delete(p.experimentalRetryRanges, id)
			for pn, rid := range p.experimentalPacketRanges {
				if rid == id {
					delete(p.experimentalPacketRanges, pn)
				}
			}
		}
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
	Object      *experimentalObjectJob `json:",omitempty"`
	Autonomous  bool                   `json:",omitempty"`
}

func (w *ExperimentalCloneWriter) dispatch(ctx context.Context, index int, rangeID uint64) (dispatchErr error) {
	source := w.sources[index]
	var snapshot *handshake.RemoteSealer
	defer func() {
		if snapshot != nil {
			if dispatchErr != nil && w.conn.sourceOffersNegotiated() && ctx.Err() == nil && w.conn.ctx.Err() == nil {
				if err := w.fenceSource(ctx, index, snapshot); err != nil {
					dispatchErr = errors.Join(errExperimentalFence, dispatchErr, err)
				}
			}
			snapshot.Close()
		}
	}()
	var payload []byte
	var nextKeyProbe time.Time
	job := experimentalCloneJob{Path: source.PathID, Sequence: w.sequences[index] + 1}
	for {
		err := w.onLoop(ctx, func() error {
			r := w.pending[rangeID]
			if r == nil {
				return nil
			} // ACK won the race with the retry timer
			if w.assignments[rangeID] != index {
				if err := r.lost(); err != nil {
					return err
				}
				var err error
				r, err = r.retry(w.conn.multipath.paths[source.PathID].cloningGrant)
				if err != nil {
					return err
				}
				w.pending[rangeID], w.assignments[rangeID] = r, index
			}
			if !w.crypto.ExperimentalRemoteReady() {
				// An automatic local update may have been carried only by an
				// ACK. Elicit new-phase peer traffic before admitting a worker.
				if now := time.Now(); !now.Before(nextKeyProbe) {
					w.conn.queueControlFrame(&wire.PingFrame{})
					nextKeyProbe = now.Add(25 * time.Millisecond)
				}
				return ErrWouldBlock
			}
			p := w.conn.multipath.paths[source.PathID]
			if !w.conn.experimentalSourceReady(source) {
				return ErrExperimentalSourceOffer
			}
			if p.abandoned || !p.serverValidated {
				return ErrExperimentalCloningNotReady
			}
			if !source.Autonomous && !w.conn.multipath.canSendOnPath(source.PathID, monotime.Now()) {
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
			fragments := []cloning.PacketFragment{{Attempt: r.attempt, Offset: desc.Range.Offset, Length: desc.Range.Length}}
			job.Object, job.Autonomous = w.objects[rangeID], source.Autonomous
			if job.Object != nil {
				err = w.conn.multipath.cloningAuthority.PrepareRemoteReferencePacket(p.cloningGrant, job.PN, fragments)
				payload = []byte{0} // content comes exclusively from the worker resolver
			} else {
				payload, err = w.conn.multipath.cloningAuthority.PrepareRemoteStreamPacket(p.cloningGrant, job.PN, fragments, w.conn.version)
			}
			if err != nil {
				return err
			}
			size := protocol.ByteCount(1 + cid.Len() + 4 + 16 + len(payload))
			if job.Object != nil {
				size = protocol.ByteCount(1 + cid.Len() + 4 + 16 + int(desc.Range.Length) + 24)
			}
			if err := w.conn.multipath.recordCloningPacket(source.PathID, job.PN, monotime.Now(), size); err != nil {
				return err
			}
			job.CID, job.Destination = cid.Bytes(), p.remoteAddr.String()
			if source.Autonomous {
				p.experimentalPacketRanges[job.PN] = rangeID
			}
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
	if job.Sequence > 1 && w.epochs[index] != job.Epoch {
		w.rotations[index]++
	}
	w.epochs[index] = job.Epoch
	return w.onLoop(ctx, func() error {
		if err := w.crypto.ReleaseExperimentalRemote(snapshot); err != nil {
			return err
		}
		if !w.crypto.ExperimentalRemoteReady() {
			w.conn.queueControlFrame(&wire.PingFrame{})
		}
		return nil
	})
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
		w.sourceMutex.Lock()
		sources := append([]ExperimentalCloneSource(nil), w.sources...)
		w.sourceMutex.Unlock()
		for _, s := range sources {
			s.Control.Close()
		}
		w.conn.CloseWithError(0x100, "experimental cloning stopped")
	})
}

// RotateKeys waits for the current write/drain, initiates a QUIC key update and
// waits for authenticated traffic in the new phase. Each worker receives the
// new derived keys in its next single-packet job. It does not reset packet numbers.
// A deadline or connection failure closes this experimental writer's connection.
func (w *ExperimentalCloneWriter) RotateKeys(ctx context.Context) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return net.ErrClosed
	}
	defer func() {
		if err != nil {
			w.fail()
		}
	}()
	for {
		err = w.onLoop(ctx, func() error {
			if err := w.crypto.RotateExperimentalKeys(); err != nil {
				w.conn.queueControlFrame(&wire.PingFrame{})
				return ErrWouldBlock
			}
			w.conn.queueControlFrame(&wire.PingFrame{})
			return nil
		})
		if !errors.Is(err, ErrWouldBlock) {
			if err != nil {
				return err
			}
			break
		}
		if err = waitCloneTick(ctx, w.conn.ctx, 25*time.Millisecond); err != nil {
			return err
		}
	}
	for {
		err = w.onLoop(ctx, func() error {
			if !w.crypto.ExperimentalRemoteReady() {
				return ErrWouldBlock
			}
			return nil
		})
		if !errors.Is(err, ErrWouldBlock) {
			return err
		}
		if err = waitCloneTick(ctx, w.conn.ctx, 5*time.Millisecond); err != nil {
			return err
		}
	}
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
func ServeExperimentalCloneWorker(ctx context.Context, control *tls.Conn, primaryCertificateSHA256 [32]byte, udp *net.UDPConn, allowDestination func(netip.AddrPort) bool, workerOptions ...*ExperimentalCloneWorkerOptions) error {
	var options *ExperimentalCloneWorkerOptions
	if len(workerOptions) != 0 {
		options = workerOptions[0]
	}
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
		meta, err := readCloneRecord(control, 1200)
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
		if job.Object != nil {
			if options == nil {
				sealer.Close()
				return ErrExperimentalSourceOffer
			}
			payload, err = job.Object.payload(options.Objects, protocol.Version1)
			if err != nil {
				sealer.Close()
				return err
			}
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
		if job.Autonomous {
			if options == nil || options.Controller == nil {
				return ErrExperimentalWorkerController
			}
			size := 1 + len(job.CID) + 4 + 16 + len(payload)
			if err := options.Controller.WaitSend(ctx, size); err != nil {
				return err
			}
			if err := options.Controller.OnSent(int64(job.PN), size, monotime.Now()); err != nil {
				options.Controller.CancelSend()
				return err
			}
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
