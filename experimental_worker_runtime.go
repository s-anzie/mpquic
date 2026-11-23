package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// ExperimentalCloneWorkerOptions is shared by the job and relay services for
// exactly one path. Controller owns pacing, congestion, loss and PTO decisions;
// the primary retains connection-wide authorization and ACK delivery accounting.
type ExperimentalCloneWorkerOptions struct {
	Controller *ExperimentalWorkerController
	Objects    ExperimentalCloneObjectResolver
}

type experimentalWorkerFeedback struct {
	ACKs  []ExperimentalWorkerACKRange `json:"a,omitempty"`
	Delay time.Duration                `json:"d,omitempty"`
	Retry *ExperimentalWorkerRetry     `json:"r,omitempty"`
}

func (c *Conn) forwardExperimentalWorkerACK(f *wire.AckFrame) error {
	if f.PathID == nil {
		return nil
	}
	p := c.multipath.paths[*f.PathID]
	if p == nil || p.abandoned || !p.experimentalWorkerControlled || p.experimentalRelay == nil {
		return nil
	}
	if err := p.experimentalRelay.queueWorkerACK(f); err != nil {
		return c.abandonFailedPath(*f.PathID, err)
	}
	return nil
}

func (r *experimentalSourceRelay) handleWorkerRetry(f *experimentalWorkerFeedback) error {
	if f.Retry == nil || len(f.ACKs) != 0 || f.Retry.PacketNumber < 0 {
		return ErrExperimentalSourceOffer
	}
	return (&ExperimentalCloneWriter{conn: r.conn}).onLoop(r.conn.ctx, func() error {
		e := r.conn.experimentalSources.entries[r.id]
		if !r.current(e.pathID) {
			return nil
		}
		p := r.conn.multipath.paths[e.pathID]
		if p == nil || p.abandoned || !p.experimentalWorkerControlled {
			return nil
		}
		pn := protocol.PacketNumber(f.Retry.PacketNumber)
		// Retire transport history even after another attempt completed the
		// range and removed its retry mapping. Otherwise a stale pending entry
		// can prevent the retention floor from advancing indefinitely.
		if !f.Retry.PTO {
			p.recordExperimentalWorkerLoss(pn)
		}
		if id, exists := p.experimentalPacketRanges[pn]; exists {
			p.experimentalRetryRanges[id] = true
		}

		return nil
	})
}

func (p *multipathPathState) recordExperimentalWorkerLoss(pn protocol.PacketNumber) {
	if p.cloningRecovery == nil || pn < p.cloningRecovery.boundary {
		return
	}
	if packet, ok := p.sentPackets[pn]; ok {
		p.bytesInFlight -= min(p.bytesInFlight, packet.size)
		for _, frame := range packet.frames {
			if frame.Handler != nil && frame.Frame != nil {
				frame.Handler.OnLost(frame.Frame)
			}
		}
		delete(p.sentPackets, pn)
	}
}

func workerRelayFeedback(ctx context.Context, control relayFeedbackWriter, controller *ExperimentalWorkerController) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-controller.Events():
		}
		for {
			retry, ok := controller.NextRetry()
			if !ok {
				break
			}
			if err := control(&experimentalWorkerFeedback{Retry: &retry}); err != nil {
				return err
			}
		}
	}
}

type relayFeedbackWriter func(*experimentalWorkerFeedback) error

// Object dispatch carries metadata only. Primary authorization binds the
// expected chunk hash to the immutable manifest; no payload travels via primary.
type experimentalObjectJob struct {
	ID           []byte
	Hash         []byte
	Size, Offset int64
	StreamID     int64
	StreamOffset int64
}

type experimentalObjectBuffer struct {
	*bytes.Reader
	offset int64
}

func (b experimentalObjectBuffer) ReadAt(p []byte, off int64) (int, error) {
	return b.Reader.ReadAt(p, off-b.offset)
}

// One source read serves a whole contiguous dispatch, but every chunk still
// verifies its own primary-authorized digest before any packet is emitted.
func (j *experimentalObjectJob) batchPayloads(resolver ExperimentalCloneObjectResolver, bodies [][]byte, version protocol.Version) ([][]byte, error) {
	if len(bodies) == 1 {
		p, e := j.payload(resolver, version)
		return [][]byte{p}, e
	}
	if resolver == nil || len(j.ID) != 32 || j.Offset < 0 || j.Offset%1000 != 0 || j.Offset >= j.Size || len(bodies) < 1 || len(bodies) > experimentalCloneBatchPackets {
		return nil, ErrExperimentalSourceOffer
	}
	length := min(int64(len(bodies)*1000), j.Size-j.Offset)
	if (length+999)/1000 != int64(len(bodies)) {
		return nil, ErrExperimentalSourceOffer
	}
	r, err := resolver.ResolveCloneObject(ExperimentalCloneObjectID(j.ID))
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrExperimentalSourceOffer
	}
	data := make([]byte, int(length))
	n, err := r.ReadAt(data, j.Offset)
	if n != len(data) || err != nil && !errors.Is(err, io.EOF) {
		return nil, io.ErrUnexpectedEOF
	}
	buffer := experimentalObjectBuffer{Reader: bytes.NewReader(data), offset: j.Offset}
	cached := ExperimentalCloneObjectResolverFunc(func(ExperimentalCloneObjectID) (io.ReaderAt, error) { return buffer, nil })
	for i, hash := range bodies {
		chunk := *j
		chunk.Offset += int64(i * 1000)
		chunk.StreamOffset += int64(i * 1000)
		chunk.Hash = hash
		bodies[i], err = chunk.payload(cached, version)
		if err != nil {
			return nil, err
		}
	}
	return bodies, nil
}

func (j *experimentalObjectJob) payload(resolver ExperimentalCloneObjectResolver, version protocol.Version) ([]byte, error) {
	if resolver == nil || len(j.ID) != 32 || len(j.Hash) != 32 || j.Offset < 0 || j.Offset%ExperimentalCloneObjectChunkSize != 0 || j.Offset >= j.Size || j.StreamID < 0 || j.StreamID > int64(protocol.MaxStreamID) || j.StreamOffset < 0 || j.StreamOffset > int64(protocol.MaxByteCount)-1000 {
		return nil, ErrExperimentalSourceOffer
	}
	if _, err := experimentalCloneObjectCount(j.Size); err != nil {
		return nil, err
	}
	r, err := resolver.ResolveCloneObject(ExperimentalCloneObjectID(j.ID))
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("nil source object")
	}
	b := make([]byte, min(int64(ExperimentalCloneObjectChunkSize), j.Size-j.Offset))
	n, err := r.ReadAt(b, j.Offset)
	if n != len(b) || err != nil && !errors.Is(err, io.EOF) {
		return nil, io.ErrUnexpectedEOF
	}
	if sha256.Sum256(b) != [32]byte(j.Hash) {
		return nil, errors.New("source object chunk integrity mismatch")
	}
	return (&wire.StreamFrame{StreamID: protocol.StreamID(j.StreamID), Offset: protocol.ByteCount(j.StreamOffset), DataLenPresent: true, Data: b}).Append(nil, version)
}

func encodeWorkerFeedback(f *experimentalWorkerFeedback) ([]byte, error) {
	if f == nil || len(f.ACKs) > 16 || (len(f.ACKs) == 0) == (f.Retry == nil) {
		return nil, ErrExperimentalSourceOffer
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append([]byte{1}, b...), nil
}

func decodeWorkerFeedback(b []byte) (*experimentalWorkerFeedback, error) {
	var f experimentalWorkerFeedback
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if _, err := encodeWorkerFeedback(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

func applyWorkerFeedback(options *ExperimentalCloneWorkerOptions, f *experimentalWorkerFeedback) error {
	if options == nil || options.Controller == nil || f.Retry != nil {
		return ErrExperimentalSourceOffer
	}
	return options.Controller.OnACK(f.ACKs, f.Delay, monotime.Now())
}
