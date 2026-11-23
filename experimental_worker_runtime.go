package quic

import (
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
	for i := 0; i < len(f.AckRanges); i += 16 {
		feedback := &experimentalWorkerFeedback{Delay: f.DelayTime}
		for _, r := range f.AckRanges[i:min(i+16, len(f.AckRanges))] {
			feedback.ACKs = append(feedback.ACKs, ExperimentalWorkerACKRange{Smallest: int64(r.Smallest), Largest: int64(r.Largest)})
		}
		select {
		case p.experimentalRelay.queue <- sourceRelayPacket{feedback: feedback}:
		default:
			return c.abandonFailedPath(*f.PathID, errors.New("worker ACK feedback queue full"))
		}
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
		id, exists := p.experimentalPacketRanges[protocol.PacketNumber(f.Retry.PacketNumber)]
		if exists {
			p.experimentalRetryRanges[id] = true
		}
		return nil
	})
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
