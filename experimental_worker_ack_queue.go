package quic

import (
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// Coalesce authenticated ACK evidence while TLS is busy. Never overwrite an
// older ACK with a newer one: the union preserves delivery and congestion credit.
func (r *experimentalSourceRelay) queueWorkerACK(f *wire.AckFrame) error {
	r.ackMutex.Lock()
	if len(r.acks) == 0 || f.LargestAcked() >= protocol.PacketNumber(r.acks[len(r.acks)-1].Largest) {
		r.ackDelay = f.DelayTime
	}
	for _, a := range f.AckRanges {
		r.acks = append(r.acks, ExperimentalWorkerACKRange{Smallest: int64(a.Smallest), Largest: int64(a.Largest)})
	}
	slices.SortFunc(r.acks, func(a, b ExperimentalWorkerACKRange) int {
		if a.Smallest < b.Smallest {
			return -1
		}
		if a.Smallest > b.Smallest {
			return 1
		}
		return 0
	})
	merged := r.acks[:0]
	for _, a := range r.acks {
		if len(merged) > 0 && a.Smallest <= merged[len(merged)-1].Largest+1 {
			merged[len(merged)-1].Largest = max(merged[len(merged)-1].Largest, a.Largest)
		} else {
			merged = append(merged, a)
		}
	}
	r.acks = merged
	tooMany := len(r.acks) > experimentalWorkerHistoryLimit
	r.ackMutex.Unlock()
	if tooMany {
		return ErrExperimentalSourceOffer
	}
	select {
	case r.ackWake <- struct{}{}:
	default:
	}
	return nil
}

func (r *experimentalSourceRelay) flushWorkerACKs() error {
	r.ackMutex.Lock()
	acks, delay := r.acks, r.ackDelay
	r.acks = nil
	r.ackMutex.Unlock()
	for len(acks) > 0 {
		n := min(16, len(acks))
		packetDelay := time.Duration(0)
		if n == len(acks) {
			packetDelay = delay
		}
		if err := writeSourceRelayPacket(r.control, sourceRelayPacket{feedback: &experimentalWorkerFeedback{ACKs: acks[:n], Delay: packetDelay}}); err != nil {
			return err
		}
		acks = acks[n:]
	}
	return nil
}
