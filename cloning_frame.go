package quic

import (
	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// frame prepares one fragment for trusted packet assembly on the assigned path.
// It neither sends nor registers a packet: the caller must still enforce path
// validation, pacing, congestion control and packet-number allocation. It must
// attach the returned handler to the actual sent packet, never to a worker receipt.
// offset is an absolute stream offset; length is a positive payload byte count.
func (r *clonedRange) frame(pathID, offset, length uint64) (ackhandler.StreamFrame, error) {
	d, data, err := r.read()
	if err != nil {
		return ackhandler.StreamFrame{}, err
	}
	if pathID != d.PathID {
		return ackhandler.StreamFrame{}, cloning.ErrPath
	}
	if length == 0 || offset < d.Range.Offset || offset-d.Range.Offset >= d.Range.Length || length > d.Range.Length-(offset-d.Range.Offset) {
		return ackhandler.StreamFrame{}, cloning.ErrLimit
	}
	start := offset - d.Range.Offset
	// Copy only the fragment so a packet does not retain the entire range buffer.
	payload := append([]byte(nil), data[start:start+length]...)
	return ackhandler.StreamFrame{
		Frame: &wire.StreamFrame{
			StreamID:       d.Range.StreamID,
			Offset:         protocol.ByteCount(offset),
			Data:           payload,
			DataLenPresent: true,
		},
		Handler: &clonedFrameHandler{rangeState: r, offset: offset, length: length},
	}, nil
}

// clonedFrameHandler captures immutable byte evidence at packet assembly time.
// The callback argument may have been recycled or changed by packet bookkeeping;
// it must not be used to expand the acknowledged interval or choose another stream.
// Fragment splitting must happen before creating this handler. A repacketized
// fragment needs a new handler, not a copy covering the original larger interval.
type clonedFrameHandler struct {
	rangeState     *clonedRange
	offset, length uint64
}

var _ ackhandler.FrameHandler = (*clonedFrameHandler)(nil)

func (h *clonedFrameHandler) OnAcked(wire.Frame) {
	// Cancellation and connection closure make delayed callbacks harmless. The
	// ledger deduplicates ACKs, including ACKs for an earlier delivery attempt.
	_ = h.rangeState.acknowledge(h.offset, h.length)
}

func (h *clonedFrameHandler) OnLost(wire.Frame) {
	// Loss makes the retained range eligible for explicit reassignment. It does
	// not refund credit, complete the stream, or schedule an unvalidated sender.
	_ = h.rangeState.lost()
}
