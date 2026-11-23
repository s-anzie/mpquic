package wire

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// FrameTypeExperimentalSourceFence is a private experimental identifier.
const FrameTypeExperimentalSourceFence FrameType = 0x3f4d505104

// ExperimentalSourceFenceFrame fences an exact source generation and path.
// Ack distinguishes a fence acknowledgement from a fence request.
type ExperimentalSourceFenceFrame struct {
	ID, Generation, PathID uint64
	Ack                    bool
}

func (f *ExperimentalSourceFenceFrame) valid() bool {
	return f.ID > 0 && f.Generation > 0 && f.PathID > 0 && f.PathID <= protocol.MaxPathID
}

func (f *ExperimentalSourceFenceFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if !f.valid() {
		return nil, errors.New("invalid source fence")
	}
	b = quicvarint.Append(b, uint64(FrameTypeExperimentalSourceFence))
	b = binary.BigEndian.AppendUint64(b, f.ID)
	b = binary.BigEndian.AppendUint64(b, f.Generation)
	b = binary.BigEndian.AppendUint64(b, f.PathID)
	var ack byte
	if f.Ack {
		ack = 1
	}
	return append(b, ack), nil
}

func (*ExperimentalSourceFenceFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeExperimentalSourceFence)) + 25)
}

func parseExperimentalSourceFenceFrame(b []byte) (*ExperimentalSourceFenceFrame, int, error) {
	if len(b) < 25 {
		return nil, 0, io.EOF
	}
	if b[24] > 1 {
		return nil, 0, errors.New("invalid source fence acknowledgement")
	}
	f := &ExperimentalSourceFenceFrame{
		ID:         binary.BigEndian.Uint64(b),
		Generation: binary.BigEndian.Uint64(b[8:]),
		PathID:     binary.BigEndian.Uint64(b[16:]),
		Ack:        b[24] == 1,
	}
	if !f.valid() {
		return nil, 0, errors.New("invalid source fence")
	}
	return f, 25, nil
}
