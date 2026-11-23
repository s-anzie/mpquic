package wire

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

const FrameTypeExperimentalSourceAccept FrameType = 0x3f4d505103

// ExperimentalSourceAcceptFrame acknowledges consent to an exact offer version.
// It is not evidence of return-path validation or worker readiness.
type ExperimentalSourceAcceptFrame struct{ ID, Generation, PathID uint64 }

func (f *ExperimentalSourceAcceptFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.ID == 0 || f.Generation == 0 || f.PathID > protocol.MaxPathID {
		return nil, errors.New("invalid source acceptance")
	}
	b = quicvarint.Append(b, uint64(FrameTypeExperimentalSourceAccept))
	b = binary.BigEndian.AppendUint64(b, f.ID)
	b = binary.BigEndian.AppendUint64(b, f.Generation)
	return binary.BigEndian.AppendUint64(b, f.PathID), nil
}
func (*ExperimentalSourceAcceptFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeExperimentalSourceAccept)) + 24)
}
func parseExperimentalSourceAcceptFrame(b []byte) (*ExperimentalSourceAcceptFrame, int, error) {
	if len(b) < 24 {
		return nil, 0, io.EOF
	}
	f := &ExperimentalSourceAcceptFrame{ID: binary.BigEndian.Uint64(b), Generation: binary.BigEndian.Uint64(b[8:]), PathID: binary.BigEndian.Uint64(b[16:])}
	if f.ID == 0 || f.Generation == 0 || f.PathID > protocol.MaxPathID {
		return nil, 0, errors.New("invalid source acceptance")
	}
	return f, 24, nil
}
