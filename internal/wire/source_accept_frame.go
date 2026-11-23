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
type ExperimentalSourceAcceptFrame struct{ ID, Generation uint64 }

func (f *ExperimentalSourceAcceptFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.ID == 0 || f.Generation == 0 {
		return nil, errors.New("invalid source acceptance")
	}
	b = quicvarint.Append(b, uint64(FrameTypeExperimentalSourceAccept))
	b = binary.BigEndian.AppendUint64(b, f.ID)
	return binary.BigEndian.AppendUint64(b, f.Generation), nil
}
func (*ExperimentalSourceAcceptFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeExperimentalSourceAccept)) + 16)
}
func parseExperimentalSourceAcceptFrame(b []byte) (*ExperimentalSourceAcceptFrame, int, error) {
	if len(b) < 16 {
		return nil, 0, io.EOF
	}
	f := &ExperimentalSourceAcceptFrame{ID: binary.BigEndian.Uint64(b), Generation: binary.BigEndian.Uint64(b[8:])}
	if f.ID == 0 || f.Generation == 0 {
		return nil, 0, errors.New("invalid source acceptance")
	}
	return f, 16, nil
}
