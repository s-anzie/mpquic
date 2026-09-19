package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/stretchr/testify/require"
)

// Embedded nil methods deliberately panic if the builder bypasses the checked
// method or applies header protection after encryption has been rejected.
type exhaustedPacketSealer struct{ sealer }

func (exhaustedPacketSealer) Overhead() int { return 16 }
func (exhaustedPacketSealer) SealWithError(_, _ []byte, _ protocol.PacketNumber, _ []byte) ([]byte, error) {
	return nil, &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
}

func TestPacketPackerRejectsExhaustedSendBudget(t *testing.T) {
	p := &packetPacker{}
	buffer := getPacketBuffer()
	defer buffer.Release()
	buffer.Data = append(buffer.Data, 42)
	_, err := p.appendShortHeaderPacket(buffer, protocol.ParseConnectionID([]byte("cid")), 1,
		protocol.PacketNumberLen4, protocol.KeyPhaseZero, payload{}, 0, 1200,
		exhaustedPacketSealer{}, false, protocol.Version1)
	var transportError *qerr.TransportError
	require.ErrorAs(t, err, &transportError)
	require.Equal(t, qerr.AEADLimitReached, transportError.ErrorCode)
	// No packet was published and no packet-number manager was accessed.
	require.Equal(t, []byte{42}, buffer.Data)
}
