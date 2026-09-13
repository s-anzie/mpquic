package wire

import (
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestPathNewConnectionIDLengths(t *testing.T) {
	for length := 0; length <= protocol.MaxConnIDLen+1; length++ {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			// The wire diagram specifies 8..160 bits, i.e. 1..20 bytes.
			data := append([]byte{1, 0, 0, byte(length)}, make([]byte, length+16)...)
			frame, n, err := parsePathNewConnectionIDFrame(data, protocol.Version1)
			if length == 0 || length > protocol.MaxConnIDLen {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, len(data), n)
			require.Equal(t, length, frame.ConnectionID.Len())
			encoded, err := frame.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, frame.Length(protocol.Version1), protocol.ByteCount(len(encoded)))
		})
	}
	_, err := (&PathNewConnectionIDFrame{}).Append(nil, protocol.Version1)
	require.Error(t, err)
}

func TestMultipathFrameRoundTrip(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	var token protocol.StatelessResetToken
	for i := range token {
		token[i] = byte(i)
	}

	frames := []Frame{
		&PathAbandonFrame{PathID: 1, ErrorCode: 0x3e75},
		&PathStatusAvailableFrame{PathID: 2, SequenceNumber: 4},
		&PathStatusBackupFrame{PathID: 3, SequenceNumber: 5},
		&PathNewConnectionIDFrame{PathID: 4, SequenceNumber: 6, RetirePriorTo: 2, ConnectionID: connID, StatelessResetToken: token},
		&PathRetireConnectionIDFrame{PathID: 5, SequenceNumber: 7},
		&MaxPathIDFrame{MaximumPathID: 8},
		&PathsBlockedFrame{MaximumPathID: 9},
		&PathCIDsBlockedFrame{PathID: 10, NextSequenceNumber: 11},
	}

	parser := NewFrameParser(false, false, false)
	parser.SetMultipath(true)
	for _, expected := range frames {
		data, err := expected.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, expected.Length(protocol.Version1), protocol.ByteCount(len(data)))

		typ, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)
		parsed, m, err := parser.ParseLessCommonFrame(typ, data[n:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(data)-n, m)
		require.Equal(t, expected, parsed)
	}
}

func TestMultipathFramesRequireNegotiation(t *testing.T) {
	data, err := (&MaxPathIDFrame{MaximumPathID: 1}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	parser := NewFrameParser(false, false, false)
	_, _, err = parser.ParseType(data, protocol.Encryption1RTT)
	require.Error(t, err)
}

func TestPathAckRoundTrip(t *testing.T) {
	pathID := uint64(2)
	expected := &AckFrame{
		PathID:    &pathID,
		AckRanges: []AckRange{{Smallest: 1, Largest: 3}},
		DelayTime: 2 * time.Millisecond,
	}
	data, err := expected.Append(nil, protocol.Version1)
	require.NoError(t, err)

	parser := NewFrameParser(false, false, false)
	parser.SetMultipath(true)
	typ, n, err := parser.ParseType(data, protocol.Encryption1RTT)
	require.NoError(t, err)
	parsed, m, err := parser.ParseAckFrame(typ, data[n:], protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data)-n, m)
	require.Equal(t, expected.PathID, parsed.PathID)
	require.Equal(t, expected.AckRanges, parsed.AckRanges)
}
