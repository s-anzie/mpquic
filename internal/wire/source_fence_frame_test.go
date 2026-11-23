package wire

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestExperimentalSourceFenceWire(t *testing.T) {
	for _, ack := range []bool{false, true} {
		for _, value := range []uint64{1, ^uint64(0)} {
			f := &ExperimentalSourceFenceFrame{ID: value, Generation: value, PathID: protocol.MaxPathID, Ack: ack}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.EqualValues(t, len(b), f.Length(protocol.Version1))
			typ, n, err := quicvarint.Parse(b)
			require.NoError(t, err)
			require.EqualValues(t, 0x3f4d505104, typ)
			require.Len(t, b[n:], 25)
			require.Equal(t, value, binary.BigEndian.Uint64(b[n:]))
			require.Equal(t, value, binary.BigEndian.Uint64(b[n+8:]))
			require.EqualValues(t, protocol.MaxPathID, binary.BigEndian.Uint64(b[n+16:]))
			expectedAck := byte(0)
			if ack {
				expectedAck = 1
			}
			require.Equal(t, expectedAck, b[n+24])
			p := NewFrameParser(true, true, true)
			_, _, err = p.ParseType(b, protocol.Encryption1RTT)
			require.Error(t, err)
			p.SetExperimentalSourceOffers(true)
			for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
				_, _, err = p.ParseType(b, level)
				require.Error(t, err)
			}
			ft, headerLen, err := p.ParseType(b, protocol.Encryption1RTT)
			require.NoError(t, err)
			require.Equal(t, FrameTypeExperimentalSourceFence, ft)
			require.Equal(t, n, headerLen)
			got, bodyLen, err := p.ParseLessCommonFrame(ft, append(append([]byte(nil), b[n:]...), 0xff), protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, f, got)
			require.Equal(t, 25, bodyLen)
			encoded, err := got.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, b, encoded)
			for i := 0; i < 25; i++ {
				_, consumed, err := parseExperimentalSourceFenceFrame(b[n : n+i])
				require.ErrorIs(t, err, io.EOF)
				require.Zero(t, consumed)
				_, _, err = p.ParseLessCommonFrame(ft, b[n:n+i], protocol.Version1)
				require.Error(t, err)
			}
			p.SetExperimentalSourceOffers(false)
			_, _, err = p.ParseType(b, protocol.Encryption1RTT)
			require.Error(t, err)
		}
	}
}

func TestExperimentalSourceFenceBounds(t *testing.T) {
	for _, f := range []ExperimentalSourceFenceFrame{
		{ID: 1, Generation: 1, PathID: 1},
		{ID: ^uint64(0), Generation: ^uint64(0), PathID: protocol.MaxPathID},
		{ID: 0, Generation: 1, PathID: 1},
		{ID: 1, Generation: 0, PathID: 1},
		{ID: 1, Generation: 1, PathID: 0},
		{ID: 1, Generation: 1, PathID: protocol.MaxPathID + 1},
		{ID: 1, Generation: 1, PathID: ^uint64(0)},
	} {
		body := binary.BigEndian.AppendUint64(nil, f.ID)
		body = binary.BigEndian.AppendUint64(body, f.Generation)
		body = binary.BigEndian.AppendUint64(body, f.PathID)
		body = append(body, 0)
		valid := f.ID > 0 && f.Generation > 0 && f.PathID > 0 && f.PathID <= protocol.MaxPathID
		_, appendErr := f.Append(nil, protocol.Version1)
		got, n, parseErr := parseExperimentalSourceFenceFrame(body)
		if valid {
			require.NoError(t, appendErr)
			require.NoError(t, parseErr)
			require.Equal(t, &f, got)
			require.Equal(t, 25, n)
		} else {
			require.Error(t, appendErr)
			require.Error(t, parseErr)
			require.Nil(t, got)
			require.Zero(t, n)
		}
	}
}

func TestExperimentalSourceFenceRejectsNoncanonicalAck(t *testing.T) {
	f := &ExperimentalSourceFenceFrame{ID: 1, Generation: 2, PathID: 3}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	body := b[len(b)-25:]
	p := NewFrameParser(false, false, false)
	p.SetExperimentalSourceOffers(true)
	for ack := 2; ack <= 255; ack++ {
		body[24] = byte(ack)
		_, n, err := parseExperimentalSourceFenceFrame(body)
		require.Error(t, err)
		require.Zero(t, n)
		_, _, err = p.ParseLessCommonFrame(FrameTypeExperimentalSourceFence, body, protocol.Version1)
		require.Error(t, err)
	}
}

func FuzzExperimentalSourceFence(f *testing.F) {
	for _, ack := range []bool{false, true} {
		b, _ := (&ExperimentalSourceFenceFrame{ID: 1, Generation: 2, PathID: 3, Ack: ack}).Append(nil, protocol.Version1)
		f.Add(b[len(b)-25:])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, n, err := parseExperimentalSourceFenceFrame(b)
		if err != nil {
			return
		}
		require.Equal(t, 25, n)
		encoded, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, b[:n], encoded[len(encoded)-25:])
	})
}
