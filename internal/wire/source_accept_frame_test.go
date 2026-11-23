package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestExperimentalSourceAcceptanceWire(t *testing.T) {
	f := &ExperimentalSourceAcceptFrame{ID: 1, Generation: 2, PathID: 7}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.EqualValues(t, len(b), f.Length(protocol.Version1))
	p := NewFrameParser(false, false, false)
	_, _, err = p.ParseType(b, protocol.Encryption1RTT)
	require.Error(t, err)
	p.SetExperimentalSourceOffers(true)
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
		_, _, err = p.ParseType(b, level)
		require.Error(t, err)
	}
	typ, n, err := p.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	got, l, err := p.ParseLessCommonFrame(typ, b[n:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, got)
	require.Equal(t, len(b), n+l)
	for i := 0; i < 24; i++ {
		_, _, err := parseExperimentalSourceAcceptFrame(b[n : n+i])
		require.Error(t, err)
	}
	_, _, err = parseExperimentalSourceAcceptFrame(make([]byte, 24))
	require.Error(t, err)
}
