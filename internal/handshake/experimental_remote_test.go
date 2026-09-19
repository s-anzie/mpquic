package handshake

import (
	"crypto/tls"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/stretchr/testify/require"
)

func TestExperimentalRemoteLeaseFencesKeyUpdates(t *testing.T) {
	s, c, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	h := &cryptoSetup{aead: s}
	require.False(t, h.ExperimentalRemoteReady())
	s.rollKeys()
	c.rollKeys()
	_, err := c.Open(nil, s.Seal(nil, []byte{1}, 0, nil), monotime.Now(), 0, s.keyPhase.Bit(), nil)
	require.NoError(t, err)
	_, err = s.Open(nil, c.Seal(nil, []byte{1}, 0, nil), monotime.Now(), 0, c.keyPhase.Bit(), nil)
	require.NoError(t, err)
	require.True(t, h.ExperimentalRemoteReady())
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	lease, epoch, pn, err := h.AcquireExperimentalRemote(authority, grant, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	defer lease.Close()
	require.Equal(t, uint64(1), epoch)
	require.Zero(t, pn)
	require.False(t, h.ExperimentalRemoteReady())
	_, _, _, err = h.AcquireExperimentalRemote(authority, grant, protocol.ParseConnectionID([]byte("cid")))
	require.ErrorIs(t, err, ErrRemoteSealer)
	reset := SetKeyUpdateInterval(1)
	defer reset()
	require.Equal(t, protocol.KeyPhaseOne, s.KeyPhase(), "primary must wait for drain")
	c.rollKeys()
	ciphertext := c.Seal(nil, []byte{1}, 1, nil)
	corrupt := append([]byte(nil), ciphertext...)
	corrupt[len(corrupt)-1] ^= 1
	_, err = s.Open(nil, corrupt, monotime.Now(), 1, c.keyPhase.Bit(), nil)
	require.ErrorIs(t, err, ErrDecryptionFailed)
	_, err = s.Open(nil, ciphertext, monotime.Now(), 1, c.keyPhase.Bit(), nil)
	var transportError *qerr.TransportError
	require.ErrorAs(t, err, &transportError)
	require.Equal(t, qerr.InternalError, transportError.ErrorCode)
	require.Equal(t, protocol.KeyPhase(1), s.keyPhase)
	require.ErrorIs(t, h.ReleaseExperimentalRemote(&RemoteSealer{}), ErrRemoteSealer)
	require.NoError(t, h.ReleaseExperimentalRemote(lease))
	require.ErrorIs(t, h.ReleaseExperimentalRemote(lease), ErrRemoteSealer)
}

func TestExperimentalRemoteRejectsProtocolConfusionAndWideWindows(t *testing.T) {
	server, _, pin := remoteTLS(t) // bare snapshot ALPN, not framed jobs
	require.ErrorIs(t, CheckRemoteTLS(server, pin), ErrRemoteSealer)
	s, _, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	for _, count := range []uint64{2, 1} {
		p, err := s.prepareRemoteSealer(authority, grant, count, protocol.ParseConnectionID([]byte("cid")))
		require.NoError(t, err)
		first := p.next
		worker := transferRemote(t, p)
		if count == 2 {
			require.ErrorIs(t, worker.ValidateExperimentalWindow(first), ErrRemoteSealer)
			continue
		}
		require.ErrorIs(t, worker.ValidateExperimentalWindow(first+1), ErrRemoteSealer)
		require.NoError(t, worker.ValidateExperimentalWindow(first))
		_, _, err = worker.SealPacket([]byte{1})
		require.NoError(t, err)
		require.ErrorIs(t, worker.ValidateExperimentalWindow(first), ErrRemoteSealer)
	}
}
