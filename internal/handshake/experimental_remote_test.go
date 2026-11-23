package handshake

import (
	"crypto/tls"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestExperimentalRemoteRetiredLeaseDuringPeerUpdate(t *testing.T) {
	s, c, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	h := &cryptoSetup{aead: s}
	s.rollKeys()
	c.rollKeys()
	_, err := c.Open(nil, s.Seal(nil, []byte{1}, 0, nil), monotime.Now(), 0, s.keyPhase.Bit(), nil)
	require.NoError(t, err)
	_, err = s.Open(nil, c.Seal(nil, []byte{1}, 0, nil), monotime.Now(), 0, c.keyPhase.Bit(), nil)
	require.NoError(t, err)
	grant, err := authority.GrantPath(1, "worker")
	require.NoError(t, err)
	lease, _, _, err := h.AcquireExperimentalRemote(authority, grant, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	defer lease.Close()
	require.ErrorIs(t, h.RetireExperimentalRemote(lease), ErrRemoteSealer)
	c.rollKeys()
	ciphertext := c.Seal(nil, []byte{2}, 1, nil)
	_, err = s.Open(nil, ciphertext, monotime.Now(), 1, c.keyPhase.Bit(), nil)
	require.ErrorIs(t, err, ErrRemoteKeyUpdatePending)
	require.NoError(t, authority.RetirePath(grant))
	require.NoError(t, h.RetireExperimentalRemote(lease))
	require.ErrorIs(t, h.ReleaseExperimentalRemote(lease), ErrRemoteSealer, "stale drain must not release a future lease")
	require.Equal(t, protocol.KeyPhase(2), s.keyPhase)
	_, err = s.Open(nil, ciphertext, monotime.Now(), 1, c.keyPhase.Bit(), nil)
	require.NoError(t, err)
	require.True(t, h.ExperimentalRemoteReady())
	_, _, err = authority.ReservePacketWindow(grant, 1)
	require.Error(t, err, "retired path can never allocate another number")
}

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
	invalidBefore := s.invalidPacketCount
	packetBefore := s.highestRcvdPN
	_, err = s.Open(nil, ciphertext, monotime.Now(), 1, c.keyPhase.Bit(), nil)
	require.ErrorIs(t, err, ErrRemoteKeyUpdatePending)
	require.Equal(t, invalidBefore, s.invalidPacketCount, "authenticated deferred packet is not an integrity failure")
	require.Equal(t, packetBefore, s.highestRcvdPN, "deferred packet must not advance receive history")
	worker := transferRemote(t, lease)
	_, _, err = worker.SealPacket([]byte{1})
	require.NoError(t, err, "current worker window must remain valid until drain")
	worker.Close()
	require.Equal(t, protocol.KeyPhase(1), s.keyPhase)
	require.ErrorIs(t, h.ReleaseExperimentalRemote(&RemoteSealer{}), ErrRemoteSealer)
	require.NoError(t, h.ReleaseExperimentalRemote(lease))
	require.Equal(t, protocol.KeyPhase(2), s.keyPhase)
	require.False(t, h.ExperimentalRemoteReady())
	plain, err := s.Open(nil, ciphertext, monotime.Now(), 1, c.keyPhase.Bit(), nil)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, plain)
	require.True(t, h.ExperimentalRemoteReady())
	next, newEpoch, nextPN, err := h.AcquireExperimentalRemote(authority, grant, protocol.ParseConnectionID([]byte("cid")))
	require.NoError(t, err)
	require.Equal(t, uint64(2), newEpoch)
	require.Equal(t, protocol.PacketNumber(1), nextPN)
	updated := transferRemote(t, next)
	require.Equal(t, worker.keys.hp, [32]byte{}, "old worker explicit keys were cleared")
	_, _, err = updated.SealPacket([]byte{1})
	require.NoError(t, err)
	updated.Close()
	require.NoError(t, h.ReleaseExperimentalRemote(next))
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
