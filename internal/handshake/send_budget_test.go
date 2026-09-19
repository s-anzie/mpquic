package handshake

import (
	"crypto/tls"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/stretchr/testify/require"
)

func TestSharedSendBudget(t *testing.T) {
	for _, suite := range cipherSuites {
		t.Run(tls.CipherSuiteName(suite.ID), func(t *testing.T) {
			s, _, authority := remoteTestEndpoints(t, suite, protocol.Version1)
			grant, err := authority.GrantPath(1, "worker")
			require.NoError(t, err)
			s.numSentWithCurrentKey = maxSendPacketsPerEpoch - 3
			prepared, err := s.prepareRemoteSealer(authority, grant, 2, protocol.ParseConnectionID([]byte("cid")))
			require.NoError(t, err)
			defer prepared.Close()
			_, err = s.SealWithError(nil, []byte{1}, 10, nil)
			require.NoError(t, err)
			require.Equal(t, maxSendPacketsPerEpoch, s.numSentWithCurrentKey)
			dst := []byte{7, 8, 9}
			_, err = s.SealWithError(dst[:0], []byte{1}, 11, nil)
			var transportError *qerr.TransportError
			require.ErrorAs(t, err, &transportError)
			require.Equal(t, qerr.AEADLimitReached, transportError.ErrorCode)
			require.Equal(t, []byte{7, 8, 9}, dst)
			require.Equal(t, maxSendPacketsPerEpoch, s.numSentWithCurrentKey)
			_, err = s.prepareRemoteSealer(authority, grant, 1, protocol.ParseConnectionID([]byte("cid")))
			require.ErrorIs(t, err, ErrRemoteSealer)
			// Normal key-phase selection, before header construction, can recover.
			require.Equal(t, protocol.KeyPhaseOne, s.KeyPhase())
			_, err = s.SealWithError(nil, []byte{1}, 12, nil)
			require.NoError(t, err)
			require.Equal(t, uint64(1), s.numSentWithCurrentKey)
		})
	}
}

func TestRemoteBootstrapInvalidatedByKeyUpdateOrClose(t *testing.T) {
	for _, closeConnection := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "close"}[closeConnection], func(t *testing.T) {
			s, _, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
			grant, err := authority.GrantPath(1, "worker")
			require.NoError(t, err)
			prepared, err := s.prepareRemoteSealer(authority, grant, 2, protocol.ParseConnectionID([]byte("cid")))
			require.NoError(t, err)
			if closeConnection {
				s.invalidateRemoteEpoch()
			} else {
				s.rollKeys()
			}
			server, _, pin := remoteTLS(t)
			require.ErrorIs(t, prepared.WriteTLS(server, pin), ErrRemoteSealer)
			require.True(t, prepared.closed)
			require.Equal(t, remoteSendKeys{}, prepared.keys)
			if !closeConnection {
				next, err := s.prepareRemoteSealer(authority, grant, 1, prepared.cid)
				require.NoError(t, err)
				require.Equal(t, protocol.PacketNumber(2), next.next)
				worker := transferRemote(t, next)
				_, _, err = worker.SealPacket([]byte{1})
				require.NoError(t, err)
			}
		})
	}
}
