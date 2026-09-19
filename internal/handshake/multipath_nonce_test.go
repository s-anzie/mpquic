package handshake

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestMultipathNoncePreservesEveryPacketNumberBit(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, suite := range cipherSuites {
			t.Run(fmt.Sprintf("%s/%x", version, suite.ID), func(t *testing.T) {
				secret := make([]byte, suite.Hash.Size())
				server := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, version)
				client := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, version)
				server.SetWriteKey(suite, secret)
				client.SetReadKey(suite, secret)
				server.SetMultipath(true)
				client.SetMultipath(true)
				require.NoError(t, server.SetPathID(7))
				require.NoError(t, client.SetPathID(7))
				seen := make(map[string]bool)
				for _, pn := range []protocol.PacketNumber{0, 1, 2, 255, 256, 1<<32 - 1, 1 << 32, 1<<32 + 1, protocol.MaxPathAndPacketNumber} {
					sealed := server.Seal(nil, []byte("same plaintext"), pn, []byte("same header"))
					require.False(t, seen[string(sealed)], "ciphertext collision for distinct packet number %d", pn)
					seen[string(sealed)] = true
					opened, err := client.Open(nil, sealed, monotime.Now(), pn, protocol.KeyPhaseZero, []byte("same header"))
					require.NoError(t, err)
					require.Equal(t, []byte("same plaintext"), opened)
					_, err = client.Open(nil, sealed, monotime.Now(), pn^1, protocol.KeyPhaseZero, []byte("same header"))
					require.ErrorIs(t, err, ErrDecryptionFailed, "changing one PN bit must fail authentication")
				}
			})
		}
	}
}

func TestApplicationNonceMatchesIndependentAEAD(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("raw reference GCM is not available in FIPS mode")
	}
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		for _, suite := range cipherSuites {
			t.Run(fmt.Sprintf("%s/%x", version, suite.ID), func(t *testing.T) {
				secret := bytes.Repeat([]byte{0x5a}, suite.Hash.Size())
				keyLabel, ivLabel := "quic key", "quic iv"
				if version == protocol.Version2 {
					keyLabel, ivLabel = "quicv2 key", "quicv2 iv"
				}
				key := hkdfExpandLabel(suite.Hash, secret, nil, keyLabel, suite.KeyLen)
				iv := hkdfExpandLabel(suite.Hash, secret, nil, ivLabel, 12)
				var reference cipher.AEAD
				if suite.ID == tls.TLS_CHACHA20_POLY1305_SHA256 {
					var err error
					reference, err = chacha20poly1305.New(key)
					require.NoError(t, err)
				} else {
					block, err := aes.NewCipher(key)
					require.NoError(t, err)
					reference, err = cipher.NewGCM(block)
					require.NoError(t, err)
				}
				a := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, version)
				a.SetWriteKey(suite, secret)
				a.SetMultipath(true)
				for _, path := range []uint64{0, 1, 256, protocol.MaxPathID} {
					require.NoError(t, a.SetPathID(path))
					for _, pn := range []protocol.PacketNumber{0, 1, 1<<32 + 1, protocol.MaxPathAndPacketNumber} {
						var nonce [12]byte
						binary.BigEndian.PutUint32(nonce[:4], uint32(path))
						binary.BigEndian.PutUint64(nonce[4:], uint64(pn))
						for i := range nonce {
							nonce[i] ^= iv[i]
						}
						want := reference.Seal(nil, nonce[:], []byte("payload"), []byte("header"))
						require.Equal(t, want, a.Seal(nil, []byte("payload"), pn, []byte("header")))
					}
				}
				// Disable multipath after selecting a nonzero path: ordinary QUIC
				// must zero the path prefix and remain wire-compatible.
				a.SetMultipath(false)
				nonce := bytes.Clone(iv)
				nonce[11] ^= 42
				require.Equal(t, reference.Seal(nil, nonce, []byte("payload"), []byte("header")), a.Seal(nil, []byte("payload"), 42, []byte("header")))
			})
		}
	}
}

func TestApplicationNonceAcrossKeyUpdates(t *testing.T) {
	for _, suite := range cipherSuites {
		t.Run(fmt.Sprintf("%x", suite.ID), func(t *testing.T) {
			a := newUpdatableAEAD(utils.NewRTTStats(), nil, utils.DefaultLogger, protocol.Version1)
			secret := bytes.Repeat([]byte{0x42}, suite.Hash.Size())
			a.SetWriteKey(suite, secret)
			a.SetReadKey(suite, secret)
			a.SetMultipath(true)
			seen := make(map[string]bool)
			for epoch := range 3 {
				for _, path := range []uint64{0, 1, 2} {
					require.NoError(t, a.SetPathID(path))
					for i := range 2 {
						pn := protocol.PacketNumber(epoch*2 + i)
						sealed := a.Seal(nil, []byte("payload"), pn, nil)
						require.False(t, seen[string(sealed)])
						seen[string(sealed)] = true
						nonce, err := protocol.PathAndPacketNumber(path, pn)
						require.NoError(t, err)
						opened, err := a.rcvAEAD.Open(nil, nonce[:], sealed, nil)
						require.NoError(t, err)
						require.Equal(t, []byte("payload"), opened)
					}
				}
				a.rollKeys()
			}
		})
	}
}

func TestApplicationNonceRejectsTruncation(t *testing.T) {
	a := createApplicationAEAD(getCipherSuite(tls.TLS_AES_128_GCM_SHA256), make([]byte, 32), protocol.Version1)
	require.Equal(t, 12, a.NonceSize())
	for _, size := range []int{0, 8, 11, 13} {
		require.Panics(t, func() { a.Seal(nil, make([]byte, size), []byte("payload"), nil) })
		require.Panics(t, func() { _, _ = a.Open(nil, make([]byte, size), make([]byte, 16), nil) })
	}
	// Initial/Handshake/0-RTT retain their original eight-byte input contract.
	long := createAEAD(getCipherSuite(tls.TLS_AES_128_GCM_SHA256), make([]byte, 32), protocol.Version1)
	require.Equal(t, 8, long.NonceSize())
}
