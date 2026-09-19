package handshake

import (
	"crypto/cipher"
	"crypto/fips140"
	"encoding/binary"

	"github.com/quic-go/quic-go/internal/protocol"
)

// createApplicationAEAD accepts the complete 96-bit QUIC packet nonce input.
// Long-header TLS wrappers continue accepting their original 64-bit input.
// Never copy a path-and-packet nonce into an eight-byte buffer: doing so drops
// the low 32 PN bits and repeats nonces for consecutive packets on a path.
func createApplicationAEAD(suite cipherSuite, trafficSecret []byte, v protocol.Version) cipher.AEAD {
	if !fips140.Enabled() {
		return &applicationNonceAEAD{createAEAD(suite, trafficSecret, v).(*xorNonceAEAD)}
	}
	keyLabel, ivLabel := hkdfLabelKeyV1, hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel, ivLabel = hkdfLabelKeyV2, hkdfLabelIVV2
	}
	key := hkdfExpandLabel(suite.Hash, trafficSecret, nil, keyLabel, suite.KeyLen)
	iv := hkdfExpandLabel(suite.Hash, trafficSecret, nil, ivLabel, suite.IVLen())
	return &pathNonceAEAD{suite: suite, key: key, iv: iv, paths: make(map[uint32]cipher.AEAD)}
}

type applicationNonceAEAD struct{ *xorNonceAEAD }

func (*applicationNonceAEAD) NonceSize() int { return protocol.PathAndPacketNumberLen }

func (a *applicationNonceAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if len(nonce) != protocol.PathAndPacketNumberLen {
		panic("invalid application nonce length")
	}
	return a.xorNonceAEAD.Seal(dst, nonce, plaintext, ad)
}

func (a *applicationNonceAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(nonce) != protocol.PathAndPacketNumberLen {
		panic("invalid application nonce length")
	}
	return a.xorNonceAEAD.Open(dst, nonce, ciphertext, ad)
}

// The FIPS TLS wrapper accepts eight-byte sequence numbers and enforces their
// monotonicity. Give each path a separate instance, XORing the path ID into the
// IV prefix; this is algebraically identical to XORing the full 96-bit nonce.
// Instances belong to one key epoch and are used only on the connection loop.
type pathNonceAEAD struct {
	suite   cipherSuite
	key, iv []byte
	paths   map[uint32]cipher.AEAD
}

func (*pathNonceAEAD) NonceSize() int { return protocol.PathAndPacketNumberLen }
func (*pathNonceAEAD) Overhead() int  { return 16 }

func (a *pathNonceAEAD) forNonce(nonce []byte) cipher.AEAD {
	if len(nonce) != protocol.PathAndPacketNumberLen {
		panic("invalid application nonce length")
	}
	id := binary.BigEndian.Uint32(nonce[:4])
	if existing := a.paths[id]; existing != nil {
		return existing
	}
	iv := append([]byte(nil), a.iv...)
	for i := range 4 {
		iv[i] ^= nonce[i]
	}
	instance := a.suite.AEAD(a.key, iv)
	a.paths[id] = instance
	return instance
}

func (a *pathNonceAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return a.forNonce(nonce).Seal(dst, nonce[4:], plaintext, ad)
}

func (a *pathNonceAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	return a.forNonce(nonce).Open(dst, nonce[4:], ciphertext, ad)
}

func createAEAD(suite cipherSuite, trafficSecret []byte, v protocol.Version) cipher.AEAD {
	keyLabel := hkdfLabelKeyV1
	ivLabel := hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel = hkdfLabelKeyV2
		ivLabel = hkdfLabelIVV2
	}
	key := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, keyLabel, suite.KeyLen)
	iv := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, ivLabel, suite.IVLen())
	return suite.AEAD(key, iv)
}

type longHeaderSealer struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	nonceBuf        [8]byte
}

var _ LongHeaderSealer = &longHeaderSealer{}

func newLongHeaderSealer(aead cipher.AEAD, headerProtector headerProtector) LongHeaderSealer {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderSealer{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

func (s *longHeaderSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(s.nonceBuf[:], uint64(pn))
	return s.aead.Seal(dst, s.nonceBuf[:], src, ad)
}

func (s *longHeaderSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (s *longHeaderSealer) Overhead() int {
	return s.aead.Overhead()
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	highestRcvdPN   protocol.PacketNumber // highest packet number received (which could be successfully unprotected)

	// use a single array to avoid allocations
	nonceBuf [8]byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector headerProtector) LongHeaderOpener {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

func (o *longHeaderOpener) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvdPN, wirePN)
}

func (o *longHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[:], uint64(pn))
	dec, err := o.aead.Open(dst, o.nonceBuf[:], src, ad)
	if err == nil {
		o.highestRcvdPN = max(o.highestRcvdPN, pn)
	} else {
		err = ErrDecryptionFailed
	}
	return dec, err
}

func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}
