package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const RemoteSealerALPN = "mpquic-send-bootstrap/1"
const remoteSealerSize = 135

// Conservative ceiling shared by all supported suites and all sending paths.
const maxSendPacketsPerEpoch uint64 = 1 << 23

var ErrRemoteSealer = errors.New("invalid, exhausted or unavailable remote sealer")

// Derived send material only: no receive keys, TLS master secret or future
// traffic secret is transferred. Header protection remains fixed across epochs.
type remoteSendKeys struct {
	key, hp [32]byte
	iv      [12]byte
}

func (*remoteSendKeys) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted send keys]") }

func deriveRemoteSendKeys(s cipherSuite, secret []byte, v protocol.Version) *remoteSendKeys {
	m := &remoteSendKeys{}
	m.update(s, secret, v)
	copy(m.hp[:], hkdfExpandLabel(s.Hash, secret, nil, hkdfHeaderProtectionLabel(v), s.KeyLen))
	return m
}

func (m *remoteSendKeys) update(s cipherSuite, secret []byte, v protocol.Version) {
	keyLabel, ivLabel := hkdfLabelKeyV1, hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel, ivLabel = hkdfLabelKeyV2, hkdfLabelIVV2
	}
	clear(m.key[:])
	copy(m.key[:], hkdfExpandLabel(s.Hash, secret, nil, keyLabel, s.KeyLen))
	copy(m.iv[:], hkdfExpandLabel(s.Hash, secret, nil, ivLabel, 12))
}

// RemoteSealer owns one finite, non-reusable packet-number window. The object
// must not be copied. It neither validates paths nor provides congestion/loss
// control. Shared keys still imply one trust domain, not cryptographic isolation.
type RemoteSealer struct {
	mu         sync.Mutex
	self       *RemoteSealer
	keys       remoteSendKeys
	suite      cipherSuite
	version    protocol.Version
	epoch      protocol.KeyPhase
	path       uint64
	next, end  protocol.PacketNumber
	cid        protocol.ConnectionID
	aead       cipher.AEAD
	hp         headerProtector
	closed     bool
	owned      bool
	used       bool
	authority  *cloning.Authority
	grant      *cloning.Path
	epochValid *atomic.Bool
}

// The crypto loop invalidates admission without waiting for bootstrap network I/O.
// This cannot revoke material already exported to another process.
func (a *updatableAEAD) invalidateRemoteEpoch() {
	if a.remoteEpochValid != nil {
		a.remoteEpochValid.Store(false)
		a.remoteEpochValid = nil
	}
}

func (*RemoteSealer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted remote sealer]")
}

// prepareRemoteSealer is intentionally not exposed on cryptoSetup/Conn yet.
// Call on the crypto loop AFTER quiescing the local path sender. The whole
// window is charged immediately against the current key's usage, never refunded.
// Live use also requires an epoch barrier across workers and sent-history handoff.
func (a *updatableAEAD) prepareRemoteSealer(authority *cloning.Authority, path *cloning.Path, count uint64, cid protocol.ConnectionID) (*RemoteSealer, error) {
	if authority == nil || !a.multipath || !a.handshakeConfirmed || a.remoteSendKeys == nil || cid.Len() == 0 || count == 0 || count > cloning.MaxRemotePacketWindow || a.numSentWithCurrentKey > maxSendPacketsPerEpoch || count > maxSendPacketsPerEpoch-a.numSentWithCurrentKey {
		return nil, ErrRemoteSealer
	}
	id, first, err := authority.ReservePacketWindow(path, count)
	if err != nil {
		return nil, err
	}
	p := &RemoteSealer{keys: *a.remoteSendKeys, suite: a.suite, version: a.version, epoch: a.keyPhase, path: id, next: first, end: first + protocol.PacketNumber(count), cid: cid}
	p.self = p
	p.authority, p.grant = authority, path
	if a.remoteEpochValid == nil {
		a.remoteEpochValid = &atomic.Bool{}
		a.remoteEpochValid.Store(true)
	}
	p.epochValid = a.remoteEpochValid
	a.numSentWithCurrentKey += count
	return p, nil
}

func checkRemoteTLS(c *tls.Conn, pin [32]byte) error {
	if c == nil {
		return ErrRemoteSealer
	}
	s := c.ConnectionState()
	if !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != RemoteSealerALPN || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || sha256.Sum256(s.PeerCertificates[0].Raw) != pin {
		return ErrRemoteSealer
	}
	return nil
}

// WriteTLS transfers a snapshot once on a dedicated, already authenticated TLS
// connection. Caller provides the expected peer certificate from trusted policy.
// A failed/partial write burns the window; there is no plaintext Marshal API.
// It must not share the framed WorkerControl connection.
func (p *RemoteSealer) WriteTLS(c *tls.Conn, pin [32]byte) error {
	if err := checkRemoteTLS(c, pin); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.closed || p.aead != nil {
		return ErrRemoteSealer
	}
	p.closed = true
	defer p.clearKeys()
	if p.epochValid == nil || !p.epochValid.Load() {
		return ErrRemoteSealer
	}
	if err := p.authority.ValidateRemotePath(p.grant); err != nil {
		return err
	}
	b := make([]byte, 0, remoteSealerSize)
	defer func() { clear(b) }()
	b = binary.BigEndian.AppendUint16(b, p.suite.ID)
	b = binary.BigEndian.AppendUint32(b, uint32(p.version))
	for _, v := range []uint64{uint64(p.epoch), p.path, uint64(p.next), uint64(p.end)} {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	b = append(b, byte(p.cid.Len()))
	var cid [20]byte
	copy(cid[:], p.cid.Bytes())
	b = append(b, cid[:]...)
	b = append(b, p.keys.key[:]...)
	b = append(b, p.keys.iv[:]...)
	b = append(b, p.keys.hp[:]...)
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	n, err := c.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

// ReadRemoteSealer binds a dedicated bootstrap channel to an expected path and
// full key epoch. Only a fresh reserved window may initialize a worker; never
// restore a consumed snapshot after restart. The live connection must enforce
// authenticated ownership, epoch barriers and restart fencing before calling it.
func ReadRemoteSealer(c *tls.Conn, pin [32]byte, path uint64, epoch protocol.KeyPhase, cid protocol.ConnectionID) (*RemoteSealer, error) {
	if err := checkRemoteTLS(c, pin); err != nil {
		return nil, err
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	var b [remoteSealerSize]byte
	defer clear(b[:])
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return nil, err
	}
	p, err := decodeRemoteSealer(b[:], path, epoch)
	if err != nil {
		return nil, err
	}
	if p.cid != cid {
		p.Close()
		return nil, ErrRemoteSealer
	}
	return p, nil
}

func decodeRemoteSealer(b []byte, path uint64, epoch protocol.KeyPhase) (*RemoteSealer, error) {
	if len(b) != remoteSealerSize {
		return nil, ErrRemoteSealer
	}
	id := binary.BigEndian.Uint16(b[:2])
	if id != tls.TLS_AES_128_GCM_SHA256 && id != tls.TLS_AES_256_GCM_SHA384 && (id != tls.TLS_CHACHA20_POLY1305_SHA256 || fips140.Enabled()) {
		return nil, ErrRemoteSealer
	}
	p := &RemoteSealer{suite: getCipherSuite(id), version: protocol.Version(binary.BigEndian.Uint32(b[2:6])), epoch: protocol.KeyPhase(binary.BigEndian.Uint64(b[6:14])), path: binary.BigEndian.Uint64(b[14:22]), next: protocol.PacketNumber(binary.BigEndian.Uint64(b[22:30])), end: protocol.PacketNumber(binary.BigEndian.Uint64(b[30:38]))}
	if (p.version != protocol.Version1 && p.version != protocol.Version2) || path == 0 || path > protocol.MaxPathID || p.path != path || p.epoch != epoch || p.next < 0 || p.end <= p.next || p.end-1 > protocol.MaxPathAndPacketNumber || p.end-p.next > cloning.MaxRemotePacketWindow || b[38] == 0 || b[38] > 20 {
		return nil, ErrRemoteSealer
	}
	p.cid = protocol.ParseConnectionID(b[39 : 39+int(b[38])])
	copy(p.keys.key[:], b[59:91])
	copy(p.keys.iv[:], b[91:103])
	copy(p.keys.hp[:], b[103:135])
	p.self = p
	if fips140.Enabled() {
		p.aead = &pathNonceAEAD{suite: p.suite, key: append([]byte(nil), p.keys.key[:p.suite.KeyLen]...), iv: append([]byte(nil), p.keys.iv[:]...), paths: make(map[uint32]cipher.AEAD)}
	} else {
		p.aead = &applicationNonceAEAD{p.suite.AEAD(p.keys.key[:p.suite.KeyLen], p.keys.iv[:]).(*xorNonceAEAD)}
	}
	if id == tls.TLS_CHACHA20_POLY1305_SHA256 {
		p.hp = &chachaHeaderProtector{key: p.keys.hp}
	} else {
		block, err := aes.NewCipher(p.keys.hp[:p.suite.KeyLen])
		if err != nil {
			return nil, err
		}
		p.hp = &aesHeaderProtector{block: block}
	}
	return p, nil
}

// SealPacket constructs a complete protected short-header packet. It consumes
// a number before the caller's UDP write, including failed writes. The caller
// still owns pacing, validation, anti-amplification and ACK/loss bookkeeping.
func (p *RemoteSealer) SealPacket(payload []byte) ([]byte, protocol.PacketNumber, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.owned {
		return nil, 0, ErrRemoteSealer
	}
	return p.sealPacketLocked(payload)
}

func (p *RemoteSealer) sealPacketLocked(payload []byte) ([]byte, protocol.PacketNumber, error) {
	if p.self != p || p.closed || p.aead == nil || p.next >= p.end || len(payload) == 0 || 1+p.cid.Len()+4+len(payload)+p.aead.Overhead() > int(protocol.MaxPacketBufferSize) {
		return nil, 0, ErrRemoteSealer
	}
	pn := p.next
	p.next++
	p.used = true
	nonce, err := protocol.PathAndPacketNumber(p.path, pn)
	if err != nil {
		return nil, 0, err
	}
	hdr, err := wire.AppendShortHeader(nil, p.cid, pn, protocol.PacketNumberLen4, p.epoch.Bit())
	if err != nil {
		return nil, 0, err
	}
	packet := p.aead.Seal(hdr, nonce[:], payload, hdr)
	offset := 1 + p.cid.Len()
	p.hp.EncryptHeader(packet[offset+4:offset+20], &packet[0], packet[offset:offset+4])
	return packet, pn, nil
}

func (p *RemoteSealer) clearKeys() { clear(p.keys.key[:]); clear(p.keys.iv[:]); clear(p.keys.hp[:]) }
func (p *RemoteSealer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p {
		return
	}
	p.closed = true
	p.aead, p.hp = nil, nil
	p.clearKeys()
}
