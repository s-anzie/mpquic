package handshake

import (
	"crypto/tls"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
)

// ExperimentalRemoteALPN separates framed jobs from the bare snapshot protocol.
const ExperimentalRemoteALPN = "mpquic-clone-lab/1"

// ExperimentalRemoteCrypto permits one outstanding, single-packet lease.
// All methods run on the connection loop. The caller must close the connection
// after uncertain dispatch, never release a lease without a worker drain receipt.
type ExperimentalRemoteCrypto interface {
	ExperimentalRemoteReady() bool
	AcquireExperimentalRemote(*cloning.Authority, *cloning.Path, protocol.ConnectionID) (*RemoteSealer, uint64, protocol.PacketNumber, error)
	ReleaseExperimentalRemote(*RemoteSealer) error
	RotateExperimentalKeys() error
}

// RotateExperimentalKeys initiates a local update only at a drained barrier
// and after the normal QUIC acknowledgment requirements permit another update.
func (h *cryptoSetup) RotateExperimentalKeys() error {
	if !h.ExperimentalRemoteReady() || !h.aead.updateAllowed() {
		return ErrRemoteSealer
	}
	h.aead.rollKeys()
	if h.aead.qlogger != nil {
		for _, keyType := range []qlog.KeyType{qlog.KeyTypeClient1RTT, qlog.KeyTypeServer1RTT} {
			h.aead.qlogger.RecordEvent(qlog.KeyUpdated{Trigger: qlog.KeyUpdateLocal, KeyType: keyType, KeyPhase: h.aead.keyPhase})
		}
	}
	return nil
}

func (h *cryptoSetup) ExperimentalRemoteReady() bool {
	// Exercise the initial key transition before delegating. Key transitions
	// temporarily stop admission until new-phase peer traffic is authenticated.
	return h.aead.handshakeConfirmed && h.aead.multipath && h.aead.keyPhase > 0 && h.aead.firstRcvdWithCurrentKey != protocol.InvalidPacketNumber && h.aead.experimentalLease == nil
}

func (h *cryptoSetup) AcquireExperimentalRemote(a *cloning.Authority, p *cloning.Path, cid protocol.ConnectionID) (*RemoteSealer, uint64, protocol.PacketNumber, error) {
	if !h.ExperimentalRemoteReady() {
		return nil, 0, 0, ErrRemoteSealer
	}
	s, err := h.aead.prepareRemoteSealer(a, p, 1, cid)
	if err != nil {
		return nil, 0, 0, err
	}
	h.aead.experimentalLease = s
	return s, uint64(s.epoch), s.next, nil
}

func (h *cryptoSetup) ReleaseExperimentalRemote(s *RemoteSealer) error {
	if s == nil || h.aead.experimentalLease != s {
		return ErrRemoteSealer
	}
	h.aead.experimentalLease = nil
	if h.aead.experimentalPeerUpdatePending {
		h.aead.experimentalPeerUpdatePending = false
		h.aead.rollKeys()
		h.aead.startKeyDropTimer(monotime.Now())
		if h.aead.qlogger != nil {
			for _, keyType := range []qlog.KeyType{qlog.KeyTypeClient1RTT, qlog.KeyTypeServer1RTT} {
				h.aead.qlogger.RecordEvent(qlog.KeyUpdated{Trigger: qlog.KeyUpdateRemote, KeyType: keyType, KeyPhase: h.aead.keyPhase})
			}
		}
	}
	return nil
}

// CheckRemoteTLS validates the preauthenticated dedicated bootstrap channel.
func CheckRemoteTLS(c *tls.Conn, expected [32]byte) error {
	if err := checkRemoteTLS(c, expected); err != nil {
		return err
	}
	if c.ConnectionState().NegotiatedProtocol != ExperimentalRemoteALPN {
		return ErrRemoteSealer
	}
	return nil
}

// ValidateExperimentalWindow checks dispatch metadata before any UDP emission.
func (p *RemoteSealer) ValidateExperimentalWindow(pn protocol.PacketNumber) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || p.closed || p.owned || p.used || p.aead == nil || pn < 0 || p.next != pn || p.end != pn+1 {
		return ErrRemoteSealer
	}
	return nil
}
