package quic

import (
	"errors"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

var errCloningRecoveryBlocked = errors.New("cloning recovery admission blocked")

type cloningPathRecovery struct {
	authority   *cloning.Authority
	grant       *cloning.Path
	boundary    protocol.PacketNumber
	onCompleted func([]uint64)
}

// attachCloningRecovery is a connection-loop staging hook, not a public handoff.
// The caller must quiesce local sending before reserving a remote PN window.
// Existing primary packet callbacks, congestion state and RTT estimates survive.
// Key barriers, remote pacing and authenticated dispatch remain prerequisites.
func (m *multipathState) attachCloningRecovery(id uint64, a *cloning.Authority, grant *cloning.Path, onCompleted func([]uint64)) error {
	p, ok := m.paths[id]
	if id == 0 || !ok || p.abandoned || p.cloningRecovery != nil || p.congestion == nil || a == nil || onCompleted == nil || p.cloningAuthority != a || p.cloningGrant != grant {
		return errCloningRecoveryBlocked
	}
	boundary, err := a.RemotePacketStart(grant)
	if err != nil {
		return err
	}
	if boundary <= p.largestSent || boundary != p.packetNumberSpace.nextPacketNumber {
		return errCloningRecoveryBlocked
	}
	p.cloningRecovery = &cloningPathRecovery{authority: a, grant: grant, boundary: boundary, onCompleted: onCompleted}
	return nil
}

// acknowledge validates only the remote portion of a possibly mixed PATH_ACK.
// Ordinary pre-handoff recovery continues to own numbers below the boundary.
func (r *cloningPathRecovery) acknowledge(f *wire.AckFrame) ([]uint64, error) {
	remote := *f
	remote.AckRanges = nil
	for _, ar := range f.AckRanges {
		if ar.Largest >= r.boundary {
			remote.AckRanges = append(remote.AckRanges, wire.AckRange{Smallest: max(ar.Smallest, r.boundary), Largest: ar.Largest})
		}
	}
	if len(remote.AckRanges) == 0 {
		return nil, nil
	}
	completed, err := r.authority.AcknowledgeDispatchedRemotePackets(r.grant, &remote)
	if err != nil {
		if !errors.Is(err, cloning.ErrPacketHistory) {
			return nil, err
		}
		return nil, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: "invalid delegated PATH_ACK"}
	}
	return completed, nil
}

// recordCloningPacket charges an approved ACK-eliciting remote packet to existing path
// congestion/recovery. sentAt must be a trusted timestamp on THIS host's clock,
// never a remote monotonic timestamp. Dispatch may conservatively charge before
// network emission; production workers still need their own pacing discipline.
func (m *multipathState) recordCloningPacket(id uint64, pn protocol.PacketNumber, sentAt monotime.Time, size protocol.ByteCount) error {
	p, ok := m.paths[id]
	if !ok || p.abandoned || p.cloningRecovery == nil || sentAt.IsZero() || size <= 0 || size > protocol.MaxPacketBufferSize || pn <= p.largestSent {
		return errCloningRecoveryBlocked
	}
	if !m.canSendOnPath(id, sentAt) {
		return errCloningRecoveryBlocked
	}
	r := p.cloningRecovery
	if err := r.authority.AdmitRemotePacket(r.grant, pn); err != nil {
		return err
	}
	handler := &cloningRecoveryHandler{recovery: r, pn: pn}
	return m.recordSentApplicationPacketWithSize(id, pn, sentAt, size, true,
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: handler}}, nil)
}

// ACK delivery is handled atomically for the whole PATH_ACK before congestion
// callbacks. This synthetic recovery token must never be serialized on the wire.
type cloningRecoveryHandler struct {
	recovery *cloningPathRecovery
	pn       protocol.PacketNumber
}

func (*cloningRecoveryHandler) OnAcked(wire.Frame) {}
func (h *cloningRecoveryHandler) OnLost(wire.Frame) {
	_ = h.recovery.authority.MarkRemotePacketLost(h.recovery.grant, h.pn)
}
