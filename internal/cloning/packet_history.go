package cloning

import (
	"errors"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

var ErrPacketHistory = errors.New("invalid remote packet history operation")

const (
	MaxRemoteHistoryPackets  = 4096 // shared by every path in the authority
	MaxRemotePacketFragments = 16
)

// PacketFragment identifies immutable retained stream bytes placed in a packet.
// These are primary-approved plans, never delivery assertions from a worker.
type PacketFragment struct {
	Attempt        *Attempt
	Offset, Length uint64
}

type remotePacket struct {
	fragments   []PacketFragment
	acked, lost bool
	dispatched  bool
}

// AdmitRemotePacket transfers a planned packet into trusted recovery exactly
// once. It must precede dispatch; a worker cannot claim admission via a receipt.
func (a *Authority) AdmitRemotePacket(p *Path, pn protocol.PacketNumber) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkPath(p); err != nil {
		return err
	}
	packet := p.remotePackets[pn]
	if !p.remoteSender || packet == nil || packet.acked || packet.lost || packet.dispatched {
		return ErrPacketHistory
	}
	packet.dispatched = true
	return nil
}

// checkRemoteHistoryPath permits late ACKs and loss processing after retirement.
func (a *Authority) checkRemoteHistoryPath(p *Path) error {
	if a.closed {
		return ErrClosed
	}
	if p == nil || p.authority != a || !p.remoteSender {
		return ErrPath
	}
	if _, ok := a.paths[p]; !ok {
		return ErrPath
	}
	return nil
}

// RecordRemotePacket registers an approved packet plan BEFORE granting the
// worker permission to send it. The number must be reserved for remote use.
// Registration neither consumes stream credit nor acknowledges delivery. The
// caller must enforce that the sender uses this exact plan, and must not treat
// this ledger as congestion control or import it into ordinary sent history yet.
func (a *Authority) RecordRemotePacket(p *Path, pn protocol.PacketNumber, fragments []PacketFragment) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validateRemotePacketLocked(p, pn, fragments); err != nil {
		return err
	}
	a.recordRemotePacketLocked(p, pn, fragments)
	return nil
}

// PrepareRemoteStreamPacket atomically builds STREAM frames from retained bytes
// and records their plan. The returned payload must be sent with exactly pn on p.
// It deliberately excludes FIN and control frames; stream finalization remains
// primary-owned. Failed preparation publishes no history entry or stream credit.
func (a *Authority) PrepareRemoteStreamPacket(p *Path, pn protocol.PacketNumber, fragments []PacketFragment, version protocol.Version) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if version != protocol.Version1 && version != protocol.Version2 || len(fragments) == 0 {
		return nil, ErrPacketHistory
	}
	if err := a.validateRemotePacketLocked(p, pn, fragments); err != nil {
		return nil, err
	}
	// Reserve worst-case short-header CID, four PN bytes and AEAD tag.
	const maxPayload = int(protocol.MaxPacketBufferSize) - 1 - 20 - 4 - 16
	var payload []byte
	for _, f := range fragments {
		if f.Length > uint64(maxPayload-len(payload)) {
			return nil, ErrLimit
		}
		d := f.Attempt.rangeState
		start := f.Offset - d.rangeInfo.Offset
		frame := wire.StreamFrame{StreamID: d.rangeInfo.StreamID, Offset: protocol.ByteCount(f.Offset),
			Data: d.data[start : start+f.Length], DataLenPresent: true}
		var err error
		payload, err = frame.Append(payload, version)
		if err != nil {
			return nil, err
		}
		if len(payload) > maxPayload {
			return nil, ErrLimit
		}
	}
	a.recordRemotePacketLocked(p, pn, fragments)
	return payload, nil
}

func (a *Authority) validateRemotePacketLocked(p *Path, pn protocol.PacketNumber, fragments []PacketFragment) error {
	if err := a.checkPath(p); err != nil {
		return err
	}
	if !p.remoteSender || pn < p.remoteFloor || pn < 0 || uint64(pn) >= p.nextPacketNumber || p.remotePackets[pn] != nil {
		return ErrPacketHistory
	}
	if a.remotePacketCount >= MaxRemoteHistoryPackets || len(fragments) > MaxRemotePacketFragments {
		return ErrLimit
	}
	for _, f := range fragments {
		d, err := a.checkAttempt(f.Attempt)
		if err != nil {
			return err
		}
		if f.Attempt.path != p || d.done || d.retryable || f.Attempt.generation != d.generation ||
			f.Offset < d.rangeInfo.Offset || f.Length == 0 || f.Offset-d.rangeInfo.Offset > d.rangeInfo.Length ||
			f.Length > d.rangeInfo.Length-(f.Offset-d.rangeInfo.Offset) {
			return ErrAttempt
		}
	}
	return nil
}

func (a *Authority) recordRemotePacketLocked(p *Path, pn protocol.PacketNumber, fragments []PacketFragment) {
	copyFragments := make([]PacketFragment, len(fragments))
	for i, f := range fragments {
		attempt := *f.Attempt
		copyFragments[i] = PacketFragment{Attempt: &attempt, Offset: f.Offset, Length: f.Length}
	}
	if p.remotePackets == nil {
		p.remotePackets = make(map[protocol.PacketNumber]*remotePacket)
	}
	p.remotePackets[pn] = &remotePacket{fragments: copyFragments}
	a.remotePacketCount++
}

// AcknowledgeRemotePackets accepts ONLY authenticated client PATH_ACK frames,
// routed by acknowledged path, never by ingress path or worker success reports.
// The whole frame is validated before delivery state changes. ACKs below the
// explicit retention floor are ignored. Above it, every acknowledged number
// must have an approved packet plan, including numbers in otherwise valid windows.
// Returned delegation IDs completed exactly once and can wake stream adapters.
func (a *Authority) AcknowledgeRemotePackets(p *Path, f *wire.AckFrame) ([]uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acknowledgeRemotePacketsLocked(p, f, false)
}

// AcknowledgeDispatchedRemotePackets additionally requires trusted recovery
// admission for every retained packet. Planning alone is insufficient.
func (a *Authority) AcknowledgeDispatchedRemotePackets(p *Path, f *wire.AckFrame) ([]uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acknowledgeRemotePacketsLocked(p, f, true)
}

func (a *Authority) acknowledgeRemotePacketsLocked(p *Path, f *wire.AckFrame, requireDispatched bool) ([]uint64, error) {
	if err := a.checkRemoteHistoryPath(p); err != nil {
		return nil, err
	}
	if f == nil || f.PathID == nil || *f.PathID != p.id || len(f.AckRanges) == 0 || len(f.AckRanges) > MaxWorkerACKRanges ||
		f.DelayTime < 0 || f.ECT0 > uint64(protocol.MaxByteCount) || f.ECT1 > uint64(protocol.MaxByteCount) || f.ECNCE > uint64(protocol.MaxByteCount) {
		return nil, ErrPacketHistory
	}
	var selected []*remotePacket
	for i, r := range f.AckRanges {
		if r.Smallest < 0 || r.Largest < r.Smallest || r.Largest > protocol.MaxPathAndPacketNumber ||
			(i > 0 && f.AckRanges[i-1].Smallest-r.Largest < 2) {
			return nil, ErrPacketHistory
		}
		first := max(r.Smallest, p.remoteFloor)
		if first > r.Largest {
			continue
		}
		// Bound CPU work even for a malicious ACK spanning the entire PN space.
		if r.Largest-first+1 > protocol.PacketNumber(len(p.remotePackets)) {
			return nil, ErrPacketHistory
		}
		for pn := first; pn <= r.Largest; pn++ {
			packet := p.remotePackets[pn]
			if packet == nil || (requireDispatched && !packet.dispatched) {
				return nil, ErrPacketHistory
			}
			selected = append(selected, packet)
		}
	}
	var completed []uint64
	for _, packet := range selected {
		if packet.acked {
			continue
		}
		packet.acked = true
		for _, fragment := range packet.fragments {
			if fragment.Attempt.rangeState.canceled {
				continue
			}
			// Plans copied validated handles and bounds at registration. Under
			// this same authority lock only cancellation could invalidate them;
			// completion and older attempt generations remain valid for late ACKs.
			done, _ := a.acknowledgeLocked(fragment.Attempt, fragment.Offset, fragment.Length)
			if done {
				completed = append(completed, fragment.Attempt.rangeState.id)
			}
		}
		packet.fragments = nil
	}
	return completed, nil
}

// MarkRemotePacketLost is called by the trusted recovery owner, not by client
// ACK parsing. Keep the plan for late ACKs; retry consumes no extra flow credit.
// A stale loss never makes a newer attempt retryable.
func (a *Authority) MarkRemotePacketLost(p *Path, pn protocol.PacketNumber) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkRemoteHistoryPath(p); err != nil {
		return err
	}
	packet := p.remotePackets[pn]
	if packet == nil {
		return ErrPacketHistory
	}
	if packet.acked || packet.lost {
		return nil
	}
	packet.lost = true
	for _, f := range packet.fragments {
		d := f.Attempt.rangeState
		if !d.done && !d.canceled && f.Attempt.generation == d.generation {
			d.retryable = true
		}
	}
	return nil
}

// ForgetRemotePacketsBefore advances a monotonic retention floor. Pending
// packets block advancement; lost plans may be dropped explicitly, forfeiting
// late byte-ACK evidence for those packets. Numbers below the floor are never
// eligible for registration again, including gaps and unused reservations.
func (a *Authority) ForgetRemotePacketsBefore(p *Path, floor protocol.PacketNumber) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkRemoteHistoryPath(p); err != nil {
		return err
	}
	if floor < p.remoteFloor || floor < 0 || uint64(floor) > p.nextPacketNumber {
		return ErrPacketHistory
	}
	for pn, packet := range p.remotePackets {
		if pn < floor && !packet.acked && !packet.lost {
			return ErrPacketHistory
		}
	}
	for pn := range p.remotePackets {
		if pn < floor {
			delete(p.remotePackets, pn)
			a.remotePacketCount--
		}
	}
	p.remoteFloor = floor
	return nil
}
