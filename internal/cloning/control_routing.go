package cloning

import (
	"encoding/binary"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	MaxWorkerControlQueue = 32
	MaxWorkerACKRanges    = 256
)

type workerControlMessage struct {
	kind byte
	body []byte // immutable after admission
}

// WorkerEvents is a coalesced wakeup, not a lossy queue of path IDs. The
// connection loop must inspect every registered grant's WorkerFailure on wakeup.
// Terminal failure state persists in the grant even if notifications coalesce.
// The channel is not closed; consumers use the owning connection's lifecycle.
func (a *Authority) WorkerEvents() <-chan struct{} { return a.workerEvents }

func (a *Authority) WorkerFailure(path *Path) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if path == nil || path.authority != a {
		return ErrPath
	}
	if _, ok := a.paths[path]; !ok {
		return ErrPath
	}
	return path.workerFailure
}

// ForwardPathACK is a trusted connection-loop entry point, not a worker RPC.
// Call only after authenticating the client packet and validating the ACK against
// sent-packet history. The grant selects the acknowledged path, not the ingress
// path. Forwarding does not acknowledge stream bytes or change flow credit.
// Packet ownership/history handoff to remote senders is still a separate step.
func (a *Authority) ForwardPathACK(path *Path, f *wire.AckFrame) error {
	a.mu.Lock()
	if err := a.checkPath(path); err != nil {
		a.mu.Unlock()
		return err
	}
	w := path.worker
	if w == nil {
		a.mu.Unlock()
		return nil // primary-owned path, no remote recipient
	}
	if f == nil || f.PathID == nil || *f.PathID != path.id || f.DelayTime < 0 || len(f.AckRanges) == 0 || f.ECT0 > uint64(protocol.MaxByteCount) || f.ECT1 > uint64(protocol.MaxByteCount) || f.ECNCE > uint64(protocol.MaxByteCount) {
		a.mu.Unlock()
		return ErrWorkerProtocol
	}
	if len(f.AckRanges) > MaxWorkerACKRanges {
		path.retired = true
		a.mu.Unlock()
		w.stop(ErrWorkerBusy)
		return ErrWorkerBusy // local capacity failure, not a QUIC protocol violation
	}
	for i, r := range f.AckRanges {
		if r.Smallest < 0 || r.Largest < r.Smallest || r.Largest > protocol.MaxPathAndPacketNumber || (i > 0 && f.AckRanges[i-1].Smallest-r.Largest < 2) {
			a.mu.Unlock()
			return ErrWorkerProtocol
		}
	}
	// Preserve parsed durations and ECN counts exactly. Process-local monotonic
	// timestamps must never be compared across geographically separate hosts.
	body := make([]byte, 0, 48+16*len(f.AckRanges))
	for _, v := range []uint64{path.id, uint64(f.DelayTime), f.ECT0, f.ECT1, f.ECNCE, uint64(len(f.AckRanges))} {
		body = binary.BigEndian.AppendUint64(body, v)
	}
	for _, r := range f.AckRanges {
		body = binary.BigEndian.AppendUint64(body, uint64(r.Smallest))
		body = binary.BigEndian.AppendUint64(body, uint64(r.Largest))
	}
	ok := w.queueControlLocked(workerControlMessage{kind: controlPathACK, body: body})
	a.mu.Unlock()
	if !ok {
		w.stop(ErrWorkerBusy)
		return ErrWorkerBusy
	}
	return nil
}

// queueControlLocked requires authority.mu. Mandatory control information must
// not be silently discarded. Retire before unlocking so new allocations cannot
// race with transport shutdown after saturation.
func (w *WorkerControl) queueControlLocked(message workerControlMessage) bool {
	select {
	case w.controls <- message:
		return true
	default:
		w.path.retired = true
		return false
	}
}

// cancelStreamWorkersLocked broadcasts cancellation of a delegated stream,
// including to previous owners whose failed attempts were already pruned.
// Ordinary, never-delegated streams need no worker notification.
// It runs before ledger cleanup, while authority.mu is held. Callers stop the
// returned saturated channels after releasing the lock (never perform TLS I/O
// while holding the authority lock).
func (a *Authority) cancelStreamWorkersLocked(id protocol.StreamID) []*WorkerControl {
	if s := a.streams[id]; s == nil || !s.delegated {
		return nil
	}
	var saturated []*WorkerControl
	for path := range a.paths {
		w := path.worker
		if w == nil || path.retired {
			continue
		}
		body := binary.BigEndian.AppendUint64(nil, uint64(id))
		if !w.queueControlLocked(workerControlMessage{kind: controlCancelStream, body: body}) {
			saturated = append(saturated, w)
		}
	}
	return saturated
}
