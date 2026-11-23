package quic

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

type experimentalSourceFence struct {
	id, generation uint64
	done           chan struct{}
	acknowledged   bool
}

func (c *Conn) receiveExperimentalSourceFence(f *wire.ExperimentalSourceFenceFrame, level protocol.EncryptionLevel) error {
	if !c.sourceOffersNegotiated() || level != protocol.Encryption1RTT || f.Ack != (c.perspective == protocol.PerspectiveServer) {
		return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: "unexpected source fence"}
	}
	if f.Ack {
		pending := c.experimentalFences[f.PathID]
		if pending == nil || pending.id != f.ID || pending.generation != f.Generation {
			return nil
		}
		if !pending.acknowledged {
			pending.acknowledged = true
			close(pending.done)
		}
		return nil
	}
	// The authenticated primary already has permission to abandon this path.
	// Keep the tombstone for the connection lifetime; no resurrection is allowed.
	if _, err := c.handleFrameForPath(&wire.PathAbandonFrame{PathID: f.PathID}, 0, level, protocol.ConnectionID{}, 0); err != nil {
		return err
	}
	c.queueControlFrame(&wire.ExperimentalSourceFenceFrame{ID: f.ID, Generation: f.Generation, PathID: f.PathID, Ack: true})
	return nil
}

func (w *ExperimentalCloneWriter) fenceSource(ctx context.Context, index int, lease *handshake.RemoteSealer) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s := w.sources[index]
	if !w.conn.sourceOffersNegotiated() {
		return ErrExperimentalSourceOffer
	}
	s.Control.Close()
	var done <-chan struct{}
	err := w.onLoop(ctx, func() error {
		if err := w.conn.abandonFailedPath(s.PathID, net.ErrClosed); err != nil {
			return err
		}
		if lease != nil {
			if err := w.crypto.RetireExperimentalRemote(lease); err != nil {
				return err
			}
		}
		if w.conn.experimentalFences == nil {
			w.conn.experimentalFences = make(map[uint64]*experimentalSourceFence)
		}
		f := w.conn.experimentalFences[s.PathID]
		if f == nil {
			f = &experimentalSourceFence{id: s.SourceID, generation: s.Generation, done: make(chan struct{})}
			w.conn.experimentalFences[s.PathID] = f
		}
		done = f.done
		w.conn.queueControlFrame(&wire.ExperimentalSourceFenceFrame{ID: s.SourceID, Generation: s.Generation, PathID: s.PathID})
		w.conn.queueControlFrame(&wire.PingFrame{})
		return nil
	})
	if err != nil {
		return err
	}
	select {
	case <-done:
		w.failed[index] = true
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-w.conn.ctx.Done():
		return context.Cause(w.conn.ctx)
	}
}

type experimentalSourceAddition struct {
	source ExperimentalCloneSource
	result chan error
	ctx    context.Context
}

// AddSource activates another accepted, directly validated source while a write
// is in progress. It must use a fresh path and a fresh worker TLS job channel.
// Application policy decides which sources to add, including energy criteria.
func (w *ExperimentalCloneWriter) AddSource(ctx context.Context, source ExperimentalCloneSource) error {
	if w.closed.Load() {
		return net.ErrClosed
	}
	if w.mu.TryLock() {
		defer w.mu.Unlock()
		return w.addSource(ctx, source)
	}
	command := experimentalSourceAddition{source: source, ctx: ctx, result: make(chan error, 1)}
	select {
	case w.additions <- command:
	case <-ctx.Done():
		return ctx.Err()
	case <-w.conn.ctx.Done():
		return context.Cause(w.conn.ctx)
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-command.result:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-w.conn.ctx.Done():
			return context.Cause(w.conn.ctx)
		case <-ticker.C:
			if w.mu.TryLock() {
				w.processAdditions()
				w.mu.Unlock()
			}
		}
	}
}

func (w *ExperimentalCloneWriter) addSource(ctx context.Context, s ExperimentalCloneSource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.closed.Load() {
		return net.ErrClosed
	}
	if len(w.sources) >= 32 {
		return ErrExperimentalSourceOffer
	}
	if err := handshake.CheckRemoteTLS(s.Control, s.CertificateSHA256); err != nil {
		return err
	}
	for _, old := range w.sources {
		if old.PathID == s.PathID || old.Control == s.Control {
			return ErrExperimentalSourceOffer
		}
	}
	err := w.onLoop(ctx, func() error {
		p := w.conn.multipath.paths[s.PathID]
		if !w.conn.sourceOffersNegotiated() || !w.conn.experimentalSourceReady(s) || p == nil || p.abandoned || !p.serverValidated || p.cloningRecovery != nil || p.cloningGrant == nil {
			return ErrExperimentalCloningNotReady
		}
		if s.Autonomous {
			p.experimentalWorkerControlled = true
			p.experimentalPacketRanges, p.experimentalRetryRanges = make(map[protocol.PacketNumber]uint64), make(map[uint64]bool)
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.sourceMutex.Lock()
	if w.closed.Load() {
		w.sourceMutex.Unlock()
		return net.ErrClosed
	}
	w.sources = append(w.sources, s)
	w.sourceMutex.Unlock()
	w.sequences = append(w.sequences, 0)
	w.batches = append(w.batches, 0)
	w.epochs = append(w.epochs, 0)
	w.rotations = append(w.rotations, 0)
	w.failed = append(w.failed, false)
	return nil
}

func (w *ExperimentalCloneWriter) processAdditions() {
	for {
		select {
		case a := <-w.additions:
			a.result <- w.addSource(a.ctx, a.source)
		default:
			return
		}
	}
}

func (w *ExperimentalCloneWriter) chooseSource(ctx context.Context, preferred int) (int, error) {
	for {
		w.processAdditions()
		chosen := -1
		var retired []int
		err := w.onLoop(ctx, func() error {
			if w.conn.sourceOffersNegotiated() {
				for i, s := range w.sources {
					p := w.conn.multipath.paths[s.PathID]
					if !w.failed[i] && (p == nil || p.abandoned || !w.conn.experimentalSourceReady(s)) {
						retired = append(retired, i)
					}
				}
			}
			for n := range len(w.sources) {
				i := (preferred + n) % len(w.sources)
				p := w.conn.multipath.paths[w.sources[i].PathID]
				if !w.failed[i] && p != nil && !p.abandoned && p.serverValidated && w.conn.experimentalSourceReady(w.sources[i]) {
					chosen = i
					break
				}
			}
			return nil
		})
		if err != nil {
			return -1, err
		}
		for _, i := range retired {
			if err := w.fenceSource(ctx, i, nil); err != nil {
				return -1, errors.Join(errExperimentalFence, err)
			}
		}
		if chosen >= 0 {
			return chosen, nil
		}
		if err := waitCloneTick(ctx, w.conn.ctx, 5*time.Millisecond); err != nil {
			return -1, err
		}
	}
}

func (w *ExperimentalCloneWriter) sendRange(ctx context.Context, preferred int, id uint64) (int, error) {
	for {
		index, err := w.chooseSource(ctx, preferred)
		if err != nil {
			return index, err
		}
		err = w.dispatch(ctx, index, id)
		if err == nil {
			return index, nil
		}
		if !w.conn.sourceOffersNegotiated() || ctx.Err() != nil || w.conn.ctx.Err() != nil || errors.Is(err, errExperimentalFence) {
			return index, err
		}
		if !w.failed[index] {
			if err := w.fenceSource(ctx, index, nil); err != nil {
				return index, err
			}
		}
		preferred = (index + 1) % len(w.sources)
	}
}

var errExperimentalFence = errors.New("experimental source fencing failed")
