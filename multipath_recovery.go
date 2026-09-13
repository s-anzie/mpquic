package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// A PTO solicits fresh acknowledgment evidence. It does not declare the
// outstanding flight lost or reduce the congestion window (RFC 9002, 6.2).
func (p *multipathPathState) probeTimeout(fallback time.Duration) monotime.Time {
	var lastSent monotime.Time
	for _, packet := range p.sentPackets {
		if !packet.isProbe && packet.ackEliciting && packet.sentAt.After(lastSent) {
			lastSent = packet.sentAt
		}
	}
	if lastSent.IsZero() || p.abandoned {
		return 0
	}
	if p.lastPTO.After(lastSent) {
		lastSent = p.lastPTO
	}
	delay := fallback
	if p.rttStats != nil {
		delay = p.rttStats.PTO(true)
	}
	// Bound the shift and duration to avoid overflow on long-lived black holes.
	delay = min(max(delay, protocol.TimerGranularity), time.Minute)
	return lastSent.Add(min(delay*time.Duration(uint64(1)<<min(p.ptoCount, 20)), time.Hour))
}

func (c *Conn) sendMultipathRecoveryProbes(now monotime.Time) error {
	for id, p := range c.multipath.paths {
		deadline := p.probeTimeout(time.Second)
		if deadline.IsZero() || deadline.After(now) {
			continue
		}
		// Back off even when this path cannot currently send a probe.
		p.lastPTO = now
		p.ptoCount++
		cid, ok := c.connIDManager.GetConnIDForPath(pathID(id))
		if !ok {
			continue
		}
		var tr *Transport
		if c.perspective == protocol.PerspectiveServer {
			if !p.serverValidated || p.remoteAddr == nil {
				continue
			}
		} else {
			pm := c.pathManagerOutgoing.Load()
			if pm == nil {
				continue
			}
			tr, ok = pm.transportForPath(pathID(id))
			if !ok {
				continue
			}
		}
		packet, buf, err := c.packPathProbePacket(id, cid, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, c.version)
		if err != nil {
			return err
		}
		// Track this as an ordinary ack-eliciting packet, not a validation probe.
		packet.IsPathProbePacket = false
		c.logShortHeaderPacket(packet, protocol.ECNNon, buf.Len())
		c.registerPackedShortHeaderPacket(packet, protocol.ECNNon, now)
		err = c.writeMultipathApplication(id, tr, buf.Data, 0)
		buf.Release()
		if err != nil {
			return err
		}
	}
	return nil
}
