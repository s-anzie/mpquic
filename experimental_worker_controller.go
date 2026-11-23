package quic

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const experimentalWorkerHistoryLimit = 4096

var ErrExperimentalWorkerController = errors.New("invalid worker controller operation")

// ExperimentalWorkerACKRange is an inclusive range authenticated and globally
// validated by the primary. The dedicated feedback relay calls OnACK; this
// controller neither authenticates feedback nor treats it as proof of delivery.
type ExperimentalWorkerACKRange struct{ Smallest, Largest int64 }

type ExperimentalWorkerRetry struct {
	PacketNumber int64
	PTO          bool
}

type ExperimentalWorkerControllerSnapshot struct {
	RTT, MinRTT, LatestRTT            time.Duration
	CongestionWindow, InFlight        int64
	Retained, PendingRetries          int
	Sent, Acked, Lost, LateACKs, PTOs uint64
}

type experimentalWorkerPacket struct {
	pn                          protocol.PacketNumber
	size                        protocol.ByteCount
	sent                        monotime.Time
	acked, lost, pending, probe bool
}

// ExperimentalWorkerController owns one worker's congestion, pacing and loss
// decisions. All methods are concurrency safe. Use one send lane: WaitSend,
// OnSent, then write one ack-eliciting datagram. Recording before the write
// prevents a fast ACK from preceding its ledger entry. CancelSend releases an
// unused reservation; after a recorded send fails, retire the path and controller.
// A successful WaitSend holds a reservation until explicitly completed, even
// if its context is subsequently canceled. Retries MUST use fresh increasing
// packet numbers; the queue identifies original data, not PNs to reuse.
//
// Run should be started with the worker's lifetime context. Events is a
// coalescing wakeup signal: inspect Snapshot and drain NextRetry on notification.
// Neither events nor retries certify application delivery. Relay integration is
// intentionally separate. Timestamps are local monotime values, never remote
// clock values (the relay must translate receipt time to the worker's clock).
type ExperimentalWorkerController struct {
	mu                    sync.Mutex
	cc                    congestion.SendAlgorithmWithDebugInfos
	rtt                   *utils.RTTStats
	mtu, flight, reserved protocol.ByteCount
	packets               []experimentalWorkerPacket
	highest, largestACK   protocol.PacketNumber
	lastSent, ptoAt       monotime.Time
	ptoCount              uint
	probePermit           bool
	closed                bool
	changed               chan struct{}
	events                chan struct{}
	stats                 ExperimentalWorkerControllerSnapshot
}

func NewExperimentalWorkerController(maxDatagramSize int, maxACKDelay time.Duration) (*ExperimentalWorkerController, error) {
	if maxDatagramSize < 1200 || maxDatagramSize > 65527 || maxACKDelay < 0 || maxACKDelay > time.Second {
		return nil, ErrExperimentalWorkerController
	}
	r := utils.NewRTTStats()
	r.SetMaxAckDelay(maxACKDelay)
	c := &ExperimentalWorkerController{rtt: r, mtu: protocol.ByteCount(maxDatagramSize), highest: protocol.InvalidPacketNumber, largestACK: protocol.InvalidPacketNumber, changed: make(chan struct{}), events: make(chan struct{}, 1)}
	c.cc = congestion.NewCubicSender(congestion.DefaultClock{}, r, &utils.ConnectionStats{}, c.mtu, true, nil)
	c.cc.SetMaxDatagramSize(c.mtu)
	return c, nil
}

func (c *ExperimentalWorkerController) Events() <-chan struct{} { return c.events }
func (c *ExperimentalWorkerController) notify() {
	close(c.changed)
	c.changed = make(chan struct{})
	select {
	case c.events <- struct{}{}:
	default:
	}
}

// Run drives worker-local loss and PTO timers and closes the controller on exit.
// It should be invoked once. Close also stops Run and wakes all waiting senders.
func (c *ExperimentalWorkerController) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	defer c.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}
			c.tick(monotime.Now())
			c.mu.Unlock()
		}
	}
}
func (c *ExperimentalWorkerController) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.notify()
	}
}

func (c *ExperimentalWorkerController) room() bool {
	if len(c.packets) < experimentalWorkerHistoryLimit {
		return true
	}
	for _, p := range c.packets {
		if (p.acked || p.lost) && !p.pending {
			return true
		}
	}
	return false
}

// WaitSend reserves a single datagram, including its entire congestion cost.
// PTO allows one paced probe beyond cwnd, as required to break an ACK stall.
// History saturation applies backpressure rather than forgetting live packets.
func (c *ExperimentalWorkerController) WaitSend(ctx context.Context, size int) error {
	if size <= 0 || protocol.ByteCount(size) > c.mtu {
		return ErrExperimentalWorkerController
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return context.Canceled
		}
		now := monotime.Now()
		if c.reserved == 0 && c.room() && (c.flight+protocol.ByteCount(size) <= c.cc.GetCongestionWindow() || c.probePermit) && c.cc.HasPacingBudget(now) {
			c.reserved = protocol.ByteCount(size)
			c.probePermit = false
			c.mu.Unlock()
			return nil
		}
		wake := c.changed
		delay := time.Hour
		if c.reserved == 0 && c.room() && (c.flight+protocol.ByteCount(size) <= c.cc.GetCongestionWindow() || c.probePermit) {
			delay = max(time.Millisecond, c.cc.TimeUntilSend(c.flight).Sub(now))
		}
		c.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}
func (c *ExperimentalWorkerController) CancelSend() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reserved = 0
	c.notify()
}

// OnSent records an actual successful write against the outstanding reservation.
// Packet numbers must strictly increase, including across evicted history.
func (c *ExperimentalWorkerController) OnSent(pn int64, size int, now monotime.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || pn < 0 || pn > (1<<62)-1 || protocol.PacketNumber(pn) <= c.highest || size <= 0 || c.reserved != protocol.ByteCount(size) || now.IsZero() || now < c.lastSent {
		return ErrExperimentalWorkerController
	}
	if len(c.packets) == experimentalWorkerHistoryLimit {
		for i, p := range c.packets {
			if (p.acked || p.lost) && !p.pending {
				copy(c.packets[i:], c.packets[i+1:])
				c.packets = c.packets[:len(c.packets)-1]
				break
			}
		}
	}
	c.cc.OnPacketSent(now, c.flight, protocol.PacketNumber(pn), protocol.ByteCount(size), true)
	c.flight += protocol.ByteCount(size)
	c.reserved = 0
	c.highest = protocol.PacketNumber(pn)
	c.lastSent = now
	c.packets = append(c.packets, experimentalWorkerPacket{pn: protocol.PacketNumber(pn), size: protocol.ByteCount(size), sent: now})
	c.stats.Sent++
	if c.ptoAt.IsZero() {
		c.armPTO(now)
	}
	c.notify()
	return nil
}

// OnACK accepts inclusive ranges in any order. Unknown PNs (including numbers
// above the worker's highest PN) are ignored: the primary owns global PN
// validation and may acknowledge packets sent by other workers. Input work is
// bounded; a relay must split feedback with more than 4096 ranges.
func (c *ExperimentalWorkerController) OnACK(ranges []ExperimentalWorkerACKRange, ackDelay time.Duration, now monotime.Time) error {
	if len(ranges) > experimentalWorkerHistoryLimit || ackDelay < 0 || now.IsZero() {
		return ErrExperimentalWorkerController
	}
	for _, r := range ranges {
		if r.Smallest < 0 || r.Largest < r.Smallest || r.Largest > (1<<62)-1 {
			return ErrExperimentalWorkerController
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return context.Canceled
	}
	prior := c.flight
	sample := -1
	fresh := false
	for i := range c.packets {
		p := &c.packets[i]
		if p.acked || now < p.sent {
			continue
		}
		matched := false
		for _, r := range ranges {
			if int64(p.pn) >= r.Smallest && int64(p.pn) <= r.Largest {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		p.acked = true
		p.pending = false
		c.stats.Acked++
		fresh = true
		c.largestACK = max(c.largestACK, p.pn)
		if p.lost {
			c.stats.LateACKs++
			continue
		}
		c.flight -= p.size
		sample = i
	}
	if !fresh {
		return nil
	}
	if sample >= 0 {
		c.rtt.UpdateRTT(now.Sub(c.packets[sample].sent), min(ackDelay, c.rtt.MaxAckDelay()))
		c.cc.MaybeExitSlowStart()
	}
	// Only newly acknowledged in-flight packets receive congestion credit.
	// Mark their callback with a temporary list-free predicate: acked packets
	// have size cleared after the callback, including on all earlier ACKs.
	for i := range c.packets {
		p := &c.packets[i]
		if p.acked && p.size > 0 {
			if !p.lost {
				c.cc.OnPacketAcked(p.pn, p.size, prior, now)
			}
			p.size = 0
		}
	}
	c.ptoCount = 0
	c.probePermit = false
	c.detectLoss(now)
	c.armPTO(now)
	c.notify()
	return nil
}

func (c *ExperimentalWorkerController) armPTO(now monotime.Time) {
	c.ptoAt = 0
	if c.flight > 0 {
		c.ptoAt = now.Add(min(60*time.Second, c.rtt.PTO(true)*time.Duration(uint64(1)<<min(c.ptoCount, 8))))
	}
}
func (c *ExperimentalWorkerController) detectLoss(now monotime.Time) {
	delay := max(time.Millisecond, max(c.rtt.LatestRTT(), c.rtt.SmoothedRTT())*9/8)
	prior := c.flight
	for i := range c.packets {
		p := &c.packets[i]
		if p.acked || p.lost || p.pn >= c.largestACK {
			continue
		}
		if c.largestACK-p.pn < 3 && now.Sub(p.sent) < delay {
			continue
		}
		p.lost = true
		p.pending = true
		p.probe = false
		c.flight -= p.size
		c.stats.Lost++
		c.cc.OnCongestionEvent(p.pn, p.size, prior)
	}
}
func (c *ExperimentalWorkerController) tick(now monotime.Time) {
	before := c.flight
	c.detectLoss(now)
	if c.flight == 0 {
		c.ptoAt = 0
	}
	if !c.ptoAt.IsZero() && now >= c.ptoAt {
		for i := range c.packets {
			p := &c.packets[i]
			if !p.acked && !p.lost {
				p.pending = true
				p.probe = true
				break
			}
		}
		c.stats.PTOs++
		c.ptoCount = min(c.ptoCount+1, 8)
		c.armPTO(now)
		c.notify()
	} else if c.flight != before {
		c.notify()
	}
}

// NextRetry drains one retry request. A PTO request grants one paced probe
// reservation. A later ACK can cancel queued work, but a dequeued request may
// race an ACK, so the worker must tolerate harmless redundant retransmission.
func (c *ExperimentalWorkerController) NextRetry() (ExperimentalWorkerRetry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ExperimentalWorkerRetry{}, false
	}
	for i := range c.packets {
		p := &c.packets[i]
		if p.pending {
			p.pending = false
			if p.probe {
				c.probePermit = true
			}
			c.notify()
			return ExperimentalWorkerRetry{int64(p.pn), p.probe}, true
		}
	}
	return ExperimentalWorkerRetry{}, false
}
func (c *ExperimentalWorkerController) Snapshot() ExperimentalWorkerControllerSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.RTT = c.rtt.SmoothedRTT()
	s.MinRTT = c.rtt.MinRTT()
	s.LatestRTT = c.rtt.LatestRTT()
	s.CongestionWindow = int64(c.cc.GetCongestionWindow())
	s.InFlight = int64(c.flight)
	s.Retained = len(c.packets)
	for _, p := range c.packets {
		if p.pending {
			s.PendingRetries++
		}
	}
	return s
}
