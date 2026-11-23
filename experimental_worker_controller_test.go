package quic

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

func workerController(t *testing.T) *ExperimentalWorkerController {
	t.Helper()
	c, err := NewExperimentalWorkerController(1200, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// Synthetic sends isolate loss tests from wall-clock pacing; send admission is
// exercised separately through the public WaitSend API.
func workerSent(t *testing.T, c *ExperimentalWorkerController, pn int64, now monotime.Time) {
	t.Helper()
	c.mu.Lock()
	c.reserved = 1200
	c.mu.Unlock()
	if err := c.OnSent(pn, 1200, now); err != nil {
		t.Fatal(err)
	}
}
func workerACK(t *testing.T, c *ExperimentalWorkerController, lo, hi int64, now monotime.Time) {
	t.Helper()
	if err := c.OnACK([]ExperimentalWorkerACKRange{{lo, hi}}, 0, now); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentalWorkerControllerACKOwnership(t *testing.T) {
	c := workerController(t)
	now := monotime.Now()
	workerSent(t, c, 100, now)
	workerSent(t, c, 102, now)
	workerACK(t, c, 0, 99, now.Add(time.Millisecond))
	workerACK(t, c, 101, 101, now.Add(time.Millisecond))
	workerACK(t, c, 103, 10000, now.Add(time.Millisecond))
	s := c.Snapshot()
	if s.Acked != 0 || s.InFlight != 2400 || s.Lost != 0 {
		t.Fatal(s)
	}
	workerACK(t, c, 100, 102, now.Add(20*time.Millisecond))
	s = c.Snapshot()
	if s.Acked != 2 || s.InFlight != 0 || s.RTT != 20*time.Millisecond {
		t.Fatal(s)
	}
	workerACK(t, c, 0, 10000, now.Add(time.Second))
	if got := c.Snapshot(); got != s {
		t.Fatalf("duplicate changed state: %+v -> %+v", s, got)
	}
}

func TestExperimentalWorkerControllerReorderLateACK(t *testing.T) {
	c := workerController(t)
	now := monotime.Now()
	for pn := int64(10); pn <= 13; pn++ {
		workerSent(t, c, pn, now)
	}
	workerACK(t, c, 11, 11, now.Add(10*time.Millisecond))
	if s := c.Snapshot(); s.Lost != 0 || s.InFlight != 3600 {
		t.Fatal(s)
	}
	workerACK(t, c, 13, 13, now.Add(10*time.Millisecond))
	s := c.Snapshot()
	if s.Lost != 1 || s.InFlight != 1200 || s.PendingRetries != 1 {
		t.Fatal(s)
	}
	cwnd := s.CongestionWindow
	workerACK(t, c, 10, 10, now.Add(11*time.Millisecond))
	s = c.Snapshot()
	if s.LateACKs != 1 || s.InFlight != 1200 || s.CongestionWindow != cwnd || s.PendingRetries != 0 {
		t.Fatal(s)
	}
	if _, ok := c.NextRetry(); ok {
		t.Fatal("ACKed retry queued")
	}
	workerACK(t, c, 10, 11, now.Add(11*time.Millisecond))
	if c.Snapshot() != s {
		t.Fatal("duplicate late ACK changed state")
	}
	workerACK(t, c, 12, 12, now.Add(11*time.Millisecond))
	if c.Snapshot().InFlight != 0 {
		t.Fatal(c.Snapshot())
	}
}

func TestExperimentalWorkerControllerTimeLossAndPTO(t *testing.T) {
	c := workerController(t)
	now := monotime.Now()
	workerSent(t, c, 1, now)
	workerSent(t, c, 2, now)
	workerACK(t, c, 2, 2, now.Add(10*time.Millisecond))
	c.mu.Lock()
	c.tick(now.Add(12 * time.Millisecond))
	c.mu.Unlock()
	r, ok := c.NextRetry()
	if !ok || r.PacketNumber != 1 || r.PTO {
		t.Fatal(r, ok)
	}
	if _, ok = c.NextRetry(); ok {
		t.Fatal("duplicate loss retry")
	}
	workerSent(t, c, 3, now.Add(13*time.Millisecond))
	c.mu.Lock()
	deadline := c.ptoAt
	c.tick(deadline)
	next := c.ptoAt
	c.mu.Unlock()
	s := c.Snapshot()
	if s.PTOs != 1 || s.Lost != 1 || s.InFlight != 1200 {
		t.Fatal(s)
	}
	r, ok = c.NextRetry()
	if !ok || !r.PTO || r.PacketNumber != 3 {
		t.Fatal(r, ok)
	}
	if next.Sub(deadline) != 2*c.rtt.PTO(true) {
		t.Fatal("PTO did not back off")
	}
	workerACK(t, c, 3, 3, deadline.Add(time.Millisecond))
	c.mu.Lock()
	c.tick(next)
	c.mu.Unlock()
	if s = c.Snapshot(); s.PTOs != 1 || s.InFlight != 0 {
		t.Fatal(s)
	}
}

func TestExperimentalWorkerControllerBoundedHistory(t *testing.T) {
	c := workerController(t)
	now := monotime.Now()
	for pn := int64(0); pn < experimentalWorkerHistoryLimit+100; pn++ {
		workerSent(t, c, pn, now)
		workerACK(t, c, pn, pn, now.Add(time.Millisecond))
	}
	s := c.Snapshot()
	if s.Retained != 0 {
		t.Fatal(s)
	}
	workerACK(t, c, 0, 99, now.Add(time.Second))
	if c.Snapshot() != s {
		t.Fatal("evicted ACK changed state")
	}
	c.mu.Lock()
	c.reserved = 1200
	c.mu.Unlock()
	if err := c.OnSent(0, 1200, now); err == nil {
		t.Fatal("reused evicted PN")
	}
	// Outstanding records and pending lost retries cannot be evicted.
	c.mu.Lock()
	c.packets = make([]experimentalWorkerPacket, experimentalWorkerHistoryLimit)
	for i := range c.packets {
		c.packets[i].acked = false
		c.packets[i].lost = true
		c.packets[i].pending = true
	}
	room := c.room()
	c.mu.Unlock()
	if room {
		t.Fatal("pending retry eviction")
	}
}

func TestExperimentalWorkerControllerSendAdmission(t *testing.T) {
	c := workerController(t)
	ctx := context.Background()
	if err := c.WaitSend(ctx, 1200); err != nil {
		t.Fatal(err)
	}
	timeout, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	if err := c.WaitSend(timeout, 1200); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	c.CancelSend()
	for pn := int64(0); pn < 32; pn++ {
		if err := c.WaitSend(ctx, 1200); err != nil {
			t.Fatal(err)
		}
		if err := c.OnSent(pn, 1200, monotime.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if s := c.Snapshot(); s.InFlight != s.CongestionWindow {
		t.Fatal(s)
	}
	timeout2, cancel2 := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel2()
	if err := c.WaitSend(timeout2, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	workerACK(t, c, 0, 31, monotime.Now())
	if err := c.WaitSend(ctx, 1200); err != nil {
		t.Fatal(err)
	}
	c.CancelSend()
}

func TestExperimentalWorkerControllerPacingAndProbe(t *testing.T) {
	c := workerController(t)
	now := monotime.Now()
	// Deplete the pacer at one instant; a tiny context cannot admit a send.
	for pn := int64(0); pn < 32; pn++ {
		workerSent(t, c, pn, now)
	}
	c.mu.Lock()
	c.tick(c.ptoAt)
	c.mu.Unlock()
	if r, ok := c.NextRetry(); !ok || !r.PTO {
		t.Fatal(r, ok)
	}
	// Probe may exceed cwnd, but still waits for the pacer.
	c.mu.Lock()
	c.cc.OnPacketSent(monotime.Now().Add(time.Second), c.flight, protocol.PacketNumber(32), 1000000, true)
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := c.WaitSend(ctx, 1200); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if s := c.Snapshot(); s.InFlight != 38400 || s.Lost != 0 {
		t.Fatal(s)
	}
}

func TestExperimentalWorkerControllerValidationAndLifecycle(t *testing.T) {
	if _, err := NewExperimentalWorkerController(0, 0); err == nil {
		t.Fatal("invalid MTU")
	}
	c := workerController(t)
	now := monotime.Now()
	if err := c.OnSent(1, 1200, now); err == nil {
		t.Fatal("unreserved send")
	}
	if err := c.OnACK([]ExperimentalWorkerACKRange{{2, 1}}, 0, now); err == nil {
		t.Fatal("invalid range")
	}
	if err := c.OnACK(make([]ExperimentalWorkerACKRange, 4097), 0, now); err == nil {
		t.Fatal("unbounded input")
	}
	if err := c.WaitSend(context.Background(), 1201); err == nil {
		t.Fatal("oversize")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Snapshot()
				c.NextRetry()
				_ = c.OnACK(nil, 0, monotime.Now())
			}
		}()
	}
	wg.Wait()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	if err := c.WaitSend(context.Background(), 1200); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-c.Events():
	default:
		t.Fatal("missing wakeup")
	}
}
