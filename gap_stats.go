package quic

import "sync/atomic"

// GapThresholds are the gap counts reported by StreamGapStats.StreamsReaching:
// StreamsReaching[i] counts the receive streams whose number of gaps (missing
// byte ranges between received STREAM frames) reached GapThresholds[i] at least
// once. Mycelium instrumentation, used to size MaxStreamFrameSorterGaps from
// measurements.
var GapThresholds = [6]int{100, 500, 1000, 2000, 5000, 10000}

// StreamGapStats summarises the reassembly gaps of a connection's receive
// streams since the connection started.
type StreamGapStats struct {
	// MaxGaps is the largest number of gaps any receive stream of the
	// connection held at once.
	MaxGaps int64
	// StreamsReaching[i] is the number of receive streams that reached
	// GapThresholds[i] gaps at least once.
	StreamsReaching [len(GapThresholds)]uint64
}

// gapStats is the connection-level accumulator behind StreamGapStats. A frame
// sorter only reports to it when its own peak grows, so the cost per frame is
// one integer comparison.
type gapStats struct {
	max      atomic.Int64
	reaching [len(GapThresholds)]atomic.Uint64
}

// observe records that a stream's peak went from old to n gaps.
func (g *gapStats) observe(old, n int) {
	for {
		cur := g.max.Load()
		if int64(n) <= cur || g.max.CompareAndSwap(cur, int64(n)) {
			break
		}
	}
	for i, t := range GapThresholds {
		if old < t && n >= t {
			g.reaching[i].Add(1)
		}
	}
}

func (g *gapStats) snapshot() StreamGapStats {
	var s StreamGapStats
	s.MaxGaps = g.max.Load()
	for i := range s.StreamsReaching {
		s.StreamsReaching[i] = g.reaching[i].Load()
	}
	return s
}
