package quic

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

// pushGaps creates n gaps in s: one frame every other frame-sized range.
func pushGaps(t testing.TB, s *frameSorter, n, frame int) {
	data := make([]byte, frame)
	for i := 1; i <= n; i++ {
		require.NoError(t, s.Push(data, protocol.ByteCount(i*2*frame), nil))
	}
}

func TestGapStatsPeakAndThresholds(t *testing.T) {
	var g gapStats
	a, b := newFrameSorter(), newFrameSorter()
	a.stats, b.stats = &g, &g
	pushGaps(t, a, 1200, 100)
	pushGaps(t, b, 600, 100)
	st := g.snapshot()
	require.EqualValues(t, 1200, st.MaxGaps)
	// thresholds 100, 500, 1000, 2000, 5000, 10000: both streams reached 100 and
	// 500, only a reached 1000.
	require.Equal(t, [len(GapThresholds)]uint64{2, 2, 1, 0, 0, 0}, st.StreamsReaching)

	// Filling the gaps lowers the current count but never the recorded peak.
	data := make([]byte, 100)
	for i := 0; i <= 1200; i++ {
		_ = a.Push(data, protocol.ByteCount((2*i+1)*100), nil)
	}
	_ = a.Push(data, 0, nil)
	require.Equal(t, 1, a.gaps.Len())
	require.EqualValues(t, 1200, g.snapshot().MaxGaps)
	require.EqualValues(t, 1, g.snapshot().StreamsReaching[2], "a stream is counted once per threshold")
}

func TestGapStatsCryptoStreamWithoutAccumulator(t *testing.T) {
	s := newFrameSorter() // crypto streams have no accumulator: must not panic
	pushGaps(t, s, 10, 100)
	require.Equal(t, 10, s.peakGaps)
}

// TestGapCostMeasurement reports the memory used to track n gaps and the cost of
// one more frame landing after them (the gap list is walked linearly). It is the
// measurement quoted when sizing MaxStreamFrameSorterGaps; run it with
// MYCELIUM_GAP_COST=1 go test -v -run TestGapCostMeasurement .
func TestGapCostMeasurement(t *testing.T) {
	if os.Getenv("MYCELIUM_GAP_COST") == "" {
		t.Skip("measurement: set MYCELIUM_GAP_COST=1")
	}
	const frame = 1200
	for _, n := range []int{100, 500, 999, 2000, 5000, 9999} {
		// Several sorters for small n, so that the heap delta dominates GC noise.
		k := max(1, 20000/n)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		sorters := make([]*frameSorter, k)
		for i := range sorters {
			sorters[i] = newFrameSorter()
			pushGaps(t, sorters[i], n, frame)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		kib := (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / 1024 / float64(k)
		s := sorters[0]
		data := make([]byte, frame)
		const reps = 5000
		start := time.Now()
		for r := 0; r < reps; r++ {
			_ = s.Push(data, protocol.ByteCount((2*n+1)*frame), nil) // walks every gap
		}
		fmt.Printf("gaps=%5d tracking=%7.0f KiB (%3.0f B/gap) out-of-order data>=%5.1f MiB push-at-end=%v\n",
			s.gaps.Len()-1, kib, kib*1024/float64(n), float64(n*frame)/(1<<20), time.Since(start)/reps)
		runtime.KeepAlive(sorters)
	}
}
