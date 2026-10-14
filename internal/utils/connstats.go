package utils

import "sync/atomic"

// ConnectionStats stores stats for the connection. See the public
// ConnectionStats struct in connection.go for more information
type ConnectionStats struct {
	BytesSent       atomic.Uint64
	PacketsSent     atomic.Uint64
	BytesReceived   atomic.Uint64
	PacketsReceived atomic.Uint64
	BytesLost       atomic.Uint64
	PacketsLost     atomic.Uint64

	// Mycelium instrumentation: congestion window and controller state,
	// published by the sent packet handler (run loop) whenever they change, so
	// that ConnectionStats() reads them from any goroutine without touching
	// the controller. CongestionState: 0 slow start, 1 congestion avoidance,
	// 2 recovery (see quic.CongestionState).
	CongestionWindow    atomic.Uint64
	MaxCongestionWindow atomic.Uint64
	CongestionState     atomic.Uint32
}
