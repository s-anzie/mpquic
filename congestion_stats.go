package quic

// CongestionState is the state of a connection's congestion controller, as
// reported by ConnectionStats (Mycelium instrumentation). The sent packet
// handler publishes it with the congestion window after each ACK frame and
// loss-detection timeout: it is a snapshot, not an event stream.
type CongestionState uint32

const (
	// CongestionSlowStart: the window grows by one datagram per acknowledged
	// datagram (below the slow-start threshold).
	CongestionSlowStart CongestionState = iota
	// CongestionAvoidance: the window grows by about one datagram per round
	// trip.
	CongestionAvoidance
	// CongestionRecovery: a loss cut the window; it stays there until a packet
	// sent after the cut is acknowledged.
	CongestionRecovery
)

func (s CongestionState) String() string {
	switch s {
	case CongestionSlowStart:
		return "slow-start"
	case CongestionAvoidance:
		return "congestion-avoidance"
	case CongestionRecovery:
		return "recovery"
	}
	return "unknown"
}
