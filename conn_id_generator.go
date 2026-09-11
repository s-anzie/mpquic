package quic

import (
	"fmt"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

type connRunnerCallbacks struct {
	AddConnectionID    func(protocol.ConnectionID)
	RemoveConnectionID func(protocol.ConnectionID)
	ReplaceWithClosed  func([]protocol.ConnectionID, []byte, time.Duration)
}

// The memory address of the Transport is used as the key.
type connRunners map[connRunner]connRunnerCallbacks

func (cr connRunners) AddConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.AddConnectionID(id)
	}
}

func (cr connRunners) RemoveConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.RemoveConnectionID(id)
	}
}

func (cr connRunners) ReplaceWithClosed(ids []protocol.ConnectionID, b []byte, expiry time.Duration) {
	for _, c := range cr {
		c.ReplaceWithClosed(ids, b, expiry)
	}
}

type connIDToRetire struct {
	t      monotime.Time
	connID protocol.ConnectionID
}

type connIDGenerator struct {
	generator   ConnectionIDGenerator
	highestSeq  uint64
	connRunners connRunners

	activeSrcConnIDs        map[uint64]protocol.ConnectionID
	pathConnectionIDs       map[pathID]map[uint64]protocol.ConnectionID
	pathConnectionIDToPath  map[protocol.ConnectionID]pathID
	nextPathConnectionIDSeq map[pathID]uint64
	abandonedPaths          map[pathID]bool
	currentPathDestConnIDs  map[pathID]protocol.ConnectionID
	connIDsToRetire         []connIDToRetire       // sorted by t
	initialClientDestConnID *protocol.ConnectionID // nil for the client

	statelessResetter *statelessResetter

	queueControlFrame func(wire.Frame)
}

func newConnIDGenerator(
	runner connRunner,
	initialConnectionID protocol.ConnectionID,
	initialClientDestConnID *protocol.ConnectionID, // nil for the client
	statelessResetter *statelessResetter,
	callbacks connRunnerCallbacks,
	queueControlFrame func(wire.Frame),
	generator ConnectionIDGenerator,
) *connIDGenerator {
	m := &connIDGenerator{
		generator:               generator,
		activeSrcConnIDs:        make(map[uint64]protocol.ConnectionID),
		pathConnectionIDs:       make(map[pathID]map[uint64]protocol.ConnectionID),
		pathConnectionIDToPath:  make(map[protocol.ConnectionID]pathID),
		nextPathConnectionIDSeq: make(map[pathID]uint64),
		abandonedPaths:          make(map[pathID]bool),
		currentPathDestConnIDs:  make(map[pathID]protocol.ConnectionID),
		statelessResetter:       statelessResetter,
		connRunners:             map[connRunner]connRunnerCallbacks{runner: callbacks},
		queueControlFrame:       queueControlFrame,
	}
	m.activeSrcConnIDs[0] = initialConnectionID
	m.initialClientDestConnID = initialClientDestConnID
	return m
}

func (m *connIDGenerator) SetMaxActiveConnIDs(limit uint64) error {
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	// The active_connection_id_limit transport parameter is the number of
	// connection IDs the peer will store. This limit includes the connection ID
	// used during the handshake, and the one sent in the preferred_address
	// transport parameter.
	// We currently don't send the preferred_address transport parameter,
	// so we can issue (limit - 1) connection IDs.
	for i := uint64(len(m.activeSrcConnIDs)); i < min(limit, protocol.MaxIssuedConnectionIDs); i++ {
		if err := m.issueNewConnID(); err != nil {
			return err
		}
	}
	return nil
}

func (m *connIDGenerator) Retire(seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	if seq > m.highestSeq {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (highest issued: %d)", seq, m.highestSeq),
		}
	}
	connID, ok := m.activeSrcConnIDs[seq]
	// We might already have deleted this connection ID, if this is a duplicate frame.
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", seq, connID),
		}
	}
	m.queueConnIDForRetiring(connID, expiry)

	delete(m.activeSrcConnIDs, seq)
	// Don't issue a replacement for the initial connection ID.
	if seq == 0 {
		return nil
	}
	return m.issueNewConnID()
}

func (m *connIDGenerator) queueConnIDForRetiring(connID protocol.ConnectionID, expiry monotime.Time) {
	idx := slices.IndexFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.t.After(expiry)
	})
	if idx == -1 {
		idx = len(m.connIDsToRetire)
	}
	m.connIDsToRetire = slices.Insert(m.connIDsToRetire, idx, connIDToRetire{t: expiry, connID: connID})
}

func (m *connIDGenerator) issueNewConnID() error {
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return err
	}
	m.activeSrcConnIDs[m.highestSeq+1] = connID
	m.connRunners.AddConnectionID(connID)
	m.queueControlFrame(&wire.NewConnectionIDFrame{
		SequenceNumber:      m.highestSeq + 1,
		ConnectionID:        connID,
		StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
	})
	m.highestSeq++
	return nil
}

// issuePathConnectionID creates and advertises a Connection ID for a
// Multipath path. Path-specific sequence numbers start at zero for every path.
func (m *connIDGenerator) issuePathConnectionID(id pathID) (wire.PathNewConnectionIDFrame, error) {
	if id <= 0 || uint64(id) > protocol.MaxPathID {
		return wire.PathNewConnectionIDFrame{}, fmt.Errorf("invalid path ID %d", id)
	}
	if m.generator.ConnectionIDLen() == 0 {
		return wire.PathNewConnectionIDFrame{}, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "cannot issue a path Connection ID when zero-length Connection IDs are in use",
		}
	}
	if m.pathConnectionIDs[id] == nil {
		m.pathConnectionIDs[id] = make(map[uint64]protocol.ConnectionID)
	}
	sequenceNumber := m.nextPathConnectionIDSeq[id]
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return wire.PathNewConnectionIDFrame{}, err
	}
	if _, exists := m.pathConnectionIDToPath[connID]; exists {
		return wire.PathNewConnectionIDFrame{}, fmt.Errorf("generated duplicate path Connection ID %s", connID)
	}
	frame := wire.PathNewConnectionIDFrame{
		PathID:              uint64(id),
		SequenceNumber:      sequenceNumber,
		ConnectionID:        connID,
		StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
	}
	m.pathConnectionIDs[id][sequenceNumber] = connID
	m.pathConnectionIDToPath[connID] = id
	m.nextPathConnectionIDSeq[id] = sequenceNumber + 1
	m.connRunners.AddConnectionID(connID)
	m.queueControlFrame(&frame)
	return frame, nil
}

func (m *connIDGenerator) ensurePathConnectionID(id pathID) error {
	if m.abandonedPaths[id] {
		return nil
	}
	if len(m.pathConnectionIDs[id]) > 0 {
		return nil
	}
	_, err := m.issuePathConnectionID(id)
	return err
}

// AbandonPath prevents future Connection ID replenishment for a path while
// retaining already issued IDs for packets that may still be reordered.
func (m *connIDGenerator) AbandonPath(id pathID) {
	if id == 0 {
		return
	}
	m.abandonedPaths[id] = true
}

// PathIDForConnectionID returns the path associated with a locally issued
// Connection ID. The initial path uses path ID zero.
func (m *connIDGenerator) PathIDForConnectionID(connID protocol.ConnectionID) (uint64, bool) {
	for _, activeConnID := range m.activeSrcConnIDs {
		if connID == activeConnID {
			return 0, true
		}
	}
	pathID, ok := m.pathConnectionIDToPath[connID]
	if !ok {
		return 0, false
	}
	return uint64(pathID), true
}

// observePathDestination records the local Connection ID currently used as
// the destination on a path. This is needed when a PATH_RETIRE_CONNECTION_ID
// frame is received on a different path than the one it refers to.
func (m *connIDGenerator) observePathDestination(id pathID, connID protocol.ConnectionID) {
	m.currentPathDestConnIDs[id] = connID
}

func (m *connIDGenerator) retirePathConnectionID(id pathID, sequenceNumber uint64, sentWithDestConnID protocol.ConnectionID) error {
	connections := m.pathConnectionIDs[id]
	connID, ok := connections[sequenceNumber]
	if !ok {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired path Connection ID %d for unknown path %d", sequenceNumber, id),
		}
	}
	currentConnID, hasCurrentConnID := m.currentPathDestConnIDs[id]
	if (hasCurrentConnID && connID == currentConnID) || (!hasCurrentConnID && connID == sentWithDestConnID) {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired path Connection ID %d currently in use on path %d", sequenceNumber, id),
		}
	}
	delete(connections, sequenceNumber)
	delete(m.pathConnectionIDToPath, connID)
	m.connRunners.RemoveConnectionID(connID)
	if !m.abandonedPaths[id] {
		_, err := m.issuePathConnectionID(id)
		return err
	}
	return nil
}

// replenishPathConnectionIDs issues enough path Connection IDs to answer a
// PATH_CIDs_BLOCKED frame without allowing an unbounded peer-controlled loop.
func (m *connIDGenerator) replenishPathConnectionIDs(id pathID, nextSequenceNumber uint64) error {
	if m.abandonedPaths[id] {
		return nil
	}
	current := m.nextPathConnectionIDSeq[id]
	if nextSequenceNumber >= current && nextSequenceNumber-current > protocol.MaxIssuedConnectionIDs {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("PATH_CIDs_BLOCKED requests an excessive sequence number %d for path %d", nextSequenceNumber, id),
		}
	}
	for current <= nextSequenceNumber {
		if _, err := m.issuePathConnectionID(id); err != nil {
			return err
		}
		current = m.nextPathConnectionIDSeq[id]
	}
	return nil
}

func (m *connIDGenerator) SetHandshakeComplete(connIDExpiry monotime.Time) {
	if m.initialClientDestConnID != nil {
		m.queueConnIDForRetiring(*m.initialClientDestConnID, connIDExpiry)
		m.initialClientDestConnID = nil
	}
}

func (m *connIDGenerator) RemoveRetiredConnIDs(now monotime.Time) {
	if len(m.connIDsToRetire) == 0 {
		return
	}
	for _, c := range m.connIDsToRetire {
		if c.t.After(now) {
			break
		}
		m.connRunners.RemoveConnectionID(c.connID)
		m.connIDsToRetire = m.connIDsToRetire[1:]
	}
}

func (m *connIDGenerator) RemoveAll() {
	if m.initialClientDestConnID != nil {
		m.connRunners.RemoveConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		m.connRunners.RemoveConnectionID(connID)
	}
	for _, connections := range m.pathConnectionIDs {
		for _, connID := range connections {
			m.connRunners.RemoveConnectionID(connID)
		}
	}
	for _, c := range m.connIDsToRetire {
		m.connRunners.RemoveConnectionID(c.connID)
	}
}

func (m *connIDGenerator) ReplaceWithClosed(connClose []byte, expiry time.Duration) {
	connIDs := make([]protocol.ConnectionID, 0, len(m.activeSrcConnIDs)+len(m.pathConnectionIDToPath)+len(m.connIDsToRetire)+1)
	if m.initialClientDestConnID != nil {
		connIDs = append(connIDs, *m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		connIDs = append(connIDs, connID)
	}
	for connID := range m.pathConnectionIDToPath {
		connIDs = append(connIDs, connID)
	}
	for _, c := range m.connIDsToRetire {
		connIDs = append(connIDs, c.connID)
	}
	m.connRunners.ReplaceWithClosed(connIDs, connClose, expiry)
}

func (m *connIDGenerator) AddConnRunner(runner connRunner, r connRunnerCallbacks) {
	// The transport might have already been added earlier.
	// This happens if the application migrates back to and old path.
	if _, ok := m.connRunners[runner]; ok {
		return
	}
	m.connRunners[runner] = r
	if m.initialClientDestConnID != nil {
		r.AddConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		r.AddConnectionID(connID)
	}
	for connID := range m.pathConnectionIDToPath {
		r.AddConnectionID(connID)
	}
}
