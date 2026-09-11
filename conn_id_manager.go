package quic

import (
	"fmt"
	"slices"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type newConnID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

type connIDManager struct {
	queue []newConnID

	highestProbingID   uint64
	pathMx             sync.Mutex
	pathProbing        map[pathID]newConnID // initialized lazily
	pathQueues         map[pathID][]newConnID
	pathHighestRetired map[pathID]uint64
	abandonedPaths     map[pathID]bool
	abandonedRetired   map[pathID]map[uint64]bool
	multipath          bool

	handshakeComplete         bool
	activeSequenceNumber      uint64
	highestRetired            uint64
	activeConnectionID        protocol.ConnectionID
	activeStatelessResetToken *protocol.StatelessResetToken

	// We change the connection ID after sending on average
	// protocol.PacketsPerConnectionID packets. The actual value is randomized
	// hide the packet loss rate from on-path observers.
	rand                   utils.Rand
	packetsSinceLastChange uint32
	packetsPerConnectionID uint32

	addStatelessResetToken    func(protocol.StatelessResetToken)
	removeStatelessResetToken func(protocol.StatelessResetToken)
	queueControlFrame         func(wire.Frame)

	closed bool
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID,
	addStatelessResetToken func(protocol.StatelessResetToken),
	removeStatelessResetToken func(protocol.StatelessResetToken),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		activeConnectionID:        initialDestConnID,
		addStatelessResetToken:    addStatelessResetToken,
		removeStatelessResetToken: removeStatelessResetToken,
		queueControlFrame:         queueControlFrame,
		queue:                     make([]newConnID, 0, protocol.MaxActiveConnectionIDs),
		pathQueues:                make(map[pathID][]newConnID),
		pathHighestRetired:        make(map[pathID]uint64),
		abandonedPaths:            make(map[pathID]bool),
		abandonedRetired:          make(map[pathID]map[uint64]bool),
	}
}

func (h *connIDManager) AddFromPreferredAddress(connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	return h.addConnectionID(1, connID, resetToken)
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if err := h.add(f); err != nil {
		return err
	}
	if len(h.queue) >= protocol.MaxActiveConnectionIDs {
		return &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}
	}
	return nil
}

func (h *connIDManager) add(f *wire.NewConnectionIDFrame) error {
	if h.activeConnectionID.Len() == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_CONNECTION_ID frame but zero-length connection IDs are in use",
		}
	}
	if h.abandonedPaths[0] {
		if h.abandonedRetired[0] == nil {
			h.abandonedRetired[0] = make(map[uint64]bool)
		}
		if !h.abandonedRetired[0][f.SequenceNumber] {
			h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: f.SequenceNumber})
			h.abandonedRetired[0][f.SequenceNumber] = true
		}
		return nil
	}
	// If the NEW_CONNECTION_ID frame is reordered, such that its sequence number is smaller than the currently active
	// connection ID or if it was already retired, send the RETIRE_CONNECTION_ID frame immediately.
	if f.SequenceNumber < max(h.activeSequenceNumber, h.highestProbingID) || f.SequenceNumber < h.highestRetired {
		h.queueControlFrame(&wire.RetireConnectionIDFrame{
			SequenceNumber: f.SequenceNumber,
		})
		return nil
	}

	if f.RetirePriorTo != 0 && h.pathProbing != nil {
		for id, entry := range h.pathProbing {
			if entry.SequenceNumber < f.RetirePriorTo {
				h.queueControlFrame(&wire.RetireConnectionIDFrame{
					SequenceNumber: entry.SequenceNumber,
				})
				h.removeStatelessResetToken(entry.StatelessResetToken)
				delete(h.pathProbing, id)
			}
		}
	}
	// Retire elements in the queue.
	// Doesn't retire the active connection ID.
	if f.RetirePriorTo > h.highestRetired {
		var newQueue []newConnID
		for _, entry := range h.queue {
			if entry.SequenceNumber >= f.RetirePriorTo {
				newQueue = append(newQueue, entry)
			} else {
				h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
			}
		}
		h.queue = newQueue
		h.highestRetired = f.RetirePriorTo
	}

	if f.SequenceNumber == h.activeSequenceNumber {
		return nil
	}

	if err := h.addConnectionID(f.SequenceNumber, f.ConnectionID, f.StatelessResetToken); err != nil {
		return err
	}

	// Retire the active connection ID, if necessary.
	if h.activeSequenceNumber < f.RetirePriorTo {
		// The queue is guaranteed to have at least one element at this point.
		h.updateConnectionID()
	}
	return nil
}

func (h *connIDManager) addConnectionID(seq uint64, connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	// fast path: add to the end of the queue
	if len(h.queue) == 0 || h.queue[len(h.queue)-1].SequenceNumber < seq {
		h.queue = append(h.queue, newConnID{
			SequenceNumber:      seq,
			ConnectionID:        connID,
			StatelessResetToken: resetToken,
		})
		return nil
	}

	// slow path: insert in the middle
	for i, entry := range h.queue {
		if entry.SequenceNumber == seq {
			if entry.ConnectionID != connID {
				return fmt.Errorf("received conflicting connection IDs for sequence number %d", seq)
			}
			if entry.StatelessResetToken != resetToken {
				return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", seq)
			}
			return nil
		}

		// insert at the correct position to maintain sorted order
		if entry.SequenceNumber > seq {
			h.queue = slices.Insert(h.queue, i, newConnID{
				SequenceNumber:      seq,
				ConnectionID:        connID,
				StatelessResetToken: resetToken,
			})
			return nil
		}
	}
	return nil // unreachable
}

func (h *connIDManager) updateConnectionID() {
	h.assertNotClosed()
	h.queueControlFrame(&wire.RetireConnectionIDFrame{
		SequenceNumber: h.activeSequenceNumber,
	})
	h.highestRetired = max(h.highestRetired, h.activeSequenceNumber)
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}

	front := h.queue[0]
	h.queue = h.queue[1:]
	h.activeSequenceNumber = front.SequenceNumber
	h.activeConnectionID = front.ConnectionID
	h.activeStatelessResetToken = &front.StatelessResetToken
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + uint32(h.rand.Int31n(protocol.PacketsPerConnectionID))
	h.addStatelessResetToken(*h.activeStatelessResetToken)
}

func (h *connIDManager) Close() {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.closed = true
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
	for _, entry := range h.pathProbing {
		h.removeStatelessResetToken(entry.StatelessResetToken)
	}
	clear(h.pathProbing)
}

// is called when the server performs a Retry
// and when the server changes the connection ID in the first Initial sent
func (h *connIDManager) ChangeInitialConnID(newConnID protocol.ConnectionID) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeConnectionID = newConnID
}

// is called when the server provides a stateless reset token in the transport parameters
func (h *connIDManager) SetStatelessResetToken(token protocol.StatelessResetToken) {
	h.assertNotClosed()
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeStatelessResetToken = &token
	h.addStatelessResetToken(token)
}

func (h *connIDManager) SentPacket() {
	h.packetsSinceLastChange++
}

func (h *connIDManager) shouldUpdateConnID() bool {
	if !h.handshakeComplete {
		return false
	}
	// initiate the first change as early as possible (after handshake completion)
	if len(h.queue) > 0 && h.activeSequenceNumber == 0 {
		return true
	}
	// For later changes, only change if
	// 1. The queue of connection IDs is filled more than 50%.
	// 2. We sent at least PacketsPerConnectionID packets
	return 2*len(h.queue) >= protocol.MaxActiveConnectionIDs &&
		h.packetsSinceLastChange >= h.packetsPerConnectionID
}

func (h *connIDManager) Get() protocol.ConnectionID {
	h.assertNotClosed()
	if h.shouldUpdateConnID() {
		h.updateConnectionID()
	}
	return h.activeConnectionID
}

func (h *connIDManager) SetHandshakeComplete() {
	h.handshakeComplete = true
}

func (h *connIDManager) SetMultipath(enabled bool) {
	h.pathMx.Lock()
	h.multipath = enabled
	h.pathMx.Unlock()
}

// AddPath adds a Connection ID advertised for a specific Multipath path.
func (h *connIDManager) AddPath(f *wire.PathNewConnectionIDFrame) error {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()
	id := pathID(f.PathID)
	if id == 0 {
		if err := h.add(&wire.NewConnectionIDFrame{
			SequenceNumber:      f.SequenceNumber,
			RetirePriorTo:       f.RetirePriorTo,
			ConnectionID:        f.ConnectionID,
			StatelessResetToken: f.StatelessResetToken,
		}); err != nil {
			return err
		}
		if len(h.queue) >= protocol.MaxActiveConnectionIDs {
			return &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}
		}
		return nil
	}

	if h.activeConnectionID.Len() == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received PATH_NEW_CONNECTION_ID frame but zero-length connection IDs are in use",
		}
	}
	if h.pathProbing != nil {
		if entry, ok := h.pathProbing[id]; ok && entry.SequenceNumber == f.SequenceNumber {
			if entry.ConnectionID != f.ConnectionID || entry.StatelessResetToken != f.StatelessResetToken {
				return fmt.Errorf("received conflicting path connection IDs for path %d and sequence number %d", f.PathID, f.SequenceNumber)
			}
			return nil
		}
	}
	if h.abandonedPaths[id] {
		if h.abandonedRetired[id] == nil {
			h.abandonedRetired[id] = make(map[uint64]bool)
		}
		if !h.abandonedRetired[id][f.SequenceNumber] {
			h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
				PathID:         f.PathID,
				SequenceNumber: f.SequenceNumber,
			})
			h.abandonedRetired[id][f.SequenceNumber] = true
		}
		return nil
	}
	queue := h.pathQueues[id]
	for _, entry := range queue {
		if entry.SequenceNumber == f.SequenceNumber {
			if entry.ConnectionID != f.ConnectionID || entry.StatelessResetToken != f.StatelessResetToken {
				return fmt.Errorf("received conflicting path connection IDs for path %d and sequence number %d", f.PathID, f.SequenceNumber)
			}
			return nil
		}
	}

	if f.SequenceNumber < h.pathHighestRetired[id] {
		h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
			PathID:         f.PathID,
			SequenceNumber: f.SequenceNumber,
		})
		return nil
	}

	if f.RetirePriorTo > h.pathHighestRetired[id] {
		for _, entry := range queue {
			if entry.SequenceNumber < f.RetirePriorTo {
				h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
					PathID:         f.PathID,
					SequenceNumber: entry.SequenceNumber,
				})
			}
		}
		queue = slices.DeleteFunc(queue, func(entry newConnID) bool {
			return entry.SequenceNumber < f.RetirePriorTo
		})
		if h.pathProbing != nil {
			if entry, ok := h.pathProbing[id]; ok && entry.SequenceNumber < f.RetirePriorTo {
				h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
					PathID:         f.PathID,
					SequenceNumber: entry.SequenceNumber,
				})
				h.removeStatelessResetToken(entry.StatelessResetToken)
				delete(h.pathProbing, id)
			}
		}
		h.pathHighestRetired[id] = f.RetirePriorTo
	}
	if f.SequenceNumber < h.pathHighestRetired[id] {
		h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
			PathID:         f.PathID,
			SequenceNumber: f.SequenceNumber,
		})
		return nil
	}

	entry := newConnID{
		SequenceNumber:      f.SequenceNumber,
		ConnectionID:        f.ConnectionID,
		StatelessResetToken: f.StatelessResetToken,
	}
	position := len(queue)
	for i, queued := range queue {
		if queued.SequenceNumber > entry.SequenceNumber {
			position = i
			break
		}
	}
	queue = slices.Insert(queue, position, entry)
	h.pathQueues[id] = queue
	return nil
}

// GetConnIDForPath retrieves a connection ID for a new path (i.e. not the active one).
// Once a connection ID is allocated for a path, it cannot be used for a different path.
// When called with the same pathID, it will return the same connection ID,
// unless the peer requested that this connection ID be retired.
func (h *connIDManager) GetConnIDForPath(id pathID) (protocol.ConnectionID, bool) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	// if we're using zero-length connection IDs, we don't need to change the connection ID
	if h.activeConnectionID.Len() == 0 {
		return protocol.ConnectionID{}, true
	}
	if h.abandonedPaths[id] {
		return protocol.ConnectionID{}, false
	}

	if h.pathProbing == nil {
		h.pathProbing = make(map[pathID]newConnID)
	}
	entry, ok := h.pathProbing[id]
	if ok {
		return entry.ConnectionID, true
	}
	if h.multipath {
		queue := h.pathQueues[id]
		if len(queue) == 0 {
			return protocol.ConnectionID{}, false
		}
		entry := queue[0]
		h.pathQueues[id] = queue[1:]
		h.pathProbing[id] = entry
		h.addStatelessResetToken(entry.StatelessResetToken)
		return entry.ConnectionID, true
	}
	if len(h.queue) == 0 {
		return protocol.ConnectionID{}, false
	}
	front := h.queue[0]
	h.queue = h.queue[1:]
	h.pathProbing[id] = front
	h.highestProbingID = front.SequenceNumber
	h.addStatelessResetToken(front.StatelessResetToken)
	return front.ConnectionID, true
}

// NextPathConnectionIDSequence returns the next sequence number that the peer
// is expected to issue for a path.
func (h *connIDManager) NextPathConnectionIDSequence(id pathID) uint64 {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	next := h.pathHighestRetired[id]
	if h.pathProbing != nil {
		if entry, ok := h.pathProbing[id]; ok {
			next = max(next, entry.SequenceNumber+1)
		}
	}
	for _, entry := range h.pathQueues[id] {
		next = max(next, entry.SequenceNumber+1)
	}
	return next
}

func (h *connIDManager) RetireConnIDForPath(pathID pathID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	entry, ok := h.pathProbing[pathID]
	if !ok {
		return
	}
	if h.multipath {
		h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
			PathID:         uint64(pathID),
			SequenceNumber: entry.SequenceNumber,
		})
	} else {
		h.queueControlFrame(&wire.RetireConnectionIDFrame{
			SequenceNumber: entry.SequenceNumber,
		})
	}
	h.removeStatelessResetToken(entry.StatelessResetToken)
	delete(h.pathProbing, pathID)
}

// AbandonPath immediately retires all peer-issued Connection IDs for a path.
// The path number space itself is kept by the Multipath state for delayed
// packets that may still arrive after PATH_ABANDON.
func (h *connIDManager) AbandonPath(id pathID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if h.abandonedPaths[id] {
		return
	}
	h.abandonedPaths[id] = true
	if h.abandonedRetired[id] == nil {
		h.abandonedRetired[id] = make(map[uint64]bool)
	}
	if id == 0 {
		if !h.abandonedRetired[0][h.activeSequenceNumber] {
			h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: h.activeSequenceNumber})
			h.abandonedRetired[0][h.activeSequenceNumber] = true
		}
		for _, entry := range h.queue {
			h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
			h.abandonedRetired[0][entry.SequenceNumber] = true
		}
		clear(h.queue)
		h.queue = nil
		if h.pathProbing != nil {
			if entry, ok := h.pathProbing[0]; ok {
				if !h.abandonedRetired[0][entry.SequenceNumber] {
					h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
					h.abandonedRetired[0][entry.SequenceNumber] = true
				}
				h.removeStatelessResetToken(entry.StatelessResetToken)
				delete(h.pathProbing, 0)
			}
		}
		return
	}
	for _, entry := range h.pathQueues[id] {
		h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
			PathID:         uint64(id),
			SequenceNumber: entry.SequenceNumber,
		})
		h.abandonedRetired[id][entry.SequenceNumber] = true
	}
	delete(h.pathQueues, id)
	if entry, ok := h.pathProbing[id]; ok {
		h.queueControlFrame(&wire.PathRetireConnectionIDFrame{
			PathID:         uint64(id),
			SequenceNumber: entry.SequenceNumber,
		})
		h.abandonedRetired[id][entry.SequenceNumber] = true
		h.removeStatelessResetToken(entry.StatelessResetToken)
		delete(h.pathProbing, id)
	}
}

func (h *connIDManager) IsActiveStatelessResetToken(token protocol.StatelessResetToken) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if h.activeStatelessResetToken != nil {
		if *h.activeStatelessResetToken == token {
			return true
		}
	}
	if h.pathProbing != nil {
		for _, entry := range h.pathProbing {
			if entry.StatelessResetToken == token {
				return true
			}
		}
	}
	return false
}

// Using the connIDManager after it has been closed can have disastrous effects:
// If the connection ID is rotated, a new entry would be inserted into the packet handler map,
// leading to a memory leak of the connection struct.
// See https://github.com/quic-go/quic-go/pull/4852 for more details.
func (h *connIDManager) assertNotClosed() {
	if h.closed {
		panic("connection ID manager is closed")
	}
}
