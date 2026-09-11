package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

// multipathPacketNumberSpace tracks the packet numbers that belong to one
// Multipath QUIC path. Each path has an independent packet number sequence.
type multipathPacketNumberSpace struct {
	nextPacketNumber    protocol.PacketNumber
	largestReceived     protocol.PacketNumber
	largestAcknowledged protocol.PacketNumber
}

func newMultipathPacketNumberSpace() multipathPacketNumberSpace {
	return multipathPacketNumberSpace{
		largestReceived:     protocol.InvalidPacketNumber,
		largestAcknowledged: protocol.InvalidPacketNumber,
	}
}

func (s *multipathPacketNumberSpace) popPacketNumber() (protocol.PacketNumber, error) {
	if s.nextPacketNumber > protocol.MaxPathAndPacketNumber {
		return protocol.InvalidPacketNumber, fmt.Errorf("path packet number space exhausted")
	}
	pn := s.nextPacketNumber
	s.nextPacketNumber++
	return pn, nil
}

func (s *multipathPacketNumberSpace) observeReceived(pn protocol.PacketNumber) error {
	if pn < 0 || pn > protocol.MaxPathAndPacketNumber {
		return fmt.Errorf("received invalid path packet number %d", pn)
	}
	if pn > s.largestReceived {
		s.largestReceived = pn
	}
	return nil
}

func (s *multipathPacketNumberSpace) observeAcknowledged(pn protocol.PacketNumber) error {
	if pn < 0 || pn > protocol.MaxPathAndPacketNumber {
		return fmt.Errorf("acknowledged invalid path packet number %d", pn)
	}
	if pn > s.largestAcknowledged {
		s.largestAcknowledged = pn
	}
	return nil
}

// multipathPathState contains the state that is independent for each path ID.
type multipathPathState struct {
	abandoned bool

	packetNumberSpace multipathPacketNumberSpace

	hasStatus      bool
	statusSequence uint64
	statusBackup   bool

	nextConnectionIDSequence uint64
	// highestRetiredConnectionID is the Retire Prior To threshold. Sequence
	// numbers below this value are retired, even when their frames arrived
	// after the frame that advanced the threshold.
	highestRetiredConnectionID uint64
	connectionIDs              map[uint64]wire.PathNewConnectionIDFrame
	retiredConnectionIDs       map[uint64]bool
}

type multipathState struct {
	localMaxPathID uint64

	peerInitialMaxPathID uint64
	peerMaxPathID        uint64

	paths                map[uint64]*multipathPathState
	connectionIDToPathID map[protocol.ConnectionID]uint64
}

func newMultipathState(localMaxPathID uint64) *multipathState {
	return &multipathState{
		localMaxPathID:       localMaxPathID,
		paths:                make(map[uint64]*multipathPathState),
		connectionIDToPathID: make(map[protocol.ConnectionID]uint64),
	}
}

func (m *multipathState) pathIDForConnectionID(connID protocol.ConnectionID) (uint64, bool) {
	pathID, ok := m.connectionIDToPathID[connID]
	return pathID, ok
}

func (m *multipathState) path(pathID uint64) (*multipathPathState, error) {
	if pathID > m.localMaxPathID {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("received path ID %d above local maximum %d", pathID, m.localMaxPathID),
		}
	}
	p, ok := m.paths[pathID]
	if !ok {
		p = &multipathPathState{
			packetNumberSpace:    newMultipathPacketNumberSpace(),
			connectionIDs:        make(map[uint64]wire.PathNewConnectionIDFrame),
			retiredConnectionIDs: make(map[uint64]bool),
		}
		m.paths[pathID] = p
	}
	return p, nil
}

func (m *multipathState) nextPacketNumber(pathID uint64) (protocol.PacketNumber, error) {
	p, err := m.path(pathID)
	if err != nil {
		return protocol.InvalidPacketNumber, err
	}
	return p.packetNumberSpace.popPacketNumber()
}

func (m *multipathState) observeReceivedPacketNumber(pathID uint64, pn protocol.PacketNumber) error {
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	return p.packetNumberSpace.observeReceived(pn)
}

func (m *multipathState) observeAcknowledgedPacketNumber(pathID uint64, pn protocol.PacketNumber) error {
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	return p.packetNumberSpace.observeAcknowledged(pn)
}

func (m *multipathState) handlePathAck(f *wire.AckFrame) error {
	if f.PathID == nil || *f.PathID == 0 {
		return fmt.Errorf("PATH_ACK must identify a non-initial path")
	}
	p, err := m.path(*f.PathID)
	if err != nil {
		return err
	}
	// Packets and ACKs can arrive after PATH_ABANDON. The path state is kept
	// long enough to ignore those delayed frames without affecting the active
	// paths.
	if p.abandoned {
		return nil
	}
	return p.packetNumberSpace.observeAcknowledged(f.LargestAcked())
}

func (m *multipathState) setPeerInitialMaxPathID(maxPathID uint64) {
	m.peerInitialMaxPathID = maxPathID
	m.peerMaxPathID = maxPathID
}

func (m *multipathState) handleMaxPathID(f *wire.MaxPathIDFrame) error {
	if f.MaximumPathID < m.peerInitialMaxPathID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("MAX_PATH_ID reduced the initial path limit from %d to %d", m.peerInitialMaxPathID, f.MaximumPathID),
		}
	}
	if f.MaximumPathID > m.peerMaxPathID {
		m.peerMaxPathID = f.MaximumPathID
	}
	return nil
}

func (m *multipathState) handlePathAbandon(f *wire.PathAbandonFrame) (bool, error) {
	p, err := m.path(f.PathID)
	if err != nil {
		return false, err
	}
	if p.abandoned {
		return false, nil
	}
	p.abandoned = true
	return true, nil
}

func (m *multipathState) handlePathStatus(pathID, sequenceNumber uint64, backup bool) error {
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	if p.hasStatus && sequenceNumber <= p.statusSequence {
		return nil
	}
	p.hasStatus = true
	p.statusSequence = sequenceNumber
	p.statusBackup = backup
	return nil
}

func (m *multipathState) handlePathNewConnectionID(f *wire.PathNewConnectionIDFrame) error {
	p, err := m.path(f.PathID)
	if err != nil {
		return err
	}
	if previous, ok := p.connectionIDs[f.SequenceNumber]; ok {
		if previous.ConnectionID != f.ConnectionID || previous.StatelessResetToken != f.StatelessResetToken {
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: fmt.Sprintf("conflicting PATH_NEW_CONNECTION_ID for path %d and sequence %d", f.PathID, f.SequenceNumber),
			}
		}
		return nil
	}
	if previousPathID, ok := m.connectionIDToPathID[f.ConnectionID]; ok && previousPathID != f.PathID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("connection ID %s is already assigned to path %d", f.ConnectionID, previousPathID),
		}
	}
	if f.RetirePriorTo > p.highestRetiredConnectionID {
		for sequenceNumber := range p.connectionIDs {
			if sequenceNumber < f.RetirePriorTo {
				delete(p.connectionIDs, sequenceNumber)
				p.retiredConnectionIDs[sequenceNumber] = true
			}
		}
		p.highestRetiredConnectionID = f.RetirePriorTo
	}
	if f.SequenceNumber < p.highestRetiredConnectionID {
		p.retiredConnectionIDs[f.SequenceNumber] = true
		return nil
	}
	p.connectionIDs[f.SequenceNumber] = *f
	m.connectionIDToPathID[f.ConnectionID] = f.PathID
	if f.SequenceNumber >= p.nextConnectionIDSequence {
		p.nextConnectionIDSequence = f.SequenceNumber + 1
	}
	return nil
}

func (m *multipathState) handlePathRetireConnectionID(f *wire.PathRetireConnectionIDFrame) error {
	p, err := m.path(f.PathID)
	if err != nil {
		return err
	}
	if f.SequenceNumber >= p.nextConnectionIDSequence {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("PATH_RETIRE_CONNECTION_ID references unknown sequence number %d for path %d", f.SequenceNumber, f.PathID),
		}
	}
	if f.SequenceNumber < p.highestRetiredConnectionID {
		return nil
	}
	if connectionID, ok := p.connectionIDs[f.SequenceNumber]; ok {
		delete(m.connectionIDToPathID, connectionID.ConnectionID)
		delete(p.connectionIDs, f.SequenceNumber)
	}
	p.retiredConnectionIDs[f.SequenceNumber] = true
	return nil
}

func (m *multipathState) handlePathCIDsBlocked(f *wire.PathCIDsBlockedFrame) error {
	p, err := m.path(f.PathID)
	if err != nil {
		return err
	}
	if f.NextSequenceNumber > p.nextConnectionIDSequence {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("PATH_CIDS_BLOCKED expects sequence number %d for path %d, next expected is %d", f.NextSequenceNumber, f.PathID, p.nextConnectionIDSequence),
		}
	}
	return nil
}
