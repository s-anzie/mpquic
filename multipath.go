package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

// multipathPathState contains the state that is independent for each path ID.
// Packet number spaces and congestion control will be added in a later lot.
type multipathPathState struct {
	abandoned bool

	hasStatus      bool
	statusSequence uint64
	statusBackup   bool

	nextConnectionIDSequence uint64
	connectionIDs            map[uint64]wire.PathNewConnectionIDFrame
	retiredConnectionIDs     map[uint64]bool
}

type multipathState struct {
	localMaxPathID uint64

	peerInitialMaxPathID uint64
	peerMaxPathID        uint64

	paths map[uint64]*multipathPathState
}

func newMultipathState(localMaxPathID uint64) *multipathState {
	return &multipathState{
		localMaxPathID: localMaxPathID,
		paths:          make(map[uint64]*multipathPathState),
	}
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
			connectionIDs:        make(map[uint64]wire.PathNewConnectionIDFrame),
			retiredConnectionIDs: make(map[uint64]bool),
		}
		m.paths[pathID] = p
	}
	return p, nil
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
	if f.RetirePriorTo > p.nextConnectionIDSequence {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("PATH_NEW_CONNECTION_ID retires an unknown sequence number %d for path %d", f.RetirePriorTo, f.PathID),
		}
	}
	for sequenceNumber := range p.connectionIDs {
		if sequenceNumber < f.RetirePriorTo {
			delete(p.connectionIDs, sequenceNumber)
			p.retiredConnectionIDs[sequenceNumber] = true
		}
	}
	p.connectionIDs[f.SequenceNumber] = *f
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
	delete(p.connectionIDs, f.SequenceNumber)
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
