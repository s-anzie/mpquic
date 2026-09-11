package quic

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

// multipathPacketNumberSpace tracks the packet numbers that belong to one
// Multipath QUIC path. Each path has an independent packet number sequence.
type multipathPacketNumberSpace struct {
	nextPacketNumber    protocol.PacketNumber
	largestReceived     protocol.PacketNumber
	largestAcknowledged protocol.PacketNumber
}

type multipathSentPacket struct {
	sentAt       monotime.Time
	size         protocol.ByteCount
	ackEliciting bool
	isProbe      bool
	frames       []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame
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
	largestSent       protocol.PacketNumber
	sentPackets       map[protocol.PacketNumber]multipathSentPacket
	congestion        congestion.SendAlgorithmWithDebugInfos
	rttStats          *utils.RTTStats
	bytesInFlight     protocol.ByteCount
	latestRTT         time.Duration
	smoothedRTT       time.Duration
	lossDelay         time.Duration

	hasStatus          bool
	statusSequence     uint64
	statusBackup       bool
	nextStatusSequence uint64

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
	newPathCongestion    func() (*utils.RTTStats, congestion.SendAlgorithmWithDebugInfos)
}

// configurePathCongestion creates an independent congestion controller for
// every Multipath path. The connection statistics remain shared so that the
// public connection metrics include all paths.
func (m *multipathState) configurePathCongestion(initialMaxDatagramSize protocol.ByteCount, connStats *utils.ConnectionStats) {
	m.newPathCongestion = func() (*utils.RTTStats, congestion.SendAlgorithmWithDebugInfos) {
		rttStats := utils.NewRTTStats()
		return rttStats, congestion.NewCubicSender(
			congestion.DefaultClock{},
			rttStats,
			connStats,
			initialMaxDatagramSize,
			true,
			nil,
		)
	}
	for _, p := range m.paths {
		if p.congestion == nil {
			p.rttStats, p.congestion = m.newPathCongestion()
		}
	}
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
			largestSent:          protocol.InvalidPacketNumber,
			sentPackets:          make(map[protocol.PacketNumber]multipathSentPacket),
			connectionIDs:        make(map[uint64]wire.PathNewConnectionIDFrame),
			retiredConnectionIDs: make(map[uint64]bool),
			lossDelay:            time.Second,
		}
		if m.newPathCongestion != nil {
			p.rttStats, p.congestion = m.newPathCongestion()
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

func (m *multipathState) allocatePacketNumber(pathID uint64) (protocol.PacketNumber, protocol.PacketNumberLen, error) {
	p, err := m.path(pathID)
	if err != nil {
		return protocol.InvalidPacketNumber, 0, err
	}
	pn, err := p.packetNumberSpace.popPacketNumber()
	if err != nil {
		return protocol.InvalidPacketNumber, 0, err
	}
	return pn, protocol.PacketNumberLengthForHeader(pn, p.packetNumberSpace.largestAcknowledged), nil
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

func (m *multipathState) handlePathAck(f *wire.AckFrame, receivedAt ...monotime.Time) error {
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
	if p.largestSent == protocol.InvalidPacketNumber || f.LargestAcked() > p.largestSent {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("received PATH_ACK for unsent packet %d on path %d", f.LargestAcked(), *f.PathID),
		}
	}
	rcvTime := monotime.Now()
	if len(receivedAt) > 0 {
		rcvTime = receivedAt[0]
	}
	if err := p.packetNumberSpace.observeAcknowledged(f.LargestAcked()); err != nil {
		return err
	}
	for packetNumber := range p.sentPackets {
		for _, ackRange := range f.AckRanges {
			if packetNumber >= ackRange.Smallest && packetNumber <= ackRange.Largest {
				packet := p.sentPackets[packetNumber]
				if packetNumber == f.LargestAcked() && packet.ackEliciting {
					m.updatePathRTT(p, packet, f.DelayTime, rcvTime)
				}
				if packet.ackEliciting && packet.size > 0 {
					priorInFlight := p.bytesInFlight
					p.bytesInFlight -= min(p.bytesInFlight, packet.size)
					if p.congestion != nil {
						p.congestion.OnPacketAcked(packetNumber, packet.size, priorInFlight, rcvTime)
					}
				}
				for _, frame := range packet.frames {
					if frame.Handler != nil && frame.Frame != nil {
						frame.Handler.OnAcked(frame.Frame)
					}
				}
				for _, frame := range packet.streamFrames {
					if frame.Handler != nil && frame.Frame != nil {
						frame.Handler.OnAcked(frame.Frame)
					}
				}
				delete(p.sentPackets, packetNumber)
				break
			}
		}
	}
	return nil
}

func (m *multipathState) updatePathRTT(p *multipathPathState, packet multipathSentPacket, ackDelay time.Duration, receivedAt monotime.Time) {
	if p.rttStats != nil {
		p.rttStats.UpdateRTT(receivedAt.Sub(packet.sentAt), ackDelay)
		p.latestRTT = p.rttStats.LatestRTT()
		p.smoothedRTT = p.rttStats.SmoothedRTT()
		maxRTT := max(p.latestRTT, p.smoothedRTT)
		p.lossDelay = max(time.Duration(9*maxRTT/8), protocol.TimerGranularity)
		return
	}
	rttSample := receivedAt.Sub(packet.sentAt) - ackDelay
	if rttSample <= 0 {
		rttSample = receivedAt.Sub(packet.sentAt)
	}
	if rttSample <= 0 {
		return
	}
	p.latestRTT = rttSample
	if p.smoothedRTT == 0 {
		p.smoothedRTT = rttSample
	} else {
		p.smoothedRTT = (7*p.smoothedRTT + rttSample) / 8
	}
	maxRTT := max(p.latestRTT, p.smoothedRTT)
	p.lossDelay = max(time.Duration(9*maxRTT/8), protocol.TimerGranularity)
}

// recordSentPacket records a packet that belongs to a Multipath path. The
// packet number is retained until a PATH_ACK acknowledges it.
func (m *multipathState) recordSentPacket(pathID uint64, packetNumber protocol.PacketNumber, sentAt monotime.Time) error {
	return m.recordSentPacketWithSize(pathID, packetNumber, sentAt, 0, false)
}

func (m *multipathState) recordSentPacketWithSize(pathID uint64, packetNumber protocol.PacketNumber, sentAt monotime.Time, size protocol.ByteCount, ackEliciting bool) error {
	if pathID == 0 {
		return nil
	}
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	if packetNumber < 0 || packetNumber > protocol.MaxPathAndPacketNumber {
		return fmt.Errorf("sent invalid path packet number %d", packetNumber)
	}
	p.largestSent = max(p.largestSent, packetNumber)
	p.sentPackets[packetNumber] = multipathSentPacket{
		sentAt:       sentAt,
		size:         size,
		ackEliciting: ackEliciting,
		isProbe:      true,
	}
	m.onPathPacketSent(p, sentAt, packetNumber, size, ackEliciting)
	return nil
}

// recordSentApplicationPacket tracks a packet that carries application data
// in a path-specific packet number space.
func (m *multipathState) recordSentApplicationPacket(pathID uint64, packetNumber protocol.PacketNumber, sentAt monotime.Time, frames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame) error {
	return m.recordSentApplicationPacketWithSize(pathID, packetNumber, sentAt, 0, false, frames, streamFrames)
}

func (m *multipathState) recordSentApplicationPacketWithSize(pathID uint64, packetNumber protocol.PacketNumber, sentAt monotime.Time, size protocol.ByteCount, ackEliciting bool, frames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame) error {
	if pathID == 0 {
		return nil
	}
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	if packetNumber < 0 || packetNumber > protocol.MaxPathAndPacketNumber {
		return fmt.Errorf("sent invalid path packet number %d", packetNumber)
	}
	p.largestSent = max(p.largestSent, packetNumber)
	p.sentPackets[packetNumber] = multipathSentPacket{
		sentAt:       sentAt,
		size:         size,
		ackEliciting: ackEliciting,
		frames:       frames,
		streamFrames: streamFrames,
	}
	m.onPathPacketSent(p, sentAt, packetNumber, size, ackEliciting)
	return nil
}

func (m *multipathState) onPathPacketSent(p *multipathPathState, sentAt monotime.Time, packetNumber protocol.PacketNumber, size protocol.ByteCount, ackEliciting bool) {
	if !ackEliciting || size == 0 || p.congestion == nil {
		return
	}
	p.bytesInFlight += size
	p.congestion.OnPacketSent(sentAt, p.bytesInFlight, packetNumber, size, true)
}

// canSendOnPath reports whether the path-specific congestion controller allows
// another ack-eliciting packet to be sent.
func (m *multipathState) canSendOnPath(pathID uint64, now monotime.Time) bool {
	p, ok := m.paths[pathID]
	if !ok || p.abandoned || p.congestion == nil {
		return true
	}
	return p.congestion.CanSend(p.bytesInFlight) && p.congestion.HasPacingBudget(now)
}

func (m *multipathState) nextPathProbeLossTime(lossDelay time.Duration) monotime.Time {
	var earliest monotime.Time
	for _, p := range m.paths {
		pathLossDelay := p.lossDelay
		if pathLossDelay <= 0 {
			pathLossDelay = lossDelay
		}
		for _, packet := range p.sentPackets {
			lossTime := packet.sentAt.Add(pathLossDelay)
			if earliest.IsZero() || lossTime.Before(earliest) {
				earliest = lossTime
			}
		}
	}
	return earliest
}

func (m *multipathState) detectLostPathProbes(now monotime.Time, lossDelay time.Duration) []uint64 {
	lostPaths := make(map[uint64]struct{})
	for pathID, p := range m.paths {
		if p.abandoned {
			continue
		}
		pathLossDelay := p.lossDelay
		if pathLossDelay <= 0 {
			pathLossDelay = lossDelay
		}
		lossTime := now.Add(-pathLossDelay)
		for packetNumber, packet := range p.sentPackets {
			if !packet.sentAt.After(lossTime) {
				if packet.ackEliciting && packet.size > 0 {
					priorInFlight := p.bytesInFlight
					p.bytesInFlight -= min(p.bytesInFlight, packet.size)
					if p.congestion != nil {
						p.congestion.OnCongestionEvent(packetNumber, packet.size, priorInFlight)
					}
				}
				for _, frame := range packet.frames {
					if frame.Handler != nil && frame.Frame != nil {
						frame.Handler.OnLost(frame.Frame)
					}
				}
				for _, frame := range packet.streamFrames {
					if frame.Handler != nil && frame.Frame != nil {
						frame.Handler.OnLost(frame.Frame)
					}
				}
				delete(p.sentPackets, packetNumber)
				if packet.isProbe {
					lostPaths[pathID] = struct{}{}
				}
			}
		}
	}
	result := make([]uint64, 0, len(lostPaths))
	for pathID := range lostPaths {
		result = append(result, pathID)
	}
	return result
}

func (m *multipathState) hasOutstandingPacket(pathID uint64, packetNumber protocol.PacketNumber) bool {
	p, ok := m.paths[pathID]
	if !ok {
		return false
	}
	_, ok = p.sentPackets[packetNumber]
	return ok
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

func (m *multipathState) markPathAbandoned(pathID uint64) error {
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	if p.abandoned {
		return nil
	}
	p.abandoned = true
	return nil
}

func (m *multipathState) handlePathStatus(pathID, sequenceNumber uint64, backup bool) error {
	p, err := m.path(pathID)
	if err != nil {
		return err
	}
	if p.abandoned {
		return nil
	}
	if p.hasStatus && sequenceNumber <= p.statusSequence {
		return nil
	}
	p.hasStatus = true
	p.statusSequence = sequenceNumber
	p.statusBackup = backup
	return nil
}

// nextPathStatusFrame creates the next status update for a path. Status
// sequence numbers are scoped to a path and increase for every update sent.
func (m *multipathState) nextPathStatusFrame(pathID uint64, backup bool) (wire.Frame, error) {
	p, err := m.path(pathID)
	if err != nil {
		return nil, err
	}
	sequenceNumber := p.nextStatusSequence
	p.nextStatusSequence++
	if backup {
		return &wire.PathStatusBackupFrame{
			PathID:         pathID,
			SequenceNumber: sequenceNumber,
		}, nil
	}
	return &wire.PathStatusAvailableFrame{
		PathID:         pathID,
		SequenceNumber: sequenceNumber,
	}, nil
}

func (m *multipathState) handlePathNewConnectionID(f *wire.PathNewConnectionIDFrame) error {
	p, err := m.path(f.PathID)
	if err != nil {
		return err
	}
	if p.abandoned {
		return nil
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
	if p.abandoned {
		return nil
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
	if p.abandoned {
		return nil
	}
	if f.NextSequenceNumber > p.nextConnectionIDSequence {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("PATH_CIDS_BLOCKED expects sequence number %d for path %d, next expected is %d", f.NextSequenceNumber, f.PathID, p.nextConnectionIDSequence),
		}
	}
	return nil
}
