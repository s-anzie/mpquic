package ackhandler

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type ReceivedPacketHandler struct {
	initialPackets   *receivedPacketTracker
	handshakePackets *receivedPacketTracker
	appDataPackets   appDataReceivedPacketTracker
	multipathPackets map[uint64]*appDataReceivedPacketTracker
	abandonedPaths   map[uint64]bool

	lowest1RTTPacket protocol.PacketNumber
}

func NewReceivedPacketHandler(logger utils.Logger) *ReceivedPacketHandler {
	return &ReceivedPacketHandler{
		initialPackets:   newReceivedPacketTracker(),
		handshakePackets: newReceivedPacketTracker(),
		appDataPackets:   *newAppDataReceivedPacketTracker(logger),
		multipathPackets: make(map[uint64]*appDataReceivedPacketTracker),
		abandonedPaths:   make(map[uint64]bool),
		lowest1RTTPacket: protocol.InvalidPacketNumber,
	}
}

// ReceivedPacketForPath records a 1-RTT packet in the independent packet
// number space of a Multipath path.
func (h *ReceivedPacketHandler) ReceivedPacketForPath(
	pathID uint64,
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	ackEliciting bool,
) error {
	tracker, ok := h.multipathPackets[pathID]
	if !ok {
		tracker = newAppDataReceivedPacketTracker(h.appDataPackets.logger)
		h.multipathPackets[pathID] = tracker
	}
	err := tracker.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	if err == nil && h.abandonedPaths[pathID] {
		tracker.disableACK()
	}
	return err
}

func (h *ReceivedPacketHandler) ReceivedPacket(
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	encLevel protocol.EncryptionLevel,
	rcvTime monotime.Time,
	ackEliciting bool,
) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.EncryptionHandshake:
		// The Handshake packet number space might already have been dropped as a result
		// of processing the CRYPTO frame that was contained in this packet.
		if h.handshakePackets == nil {
			return nil
		}
		return h.handshakePackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.Encryption0RTT:
		if h.lowest1RTTPacket != protocol.InvalidPacketNumber && pn > h.lowest1RTTPacket {
			return fmt.Errorf("received packet number %d on a 0-RTT packet after receiving %d on a 1-RTT packet", pn, h.lowest1RTTPacket)
		}
		return h.appDataPackets.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	case protocol.Encryption1RTT:
		if h.lowest1RTTPacket == protocol.InvalidPacketNumber || pn < h.lowest1RTTPacket {
			h.lowest1RTTPacket = pn
		}
		err := h.appDataPackets.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
		if err == nil && h.abandonedPaths[0] {
			h.appDataPackets.disableACK()
		}
		return err
	default:
		panic(fmt.Sprintf("received packet with unknown encryption level: %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) IgnorePacketsBelow(pn protocol.PacketNumber) {
	h.appDataPackets.IgnoreBelow(pn)
}

// AbandonPath stops scheduling ACKs for a path while retaining its packet
// number state for duplicate detection and delayed packet processing.
func (h *ReceivedPacketHandler) AbandonPath(pathID uint64) {
	h.abandonedPaths[pathID] = true
	if pathID == 0 {
		h.appDataPackets.disableACK()
		return
	}
	if tracker, ok := h.multipathPackets[pathID]; ok {
		tracker.disableACK()
	}
}

func (h *ReceivedPacketHandler) DropPackets(encLevel protocol.EncryptionLevel) {
	//nolint:exhaustive // 1-RTT packet number space is never dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// Nothing to do here.
		// If we are rejecting 0-RTT, no 0-RTT packets will have been decrypted.
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) GetAlarmTimeout() monotime.Time {
	earliest := h.appDataPackets.GetAlarmTimeout()
	for _, tracker := range h.multipathPackets {
		alarm := tracker.GetAlarmTimeout()
		if !alarm.IsZero() && (earliest.IsZero() || alarm.Before(earliest)) {
			earliest = alarm
		}
	}
	return earliest
}

func (h *ReceivedPacketHandler) GetAckFrame(encLevel protocol.EncryptionLevel, now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	//nolint:exhaustive // 0-RTT packets can't contain ACK frames.
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialPackets != nil {
			return h.initialPackets.GetAckFrame()
		}
		return nil
	case protocol.EncryptionHandshake:
		if h.handshakePackets != nil {
			return h.handshakePackets.GetAckFrame()
		}
		return nil
	case protocol.Encryption1RTT:
		return h.appDataPackets.GetAckFrame(now, onlyIfQueued)
	default:
		// 0-RTT packets can't contain ACK frames
		return nil
	}
}

func (h *ReceivedPacketHandler) IsPotentiallyDuplicate(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) bool {
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialPackets != nil {
			return h.initialPackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.EncryptionHandshake:
		if h.handshakePackets != nil {
			return h.handshakePackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.appDataPackets.IsPotentiallyDuplicate(pn)
	}
	panic("unexpected encryption level")
}

// IsPotentiallyDuplicateForPath checks the packet number space of a
// Multipath path instead of the regular application-data packet number space.
func (h *ReceivedPacketHandler) IsPotentiallyDuplicateForPath(pathID uint64, pn protocol.PacketNumber) bool {
	tracker, ok := h.multipathPackets[pathID]
	return ok && tracker.IsPotentiallyDuplicate(pn)
}

// GetAckFrameForPath returns a PATH_ACK for a Multipath path when an ACK is
// due. The caller is responsible for placing the frame on that path.
func (h *ReceivedPacketHandler) GetAckFrameForPath(pathID uint64, now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	tracker, ok := h.multipathPackets[pathID]
	if !ok {
		return nil
	}
	ack := tracker.GetAckFrame(now, onlyIfQueued)
	if ack == nil {
		return nil
	}
	ackPathID := pathID
	ack.PathID = &ackPathID
	return ack
}
