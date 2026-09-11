package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

func parseMultipathPathID(b []byte) (uint64, int, error) {
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, replaceUnexpectedEOF(err)
	}
	if pathID > protocol.MaxPathID {
		return 0, 0, fmt.Errorf("invalid path ID: %d (maximum %d)", pathID, protocol.MaxPathID)
	}
	return pathID, l, nil
}

func appendMultipathPathID(b []byte, pathID uint64) ([]byte, error) {
	if pathID > protocol.MaxPathID {
		return nil, fmt.Errorf("invalid path ID: %d (maximum %d)", pathID, protocol.MaxPathID)
	}
	return quicvarint.Append(b, pathID), nil
}

// PathAbandonFrame is a PATH_ABANDON frame.
type PathAbandonFrame struct {
	PathID    uint64
	ErrorCode uint64
}

func parsePathAbandonFrame(b []byte, _ protocol.Version) (*PathAbandonFrame, int, error) {
	startLen := len(b)
	pathID, l, err := parseMultipathPathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	errorCode, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &PathAbandonFrame{PathID: pathID, ErrorCode: errorCode}, startLen - len(b) + l, nil
}

func (f *PathAbandonFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	var err error
	b, err = appendMultipathPathID(quicvarint.Append(b, uint64(FrameTypePathAbandon)), f.PathID)
	if err != nil {
		return nil, err
	}
	return quicvarint.Append(b, f.ErrorCode), nil
}

func (f *PathAbandonFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathAbandon)) + quicvarint.Len(f.PathID) + quicvarint.Len(f.ErrorCode))
}

// PathStatusAvailableFrame is a PATH_STATUS_AVAILABLE frame.
type PathStatusAvailableFrame struct {
	PathID         uint64
	SequenceNumber uint64
}

func (f *PathStatusAvailableFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return appendPathStatusFrame(b, FrameTypePathStatusAvailable, f.PathID, f.SequenceNumber)
}

func (f *PathStatusAvailableFrame) Length(protocol.Version) protocol.ByteCount {
	return pathStatusFrameLength(FrameTypePathStatusAvailable, f.PathID, f.SequenceNumber)
}

// PathStatusBackupFrame is a PATH_STATUS_BACKUP frame.
type PathStatusBackupFrame struct {
	PathID         uint64
	SequenceNumber uint64
}

func (f *PathStatusBackupFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return appendPathStatusFrame(b, FrameTypePathStatusBackup, f.PathID, f.SequenceNumber)
}

func (f *PathStatusBackupFrame) Length(protocol.Version) protocol.ByteCount {
	return pathStatusFrameLength(FrameTypePathStatusBackup, f.PathID, f.SequenceNumber)
}

func appendPathStatusFrame(b []byte, typ FrameType, pathID, sequenceNumber uint64) ([]byte, error) {
	b = quicvarint.Append(b, uint64(typ))
	var err error
	b, err = appendMultipathPathID(b, pathID)
	if err != nil {
		return nil, err
	}
	return quicvarint.Append(b, sequenceNumber), nil
}

func pathStatusFrameLength(typ FrameType, pathID, sequenceNumber uint64) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(typ)) + quicvarint.Len(pathID) + quicvarint.Len(sequenceNumber))
}

func parsePathStatusFrame(b []byte, typ FrameType, _ protocol.Version) (Frame, int, error) {
	startLen := len(b)
	pathID, l, err := parseMultipathPathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	sequenceNumber, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if typ == FrameTypePathStatusAvailable {
		return &PathStatusAvailableFrame{PathID: pathID, SequenceNumber: sequenceNumber}, startLen - len(b), nil
	}
	return &PathStatusBackupFrame{PathID: pathID, SequenceNumber: sequenceNumber}, startLen - len(b), nil
}

// PathNewConnectionIDFrame is a PATH_NEW_CONNECTION_ID frame.
type PathNewConnectionIDFrame struct {
	PathID              uint64
	SequenceNumber      uint64
	RetirePriorTo       uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func parsePathNewConnectionIDFrame(b []byte, _ protocol.Version) (*PathNewConnectionIDFrame, int, error) {
	startLen := len(b)
	pathID, l, err := parseMultipathPathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	sequenceNumber, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	retirePriorTo, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if retirePriorTo > sequenceNumber {
		return nil, 0, errors.New("Retire Prior To value larger than Sequence Number")
	}
	b = b[l:]
	if len(b) == 0 {
		return nil, 0, io.EOF
	}
	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen < 8 || connIDLen > protocol.MaxConnIDLen {
		return nil, 0, fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	if len(b) < connIDLen+len(protocol.StatelessResetToken{}) {
		return nil, 0, io.EOF
	}
	frame := &PathNewConnectionIDFrame{
		PathID:         pathID,
		SequenceNumber: sequenceNumber,
		RetirePriorTo:  retirePriorTo,
		ConnectionID:   protocol.ParseConnectionID(b[:connIDLen]),
	}
	b = b[connIDLen:]
	copy(frame.StatelessResetToken[:], b[:len(frame.StatelessResetToken)])
	b = b[len(frame.StatelessResetToken):]
	return frame, startLen - len(b), nil
}

func (f *PathNewConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.ConnectionID.Len() < 8 || f.ConnectionID.Len() > protocol.MaxConnIDLen {
		return nil, fmt.Errorf("invalid connection ID length: %d", f.ConnectionID.Len())
	}
	if f.RetirePriorTo > f.SequenceNumber {
		return nil, errors.New("Retire Prior To value larger than Sequence Number")
	}
	b = quicvarint.Append(b, uint64(FrameTypePathNewConnectionID))
	var err error
	b, err = appendMultipathPathID(b, f.PathID)
	if err != nil {
		return nil, err
	}
	b = quicvarint.Append(b, f.SequenceNumber)
	b = quicvarint.Append(b, f.RetirePriorTo)
	b = append(b, byte(f.ConnectionID.Len()))
	b = append(b, f.ConnectionID.Bytes()...)
	b = append(b, f.StatelessResetToken[:]...)
	return b, nil
}

func (f *PathNewConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathNewConnectionID)) + quicvarint.Len(f.PathID) + quicvarint.Len(f.SequenceNumber) + quicvarint.Len(f.RetirePriorTo) + 1 + f.ConnectionID.Len() + len(f.StatelessResetToken))
}

// PathRetireConnectionIDFrame is a PATH_RETIRE_CONNECTION_ID frame.
type PathRetireConnectionIDFrame struct {
	PathID         uint64
	SequenceNumber uint64
}

func parsePathRetireConnectionIDFrame(b []byte, _ protocol.Version) (*PathRetireConnectionIDFrame, int, error) {
	startLen := len(b)
	pathID, l, err := parseMultipathPathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	sequenceNumber, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &PathRetireConnectionIDFrame{PathID: pathID, SequenceNumber: sequenceNumber}, startLen - len(b) + l, nil
}

func (f *PathRetireConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathRetireConnectionID))
	var err error
	b, err = appendMultipathPathID(b, f.PathID)
	if err != nil {
		return nil, err
	}
	return quicvarint.Append(b, f.SequenceNumber), nil
}

func (f *PathRetireConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathRetireConnectionID)) + quicvarint.Len(f.PathID) + quicvarint.Len(f.SequenceNumber))
}

// MaxPathIDFrame is a MAX_PATH_ID frame.
type MaxPathIDFrame struct {
	MaximumPathID uint64
}

func parseMaxPathIDFrame(b []byte, _ protocol.Version) (*MaxPathIDFrame, int, error) {
	value, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if value > protocol.MaxPathID {
		return nil, 0, fmt.Errorf("invalid maximum path ID: %d", value)
	}
	return &MaxPathIDFrame{MaximumPathID: value}, l, nil
}

func (f *MaxPathIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.MaximumPathID > protocol.MaxPathID {
		return nil, fmt.Errorf("invalid maximum path ID: %d", f.MaximumPathID)
	}
	b = quicvarint.Append(b, uint64(FrameTypeMaxPathID))
	return quicvarint.Append(b, f.MaximumPathID), nil
}

func (f *MaxPathIDFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeMaxPathID)) + quicvarint.Len(f.MaximumPathID))
}

// PathsBlockedFrame is a PATHS_BLOCKED frame.
type PathsBlockedFrame struct {
	MaximumPathID uint64
}

func parsePathsBlockedFrame(b []byte, _ protocol.Version) (*PathsBlockedFrame, int, error) {
	value, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if value > protocol.MaxPathID {
		return nil, 0, fmt.Errorf("invalid maximum path ID: %d", value)
	}
	return &PathsBlockedFrame{MaximumPathID: value}, l, nil
}

func (f *PathsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.MaximumPathID > protocol.MaxPathID {
		return nil, fmt.Errorf("invalid maximum path ID: %d", f.MaximumPathID)
	}
	b = quicvarint.Append(b, uint64(FrameTypePathsBlocked))
	return quicvarint.Append(b, f.MaximumPathID), nil
}

func (f *PathsBlockedFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathsBlocked)) + quicvarint.Len(f.MaximumPathID))
}

// PathCIDsBlockedFrame is a PATH_CIDS_BLOCKED frame.
type PathCIDsBlockedFrame struct {
	PathID             uint64
	NextSequenceNumber uint64
}

func parsePathCIDsBlockedFrame(b []byte, _ protocol.Version) (*PathCIDsBlockedFrame, int, error) {
	startLen := len(b)
	pathID, l, err := parseMultipathPathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	nextSequenceNumber, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &PathCIDsBlockedFrame{PathID: pathID, NextSequenceNumber: nextSequenceNumber}, startLen - len(b) + l, nil
}

func (f *PathCIDsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathCIDsBlocked))
	var err error
	b, err = appendMultipathPathID(b, f.PathID)
	if err != nil {
		return nil, err
	}
	return quicvarint.Append(b, f.NextSequenceNumber), nil
}

func (f *PathCIDsBlockedFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathCIDsBlocked)) + quicvarint.Len(f.PathID) + quicvarint.Len(f.NextSequenceNumber))
}
