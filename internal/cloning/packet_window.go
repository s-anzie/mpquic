package cloning

import "github.com/quic-go/quic-go/internal/protocol"

const MaxRemotePacketWindow = 64

// ValidateRemotePath rejects bootstrap admission after retirement or closure.
// It cannot recall an export that already passed admission and started I/O.
func (a *Authority) ValidateRemotePath(p *Path) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkPath(p); err != nil {
		return err
	}
	if !p.remoteSender {
		return ErrPath
	}
	return nil
}

// ReservePacketWindow permanently transfers allocation away from the ordinary
// primary sender. Call only after quiescing that sender on the connection loop.
// Windows never overlap and are never refunded, including on failed bootstrap.
// This does not establish a path, validate an address or transfer packet history.
func (a *Authority) ReservePacketWindow(p *Path, count uint64) (path uint64, first protocol.PacketNumber, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.checkPath(p); err != nil {
		return 0, 0, err
	}
	if count == 0 || count > MaxRemotePacketWindow || p.nextPacketNumber > uint64(protocol.MaxPathAndPacketNumber) || count-1 > uint64(protocol.MaxPathAndPacketNumber)-p.nextPacketNumber {
		return 0, 0, ErrLimit
	}
	first = protocol.PacketNumber(p.nextPacketNumber)
	p.nextPacketNumber += count
	p.remoteSender = true
	return p.id, first, nil
}
