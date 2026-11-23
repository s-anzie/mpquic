package quic

import (
	"net"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

func (p *multipathPathState) validateServerResponse(data [8]byte) {
	if !p.abandoned && p.serverChallengePending && p.serverChallenge == data {
		p.serverValidated = true
		p.serverChallengePending = false
		p.serverChallengeDeadline = 0
	}
}

// Retry a lost validation exchange without allowing an unvalidated address
// to receive application traffic or exceed its amplification budget.
func (c *Conn) retryServerPathValidation(now monotime.Time) error {
	if c.perspective != protocol.PerspectiveServer {
		return nil
	}
	for id, p := range c.multipath.paths {
		if p.abandoned || !p.serverChallengePending || p.serverChallengeDeadline.IsZero() || p.serverChallengeDeadline.After(now) {
			continue
		}
		p.serverChallengeDeadline = 0
		if p.serverChallengeAttempts >= 3 || p.serverProbeBytesSent+protocol.MinInitialPacketSize > 3*p.serverBytesReceived {
			continue
		}
		cid, ok := c.connIDManager.GetConnIDForPath(pathID(id))
		if !ok {
			continue
		}
		packet, buf, err := c.packPathProbePacket(id, cid, []ackhandler.Frame{{Frame: &wire.PathChallengeFrame{Data: p.serverChallenge}}}, c.version)
		if err != nil {
			return err
		}
		c.registerPackedShortHeaderPacket(packet, protocol.ECNNon, now)
		err = c.writeExperimentalPath(id, buf.Data, p.remoteAddr, p.packetInfo)
		p.serverProbeBytesSent += buf.Len()
		buf.Release()
		if err != nil {
			return err
		}
		p.serverChallengeAttempts++
		p.serverChallengeDeadline = now.Add(time.Duration(1<<p.serverChallengeAttempts) * 200 * time.Millisecond)
	}
	return nil
}

// nextServerApplicationPath schedules only paths whose peer address has been
// validated by a matching PATH_RESPONSE. Receiving a challenge is not enough.
func (c *Conn) nextServerApplicationPath(now monotime.Time) (pathID, protocol.ConnectionID, bool) {
	ids := []uint64{0}
	for id, p := range c.multipath.paths {
		if id != 0 && p.serverValidated && !p.abandoned && p.remoteAddr != nil && p.cloningRecovery == nil && p.experimentalRelay == nil {
			ids = append(ids, id)
		}
	}
	// Preserve the ordinary send path until a secondary address is validated.
	if len(ids) == 1 {
		return 0, protocol.ConnectionID{}, false
	}
	slices.Sort(ids)
	start, _ := slices.BinarySearch(ids, c.multipath.nextServerApplicationPath)
	for i := range ids {
		id := ids[(start+i)%len(ids)]
		if c.multipath.isPathAbandoned(id) {
			continue
		}
		if id == 0 {
			if c.sentPacketHandler.SendMode(now) != ackhandler.SendAny {
				continue
			}
			c.multipath.nextServerApplicationPath = 1
			return 0, c.connIDManager.Get(), true
		}
		if !c.multipath.canSendOnPath(id, now) {
			continue
		}
		cid, ok := c.connIDManager.GetConnIDForPath(pathID(id))
		if !ok {
			continue
		}
		c.multipath.nextServerApplicationPath = id + 1
		return pathID(id), cid, true
	}
	return 0, protocol.ConnectionID{}, false
}

func (c *Conn) writeMultipathApplication(id uint64, tr *Transport, data []byte, gsoSize uint16) (err error) {
	defer func() {
		if err != nil {
			err = c.handlePathSendError(id, err)
		}
	}()
	if c.perspective == protocol.PerspectiveClient {
		return tr.writePacket(data, c.conn.RemoteAddr(), gsoSize)
	}
	path := c.multipath.paths[id]
	if conn, ok := c.conn.(*sconn); ok && gsoSize != 0 && path.experimentalRelay == nil {
		_, err := conn.rawConn.WritePacket(data, path.remoteAddr, path.packetInfo.OOB(), gsoSize, protocol.ECNUnsupported)
		if err == nil || !isGSOError(err) {
			return err
		}
	}
	// Preserve packet boundaries on sockets without GSO and on GSO failure.
	for len(data) > 0 {
		n := len(data)
		if gsoSize != 0 {
			n = min(n, int(gsoSize))
		}
		if err := c.writeExperimentalPath(id, data[:n], path.remoteAddr, path.packetInfo); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// sendMultipathApplicationBuffer transfers buffer ownership to the send queue.
// Capture the validated destination on the connection loop: the writer must not
// access mutable path, recovery, or cloning state.
func (c *Conn) sendMultipathApplicationBuffer(id uint64, tr *Transport, buf *packetBuffer, gsoSize uint16) error {
	q, ok := c.sendQueue.(*sendQueue)
	if !ok {
		defer buf.Release()
		return c.writeMultipathApplication(id, tr, buf.Data, gsoSize)
	}
	var socket rawConn
	var addr net.Addr
	var oob []byte
	if c.perspective == protocol.PerspectiveClient {
		if err := tr.init(false); err != nil {
			buf.Release()
			return c.handlePathSendError(id, err)
		}
		socket, addr = tr.conn, c.conn.RemoteAddr()
	} else {
		path := c.multipath.paths[id]
		conn, ok := c.conn.(*sconn)
		if !ok || path.experimentalRelay != nil {
			defer buf.Release()
			return c.writeMultipathApplication(id, tr, buf.Data, gsoSize)
		}
		socket, addr, oob = conn.rawConn, path.remoteAddr, path.packetInfo.OOB()
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		snapshot := *udp
		snapshot.IP = append(net.IP(nil), udp.IP...)
		addr = &snapshot
	}
	oob = append([]byte(nil), oob...)
	q.enqueue(queueEntry{
		buf: buf, pathID: id, gsoSize: gsoSize,
		write: func(data []byte, size uint16) error {
			written, err := socket.WritePacket(data, addr, oob, size, protocol.ECNUnsupported)
			if err == nil || written != 0 || size == 0 || !isGSOError(err) {
				return err
			}
			// Retry the rejected GSO batch as complete individual datagrams.
			for len(data) > 0 {
				n := min(len(data), int(size))
				if _, err := socket.WritePacket(data[:n], addr, oob, 0, protocol.ECNUnsupported); err != nil {
					return err
				}
				data = data[n:]
			}
			return nil
		},
	})
	return nil
}
