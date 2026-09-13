package quic

import (
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
		err = c.conn.WriteTo(buf.Data, p.remoteAddr, p.packetInfo)
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
		if id != 0 && p.serverValidated && !p.abandoned && p.remoteAddr != nil {
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

func (c *Conn) writeMultipathApplication(id uint64, tr *Transport, data []byte, gsoSize uint16) error {
	if c.perspective == protocol.PerspectiveClient {
		return tr.writePacket(data, c.conn.RemoteAddr(), gsoSize)
	}
	path := c.multipath.paths[id]
	if conn, ok := c.conn.(*sconn); ok && gsoSize != 0 {
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
		if err := c.conn.WriteTo(data[:n], path.remoteAddr, path.packetInfo); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
