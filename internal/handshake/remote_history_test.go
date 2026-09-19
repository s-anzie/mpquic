package handshake

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/cloning"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// This exercises the crypto/ledger boundary over real UDP, not a full Conn.
// The primary still owns packet planning; no worker receipt counts as delivery.
func TestRemoteHistoryTwoSourcesAndProtectedClientACK(t *testing.T) {
	primary, client, authority := remoteTestEndpoints(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
	require.NoError(t, authority.BindPrimary(1000, 0))
	receiver, primarySocket := remoteUDPSocket(t), remoteUDPSocket(t)
	open := func(a *updatableAEAD, socket *net.UDPConn, cid protocol.ConnectionID, path uint64) []byte {
		t.Helper()
		require.NoError(t, socket.SetReadDeadline(time.Now().Add(time.Second)))
		packet := make([]byte, 1500)
		n, _, err := socket.ReadFromUDP(packet)
		require.NoError(t, err)
		packet = packet[:n]
		offset := 1 + cid.Len()
		a.DecryptHeader(packet[offset+4:offset+20], &packet[0], packet[offset:offset+4])
		length, pn, _, phase, err := wire.ParseShortHeader(packet, cid.Len())
		require.NoError(t, err)
		require.NoError(t, a.SetPathID(path))
		plain, err := a.Open(nil, packet[length:], monotime.Now(), pn, phase, packet[:length])
		require.NoError(t, err)
		return plain
	}
	for id := uint64(1); id <= 2; id++ {
		grant, err := authority.GrantPath(id, "worker")
		require.NoError(t, err)
		cid := protocol.ParseConnectionID([]byte{1, 2, 3, byte(id)})
		prepared, err := primary.prepareRemoteSealer(authority, grant, 1, cid)
		require.NoError(t, err)
		worker := transferRemote(t, prepared)
		sender, err := NewRemotePathSender(worker, remoteUDPSocket(t), receiver.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
		defer sender.Close()
		offset := (id - 1) * 4
		attempt, err := authority.DelegatePrimary(grant, 0, offset, 1000, []byte{byte(id), 2, 3, 4}, 1000)
		require.NoError(t, err)
		payload, err := authority.PrepareRemoteStreamPacket(grant, 0, []cloning.PacketFragment{{Attempt: attempt, Offset: offset, Length: 4}}, protocol.Version1)
		require.NoError(t, err)
		pn, err := sender.WritePayload(payload)
		require.NoError(t, err)
		require.Zero(t, pn)
		require.Equal(t, payload, open(client, receiver, cid, id))
		// A successful worker write has not completed the delegation.
		_, _, err = authority.ReadAttempt(attempt)
		require.NoError(t, err)
		ack := &wire.AckFrame{PathID: &id, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
		ackBytes, err := ack.Append(nil, protocol.Version1)
		require.NoError(t, err)
		ackCID := protocol.ParseConnectionID([]byte("primary"))
		ackPN := protocol.PacketNumber(id - 1)
		require.NoError(t, client.SetPathID(0))
		header, err := wire.AppendShortHeader(nil, ackCID, ackPN, protocol.PacketNumberLen4, client.KeyPhase())
		require.NoError(t, err)
		packet, err := client.SealWithError(header, ackBytes, ackPN, header)
		require.NoError(t, err)
		pnOffset := 1 + ackCID.Len()
		client.EncryptHeader(packet[pnOffset+4:pnOffset+20], &packet[0], packet[pnOffset:pnOffset+4])
		_, err = receiver.WriteToUDP(packet, primarySocket.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
		plain := open(primary, primarySocket, ackCID, 0)
		parser := wire.NewFrameParser(false, false, false)
		parser.SetMultipath(true)
		typ, n, err := parser.ParseType(plain, protocol.Encryption1RTT)
		require.NoError(t, err)
		parsed, _, err := parser.ParseAckFrame(typ, plain[n:], protocol.Encryption1RTT, protocol.Version1)
		require.NoError(t, err)
		completed, err := authority.AcknowledgeRemotePackets(grant, parsed)
		require.NoError(t, err)
		require.Len(t, completed, 1)
		completed, err = authority.AcknowledgeRemotePackets(grant, parsed)
		require.NoError(t, err)
		require.Empty(t, completed)
	}
	_, used, _, err := authority.PrimaryState(0)
	require.NoError(t, err)
	require.Equal(t, uint64(8), used)
}
