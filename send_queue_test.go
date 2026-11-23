package quic

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSendQueueIsolatesPathFailureAndDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := NewMockSendConn(gomock.NewController(t))
		q := newSendQueue(c).(*sendQueue)
		var failures int
		q.onWriteError = func(err error) bool {
			require.ErrorIs(t, err, syscall.ENETUNREACH)
			failures++
			return true
		}
		c.EXPECT().Write([]byte("first"), uint16(0), protocol.ECNNon).Return(syscall.ENETUNREACH)
		done := make(chan error, 1)
		go func() { done <- q.Run() }()
		q.Send(getPacketWithContents([]byte("first")), 0, protocol.ECNNon)
		q.Send(getPacketWithContents([]byte("queued")), 0, protocol.ECNNon)
		synctest.Wait()
		require.Equal(t, 1, failures)
		require.False(t, q.WouldBlock())
		q.Close()
		require.NoError(t, <-done)
	})
}

func getPacketWithContents(b []byte) *packetBuffer {
	buf := getPacketBuffer()
	buf.Data = buf.Data[:len(b)]
	copy(buf.Data, b)
	return buf
}

func TestSendQueueSendOnePacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		written := make(chan struct{})
		c.EXPECT().Write([]byte("foobar"), uint16(10), protocol.ECT1).Do(
			func([]byte, uint16, protocol.ECN) error { close(written); return nil },
		)

		done := make(chan struct{})
		go func() {
			q.Run()
			close(done)
		}()

		q.Send(getPacketWithContents([]byte("foobar")), 10, protocol.ECT1)
		synctest.Wait()

		select {
		case <-written:
		default:
			t.Fatal("write should have returned")
		}

		q.Close()
		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("Run should have returned")
		}
	})
}

func TestSendQueueBlocking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		blockWrite := make(chan struct{})
		written := make(chan struct{}, 1)
		c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
			func([]byte, uint16, protocol.ECN) error {
				select {
				case written <- struct{}{}:
				default:
				}
				<-blockWrite
				return nil
			},
		).AnyTimes()

		done := make(chan struct{})
		go func() {
			q.Run()
			close(done)
		}()

		// +1, since one packet will be queued in the Write call
		for i := range sendQueueCapacity + 1 {
			require.False(t, q.WouldBlock())
			q.Send(getPacketWithContents([]byte("foobar")), 10, protocol.ECT1)
			// make sure that the first packet is actually enqueued in the Write call
			if i == 0 {
				select {
				case <-written:
				case <-time.After(time.Second):
					t.Fatal("timeout")
				}
			}
		}
		require.True(t, q.WouldBlock())
		select {
		case <-q.Available():
			t.Fatal("should not be available")
		default:
		}
		require.Panics(t, func() { q.Send(getPacketWithContents([]byte("foobar")), 10, protocol.ECT1) })

		// allow one packet to be sent
		blockWrite <- struct{}{}
		select {
		case <-written:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
		select {
		case <-q.Available():
			require.False(t, q.WouldBlock())
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		// when calling Close, all packets are first sent out
		closed := make(chan struct{})
		go func() {
			q.Close()
			close(closed)
		}()

		synctest.Wait()

		select {
		case <-closed:
			t.Fatal("Close should have blocked")
		default:
		}

		for range sendQueueCapacity {
			blockWrite <- struct{}{}
		}
		synctest.Wait()

		select {
		case <-closed:
		default:
			t.Fatal("Close should have returned")
		}
		select {
		case <-done:
		default:
			t.Fatal("Run should have returned")
		}
	})
}

func TestSendQueueWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c)

		c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(assert.AnError)
		q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)

		errChan := make(chan error, 1)
		go func() { errChan <- q.Run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("Run should have returned")
		}

		// further calls to Send should not block
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			for range 2 * sendQueueCapacity {
				q.Send(getPacketWithContents([]byte("raboof")), 6, protocol.ECNNon)
			}
		}()

		synctest.Wait()

		select {
		case <-sent:
		default:
			t.Fatal("Send should have returned")
		}
	})
}

func TestSendQueueSendProbe(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c)

	addr := &net.UDPAddr{IP: net.IPv4(42, 42, 42, 42), Port: 42}
	localAddr := netip.MustParseAddr("43.43.43.43")
	c.EXPECT().WriteTo([]byte("foobar"), addr, packetInfo{
		addr: localAddr,
	})
	q.SendProbe(getPacketWithContents([]byte("foobar")), addr, packetInfo{
		addr: localAddr,
	})
}

func TestSendQueueSecondaryFailureKeepsOtherPathsWritable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := NewMockSendConn(gomock.NewController(t))
		q := newSendQueue(conn).(*sendQueue)
		var failed []uint64
		q.onPathWriteError = func(id uint64, err error) bool {
			require.ErrorIs(t, err, syscall.ENETUNREACH)
			failed = append(failed, id)
			return true
		}
		conn.EXPECT().Write([]byte("initial"), uint16(0), protocol.ECNNon).Return(nil)
		var writes []string
		write := func(b []byte, _ uint16) error {
			writes = append(writes, string(b))
			if string(b) == "fail" {
				return syscall.ENETUNREACH
			}
			return nil
		}
		q.enqueue(queueEntry{buf: getPacketWithContents([]byte("fail")), pathID: 1, write: write})
		q.enqueue(queueEntry{buf: getPacketWithContents([]byte("discard")), pathID: 1, write: write})
		q.enqueue(queueEntry{buf: getPacketWithContents([]byte("survivor")), pathID: 2, write: write})
		q.Send(getPacketWithContents([]byte("initial")), 0, protocol.ECNNon)
		done := make(chan error, 1)
		go func() { done <- q.Run() }()
		synctest.Wait()
		q.Close()
		require.NoError(t, <-done)
		require.Equal(t, []uint64{1}, failed)
		require.Equal(t, []string{"fail", "survivor"}, writes)
	})
}

func TestMultipathQueuedWriteCapturesDestinationAndSplitsGSO(t *testing.T) {
	if !platformSupportsGSO {
		t.Skip("GSO is not supported on this platform")
	}
	ctrl := gomock.NewController(t)
	socket := NewMockRawConn(ctrl)
	c := &Conn{perspective: protocol.PerspectiveServer, multipath: newMultipathState(4)}
	c.conn = &sconn{rawConn: socket}
	c.sendQueue = newSendQueue(c.conn)
	path, err := c.multipath.path(1)
	require.NoError(t, err)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	path.remoteAddr = addr
	require.NoError(t, c.sendMultipathApplicationBuffer(1, nil, getPacketWithContents([]byte("abcdef")), 4))
	// A later migration must not redirect already encrypted queued packets.
	addr.Port = 444
	addr.IP[15] = 2
	expected := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	gomock.InOrder(
		socket.EXPECT().WritePacket([]byte("abcdef"), expected, gomock.Any(), uint16(4), protocol.ECNUnsupported).Return(0, errGSO),
		socket.EXPECT().WritePacket([]byte("abcd"), expected, gomock.Any(), uint16(0), protocol.ECNUnsupported).Return(4, nil),
		socket.EXPECT().WritePacket([]byte("ef"), expected, gomock.Any(), uint16(0), protocol.ECNUnsupported).Return(2, nil),
	)
	entry := <-c.sendQueue.(*sendQueue).queue
	defer entry.buf.Release()
	require.NoError(t, entry.write(entry.buf.Data, entry.gsoSize))
}

func TestSendQueuePrimaryFailureKeepsSecondaryWritable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := NewMockSendConn(gomock.NewController(t))
		q := newSendQueue(conn).(*sendQueue)
		q.onWriteError = func(error) bool { return true }
		conn.EXPECT().Write([]byte("initial"), uint16(0), protocol.ECNNon).Return(syscall.ENETUNREACH)
		q.Send(getPacketWithContents([]byte("initial")), 0, protocol.ECNNon)
		var sent bool
		q.enqueue(queueEntry{buf: getPacketWithContents([]byte("secondary")), pathID: 2,
			write: func([]byte, uint16) error { sent = true; return nil }})
		done := make(chan error, 1)
		go func() { done <- q.Run() }()
		synctest.Wait()
		q.Close()
		require.NoError(t, <-done)
		require.True(t, sent)
	})
}

func TestSendQueueSecondaryFatalError(t *testing.T) {
	q := newSendQueue(nil).(*sendQueue)
	q.onPathWriteError = func(uint64, error) bool { return false }
	q.enqueue(queueEntry{buf: getPacketWithContents([]byte("fatal")), pathID: 1,
		write: func([]byte, uint16) error { return syscall.EPERM }})
	require.ErrorIs(t, q.Run(), syscall.EPERM)
	q.Close()
}

func TestConnectionSendQueueRetainsDistinctSecondaryFailures(t *testing.T) {
	c := &Conn{config: &Config{EnableMultipath: true}}
	q := c.newConnectionSendQueue().(*sendQueue)
	for id := uint64(1); id <= 32; id++ {
		require.True(t, q.onPathWriteError(id, syscall.ENETUNREACH))
	}
	for id := uint64(1); id <= 32; id++ {
		err, ok := c.secondarySendErrors.Load(id)
		require.True(t, ok)
		require.ErrorIs(t, err.(error), syscall.ENETUNREACH)
	}
}

func TestMultipathQueuedWriteDoesNotReplayPartialGSO(t *testing.T) {
	if !platformSupportsGSO {
		t.Skip("GSO is not supported on this platform")
	}
	socket := NewMockRawConn(gomock.NewController(t))
	c := &Conn{perspective: protocol.PerspectiveServer, multipath: newMultipathState(4)}
	c.conn = &sconn{rawConn: socket}
	c.sendQueue = newSendQueue(c.conn)
	path, err := c.multipath.path(1)
	require.NoError(t, err)
	path.remoteAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	require.NoError(t, c.sendMultipathApplicationBuffer(1, nil, getPacketWithContents([]byte("abcdef")), 4))
	socket.EXPECT().WritePacket([]byte("abcdef"), gomock.Any(), gomock.Any(), uint16(4), protocol.ECNUnsupported).Return(4, errGSO)
	entry := <-c.sendQueue.(*sendQueue).queue
	defer entry.buf.Release()
	require.ErrorIs(t, entry.write(entry.buf.Data, entry.gsoSize), errGSO)
}
