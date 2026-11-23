//go:build linux

package handshake

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

func remoteGSODisabled() bool {
	disabled, _ := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_GSO"))
	return disabled
}

// Only equal-size datagrams, optionally followed by a shorter final datagram,
// may share a GSO write. The complete payload fits one UDP super-packet.
func (w *remoteUDPBatchWriter) writeGSO(packets [][]byte, addr *net.UDPAddr) (int, error) {
	size := len(packets[0])
	if size == 0 || size > 65507 {
		return 0, nil
	}
	count, length := 1, size
	for count < len(packets) && count < 64 {
		n := len(packets[count])
		if n == 0 || n > size || length+n > 65507 {
			break
		}
		count++
		length += n
		if n < size {
			break
		}
	}
	if count < 2 {
		return 0, nil
	}
	w.gsoBuffer = w.gsoBuffer[:0]
	for _, packet := range packets[:count] {
		w.gsoBuffer = append(w.gsoBuffer, packet...)
	}
	if w.gsoOOB == nil {
		w.gsoOOB = make([]byte, unix.CmsgSpace(2))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&w.gsoOOB[0]))
		header.Level, header.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
		header.SetLen(unix.CmsgLen(2))
	}
	binary.NativeEndian.PutUint16(w.gsoOOB[unix.CmsgSpace(0):], uint16(size))
	n, _, err := w.writeMsg(w.gsoBuffer, w.gsoOOB, addr)
	if err != nil {
		if n == 0 && (errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EMSGSIZE)) {
			w.gsoDisabled = true
			return 0, nil // resend the same ciphertext using ordinary datagrams
		}
		return 0, err
	}
	if n != length {
		return 0, io.ErrShortWrite
	}
	return count, nil
}
