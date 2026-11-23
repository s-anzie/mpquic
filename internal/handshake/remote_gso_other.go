//go:build !linux

package handshake

import "net"

func remoteGSODisabled() bool                                              { return true }
func (*remoteUDPBatchWriter) writeGSO([][]byte, *net.UDPAddr) (int, error) { return 0, nil }
