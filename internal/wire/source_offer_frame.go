package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// Private experimental identifiers, not IETF allocations. Both endpoints must
// negotiate this version; announcements never imply address validation.
const FrameTypeExperimentalSourceOffer FrameType = 0x3f4d505101
const experimentalSourceOffersParameterID transportParameterID = 0x3f4d505102

type ExperimentalSourceOfferFrame struct {
	ID, Generation uint64
	TTL            uint32 // seconds; zero permanently withdraws this ID
	Address        netip.AddrPort
}

func (f *ExperimentalSourceOfferFrame) valid() bool {
	return f.ID > 0 && f.Generation > 0 && f.TTL <= 3600 &&
		((f.TTL == 0 && !f.Address.IsValid()) || (f.TTL > 0 && f.Address.IsValid() && f.Address.Port() != 0 &&
			f.Address.Addr().Zone() == "" && !f.Address.Addr().IsUnspecified() && !f.Address.Addr().IsMulticast()))
}

func (f *ExperimentalSourceOfferFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if !f.valid() {
		return nil, errors.New("invalid experimental source offer")
	}
	b = quicvarint.Append(b, uint64(FrameTypeExperimentalSourceOffer))
	b = binary.BigEndian.AppendUint64(b, f.ID)
	b = binary.BigEndian.AppendUint64(b, f.Generation)
	b = binary.BigEndian.AppendUint32(b, f.TTL)
	var addr [16]byte
	if f.TTL > 0 {
		addr = f.Address.Addr().As16()
	}
	b = append(b, addr[:]...)
	b = binary.BigEndian.AppendUint16(b, f.Address.Port())
	return b, nil
}

func (*ExperimentalSourceOfferFrame) Length(protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeExperimentalSourceOffer)) + 38)
}

func parseExperimentalSourceOfferFrame(b []byte) (*ExperimentalSourceOfferFrame, int, error) {
	if len(b) < 38 {
		return nil, 0, io.EOF
	}
	f := &ExperimentalSourceOfferFrame{ID: binary.BigEndian.Uint64(b), Generation: binary.BigEndian.Uint64(b[8:]), TTL: binary.BigEndian.Uint32(b[16:])}
	var addr [16]byte
	copy(addr[:], b[20:36])
	port := binary.BigEndian.Uint16(b[36:])
	if f.TTL > 0 {
		f.Address = netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), port)
	} else if addr != [16]byte{} || port != 0 {
		return nil, 0, errors.New("nonempty withdrawn endpoint")
	}
	if !f.valid() {
		return nil, 0, errors.New("invalid experimental source offer")
	}
	return f, 38, nil
}
