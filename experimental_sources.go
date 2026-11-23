package quic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

var ErrExperimentalSourceOffer = errors.New("experimental source announcement unavailable or invalid")

// ExperimentalSourceOffer describes an authenticated proposal, NOT a validated
// path or permission to probe. Applications must apply destination policy.
type ExperimentalSourceOffer struct {
	ID, Generation uint64
	Address        netip.AddrPort
	ExpiresAt      time.Time
}

type experimentalSourceEntry struct {
	frame   wire.ExperimentalSourceOfferFrame
	expires time.Time
}

type experimentalSourceRegistry struct {
	entries map[uint64]experimentalSourceEntry
}

// apply runs only on the connection loop. Lifetime IDs are capped, including
// expired and withdrawn tombstones, to prevent unbounded attacker-controlled state.
func (r *experimentalSourceRegistry) apply(f wire.ExperimentalSourceOfferFrame, now time.Time) error {
	if _, err := f.Append(nil, protocol.Version1); err != nil {
		return err
	}
	if r.entries == nil {
		r.entries = make(map[uint64]experimentalSourceEntry)
	}
	old, exists := r.entries[f.ID]
	if exists {
		if f.Generation < old.frame.Generation {
			return nil
		}
		if f.Generation == old.frame.Generation {
			if f != old.frame {
				return ErrExperimentalSourceOffer
			}
			return nil // retransmissions must not renew the lease
		}
		if old.frame.TTL == 0 {
			return ErrExperimentalSourceOffer
		}
	} else if len(r.entries) >= 32 {
		return ErrExperimentalSourceOffer
	}
	r.entries[f.ID] = experimentalSourceEntry{frame: f, expires: now.Add(time.Duration(f.TTL) * time.Second)}
	return nil
}

func (c *Conn) sourceOffersNegotiated() bool {
	return c.multipathEnabled && c.config != nil && c.config.EnableExperimentalSourceOffers && c.peerParams != nil && c.peerParams.ExperimentalSourceOffers
}

func (c *Conn) receiveSourceOffer(f *wire.ExperimentalSourceOfferFrame, level protocol.EncryptionLevel) error {
	if !c.sourceOffersNegotiated() || c.perspective != protocol.PerspectiveClient || level != protocol.Encryption1RTT {
		return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: "unexpected experimental source announcement"}
	}
	if c.experimentalSources == nil {
		c.experimentalSources = &experimentalSourceRegistry{}
	}
	if err := c.experimentalSources.apply(*f, time.Now()); err != nil {
		return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: "invalid experimental source announcement"}
	}
	return nil
}

// AnnounceExperimentalSource advertises one literal IP:UDP endpoint through a
// negotiated, authenticated QUIC control frame. No application stream is used.
// ttl must be an integral number of seconds in [1,3600]; zero withdraws an ID
// permanently and requires an empty address. Generations increase per source.
// This API does not provision workers, validate their addresses or activate paths.
func (c *Conn) AnnounceExperimentalSource(ctx context.Context, id, generation uint64, address netip.AddrPort, ttl time.Duration) error {
	if address.IsValid() {
		address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	}
	if ttl < 0 || ttl > time.Hour || ttl%time.Second != 0 {
		return ErrExperimentalSourceOffer
	}
	f := wire.ExperimentalSourceOfferFrame{ID: id, Generation: generation, Address: address, TTL: uint32(ttl / time.Second)}
	if _, err := f.Append(nil, c.version); err != nil {
		return err
	}
	return (&ExperimentalCloneWriter{conn: c}).onLoop(ctx, func() error {
		if !c.sourceOffersNegotiated() || !c.handshakeConfirmed || c.perspective != protocol.PerspectiveServer {
			return ErrExperimentalSourceOffer
		}
		if c.experimentalSources == nil {
			c.experimentalSources = &experimentalSourceRegistry{}
		}
		if old, ok := c.experimentalSources.entries[id]; ok && generation <= old.frame.Generation {
			return ErrExperimentalSourceOffer
		}
		if err := c.experimentalSources.apply(f, time.Now()); err != nil {
			return err
		}
		c.queueControlFrame(&f)
		return nil
	})
}

// ExperimentalSourceOffers returns copies of unexpired proposals. It performs
// no DNS lookup, socket creation, network probe, or automatic source acceptance.
// Private, loopback and link-local destinations require explicit application
// permission before any future path-establishment API can use them.
func (c *Conn) ExperimentalSourceOffers(ctx context.Context) ([]ExperimentalSourceOffer, error) {
	// A buffered result avoids sharing caller-visible memory after cancellation.
	result := make(chan []ExperimentalSourceOffer, 1)
	err := (&ExperimentalCloneWriter{conn: c}).onLoop(ctx, func() error {
		if !c.sourceOffersNegotiated() || c.perspective != protocol.PerspectiveClient {
			return ErrExperimentalSourceOffer
		}
		var offers []ExperimentalSourceOffer
		if c.experimentalSources != nil {
			now := time.Now()
			for _, entry := range c.experimentalSources.entries {
				if entry.frame.TTL > 0 && entry.expires.After(now) {
					offers = append(offers, ExperimentalSourceOffer{ID: entry.frame.ID, Generation: entry.frame.Generation, Address: entry.frame.Address, ExpiresAt: entry.expires})
				}
			}
		}
		slices.SortFunc(offers, func(a, b ExperimentalSourceOffer) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		result <- offers
		return nil
	})
	if err != nil {
		return nil, err
	}
	return <-result, nil
}
