# Distributed multipath session cloning

## Objective and scope

Expose one QUIC connection to the client while multiple trusted, geographically
distributed servers send different portions of its streams. Each participating
server owns a distinct path. The primary establishes the connection and offers
additional source endpoints; the client initiates and validates those paths.
Application policy chooses sources using energy provenance or other criteria.
That policy and the application's inter-server communication mechanism remain
outside QUIC.

The transport still needs a coordination contract for packet protection, stream
offsets, acknowledgment routing, and flow control. Applications may provide the
communication channel, but cannot bypass transport invariants.

This is an experimental project extension, not TLS session resumption, a socket
proxy, or multiple independent QUIC connections hidden behind an API.
The [multipath draft used by this implementation](https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html)
defines client-initiated paths and path-specific packet number spaces, but leaves
address discovery outside its scope. It does not define our distributed endpoint
coordination protocol. The source advertisement format and negotiation are still
to be designed; they must not be presented as standard multipath frames.

## Architecture decision

Use one logical transport authority with multiple path workers. Do not copy a
live `Conn`: it contains process-local sockets, goroutines, queues, pointers,
timers, and mutable state that cannot safely be duplicated.

The primary authority owns:

- Connection lifecycle, negotiated parameters, key-generation transitions, and
  connection-wide cryptographic usage accounting.
- Path ownership, CID allocation/routing, stream allocation and final sizes.
- Stream offset reservations and shared MAX_DATA / MAX_STREAM_DATA accounting.
- Dispatch of received control information to its owning path or stream.

A worker will own its assigned path's sending loop, packet history, ACK/loss
recovery, congestion controller, pacing, and RTT/PMTU state. PATH_ACK may arrive
on a different path: it must reach the worker whose packet number space it
acknowledges, not whichever server received the UDP packet.

For the first network prototype, the primary remains required. Losing it closes
the logical connection. Transparent authority failover is explicitly deferred
until durable counters and split-brain prevention are implemented and tested.
Never reconstruct an authority with counters reset for an existing connection.

## Safety rules

1. A path has one worker. Never restart or reassign a retired path ID. A
   replacement gets a fresh client-established path ID.
2. Packet numbers cannot repeat within a path, including across key updates or
   failed sends. Path zero remains controlled by the original endpoint.
3. Unique stream bytes consume shared connection credit once. Reservations are
   never refunded just because a worker failed: it might already have sent them.
   Retransmission uses the same offsets and identical content, with fresh packet
   numbers. A future range ledger must bind content and track delivery/retry
   ownership before workers can emit these reservations.
4. Final size is fixed once. Finalizing reservations does not prove delivery and
   does not authorize discarding outstanding bytes.
5. Path validation and anti-amplification checks still apply. A grant alone is
   not address validation. Endpoint offers must be authenticated, bounded, and
   subject to client acceptance policy to avoid unsolicited network probing.
6. All workers sharing connection secrets belong to one trust domain. Ordinary
   QUIC traffic keys do not cryptographically confine a worker to one path.
   Compromise of a worker can compromise the shared connection. No raw keys or
   connection snapshots may be logged, committed, or exported in plaintext.
7. Local grant retirement only stops future allocations. It cannot recall a
   previously issued packet number or stop a disconnected worker from sending.
   Network integration needs explicit stop/acknowledgment and path-abandonment
   handling, not merely an epoch field advertised as remote fencing.
8. HTTP/3 retains one coherent protocol state, including control streams and
   QPACK. Workers cannot independently create HTTP/3 framing for the same stream.
   Mapping source content to those shared transport offsets remains future work.

## Implementation lots

| Lot | Deliverable | Status |
| --- | --- | --- |
| C01 | Local authority: exclusive path grants, monotonic packet numbers, shared stream range and credit reservations, final size, closure, concurrent tests | Implemented as an internal primitive |
| C02 | Connect authority to a confirmed server connection, import packet-number and stream/credit high-water marks, enforce all primary and worker emissions through the same authority | Pending |
| C03 | Authenticated worker coordination contract, range/content ledger, ACK/control routing, bounded queues and loss of coordination behavior | Pending |
| C04 | Secure worker bootstrap and packet protection state, coordinated key updates and global AEAD accounting | Pending |
| C05 | Negotiated source endpoint advertisement and client validation for different server IPs | Pending |
| C06 | Direct multi-server transmission and cross-path retransmission of distinct ranges | Pending |
| C07 | HTTP/3 integration, three-source transfers, failures, reordered messages, key updates, and performance measurements | Pending |

Dependencies can require splitting or reordering lots; none should weaken the
single-connection safety rules merely to produce an early demo.

## C01: what exists now

`internal/cloning.Authority` is deliberately internal and process-local. It is
not used by `Conn`, packet packing, TLS, HTTP/3, or live flow-control handlers yet.
Existing QUIC traffic is unchanged. The library currently exposes no public
session-cloning switch and no network snapshot import/export API.

The authority uses opaque local grants. Worker names are labels, not verified
identities. Both packet allocation and stream reservation are serialized; ranges
start at zero and streams must be registered before any data emission. This is
not yet suitable for attaching to an already active stream without importing
its authoritative high-water mark. Likewise, a zero-based path grant must precede
all server packets on that path, including validation responses; it cannot be
attached to a path that already sent packets. MAX_STREAMS eligibility must be checked by
the future connection adapter, not inferred from a valid stream ID.

Tests cover concurrent uniqueness, foreign/copied/retired grants, permanent
path retirement, connection-wide credit across streams, failed reservations,
final-size immutability, numeric exhaustion, and terminal authority closure.
They do not constitute an end-to-end cloned connection test.

```sh
go test -race ./internal/cloning
go test ./...
```
