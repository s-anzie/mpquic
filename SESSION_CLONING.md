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
| C02a | Bind a confirmed multipath server's additional-path packet allocation to the authority, preserving existing high-water marks | Implemented behind an internal staging hook |
| C02b | Import primary stream/credit state and account ordinary writes, pre-reserved buffers, and FIN through the authority | Implemented; remote reservations remain disabled |
| C03a | Bounded content/range ledger connected to live SendStream offsets and completion, partial delivery, retries and cancellation | Implemented as internal local primitives |
| C03b | Authenticated worker coordination contract, packet-to-byte ACK evidence, control routing and bounded communication queues | In progress: internal fragment/ACK adapter implemented; worker transport pending |
| C04 | Secure worker bootstrap and packet protection state, coordinated key updates and global AEAD accounting | Pending |
| C05 | Negotiated source endpoint advertisement and client validation for different server IPs | Pending |
| C06 | Direct multi-server transmission and cross-path retransmission of distinct ranges | Pending |
| C07 | HTTP/3 integration, three-source transfers, failures, reordered messages, key updates, and performance measurements | Pending |

Dependencies can require splitting or reordering lots; none should weaken the
single-connection safety rules merely to produce an early demo.

## C01: what exists now

`internal/cloning.Authority` is deliberately internal and process-local. C02a
now provides optional integration with `Conn` and additional-path packet packing,
as described below. C02b adds live primary stream accounting. TLS and HTTP/3
state are not cloned. Cloning remains opt-in through an internal hook; ordinary
streams retain their flow-control semantics. The library currently exposes no public
session-cloning switch and no network snapshot import/export API.

The authority uses opaque local grants. Worker names are labels, not verified
identities. Both packet allocation and stream reservation are serialized; ranges
start at zero and streams must be registered before any data emission. This is
not suitable for attaching to an already active stream without the C02b primary
adapter, which imports its authoritative high-water mark. Likewise, a zero-based path grant must precede
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

## C02a: live additional-path packet allocation

The internal `Conn.prepareCloningAuthority` staging hook runs on the connection
loop. It rejects clients, unconfirmed handshakes, and connections without
negotiated multipath. Repeated activation preserves the same authority.

Activation imports the next unused packet number for every known nonzero path,
including numbers consumed by validation and unsuccessful packing attempts.
Retired paths stay retired. The new authority is published only after all imports
succeed; a failed import does not partially change the connection's allocators.
New paths are imported on first allocation, allowing packet arrival in a
different order than client path-ID allocation. No previously imported ID can
be imported again, even after retirement.

Both multipath packet-number entry points delegate to this authority after
activation. The original counter becomes a mirror for local state inspection,
not a competing allocator. Abandonment revokes its grant; connection shutdown
closes the authority. The initial path continues to use quic-go's original
allocator, remains primary-owned, and cannot be handed to a worker.

Originally the staging authority started with zero connection credit. C02b now
binds the actual connection credit before publishing activation, and lazily imports
live stream state under the existing write locks. Remote range reservations remain
disabled: packet-number integration alone does not authorize a worker to reserve
already-used offsets or consume credit outside the live stream state.

Coverage includes synthetic imported counters, skipped numbers, late-created
paths, exhaustion, atomic activation failure, and grant retirement. A real UDP
test transfers data over a discovered secondary path before activation, activates
the authority on that same server connection, transfers again, checks that the
path counter advanced, and confirms that shutdown disables further allocations.
The client uses the ordinary multipath implementation, not a cloning-specific
wire protocol. This is a live **single-server** integration test, not a remote
worker or multi-source transfer.

```sh
go test -race . -run 'TestCloning|TestQUICAutomaticPathDiscovery/cloning' -count=10
go test -race ./internal/cloning
```

## C02b: primary stream accounting

Activation imports the connection's current send window and total consumed
credit while holding its send-side lock. This total includes bytes pre-reserved
by `TryWriteAll` and bytes belonging to streams removed from the live stream map.
It must not be recomputed by summing only currently open streams.

Each stream is imported at its first subsequent credit reservation, using its
flow controller's high-water mark, not its last acknowledged offset or buffer
length. Imported bytes are not charged again. Ordinary writes, limited writes,
and eager buffer reservations pass through one connection-level reservation
operation. Pending pre-reserved frames and retransmissions bypass fresh credit
allocation. Received window increases are reflected in the ledger on the next
reservation. FIN records the exact already-accounted final size, including empty
streams. Accounting disagreement fails closed through connection shutdown.

Lock order is SendStream -> connection send-side -> authority. Activation needs
only the latter two locks and does not traverse and lock every active stream.
This permits application writes concurrent with activation without an inconsistent
snapshot or reverse lock ordering.

Tests cover shared credit across streams, activation with pre-reserved but unsent
data, frame splitting, retransmission without additional credit, window increases,
write limiters, final size, stale offsets, and concurrent streams across activation.
The real UDP test now pauses an open stream after a received prefix, activates the
authority, then verifies the suffix and final offset on that same stream/connection.

The bare `Authority.Reserve` method still returns `ErrDelegationNotReady` on a
bound primary: bypassing SendStream would leave its offsets behind. C03a adds a
separate trusted adapter that couples retained content and reservations to that
live stream. There is still no authenticated remote coordination interface.

Validation note: an initial full-suite run timed out in the cloning test's first
warmup transfer, before authority activation, while another test invocation ran
concurrently. Targeted repeated race runs and the subsequent isolated full-suite
run passed. The timeout's cause is not established; it is not evidence that
distributed cloning has been validated or that the transport is failure-free.
Final validation of C02b passed `go test ./...` followed sequentially by
`go test -race . ./http3 ./internal/cloning`. Targeted cloning tests, including
the live activation case, also passed ten race-enabled repetitions.

## C03a: retained ranges and delivery ownership

The internal `SendStream.delegateCloningRange` adapter reserves credit, retains a
copy of the supplied bytes, advances the live stream offset, and adds one delivery
obligation while holding the stream and connection send locks. Normal subsequent
writes start after that range. Pending primary write buffers must be drained first;
the adapter returns `ErrWouldBlock` rather than silently reorder them. A FIN may
be sent and acknowledged while delegated bytes are missing, but stream completion
waits for every delegated byte too.

Each range has an immutable identity, stream interval and SHA-256 digest. Attempts
bind that range to a path grant and a monotonically increasing generation. Retained
bytes are copied on admission and readout. The primary currently holds the bytes
needed to retry: this first implementation is not a content-reference-only design
and does not establish an efficient geographically distributed data plane. A later
content-provider contract may replace retention, but must guarantee reproducible
identical bytes after source failure without making that source indispensable.

Loss or source-path retirement allows another attempt on a valid path, without
changing offsets, content, stream completion obligations, or flow-control credit.
Stale loss notifications do not invalidate a newer attempt. Old attempts cannot
retrieve content for new work, but their late delivery evidence still counts.
Byte-level ACK bitmaps deduplicate overlapping or repeated intervals; only full
coverage produces a completion transition. An invalid interval cannot acknowledge
bytes outside the assigned range.

Bounds are currently fixed: 64 KiB per range, 256 pending ranges, 8 MiB retained
payload per authority, plus bounded ACK bitmaps. Completed/canceled payload and
bitmaps are released; connection credit is never refunded. Range identifiers are
never reused. Held attempt handles retain small terminal metadata, not payload.
Capacity exhaustion rejects admission without consuming stream offsets or credit.

Ordinary cancellation, STOP_SENDING and shutdown invalidate pending ranges before
their callbacks can complete the stream, and retain a local canceled-stream
tombstone to reject fresh assignments. Those identities last until connection
teardown; compacting long-lived stream history remains future work. Partial reliable reset (`RESET_STREAM_AT`)
is intentionally rejected at delegation admission until reliable-prefix ownership
is implemented. Already supplied bytes cannot be recalled from a failed worker;
retirement and cancellation here are local bookkeeping, not remote fencing.

No packet sender or RPC receiver invokes the new delegation callbacks yet. The
`acknowledge` callback requires authenticated QUIC packet delivery evidence, not a
worker's claim of successful sending. C03b must map packet ACKs to the exact byte
intervals carried, route cross-path control events, authenticate workers and bound
its queues. Calling a local callback in a test is not network delivery proof.

Tests exercise copied content, stable digests, partial and overlapping ACKs,
late ACKs after reassignment/retirement, exactly-once completion, bounded retention,
credit conservation, live-stream continuation, FIN-before-data-ACK behavior,
cancellation, STOP_SENDING, shutdown, and admission guards. These are local state
and SendStream integration tests, not a multi-source client/server transfer.

C03a validation passed the full Go suite, race-enabled QUIC/HTTP/3/cloning tests,
and ten race-enabled repetitions of the delegation tests. No remote-worker
benchmark or multi-source wire interoperability claim is made by this lot.

## C03b, first increment: packet-to-byte evidence

The internal `clonedRange.frame` adapter creates a STREAM fragment from retained
content and attaches an ACK/loss handler capturing its absolute byte interval.
It rejects another path, invalid intervals, retired or obsolete attempts and
canceled ranges. Fragments contain no FIN: final size remains primary-owned.
Callback arguments cannot enlarge the captured interval or change its stream.
Splitting must precede handler creation; copying a handler onto a smaller
fragment would incorrectly acknowledge the original interval and is prohibited.

Tests register these fragments in the existing multipath sent-packet history and
drive its PATH_ACK and loss handling. They cover reordered and duplicate ACKs,
unsent packet rejection, path-specific packet numbers, FIN waiting for data,
retry on another path without charging credit again, absolute offsets, payload
copy isolation, concurrent callbacks and cancellation.

This adapter is not yet called by the live packet scheduler or a remote worker.
It does not bypass path validation, congestion control, pacing or packet-number
allocation, and does not accept worker receipts as proof of delivery. The tests
exercise real transport bookkeeping locally, not UDP multi-source transmission.
The existing multipath history discards lost packets, so a late wire ACK for a
discarded packet does not reach this adapter; retained callbacks can safely handle
late evidence, but late-ACK history retention is not implemented by this increment.
Loss enables explicit range retry; automatic worker dispatch is still pending.
Authenticated coordination, bounded message queues and control routing remain
the unfinished parts of C03b; secure packet protection bootstrap remains C04.

Validation: the full Go suite, race-enabled QUIC/HTTP/3/cloning suites and ten
race-enabled repetitions of `TestCloningFrame` passed for this increment.
