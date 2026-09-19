# Distributed multipath session cloning

> Security correction discovered during C04 preparation: the earlier multipath
> sender truncated the 96-bit path-and-packet nonce to 64 bits, dropping the low
> 32 packet-number bits. Do not deploy those revisions for multipath. The nonce
> safety increment described at the end fixes this; old multipath peers using
> the truncated construction are not wire-compatible with the correction.

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
| C03b | Authenticated worker coordination contract, packet-to-byte ACK evidence, control routing and bounded communication queues | In progress: control routing and bounded remote packet-plan/ACK ledger implemented; live packet-history handoff and recovery-owner integration pending |
| C04 | Secure worker bootstrap and packet protection state, coordinated key updates and global AEAD accounting | In progress: bootstrap, shared send-budget enforcement and local worker pause/resume implemented; distributed epoch barriers and sender/history handoff pending |
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
At this checkpoint, authenticated coordination, bounded message queues and
control routing remained unfinished; the next increment is described below.
Secure packet protection bootstrap remains C04.

Validation: the full Go suite, race-enabled QUIC/HTTP/3/cloning suites and ten
race-enabled repetitions of `TestCloningFrame` passed for this increment.

## C03b, second increment: authenticated worker control transport

`internal/cloning.Authority.BindWorker` now accepts a dedicated raw connection
and runs a server-side mutual TLS handshake. It requires verified client
certificates, TLS 1.3, the `mpquic-worker-control/1` ALPN, and an exact SHA-256
fingerprint of the worker leaf certificate supplied by trusted primary policy.
A worker-provided label or fingerprint is never an authorization source.
Configuration-swapping ClientHello callbacks and TLS resumption are rejected.
The TLS configuration is cloned; trust roots and certificate policy remain the
caller's responsibility. Go's normal certificate-chain verification is required,
not replaced by pinning (see the [TLS verification contract](https://pkg.go.dev/crypto/tls#ConnectionState)).

This is an internal reference control transport, not a requirement imposed on
application-level coordination or energy-source selection. There is no listener
or public cloning API, and no worker packet-sending executable yet. The caller
must bound incoming handshakes and supply an already client-established path
reserved for this worker. Binding does not transfer a path still used by the
primary sender. Moving that sender and its packet protection state is pending.

Each channel is bound once to one authority and one path, with no remote
authority/path selector. Up to 16 channels can be active per authority. An
authenticated competing bind is rejected without interrupting the current one.
Disconnect, timeout, protocol failure, context cancellation, explicit stop or
authority closure closes the transport and permanently retires the bound path.
Capacity becomes reusable for a fresh path, not for resurrecting a retired ID.
Closed channels are detached from path metadata so their TLS buffers and queues
can be collected. Existing path-ID tombstones are still retained.

### Reference wire contract

All integers are unsigned and big-endian. Each message has a four-byte body
length, a one-byte kind and an eight-byte per-direction sequence number starting
at one. Gaps, repeats, zero and wraparound terminate the channel. TLS supplies
confidentiality and integrity; sequence numbers are not a replacement for TLS.

| Direction | Kind | Payload after kind and sequence |
| --- | --- | --- |
| Primary to worker | 1: welcome | Path ID (8 bytes) |
| Primary to worker | 2: assignment | Range ID, generation, path ID, stream ID, offset and length (six 8-byte integers), SHA-256 digest (32 bytes), exact retained data |
| Worker to primary | 3: failed | Range ID and generation (two 8-byte integers) |
| Worker to primary | 4: stopped | Empty |
| Worker to primary | 5: heartbeat | Empty |

There is deliberately no worker-to-primary delivery/ACK operation. Failure only
makes an actually offered, matching current attempt retryable. Unknown IDs,
unoffered ranges, duplicates and obsolete generations do not change delivery
state. Reading an assignment never marks its bytes acknowledged. Client QUIC
packet evidence remains the sole delivery input to the ledger.

`WorkerControl.Queue` admits at most 16 waiting attempt handles without blocking
on network I/O. It does not reserve new offsets or credit. A full queue returns
`ErrWorkerBusy`; the caller retains its original reservation and can retry
admission. Pending metadata is bounded by the 256-range ledger limit and pruned
on admission. The writer skips canceled/obsolete work before taking a retained
content snapshot. A snapshot already being sent cannot be recalled.
The ledger retains at most 8 MiB globally and one range is at most 64 KiB;
serialization has bounded per-writer buffers rather than queued payload copies.
Incoming messages are limited to 25 bytes before allocation. Handshakes and
writes have five-second deadlines. Workers must send a heartbeat or other valid
control message within 30 seconds, including during transfers.

### Validation and remaining scope

Tests exercise a genuine loopback TCP/TLS control exchange, certificate pinning
and CA rejection, protocol/version policy, assignment content/digest, scoped
failure and retry, exclusive binding, replay and malformed input rejection,
bounded queues/channels, cancellation, disconnect and concurrent shutdown.
In-memory transports provide deterministic queue backpressure; the codec also
has a fuzz target. These are control-channel tests, not a cloned QUIC data-plane
transfer or multi-server throughput benchmark.

Still pending: connecting the channel to the live connection scheduler, routing
authenticated client control/ACK information to packet owners, remote packet
history, secure key bootstrap and key updates, endpoint offers and client path
validation. No traffic secrets are transmitted by this increment. The next lots
must not use this channel alone as proof that a worker can safely send QUIC.

Validation passed: the full Go suite; race-enabled QUIC, HTTP/3 and cloning
suites; ten race-enabled repetitions of the entire cloning package; and
`go vet ./internal/cloning`. A ten-second codec fuzz run completed 137,523
executions without failure. These results do not establish production readiness
or multi-source data-plane interoperability.

## C03b, third increment: ACK, cancellation and failure routing

The connection's existing ACK ingestion now forwards successfully processed
non-initial PATH_ACK frames to the worker bound to the **acknowledged** path.
The arrival path is not the routing key: the multipath draft explicitly allows
[PATH_ACK on another path](https://www.ietf.org/archive/id/draft-ietf-quic-multipath-21.html#section-3.1).
Parsing, encryption-level checks and existing sent-history checks still happen
before forwarding. Abandoned paths are ignored. Paths with no worker retain
their original behavior and do not allocate a notification.

`Authority.ForwardPathACK` is a trusted connection-loop API, not a worker RPC.
It snapshots ACK ranges, the parsed ACK delay and ECN counters into immutable
notification bytes. It does not acknowledge stream data, reserve packet numbers,
refund credit or accept a worker's claim of delivery. The existing packet
callbacks remain responsible for delivery accounting. Process-local monotonic
timestamps are not transmitted or compared across hosts; any future worker RTT
algorithm must account for the actual feedback route, including control relay
latency, rather than assuming synchronized clocks.

### Reference control protocol version 2

The ALPN is now `mpquic-worker-control/2`; version 1 is rejected. This explicitly
requires workers to understand the new primary-to-worker notifications instead
of silently assuming that old receivers support them. Message framing and the
existing kinds remain unchanged. Two primary-to-worker kinds are added:

| Kind | Payload after kind and sequence |
| --- | --- |
| 6: PATH_ACK observation | Acknowledged path ID, ACK delay in nanoseconds, ECT0, ECT1, ECNCE, range count (six 8-byte integers); then smallest and largest packet number for each range (two 8-byte integers per range, highest range first) |
| 7: cancel stream | Stream ID (8 bytes) |

Both kinds are rejected in the worker-to-primary direction. The separate
notification queue holds at most 32 entries; an ACK notification holds at most
256 ranges, with no silent truncation. Control messages take priority over
queued assignments, but cannot interrupt a TLS message already being written.
The existing write deadline bounds that in-progress operation.

Canceling a stream that has ever had a delegated range broadcasts one cancel
notification to all active workers on this authority. Broadcasting includes
previous owners whose failed attempts have already left pending metadata.
Workers must treat cancellation of an unknown/already-canceled stream as an
idempotent stop instruction, not an error. Repeated primary cancellation emits
no further notification. Never-delegated streams do not generate worker traffic.
Canceled queued assignments are skipped; already-issued work cannot be recalled.
This is a control instruction, not an implementation of the remote sender yet.

Saturating the notification queue or exceeding its ACK-range bound retires the
affected worker path rather than discarding mandatory controls. This is a local
resource failure, not a claim that a large peer ACK violates QUIC. Assignment
queue saturation still only returns backpressure without retiring the path.

### Connection-loop failure handling

Worker termination records a permanent failure on the grant and signals a
one-entry coalescing wakeup channel. The connection loop inspects all grants, so
simultaneous failures cannot be lost and no new client ACK is needed to trigger
cleanup. It uses the same path-failure cleanup as socket errors: pending packet
frames are returned to their handlers, receive/CID state is abandoned and a
PATH_ABANDON is queued for the peer. Surviving validated paths are preserved;
without one, the connection reports NO_VIABLE_PATH.
Survivor selection excludes workers already marked failed even before their
coalesced notification has triggered connection-loop CID cleanup. Simultaneous
worker failures must not count each other as usable alternatives.

### Validation boundary

Tests combine the actual QUIC frame parser, sent-packet bookkeeping, connection
ACK handler and mutually authenticated worker TLS channels. They cover ACKs
arriving on another path, invalid/Handshake-level ACK rejection, immutable
snapshots, exact range limits, cancellation after failed ownership, control
saturation, CID cleanup, independent surviving paths and coalesced failures
without another ACK. The connection fixture has no running packet sender: it
uses pre-handoff history, not a remote sender sharing a live local path.

This increment does **not** transfer packet-history ownership, accept remotely
issued packet numbers into the live history, or distribute keys. ACK forwarding
currently operates on history already registered with the primary; it must not
be mistaken for support for arbitrary worker-generated QUIC packets. The remote
packet engine, coordinated key lifecycle and direct multi-server data-plane
test remain pending.

Validation for this increment: full Go suite, race-enabled QUIC/HTTP3/cloning
suites, ten race-enabled repetitions of the worker-control and connection-routing
tests, and `go vet ./internal/cloning`.
The simultaneous-failure regression additionally verifies that a worker which
has stopped cannot count as a validated survivor before loop-side cleanup.

## C04 prerequisite: correct full-width application packet nonces

Preparing independent worker packet protection exposed a pre-existing security
defect: `updatableAEAD.setNonce` copied the 12-byte path-and-packet number into
the eight-byte nonce buffer provided by the TLS-style AEAD wrapper. This kept
the path ID and high packet-number bits but dropped the low 32 packet-number
bits, reusing a nonce for consecutive packets under one traffic key. Round-trip
tests had not caught this because both peers made the same error. Earlier
throughput tests establish neither cryptographic correctness nor confidentiality.

All application-data key generations (current, next, previous) now use an
explicit 12-byte input AEAD. The ordinary non-multipath construction zeros the
prefix and places the packet number in the final eight bytes, preserving its
existing wire behavior. Initial, Handshake and 0-RTT AEAD wrappers keep their
eight-byte input contract. Truncated inputs to the application wrapper panic
instead of silently constructing another nonce.

Outside FIPS mode, XOR uses the full IV width. In FIPS mode the TLS AES wrapper
still takes an eight-byte sequence number: independent instances per path use
an IV with the path ID XORed into its first four bytes, then receive the final
eight packet-number bytes. This yields the same 96-bit nonce and keeps each
path's monotonic send sequence independent. The instance map lives for one key
generation; it is local cryptographic state, not an exported worker snapshot.

Regression tests reproduce successful authentication with an incorrect packet
number before the fix. They now require distinct ciphertexts and failed
authentication for changed packet numbers, including low-bit changes, the
32-bit boundary and maximum packet numbers. An independent AES-GCM/ChaCha20
reference checks every nonce byte for QUIC v1/v2, zero/nonzero/maximum path IDs
and ordinary-QUIC compatibility. Additional tests cover multiple key generations
and FIPS path separation. No ciphertext or traffic-secret value is logged.

This prerequisite does not implement remote cryptographic bootstrap. The planned
bootstrap code was deferred rather than exporting the unsafe existing state.
Live key-generation coordination, global worker encryption budgets, path sender
handoff and the multi-server QUIC transfer are still pending. Main is not changed
by the cloning branch workflow; it must receive this correction before use for
multipath. Fixed and old multipath builds must not be mixed.

Validation: the full Go suite, the full handshake suite with FIPS enabled,
race-enabled QUIC/HTTP3/handshake/cloning suites, ten race-enabled repetitions of the
nonce regressions, ten live single-server automatic-discovery/cloning transfers,
and `go vet ./internal/handshake` passed. These replace no independent security
review and make no claim that distributed key export is ready.

## C04a: send-only bootstrap and independent packet protection

`Authority.ReservePacketWindow` atomically reserves 1–64 consecutive numbers
from an existing nonzero path's high-water mark. The first successful reservation
permanently disables `NextPacketNumber` on that grant; future reservations must
use disjoint windows. Invalid reservations do not mutate counters. Failed
bootstrap, abandoned work and failed UDP writes never refund numbers. The caller
must quiesce the local sender before reserving: changing the allocator alone
cannot recall already packed packets or migrate the recovery history.

`updatableAEAD.prepareRemoteSealer` is an internal staging entry point, deliberately
not exposed through `cryptoSetup` or `Conn`. It requires confirmed multipath and
a nonempty destination CID. It snapshots only derived send key, IV and header
protection key for the current full key epoch, and charges the complete window
to `numSentWithCurrentKey` before any export. Admission enforces a conservative
2^23-packet epoch bound. This is reservation accounting, **not yet a global live
send gate**: coordinating all primary/worker sends and key transitions remains
required before exposing the feature. Receive keys, next-generation secrets and
TLS resumption state are not transferred. Derived material retained at the
primary is refreshed on key update; the header protection key remains unchanged.
The extra primary material is cleared when the crypto setup closes.

### Dedicated authenticated bootstrap channel

`RemoteSealer.WriteTLS` serializes exactly once, directly into an already
authenticated TLS 1.3 connection with ALPN `mpquic-send-bootstrap/1`. Both ends
require a verified peer chain and an exact leaf-certificate fingerprint supplied
by trusted policy. The caller establishes mutual TLS and dedicates this channel
to one bootstrap: it cannot share the framed worker-control stream. There is no
public plaintext marshal function, file export or traffic-secret logging.

The fixed-size, 135-byte record contains suite (2 bytes), QUIC version (4), full
epoch, path ID, first PN and exclusive end PN (four 8-byte integers), CID length
(1), padded CID (20), padded send key (32), IV (12), and padded HP key (32).
Integers are big-endian. The receiver validates sizes, supported suite/version,
expected path, full epoch and destination CID before exposing a sealer. I/O has
a five-second deadline. The primary snapshot becomes unusable before writing;
even a partial write burns it. Temporary serialization bytes and explicit key
arrays are cleared after use; Go/runtime cipher copies are not guaranteed to be
securely erased. The receiver must never restore or replay a consumed bootstrap
after restart. Live connection-scoped restart fencing remains pending.
Retirement or authority closure before export admission rejects the transfer and
clears its snapshot. Retirement racing with an already admitted network write
cannot recall bytes already handed to the channel.

### Independent worker packet engine

`RemoteSealer.SealPacket` builds a complete protected short-header packet using
the fixed destination CID, key-phase bit and 96-bit path-and-packet nonce. It
uses four encoded PN bytes and enforces the repository packet-size limit. Its
private counter is mutex-protected and consumes each reserved number once before
the caller's network write. Exhaustion, closure and invalid payloads are rejected.
The primary export object cannot encrypt from the worker's window. Separate
worker objects do not share mutable cipher instances or header-protection buffers.
The bounds are software checks in a trusted worker, not cryptographic confinement
of the exported connection keys to one path.

Tests transfer snapshots over mutual TLS and send protected STREAM fragments
from two real loopback UDP source sockets to one receiver's QUIC cryptographic
engine. Both source paths begin at PN zero and carry distinct stream offsets.
The receiver removes header protection and authenticates the exact frames using
the existing implementation. Tests cover v1/v2 and AES-128, AES-256, ChaCha20;
AES also runs in FIPS mode. Additional coverage includes concurrent uniqueness,
counter exhaustion, wrong certificate/CID/epoch/path, failed export, reservation
budget, malformed bootstrap, and changed payload keys with stable HP keys after
an explicitly coordinated test key update.

These are multi-source **packet-protection tests**, not a live multi-server
`Conn` or HTTP/3 transfer. The test manually coordinates key epochs. There is no
worker-side autonomous key update, automatic lease refill, remote pacing/recovery
engine, source advertisement, or connection scheduler handoff yet. Old exported
windows cannot be remotely revoked by changing an in-memory flag. Epoch barriers,
restart fencing, shared encryption limits and packet-history ownership must be
connected before this internal bootstrap is enabled on live connections.

Validation: full Go suite, race-enabled QUIC/HTTP3/handshake/cloning suites,
ten race-enabled repetitions of the bootstrap/window tests, full handshake
suite in FIPS mode and vet passed. A bounded decoder fuzz run completed 157,380
executions without failure. No end-to-end HTTP/3 cloning claim is made.

A later full-suite run timed out in the existing `TestHTTP3Multipath` HTTP POST
after 30 seconds. Ten isolated repetitions subsequently passed without changing
the timeout. The cause is not established; this remains a validation caveat,
not evidence of a resolved HTTP/3 issue. A subsequent full-suite run with
package-level parallelism disabled (`go test -p 1 ./...`) passed.

## C04b: shared send budget and worker-side quiescence

The live packet builder now calls the optional `CheckedSealer.SealWithError`
interface for application packets. Primary encryption and reserved worker windows
share a conservative 2^23-packet budget per key epoch across all sending paths.
The packet that would exceed the budget is rejected with `AEAD_LIMIT_REACHED`
before encryption, header protection, publication in the output buffer or path-0
packet-number consumption. This follows the fail-closed requirement in
[RFC 9001 section 6.6](https://www.rfc-editor.org/rfc/rfc9001.html#section-6.6).
The existing key-phase selection can rotate keys before building the header when
updates are allowed; encryption itself never silently changes the selected phase.
Legacy direct `Seal` callers panic at the limit because their interface cannot
return an error; production packet construction uses the checked interface.

Key rotation, write-key replacement and crypto shutdown atomically invalidate
admission for outstanding unexported bootstrap snapshots. Rejected snapshots
erase their explicit material without refunding packet numbers or budget. An
export already admitted to network I/O cannot be recalled by this flag. Exported
workers still require distributed coordination: invalidation is not remote
revocation, and primary key rotation does not yet wait for worker drain receipts.

`RemotePathSender` takes exclusive ownership of a fresh imported sealer and
serializes UDP writes with `Pause`, `Resume` and permanent `Close`. Direct packet
sealing through an adopted handle is rejected. Pause waits for the current write
(which has a five-second socket deadline), closes the sealer, and burns every
remaining number in its window. Its boundary reports the full epoch and exclusive
reservation end, not delivery or acknowledgment. Previously sent datagrams can
still arrive after a pause. The socket remains owned by the caller and must be
dedicated to this sender.

Resume is permitted only after pause. It rejects consumed handles, overlapping
windows, backwards full epochs, changed path/CID/suite/version, and another
connection's header-protection key. That key stays fixed across key updates and
binds replacements to the same sending direction. Same-epoch replenishment is
allowed; rejected and failed-write windows remain burned. Sender objects cannot
be copied. These are in-memory fences, not durable process-restart protection.

Tests cover the last permitted encryption, shared reservation accounting,
rejection without modifying the destination, key-update recovery, stale bootstrap
admission, packet-builder error propagation, actual UDP sends, concurrent pause,
a deterministically blocked write, failed writes, and invalid replacement state.

This increment replaces C04a's missing live primary encryption gate, but does
**not** enable remote cloning through `Conn`. Distributed pause/resume control,
packet-history transfer, authenticated restart fencing, pacing/congestion and
loss recovery remain prerequisites. No multi-server HTTP/3 completion is claimed.

Validation: `go test -p 1 ./...`, race-enabled root/HTTP3/handshake/cloning suites,
the handshake suite in FIPS mode, vet on root/handshake/cloning, and ten
race-enabled repetitions of the new handshake scenarios passed.

## C03b continuation: bounded remote packet plans and client ACK evidence

The authority now stores approved remote packet plans keyed by path and packet
number. `RecordRemotePacket` must run before the sender receives permission to
send that exact plan. It accepts only reserved remote numbers, never prior
primary numbers, duplicate registrations, retired grants, obsolete attempts or
byte intervals outside retained data. Empty plans can represent control-only
packets. Metadata is capped at 4,096 packets across all paths, with at most 16
stream fragments per packet; capacity exhaustion is an explicit error.

`PrepareRemoteStreamPacket` builds STREAM frames directly from the authority's
retained immutable bytes and records the plan atomically. It bounds the payload
including frame overhead and reserves room for the largest short header and
authentication tag. Invalid or oversized plans publish no history entry. FIN
and stream finalization remain primary-owned. Payload construction is not a
worker assignment protocol and does not independently enforce remote pacing.

`AcknowledgeRemotePackets` is a trusted authenticated-client entry point, never
a worker RPC. It validates the entire PATH_ACK before changing any delivery
state: acknowledged path, range ordering, bounds, and every number above the
retention floor must match a registered plan. Merely reserving a window is not
enough. Work is bounded by the retained packet count, even for enormous incoming
ranges. Validated plans feed the existing byte ledger; overlapping fragments,
duplicates and late ACKs complete each delegation exactly once, without consuming
additional flow credit. Completed IDs are returned for future adapter wakeups.

`MarkRemotePacketLost` makes the current delegation retryable but preserves its
plan for late client evidence. Loss from an old attempt cannot invalidate its
replacement. Retired paths still accept late ACK/loss processing; canceled stream
bytes are not resurrected. `ForgetRemotePacketsBefore` explicitly advances a
monotonic floor, refuses to discard pending packets, and frees acknowledged/lost
metadata. Forgetting a lost plan sacrifices its future ACK evidence; retransmitted
bytes still need confirmation. Old numbers, including burned gaps, cannot be
registered again. Closing the authority clears all retained packet metadata.

Tests cover atomic rejection of mixed valid/invalid ACK ranges, unsent numbers,
late ACKs after loss/retry/retirement, cancellation, concurrent duplicate ACKs,
capacity shared by multiple paths, retention floors, grant identity, and payload
construction. A combined handshake test sends distinct retained STREAM portions
from two real UDP sources after mTLS bootstrap, then sends encrypted client
PATH_ACK packets back on path zero. Only after the primary authenticates and
parses those packets does the ledger release the portions, with unchanged credit.

This is a **crypto/packet-ledger integration test**, not a live `Conn` or HTTP/3
transfer. The existing connection loop still validates its ordinary sent history;
it is deliberately not redirected to this staging ledger. Live handoff must
preserve primary pre-handoff history (ACKs below this ledger's floor must not
bypass that validation), enforce approved plans at the remote sender, connect
completion wakeups, and assign RTT/congestion/loss ownership. No worker-reported
success or socket-write result is accepted as delivery proof.

Validation: the full suite (`go test -p 1 ./...`), race-enabled root/HTTP3/
cloning/handshake suites, ten race-enabled repetitions of the history scenarios,
the FIPS handshake suite, and vet on cloning/handshake passed.
