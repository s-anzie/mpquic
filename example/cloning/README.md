# Experimental single-connection cloning laboratory

This example runs **one real QUIC connection**, a primary, and two independent
worker UDP senders. Each worker receives send-only key material over mutually
authenticated TLS and encrypts different stream portions itself. The client uses
the normal QUIC stream receiver. Worker receipts are not delivery proofs: the
primary waits for authenticated client PATH_ACKs.

The actors run in one process for a reproducible loopback laboratory, using real
TCP/TLS and UDP sockets. This is not a three-machine deployment test or three
independent QUIC downloads. A separate mTLS channel relays opaque received packets
and primary-generated validation replies; workers encrypt the data packets.

## Run

From this repository, with Go 1.26:

```sh
go run ./example/cloning
go run ./example/cloning -bytes 1048576 -timeout 90s
```

The default transfers 64 KiB. Output includes source/destination sockets,
verified byte count, SHA-256, elapsed time, throughput and packets per worker.
Certificates and keys are generated in memory. Independent temporary worker files
are created and removed for each run; all listeners bind to loopback. The 512 KiB ordinary warm-up is
excluded from the reported cloned-transfer throughput.

The autonomous writer permits up to 4,096 1,000-byte portions awaiting client ACKs.
Worker key leases remain serialized: this is bounded packet pipelining, not
concurrent key export. It is a correctness prototype, **not representative of
geographical multipath capacity**.

## Public experimental API

The repository still uses the module name `github.com/quic-go/quic-go`. Run the
example in this checkout, or use a local module replacement when integrating it
into another application; the upstream quic-go module does not contain this API.

1. Establish one QUIC connection with `EnableMultipath: true`,
   `EnableExperimentalSourceOffers: true` and sufficient
   `MaxPathID` on both endpoints. Do not enable partial-delivery stream resets.
2. Exchange ordinary traffic first (the example uses 512 KiB) to complete the
   initial key transition. `NewExperimentalCloneWriter` can return
   `ErrExperimentalCloningNotReady`; retry only with a bounded context.
3. On the primary, announce each worker's literal UDP endpoint using
   `AnnounceExperimentalSource`. Establish a dedicated mutually authenticated
   TLS 1.3 channel with `ExperimentalSourceRelayALPN`. Call
   `PrepareExperimentalSource` on the primary and `ServeExperimentalSourceRelay`
   on the worker, using the same UDP socket that will send cloned data.
4. On the client, explicitly accept the offer through `AcceptExperimentalSource`
   with destination policy, then call `ProbeExperimentalSource` with a dedicated
   client UDP socket. Keep the returned path alive until the transfer ends.
   Its `ID()` identifies the path. Both challenge/response directions traverse
   the worker UDP endpoint; validation against the primary is not reused.
5. Establish another dedicated TLS 1.3 connection per worker with
   `ExperimentalCloningALPN`, certificate-chain validation and client certificates.
   Configure trusted SHA-256 leaf-certificate fingerprints on both sides. Do not
   derive expected fingerprints from the connection being authenticated.
6. Create one `ExperimentalWorkerController` per worker and share it through
   `ExperimentalCloneWorkerOptions` between the job and relay services. Set
   `Objects` to a resolver for that worker's immutable local files. On each worker, call `ServeExperimentalCloneWorker` with its dedicated UDP
   socket and an explicit destination allowlist. The example permits exactly the
   associated client's additional-path socket, not an arbitrary address.
7. On the primary, create one `ExperimentalCloneWriter` for a `SendStream` and
   source assignments containing `SourceID`, `Generation`, `PathID`, the job TLS
   channel, `Autonomous: true` and the worker certificate pin. Both channels must use the same worker
   identity. Retry readiness until the server has also validated its return path.
   `WriteObject(ctx, manifest)` distributes metadata for verified worker-local
   reads and returns the confirmed prefix length. `WriteObjectRange` supports
   aligned ranges; `WriteContext` supports primary-held bytes. Close the original stream after a
   successful write so the primary sends FIN. Read any application confirmation
   before closing the writer: **writer Close closes the entire connection**.

`Stats()` counts successfully drained worker packet jobs, including retries;
it is not a separate delivery or application-byte counter. Concurrent ordinary
writes to the same stream should be avoided. A writer serializes its writes and
supports concurrent `Close` to interrupt them.

## Limits — read before using

- **Experimental, private-network use only; not production-ready.** No independent
  security review has been performed. All workers share the connection's trust
  domain and must be trusted with its derived sending keys.
- No standardized source advertisement, automatic NAT traversal, endpoint
  migration or geographic-network validation. The client directly probes the
  accepted worker address. The lab uses explicitly trusted loopback endpoints;
  policy must restrict destinations before any Internet deployment.
- One clone writer and one send stream per connection, up to eight initial sources
  and 32 lifetime entries. At most 4,096 1,000-byte chunks are outstanding with autonomous workers (eight otherwise).
  Source-local reads are the default (`-source-local=false` uses primary-held bytes).
  Authenticate the object manifest through your application before importing it.
- Finite leases of up to 1,024 packets serialize cryptographic handoff. Worker-local congestion,
  pacing, loss and PTO decisions control UDP sends; the primary still authorizes
  packet numbers, shared credit, keys and delivery. Losing the primary remains fatal.
- Source failure, withdrawal or invalid content triggers path retirement and an
  authenticated client fence before retrying ranges on another source. A fence is
  not a delivery receipt or cryptographic revocation of worker keys. Workers must
  be trusted and must never replay old jobs or leases after restart.
- `writer.AddSource(ctx, source)` can add a freshly accepted and validated path
  during a write. With no healthy source, the write waits for an addition until
  its context expires. Cancellation or fence failure closes the connection.
  Delegated-path endpoint migration requires retirement and a fresh path.
- `writer.RotateKeys(ctx)` requests an update between writes. `Stats()` reports
  drained jobs, epochs and rotations; worker controller snapshots report local
  ACK, loss, PTO, RTT and congestion state. Neither replaces application confirmation.
- Energy-aware selection, geographically distributed deployment testing and
  durable restart recovery remain outside this laboratory.
- **No HTTP/3 integration.** This API writes raw QUIC streams, not HTTP/3 responses
  or QPACK state. Existing HTTP/3 multipath remains separate.

### Source announcements and direct validation

`Config.EnableExperimentalSourceOffers` now permits the primary to publish and
withdraw literal endpoints through `Conn.AnnounceExperimentalSource`. The client
can read authenticated proposals with `Conn.ExperimentalSourceOffers`. Both peers
must opt in; this uses private negotiated QUIC control frames, not application
streams. Announcements do **not** establish paths, validate workers, or authorize
network probes. The lab follows announcement, explicit acceptance, direct probing
and writer activation. See `SESSION_CLONING.md` for lifecycle limits.
The client can call `AcceptExperimentalSource(ctx, id, generation, policy)` with
an explicit destination policy. The primary reads consent with
`ExperimentalAcceptedSources(ctx)`. Consent applies only to that generation;
renewal, withdrawal and expiry invalidate it. The negotiated private extension
is now version 4 and must match on both peers. Acceptance alone performs no
network probe. `ProbeExperimentalSource` binds the generation to a fresh path and
validates it. The writer rejects missing, stale, mismatched or unvalidated bindings.
Withdrawal or relay failure retires the affected path; pending ranges can move
to a healthy source after the client fence. Renewal requires fresh consent and
a fresh validated path. Job and relay ALPNs are `mpquic-clone-lab/3` and
`mpquic-clone-relay/2`.

## Verification

Run a transfer with an explicit key update halfway through:

```sh
go run ./example/cloning -bytes 1048576 -rotate -fail-first
```

```sh
go test -race . -run '^TestExperimentalCloning' -count=3
go test -race ./internal/handshake -run '^TestExperimentalRemote'
```

The live tests cover exact content over one QUIC stream from two workers, loss
and fresh-number retransmission, worker failure with same-connection recovery,
concurrent replacement, withdrawal, corrupt content and lost drain receipts.
Crypto tests cover local key-update deferral, authenticated peer-update deferral
until worker drain, and fresh worker leases in the next epoch.


## Throughput diagnostics

The bounded autonomous writer uses Linux UDP segmentation where available and
falls back to batch datagram sends. `QUIC_GO_DISABLE_GSO=true` disables this
worker offload as well. Experimental source-offer connections allow a bounded
4,096-datagram receive queue; ordinary multipath configurations allow 1,024 and single-path configurations retain 256.
`ConnectionStats.ReceiveQueueDrops` exposes local queue overflow, and source
statistics expose capacity/dispatch/drain timing. Drain timing is included in
dispatch timing and is not proof of client delivery.

The benchmark's `-worker-profile-dir` saves per-source CPU, blocking and controller
statistics, with graceful child cleanup so profiles can finish. Profiled runs
must be kept separate from throughput repetitions. See the [worker throughput
report](../../integrationtests/tools/transfercompare/results/1gib-worker-optimized/README.md)
for the 1 GiB results and the remaining control-channel serialization.
