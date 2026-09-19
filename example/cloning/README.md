# Experimental single-connection cloning laboratory

This example runs **one real QUIC connection**, a primary, and two independent
worker UDP senders. Each worker receives send-only key material over mutually
authenticated TLS and encrypts different stream portions itself. The client uses
the normal QUIC stream receiver. Worker receipts are not delivery proofs: the
primary waits for authenticated client PATH_ACKs.

The actors run in one process for a reproducible loopback laboratory, using real
TCP/TLS and UDP sockets. This is not a three-machine deployment test, a socket
relay, or three independent QUIC downloads.

## Run

From this repository, with Go 1.26:

```sh
go run ./example/cloning
go run ./example/cloning -bytes 1048576 -timeout 90s
```

The default transfers 64 KiB. Output includes source/destination sockets,
verified byte count, SHA-256, elapsed time, throughput and packets per worker.
Certificates and keys are generated in memory for each run; nothing is written
to disk, and all listeners bind to loopback. The 512 KiB ordinary warm-up is
excluded from the reported cloned-transfer throughput.

This baseline is deliberately stop-and-wait, with 1,000-byte portions. It is
expected to be slow: it is a correctness prototype, **not representative of
multipath capacity**.

## Public experimental API

The repository still uses the module name `github.com/quic-go/quic-go`. Run the
example in this checkout, or use a local module replacement when integrating it
into another application; the upstream quic-go module does not contain this API.

1. Establish one QUIC connection with `EnableMultipath: true` and sufficient
   `MaxPathID` on both endpoints. Do not enable partial-delivery stream resets.
2. Exchange ordinary traffic first (the example uses 512 KiB) to complete the
   initial key transition. `NewExperimentalCloneWriter` can return
   `ErrExperimentalCloningNotReady`; retry only with a bounded context.
3. On the client, call `AddPath` and `Probe`. `Path.ID()` identifies each source
   assignment. Exchange source choices out of band with explicit client consent.
4. Establish a dedicated TLS 1.3 connection per worker with
   `ExperimentalCloningALPN`, certificate-chain validation and client certificates.
   Configure trusted SHA-256 leaf-certificate fingerprints on both sides. Do not
   derive expected fingerprints from the connection being authenticated.
5. On each worker, call `ServeExperimentalCloneWorker` with its dedicated UDP
   socket and an explicit destination allowlist. The example permits exactly the
   associated client's additional-path socket, not an arbitrary address.
6. On the primary, create one `ExperimentalCloneWriter` for a `SendStream` and
   the source assignments. `WriteContext` alternates portions across workers and
   returns the confirmed prefix length. Close the original stream after a
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
- No standardized source advertisement, discovery, NAT traversal, endpoint
  migration or geographic-network validation. Client path establishment initially
  targets the primary; this lab relies on explicitly trusted worker sources being
  reachable directly on loopback/private networks. Do not expose it as a general
  Internet endpoint-discovery mechanism.
- One clone writer and one send stream per connection, up to eight sources.
  The primary retains and distributes the bytes. Independent source retrieval
  and energy-aware selection remain application work.
- Single-packet leases serialize cryptographic handoff. A receipt is accepted
  only after the worker exhausts and closes its window. Primary local key updates
  wait for that drain; a peer key update during a lease **terminates** the
  connection. Some transitions between jobs can also make the prototype stop;
  seamless distributed key rotation is not implemented.
- Worker failure, invalid control traffic, changed CID/destination, uncertain
  dispatch or cancellation closes the whole connection. No transparent failover
  or restart from old keys/counters. Retry the application transfer on a fresh
  connection if needed.
- Each portion waits one second for its ACK before a fresh-PN retransmission,
  with at most eight transmissions. This is not adaptive geographical PTO or
  worker-local congestion control. The existing primary path recovery owns
  congestion accounting. Worker control has bounded I/O deadlines and a
  30-second idle deadline.
- **No HTTP/3 integration.** This API writes raw QUIC streams, not HTTP/3 responses
  or QPACK state. Existing HTTP/3 multipath remains separate.

## Verification

```sh
go test -race . -run '^TestExperimentalCloning' -count=3
go test -race ./internal/handshake -run '^TestExperimentalRemote'
```

The live tests cover exact content over one QUIC stream from two workers, loss
and fresh-number retransmission, and worker failure closing the connection.
Crypto tests cover local key-update deferral and authenticated peer-key-update
rejection while a worker lease is outstanding.
