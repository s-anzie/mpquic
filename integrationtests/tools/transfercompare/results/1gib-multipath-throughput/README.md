# Multipath throughput: direct batch packing

Baseline: 97f62fcb. Go 1.26.0, GOMAXPROCS=8, Linux, 1 GiB
(1,073,741,824 application bytes). Runs execute sequentially, with baseline and
candidate interleaved in each repetition. Source preparation is outside the timer.

The candidate seals subsequent multipath GSO segments directly into the large
batch buffer, removing a small-buffer pool round trip and ciphertext copy per
segment. The first segment still uses the existing buffer. Packet numbers,
PATH_ACK reservation, encryption and congestion accounting are unchanged.

## Loopback, client content SHA disabled

No source worker or cloning is involved. TLS/QUIC protection remains enabled.
The source preparation still computes the reference hash outside the timer.

| Build | Mode | Seconds (three runs) | Median seconds |
|---|---|---|---|
| baseline | single | 2.160, 2.506, 2.682 | 2.506 |
| baseline | multipath | 3.691, 4.207, 4.414 | 4.207 |
| after | single | 2.385, 2.583, 2.807 | 2.583 |
| after | multipath | 3.795, 4.120, 4.491 | 4.120 |

The multipath median is 2.1% lower, but the ranges overlap substantially and the
single-path control also varies. This does **not** establish a reproducible
throughput improvement. Direct packing removes unnecessary work but does not
resolve the loopback multipath penalty.

Receive queue drops vary across runs (see JSON). Both baseline and candidate
also have multipath runs with zero queue drops, so queue overflow does not
explain the whole penalty.

A separate baseline CPU profile measured 8.10 CPU seconds for single path and
11.44 CPU seconds for multipath. Multipath secondary-path writes still run
synchronously on the connection loop, whereas initial-path writes use the send
queue. Moving secondary writes requires preserving destination snapshots, buffer
ownership, per-path failure isolation and cloning handoff semantics; this change
does not attempt that broader refactoring.

## Independently rate-limited paths

The existing multiinterface harness runs in disposable network namespaces:
two veth links, each direction limited to 200 Mbit/s with 2 ms added delay and
zero configured random loss. Automatic interface discovery is exercised.
Unlike the loopback comparison, complete client SHA verification is enabled.
This tests aggregation under link limits; it is not a physical WAN benchmark.

| Mode | Seconds | Useful Mbit/s | Content SHA | Follow-up on same connection |
|---|---:|---:|---|---|
| Single path | 45.030 | 190.760 | Passed | Passed |
| Two paths | 24.553 | 349.859 | Passed | Passed |

Two paths deliver 1.834x useful throughput and reduce transfer time by 45.48%.
Both interfaces carry substantial traffic (about 501 MB and 598 MB received,
including network overhead). This is one run per mode, not a statistical
distribution. The result confirms aggregation, not that the implementation
reaches the full theoretical 400 Mbit/s sum.

Reproduce the isolated-link experiment from the repository root:

```sh
GOTOOLCHAIN=local go build -o /tmp/mpquic-multiinterface ./integrationtests/tools/multiinterface
MPQUIC_PROTOCOLS=quic MPQUIC_SCENARIOS='single multipath' GOMAXPROCS=8 bash integrationtests/tools/multiinterface/run.sh /tmp/mpquic-multiinterface /tmp/mpquic-shaped-results 1073741824
```

Loopback command (repeat sequentially for both binaries and modes):

```sh
GOMAXPROCS=8 /tmp/mpquic-mp-after -mode multipath -bytes 1073741824 -verify-sha256=false
```

Raw results and logs are stored beside this report. Shaper counters are cumulative
within the namespace run; do not treat the final counter as a per-scenario delta.

## Validation

- Root module: `GOTOOLCHAIN=local go test ./...` passed.
- Focused race tests for path packing and connection GSO batches passed.
- `GOTOOLCHAIN=local go vet ./...` passed.
- Separate `integrationtests/fips` module tests passed.
- New regression coverage checks both initial and secondary path appends preserve
  preceding batch bytes, packet lengths, path identity, packet numbers and PATH_ACK.
- Both 1 GiB namespace transfers passed content verification, interface traffic
  checks and a follow-up transfer on the same connection.

The ordinary multipath implementation still has a high-throughput CPU penalty.
This change does not claim to remove all bottlenecks or change cloning scheduling.
