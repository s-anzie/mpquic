# Asynchronous multipath sending and bounded burst admission

Baseline: 825fcdca. Linux, Go 1.26.0, GOMAXPROCS=8.
Each throughput comparison transfers 1 GiB (1,073,741,824 application bytes).
Runs are sequential, with baseline and candidate interleaved in each repetition.
No benchmark runs concurrently with compilation or automated tests.

## Final loopback comparison

Client content SHA is disabled; no cloning workers are involved. TLS/QUIC packet
protection remains enabled. Source preparation, including its reference hash,
is outside the transfer timer.

| Build | Run 1 (s) | Run 2 (s) | Run 3 (s) | Median (s) | Receive queue drops |
|---|---:|---:|---:|---:|---|
| Baseline | 3.901 | 4.054 | 4.145 | 4.054 | 37, 0, 0 |
| Async + 1024-packet queue | 3.723 | 3.910 | 3.857 | 3.857 | 0, 0, 0 |

Median time decreases by **4.85%**, from 4.054044 to 3.857293 seconds,
and median-derived throughput increases by 5.10%.
Each candidate run is faster than its paired baseline run. Three trials do not
establish a general performance guarantee. Earlier single-path validation took
2.454 s: the remaining loopback multipath CPU penalty is not resolved.

## Implementation

Secondary-path application batches use the bounded connection send queue instead
of writing sockets on the connection loop. Each entry captures its socket,
destination address and packet-info bytes. UDP addresses are copied so migration
cannot redirect already encrypted queued data. Encryption, packet numbering and
congestion accounting remain on the connection loop.

The writer reports failures through a concurrent map, preserving distinct path
errors until the connection loop handles abandonment. A failed path is suppressed
independently; surviving paths remain writable. Rejected GSO batches fall back
to complete individual datagrams. Partial writes are never replayed.

Recovery registers queued packets before handoff, as on the initial path.
The writer does not read mutable path or cloning state. Relay paths retain their
existing send logic.

Receive admission depends only on immutable configuration:

- Single-path configurations: 256 queued datagrams.
- Multipath enabled: 1024 queued datagrams.
- Experimental source offers enabled: 4096 queued datagrams, unchanged.

The queue grows on demand and retains a hard bound. Raising the ordinary
multipath bound absorbs combined socket bursts but increases its worst-case
queued memory. It does not change flow control, congestion windows or integrity
checks, and does not imply that every network loss can be prevented.

## Why asynchronous sending alone was insufficient

Initial async-only trials (256 queued datagrams) had medians 4.063 s before and
3.708 s after. A repeat with a defensive partial-GSO-write guard had medians
4.203 s before and 4.135 s after. Another candidate transfer took 4.700 s and
dropped 484 datagrams at receive admission. These results show that the apparent
initial 8.7% gain was not stable.

The final comparison above includes the bounded receive queue adjustment, with
zero admission drops in all three candidate runs. Raw exploratory results remain
available: `before/after-multipath-*`, `repeat-before/final-*` and
`final-multipath.json`. The final comparison uses
`buffered-comparison-before/buffered-*`.

## Regression checks

Root-module tests, focused race tests (queues, receive limits, path failures,
cloning and discovery), root-module vet and separate FIPS tests all passed
on the final code, including the late-error retirement guard.

New tests cover destination snapshots, GSO fallback boundaries, refusal to replay
partial GSO writes, primary/secondary failure isolation, fatal secondary errors,
preservation of 32 distinct failure reports, bounded receive admission and
shared-buffer ownership on overflow.

The async-only version also passed these checks:

- 1 GiB multisource transfer with both source and client SHA enabled:
  12.814 s, correct digest, zero receive queue drops and ten key rotations/source.
  The subsequent ordinary multipath queue change leaves its 4096-packet limit unchanged.
- 64 MiB multipath transfer with GSO disabled and full SHA verification: passed.
- Four 1 GiB namespace scenarios: single path (45.033 s), two paths (24.046 s),
  secondary cut at 6.104 s (40.286 s total), primary cut at 6.114 s
  (39.873 s total). Each passed content verification, traffic checks and a
  follow-up transfer on the same connection. These are stored in `shaped/`.

## Reproduction

Build the final comparison tool and run each mode sequentially:

```sh
GOTOOLCHAIN=local go build -o /tmp/mpquic-async-buffered ./integrationtests/tools/transfercompare
GOMAXPROCS=8 /tmp/mpquic-async-buffered -mode multipath -bytes 1073741824 -verify-sha256=false
```

The namespace harness creates two isolated veth links, each direction limited to
200 Mbit/s with 2 ms added delay and no configured random loss. It exercises
automatic discovery and full content verification without changing host routes.
Its counters are cumulative within a namespace run, not per-scenario deltas.

```sh
GOTOOLCHAIN=local go build -o /tmp/mpquic-async-multiinterface ./integrationtests/tools/multiinterface
MPQUIC_PROTOCOLS=quic GOMAXPROCS=8 bash integrationtests/tools/multiinterface/run.sh /tmp/mpquic-async-multiinterface /tmp/mpquic-async-shaped 1073741824
```


## Combined-version namespace results

The asynchronous writer plus 1024-packet multipath receive bound passed all four
1 GiB scenarios, including full SHA, per-interface traffic and follow-up transfer
checks on the same connection:

| Scenario | Seconds | Useful Mbit/s |
|---|---:|---:|
| single | 45.033 | 190.749 |
| multipath | 24.393 | 352.145 |
| cut-secondary | 40.350 | 212.885 |
| cut-primary | 39.891 | 215.334 |

The two-path run provides 1.846x the single-path throughput. These are isolated
rate-limited links, not a physical WAN test. Raw results are in `final-shaped/`.
A separate 64 MiB transfer with GSO disabled also passed full content SHA.

Review of queued-write retirement added one final error-path safeguard:
errors arriving after a path has already been abandoned are ignored; unexpected
errors on a live path remain fatal. Classification occurs on the connection loop,
after pending retirement actions, rather than in the writer. Dedicated tests
cover late closed-socket errors and forwarding fatal errors to the connection
loop. Performance and namespace measurements above precede this final guard;
the successful-send path is unchanged.
