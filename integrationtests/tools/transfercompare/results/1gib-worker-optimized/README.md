# Worker and receive-path throughput optimization

This follows the experiment without client or source content SHA verification.
The SHA bypass is still confined to the benchmark build overlay. Normal library
builds retain all content checks. TLS authentication, QUIC packet protection,
congestion control, finite packet-number leases and key rotation remain active
in every measurement.

## Evidence and fixes

1. **Worker UDP system calls.** Worker CPU profiles attributed approximately
   40–43% of sampled CPU to system calls. The batch send path alone accounted for
   about 30% cumulative CPU in one source. Added Linux UDP segmentation (GSO),
   grouping equal-sized encrypted datagrams with an optional shorter final one.
   Groups stay within 64 segments and 65,507 bytes. Unsupported offloads fall back
   to ordinary batch sends with the same ciphertext. Partial/uncertain writes
   fail; they are not blindly replayed. `QUIC_GO_DISABLE_GSO=true` is respected.
2. **Local receive-queue overflow.** A diagnostic 1 GiB run recorded exactly 165
   client queue drops and 165 extra packet jobs, despite running over loopback.
   The old 256-datagram queue was smaller than a bounded multisource flight.
   Opting into experimental source offers now allows 4,096 queued datagrams;
   ordinary connections retain 256. The memory bound remains explicit (roughly
   6 MiB of normal packet buffers at the larger limit, plus queue metadata).
   Discarded buffers are returned to the pool, including shared-buffer ownership.
   `ConnectionStats.ReceiveQueueDrops` exposes these local losses.
3. **Per-range scheduler round trips.** Completion polling previously returned
   to the connection loop for every unacknowledged range. Delivery and retry
   state are now sampled together in one bounded action, with source readiness
   evaluated once per source. Retry ownership and loss/expiry handling remain on
   the connection loop.
4. **Packet allocations and copies.** A sender reuses its bounded 64-packet
   ciphertext storage. Header construction reserves room for the full encrypted
   packet. Batched object reads no longer copy each already-loaded chunk through
   another ReaderAt buffer. Each normal-build chunk is still verified before any
   packet in its batch is emitted, including the final short chunk.
5. **Useless remote-history scans.** Worker recovery already owned remote loss
   decisions, but primary timer passes still walked the entire remote mirror to
   skip every entry. They now inspect only the primary packets outstanding at
   handoff. Those original callbacks and recovery deadlines are preserved.

The first GSO-only diagnostic took 15.190 s, so offload alone did not eliminate
variability. Intermediate receive-queue and grouped-polling measurements are
preserved under `diagnostics-before`; these are observations rather than isolated
randomized ablations.

## Timing interpretation

`CapacityWait` measures successful worker capacity exchanges. `DispatchTime`
measures successful lease dispatches, including `DrainWait`, which is time spent
waiting for worker emission receipts. Drain receipts are not client ACKs.
Durations in raw source statistics are nanoseconds. Do not add DrainWait to
DispatchTime: it is a subset. Other work overlaps these waits.

CPU profiles are available for the primary/client process and both source
processes. Worker profiles include bootstrap and shutdown; the primary profile
covers the timed transfer. Blocking profiles aggregate simultaneous goroutines,
so their delay sums are not elapsed transfer time. Profiling runs are excluded
from the final timing medians.

The comparison transfers exactly 1 GiB (1,073,741,824 bytes), with GOMAXPROCS=8,
Go 1.26.0, separate worker processes and loopback paths on one physical host.
The transfer clock excludes file/manifest creation, TLS setup, warm-up and path
validation. Whole-process timings include them and are recorded separately.
These are implementation-overhead measurements, not geographic bandwidth tests.

## Validation

The full root-module suite, targeted race suite, vet and separate FIPS module
passed. New regressions cover UDP segment boundaries (including a final short
segment and payload-size splitting), offload fallback and partial-write errors,
bounded receive queues and shared-buffer release, corrupt final object chunks,
and recovery of primary packets that predate worker handoff. Existing failure,
expiry, small flow windows, key transitions and uncertain drain-receipt tests
remain active.

An early race-suite run timed out in the lost-drain-receipt test. Three isolated
repeats, a subsequent complete targeted race run, and ten further isolated race
repeats passed; the full normal suite also passed. No causal fix for that isolated
timeout is claimed.

The cryptographic lease remains globally serialized. Source catalog selection,
geographic RTT validation and simultaneous independent leases are not introduced
by these optimizations.

## Final 1 GiB measurements

| No-content-SHA run | Seconds | Mbit/s | Queue drops | Extra packet jobs |
| --- | ---: | ---: | ---: | ---: |
| 1 | 8.130 | 1056.5 | 0 | 0 |
| 2 | 9.504 | 903.8 | 0 | 0 |
| 3 | 8.529 | 1007.2 | 0 | 0 |

Median: **8.529 s / 1007.2 Mbit/s**, compared with the previous no-content-SHA median of **12.611 s / 681.1 Mbit/s**. Observed duration reduction: **32.4%**, throughput increase: **47.9%**. All three runs used both sources and observed ten key rotations on each.

With client and source verification enabled, a separate 1 GiB run completed in **11.738 s / 731.8 Mbit/s**, with the expected SHA-256 and no queue drops or additional packet jobs. This verified result is one run, not a three-run median.

For the median-time unverified run, wall-clock attribution is:

- Capacity exchanges: 0.307 s.
- Dispatch: 6.300 s, **including** 4.111 s waiting for source emission receipts.
- Outside those calls: 1.922 s, including admission, completion processing and client delivery.

These measurements show that serialized lease dispatch and worker emission remain the dominant wall-clock span. The drain span combines pacing, source work, socket submission and control delivery; it is not a pure CPU measurement. No claim is made that every remaining throughput limit is removed.


## Profile follow-up

The separately profiled final 1 GiB transfer took 8.426 s (excluded from the
medians). Sampled CPU seconds changed as follows; worker intervals also include
bootstrap/shutdown, so these are diagnostic totals, not isolated transfer-only
CPU efficiency statistics:

| Process | Before CPU seconds | After CPU seconds |
| --- | ---: | ---: |
| Primary + client | 23.79 | 15.55 |
| Source 1 | 10.90 | 3.93 |
| Source 2 | 10.61 | 4.03 |

The source controller snapshots provide stronger evidence of the local-loss
feedback effect: before, sources recorded 94 / 242 losses and 1 / 2 PTOs, with
final congestion windows of 211,061 / 234,448 bytes and smoothed RTTs of 6.53 / 7.01 ms. After, both recorded zero losses and
zero PTOs, with windows of 1,992,144 / 2,018,280 bytes and smoothed RTTs of
0.723 / 0.531 ms. These are end-of-run snapshots, not time averages.

Remaining primary CPU costs include packet processing, system calls and ledger
map operations. Removing content SHA alone had not addressed the local drops,
congestion reductions or duplicated scheduling and allocation work.
