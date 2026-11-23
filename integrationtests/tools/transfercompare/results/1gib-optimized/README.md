# Bounded clone dispatch throughput investigation

Measurements use exactly 1 GiB (1,073,741,824 application bytes). The final
comparison is three sequential runs per mode, with GOMAXPROCS=8 and Go 1.26.0.
Client and primary share one process. Multisource has two distinct worker
processes, each with its own file and UDP source address, plus the primary control
path. All processes run on one physical host over loopback. This measures the
implementation overhead, not aggregation of independent WAN links.

The timed region includes delivery, EOF and streaming SHA-256 verification. It
excludes file creation, manifest preparation, TLS setup, path validation and the
512 KiB ordinary warm-up. Process CPU figures include those excluded phases and
child cleanup, so they must not be divided by transfer time as a transfer-only
CPU utilization estimate. Baseline has one run, optimized results have three;
this is not a randomized statistically controlled hardware benchmark.

## Final 1 GiB results

| Mode | Median seconds | Range, seconds | Median Mbit/s |
| --- | ---: | ---: | ---: |
| One server, one path | 4.264 | 4.055–4.325 | 2014.6 |
| One server, two paths | 4.467 | 4.349–4.609 | 1922.9 |
| Two data sources, two paths plus primary control | 17.249 | 16.679–18.461 | 498.0 |

Baseline cloning: 625.606 seconds, 13.73 Mbit/s (one run). Final median speedup: 36.27×; duration reduction: 97.24%. Cloning remains 4.05× slower than the final single-path median.

All nine comparison runs verified the same complete SHA-256. Each multisource run used both sources and completed ten observed key rotations on each source. Raw JSON and process CPU accounting are in `run1` through `run3`. The separately profiled run is excluded from these medians.

| Multisource run | Packet jobs | Lease batches | Extra packet jobs above unique chunks |
| --- | ---: | ---: | ---: |
| 1 | 1,074,038 | 3,081 | 296 |
| 2 | 1,074,042 | 4,878 | 300 |
| 3 | 1,073,799 | 2,810 | 57 |

Additional packet jobs include fresh-PN retries; they are not an exact UDP loss count. Packet counters cover fully drained jobs, while socket counters also include protocol overhead.

## Diagnosed costs and changes

| Cost | Evidence or mechanism | Change |
| --- | --- | --- |
| Idle timer loop | Baseline CPU profile: `nextPathProbeLossTime` accounted for 36.02% cumulative CPU; ready pacing paths repeatedly armed an immediate timer | Arm only future pacing deadlines; delegated paths do not use the primary's pacing timer |
| Per-packet control handoff | Baseline needed 1,073,742 jobs for 1 GiB | Negotiate worker capacity, then dispatch a finite lease of up to 1,024 packets per receipt |
| Tiny application flight | Eight 1,000-byte portions were allowed before waiting for client delivery | Autonomous flight limit is 4,096 portions; actual stream credit, congestion and history capacity still gate admission |
| Duplicate recovery | Primary and worker could independently inspect/probe delegated packets | Worker owns loss and PTO; authenticated reports update primary delivery history |
| Persistent history scans | ACK-only packets and completed worker records stayed in recovery histories | Do not retain untracked ACK-only packets; prune completed worker history; reverse-index ranges to packet numbers |
| Late loss after successful retry | Removing a completed range's retry mapping could prevent a later loss report from cleaning its original packet history | Retire remote transport history independently of the mapping; protect pre-handoff primary packets |
| Control fragmentation | One small descriptor and source read per chunk | Group contiguous object reads and descriptors; verify each chunk before emitting any packet in the batch |
| Lost socket capabilities | Source wrapper exposed only generic packet I/O | Preserve OOB and batch receive with endpoint pinning; up to 64 receive slots on source sockets |
| UDP syscall overhead | Worker wrote one datagram at a time | Paced groups of at most 64 datagrams using batch writes; flush before waiting for credit |
| Feedback overhead | Separate authenticated feedback records could queue per ACK | Coalesce the union of delivery ranges; preserve the delay belonging to the highest ACK |
| Idle worker polling | Loss/PTO loop woke every millisecond | State changes and actual deadlines drive a reusable timer |

A key safety constraint determines the order: reserve congestion/history capacity
**before** exporting keys. Waiting for fresh ACK credit while holding a key lease
could otherwise deadlock a peer key transition. A congestion reduction does not
revoke already committed batch credit; pacing still gates every packet and the
next reservation uses the reduced congestion window.

The entire packet-number window is charged to the key epoch and never refunded.
A partial or uncertain dispatch still requires path retirement and the client
fence before cross-source retry. The job ALPN changes to `mpquic-clone-lab/3`;
older job peers are incompatible. The relay remains `mpquic-clone-relay/2`.

## Failed exploratory run

`failed-before-late-loss-fix` preserves the failed first comparison, excluded from
final performance statistics. It stopped at 473,827,000 received bytes after both
sources disconnected; the writer waited for replacement sources. The process
was stopped to inspect goroutines. Subsequent inspection found the late-loss
cleanup gap described above. A dedicated regression now covers that gap, but the
original dispatch error was not captured: its causal connection to this exact
stall is not proven. Three diagnostic 1 GiB transfers before that cleanup change
also succeeded. Successful final repetitions are evidence, not proof that every
intermittent failure is eliminated.

## Validation

- Full root-module suite: `go test -p 1 ./... -timeout=180s` passed.
- Race-enabled experimental, remote crypto, multipath, cloning and source I/O
  groups passed in the root, handshake and cloning packages.
- `go vet ./...` passed; the separate FIPS integration module passed.
- Added regressions cover full 1,024-packet key-window exhaustion, capacity before
  key export, bounded history, ACK union and reordered delay, source pinning with
  receive-buffer ownership, ACK-only history, and late worker-loss cleanup.
- Existing failure, corrupt-content, small flow-window, peer/local key-update and
  uncertain partial-window receipt tests remain active.
- A timing-sensitive ordinary flow-control test failed during concurrent test
  activity, then passed ten isolated repetitions and the full-suite rerun. A
  capacity test fixture was updated to supply credit above the new entry limit.

## Final CPU profile

The separate 1 GiB profile (`optimized.pprof`, `profile-run.json`) recorded
16.95 seconds wall time and 24.80 CPU seconds in client/primary (146% of one
core). SHA-256 block processing represents 19.31% flat CPU, system calls 14.48%,
and map iteration 5.32% cumulative. `nextPathProbeLossTime` is now 4.03%
cumulative instead of the baseline profile's 36.02%. The baseline profile used
32 MiB, so these shares are diagnostic observations rather than a controlled
same-size profile comparison. Worker CPU is not included in this profile.

Reproduce a comparison run after building the tool:

```sh
go build -o /tmp/mpquic-transfercompare ./integrationtests/tools/transfercompare
GOMAXPROCS=8 python3 integrationtests/tools/transfercompare/run.py \
  --binary /tmp/mpquic-transfercompare --bytes 1073741824 --timeout 90s \
  --output /tmp/mpquic-comparison
```

## Remaining throughput constraints

These changes remove the measured local bottlenecks; they do not establish a
multi-gigabit geographically distributed implementation:

1. Only one cryptographic lease is active globally. Source dispatch remains
   serialized, and the capacity exchange plus drain receipt cost control RTTs.
   A full 1,024,000-byte window with two 50 ms control round trips has an ideal
   ceiling near 81.9 Mbit/s even before sending and processing time. Concurrent
   leases require a redesigned epoch drain barrier and failure accounting, not
   simply goroutines around the current writer.
2. The 4,096,000-byte application flight bounds bandwidth-delay product. At
   100 ms delivery RTT its ideal ceiling is about 327.7 Mbit/s. Congestion,
   receive credit and smaller negotiated batches may impose lower limits.
3. Object chunks remain 1,000 bytes. Larger MTU-aware framing, buffer reuse and
   further relay batching are possible future improvements. Changing immutable
   object chunk boundaries also changes manifest compatibility.
4. Client SHA-256, packet encryption/decryption, socket calls and history handling
   still consume CPU. Profile percentages describe CPU work, not a causal
   fraction of wall-clock delay, and the profile excludes worker processes.
5. One primary remains necessary for keys, offsets, shared credit and delivery.
   A trusted-worker model and experimental protocol remain in place. Energy
   selection and a source catalog are outside QUIC.

Test independently throttled links with latency, loss and asymmetry before
claiming bandwidth aggregation or geographical performance. Compare the final
multisource median with the final single-server medians, not only with the slow
old cloning baseline.
