# Lot 68: path failure isolation

Date: 2026-09-13. This report supplements, rather than replaces, the lot 67
baseline in RESULTS.md. The topology and link shaping are unchanged: two
independently routed veth links in isolated Linux network namespaces, each
200 Mbit/s with 2 ms one-way delay. These are not two physical access links.

## Changes

- Isolate recognized path socket errors when a validated alternative exists.
- Detach an automatically discovered transport before closing its socket, so
  closing that transport does not destroy the shared QUIC connection.
- Return outstanding frames on abandoned paths to retransmission handling.
- Continue connection-wide control updates when the initial path is abandoned.
- Stop initial-path connection ID replenishment after abandonment and accept
  duplicate retirements for previously issued path connection IDs.
- Drain failed send queues and release packet buffers.

## Fault-injection results

Each server-to-client transfer contains 67,108,864 bytes (64 MiB). The selected
client interface is disabled after one quarter of the payload is received.
Each row is one diagnostic measurement, not a statistical benchmark.

| Protocol | Disabled path | Total seconds | Application Mbit/s |
| --- | --- | ---: | ---: |
| QUIC | Initial | 23.0733 | 23.2681 |
| QUIC | Secondary | 3.2051 | 167.5034 |
| HTTP/3 | Initial | 25.2277 | 21.2810 |
| HTTP/3 | Secondary | 3.0894 | 173.7809 |

All four scenarios passed payload length, SHA-256, traffic on both interfaces,
and a follow-up on the same connection. Before this lot, all four hard-link
failure scenarios failed. A 1 GiB failover rerun is not claimed by this report.

Reproduce after building the helper as documented in README.md:

```sh
go build -o /tmp/mpquic-multiinterface-lot68d ./integrationtests/tools/multiinterface
MPQUIC_SCENARIOS='cut-primary cut-secondary' MPQUIC_TIMEOUT=30s \
  bash integrationtests/tools/multiinterface/run.sh /tmp/mpquic-multiinterface-lot68d /tmp/mpquic-lot68-recheck
```

## Remaining limitations

Initial-path failure still causes excessive traffic and poor goodput. In the
QUIC run, the surviving interface received 562,156,689 bytes; in HTTP/3 it
received 617,837,523 bytes, for a 64 MiB payload. Interface counters include
headers and repeated traffic, not unique application bytes.

Inspection identified a recovery concern: the additional-path loss timer applies
the time threshold to all outstanding packets, without requiring evidence that
a later packet was acknowledged. Separating loss detection from probe timeout
is a follow-up; this report does not establish the proportion of overhead caused
by that behavior. Neither production readiness nor distributed session cloning
is claimed. Black-holed links, repeated failures, and loss of every path need
further end-to-end coverage.

## Regression checks

The complete Go test suite passed. The root QUIC and HTTP/3 packages also passed
with the race detector. Added regression assertions cover socket error
classification, validated survivors, send queue draining, one-time frame
requeueing, duplicate retirement, abandoned initial-path ID replenishment, and
HTTP/3 connection identity across automatic path removal.
