# Multi-interface validation results — 2026-09-13

## Verdict

Automatic discovery and complete downloads work over two independently routed
Linux interfaces. Hard-link failover does **not** pass: disabling either interface
interrupts the connection in both QUIC and HTTP/3. Multipath is slower than
single-path in these measurements. This is not a production-readiness sign-off.

No production code was changed during this validation. The protocol revision
under test is `b96af38b`. The new executable and runner make the failures
reproducible. Go: `go1.26.0`; kernel: `Linux 7.0.12+kali-amd64 x86_64`.

## Environment and coverage

Only Wi-Fi was physically connected; Ethernet was down. Therefore this test used
two veth pairs between isolated client and server network namespaces, **not**
two physical access links. Host networking and existing Docker networks were
left unchanged.

Each link was shaped to 200 Mbit/s in each direction, with 2 ms one-way delay.
Source-policy routing provided genuinely separate outgoing interfaces. The
production interface inventory discovered the candidates without `AddPath`
or an injected address provider. The route checks returned:

```text
10.66.0.1 from 10.66.1.1 via 10.66.1.2 dev mpq-ca
10.66.0.1 from 10.66.2.1 via 10.66.2.2 dev mpq-cb table 102
```

These are server-to-client application transfers; client-to-server traffic
includes requests and acknowledgments, not an equivalent bulk upload benchmark.
Both protocols were tested with 64 MiB and 1 GiB payloads. Each size/protocol/mode
has one measurement: these are diagnostic results, not statistical performance
estimates. Setup and warmup are excluded from elapsed transfer time.

## Complete 1 GiB downloads

1 GiB is 1,073,741,824 application bytes. All four complete downloads matched the
expected length and SHA-256 and passed a follow-up on the same connection.

| Protocol | Mode | Seconds | Application Mbit/s | RX on A (bytes) | RX on B (bytes) |
| --- | --- | ---: | ---: | ---: | ---: |
| QUIC | Single path | 45.03 | 190.77 | 1100605599 | 460 |
| QUIC | Multipath | 60.80 | 141.28 | 1098196618 | 1479653189 |
| HTTP3 | Single path | 45.19 | 190.07 | 1105788476 | 0 |
| HTTP3 | Multipath | 64.77 | 132.63 | 1112091513 | 1577729989 |

The small B-interface counters in single-path mode are background network traffic,
not a second application path. In multipath mode, both interface counters are
large, proving that the transfer uses both paths. RX totals include headers and
retransmitted traffic and must not be confused with unique delivered payload.
The excessive interface traffic and reduced goodput warrant a separate recovery
and scheduling investigation; these counters alone do not identify its cause.

## Hard-link failure during a 1 GiB download

The selected client interface was disabled at one quarter of the received payload.
Both interfaces and their source routes were restored before the next scenario.

| Protocol | Disabled interface | Bytes received before failure | Seconds until failure | Result |
| --- | --- | ---: | ---: | --- |
| QUIC | mpq-cb | 275884796 | 15.24 | Connection interrupted |
| QUIC | mpq-ca | 268856052 | 15.57 | Connection interrupted |
| HTTP3 | mpq-cb | 273874944 | 7.04 | Connection interrupted |
| HTTP3 | mpq-ca | 268566528 | 14.12 | Connection interrupted |

The secondary-link failures report `quic: transport closed`. The primary-link
failures report a UDP send error, `network is unreachable`. No failed transfer
passed the same-connection follow-up. A false checksum flag on these incomplete
transfers means the full payload was not delivered, not that data corruption was
independently demonstrated.

The 64 MiB matrix reproduced the same result: four intact-link cases passed and
all four hard-link failure cases failed. The raw records are retained in
[results-64m.json](results-64m.json) and [results-1g.json](results-1g.json).

## Code paths implicated

- Secondary removal: `discoveredPath.close` closes its `quic.Transport`.
  `Transport.close` destroys connections registered on that transport.
  `connIDGenerator.AddConnRunner` registers connection IDs on additional
  transports, while `AbandonPath` retains issued IDs. Closing the secondary
  transport can therefore terminate the entire connection instead of detaching
  only that path.
- Primary failure: an error from `sendQueue.Run` invokes `Conn.destroyImpl`.
  Losing the primary interface's route therefore turns a path-local send failure
  into a connection-fatal error rather than continuing over the surviving path.
- Previous loopback inventory tests did not establish hard-link failover on the
  same connection. This runner checks connection reuse explicitly, preventing a
  fresh HTTP/3 connection from being mistaken for session continuity.

These findings were recorded, not patched, in this validation-only lot.

## Reproduction and remaining validation

See [README.md](README.md) for the runner and topology. The runner exits nonzero
when any scenario fails; the nonzero result here is intentional evidence of the
unresolved failures, not a successful test suite.

Still unvalidated: Wi-Fi plus Ethernet/cellular hardware, independent access
networks and NATs, IPv6 multi-interface operation, bulk uploads, and repeated
handover recovery. A second physical interface must be connected to perform the
physical-link portion.
