# Lot 69: additional-path recovery

Date: 2026-09-13. Same isolated two-veth topology as lots 67 and 68: each
direction is shaped to 200 Mbit/s with 2 ms delay. No physical dual-access-link
or geographically distributed server validation is claimed.

## Root cause and correction

The additional-path recovery timer treated packet age alone as evidence of
application packet loss. That could retransmit an entire unacknowledged flight
and reduce its congestion window while packets were still in transit.

Time-threshold loss now requires acknowledgment of a later packet in the same
path packet-number space. A separate probe timeout uses the path RTT estimator,
maximum acknowledgment delay, and exponential backoff. It sends one PING on the
affected path, without discarding outstanding packets or reducing the congestion
window merely because PTO elapsed. Fresh acknowledgment of an outstanding
ack-eliciting packet resets that path's backoff. Validation probes retain their
existing retry lifecycle.

Reference: [RFC 9002, sections 6.1 and 6.2](https://www.rfc-editor.org/rfc/rfc9002.html#section-6).
This is a targeted recovery correction, not a claim of complete RFC 9002 audit
coverage for every additional-path behavior. In particular, the recovery probes
currently carry PING rather than copies of outstanding application frames.

## 64 MiB hard-link failures

The selected client interface is disabled at 25% of received application data.
All four scenarios pass exact length, SHA-256, traffic on both interfaces, and a
follow-up on the same connection. Timings cover the whole transfer, not just the
post-failure portion.

| Protocol | Disabled path | Lot 68 seconds | Lot 69 seconds | Lot 69 Mbit/s |
| --- | --- | ---: | ---: | ---: |
| QUIC | Initial | 23.0733 | 2.5080 | 214.0594 |
| HTTP/3 | Initial | 25.2277 | 2.4807 | 216.4171 |
| QUIC | Secondary | 3.2051 | 3.3693 | 159.3420 |
| HTTP/3 | Secondary | 3.0894 | 3.4795 | 154.2948 |

For initial-path failure, RX on the surviving interface drops from 562,156,689
to 60,564,460 bytes for QUIC, and from 617,837,523 to 59,886,325 bytes for HTTP/3.
Counters include headers and repeated traffic; they are not unique payload
counts. Aggregate goodput can exceed 200 Mbit/s because both links carried the
first quarter of the transfer. Secondary-path failure did not improve in these
single measurements; it predominantly uses the original path's recovery engine.

## 1 GiB baseline downloads

One GiB is 1,073,741,824 application bytes. Without injected failures, both
protocols complete with exact length, matching SHA-256, and same-connection
follow-up. Both interfaces carry substantial traffic in multipath mode.

| Protocol | Mode | Seconds | Application Mbit/s | RX A bytes | RX B bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| QUIC | Single | 45.0329 | 190.7480 | 1100578014 | 546 |
| QUIC | Multipath | 24.2739 | 353.8750 | 522599033 | 590406952 |
| HTTP/3 | Single | 45.1952 | 190.0631 | 1105013788 | 0 |
| HTTP/3 | Multipath | 23.3882 | 367.2769 | 545368780 | 568743290 |

Compared with lot 67, multipath goodput rises from 141.28 to 353.87 Mbit/s in
QUIC and from 132.63 to 367.28 Mbit/s in HTTP/3. Single-path goodput remains
approximately 190 Mbit/s. Tiny counters on B in single-path mode are background
network traffic, not a second application path.

## 1 GiB hard-link failures

All four clients completed the entire payload with a valid SHA-256 and a
same-connection follow-up, after disabling the selected interface at 25%.

| Protocol | Disabled path | Seconds | Application Mbit/s |
| --- | --- | ---: | ---: |
| QUIC | Secondary | 41.5822 | 206.5771 |
| QUIC | Initial | 39.9520 | 215.0064 |
| HTTP/3 | Secondary | 39.6837 | 216.4600 |
| HTTP/3 | Initial | 39.6206 | 216.8047 |

Raw client results: [results-lot69-1g.json](results-lot69-1g.json).
The eight client commands printed PASS, but the enclosing 1 GiB runner exited
with a shell parsing error after the last scenario because its file was edited
while executing. Its cleanup ran and no test namespace processes remained.
The persisted script passes `bash -n`; subsequent runs use the unchanged file.
The table reports the completed clients, not a successful wrapper exit. A fresh
run of all eight scenarios at 64 MiB with the unchanged script subsequently
completed with eight PASS results and exit status zero.

## Random-loss checks

With 1% independent random netem loss in each direction of both links, all four
64 MiB clients pass integrity, both-path traffic, and same-connection follow-up.
The unchanged runner exits successfully with zero failures. No fixed random
seed is used, so these timings are diagnostic only.

| Protocol | Scenario | Seconds | Application Mbit/s |
| --- | --- | ---: | ---: |
| QUIC | Multipath | 2.4629 | 217.9823 |
| QUIC | Initial-path cut | 2.7579 | 194.6701 |
| HTTP/3 | Multipath | 2.5136 | 213.5823 |
| HTTP/3 | Initial-path cut | 2.8144 | 190.7608 |

Raw results: [results-lot69-loss-64m.json](results-lot69-loss-64m.json).

## Reproduction

```sh
go build -o /tmp/mpquic-lot69 ./integrationtests/tools/multiinterface
bash integrationtests/tools/multiinterface/run.sh /tmp/mpquic-lot69 /tmp/mpquic-lot69-1g 1073741824
MPQUIC_SCENARIOS='cut-primary cut-secondary' MPQUIC_TIMEOUT=30s \
  bash integrationtests/tools/multiinterface/run.sh /tmp/mpquic-lot69 /tmp/mpquic-lot69-64m
MPQUIC_LOSS=1% MPQUIC_SCENARIOS='multipath cut-primary' MPQUIC_TIMEOUT=60s \
  bash integrationtests/tools/multiinterface/run.sh /tmp/mpquic-lot69 /tmp/mpquic-lot69-loss-64m
```

## Regression coverage

`GOTOOLCHAIN=local go test ./...` and
`GOTOOLCHAIN=local go test -race . ./http3` both passed with Go 1.26.0.

Focused tests verify that elapsed time without same-path acknowledgment evidence
does not discard the flight or reduce its congestion window; another path's ACK
does not change that decision; a later same-path ACK enables loss detection;
PTO backs off and resets on fresh ACKs; ACK-only and abandoned paths do not arm
PTO; and the send loop emits one recovery PING, retains the original packet,
and does not treat that PING as a path-validation retry.

Each result is a single diagnostic run. Multiple repetitions, wider RTT/loss
distributions, upload-heavy workloads, and physical interfaces remain necessary
before drawing general performance or production-readiness conclusions.
