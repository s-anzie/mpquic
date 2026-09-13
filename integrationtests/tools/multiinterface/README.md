# Multi-interface validation

This executable runs a client and server in separate Linux network namespaces.
It exercises production address discovery (`net.Interfaces`), not a mocked
inventory, using two veth pairs with distinct subnets and source-policy routes.
No `AddPath` call or custom address provider is used.

The host's physical interfaces, routes and Docker networks are not changed.
Unprivileged user/network namespaces, `ip`, `tc`, `nsenter`, `sysctl`, `timeout`
and Go are required. `sudo` is not required on hosts permitting user namespaces.
The runner rejects execution in its original network namespace. Namespace
processes are stopped on exit; result files are retained.

```sh
go build -o /tmp/mpquic-multiinterface-validation ./integrationtests/tools/multiinterface
bash integrationtests/tools/multiinterface/run.sh \
  /tmp/mpquic-multiinterface-validation /tmp/mpquic-multiinterface-results 1073741824
```

## Topology

- Client `mpq-ca`: `10.66.1.1/24`, server `mpq-sa`: `10.66.1.2/24`.
- Client `mpq-cb`: `10.66.2.1/24`, server `mpq-sb`: `10.66.2.2/24`.
- Server service address: `10.66.0.1:4433`, assigned to server loopback.
- Default service route uses A. Source `10.66.2.1` uses policy table 102 over B.
- Each direction of each veth pair has 200 Mbit/s rate and 2 ms delay shaping.
- Reverse-path filtering is disabled only in the isolated client namespace.

Policy routing is part of this setup: source-address binding alone does not
guarantee selection of a separate interface on an arbitrary host.

## Scenarios and success criteria

For QUIC streams and HTTP/3, run single-path, multipath, secondary-link removal,
and primary-link removal. Each case uses a fresh server and connection. Failure
injection executes `ip link set ... down` after receiving one quarter of the
requested application payload. Both links and source routes are restored before
the next case. These are hard link failures, not simulated inventory changes.

The executable verifies payload length and SHA-256, then sends a follow-up request
on the same connection. Multipath cases additionally require more than 64 KiB
received on each interface. HTTP/3 verifies the server-assigned connection ID
across the warmup, main request and follow-up. There is no application retry for
the main transfer. A failed scenario makes the runner exit nonzero after the
remaining cases finish.

JSON reports include transfer time, application goodput (decimal Mbit/s), received
bytes, checksum result, same-connection follow-up result and per-interface byte
deltas (`[RX, TX]`). Interface counters include network headers and retransmitted
traffic; they are not counts of unique application bytes. Timing excludes initial
connection setup, the discovery warmup, and reference checksum computation.
Qdisc snapshots are cumulative across scenarios and include the current backlog;
they should not be interpreted as per-transfer loss counters without subtraction.

## Interpretation

Optional environment controls: `MPQUIC_PROTOCOLS` selects `quic`, `http3`, or
both; `MPQUIC_SCENARIOS` selects a space-separated subset of the scenarios;
`MPQUIC_TIMEOUT` sets the client deadline (default `150s`, below the runner's
170-second process timeout). `MPQUIC_LOSS` adds independent random netem loss
in each direction of each link (default `0%`). Loss runs are diagnostic and
must not be compared as deterministic repetitions.

These tests validate kernel interface enumeration, routing, actual UDP traffic,
and failure handling. They do not establish behavior of Wi-Fi/Ethernet/cellular
hardware, radio handovers, independent Internet access links, NAT traversal, or
performance on another machine. A successful baseline does not imply successful
failover; read every scenario's status and error.
