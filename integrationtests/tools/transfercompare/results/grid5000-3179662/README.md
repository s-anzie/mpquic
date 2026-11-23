# Grid'5000: 1 GiB distributed QUIC transfers

## Allocation and software

- Date: 2026-11-23; OAR job **3179662**, Grenoble, cluster **dahu**.
- Requested: three entire nodes for one hour, immediate reservation.
- Allocation started at 14:12:43 Europe/Paris; scheduled end 15:12:15.
  OAR adjusted the remaining walltime to 3572 seconds after reservation startup.
- Client: dahu-1 (172.16.20.1 / 172.18.20.1).
- Primary server and first source worker: dahu-13 (172.16.20.13 / 172.18.20.13).
- Second source worker: dahu-2 (172.16.20.2 / 172.18.20.2).
- Library baseline: commit **2fccdfe9**. This experiment adds a distributed
  benchmark launcher; it does not modify the transport library.
- Go 1.26.0, CGO disabled, GOMAXPROCS=8 per process. Each source worker is a
  separate process. All servers and workers run on the reserved nodes, not the
  frontend or the local workstation.
- Each node has two Xeon Gold 6130 processors, 32 physical cores / 64 hardware
  threads. The frontend runs only orchestration and stores small result files.

Dahu has Ethernet 10 Gbit/s and Omni-Path 100 Gbit/s. The latter is exposed as
`ib0`; folder names containing `infiniband` refer to that IP interface, not a
different physical network.
See [Grid'5000 hardware](https://www.grid5000.fr/w/Hardware) and
[Grenoble networking](https://www.grid5000.fr/w/Grenoble%3ANetwork).
Measured node metadata and binary hashes are retained in `metadata-*.txt`.

## Method

Every measured transfer contains **1,073,741,824 application bytes** on one QUIC
connection. Three repeats per configuration, sequentially, with fresh processes
and connections. Source data is generated on each node's local /tmp filesystem
before measurement and is cached; no NFS file read is in the data path.

The initial path receives a 512 KiB untimed warm-up. Additional paths are
validated before measurement but do not receive a separate bulk-data warm-up.
Object manifests, worker startup and path validation are outside the timer.
The client starts its monotonic timer before sending the start message and stops
at stream EOF. This includes the start-message transit, but excludes result
collection and teardown. Byte count is checked in every run.

Main measurements disable client content SHA. For multisource, a build overlay
also disables source per-chunk content SHA. Metadata checks, TLS authentication,
QUIC encryption and preparation-time manifest hashing remain enabled. Normal
builds keep all digest checks; no unsafe library API was added. Separate verified
runs use both source and client SHA.

Two ordinary paths on Ethernet use two client UDP sockets on the same physical
interface. The dual-fabric case binds the second socket to 172.18.20.1. A narrow
source/destination policy route on the reserved client sends traffic from that
address to 172.16.20.13 through 172.18.20.13 on ib0. The server retains one QUIC
listener. For dual-fabric multisource, source 1 sends over Ethernet and source 2
over Omni-Path. The primary coordinates the workers over authenticated TLS.

No bandwidth shaping or artificial delay is used. These are three machines in
one cluster, not a geographically distributed WAN. The network capacities are
unequal; this is not a symmetric two-link aggregation benchmark.

## Results without content SHA

| Network / architecture | Seconds, runs 1 / 2 / 3 | Median seconds | Useful Gbit/s |
|---|---|---:|---:|
| Ethernet / single | 1.930 / 1.816 / 1.933 | 1.930 | 4.450 |
| Omni-Path / single | 1.781 / 1.989 / 1.778 | 1.781 | 4.822 |
| Ethernet, two sockets / multipath | 2.657 / 2.538 / 2.931 | 2.657 | 3.233 |
| Ethernet + Omni-Path / multipath | 2.394 / 2.470 / 2.349 | 2.394 | 3.588 |
| Ethernet, two sources / multisource | 9.143 / 9.051 / 8.730 | 9.051 | 0.949 |
| Ethernet + Omni-Path, two sources / multisource | 7.600 / 8.237 / 7.598 | 7.600 | 1.130 |

The best single-path result remains faster than either multipath architecture.
On Ethernet, ordinary multipath takes about 38% longer than single path.
Using both fabrics reduces ordinary multipath time by about 10%, and multisource
time by about 16%, relative to their Ethernet-only variants, but does not remove
the implementation overhead. These three-repeat medians are not confidence
intervals or maximum sustainable-throughput claims.

All multipath and multisource measured runs have zero client receive-queue drops.
Single-path runs have 190–429 such drops on Ethernet and 95–626 on Omni-Path.
These counters count admission drops inside the library, not all network loss.
Raw UDP and interface counters are retained alongside every result.

The median-time Ethernet multisource run reports 6.845 s of accumulated dispatch
time, including 3.857 s of worker-drain wait, and 0.914 s of capacity wait.
Drain wait is a subset of dispatch time: do not add it twice or interpret it as
pure network latency. The client receives about 1.078 million datagrams in that
run, versus about 0.771 million for ordinary QUIC. These identify remaining
transport/coordination costs; this experiment alone does not prove one root cause.

## Integrity and physical-path validation

All seven complete 1 GiB runs using the verified build passed byte count and
SHA verification. Their SHA-256 is:

`188e43c2f1b607dc07b58ee779b9b58fb176a51d79a7abfa70c80a16947b692c`

| Verified configuration | Seconds |
|---|---:|
| Ethernet single | 3.242 |
| Ethernet multipath | 3.386 |
| Ethernet multisource | 12.175 |
| Dual-fabric multipath | 3.500 |
| Dual-fabric multisource | 11.673 |
| Dual-fabric multipath, extra counter validation | 3.380 |
| Dual-fabric multisource, extra counter validation | 10.500 |

In the extra counter-validation multipath run, the Ethernet-bound client socket
receives 550,007,709 UDP bytes and the Omni-Path-bound socket 549,292,666 UDP bytes.
The Ethernet interface receive counter increases by 561,386,038 bytes and the
hfi1 hardware receive-data counter by 72,079,446 raw units.
For multisource, the worker-bound sockets receive 382,500,349 and 730,969,893 UDP
bytes respectively, and the hfi1 hardware counter increases by 97,979,774 units.

The generic ib0 byte counters do not reflect these transfers on this environment.
Hardware counter deltas are deliberately retained in raw units, without inferring
a byte conversion for this hfi1/Omni-Path device. Thus the physical-path check uses
socket bytes, routing, Ethernet counters and increasing hardware port counters
together; it does not report a misleading zero on the second link.

A preliminary 64 MiB multisource smoke attempt failed before listening because it
referenced the prepared 1 GiB object. The object-size guard correctly rejected
it. No transfer result was produced. The launcher error handling and diagnostic
were corrected, and complete 1 GiB tests used exactly matching objects. The
preliminary artifacts are retained in `dual-fabric-smoke-verified/`.

## Validation and cleanup

Local 64 MiB smoke transfers in all three distributed roles passed full SHA
before deployment. Root-module tests and benchmark vet passed. The actual
distributed benchmark then passed all complete configurations above.

After measurements, no benchmark process remained on any of the three nodes.
The temporary client policy rule and route (table/priority 31796) were removed.
The requested OAR allocation was left active until its scheduled expiry;
no additional reservation or extension was requested. Node-local experiment
files remain available within the allocation.

## Reproduction

Build normal and no-source-SHA executables with the existing overlay builder.
Generate an ephemeral experiment identity using `-role identity -state-dir DIR`.
Copy binaries and the public certificate to the nodes, and the private key to the
primary. On each source node, prepare the local data with:

```sh
GOMAXPROCS=8 /tmp/mpquic-JOB/mpquic-distributed-verified -role object -object /tmp/mpquic-JOB/data -bytes 1073741824
```

The launcher expects the node-local directory `/tmp/mpquic-$OAR_JOB_ID`.
On the site's frontend, with the existing allocation:

```sh
export OAR_JOB_ID=3179662
python3 run_grid5000.py --directory "$HOME/mpquic-3179662" --client dahu-1 --primary dahu-13 --source dahu-2 --client-ip 172.16.20.1 --primary-ip 172.16.20.13 --source-ip 172.16.20.2 --label ethernet-no-sha --repeats 3
```

For verified runs add `--verified`. For dual-fabric runs also add
`--client-second-ip 172.18.20.1 --source-second-ip 172.18.20.2` and the temporary
policy route on the reserved client:

```sh
sudo-g5k ip route add table 31796 172.16.20.13/32 via 172.18.20.13 dev ib0 onlink src 172.18.20.1
sudo-g5k ip rule add priority 31796 from 172.18.20.1/32 to 172.16.20.13/32 lookup 31796
```

Remove that exact rule and route after the experiment. Addresses and job IDs
above describe this allocation and must be replaced for a new allocation.
