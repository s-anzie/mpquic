# 1 GiB multisource transfers without content SHA verification

This experiment disables both the benchmark client's streaming SHA-256 and the
source worker's per-chunk SHA-256 comparison. Exact byte counts, EOF, source
object metadata validation, read-length checks, TLS peer authentication, QUIC
packet protection, congestion control and key rotation remain enabled. Object
manifest and file digest preparation still happens before the transfer timer.
This does not disable cryptographic hashing used by TLS or QUIC.

The source bypass exists only in the separately compiled benchmark executable.
`build_no_source_sha.py` uses a Go build overlay to remove exactly the source
content digest guard without modifying the library source on disk. Normal
builds retain verification. The executable labels results with
`source_sha256_verification: disabled-build-overlay`; the client check is labeled
`sha256_verified: false` and no verified content digest is published.

Three sequential multisource runs transfer 1,073,741,824 bytes each, with
GOMAXPROCS=8 and Go 1.26.0. Client and primary share one process; two distinct
source subprocesses read their own files and send over loopback paths. These are
local implementation measurements, not geographic link-capacity measurements.
The comparison uses the preceding three-run series in `../1gib-no-client-sha`
and `../1gib-optimized`; the series are not randomized or interleaved.

The one-server modes do not use the source chunk verification code, so they were
not rerun in this experiment. Their previous no-client-SHA medians remain 2.893 s
(one path) and 4.145 s (two paths), rather than new measurements here.

Reproduce from the repository root:

```sh
GOTOOLCHAIN=local python3 integrationtests/tools/transfercompare/build_no_source_sha.py \
  --output /tmp/mpquic-no-source-sha
GOMAXPROCS=8 python3 integrationtests/tools/transfercompare/run.py \
  --binary /tmp/mpquic-no-source-sha --skip-sha256 --bytes 1073741824 \
  --modes multisource --timeout 90s --output /tmp/no-content-sha
```

The skip is an attribution experiment, not a production optimization. Moving
verification into setup or a cache would need an explicit immutable-content
contract and separate accounting of preparation costs; it cannot be counted as
eliminating the total verification work.

## Results

| Run | Seconds | Mbit/s | Lease batches |
| --- | ---: | ---: | ---: |
| 1 | 12.309 | 697.9 | 4,107 |
| 2 | 12.611 | 681.1 | 3,776 |
| 3 | 18.917 | 454.1 | 6,254 |

Median: **12.611 s / 681.1 Mbit/s**. Previous source-verified, client-unverified median: **18.623 s / 461.3 Mbit/s**. The observed median duration reduction is 32.3% (throughput increase 47.7%).

All three runs delivered the expected byte count with both sources active and ten observed key rotations per source. They do not certify content SHA integrity, which was deliberately skipped.

The third run took 18.917 s, overlapping the source-verified measurements. It used 6,254 lease batches versus 3,776–4,107 in the first two runs. This is an observation, not proof that batch count caused the difference. Source hashing contributes overhead in this experiment, but removing it does not eliminate throughput variability or establish a guaranteed speedup.

Normal-build validation: the corrupt-source failover and bad-content tests remain enabled; a small normal-build transfer checks that client and source verification are still on by default.
