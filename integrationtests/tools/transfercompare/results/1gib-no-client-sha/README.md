# 1 GiB transfers without the client content digest

This experiment disables only the benchmark client's streaming SHA-256 check
with `-verify-sha256=false` / runner `--skip-sha256`. The exact byte count and EOF
are still checked. QUIC packet protection and source-side per-chunk object hash
verification remain enabled. File/manifest preparation remains outside the timer.
This is not a transfer with every cryptographic hash removed from the protocol.

The flag defaults to true. Disabled runs emit `sha256_verified: false` and omit
the `sha256` field rather than publishing an unverified expected digest.

Each mode transfers exactly 1,073,741,824 bytes, three sequential repetitions,
GOMAXPROCS=8, Go 1.26.0. The same loopback topology and optimized implementation
are used as in `../1gib-optimized`. Two-source mode has two worker subprocesses
and an additional primary control path. These measurements do not test WAN
bandwidth aggregation.

The with-SHA reference is the preceding three-run median, not an interleaved,
randomized paired experiment. Differences within the observed run variability
must not be interpreted as a causal speedup or slowdown from SHA verification.
CPU time spent hashing cannot be subtracted from elapsed transfer time because
hashing overlaps transport and source coordination.

Reproduce after building the benchmark:

```sh
go build -o /tmp/mpquic-transfercompare ./integrationtests/tools/transfercompare
GOMAXPROCS=8 python3 integrationtests/tools/transfercompare/run.py \
  --binary /tmp/mpquic-transfercompare --bytes 1073741824 --timeout 90s \
  --skip-sha256 --output /tmp/mpquic-no-client-sha
```

## Results

| Mode | Median without client SHA, s | Observed range, s | Mbit/s | Previous median with SHA, s |
| --- | ---: | ---: | ---: | ---: |
| One server, one path | 2.893 | 2.510–3.068 | 2969.5 | 4.264 |
| One server, two paths | 4.145 | 4.069–4.179 | 2072.1 | 4.467 |
| Two data sources, two paths plus primary control | 18.623 | 17.605–18.917 | 461.3 | 17.249 |

All nine runs completed with the expected byte count. The multisource results do not show a reduction in elapsed time from removing the client digest. Their range overlaps the with-SHA reference; no meaningful slowdown should be inferred either. The single-path benchmark improves substantially, while two-path overhead and multisource coordination remain.
