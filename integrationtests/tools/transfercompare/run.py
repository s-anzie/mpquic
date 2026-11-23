#!/usr/bin/env python3
"""Run equal-sized transfers sequentially and preserve every raw result."""
import argparse
import json
import hashlib
import os
import platform
import resource
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--binary", default="/tmp/mpquic-transfercompare")
parser.add_argument("--timeout", default="2h")
parser.add_argument("--bytes", type=int, default=1 << 30)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--modes", nargs="+", default=["single", "multipath", "multisource"])
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
metadata = {
    "created_unix": time.time(), "platform": platform.platform(),
    "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "git_status": subprocess.check_output(["git", "status", "--short"], text=True),
    "bytes": args.bytes, "initial_load_average": os.getloadavg(),
    "timeout": args.timeout,
    "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
    "gomaxprocs_environment": os.environ.get("GOMAXPROCS"),
    "measurement": "loopback; client and primary share a process; each source is a distinct subprocess",
}
(args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
for mode in args.modes:
    print(f"Starting {mode}: {args.bytes} application bytes", flush=True)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    with (args.output / f"{mode}.json").open("w") as out, (args.output / f"{mode}.log").open("w") as log:
        completed = subprocess.run([args.binary, "-mode", mode, "-bytes", str(args.bytes), "-timeout", args.timeout], stdout=out, stderr=log)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    timing = {"exit_code": completed.returncode, "whole_process_seconds": time.monotonic() - start,
              "user_cpu_seconds": after.ru_utime - before.ru_utime,
              "system_cpu_seconds": after.ru_stime - before.ru_stime,
              "note": "CPU and whole-process time include preparation, warm-up and cleanup; transfer time is in the mode JSON."}
    (args.output / f"{mode}-process.json").write_text(json.dumps(timing, indent=2) + "\n")
    print(f"Finished {mode}: {timing}", flush=True)
    if completed.returncode:
        raise SystemExit(completed.returncode)
