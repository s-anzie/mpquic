#!/usr/bin/env python3
"""Run sequential distributed transfers inside an existing three-node OAR job.

Run this script on the site's frontend. Nodes and the one-hour allocation must
already exist; this script never requests or extends a reservation.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--directory", required=True)
parser.add_argument("--client", required=True)
parser.add_argument("--primary", required=True)
parser.add_argument("--source", required=True)
parser.add_argument("--client-ip", required=True)
parser.add_argument("--primary-ip", required=True)
parser.add_argument("--source-ip", required=True)
parser.add_argument("--client-second-ip")
parser.add_argument("--source-second-ip")
parser.add_argument("--repeats", type=int, default=3)
parser.add_argument("--bytes", type=int, default=1 << 30)
parser.add_argument("--verified", action="store_true")
parser.add_argument("--label", default="ethernet")
parser.add_argument("--modes", default="single,multipath,multisource")
args = parser.parse_args()
if not os.environ.get("OAR_JOB_ID"):
    raise SystemExit("OAR_JOB_ID is required")
directory = Path(args.directory)
results = directory / args.label
results.mkdir(parents=True, exist_ok=True)
node_directory = f"/tmp/mpquic-{os.environ['OAR_JOB_ID']}"
binary = node_directory + "/mpquic-distributed-" + ("verified" if args.verified else "no-sha")
common = ["env", "OAR_JOB_ID=" + os.environ["OAR_JOB_ID"], "GOMAXPROCS=8",
          binary, "-bytes", str(args.bytes), "-timeout", "180s",
          "-state-dir", node_directory, "-server", args.primary_ip + ":24444",
          "-verify-sha256=" + str(args.verified).lower()]

def remote(node, command):
    return ["oarsh", node, shlex.join(command)]

def counters(node):
    script = (
        "from pathlib import Path; import json,datetime; "
        "print(Path('/proc/net/dev').read_text()); "
        "print(Path('/proc/net/snmp').read_text()); "
        "print(json.dumps({'rdma_counters': {str(p): int(p.read_text()) "
        "for p in Path('/sys/class/infiniband').glob('*/ports/*/counters/port_*_data')}})); "
        "print(datetime.datetime.now(datetime.timezone.utc).isoformat())"
    )
    result = subprocess.run(remote(node, ["python3", "-c", script]),
        capture_output=True, text=True, timeout=20)
    result.check_returncode()
    return result.stdout

for iteration in range(1, args.repeats + 1):
    for mode in args.modes.split(","):
        name = f"{mode}-{iteration}"
        server_args = common + ["-mode", mode, "-role", "server",
            "-object", node_directory + "/data",
            "-worker-hosts", "," + args.source,
            "-worker-ips", args.primary_ip + "," + (args.source_second_ip or args.source_ip)]
        client_args = common + ["-mode", mode, "-role", "client",
            "-bind", args.client_ip, "-second-bind", args.client_second_ip or args.client_ip]
        for node in [args.client, args.primary, args.source]:
            (results / f"{name}-{node}-before.txt").write_text(counters(node))
        print(f"RUN {args.label} {name} bytes={args.bytes}", flush=True)
        with (results / f"{name}-server.stderr").open("w") as stderr:
            server = subprocess.Popen(remote(args.primary, server_args),
                stdout=subprocess.PIPE, stderr=stderr, text=True)
            remote_pid = None
            try:
                selector = selectors.DefaultSelector()
                selector.register(server.stdout, selectors.EVENT_READ)
                if not selector.select(30):
                    raise TimeoutError("server readiness deadline")
                line = server.stdout.readline()
                selector.close()
                if not line:
                    raise RuntimeError(f"server exited before readiness; see {name}-server.stderr")
                ready = json.loads(line)
                remote_pid = ready.get("pid")
                if "listening" not in ready:
                    raise RuntimeError("server failed to become ready")
                client = subprocess.run(remote(args.client, client_args),
                    capture_output=True, text=True, timeout=190)
                (results / f"{name}.json").write_text(client.stdout)
                (results / f"{name}-client.stderr").write_text(client.stderr)
                rest, _ = server.communicate(timeout=20)
                (results / f"{name}-server.jsonl").write_text(line + rest)
                client.check_returncode()
                if server.returncode:
                    raise RuntimeError(f"server exit {server.returncode}")
                value = json.loads(client.stdout)
                if value["bytes"] != args.bytes:
                    raise RuntimeError("incomplete transfer")
                if args.verified and not value["sha256_verified"]:
                    raise RuntimeError("missing integrity check")
                paths = value["client_sockets"]
                data_paths = paths[1:] if mode == "multisource" else paths
                if mode in ("multipath", "multisource") and (
                    len(data_paths) != 2 or any(p["UDPBytes"] < args.bytes // 10 for p in data_paths)
                ):
                    raise RuntimeError("both data paths must carry substantial traffic")
                if mode == "multisource" and (
                    len(value["sources"]) != 2 or any(s["Packets"] == 0 for s in value["sources"])
                ):
                    raise RuntimeError("both source workers must send packets")
                print(f"PASS {name} {value['seconds']:.6f}s {value['mbit_per_second']:.2f} Mbit/s", flush=True)
            finally:
                if server.poll() is None:
                    if isinstance(remote_pid, int) and remote_pid > 1:
                        subprocess.run(remote(args.primary, ["kill", "-TERM", str(remote_pid)]),
                            capture_output=True, timeout=10)
                    # oarsh can be setuid; the frontend user cannot signal its
                    # wrapper directly. Stop the owned remote process instead.
                    try:
                        server.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        raise RuntimeError("OAR transport did not stop; server has a 180s deadline")
        for node in [args.client, args.primary, args.source]:
            (results / f"{name}-{node}-after.txt").write_text(counters(node))
        time.sleep(1)
