#!/usr/bin/env bash
# All routing, shaping and failure injection occur inside disposable namespaces.
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
  if [[ $# -lt 2 ]]; then
    echo "usage: bash run.sh /absolute/path/to/binary /absolute/output/directory [bytes]" >&2
    exit 2
  fi
  export MPQUIC_HOST_NETNS
  MPQUIC_HOST_NETNS=$(readlink /proc/self/ns/net)
  exec unshare -Urn bash "$0" --isolated "$@"
fi
shift
binary=$1
results=$2
bytes=${3:-67108864}
mkdir -p "$results"
if [[ -z ${MPQUIC_HOST_NETNS:-} || $(readlink /proc/self/ns/net) == "$MPQUIC_HOST_NETNS" ]]; then
  echo "refusing to configure the host network namespace" >&2
  exit 2
fi

unshare -n sleep 3600 &
server_namespace=$!
server_pid=
cleanup() {
  if [[ -n $server_pid ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  kill "$server_namespace" 2>/dev/null || true
  wait "$server_namespace" 2>/dev/null || true
}
trap cleanup EXIT
# Wait until the child has entered its separate namespace.
for attempt in $(seq 1 100); do
  if [[ $(readlink "/proc/$server_namespace/ns/net") != $(readlink /proc/self/ns/net) ]]; then break; fi
  sleep 0.01
done
server() { nsenter -t "$server_namespace" -n "$@"; }
ip link set lo up
server ip link set lo up
server ip address add 10.66.0.1/32 dev lo
for path in a b; do
  subnet=1
  if [[ $path == b ]]; then subnet=2; fi
  ip link add "mpq-c$path" type veth peer name "mpq-s$path"
  ip link set "mpq-s$path" netns "$server_namespace"
  ip address add "10.66.$subnet.1/24" dev "mpq-c$path"
  server ip address add "10.66.$subnet.2/24" dev "mpq-s$path"
  ip link set "mpq-c$path" up
  server ip link set "mpq-s$path" up
  tc qdisc add dev "mpq-c$path" root netem delay 2ms rate 200mbit
  server tc qdisc add dev "mpq-s$path" root netem delay 2ms rate 200mbit
done
ip route add 10.66.0.1/32 via 10.66.1.2 dev mpq-ca src 10.66.1.1
ip rule add from 10.66.2.1/32 table 102
ip route add table 102 10.66.0.1/32 via 10.66.2.2 dev mpq-cb src 10.66.2.1
# Source policy routing requires loose reverse-path validation on the client.
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.mpq-ca.rp_filter=0 net.ipv4.conf.mpq-cb.rp_filter=0
ip -j address > "$results/client-addresses.json"
ip -j rule > "$results/client-rules.json"
ip route get 10.66.0.1 from 10.66.1.1 > "$results/route-a.txt"
ip route get 10.66.0.1 from 10.66.2.1 > "$results/route-b.txt"
server ip -j address > "$results/server-addresses.json"

failed=0
for protocol in ${MPQUIC_PROTOCOLS:-quic http3}; do
  for scenario in ${MPQUIC_SCENARIOS:-single multipath cut-secondary cut-primary}; do
    name="$protocol-$scenario"
    ip link set mpq-ca up
    ip link set mpq-cb up
    # Link-down removes static routes; restore both before each independent case.
    ip route replace 10.66.0.1/32 via 10.66.1.2 dev mpq-ca src 10.66.1.1
    ip route replace table 102 10.66.0.1/32 via 10.66.2.2 dev mpq-cb src 10.66.2.1
    enabled=true
    cut=
    case $scenario in
      single) enabled=false ;;
      cut-secondary) cut=mpq-cb ;;
      cut-primary) cut=mpq-ca ;;
    esac
    nsenter -t "$server_namespace" -n "$binary" -role server -protocol "$protocol" -multipath="$enabled" -bytes "$bytes" > "$results/$name-server.log" 2>&1 &
    server_pid=$!
    sleep 0.2
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server startup failed: $results/$name-server.log" >&2
      exit 1
    fi
    echo "RUN $name bytes=$bytes"
    if timeout 170 "$binary" -protocol "$protocol" -multipath="$enabled" -bytes "$bytes" -cut "$cut" -timeout "${MPQUIC_TIMEOUT:-150s}" > "$results/$name.json" 2> "$results/$name-client.log"; then
      echo "PASS $name"
    else
      echo "FAIL $name"
      failed=$((failed+1))
    fi
    server tc -s qdisc show > "$results/$name-server-qdisc.txt"
    tc -s qdisc show > "$results/$name-client-qdisc.txt"
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
  done
done
echo "Completed with $failed failed scenarios. Results: $results"
test "$failed" -eq 0
