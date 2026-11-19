#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 5, the measurement: every serving binary against v1.5.5 by ONE method.
# Runs on the measurement machine only (never on a laptop, never in CI's build stage).
#
#   bar.sh <out.tsv> <reps> <server-dir> [<server-dir> ...]
#
# A server directory describes one engine binary to measure:
#   bin            a file holding the path of the release binary
#   port           the port its config.yaml listens on (loopback)
#   config.yaml    its configuration, plain HTTP/1.1 on that port, provider "mock" pointing at
#                  the stub on $STUB_PORT, one caller key
#   config-tls.yaml (optional) the same with the listener serving TLS from tls/leaf.pem and
#                  tls/leaf.key; when present every row is measured over TLS as well
#   routes         (optional) the routes it can serve, one word each: healthz chat stream
#                  (default: healthz). A binary that cannot serve a route yet lists fewer;
#                  the comparison then reports that route as NOT MEASURED, never as a pass.
#   env            (optional) KEY=VALUE lines exported to the engine
# The directory's name is the row label; the baseline's is v155.
#
# Method, the same for every binary (it is the method of the v1.5.5 baseline, perf-155): loopback,
# a fresh engine per (route, transport, client thread count), kept-alive then new-connection,
# 1 and 8 client threads, <reps> repetitions; then memory per idle connection on a fresh engine.
# Counts per client thread come from the environment so a rehearsal can be short:
#   KEEP_N (default 200000) NEW_N (default 20000) IDLE_CONNS (default 2000)
set -eu

out=$1
reps=$2
shift 2
here=$(cd "$(dirname "$0")" && pwd)
tool=${PERF_BAR:-$here/../../tools/perf-bar/target/release/perf-bar}
[ -x "$tool" ] || { echo "bar.sh: build tools/perf-bar first (cargo build --release in tools/perf-bar): $tool" >&2; exit 2; }

KEEP_N=${KEEP_N:-200000}
NEW_N=${NEW_N:-20000}
IDLE_CONNS=${IDLE_CONNS:-2000}
STUB_PORT=${STUB_PORT:-18090}
PERF_CLK_TCK=$(getconf CLK_TCK)
export PERF_CLK_TCK STUB_PORT
export PERF_KEY=${PERF_KEY:-x} PERF_MODEL=${PERF_MODEL:-mock}

work=$(mktemp -d "${TMPDIR:-/tmp}/perf-bar.XXXXXX")
engine=""
stub=""
cleanup() {
  [ -n "$engine" ] && kill "$engine" 2>/dev/null || true
  [ -n "$stub" ] && kill "$stub" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

"$tool" header > "$out"
{
  echo "# host $(uname -r) cores=$(nproc) load=$(cut -d' ' -f1-3 /proc/loadavg) $(date -u +%FT%TZ)"
  echo "# keep_n=$KEEP_N new_n=$NEW_N idle_conns=$IDLE_CONNS reps=$reps"
} >> "$out"

"$tool" stub "$STUB_PORT" &
stub=$!

# start <dir> <config file>: a fresh engine; sets $engine and $port.
start() {
  dir=$1
  port=$(cat "$dir/port")
  bin=$(cat "$dir/bin")
  run="$work/run-$(basename "$dir")"
  rm -rf "$run"
  mkdir -p "$run"
  (
    cd "$run"
    if [ -f "$dir/env" ]; then
      set -a
      . "$dir/env"
      set +a
    fi
    BUSBAR_CONFIG=$2 exec "$bin" > "$run/engine.log" 2>&1
  ) &
  engine=$!
}

stop() {
  kill "$engine" 2>/dev/null || true
  wait "$engine" 2>/dev/null || true
  engine=""
}

# measure <dir> <transport word> <config> <tls argument or empty>
measure() {
  dir=$1
  label=$(basename "$dir")
  routes=healthz
  [ -f "$dir/routes" ] && routes=$(cat "$dir/routes")
  for route in $routes; do
    for threads in 1 8; do
      start "$dir" "$3"
      if ! "$tool" wait "127.0.0.1:$port" healthz $4; then
        echo "# BOOT FAILED $label $2 $route" >> "$out"
        tail -25 "$work/run-$label/engine.log" | cut -c1-400 >&2
        stop
        return 1
      fi
      "$tool" keep "$label" "$threads" "$((KEEP_N / threads))" "$((KEEP_N / threads / 10))" \
        "127.0.0.1:$port" "$engine" "$route" $4 >> "$out"
      "$tool" new "$label" "$threads" "$((NEW_N / threads))" "$((NEW_N / threads / 10))" \
        "127.0.0.1:$port" "$engine" "$route" $4 >> "$out"
      stop
    done
  done
  # Memory per connection: idle, and after one request each, on a fresh engine.
  start "$dir" "$3"
  "$tool" wait "127.0.0.1:$port" healthz $4
  "$tool" idle "$label" "$IDLE_CONNS" "127.0.0.1:$port" "$engine" healthz $4 >> "$out"
  stop
}

rep=1
while [ "$rep" -le "$reps" ]; do
  for dir in "$@"; do
    dir=$(cd "$dir" && pwd)
    measure "$dir" plain "$dir/config.yaml" ""
    if [ -f "$dir/config-tls.yaml" ]; then
      measure "$dir" tls "$dir/config-tls.yaml" "tls:$dir/tls/ca.pem:localhost"
    fi
  done
  rep=$((rep + 1))
done
echo "# MEASURE-DONE $(date -u +%FT%TZ)" >> "$out"
