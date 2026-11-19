#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 5, the measurement: every serving binary against v1.5.5 by ONE method.
# Runs on the measurement machine only (never on a laptop, never in CI's build stage).
#
#   bar.sh <out.tsv> <reps> <server-dir> [<server-dir> ...]
#
# A server directory (ci/perf/servers/<label>) describes one engine binary to measure:
#   bin              a file holding the path of the release binary on this machine (not committed)
#   port             the port its configuration listens on
#   config.yaml      its configuration: a template in which @RUN@ is the run directory,
#                    @STUB_PORT@ the stub's port, @ADMIN_SHA256@ the digest of this run's admin
#                    token (the token itself is random per run and only in the engine's
#                    environment as BUSBAR_ADMIN_TOKEN) and @TLS@ the directory of this run's
#                    certificate (ca.pem, leaf.pem, leaf.key)
#   providers.yaml   (optional) rendered the same way next to it
#   config-tls.yaml  (optional) the same listener serving TLS; when present every row is
#                    measured over TLS as well
#   routes           the routes it can serve, one word each: healthz chat stream. A binary that
#                    cannot serve a route yet lists fewer; the verdict then reports that route as
#                    NOT MEASURED, never as a pass.
# The directory's name is the row label; the baseline's is v155.
#
# The method is the v1.5.5 baseline's (perf-155, 18 Nov 2026) and its counts are that run's:
# loopback, a fresh engine per (route, transport, client thread count), kept-alive then
# new-connection, per client thread 20,000 kept-alive and 10,000 new at 1 thread, 4,000 and 2,500
# at 8 threads, a tenth of that again as warm-up; then, on a fresh engine, 200 warm-up requests of
# each kind and 2,000 connections held for the memory figures. SMOKE=1 divides every count by 100
# for a rehearsal whose numbers mean nothing.
set -eu

out=$1
reps=$2
shift 2
here=$(cd "$(dirname "$0")" && pwd)
tool=${PERF_BAR:-$here/../../tools/perf-bar/target/release/perf-bar}
[ -x "$tool" ] || { echo "bar.sh: build tools/perf-bar first (cargo build --release in tools/perf-bar): $tool" >&2; exit 2; }

div=1
[ "${SMOKE:-0}" = 1 ] && div=100
KEEP_1=$((20000 / div)); NEW_1=$((10000 / div)); KEEP_8=$((4000 / div)); NEW_8=$((2500 / div))
HOLD=$((2000 / div)); HOLD_WARM=$((200 / div))
STUB_PORT=18090
PERF_CLK_TCK=$(getconf CLK_TCK)
export PERF_CLK_TCK
export MOCK_KEY=x

work=$(mktemp -d "${TMPDIR:-/tmp}/perf-bar.XXXXXX")
engine=""
stub=""
cleanup() {
  [ -n "$engine" ] && kill "$engine" 2>/dev/null || true
  [ -n "$stub" ] && kill "$stub" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

# This run's admin token (never written to disk) and its certificate.
BUSBAR_ADMIN_TOKEN=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
export BUSBAR_ADMIN_TOKEN
admin_sha256=$(printf '%s' "$BUSBAR_ADMIN_TOKEN" | sha256sum | cut -d' ' -f1)
tls=$work/tls
mkdir -p "$tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=perf-bar CA" \
  -keyout "$tls/ca.key" -out "$tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
  -keyout "$tls/leaf.key" -out "$tls/leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$tls/san.cnf"
openssl x509 -req -in "$tls/leaf.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca.key" -CAcreateserial \
  -days 2 -extfile "$tls/san.cnf" -out "$tls/leaf.pem" 2>/dev/null

"$tool" header > "$out"
{
  echo "# host $(uname -r) cores=$(nproc) load=$(cut -d' ' -f1-3 /proc/loadavg) $(date -u +%FT%TZ)"
  echo "# keep_1=$KEEP_1 new_1=$NEW_1 keep_8=$KEEP_8 new_8=$NEW_8 hold=$HOLD reps=$reps smoke=${SMOKE:-0}"
  for dir in "$@"; do
    echo "# binary $(basename "$dir") $(sha256sum "$(cat "$dir/bin")" | cut -d' ' -f1)"
  done
} >> "$out"

"$tool" stub "$STUB_PORT" 64 &
stub=$!

render() {
  sed -e "s|@RUN@|$3|g" -e "s|@STUB_PORT@|$STUB_PORT|g" -e "s|@ADMIN_SHA256@|$admin_sha256|g" \
    -e "s|@TLS@|$tls|g" "$1" > "$2"
}

# start <dir> <config template>: a fresh engine; sets $engine, $port and $label.
start() {
  dir=$1
  label=$(basename "$dir")
  port=$(cat "$dir/port")
  bin=$(cat "$dir/bin")
  run="$work/run-$label"
  rm -rf "$run"
  mkdir -p "$run"
  render "$2" "$run/config.yaml" "$run"
  [ -f "$dir/providers.yaml" ] && render "$dir/providers.yaml" "$run/providers.yaml" "$run"
  (
    cd "$run"
    BUSBAR_CONFIG=$run/config.yaml exec "$bin" > "$run/engine.log" 2>&1
  ) &
  engine=$!
}

stop() {
  kill "$engine" 2>/dev/null || true
  wait "$engine" 2>/dev/null || true
  engine=""
}

# up <tls argument or empty>: wait for the engine just started, or say why it did not come up.
up() {
  if ! "$tool" wait "$port" $1; then
    echo "# BOOT FAILED $label" >> "$out"
    grep -v 'serves PLAINTEXT' "$work/run-$label/engine.log" | tail -25 | cut -c1-400 >&2
    stop
    return 1
  fi
}

# measure <dir> <config template> <tls argument or empty>
measure() {
  for route in $(cat "$1/routes"); do
    for threads in 1 8; do
      if [ "$threads" = 1 ]; then kn=$KEEP_1; nn=$NEW_1; else kn=$KEEP_8; nn=$NEW_8; fi
      start "$1" "$2"
      up "$3"
      "$tool" keep "$label" "$threads" "$kn" "$((kn / 10))" "$port" "$engine" "$route" $3 >> "$out"
      "$tool" new "$label" "$threads" "$nn" "$((nn / 10))" "$port" "$engine" "$route" $3 >> "$out"
      stop
    done
  done
  # Memory per connection, on a fresh engine, as the baseline's hold job.
  start "$1" "$2"
  up "$3"
  "$tool" keep "$label" 1 "$HOLD_WARM" 0 "$port" "$engine" healthz $3 > /dev/null
  "$tool" new "$label" 1 "$HOLD_WARM" 0 "$port" "$engine" healthz $3 > /dev/null
  sleep 1
  "$tool" hold "$label" "$HOLD" "$port" "$engine" healthz $3 >> "$out"
  stop
}

rep=1
while [ "$rep" -le "$reps" ]; do
  for dir in "$@"; do
    dir=$(cd "$dir" && pwd)
    measure "$dir" "$dir/config.yaml" ""
    if [ -f "$dir/config-tls.yaml" ]; then
      measure "$dir" "$dir/config-tls.yaml" "tls:$tls/ca.pem:localhost"
    fi
  done
  rep=$((rep + 1))
done
echo "# MEASURE-DONE $(date -u +%FT%TZ)" >> "$out"
