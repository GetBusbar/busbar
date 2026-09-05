#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family: README.md:188-192's container one-liner
# (`docker run --rm -p 8080:8080 -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN getbusbar/busbar`) boots the
# EXACT shipped default config (`docker/config.yaml`, byte-for-byte except the `listen:` port, which
# is rewritten off 8080 so the recorder never fights another test for that port) with only the two
# named env vars set, and answers /healthz — proving the file this repo ships is not merely a
# committed artifact but an actually-bootable default.
#
#   documented-docker-defaults.sh
#
# Writes $RAW/captured.json. Env from the recorder: BUSBAR_BIN RAW WORK.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
LP="${DOCKERDEF_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48911}}"
W="$RAW/docker-defaults-work"; mkdir -p "$W"

for p in "$LP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

python3 - "${repo}/docker/config.yaml" "$W/config.yaml" "$LP" <<'PY'
import sys, re
src, dst, port = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(src).read()
s = re.sub(r'^listen: .*$', f'listen: "127.0.0.1:{port}"', s, flags=re.M)
open(dst, "w").write(s)
PY
cat >"$W/providers.yaml" <<YAML
anthropic:
  protocol: anthropic
  base_url: "http://127.0.0.1:1"
YAML

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ANTHROPIC_KEY=unused BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn "$BIN" ) \
  >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
if wait_for_http "http://127.0.0.1:${LP}/healthz" 30; then
  step booted "true"
else
  step booted "false"
  fail 1 "$(tail -c 800 "$W/busbar.log")"
fi
step open_relay_warn_present "$(grep -qi 'OPEN RELAY' "$W/busbar.log" && echo true || echo false)"
step healthz_status "$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${LP}/healthz")"
step models_status "$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${LP}/v1/models")"

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

jq -n --argjson eff "$eff" --arg body "$(jq -c . <<<"$eff")" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
