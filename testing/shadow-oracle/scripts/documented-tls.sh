#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family: README.md:280 — "native TLS and mTLS with
# no reverse proxy in front." Generates a throwaway self-signed cert with openssl, boots busbar with
# `tls: { cert:, key: }`, and confirms /healthz answers over HTTPS directly (no proxy). Full mTLS
# (client_ca + a client cert) is a heavier fixture the config plane already owns
# (config/tests/tests.rs test_tls_typo_and_removed_keys_rejected_at_parse and friends); this cell
# proves the plain-TLS half of the claim actually serves traffic, not just that the config parses.
#
#   documented-tls.sh
#
# Writes $RAW/captured.json. Env from the recorder: BUSBAR_BIN RAW WORK.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
LP="${TLS_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48921}}"
W="$RAW/tls-work"; mkdir -p "$W"

for p in "$LP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"; exit 0; }

if ! command -v openssl >/dev/null; then
  step openssl_available "false"
  fail -1 "openssl not available on this host"
fi
step openssl_available "true"

openssl req -x509 -newkey rsa:2048 -keyout "$W/key.pem" -out "$W/cert.pem" -days 1 -nodes \
  -subj "/CN=oracle-tls-test" >"$W/openssl.log" 2>&1
[ -s "$W/cert.pem" ] && [ -s "$W/key.pem" ] || fail 1 "$(cat "$W/openssl.log")"

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
YAML
cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
tls:
  cert: { file: "${W}/cert.pem" }
  key: { file: "${W}/key.pem" }
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
groups:
  oracle:
    limits:
      - { budget: 1000000, per: day }
providers:
  openai-chat:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-openai-chat:
    provider: openai-chat
rate_card:
  m-openai-chat: { input_utok: 100000, output_utok: 200000 }
YAML

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn "$BIN" ) \
  >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
i=0; healthy=0
while [ $i -lt 100 ]; do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  if curl -k -fsS -m 1 -o /dev/null "https://127.0.0.1:${LP}/healthz" 2>/dev/null; then healthy=1; break; fi
  sleep 0.1; i=$((i+1))
done
step booted_https "$([ "$healthy" -eq 1 ] && echo true || echo false)"
if [ "$healthy" -ne 1 ]; then
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  fail 2 "$(tail -c 800 "$W/busbar.log")"
fi
step healthz_https_status "$(curl -k -sS -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${LP}/healthz")"
# confirm PLAIN http on the same port is refused (busbar is TLS-only once configured, no fallback)
plain_rc=0
curl -fsS -m 2 -o /dev/null "http://127.0.0.1:${LP}/healthz" 2>/dev/null || plain_rc=$?
step plain_http_refused "$([ "$plain_rc" -ne 0 ] && echo true || echo false)"

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

jq -n --argjson eff "$eff" --arg body "$(jq -c . <<<"$eff")" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
