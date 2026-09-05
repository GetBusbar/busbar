#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Shared boot/mint/call helpers for the H2 A2A gating scenarios (scripts/a2a-subject/h2-*.sh),
# tracker row H2 (docs/design/ARCHITECTURE.md #2.2). Each h2-*.sh script sources this, boots its OWN
# throwaway busbar + its own instance of h2-mock-agent.py on its own ports (the same isolation
# testing/shadow-oracle/scripts/teller-*.sh use for the llm plane, and scripts/mcp-subject/h2-lib.sh
# uses for the sibling plane).
#
# `pin.mechanism: jws_issuer_key`, exactly as a2a-subject/boot.sh's own signing-vendor.mjs uses:
# `crates/busbar-a2a/src/a2a/pin.rs` caps `unpinned` on purpose ("An Unpinned registration ... can
# never be approved"), so a registration this rig needs Busbar to actually SERVE needs a real
# authenticity root. `h2-mock-agent.mjs` generates its own throwaway Ed25519 issuer key at boot and
# signs its own card with it -- the H2 gating scenarios are about the ADMISSION path
# (authenticate/verify/admit/route/meter/audit/exit), not about the card-trust axis itself, so the
# key only needs to be real, not operator-provisioned out of band.
set -uo pipefail
H2_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H2_REPO="$(cd "${H2_HERE}/../.." && pwd)"
# shellcheck source=../../testing/fleet-fixtures/lib.sh
source "${H2_REPO}/testing/fleet-fixtures/lib.sh"

H2_BIN="${A2A_SUBJECT_BUSBAR_BIN:-${H2_REPO}/target/release/busbar}"
[ -x "$H2_BIN" ] || { echo "H2: no busbar binary at $H2_BIN (build with: cargo build --release -p busbar)" >&2; exit 2; }

h2_free_ports() {
  python3 - <<'PY'
import socket
socks = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(3)]
ports = []
for s in socks:
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
for s in socks:
    s.close()
print(" ".join(str(p) for p in ports))
PY
}

# h2_boot <workdir> <group-yaml-block>
# Boots busbar with one registered A2A agent "probe" (scripts/a2a-subject/h2-mock-agent.py,
# `pin: unpinned`), and the group(s) named in <group-yaml-block>.
# Sets: H2_DATA_PORT H2_ADMIN_PORT H2_AGENT_PORT H2_PLANE_URL H2_ADMIN_TOKEN H2_SIGNING_KEY
#       H2_AGENT_PID H2_BUSBAR_PID H2_EGRESS_DIR H2_WORKDIR H2_CONTROL_FILE
h2_boot() {
  local dir="$1" groups_yaml="$2"
  mkdir -p "$dir"
  dir="$(cd "$dir" && pwd)"
  H2_WORKDIR="$dir"
  H2_EGRESS_DIR="$dir/egress"
  H2_CONTROL_FILE="$dir/agent.control"
  mkdir -p "$H2_EGRESS_DIR"
  : >"$H2_CONTROL_FILE"

  read -r H2_DATA_PORT H2_ADMIN_PORT H2_AGENT_PORT <<<"$(h2_free_ports)"
  H2_PLANE_URL="http://127.0.0.1:${H2_DATA_PORT}/a2a/agents/probe"
  H2_SIGNING_KEY="$dir/signing.key"
  H2_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"

  local issuer_key_file="$dir/issuer.spki"
  A2A_MOCK_CAPTURE_DIR="$H2_EGRESS_DIR" node "${H2_HERE}/h2-mock-agent.mjs" "$H2_AGENT_PORT" "$H2_CONTROL_FILE" "$issuer_key_file" \
    >"$dir/agent.log" 2>&1 &
  H2_AGENT_PID=$!
  track_pid "$H2_AGENT_PID"
  wait_for_http "http://127.0.0.1:${H2_AGENT_PORT}/.well-known/agent-card.json" 10 || true
  local waited_key=0
  until [ -s "$issuer_key_file" ]; do
    waited_key=$((waited_key+1))
    [ "$waited_key" -lt 50 ] || { cat "$dir/agent.log" >&2; return 1; }
    sleep 0.1
  done
  H2_ISSUER_KEY="$(cat "$issuer_key_file")"

  ( umask 077; "$H2_BIN" --generate-signing-key >"$H2_SIGNING_KEY" 2>"$dir/genkey.log" ) \
    || { cat "$dir/genkey.log" >&2; return 1; }

  cat >"$dir/providers.yaml" <<'YAML'
{}
YAML
  cat >"$dir/config.yaml" <<YAML
listen: "127.0.0.1:${H2_DATA_PORT}"
admin_listen: "127.0.0.1:${H2_ADMIN_PORT}"
public_url: "http://127.0.0.1:${H2_DATA_PORT}"
providers: {}
models: {}
pools: {}
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { file: ${H2_SIGNING_KEY} }
per_request_fee: 1
${groups_yaml}
agents:
  probe:
    url: "http://127.0.0.1:${H2_AGENT_PORT}/"
    allow_private: true
    pin: { mechanism: jws_issuer_key, key: "${H2_ISSUER_KEY}" }
YAML

  BUSBAR_CONFIG="$dir/config.yaml" BUSBAR_ADMIN_TOKEN="$H2_ADMIN_TOKEN" RUST_LOG=warn \
    nohup "$H2_BIN" >"$dir/busbar.log" 2>&1 &
  H2_BUSBAR_PID=$!
  track_pid "$H2_BUSBAR_PID"

  local waited=0
  until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:${H2_DATA_PORT}/.well-known/agent-card.json")" != "000" ]; do
    kill -0 "$H2_BUSBAR_PID" 2>/dev/null || { cat "$dir/busbar.log" >&2; return 1; }
    waited=$((waited+1))
    [ "$waited" -lt 60 ] || { cat "$dir/busbar.log" >&2; return 1; }
    sleep 1
  done

  local preview fingerprint approved state
  preview="$(curl -s --max-time 30 -X POST "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/agents/probe/connect" \
    -H "authorization: Bearer $H2_ADMIN_TOKEN")"
  fingerprint="$(python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("fingerprint") or "")
except Exception:
    print("")' <<<"$preview")"
  [ -n "$fingerprint" ] || { echo "H2: connect reported no fingerprint for 'probe': $preview" >&2; return 1; }
  approved="$(curl -s --max-time 30 -X POST "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/agents/probe/approve" \
    -H "authorization: Bearer $H2_ADMIN_TOKEN" -H 'content-type: application/json' \
    -d "{\"fingerprint\":\"$fingerprint\"}")"
  state="$(python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("state") or "")
except Exception:
    print("")' <<<"$approved")"
  [ "$state" = "approved" ] || { echo "H2: approve left 'probe' in state '$state': $approved" >&2; return 1; }
  return 0
}

h2_stop() {
  kill "$H2_BUSBAR_PID" 2>/dev/null || true
  kill "$H2_AGENT_PID" 2>/dev/null || true
  wait "$H2_BUSBAR_PID" 2>/dev/null || true
  wait "$H2_AGENT_PID" 2>/dev/null || true
}

h2_mint() {
  local group="$1" extra="${2:-}" body
  if [ -n "$group" ]; then
    body="{\"name\":\"h2-key\",\"group\":\"$group\"${extra:+,${extra}}}"
  else
    body="{\"name\":\"h2-key\"${extra:+,${extra}}}"
  fi
  local resp
  resp="$(curl -sS -m 10 -X POST "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/keys" \
            -H "Authorization: Bearer $H2_ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$body")"
  local kid tok
  kid="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or "")' <<<"$resp")"
  tok="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("token") or "")' <<<"$resp")"
  printf '%s %s\n' "$kid" "$tok"
}

h2_bind() {
  node "${H2_REPO}/scripts/mcp-subject/mint-audience-token.mjs" "$H2_SIGNING_KEY" "$1" "http://127.0.0.1:${H2_DATA_PORT}/a2a"
}

# h2_call <bound-token> <text> -> prints "<status> <body>"
h2_call() {
  local tok="$1" text="$2" out status
  out="${H2_WORKDIR}/call.$$.$RANDOM"
  status="$(curl -sS -m 20 -o "$out" -w '%{http_code}' -X POST "$H2_PLANE_URL" \
    -H "authorization: Bearer $tok" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"message/send\",\"params\":{\"message\":{\"role\":\"user\",\"parts\":[{\"text\":\"$text\"}]}}}")"
  printf '%s %s\n' "$status" "$(tr -d '\n' <"$out")"
  rm -f "$out"
}

h2_usage() {
  local kid="$1"
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/keys/${kid}/usage"
}

h2_egress_count() { find "$H2_EGRESS_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }

h2_audit_max_seq() {
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/audit?limit=1" \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
items=d.get("items") or []
print(items[0]["seq"] if items else 0)'
}

h2_audit_rows_since() {
  local since="$1" action="$2" resource="$3"
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/audit?limit=50" \
    | python3 -c "import json,sys
d=json.load(sys.stdin)
since=$since
action=\"$action\"
resource=\"$resource\"
items=d.get('items') or []
print(sum(1 for r in items if r.get('seq',0) > since and r.get('action')==action and r.get('resource')==resource))"
}

h2_verdict() {
  local outcome="$1" detail="$2"
  printf '%s\t%s\n' "$outcome" "$detail"
  [ "$outcome" = PASS ]
}
