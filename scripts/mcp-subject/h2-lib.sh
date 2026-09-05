#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Shared boot/mint/call helpers for the H2 MCP gating scenarios (scripts/mcp-subject/h2-*.sh),
# tracker row H2 (docs/design/ARCHITECTURE.md #2.2). Each h2-*.sh script sources this, boots its OWN
# throwaway busbar + its own instance of h2-mock-upstream.mjs on its own ports (the same isolation
# testing/shadow-oracle/scripts/teller-*.sh use for the llm plane), and asserts one Teller step.
#
# Why a fresh boot per scenario rather than one shared boot for all six: budget/audit/usage state is
# cumulative, and a scenario that shares a boot with another cannot prove a CLEAN before/after delta
# without also proving the other scenario ran first in some order. Isolation costs a few seconds of
# boot time and buys scenarios that are readable and reorderable independently.
#
# The virtual-key scope grammar this file exercises (`allowed_pools`, C6 semantics) is core's own —
# see busbar-api's `VirtualKey::scope_allowed`: an OMITTED list grants every scope kind, an explicit
# EMPTY list grants none of them (cross-kind, not per-kind), which is what h2-verify-refusal.sh uses
# to mint a key with no mcp_server/mcp_tool entitlement at all, through the admin API exactly as an
# operator would.
set -uo pipefail
H2_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
H2_REPO="$(cd "${H2_HERE}/../.." && pwd)"
# shellcheck source=../../testing/fleet-fixtures/lib.sh
source "${H2_REPO}/testing/fleet-fixtures/lib.sh"

H2_BIN="${MCP_SUBJECT_BUSBAR_BIN:-${H2_REPO}/target/release/busbar}"
[ -x "$H2_BIN" ] || { echo "H2: no busbar binary at $H2_BIN (build with: cargo build --release -p busbar)" >&2; exit 2; }

# Three free loopback ports: data, admin, upstream.
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
# Boots busbar with one registered MCP server "probe", one tool "ping", `per_request_fee: 1` (so a
# served call posts a real, non-zero priced figure -- see h2-meter-row.sh), and the group(s) named
# in <group-yaml-block> (indented under `groups:`, caller's responsibility to indent correctly).
# Sets: H2_DATA_PORT H2_ADMIN_PORT H2_UPSTREAM_PORT H2_CANON H2_ADMIN_TOKEN H2_SIGNING_KEY
#       H2_UPSTREAM_PID H2_BUSBAR_PID H2_EGRESS_DIR H2_WORKDIR
h2_boot() {
  local dir="$1" groups_yaml="$2"
  mkdir -p "$dir"
  dir="$(cd "$dir" && pwd)"
  H2_WORKDIR="$dir"
  H2_EGRESS_DIR="$dir/egress"
  mkdir -p "$H2_EGRESS_DIR"

  read -r H2_DATA_PORT H2_ADMIN_PORT H2_UPSTREAM_PORT <<<"$(h2_free_ports)"
  H2_CANON="http://127.0.0.1:${H2_DATA_PORT}/mcp"
  H2_SIGNING_KEY="$dir/signing.key"
  H2_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"

  MCP_MOCK_CAPTURE_DIR="$H2_EGRESS_DIR" node "${H2_HERE}/h2-mock-upstream.mjs" "$H2_UPSTREAM_PORT" \
    >"$dir/upstream.log" 2>&1 &
  H2_UPSTREAM_PID=$!
  track_pid "$H2_UPSTREAM_PID"
  wait_for_http "http://127.0.0.1:${H2_UPSTREAM_PORT}/" 10 || true

  ( umask 077; "$H2_BIN" --generate-signing-key >"$H2_SIGNING_KEY" 2>"$dir/genkey.log" ) \
    || { cat "$dir/genkey.log" >&2; return 1; }

  local digest
  digest="$(node "${H2_HERE}/tool-digest.mjs" "http://127.0.0.1:${H2_UPSTREAM_PORT}/mcp" | awk '{print $2}')"
  [ -n "$digest" ] || { echo "H2: could not digest the h2 mock upstream's served tools" >&2; return 1; }

  cat >"$dir/providers.yaml" <<'YAML'
{}
YAML
  cat >"$dir/config.yaml" <<YAML
listen: "127.0.0.1:${H2_DATA_PORT}"
admin_listen: "127.0.0.1:${H2_ADMIN_PORT}"
providers: {}
models: {}
pools: {}
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { file: ${H2_SIGNING_KEY} }
mcp:
  canonical_uri: "${H2_CANON}"
  authorization_servers:
    - "http://127.0.0.1:${H2_ADMIN_PORT}"
  scopes_supported: ["mcp:tools:list", "mcp:tools:call"]
per_request_fee: 1
${groups_yaml}
tools:
  probe:
    url: "http://127.0.0.1:${H2_UPSTREAM_PORT}/mcp"
    allow_private: true
    pin:
      mechanism: pinned_pubkey
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      ping:
        schema_hash: "${digest}"
        description: "Returns the label it was given."
YAML

  BUSBAR_CONFIG="$dir/config.yaml" BUSBAR_ADMIN_TOKEN="$H2_ADMIN_TOKEN" RUST_LOG=warn \
    nohup "$H2_BIN" >"$dir/busbar.log" 2>&1 &
  H2_BUSBAR_PID=$!
  track_pid "$H2_BUSBAR_PID"

  local waited=0
  until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 -X POST "$H2_CANON" \
              -H 'content-type: application/json' -H 'mcp-method: tools/list' \
              -H 'mcp-protocol-version: 2026-07-28' \
              -d '{"jsonrpc":"2.0","id":0,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}')" != "000" ]; do
    kill -0 "$H2_BUSBAR_PID" 2>/dev/null || { cat "$dir/busbar.log" >&2; return 1; }
    waited=$((waited+1))
    [ "$waited" -lt 60 ] || { cat "$dir/busbar.log" >&2; return 1; }
    sleep 1
  done

  local view
  view="$(curl -s --max-time 30 -X POST "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/tools/probe/connect" \
            -H "authorization: Bearer $H2_ADMIN_TOKEN")"
  case "$view" in
    *'"state":"approved"'*) ;;
    *) echo "H2: the boot-time connect of 'probe' did not land approved: $view" >&2; return 1 ;;
  esac
  return 0
}

h2_stop() {
  kill "$H2_BUSBAR_PID" 2>/dev/null || true
  kill "$H2_UPSTREAM_PID" 2>/dev/null || true
  wait "$H2_BUSBAR_PID" 2>/dev/null || true
  wait "$H2_UPSTREAM_PID" 2>/dev/null || true
}

# h2_mint <group-or-empty> <extra-json-fields-or-empty> -> prints "id token" on one line
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

# h2_bind <plain-token> -> prints an audience-bound bearer for H2_CANON
h2_bind() {
  node "${H2_HERE}/mint-audience-token.mjs" "$H2_SIGNING_KEY" "$1" "$H2_CANON"
}

# h2_call <bound-token> <label> -> prints "<status> <body>" (body on one line, JSON-compact)
h2_call() {
  local tok="$1" label="$2" out status
  out="${H2_WORKDIR}/call.$$.$RANDOM"
  status="$(curl -sS -m 20 -o "$out" -w '%{http_code}' -X POST "$H2_CANON" \
    -H "authorization: Bearer $tok" -H 'content-type: application/json' \
    -H 'mcp-method: tools/call' -H 'mcp-protocol-version: 2026-07-28' -H 'Mcp-Name: probe_ping' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"probe_ping\",\"arguments\":{\"label\":\"$label\"},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}")"
  printf '%s %s\n' "$status" "$(tr -d '\n' <"$out")"
  rm -f "$out"
}

h2_usage() {
  local kid="$1"
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/keys/${kid}/usage"
}

h2_egress_count() { find "$H2_EGRESS_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }

# h2_audit_max_seq -> the current top seq of the admin audit chain (0 if empty)
h2_audit_max_seq() {
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/audit?limit=1" \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
items=d.get("items") or []
print(items[0]["seq"] if items else 0)'
}

# h2_audit_rows_since <seq> <action> <resource> -> count of rows with seq > <seq> matching action+resource
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

# Emit a PASS/FAIL verdict line and exit accordingly.
h2_verdict() {
  local outcome="$1" detail="$2"
  printf '%s\t%s\n' "$outcome" "$detail"
  [ "$outcome" = PASS ]
}
