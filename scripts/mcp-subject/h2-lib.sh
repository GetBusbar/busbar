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

# THE BILLING SWITCH (DECISION #42), and it is a PRESENCE, not a flag: `rate_card:` present ⇒ the
# deployment is BILLED; `rate_card:` absent ⇒ it is not billed at all. The difference is not
# cosmetic on this plane: `crates/busbar-kernel/src/plane_host/govern.rs:226` gates the whole
# metering write on `state.app.cost.pricing_enabled()`, which is `rate_card.is_some()`
# (`crates/busbar-kernel/src/cost.rs:649`), so the rigs' previous `per_request_fee: 1` with NO
# `rate_card:` key booted a node that wrote NO metering row for a served `tools/call` at all — it
# could only ever assert the flat fee (#44) off the admission counter, and a priced meter class was
# unreachable by construction.
#
# IT IS EMPTY, AND THE EMPTINESS IS THE HONEST SHAPE — not a stub left unfilled. The config grammar
# in this tree keys `rate_card:` by CONFIG MODEL NAME and validates every key against `models:`
# (`crates/busbar-kernel/src/config_validate/mod.rs:1465-1472`), and an entry's only members are the
# four LLM token tiers (`RateEntryCfg`, `crates/busbar-kernel/src/config/sections.rs:324`,
# `deny_unknown_fields`). This plane declares `tool_calls` and `bytes`
# (`crates/busbar-plane-mcp/src/meta.rs:33-52`); neither is a `models:` key and neither is one of the
# four tiers, so THERE IS NO CONFIGURATION THAT PRICES EITHER DECLARED CLASS. An empty map is
# therefore the most a billing-ON mcp deployment can say today, and `h2-class-price.sh` is the leg
# that says what that costs.
H2_RATE_CARD_DEFAULT='rate_card: {}'

H2_BIN="${MCP_SUBJECT_BUSBAR_BIN:-${H2_REPO}/target/release/busbar}"
# `--selftest` (bottom of this file) drives no busbar at all, so it is the one run that needs no binary.
[ -x "$H2_BIN" ] || [ "${BASH_SOURCE[0]}:${1:-}" = "$0:--selftest" ] || { echo "H2: no busbar binary at $H2_BIN (build with: cargo build --release -p busbar)" >&2; exit 2; }

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
${H2_RATE_CARD_YAML:-$H2_RATE_CARD_DEFAULT}
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

  h2_approve_server
}

# THE OPERATOR'S APPROVAL CEREMONY — connect re-contacts the registered server, re-pins it and
# records the approval. Factored out of `h2_boot` because it is needed TWICE by any leg that applies
# live config: `PUT /api/v1/admin/config/settings` rebuilds the App, and a rebuilt App's registry
# starts unapproved again. Re-running the ceremony is what an operator does after a config change,
# so a leg that re-approves is driving the real path rather than working around it.
h2_approve_server() {
  local view
  view="$(curl -s --max-time 30 -X POST "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/tools/probe/connect" \
            -H "authorization: Bearer $H2_ADMIN_TOKEN")"
  case "$view" in
    *'"state":"approved"'*) ;;
    *) echo "H2: the connect of 'probe' did not land approved: $view" >&2; return 1 ;;
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

# ── THE MONEY READERS (added with the rate-card switch; see H2_RATE_CARD_DEFAULT above) ──────────

# One scalar off `GET /api/v1/admin/keys/<kid>/usage`: `requests`, `spend_cents` or `tokens`.
# THIS IS THE BUDGET CELL, not the metering series — `GovState::derived_bucket_usage`
# (crates/busbar-kernel/src/governance/state.rs:1581) reads the cell `try_admit` bumped, and derives
# `spend_cents` as `Σ counts × current rates + per_request_fee × billable_requests`. It survives a
# live config swap, which the write-behind metering buffer does not, so every leg that spans an
# apply reads its money HERE.
h2_usage_field() {
  local kid="$1" field="$2"
  h2_usage "$kid" | python3 -c "import json,sys; print(json.load(sys.stdin).get('$field') or 0)"
}

# One field of the `by_model` row `GET /api/v1/admin/usage` carries for (model, provider), or `-`
# when this node has metered no such row.
#
# THIS IS THE ONLY ADMIN SURFACE A NON-LLM PLANE'S METERED TRAFFIC APPEARS ON AT ALL, and it appears
# only when billing is ON: `plane_host/govern.rs:226` gates `record_metering` on
# `cost.pricing_enabled()` (`rate_card.is_some()`, cost.rs:649). With the rigs' previous no-card
# config this row did not exist — measured, `by_model: []` — which is why asserting it is a real
# assertion and not a restatement of the flat fee.
h2_meter_row_field() {
  local model="$1" provider="$2" field="$3"
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/usage" \
    | python3 -c "import json,sys
d=json.load(sys.stdin)
rows=[r for r in (d.get('by_model') or []) if r.get('model')=='$model' and r.get('provider')=='$provider']
print(rows[0].get('$field') if rows else '-')"
}

# The SUM of every quantity column `GET /api/v1/admin/usage` exposes for (model, provider) — the
# whole of what this node can say a plane's traffic measured, excluding the request COUNT (a request
# is not a quantity; #44's flat fee is the dimension that prices it). Used by the class-price leg to
# ask the one question that needs no rate card to be answerable: did the plane report a number for
# what it moved, at all?
h2_meter_row_quantity() {
  local model="$1" provider="$2"
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/usage" \
    | python3 -c "import json,sys
d=json.load(sys.stdin)
rows=[r for r in (d.get('by_model') or []) if r.get('model')=='$model' and r.get('provider')=='$provider']
if not rows:
    print('-')
else:
    r=rows[0]
    print(sum(int(r.get(k) or 0) for k in ('tokens_input','tokens_output','tokens_cache_read','tokens_cache_creation')))"
}

# One scalar off `GET /api/v1/admin/usage`'s `total` block — the OTHER admin money read, and since
# `root/kernel.rs:497` it is the only one that resolves through the dated rate-card history
# (`install_usage_rate_history`). `GET /keys/<id>/usage` does NOT: `busbar-core-admin/src/keys.rs`
# names `rate_history` nowhere and still derives through `CostModel::derive_spend_cents` against the
# CURRENT card. So after a card change the two reads answer different money for the same window, and
# `h2-card-epoch.sh` prints both rather than picking one — a disagreement between two readings of one
# ledger is a defect in one of them, not a threshold to tune.
h2_admin_usage_total() {
  local field="$1"
  curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
    "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/usage" \
    | python3 -c "import json,sys
d=json.load(sys.stdin)
print((d.get('total') or {}).get('$field', '-'))"
}

# APPEND A DATED RATE CARD (#79) by applying live config. `RootHistory::apply`
# (crates/busbar/src/root/kernel.rs:249-278) dates the entry at the instant the apply lands: the
# FIRST card a node resolves is effective from 0 (`HistorySeq::OPENING`) and every later one from
# `now_ms`, and neither closes the one before it. `rate_card: {}` rides along on purpose — the PUT
# merges whole sections and dropping the key would leave billing on but the intent unreadable.
# `per_request_fee` is the ONE pricing dimension of this card that both planes can actually move
# (#44: a flat fee is a plane-agnostic rate-card dimension), which is what makes a dated-card
# question askable on a plane whose declared classes no card can name.
h2_put_fee() {
  local cents="$1"
  curl -sS -m 15 -X PUT "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/config/settings" \
    -H "Authorization: Bearer $H2_ADMIN_TOKEN" -H 'content-type: application/json' \
    -d "{\"per_request_fee\":${cents},\"rate_card\":{}}"
}

# `--validate` THIS boot's own config with its `rate_card:` line replaced by <card-yaml>, and print
# `ok` or the validator's first error line. Runs the exact load → resolve → validate boot runs
# (crates/busbar/src/main.rs:262), so "would this deployment boot?" is answered by the binary rather
# than by a script's opinion of the grammar.
h2_validate_card() {
  local card_yaml="$1" out
  out="${H2_WORKDIR}/validate-card.$$.yaml"
  # The substitution is CHECKED, not assumed: a boot that overrode `H2_RATE_CARD_YAML` has no
  # `rate_card: {}` line to replace, and a silent no-op here would validate the UNCHANGED config and
  # report `ok` — a false green on the one question this helper exists to ask.
  if ! CARD="$card_yaml" python3 -c "import os,sys
src=open(sys.argv[1]).read()
needle='rate_card: {}'
if needle not in src:
    sys.exit(3)
sys.stdout.write(src.replace(needle, os.environ['CARD']))" "${H2_WORKDIR}/config.yaml" >"$out"; then
    rm -f "$out"
    printf 'harness: this boot wrote no `rate_card: {}` line to substitute\n'
    return
  fi
  local res rc
  res="$(BUSBAR_CONFIG="$out" BUSBAR_ADMIN_TOKEN="$H2_ADMIN_TOKEN" "$H2_BIN" --validate 2>&1)"
  rc=$?
  rm -f "$out"
  # THE EXIT CODE IS THE ANSWER, AND A SUBSTRING MATCH IS NOT. `--validate`'s refusal banner reads
  # "config validation failed", which CONTAINS "config valid" — so the obvious `*"config valid"*`
  # case arm reports a REFUSED config as `ok`, a false green on the one question this helper exists
  # to ask. (Found by running the helper against a stub that printed the binary's real two shapes.)
  # The text is still required to carry the success line, so a future `--validate` that exits 0 while
  # printing a refusal cannot slip through either.
  if [ "$rc" -eq 0 ] && case "$res" in "ok: config valid"*) true ;; *) false ;; esac; then
    printf 'ok\n'
    return
  fi
  # The validator prints its reasons as `  - <reason>` bullets under a BUSBAR-3015 header; take the
  # first, else the last non-empty line so a shape this does not know still says something.
  local why
  why="$(printf '%s' "$res" | sed -n 's/^ *- *//p' | head -1)"
  [ -n "$why" ] || why="$(printf '%s' "$res" | grep -v '^$' | tail -1)"
  printf 'rc=%s %s\n' "$rc" "$(printf '%s' "$why" | tr -d '\n')"
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

# h2_int_is <value> <test-op> <n> -- true ONLY when <value> is a base-10 integer AND `[ value op n ]`
# holds. A money assertion asks its question through this, negated (`if ! h2_int_is "$x" -eq 8`),
# because the bare `if [ "$x" -ne 8 ]` FAILS OPEN on a read that came back empty or non-numeric: `[`
# exits 2, the `if` takes its false arm and the leg records no failure. Here a non-integer read is
# simply "not equal", so it fails closed. Pinned by `--selftest`.
h2_int_is() {
  [[ "${1:-}" =~ ^-?[0-9]+$ ]] || return 1
  [ "$1" "$2" "$3" ]
}

# Emit a PASS/FAIL verdict line and EXIT the rig: 0 on PASS, 1 on FAIL or on any other outcome word
# (a verdict nobody can read is not a pass). It exits rather than returns so a rig that writes
# `h2_verdict FAIL "..."` followed by anything else -- a cleanup line, a second check -- still ends
# red; a `return` made every call site's exit status depend on the verdict being the script's last
# command. The EXIT trap each rig sets (`h2_stop`) still runs. Pinned by `--selftest` (verdict-exits).
h2_verdict() {
  local outcome="$1" detail="$2"
  printf '%s\t%s\n' "$outcome" "$detail"
  [ "$outcome" = PASS ] && exit 0
  exit 1
}

# ── --selftest ────────────────────────────────────────────────────────────────────────────────────
# `./scripts/mcp-subject/h2-lib.sh --selftest [case]` -- no busbar, no node, no network. Each rig case
# copies the REAL rig script into a scratch dir beside a STUB h2-lib.sh (this file's own h2_verdict
# and h2_int_is, plus canned answers for every reader the rig calls) and runs it, so what is judged is
# the rig's own decision logic against a read it was never written for. Every case carries a control
# the rig must PASS, so a stub that broke the rig outright cannot pass for a red.
_h2_st_stub() {
  local dir="$1"
  {
    echo 'set -uo pipefail'
    declare -f h2_verdict h2_int_is 2>/dev/null
    cat <<'STUB'
_st_next() { local f="$H2_ST_DIR/n.$1" n v; n="$(cat "$f" 2>/dev/null || echo 0)"; echo $((n+1)) >"$f"; IFS='|' read -r -a v <<<"$2"; printf '%s\n' "${v[$n]:-}"; }
h2_boot() { return 0; }
h2_stop() { :; }
h2_approve_server() { return 0; }
h2_mint() { echo "kid-selftest tok-selftest"; }
h2_bind() { echo "bound-selftest"; }
h2_call() { if [ -n "${H2_RATE_CARD_YAML+x}" ]; then echo "200 {}"; else echo "${H2_ST_CALL:-200} {}"; fi; }
h2_usage_field() { _st_next usage "${H2_ST_USAGE:-1}"; }
h2_put_fee() { echo '{"applied":true}'; }
h2_admin_usage_total() { echo 80000; }
h2_meter_row_field() { case "$3" in requests) echo 1 ;; *) echo 10000 ;; esac; }
h2_meter_row_quantity() { printf '%s\n' "${H2_ST_QTY-3}"; }
h2_validate_card() { echo ok; }
sleep() { :; }
STUB
  } >"${dir}/h2-lib.sh"
}

# _h2_st_rig <script> [VAR=value ...] -> prints the rig's exit status
_h2_st_rig() {
  local script="$1" d
  shift
  d="$(mktemp -d "${_H2_ST_TMP}/case.XXXXXX")"
  cp "${H2_HERE}/${script}" "${d}/"
  _h2_st_stub "$d"
  env -u H2_RATE_CARD_YAML H2_ST_DIR="$d" H2_WORK="${d}/work" "$@" bash "${d}/${script}" >"${d}/out" 2>&1
  echo "$?"
}

# _h2_st_want <label> <0|red> <got>
_h2_st_want() {
  local label="$1" want="$2" got="$3" ok=1
  _H2_ST_RAN=$((_H2_ST_RAN+1))
  case "$want" in
    0) [ "$got" = "0" ] || ok=0 ;;
    red) [ "$got" != "0" ] || ok=0 ;;
  esac
  if [ "$ok" = 1 ]; then
    printf 'ok\t%s\n' "$label"
  else
    printf 'FAIL\t%s (want %s, got exit %s)\n' "$label" "$want" "$got"
    _H2_ST_FAILED=$((_H2_ST_FAILED+1))
  fi
}

_h2_st_case_verdict_exits() {
  local out st
  out="$( (h2_verdict FAIL "selftest" >/dev/null; echo REACHED) )"; st=$?
  _h2_st_want "verdict-exits: FAIL ends the rig red" red "$st"
  _h2_st_want "verdict-exits: nothing after a FAIL verdict runs" 0 "$([ -z "$out" ]; echo $?)"
  out="$( (h2_verdict PASS "selftest" >/dev/null; echo REACHED; exit 7) )"; st=$?
  _h2_st_want "verdict-exits: PASS ends the rig green" 0 "$st"
  _h2_st_want "verdict-exits: nothing after a PASS verdict runs" 0 "$([ -z "$out" ]; echo $?)"
  ( h2_verdict MAYBE "selftest" >/dev/null ); st=$?
  _h2_st_want "verdict-exits: an unknown outcome word is red" red "$st"
}

_h2_st_case_card_epoch() {
  _h2_st_want "card-epoch: control 1, 1, 8 passes" 0 "$(_h2_st_rig h2-card-epoch.sh H2_ST_USAGE='1|1|8')"
  _h2_st_want "card-epoch: total 14 (newest-card reprice) is red" red "$(_h2_st_rig h2-card-epoch.sh H2_ST_USAGE='1|1|14')"
  _h2_st_want "card-epoch: an EMPTY total read is red, not a pass" red "$(_h2_st_rig h2-card-epoch.sh H2_ST_USAGE='1|1|')"
  _h2_st_want "card-epoch: a non-numeric total read is red, not a pass" red "$(_h2_st_rig h2-card-epoch.sh H2_ST_USAGE='1|1|8.0')"
}

_h2_st_case_class_price() {
  _h2_st_want "class-price: control quantity 3 passes" 0 "$(_h2_st_rig h2-class-price.sh H2_ST_QTY=3)"
  _h2_st_want "class-price: no metering row (-) is red" red "$(_h2_st_rig h2-class-price.sh H2_ST_QTY=-)"
  _h2_st_want "class-price: quantity 0 is red" red "$(_h2_st_rig h2-class-price.sh H2_ST_QTY=0)"
  _h2_st_want "class-price: an EMPTY quantity read is red, not a pass" red "$(_h2_st_rig h2-class-price.sh H2_ST_QTY=)"
  _h2_st_want "class-price: a non-numeric quantity read is red, not a pass" red "$(_h2_st_rig h2-class-price.sh H2_ST_QTY=None)"
}

h2_selftest() {
  local only="${1:-}" c
  _H2_ST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/h2-selftest.XXXXXX")" || return 1
  _H2_ST_RAN=0
  _H2_ST_FAILED=0
  for c in verdict_exits card_epoch class_price; do
    [ -z "$only" ] || [ "$only" = "$c" ] || continue
    "_h2_st_case_${c}"
  done
  rm -rf "$_H2_ST_TMP"
  if [ "$_H2_ST_RAN" -eq 0 ]; then
    printf 'FAIL\tno selftest case named %s\n' "$only"
    return 1
  fi
  printf '%s\th2-lib selftest: %s checks, %s failed\n' \
    "$([ "$_H2_ST_FAILED" -eq 0 ] && echo PASS || echo FAIL)" "$_H2_ST_RAN" "$_H2_ST_FAILED"
  [ "$_H2_ST_FAILED" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --selftest) h2_selftest "${2:-}"; exit $? ;;
    *) echo "usage: $0 --selftest [case]  (this file is otherwise sourced by scripts/mcp-subject/h2-*.sh)" >&2; exit 2 ;;
  esac
fi
