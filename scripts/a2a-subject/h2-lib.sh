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

# THE BILLING SWITCH (DECISION #42), and it is a PRESENCE, not a flag: `rate_card:` present ⇒ the
# deployment is BILLED; `rate_card:` absent ⇒ it is not billed at all — a cost request reads 0, no
# metering row is written, nothing is afforded-gated. The rigs used to write `per_request_fee: 1`
# and NO `rate_card:` key, so every one of them booted a BILLING-OFF node and could only ever assert
# the flat fee (#44); a priced meter class was unreachable by construction. This default makes the
# rigs' subject a BILLING-ON deployment, which is the only kind in which "price = Σ count × rate"
# (#71), "the card in force at `arrived_ms`" (#79) and "a hit class with no entry REFUSES" (#42) are
# even questions that can be asked.
#
# IT IS EMPTY, AND THE EMPTINESS IS THE HONEST SHAPE — not a stub left unfilled. The config grammar
# in this tree keys `rate_card:` by CONFIG MODEL NAME and validates every key against `models:`
# (`crates/busbar-kernel/src/config_validate/mod.rs:1465-1472`: "rate_card names model 'X', which is
# not defined under models:"), and each entry's only members are the four LLM token tiers
# (`RateEntryCfg`, `crates/busbar-kernel/src/config/sections.rs:324`, `deny_unknown_fields`). An a2a
# lane is `agent:<id>` and an a2a meter class is `bytes`; neither is a `models:` key and neither is
# one of the four tiers, so THERE IS NO CONFIGURATION THAT PRICES THIS PLANE'S DECLARED CLASS. An
# empty map is therefore the most a billing-ON a2a deployment can say today, and `h2-class-price.sh`
# is the leg that says what that costs.
H2_RATE_CARD_DEFAULT='rate_card: {}'

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
${H2_RATE_CARD_YAML:-$H2_RATE_CARD_DEFAULT}
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

  h2_approve_agent
}

# THE OPERATOR'S APPROVAL CEREMONY — connect (re-contact + re-pin) then approve the fingerprint it
# reports. Factored out of `h2_boot` because it is needed TWICE by any leg that applies live config:
# `PUT /api/v1/admin/config/settings` rebuilds the App, and a rebuilt App's agent registry starts at
# `Pending` again (measured: the next call answers 503 "fronted agent `probe` is not serving
# (Pending)"). Re-running the ceremony is what an operator does after a config change, so a leg that
# re-approves is driving the real path rather than working around it.
h2_approve_agent() {
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

# h2_call <bound-token> <text> [<header-dump-file>] -> prints "<status> <body>". With a third
# argument the response headers are written to that file (curl -D), for a leg that asserts on them.
h2_call() {
  local tok="$1" text="$2" hdr="${3:-/dev/null}" out status
  out="${H2_WORKDIR}/call.$$.$RANDOM"
  status="$(curl -sS -m 20 -D "$hdr" -o "$out" -w '%{http_code}' -X POST "$H2_PLANE_URL" \
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
# The POSTs the fixture agent received -- the dispatched calls, NOT the agent-card GETs busbar makes
# at boot, which h2_egress_count also counts (captureEgress runs before the card branch).
h2_egress_post_count() {
  find "$H2_EGRESS_DIR" -type f -name '*.json' -exec grep -l '"method":"POST"' {} + 2>/dev/null \
    | wc -l | tr -d ' '
}

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
