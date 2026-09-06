#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The shadow oracle's busbar CONFIGURATION + KEY MINTING — the setup half of record.sh / replay.sh,
# lifted out so the recorder and the replayer start busbar IDENTICALLY (the same config is the only
# way an old-vs-new byte-diff means anything). Sourced, not executed. Builds on fleet-fixtures/lib.sh.
#
#   oracle_write_config <work> <listen_port> <admin_port> <mock_port>
#       writes <work>/providers.yaml + <work>/config.yaml + <work>/signing.key
#         - six providers, one per LLM dialect, ALL pointing at the multi-dialect mock upstream, so a
#           request whose ingress dialect != the target model's provider dialect is a CROSS-PROTOCOL
#           cell (the LLM plane's defining feature) and the diagonal is the codec's own round trip;
#         - governance ON (keys auth chain), admin API on a token, prometheus export for /metrics;
#         - three budget groups: `oracle` (loose), `broke` (requests: 1/day + a 1-cent/day budget) and
#           `broke-quota` (a 1-cent/day budget ONLY, no requests cap) so after the recorder's one
#           PRIMING request the over-budget refusal is a REAL 429 at Admit — `broke` always blocks on
#           its `requests` cap first (governance::state checks requests before budget), so only
#           `broke-quota`'s bucket can ever surface the group's own BUDGET exhaustion (metric: budget).
#   oracle_mint_keys <admin_port>
#       mints the four principals every outcome class needs and exports:
#         ORACLE_TOKEN_OK / ORACLE_KEY_OK         normal key, group `oracle`
#         ORACLE_TOKEN_BROKE / ORACLE_KEY_BROKE   group `broke`        -> 429 over_budget (requests cap) at Admit
#         ORACLE_TOKEN_QUOTA / ORACLE_KEY_QUOTA   group `broke-quota`  -> 429 over_budget_total (budget cap) at Admit
#         ORACLE_TOKEN_NOSCOPE / ORACLE_KEY_NOSCOPE allowed_pools limited to a pool no cell uses -> 403
#
# The six model names are `m-<dialect>`; a cell targets `m-<egress_dialect>` so the LANE selects the
# egress codec while the request PATH selects the ingress codec.

# An ARRAY (not a space-separated string): this file is sourced under bash in CI and may be sourced
# under zsh on a laptop, and zsh does not word-split an unquoted scalar — the six dialects would
# collapse into one key. "${ORACLE_DIALECTS[@]}" iterates correctly in both.
ORACLE_DIALECTS=(anthropic openai-chat openai-responses gemini bedrock cohere)
ORACLE_ADMIN_TOKEN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"

# Oracle dialect name -> busbar `protocol:` value. The provider/model NAMES stay dialect-named (so a
# cell reads `m-openai-chat`), but busbar's protocol vocabulary — verified identical on 1.5.5 and
# 1.6.0 via selftest.sh — is: anthropic, openai, gemini, bedrock, responses, cohere.
oracle_protocol() {  # <dialect>
  case "$1" in
    openai-chat) echo openai ;;
    openai-responses) echo responses ;;
    *) echo "$1" ;;
  esac
}

oracle_write_config() {  # <work> <listen_port> <admin_port> <mock_port>
  # A fresh config means a fresh overlay: the runtime overlay file the previous variant's admin
  # writes left beside config.yaml (a hook registered under the hooks variant, say) must not leak
  # into the next boot, where the plugin dir it names is no longer configured.
  rm -f "${1}/busbar-overlay.json"
  local work="$1" listen="$2" admin="$3" mock="$4"
  # concurrency/queue/cooldown-family knobs. `queue_max_ms` is generous enough (well under the
  # default failover budget) for the "admit 1, queue N-1, serve them off the freed permit" cell;
  # the `queue-timeout` variant shrinks it so the SAME pool shape proves the bounded-wait-expires
  # arm instead (paired with the mock's `slow` control on that lane so the permit never frees in
  # time). `inbound_concurrent` stays empty (key omitted -> the real 8192 default) unless the
  # `inbound-concurrency-2` variant asks for the tiny cap the inbound-shed cell needs.
  local queue_max_ms=4000 inbound_concurrent=""
  case "${ORACLE_VARIANT:-}" in
    queue-timeout) queue_max_ms=50 ;;
    inbound-concurrency-2) inbound_concurrent=2 ;;
  esac
  : >"${work}/providers.yaml"
  local d
  for d in "${ORACLE_DIALECTS[@]}"; do
    cat >>"${work}/providers.yaml" <<EOF
${d}:
  protocol: $(oracle_protocol "$d")
  base_url: "http://127.0.0.1:${mock}"
EOF
  done
  "$BUSBAR_BIN" --generate-signing-key >"${work}/signing.key" 2>/dev/null
  [ -s "${work}/signing.key" ] || { echo "oracle: --generate-signing-key produced no key" >&2; return 1; }

  {
    cat <<EOF
listen: "127.0.0.1:${listen}"
admin_listen: "127.0.0.1:${admin}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain:
    - keys
  signing_key: { file: "${work}/signing.key" }
  admin_auth: [admin-tokens]
export:
  metrics: { module: prometheus, settings: { buffer_seconds: 60 } }
EOF
    if [ -n "$inbound_concurrent" ]; then
      cat <<EOF
limits:
  max_inbound_concurrent: ${inbound_concurrent}
EOF
    fi
    cat <<EOF
groups:
  oracle:
    limits:
      - { budget: 1000000, per: day }
  broke:
    limits:
      - { requests: 1, per: day }
      - { budget: 1, per: day }
  broke-quota:
    limits:
      - { budget: 1, per: day }
providers:
EOF
    for d in "${ORACLE_DIALECTS[@]}"; do
      echo "  ${d}:"
      echo "    api_key: { env: ORACLE_UPSTREAM_KEY }"
    done
    echo "models:"
    for d in "${ORACLE_DIALECTS[@]}"; do
      echo "  m-${d}:"
      echo "    provider: ${d}"
    done
    # Dedicated lanes for the concurrency/queue/cooldown families, isolated from the six dialect
    # lanes above so saturating one of these can never perturb an unrelated cell sharing a boot:
    #   m-lane-c1    max_concurrent: 1  -> oracle-lc1 (per-lane AtCapacity / on_exhausted 503 shape)
    #   m-queue-lane max_concurrent: 1  -> oracle-q   (on_exhausted: queue)
    #   m-cd-lane    unbounded          -> oracle-cd  (base_cooldown_secs 1: trip/settle/serve)
    cat <<'EOF'
  m-lane-c1:
    provider: openai-chat
    max_concurrent: 1
  m-queue-lane:
    provider: openai-chat
    max_concurrent: 1
  m-cd-lane:
    provider: openai-chat
EOF
    # A PRICED card so spend is real: input 0.1 / output 0.2 units per token -> the mock's fixed
    # 11 in / 7 out costs 2.5 units per call, so cents-truncation, fee and refund arithmetic are all
    # exercised on every cell (spend_cents 2, not 2.5; PB-16/22).
    echo "rate_card:"
    for d in "${ORACLE_DIALECTS[@]}"; do
      echo "  m-${d}: { input_utok: 100000, output_utok: 200000 }"
    done
    cat <<'EOF'
  m-lane-c1: { input_utok: 100000, output_utok: 200000 }
  m-queue-lane: { input_utok: 100000, output_utok: 200000 }
  m-cd-lane: { input_utok: 100000, output_utok: 200000 }
EOF
    # Pools:
    #   oracle-unused  no cell targets it: the NOSCOPE key is allowed ONLY this pool -> 403 at Approve
    #   oracle-fo      two members with a consecutive-1 breaker: a down member trips on the first 5xx
    #                  and the walk fails over (max_hops 3, deadline 120) — the route.failover family
    #   oracle-fb      one member, on_exhausted -> fallback_pool oracle-fo (the cross-pool hop, PB-4/47)
    #   oracle-lb      least_bad terminal
    #   oracle-lc1     one member, models.<m>.max_concurrent: 1 -> the concurrency family's
    #                  per-lane AtCapacity / on_exhausted 503 shape
    #   oracle-q       one member, models.<m>.max_concurrent: 1, on_exhausted: queue { max_ms } ->
    #                  the queue family (admit 1, queue+serve the rest, or time out the wait)
    #   oracle-cd      one member, base_cooldown_secs 1 -> the cooldown family (trip, settle, serve)
    if [ "${ORACLE_VARIANT:-}" = hooks ]; then
      # The PUBLISHED 1.5.5-era hook plugins (by digest) loaded through the binary under test, and
      # one gate instance of headroom attached to its own pool — the hooks / plugin admin surfaces.
      mkdir -p "${work}/plugins"
      local pl
      for pl in headroom-hook webrequest-hook; do
        cp "$(bash "$(dirname "${BASH_SOURCE[0]}")/fetch-plugin.sh" "$pl")" "${work}/plugins/" || return 1
      done
      cat <<EOF
plugins:
  enabled: true
  dir: "${work}/plugins"
hooks:
  busbar-headroom:
    module: busbar-headroom
    kind: gate
    prompt: rw
    timeout_ms: 50
    on_error: nothing
    settings:
      target_ratio: 0.5
      min_savings_pct: 10
EOF
    fi
    cat <<EOF
pools:
  oracle-unused:
    members:
      - model: m-openai-chat
EOF
    if [ "${ORACLE_VARIANT:-}" = hooks ]; then
      cat <<EOF
  oracle-hooked:
    hooks: [busbar-headroom]
    members:
      - model: m-openai-chat
EOF
    fi
    cat <<EOF
  oracle-fo:
    members:
      - { model: m-openai-chat, weight: 3 }
      - { model: m-anthropic, weight: 1 }
    breaker: { base_cooldown_secs: 15, max_cooldown_secs: 120, trip: { mode: consecutive, consecutive_n: 1 } }
    failover: { timeout_secs: 120, max_hops: 3 }
  oracle-fb:
    members:
      - { model: m-cohere }
    breaker: { trip: { mode: consecutive, consecutive_n: 1 } }
    on_exhausted: { fallback_pool: oracle-fo }
  oracle-lb:
    members:
      - { model: m-gemini }
    breaker: { trip: { mode: consecutive, consecutive_n: 1 } }
    on_exhausted: least_bad
  oracle-lc1:
    members:
      - { model: m-lane-c1 }
  oracle-q:
    members:
      - { model: m-queue-lane }
    on_exhausted: { queue: { max_ms: ${queue_max_ms} } }
  oracle-cd:
    members:
      - { model: m-cd-lane }
    breaker: { base_cooldown_secs: 1, max_cooldown_secs: 5, trip: { mode: consecutive, consecutive_n: 1 } }
EOF
  } >"${work}/config.yaml"
}

oracle_env() {  # run "$@" with the oracle's busbar environment
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" RUST_LOG="${RUST_LOG:-warn}" "$@"
}

# Spawn busbar in the background so that `$!` IS busbar's pid. `oracle_env "$BIN" &` backgrounds a
# SUBSHELL running the function; killing that subshell orphans busbar, which keeps its listen port,
# the next boot fails to bind, and every later cell is silently served by the OLD process (the
# isolation the recorder promises would be a lie). `exec` in the subshell makes the pid the binary's.
oracle_spawn() {  # <log-file> <bin> [args...]
  local log="$1"; shift
  ( exec env BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
      ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" RUST_LOG="${RUST_LOG:-warn}" "$@" ) >>"$log" 2>&1 &
  echo $!
}

_oracle_mint() {  # <admin_port> <json-body>  -> prints "id<US>token<US>akid<US>secret" (US = 0x1f)
  local out
  # -m: a mint that hangs is neither red nor green until the whole job times out, and every OTHER
  # call in this harness already carries a bound. Without it a wedged admin listener stalls the run.
  out="$(curl -fsS -m 10 -X POST "http://127.0.0.1:$1/api/v1/admin/keys" \
    -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" -H "Content-Type: application/json" \
    -d "$2" 2>/dev/null || true)"
  # UNIT-SEPARATOR-SEPARATED (0x1f), AND EMPTY FIELDS STAY EMPTY. The four values were joined with SPACES and split by
  # the callers with an unquoted `set -- $r`, which is word splitting: an empty id or token
  # contributes NO word, so every later field shifts left by one. A mint that answered without an
  # `id` therefore produced $1=<the token>, and a mint that answered with neither id nor token
  # produced $1="-" and $2="-" from the AWS placeholders — and `-` is a non-empty string, so the
  # `[ -n "$ORACLE_TOKEN_OK" ]` guard at the end of oracle_mint_keys passed. The recorder then ran a
  # whole plane sending `Authorization: Bearer -`, every request 401'd, and each of those 401s was
  # recorded as the cell's honest answer. The separator must not be IFS WHITESPACE:
  # `IFS=$'\t' read` still collapses runs of tabs and strips leading ones, because a tab IS
  # whitespace to `read` — that would have reproduced the very same bug, one delimiter later. 0x1f is
  # not whitespace, so `read` keeps every field, empty or not, in its own position; and it cannot
  # occur inside a key id or a bearer secret.
  printf '%s\037%s\037%s\037%s\n' "$(printf '%s' "$out" | jq -r '.id // empty')" "$(printf '%s' "$out" | jq -r '.token // empty')" \
    "$(printf '%s' "$out" | jq -r '.aws_access_key_id // "-"')" "$(printf '%s' "$out" | jq -r '.aws_secret_access_key // "-"')"
}

# A minted principal is either COMPLETE or the run stops. `-` is the AWS placeholder this file emits
# for a key minted without SigV4 credentials; it is never a valid id or bearer secret, and it is the
# exact value the old word-splitting bug served up. Rejected explicitly so the same shape can never
# be mistaken for a credential again, whatever produced it.
_oracle_take_mint() {  # <label> <0x1f-separated-row> -> sets _M_ID _M_TOKEN _M_AKID _M_SECRET
  local label="$1" row="$2"
  IFS=$'\037' read -r _M_ID _M_TOKEN _M_AKID _M_SECRET <<<"$row"
  _M_ID="${_M_ID:-}"; _M_TOKEN="${_M_TOKEN:-}"; _M_AKID="${_M_AKID:-}"; _M_SECRET="${_M_SECRET:-}"
  case "$_M_ID" in ""|"-") echo "oracle-config: minting '${label}' returned no key id (got '${_M_ID}')" >&2; return 1 ;; esac
  case "$_M_TOKEN" in ""|"-") echo "oracle-config: minting '${label}' returned no bearer token (got '${_M_TOKEN}')" >&2; return 1 ;; esac
  return 0
}

oracle_mint_keys() {  # <admin_port>
  # Every principal also carries an AWS-style credential (issue_aws_credential) so the bedrock
  # ingress door — inbound SigV4 — records the same outcome classes as the bearer doors.
  local a="$1"
  _oracle_take_mint oracle-ok "$(_oracle_mint "$a" '{"name":"oracle-ok","group":"oracle","issue_aws_credential":true}')" || return 1
  ORACLE_KEY_OK="$_M_ID"; ORACLE_TOKEN_OK="$_M_TOKEN"; ORACLE_AWS_AKID_OK="$_M_AKID"; ORACLE_AWS_SECRET_OK="$_M_SECRET"
  _oracle_take_mint oracle-broke "$(_oracle_mint "$a" '{"name":"oracle-broke","group":"broke","issue_aws_credential":true}')" || return 1
  ORACLE_KEY_BROKE="$_M_ID"; ORACLE_TOKEN_BROKE="$_M_TOKEN"; ORACLE_AWS_AKID_BROKE="$_M_AKID"; ORACLE_AWS_SECRET_BROKE="$_M_SECRET"
  _oracle_take_mint oracle-quota "$(_oracle_mint "$a" '{"name":"oracle-quota","group":"broke-quota","issue_aws_credential":true}')" || return 1
  ORACLE_KEY_QUOTA="$_M_ID"; ORACLE_TOKEN_QUOTA="$_M_TOKEN"; ORACLE_AWS_AKID_QUOTA="$_M_AKID"; ORACLE_AWS_SECRET_QUOTA="$_M_SECRET"
  _oracle_take_mint oracle-noscope "$(_oracle_mint "$a" '{"name":"oracle-noscope","group":"oracle","allowed_pools":["oracle-unused"],"issue_aws_credential":true}')" || return 1
  ORACLE_KEY_NOSCOPE="$_M_ID"; ORACLE_TOKEN_NOSCOPE="$_M_TOKEN"; ORACLE_AWS_AKID_NOSCOPE="$_M_AKID"; ORACLE_AWS_SECRET_NOSCOPE="$_M_SECRET"
  export ORACLE_KEY_OK ORACLE_TOKEN_OK ORACLE_KEY_BROKE ORACLE_TOKEN_BROKE ORACLE_KEY_QUOTA ORACLE_TOKEN_QUOTA ORACLE_KEY_NOSCOPE ORACLE_TOKEN_NOSCOPE
  export ORACLE_AWS_AKID_OK ORACLE_AWS_SECRET_OK ORACLE_AWS_AKID_BROKE ORACLE_AWS_SECRET_BROKE ORACLE_AWS_AKID_QUOTA ORACLE_AWS_SECRET_QUOTA ORACLE_AWS_AKID_NOSCOPE ORACLE_AWS_SECRET_NOSCOPE
}

# Scrape /metrics into <out>, retrying through the boot window in which the recorder is not yet
# installed (a candidate answers 503 + Retry-After there, never an empty 200). Key-authed first
# (1.5.5's RouteAuth::Key on the data listener), then unauthenticated; absent after 3 s.
oracle_scrape_metrics() {  # <listen-port> <token> <out-file>
  local port="$1" token="$2" out="$3" i=0 code
  while [ $i -lt 60 ]; do
    code="$(curl -sS -m 5 -H "Authorization: Bearer ${token}" "http://127.0.0.1:${port}/metrics" -o "$out" -w '%{http_code}' 2>/dev/null || echo 000)"
    # 1.5.5 can answer an empty 200 from a worker whose recorder has described nothing yet (the
    # cold-worker window a candidate refuses with 503 instead); an exposition with no series is
    # not a scrape, so it retries like the refusal does
    [ "$code" = 200 ] && grep -q '^# ' "$out" 2>/dev/null && return 0
    # 401: the just-minted key is not visible to this worker yet (write-behind); 503: the recorder
    # is not installed yet; 000: the listener is not answering yet. All three are boot-window
    # transients on one binary or the other, so all three retry; anything else is the answer.
    case "$code" in 200|401|503|000) ;; *) break ;; esac
    sleep 0.05; i=$((i+1))
  done
  rm -f "$out"; return 1
}

# ── selftest ─────────────────────────────────────────────────────────────────────────────────────
# This file is SOURCED by record.sh and replay.sh, so running it does nothing to a recording. Run
# directly it proves the one thing in it that is pure logic and was silently wrong: how a mint
# response is split into a principal.
if [ "${BASH_SOURCE[0]}" = "${0}" ] && [ "${1:-}" = "--selftest" ]; then
  _oc_fails=0
  _oc() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || _oc_fails=$((_oc_fails+1)); }

  # A COMPLETE MINT IS TAKEN, FIELD FOR FIELD.
  if _oracle_take_mint t "$(printf 'vk_abc\037bbk_secret\037AKIA1\037wow')" 2>/dev/null \
      && [ "$_M_ID" = vk_abc ] && [ "$_M_TOKEN" = bbk_secret ] && [ "$_M_AKID" = AKIA1 ] && [ "$_M_SECRET" = wow ]; then
    _oc PASS "a complete mint row is split into id/token/akid/secret"
  else
    _oc FAIL "a complete mint row was mis-split (id=${_M_ID:-} token=${_M_TOKEN:-} akid=${_M_AKID:-} secret=${_M_SECRET:-})"
  fi

  # THE BUG. A mint that answered with no id and no token used to word-split down to the AWS
  # PLACEHOLDERS: `set -- $r` on "  - -" gives $1="-" and $2="-", and `[ -n "-" ]` is true, so the
  # recorder went on to send `Authorization: Bearer -` for a whole plane and recorded every 401 as
  # the cell's answer. Both halves are proven: the fields no longer shift, and `-` is refused.
  if _oracle_take_mint t "$(printf '\037\037-\037-')" 2>/dev/null; then
    _oc FAIL "a mint with no id and no token was accepted as a principal (id='${_M_ID:-}' token='${_M_TOKEN:-}') — this is the 'Bearer -' run"
  else
    _oc PASS "a mint with no id and no token is refused, not shifted onto the AWS placeholders"
  fi
  case "${_M_TOKEN:-unset}" in
    "-") _oc FAIL "the empty token still collapsed onto the AWS placeholder '-'" ;;
    *)   _oc PASS "an empty token stays empty (fields do not shift left)" ;;
  esac

  # A MISSING ID ALONE SHIFTED EVERY LATER FIELD: the token landed in the id and the akid in the
  # token, so the run authenticated with a placeholder while looking entirely well-formed.
  if _oracle_take_mint t "$(printf '\037bbk_secret\037AKIA1\037wow')" 2>/dev/null; then
    _oc FAIL "a mint with no id was accepted (id='${_M_ID:-}')"
  else
    [ "${_M_TOKEN:-}" = bbk_secret ] \
      && _oc PASS "a mint with no id is refused, and the token did not shift into the id" \
      || _oc FAIL "a mint with no id shifted its fields (token read as '${_M_TOKEN:-}')"
  fi

  # A LITERAL '-' IN EITHER CREDENTIAL IS REFUSED WHATEVER PRODUCED IT.
  if _oracle_take_mint t "$(printf -- '-\037bbk_secret\037-\037-')" 2>/dev/null; then
    _oc FAIL "'-' was accepted as a key id"
  else
    _oc PASS "'-' is never a key id"
  fi
  if _oracle_take_mint t "$(printf -- 'vk_abc\037-\037-\037-')" 2>/dev/null; then
    _oc FAIL "'-' was accepted as a bearer token"
  else
    _oc PASS "'-' is never a bearer token"
  fi

  # AN AWS-LESS MINT IS STILL A VALID PRINCIPAL: '-' is legal in the AWS columns (it is this file's
  # own placeholder), so the refusal above must be about the credentials, not about the character.
  if _oracle_take_mint t "$(printf -- 'vk_abc\037bbk_secret\037-\037-')" 2>/dev/null; then
    _oc PASS "a key minted without SigV4 credentials is still a valid principal"
  else
    _oc FAIL "a key with no AWS credential was refused — the guard is refusing the placeholder, not a missing credential"
  fi

  echo
  [ "$_oc_fails" -eq 0 ] && { echo "oracle-config selftest: GREEN"; exit 0; } \
    || { echo "oracle-config selftest: RED ($_oc_fails)"; exit 1; }
fi
