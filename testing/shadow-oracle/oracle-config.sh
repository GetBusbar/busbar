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
#         - two budget groups: `oracle` (loose) and `broke` (requests: 1/day + a 1-cent/day budget) so
#           after the recorder's one PRIMING request the over-budget refusal is a REAL 429 at Admit.
#   oracle_mint_keys <admin_port>
#       mints the three principals every outcome class needs and exports:
#         ORACLE_TOKEN_OK / ORACLE_KEY_OK         normal key, group `oracle`
#         ORACLE_TOKEN_BROKE / ORACLE_KEY_BROKE   group `broke`  -> 429 over_budget at Admit
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
  local work="$1" listen="$2" admin="$3" mock="$4"
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
groups:
  oracle:
    limits:
      - { budget: 1000000, per: day }
  broke:
    limits:
      - { requests: 1, per: day }
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
    # A PRICED card so spend is real: input 0.1 / output 0.2 units per token -> the mock's fixed
    # 11 in / 7 out costs 2.5 units per call, so cents-truncation, fee and refund arithmetic are all
    # exercised on every cell (spend_cents 2, not 2.5; PB-16/22).
    echo "rate_card:"
    for d in "${ORACLE_DIALECTS[@]}"; do
      echo "  m-${d}: { input_utok: 100000, output_utok: 200000 }"
    done
    # Pools:
    #   oracle-unused  no cell targets it: the NOSCOPE key is allowed ONLY this pool -> 403 at Approve
    #   oracle-fo      two members with a consecutive-1 breaker: a down member trips on the first 5xx
    #                  and the walk fails over (max_hops 3, deadline 120) — the route.failover family
    #   oracle-fb      one member, on_exhausted -> fallback_pool oracle-fo (the cross-pool hop, PB-4/47)
    #   oracle-lb      least_bad terminal
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
EOF
  } >"${work}/config.yaml"
}

oracle_env() {  # run "$@" with the oracle's busbar environment
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" RUST_LOG="${RUST_LOG:-warn}" "$@"
}

_oracle_mint() {  # <admin_port> <json-body>  -> prints "id token akid secret"
  local out
  out="$(curl -fsS -X POST "http://127.0.0.1:$1/api/v1/admin/keys" \
    -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" -H "Content-Type: application/json" \
    -d "$2" 2>/dev/null || true)"
  printf '%s %s %s %s\n' "$(printf '%s' "$out" | jq -r '.id // empty')" "$(printf '%s' "$out" | jq -r '.token // empty')" \
    "$(printf '%s' "$out" | jq -r '.aws_access_key_id // "-"')" "$(printf '%s' "$out" | jq -r '.aws_secret_access_key // "-"')"
}

oracle_mint_keys() {  # <admin_port>
  # Every principal also carries an AWS-style credential (issue_aws_credential) so the bedrock
  # ingress door — inbound SigV4 — records the same outcome classes as the bearer doors.
  local a="$1" r
  r="$(_oracle_mint "$a" '{"name":"oracle-ok","group":"oracle","issue_aws_credential":true}')"
  set -- $r; ORACLE_KEY_OK="${1:-}"; ORACLE_TOKEN_OK="${2:-}"; ORACLE_AWS_AKID_OK="${3:-}"; ORACLE_AWS_SECRET_OK="${4:-}"
  r="$(_oracle_mint "$a" '{"name":"oracle-broke","group":"broke","issue_aws_credential":true}')"
  set -- $r; ORACLE_KEY_BROKE="${1:-}"; ORACLE_TOKEN_BROKE="${2:-}"; ORACLE_AWS_AKID_BROKE="${3:-}"; ORACLE_AWS_SECRET_BROKE="${4:-}"
  r="$(_oracle_mint "$a" '{"name":"oracle-noscope","group":"oracle","allowed_pools":["oracle-unused"],"issue_aws_credential":true}')"
  set -- $r; ORACLE_KEY_NOSCOPE="${1:-}"; ORACLE_TOKEN_NOSCOPE="${2:-}"; ORACLE_AWS_AKID_NOSCOPE="${3:-}"; ORACLE_AWS_SECRET_NOSCOPE="${4:-}"
  export ORACLE_KEY_OK ORACLE_TOKEN_OK ORACLE_KEY_BROKE ORACLE_TOKEN_BROKE ORACLE_KEY_NOSCOPE ORACLE_TOKEN_NOSCOPE
  export ORACLE_AWS_AKID_OK ORACLE_AWS_SECRET_OK ORACLE_AWS_AKID_BROKE ORACLE_AWS_SECRET_BROKE ORACLE_AWS_AKID_NOSCOPE ORACLE_AWS_SECRET_NOSCOPE
  [ -n "$ORACLE_TOKEN_OK" ] && [ -n "$ORACLE_TOKEN_BROKE" ] && [ -n "$ORACLE_TOKEN_NOSCOPE" ]
}
