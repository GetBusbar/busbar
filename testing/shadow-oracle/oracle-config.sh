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
#         - two budget groups: `oracle` (loose) and `broke` (a 1-cent/day budget) so an over-budget
#           refusal is a REAL 429 at Admit, not a stub.
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
    # A pool no cell targets: the NOSCOPE key is allowed ONLY this pool, so every cell it presents on
    # is out-of-scope (403 at Approve) — a real refusal, not a stub.
    cat <<EOF
pools:
  oracle-unused:
    members:
      - model: m-openai-chat
EOF
  } >"${work}/config.yaml"
}

oracle_env() {  # run "$@" with the oracle's busbar environment
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" RUST_LOG=warn "$@"
}

_oracle_mint() {  # <admin_port> <json-body>  -> prints "id token"
  local out
  out="$(curl -fsS -X POST "http://127.0.0.1:$1/api/v1/admin/keys" \
    -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" -H "Content-Type: application/json" \
    -d "$2" 2>/dev/null || true)"
  printf '%s %s\n' "$(printf '%s' "$out" | jq -r '.id // empty')" "$(printf '%s' "$out" | jq -r '.token // empty')"
}

oracle_mint_keys() {  # <admin_port>
  local a="$1" r
  r="$(_oracle_mint "$a" '{"name":"oracle-ok","group":"oracle"}')"
  ORACLE_KEY_OK="${r%% *}"; ORACLE_TOKEN_OK="${r#* }"
  r="$(_oracle_mint "$a" '{"name":"oracle-broke","group":"broke"}')"
  ORACLE_KEY_BROKE="${r%% *}"; ORACLE_TOKEN_BROKE="${r#* }"
  r="$(_oracle_mint "$a" '{"name":"oracle-noscope","group":"oracle","allowed_pools":["oracle-unused"]}')"
  ORACLE_KEY_NOSCOPE="${r%% *}"; ORACLE_TOKEN_NOSCOPE="${r#* }"
  export ORACLE_KEY_OK ORACLE_TOKEN_OK ORACLE_KEY_BROKE ORACLE_TOKEN_BROKE ORACLE_KEY_NOSCOPE ORACLE_TOKEN_NOSCOPE
  [ -n "$ORACLE_TOKEN_OK" ] && [ -n "$ORACLE_TOKEN_BROKE" ] && [ -n "$ORACLE_TOKEN_NOSCOPE" ]
}
