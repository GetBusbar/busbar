#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family: four independent `busbar --validate` checks,
# each pinning one CHANGELOG.md claim's ACTUAL 1.5.5 behaviour, packed into one script cell (no
# running server needed for any of them, so no ports to manage):
#   step1_secrets   1.5.3, CHANGELOG:81-87 — an unresolvable env:/file: secret ref fails --validate
#   step2_mtls      1.5.3, CHANGELOG:110-112 — `admin_insecure` retired, `admin_require_mtls` (bool,
#                   meaning INVERTED) takes its place
#   step3_no_minter 1.5.2, CHANGELOG:196-197 — `auth.chain: [keys]` with no way to ever mint an admin
#                   token (no identity-providers block, empty admin_auth) — the ACTUAL exit/message
#                   observed against the real binary, recorded rather than assumed
#   step4_bare_path 1.5.3, CHANGELOG:185-186 — BUSBAR_CONFIG named with no directory component,
#                   invoked from that file's own (writable) directory
#
# One selftest is missing on purpose: `documented-providers-env-wins.sh` and
# `documented-overlay-refused.sh` are their own cells (they need a full config + boot / two catalogs
# each); this script covers only the four --validate-only checks above.
#
# Writes $RAW/captured.json: status = 0 once all four steps ran. Env from the recorder: BUSBAR_BIN
# RAW WORK.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
W="$RAW/validate-checks-work"; mkdir -p "$W"
"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null

BASE_PROVIDERS='openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
'
BASE_TAIL="groups:
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
"

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
scrub() { sed -e "s#${W}#<WORK>#g"; }

# ---- step1: unresolvable secret ref ----
mkdir -p "$W/s1"; printf '%s' "$BASE_PROVIDERS" >"$W/s1/providers.yaml"
cat >"$W/s1/config.yaml" <<YAML
listen: "127.0.0.1:1"
admin_listen: "127.0.0.1:2"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
${BASE_TAIL}
YAML
# overwrite the provider's api_key with an unresolvable env ref
python3 - "$W/s1/config.yaml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("api_key: { env: ORACLE_UPSTREAM_KEY }", "api_key: { env: DOES_NOT_EXIST_ORACLE_SECRET_REF }")
open(p, "w").write(s)
PY
rc1=0
env BUSBAR_CONFIG="$W/s1/config.yaml" BUSBAR_PROVIDERS="$W/s1/providers.yaml" \
  BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn \
  "$BIN" --validate >"$W/s1/stdout" 2>"$W/s1/stderr" </dev/null || rc1=$?
step step1_secrets_exit "$rc1"
step step1_secrets_stderr "$(scrub <"$W/s1/stderr")"

# ---- step2: admin_require_mtls vs retired admin_insecure ----
mkdir -p "$W/s2a" "$W/s2b"
printf '%s' "$BASE_PROVIDERS" >"$W/s2a/providers.yaml"
cat >"$W/s2a/config.yaml" <<YAML
listen: "127.0.0.1:1"
admin_listen: "127.0.0.1:2"
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
${BASE_TAIL}
YAML
rc2a=0
env BUSBAR_CONFIG="$W/s2a/config.yaml" BUSBAR_PROVIDERS="$W/s2a/providers.yaml" \
  ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn \
  "$BIN" --validate >"$W/s2a/stdout" 2>"$W/s2a/stderr" </dev/null || rc2a=$?
step step2_admin_require_mtls_exit "$rc2a"

printf '%s' "$BASE_PROVIDERS" >"$W/s2b/providers.yaml"
cat >"$W/s2b/config.yaml" <<YAML
listen: "127.0.0.1:1"
admin_listen: "127.0.0.1:2"
admin_insecure: true
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
${BASE_TAIL}
YAML
rc2b=0
env BUSBAR_CONFIG="$W/s2b/config.yaml" BUSBAR_PROVIDERS="$W/s2b/providers.yaml" \
  ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn \
  "$BIN" --validate >"$W/s2b/stdout" 2>"$W/s2b/stderr" </dev/null || rc2b=$?
step step2_admin_insecure_exit "$rc2b"
step step2_admin_insecure_stderr "$(scrub <"$W/s2b/stderr")"

# ---- step3: auth.chain: [keys] with no way to ever mint an admin token ----
mkdir -p "$W/s3"; printf '%s' "$BASE_PROVIDERS" >"$W/s3/providers.yaml"
cat >"$W/s3/config.yaml" <<YAML
listen: "127.0.0.1:1"
admin_listen: "127.0.0.1:2"
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
${BASE_TAIL}
YAML
rc3=0
env BUSBAR_CONFIG="$W/s3/config.yaml" BUSBAR_PROVIDERS="$W/s3/providers.yaml" \
  ORACLE_UPSTREAM_KEY=unused RUST_LOG=warn \
  "$BIN" --validate >"$W/s3/stdout" 2>"$W/s3/stderr" </dev/null || rc3=$?
step step3_no_minter_exit "$rc3"
step step3_no_minter_stderr "$(scrub <"$W/s3/stderr")"

# ---- step4: BUSBAR_CONFIG named with no directory component ----
mkdir -p "$W/s4"; printf '%s' "$BASE_PROVIDERS" >"$W/s4/providers.yaml"
cat >"$W/s4/config.yaml" <<YAML
listen: "127.0.0.1:1"
admin_listen: "127.0.0.1:2"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
${BASE_TAIL}
YAML
rc4=0
( cd "$W/s4" && env BUSBAR_CONFIG="config.yaml" BUSBAR_PROVIDERS="providers.yaml" \
  ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn \
  "$BIN" --validate >"$W/s4/stdout" 2>"$W/s4/stderr" </dev/null ) || rc4=$?
step step4_bare_path_exit "$rc4"
step step4_bare_path_stderr "$(scrub <"$W/s4/stderr")"

jq -n --argjson eff "$eff" --arg body "$(jq -c . <<<"$eff")" '{status:0, headers:{}, body:$body, effects:$eff}' \
  >"$RAW/captured.json"
