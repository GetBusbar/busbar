#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family. CHANGELOG.md:134-137 (1.5.3 entry) says of
# BUSBAR_PROVIDERS / BUSBAR_CONFIG_OVERLAY / BUSBAR_WORKER_THREADS / BUSBAR_UPSTREAM_HTTP1_ONLY /
# BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE: "Each still works for one more release, and the config key
# wins if you set both." PARTIALLY CONTRADICTED BY CODE (main.rs:1645-1647 in the 1.5.5 tag): for
# BUSBAR_PROVIDERS specifically, the ENV VAR wins over `providers_file:`, not the config key. This
# pins the actual precedence: two providers catalogs, config.yaml declares `providers_file:` for
# ONE of them, BUSBAR_PROVIDERS names the OTHER; `busbar --validate`'s own success line echoes back
# the catalog PATH it actually resolved (`providers: {path}` — ops-observability inventory §2.3), so
# the golden literally names the file that won.
#
#   documented-providers-env-wins.sh
#
# Writes $RAW/captured.json: status = 0 once --validate ran (else the failing step number).
# Env from the recorder: BUSBAR_BIN RAW WORK.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
W="$RAW/providers-env-work"; mkdir -p "$W"

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null

cat >"$W/providers-config.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
YAML
cat >"$W/providers-env.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:2"
YAML
cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:1"
admin_listen: "127.0.0.1:2"
providers_file: "${W}/providers-config.yaml"
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

rc=0
env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers-env.yaml" \
  ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN=shadow-oracle-admin RUST_LOG=warn \
  "$BIN" --validate >"$W/stdout" 2>"$W/stderr" </dev/null || rc=$?

# Paths under $W are a fresh tmpdir every run (recorder and replayer alike) — report only which
# named catalog won ("config" | "env" | "neither"), never the absolute path, so the golden is
# host/run independent.
stdout="$(cat "$W/stdout" 2>/dev/null)"
stderr="$(cat "$W/stderr" 2>/dev/null)"
providers_line_raw="$(grep -o 'providers: .*' "$W/stdout" 2>/dev/null | head -1)"
resolved="neither"
case "$providers_line_raw" in
  *providers-env.yaml*) resolved="env" ;;
  *providers-config.yaml*) resolved="config" ;;
esac
stdout_scrubbed="$(printf '%s' "$stdout" | sed -e "s#${W}#<WORK>#g")"
stderr_scrubbed="$(printf '%s' "$stderr" | sed -e "s#${W}#<WORK>#g")"

jq -n --argjson rc "$rc" --arg stdout "$stdout_scrubbed" --arg stderr "$stderr_scrubbed" \
  --arg resolved "$resolved" \
  '{status:0, headers:{}, body:($stdout+"|"+$stderr),
    effects:{exit_code:$rc, stdout:$stdout, stderr:$stderr, resolved:$resolved,
             note:"resolved=env means BUSBAR_PROVIDERS won over providers_file: (the actual 1.5.5 code path); resolved=config would match the CHANGELOG:134-137 text"}}' \
  >"$RAW/captured.json"
