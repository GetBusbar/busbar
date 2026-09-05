#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: four boot.refusal/boot.warning rows whose precondition a single-exec mutation
# cannot produce — each needs a REAL durable governance store that already holds state from a PRIOR
# boot, then a SECOND boot that reads it back and refuses/warns:
#
#   governance-init    BOOT-175  `governance init failed: {e}` — GovState::new_with_signer's own
#                       store reads (Self::load / Self::load_by_credential / list_denylist) fail.
#                       Produced by corrupting the durable store's `keys` table page in place: the
#                       plugin's schema-migration-on-open heals a DROPPED table (busbar boots clean
#                       against it), so the fixture instead flips the leading byte of the `keys`
#                       table's own root PAGE — a real SQLite page-level corruption no migration can
#                       repair — verified against the live 1.5.5 binary: `store error: database disk
#                       image is malformed`.
#   budget-hydration   BOOT-172  `governance boot: budget hydration failed ({e})` — same corruption
#                       technique, applied to the `usage_windows` table's root page instead (the
#                       ledger `hydrate_budgets` reads), so `GovState::new_with_signer` itself
#                       succeeds (its own reads never touch that table) and boot reaches, then fails,
#                       the hydration step specifically.
#   dangling-group     BOOT-174  a virtual key minted under a config that HAD group `oracle` survives
#                       into a second boot whose config no longer defines it — no store corruption at
#                       all, just a config change between two boots against the SAME durable store.
#   inert-keys         BOOT-W13  a virtual key durably minted with `keys` in the chain, then a second
#                       boot against the SAME store with `keys` dropped from `auth.chain` (still
#                       exit 0 — this family is a WARN, never a boot failure) — the INERT-KEYS GUARD.
#
# BOOT-173 (`could not read stored keys to validate budget_group references ({e})`, `gs.all_keys()`)
# is NOT one of the four: `GovState::all_keys` and the `Self::load` called one step earlier inside
# `new_with_signer` both resolve to the identical `Store::list_keys()` call against the identical,
# unchanged-between-the-two-calls durable file — any corruption that fails the second call already
# fails the first, surfacing as BOOT-175 (`governance init failed`) before `all_keys()` is ever
# reached. Investigated and left OUT of this script; see docs/design (A10b follow-up) for the
# writeup. A row this script does not attempt is a named gap, not a forced pass.
#
# Writes $RAW/captured.json in capture-exec.py's shape (status/headers/body/effects.stderr) — the
# SAME shape record_exec_cell's own `boot` mode produces — so this cell diffs against golden/HEAD
# exactly like any other boot.refusal/boot.warning row.
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN; SCRIPT_LISTEN_PORT/SCRIPT_ADMIN_PORT
# (this cell never needs a mock upstream — no request is ever sent through the data plane).
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"

MODE="${1:?mode: governance-init|budget-hydration|dangling-group|inert-keys}"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${GOV_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49751}}" AP="${GOV_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49752}}"
fail() { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"$1\"}}" >"$RAW/captured.json"; exit 0; }

W="$RAW/gov-work"; mkdir -p "$W/plugins" "$W/tmp"
# `busbar_plugin_loader::sweep_dead_staging` scans `std::env::temp_dir()` (`$TMPDIR`) for orphaned
# plugin staging directories left by a CRASHED prior run and prints `[info] removed N ...` when it
# finds any — a real host-wide count that has nothing to do with this cell and is NOT the same on
# every run (a prior kill -9'd busbar anywhere on the host leaves one). Point every busbar invocation
# below at its own fresh, empty TMPDIR so that line never fires here.
export TMPDIR="$W/tmp"
for p in "$LP" "$AP"; do assert_port_free "$p" || fail "port $p busy"; done

tarball="$(bash "${here}/fetch-plugin.sh" store-sqlite)" || fail "store-sqlite plugin fetch failed"
cp "$tarball" "$W/plugins/"
"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
[ -s "$W/signing.key" ] || fail "--generate-signing-key produced no key"
DB="$W/gov.db"

cat >"$W/providers.yaml" <<EOF
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
EOF

write_config() {  # write_config <out> <groups-yaml> <auth-chain-yaml> <db>
  cat >"$1" <<EOF
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [${3}]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "${W}/plugins"
store:
  module: sqlite
  settings: { db_path: "${4}" }
${2}
providers:
  openai-chat:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-openai-chat:
    provider: openai-chat
rate_card:
  m-openai-chat: { input_utok: 100000, output_utok: 200000 }
EOF
}

GROUPS_ORACLE=$'groups:\n  oracle:\n    limits:\n      - { budget: 1000000, per: day }'
GROUPS_OTHER=$'groups:\n  other:\n    limits:\n      - { budget: 1000000, per: day }'

write_config "$W/boot1.yaml" "$GROUPS_ORACLE" "keys" "$DB"

env_() { BUSBAR_CONFIG="$1" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "${@:2}"; }
spawn_() { local log="$1" cfg="$2"; ( exec env BUSBAR_CONFIG="$cfg" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >>"$log" 2>&1 & echo $!; }

# ---- boot 1: create the durable store + mint one key under group `oracle` -------------------------
pid="$(spawn_ "$W/busbar1.log" "$W/boot1.yaml")"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail "busbar1 did not come up: $(tail -c 400 "$W/busbar1.log")"
mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"gov-oracle","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"
[ -n "$kid" ] || fail "mint failed: $mint"
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

# ---- corrupt/reconfigure between the two boots, per mode -------------------------------------------
DB2="$DB"; cfg2_groups="$GROUPS_ORACLE"; cfg2_chain="keys"; expect_boot=refuse
case "$MODE" in
  governance-init|budget-hydration)
    table=keys; [ "$MODE" = budget-hydration ] && table=usage_windows
    rootpage="$(sqlite3 "$DB" "SELECT rootpage FROM sqlite_master WHERE name='${table}';" 2>/dev/null)"
    [ -n "$rootpage" ] || fail "could not find ${table}'s rootpage in the durable store"
    pagesize="$(sqlite3 "$DB" "PRAGMA page_size;" 2>/dev/null)"
    DB2="$W/gov-corrupt.db"; cp "$DB" "$DB2"
    offset=$(( (rootpage - 1) * pagesize ))
    python3 - "$DB2" "$offset" <<'PY'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    f.seek(offset)
    b = f.read(1)
    f.seek(offset)
    f.write(bytes([b[0] ^ 0xFF]))
PY
    ;;
  dangling-group)
    cfg2_groups="$GROUPS_OTHER"
    ;;
  inert-keys)
    cfg2_chain=""
    expect_boot=warn
    ;;
  *) fail "unknown mode ${MODE}" ;;
esac
write_config "$W/boot2.yaml" "$cfg2_groups" "$cfg2_chain" "$DB2"

# ---- boot 2: observe the refusal (exit 1) or the warning (exit 0, alive on /healthz) ---------------
if [ "$expect_boot" = refuse ]; then
  env_ "$W/boot2.yaml" "$BIN" >"$RAW/stdout" 2>"$RAW/stderr" </dev/null
  rc=$?
else
  pid2="$(spawn_ "$W/busbar2.log" "$W/boot2.yaml")"; track_pid "$pid2"
  if wait_for_http "http://127.0.0.1:${LP}/healthz" 30; then
    kill "$pid2" 2>/dev/null; wait "$pid2" 2>/dev/null; rc=0
  elif kill -0 "$pid2" 2>/dev/null; then
    kill -9 "$pid2" 2>/dev/null; wait "$pid2" 2>/dev/null; rc=124
  else
    wait "$pid2"; rc=$?
  fi
  : >"$RAW/stdout"
  cp "$W/busbar2.log" "$RAW/stderr"
fi
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

python3 "${here}/capture-exec.py" "$rc" "$RAW/stdout" "$RAW/stderr" \
  --strip-path "$W" --strip-path "$RAW" --strip-path "$repo" --strip-path "$BIN" >"$RAW/captured.json" 2>"$RAW/capture.err" \
  || fail "capture-exec.py failed: $(tail -c 300 "$RAW/capture.err")"
