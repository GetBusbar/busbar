#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The shadow oracle RECORDER: drive one busbar binary through every LLM cell and write a normalized
# capture (response + effects) per cell. Run it against the published reference (1.5.5) to make the
# GOLDEN; run it against a dev build and `replay.sh` diffs the two. Same config, same mock, same
# keys-by-role, same normalizer — so a diff is busbar's behavior and nothing else.
#
#   record.sh --bin <busbar> --out <dir> [--filter <regex-on-cell-id>] [--plane llm]
#
# Layout of <out>:
#   cells/<id>.json   normalized capture (what replay.sh diffs)
#   raw/<id>/         headers, body, status, before/, after/ (kept for forensics)
#   ledger.tsv        one row per cell: RECORDED | UNSUPPORTED | FAIL   ("zero rows is red")
#   meta.json         binary version, cell count, timestamp
#
# Per-cell principal (minted by oracle_mint_keys — every refusal is REAL, not a stub):
#   ok / ok_stream / malformed / upstream_down  -> the OK key
#   over_budget                                 -> the BROKE key (1-cent/day budget -> 429 at Admit)
#   out_of_scope                                -> the NOSCOPE key (allowed only an unused pool -> 403)
#   unauthenticated                             -> no Authorization header at all
# upstream_down flips the mock's CONTROL FILE for the duration of the cell; busbar sees nothing.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"
# shellcheck source=oracle-config.sh
source "${here}/oracle-config.sh"

BIN="" OUT="" FILTER="" PLANE="llm"
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --filter) FILTER="$2"; shift 2 ;;
    --plane) PLANE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -x "$BIN" ] && [ -n "$OUT" ] || { echo "usage: $0 --bin <busbar> --out <dir> [--filter re]" >&2; exit 2; }
command -v jq >/dev/null || { echo "record.sh needs jq" >&2; exit 2; }
[ "$PLANE" = llm ] || { echo "record.sh: only the llm plane records natively today; mcp/a2a go through the conformance rigs" >&2; exit 2; }

LISTEN_PORT="${ORACLE_LISTEN_PORT:-48811}" ADMIN_PORT="${ORACLE_ADMIN_PORT:-48812}" MOCK_PORT="${ORACLE_MOCK_PORT:-48781}"
assert_port_free "$LISTEN_PORT"; assert_port_free "$ADMIN_PORT"; assert_port_free "$MOCK_PORT"

mkdir -p "$OUT/cells" "$OUT/raw"
LEDGER="$OUT/ledger.tsv"; : >"$LEDGER"; export LEDGER
WORK="$(mktemp -d "${TMPDIR:-/tmp}/shadow-oracle-record.XXXXXX")"; export WORK
export BUSBAR_BIN="$BIN"
declaw "$BIN"
VER="$("$BIN" --version 2>/dev/null | head -1)"
CONTROL="$WORK/mock.control"

fail_setup() { record "setup" FAIL "$1" "${2:-}"; exit 1; }

# ── mock upstream (all six dialects, byte-deterministic) ────────────────────────────────────────
python3 "${here}/mock-upstream.py" "$MOCK_PORT" oracle-marker "$CONTROL" >"$WORK/mock.log" 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${MOCK_PORT}/" 8 || fail_setup "mock upstream did not come up" "$(tail -c 300 "$WORK/mock.log")"

# ── busbar under the oracle config ──────────────────────────────────────────────────────────────
oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || fail_setup "oracle config could not be written"
oracle_env "$BIN" --validate >"$WORK/validate.log" 2>&1 || fail_setup "busbar rejected the oracle config (run selftest.sh)" "$(tail -c 400 "$WORK/validate.log")"
oracle_env "$BIN" >"$WORK/busbar.log" 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30 || fail_setup "busbar (${VER}) did not come up" "$(tr '\n' '|' <"$WORK/busbar.log" | tail -c 500)"
oracle_mint_keys "$ADMIN_PORT" || fail_setup "could not mint the three oracle keys" "admin API on ${ADMIN_PORT}; see $WORK/busbar.log"

# ── effect snapshots ────────────────────────────────────────────────────────────────────────────
snapshot() {  # snapshot <dir> <key-id>
  local d="$1" kid="$2"; mkdir -p "$d"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${kid}/usage" -o "$d/usage.json" 2>/dev/null || rm -f "$d/usage.json"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/audit?limit=1000" -o "$d/audit.json" 2>/dev/null || rm -f "$d/audit.json"
  curl -fsS -m 5 "http://127.0.0.1:${LISTEN_PORT}/metrics" -o "$d/metrics.txt" 2>/dev/null \
    || curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" "http://127.0.0.1:${ADMIN_PORT}/metrics" -o "$d/metrics.txt" 2>/dev/null \
    || rm -f "$d/metrics.txt"
}

# ── the cells ───────────────────────────────────────────────────────────────────────────────────
n=0
while IFS= read -r cell; do
  id="$(jq -r .id <<<"$cell")"
  [ -z "$FILTER" ] || [[ "$id" =~ $FILTER ]] || continue
  outcome="$(jq -r .outcome <<<"$cell")"
  safe="${id//|/__}"
  raw="$OUT/raw/$safe"; mkdir -p "$raw"

  req="$(python3 "${here}/build-request.py" --cell "$cell")" || { record "$id" FAIL "build-request failed" "$req"; continue; }
  auth="$(jq -r .auth <<<"$req")"
  if [ "$auth" != bearer ]; then
    record "$id" SKIP "UNSUPPORTED: $(jq -r .note <<<"$req")" "recorded as a named gap, not a pass"
    continue
  fi
  path="$(jq -r .path <<<"$req")"
  jq -r .body <<<"$req" >"$raw/request.body"

  case "$outcome" in
    over_budget) token="$ORACLE_TOKEN_BROKE"; kid="$ORACLE_KEY_BROKE" ;;
    out_of_scope) token="$ORACLE_TOKEN_NOSCOPE"; kid="$ORACLE_KEY_NOSCOPE" ;;
    unauthenticated) token=""; kid="$ORACLE_KEY_OK" ;;
    *) token="$ORACLE_TOKEN_OK"; kid="$ORACLE_KEY_OK" ;;
  esac

  hdr_args=()
  while IFS= read -r kv; do hdr_args+=(-H "$kv"); done < <(jq -r '.headers | to_entries[] | "\(.key): \(.value)"' <<<"$req")
  [ -z "$token" ] || hdr_args+=(-H "Authorization: Bearer ${token}")

  [ "$outcome" != upstream_down ] || echo down >"$CONTROL"
  snapshot "$raw/before" "$kid"
  status="$(curl -sS -m 20 -N -X POST "http://127.0.0.1:${LISTEN_PORT}${path}" "${hdr_args[@]}" \
    --data-binary @"$raw/request.body" -D "$raw/headers" -o "$raw/body" -w '%{http_code}' 2>"$raw/curl.err")" || status="000"
  # Metering may post after the response bytes are flushed; give the ledger a beat before reading it.
  sleep 0.3
  snapshot "$raw/after" "$kid"
  rm -f "$CONTROL"
  printf '%s\n' "$status" >"$raw/status"

  if [ "$status" = "000" ]; then
    record "$id" FAIL "no HTTP response (curl)" "$(tr '\n' ' ' <"$raw/curl.err" | tail -c 300)"; continue
  fi
  if ! python3 "${here}/capture.py" "$raw/headers" "$status" "$raw/body" "$raw/before" "$raw/after" >"$raw/captured.json" 2>"$raw/capture.err"; then
    record "$id" FAIL "capture.py failed" "$(tail -c 300 "$raw/capture.err")"; continue
  fi
  if ! python3 "${here}/normalize.py" "$raw/captured.json" --key-id "$kid" >"$OUT/cells/$safe.json" 2>"$raw/normalize.err"; then
    record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; continue
  fi
  usage_note="$(jq -c '.effects.usage' "$OUT/cells/$safe.json")"
  record "$id" PASS "HTTP ${status}; usage Δ ${usage_note}" ""
  n=$((n + 1))
done < <(jq -c --arg p "$PLANE" '.cells[] | select(.plane == $p)' "${here}/cells.json")

jq -n --arg ver "$VER" --arg bin "$BIN" --argjson recorded "$n" \
  '{binary: $bin, version: $ver, recorded: $recorded, at: (now | todate)}' >"$OUT/meta.json"
cp "$WORK/busbar.log" "$OUT/busbar.log" 2>/dev/null || true

echo
echo "recorded ${n} cells for ${VER} -> ${OUT}"
[ "$n" -gt 0 ] || { echo "ZERO ROWS IS RED" >&2; exit 1; }
