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

BIN="" OUT="" FILTER="" PLANE="llm" FRESH_ALL=1
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --filter) FILTER="$2"; shift 2 ;;
    --plane) PLANE="$2"; shift 2 ;;
    --shared-state) FRESH_ALL=0; shift ;;   # cells see each other's state (faster; NOT for goldens)
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -x "$BIN" ] && [ -n "$OUT" ] || { echo "usage: $0 --bin <busbar> --out <dir> [--filter re]" >&2; exit 2; }
command -v jq >/dev/null || { echo "record.sh needs jq" >&2; exit 2; }
case "$PLANE" in llm|core|all) ;; *) echo "record.sh: planes recorded natively: llm, core (cli/config/scrape/crosscut/admin/boot), all; mcp/a2a go through the conformance rigs" >&2; exit 2 ;; esac

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

BUSBAR_PID="" CUR_VARIANT=""
boot_busbar() {  # [variant] start busbar, wait for /healthz, mint the three keys, prime the BROKE key
  local variant="${1:-}"
  if [ "$variant" != "$CUR_VARIANT" ]; then
    ORACLE_VARIANT="$variant" oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || return 3
    CUR_VARIANT="$variant"
  fi
  BUSBAR_PID="$(oracle_spawn "$WORK/busbar.log" "$BIN")"; track_pid "$BUSBAR_PID"
  # busbar boots in tens of ms; poll at 25 ms (the shared wait_for_http sleeps a whole second)
  local w=0; while [ $w -lt 800 ]; do
    curl -fsS -m 1 -o /dev/null "http://127.0.0.1:${LISTEN_PORT}/healthz" 2>/dev/null && break
    kill -0 "$BUSBAR_PID" 2>/dev/null || return 1
    sleep 0.025; w=$((w+1))
  done
  [ $w -lt 800 ] || return 1
  oracle_mint_keys "$ADMIN_PORT" || return 2
  # PRIME the BROKE key: its group admits exactly one request per day, so one un-recorded request
  # now makes every over_budget cell a real 429 at Admit (the first request would be admitted).
  curl -sS -m 20 -o /dev/null -X POST "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
    -H "Authorization: Bearer ${ORACLE_TOKEN_BROKE}" -H "Content-Type: application/json" \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"prime"}]}' || true
}
stop_busbar() {  # stop the current busbar and wait until the listen port is free again
  [ -n "$BUSBAR_PID" ] || return 0
  kill "$BUSBAR_PID" 2>/dev/null || true; wait "$BUSBAR_PID" 2>/dev/null || true; BUSBAR_PID=""
  local i=0; while [ $i -lt 50 ] && ! assert_port_free "$LISTEN_PORT"; do sleep 0.1; i=$((i+1)); done
  # a port still answering after the kill means the OLD process survived: refuse to continue on it
  assert_port_free "$LISTEN_PORT" || { echo "record.sh: port ${LISTEN_PORT} still answers after stopping busbar ${BUSBAR_PID:-?}; refusing to record against a stale process" >&2; exit 1; }
}
boot_busbar; rc=$?
[ "$rc" -eq 0 ] || { [ "$rc" -eq 1 ] && fail_setup "busbar (${VER}) did not come up" "$(tr '\n' '|' <"$WORK/busbar.log" | tail -c 500)"; fail_setup "could not mint the three oracle keys" "admin API on ${ADMIN_PORT}; see $WORK/busbar.log"; }

# ── effect snapshots ────────────────────────────────────────────────────────────────────────────
snapshot() {  # snapshot <dir> <key-id>
  local d="$1" kid="$2"; mkdir -p "$d"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${kid}/usage" -o "$d/usage.json" 2>/dev/null || rm -f "$d/usage.json"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/audit?limit=1000" -o "$d/audit.json" 2>/dev/null || rm -f "$d/audit.json"
  # /metrics on the data listener is key-authed in 1.5.5 (RouteAuth::Key): present the OK client key.
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_TOKEN_OK}" "http://127.0.0.1:${LISTEN_PORT}/metrics" -o "$d/metrics.txt" 2>/dev/null \
    || curl -fsS -m 5 "http://127.0.0.1:${LISTEN_PORT}/metrics" -o "$d/metrics.txt" 2>/dev/null \
    || rm -f "$d/metrics.txt"
}

# ── exec cells: CLI flags, --validate, --migrate-config, boot refusals/warnings ──────────────────
# The process under test is the binary itself; the "response" is exit code + stdout + stderr.
#   exec.mode     cli       run once with exec.args, capture, done
#                 validate  run `--validate` (args) under the oracle env against exec.config
#                 boot      start the process; a refusal exits; a warning boots — wait for /healthz on
#                           spare ports, then stop; capture the log tail
#   exec.config   baseline | none | missing | migrated:<corpus-path> | mutation:<id> (fixtures/boot-mutations.json)
record_exec_cell() {  # <id> <cell-json> <raw-dir> <safe>
  local id="$1" cell="$2" raw="$3" safe="$4" mode cfg cfgfile envkv rc
  mode="$(jq -r '.exec.mode' <<<"$cell")"; cfg="$(jq -r '.exec.config // "baseline"' <<<"$cell")"
  local -a args=() envs=()
  while IFS= read -r a; do args+=("$a"); done < <(jq -r '.exec.args[]' <<<"$cell")
  while IFS= read -r envkv; do [ -n "$envkv" ] && envs+=("$envkv"); done < <(jq -r '.exec.env // {} | to_entries[] | "\(.key)=\(.value)"' <<<"$cell")
  local xwork="$raw/work"; mkdir -p "$xwork"
  case "$cfg" in
    baseline) cfgfile="$WORK/config.yaml" ;;
    none) cfgfile="" ;;
    missing) cfgfile="$xwork/does-not-exist.yaml" ;;
    migrated:*) # the corpus file migrated by THIS binary, then validated
      "$BIN" --migrate-config "${repo}/${cfg#migrated:}" >"$xwork/migrated.yaml" 2>/dev/null
      cfgfile="$xwork/migrated.yaml" ;;
    mutation:*) python3 "${here}/apply-mutation.py" --baseline "$WORK/config.yaml" --providers "$WORK/providers.yaml" \
        --mutation "${cfg#mutation:}" --out "$xwork" >"$xwork/mutation.env" 2>"$xwork/mutation.err" \
        || { record "$id" SKIP "UNSUPPORTED: $(tr '\n' ' ' <"$xwork/mutation.err" | cut -c1-200)" "mutation could not be applied (named gap)"; return; }
      cfgfile="$xwork/config.yaml"
      while IFS= read -r envkv; do [ -n "$envkv" ] && envs+=("$envkv"); done <"$xwork/mutation.env"
      while IFS= read -r a; do [ -n "$a" ] && args+=("$a"); done < <(jq -r '.args[]? // empty' "$xwork/mutation-args.json" 2>/dev/null) ;;
    *) record "$id" FAIL "unknown exec.config $cfg" ""; return ;;
  esac
  local providers="$WORK/providers.yaml"; [ -f "$xwork/providers.yaml" ] && providers="$xwork/providers.yaml"
  # the providers catalog also sits BESIDE the config under test (its default location) so a cell
  # about some other row is not decided by how the binary resolves BUSBAR_PROVIDERS — that env
  # precedence has its own cells (cli|env|*)
  [ -z "$cfgfile" ] || [ -f "$(dirname "$cfgfile")/providers.yaml" ] || cp "$providers" "$(dirname "$cfgfile")/providers.yaml" 2>/dev/null || true
  local -a envcmd=(env BUSBAR_PROVIDERS="$providers" ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" RUST_LOG=warn)
  [ -n "$cfgfile" ] && envcmd+=(BUSBAR_CONFIG="$cfgfile")
  [ "${#envs[@]}" -eq 0 ] || envcmd+=("${envs[@]}")
  case "$mode" in
    cli|validate)
      "${envcmd[@]}" "$BIN" "${args[@]}" >"$raw/stdout" 2>"$raw/stderr" </dev/null; rc=$? ;;
    boot)
      # a boot cell must not collide with the recording busbar: rewrite the listen ports
      python3 - "$cfgfile" "$xwork/boot.yaml" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
s=re.sub(r'^listen: .*$', 'listen: "127.0.0.1:48821"', s, flags=re.M)
s=re.sub(r'^admin_listen: .*$', 'admin_listen: "127.0.0.1:48822"', s, flags=re.M)
open(sys.argv[2],'w').write(s)
PY
      envcmd+=(BUSBAR_CONFIG="$xwork/boot.yaml")
      "${envcmd[@]}" "$BIN" "${args[@]}" >"$raw/stdout" 2>"$raw/stderr" </dev/null &
      local bpid=$! i=0 alive=1
      while [ $i -lt 100 ]; do
        if ! kill -0 "$bpid" 2>/dev/null; then alive=0; break; fi
        if curl -fsS -m 1 -o /dev/null "http://127.0.0.1:48821/healthz" 2>/dev/null; then break; fi
        sleep 0.1; i=$((i+1))
      done
      if [ "$alive" -eq 1 ]; then kill "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null; rc=0; else wait "$bpid"; rc=$?; fi ;;
    *) record "$id" FAIL "unknown exec.mode $mode" ""; return ;;
  esac
  printf '%s\n' "$rc" >"$raw/status"
  python3 "${here}/capture-exec.py" "$rc" "$raw/stdout" "$raw/stderr" --strip-path "$WORK" --strip-path "$xwork" --strip-path "$repo" --strip-path "$BIN" >"$raw/captured.json" 2>"$raw/capture.err" \
    || { record "$id" FAIL "capture-exec.py failed" "$(tail -c 300 "$raw/capture.err")"; return; }
  python3 "${here}/normalize.py" "$raw/captured.json" >"$OUT/cells/$safe.json" 2>"$raw/normalize.err" \
    || { record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; return; }
  record "$id" PASS "exit ${rc}; $(head -c 60 "$raw/stdout" | tr '\n' ' ')" ""
  n=$((n + 1))
}

# Metering posts write-behind (usage_flush_interval_ms) and the gauges are scrape-time derived, so an
# "after" snapshot taken at a fixed delay races the flush. Poll until two consecutive scrapes agree
# (a fixed point), bounded, then snapshot — deterministic on every binary, never "sleep and hope".
settle_then_snapshot() {  # <dir> <key-id>
  local d="$1" kid="$2" i=0 prev="" cur=""
  while [ $i -lt 20 ]; do
    cur="$(curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${kid}/usage" 2>/dev/null | jq -c 'del(.as_of)' 2>/dev/null)$(curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_TOKEN_OK}" "http://127.0.0.1:${LISTEN_PORT}/metrics" 2>/dev/null | grep -v '^#' | grep -v '_seconds' | sort | md5 2>/dev/null || true)"
    [ -n "$prev" ] && [ "$cur" = "$prev" ] && [ $i -ge 2 ] && break
    prev="$cur"; sleep 0.15; i=$((i+1))
  done
  snapshot "$d" "$kid"
}

# Bind the fixture placeholders to THIS boot: minted key ids, listen addresses, the work dir, the mock.
subst_placeholders() {  # <cell-json> -> cell-json
  jq -c --arg ok "$ORACLE_KEY_OK" --arg broke "$ORACLE_KEY_BROKE" --arg noscope "$ORACLE_KEY_NOSCOPE" \
        --arg tmp "$WORK/tmp" --arg work "$WORK" --arg la "127.0.0.1:${LISTEN_PORT}" --arg aa "127.0.0.1:${ADMIN_PORT}" \
        --arg mock "http://127.0.0.1:${MOCK_PORT}" --arg triple "$ORACLE_TRIPLE" \
        --rawfile b64_webrequest "$WORK/tmp/webrequest.b64" '
    def sub: if type == "string" then
        gsub("\\{KEY_OK\\}"; $ok) | gsub("\\{KEY_BROKE\\}"; $broke) | gsub("\\{KEY_NOSCOPE\\}"; $noscope)
        | gsub("\\{TMP\\}"; $tmp) | gsub("\\{WORK\\}"; $work) | gsub("\\{LISTEN_ADDR\\}"; $la)
        | gsub("\\{ADMIN_LISTEN_ADDR\\}"; $aa) | gsub("\\{MOCK_URL\\}"; $mock)
        | gsub("\\{TRIPLE\\}"; $triple) | gsub("\\{TARBALL_B64:webrequest-hook\\}"; $b64_webrequest)
      elif type == "array" then map(sub)
      elif type == "object" then with_entries(.value |= sub)
      else . end;
    sub' <<<"$1"
}
mkdir -p "$WORK/tmp"
# a plugin tarball as base64 is ~1.5 MB: far past the argv limit, so it rides in as a --rawfile
base64 <"$(bash "${here}/fetch-plugin.sh" webrequest-hook)" | tr -d '\n' >"$WORK/tmp/webrequest.b64"
case "$(uname -sm)" in "Darwin arm64") ORACLE_TRIPLE=aarch64-apple-darwin ;; "Darwin x86_64") ORACLE_TRIPLE=x86_64-apple-darwin ;; "Linux aarch64"|"Linux arm64") ORACLE_TRIPLE=aarch64-unknown-linux-gnu ;; *) ORACLE_TRIPLE=x86_64-unknown-linux-gnu ;; esac

run_pre_request() {  # <request-json {method,path,headers,body,auth,listener}> — unrecorded setup call
  local rq="$1" m pth lst tok port
  m="$(jq -r .method <<<"$rq")"; pth="$(jq -r .path <<<"$rq")"; lst="$(jq -r '.listener // "admin"' <<<"$rq")"
  case "$(jq -r '.auth // "admin"' <<<"$rq")" in admin) tok="$ORACLE_ADMIN_TOKEN" ;; broke) tok="$ORACLE_TOKEN_BROKE" ;; none) tok="" ;; *) tok="$ORACLE_TOKEN_OK" ;; esac
  port="$LISTEN_PORT"; [ "$lst" = admin ] && port="$ADMIN_PORT"
  local -a h=()
  while IFS= read -r kv; do h+=(-H "$kv"); done < <(jq -r '.headers // {} | to_entries[] | "\(.key): \(.value)"' <<<"$rq")
  [ -z "$tok" ] || h+=(-H "Authorization: Bearer ${tok}")
  local b; b="$(jq -r '.body // empty' <<<"$rq")"
  [ -z "$b" ] || h+=(-H "Content-Type: application/json")
  echo "pre $m $pth -> $(curl -sS -m 30 -o /dev/null -w '%{http_code}' -X "$m" "http://127.0.0.1:${port}${pth}" "${h[@]}" ${b:+--data-binary "$b"} 2>&1)"
}

# ── the cells ───────────────────────────────────────────────────────────────────────────────────
n=0
while IFS= read -r cell; do
  id="$(jq -r .id <<<"$cell")"
  [ -z "$FILTER" ] || [[ "$id" =~ $FILTER ]] || continue
  outcome="$(jq -r .outcome <<<"$cell")"
  safe="${id//|/__}"
  raw="$OUT/raw/$safe"; mkdir -p "$raw"
  driver="$(jq -r '.driver // "llm"' <<<"$cell")"
  if [ "$(jq -r '.needs_fixture // false' <<<"$cell")" = true ]; then
    record "$id" SKIP "UNSUPPORTED: $(jq -r .why <<<"$cell" | cut -c1-140)" "named gap: the fixture this cell needs is not in the tree yet"; continue
  fi
  case "$(jq -r .plane <<<"$cell")" in
    mcp|a2a) record "$id" SKIP "UNSUPPORTED: $(jq -r .plane <<<"$cell") is proven by its conformance rig, not recorded here" "named gap on the golden, never owed"; continue ;;
  esac
  if [ "$driver" = exec ]; then
    record_exec_cell "$id" "$cell" "$raw" "$safe"; continue
  fi

  if [ "$driver" = script ]; then
    # A named script owns the whole cell (its own processes on spare ports) and writes captured.json.
    sname="$(jq -r .script.name <<<"$cell")"
    local_args=(); while IFS= read -r a; do [ -n "$a" ] && local_args+=("$a"); done < <(jq -r '.script.args[]? // empty' <<<"$cell")
    stop_busbar   # a script cell never needs the recording busbar; free its ports and CPU
    BUSBAR_BIN="$BIN" RAW="$raw" WORK="$WORK" ORACLE_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" \
      bash "${here}/scripts/${sname}" "${local_args[@]}" >"$raw/script.log" 2>&1
    [ -s "$raw/captured.json" ] || { record "$id" FAIL "script ${sname} produced no captured.json" "$(tail -c 300 "$raw/script.log")"; continue; }
    python3 "${here}/normalize.py" "$raw/captured.json" >"$OUT/cells/$safe.json" 2>"$raw/normalize.err" \
      || { record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; continue; }
    st="$(jq -r .status "$raw/captured.json")"
    if [ "$st" = "-1" ]; then record "$id" SKIP "UNSUPPORTED: $(jq -r '.effects.error // "script could not run"' "$raw/captured.json")" "named gap"; continue; fi
    record "$id" PASS "script ${sname}: status ${st}" ""; n=$((n + 1)); continue
  fi

  # `fresh: true` — this cell must not see state (breaker, budgets) left by earlier cells.
  variant="$(jq -r '.config_variant // empty' <<<"$cell")"
  if [ "$FRESH_ALL" = 1 ] || [ "$(jq -r '.fresh // false' <<<"$cell")" = true ] || [ "$variant" != "$CUR_VARIANT" ]; then
    stop_busbar
    boot_busbar "$variant" || { record "$id" FAIL "fresh boot before cell failed (variant '${variant}')" "$(tr '\n' '|' <"$WORK/busbar.log" | tail -c 300)"; continue; }
  fi
  if [ "$driver" = http ]; then
    # An explicit request: {method, path, headers, body, auth: ok|broke|noscope|admin|none, listener,
    # pre: [requests run UNRECORDED first, same boot], repeat: N (record the LAST response)}.
    # Placeholders in path/headers/body are bound to this boot's values.
    cell="$(subst_placeholders "$cell")"
    while IFS= read -r pre; do
      [ -n "$pre" ] || continue
      run_pre_request "$pre" >>"$raw/pre.log" 2>&1
    done < <(jq -c '.request.pre[]? // empty' <<<"$cell")
    method="$(jq -r .request.method <<<"$cell")"; path="$(jq -r .request.path <<<"$cell")"
    listener="$(jq -r '.request.listener // "data"' <<<"$cell")"
    repeat="$(jq -r '.request.repeat // 1' <<<"$cell")"
    body_spec="$(jq -r '.request.body // empty' <<<"$cell")"
    case "$body_spec" in
      @oversize:*) python3 - "${body_spec#@oversize:}" >"$raw/request.body" <<'PY'
import sys
spec = sys.argv[1]
n = int(spec[:-3]) * 1024 * 1024 if spec.endswith("MiB") else int(spec)
sys.stdout.write('{"model":"m-openai-chat","messages":[{"role":"user","content":"' + "x" * n + '"}]}')
PY
        ;;
      "") : >"$raw/request.body" ;;
      *) printf '%s' "$body_spec" >"$raw/request.body" ;;
    esac
    case "$(jq -r '.request.auth // "ok"' <<<"$cell")" in
      broke) token="$ORACLE_TOKEN_BROKE"; kid="$ORACLE_KEY_BROKE" ;;
      noscope) token="$ORACLE_TOKEN_NOSCOPE"; kid="$ORACLE_KEY_NOSCOPE" ;;
      admin) token="$ORACLE_ADMIN_TOKEN"; kid="$ORACLE_KEY_OK" ;;
      none) token=""; kid="$ORACLE_KEY_OK" ;;
      *) token="$ORACLE_TOKEN_OK"; kid="$ORACLE_KEY_OK" ;;
    esac
    hdr_args=()
    while IFS= read -r kv; do hdr_args+=(-H "$kv"); done < <(jq -r '.request.headers // {} | to_entries[] | "\(.key): \(.value)"' <<<"$cell")
    [ -z "$token" ] || hdr_args+=(-H "Authorization: Bearer ${token}")
    [ -s "$raw/request.body" ] && hdr_args+=(-H "Content-Type: application/json")
    port="$LISTEN_PORT"; [ "$listener" = admin ] && port="$ADMIN_PORT"
    local_m=(-X "$method" --data-binary "@$raw/request.body"); [ "$method" = HEAD ] && local_m=(--head)
    mc="$(jq -c '.mock_control // empty' <<<"$cell")"
    [ -z "$mc" ] || [ "$mc" = "{}" ] || printf '%s' "$mc" >"$CONTROL"
    settle_then_snapshot "$raw/before" "$kid"
    k=1
    while [ "$k" -le "$repeat" ]; do
      status="$(curl -sS -m 30 -N "${local_m[@]}" "http://127.0.0.1:${port}${path}" "${hdr_args[@]}" \
        -D "$raw/headers" -o "$raw/body" -w '%{http_code}' 2>"$raw/curl.err")"; curl_rc=$?
      # a cut mid-body (18/56) still carries the status line and the bytes that arrived: that IS the response
      case "$curl_rc:$status" in 0:*|18:[1-5]??|56:[1-5]??) printf '%s\n' "$curl_rc" >"$raw/curl.rc" ;; *) status="000" ;; esac
      k=$((k+1))
    done
  else
  case "$outcome" in
    over_budget) sig_akid="$ORACLE_AWS_AKID_BROKE"; sig_secret="$ORACLE_AWS_SECRET_BROKE" ;;
    out_of_scope) sig_akid="$ORACLE_AWS_AKID_NOSCOPE"; sig_secret="$ORACLE_AWS_SECRET_NOSCOPE" ;;
    *) sig_akid="$ORACLE_AWS_AKID_OK"; sig_secret="$ORACLE_AWS_SECRET_OK" ;;
  esac
  req="$(ORACLE_AWS_AKID="$sig_akid" ORACLE_AWS_SECRET="$sig_secret" ORACLE_HOST="127.0.0.1:${LISTEN_PORT}" \
        python3 "${here}/build-request.py" --cell "$cell")" || { record "$id" FAIL "build-request failed" "$req"; continue; }
  auth="$(jq -r .auth <<<"$req")"
  case "$auth" in
    bearer|sigv4-signed) ;;
    *) record "$id" SKIP "UNSUPPORTED: $(jq -r .note <<<"$req")" "recorded as a named gap, not a pass"; continue ;;
  esac
  path="$(jq -r .path <<<"$req")"
  jq -j .body <<<"$req" >"$raw/request.body"

  case "$outcome" in
    over_budget) token="$ORACLE_TOKEN_BROKE"; kid="$ORACLE_KEY_BROKE" ;;
    out_of_scope) token="$ORACLE_TOKEN_NOSCOPE"; kid="$ORACLE_KEY_NOSCOPE" ;;
    unauthenticated) token=""; kid="$ORACLE_KEY_OK" ;;
    *) token="$ORACLE_TOKEN_OK"; kid="$ORACLE_KEY_OK" ;;
  esac

  hdr_args=()
  while IFS= read -r kv; do hdr_args+=(-H "$kv"); done < <(jq -r '.headers | to_entries[] | "\(.key): \(.value)"' <<<"$req")
  # a signed request already carries its Authorization (SigV4); a bearer cell gets the token here
  [ "$auth" = sigv4-signed ] || [ -z "$token" ] || hdr_args+=(-H "Authorization: Bearer ${token}")

  [ "$outcome" != upstream_down ] || echo down >"$CONTROL"
  settle_then_snapshot "$raw/before" "$kid"
  status="$(curl -sS -m 20 -N -X POST "http://127.0.0.1:${LISTEN_PORT}${path}" "${hdr_args[@]}" \
    --data-binary @"$raw/request.body" -D "$raw/headers" -o "$raw/body" -w '%{http_code}' 2>"$raw/curl.err")"; curl_rc=$?
  case "$curl_rc:$status" in 0:*|18:[1-5]??|56:[1-5]??) printf '%s\n' "$curl_rc" >"$raw/curl.rc" ;; *) status="000" ;; esac
  fi
  settle_then_snapshot "$raw/after" "$kid"
  rm -f "$CONTROL"
  printf '%s\n' "$status" >"$raw/status"
  printf '%s\n' "$kid" >"$raw/key-id"

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
done < <(jq -c --arg p "$PLANE" '.cells[] | select($p == "all" or .plane == $p)' "${here}/cells.json")

jq -n --arg ver "$VER" --arg bin "$BIN" --argjson recorded "$n" \
  '{binary: $bin, version: $ver, recorded: $recorded, at: (now | todate)}' >"$OUT/meta.json"
cp "$WORK/busbar.log" "$OUT/busbar.log" 2>/dev/null || true
cp "$WORK/mock.log" "$OUT/mock.log" 2>/dev/null || true

echo
echo "recorded ${n} cells for ${VER} -> ${OUT}"
[ "$n" -gt 0 ] || { echo "ZERO ROWS IS RED" >&2; exit 1; }
