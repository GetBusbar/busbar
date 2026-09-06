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
#   over_budget                                 -> the BROKE key (group `broke`: requests 1/day trips
#                                                   FIRST, so this is the requests-cap refusal)
#   over_budget_total                           -> the QUOTA key (group `broke-quota`: budget 1/day is
#                                                   the ONLY cap, so this is the group's own budget-cap
#                                                   refusal — the arm the Anthropic writer projects as
#                                                   `billing_error` rather than `rate_limit_error`)
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

# A RECORDING MAY NOT DEPEND ON WHERE IT WAS STARTED FROM. Some cells carry a REPO-RELATIVE path in
# their own argv — every `config.migrate|*` cell runs `--migrate-config
# tests/migration-corpus/from-tags/<v>_config.yaml` — so the binary resolved it against whatever
# directory the operator happened to be in. Recorded from testing/shadow-oracle instead of the repo
# root, all 78 of those cells recorded `busbar: cannot read '...': No such file or directory` with
# exit 1 and the ledger said PASS for every one of them (their `why` accepts exit 0/1/2), i.e. a
# golden re-recorded from the wrong directory is quietly a golden of the file-not-found path. The
# effects.files class has the same exposure: capture.py watches THE PROCESS'S WORKING DIRECTORY.
# So: absolutize the two paths the caller gave us and record from the repo root, always. (The
# absolutize also makes a relative --out/--bin safe everywhere downstream, which the script-cell
# path already had to re-derive for itself.)
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
cd "$repo" || { echo "record.sh: cannot cd to the repo root $repo" >&2; exit 2; }

mkdir -p "$OUT/cells" "$OUT/raw"
LEDGER="$OUT/ledger.tsv"; : >"$LEDGER"; export LEDGER
# AN UNCHECKED `mktemp -d` POINTS THE WHOLE RUN AT `/`. Every path below is built as "$WORK/…", so a
# mktemp that failed (a full or read-only temp filesystem, a TMPDIR that does not exist) left WORK
# empty and the run went on writing "/config.yaml", "/egress", "/mock.control" — and `rm -rf "$WORK"`
# in the cleanup trap became `rm -rf /`. Checked, and checked to be a directory we can write.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/shadow-oracle-record.XXXXXX")" \
  || { echo "record.sh: could not create a work directory under ${TMPDIR:-/tmp}" >&2; exit 2; }
[ -n "$WORK" ] && [ -d "$WORK" ] && [ -w "$WORK" ] \
  || { echo "record.sh: mktemp -d gave no usable work directory (got '${WORK}')" >&2; exit 2; }
export WORK
# WORK holds a config, a signing key, the egress captures and every cell's scratch — tens of MB per
# run, and a full recording is ~900 cells. Nothing removed it, so every run (and every run that died
# in its preamble) left one behind until the machine was rebooted. lib.sh has already installed
# `trap _reap_fixtures EXIT`; replacing that trap outright would strand every busbar and mock this
# script spawned, so the reaper is called FIRST and the tree goes only once nothing is writing to it.
# ORACLE_KEEP_WORK=1 keeps it, for the forensics the `raw/` tree cannot answer (busbar.log mid-run,
# the mock's control file, a half-written mutation config).
_oracle_cleanup() {
  _reap_fixtures
  [ "${ORACLE_KEEP_WORK:-0}" = 1 ] || rm -rf "$WORK"
}
trap _oracle_cleanup EXIT

# ── A RECORDING MAY NOT DEPEND ON THE ORDER ITS CELLS RAN IN ────────────────────────────────────
# busbar sweeps orphaned plugin staging directories at boot: `busbar_plugin_loader::sweep_dead_staging`
# walks `std::env::temp_dir()` (i.e. `$TMPDIR`) for `busbar-plugins-<pid>-<random>` directories whose
# owning pid is DEAD, removes them, and — only when it removed at least one — prints
#
#     [info] removed N orphaned plugin staging dir(s) left by a crashed prior run
#
# on stdout. That is correct behaviour for an operator and poison for a golden: THIS recorder kills
# busbars on purpose (every `fresh` cell reboots, script cells stop the recording busbar,
# store-persist kills its first busbar by design), so a plugin-loading boot that is killed leaves a
# staging directory behind and WHICHEVER BOOT COMES NEXT prints the line — a different cell on every
# run (documented|readme|tls-mtls, neutrality|boot-lines, documented|readme|docker-defaults,
# documented|changelog|admin-restart have all been seen wearing it). One random boot-log cell per full
# `--plane all` run carried an extra line that says nothing about the binary and everything about
# which cell happened to run before it.
#
# BOTH HALVES, and each closes a different hole — this is deliberately not one-or-the-other:
#
#   (1) A PRIVATE PER-RUN TMPDIR. busbar is pointed at a temp base this run owns, so it can never see
#       a staging directory left by a PARALLEL recording, by an earlier run of this script, by the
#       test suite, or by any other busbar on the machine. Cross-RUN and cross-PROCESS contamination
#       goes away by construction rather than by racing it. It is inside $WORK, so the existing
#       cleanup already removes it and the existing `--strip-path "$WORK"` already scrubs any path
#       that reaches a capture.
#   (2) A DEAD-PID SWEEP BEFORE EVERY BOOT. (1) alone does NOT fix this: the directories that cause
#       the line are made by THIS run's own busbars, inside this run's own TMPDIR. So the harness
#       sweeps them itself, before each boot, and busbar's own sweep then always finds nothing and
#       stays silent. The sweep lives HERE, in the harness, never in busbar: busbar's boot-time
#       sweep is a documented behaviour the oracle exists to record, and a recorder that needed the
#       binary changed to be recordable would be recording the harness.
#
# Dead pids only, exactly like busbar's own sweep: a live busbar's staging directory is in use (the
# recording busbar is still up while an exec `boot` cell spawns a second one), and removing it would
# manufacture a failure this cell is not about.
export TMPDIR="$WORK/tmp"
mkdir -p "$TMPDIR"
sweep_orphan_staging() {  # remove busbar-plugins-<dead pid>-* under this run's private TMPDIR
  local d pid
  for d in "$TMPDIR"/busbar-plugins-*; do
    # a glob that matched nothing expands to itself; a symlink is not a staging dir (never followed)
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    pid="${d##*/busbar-plugins-}"; pid="${pid%%-*}"
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    kill -0 "$pid" 2>/dev/null && continue
    rm -rf "$d"
  done
}

export BUSBAR_BIN="$BIN"
declaw "$BIN"
VER="$("$BIN" --version 2>/dev/null | head -1)"
CONTROL="$WORK/mock.control"

fail_setup() { record "setup" FAIL "$1" "${2:-}"; exit 1; }

# exec and script cells do not boot the recording busbar, so nothing on their path rewrites
# "$WORK/config.yaml" — they read whatever variant the LAST http/llm cell's boot happened to leave
# there. Under `--plane all` the ordering makes that the baseline already, but under `--filter` a
# hooks/queue-timeout/inbound-concurrency-2 cell can strand its config on disk and every later
# `exec.config: baseline` / `mutation:` cell is then recorded against THAT config (a mutation
# applied to the wrong baseline is a different cell). Called before any such cell reads the file.
ensure_baseline_config() {
  [ -n "${DISK_VARIANT:-}" ] || return 0
  ORACLE_VARIANT="" oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || return 1
  DISK_VARIANT=""
}

# ── port ownership: the ONLY evidence that what answers is what we started ───────────────────────
# This script has no `set -e`, so an unchecked `assert_port_free` is a no-op — and every readiness
# probe below is a bare HTTP answer, which a stale busbar or a parallel recording on the same port
# gives just as cheerfully as ours. A recording made against someone else's process is not a
# recording of the binary under test; it is a green that hides whatever the binary actually does.
# So: prove the port free BEFORE the spawn, and prove the listener afterwards is OUR pid.
port_owner_pid() {  # <port> -> the pid listening on <port>, or nothing if it cannot be determined
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | head -1
  elif command -v ss >/dev/null 2>&1; then
    ss -lntpH "sport = :$1" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1
  fi
}
assert_port_is_ours() {  # <port> <pid> — 0 iff <pid> is alive and owns the listener on <port>
  local port="$1" pid="$2" owner
  [ -n "$pid" ] || return 1
  # a dead pid can never be the owner, whatever is answering on the port
  kill -0 "$pid" 2>/dev/null || return 1
  owner="$(port_owner_pid "$port")"
  # No inspector on this host (no lsof, no ss): fall back to `kill -0` plus the fact that the port
  # was PROVEN FREE immediately before the spawn — every caller below establishes that first.
  [ -n "$owner" ] || return 0
  [ "$owner" = "$pid" ]
}
assert_ports_free_or_fail() {  # <port>... — a busy port is a setup failure, never a recording
  local p
  for p in "$@"; do
    assert_port_free "$p" || fail_setup "port ${p} is already in use" \
      "another recording, a stale busbar or a foreign service is listening on 127.0.0.1:${p}; adopting it would record that process instead of ${BIN} — choose free ORACLE_LISTEN_PORT/ORACLE_ADMIN_PORT/ORACLE_MOCK_PORT"
  done
}
assert_ports_free_or_fail "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT"

# Spare listeners for exec `boot` cells: those start a SECOND busbar, which must not collide with the
# recording's own. Derived from the same ORACLE_* knobs rather than hardcoded, or two recordings on
# deliberately different ports still fight over one fixed pair (48821/48822) and each adopts the
# other's process. The defaults are unchanged (48811+10 / 48812+10), so the golden does not move.
BOOT_LISTEN_PORT="${ORACLE_BOOT_LISTEN_PORT:-$((LISTEN_PORT + 10))}"
BOOT_ADMIN_PORT="${ORACLE_BOOT_ADMIN_PORT:-$((ADMIN_PORT + 10))}"
# A caller is free to choose ORACLE_* values that land the derived pair on a port this run already
# owns (script cells take ADMIN_PORT+1 for their mock); step the pair by two until it does not.
_boot_port_reserved() {  # <port>
  case " ${LISTEN_PORT} ${ADMIN_PORT} ${MOCK_PORT} $((ADMIN_PORT + 1)) " in *" $1 "*) return 0 ;; esac
  return 1
}
_bp=0
while [ "$_bp" -lt 200 ] && { _boot_port_reserved "$BOOT_LISTEN_PORT" || _boot_port_reserved "$BOOT_ADMIN_PORT" \
        || [ "$BOOT_LISTEN_PORT" = "$BOOT_ADMIN_PORT" ]; }; do
  BOOT_LISTEN_PORT=$((BOOT_LISTEN_PORT + 2)); BOOT_ADMIN_PORT=$((BOOT_ADMIN_PORT + 2)); _bp=$((_bp + 1))
done
unset _bp

# ── mock upstream (all six dialects, byte-deterministic) ────────────────────────────────────────
mkdir -p "$WORK/egress"
# the mock records every request it receives (path, method, headers, body) so the EGRESS side of a
# cell is judged too, not only what came back
ORACLE_MOCK_CAPTURE_DIR="$WORK/egress" python3 "${here}/mock-upstream.py" "$MOCK_PORT" oracle-marker "$CONTROL" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
track_pid "$MOCK_PID"
wait_for_http "http://127.0.0.1:${MOCK_PORT}/" 8 || fail_setup "mock upstream did not come up" "$(tail -c 300 "$WORK/mock.log")"
# a FOREIGN mock answering here would take every egress request and ignore $CONTROL — which this run
# cannot write into its work dir — so `upstream_down` cells would record a healthy upstream.
assert_port_is_ours "$MOCK_PORT" "$MOCK_PID" \
  || fail_setup "the process answering on mock port ${MOCK_PORT} is not the mock this run started" \
                "expected pid ${MOCK_PID}, port owned by '$(port_owner_pid "$MOCK_PORT")'; its control file (${CONTROL}) would be ignored"

# ── busbar under the oracle config ──────────────────────────────────────────────────────────────
oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || fail_setup "oracle config could not be written"
oracle_env "$BIN" --validate >"$WORK/validate.log" 2>&1 || fail_setup "busbar rejected the oracle config (run selftest.sh)" "$(tail -c 400 "$WORK/validate.log")"
# The hooks variant loads the published first-party plugins, which a candidate can only verify with
# the release public key embedded at build time (BUSBAR_RELEASE_PUBKEY). A binary built without it
# refuses every hooks-variant boot, so that is judged ONCE here instead of as 29 failed cells.
if ORACLE_VARIANT=hooks oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" 2>/dev/null; then
  oracle_env "$BIN" --validate >"$WORK/validate-hooks.log" 2>&1 \
    || fail_setup "busbar rejected the hooks-variant config: a candidate must be built with BUSBAR_RELEASE_PUBKEY exported (see plugin-sign)" "$(tail -c 400 "$WORK/validate-hooks.log")"
  oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || fail_setup "oracle config could not be written"
fi

# DISK_VARIANT is the variant the config FILE currently on disk was written for — a property of
# "$WORK/config.yaml", not of any process. "is a busbar running" is BUSBAR_PID, and only that; the
# two must never be conflated (see stop_busbar).
BUSBAR_PID="" DISK_VARIANT=""
boot_busbar() {  # [variant] start busbar, wait for /healthz, mint the three keys, prime the BROKE key
  local variant="${1:-}"
  if [ "$variant" != "$DISK_VARIANT" ]; then
    ORACLE_VARIANT="$variant" oracle_write_config "$WORK" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || return 3
    DISK_VARIANT="$variant"
  fi
  # PROVE THE PORTS FREE IMMEDIATELY BEFORE THE SPAWN. Without this the /healthz poll below adopts
  # whatever answers first — including a busbar left behind by a crashed run — and every cell after
  # it is recorded against a process this script never started and cannot configure.
  assert_port_free "$LISTEN_PORT" || return 4
  assert_port_free "$ADMIN_PORT" || return 4
  # BEFORE THE SPAWN, not after: what busbar prints at boot is decided by what it finds when it
  # boots. A staging dir left by the busbar this cell's `stop_busbar` just killed would otherwise be
  # swept BY BUSBAR, and this cell's boot log would carry an extra line the previous cell caused.
  sweep_orphan_staging
  BUSBAR_PID="$(oracle_spawn "$WORK/busbar.log" "$BIN")"; track_pid "$BUSBAR_PID"
  # busbar boots in tens of ms; poll at 25 ms (the shared wait_for_http sleeps a whole second).
  # The bound is ORACLE_BOOT_BOUND_SECS (default 60), not 20: a hooks-variant boot loads the
  # published plugins, and on a machine running a test suite beside the recording that took longer
  # than 20 s and read as a failed cell. ONE KNOB: scripts/store-persist.sh does its own real double
  # boot of a published store plugin and reads this SAME env var, so a host slow enough to blow one
  # bound blows both consistently instead of the harness inventing a second, independently-drifting
  # hard-code.
  local boot_bound="${ORACLE_BOOT_BOUND_SECS:-60}" w_max
  w_max=$(( boot_bound * 40 ))  # 40 polls/sec at the 25ms step below
  local w=0; while [ $w -lt "$w_max" ]; do
    curl -fsS -m 1 -o /dev/null "http://127.0.0.1:${LISTEN_PORT}/healthz" 2>/dev/null && break
    kill -0 "$BUSBAR_PID" 2>/dev/null || return 1
    sleep 0.025; w=$((w+1))
  done
  [ $w -lt "$w_max" ] || return 1
  # /healthz answered — but by WHOM. Both listeners must be held by the pid we just spawned.
  assert_port_is_ours "$LISTEN_PORT" "$BUSBAR_PID" || return 4
  assert_port_is_ours "$ADMIN_PORT" "$BUSBAR_PID" || return 4
  oracle_mint_keys "$ADMIN_PORT" || return 2
  # PRIME the BROKE key: its group admits exactly one request per day, so one un-recorded request
  # now makes every over_budget cell a real 429 at Admit (the first request would be admitted).
  # PRIME the QUOTA key too: group `broke-quota` carries only a budget cap (no requests cap), so one
  # un-recorded request exhausts that TOTAL and every over_budget_total cell is a real 429 at Admit
  # with metric: budget, not metric: requests.
  #
  # THE PRIMING IS THE CELL'S PRECONDITION, SO IT IS ASSERTED. `|| true` made the ONE request that
  # exhausts each cap optional: if it never landed (a connection reset in the boot window, a mock
  # blip, a 500) the cap was still intact and every `over_budget` / `over_budget_total` cell that
  # followed recorded a cheerful 200 instead of the 429 it exists to pin — a whole refusal family
  # silently re-recorded as the success path, on both binaries, agreeing with each other. An
  # admitted request is a 2xx; anything else (including curl's own 000) means the cap was not
  # exhausted and this boot cannot serve those cells.
  local pk pcode
  for pk in "$ORACLE_TOKEN_BROKE" "$ORACLE_TOKEN_QUOTA"; do
    pcode="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
      -H "Authorization: Bearer ${pk}" -H "Content-Type: application/json" \
      -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"prime"}]}' 2>/dev/null || echo 000)"
    case "$pcode" in 2??) ;; *) PRIME_CODE="$pcode"; return 5 ;; esac
  done
}
stop_busbar() {  # stop the current busbar and wait until BOTH its ports are free again
  [ -n "$BUSBAR_PID" ] || return 0
  local dead="$BUSBAR_PID"
  kill "$dead" 2>/dev/null || true; wait "$dead" 2>/dev/null || true; BUSBAR_PID=""
  # DO NOT clear DISK_VARIANT here. Stopping a process does not rewrite a file: the config still on
  # disk is still the one this busbar was booted under, and DISK_VARIANT is the only record of which
  # variant that is. Clearing it made the baseline variant (the empty string) indistinguishable from
  # "unknown", so the next `boot_busbar ""` saw ""=="" and SKIPPED oracle_write_config — every
  # baseline cell after the first hooks/queue-timeout/inbound-concurrency-2 cell then booted, and was
  # recorded against, the leftover variant config. "Is a busbar running" is BUSBAR_PID, cleared just
  # above, and the per-cell guard below reboots on it.
  # Wait for the PID to be reaped AND for both listeners to go: handing only the data port to a
  # script cell (which takes LISTEN_PORT *and* ADMIN_PORT) leaves it racing the admin socket's close,
  # and its own assert_port_free then reports "port busy" for a process that is already exiting.
  local i=0
  while [ $i -lt 100 ]; do
    kill -0 "$dead" 2>/dev/null || { assert_port_free "$LISTEN_PORT" && assert_port_free "$ADMIN_PORT" && break; }
    sleep 0.1; i=$((i+1))
  done
  # a port still answering after the kill means the OLD process survived: refuse to continue on it
  local p
  for p in "$LISTEN_PORT" "$ADMIN_PORT"; do
    assert_port_free "$p" || { echo "record.sh: port ${p} still answers after stopping busbar ${dead}; refusing to record against a stale process" >&2; exit 1; }
  done
}
boot_busbar; rc=$?
case "$rc" in
  0) ;;
  1) fail_setup "busbar (${VER}) did not come up" "$(tr '\n' '|' <"$WORK/busbar.log" | tail -c 500)" ;;
  4) fail_setup "the listeners on ${LISTEN_PORT}/${ADMIN_PORT} are not the busbar this run spawned" \
       "pid ${BUSBAR_PID:-?} vs port owners '$(port_owner_pid "$LISTEN_PORT")'/'$(port_owner_pid "$ADMIN_PORT")'; refusing to record a foreign process as ${BIN}" ;;
  5) fail_setup "the over-budget priming request was not admitted (HTTP ${PRIME_CODE:-?})" \
       "the broke/broke-quota caps are therefore intact, and every over_budget cell would record a 200 where the refusal belongs" ;;
  *) fail_setup "could not mint the three oracle keys" "admin API on ${ADMIN_PORT}; see $WORK/busbar.log" ;;
esac

# ── effect snapshots ────────────────────────────────────────────────────────────────────────────
snapshot() {  # snapshot <dir> <key-id>
  local d="$1" kid="$2"; mkdir -p "$d"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${kid}/usage" -o "$d/usage.json" 2>/dev/null || rm -f "$d/usage.json"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/audit?limit=1000" -o "$d/audit.json" 2>/dev/null || rm -f "$d/audit.json"
  # /metrics on the data listener is key-authed in 1.5.5 (RouteAuth::Key): present the OK client key.
  oracle_scrape_metrics "$LISTEN_PORT" "$ORACLE_TOKEN_OK" "$d/metrics.txt" || true
}

# The providers catalog a migrated corpus config should be validated against — mirrors `providers_for`
# in crates/busbar/tests/migration_corpus.rs so a corpus config is judged against the catalog it
# actually shipped beside: `bench/latency/config.mock.yaml` names a `mock` provider that exists only
# in `bench/latency/providers.mock.yaml`, and the oracle's own synthetic six-dialect catalog (see
# oracle-config.sh) knows no such name — validating against it would report a true statement about the
# wrong pairing, not a migration defect. Prints an absolute path, or nothing if no sibling exists (the
# caller then falls back to the oracle's own catalog, which is correct for a plain `config.yaml`).
corpus_providers_for() {  # <repo-relative corpus config path>
  local relpath="$1" name tag rest sibling dir candidate f
  name="$(basename "$relpath")"
  tag="${name%%_*}"; rest="${name#*_}"
  dir="${repo}/tests/migration-corpus/providers"
  sibling="${rest/config/providers}"  # first occurrence only, keeps a `.mock`/`.anthropic` suffix
  candidate="${dir}/${tag}_${sibling}"
  if [ -f "$candidate" ]; then echo "$candidate"; return; fi
  for f in "$dir"/*"$sibling"; do [ -f "$f" ] && { echo "$f"; return; }; done
}

# ── exec cells: CLI flags, --validate, --migrate-config, boot refusals/warnings ──────────────────
# The process under test is the binary itself; the "response" is exit code + stdout + stderr.
#   exec.mode     cli       run once with exec.args, capture, done
#                 validate  run `--validate` (args) under the oracle env against exec.config
#                 boot      start the process; a refusal exits; a warning boots — wait for /healthz on
#                           spare ports, then stop; capture the log tail
#   exec.config   baseline | none | missing | migrated:<corpus-path> | mutation:<id> (fixtures/boot-mutations.json)
record_exec_cell() {  # <id> <cell-json> <raw-dir> <safe>
  local id="$1" cell="$2" raw="$3" safe="$4" mode cfg cfgfile envkv rc corpus_prov
  mode="$(jq -r '.exec.mode' <<<"$cell")"; cfg="$(jq -r '.exec.config // "baseline"' <<<"$cell")"
  # An exec cell's contract can ALSO be "what is NOT there" (`body_lines`) or "keep this one value
  # raw" (`keep`) — the same two opt-ins the http path already honors — so a boot-log cell can pin
  # only the INFO-and-above lines instead of every DEBUG line a level bump might add.
  local xkeep_lines xkeep_spec
  xkeep_lines="$(jq -r '.body_lines // empty' <<<"$cell")"
  xkeep_spec="$(jq -c '.keep // empty' <<<"$cell")"
  local -a args=() envs=()
  while IFS= read -r a; do args+=("$a"); done < <(jq -r '.exec.args[]' <<<"$cell")
  while IFS= read -r envkv; do [ -n "$envkv" ] && envs+=("$envkv"); done < <(jq -r '.exec.env // {} | to_entries[] | "\(.key)=\(.value)"' <<<"$cell")
  local xwork="$raw/work"; mkdir -p "$xwork"
  case "$cfg" in
    baseline) ensure_baseline_config || { record "$id" FAIL "could not restore the baseline oracle config" ""; return; }
      cfgfile="$WORK/config.yaml" ;;
    none) cfgfile="" ;;
    missing) cfgfile="$xwork/does-not-exist.yaml" ;;
    migrated:*) # the corpus file migrated by THIS binary, then validated against ITS OWN catalog.
      # `--migrate-config` alone is not enough: mirrors apply_deferred_decisions()/validate() in
      # crates/busbar/tests/migration_corpus.rs — supply the two decisions a migrator explicitly
      # refuses to invent (an admin-tokens credential when auth.chain names `keys`, a signing key
      # when the migrator left a TODO for it), stand in a real file for any genuine `file:` secret
      # ref the migrated document still carries (e.g. v1.5.1/v1.5.2 ship one already), and stub every
      # `env:NAME` secret ref so --validate fails on the migration, never on this machine's env.
      "$BIN" --migrate-config "${repo}/${cfg#migrated:}" >"$xwork/migrated.yaml" 2>/dev/null
      python3 "${here}/scripts/apply-deferred-decisions.py" "$xwork/migrated.yaml" \
        --stand-in "$xwork/corpus-secret" >"$xwork/migrated-ready.yaml"
      cfgfile="$xwork/migrated-ready.yaml"
      corpus_prov="$(corpus_providers_for "${cfg#migrated:}")"
      [ -n "$corpus_prov" ] && cp "$corpus_prov" "$xwork/providers.yaml"
      while IFS= read -r envname; do
        [ -n "$envname" ] && envs+=("${envname}=$(printf 'a%.0s' {1..64})")
      done < <(grep -o 'env:[[:space:]]*[A-Za-z0-9_]\+' "$cfgfile" | sed -E 's/env:[[:space:]]*//' | sort -u) ;;
    mutation:*) ensure_baseline_config || { record "$id" FAIL "could not restore the baseline oracle config" ""; return; }
      python3 "${here}/apply-mutation.py" --baseline "$WORK/config.yaml" --providers "$WORK/providers.yaml" \
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
      # a boot cell must not collide with the recording busbar: rewrite the listen ports onto THIS
      # run's derived spare pair (see BOOT_LISTEN_PORT/BOOT_ADMIN_PORT above), never a fixed one
      python3 - "$cfgfile" "$xwork/boot.yaml" "$BOOT_LISTEN_PORT" "$BOOT_ADMIN_PORT" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
s=re.sub(r'^listen: .*$', 'listen: "127.0.0.1:%s"' % sys.argv[3], s, flags=re.M)
s=re.sub(r'^admin_listen: .*$', 'admin_listen: "127.0.0.1:%s"' % sys.argv[4], s, flags=re.M)
open(sys.argv[2],'w').write(s)
PY
      # The spare port must be PROVEN FREE before the spawn: otherwise the /healthz poll below reads
      # somebody else's answer as "this cell's busbar came up degraded-but-serving" and records a pass
      # for a process that never started.
      assert_port_free "$BOOT_LISTEN_PORT" \
        || { record "$id" FAIL "boot-cell port ${BOOT_LISTEN_PORT} is already in use" \
               "owner pid '$(port_owner_pid "$BOOT_LISTEN_PORT")'; set ORACLE_BOOT_LISTEN_PORT/ORACLE_BOOT_ADMIN_PORT"; return; }
      envcmd+=(BUSBAR_CONFIG="$xwork/boot.yaml")
      # A boot cell's contract IS its stdout (neutrality|boot-lines pins the exact ordered set of
      # INFO-and-above lines), so it is the loudest victim of a staging dir some earlier cell's
      # killed busbar left behind: sweep it before this boot, exactly as boot_busbar does.
      sweep_orphan_staging
      "${envcmd[@]}" "$BIN" "${args[@]}" >"$raw/stdout" 2>"$raw/stderr" </dev/null &
      local bpid=$! i=0 healthy=0
      while [ $i -lt 100 ]; do
        if ! kill -0 "$bpid" 2>/dev/null; then break; fi
        if curl -fsS -m 1 -o /dev/null "http://127.0.0.1:${BOOT_LISTEN_PORT}/healthz" 2>/dev/null; then
          # answered — but only OUR pid holding the listener makes that this cell's evidence
          if assert_port_is_ours "$BOOT_LISTEN_PORT" "$bpid"; then healthy=1; else healthy=2; fi
          break
        fi
        sleep 0.1; i=$((i+1))
      done
      if [ "$healthy" -eq 2 ]; then
        kill -9 "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null
        record "$id" FAIL "the listener on ${BOOT_LISTEN_PORT} is not this cell's busbar" \
          "expected pid ${bpid}, port owned by '$(port_owner_pid "$BOOT_LISTEN_PORT")'"
        return
      fi
      if [ "$healthy" -eq 1 ]; then
        # a real warning-boot: /healthz answered on the data listener, so busbar came up degraded-but-
        # serving. That IS the "alive" contract for this cell family — stop it and record a pass.
        kill "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null; rc=0
      elif kill -0 "$bpid" 2>/dev/null; then
        # still running after the whole wait window, but /healthz never answered: this is a HANG, not
        # a boot. Recording rc=0 here would let a stuck process pass as a warning-boot; use a distinct,
        # unmistakable status (the `timeout`(1) convention) so it never looks like the 0 above.
        kill -9 "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null; rc=124
      else
        # the process exited on its own (a refusal) — its own exit code is the cell's contract
        wait "$bpid"; rc=$?
      fi ;;
    *) record "$id" FAIL "unknown exec.mode $mode" ""; return ;;
  esac
  printf '%s\n' "$rc" >"$raw/status"
  python3 "${here}/capture-exec.py" "$rc" "$raw/stdout" "$raw/stderr" --strip-path "$WORK" --strip-path "$xwork" --strip-path "$repo" --strip-path "$BIN" >"$raw/captured.json" 2>"$raw/capture.err" \
    || { record "$id" FAIL "capture-exec.py failed" "$(tail -c 300 "$raw/capture.err")"; return; }
  python3 "${here}/normalize.py" "$raw/captured.json" ${xkeep_lines:+--keep-body-lines "$xkeep_lines"} ${xkeep_spec:+--keep "$xkeep_spec"} >"$OUT/cells/$safe.json" 2>"$raw/normalize.err" \
    || { record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; return; }
  record "$id" PASS "exit ${rc}; $(head -c 60 "$raw/stdout" | tr '\n' ' ')" ""
  n=$((n + 1))
}

# Metering posts write-behind (usage_flush_interval_ms) and the gauges are scrape-time derived, so an
# "after" snapshot taken at a fixed delay races the flush. Poll until two consecutive scrapes agree
# (a fixed point), bounded, then snapshot — deterministic on every binary, never "sleep and hope".

# A portable content digest for the settle fixed point. `md5`(1) is macOS-only: on Linux the old
# `... | md5 2>/dev/null || true` printed NOTHING and the `|| true` swallowed the missing command, so
# half of the fixed point (the metrics half) was the empty string on every Linux run — the loop then
# settled on the usage view alone and snapshotted before metrics had caught up. No `|| true` here:
# if no digest tool exists at all the caller must see it, not silently lose the metrics half.
_digest() {  # stdin -> one hex digest line
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
  fi
}
settle_then_snapshot() {  # <dir> <key-id>
  local d="$1" kid="$2" i=0 prev="" cur=""
  while [ $i -lt 20 ]; do
    cur="$(curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${kid}/usage" 2>/dev/null | jq -c 'del(.as_of)' 2>/dev/null)$(curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_TOKEN_OK}" "http://127.0.0.1:${LISTEN_PORT}/metrics" 2>/dev/null | grep -v '^#' | grep -v '_seconds' | sort | _digest)"
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
#
# AN EMPTY FILE HERE IS AN EMPTY TARBALL IN EVERY CELL THAT UPLOADS ONE. `base64 <"$(fetch-plugin.sh
# …)"` was unchecked from end to end: a fetch that failed printed its reason on stderr and NOTHING on
# stdout, so the redirect was from the empty filename, base64 read nothing, and webrequest.b64 was
# written EMPTY — every `{TARBALL_B64:webrequest-hook}` cell then POSTed a zero-byte tarball and
# recorded busbar's answer to THAT as the plugin-install contract. Both binaries would agree, and
# the golden would freeze "busbar rejects an empty upload" in place of "busbar installs a published
# plugin". A plugin the recorder could not fetch is a setup failure, not a cell.
_webrequest_tarball="$(bash "${here}/fetch-plugin.sh" webrequest-hook)" \
  || fail_setup "the published webrequest-hook plugin could not be fetched" \
       "every {TARBALL_B64:webrequest-hook} cell would upload an empty tarball and record the refusal as the contract"
[ -n "$_webrequest_tarball" ] && [ -s "$_webrequest_tarball" ] \
  || fail_setup "fetch-plugin.sh named no webrequest-hook tarball (or an empty one): '${_webrequest_tarball}'" \
       "refusing to record an empty upload as the plugin-install contract"
base64 <"$_webrequest_tarball" | tr -d '\n' >"$WORK/tmp/webrequest.b64"
[ -s "$WORK/tmp/webrequest.b64" ] \
  || fail_setup "the webrequest-hook tarball encoded to nothing" "base64 of ${_webrequest_tarball} produced an empty file"
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
  # A `pre` IS THE CELL'S SETUP, AND IT WAS NEVER CHECKED. The status was printed into pre.log and
  # the caller ignored it, so a `pre` that never reached busbar at all (curl's own "000": connection
  # refused, a timeout, a boot window that had not opened yet) left the cell recording the UNPREPARED
  # state — a breaker that was never tripped, a hook that was never registered, a key that was never
  # rotated — as if that were the contract. Both binaries then agree on the wrong cell.
  #
  # The bar is deliberately "busbar ANSWERED", not "the answer was 2xx": several cells prime state
  # with a request that is SUPPOSED to be refused (a 5xx from a downed upstream is how the failover
  # family trips its breaker), and demanding success there would refuse cells that are working. What
  # can never be right is no answer at all.
  local code
  code="$(curl -sS -m 30 -o /dev/null -w '%{http_code}' -X "$m" "http://127.0.0.1:${port}${pth}" "${h[@]}" ${b:+--data-binary "$b"} 2>&1)"
  echo "pre $m $pth -> $code"
  case "$code" in [1-5]??) return 0 ;; *) return 1 ;; esac
}

run_readback() {  # <request-json {path,headers,auth,listener}> <write-response-body-file> <key-id>
  # A mutating cell's `request.post`: a follow-up GET at the resource the write just touched, run
  # AFTER the after-effects snapshot (so it never pollutes the write's own usage/metrics/audit delta)
  # and normalized the same way any response is, so its bytes are as comparable as the write's own.
  # `{RESP:/pointer}` in the path is filled in from the write's OWN captured response body (e.g. the
  # id/name a POST just minted) — see fixtures/admin-readback.json for the kind vocabulary.
  local rq="$1" respfile="$2" kid="$3" pth ptr val tok port rbody rstatus cap normd
  pth="$(jq -r .path <<<"$rq")"
  if [[ "$pth" == *'{RESP:'* ]]; then
    ptr="${pth#*\{RESP:}"; ptr="${ptr%%\}*}"
    val="$(jq -r --arg p "$ptr" 'try getpath($p | ltrimstr("/") | split("/")) catch empty' "$respfile" 2>/dev/null)"
    pth="$(python3 -c 'import re,sys; print(re.sub(r"\{RESP:[^}]*\}", sys.argv[1], sys.argv[2]))' "$val" "$pth")"
  fi
  case "$(jq -r '.auth // "admin"' <<<"$rq")" in admin) tok="$ORACLE_ADMIN_TOKEN" ;; none) tok="" ;; *) tok="$ORACLE_TOKEN_OK" ;; esac
  port="$LISTEN_PORT"; [ "$(jq -r '.listener // "admin"' <<<"$rq")" = admin ] && port="$ADMIN_PORT"
  local -a h=()
  while IFS= read -r kv; do h+=(-H "$kv"); done < <(jq -r '.headers // {} | to_entries[] | "\(.key): \(.value)"' <<<"$rq")
  [ -z "$tok" ] || h+=(-H "Authorization: Bearer ${tok}")
  rbody="$(mktemp "$raw/readback.XXXXXX")"
  rstatus="$(curl -sS -m 10 -X GET "http://127.0.0.1:${port}${pth}" "${h[@]}" -o "$rbody" -w '%{http_code}' 2>/dev/null)"
  # curl's own "no HTTP response" placeholder is the 3-digit literal "000": it PASSES a [0-9]+ test
  # but is not a valid JSON number (leading zero), so `--argjson` below rejected it, normalize.py
  # then read an empty document and died, and the old fallback wrote a synthetic
  # {"status":0,"body":{"text":""}} into effects.readback as though the readback had answered it.
  # Golden and candidate produce the SAME placeholder, so a readback that never happened compares
  # clean on a weight-10 class. Base-10 it, exactly as the concurrent driver does with its own
  # %{http_code}, and let a real failure be a FAIL row rather than a value nobody measured.
  if [[ "$rstatus" =~ ^[0-9]+$ ]]; then rstatus=$((10#$rstatus)); else rstatus=0; fi
  if ! cap="$(jq -n --argjson s "$rstatus" --rawfile b "$rbody" '{status: $s, headers: {}, body: $b, effects: {}}' 2>"$raw/readback.err")"; then
    rm -f "$rbody"; printf 'could not build the readback capture for %s: %s\n' "$pth" "$(tr '\n' ' ' <"$raw/readback.err" | tail -c 200)"; return 1
  fi
  normd="$(printf '%s' "$cap" | python3 "${here}/normalize.py" --key-id "$kid" 2>"$raw/readback.err")"
  if [ -z "$normd" ]; then
    rm -f "$rbody"; printf 'normalize.py failed on the readback of %s: %s\n' "$pth" "$(tr '\n' ' ' <"$raw/readback.err" | tail -c 200)"; return 1
  fi
  rm -f "$rbody"
  # the path names the minted key by id, which differs per boot: normalize it as bodies are
  pth="$(sed -E 's/vk_[0-9a-f]+/vk_<KEY>/g' <<<"$pth")"
  jq -c --arg p "$pth" '{path: $p, status: .status, body: .body}' <<<"$normd"
}

# ── concurrent cells: N parallel requests, one recorded outcome ──────────────────────────────────
# {request: {method,path,headers,body,auth,listener}, concurrent: {n: <N>}, mock_control, fresh,
#  config_variant}. Busbar's disposition of a burst is inherently a SET, not one transaction, so the
# contract this driver records is the sorted multiset of the N statuses (capture-concurrent.py) plus
# the same before/after usage-and-metrics deltas every other driver records — never a single status.
# Needs mock-upstream.py to actually run the N requests concurrently (ThreadingHTTPServer); a
# single-threaded upstream would serialize them and there would be nothing "concurrent" left to prove.
record_concurrent_cell() {  # <id> <cell-json> <raw-dir> <safe>
  local id="$1" cell="$2" raw="$3" safe="$4" cn method path listener body_spec token kid mc port statuses
  cell="$(subst_placeholders "$cell")"
  cn="$(jq -r '.concurrent.n // 2' <<<"$cell")"
  method="$(jq -r '.request.method // "POST"' <<<"$cell")"; path="$(jq -r .request.path <<<"$cell")"
  listener="$(jq -r '.request.listener // "data"' <<<"$cell")"
  body_spec="$(jq -r '.request.body // empty' <<<"$cell")"
  printf '%s' "${body_spec:-{\}}" >"$raw/request.body"
  case "$(jq -r '.request.auth // "ok"' <<<"$cell")" in
    broke) token="$ORACLE_TOKEN_BROKE"; kid="$ORACLE_KEY_BROKE" ;;
    noscope) token="$ORACLE_TOKEN_NOSCOPE"; kid="$ORACLE_KEY_NOSCOPE" ;;
    admin) token="$ORACLE_ADMIN_TOKEN"; kid="$ORACLE_KEY_OK" ;;
    none) token=""; kid="$ORACLE_KEY_OK" ;;
    *) token="$ORACLE_TOKEN_OK"; kid="$ORACLE_KEY_OK" ;;
  esac
  local hdr_args=(-H "Content-Type: application/json")
  while IFS= read -r kv; do hdr_args+=(-H "$kv"); done < <(jq -r '.request.headers // {} | to_entries[] | "\(.key): \(.value)"' <<<"$cell")
  [ -z "$token" ] || hdr_args+=(-H "Authorization: Bearer ${token}")
  port="$LISTEN_PORT"; [ "$listener" = admin ] && port="$ADMIN_PORT"
  mc="$(jq -c '.mock_control // empty' <<<"$cell")"
  if [ -n "$mc" ] && [ "$mc" != "{}" ]; then
    oracle_write_control "$CONTROL" "$MOCK_PORT" "$mc" \
      || { record "$id" FAIL "mock control write never landed" "wrote '${mc}' to ${CONTROL}"; return; }
  fi
  settle_then_snapshot "$raw/before" "$kid"
  mkdir -p "$raw/par"
  local pids=() i
  for ((i = 1; i <= cn; i++)); do
    ( curl -sS -m 30 -o "$raw/par/$i.body" -w '%{http_code}' -X "$method" "http://127.0.0.1:${port}${path}" \
        "${hdr_args[@]}" --data-binary "@$raw/request.body" >"$raw/par/$i.status" 2>"$raw/par/$i.err" ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
  settle_then_snapshot "$raw/after" "$kid"
  oracle_clear_control "$CONTROL" "$MOCK_PORT" || true
  # each par/<i>.status file holds exactly the one %{http_code} curl wrote for that request; a
  # missing/empty file (curl itself never got a status line) counts as 0, same convention capture.py
  # uses for "no HTTP response" elsewhere in this recorder.
  local codes=() no_answer=0
  for ((i = 1; i <= cn; i++)); do
    local c; c="$(cat "$raw/par/$i.status" 2>/dev/null)"
    # curl's own "no HTTP response" placeholder is the 3-digit literal "000", which is a leading
    # zero and therefore not a valid JSON number: force base-10 so it becomes the plain integer 0.
    [[ "$c" =~ ^[0-9]+$ ]] && c=$((10#$c)) || c=0
    [ "$c" -eq 0 ] && no_answer=$((no_answer + 1))
    codes+=("$c")
  done
  # A 0 IS THE DRIVER FAILING, NOT THE POOL REFUSING. The single-request path has always treated
  # curl's 000 as a FAIL row ("no HTTP response (curl)"); this driver instead folded the same 0 into
  # the recorded multiset, so `[200,0,503]` went into the golden as if "no answer" were one of the
  # outcomes a concurrency cell can pin. It is not: the shed arm answers 503, the queued arm answers
  # 200, and a request that got no status line at all means the recorder could not run the cell —
  # a connection this harness failed to make, recorded on both binaries, agreeing.
  if [ "$no_answer" -gt 0 ]; then
    record "$id" FAIL "${no_answer} of ${cn} concurrent requests got no HTTP response (curl)" \
      "$(cat "$raw/par/1.err" 2>/dev/null | tr '\n' ' ' | tail -c 200)"
    return
  fi
  statuses="$(printf '%s\n' "${codes[@]}" | sort -n | paste -sd, - | sed 's/^/[/; s/$/]/')"
  printf '%s\n' "$statuses" >"$raw/statuses.json"
  if ! python3 "${here}/capture-concurrent.py" "$statuses" "$raw/before" "$raw/after" >"$raw/captured.json" 2>"$raw/capture.err"; then
    record "$id" FAIL "capture-concurrent.py failed" "$(tail -c 300 "$raw/capture.err")"; return
  fi
  printf '%s\n' "$kid" >"$raw/key-id"   # so renormalize.sh can re-run this cell faithfully
  if ! python3 "${here}/normalize.py" "$raw/captured.json" --key-id "$kid" >"$OUT/cells/$safe.json" 2>"$raw/normalize.err"; then
    record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; return
  fi
  record "$id" PASS "N=${cn}; statuses ${statuses}" ""
  n=$((n + 1))
}

# ── the cells ───────────────────────────────────────────────────────────────────────────────────
n=0
# THE PRODUCER PROJECTS THE DISPATCH FIELDS; the loop reads them, it does not re-parse the cell to
# find them. Every cell used to pay for seven `jq` processes BEFORE the filter and the skip guards
# had even run — ~16k processes across the 2283-cell corpus, most of them for cells a --filter run
# then discarded. The fields below are the same expressions, evaluated once, in the one jq pass that
# was already reading the file. Joined on US (), with the whole cell LAST so it absorbs
# anything after it; no projected value contains that byte or a newline (checked across cells.json).
# NOT a tab: a tab is IFS *whitespace*, so bash collapses runs of them and drops leading/trailing
# ones — and `.body_lines`/`.keep` are empty on almost every cell, so every field after them shifted
# by one and the loop drove its requests with an empty `$cell`. A non-whitespace separator keeps
# empty fields. `.why` is deliberately NOT projected: it is free text, and it is only wanted on the
# rare skip path, which can afford its own jq.
#
#   `.outcome | tostring` and the `// ` defaults reproduce `jq -r` exactly, including "null".
while IFS=$'\x1f' read -r id outcome driver keep_lines keep_spec needs_fixture plane cell; do
  [ -z "$FILTER" ] || [[ "$id" =~ $FILTER ]] || continue
  safe="${id//|/__}"
  raw="$OUT/raw/$safe"; mkdir -p "$raw"
  # `keep_lines` (.body_lines): the cell's contract is the ABSENCE of matching lines; the normalizer
  # keeps only those. `keep_spec` (.keep): the contract is the PRESENCE of a specific
  # header/JSON-key/metrics-line value normalize.py would otherwise strip — passed through verbatim.
  if [ "$needs_fixture" = true ]; then
    record "$id" SKIP "UNSUPPORTED: $(jq -r .why <<<"$cell" | cut -c1-140)" "named gap: the fixture this cell needs is not in the tree yet"; continue
  fi
  case "$plane" in
    mcp|a2a) record "$id" SKIP "UNSUPPORTED: ${plane} is proven by its conformance rig, not recorded here" "named gap on the golden, never owed"; continue ;;
  esac
  if [ "$driver" = exec ]; then
    record_exec_cell "$id" "$cell" "$raw" "$safe"; continue
  fi

  if [ "$driver" = script ]; then
    # A named script owns the whole cell (its own processes on spare ports) and writes captured.json.
    sname="$(jq -r .script.name <<<"$cell")"
    local_args=(); while IFS= read -r a; do [ -n "$a" ] && local_args+=("$a"); done < <(jq -r '.script.args[]? // empty' <<<"$cell")
    # a script cell never needs the recording busbar; free its ports and CPU. stop_busbar clears
    # BUSBAR_PID, so the next cell reboots instead of assuming the variant it wanted is still being
    # served here — under --shared-state that assumption was a dead port.
    stop_busbar
    # a script cell drives its own busbar off "$WORK/config.yaml": that must be the baseline, not
    # whatever variant an earlier cell's boot left there (see ensure_baseline_config).
    ensure_baseline_config || { record "$id" FAIL "could not restore the baseline oracle config" ""; continue; }
    # the script reuses this recording's own (now free) listen/admin ports so two recordings never
    # collide; the recording's mock upstream is still up on MOCK_PORT, so the script's mock takes
    # the port after the admin one (inside this recording's own block)
    # A script cell boots busbar ITSELF, several times in some cells (store-persist kills its first
    # busbar by design, admin-restart restarts one), and the recorder cannot reach in to sweep
    # between those boots. So each script cell gets its OWN empty temp base: the only staging dirs
    # its busbars can ever see are the ones that cell made, which makes what it records a property
    # of the cell instead of a property of which cell ran before it. (Two scripts —
    # durable-governance-precondition, plugins-fetch-reload-miss — already did this for themselves;
    # this makes it true for every script, including the ones that boot no plugins today and might
    # tomorrow.) The sweep still runs first, for the recording busbar's dirs this cell inherits.
    sweep_orphan_staging
    local_tmp="$WORK/cell-tmp/$safe"; rm -rf "$local_tmp"; mkdir -p "$local_tmp"
    BUSBAR_BIN="$BIN" RAW="$raw" WORK="$WORK" ORACLE_ADMIN_TOKEN="$ORACLE_ADMIN_TOKEN" TMPDIR="$local_tmp" \
      SCRIPT_LISTEN_PORT="$LISTEN_PORT" SCRIPT_ADMIN_PORT="$ADMIN_PORT" SCRIPT_MOCK_PORT="$((ADMIN_PORT+1))" \
      bash "${here}/scripts/${sname}" "${local_args[@]}" >"$raw/script.log" 2>&1
    [ -s "$raw/captured.json" ] || { record "$id" FAIL "script ${sname} produced no captured.json" "$(tail -c 300 "$raw/script.log")"; continue; }
    # STRIP THE DIRECTORIES THIS RUN CHOSE, exactly as record_exec_cell does for an exec cell. A
    # script cell quotes busbar's own stdout back into its effects ("plugins dir: <path>", a
    # --validate tail), and those name $OUT/$raw/$WORK/$repo/$BIN — so the same binary recorded to
    # two different --out dirs produced two different cell files and the diff was about where the
    # harness put things. In place, because renormalize.sh re-derives cells from this exact file:
    # writing a second scrubbed copy would make a re-normalized cell disagree with the recorded one.
    # Both the given and the absolute form of each dir: a relative --out still reaches busbar's own
    # output absolutized, and a relative one survives in the strings the script built itself.
    abs_out="$(cd "$OUT" 2>/dev/null && pwd)"; abs_raw="$(cd "$raw" 2>/dev/null && pwd)"
    abs_bin="$(cd "$(dirname "$BIN")" 2>/dev/null && pwd)/$(basename "$BIN")"
    if python3 "${here}/capture-exec.py" --scrub-paths "$raw/captured.json" \
         --strip-path "$abs_raw" --strip-path "$raw" --strip-path "$abs_out" --strip-path "$OUT" \
         --strip-path "$WORK" --strip-path "$repo" --strip-path "$abs_bin" --strip-path "$BIN" \
         >"$raw/captured.scrubbed" 2>"$raw/scrub.err"; then
      mv "$raw/captured.scrubbed" "$raw/captured.json"
    else
      record "$id" FAIL "could not strip the harness paths out of ${sname}'s capture" "$(tail -c 300 "$raw/scrub.err")"; continue
    fi
    python3 "${here}/normalize.py" "$raw/captured.json" >"$OUT/cells/$safe.json" 2>"$raw/normalize.err" \
      || { record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; continue; }
    st="$(jq -r .status "$raw/captured.json")"
    if [ "$st" = "-1" ]; then record "$id" SKIP "UNSUPPORTED: $(jq -r '.effects.error // "script could not run"' "$raw/captured.json")" "named gap"; continue; fi
    record "$id" PASS "script ${sname}: status ${st}" ""; n=$((n + 1)); continue
  fi

  # `fresh: true` — this cell must not see state (breaker, budgets) left by earlier cells.
  variant="$(jq -r '.config_variant // empty' <<<"$cell")"
  # `-z "$BUSBAR_PID"` is not redundant: a script cell just before this one stopped the recording
  # busbar, and with --shared-state a following cell whose variant equals DISK_VARIANT would
  # otherwise skip the boot and drive every request at a port nothing is listening on.
  if [ -z "$BUSBAR_PID" ] || [ "$FRESH_ALL" = 1 ] || [ "$(jq -r '.fresh // false' <<<"$cell")" = true ] || [ "$variant" != "$DISK_VARIANT" ]; then
    stop_busbar
    boot_busbar "$variant" || { record "$id" FAIL "fresh boot before cell failed (variant '${variant}')" "$(tr '\n' '|' <"$WORK/busbar.log" | tail -c 300)"; continue; }
  fi
  if [ "$driver" = concurrent ]; then
    record_concurrent_cell "$id" "$cell" "$raw" "$safe"; continue
  fi
  if [ "$driver" = http ]; then
    # An explicit request: {method, path, headers, body, auth: ok|broke|noscope|admin|none, listener,
    # pre: [requests run UNRECORDED first, same boot], repeat: N (record the LAST response)}.
    # Placeholders in path/headers/body are bound to this boot's values.
    cell="$(subst_placeholders "$cell")"
    pre_failed=""
    while IFS= read -r pre; do
      [ -n "$pre" ] || continue
      run_pre_request "$pre" >>"$raw/pre.log" 2>&1 || pre_failed="$pre"
    done < <(jq -c '.request.pre[]? // empty' <<<"$cell")
    if [ -n "$pre_failed" ]; then
      record "$id" FAIL "a pre-request never reached busbar" \
        "$(printf '%s' "$pre_failed" | cut -c1-160); see $(basename "$raw")/pre.log — the state this cell needs was not set up, so what follows would be recorded against the unprepared boot"
      continue
    fi
    method="$(jq -r .request.method <<<"$cell")"; path="$(jq -r .request.path <<<"$cell")"
    listener="$(jq -r '.request.listener // "data"' <<<"$cell")"
    repeat="$(jq -r '.request.repeat // 1' <<<"$cell")"
    body_spec="$(jq -r '.request.body // empty' <<<"$cell")"
    case "$body_spec" in
      @oversize:*) python3 - "${body_spec#@oversize:}" >"$raw/request.body" 2>"$raw/oversize.err" <<'PY'
import sys
spec = sys.argv[1]
# An unparseable spec must be LOUD. A bare int() raising here used to leave request.body empty and
# the exit status unchecked, so the cell POSTed nothing at all and recorded whatever busbar says to
# an empty body -- a PASS for a request that was never the one the cell is about.
try:
    n = int(spec[:-3]) * 1024 * 1024 if spec.endswith("MiB") else int(spec)
except ValueError:
    sys.exit("bad @oversize spec %r: expected <bytes> or <N>MiB" % spec)
if n <= 0:
    sys.exit("bad @oversize spec %r: size must be positive" % spec)
sys.stdout.write('{"model":"m-openai-chat","messages":[{"role":"user","content":"' + "x" * n + '"}]}')
PY
        oversize_rc=$?
        if [ "$oversize_rc" -ne 0 ] || [ ! -s "$raw/request.body" ]; then
          record "$id" FAIL "could not build the @oversize body for ${body_spec}" \
            "$(tail -c 200 "$raw/oversize.err" | tr '\n' ' ')"; continue
        fi ;;
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
    if [ -n "$mc" ] && [ "$mc" != "{}" ]; then
      oracle_write_control "$CONTROL" "$MOCK_PORT" "$mc" \
        || { record "$id" FAIL "mock control write never landed" "wrote '${mc}' to ${CONTROL}"; continue; }
    fi
    settle_then_snapshot "$raw/before" "$kid"
    ls "$WORK/egress" 2>/dev/null | sort >"$raw/egress.before"
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
    over_budget_total) sig_akid="$ORACLE_AWS_AKID_QUOTA"; sig_secret="$ORACLE_AWS_SECRET_QUOTA" ;;
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
    over_budget_total) token="$ORACLE_TOKEN_QUOTA"; kid="$ORACLE_KEY_QUOTA" ;;
    out_of_scope) token="$ORACLE_TOKEN_NOSCOPE"; kid="$ORACLE_KEY_NOSCOPE" ;;
    unauthenticated) token=""; kid="$ORACLE_KEY_OK" ;;
    *) token="$ORACLE_TOKEN_OK"; kid="$ORACLE_KEY_OK" ;;
  esac

  hdr_args=()
  while IFS= read -r kv; do hdr_args+=(-H "$kv"); done < <(jq -r '.headers | to_entries[] | "\(.key): \(.value)"' <<<"$req")
  # a signed request already carries its Authorization (SigV4); a bearer cell gets the token here
  [ "$auth" = sigv4-signed ] || [ -z "$token" ] || hdr_args+=(-H "Authorization: Bearer ${token}")

  if [ "$outcome" = upstream_down ]; then
    oracle_write_control "$CONTROL" "$MOCK_PORT" "down" \
      || { record "$id" FAIL "mock control write never landed" "wrote 'down' to ${CONTROL}"; continue; }
  fi
  settle_then_snapshot "$raw/before" "$kid"
  ls "$WORK/egress" 2>/dev/null | sort >"$raw/egress.before"
  status="$(curl -sS -m 20 -N -X POST "http://127.0.0.1:${LISTEN_PORT}${path}" "${hdr_args[@]}" \
    --data-binary @"$raw/request.body" -D "$raw/headers" -o "$raw/body" -w '%{http_code}' 2>"$raw/curl.err")"; curl_rc=$?
  case "$curl_rc:$status" in 0:*|18:[1-5]??|56:[1-5]??) printf '%s\n' "$curl_rc" >"$raw/curl.rc" ;; *) status="000" ;; esac
  fi
  settle_then_snapshot "$raw/after" "$kid"
  oracle_clear_control "$CONTROL" "$MOCK_PORT" || true
  ls "$WORK/egress" 2>/dev/null | sort >"$raw/egress.after"
  egress_files=()
  while IFS= read -r f; do [ -n "$f" ] && egress_files+=("$WORK/egress/$f"); done < <(comm -13 "$raw/egress.before" "$raw/egress.after")
  printf '%s\n' "$status" >"$raw/status"
  printf '%s\n' "$kid" >"$raw/key-id"

  if [ "$status" = "000" ]; then
    record "$id" FAIL "no HTTP response (curl)" "$(tr '\n' ' ' <"$raw/curl.err" | tail -c 300)"; continue
  fi
  if ! python3 "${here}/capture.py" "$raw/headers" "$status" "$raw/body" "$raw/before" "$raw/after" "${egress_files[@]}" >"$raw/captured.json" 2>"$raw/capture.err"; then
    record "$id" FAIL "capture.py failed" "$(tail -c 300 "$raw/capture.err")"; continue
  fi
  if ! python3 "${here}/normalize.py" "$raw/captured.json" --key-id "$kid" ${keep_lines:+--keep-body-lines "$keep_lines"} ${keep_spec:+--keep "$keep_spec"} >"$OUT/cells/$safe.json" 2>"$raw/normalize.err"; then
    record "$id" FAIL "normalize.py failed" "$(tail -c 300 "$raw/normalize.err")"; continue
  fi
  # a mutating admin cell's `request.post`: read back the resource the write touched (AFTER the
  # after-snapshot, so it never shows up in the write's own usage/metrics/audit delta) and fold the
  # normalized {path,status,body} triples into this cell's own effects, so a write that answered 200
  # but touched nothing is a byte diff on THIS cell, not a silent pass.
  if [ "$driver" = http ]; then
    readback="[]"; rb_err=""
    while IFS= read -r rb; do
      [ -n "$rb" ] || continue
      if ! item="$(run_readback "$rb" "$raw/body" "$kid")"; then rb_err="$item"; break; fi
      readback="$(jq -c --argjson it "$item" '. + [$it]' <<<"$readback")"
    done < <(jq -c '.request.post[]? // empty' <<<"$cell")
    # A readback that could not be captured is not a readback that returned nothing. Recording the
    # placeholder here was a PASS on a cell whose whole point is "the write actually touched the
    # resource" — so it is a FAIL row, with what went wrong, and this cell is not counted.
    if [ -n "$rb_err" ]; then
      # and drop the half-made cell: a cells/ file with no ledger PASS behind it is exactly the
      # silence-read-as-green the ledger exists to refuse.
      rm -f "$OUT/cells/$safe.json"
      record "$id" FAIL "readback capture failed" "$rb_err"; continue
    fi
    if [ "$readback" != "[]" ]; then
      jq --argjson rb "$readback" '.effects.readback = $rb' "$OUT/cells/$safe.json" >"$raw/with-readback.json" \
        && mv "$raw/with-readback.json" "$OUT/cells/$safe.json"
    fi
  fi
  usage_note="$(jq -c '.effects.usage' "$OUT/cells/$safe.json")"
  record "$id" PASS "HTTP ${status}; usage Δ ${usage_note}" ""
  n=$((n + 1))
done < <(jq -r --arg p "$PLANE" '
  .cells[] | select($p == "all" or .plane == $p)
  | [ .id,
      (.outcome | tostring),
      (.driver // "llm"),
      (.body_lines // ""),
      (if (.keep // null) == null then "" else (.keep | tojson) end),
      ((.needs_fixture // false) | tostring),
      .plane,
      tojson ] | join("\u001f")' "${here}/cells.json")

# Provenance: which harness revision (cells.json/normalize.py/etc — see harness-rev.sh) and which
# exact binary file produced this recording, plus the host triple, so a later diff can tell "busbar
# changed" apart from "the harness changed" (diff-cells.py refuses to compare two meta.json with
# different/absent harness_rev unless told to). `at` is the time of THIS write, not of a cell added
# to an old recording later.
# shellcheck source=harness-rev.sh
source "${here}/harness-rev.sh"
BIN_SHA256="$(binary_sha256 "$BIN")"
HARNESS_REV="$(harness_rev)"
HOST_TRIPLE="$(host_triple)"
# `binary` IS BOOKKEEPING, AND IT IS COMMITTED. The golden recording's meta.json is a checked-in
# public file, and `--bin ~/.cache/busbar-oracle/1.5.5/busbar` wrote an absolute path under a
# personal home directory into it — which names a person AND a machine, the one thing
# scripts/public-hygiene-lint.py's `machine-path` rule exists to keep out of published files. It
# also says nothing: merge-recordings.py and fetch-golden.sh --check-golden both identify a
# recording's source by `binary_sha256`, never by where the file sat (see e0923a7a).
# So the path is written in a MACHINE-INDEPENDENT form — the same information about WHICH
# well-known location it came from, with the operator's name and home layout removed:
#   under this repo             -> <repo>/target/release/busbar
#   under the oracle cache      -> <oracle-cache>/1.5.5/busbar   (BUSBAR_ORACLE_CACHE or ~/.cache/busbar-oracle)
#   anywhere else under $HOME   -> <home>/some/path/busbar
#   anywhere else               -> unchanged (/usr/local/bin/busbar names no person)
# The digest beside it is unchanged and is still the identity.
_oracle_cache_root="${BUSBAR_ORACLE_CACHE:-${HOME:-/nonexistent}/.cache/busbar-oracle}"
case "$BIN" in
  "$repo"/*) BIN_DISPLAY="<repo>/${BIN#"$repo"/}" ;;
  "$_oracle_cache_root"/*) BIN_DISPLAY="<oracle-cache>/${BIN#"$_oracle_cache_root"/}" ;;
  "${HOME:-/nonexistent}"/*) BIN_DISPLAY="<home>/${BIN#"${HOME:-/nonexistent}"/}" ;;
  *) BIN_DISPLAY="$BIN" ;;
esac
jq -n --arg ver "$VER" --arg bin "$BIN_DISPLAY" --argjson recorded "$n" \
  --arg binsha "$BIN_SHA256" --arg hrev "$HARNESS_REV" --arg host "$HOST_TRIPLE" \
  '{binary: $bin, version: $ver, recorded: $recorded, binary_sha256: $binsha, harness_rev: $hrev,
    host_triple: $host, at: (now | todate)}' >"$OUT/meta.json"
cp "$WORK/busbar.log" "$OUT/busbar.log" 2>/dev/null || true
cp "$WORK/mock.log" "$OUT/mock.log" 2>/dev/null || true

echo
echo "recorded ${n} cells for ${VER} -> ${OUT}"
[ "$n" -gt 0 ] || { echo "ZERO ROWS IS RED" >&2; exit 1; }
