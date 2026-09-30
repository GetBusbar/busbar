#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE jev (DECISIONS PLANE) CONFORMANCE VERDICT — the job that writes `conformance/verdicts/jev.json`.
#
# Two legs, both run on every invocation, and one verdict over them:
#
#   battery   the decisions plane's own suites (`cargo test -p busbar-plane-decisions`): the codec,
#             the fixtures, the PII witness, the purity and invariance tests. It says the plane reads
#             and writes the jev dialect correctly. It does not say busbar SERVES the dialect.
#   served    boot the busbar binary with a configured `decisions:` section and send the jev
#             operation the plane serves, `POST /v1/systemone`. The answer is judged against the
#             ABSENCE CODE measured on the same boot (one request to a path no plane can own), so
#             "the route is not mounted" is a measurement, never an assumption.
#
# THE VERDICT IS NEVER GREEN WITHOUT A SERVED LEG THAT JUDGED THE SERVED BYTES. The rules, in order:
#
#   battery red                       -> fail, naming the battery.
#   no subject binary                 -> fail, naming the failed build (a stale binary is never booted).
#   subject did not boot              -> fail, naming the boot.
#   POST /v1/systemone reads absent   -> fail, "not served": the plane is registered and configured
#                                        and nothing answers its operation. The kernel plane driver
#                                        (BUSBAR-1.6.0.md Part 3, section 12) is what serves it.
#   POST /v1/systemone is mounted     -> fail, until a served battery judging the relayed bytes, the
#                                        usage count and the refusal shapes exists in this file.
#                                        A mounted route is not a conformant one.
#
# `GET /v1/models` is NOT a jev leg: that path keeps its 1.5.5 bytes (the LLM plane's model list),
# so the decisions plane does not claim it.
#
# USAGE
#   jev-conformance.sh [--out FILE] [--bin PATH] [--run-id ID]
#       Run both legs and write the verdict (default FILE: conformance/verdicts/jev.json). Exit 0 when
#       a verdict was written, whatever its status; exit 2 when no verdict could be written. The
#       verdict's status is the result, not the exit code, exactly as the other suites' verdict jobs.
#       --bin skips the build and boots PATH. --run-id names the run in `run_id`/`evidence`.
#   jev-conformance.sh --selftest
#       Prove the judgement: every red rule fires on its planted input, and no planted input yields
#       a pass; and prove the workflow runs every battery target. No cargo, no boot.
#
# THE SAME TWO LEGS, ONE CI JOB PER PIECE (.github/workflows/qa-conformance-jev.yml). The workflow
# runs each piece as its own job, and its `verdict` job judges them through the same `judge`:
#   jev-conformance.sh --targets
#       Print the battery's test targets, DISCOVERED from the crate (`lib` plus every tests/*.rs),
#       never listed by hand.
#   jev-conformance.sh --battery TARGET
#       Run one target of the battery. Red when cargo fails OR when it ran zero tests: a target
#       that selects nothing proves nothing.
#   jev-conformance.sh --served [--bin PATH]
#       Build (or take PATH), boot and measure the served leg. Prints build=, booted=, absent=,
#       code= lines (and appends them to $GITHUB_OUTPUT when set). Exit 0 when the measurement was
#       taken, whatever it says: the judgement is the verdict's.
#   jev-conformance.sh --judge BATTERY BUILD BOOTED ABSENT CODE [--out FILE] [--run-id ID]
#       Write the verdict from legs measured by other jobs, through the same judge.

set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CRATE="$REPO/crates/busbar-plane-decisions"
WORKFLOW="$REPO/.github/workflows/qa-conformance-jev.yml"
OUT="$REPO/conformance/verdicts/jev.json"
BIN=""
RUN_ID="${JEV_RUN_ID:-}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '%s\n' "$*"; }

# judge <battery-rc> <build> <booted 0|1> <absence-code> <systemone-code> → prints
# "<status>\t<reason>". <build> is `0` when the subject binary was built (or handed in with --bin
# and is executable), else the reason there is none. A PURE FUNCTION, so `--selftest` drives every
# rule without a build or a boot.
judge() {
  local battery="$1" build="$2" booted="$3" absent="$4" code="$5"
  if [ "$battery" != "0" ]; then
    printf 'fail\tbattery: cargo test -p busbar-plane-decisions exited %s\n' "$battery"; return
  fi
  if [ "$build" != "0" ]; then
    printf 'fail\tserved: no subject binary (%s), so nothing was booted or judged\n' "$build"; return
  fi
  if [ "$booted" != "1" ] || [ -z "$absent" ] || [ "$absent" = "000" ]; then
    printf 'fail\tserved: the subject binary did not boot with a configured decisions: section, so nothing was judged\n'; return
  fi
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    printf 'fail\tserved: POST /v1/systemone got no answer from the booted subject\n'; return
  fi
  if [ "$code" = "$absent" ]; then
    printf 'fail\tnot served: POST /v1/systemone answers %s, the absence code on this boot; the decisions plane is registered and configured but no route serves its operation (the kernel plane driver serves it)\n' "$code"; return
  fi
  printf 'fail\tserved: POST /v1/systemone is mounted (answers %s) but no served battery judges the relayed bytes, the usage count and the refusal shapes yet; a mounted route is not a conformant one\n' "$code"
}

# discover_targets <crate-dir> → one battery target per line: `lib`, then every tests/<name>.rs.
discover_targets() {
  local crate="$1" f
  [ -f "$crate/src/lib.rs" ] && echo lib
  for f in "$crate"/tests/*.rs; do
    [ -f "$f" ] && basename "$f" .rs
  done
  return 0
}

# workflow_targets <workflow-file> → every `--battery NAME` the workflow runs, one per line.
workflow_targets() {
  grep -oE -- '--battery [A-Za-z0-9_]+' "$1" 2>/dev/null | awk '{print $2}' | sort -u
}

# coverage <crate-dir> <workflow-file> → prints every target the workflow does not run and every
# `--battery` it runs that names no target; returns 1 when either list is non-empty.
coverage() {
  local want got missing ghost
  want="$(discover_targets "$1" | sort -u)"
  got="$(workflow_targets "$2")"
  [ -n "$want" ] || { echo "no battery target discovered under $1"; return 1; }
  missing="$(comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$got"))"
  ghost="$(comm -13 <(printf '%s\n' "$want") <(printf '%s\n' "$got"))"
  [ -z "$missing" ] && [ -z "$ghost" ] && return 0
  [ -n "$missing" ] && printf 'battery target run by no job: %s\n' $missing
  [ -n "$ghost" ] && printf 'job runs --battery for no such target: %s\n' $ghost
  return 1
}

# tests_ran <cargo-test-output> → the number of tests cargo says passed, summed over binaries.
tests_ran() {
  printf '%s\n' "$1" | sed -nE 's/^test result: ok\. ([0-9]+) passed.*/\1/p' | awk '{s+=$1} END {print s+0}'
}

selftest() {
  local fail=0 out
  check() { # check <name> <expect-substring> <args...>
    local name="$1" want="$2"; shift 2
    out="$(judge "$@")"
    case "$out" in
      fail*"$want"*) note "PASS  $name" ;;
      *) fail=1; red "FAIL  $name: got '$out'" ;;
    esac
  }
  check "battery red is a fail naming the battery" "battery:" 101 0 1 404 404
  check "a failed build is a fail naming the build, whatever a stale binary would answer" "cargo build exited 101" 0 "cargo build exited 101" 1 404 200
  check "no boot is a fail, never a pass" "did not boot" 0 0 0 "" ""
  check "an unmeasured absence code is a fail" "did not boot" 0 0 1 "" 404
  check "no answer is a fail" "no answer" 0 0 1 404 000
  check "an absent route is NOT SERVED" "not served" 0 0 1 404 404
  check "absence is measured, not assumed (401 boot)" "not served" 0 0 1 401 401
  check "a mounted route without a served battery is still a fail" "mounted" 0 0 1 404 200
  # A FAILED BUILD YIELDS NO BINARY: `subject_bin` never names a target path after a failed build,
  # so a stale binary from an earlier build is never booted under this commit's sha.
  if [ -z "$(subject_bin 101 /nonexistent-target)" ] && [ -n "$(subject_bin 0 /t)" ]; then
    note "PASS  a failed build names no subject binary; a good one names its target path"
  else
    fail=1; red "FAIL  subject_bin named a binary after a failed build (or none after a good one)"
  fi
  # And no input at all yields a pass: the judge has no pass arm to reach.
  for b in 0 1; do for bu in 0 "cargo build exited 1"; do for bo in 0 1; do for a in 404 401 ""; do for c in 200 404 401 500 ""; do
    case "$(judge "$b" "$bu" "$bo" "$a" "$c")" in pass*) fail=1; red "FAIL  judge passed ($b $bu $bo $a $c)" ;; esac
  done; done; done; done; done
  [ "$fail" -eq 0 ] && note "PASS  no planted input yields a pass"
  # The writer emits valid JSON carrying the status and the reason.
  local tmp; tmp="$(mktemp)"
  write_verdict "$tmp" fail "not served: planted" "0123456789abcdef" "selftest"
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["status"]=="fail" and d["armed"] is True and d["suite"]=="jev" and d["reason"]=="not served: planted"' "$tmp" 2>/dev/null; then
    note "PASS  the verdict writer emits the schema's fields"
  else
    fail=1; red "FAIL  the verdict writer's output is not the verdict shape"
  fi
  rm -f "$tmp"
  # THE BATTERY IS SPLIT ACROSS JOBS, SO THE SPLIT MUST COVER IT. A planted crate and workflows
  # prove the coverage check bites both ways; then the real crate and the real workflow must agree.
  local fx; fx="$(mktemp -d)"
  mkdir -p "$fx/c/src" "$fx/c/tests"
  : >"$fx/c/src/lib.rs"; : >"$fx/c/tests/one.rs"; : >"$fx/c/tests/two.rs"
  printf 'run: x --battery lib\nrun: x --battery one\nrun: x --battery two\n' >"$fx/full.yml"
  printf 'run: x --battery lib\nrun: x --battery one\n' >"$fx/short.yml"
  printf 'run: x --battery lib\nrun: x --battery one\nrun: x --battery two\nrun: x --battery three\n' >"$fx/ghost.yml"
  if coverage "$fx/c" "$fx/full.yml" >/dev/null; then note "PASS  a workflow running every target covers the battery"
  else fail=1; red "FAIL  full coverage was refused"; fi
  if coverage "$fx/c" "$fx/short.yml" >/dev/null; then fail=1; red "FAIL  a target run by no job was accepted"
  else note "PASS  a target run by no job is refused"; fi
  if coverage "$fx/c" "$fx/ghost.yml" >/dev/null; then fail=1; red "FAIL  a --battery naming no target was accepted"
  else note "PASS  a --battery naming no target is refused"; fi
  rm -rf "$fx"
  if out="$(coverage "$CRATE" "$WORKFLOW")"; then
    note "PASS  qa-conformance-jev.yml runs every battery target: $(discover_targets "$CRATE" | tr '\n' ' ')"
  else
    fail=1; red "FAIL  qa-conformance-jev.yml does not cover the battery:"; printf '%s\n' "$out"
  fi
  # A green cargo run that selected nothing is not a pass, so the counter must read cargo's lines.
  if [ "$(tests_ran 'test result: ok. 0 passed; 0 failed')" = "0" ] \
     && [ "$(tests_ran "$(printf 'test result: ok. 3 passed; 0 failed\ntest result: ok. 2 passed; 0 failed')")" = "5" ]; then
    note "PASS  the test counter reads cargo's summary lines"
  else
    fail=1; red "FAIL  the test counter misreads cargo's summary lines"
  fi
  if [ "$fail" -eq 0 ]; then grn "jev-conformance self-test: ALL GREEN"; return 0; fi
  red "jev-conformance self-test: FAILED"; return 1
}

# write_verdict <file> <status> <reason> <commit> <run-id>
write_verdict() {
  local f="$1" status="$2" reason="$3" commit="$4" run="$5"
  python3 - "$f" "$status" "$reason" "$commit" "$run" <<'PYEOF'
import json, sys, datetime
f, status, reason, commit, run = sys.argv[1:6]
doc = {
    "schema": "busbar.conformance.verdict/1",
    "suite": "jev",
    "standard": "jev decision plane",
    "status": status,
    "armed": True,
    "commit": commit,
    "run_id": run,
    "evidence": run,
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "reason": reason,
}
with open(f, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
PYEOF
}

# subject_bin <build-rc> <target-dir> → the built binary's path, or NOTHING when the build failed.
subject_bin() {
  [ "$1" = "0" ] || return 0
  printf '%s/debug/busbar\n' "$2"
}

free_port_pair() {
  python3 - <<'PYEOF' 2>/dev/null
import socket, random
for _ in range(200):
    base = random.randrange(47000, 47998, 2)
    socks = []
    try:
        for port in (base, base + 1):
            s = socket.socket()
            s.bind(("127.0.0.1", port))
            socks.append(s)
        print(base)
        break
    except OSError:
        continue
    finally:
        for s in socks:
            s.close()
PYEOF
}

# served_leg <bin> → sets BOOTED, ABSENT, CODE.
served_leg() {
  local bin="$1" ports port admin fix pid code
  BOOTED=0; ABSENT=""; CODE=""
  ports="$(free_port_pair)"; [ -n "$ports" ] || { red "served: no free port pair"; return; }
  port="$ports"; admin=$((port + 1))
  fix="$(mktemp -d "${TMPDIR:-/tmp}/jev-conformance.XXXXXX")" || return
  # One decision provider on the one dialect this plane speaks, and one model on it. The catalog
  # entry carries the connection and the dialect; the config entry carries the credential. The far
  # end is a closed loopback port: this leg asks whether busbar SERVES the operation, and a served
  # route answers before any far end is reached or refuses in its own words when it cannot be.
  cat >"$fix/providers.yaml" <<EOF
typesafe:
  protocol: jev
  base_url: http://127.0.0.1:9
  error_map: {}
EOF
  cat >"$fix/config.yaml" <<EOF
listen: "127.0.0.1:$port"
admin_listen: "127.0.0.1:$admin"
providers:
  typesafe:
    api_key: { env: JEV_CONFORMANCE_KEY }
models: {}
decisions:
  models:
    jev-1:
      provider: typesafe
EOF
  JEV_CONFORMANCE_KEY=conformance-key \
  BUSBAR_CONFIG="$fix/config.yaml" BUSBAR_PROVIDERS="$fix/providers.yaml" \
    "$bin" >"$fix/boot.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/stats" 2>/dev/null)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then BOOTED=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if [ "$BOOTED" = "1" ]; then
    ABSENT="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
      "http://127.0.0.1:$port/.jev-conformance/no-such-route-any-plane-could-own" \
      -H 'content-type: application/json' -d '{}')"
    CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/v1/systemone" \
      -H 'content-type: application/json' -d '{"state":{},"context":{}}')"
    note "served: absence on this boot = $ABSENT; POST /v1/systemone = $CODE"
  else
    red "served: the subject did not boot; its log:"
    tail -15 "$fix/boot.log" 2>/dev/null | sed 's/^/    /'
  fi
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  rm -rf "$fix"
}

# run_battery <target> → runs one battery target; its exit status is the leg's.
run_battery() {
  local target="$1" out rc n
  if ! discover_targets "$CRATE" | grep -qxF -- "$target"; then
    red "battery: no target '$target' (targets: $(discover_targets "$CRATE" | tr '\n' ' '))"; return 2
  fi
  local sel=(--lib)
  [ "$target" = "lib" ] || sel=(--test "$target")
  note "battery: cargo test -p busbar-plane-decisions ${sel[*]}"
  out="$(cd "$REPO" && cargo test -p busbar-plane-decisions "${sel[@]}" 2>&1)"; rc=$?
  printf '%s\n' "$out"
  [ "$rc" -eq 0 ] || { red "battery $target: cargo exited $rc"; return "$rc"; }
  n="$(tests_ran "$out")"
  [ "$n" -ge 1 ] || { red "battery $target: ran 0 tests; a target that selects nothing proves nothing"; return 1; }
  grn "battery $target: $n test(s) passed"
}

# measure_served → builds (unless --bin was given) and runs the served leg; sets BUILD, BOOTED,
# ABSENT and CODE. BUILD is `0` when there is a subject binary, else the reason there is none.
measure_served() {
  local rc
  BUILD=0
  if [ -z "$BIN" ]; then
    (cd "$REPO" && cargo build -q -p busbar); rc=$?
    BIN="$(subject_bin "$rc" "${CARGO_TARGET_DIR:-$REPO/target}")"
    if [ "$rc" -ne 0 ]; then BUILD="cargo build exited $rc"; red "served: the busbar binary did not build"; fi
  elif [ ! -x "$BIN" ]; then
    BUILD="--bin $BIN is not an executable"
  fi
  BOOTED=0; ABSENT=""; CODE=""
  [ "$BUILD" = "0" ] && served_leg "$BIN"
  return 0
}

main() {
  local mode=all target="" jb="" jbu="" jbo="" ja="" jc=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --selftest) selftest; exit $? ;;
      --targets) discover_targets "$CRATE"; exit 0 ;;
      --battery) mode=battery; target="${2:-}"; shift; [ $# -gt 0 ] && shift ;;
      --served) mode=served; shift ;;
      --judge)
        [ $# -ge 6 ] || { echo "--judge needs BATTERY BUILD BOOTED ABSENT CODE" >&2; exit 2; }
        mode=judge; jb="$2"; jbu="$3"; jbo="$4"; ja="$5"; jc="$6"; shift 6 ;;
      --out) OUT="$2"; shift 2 ;;
      --bin) BIN="$2"; shift 2 ;;
      --run-id) RUN_ID="$2"; shift 2 ;;
      *) echo "usage: $0 [--selftest | --targets | --battery TARGET | --served | --judge BATTERY BUILD BOOTED ABSENT CODE] [--out FILE] [--bin PATH] [--run-id ID]" >&2; exit 2 ;;
    esac
  done
  case "$mode" in
    battery)
      [ -n "$target" ] || { echo "--battery needs a TARGET" >&2; exit 2; }
      run_battery "$target"; exit $? ;;
    served)
      command -v curl >/dev/null 2>&1 || { echo "jev-conformance: curl not found" >&2; exit 2; }
      measure_served
      local kv
      for kv in "build=$BUILD" "booted=$BOOTED" "absent=$ABSENT" "code=$CODE"; do
        note "$kv"
        if [ -n "${GITHUB_OUTPUT:-}" ]; then printf '%s\n' "$kv" >>"$GITHUB_OUTPUT"; fi
      done
      exit 0 ;;
  esac
  command -v python3 >/dev/null 2>&1 || { echo "jev-conformance: python3 not found" >&2; exit 2; }
  local commit battery status reason
  commit="$(git -C "$REPO" rev-parse HEAD 2>/dev/null)" || { echo "jev-conformance: no commit to record" >&2; exit 2; }
  [ -n "$RUN_ID" ] || RUN_ID="local:$(hostname)"

  if [ "$mode" = judge ]; then
    battery="$jb"; BUILD="$jbu"; BOOTED="$jbo"; ABSENT="$ja"; CODE="$jc"
  else
    command -v curl >/dev/null 2>&1 || { echo "jev-conformance: curl not found" >&2; exit 2; }
    note "battery: cargo test -p busbar-plane-decisions"
    (cd "$REPO" && cargo test -q -p busbar-plane-decisions) >"${TMPDIR:-/tmp}/jev-battery.$$.log" 2>&1
    battery=$?
    if [ "$battery" -eq 0 ]; then grn "battery: green"; else
      red "battery: exited $battery"; grep -m20 -E 'FAILED|panicked|error(\[|:)' "${TMPDIR:-/tmp}/jev-battery.$$.log"
    fi
    rm -f "${TMPDIR:-/tmp}/jev-battery.$$.log"
    measure_served
  fi

  IFS="$(printf '\t')" read -r status reason <<EOF
$(judge "$battery" "$BUILD" "$BOOTED" "$ABSENT" "$CODE")
EOF
  write_verdict "$OUT" "$status" "$reason" "$commit" "$RUN_ID" || exit 2
  note "verdict: $status — $reason"
  note "written: $OUT"
  exit 0
}

main "$@"
