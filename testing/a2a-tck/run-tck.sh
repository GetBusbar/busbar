#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Run the OFFICIAL A2A Technology Compatibility Kit against one target.
#
# WHY THIS AND NOT A HAND-WRITTEN gRPC DRIVER. `a2aproject/a2a-tck` already covers all three
# transports the specification defines -- gRPC, JSON-RPC and HTTP+JSON -- across 36 test modules,
# and it is maintained by the people who publish the specification. Writing our own gRPC driver
# would be several days spent duplicating a suite somebody else keeps current. The independent
# battery in ../a2a-harness is a DIFFERENT instrument and both are wired: the battery is a
# clean-room reading of the spec with adversarial and hostile-peer coverage the TCK does not have,
# and the TCK is the publisher's own oracle with transport coverage the battery does not have.
# Neither substitutes for the other.
#
# WHAT IS PINNED, AND WHY EACH PIN IS LOAD-BEARING
#   TCK_REF        the suite defines what "conformant" means here; a silent upgrade silently
#                  changes the answer.
#   CONTROL_GO_VERSION  the reference implementation the control legs judge; it must match
#                  ../a2a-harness/scripts/install-control.sh so both instruments talk about the
#                  same peer, and `install_control` refuses to run when the two disagree or when
#                  the installed binary is not the pinned module version.
#   TZ             NOT cosmetic. a2a-go v2.4.0 serialises task timestamps in the HOST's local
#                  zone rather than UTC, which is a real spec violation (SPEC 5.6.1) that is
#                  INVISIBLE on a UTC host -- and CI runners are UTC. Running these legs in UTC
#                  would silently retire a real finding and quietly weaken the suite. So the zone
#                  is fixed to a non-UTC one, and `tz-is-load-bearing.sh` proves the choice still
#                  changes the result rather than sitting there as decoration.
#
# LICENCE: see LICENSING.md next to this file. The TCK's terms are AMBIGUOUS in its own tree, so
# nothing from it is vendored; it is fetched at a pinned commit at run time and used as a tool.
#
# USAGE
#   run-tck.sh control-http-json     pinned control, HTTP+JSON binding; checked against a baseline
#   run-tck.sh control-jsonrpc       pinned control, JSON-RPC binding;  checked against a baseline
#   run-tck.sh control-scenario      the agent the SUBJECT leg fronts, judged directly with no
#                                    busbar in the path. The CEILING for the subject number, and
#                                    the only control it may be read against. Reported, never
#                                    pinned.
#   run-tck.sh subject               the endpoint in BUSBAR_A2A_ENDPOINT; reported, never pinned
#   run-tck.sh prepare               fetch + install the pinned suite only, and print the paths another
#                                    instrument can borrow (used by testing/a2a-supplement)
#   run-tck.sh record-baselines      re-record both control baselines (deliberate act, read the diff)
#   run-tck.sh selftest              the runner's own report handling, with the suite replaced by a
#                                    stand-in that crashes or reports (no network, no control)
set -euo pipefail

TCK_REF="5996b79f9cefa6fc390980e383e358a66fb9e49e"   # a2aproject/a2a-tck, 2026-06-29
CONTROL_GO_VERSION="v2.4.0"                          # github.com/a2aproject/a2a-go
export TZ="${A2A_TCK_TZ:-America/New_York}"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${A2A_TCK_WORK:-${TMPDIR:-/tmp}/a2a-tck-work}"
TCK_DIR="$WORK/a2a-tck"
VENV="$WORK/venv"
BIN_DIR="${A2AHT_CONTROL_BIN:-$WORK/bin}"
OUT="${A2A_TCK_OUT:-$WORK/out}"
mkdir -p "$WORK" "$BIN_DIR" "$OUT"

say () { printf '\n=== %s ===\n' "$*"; }

fetch_tck () {
  if [ ! -d "$TCK_DIR/.git" ]; then
    say "fetching a2a-tck at pinned ${TCK_REF}"
    git init -q "$TCK_DIR"
    git -C "$TCK_DIR" remote add origin https://github.com/a2aproject/a2a-tck.git
    git -C "$TCK_DIR" fetch -q --depth 1 origin "$TCK_REF"
    git -C "$TCK_DIR" checkout -q FETCH_HEAD
  fi
  got="$(git -C "$TCK_DIR" rev-parse HEAD)"
  # A pin that is not verified after checkout is a wish. A cached working copy from an earlier,
  # different pin would otherwise be used silently and the baseline compared against the wrong suite.
  if [ "$got" != "$TCK_REF" ]; then
    echo "a2a-tck checkout is $got, pin is $TCK_REF -- refusing to run" >&2
    exit 2
  fi
  echo "a2a-tck @ $got"
}

install_tck () {
  if [ ! -x "$VENV/bin/python" ]; then
    say "installing a2a-tck into $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" -q install --upgrade pip
    ( cd "$TCK_DIR" && "$VENV/bin/pip" -q install -e . )
  fi
  "$VENV/bin/python" -c 'import pytest, grpc, jsonschema' \
    || { echo "a2a-tck dependencies did not import" >&2; exit 2; }
}

install_control () {
  # ONE PIN FOR ONE PEER. The harness installs the same control into the same cache; a version
  # spelled here and there that has drifted is two instruments describing different peers, so the
  # disagreement -- or a harness file that no longer states its pin -- refuses the run.
  local harness_pin_file="$HERE/../a2a-harness/scripts/install-control.sh" harness_pin=""
  if [ -f "$harness_pin_file" ]; then
    harness_pin="$(sed -n 's/^CONTROL_GO_VERSION="\([^"]*\)".*/\1/p' "$harness_pin_file" | head -1)"
  fi
  if [ -z "$harness_pin" ]; then
    echo "no CONTROL_GO_VERSION pin readable in $harness_pin_file -- refusing to run" >&2
    exit 2
  fi
  if [ "$harness_pin" != "$CONTROL_GO_VERSION" ]; then
    echo "a2a-go pin disagreement: run-tck.sh pins $CONTROL_GO_VERSION, testing/a2a-harness pins \
$harness_pin -- reconcile them before running" >&2
    exit 2
  fi
  if [ ! -x "$BIN_DIR/a2a" ]; then
    say "installing control a2a-go ${CONTROL_GO_VERSION}"
    GOBIN="$BIN_DIR" go install \
      "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}"
  fi
  # A pin that is not verified after install is a wish. BIN_DIR is a persistent cache in the wired
  # recorder, so a binary another pin left there would otherwise be judged -- and, under
  # `record-baselines`, recorded -- as a2a-go ${CONTROL_GO_VERSION}. The module version is read out
  # of the binary's own build information.
  local got=""
  got="$(go version -m "$BIN_DIR/a2a" 2>/dev/null \
    | awk '$1 == "mod" && $2 == "github.com/a2aproject/a2a-go/v2" { print $3 }')" || true
  if [ "$got" != "$CONTROL_GO_VERSION" ]; then
    echo "control binary $BIN_DIR/a2a is a2a-go '${got:-unreadable}', pin is \
$CONTROL_GO_VERSION -- refusing to run" >&2
    exit 2
  fi
  "$BIN_DIR/a2a" --help >/dev/null
}

# run_tck <base-url> <report-name>  -> sets RUN_STARTED
run_tck () {
  local url="$1" name="$2" rc=0
  rm -rf "$TCK_DIR/reports"
  # A REPORT AN EARLIER RUN COPIED HERE IS NOT THIS RUN'S EVIDENCE. OUT sits under WORK, which the
  # wired recorder keeps in a persistent cache; left in place, the last good run's report would be
  # read as the report of a run that crashed before writing one, and it would match its baseline.
  # Removed before the suite starts, and the comparator separately refuses any report older than
  # RUN_STARTED, so the crashed run reaches the missing-report refusal it is owed.
  rm -f "$OUT/$name.json"
  if [ -e "$OUT/$name.json" ]; then
    echo "could not remove the previous run's report $OUT/$name.json -- refusing to run" >&2
    exit 2
  fi
  RUN_STARTED="$(date +%s)"
  ( cd "$TCK_DIR" && "$VENV/bin/python" run_tck.py --sut-host "$url" ) \
    > "$OUT/$name.txt" 2>&1 || rc=$?
  # The TCK exits non-zero whenever any requirement fails, which is the NORMAL state against
  # every implementation we have. The verdict here is the baseline comparison, not the exit
  # code -- but a MISSING report is still fatal, and that is checked by the comparator.
  echo "  (a2a-tck exit $rc; verdict comes from the baseline comparison)"
  if [ -f "$TCK_DIR/reports/compatibility.json" ]; then
    cp "$TCK_DIR/reports/compatibility.json" "$OUT/$name.json"
  fi
  sed -n '/A2A TCK Compatibility Report/,/FAILED REQUIREMENTS/p' "$OUT/$name.txt" || true
}

# compare_control <transport> <report-name> [--record --label L]
#
# The report of the run `run_tck` just made, held to (or, with --record, recorded as) the pinned
# baseline, with this run's provenance stated so a baseline of anything else is refused.
compare_control () {
  local transport="$1" name="$2"
  shift 2
  A2A_TCK_REF="$TCK_REF" A2A_TCK_CONTROL="a2a-go@${CONTROL_GO_VERSION}/${transport}" \
    python3 "$HERE/check-baseline.py" --run-started "$RUN_STARTED" \
      --report "$OUT/$name.json" --baseline "$HERE/baselines/$name.json" "$@"
}

# require_ceiling_report: the ceiling leg is reported and never pinned, but a run that produced no
# report, an earlier run's report, or a report of a collapsed run has measured nothing.
require_ceiling_report () {
  python3 "$HERE/check-baseline.py" --report-only --run-started "$RUN_STARTED" \
    --report "$OUT/control-scenario-agent.json"
}

# serve_control <port> <transport>  -> exports CONTROL_PID
serve_control () {
  local port="$1" transport="$2"
  "$BIN_DIR/a2a" serve --echo --port "$port" --quiet --transport "$transport" \
    > "$OUT/control-$transport.log" 2>&1 &
  CONTROL_PID=$!
  for _ in $(seq 1 50); do
    if curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$port/.well-known/agent-card.json"; then
      return 0
    fi
    sleep 0.2
  done
  echo "control did not come up on port $port" >&2
  cat "$OUT/control-$transport.log" >&2 || true
  kill "$CONTROL_PID" 2>/dev/null || true
  exit 2
}

stop_control () { [ -n "${CONTROL_PID:-}" ] && kill "$CONTROL_PID" 2>/dev/null || true; }

# serve_scenario_agent <port>  -> exports CONTROL_PID
#
# The agent the SUBJECT leg fronts, served here with NO busbar in the path. That is the whole point
# of this leg: `scripts/a2a-subject/boot.sh` measures busbar-fronting-this-agent, and a number has
# no meaning without the number the same suite gives the same agent alone. The difference between
# the two is busbar's contribution, in both directions, and nothing else.
serve_scenario_agent () {
  local port="$1"
  "$HERE/scenario-agent/serve.sh" "$port" > "$OUT/control-scenario.log" 2>&1 &
  CONTROL_PID=$!
  # A first run installs a virtualenv, so this waits longer than the binary controls do.
  for _ in $(seq 1 300); do
    if curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$port/.well-known/agent-card.json"; then
      return 0
    fi
    sleep 0.5
  done
  echo "the scenario agent did not come up on port $port" >&2
  cat "$OUT/control-scenario.log" >&2 || true
  kill "$CONTROL_PID" 2>/dev/null || true
  exit 2
}

control_leg () {          # control_leg <transport> <port> <name>
  local transport="$1" port="$2" name="$3"
  fetch_tck; install_tck; install_control
  say "control: a2a-go ${CONTROL_GO_VERSION} / ${transport}  (TZ=$TZ)"
  serve_control "$port" "$transport"
  trap stop_control EXIT
  run_tck "http://127.0.0.1:$port" "$name"
  stop_control; trap - EXIT
  echo
  compare_control "$transport" "$name"
}

case "${1:-}" in
  control-http-json) control_leg http_json 9701 control-a2a-go-http-json ;;
  control-jsonrpc)   control_leg jsonrpc   9702 control-a2a-go-jsonrpc ;;

  # THE CEILING LEG. The same suite, the same transport, the same agent the subject leg fronts —
  # judged directly. It is REPORTED and never baseline-compared, for the same reason the subject
  # leg is not: a recorded expectation for a peer we assemble ourselves would pin our own choices
  # as the standard. Read it as the highest score the subject leg could possibly reach, not as a
  # pass/fail of its own.
  control-scenario)
    fetch_tck; install_tck
    say "control: TCK scenario agent / jsonrpc, direct (TZ=$TZ)"
    serve_scenario_agent 9703
    trap stop_control EXIT
    run_tck "http://127.0.0.1:9703" control-scenario-agent
    stop_control; trap - EXIT
    require_ceiling_report
    ;;

  subject)
    : "${BUSBAR_A2A_ENDPOINT:?run-tck.sh subject needs BUSBAR_A2A_ENDPOINT}"
    fetch_tck; install_tck
    say "subject: $BUSBAR_A2A_ENDPOINT"
    run_tck "$BUSBAR_A2A_ENDPOINT" subject
    # Deliberately NOT baseline-compared. A subject baseline would pin our own defects as the
    # expectation, which is the failure the control legs exist to avoid importing.
    ;;

  # PREPARE ONLY: fetch the pinned suite, build its virtualenv, and print the two paths another
  # instrument needs to borrow them. It exists so that `testing/a2a-supplement` can speak gRPC over
  # the SPECIFICATION'S OWN generated stubs and validate against the same pinned artefacts, without
  # a second copy of the pin, a second venv, or a hand-rolled protobuf encoder. One pin, verified in
  # one place, used by both instruments.
  prepare)
    fetch_tck; install_tck
    # ONE EXTRA DEPENDENCY, INSTALLED HERE AND NOWHERE ELSE: `cryptography`. The supplementary
    # suite verifies agent-card JWS signatures, which needs asymmetric crypto, and the pinned TCK
    # does not depend on it. It is added to the WORK virtualenv, never to the pinned checkout --
    # `fetch_tck` still verifies the commit byte-for-byte and nothing in `$TCK_DIR` is touched.
    #
    # AND IT IS FATAL IF IT DOES NOT INSTALL. The alternative -- letting the signing checks report
    # "could not verify" -- is a suite that silently stops checking signatures the day a wheel
    # stops building. An unverified signature is never reported as a valid one, so the only honest
    # options are "verified" and "the run failed".
    "$VENV/bin/python" -c 'import cryptography' 2>/dev/null \
      || "$VENV/bin/pip" -q install cryptography \
      || { echo "could not install cryptography into $VENV; the card-signing checks cannot run" >&2; exit 2; }
    echo "A2A_TCK_DIR=$TCK_DIR"
    echo "A2A_TCK_PYTHON=$VENV/bin/python"
    ;;

  record-baselines)
    fetch_tck; install_tck; install_control
    mkdir -p "$HERE/baselines"
    record_one () {       # record_one <transport> <port> <name>
      say "recording: a2a-go ${CONTROL_GO_VERSION} / $1  (TZ=$TZ)"
      serve_control "$2" "$1"
      trap stop_control EXIT
      run_tck "http://127.0.0.1:$2" "$3"
      stop_control; trap - EXIT
      compare_control "$1" "$3" --record \
        --label "a2a-tck@${TCK_REF:0:12} vs a2a-go@${CONTROL_GO_VERSION} / $1"
    }
    record_one http_json 9701 control-a2a-go-http-json
    record_one jsonrpc   9702 control-a2a-go-jsonrpc
    ;;

  # THE RUNNER'S OWN SELFTEST, run by `check-baseline-selftest.py`. It drives the real `run_tck`,
  # `compare_control` and `require_ceiling_report` with the suite replaced by a stand-in, in a
  # scratch directory: no network, no pinned checkout, no control. Each red leg plants the previous
  # run's GOOD report where the runner writes its own -- the state the persistent cache leaves --
  # and has the stand-in crash without writing one; the leg must end in the missing-report refusal,
  # never in a match. Each has a green twin whose stand-in does write the report.
  selftest)
    st="$(mktemp -d "${TMPDIR:-/tmp}/a2a-tck-selftest.XXXXXX")"
    trap 'rm -rf "$st"' EXIT
    TCK_DIR="$st/tck"; VENV="$st/venv"; OUT="$st/out"
    mkdir -p "$TCK_DIR" "$VENV/bin" "$OUT"
    printf '#!/bin/sh\nexec python3 "$@"\n' > "$VENV/bin/python"
    chmod +x "$VENV/bin/python"
    base="$HERE/baselines/control-a2a-go-jsonrpc.json"
    # The baseline's own zone, so the leg is about the report and not about the caller's TZ.
    TZ="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["tz"])' "$base")"
    export TZ
    # The last good run's report: the pinned verdicts, in the suite's report shape.
    export A2A_TCK_SELFTEST_GOOD="$st/good.json"
    python3 -c 'import json, sys
b = json.load(open(sys.argv[1]))
json.dump({"summary": {}, "per_requirement":
           {k: {"status": v} for k, v in b["per_requirement"].items()}}, sys.stdout)' \
      "$base" > "$A2A_TCK_SELFTEST_GOOD"
    printf 'import sys\nsys.exit(1)\n' > "$st/crashes.py"
    printf '%s\n' 'import os, shutil, sys' 'os.makedirs("reports", exist_ok=True)' \
      'shutil.copy(os.environ["A2A_TCK_SELFTEST_GOOD"], "reports/compatibility.json")' \
      'sys.exit(1)' > "$st/reports.py"
    fails=0 legs=0
    leg () {        # leg <name> <stand-in> <want-exit> <want-text> <report-name> <judge...>
      local name="$1" standin="$2" want="$3" text="$4" report="$5" rc=0
      shift 5
      legs=$((legs + 1))
      cp "$st/$standin.py" "$TCK_DIR/run_tck.py"
      cp "$A2A_TCK_SELFTEST_GOOD" "$OUT/$report.json"
      touch -t 202601010000 "$OUT/$report.json"
      ( run_tck "http://127.0.0.1:9" "$report" && "$@" ) > "$st/$name.log" 2>&1 || rc=$?
      if [ "$rc" = "$want" ] && grep -qF -- "$text" "$st/$name.log"; then
        echo "  ok   $name"
      else
        fails=$((fails + 1))
        echo "  FAIL $name -- exit $rc, wanted $want with '$text'"
        sed 's/^/       /' "$st/$name.log"
      fi
    }
    leg crashed_control_run_is_red crashes 2 "does not exist" control-a2a-go-jsonrpc \
      compare_control jsonrpc control-a2a-go-jsonrpc
    leg reporting_control_run_matches reports 0 "BASELINE MATCHED" control-a2a-go-jsonrpc \
      compare_control jsonrpc control-a2a-go-jsonrpc
    leg crashed_ceiling_run_is_red crashes 2 "does not exist" control-scenario-agent \
      require_ceiling_report
    leg reporting_ceiling_run_is_reported reports 0 "REPORT PRESENT" control-scenario-agent \
      require_ceiling_report
    if [ "$fails" -ne 0 ]; then
      echo "runner selftest: $fails of $legs legs FAILED"
      exit 1
    fi
    echo "runner selftest: $legs legs, all green"
    ;;

  *) sed -n '/^# USAGE/,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
