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
#   run-tck.sh selftest              every refusal this runner and scenario-agent/serve.sh make,
#                                    planted with stand-ins (no network, no control)
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
mkdir -p "$WORK" "$BIN_DIR" "$OUT" 2>/dev/null || {
  echo "could not create the work directories under $WORK, $BIN_DIR and $OUT -- refusing to run" >&2
  exit 2
}

say () { printf '\n=== %s ===\n' "$*"; }

# discard <dir> <what>: remove a half-made <what> so the next run builds it again instead of
# trusting it, and say whether it is gone (a refusal names both outcomes; it never assumes one).
discard () {
  if [ ! -e "$1" ]; then
    echo "nothing was left at $1"
    return 0
  fi
  rm -rf "$1" 2>/dev/null || true
  if [ -e "$1" ]; then
    echo "the half-made $2 at $1 could not be removed; remove it by hand"
  else
    echo "the half-made $2 at $1 was removed"
  fi
}

# read_pin <file> <NAME> -> prints the value of the first NAME="..." line. Refuses (exit 2) when
# the file is not there or cannot be read; prints nothing when it holds no such line. One sed pass
# that quits on the first match, so no pipe can fail under pipefail.
read_pin () {
  local file="$1" name="$2" text=""
  if [ ! -e "$file" ]; then
    echo "the pin file $file is not there -- refusing to run" >&2
    exit 2
  fi
  text="$(cat "$file" 2>/dev/null)" \
    || { echo "the pin file $file cannot be read -- refusing to run" >&2; exit 2; }
  sed -n "/^$name=\"/{s/^$name=\"\([^\"]*\)\".*/\1/p;q;}" <<< "$text"
}

fetch_tck () {
  if [ ! -d "$TCK_DIR/.git" ]; then
    say "fetching a2a-tck at pinned ${TCK_REF}"
    # A half-made checkout is removed, so the next run fetches again instead of trusting it.
    git init -q "$TCK_DIR" \
      && git -C "$TCK_DIR" remote add origin https://github.com/a2aproject/a2a-tck.git \
      && git -C "$TCK_DIR" fetch -q --depth 1 origin "$TCK_REF" \
      && git -C "$TCK_DIR" checkout -q FETCH_HEAD \
      || {
        note="$(discard "$TCK_DIR" checkout)"
        echo "could not fetch a2a-tck at $TCK_REF into $TCK_DIR; $note -- refusing to run" >&2
        exit 2
      }
  fi
  got="$(git -C "$TCK_DIR" rev-parse HEAD 2>/dev/null)" || got="no commit"
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
    python3 -m venv "$VENV" \
      && "$VENV/bin/pip" -q install --upgrade pip \
      && ( cd "$TCK_DIR" && "$VENV/bin/pip" -q install -e . ) \
      || {
        note="$(discard "$VENV" virtualenv)"
        echo "could not install a2a-tck into $VENV; $note -- refusing to run" >&2
        exit 2
      }
  fi
  "$VENV/bin/python" -c 'import pytest, grpc, jsonschema' \
    || { echo "a2a-tck dependencies did not import" >&2; exit 2; }
}

install_control () {
  # ONE PIN FOR ONE PEER. The harness installs the same control into the same cache; a version
  # spelled here and there that has drifted is two instruments describing different peers, so the
  # disagreement -- or a harness file that no longer states its pin -- refuses the run.
  local harness_pin_file="$HERE/../a2a-harness/scripts/install-control.sh" harness_pin=""
  harness_pin="$(read_pin "$harness_pin_file" CONTROL_GO_VERSION)" || exit 2
  if [ -z "$harness_pin" ]; then
    echo "no CONTROL_GO_VERSION pin in $harness_pin_file -- refusing to run" >&2
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
      "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}" \
      || { echo "could not install control a2a-go ${CONTROL_GO_VERSION} into $BIN_DIR -- refusing to run" >&2; exit 2; }
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
  "$BIN_DIR/a2a" --help >/dev/null 2>&1 \
    || { echo "control binary $BIN_DIR/a2a does not run (\`a2a --help\` failed) -- refusing to run" >&2; exit 2; }
}

# run_tck <base-url> <report-name>  -> sets RUN_STARTED
run_tck () {
  local url="$1" name="$2" rc=0
  # The suite's own report directory from an earlier run goes first, for the same reason as the
  # copied report below: what is found there afterwards must be this run's.
  rm -rf "$TCK_DIR/reports" 2>/dev/null || true
  if [ -e "$TCK_DIR/reports" ]; then
    echo "could not remove the suite's previous reports directory $TCK_DIR/reports -- refusing to run" >&2
    exit 2
  fi
  # A REPORT AN EARLIER RUN COPIED HERE IS NOT THIS RUN'S EVIDENCE. OUT sits under WORK, which the
  # wired recorder keeps in a persistent cache; left in place, the last good run's report would be
  # read as the report of a run that crashed before writing one, and it would match its baseline.
  # Removed before the suite starts, and the comparator separately refuses any report older than
  # RUN_STARTED, so the crashed run reaches the missing-report refusal it is owed.
  rm -f "$OUT/$name.json" 2>/dev/null || true
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
    cp "$TCK_DIR/reports/compatibility.json" "$OUT/$name.json" 2>/dev/null \
      || { echo "could not copy the suite's report to $OUT/$name.json -- refusing to run" >&2; exit 2; }
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

# await_card <port> <tries> <interval> <what> <log>
#
# Waits for the peer started as CONTROL_PID to serve its card. A peer that has already exited will
# never serve it, so that ends the wait at once instead of after every try; either way the run is
# refused with the peer's own log.
await_card () {
  local port="$1" tries="$2" interval="$3" what="$4" log="$5"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$port/.well-known/agent-card.json"; then
      return 0
    fi
    kill -0 "$CONTROL_PID" 2>/dev/null || break
    sleep "$interval"
  done
  cat "$log" >&2 || true
  stop_control
  echo "$what did not come up on port $port -- refusing to run" >&2
  exit 2
}

# serve_control <port> <transport>  -> exports CONTROL_PID
serve_control () {
  local port="$1" transport="$2"
  "$BIN_DIR/a2a" serve --echo --port "$port" --quiet --transport "$transport" \
    > "$OUT/control-$transport.log" 2>&1 &
  CONTROL_PID=$!
  await_card "$port" 50 0.2 control "$OUT/control-$transport.log"
}

# stop_control: kill the peer AND wait for it, so its port is free when this returns. A peer that
# ignores the polite signal for five seconds gets SIGKILL, so the wait is bounded.
stop_control () {
  if [ -n "${CONTROL_PID:-}" ]; then
    kill "$CONTROL_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$CONTROL_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$CONTROL_PID" 2>/dev/null || true
    wait "$CONTROL_PID" 2>/dev/null || true
  fi
}

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
  await_card "$port" 300 0.5 "the scenario agent" "$OUT/control-scenario.log"
}

# install_crypto: the one extra dependency `prepare` adds -- see that verb.
install_crypto () {
  "$VENV/bin/python" -c 'import cryptography' 2>/dev/null \
    || "$VENV/bin/pip" -q install cryptography \
    || { echo "could not install cryptography into $VENV; the card-signing checks cannot run" >&2; exit 2; }
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
  #
  # NOT RUN IN CI. The conformance recorder (`xtask/src/conformance_record/a2a.rs`) runs
  # `control-http-json` and `control-jsonrpc` and not this leg, which is run by hand. Its refusal of
  # a run that produced no report is proven in CI only through `run-tck.sh selftest`
  # (`crashed_ceiling_run_is_red` and its green twin), never by a run of this leg.
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
    install_crypto
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

  # THE RUNNER'S OWN SELFTEST, run by `check-baseline-selftest.py`. EVERY REFUSAL THIS RUNNER AND
  # `scenario-agent/serve.sh` CAN MAKE IS PLANTED HERE, against the real functions, in a scratch
  # directory, with the suite, the control binary, `go`, `git`, `python3`, `rm`, the harness pin
  # file and the scenario agent replaced by stand-ins: no network, no pinned checkout, no control.
  # A leg passes only when its wanted text is on the LAST line the command printed (blank lines and
  # `====` rules aside), so a refusal must also STOP the run: one that printed its message and
  # carried on into a further stage fails its leg. Legs about a half-made checkout or virtualenv also
  # look at the disk afterwards.
  #
  # WHAT COUNTS AS EVERY REFUSAL. Every step either script runs that can fail is guarded and
  # refuses with its own message; the comparator's own refusals, which `compare_control` and
  # `require_ceiling_report` pass through, are planted by `check-baseline-selftest.py` itself.
  # The only unguarded steps are the ones that cannot fail on a checkout: `cd` into the script's
  # own directory, `mkdir -p` of the tracked `baselines/` directory, and serve.sh's final `exec` of
  # the interpreter it has just run.
  #
  # Every refusal has a green twin -- the same stand-ins minus the planted defect -- with TWO
  # exceptions, both because their green side needs the network: `fetch_tck`'s pin refusal (a
  # checkout AT the pin can only be fetched), exercised by every control leg the conformance
  # recorder runs; and the subject verb's endpoint refusal (a subject run fetches the suite and
  # needs a live endpoint), exercised by `scripts/a2a-subject/boot.sh --tck`.
  #
  # The report legs plant the previous run's GOOD report where the runner writes its own -- the
  # state the persistent cache leaves -- and have the stand-in suite crash without writing one; the
  # leg must end in the missing-report refusal, never in a match. Each peer leg gets its own port,
  # and `stop_control` waits (boundedly) for the peer it kills, so no leg inherits another's listener.
  selftest)
    st="$(mktemp -d "${TMPDIR:-/tmp}/a2a-tck-selftest.XXXXXX")"
    trap 'rm -rf "$st"' EXIT
    REAL_HERE="$HERE"
    TCK_DIR="$st/tck"; VENV="$st/venv"; OUT="$st/out"
    mkdir -p "$TCK_DIR" "$VENV/bin" "$OUT"
    # stand-in <path> <shell body>: an executable /bin/sh script.
    standin () { mkdir -p "$(dirname "$1")"; printf '#!/bin/sh\n%s\n' "$2" > "$1"; chmod +x "$1"; }
    standin "$VENV/bin/python" 'exec python3 "$@"'
    base="$HERE/baselines/control-a2a-go-jsonrpc.json"
    # The baseline's own zone, so the legs are about the runner and not about the caller's TZ.
    TZ="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["tz"])' "$base")"
    export TZ
    # The last good run's report: the pinned verdicts, in the suite's report shape.
    export A2A_TCK_SELFTEST_GOOD="$st/good.json"
    python3 -c 'import json, sys
b = json.load(open(sys.argv[1]))
json.dump({"summary": {}, "per_requirement":
           {k: {"status": v} for k, v in b["per_requirement"].items()}}, sys.stdout)' \
      "$base" > "$A2A_TCK_SELFTEST_GOOD"
    # Stand-in suites: one that crashes, one that reports, and one that reports but leaves a
    # directory where the runner must copy the report (`A2A_TCK_SELFTEST_BLOCK` names it).
    printf 'import sys\nsys.exit(1)\n' > "$st/crashes.py"
    printf '%s\n' 'import os, shutil, sys' 'os.makedirs("reports", exist_ok=True)' \
      'shutil.copy(os.environ["A2A_TCK_SELFTEST_GOOD"], "reports/compatibility.json")' \
      'sys.exit(1)' > "$st/reports.py"
    printf '%s\n' 'import os, shutil, sys' 'os.makedirs("reports", exist_ok=True)' \
      'shutil.copy(os.environ["A2A_TCK_SELFTEST_GOOD"], "reports/compatibility.json")' \
      'os.makedirs(os.path.join(os.environ["A2A_TCK_SELFTEST_BLOCK"], "compatibility.json"))' \
      'sys.exit(1)' > "$st/blocks-the-copy.py"
    # A peer that serves a card on the port it is given (`--port N`, or the first argument).
    printf '%s\n' '#!/usr/bin/env python3' 'import http.server, sys' \
      'a = sys.argv[1:]' 'port = int(a[a.index("--port") + 1] if "--port" in a else a[0])' \
      'class H(http.server.BaseHTTPRequestHandler):' \
      '    def do_GET(self):' \
      '        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")' \
      '    def log_message(self, *args):' '        pass' \
      'http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()' > "$st/serving-peer"
    chmod +x "$st/serving-peer"
    free_port () { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
    # A harness tree beside a fake HERE: harness_tree <dir> <install-control.sh body, or -none->.
    harness_tree () {
      mkdir -p "$1/a2a-tck/scenario-agent"
      cp "$REAL_HERE/scenario-agent/serve.sh" "$1/a2a-tck/scenario-agent/serve.sh"
      if [ "$2" != "-none-" ]; then
        mkdir -p "$1/a2a-harness/scripts"
        printf '%s\n' "$2" > "$1/a2a-harness/scripts/install-control.sh"
      fi
    }
    pins () { printf 'CONTROL_GO_VERSION="%s"\nCONTROL_PY_VERSION="%s"\n' "$1" "$2"; }
    harness_tree "$st/h-nofile" -none-
    harness_tree "$st/h-noline" '# a harness file that no longer states its pins'
    # A pin file that is there and cannot be read (a directory: unreadable as a file even to root).
    harness_tree "$st/h-unreadable" -none-
    mkdir -p "$st/h-unreadable/a2a-harness/scripts/install-control.sh"
    harness_tree "$st/h-disagrees" "$(pins v0.0.1 0.0.1)"
    harness_tree "$st/h-agrees" "$(pins "$CONTROL_GO_VERSION" 9.9.9)"
    harness_tree "$st/h-sdk-other" "$(pins "$CONTROL_GO_VERSION" 7.7.7)"
    harness_tree "$st/h-sdk-unreadable" "$(pins "$CONTROL_GO_VERSION" 6.6.6)"
    harness_tree "$st/h-sdk-uninstallable" "$(pins "$CONTROL_GO_VERSION" 5.5.5)"
    # `go` stand-ins: `go version -m` reporting the pinned module version or another one; a `go`
    # whose every command fails; and one whose `go install` installs a working binary.
    for v in "$CONTROL_GO_VERSION" v2.3.0; do
      standin "$st/go-$v/go" "printf '%s\\n' \"\$3: go1.22\" '	path	github.com/a2aproject/a2a-go/v2/cmd/a2a' '	mod	github.com/a2aproject/a2a-go/v2	$v	h1:selftest'"
    done
    standin "$st/go-fails/go" 'echo "go stand-in: failing" >&2; exit 1'
    standin "$st/go-installs/go" "if [ \"\$1\" = install ]; then mkdir -p \"\$GOBIN\"; printf '#!/bin/sh\\nexit 0\\n' > \"\$GOBIN/a2a\"; chmod +x \"\$GOBIN/a2a\"; else exec \"$st/go-$CONTROL_GO_VERSION/go\" \"\$@\"; fi"
    standin "$st/git-fails/git" 'echo "git stand-in: failing" >&2; exit 1'
    standin "$st/python3-fails/python3" 'echo "python3 stand-in: failing" >&2; exit 1'
    # Stand-ins that leave something half-made: a `git` whose `init` is the real one and whose
    # every step after it fails; a `python3 -m venv` that makes a virtualenv whose `pip` fails. Each
    # also comes paired with an `rm` that cannot remove anything.
    real_git="$(command -v git)"
    for d in half half+rm-fails; do
      standin "$st/git-$d/git" "if [ \"\$1\" = init ]; then exec \"$real_git\" \"\$@\"; fi; echo 'git stand-in: fetch fails' >&2; exit 1"
      standin "$st/python3-$d/python3" "if [ \"\$1\" = -m ] && [ \"\$2\" = venv ]; then mkdir -p \"\$3/bin\"; printf '#!/bin/sh\\nexit 0\\n' > \"\$3/bin/python\"; printf '#!/bin/sh\\necho pip stand-in: failing >&2; exit 1\\n' > \"\$3/bin/pip\"; chmod +x \"\$3/bin/python\" \"\$3/bin/pip\"; exit 0; fi; exit 1"
    done
    for d in rm-fails git-half+rm-fails python3-half+rm-fails; do
      standin "$st/$d/rm" 'echo "rm stand-in: cannot remove" >&2; exit 1'
    done
    # A peer that ignores SIGTERM, and leaves by itself after 30 seconds.
    standin "$st/stubborn-peer" "trap '' TERM; i=0; while [ \$i -lt 30 ]; do sleep 1; i=\$((i + 1)); done"
    standin "$st/bin/a2a" 'exit 0'                       # a cached binary that answers --help
    standin "$st/bin-broken/a2a" 'echo "a2a stand-in: broken" >&2; exit 1'
    mkdir -p "$st/bin-serving"; ln -s "$st/serving-peer" "$st/bin-serving/a2a"
    # Scenario agents behind a fake HERE: one that dies at once, one that serves.
    standin "$st/agent-dies/scenario-agent/serve.sh" 'echo "scenario agent stand-in exits"; exit 1'
    mkdir -p "$st/agent-serves/scenario-agent"
    ln -s "$st/serving-peer" "$st/agent-serves/scenario-agent/serve.sh"
    # A scenario-agent work directory: venv-9.9.9 is the pinned SDK and does not serve, venv-7.7.7
    # holds another SDK version, venv-6.6.6 cannot say its version; there is no venv-5.5.5.
    standin "$st/agent-work/venv-9.9.9/bin/python" \
      "if [ \"\$1\" = -c ]; then echo 9.9.9; else echo \"scenario agent would serve with a2a-sdk 9.9.9: \$*\"; fi"
    standin "$st/agent-work/venv-7.7.7/bin/python" 'echo 1.1.2'
    standin "$st/agent-work/venv-6.6.6/bin/python" 'exit 1'
    # Virtualenvs for install_tck and install_crypto: one whose imports fail and whose pip fails,
    # one whose imports succeed, and none at all.
    standin "$st/venv-broken/bin/python" 'exit 1'
    standin "$st/venv-broken/bin/pip" 'exit 1'
    standin "$st/venv-ok/bin/python" 'exit 0'
    # Cached suite checkouts that are not the pin: one at another commit, one with no commit.
    git init -q "$st/tck-wrong"
    git -C "$st/tck-wrong" -c user.name=selftest -c user.email=selftest@invalid \
      -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -q --allow-empty -m selftest
    git init -q "$st/tck-empty"

    fails=0 legs=0
    # expect <name> <want-exit> <want-text> <command...>
    expect () {
      local name="$1" want="$2" text="$3" rc=0
      shift 3
      legs=$((legs + 1))
      ( "$@" ) > "$st/$name.log" 2>&1 || rc=$?
      local last
      last="$(grep -v '^[[:space:]]*$' "$st/$name.log" | grep -v '^=*$' | tail -n 1)" || last=""
      if [ "$rc" = "$want" ] && printf '%s\n' "$last" | grep -qF -- "$text"; then
        echo "  ok   $name"
      else
        fails=$((fails + 1))
        echo "  FAIL $name -- exit $rc, wanted $want with '$text' on the last line"
        sed 's/^/       /' "$st/$name.log"
      fi
    }
    # report_leg <name> <stand-in> <want-exit> <want-text> <report-name> <judge...>
    report_leg () {
      local name="$1" standin="$2" want="$3" text="$4" report="$5"
      shift 5
      cp "$st/$standin.py" "$TCK_DIR/run_tck.py"
      rm -rf "$OUT/$report.json"
      cp "$A2A_TCK_SELFTEST_GOOD" "$OUT/$report.json"
      touch -t 202601010000 "$OUT/$report.json"
      expect "$name" "$want" "$text" run_then_judge "$report" "$@"
    }
    run_then_judge () { local report="$1"; shift; run_tck "http://127.0.0.1:9" "$report" && "$@"; }
    # disk_after <dir> <refusal-text> <command...>: run the command, then say what is at <dir> and
    # whether the command's own last line was the refusal (so it stopped there). The command's
    # exit status is kept, so the leg still judges the refusal's exit too.
    disk_after () {
      local dir="$1" text="$2" rc=0 out="" last="" stopped=no state=gone
      shift 2
      out="$( ( "$@" ) 2>&1 )" || rc=$?
      printf '%s\n' "$out"
      last="$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -n 1)" || last=""
      case "$last" in *"$text"*) stopped=yes ;; esac
      [ -e "$dir" ] && state=left
      echo "on disk afterwards: $dir is $state; stopped on the refusal: $stopped"
      return "$rc"
    }

    # -- the work directories
    expect the_runner_refuses_work_directories_it_cannot_create 2 "could not create the work directories" \
      env -u A2AHT_CONTROL_BIN -u A2A_TCK_OUT A2A_TCK_WORK=/dev/null/selftest \
      bash "$REAL_HERE/run-tck.sh" no-such-verb

    # -- the report a run leaves, and the previous run's report it must not be judged by
    report_leg crashed_control_run_is_red crashes 2 "Nothing was compared" control-a2a-go-jsonrpc \
      compare_control jsonrpc control-a2a-go-jsonrpc
    report_leg reporting_control_run_matches reports 0 "every status identical to the pin" control-a2a-go-jsonrpc \
      compare_control jsonrpc control-a2a-go-jsonrpc
    report_leg crashed_ceiling_run_is_red crashes 2 "Nothing was compared" control-scenario-agent \
      require_ceiling_report
    report_leg reporting_ceiling_run_is_reported reports 0 "reported, not compared" control-scenario-agent \
      require_ceiling_report
    # The previous report cannot be removed (it is a directory with something in it).
    cp "$st/crashes.py" "$TCK_DIR/run_tck.py"
    mkdir -p "$OUT/undeletable.json/held"
    expect run_tck_refuses_a_report_it_cannot_remove 2 "could not remove the previous run's report" \
      run_tck "http://127.0.0.1:9" undeletable
    rm -rf "$OUT/undeletable.json"
    # The suite's previous reports directory cannot be removed; and the twin, where it can be.
    rt () { PATH="$1:$PATH"; mkdir -p "$TCK_DIR/reports"; run_tck "http://127.0.0.1:9" removable; }
    expect run_tck_refuses_a_reports_directory_it_cannot_remove 2 \
      "could not remove the suite's previous reports directory" rt "$st/rm-fails"
    expect run_tck_removes_what_an_earlier_run_left 0 "a2a-tck exit 1" rt "$st/no-stand-in"
    # The suite's report cannot be copied into place.
    cp "$st/blocks-the-copy.py" "$TCK_DIR/run_tck.py"
    copy_blocked () { export A2A_TCK_SELFTEST_BLOCK="$OUT/blocked.json"; run_tck "http://127.0.0.1:9" blocked; }
    expect run_tck_refuses_a_report_it_cannot_copy 2 "could not copy the suite's report" copy_blocked

    # -- the control binary and its pin
    ic () { HERE="$1"; BIN_DIR="$2"; PATH="$3:$PATH"; install_control && echo "control binary verified"; }
    expect install_control_refuses_a_missing_harness_pin_file 2 "is not there" \
      ic "$st/h-nofile/a2a-tck" "$st/bin" "$st/go-$CONTROL_GO_VERSION"
    expect install_control_refuses_an_unreadable_harness_pin_file 2 "cannot be read" \
      ic "$st/h-unreadable/a2a-tck" "$st/bin" "$st/go-$CONTROL_GO_VERSION"
    expect install_control_refuses_a_harness_file_without_a_pin 2 "no CONTROL_GO_VERSION pin in" \
      ic "$st/h-noline/a2a-tck" "$st/bin" "$st/go-$CONTROL_GO_VERSION"
    expect install_control_refuses_a_harness_pin_disagreement 2 "a2a-go pin disagreement" \
      ic "$st/h-disagrees/a2a-tck" "$st/bin" "$st/go-$CONTROL_GO_VERSION"
    expect install_control_refuses_a_failed_install 2 "could not install control a2a-go" \
      ic "$st/h-agrees/a2a-tck" "$st/bin-empty" "$st/go-fails"
    expect install_control_installs_a_missing_binary 0 "control binary verified" \
      ic "$st/h-agrees/a2a-tck" "$st/bin-fresh" "$st/go-installs"
    expect install_control_refuses_a_binary_of_another_version 2 "is a2a-go 'v2.3.0'" \
      ic "$st/h-agrees/a2a-tck" "$st/bin" "$st/go-v2.3.0"
    expect install_control_refuses_a_binary_that_does_not_run 2 "does not run" \
      ic "$st/h-agrees/a2a-tck" "$st/bin-broken" "$st/go-$CONTROL_GO_VERSION"
    expect install_control_accepts_the_pinned_binary 0 "control binary verified" \
      ic "$st/h-agrees/a2a-tck" "$st/bin" "$st/go-$CONTROL_GO_VERSION"

    # -- the suite checkout and its virtualenv
    ft () { TCK_DIR="$1"; PATH="$2:$PATH"; fetch_tck; }
    expect fetch_tck_refuses_a_failed_fetch 2 "nothing was left at $st/tck-unfetched -- refusing to run" \
      ft "$st/tck-unfetched" "$st/git-fails"
    expect fetch_tck_removes_a_half_made_checkout 2 "$st/tck-half is gone; stopped on the refusal: yes" \
      disk_after "$st/tck-half" "was removed -- refusing to run" ft "$st/tck-half" "$st/git-half"
    expect fetch_tck_says_when_a_half_made_checkout_remains 2 "$st/tck-half2 is left; stopped on the refusal: yes" \
      disk_after "$st/tck-half2" "could not be removed; remove it by hand -- refusing to run" ft "$st/tck-half2" "$st/git-half+rm-fails"
    expect fetch_tck_refuses_a_checkout_that_is_not_the_pin 2 "refusing to run" \
      ft "$st/tck-wrong" "$st/no-stand-in"
    expect fetch_tck_refuses_a_checkout_with_no_commit 2 "a2a-tck checkout is no commit" \
      ft "$st/tck-empty" "$st/no-stand-in"
    it () { VENV="$1"; PATH="$2:$PATH"; install_tck && echo "suite dependencies import"; }
    expect install_tck_refuses_a_failed_install 2 "nothing was left at $st/venv-none -- refusing to run" \
      it "$st/venv-none" "$st/python3-fails"
    expect install_tck_removes_a_half_made_virtualenv 2 "$st/venv-half is gone; stopped on the refusal: yes" \
      disk_after "$st/venv-half" "was removed -- refusing to run" it "$st/venv-half" "$st/python3-half"
    expect install_tck_says_when_a_half_made_virtualenv_remains 2 "$st/venv-half2 is left; stopped on the refusal: yes" \
      disk_after "$st/venv-half2" "could not be removed; remove it by hand -- refusing to run" it "$st/venv-half2" "$st/python3-half+rm-fails"
    expect install_tck_refuses_dependencies_that_do_not_import 2 "did not import" \
      it "$st/venv-broken" "$st/no-stand-in"
    expect install_tck_accepts_dependencies_that_import 0 "suite dependencies import" \
      it "$st/venv-ok" "$st/no-stand-in"
    icr () { VENV="$1"; install_crypto && echo "cryptography imports"; }
    expect install_crypto_refuses_when_it_cannot_install 2 "could not install cryptography" \
      icr "$st/venv-broken"
    expect install_crypto_accepts_an_importable_cryptography 0 "cryptography imports" icr "$st/venv-ok"

    # -- the peers: one that exits before serving, one that serves; each on its own port
    sc () { BIN_DIR="$1"; serve_control "$(free_port)" jsonrpc && echo "control came up"; stop_control; }
    expect serve_control_refuses_a_control_that_never_serves 2 "control did not come up" sc "$st/bin"
    expect serve_control_waits_for_a_control_that_serves 0 "control came up" sc "$st/bin-serving"
    ssa () { HERE="$1"; serve_scenario_agent "$(free_port)" && echo "scenario agent came up"; stop_control; }
    expect serve_scenario_agent_refuses_an_agent_that_never_serves 2 \
      "the scenario agent did not come up" ssa "$st/agent-dies"
    expect serve_scenario_agent_waits_for_an_agent_that_serves 0 "scenario agent came up" \
      ssa "$st/agent-serves"

    # A peer that ignores SIGTERM is still gone within the bound, not after its own 30 seconds.
    stc () {
      "$st/stubborn-peer" & CONTROL_PID=$!
      sleep 0.3
      local t0=$SECONDS took
      stop_control
      took=$((SECONDS - t0))
      if kill -0 "$CONTROL_PID" 2>/dev/null; then echo "peer still running"; return 1; fi
      if [ "$took" -le 10 ]; then echo "peer stopped in ${took}s, within the bound"; else echo "peer stopped in ${took}s, past the bound"; fi
    }
    expect stop_control_stops_a_peer_that_ignores_term 0 "within the bound" stc

    # -- scenario-agent/serve.sh and the a2a-sdk pin it reads
    # sv <tree> [work-dir] [stand-in PATH dir] [-no-port-]
    sv () {
      local work="${2:-$st/agent-work}" path="${3:-$st/no-stand-in}"
      if [ "${4:-}" = -no-port- ]; then
        A2A_SCENARIO_AGENT_WORK="$work" PATH="$path:$PATH" bash "$1/a2a-tck/scenario-agent/serve.sh"
      else
        A2A_SCENARIO_AGENT_WORK="$work" PATH="$path:$PATH" bash "$1/a2a-tck/scenario-agent/serve.sh" 1
      fi
    }
    expect serve_sh_refuses_without_a_port 1 "usage: serve.sh" sv "$st/h-agrees" "" "" -no-port-
    expect serve_sh_refuses_a_missing_pin_file 2 "file is not there" sv "$st/h-nofile"
    expect serve_sh_refuses_an_unreadable_pin_file 2 "is there but is not readable as a file" sv "$st/h-unreadable"
    expect serve_sh_refuses_a_missing_pin_line 2 "states no CONTROL_PY_VERSION" sv "$st/h-noline"
    expect serve_sh_refuses_a_work_directory_it_cannot_create 2 "could not create the scenario agent's work directory" \
      sv "$st/h-agrees" /dev/null/selftest
    expect serve_sh_refuses_a_failed_install 2 "nothing was left at $st/agent-work/venv-5.5.5 -- refusing to serve" \
      sv "$st/h-sdk-uninstallable" "" "$st/python3-fails"
    expect serve_sh_removes_a_half_made_virtualenv 2 "$st/agent-work/venv-5.5.5 is gone; stopped on the refusal: yes" \
      disk_after "$st/agent-work/venv-5.5.5" "was removed -- refusing to serve" sv "$st/h-sdk-uninstallable" "" "$st/python3-half"
    expect serve_sh_says_when_a_half_made_virtualenv_remains 2 "$st/agent-work/venv-5.5.5 is left; stopped on the refusal: yes" \
      disk_after "$st/agent-work/venv-5.5.5" "could not be removed; remove it by hand -- refusing to serve" sv "$st/h-sdk-uninstallable" "" "$st/python3-half+rm-fails"
    rm -rf "$st/agent-work/venv-5.5.5"
    expect serve_sh_refuses_an_a2a_sdk_of_another_version 2 "is 1.1.2, pin is 7.7.7" \
      sv "$st/h-sdk-other"
    expect serve_sh_refuses_an_a2a_sdk_that_cannot_say_its_version 2 "is unreadable, pin is 6.6.6" \
      sv "$st/h-sdk-unreadable"
    expect serve_sh_serves_at_the_pin_it_reads 0 "would serve with a2a-sdk 9.9.9" sv "$st/h-agrees"

    # -- the verbs
    expect subject_refuses_without_an_endpoint 1 "needs BUSBAR_A2A_ENDPOINT" \
      env -u BUSBAR_A2A_ENDPOINT bash "$REAL_HERE/run-tck.sh" subject
    expect an_unknown_verb_prints_usage_and_refuses 2 "planted with stand-ins (no network, no control)" \
      bash "$REAL_HERE/run-tck.sh" no-such-verb

    if [ "$fails" -ne 0 ]; then
      echo "runner selftest: $fails of $legs legs FAILED"
      exit 1
    fi
    echo "runner selftest: $legs legs, all green"
    ;;

  *) sed -n '/^# USAGE/,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
