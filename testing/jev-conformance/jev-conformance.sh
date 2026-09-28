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
#       a pass. No cargo, no boot.

set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/conformance/verdicts/jev.json"
BIN=""
RUN_ID="${JEV_RUN_ID:-}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '%s\n' "$*"; }

# judge <battery-rc> <booted 0|1> <absence-code> <systemone-code> → prints "<status>\t<reason>".
# A PURE FUNCTION, so `--selftest` drives every rule without a build or a boot.
judge() {
  local battery="$1" booted="$2" absent="$3" code="$4"
  if [ "$battery" != "0" ]; then
    printf 'fail\tbattery: cargo test -p busbar-plane-decisions exited %s\n' "$battery"; return
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
  check "battery red is a fail naming the battery" "battery:" 101 1 404 404
  check "no boot is a fail, never a pass" "did not boot" 0 0 "" ""
  check "an unmeasured absence code is a fail" "did not boot" 0 1 "" 404
  check "no answer is a fail" "no answer" 0 1 404 000
  check "an absent route is NOT SERVED" "not served" 0 1 404 404
  check "absence is measured, not assumed (401 boot)" "not served" 0 1 401 401
  check "a mounted route without a served battery is still a fail" "mounted" 0 1 404 200
  # And no input at all yields a pass: the judge has no pass arm to reach.
  for b in 0 1; do for bo in 0 1; do for a in 404 401 ""; do for c in 200 404 401 500 ""; do
    case "$(judge "$b" "$bo" "$a" "$c")" in pass*) fail=1; red "FAIL  judge passed ($b $bo $a $c)" ;; esac
  done; done; done; done
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

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --selftest) selftest; exit $? ;;
      --out) OUT="$2"; shift 2 ;;
      --bin) BIN="$2"; shift 2 ;;
      --run-id) RUN_ID="$2"; shift 2 ;;
      *) echo "usage: $0 [--selftest] [--out FILE] [--bin PATH] [--run-id ID]" >&2; exit 2 ;;
    esac
  done
  command -v curl >/dev/null 2>&1 || { echo "jev-conformance: curl not found" >&2; exit 2; }
  command -v python3 >/dev/null 2>&1 || { echo "jev-conformance: python3 not found" >&2; exit 2; }
  local commit battery status reason
  commit="$(git -C "$REPO" rev-parse HEAD 2>/dev/null)" || { echo "jev-conformance: no commit to record" >&2; exit 2; }
  [ -n "$RUN_ID" ] || RUN_ID="local:$(hostname)"

  note "battery: cargo test -p busbar-plane-decisions"
  (cd "$REPO" && cargo test -q -p busbar-plane-decisions) >"${TMPDIR:-/tmp}/jev-battery.$$.log" 2>&1
  battery=$?
  if [ "$battery" -eq 0 ]; then grn "battery: green"; else
    red "battery: exited $battery"; grep -m20 -E 'FAILED|panicked|error(\[|:)' "${TMPDIR:-/tmp}/jev-battery.$$.log"
  fi
  rm -f "${TMPDIR:-/tmp}/jev-battery.$$.log"

  if [ -z "$BIN" ]; then
    (cd "$REPO" && cargo build -q -p busbar) || { red "served: the busbar binary did not build"; BIN=""; }
    [ -n "${CARGO_TARGET_DIR:-}" ] && BIN="${CARGO_TARGET_DIR}/debug/busbar" || BIN="$REPO/target/debug/busbar"
  fi
  BOOTED=0; ABSENT=""; CODE=""
  [ -x "$BIN" ] && served_leg "$BIN"

  IFS="$(printf '\t')" read -r status reason <<EOF
$(judge "$battery" "$BOOTED" "$ABSENT" "$CODE")
EOF
  write_verdict "$OUT" "$status" "$reason" "$commit" "$RUN_ID" || exit 2
  note "verdict: $status — $reason"
  note "written: $OUT"
  exit 0
}

main "$@"
