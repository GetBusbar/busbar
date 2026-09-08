#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# documented-claims-check.sh -- the DOCUMENTED-BEHAVIOUR CLAIM GATE.
#
# qa/documented-claims.json records every README and CHANGELOG behaviour claim the ops inventory
# cross-checks, each either pinned by a shadow-oracle cell or excused, in writing, as untestable
# prose -- and the two rows the design calls CONTRADICTED, which carry the CODE's behaviour as the
# parity target rather than the document's.
#
# WHY THIS GATE EXISTS. That register was cited as a `gate` by the design-bindings ledger while
# nothing in the tree opened it, and its own header claimed a sibling gate verified its cell ids.
# Neither was so. A data file compares nothing: it is an INPUT to a gate, never a gate. Until this
# script existed, a cited cell could be renamed away, a claim dropped, or a CONTRADICTED row quietly
# demoted to prose, with every check in the tree still green.
#
#   --check      assert the register: shape, a complete and contiguous claim run for README and for
#                CHANGELOG, a `counts` block re-derived from the claims rather than trusted, every
#                cited cell present in cells.json AND recorded PASS by the pinned golden, and both
#                CONTRADICTED rows still flagged, still pinned by a cell, and still naming the
#                documentation line they contradict and the behaviour the code actually has.
#   --selftest   the gate proves itself first: one planted defect per arm, each asserted to be
#                caught, and the unmodified register asserted green. A gate that cannot show it
#                sees a violation is not evidence that there is none.
#
# Existence and content only; nothing is executed and no cell is recorded.
# bash 3.2 + python3 (stdlib) -- the bare-runner posture of the sibling gates.
set -uo pipefail
cd "$(dirname "$0")/.."
repo="$(pwd)"

PY=python3
CHECK="scripts/documented-claims-check.py"
CLAIMS="qa/documented-claims.json"

usage() { sed -n '5,28p' "$0"; }

# ── SELF-TEST ───────────────────────────────────────────────────────────────────────────────────
# Each case mutates a COPY of the register with python and asserts the checker reds on it. The real
# cells.json and the real golden ledger are used throughout, so a case that passes for the wrong
# reason (an unreadable input reading as "no problems") cannot hide here.
selftest() {
  echo "== documented claims SELF-TEST (the gate proves itself before it judges the register) =="
  local tmp fails=0 cases=0 rc
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/documented-claims-selftest.XXXXXX")" || return 2
  trap 'rm -rf "$tmp"' RETURN
  say() { printf '%s  %s\n' "$1" "$2"; cases=$((cases+1)); [ "$1" = PASS ] || fails=$((fails+1)); }

  # plant <out> <python-body>  -- `d` is the parsed register; mutate it in place.
  plant() {
    local out="$1" body="$2"
    "$PY" - "$CLAIMS" "$out" "$body" <<'PYEOF'
import json, sys
src, out, body = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(src, encoding="utf-8"))
def claim(i):
    return next(c for c in d["claims"] if c["id"] == i)
exec(body)
json.dump(d, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
PYEOF
  }

  # run_case <label> <planted.json> <expected-substring>
  run_case() {
    local label="$1" file="$2" want="$3" log
    log="$tmp/$(basename "$file").log"
    "$PY" "$CHECK" --claims "$file" >"$log" 2>&1; rc=$?
    if [ "$rc" -ne 0 ] && grep -qF "$want" "$log"; then
      say PASS "$label"
    else
      say FAIL "$label (rc=$rc, expected a red naming '$want')"; sed 's/^/      /' "$log"
    fi
  }

  # (0) the register as committed is green -- the fixture the other cases are deltas from.
  "$PY" "$CHECK" --claims "$CLAIMS" >"$tmp/green.log" 2>&1; rc=$?
  [ "$rc" -eq 0 ] && say PASS "the committed register is green" \
    || { say FAIL "the committed register is RED"; sed 's/^/      /' "$tmp/green.log"; }

  # (a) a claim that is neither pinned nor excused
  plant "$tmp/a.json" 'c = claim("README:1054"); c["cell"] = []'
  run_case "a 'cell' claim naming no cell is caught" "$tmp/a.json" "names no cell"

  # (b) a claim dropped without a stated reason
  plant "$tmp/b.json" 'c = claim("README:1066"); c.pop("reason")'
  run_case "a 'prose' claim with no reason is caught" "$tmp/b.json" "dropped without saying why"

  # (c) a hole in the claim run -- the last CHANGELOG claim deleted
  plant "$tmp/c.json" 'd["claims"] = [c for c in d["claims"] if c["id"] != "CHANGELOG:1115"]'
  run_case "a dropped claim leaves a hole in the run" "$tmp/c.json" "CHANGELOG:1115"

  # (d) the hand-written summary drifting from the claims it summarises
  plant "$tmp/d.json" 'd["counts"]["cell"] = d["counts"]["cell"] + 1'
  run_case "a drifted counts block is caught" "$tmp/d.json" "counts.cell says"

  # (e) a cited cell that names nothing in cells.json
  plant "$tmp/e.json" 'claim("README:1057")["cell"] = ["documented|readme|no-such-cell-selftest"]'
  run_case "a cited cell absent from cells.json is caught" "$tmp/e.json" "is in no cell of"

  # (f) a cited cell that EXISTS but the pinned golden never recorded -- a pin whose comparison
  #     has never once run. The mysql store cell is exactly that shape in this tree.
  plant "$tmp/f.json" 'claim("README:1057")["cell"] = ["plugins.store-persist|store-mysql"]'
  run_case "a cited cell the golden never recorded is caught" "$tmp/f.json" "never recorded"

  # (g) a CONTRADICTED row demoted to ordinary prose -- a known documentation defect deleted
  plant "$tmp/g.json" 'c = claim("README:1061"); c["status"] = "prose"; c.pop("contradicted"); c.pop("cell"); c["reason"] = "selftest"'
  run_case "a CONTRADICTED row demoted to prose is caught" "$tmp/g.json" "README:1061"

  # (h) a CONTRADICTED row that stops saying what the code actually does
  plant "$tmp/h.json" 'claim("CHANGELOG:1099").pop("code_wins")'
  run_case "a CONTRADICTED row with no code_wins is caught" "$tmp/h.json" "no \`code_wins\`"

  # (i) an unreadable register is RED, never vacuously green
  printf 'not json at all\n' >"$tmp/i.json"
  run_case "an unreadable register is red, not vacuously green" "$tmp/i.json" "unreadable claim register"

  if [ "$fails" -eq 0 ]; then echo "documented claims selftest: GREEN (${cases} cases)"; return 0; fi
  echo "documented claims selftest: RED (${fails}/${cases} cases failed)"; return 1
}

MODE=check
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --selftest) MODE=selftest ;;
    -h|--help) usage; exit 0 ;;
    *) echo "usage: $0 --check | --selftest" >&2; exit 2 ;;
  esac
  shift
done

case "$MODE" in
  check)    "$PY" "$CHECK" ;;
  selftest) selftest ;;
esac
