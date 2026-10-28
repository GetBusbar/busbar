#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RENDERED by `busbar-release plugin heal` from GetBusbar/busbar-release template/conformance/run.sh;
# a hand edit is overwritten by the next sync.
#
# THE CONFORMANCE CHECK: every official suite this repo owns, run against busbar at the pin in
# `.busbar-ref` (busbar itself, which has no pin, judges its own HEAD), each judged into one busbar.conformance.verdict/1 file that busbar's
# conformance/verdicts/ imports. ModernCI runs it as the `conformance` check of every plugin repo
# (template/modernci/conformance.yaml):
#
#     bash testing/conformance/run.sh            # every suite in testing/conformance/suites.tsv
#     bash testing/conformance/run.sh --selftest # the verdict judge bites on planted verdicts
#
# THE SUITE LIST is this repo's own `testing/conformance/suites.tsv` (not templated): one suite per
# line, `<suite-id><TAB><command>`; `#` starts a comment. The id is busbar's registry id
# (conformance/registry.toml). The command runs from the repo root with:
#
#     CONFORMANCE_SUITE  the suite id
#     CONFORMANCE_OUT    an empty directory; the command MUST write $CONFORMANCE_OUT/verdict.json
#     BUSBAR_CHECKOUT    busbar at the pin (a full checkout)
#     BUSBAR_PIN         the pin's sha
#     CARGO_TARGET_DIR   this repo's target/ (the subject builds there)
#
# and node 22 and rust on PATH (testing/conformance/tools.sh). Its verdict states `suite`, `status`
# (pass|fail|not-run), `armed`, and may state `standard`, `plan`, `spec_version`, `reason`. A command
# keeps the suite's three legs: the control (a known-good third-party peer) always runs, the negative
# control (a deliberately broken peer) must grade red, and the subject is armed or red. `pass` means
# all three held.
#
# THIS SCRIPT then holds each verdict to the schema (an absent, unreadable or mismatched verdict is
# `fail`, never skipped), stamps what the suite's freshness is judged by (`repo`, `commit`,
# `core_pin`, `run_id`, `evidence`: the ModernCI move, `generated_at`) and writes it to
# target/conformance/verdicts/<id>.json, the check's output. Exit 0 only when every suite passed; an
# empty list exits 0 and says so.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$here" || exit 2
LIST="testing/conformance/suites.tsv"
OUT="$here/target/conformance"
MCI_URL="${MODERNCI_URL:-https://eu-central.modernci.dev}"

say() { printf 'conformance: %s\n' "$*" >&2; }

# judge <raw verdict> <suite id> <command rc> <out file>: the verdict as published, or exit 1.
judge() {
  python3 -I - "$@" <<'PY'
import json, sys, os, datetime
raw, suite, rc, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
KEYS = {"schema", "suite", "standard", "plan", "spec_version", "status", "armed", "commit",
        "run_id", "evidence", "generated_at", "reason", "repo", "core_pin"}
def refuse(why):
    return {"suite": suite, "status": "fail", "armed": True,
            "reason": "the suite wrote no valid verdict: " + why}
def check(v):
    if not isinstance(v, dict):
        return "verdict.json is not an object"
    if v.get("suite") != suite:
        return f"verdict names suite {v.get('suite')!r}, filed under {suite!r}"
    extra = set(v) - KEYS
    if extra:
        return f"verdict carries unknown fields {sorted(extra)}"
    if v.get("status") not in ("pass", "fail", "not-run"):
        return f"status {v.get('status')!r} is not pass|fail|not-run"
    if not isinstance(v.get("armed"), bool):
        return "armed is not a boolean"
    if v["armed"] is False and v["status"] != "not-run":
        return f"an unarmed verdict claims {v['status']}"
    if v["status"] == "pass" and rc != 0:
        return f"the verdict says pass but the command exited {rc}"
    return None
try:
    v = json.load(open(raw))
    why = check(v)
    if why:
        v = refuse(why)
except FileNotFoundError:
    v = refuse(f"no verdict.json (command exit {rc})")
except ValueError as e:
    v = refuse(f"verdict.json is not JSON: {e}")
env = os.environ
repo = env.get("MODERNCI_REPO") or env["CONF_REPO"]
head = env["CONF_HEAD"]
frm = env.get("MODERNCI_FROM") or env.get("CONF_BRANCH") or "dev"
v["schema"] = "busbar.conformance.verdict/1"
v["repo"] = repo
v["commit"] = head
v["core_pin"] = env["BUSBAR_PIN"]
url = env["CONF_MCI_URL"] + "/move?repo=" + repo.replace("/", "%2F") + "&from=" + frm + "&head=" + head
v["run_id"] = "modernci:" + repo + "@" + head + ":conformance"
v["evidence"] = url
v["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(out, "w") as f:
    json.dump(v, f, indent=2, sort_keys=True)
    f.write("\n")
print(v["status"], v.get("reason", ""))
sys.exit(0 if v["status"] == "pass" else 1)
PY
}

selftest() {
  local t; t="$(mktemp -d)"; trap 'rm -rf "$t"' RETURN
  export BUSBAR_PIN=0000000000000000000000000000000000000000 CONF_REPO=selftest/repo CONF_HEAD=1111111111111111111111111111111111111111 CONF_MCI_URL="$MCI_URL"
  local ok=0
  expect() { # expect <want rc> <name> <verdict text or -> <rc>
    local want="$1" name="$2" text="$3" rc="$4" got=0
    rm -f "$t/v.json"; [ "$text" = - ] || printf '%s' "$text" > "$t/v.json"
    judge "$t/v.json" s1 "$rc" "$t/out.json" >/dev/null || got=1
    if [ "$got" != "$want" ]; then echo "selftest FAILED: $name (exit $got, wanted $want)"; ok=1; else echo "  ok: $name"; fi
  }
  expect 0 "an armed pass is published" '{"suite":"s1","status":"pass","armed":true}' 0
  expect 1 "no verdict file is red" - 0
  expect 1 "a verdict that is not JSON is red" 'nope' 0
  expect 1 "a verdict filed under another suite is red" '{"suite":"s2","status":"pass","armed":true}' 0
  expect 1 "an unarmed pass is red" '{"suite":"s1","status":"pass","armed":false}' 0
  expect 1 "a pass whose command failed is red" '{"suite":"s1","status":"pass","armed":true}' 1
  expect 1 "an unknown field is red" '{"suite":"s1","status":"pass","armed":true,"x":1}' 0
  expect 1 "a fail is red" '{"suite":"s1","status":"fail","armed":true}' 1
  expect 1 "not-run is red" '{"suite":"s1","status":"not-run","armed":false}' 3
  judge <(printf '%s' '{"suite":"s1","status":"pass","armed":true}') s1 0 "$t/out.json" >/dev/null
  python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["repo"]=="selftest/repo" and v["core_pin"].startswith("0000") and v["evidence"].endswith("&head=1111111111111111111111111111111111111111"), v' "$t/out.json" \
    && echo "  ok: the stamp names the repo, the commit, the core pin and the move" || { echo "selftest FAILED: the stamp"; ok=1; }
  return "$ok"
}

[ "${1:-}" = --selftest ] && { selftest; exit $?; }

if [ ! -s "$LIST" ] || ! grep -qvE '^[[:space:]]*(#|$)' "$LIST"; then
  say "this repo lists no suites ($LIST); nothing to judge"
  exit 0
fi

export CONF_HEAD="${MODERNCI_COMMIT:-$(git rev-parse HEAD)}"
# busbar itself carries no .busbar-ref: its core suites judge this checkout, so the pin is HEAD.
if [ -f .busbar-ref ]; then
  pin="$(awk '{print $1; exit}' .busbar-ref)"
  [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || { say ".busbar-ref field 1 is not a full sha: '$pin'"; exit 2; }
else
  [ -f crates/busbar-contract/Cargo.toml ] || { say "no .busbar-ref, and this is not busbar"; exit 2; }
  pin="$CONF_HEAD"
fi
export BUSBAR_PIN="$pin"
export CONF_REPO="$(git config --get remote.origin.url | sed -E 's#^(https://github.com/|git@github.com:)##; s#\.git$##')"
export CONF_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
export CONF_MCI_URL="$MCI_URL"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$here/target}"

# busbar at the pin, outside this checkout (its scripts and crates are what the subjects build on).
W="$(mktemp -d "${TMPDIR:-/tmp}/conformance.XXXXXX")"
trap 'rm -rf "$W"' EXIT
if [ "$pin" = "$CONF_HEAD" ] && [ ! -f .busbar-ref ]; then
  export BUSBAR_CHECKOUT="$here"
else
export BUSBAR_CHECKOUT="$W/busbar"
git init -q "$BUSBAR_CHECKOUT" && git -C "$BUSBAR_CHECKOUT" remote add origin https://github.com/GetBusbar/busbar.git \
  && git -C "$BUSBAR_CHECKOUT" fetch -q --depth 1 --no-tags origin "$pin" \
  && git -C "$BUSBAR_CHECKOUT" -c advice.detachedHead=false checkout -q FETCH_HEAD \
  || { say "busbar $pin could not be fetched"; exit 2; }
fi

# shellcheck source=testing/conformance/tools.sh
. testing/conformance/tools.sh rust node || { say "the pinned tools could not be provisioned"; exit 2; }

rm -rf "$OUT"; mkdir -p "$OUT/verdicts"
fail=0; n=0
while IFS=$'\t' read -r id cmd; do
  case "$id" in ''|\#*) continue ;; esac
  [ -n "${cmd:-}" ] || { say "$LIST: suite $id names no command"; fail=1; continue; }
  n=$((n + 1))
  dir="$OUT/$id"; mkdir -p "$dir"
  say "=== $id: $cmd"
  start=$(date +%s); rc=0
  ( export CONFORMANCE_SUITE="$id" CONFORMANCE_OUT="$dir"; bash -c "$cmd" ) || rc=$?
  say "$id: command exit $rc after $(( $(date +%s) - start ))s"
  if res="$(judge "$dir/verdict.json" "$id" "$rc" "$OUT/verdicts/$id.json")"; then
    say "$id: PASS"
  else
    say "$id: NOT PASS ($res)"; fail=1
  fi
done < "$LIST"
say "$n suite(s) judged; verdicts in target/conformance/verdicts/"
for f in "$OUT"/verdicts/*.json; do [ -f "$f" ] && printf '%s  %s\n' "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$f")" "$(basename "$f" .json)"; done
exit "$fail"
