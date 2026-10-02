#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE SELF-TEST FOR scripts/promote.sh.
#
# promote.sh is the last gate before a SHA becomes qa's or main's HEAD, and every one of its
# refusals is about a state that must never be produced on purpose in the real repository. So the
# remote is a throwaway bare repository (real git, real fast-forward semantics) and `gh` is a shim
# that serves canned protection contexts and canned check runs from files the cases rewrite.
#
# Cases:
#   A  a green SHA promotes, and the push names the SHA, not the branch.
#   B  a RED required context refuses.
#   C  a MISSING required context (a required name nothing reported) refuses — not-red is not green.
#   D  empty/unreadable protection refuses rather than looping over nothing and passing.
#   E  a non-fast-forward refuses.
#   F  local != origin refuses.
#   G  only dev->qa and qa->main are allowed; --to is the same guard as the positional.
#   H  the contexts come from protection BY NAME: rename one there and the verdict follows.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$here/.fix/promote-selftest.$$"
trap 'rm -rf "$root"' EXIT
rm -rf "$root"; mkdir -p "$root/bin" "$root/nohooks"

fails=0
ok()  { echo "  ok   — $*"; }
bad() { echo "  BAD  — $*" >&2; fails=$((fails + 1)); }

# ── THE gh SHIM ───────────────────────────────────────────────────────────────────────────────────
# `gh api .../protection/required_status_checks` -> $GH_CONTEXTS (exit 1 if the file is absent, the
# way gh exits on a branch with no protection). `gh api .../check-runs` -> $GH_RUNS.
cat >"$root/bin/gh" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
case "$*" in
  *required_status_checks*)
    [ -f "$GH_CONTEXTS" ] || { echo "gh: HTTP 404" >&2; exit 1; }
    cat "$GH_CONTEXTS"; exit 0 ;;
  *check-runs*)
    cat "$GH_RUNS"; exit 0 ;;
esac
exit 0
SHIM
chmod +x "$root/bin/gh"
export PATH="$root/bin:$PATH" PROMOTE_REPO="acme/thing"
export GH_LOG="$root/gh.log" GH_CONTEXTS="$root/contexts.json" GH_RUNS="$root/runs.json"

contexts() { printf '%s\n' "$1" >"$GH_CONTEXTS"; }
runs()     { printf '%s\n' "$1" >"$GH_RUNS"; }

# ── THE THROWAWAY REPOSITORY ──────────────────────────────────────────────────────────────────────
# origin carries dev, qa and main. dev is two commits ahead of qa (a clean fast-forward); a fourth
# commit is minted on qa alone for the non-fast-forward case.
wt="$root/wt"; bare="$root/origin.git"
git init -q --bare "$bare"
git init -q -b dev "$wt"
git -C "$wt" config user.email t@example.invalid
git -C "$wt" config user.name  Selftest
git -C "$wt" config core.hooksPath "$root/nohooks"
git -C "$wt" remote add origin "$bare"
echo 1 >"$wt/f"; git -C "$wt" add f; git -C "$wt" commit -qm one
BASE="$(git -C "$wt" rev-parse HEAD)"
git -C "$wt" push -q origin "dev:refs/heads/qa" "dev:refs/heads/main"
echo 2 >"$wt/f"; git -C "$wt" commit -qam two
echo 3 >"$wt/f"; git -C "$wt" commit -qam three
DEVSHA="$(git -C "$wt" rev-parse HEAD)"
git -C "$wt" push -q origin dev
git -C "$wt" fetch -q origin

run() { (cd "$wt" && bash "$here/scripts/promote.sh" "$@") 2>&1; }
reset_origin() {
  git -C "$wt" push -q -f origin "$BASE:refs/heads/qa" "$BASE:refs/heads/main"
  git -C "$wt" fetch -q origin
  : >"$GH_LOG"
}

GREEN_RUNS='[{"name":"ci umbrella","conclusion":"success","started_at":"2026-09-06T00:00:00Z"},
{"name":"qa-gate umbrella","conclusion":"success","started_at":"2026-09-06T00:00:00Z"}]'
RED_RUNS='[{"name":"ci umbrella","conclusion":"failure","started_at":"2026-09-06T00:00:00Z"},
{"name":"qa-gate umbrella","conclusion":"success","started_at":"2026-09-06T00:00:00Z"}]'

# ── CASE A: A GREEN SHA PROMOTES, AND THE PUSH NAMES THE SHA ─────────────────────────────────────
echo "case A — a green sha promotes with an exact-sha fast-forward"
reset_origin; contexts '["ci umbrella"]'; runs "$GREEN_RUNS"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -eq 0 ] && ok "exit 0" || bad "a green promote exited $rc: $out"
[ "$(git -C "$wt" ls-remote origin refs/heads/qa | cut -f1)" = "$DEVSHA" ] \
  && ok "origin/qa is now exactly the dev sha" || bad "origin/qa did not move to $DEVSHA"
reset_origin; contexts '["ci umbrella"]'; runs "$GREEN_RUNS"
out="$(run dev --to qa --dry-run)"
case "$out" in *"git push origin ${DEVSHA}:refs/heads/qa"*) ok "the refspec names the sha, not the branch" ;;
  *) bad "the dry-run refspec is not an exact sha: $out" ;; esac
[ "$(git -C "$wt" ls-remote origin refs/heads/qa | cut -f1)" = "$BASE" ] && ok "--dry-run pushed nothing" || bad "--dry-run pushed"

# ── CASE B: A RED REQUIRED CONTEXT REFUSES ────────────────────────────────────────────────────────
echo "case B — a red required context refuses"
reset_origin; contexts '["ci umbrella"]'; runs "$RED_RUNS"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "promoted on a red context"
case "$out" in *"ci umbrella: failure"*) ok "names the red context and its conclusion" ;; *) bad "does not name the red context" ;; esac
[ "$(git -C "$wt" ls-remote origin refs/heads/qa | cut -f1)" = "$BASE" ] && ok "qa did not move" || bad "qa moved on red"

# ── CASE C: A MISSING REQUIRED CONTEXT REFUSES ────────────────────────────────────────────────────
echo "case C — a required context that never reported refuses (not-red is not green)"
reset_origin; contexts '["ci umbrella","record the staged digest (the promote'"'"'s only input)"]'; runs "$GREEN_RUNS"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "promoted with an unreported required context"
case "$out" in *": missing"*) ok "reports the context as missing" ;; *) bad "did not report it missing: $out" ;; esac

# ── CASE D: UNREADABLE OR EMPTY PROTECTION REFUSES ────────────────────────────────────────────────
echo "case D — unreadable or empty protection refuses rather than passing an empty loop"
reset_origin; rm -f "$GH_CONTEXTS"; runs "$GREEN_RUNS"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "unreadable protection: exit non-zero ($rc)" || bad "promoted with unreadable protection"
case "$out" in *"refusing to promote blind"*) ok "says it refuses to promote blind" ;; *) bad "no blind-promote refusal: $out" ;; esac
reset_origin; contexts '[]'; runs "$GREEN_RUNS"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "empty context list: exit non-zero ($rc)" || bad "promoted with zero required contexts"

# ── CASE E: A NON-FAST-FORWARD REFUSES ────────────────────────────────────────────────────────────
echo "case E — a non-fast-forward refuses"
reset_origin; contexts '["ci umbrella"]'; runs "$GREEN_RUNS"
git -C "$wt" switch -q -c qa-side "$BASE"
echo divergent >"$wt/f"; git -C "$wt" commit -qam "a commit qa has and dev does not"
git -C "$wt" push -q -f origin "qa-side:refs/heads/qa"
git -C "$wt" switch -q dev
git -C "$wt" fetch -q origin
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "promoted a non-fast-forward"
case "$out" in *"would not be a fast-forward"*) ok "says it would not be a fast-forward" ;; *) bad "no fast-forward message: $out" ;; esac

# ── CASE F: LOCAL != ORIGIN REFUSES ───────────────────────────────────────────────────────────────
echo "case F — a local branch ahead of origin refuses"
reset_origin; contexts '["ci umbrella"]'; runs "$GREEN_RUNS"
echo local-only >"$wt/g"; git -C "$wt" add g; git -C "$wt" commit -qm "not pushed"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "promoted a sha origin has never seen"
case "$out" in *"is not identical to origin/dev"*) ok "says local and origin differ" ;; *) bad "no local/origin message: $out" ;; esac
git -C "$wt" reset -q --hard "$DEVSHA"

# ── CASE G: ONLY THE TWO PROMOTIONS ───────────────────────────────────────────────────────────────
echo "case G — only dev->qa and qa->main, by flag or by positional"
reset_origin; contexts '["ci umbrella"]'; runs "$GREEN_RUNS"
for pair in "dev main" "qa qa" "main dev" "dev dev"; do
  # shellcheck disable=SC2086
  set -- $pair
  out="$(run "$1" --to "$2")"; rc=$?
  [ "$rc" -ne 0 ] && ok "refuses $1 -> $2" || bad "allowed $1 -> $2"
done
out="$(run dev qa --dry-run)"; rc=$?
[ "$rc" -eq 0 ] && ok "the positional form still works" || bad "the positional form broke: $out"
out="$(run dev --to qa --dry-run)"; rc=$?
[ "$rc" -eq 0 ] && ok "the --to form works" || bad "--to broke: $out"

# ── CASE H: THE CONTEXTS FOLLOW PROTECTION, BY NAME ───────────────────────────────────────────────
echo "case H — the required contexts are read from protection by name, never hardcoded"
reset_origin; contexts '["some context this script has never heard of"]'; runs "$GREEN_RUNS"
out="$(run dev --to qa)"; rc=$?
[ "$rc" -ne 0 ] && ok "a context only protection knows about is still enforced" || bad "ignored a protection-named context"
case "$out" in *"some context this script has never heard of: missing"*) ok "names it verbatim" ;; *) bad "did not name it: $out" ;; esac
grep -q "branches/qa/protection/required_status_checks" "$GH_LOG" && ok "read protection for the DESTINATION branch" || bad "never read the destination's protection"

if [ "$fails" -eq 0 ]; then
  echo "promote-selftest: GREEN — 8 cases; exact-sha ff, red/missing/blind/non-ff/local-drift/pairs all refuse"
  exit 0
fi
echo "promote-selftest: RED — $fails assertion(s) failed" >&2
exit 1
