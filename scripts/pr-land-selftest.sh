#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE SELF-TEST FOR scripts/pr-land.sh, RUN AGAINST A THROWAWAY REPOSITORY AND A STUBBED `gh`.
#
# pr-land.sh is a courier whose whole value is that it does the same four things every time and
# refuses in the two cases where doing them would be wrong. None of that can be proven against the
# real repository — proving "a conflict aborts" would need a real conflicting pick, and proving "red
# leaves the PR open" would need a real red PR. So the remote is a local bare repository (real git,
# real push, real cherry-pick, real conflicts) and `gh` is a shim on PATH that records every call
# and replays a canned check-run answer. What is exercised is exactly the script's own logic.
#
# Four cases, each proven by constructing the failing condition and confirming it is caught:
#   A  a conflicting pick ABORTS: non-zero, no `pr create` in the call log, no branch left behind.
#   B  the PR body NAMES every picked commit and its cherry-pick trailer.
#   C  a red required check leaves the PR OPEN: non-zero, no `pr close`, auto-merge still armed.
#   D  an all-green check set reports GREEN with the run URLs.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$here/.fix/pr-land-selftest.$$"
trap 'rm -rf "$root"' EXIT
rm -rf "$root"; mkdir -p "$root"

fails=0
ok()   { echo "  ok   — $*"; }
bad()  { echo "  BAD  — $*" >&2; fails=$((fails + 1)); }

# ── THE gh SHIM ───────────────────────────────────────────────────────────────────────────────────
# It answers only what pr-land.sh asks, records every invocation, and reads its check-run verdict
# from $GH_CHECKS so one shim serves both the red and the green case.
mkdir -p "$root/bin"
cat >"$root/bin/gh" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
case "$1" in
  auth) exit 0 ;;
  repo) echo "acme/thing"; exit 0 ;;
  api)  echo "true"; exit 0 ;;
  run)  echo "2026-09-06T00:00:00Z build\tFAILED: the canned first failing line"; exit 0 ;;
  pr)
    case "$2" in
      create)
        # Record the body so the test can assert on what a reviewer would actually read.
        while [ $# -gt 0 ]; do
          [ "$1" = "--body-file" ] && cp "$2" "$GH_BODY"
          shift
        done
        echo "https://github.com/acme/thing/pull/1"; exit 0 ;;
      merge) exit 0 ;;
      view)  echo "https://github.com/acme/thing/pull/1"; exit 0 ;;
      checks) cat "$GH_CHECKS"; exit 0 ;;
      close) exit 0 ;;
    esac ;;
esac
exit 0
SHIM
chmod +x "$root/bin/gh"
export PATH="$root/bin:$PATH"

# ── THE THROWAWAY REPOSITORY ──────────────────────────────────────────────────────────────────────
# dev carries `f=three`; `feat` carries `f=two` off the same parent, so picking feat onto dev is a
# guaranteed conflict. Two further commits touch files of their own and pick cleanly.
mk_repo() {
  local wt="$1" bare="$1.git"
  rm -rf "$wt" "$bare"
  git init -q --bare "$bare"
  git init -q -b dev "$wt"
  git -C "$wt" config user.email t@example.invalid
  git -C "$wt" config user.name  Selftest
  # The operator's global hooks (identity policy, and whatever else) must not judge a throwaway
  # repository: they would reject its synthetic author and the whole fixture would fail to build,
  # which reads as "pr-land.sh is broken" when nothing about pr-land.sh was exercised at all.
  mkdir -p "$root/nohooks"
  git -C "$wt" config core.hooksPath "$root/nohooks"
  git -C "$wt" remote add origin "$bare"
  echo one >"$wt/f"; git -C "$wt" add f; git -C "$wt" commit -qm "base"
  git -C "$wt" branch feat
  git -C "$wt" switch -q feat
  echo two >"$wt/f"; git -C "$wt" commit -qam "feat: f becomes two"
  CONFLICTER="$(git -C "$wt" rev-parse HEAD)"
  echo g >"$wt/g"; git -C "$wt" add g; git -C "$wt" commit -qm "feat: add g"
  CLEAN1="$(git -C "$wt" rev-parse HEAD)"
  echo h >"$wt/h"; git -C "$wt" add h; git -C "$wt" commit -qm "feat: add h"
  CLEAN2="$(git -C "$wt" rev-parse HEAD)"
  git -C "$wt" switch -q dev
  echo three >"$wt/f"; git -C "$wt" commit -qam "dev: f becomes three"
  git -C "$wt" push -q origin dev
}

checks_json() { printf '%s\n' "$1" >"$root/checks.json"; }
GREEN_JSON='[{"name":"ci umbrella","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/11"},
{"name":"A2A conformance verdict","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/12"},
{"name":"MCP conformance verdict","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/13"},
{"name":"Voice conformance verdict","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/14"}]'
RED_JSON='[{"name":"ci umbrella","state":"FAILURE","link":"https://github.com/acme/thing/actions/runs/11/job/99"},
{"name":"A2A conformance verdict","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/12"},
{"name":"MCP conformance verdict","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/13"},
{"name":"Voice conformance verdict","state":"SUCCESS","link":"https://github.com/acme/thing/actions/runs/14"}]'

# ── CASE A: A CONFLICTING PICK ABORTS ─────────────────────────────────────────────────────────────
echo "case A — a conflicting pick aborts"
wt="$root/a"; mk_repo "$wt"
export GH_LOG="$root/a.log" GH_BODY="$root/a.body" GH_CHECKS="$root/checks.json"
: >"$GH_LOG"; checks_json "$GREEN_JSON"
out="$( (cd "$wt" && bash "$here/scripts/pr-land.sh" "$CONFLICTER" --base dev) 2>&1 )"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "a conflicting pick exited 0"
case "$out" in *"conflicted on: f"*) ok "names the conflicting path" ;; *) bad "does not name the conflicting path: $out" ;; esac
grep -q 'pr create' "$GH_LOG" && bad "opened a PR despite the conflict" || ok "no PR was opened"
git -C "$wt" show-ref --verify --quiet "refs/heads/$(git -C "$wt" branch --list 'land/*' | head -1 | tr -d ' *')" 2>/dev/null \
  && bad "left the land/ branch behind" || ok "no land/ branch left behind"
git -C "$wt" ls-remote --heads origin 'land/*' | grep -q . && bad "pushed a branch" || ok "nothing pushed"

# ── CASE B: THE BODY LISTS EVERY PICK AND ITS TRAILER ─────────────────────────────────────────────
echo "case B — the PR body lists every picked commit and its trailer"
wt="$root/b"; mk_repo "$wt"
export GH_LOG="$root/b.log" GH_BODY="$root/b.body"
: >"$GH_LOG"; checks_json "$GREEN_JSON"
out="$( (cd "$wt" && bash "$here/scripts/pr-land.sh" "$CLEAN1" "$CLEAN2" --base dev) 2>&1 )"; rc=$?
[ "$rc" -eq 0 ] && ok "exit 0" || bad "clean picks exited $rc: $out"
if [ -f "$GH_BODY" ]; then
  grep -q "$CLEAN1" "$GH_BODY" && ok "body names the first hash" || bad "body omits $CLEAN1"
  grep -q "$CLEAN2" "$GH_BODY" && ok "body names the second hash" || bad "body omits $CLEAN2"
  grep -q "cherry picked from commit $CLEAN1" "$GH_BODY" && ok "body carries the first trailer" \
    || bad "body carries no trailer for $CLEAN1"
  grep -q 'ci umbrella' "$GH_BODY" && ok "body names the required contexts" || bad "body omits the contexts"
else
  bad "no PR body was posted at all"
fi
grep -q 'pr merge .* --auto --rebase' "$GH_LOG" && ok "auto-merge armed with --rebase" || bad "auto-merge not armed with --rebase"
grep -q 'squash' "$GH_LOG" && bad "asked GitHub to squash" || ok "never asked GitHub to squash"

# ── CASE C: RED LEAVES THE PR OPEN ────────────────────────────────────────────────────────────────
echo "case C — a red required check leaves the PR open"
wt="$root/c"; mk_repo "$wt"
export GH_LOG="$root/c.log" GH_BODY="$root/c.body"
: >"$GH_LOG"; checks_json "$RED_JSON"
out="$( (cd "$wt" && bash "$here/scripts/pr-land.sh" "$CLEAN1" --base dev --wait) 2>&1 )"; rc=$?
[ "$rc" -ne 0 ] && ok "exit non-zero ($rc)" || bad "a red check reported success"
case "$out" in *"ci umbrella"*) ok "names the failing check" ;; *) bad "does not name the failing check" ;; esac
case "$out" in *"canned first failing line"*) ok "prints the first failing line from --log-failed" ;;
  *) bad "did not print the first failing line" ;; esac
grep -q 'pr close' "$GH_LOG" && bad "closed the PR on red" || ok "PR left open"
grep -q 'pr merge .* --auto' "$GH_LOG" && ok "auto-merge stays armed" || bad "auto-merge was never armed"

# ── CASE D: GREEN REPORTS ─────────────────────────────────────────────────────────────────────────
echo "case D — an all-green check set reports GREEN with run URLs"
wt="$root/d"; mk_repo "$wt"
export GH_LOG="$root/d.log" GH_BODY="$root/d.body"
: >"$GH_LOG"; checks_json "$GREEN_JSON"
out="$( (cd "$wt" && bash "$here/scripts/pr-land.sh" "$CLEAN1" --base dev --wait) 2>&1 )"; rc=$?
[ "$rc" -eq 0 ] && ok "exit 0" || bad "a green check set exited $rc: $out"
case "$out" in *"GREEN — every required context succeeded"*) ok "reports GREEN" ;; *) bad "no GREEN verdict: $out" ;; esac
case "$out" in *"actions/runs/14"*) ok "prints the run URLs" ;; *) bad "no run URLs in the verdict" ;; esac

# ── THE DRY RUN EXECUTES NOTHING ──────────────────────────────────────────────────────────────────
echo "case E — --dry-run touches nothing"
wt="$root/e"; mk_repo "$wt"
export GH_LOG="$root/e.log" GH_BODY="$root/e.body"
: >"$GH_LOG"; checks_json "$GREEN_JSON"
out="$( (cd "$wt" && bash "$here/scripts/pr-land.sh" "$CLEAN1" --base dev --dry-run) 2>&1 )"; rc=$?
[ "$rc" -eq 0 ] && ok "exit 0" || bad "--dry-run exited $rc: $out"
grep -q 'pr create' "$GH_LOG" && bad "--dry-run opened a PR" || ok "--dry-run opened no PR"
git -C "$wt" ls-remote --heads origin 'land/*' | grep -q . && bad "--dry-run pushed" || ok "--dry-run pushed nothing"
case "$out" in *"+ git -C"*) ok "printed the commands it would run" ;; *) bad "printed no commands" ;; esac

if [ "$fails" -eq 0 ]; then
  echo "pr-land-selftest: GREEN — 5 cases, conflict/body/red/green/dry-run all discriminate"
  exit 0
fi
echo "pr-land-selftest: RED — $fails assertion(s) failed" >&2
exit 1
