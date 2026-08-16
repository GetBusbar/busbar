#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# no-self-filed-issues-lint.sh — THE REPOSITORY DOES NOT FILE ISSUES AGAINST ITSELF.
#
# WHY THIS EXISTS, and it is not style. `verify-deploy.yml` used to open an issue when a published
# release was broken for consumers. Issue #51 is one it filed. Three things were wrong with that:
#
#   1. A SELF-FILED ISSUE IS INDISTINGUISHABLE FROM A USER'S. It lands in the same queue a human
#      triages, wearing the same clothes as a real report, and it costs the same attention to
#      dismiss. The issue tracker is the channel users talk to us on; a robot writing into it is
#      noise on a channel whose whole value is signal.
#
#   2. IT LEFT THE RUN GREEN. The filing step began `set +e` and ended on an `echo`, so the `alert`
#      job exited 0. A broken release therefore produced a green check and an issue nobody was
#      paged by. The notification replaced the failure instead of accompanying it.
#
#   3. IT CREATED STATE THAT COULD GO STALE. A long-lived mutable object outside the run that
#      produced it needs a second job to close it, a label to deduplicate it, and a rule about which
#      cron is allowed to have an opinion — all of which existed, and all of which only existed
#      because the notification was an issue rather than a red square.
#
# The replacement is a RED CHECK plus a run summary. It blocks, it is attached to the evidence that
# produced it, it clears by itself when a later run passes, and it cannot be triaged away.
#
# WHAT THIS LINT ASSERTS, over `.github/workflows/*.yml`:
#
#   A. No workflow invokes an issue-writing operation — `gh issue create|edit|close|comment|reopen`,
#      `gh label create`, an `issues.create`/`issues.update` script call, or a REST/GraphQL POST to
#      an issues endpoint.
#   B. No workflow requests the `issues: write` permission. This is the belt to (A)'s braces: even
#      if a filing call is smuggled in past the pattern list, without the token scope it fails on
#      the API rather than quietly succeeding.
#
# Comments are stripped before matching, so the workflows may — and do — explain in prose why the
# filing was removed without the explanation tripping the check that removed it. That is the same
# hazard `full-gate.sh`'s header hit: a gate its own explanation fails is a gate people learn to
# skip.
#
# SELF-TEST (`--selftest`, run FIRST in CI like every other scripts/*-lint.sh): drives the matcher
# over fixtures whose verdict is known — a clean workflow, one filing an issue, one granting the
# permission, and one that merely MENTIONS filing in a comment — and asserts the exact exit codes,
# so the lint proves it can go red before it is trusted to say green. It also asserts its own
# executed case count, so deleted coverage cannot present itself as a pass.
set -uo pipefail
cd "$(dirname "$0")/.."

WF_DIR=".github/workflows"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# Strip full-line and trailing `#` comments so prose about the ban does not trip the ban. Naive on
# purpose about `#` inside quotes: a false POSITIVE here is a loud, fixable lint failure, whereas
# tolerating comments would be a false NEGATIVE, and this file's whole point is failing closed.
strip_comments() { sed -e 's/[[:space:]]#[^"'"'"']*$//' -e 's/^[[:space:]]*#.*$//' "$1"; }

# (A) issue-writing operations.
ISSUE_WRITE_RE='gh (issue (create|edit|close|comment|reopen)|label create)|issues\.(create|update|createComment|addLabels)|(POST|--method[[:space:]]+POST)[^|]*\/issues|gh api[^|]*\/issues'
# (B) the permission that makes them possible.
ISSUE_PERM_RE='issues:[[:space:]]*write'

scan_file() {  # 0 = clean, 1 = violation. Prints the offending lines.
  local f="$1" tmp rc=0
  tmp="$(mktemp)"
  strip_comments "$f" > "$tmp"
  local hits
  hits="$(grep -nE "$ISSUE_WRITE_RE" "$tmp" 2>/dev/null)"
  if [ -n "$hits" ]; then
    red "  FAIL: $f files or mutates a GitHub issue"
    printf '    %s\n' "$hits"
    rc=1
  fi
  hits="$(grep -nE "$ISSUE_PERM_RE" "$tmp" 2>/dev/null)"
  if [ -n "$hits" ]; then
    red "  FAIL: $f requests \`issues: write\`"
    printf '    %s\n' "$hits"
    rc=1
  fi
  rm -f "$tmp"
  return $rc
}

# ── SELF-TEST ──────────────────────────────────────────────────────────────────────────────────────
selftest() {
  printf '\n== no-self-filed-issues SELF-TEST (the lint proves itself before it judges the tree) ==\n'
  local tmp fails=0 cases=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  cat >"$tmp/clean.yml" <<'YAML'
name: clean
permissions:
  contents: read
  actions: read
jobs:
  alert:
    steps:
      - run: |
          echo "::error::broken"
          exit 1
YAML

  cat >"$tmp/files-issue.yml" <<'YAML'
name: files
jobs:
  alert:
    steps:
      - run: gh issue create --repo "$REPO" --title "$TITLE" --body-file /tmp/b.md
YAML

  cat >"$tmp/grants-perm.yml" <<'YAML'
name: grants
permissions:
  contents: read
  issues: write
jobs:
  alert:
    steps:
      - run: echo hi
YAML

  cat >"$tmp/comment-only.yml" <<'YAML'
name: comment-only
# This workflow used to run `gh issue create` and request `issues: write`. It does not any
# more; it fails the run instead.
permissions:
  contents: read   # no issues: write here either
jobs:
  alert:
    steps:
      - run: exit 1   # never `gh issue create`
YAML

  # name|expected-rc
  local c
  for c in "clean.yml|0" "files-issue.yml|1" "grants-perm.yml|1" "comment-only.yml|0"; do
    local name="${c%%|*}" want="${c#*|}" got
    scan_file "$tmp/$name" >/dev/null 2>&1; got=$?
    cases=$((cases + 1))
    if [ "$got" != "$want" ]; then
      red "  selftest FAIL: $name expected rc=$want, got rc=$got"
      fails=$((fails + 1))
    else
      note "ok: $name -> rc=$got"
    fi
  done

  # A deleted case must not look like a pass.
  if [ "$cases" -ne 4 ]; then
    red "  selftest FAIL: expected 4 cases, executed $cases (coverage was deleted)"
    fails=$((fails + 1))
  fi

  if [ "$fails" -ne 0 ]; then
    red "no-self-filed-issues SELF-TEST: $fails failure(s)"
    return 1
  fi
  grn "no-self-filed-issues SELF-TEST: $cases/$cases cases correct"
  return 0
}

# ── MAIN ───────────────────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
  selftest; exit $?
fi

[ -d "$WF_DIR" ] || { red "no-self-filed-issues: $WF_DIR not found -- run this from the repository root."; exit 2; }

printf '\n== no-self-filed-issues: the repo must not open issues against itself ==\n'

mapfile -t FILES < <(find "$WF_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)

# A discovery step that finds nothing passes everything.
if [ "${#FILES[@]}" -lt 5 ]; then
  red "no-self-filed-issues: found only ${#FILES[@]} workflow file(s) (floor 5). Discovery is broken, and broken discovery reports a clean tree."
  exit 2
fi

fails=0
for f in "${FILES[@]}"; do
  scan_file "$f" || fails=$((fails + 1))
done

if [ "$fails" -ne 0 ]; then
  red "no-self-filed-issues: $fails workflow file(s) file issues or request \`issues: write\`."
  note "Busbar does not open issues against its own repositories. Make the check RED instead:"
  note "  write the findings to \$GITHUB_STEP_SUMMARY, emit ::error:: annotations, and exit 1."
  note "A red check blocks, is attached to the run that produced it, and clears when a later run passes."
  exit 1
fi

grn "no-self-filed-issues: ${#FILES[@]} workflow file(s) clean -- nothing files an issue, nothing asks for \`issues: write\`."
