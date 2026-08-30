#!/usr/bin/env bash
# Release-script lint — durable CI guard for the release-harness (scripts/release-check*.sh).
#
# WHY THIS EXISTS (the bug it prevents from ever recurring):
#   The 1.5.2 gate (scripts/release-check-1.5.2.sh) once wedged CI for 2h31m — a full 180-min
#   timeout `cancelled`, not a fast failure. Root cause: a helper that launched a long-lived python
#   server was BACKGROUNDED with NO stdout redirect — `python3 "$script" &` — and that helper was
#   captured in a command substitution:
#
#       reg_pid="$(start_plugin_registry ...)"      # <-- $(...) capture
#       ...
#       python3 "$script" &                         # <-- server inherits the $(...) stdout pipe
#
#   `$(...)` reads the child's stdout until EOF. A backgrounded `serve_forever()` holds that pipe
#   open for its whole life, so the substitution never returns and the whole gate hangs until the
#   job timeout kills it. The fix (already in the script) is to redirect the server's stdout:
#   `python3 "$script" >/dev/null 2>&1 &`. The helper's own `echo "$pid"` still reaches `$(...)`.
#
# WHAT THIS GUARD ENFORCES (so the antipattern cannot come back):
#   1. GATE-HANG rule: in any server-launching gate script (release-check*.sh and
#      no-plugins-gate.sh — see the scan set below), a line that BACKGROUNDS a server process
#      (python / serve_forever / http.server, ending in a lone `&`) MUST redirect stdout on that
#      same line (`>`, `1>`, or `&>` — a bare `2>…` that only covers stderr does NOT count, because
#      the stdout pipe is exactly what wedges `$(...)`). This is deliberately STRICTER than
#      "only flag inside a $(...) capture": a backgrounded server that leaks stdout is a latent hang
#      the moment anyone wraps its launcher in a capture, so we require the redirect unconditionally
#      and the rule cannot be defeated by refactoring the capture site.
#   2. WATCHDOG rule: release-check-1.5.2.sh must keep its belt-and-suspenders `timeout` re-exec so
#      that ANY future hang (not just this one) fails fast with exit 124 instead of a multi-hour
#      `cancelled`.
#   3. LOST-REGISTRATION rule: a helper that registers something for cleanup by appending to a
#      global array (`TMP_DIRS+=(...)`, `BG_PIDS+=(...)`, `DOCKER_CIDS+=(...)`) must NOT be invoked
#      inside a command substitution. `x="$(new_tmpdir)"` runs the helper in a SUBSHELL, so the
#      append mutates a COPY of the array that dies with the subshell; the parent's array stays
#      empty and the EXIT trap's cleanup loop iterates NOTHING. This is the same class of defect as
#      rule 1 (a `$(...)` capture around a helper that has a side effect outside its stdout) and it
#      had gone unnoticed in three gates at once: no-plugins-gate.sh leaked 8 directories / 213 MB
#      per run, release-check.sh had never deleted a working directory it created, and
#      release-check-1.5.2.sh additionally lost every backgrounded server's PID, so a run that hit
#      an assertion failure left a live python upstream holding its port. The fix shape, used by all
#      three now: the helper SETS a global (`NEW_TMPDIR` / `NEW_BG_PID`) and the caller reads it on
#      the next statement, so the append lands in the caller's own shell.
#   4. EXEC-BIT rule: any `scripts/….sh` a workflow EXECUTES DIRECTLY (a `run:` command that is the
#      path itself, not `bash …`/`sh …`/`source …`/`. …`) must be tracked mode 100755. A 100644 mode
#      makes the shell refuse the script with exit 126 the instant CI runs it — the release-stage
#      regression that failed every busbar-store-sqlite artifact build (release-build.sh) and lurked
#      one stage downstream in release-fleet (fleet-checks.sh), both invoked directly and both left
#      non-executable. Sourced libraries (scripts/plane-roots.sh, dot-sourced by three lints and
#      intentionally 100644) are correctly exempt: the interpreter, not the file's own bit, runs them.
#
# Runs in CI (see .github/workflows/ci.yml, structure-lint job). No external deps; bash 3.2 + POSIX
# awk (macOS/Linux). `--selftest` proves the scanner still catches the real antipattern before its
# verdict on the tree is trusted (same discipline as structure-lint.sh --selftest).
set -euo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits `file:lineno: <line>` for every backgrounded server launch that fails to redirect stdout.
# A backgrounded launch = a non-comment line ending in a single `&` (not `&&`). A "server" = a line
# mentioning python / serve_forever / http.server. stdout is considered redirected if, AFTER removing
# stderr-only redirects (`2>&1`, `2>FILE`, `2>>FILE`), any `>` remains (`>FILE`, `1>FILE`, `&>FILE`).
scan_backgrounded_servers() {
  awk '
    function has_stdout_redirect(s,   t) {
      t = s
      gsub(/2>&[0-9]/, "", t)               # strip stderr-dup (2>&1)
      gsub(/2>>?[^[:space:]&]*/, "", t)     # strip stderr-to-file (2>FILE, 2>>FILE)
      return (t ~ />/)                       # any surviving > redirects stdout (>, 1>, &>)
    }
    /^[[:space:]]*#/ { next }                                  # whole-line comment: prose, skip
    {
      is_bg = ($0 ~ /&[[:space:]]*$/) && ($0 !~ /&&[[:space:]]*$/)
      if (!is_bg) next
      launches = ($0 ~ /python3?[[:space:]]/) || ($0 ~ /serve_forever/) || ($0 ~ /http\.server/)
      if (!launches) next
      if (has_stdout_redirect($0)) next
      disp = $0; sub(/^[[:space:]]+/, "", disp)
      printf "%s:%d: %s\n", FILENAME, FNR, disp
    }
  ' "$@"
}

# ── THE LOST-REGISTRATION SCANNER (rule 3; one copy, driven by the self-test below) ───────────────
# Emits `file:lineno: <line>` for every command substitution / backtick capture of a function whose
# body appends to a global array. Two passes over each file:
#   pass 1  walk the brace depth, tracking which function (including a NESTED one) each line belongs
#           to, every `local` name declared in it, and every `NAME+=(` whose NAME is not one of them;
#   pass 2  flag any line that captures such a function in `$( ... )` or backticks.
# Deliberately NOT flagged: a helper whose array IS `local` (per-call scratch, no cleanup contract),
# a plain call `helper arg` (the append lands correctly), and a name that only appears in a comment.
scan_lost_registrations() {
  local f
  for f in "$@"; do
    awk '
      function strip(s,   t) { t = s; sub(/[[:space:]]#.*$/, "", t); sub(/^[[:space:]]*#.*$/, "", t); return t }
      function opens(s,  n) { n = gsub(/\{/, "{", s); return n }
      function closes(s, n) { n = gsub(/\}/, "}", s); return n }

      # ── pass 1: which functions append to a non-local global array? ──
      NR == FNR {
        line = strip($0)
        if (line ~ /^[[:space:]]*(function[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)[[:space:]]*\{[[:space:]]*$/) {
          nm = line
          sub(/^[[:space:]]*(function[[:space:]]+)?/, "", nm)
          sub(/[[:space:]]*\(\).*$/, "", nm)
          sp++; stack[sp] = nm; sdepth[sp] = depth
          depth += opens(line) - closes(line)
          next
        }
        depth += opens(line) - closes(line)
        while (sp > 0 && depth <= sdepth[sp]) sp--
        if (sp == 0) next
        # every `local a b c=1` on this line, wherever it sits (`local x; x=...` is idiomatic here)
        rest = line
        while (match(rest, /(^|[;&|[:space:]])local[[:space:]]+[^;#]*/)) {
          decl = substr(rest, RSTART, RLENGTH)
          rest = substr(rest, RSTART + RLENGTH)
          sub(/^[^l]*local[[:space:]]+/, "", decl)
          n = split(decl, toks, /[[:space:]]+/)
          for (i = 1; i <= n; i++) { sub(/=.*$/, "", toks[i]); if (toks[i] != "") loc[stack[sp] SUBSEP toks[i]] = 1 }
        }
        rest = line
        while (match(rest, /[A-Za-z_][A-Za-z0-9_]*\+=\(/)) {
          g = substr(rest, RSTART, RLENGTH - 3)
          rest = substr(rest, RSTART + RLENGTH)
          # attribute the append to every enclosing function that has not localised the name
          for (j = sp; j >= 1; j--) if (!((stack[j] SUBSEP g) in loc)) reg[stack[j]] = reg[stack[j]] " " g
        }
        next
      }

      # ── pass 2: who captures one of them in a subshell? ──
      {
        line = strip($0)
        if (line == "") next
        for (fn in reg) {
          if (line ~ ("\\$\\([[:space:]]*" fn "[[:space:])]") || line ~ ("`[[:space:]]*" fn "[[:space:]`]")) {
            disp = $0; sub(/^[[:space:]]+/, "", disp)
            printf "%s:%d: %s  [captures %s(), which appends to%s]\n", FILENAME, FNR, disp, fn, reg[fn]
          }
        }
      }
    ' "$f" "$f"
  done
}

# ── THE EXEC-BIT SCANNER (rule 4; one copy, driven by the self-test below) ────────────────────────
# Emits each unique `scripts/…​.sh` path that a workflow file EXECUTES DIRECTLY (a `run:` command that
# is the path itself). A path preceded by an interpreter/source token (`bash `, `sh `, `source `, or
# `. `) is NOT a direct exec — the interpreter supplies the exec bit — and is skipped, so a sourced
# library (e.g. scripts/plane-roots.sh, dot-sourced by three lints and intentionally 100644) is never
# reported. The caller maps each emitted path through `git ls-files -s`: a direct-exec script whose
# TRACKED mode is not 100755 fails the shell with exit 126 the moment CI runs it — exactly the
# release-stage regression this rule exists to catch before staging rather than during it.
list_direct_invoked_scripts() {
  awk '
    /^[[:space:]]*#/ { next }                                  # whole-line comment: skip
    {
      s = $0
      while (match(s, /(\.\/)?scripts\/[A-Za-z0-9_.\/-]+\.sh/)) {
        path = substr(s, RSTART, RLENGTH); sub(/^\.\//, "", path)
        pre  = substr(s, 1, RSTART - 1)
        # interpreted/sourced iff the token immediately before the path is bash/sh/source/. at a
        # word boundary (so the `sh` in `bash ` cannot match — it lacks a preceding boundary).
        if (pre !~ /(^|[[:space:][|&;(])(bash|sh|source|\.)[[:space:]]+([^[:space:]]*\/)?$/) print path
        s = substr(s, RSTART + RLENGTH)
      }
    }
  ' "$@" | sort -u
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "release-script-lint SELF-TEST (the GATE-HANG scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 pass=0

  # RED fixtures — each is the real hang antipattern; the scanner MUST flag every one.
  cat >"${tmp}/red.sh" <<'RED'
start_registry() {
  python3 "$script" &
  echo $!
}
start_mock() {
  python3 "$srv" 2>/dev/null &
  echo $!
}
serve() { python3 -m http.server "$port" &
}
RED
  local red_hits; red_hits="$(scan_backgrounded_servers "${tmp}/red.sh" || true)"
  local red_n; red_n="$(printf '%s' "$red_hits" | grep -c ':' || true)"
  if [ "$red_n" -eq 3 ]; then
    pass=$((pass+1)); note "RED: flagged all 3 backgrounded-server-without-stdout-redirect lines"
  else
    fail=1; note "RED FAILED: expected 3 flags, got ${red_n}:"; printf '%s\n' "$red_hits"
  fi

  # GREEN fixtures — the fix (stdout redirected) plus benign backgrounds the scanner must NOT flag.
  cat >"${tmp}/green.sh" <<'GREEN'
start_registry() {
  python3 "$script" >/dev/null 2>&1 &
  echo $!
}
start_mock() {
  python3 "$srv" >"$log" 2>&1 &
}
start_https() { python3 "$s" &>/dev/null &
}
boot_busbar() {
  "$BUSBAR_BIN" >"$log" 2>&1 &            # not a python server, and redirected anyway
}
run_pair() { true && sleep 1 &            # backgrounded, but not a server
}
# python3 "$script" &                     # a comment that merely SHOWS the antipattern: not code
GREEN
  local green_hits; green_hits="$(scan_backgrounded_servers "${tmp}/green.sh" || true)"
  if [ -z "$green_hits" ]; then
    pass=$((pass+1)); note "GREEN: flagged none of the redirected / benign / commented backgrounds"
  else
    fail=1; note "GREEN FAILED: expected 0 flags, got:"; printf '%s\n' "$green_hits"
  fi

  # ── rule 3: LOST-REGISTRATION ────────────────────────────────────────────────────────────────
  # RED — every one of these captures a cleanup-registering helper in a subshell, which is exactly
  # the defect that left 8 leaked staging dirs per no-plugins-gate run and an unkillable mock
  # upstream in the 1.5.2 gate.
  cat >"${tmp}/red3.sh" <<'RED3'
TMP_DIRS=()
BG_PIDS=()
new_tmpdir() {
  local d; d="$(mktemp -d)"
  TMP_DIRS+=("$d"); echo "$d"
}
start_mock() {
  python3 "$s" >/dev/null 2>&1 &
  local pid=$!; BG_PIDS+=("$pid"); echo "$pid"
}
run_phase() {
  local work; work="$(new_tmpdir)"
  local out1 out2; out1="$(new_tmpdir)"; out2="$(new_tmpdir)"
  local mock; mock="$(start_mock 8080)"
  local legacy; legacy=`start_mock 8081`
}
RED3
  local red3_hits; red3_hits="$(scan_lost_registrations "${tmp}/red3.sh" || true)"
  local red3_n; red3_n="$(printf '%s' "$red3_hits" | grep -c ':' || true)"
  # 4 lines carry a capture (the `out1/out2` line carries two, and the scanner reports per LINE)
  if [ "$red3_n" -eq 4 ]; then
    pass=$((pass+1)); note "RED3: flagged all 4 lines that capture a cleanup-registering helper"
  else
    fail=1; note "RED3 FAILED: expected 4 flags, got ${red3_n}:"; printf '%s\n' "$red3_hits"
  fi

  # GREEN — the fix shape, plus the three things the scanner must NEVER flag: a helper whose array is
  # `local` (per-call scratch, no cleanup contract), a plain non-captured call, and a comment.
  cat >"${tmp}/green3.sh" <<'GREEN3'
TMP_DIRS=()
BG_PIDS=()
new_tmpdir() {
  NEW_TMPDIR="$(mktemp -d)"
  TMP_DIRS+=("$NEW_TMPDIR")
}
start_mock() {
  python3 "$s" >/dev/null 2>&1 &
  NEW_BG_PID=$!; BG_PIDS+=("$NEW_BG_PID")
}
collect_files() {          # a LOCAL array: per-call scratch, nothing to clean up
  local files=()
  local f
  while IFS= read -r f; do files+=("$f"); done < <(find . -name '*.rs')
  printf '%s\n' "${files[@]}"
}
run_phase() {
  local work; new_tmpdir; work="$NEW_TMPDIR"
  new_tmpdir; local out="$NEW_TMPDIR"
  start_mock 8080; local mock="$NEW_BG_PID"
  local listing; listing="$(collect_files)"
  # local bad; bad="$(new_tmpdir)"   <-- a comment SHOWING the antipattern, not code
}
GREEN3
  local green3_hits; green3_hits="$(scan_lost_registrations "${tmp}/green3.sh" || true)"
  if [ -z "$green3_hits" ]; then
    pass=$((pass+1)); note "GREEN3: flagged none of the fixed / local-array / plain-call / commented forms"
  else
    fail=1; note "GREEN3 FAILED: expected 0 flags, got:"; printf '%s\n' "$green3_hits"
  fi

  # ── rule 4: EXEC-BIT direct-invocation detector ──────────────────────────────────────────────
  # The detector must pick out ONLY the paths a workflow executes directly, and must never pick a
  # path that is interpreted (`bash …`), sourced (`source …` / `. …`), or mentioned in a comment.
  cat >"${tmp}/wf.yml" <<'WF'
jobs:
  build:
    steps:
      - run: scripts/release-build.sh "$TARGET"        # direct exec -> MUST be listed
      - run: bash scripts/helper.sh                     # interpreted -> never
      - run: |
          ./scripts/gate/run.sh --all                   # direct exec in a block -> MUST be listed
          source scripts/lib.sh                          # sourced -> never
          . scripts/env.sh                               # dot-sourced -> never
      # run: scripts/commented-out.sh                    # a comment -> never
WF
  local eb_hits; eb_hits="$(list_direct_invoked_scripts "${tmp}/wf.yml")"
  local eb_want; eb_want="$(printf 'scripts/gate/run.sh\nscripts/release-build.sh\n')"
  if [ "$eb_hits" = "$eb_want" ]; then
    pass=$((pass+1)); note "EXEC-BIT: listed exactly the 2 directly-run scripts (not interpreted / sourced / commented)"
  else
    fail=1; note "EXEC-BIT FAILED: expected two paths, got:"; printf '%s\n' "$eb_hits"
  fi

  note "self-test: ${pass}/5 fixture groups passed"
  if [ "$fail" -ne 0 ]; then
    note "release-script-lint SELF-TEST FAILED — the scanner would let the hang antipattern through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

fail=0

# ── Rule 1: GATE-HANG — no backgrounded server may leak stdout into a would-be $(...) capture ─────
hdr "GATE-HANG (backgrounded server must redirect stdout — the \$(...) 2h31m-hang antipattern)"
scripts_to_scan=()
# The GATE-HANG rule is about the ANTIPATTERN, not about one filename: any harness that backgrounds a
# server is one `$(...)` refactor away from the same multi-hour wedge. So the scan set is every gate
# script that launches one — scripts/no-plugins-gate.sh starts a mock upstream and self-test stubs
# exactly the way release-check.sh does, and is covered here rather than being a second blind spot.
for f in scripts/release-check*.sh scripts/no-plugins-gate.sh; do [ -f "$f" ] && scripts_to_scan+=("$f"); done
if [ ${#scripts_to_scan[@]} -eq 0 ]; then
  note "no server-launching gate scripts found — nothing to scan"
else
  hits="$(scan_backgrounded_servers "${scripts_to_scan[@]}" || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r h; do
      note "GATE-HANG: $h"
    done <<<"$hits"
    note "→ a backgrounded server that inherits a \$(...) stdout pipe wedges the gate until the CI"
    note "  timeout. Redirect the child's stdout: append \`>/dev/null 2>&1 &\`. Required even when the"
    note "  helper is not captured today — see rule 3, whose fix has launchers set \`\$NEW_BG_PID\`"
    note "  rather than echo a pid, so a future \`\$(...)\` around one must not be able to wedge."
    fail=1
  else
    note "ok (${#scripts_to_scan[@]} script(s) scanned, no unredirected backgrounded server)"
  fi
fi

# ── Rule 3: LOST-REGISTRATION — a cleanup registrar must not be called inside `$(...)` ────────────
hdr "LOST-REGISTRATION (a helper that appends to a cleanup array must not be run in a subshell)"
if [ ${#scripts_to_scan[@]} -eq 0 ]; then
  note "no gate scripts found — nothing to scan"
else
  lr_hits="$(scan_lost_registrations "${scripts_to_scan[@]}" || true)"
  if [ -n "$lr_hits" ]; then
    while IFS= read -r h; do
      note "LOST-REGISTRATION: $h"
    done <<<"$lr_hits"
    note "→ HOW TO FIX: a command substitution runs the helper in a SUBSHELL, so its \`ARR+=(...)\`"
    note "  mutates a copy that dies with the subshell and the EXIT trap cleans up NOTHING. Change"
    note "  the helper to SET a global instead of echoing, and read it on the caller's next"
    note "  statement:"
    note "      new_tmpdir() { NEW_TMPDIR=\"\$(mktemp -d ...)\"; TMP_DIRS+=(\"\$NEW_TMPDIR\"); }"
    note "      new_tmpdir; work=\"\$NEW_TMPDIR\"        # NOT: work=\"\$(new_tmpdir)\""
    note "  If the array is genuinely per-call scratch with no cleanup contract, declare it"
    note "  \`local\` in the helper and this rule stops caring about it."
    fail=1
  else
    note "ok (${#scripts_to_scan[@]} script(s) scanned, every cleanup registrar called in its caller's shell)"
  fi
fi

# ── Rule 4: EXEC-BIT — a script a workflow runs directly must be tracked 100755 ───────────────────
hdr "EXEC-BIT (a script executed directly by a workflow \`run:\` must be tracked executable)"
eb_fail=0
eb_scanned=0
while IFS= read -r p; do
  [ -z "$p" ] && continue
  # A workflow's `run:` path is relative to the step's working-directory, which may be a testing
  # subtree (e.g. testing/mcp-conformance), not the repo root. Resolve by tracked-path SUFFIX — the
  # exact path OR any `**/`-prefixed match — so both repo-root release scripts and working-directory
  # scripts are adjudicated. A path that matches NO tracked file is silently skipped (generated, or a
  # working-dir we cannot resolve) rather than mis-reported as a non-exec failure.
  while IFS="$(printf '\t')" read -r mode file; do
    [ -z "$file" ] && continue
    eb_scanned=$((eb_scanned+1))
    if [ "$mode" != "100755" ]; then
      note "EXEC-BIT: $file is executed directly by a workflow but tracked mode is $mode — the shell"
      note "  will refuse it with exit 126 at run time. Restore: git update-index --chmod=+x $file"
      eb_fail=1
    fi
  done < <(git ls-files -s -- "$p" "**/$p" 2>/dev/null \
             | awk '{m=$1; sub(/^[0-9]+ [0-9a-f]+ [0-9]+\t/,""); print m"\t"$0}' | sort -u)
done < <(list_direct_invoked_scripts .github/workflows/*.yml)
if [ "$eb_fail" -ne 0 ]; then
  fail=1
else
  note "ok (${eb_scanned} directly-run workflow script(s) scanned, all tracked 100755)"
fi

# ── Rule 2: WATCHDOG — the 1.5.2 gate must keep its `timeout` re-exec (defense in depth) ──────────
hdr "WATCHDOG (release-check-1.5.2.sh keeps its \`timeout\` re-exec so any hang fails fast)"
wd="scripts/release-check-1.5.2.sh"
if [ ! -f "$wd" ]; then
  note "ok (${wd} not present — nothing to check)"
elif grep -q 'WATCHDOG_ARMED' "$wd" && grep -Eq 'exec[[:space:]]+(g)?timeout' "$wd"; then
  note "ok (armed-sentinel + \`exec timeout\` re-exec present)"
else
  note "WATCHDOG MISSING: ${wd} no longer re-execs itself under \`timeout\` with an arm sentinel."
  note "  Restore the guard so a future hang fails fast (exit 124) instead of a multi-hour cancel."
  fail=1
fi

hdr "result"
if [ "$fail" -ne 0 ]; then note "release-script-lint FAILED"; exit 1; fi
note "release-script-lint passed"
