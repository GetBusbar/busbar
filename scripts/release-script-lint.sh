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
#   1. GATE-HANG rule: in any release-check*.sh, a line that BACKGROUNDS a server process
#      (python / serve_forever / http.server, ending in a lone `&`) MUST redirect stdout on that
#      same line (`>`, `1>`, or `&>` — a bare `2>…` that only covers stderr does NOT count, because
#      the stdout pipe is exactly what wedges `$(...)`). This is deliberately STRICTER than
#      "only flag inside a $(...) capture": a backgrounded server that leaks stdout is a latent hang
#      the moment anyone wraps its launcher in a capture, so we require the redirect unconditionally
#      and the rule cannot be defeated by refactoring the capture site.
#   2. WATCHDOG rule: release-check-1.5.2.sh must keep its belt-and-suspenders `timeout` re-exec so
#      that ANY future hang (not just this one) fails fast with exit 124 instead of a multi-hour
#      `cancelled`.
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

  note "self-test: ${pass}/2 fixture groups passed"
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
for f in scripts/release-check*.sh; do [ -f "$f" ] && scripts_to_scan+=("$f"); done
if [ ${#scripts_to_scan[@]} -eq 0 ]; then
  note "no scripts/release-check*.sh found — nothing to scan"
else
  hits="$(scan_backgrounded_servers "${scripts_to_scan[@]}" || true)"
  if [ -n "$hits" ]; then
    while IFS= read -r h; do
      note "GATE-HANG: $h"
    done <<<"$hits"
    note "→ a backgrounded server that inherits a \$(...) stdout pipe wedges the gate until the CI"
    note "  timeout. Redirect the child's stdout: append \`>/dev/null 2>&1 &\` (keep the helper's own"
    note "  \`echo \"\$pid\"\`, which still reaches the capture)."
    fail=1
  else
    note "ok (${#scripts_to_scan[@]} script(s) scanned, no unredirected backgrounded server)"
  fi
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
