#!/usr/bin/env bash
# testing/fleet-fixtures/lib.sh — the shared machinery of the plugin FUNCTIONAL gate.
#
# ONE MECHANISM, DELIBERATELY THE SAME AS scripts/release-gate/lib.sh.
#
# The release gate proved a design: every check appends exactly one row to a ledger and NEVER
# controls flow; a single verdict step diffs the ledger against the list of ids that were OWED and
# is the only place anything is decided. That inversion is what makes three properties true at once
# and it is why this file copies it rather than inventing a second style:
#
#   * NO PROBE CAN MASK ANOTHER. A probe that fails records FAIL and returns; the next probe still
#     runs. "the auth exchange failed" never hides "and the store did not persist either".
#   * A PROBE THAT COULD NOT RUN IS NOT A PASS. The verdict knows which ids were owed (the kinds
#     the caller asked for), so an id with no row is `did not run` — RED, in its own column,
#     distinct from PASS. A step that dies in its preamble produces silence, and silence used to
#     read as green.
#   * ZERO ROWS IS RED. A functional gate that passes because it exercised nothing is the exact
#     "green-having-run-nothing" failure the audit named; verdict.sh checks for it by name.
#
# WHY THE LOGIC LIVES HERE AND NOT INLINE IN plugin-functional.yml. Same reason as the release
# gate: a check nobody can run on a laptop is a check nobody exercises against a real artifact
# before trusting it. Every probe below is runnable directly —
#
#     BUSBAR_BIN=./busbar PLUGIN_DIR=./plugins LEDGER=/tmp/l.tsv \
#       testing/fleet-fixtures/probe-store.sh sqlite
#
# — which is how the store probe in this change was validated against the real published busbar
# 1.5.4 and store-sqlite 1.0.4 before the workflow was trusted. A probe that has never executed is
# a guess.
set -uo pipefail

# ── Ledger ──────────────────────────────────────────────────────────────────────────────────────
# TSV: <id> <TAB> PASS|FAIL|SKIP <TAB> <title> <TAB> <detail>. Tabs/newlines are stripped from the
# free-text fields because one stray tab silently corrupts every downstream column — the invisible
# degradation this whole approach exists to refuse.
: "${LEDGER:=${RUNNER_TEMP:-/tmp}/plugin-functional-ledger.tsv}"
export LEDGER
mkdir -p "$(dirname "$LEDGER")"
[ -f "$LEDGER" ] || : > "$LEDGER"

record() {  # record <id> <PASS|FAIL|SKIP> <title> <detail>
  local id="$1" status="$2" title="$3" detail="${4:-}"
  title="$(printf '%s' "$title" | tr '\t\n' '  ')"
  detail="$(printf '%s' "$detail" | tr '\t\n' '  ')"
  printf '%s\t%s\t%s\t%s\n' "$id" "$status" "$title" "$detail" >> "$LEDGER"
  case "$status" in
    PASS) printf 'PASS  %-40s %s\n' "$id" "$title" ;;
    FAIL)
      printf 'FAIL  %-40s %s\n' "$id" "$title"
      printf '      %s\n' "$detail"
      echo "::error title=plugin-functional ${id}::${title} — ${detail}"
      ;;
    SKIP)
      printf 'SKIP  %-40s %s\n' "$id" "$title"
      printf '      %s\n' "$detail"
      echo "::warning title=plugin-functional ${id} DID NOT VERIFY::${title} — ${detail}"
      ;;
  esac
}

# ── Background process bookkeeping ──────────────────────────────────────────────────────────────
# Every busbar/mock/fixture pid a probe launches goes here so the EXIT trap can reap it. Without a
# single reaper a probe that fails mid-way leaves busbar holding the listen port and the NEXT probe
# reports a false PASS against the wrong process — the port-not-free trap the consumer-verify
# workflow documents at length.
FIXTURE_PIDS=()
_reap_fixtures() {
  local pid
  for pid in "${FIXTURE_PIDS[@]:-}"; do
    [ -n "${pid:-}" ] || continue
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${FIXTURE_PIDS[@]:-}"; do
    [ -n "${pid:-}" ] || continue
    wait "$pid" 2>/dev/null || true
  done
}
trap _reap_fixtures EXIT

track_pid() { FIXTURE_PIDS+=("$1"); }

# ── HTTP helpers ────────────────────────────────────────────────────────────────────────────────
# Every outbound call carries a timeout: a TCP connection that is accepted and never answered hangs,
# and a hang is the one outcome that is neither red nor green until the job timeout fires.
wait_for_http() {  # wait_for_http <url> <max-seconds> — returns 0 the moment it answers 2xx/3xx
  local url="$1" max="${2:-30}" i=0
  while [ "$i" -lt "$max" ]; do
    if curl -fsS -m 3 -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  return 1
}

# THE PORT MUST BE PROVEN FREE BEFORE A PROBE BINDS IT. Probing a port something else already
# answers on returns a cheerful 200 from the wrong process while the thing under test is dead. This
# happened while consumer-verify was being written and briefly reported a bundle healthy that had
# exited 1. Refuse to proceed rather than risk a false PASS.
assert_port_free() {  # assert_port_free <port>
  local port="$1"
  if curl -s -m 2 -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
    return 1
  fi
  return 0
}

# ── Binary / plugin resolution ──────────────────────────────────────────────────────────────────
# macOS quarantines anything curl downloaded; without clearing it the runner refuses to exec the
# binary and the failure looks like a busbar defect rather than a Gatekeeper attribute.
declaw() {  # declaw <path> — strip the macOS quarantine xattr if present
  command -v xattr >/dev/null 2>&1 && xattr -dr com.apple.quarantine "$1" 2>/dev/null || true
}

libext() { case "$(uname -s)" in Darwin) echo dylib ;; *) echo so ;; esac; }
