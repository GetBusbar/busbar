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

# GATE_NAME, not a hardcoded "plugin-functional": these annotations are what a reader sees in the
# Actions summary, and verdict.sh already names the gate from this variable. The shadow oracle sources
# this same file, so every one of its FAIL rows was annotating itself as a plugin gate it is not.
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
      echo "::error title=${GATE_NAME:-plugin-functional} ${id}::${title} — ${detail}"
      ;;
    SKIP)
      printf 'SKIP  %-40s %s\n' "$id" "$title"
      printf '      %s\n' "$detail"
      echo "::warning title=${GATE_NAME:-plugin-functional} ${id} DID NOT VERIFY::${title} — ${detail}"
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
#
# THE QUESTION IS BINDABILITY, NOT HTTP, and asking it in HTTP got the wrong answer for the cases
# that matter. An HTTP GET calls a port free whenever no 2xx/3xx comes back within the timeout, and
# three different things produce that: nothing is listening (free — correct), something is bound and
# does not speak HTTP or does not answer at all (NOT free — a gRPC or voice listener, or a process
# wedged mid-shutdown), and something is bound and still starting (NOT free — the previous probe's
# busbar, which is exactly the process this guard exists to notice). The last two are the ones the
# guard was written for, and it read both as FREE, after which the probe bound nothing, talked to the
# stale process, and reported on it. The teardown waits in the oracle's script cells have the same
# dependence in reverse: they spin until the port reads free, and an HTTP probe let them stop
# spinning while the old busbar still held the socket.
#
# A TCP connect answers the question that was actually being asked. Connection refused means nothing
# is accepting, which is the only thing that makes the port bindable; a completed connect means
# something is, whatever protocol it goes on to speak or fail to speak.
#
# Return contract unchanged: 0 = free, non-zero = in use.
assert_port_free() {  # assert_port_free <port>
  local port="$1"
  python3 - "$port" <<'PY'
import errno, socket, sys
s = socket.socket()
s.settimeout(1.0)
# connect_ex returns 0 on success and an errno otherwise. A refusal is the free case; a timeout is
# NOT (a filtered or wedged listener is still holding the port), so only "refused" is treated as
# free and everything else, including 0, is in-use — unknown is not free.
rc = s.connect_ex(("127.0.0.1", int(sys.argv[1])))
s.close()
sys.exit(0 if rc == errno.ECONNREFUSED else 1)
PY
}

# ── Oracle mock control-file writes (atomic + confirmed) ──────────────────────────────────────────
# testing/shadow-oracle/mock-upstream.py re-reads its control file on every request. A plain
# `> "$CONTROL"` truncates the file in place, so a request that lands mid-write can observe an EMPTY
# file -- and the mock now holds its last-known verb rather than treat that as "no outage", but the
# writer side of that contract is: never let a reader observe a partial write in the first place.
# Every writer of that file goes through these two functions:
#   * the write is temp-file-beside-then-rename (atomic on the same filesystem: a reader either sees
#     the old, complete content or the new, complete content, never a torn mix);
#   * the write is CONFIRMED by polling the mock's own `GET /__control` echo before the caller is
#     allowed to fire the cell's request that depends on it -- a write nobody can prove landed is not
#     a write.
oracle_write_control() {  # oracle_write_control <control-file> <mock-port> <value>
  local file="$1" port="$2" val="$3" tmp got i=0
  tmp="$(mktemp "${file}.XXXXXX")" || return 1
  printf '%s' "$val" >"$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$file" || return 1
  while [ "$i" -lt 100 ]; do
    got="$(curl -sS -m 2 "http://127.0.0.1:${port}/__control" 2>/dev/null | jq -r '.raw // empty' 2>/dev/null)"
    [ "$got" = "$val" ] && return 0
    sleep 0.02; i=$((i + 1))
  done
  echo "oracle_write_control: mock on port ${port} never echoed the write to ${file} (wrote '${val}', last saw '${got}')" >&2
  return 1
}

oracle_clear_control() {  # oracle_clear_control <control-file> <mock-port>
  local file="$1" port="$2" got i=0
  rm -f "$file"  # unlink is already atomic: no reader ever observes a partially-removed file
  while [ "$i" -lt 100 ]; do
    got="$(curl -sS -m 2 "http://127.0.0.1:${port}/__control" 2>/dev/null | jq -r '.raw // empty' 2>/dev/null)"
    [ -z "$got" ] && return 0
    sleep 0.02; i=$((i + 1))
  done
  echo "oracle_clear_control: mock on port ${port} still echoes a control value for ${file} after removal (last saw '${got}')" >&2
  return 1
}

# ── Oracle driver give-ups: THE HARNESS GIVING UP IS NOT A RECORDING (AUDIT NOTE-36) ────────────
# Every script driver under testing/shadow-oracle/scripts has paths it cannot continue from: a port
# something else is holding, a mock upstream that never answered, a plugin that would not fetch, a
# result body it could not assemble from its own measurements. NONE of those is an answer from
# busbar. They used to be written as `{status:-1, effects:{error:"port N busy"}}` followed by
# `exit 0` — a capture nothing in the product produced, handed to the recorder as if the cell had
# run. The recorder read the -1 as a NAMED GAP and filed the cell SKIP, which takes it out of the
# owed set: never compared, never in diverging.txt, permanently green about nothing. On an older
# recorder the same shape was recorded as the golden outright.
#
# TWO WORDS, BECAUSE THERE ARE TWO SITUATIONS AND ONLY ONE OF THEM IS A FAILURE:
#
#   oracle_harness_give_up  the harness broke. Marks `effects.harness_error` — which record.sh's
#                           script_cell_verdict refuses a cell for, ahead of every other test — and
#                           exits NON-ZERO, which it refuses the cell for again. Two independent
#                           signals for one fact, because the whole defect was a single signal the
#                           recorder happened to read as something else.
#   oracle_named_gap        this HOST cannot host this cell, AND busbar's own cell list says so:
#                           the cell declares `needs_fixture: "<ENV VAR>"` and that variable is
#                           unset here. That is not a failure and never was: it stays the -1 SKIP
#                           the recorder reads as UNSUPPORTED, and it exits 0 — but the entitlement
#                           is the CELL'S, checked against cells.json on the way through, so a
#                           driver cannot exempt itself by naming its own trouble a gap.
#
# 70 (EX_SOFTWARE) rather than 1: a driver's own `fail 1` means "busbar exited 1", and the two must
# not read alike in a log.
oracle_harness_give_up() {  # oracle_harness_give_up <why> [effects-json]
  local why="$1" eff="${2-}"
  [ -n "$eff" ] || eff='{}'
  jq -n --arg err "$why" --argjson eff "$eff" \
    '{status:-1, headers:{}, body:$err, effects:($eff + {error:$err, harness_error:$err})}' >"${RAW:?}/captured.json"
  printf 'harness give-up: %s\n' "$why" >&2
  exit 70
}

# A NAMED GAP IS A CLAIM, AND A CLAIM THE PRODUCT DID NOT MAKE IS A FAILURE. `oracle_named_gap`
# writes a capture that the recorder reads as UNSUPPORTED and files SKIP, which takes the cell out
# of the owed set: never compared, never in diverging.txt. That is the right answer when the BOX
# cannot host the cell — and it is exactly the answer a broken driver would like to give about
# itself. So the entitlement is not the driver's to assert. It is DECLARED IN cells.json, by the
# cell, as `needs_fixture: "<ENV VAR>"` — the same field the recorder itself skips a cell on, so the
# two halves cannot disagree about which cells may be gaps. Two conditions, both checked here:
#
#   * SOME CELL DECLARES IT. A driver naming a variable no cell in busbar's own cell list asks for
#     is claiming an exemption nobody wrote down, which is the whole shape this rule exists to
#     refuse. Undeclared -> it is a harness failure, marked and non-zero, like any other.
#   * AND THE VARIABLE IS ACTUALLY UNSET. A gap claimed while the fixture IS present is a driver
#     giving up on a cell it was equipped to record — the cell would silently stop being owed on a
#     box that could have answered it.
#
# The cell list is read where the oracle keeps it ($BUSBAR_ORACLE_DATA, else the tree's own copy),
# never from a path beside this file, so a driver cannot be pointed at a friendlier cell list.
oracle_cells_json() {  # the product's own cell list, whatever root this recording is rooted at
  local d="${BUSBAR_ORACLE_DATA:-}"
  [ -n "$d" ] || d="$(cd "$(dirname "${BASH_SOURCE[0]}")/../shadow-oracle" 2>/dev/null && pwd)"
  printf '%s/cells.json' "$d"
}

oracle_gap_is_declared() {  # oracle_gap_is_declared <ENV VAR> — rc 0 when a cell asks for it
  local var="${1-}" cells; cells="$(oracle_cells_json)"
  [ -n "$var" ] && [ -f "$cells" ] || return 1
  python3 - "$cells" "$var" <<'PY'
import json, sys
cells = json.load(open(sys.argv[1], encoding="utf-8")).get("cells", [])
sys.exit(0 if any(c.get("needs_fixture") == sys.argv[2] for c in cells) else 1)
PY
}

oracle_named_gap() {  # oracle_named_gap <why> <ENV VAR the cell declares as needs_fixture>
  local why="$1" var="${2-}" cells; cells="$(oracle_cells_json)"
  if ! oracle_gap_is_declared "$var"; then
    oracle_harness_give_up "claimed a named gap (${why}) on \`${var:-<no variable named>}\`, which no cell in ${cells} declares as needs_fixture. A gap is an entitlement the CELL holds, not one a driver may take: undeclared, this is the harness giving up"
  fi
  if [ -n "${!var:-}" ]; then
    oracle_harness_give_up "claimed a named gap (${why}) while \`${var}\` IS set: the fixture this cell needs is present, so the cell was recordable and giving up on it would take it out of the owed set on a box that could have answered it"
  fi
  jq -n --arg err "$why" --arg var "$var" \
    '{status:-1, headers:{}, body:"", effects:{error:$err, named_gap:$err, named_gap_fixture:$var}}' >"${RAW:?}/captured.json"
  printf 'named gap: %s (declared by cells.json as needs_fixture %s)\n' "$why" "$var" >&2
  exit 0
}

# ── Binary / plugin resolution ──────────────────────────────────────────────────────────────────
# macOS quarantines anything curl downloaded; without clearing it the runner refuses to exec the
# binary and the failure looks like a busbar defect rather than a Gatekeeper attribute.
declaw() {  # declaw <path> — strip the macOS quarantine xattr if present
  command -v xattr >/dev/null 2>&1 && xattr -dr com.apple.quarantine "$1" 2>/dev/null || true
}

libext() { case "$(uname -s)" in Darwin) echo dylib ;; *) echo so ;; esac; }
