#!/usr/bin/env bash
# THE LANDING ENGINE'S SUPERVISOR — ONE ENGINE HOME, ONE ENV FILE, ONE RESTART COMMAND (F1)
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MEASURED 09-09..09-11 on the runner log and the ledger: thirteen engine versions adopted by
# copying scripts/ to a land-fanout-<sha> directory by hand, a STOP marker, and a restart typed out
# of the ledger with a fifteen-variable env line — thirty-one restarts, fourteen STOP exits, and a
# boundary lost to each. The engine works when it runs; what cost the date is the minutes between
# "it stopped" and "somebody noticed and re-typed the line".
#
# SO THE RESTART IS A LOOP AND NOT A PERSON:
#
#   bash scripts/landq-supervisor.sh        # the one command, from any cwd that is not the runner tree
#
#   * THE ENGINE HOME is ~/.busbar-engine: `current/scripts` is a `git archive` of the landed tip's
#     scripts/ at the sha in `sha`, never a hand copy and never a checkout that can be edited under
#     the runner. `env` is the restart line, one NAME=value per line (scripts/landq.env.example).
#   * ADOPTION IS A LANDING, AND ONLY A LANDING. At every boundary the runner signals
#     (target/gate/landq.boundary) the supervisor asks the landed tip which commit last touched
#     scripts/, and compares it with what the PREVIOUS boundary's tip said (~/.busbar-engine/
#     last-tip-engine). They differ only when a landing CHANGED the tip's engine — and a landing is
#     newer by construction, which is the only ordering available: landings are `cherry-pick -x`, so
#     a landed engine commit is never the branch sha an ancestry test would ask about. Then, and
#     only then, it asks the runner to stop AT THE BOUNDARY (never mid-batch — a batch is an hour of
#     a fleet box), re-archives and starts the new engine. Nobody types anything.
#     THE HOME'S SHA IS A PIN, NOT A COMPARISON. Measured 2026-09-11: the tip carried a scripts/ sha
#     from the T0-S era while the engine actually running was two unlanded lines AHEAD of it — a
#     supervisor that adopted "whatever differs from the home" would have adopted that older engine
#     at its first start and flipped back to it at every boundary after. The integrator pins the
#     home once; landings move it from there, and ~/.busbar-engine/PIN stops even that.
#   * THE EXIT CLASS DECIDES (landq4.sh's THE EXIT-CODE CONTRACT, and nothing else):
#       0  STOP marker            the supervisor exits too — a stop is a stop
#       1  HALT head-conflict-twice   a fact about the tree: PAGE and WAIT for the integrator
#       2  another runner holds the lock  exit, quietly: somebody else is landing on this host
#       3  HALT tree-moved            the other tree fact: PAGE and WAIT
#       *  anything else = INFRASTRUCTURE: restart on the 60/120/240/480/900 s ladder, counted
#     A page writes ~/.busbar-engine/PAGED and a line in the runner's status JSON, and the loop
#     starts nothing while that file exists. `rm ~/.busbar-engine/PAGED` is the unpage.
#   * THE RUNNER REMAINS THE ONLY WRITER OF THE QUEUE. This file never opens land-queue.txt: not to
#     read it, not to count it, not to fix it. Its only writes are under the engine home, the
#     STOP marker it sets for an adoption (and removes again), and the status file's supervisor
#     section — written only while no runner is alive, so there is never a second writer of it.
#
#   scripts/landq-supervisor.sh --selftest  # every decision, proven against a stub runner
#   scripts/landq-supervisor.sh --once      # one start, one decision, then return (what the tests run)
#
# NO `set -e`: the exit status of the runner IS the signal, and a shell that dies on it before it
# can be read is a shell that turns every class into the same silence.
set -uo pipefail

ENGINE_HOME="${BUSBAR_ENGINE_HOME:-$HOME/.busbar-engine}"
CURRENT="$ENGINE_HOME/current"          # $CURRENT/scripts/* — the archived engine that runs
SHAF="$ENGINE_HOME/sha"                 # the sha that archive was taken at
ENVF="$ENGINE_HOME/env"                 # the restart line, as a file
PAGEDF="$ENGINE_HOME/PAGED"             # present = the integrator owes the engine an answer
ADOPTF="$ENGINE_HOME/ADOPT"             # present = the STOP marker downstairs is OURS, for an adoption
PINF="$ENGINE_HOME/PIN"                 # present = adopt nothing, whatever lands (the integrator's pin)
LASTF="$ENGINE_HOME/last-tip-engine"    # the tip's engine sha AS OF THE LAST BOUNDARY WE SAW
SUPLOG="${LANDQ_SUP_LOG:-$ENGINE_HOME/supervisor.log}"
# SCRATCH UNDER $LAND_TMP AND NEVER UNDER /tmp (owner rule, 2026-09-11): a wiped directory took a
# running engine's staged scripts once already.
LAND_TMP="${LAND_TMP:-$HOME/Developer/tmp}"
POLL="${LANDQ_SUP_POLL_SECS:-30}"       # how often the boundary signal is read while a runner runs
PAGE_POLL="${LANDQ_SUP_PAGE_POLL_SECS:-60}"
BACKOFF_CAP="${LANDQ_SUP_BACKOFF_CAP_SECS:-900}"

sup_log() { # every line the supervisor writes goes to one file, and to the terminal when there is one
  local line; line="$(date -u +%FT%TZ) supervisor: $*"
  mkdir -p "$(dirname "$SUPLOG")" 2>/dev/null || true
  printf '%s\n' "$line" >>"$SUPLOG"
  [ -t 1 ] && printf '%s\n' "$line"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE ENV FILE — READ ONCE PER START, AND NEVER EXECUTED
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A file the operator edits is a file that will one day carry a typo, and a typo that is a COMMAND
# is a typo that runs as the runner. So the grammar is assignments and nothing else: every
# non-comment line must be NAME=..., and a line carrying a command substitution or a pipeline is
# refused before anything is sourced. What survives that check is sourced (so `$HOME` and `$PATH`
# expand as the operator means them) in the SUBSHELL THAT BECOMES THE RUNNER — one read per start,
# so an edit takes effect at the next restart and never half-way through one.
sup_env_check() { # $1 = env file; prints the number of assignments, non-zero on a bad line
  local f="${1:-$ENVF}" n=0 bad=0 line
  [ -f "$f" ] || { printf '0\n'; return 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*|' '*'#'*) continue ;; esac
    printf '%s' "$line" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*=' || { bad=1; break; }
    case "$line" in *'$('*|*'`'*|*';'*|*'|'*|*'&'*) bad=1; break ;; esac
    n=$((n + 1))
  done <"$f"
  printf '%s\n' "$n"
  [ "$bad" = 0 ] || return 1
  [ "$n" -gt 0 ] || return 1
  return 0
}
sup_env_value() { # $1 = name, $2 = env file; the supervisor's own lookup (LANDQ_ROOT, LAND_TMP)
  local name="$1" f="${2:-$ENVF}"
  [ -f "$f" ] || return 0
  ( set -a; . "$f" >/dev/null 2>&1; set +a; eval "printf '%s\n' \"\${$name:-}\"" ) 2>/dev/null
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE ENGINE HOME — `git archive`, NEVER A COPY AND NEVER A CHECKOUT
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A `cp -r` leaves whatever the source directory happened to hold (a slot's half-finished edit, a
# selftest's leftovers); a checkout can be moved under the running engine by anything that runs
# `git checkout` in that tree. An archive of one sha is exactly the engine that landed, and the sha
# file beside it is what makes "which engine is running" a fact instead of a guess.
sup_engine_sha_for_tip() { # $1 = the landed tip, $2 = repo; prints the sha that last touched scripts/
  local tip="$1" repo="${2:-$REPO}"
  git -C "$repo" log -1 --format=%H "$tip" -- scripts/ 2>/dev/null
}
sup_current_sha() { [ -f "$SHAF" ] && head -n1 "$SHAF" | tr -d ' \n' || true; }
sup_archive() { # $1 = sha, $2 = repo; replaces $CURRENT with scripts/ at that sha
  local sha="$1" repo="${2:-$REPO}" d
  [ -n "$sha" ] || return 1
  mkdir -p "$LAND_TMP" "$ENGINE_HOME" 2>/dev/null || true
  d="$(mktemp -d "$LAND_TMP/landq-engine.XXXXXX")" || return 1
  if ! git -C "$repo" archive "$sha" scripts | tar -x -C "$d" 2>/dev/null; then
    rm -rf "$d"; sup_log "could not archive scripts/ at $sha out of $repo"; return 1
  fi
  [ -d "$d/scripts" ] || { rm -rf "$d"; sup_log "the archive at $sha carries no scripts/"; return 1; }
  chmod +x "$d/scripts"/*.sh 2>/dev/null || true
  rm -rf "$CURRENT.prev"
  [ -e "$CURRENT" ] && mv "$CURRENT" "$CURRENT.prev"
  mv "$d" "$CURRENT" || return 1
  printf '%s\n' "$sha" >"$SHAF.tmp" && mv "$SHAF.tmp" "$SHAF"
  sup_log "engine home is now scripts/ at $sha (archived from $repo)"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE DECISION — ONE WORD PER EXIT STATUS, AND NOTHING ELSE DECIDES
# ──────────────────────────────────────────────────────────────────────────────────────────────────
sup_decision() { # $1 = the runner's exit status
  case "${1:-}" in
    0) printf 'stop\n' ;;
    1) printf 'page-head-conflict-twice\n' ;;
    2) printf 'locked\n' ;;
    3) printf 'page-tree-moved\n' ;;
    *) printf 'restart\n' ;;
  esac
}
# THE LADDER, the runner's own: 1, 2, 4, 8, 15 minutes and 15 from then on. A cap and not a
# give-up — the engine never stops asking.
sup_backoff_secs() { # $1 = how many restarts in a row
  local n="${1:-1}" s=60
  case "$n" in ''|*[!0-9]*) n=1 ;; esac
  [ "$n" -ge 1 ] || n=1
  while [ "$n" -gt 1 ]; do s=$((s * 2)); n=$((n - 1)); [ "$s" -ge "$BACKOFF_CAP" ] && break; done
  [ "$s" -gt "$BACKOFF_CAP" ] && s="$BACKOFF_CAP"
  printf '%s\n' "$s"
}
sup_sleep() { # the selftest records the ladder instead of living through it
  [ "${LANDQ_SUP_NO_SLEEP:-}" = 1 ] && { printf '%s\n' "${1:-0}" >>"${LANDQ_SUP_SLEEPLOG:-/dev/null}"; return 0; }
  sleep "${1:-0}"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE PAGE — A FILE, A LINE IN THE STATUS, AND A LOOP THAT STARTS NOTHING UNTIL IT IS GONE
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# A HALT is a fact about the tree, and no amount of restarting makes a head line apply. The engine
# stops asking exactly here and nowhere else. The status JSON is the runner's file; the supervisor
# merges into it ONLY while no runner is alive (between a wait and a start), so the "written
# temp+mv, one writer" rule the status file was built on still holds.
sup_status_merge() { # $1 = key/value JSON object for "supervisor", $2 = page kind (optional), $3 = page text
  local sj="${STATUSJ:-}"
  [ -n "$sj" ] || return 0
  SUP_J="$1" SUP_KIND="${2:-}" SUP_TEXT="${3:-}" SUP_OUT="$sj" python3 - <<'PY' 2>/dev/null || return 0
import json, os, time
E = os.environ
out = E["SUP_OUT"]
try:
    d = json.load(open(out, encoding="utf-8"))
    if not isinstance(d, dict):
        d = {}
except Exception:
    d = {}
try:
    sup = json.loads(E["SUP_J"])
except Exception:
    sup = {}
sup["written"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
d["supervisor"] = sup
if E.get("SUP_KIND"):
    pages = d.get("pages") or []
    pages.append({"at": sup["written"], "kind": E["SUP_KIND"], "text": E.get("SUP_TEXT") or ""})
    d["pages"] = pages[-5:]
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
tmp = out + ".sup.tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(d, fh, indent=1, sort_keys=True)
    fh.write("\n")
os.replace(tmp, out)
PY
  return 0
}
sup_page() { # $1 = kind, $2 = text
  local kind="$1" text="${2:-}"
  mkdir -p "$ENGINE_HOME" 2>/dev/null || true
  printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$kind" "$text" >>"$PAGEDF"
  # The runner's own page ledger too, so the page survives into the next runner's status file.
  [ -n "${REPO:-}" ] && [ -d "$REPO/target/gate" ] && \
    printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$kind" "$text" >>"$REPO/target/gate/landq4.page.txt"
  sup_log "PAGE [$kind]: $text — waiting for the integrator (rm $PAGEDF to unpage)"
  return 0
}
sup_paged() { [ -s "$PAGEDF" ]; }

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE BOUNDARY WATCH — THE ONLY MOMENT AN ENGINE IS ADOPTED
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The runner writes `<epoch> <tip>` at the end of every batch (landq4.sh's lq_boundary). The
# supervisor reads that signal while the runner runs; when the tip's engine sha is not the one it
# archived, it sets the STOP marker — and a marker of its OWN beside it, so that the exit that
# follows is read as "adopt and restart" rather than "the integrator wants the engine down".
# IT NEVER SETS STOP OVER SOMEBODY ELSE'S: a STOP that was already there is the integrator's, and
# the adoption simply happens at the next start instead.
sup_boundary_tip() { # $1 = the boundary file
  local f="${1:-${BOUNDARY:-}}"
  [ -n "$f" ] && [ -f "$f" ] && awk 'NF { print $2 }' "$f" | tail -n1 || true
}
sup_last_tip_engine() { [ -f "$LASTF" ] && head -n1 "$LASTF" | tr -d ' \n' || true; }
sup_remember_tip_engine() { # $1 = the tip's engine sha at this boundary
  [ -n "${1:-}" ] || return 0
  mkdir -p "$ENGINE_HOME" 2>/dev/null || true
  printf '%s\n' "$1" >"$LASTF.tmp" && mv "$LASTF.tmp" "$LASTF"
}
# ADOPTION IS A CHANGE AT THE TIP, NOT A DIFFERENCE FROM THE HOME. Prints the sha to adopt and
# returns 0 only when a landing moved the tip's engine since the last boundary this supervisor saw.
# Three refusals, and each of them is a defect this rule exists to avoid:
#   * NO BASELINE YET (first start, or a fresh engine home): the baseline is RECORDED and nothing is
#     adopted. The home is whatever the integrator pinned, and a tip that is behind it stays behind.
#   * THE TIP'S ENGINE DID NOT MOVE: a landing that touches no script changes nothing here.
#   * ~/.busbar-engine/PIN EXISTS: the integrator is holding an engine on purpose (a bisect, a
#     revert in flight, an engine being proven by hand). Landings are still tracked — the baseline
#     moves — so that removing the pin does not adopt a change that landed three batches ago.
sup_adopt_wanted() { # $1 = tip; prints the sha to adopt, 0 = adopt it
  local tip="$1" want prev
  [ -n "$tip" ] || return 1
  want="$(sup_engine_sha_for_tip "$tip")"
  [ -n "$want" ] || return 1
  prev="$(sup_last_tip_engine)"
  if [ -z "$prev" ]; then
    sup_remember_tip_engine "$want"
    sup_log "engine baseline recorded at $(printf '%.9s' "$want"); the home stays pinned at $(sup_current_sha) until a landing moves it"
    return 1
  fi
  [ "$want" = "$prev" ] && return 1
  if [ -e "$PINF" ]; then
    sup_remember_tip_engine "$want"
    sup_log "a landing moved the tip's engine to $(printf '%.9s' "$want") but $PINF is set: NOT adopting"
    return 1
  fi
  printf '%s\n' "$want"
  return 0
}
sup_request_adoption() { # $1 = the sha to adopt
  if [ -f "$STOPF" ]; then
    sup_log "adoption to $1 waits: a STOP marker is already set, and it is not ours"
    return 1
  fi
  printf '%s\n' "$1" >"$ADOPTF"
  : >"$STOPF"
  sup_log "adoption requested at the boundary: engine $(sup_current_sha) -> $1; STOP set, the runner stops after this batch"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE LOOP
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# SETS $SUP_PID rather than printing it: a `$(…)` here would start the runner inside a command
# substitution's subshell, and the `wait` that reads its exit status — the whole contract — would
# then be waiting on a process that is not its child. Measured the hard way.
sup_start_runner() { # sets SUP_PID; reads the env file ONCE, here, per start
  local n
  n="$(sup_env_check "$ENVF")" || { sup_log "the env file $ENVF is missing, empty, or carries a line that is not an assignment — nothing started"; return 1; }
  sup_log "env: read $n variable(s) from $ENVF"
  ( set -a; . "$ENVF" >/dev/null 2>&1; set +a
    export LAND_SH_SRC="${LANDQ_SUP_SCRIPTS:-$CURRENT/scripts}"
    exec bash "$RUNNER" ) >>"${LANDQ_SUP_RUNNER_LOG:-$SUPLOG}" 2>&1 &
  SUP_PID=$!
  return 0
}
sup_watch() { # $1 = the runner's pid; polls the boundary signal until the runner is gone
  local pid="$1" seen="" now adopt
  seen="$(sup_boundary_tip)"
  while kill -0 "$pid" 2>/dev/null; do
    sup_sleep "$POLL"
    kill -0 "$pid" 2>/dev/null || break
    now="$(sup_boundary_tip)"
    [ -n "$now" ] && [ "$now" != "$seen" ] || continue
    seen="$now"
    sup_log "boundary at $(printf '%.9s' "$now")"
    adopt="$(sup_adopt_wanted "$now")" || continue
    # THE BASELINE MOVES ONLY WITH THE ADOPTION. A request refused (the integrator's own STOP is
    # already set) must fire again at the next boundary, not be forgotten as "seen".
    sup_request_adoption "$adopt" && sup_remember_tip_engine "$adopt"
  done
  wait "$pid"; return $?
}
sup_loop() {
  local starts=0 consec=0 rc d wait_s adopt tip
  while true; do
    if sup_paged; then
      sup_log "PAGED ($(tail -n1 "$PAGEDF" | cut -f2)) — nothing starts until $PAGEDF is removed"
      sup_status_merge "{\"state\":\"paged\",\"starts\":$starts,\"paged\":true,\"engine_sha\":\"$(sup_current_sha)\"}"
      while sup_paged; do
        [ "${LANDQ_SUP_PAGE_WAIT_ONCE:-}" = 1 ] && return 4
        sup_sleep "$PAGE_POLL"
      done
      sup_log "the page is cleared; starting again"
      consec=0
    fi
    # THE ENGINE THE LANDED TIP CARRIES, at every start (the second half of "adoption is a landing":
    # a supervisor started by hand after an engine landed adopts it without being told to).
    tip="$(sup_boundary_tip)"; [ -n "$tip" ] || tip="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || true)"
    if adopt="$(sup_adopt_wanted "$tip")"; then
      sup_archive "$adopt" && sup_remember_tip_engine "$adopt" || sup_log "the archive failed; running the engine already in the home"
    fi
    [ -d "$CURRENT/scripts" ] || [ -n "${LANDQ_SUP_RUNNER:-}" ] || { sup_log "no engine in $CURRENT — archive one first"; return 2; }
    rm -f "$ADOPTF"
    local pid; SUP_PID=""; sup_start_runner || return 2; pid="$SUP_PID"
    starts=$((starts + 1))
    sup_log "runner started (pid $pid, engine $(sup_current_sha), tree $REPO)"
    sup_status_merge "{\"state\":\"running\",\"pid\":$pid,\"starts\":$starts,\"restarts_in_a_row\":$consec,\"paged\":false,\"engine_sha\":\"$(sup_current_sha)\"}"
    sup_watch "$pid"; rc=$?
    d="$(sup_decision "$rc")"
    sup_log "runner exited $rc -> $d"
    case "$d" in
      stop)
        if [ -f "$ADOPTF" ]; then
          adopt="$(head -n1 "$ADOPTF")"; rm -f "$ADOPTF" "$STOPF"
          sup_archive "$adopt" && sup_remember_tip_engine "$adopt" || sup_log "the adoption archive failed; the engine in the home stands"
          consec=0
          sup_log "adopted at the boundary; restarting on $(sup_current_sha)"
          sup_status_merge "{\"state\":\"adopted\",\"starts\":$starts,\"last_exit\":$rc,\"paged\":false,\"engine_sha\":\"$(sup_current_sha)\"}"
        else
          sup_log "STOP: the runner stopped at a boundary and so does the supervisor"
          sup_status_merge "{\"state\":\"stopped\",\"starts\":$starts,\"last_exit\":$rc,\"paged\":false,\"engine_sha\":\"$(sup_current_sha)\"}"
          return 0
        fi ;;
      locked)
        sup_log "another runner holds the host lock — this supervisor exits rather than race it"
        sup_status_merge "{\"state\":\"locked\",\"starts\":$starts,\"last_exit\":$rc,\"paged\":false,\"engine_sha\":\"$(sup_current_sha)\"}"
        return 0 ;;
      page-head-conflict-twice|page-tree-moved)
        sup_page "${d#page-}" "the runner exited $rc: ${d#page-} — a fact about the tree, not the infrastructure"
        sup_status_merge "{\"state\":\"paged\",\"starts\":$starts,\"last_exit\":$rc,\"fault\":\"${d#page-}\",\"paged\":true,\"engine_sha\":\"$(sup_current_sha)\"}" \
          "${d#page-}" "the runner exited $rc"
        [ "${LANDQ_SUP_ONCE:-}" = 1 ] && return 0 ;;
      restart)
        consec=$((consec + 1))
        wait_s="$(sup_backoff_secs "$consec")"
        sup_log "infrastructure exit $rc (restart $consec in a row): waiting ${wait_s}s"
        sup_status_merge "{\"state\":\"backoff\",\"starts\":$starts,\"last_exit\":$rc,\"restarts_in_a_row\":$consec,\"next_restart_secs\":$wait_s,\"paged\":false,\"engine_sha\":\"$(sup_current_sha)\"}"
        sup_sleep "$wait_s" ;;
    esac
    [ "${LANDQ_SUP_ONCE:-}" = 1 ] && return 0
    [ -n "${LANDQ_SUP_MAX_STARTS:-}" ] && [ "$starts" -ge "$LANDQ_SUP_MAX_STARTS" ] && { sup_log "start ceiling ${LANDQ_SUP_MAX_STARTS} reached"; return 0; }
  done
}

sup_bind_tree() { # everything that depends on the tree, resolved once, from the env file
  REPO="${LANDQ_ROOT:-$(sup_env_value LANDQ_ROOT)}"
  [ -n "$REPO" ] || { sup_log "no LANDQ_ROOT in $ENVF — the supervisor does not guess which tree the runner lands into"; return 2; }
  STOPF="$REPO/target/gate/STOP"
  BOUNDARY="${LANDQ_BOUNDARY:-$REPO/target/gate/landq.boundary}"
  STATUSJ="${LANDQ_STATUS_JSON:-$REPO/target/gate/landq.status.json}"
  RUNNER="${LANDQ_SUP_RUNNER:-$CURRENT/scripts/landq4.sh}"
  local t; t="$(sup_env_value LAND_TMP)"; [ -n "$t" ] && LAND_TMP="$t"
  mkdir -p "$LAND_TMP" 2>/dev/null || true
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest: every decision, against a stub runner that exits with each code of the contract
# ──────────────────────────────────────────────────────────────────────────────────────────────────
sup_selftest() {
  local root fails=0
  mkdir -p "$LAND_TMP" 2>/dev/null || true
  root="$(mktemp -d "$LAND_TMP/landq-sup-selftest.XXXXXX")" || return 1
  local SRC="$root/src.sh"
  # The implementation with the selftest cut out of it: a `grep -c` that asks whether the supervisor
  # does something must not count the line that ASSERTS it.
  sed '/^sup_selftest() {/,/^}$/d' "${BASH_SOURCE[0]}" >"$SRC"
  _t() { if [ "$2" = "$3" ]; then printf '  ok   %-56s\n' "$1"
         else printf '  FAIL %-56s (wanted [%s], got [%s])\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi; }

  # ── the tree: an engine sha is the newest commit that touched scripts/, and nothing else ───────
  local repo="$root/repo"; mkdir -p "$repo/scripts" "$repo/docs"
  git -C "$repo" init -q
  git -C "$repo" config user.email landq@selftest; git -C "$repo" config user.name landq
  git -C "$repo" config commit.gpgsign false
  mkdir -p "$root/nohooks"; git -C "$repo" config core.hooksPath "$root/nohooks"
  printf '#!/usr/bin/env bash\necho engine-1\n' >"$repo/scripts/landq4.sh"
  git -C "$repo" add -A; git -C "$repo" commit -qm "engine 1"
  local shaA; shaA="$(git -C "$repo" rev-parse HEAD)"
  printf 'docs\n' >"$repo/docs/x.md"; git -C "$repo" add -A; git -C "$repo" commit -qm "docs only"
  local tipB; tipB="$(git -C "$repo" rev-parse HEAD)"
  printf '#!/usr/bin/env bash\necho engine-2\n' >"$repo/scripts/landq4.sh"
  git -C "$repo" add -A; git -C "$repo" commit -qm "engine 2"
  local tipC; tipC="$(git -C "$repo" rev-parse HEAD)"

  # ── the engine home, entirely inside the scratch root ─────────────────────────────────────────
  ENGINE_HOME="$root/home"; mkdir -p "$ENGINE_HOME"
  CURRENT="$ENGINE_HOME/current"; SHAF="$ENGINE_HOME/sha"; ENVF="$ENGINE_HOME/env"
  PAGEDF="$ENGINE_HOME/PAGED"; ADOPTF="$ENGINE_HOME/ADOPT"; SUPLOG="$ENGINE_HOME/supervisor.log"
  PINF="$ENGINE_HOME/PIN"; LASTF="$ENGINE_HOME/last-tip-engine"
  REPO="$repo"; STOPF="$repo/target/gate/STOP"; BOUNDARY="$repo/target/gate/landq.boundary"
  STATUSJ="$repo/target/gate/landq.status.json"; mkdir -p "$repo/target/gate"
  POLL=0; PAGE_POLL=0
  export LANDQ_SUP_NO_SLEEP=1; LANDQ_SUP_SLEEPLOG="$root/sleeps.txt"; : >"$LANDQ_SUP_SLEEPLOG"

  echo "supervisor selftest: the decision, one per exit status of the contract"
  _t "0 is a stop, and the supervisor stops too"  stop                     "$(sup_decision 0)"
  _t "1 is HALT head-conflict-twice: a page"      page-head-conflict-twice "$(sup_decision 1)"
  _t "2 is another runner's lock: not a fault"    locked                   "$(sup_decision 2)"
  _t "3 is HALT tree-moved: a page"               page-tree-moved          "$(sup_decision 3)"
  _t "75 (the box went away) is a restart"        restart                  "$(sup_decision 75)"
  _t "70 (the harness gave up) is a restart"      restart                  "$(sup_decision 70)"
  _t "137 (killed) is a restart"                  restart                  "$(sup_decision 137)"
  _t "a plain crash is a restart"                 restart                  "$(sup_decision 42)"
  _t "  ...and so is an exit nobody has seen yet" restart                  "$(sup_decision 199)"
  _t "NO infrastructure status is ever a page"    0 \
     "$(for c in 70 75 126 137 139 42 199; do sup_decision "$c"; done | grep -c page)"

  echo "supervisor selftest: the backoff ladder is the runner's own"
  _t "the first restart waits a minute"   60  "$(sup_backoff_secs 1)"
  _t "then two"                          120  "$(sup_backoff_secs 2)"
  _t "then four"                         240  "$(sup_backoff_secs 3)"
  _t "then eight"                        480  "$(sup_backoff_secs 4)"
  _t "then the cap"                      900  "$(sup_backoff_secs 5)"
  _t "  ...and the cap is a cap, not a give-up" 900 "$(sup_backoff_secs 99)"

  echo "supervisor selftest: the env file is assignments and nothing else"
  printf '# a comment\n\nLANDQ_ROOT=%s\nLAND_BATCH=8\nPATH=$HOME/.local/bin:$PATH\n' "$repo" >"$ENVF"
  _t "a good file counts its assignments"  3 "$(sup_env_check "$ENVF")"
  _t "  ...and is accepted"                0 "$(sup_env_check "$ENVF" >/dev/null; echo $?)"
  _t "  ...with \$HOME expanded as the operator means it" 1 \
     "$(sup_env_value PATH "$ENVF" | grep -c "^$HOME/.local/bin:")"
  _t "  ...and LANDQ_ROOT read straight out of it" "$repo" "$(sup_env_value LANDQ_ROOT "$ENVF")"
  printf 'LANDQ_ROOT=%s\nrm -rf /\n' "$repo" >"$root/bad1"
  _t "a command is refused, never sourced"  1 "$(sup_env_check "$root/bad1" >/dev/null; echo $?)"
  printf 'LANDQ_ROOT=%s\nX=$(id -u)\n' "$repo" >"$root/bad2"
  _t "  ...and so is a command substitution" 1 "$(sup_env_check "$root/bad2" >/dev/null; echo $?)"
  printf 'X=1; rm -rf /\n' >"$root/bad3"
  _t "  ...and a second command on one line" 1 "$(sup_env_check "$root/bad3" >/dev/null; echo $?)"
  _t "no env file at all starts nothing"     2 "$(sup_env_check "$root/absent" >/dev/null; echo $?)"

  echo "supervisor selftest: the engine home is a git archive of one sha"
  _t "archiving the tip's scripts"          0 "$(sup_archive "$shaA" "$repo" >/dev/null 2>&1; echo $?)"
  _t "  ...puts scripts/ in the home"       1 "$([ -f "$CURRENT/scripts/landq4.sh" ] && echo 1 || echo 0)"
  _t "  ...at that very sha"                "$shaA" "$(sup_current_sha)"
  _t "  ...and the archive is the sha's content, not a copy of the worktree" 1 \
     "$(grep -c 'engine-1' "$CURRENT/scripts/landq4.sh")"
  _t "  ...and it carries nothing else"     0 "$([ -e "$CURRENT/docs" ] && echo 1 || echo 0)"

  echo "supervisor selftest: adoption is a CHANGE AT THE TIP, never a difference from the home"
  rm -f "$LASTF" "$PINF"
  _t "the engine sha of a tip is the last commit touching scripts/" "$shaA" "$(sup_engine_sha_for_tip "$tipB" "$repo")"
  # A FIRST START HAS NO BASELINE, and a supervisor with nothing to compare adopts nothing: the home
  # is whatever the integrator pinned, and the tip may be a dozen engine lines behind it.
  _t "a first start adopts nothing"          1 "$(sup_adopt_wanted "$tipB" >/dev/null 2>&1; echo $?)"
  _t "  ...it records the baseline instead"  "$shaA" "$(sup_last_tip_engine)"
  # THE DEFECT THIS RULE EXISTS FOR (measured 2026-09-11): the home is pinned AHEAD of the tip,
  # because the engine that is running has not landed yet. Comparing the home with the tip would
  # adopt the OLDER engine off the tip at the first start and flip back to it at every boundary.
  printf '%s\n' "$tipC" >"$SHAF"
  _t "a tip BEHIND the pinned home is never adopted" 1 "$(sup_adopt_wanted "$tipB" >/dev/null 2>&1; echo $?)"
  _t "  ...and the home stays pinned"        "$tipC" "$(sup_current_sha)"
  printf '%s\n' "$shaA" >"$SHAF"
  # ...AND THE ONE THING THAT *IS* AN ADOPTION: a landing that changed the tip's engine.
  _t "a docs-only landing moves nothing"     1 "$(sup_adopt_wanted "$tipB" >/dev/null 2>&1; echo $?)"
  _t "a landing that touches scripts/ adopts" "$tipC" "$(sup_adopt_wanted "$tipC")"
  # THE PIN: while it exists nothing is adopted, but landings are still TRACKED, so removing it
  # cannot adopt a change that landed three batches ago.
  : >"$PINF"
  _t "a PIN refuses the adoption"            1 "$(sup_adopt_wanted "$tipC" >/dev/null 2>&1; echo $?)"
  _t "  ...says so in the log"               1 "$(grep -c 'is set: NOT adopting' "$SUPLOG")"
  _t "  ...and still tracks the landing"     "$tipC" "$(sup_last_tip_engine)"
  rm -f "$PINF"
  _t "  ...so unpinning adopts nothing by itself" 1 "$(sup_adopt_wanted "$tipC" >/dev/null 2>&1; echo $?)"
  printf '%s\n' "$shaA" >"$LASTF"
  printf '%s %s\n' "$(date +%s)" "$tipC" >"$BOUNDARY"
  _t "the boundary signal names the tip"     "$tipC" "$(sup_boundary_tip)"
  rm -f "$STOPF"
  _t "an adoption sets the STOP marker at the boundary" 0 "$(sup_request_adoption "$tipC" >/dev/null; echo $?)"
  _t "  ...and a marker of its own beside it" "$tipC" "$(cat "$ADOPTF")"
  _t "  ...so the stop is read as an adoption" 1 "$([ -f "$STOPF" ] && echo 1 || echo 0)"
  rm -f "$ADOPTF"
  _t "  ...but never over the integrator's STOP" 1 "$(sup_request_adoption "$tipC" >/dev/null; echo $?)"
  _t "  ...which stays the integrator's"      0 "$([ -f "$ADOPTF" ] && echo 1 || echo 0)"
  rm -f "$STOPF" "$BOUNDARY"

  # ── THE STUB RUNNER: it exits with the next code of a list, and says it started ────────────────
  local stub="$root/stub-landq4.sh"
  cat >"$stub" <<'STUB'
#!/usr/bin/env bash
printf 'start batch=%s\n' "${SUPTEST_MARK:-none}" >>"$SUPTEST_STARTS"
n="$(grep -c . "$SUPTEST_STARTS")"
rc="$(awk -v n="$n" 'NR == n { print $1 }' "$SUPTEST_CODES")"; [ -n "$rc" ] || rc=0
if [ -n "${SUPTEST_ADOPT:-}" ]; then printf '%s\n' "$SUPTEST_ADOPT" >"$SUPTEST_ADOPTF"; : >"$SUPTEST_STOPF"; fi
exit "$rc"
STUB
  chmod +x "$stub"
  RUNNER="$stub"; export LANDQ_SUP_RUNNER="$stub"
  local starts="$root/starts.txt" codes="$root/codes.txt"
  sup_env_write() { # the env file the stub is started with, so the DELIVERY of the env is proven too
    { printf 'LANDQ_ROOT=%s\n' "$repo"
      printf 'SUPTEST_STARTS=%s\n' "$starts"
      printf 'SUPTEST_CODES=%s\n' "$codes"
      printf 'SUPTEST_ADOPTF=%s\n' "$ADOPTF"
      printf 'SUPTEST_STOPF=%s\n' "$STOPF"
      printf 'SUPTEST_MARK=%s\n' "${1:-plain}"
      [ -n "${2:-}" ] && printf 'SUPTEST_ADOPT=%s\n' "$2"
      true; } >"$ENVF"
  }

  echo "supervisor selftest: three infrastructure exits, then a stop"
  : >"$starts"; : >"$LANDQ_SUP_SLEEPLOG"; : >"$SUPLOG"; rm -f "$PAGEDF"
  printf '75\n70\n137\n0\n' >"$codes"; sup_env_write infra
  _t "the loop returns cleanly on the stop"   0 "$(sup_loop >/dev/null 2>&1; echo $?)"
  _t "  ...after four starts (three restarts)" 4 "$(grep -c . "$starts")"
  _t "  ...on the 60/120/240 ladder"          "60 120 240" "$(tr '\n' ' ' <"$LANDQ_SUP_SLEEPLOG" | sed 's/ *$//')"
  _t "  ...paging nobody for infrastructure"  0 "$([ -e "$PAGEDF" ] && echo 1 || echo 0)"
  _t "the env file is read ONCE PER START"    4 "$(grep -c 'env: read 6 variable(s)' "$SUPLOG")"
  _t "  ...and the runner was started with it" 4 "$(grep -c 'batch=infra' "$starts")"

  echo "supervisor selftest: a HALT pages and waits, and the page blocks the next start"
  : >"$starts"; : >"$LANDQ_SUP_SLEEPLOG"; rm -f "$PAGEDF"
  printf '1\n' >"$codes"; sup_env_write halt
  _t "head-conflict-twice returns"            0 "$(LANDQ_SUP_ONCE=1 sup_loop >/dev/null 2>&1; echo $?)"
  _t "  ...having started the runner once"    1 "$(grep -c . "$starts")"
  _t "  ...and paged"                         1 "$(grep -c 'head-conflict-twice' "$PAGEDF")"
  _t "  ...without a restart ladder"          0 "$(grep -c . "$LANDQ_SUP_SLEEPLOG")"
  _t "  ...writing the fault to the status"   "head-conflict-twice" \
     "$(python3 -c 'import json,sys;print((json.load(open(sys.argv[1])).get("supervisor") or {}).get("fault",""))' "$STATUSJ")"
  _t "  ...and a page line beside it"         1 \
     "$(python3 -c 'import json,sys;print(sum(1 for p in (json.load(open(sys.argv[1])).get("pages") or []) if p.get("kind")=="head-conflict-twice"))' "$STATUSJ")"
  : >"$starts"; printf '0\n' >"$codes"
  _t "a PAGED marker starts NOTHING"          4 "$(LANDQ_SUP_PAGE_WAIT_ONCE=1 sup_loop >/dev/null 2>&1; echo $?)"
  _t "  ...not one start while it is there"   0 "$(grep -c . "$starts")"
  rm -f "$PAGEDF"
  _t "unpaged, it starts again"               0 "$(LANDQ_SUP_ONCE=1 sup_loop >/dev/null 2>&1; echo $?)"
  _t "  ...exactly once"                      1 "$(grep -c . "$starts")"

  echo "supervisor selftest: the other tree fact, and the lock that is not a fault"
  : >"$starts"; rm -f "$PAGEDF"; printf '3\n' >"$codes"; sup_env_write treemoved
  _t "tree-moved pages too"                   0 "$(LANDQ_SUP_ONCE=1 sup_loop >/dev/null 2>&1; echo $?)"
  _t "  ...naming the fault"                  1 "$(grep -c 'tree-moved' "$PAGEDF")"
  _t "  ...and it is in the runner's page ledger for the next status file" 1 \
     "$(grep -c 'tree-moved' "$repo/target/gate/landq4.page.txt")"
  rm -f "$PAGEDF"
  : >"$starts"; printf '2\n' >"$codes"; sup_env_write locked
  _t "a held host lock exits the supervisor"  0 "$(sup_loop >/dev/null 2>&1; echo $?)"
  _t "  ...after one start"                   1 "$(grep -c . "$starts")"
  _t "  ...and pages nobody: it is not a fault" 0 "$([ -e "$PAGEDF" ] && echo 1 || echo 0)"

  echo "supervisor selftest: adoption at the boundary, and no adoption without one"
  : >"$starts"; rm -f "$PAGEDF" "$ADOPTF" "$STOPF" "$PINF"
  sup_archive "$shaA" "$repo" >/dev/null 2>&1; printf '%s\n' "$shaA" >"$LASTF"
  printf '%s %s\n' "$(date +%s)" "$tipB" >"$BOUNDARY"     # a docs-only landing: the engine did not move
  printf '0\n' >"$codes"; sup_env_write nomove
  sup_loop >/dev/null 2>&1
  _t "a tip whose scripts/ did not move is not adopted" "$shaA" "$(sup_current_sha)"
  _t "  ...and the engine ran once"           1 "$(grep -c . "$starts")"
  # THE TIP MOVED WHILE THE SUPERVISOR WAS DOWN: the baseline says so at the next start.
  : >"$starts"; printf '0\n' >"$codes"; sup_env_write moved
  printf '%s %s\n' "$(date +%s)" "$tipC" >"$BOUNDARY"
  sup_loop >/dev/null 2>&1
  _t "a landing that moved the tip's engine is adopted at the start" "$tipC" "$(sup_current_sha)"
  _t "  ...and the baseline follows it"       "$tipC" "$(sup_last_tip_engine)"
  # ...AND AT A BOUNDARY, through the STOP marker (the stub plays the part of the watch).
  sup_archive "$shaA" "$repo" >/dev/null 2>&1; printf '%s\n' "$shaA" >"$LASTF"
  : >"$starts"; printf '0\n0\n' >"$codes"; sup_env_write adopt "$tipC"
  printf '%s %s\n' "$(date +%s)" "$tipB" >"$BOUNDARY"
  LANDQ_SUP_MAX_STARTS=2 sup_loop >/dev/null 2>&1
  _t "a boundary carrying a new engine sha adopts it" "$tipC" "$(sup_current_sha)"
  _t "  ...re-archived from the tip"          1 "$(grep -c 'engine-2' "$CURRENT/scripts/landq4.sh")"
  _t "  ...restarting the runner at that boundary" 2 "$(grep -c . "$starts")"
  _t "  ...and the STOP it set is taken away again" 0 "$([ -f "$STOPF" ] && echo 1 || echo 0)"
  _t "  ...with its own marker cleared"       0 "$([ -f "$ADOPTF" ] && echo 1 || echo 0)"
  _t "  ...and the baseline is the engine that landed" "$tipC" "$(sup_last_tip_engine)"
  # A PIN STOPS THE WHOLE OF IT, end to end.
  sup_archive "$shaA" "$repo" >/dev/null 2>&1; printf '%s\n' "$shaA" >"$LASTF"; : >"$PINF"
  : >"$starts"; printf '0\n' >"$codes"; sup_env_write pinned
  printf '%s %s\n' "$(date +%s)" "$tipC" >"$BOUNDARY"
  sup_loop >/dev/null 2>&1
  _t "a PIN keeps the pinned engine through a landing" "$shaA" "$(sup_current_sha)"
  _t "  ...and the runner still ran"          1 "$(grep -c . "$starts")"
  rm -f "$PINF"

  echo "supervisor selftest: the status file keeps what the runner wrote"
  printf '{"tip":"4197eb098","live":23,"pages":[]}\n' >"$STATUSJ"
  sup_status_merge '{"state":"running","starts":1}' 
  _t "the runner's keys survive a merge"      "4197eb098" \
     "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("tip",""))' "$STATUSJ")"
  _t "  ...beside the supervisor's own"       "running" \
     "$(python3 -c 'import json,sys;print((json.load(open(sys.argv[1])).get("supervisor") or {}).get("state",""))' "$STATUSJ")"

  echo "supervisor selftest: what this file is not allowed to touch"
  _t "the runner is the ONLY writer of the queue" 0 \
     "$(grep -vE '^[[:space:]]*#' "$SRC" | grep -c 'land-queue' || true)"
  local _sl="/" _pat; _pat="(^|[^[:alnum:]_.-])${_sl}tmp(${_sl}|[^[:alnum:]]|\$)"
  _t "no scratch under the wiped directories"  0 \
     "$(grep -vE '^[[:space:]]*#' "$SRC" | grep -cE "$_pat" || true)"
  _t "  ...and no TMPDIR fallback either"      0 "$(grep -vE '^[[:space:]]*#' "$SRC" | grep -c 'TMPDIR' || true)"
  _t "no set -e to swallow the exit class"     0 "$(grep -cE '^set -e|set -euo' "$SRC" || true)"
  _t "  ...and the exit class is read by wait"  1 "$(grep -c 'wait "\$pid"; return \$?' "$SRC")"
  _t "this selftest ran under LAND_TMP"        1 "$(case "$root" in "$LAND_TMP"/*) echo 1 ;; *) echo 0 ;; esac)"

  rm -rf "$root"
  if [ "$fails" = 0 ]; then
    echo "supervisor selftest: GREEN (the contract's five decisions, the ladder, the env file, the archive, adoption, the page)"
    return 0
  fi
  echo "supervisor selftest: RED ($fails failure(s))" >&2
  return 1
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest) sup_selftest; exit $? ;;
  --once)     LANDQ_SUP_ONCE=1 ;;
  -h|--help)  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  '')         : ;;
  *)          printf 'landq-supervisor: unknown argument [%s] — --selftest | --once | (nothing)\n' "$1" >&2; exit 2 ;;
esac

sup_bind_tree || exit $?
# THE SUPERVISOR IS NOT A SECOND RUNNER IN THE TREE. Started from inside the runner tree it would
# be counted by the census as a stranger and killed — and rightly: one engine in the tree.
case "$PWD/" in "$REPO"/*) printf 'landq-supervisor: run me from outside %s (one engine in the tree)\n' "$REPO" >&2; exit 2 ;; esac
sup_log "supervising $REPO (engine home $ENGINE_HOME, env $ENVF)"
sup_loop
exit $?
