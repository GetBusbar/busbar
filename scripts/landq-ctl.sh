#!/usr/bin/env bash
# THE INTEGRATOR'S ONLY TOOL FOR THE LANDING QUEUE (F3).
#
# Nobody edits target/gate/land-queue.txt — not the integrator, not a slot, not a tick. The runner
# is its only writer; everything else is a COMMAND appended to target/gate/land-queue.inbox.txt,
# which the runner folds under its own lock at the top of its next loop (landq4.sh's
# lq_inbox_fold). That is what makes a hand-back free: an append can never race the runner's
# rewrite, so it can never cost a pop.
#
#   scripts/landq-ctl.sh add "--prove --tests xtask <sha> <sha>"   # a line, at the tail
#   scripts/landq-ctl.sh add "#HOLD-after-<sha> --prove … <sha>"   # held, same thing
#   scripts/landq-ctl.sh park <sha> "<reason>"                     # stop it being live
#   scripts/landq-ctl.sh unpark <sha>                              # live again
#   scripts/landq-ctl.sh supersede <old-sha> "<new line>"          # re-cut, one command
#   scripts/landq-ctl.sh retag <sha> [#TAG …]                      # tags replaced; none = live
#   scripts/landq-ctl.sh front <sha>                               # to the head of the queue
#   scripts/landq-ctl.sh status                                    # the runner's state, 25 lines
#   scripts/landq-ctl.sh inbox                                     # what is still unfolded
#   scripts/landq-ctl.sh --selftest
#
# APPEND-ONLY, ONE LINE PER COMMAND. `>>` on a file opened O_APPEND is atomic for a write this size
# on every filesystem the fleet has, which is why this tool needs no lock of its own and why two
# people using it at once cannot lose each other's command.
set -uo pipefail

W="${LANDQ_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
Q="${LANDQ_QUEUE:-$W/target/gate/land-queue.txt}"
INBOX="${LANDQ_INBOX:-$W/target/gate/land-queue.inbox.txt}"
STATUSJ="${LANDQ_STATUS_JSON:-$W/target/gate/landq.status.json}"

ctl_die() { printf 'landq-ctl: %s\n' "$*" >&2; exit 2; }
ctl_emit() { # $1… = the command, written as one line
  local line="$*" nl
  # A NEWLINE IN A COMMAND WOULD BE TWO COMMANDS, one of which nobody wrote. `$(printf '\n')` is
  # not the way to ask — the substitution strips the newline and the pattern then matches every
  # string there is — so the character is built with the trailing-dot trick, as landq4.sh builds it.
  nl="$(printf '\n.')"; nl="${nl%.}"
  case "$line" in *"$nl"*) ctl_die "a command is one line; this one is not" ;; esac
  mkdir -p "$(dirname "$INBOX")" 2>/dev/null || true
  printf '%s\n' "$line" >>"$INBOX" || ctl_die "could not append to $INBOX"
  printf 'landq-ctl: queued -> %s\n' "$line"
}
ctl_sha() { # $1 = the argument that must be a sha
  [ -n "${1:-}" ] || ctl_die "that verb needs a sha"
  printf '%s' "$1" | grep -qxE '[0-9a-f]{7,40}' || ctl_die "[$1] is not a sha (7-40 hex)"
}

# ── status, in twenty-five lines or fewer ─────────────────────────────────────────────────────────
# The file the runner writes every loop (landq4.sh's lq_status_json) is the ONLY source: a tick that
# reconstructs the queue from five symlinked logs with tail-headed pipelines is a tick that is
# usually wrong and always slow. Rendered with python3's json so a half-written file cannot be read
# as a confident wrong answer — though the runner writes it temp+mv, so it cannot be half-written.
ctl_status() {
  [ -f "$STATUSJ" ] || ctl_die "no status file at $STATUSJ — the runner has not written one yet"
  LANDQ_STATUS_JSON="$STATUSJ" python3 - <<'PY'
import json, os, sys, time
p = os.environ["LANDQ_STATUS_JSON"]
try:
    d = json.load(open(p))
except Exception as e:
    print("landq-ctl: %s is not readable JSON (%s)" % (p, e)); sys.exit(2)
def age(t):
    try: return "%dm" % ((time.time() - float(t)) / 60)
    except Exception: return "?"
print("tip %s   engine %s   loop %s (%s ago)" % (d.get("tip","?"), d.get("engine_sha","?"), d.get("loop","?"), age(d.get("written_epoch",0))))
print("queue: live %s  held %s  parked %s  landed %s" % (d.get("live","?"), d.get("held","?"), d.get("parked","?"), d.get("landed","?")))
print("fleet: %s proof slot(s) per box, %s wanted per sweep" % (d.get("prove_per_box","?"), d.get("preprove_lines","?")))
b = d.get("batch") or {}
if b.get("lines"):
    print("batch of %s, started %s ago:" % (len(b["lines"]), age(b.get("started_epoch",0))))
    for l in b["lines"][:6]: print("   %s" % l[:96])
    if b.get("legs"): print("   legs: %s" % ", ".join(b["legs"])[:96])
else:
    print("batch: none in flight")
sw = d.get("sweep") or []
if sw:
    print("sweep, %s line(s) on boxes:" % len(sw))
    for s in sw[:6]: print("   %-22s %5s  %s" % (s.get("box","?"), age(s.get("started_epoch",0)), (s.get("line") or "")[:60]))
else:
    print("sweep: no line on a box")
bo = d.get("backoff") or {}
print("faults, consecutive by class: %s" % (", ".join("%s=%s" % (k, v) for k, v in sorted(bo.items())) or "none"))
for f in (d.get("faults") or [])[-5:]:
    print("   %s %-16s %s" % (f.get("at","?"), f.get("class","?"), (f.get("text") or "")[:60]))
if d.get("direct_edit"):
    print("PAGE: DIRECT EDIT — %s" % str(d["direct_edit"])[:100])
for pg in (d.get("pages") or [])[-2:]:
    print("PAGE: %s %s" % (pg.get("kind","?"), (pg.get("text") or "")[:80]))
PY
}

if [ "${1:-}" = "--selftest" ]; then
  fails=0; root="${LAND_TMP:-$HOME/Developer/tmp}"; mkdir -p "$root"
  root="$(mktemp -d "$root/landq-ctl-selftest.XXXXXX")"
  _t() { if [ "$2" = "$3" ]; then printf '  ok   %-52s\n' "$1"
         else printf '  FAIL %-52s (wanted [%s], got [%s])\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi; }
  INBOX="$root/inbox.txt"; STATUSJ="$root/status.json"; : >"$INBOX"
  echo "landq-ctl selftest: every verb writes ONE line to the inbox and nothing else"
  ( ctl_emit ADD "--prove --tests xtask deadbee1" ) >/dev/null
  _t "add writes one line"                   1 "$(grep -c . "$INBOX")"
  _t "  ...in the grammar the runner folds"  1 "$(grep -cx -- 'ADD --prove --tests xtask deadbee1' "$INBOX")"
  ( ctl_emit PARK deadbee1 "waiting on the owner" ) >/dev/null
  _t "park names its reason"                 1 "$(grep -cx -- 'PARK deadbee1 waiting on the owner' "$INBOX")"
  ( ctl_emit UNPARK deadbee1 ) >/dev/null
  _t "unpark is a verb and a sha"            1 "$(grep -cx -- 'UNPARK deadbee1' "$INBOX")"
  ( ctl_emit SUPERSEDE deadbee1 "--prove --tests xtask cafe123" ) >/dev/null
  _t "supersede carries the whole new line"  1 "$(grep -cx -- 'SUPERSEDE deadbee1 --prove --tests xtask cafe123' "$INBOX")"
  ( ctl_emit RETAG deadbee1 "#HOLD-after-cafe123" "#T0-B2-seam" ) >/dev/null
  _t "retag carries every tag"               1 "$(grep -cx -- 'RETAG deadbee1 #HOLD-after-cafe123 #T0-B2-seam' "$INBOX")"
  ( ctl_emit FRONT deadbee1 ) >/dev/null
  _t "front is a verb and a sha"             1 "$(grep -cx -- 'FRONT deadbee1' "$INBOX")"
  _t "the inbox is append-only: six commands"  6 "$(grep -c . "$INBOX")"
  # A SHA THAT IS NOT A SHA IS REFUSED HERE, before it can be a malformed command the runner skips.
  _t "a park with no sha is refused"         2 "$( ( ctl_sha "" ) >/dev/null 2>&1; echo $?)"
  _t "  ...and so is a word"                 2 "$( ( ctl_sha "strike" ) >/dev/null 2>&1; echo $?)"
  _t "  ...a real sha is accepted"           0 "$( ( ctl_sha "4197eb098" ) >/dev/null 2>&1; echo $?)"
  # THE STATUS RENDERER READS THE RUNNER'S FILE AND NOTHING ELSE, and it fits on a screen.
  cat >"$STATUSJ" <<'J'
{"tip":"4197eb098","engine_sha":"9b3a48fb8","loop":41,"written_epoch":1789155221,
 "live":23,"held":116,"parked":4,"landed":37,"prove_per_box":2,"preprove_lines":12,
 "batch":{"lines":["--prove --tests xtask aaaaaaa","--prove --tests xtask bbbbbbb"],"legs":["gates","oracle"],"started_epoch":1789155000},
 "sweep":[{"box":"i-071084387d22ed544","line":"--prove ccccccc","started_epoch":1789154000}],
 "backoff":{"box-unreachable":2},"faults":[{"at":"2026-09-11T20:00:00Z","class":"box-unreachable","text":"scp: Connection closed"}],
 "direct_edit":"land-queue.txt was written by somebody else","pages":[]}
J
  _t "status renders"                        0 "$( ( ctl_status ) >"$root/out.txt" 2>&1; echo $?)"
  _t "  ...in twenty-five lines or fewer"    1 "$([ "$(grep -c . "$root/out.txt")" -le 25 ] && echo 1 || echo 0)"
  _t "  ...naming the tip"                   1 "$(grep -c '4197eb098' "$root/out.txt")"
  _t "  ...the engine it is running"         1 "$(grep -c 'engine 9b3a48fb8' "$root/out.txt")"
  _t "  ...the per-box slot count it READ, never a constant" 1 "$(grep -c '2 proof slot(s) per box' "$root/out.txt")"
  _t "  ...the batch in flight"              1 "$(grep -c 'batch of 2' "$root/out.txt")"
  _t "  ...the sweep's box"                  1 "$(grep -c 'i-071084387d22ed544' "$root/out.txt")"
  _t "  ...the backoff counter"              1 "$(grep -c 'box-unreachable=2' "$root/out.txt")"
  _t "  ...and the direct-edit page"         1 "$(grep -c 'PAGE: DIRECT EDIT' "$root/out.txt")"
  printf 'not json' >"$STATUSJ"
  _t "a file that is not JSON is refused, never guessed at" 2 "$( ( ctl_status ) >/dev/null 2>&1; echo $?)"
  rm -f "$STATUSJ"
  _t "and no file at all is refused too"     2 "$( ( ctl_status ) >/dev/null 2>&1; echo $?)"
  rm -rf "$root"
  if [ "$fails" = 0 ]; then echo "landq-ctl selftest: GREEN (every verb, the refusals, the rendering)"; exit 0; fi
  echo "landq-ctl selftest: RED ($fails failure(s))" >&2; exit 1
fi

verb="${1:-}"; shift 2>/dev/null || true
case "$verb" in
  add)        [ -n "${1:-}" ] || ctl_die "add needs a queue line"; ctl_emit ADD "$*" ;;
  park)       ctl_sha "${1:-}"; ctl_emit PARK "$1" "${2:-by-hand}" ;;
  unpark)     ctl_sha "${1:-}"; ctl_emit UNPARK "$1" ;;
  supersede)  ctl_sha "${1:-}"; [ -n "${2:-}" ] || ctl_die "supersede needs the new line"
              s="$1"; shift; ctl_emit SUPERSEDE "$s" "$*" ;;
  retag)      ctl_sha "${1:-}"; s="$1"; shift; ctl_emit RETAG "$s" "$*" ;;
  front)      ctl_sha "${1:-}"; ctl_emit FRONT "$1" ;;
  status)     ctl_status ;;
  inbox)      [ -s "$INBOX" ] && cat "$INBOX" || echo "landq-ctl: the inbox is empty (the runner has folded everything)" ;;
  queue)      [ -f "$Q" ] && cat "$Q" || ctl_die "no queue at $Q" ;;
  ''|-h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *)          ctl_die "unknown verb [$verb] — add|park|unpark|supersede|retag|front|status|inbox|queue" ;;
esac
