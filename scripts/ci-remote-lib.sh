#!/usr/bin/env bash
# Shared transport for the two remote entry points: scripts/land.sh --remote and
# scripts/prove-remote.sh. Nothing here runs a proof; it gets a shell, a host and a tree onto a box.
#
# ── WHY SSH GOES THROUGH SSM, AND WHY THE SECURITY GROUP STILL OPENS NOTHING ────────────────────
# The obvious shape — open tcp/22 to the operator's /32 and ssh to the public IP — was built, tried
# and abandoned on evidence. Outbound 22 (and 443-as-ssh) from the operator's network never reaches
# the box: the TCP handshake "succeeds" against *any* address, including 1.2.3.4, which is a
# middlebox forging SYN-ACK and then dropping the stream, so every session died in `banner exchange`
# while sshd sat healthy on the box and logged nothing. A rule that admits an operator who cannot
# connect is an attack surface bought for nothing.
#
# So the transport is `aws ssm start-session --document-name AWS-StartSSHSession` as an ssh
# ProxyCommand: the ssh stream is tunnelled inside the SSM channel, which is ordinary HTTPS to the
# regional SSM endpoint. This is strictly better than the rule it replaces:
#   * the security group stays EGRESS-ONLY — nothing on the fleet listens to the internet;
#   * there is no operator IP to keep current, and no rule to re-add when the ISP rotates it;
#   * access is IAM, so it is revoked by removing a policy rather than by editing a CIDR, and every
#     session is recorded in CloudTrail against a named principal;
#   * the host is the INSTANCE ID, stable for the life of the box, unlike a public IP.
# The cost is one local dependency, `session-manager-plugin`; ci-runners-ssh.sh installs it.
#
# THE SSH INVOCATION IS A GENERATED WRAPPER SCRIPT, not a shell variable. `ssh`, `scp` and
# `GIT_SSH_COMMAND` each want the same options, and one of those options is a ProxyCommand
# containing quoted whitespace and `%h`/`%p` tokens. Passing that through three different quoting
# regimes is how a transport acquires a bug that only shows up on the host whose name has a dash in
# it. One executable file, three consumers, no re-quoting.
set -uo pipefail

: "${AWS_REGION:=us-east-1}"
export AWS_REGION AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-$AWS_REGION}"
export PATH="$HOME/.local/bin:$PATH"   # session-manager-plugin, installed without root

FLEET_FILE="${BUSBAR_FLEET_FILE:-$HOME/.busbar-fleet}"
FLEET_KEY="${FLEET_SSH_KEY:-$HOME/.ssh/busbar-ci-fleet}"
REMOTE_USER="${BUSBAR_REMOTE_USER:-ubuntu}"
REMOTE_BARE="${BUSBAR_REMOTE_BARE:-busbar.git}"     # relative to the remote user's home
REMOTE_WORK="${BUSBAR_REMOTE_WORK:-busbar-prove}"

# ── RAIL 14, CLOSED AT THE SOURCE: ONE CHECKOUT PER BRANCH, NOT ONE PER BOX ──────────────────────
# Rail 14 exists because two slots proved two branches on one box and both of them were
# `~/busbar-prove`: the second `git checkout -f` moved the tree out from under the first one's
# `cargo test`, and the verdict that came back was about neither branch. The standing answer has
# been "one proof per box", which on a 32-vCPU box with CARGO_BUILD_JOBS=8 leaves three quarters of
# the machine idle while a queue of two hundred and fifty landings waits for it.
#
# The tree is what races, so the tree is what is per-branch: `~/busbar-prove-<slug>`, cloned from
# the box's own bare repo (a LOCAL clone — the objects are hardlinked, so it costs no download and
# no disk), with its own CARGO_TARGET_DIR seeded once from the shared `~/busbar-prove/target`.
#
# THE SEED, MEASURED ON A FLEET BOX (2026-09-10, ext4, gp3, 2.8 GB / 4657 files of warm target/):
#     cp -al   (hardlink)     98 ms
#     cp -a    (real copy)  1 164 ms
#     rsync -a              3 756 ms
# Hardlinking is twelve times faster and it is NOT the default, because what it buys back is the
# thing this whole change exists to remove: a hardlinked seed shares inodes with the box's shared
# tree, and cargo does not always replace an artifact by rename. One second against a proof of
# forty is not a price; two proofs writing one inode is the bug. `BUSBAR_PROVE_SEED=hardlink` is
# there for an operator who has measured their own box and wants it; `none` starts cold.
# (The box has 290 GB and a warm target/ is under 3 GB, so N branches is not a disk question.)
REMOTE_WORK_SHARED="${BUSBAR_REMOTE_WORK_SHARED:-busbar-prove}"
PROVE_SEED="${BUSBAR_PROVE_SEED:-copy}"        # copy | hardlink | none
# THE PER-BOX CEILING ON CONCURRENT PROOFS. Two, not four: CARGO_BUILD_JOBS is 8 and each box also
# carries four CI runner agents, so two proofs is 16 of 32 vCPU for the proofs and the rest for the
# agents that are the fleet's day job. It is a ceiling the ALLOCATOR enforces, so the third slot
# goes to another box rather than queueing behind these two.
PROVE_PER_BOX="${BUSBAR_PROVE_PER_BOX:-2}"
SSH_WRAP="${BUSBAR_SSH_WRAPPER:-$HOME/.busbar-fleet-ssh}"

rlog() { printf '[remote %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
rdie() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

remote_wrapper() {
  cat > "$SSH_WRAP" <<WRAP
#!/bin/sh
# GENERATED by scripts/ci-remote-lib.sh. The one ssh invocation the fleet is reached by.
exec ssh -i "$FLEET_KEY" \\
  -o StrictHostKeyChecking=accept-new \\
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts_busbar_fleet" \\
  -o LogLevel=ERROR \\
  -o ServerAliveInterval=30 -o ServerAliveCountMax=6 \\
  -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-busbar-%r@%h" -o ControlPersist=10m \\
  -o ProxyCommand="aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region $AWS_REGION" \\
  "\$@"
WRAP
  chmod 0755 "$SSH_WRAP"
  command -v session-manager-plugin >/dev/null \
    || rdie "session-manager-plugin is not on PATH — run ./scripts/ci-runners-ssh.sh to install it"
}

# ── The host allocator ──────────────────────────────────────────────────────────────────────────
# The cursor is a FILE, not a shell variable, because the callers are separate processes:
# prove-remote.sh invoked from four worktrees is four `bash` invocations sharing only the filesystem.
fleet_hosts() {
  [ -f "$FLEET_FILE" ] || rdie "no $FLEET_FILE — run ./scripts/ci-runners-ssh.sh first"
  awk 'NF && $1 !~ /^#/ {print $1}' "$FLEET_FILE"
}

# READY AND LEAST LOADED, NOT BLIND ROUND-ROBIN. Measured 20:2x: the cursor handed a landing to a
# box that no longer answered (a reclaimed spot instance) and the whole queue HALTed on "push
# failed"; every box also hosts four CI runner agents, so the 1-minute load differs threefold across
# the fleet in any given minute. Each candidate, starting at the cursor, is asked with a short
# timeout whether it is prepared and what its load is; the prepared box with the lowest load wins
# and a box that does not answer is skipped, not chosen. The cursor still advances so equal loads
# spread. A named host is never second-guessed — the allocator is only consulted when nothing was named.
_fleet_tmo() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi; }

# A FILESYSTEM-SAFE NAME FOR A BRANCH, and never an empty one. `integration/plane-extraction` and
# `keep-land-engine-9` and a bare sha all have to become one directory name that cannot escape
# $HOME, cannot collide with the shared checkout, and cannot be the empty string — because
# `busbar-prove-` with nothing after it IS `busbar-prove`'s neighbour by one character and a slug
# that silently degrades to the shared tree is the race back again. rc 1 when nothing survives.
remote_branch_slug() { # $1 = branch name, ref or sha
  local sl
  sl="$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9._-' '-' | sed 's/^[-.]*//; s/[-.]*$//' | cut -c1-48)"
  [ -n "$sl" ] || return 1
  printf '%s\n' "$sl"
}
# `busbar-prove-<slug>`; the shared checkout has no slug and is never returned by this.
remote_work_dir() { # $1 = slug
  [ -n "${1:-}" ] || return 1
  printf '%s-%s\n' "$REMOTE_WORK_SHARED" "$1"
}

# THE BOX-SIDE SCRIPT THAT MAKES (OR REUSES) A PER-BRANCH CHECKOUT. A function that EMITS the text,
# so --selftest runs the real thing against a scratch $HOME instead of a paraphrase of it. Prints
# the checkout path on stdout and nothing else; every other word goes to stderr.
remote_workdir_script() {
  cat <<'WORKDIR'
set -uo pipefail
SLUG="${1:-}"; SEED="${2:-copy}"
BARE="$HOME/busbar.git"
SHARED="$HOME/busbar-prove"
[ -n "$SLUG" ] || { echo "no branch slug: refusing to fall back to the shared tree" >&2; exit 2; }
W="$HOME/busbar-prove-$SLUG"
if [ ! -d "$W/.git" ]; then
  # LOCAL clone: git hardlinks the object database, so a second branch on this box costs no
  # download and (until it writes) no disk.
  git clone -q --local "$BARE" "$W" 2>/dev/null || git clone -q "$BARE" "$W" || exit 2
  git -C "$W" remote rename origin prove 2>/dev/null || git -C "$W" remote add prove "$BARE"
  if [ -d "$SHARED/target" ] && [ ! -d "$W/target" ]; then
    case "$SEED" in
      hardlink) cp -al "$SHARED/target" "$W/target" 2>/dev/null || true ;;
      none)     : ;;
      *)        cp -a  "$SHARED/target" "$W/target" 2>/dev/null || true ;;
    esac
  fi
fi
git -C "$W" remote get-url prove >/dev/null 2>&1 || git -C "$W" remote add prove "$BARE"
git -C "$W" fetch -q prove "+refs/audit-pins/*:refs/audit-pins/*" 2>/dev/null || true
git -C "$W" config user.name  "busbar remote prove"
git -C "$W" config user.email "ci@busbar.invalid"
git -C "$W" config advice.detachedHead false
printf '%s\n' "$W"
WORKDIR
}

# HOW MANY PROOFS ARE RUNNING ON A BOX — as one shell line, because it travels as an ssh command
# line. Every proof drops its pid in `<checkout>/.proof.pid` and removes it on the way out; a pid
# whose process is gone is a crashed proof, not a running one, and is not counted. `busbar-prove*`
# covers the shared checkout and every per-branch one. THE PATTERN MUST NOT MATCH ITSELF: this is a
# glob over directories, not a pgrep, so it cannot — which is the other half of why the count is a
# file and not a process scan.
_prove_count_snippet() {
  printf '%s' 'n=0; for f in "$HOME"/busbar-prove*/.proof.pid; do [ -f "$f" ] || continue; p="$(cat "$f" 2>/dev/null)"; case "$p" in ""|*[!0-9]*) continue ;; esac; kill -0 "$p" 2>/dev/null && n=$((n+1)); done; echo "$n"'
}
fleet_pick_host() {
  local hosts n cur cursor h probe np ld best="" bestload="" bestn=""
  hosts="$(fleet_hosts)"
  n="$(printf '%s\n' "$hosts" | grep -c .)"
  [ "$n" -gt 0 ] || rdie "$FLEET_FILE names no hosts"
  cursor="${FLEET_FILE}.cursor"
  cur="$(cat "$cursor" 2>/dev/null || echo 0)"
  case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
  echo $(( (cur + 1) % n )) > "$cursor" 2>/dev/null || true
  for h in $(printf '%s\n' "$hosts" | awk -v s=$((cur % n)) 'NR>s'; printf '%s\n' "$hosts" | awk -v s=$((cur % n)) 'NR<=s'); do
    probe="$(_fleet_tmo 15 "$SSH_WRAP" "$REMOTE_USER@$h" "test -d ~/busbar.git && test -d ~/busbar-prove || exit 1; $(_prove_count_snippet); cut -d' ' -f1 /proc/loadavg" </dev/null 2>/dev/null || true)"
    # TWO LINES NOW: how many proofs are running here, then the 1-minute load. A box is skipped when
    # it is at the ceiling — that is what makes a third slot go somewhere else instead of racing.
    np="$(printf '%s\n' "$probe" | sed -n 1p)"; ld="$(printf '%s\n' "$probe" | sed -n 2p)"
    case "$np" in ''|*[!0-9]*) rlog "fleet: $h skipped (unreachable or unprepared)"; continue ;; esac
    case "$ld" in ''|*[!0-9.]*) rlog "fleet: $h skipped (unreachable or unprepared)"; continue ;; esac
    if [ "$np" -ge "$PROVE_PER_BOX" ]; then
      rlog "fleet: $h skipped ($np proof(s) running, ceiling $PROVE_PER_BOX)"; continue
    fi
    # PROOFS FIRST, THEN LOAD. An empty box beats a box with one proof on it however quiet the
    # loadavg looks, because loadavg is a one-minute average and a proof that started forty seconds
    # ago is not in it yet.
    if [ -z "$best" ] || awk -v a="$np" -v b="$bestn" -v c="$ld" -v d="$bestload" \
         'BEGIN { exit !(a + 0 < b + 0 || (a + 0 == b + 0 && c + 0 < d + 0)) }'; then
      best="$h"; bestload="$ld"; bestn="$np"
    fi
  done
  [ -n "$best" ] || rdie "no prepared, reachable box among the $n in $FLEET_FILE"
  rlog "fleet: $best chosen ($bestn proof(s) running, 1-min load $bestload)"
  printf '%s\n' "$best"
}

# N DISTINCT BOXES, LEAST LOADED FIRST, NEVER ONE OF THE EXCLUDED — for the shard fan-out, which
# hands one self-test shard to each of them while the primary runs its own. One probe pass over the
# fleet (the same probe fleet_pick_host makes), sorted by 1-minute load; a box that does not answer
# or is not prepared is skipped, not chosen; the excluded boxes (the primary, and anything the caller
# already holds) are never returned. Prints up to $1 hosts, one per line — FEWER when the fleet is
# short, and the caller decides what a short fleet means (land-remote.sh degrades to an unsharded
# landing and says so; it does not launch three shards and call it four).
fleet_pick_hosts() { # $1 = how many  $2.. = hosts to exclude
  local want="$1"; shift
  local hosts h probe np ld ex skip rows=""
  hosts="$(fleet_hosts)"
  for h in $hosts; do
    skip=0; for ex in "$@"; do [ "$h" = "$ex" ] && skip=1; done; [ "$skip" = 1 ] && continue
    # A BOX ALREADY RUNNING A LANDING IS NOT A SIBLING. The live runner's box carries its landing and
    # four CI agents; a shard on top of that slows the landing everybody is waiting on and the shard
    # alike. The probe answers BUSY when the runner's engine is in the box's process list (measured:
    # the first allocation without this handed shard 2 to the box the queue runner was landing on).
    # THE PATTERN MUST NOT MATCH ITSELF: this probe travels as a shell command line that contains it,
    # so an unbracketed pattern found its own shell on every box and the fleet "gave 0" (measured:
    # a sharded pre-proof that degraded to unsharded on an idle fleet).
    probe="$(_fleet_tmo 15 "$SSH_WRAP" "$REMOTE_USER@$h" "test -d ~/busbar.git && test -d ~/busbar-prove || exit 1; if pgrep -f '[l]and.run.local.sh' >/dev/null 2>&1; then echo BUSY; else $(_prove_count_snippet); cut -d' ' -f1 /proc/loadavg; fi" </dev/null 2>/dev/null || true)"
    case "$probe" in
      BUSY) rlog "fleet: $h skipped (a landing is running there)"; continue ;;
    esac
    np="$(printf '%s\n' "$probe" | sed -n 1p)"; ld="$(printf '%s\n' "$probe" | sed -n 2p)"
    case "$np" in ''|*[!0-9]*) rlog "fleet: $h skipped (unreachable or unprepared)"; continue ;; esac
    case "$ld" in ''|*[!0-9.]*) rlog "fleet: $h skipped (unreachable or unprepared)"; continue ;; esac
    if [ "$np" -ge "$PROVE_PER_BOX" ]; then
      rlog "fleet: $h skipped ($np proof(s) running, ceiling $PROVE_PER_BOX)"; continue
    fi
    # Sorted on the pair, so a box with a proof on it is behind every empty box.
    rows="$rows$np $ld $h
"
  done
  printf '%s' "$rows" | sort -k1,1n -k2,2n | head -n "$want" | awk '{print $3}'
}

# Push ONE NAMED COMMIT (not HEAD) into a box's bare repo under a ref of the caller's choosing. The
# fan-out needs it because the tree a shard must prove is the primary box's cherry-picked tip, which
# this repository only holds after fetching it from the primary — it is nobody's HEAD here.
remote_push_sha() { # $1 = host  $2 = local repo  $3 = ref name  $4 = sha
  local host="$1" repo="$2" ref="$3" sha="$4"
  GIT_SSH_COMMAND="$SSH_WRAP" git -C "$repo" push -q --force \
    "ssh://$REMOTE_USER@$host/~/$REMOTE_BARE" "+$sha:refs/heads/$ref"
}

# A REQUEST LINE, as the primary's land.sh writes it (`land_shard_request`): `gate=G n=N sha=S ref=R
# ceil=VAR=SECS`. Parsed into R_gate R_n R_sha R_ref R_ceil, and REFUSED — return 1 — when any field
# is missing or malformed, because a request the laptop half-understood would launch shards of the
# wrong tree or the wrong count, and the union check would then be RED for a reason nobody could name.
fanout_parse_request() { # $1 = the line
  local f
  R_gate=""; R_n=""; R_sha=""; R_ref=""; R_ceil=""
  for f in $1; do
    case "$f" in
      gate=*) R_gate="${f#gate=}" ;;
      n=*)    R_n="${f#n=}" ;;
      sha=*)  R_sha="${f#sha=}" ;;
      ref=*)  R_ref="${f#ref=}" ;;
      ceil=*) R_ceil="${f#ceil=}" ;;
      *) return 1 ;;
    esac
  done
  [ -n "$R_gate" ] && [ -n "$R_ref" ] || return 1
  case "$R_n" in ''|*[!0-9]*) return 1 ;; esac
  [ "$R_n" -ge 2 ] && [ "$R_n" -le 4 ] || return 1
  case "$R_sha" in *[!0-9a-f]*|'') return 1 ;; esac
  [ "${#R_sha}" -eq 40 ] || return 1
  case "$R_ceil" in *=*) ;; *) return 1 ;; esac
  case "${R_ceil#*=}" in ''|*[!0-9]*) return 1 ;; esac
  return 0
}

# EVERY ARGUMENT IS QUOTED FOR THE REMOTE SHELL. ssh does not exec an argv; it concatenates what it
# is given and hands the STRING to the login shell, which then re-splits and re-globs it. An oracle
# id-filter is a regex — `^(billing|ledger)([|.]|$)` — and unquoted that is a subshell, a pipeline
# and a glob before it ever reaches the proof. Observed, first run: `syntax error near unexpected
# token ('`. `printf %q` is the quoting the remote bash will undo exactly.
_rq() { local out="" a; for a in "$@"; do out="$out $(printf '%q' "$a")"; done; printf '%s' "${out# }"; }
rsh()        { local h="$1"; shift; "$SSH_WRAP" "$REMOTE_USER@$h" "$(_rq "$@")"; }
rsh_script() { local h="$1"; shift; "$SSH_WRAP" -T "$REMOTE_USER@$h" "bash -s -- $(_rq "$@")"; }
rcp_back()   { scp -q -S "$SSH_WRAP" "$REMOTE_USER@$1:$2" "$3"; }
rcp_to()     { scp -q -S "$SSH_WRAP" "$2" "$REMOTE_USER@$1:$3"; }

# ── One-time (and idempotent) preparation of a box ──────────────────────────────────────────────
# A BARE REPO AND A SEPARATE CHECKOUT, not one non-bare repo. Pushing into a non-bare repo's
# checked-out branch is refused by git for a good reason, and `receive.denyCurrentBranch=false`
# buys that refusal off by letting a push desynchronise the index from HEAD — which shows up later
# as a proof run against a tree that is not the one that was pushed. The bare repo takes the push;
# the checkout is reset to it explicitly, by the same script that then runs the proof.
remote_setup() { # $1 = host
  local host="$1"
  rlog "preparing $host: bare ~/$REMOTE_BARE + checkout ~/$REMOTE_WORK"
  rsh_script "$host" <<'SETUP'
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
BARE="$HOME/busbar.git"
WORK="$HOME/busbar-prove"
if [ ! -d "$BARE" ]; then
  # SEEDED FROM GITHUB, NOT `git init --bare`. An empty bare repo means the operator's first
  # `push HEAD` carries the ENTIRE history over the SSM tunnel: measured at many minutes of
  # nothing-happening, ending in `unexpected disconnect while reading sideband packet` — which
  # reads exactly like a hung transport and is really a cold repository. The box has a fast,
  # direct link to github.com; let it fetch its own objects, and every push after is a delta.
  git clone --bare -q https://github.com/GetBusbar/busbar.git "$BARE" || exit 1
  git -C "$BARE" config gc.auto 256
fi
# Kept current for the same reason: a bare repo a week behind makes the next push a week of objects.
# WITHOUT --prune, AND THIS IS THE WHOLE OF IT. `--prune` over `+refs/heads/*:refs/heads/*` deletes
# every ref under refs/heads that origin does not have — which is exactly the set a live landing
# owns: `land-<stamp>-<pid>`, its `-base`, and the `-landed` tip the box publishes when land.sh
# returns. The fleet refresh runs on a timer against every box, so it lands inside other people's
# runs by construction. Measured (sweep at 76f1887af, line 3, i-0b0e1585e8567d01a): a refresh at
# 14:33:12Z between the box's push and the laptop's fetch took the `-landed` ref; refs/proof/* —
# outside this refspec, and so outside the prune — survived, which is the fingerprint. The laptop
# read "no landed tip came back", scored exit 2, and a GREEN 7950 s pre-proof was parked as RED.
# Stale mirrors are the smaller cost, and they are bounded below: run refs carry a UTC stamp in
# their NAME, so a run older than a day is provably nobody's and is the only thing swept here.
git -C "$BARE" fetch -q origin "+refs/heads/*:refs/heads/*" 2>/dev/null || true
CUT="$(date -u -d '24 hours ago' +%Y%m%d-%H%M%S 2>/dev/null || date -u -v-24H +%Y%m%d-%H%M%S 2>/dev/null || true)"
if [ -n "$CUT" ]; then
  git -C "$BARE" for-each-ref --format='%(refname)' 'refs/heads/land-*' 'refs/proof/land-*' 2>/dev/null \
  | while read -r r; do
      st="$(printf '%s' "$r" | sed -n 's|.*/land-\([0-9]\{8\}-[0-9]\{6\}\).*|\1|p')"
      [ -n "$st" ] || continue
      [ "$st" \< "$CUT" ] && git -C "$BARE" update-ref -d "$r" 2>/dev/null || true
    done
fi
if [ ! -d "$WORK/.git" ]; then
  # Cloned from the bare repo (which the block above has just seeded), so the box downloads the
  # history once and the checkout is a local hardlink copy. The objects and the warm target/ are the
  # two things that make a persistent box worth having over a fresh container.
  git clone -q "$BARE" "$WORK" || exit 1
  git -C "$WORK" remote rename origin prove 2>/dev/null || git -C "$WORK" remote add prove "$BARE"
fi
git -C "$WORK" remote get-url prove >/dev/null 2>&1 || git -C "$WORK" remote add prove "$BARE"
# THE AUDIT PINS FOLLOW THE CHECKOUT, NOT ONLY THE BARE REPO (see remote_push_tree). They are pushed
# into ~/busbar.git under refs/audit-pins/<sha>, and ~/busbar-prove is CLONED from it — with git's
# default refspec, which is refs/heads/* and nothing else. So a fresh box has the pins in the bare
# repo and none in the checkout, `qa/audit-ledger.json`'s `audited_at` commits do not resolve, and
# the audit-ledger gate is RED for a reason that has nothing to do with the tree being proven
# (measured by CFG-MIGRATE on a fresh prove box; `gate --all` went green by hand after this fetch).
# It runs on every setup, not only the first: a pin minted after the clone is exactly the case.
git -C "$WORK" fetch -q prove "+refs/audit-pins/*:refs/audit-pins/*" 2>/dev/null || true
git -C "$WORK" config user.name  "busbar remote prove"
git -C "$WORK" config user.email "ci@busbar.invalid"
git -C "$WORK" config advice.detachedHead false
if [ -f "$WORK/rust-toolchain.toml" ]; then
  ch=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$WORK/rust-toolchain.toml" | head -1)
  [ -n "$ch" ] && rustup toolchain install "$ch" -c clippy -c rustfmt >/dev/null 2>&1
fi
sudo install -d -m 0777 -o ubuntu /var/cache/sccache 2>/dev/null || true
docker info >/dev/null 2>&1 || echo "WARNING: docker is not usable by $(id -un)" >&2
printf 'READY %s\n  cargo   %s\n  rustc   %s\n  sccache %s\n  docker  %s\n' \
  "$(hostname)" "$(cargo --version 2>&1)" "$(rustc --version 2>&1)" \
  "$(sccache --version 2>&1)" "$(docker --version 2>&1)"
SETUP
}

# Push the local tip (and any extra commit-ish the caller names — a batch's picks live in agent
# worktrees and are not reachable from HEAD) into the box's bare repo. Refs are namespaced by a
# per-run tag so two concurrent proofs on one box cannot overwrite each other mid-checkout.
remote_push_tree() { # $1 = host  $2 = local repo  $3 = ref name  $4.. = extra commit-ish
  local host="$1" repo="$2" ref="$3"; shift 3
  local -a specs=( "+HEAD:refs/heads/$ref" )
  local h
  for h in "$@"; do
    [ -n "$h" ] || continue
    specs+=( "+$h:refs/proof/$ref/$h" )
  done
  # THE AUDIT PINS TRAVEL TOO. qa/audit-ledger.json records the commit each audit round read
  # (`audited_at`), and the audit-ledger gate re-derives that tree with `git ls-tree`. Those commits
  # are audit worktree pins, not ancestors of the tree, so a fresh clone cannot resolve them and the
  # gate is red for a reason that has nothing to do with the landing. The integrator keeps a local
  # ref per pin under refs/audit-pins/<sha> (mirrored to origin refs/backup/audit-pins/); they ride
  # along on every push so the box can produce the same trees the laptop can.
  local pin
  for pin in $(git -C "$repo" for-each-ref --format='%(refname)' refs/audit-pins/ 2>/dev/null); do
    specs+=( "+$pin:$pin" )
  done
  rlog "pushing $(git -C "$repo" rev-parse --short HEAD) and ${#} extra object(s) to $host"
  GIT_SSH_COMMAND="$SSH_WRAP" git -C "$repo" push -q --force \
    "ssh://$REMOTE_USER@$host/~/$REMOTE_BARE" "${specs[@]}" \
    || rdie "push to $host failed — prepare the box with ./scripts/prove-remote.sh --setup $host"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest, when this file is EXECUTED rather than sourced: the allocator's choices against a
# stub fleet, and the request parser's refusals. The stub wrapper stands in for ~/.busbar-fleet-ssh
# and answers per host from a table, so "least loaded", "unprepared", "silent" and "excluded" are
# each a box in the table rather than a fact about the live fleet.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
_lib_selftest() {
  local root fails=0
  root="$(mktemp -d "${TMPDIR:-/tmp}/ci-remote-lib-selftest.XXXXXX")"
  _t() { if [ "$2" = "$3" ]; then printf '  ok   %-52s\n' "$1"; else printf '  FAIL %-52s (wanted [%s], got [%s])\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi; }
  echo "ci-remote-lib selftest: the box's bare repo is refreshed WITHOUT pruning a live run's refs"
  _t "the refresh does not prune refs/heads" 0 "$(grep -c 'fetch -q --prune origin "+refs/heads/\*:refs/heads/\*"' "${BASH_SOURCE[0]}")"
  _t "  ...it mirrors origin plainly"        1 "$(grep -c 'fetch -q origin "+refs/heads/\*:refs/heads/\*"' "${BASH_SOURCE[0]}")"
  # The age rule itself, over the names the fleet really writes: today's run stays, yesterday's goes,
  # a name with no stamp is never touched. The comparison is the one the setup script runs.
  _age() { # $1 = refname  $2 = cutoff; prints KEEP or SWEEP
    local st; st="$(printf '%s' "$1" | sed -n 's|.*/land-\([0-9]\{8\}-[0-9]\{6\}\).*|\1|p')"
    [ -n "$st" ] || { echo KEEP; return 0; }
    if [ "$st" \< "$2" ]; then echo SWEEP; else echo KEEP; fi
  }
  _t "a live run's -landed ref is kept"      KEEP  "$(_age refs/heads/land-20260910-122102-15256-landed 20260909-143312)"
  _t "  ...as is its -base"                  KEEP  "$(_age refs/heads/land-20260910-122102-15256-base 20260909-143312)"
  _t "  ...as is its proof namespace"        KEEP  "$(_age refs/proof/land-20260910-122102-15256/4b6e3e40c 20260909-143312)"
  _t "yesterday's run is swept"              SWEEP "$(_age refs/heads/land-20260908-112641-43934-landed 20260909-143312)"
  _t "a branch with no run stamp is untouched" KEEP "$(_age refs/heads/keep-land-engine-4 20260909-143312)"

  # ── THE AUDIT PINS REACH THE CHECKOUT, not only the box's bare repo ──────────────────────────
  # The command under test is EXTRACTED FROM THE SETUP SCRIPT IN THIS FILE, so the thing proven here
  # is the thing the box runs. A fixture: a bare repo carrying a pin the way remote_push_tree leaves
  # it, a clone of it the way the setup makes ~/busbar-prove, and the pin must be resolvable in the
  # CLONE afterwards — which, with git's default clone refspec, it is not until this line runs.
  echo "ci-remote-lib selftest: a pushed audit pin is in the prove checkout after setup"
  local pinfetch; pinfetch="$(grep -F 'git -C "$WORK" fetch -q prove "+refs/audit-pins/*:refs/audit-pins/*"' "${BASH_SOURCE[0]}" | head -n1)"
  _t "the setup fetches the audit pins into the checkout" 1 "$(printf '%s' "$pinfetch" | grep -c . || true)"
  local src="$root/pinsrc" bare="$root/pinbare" work="$root/pinwork"
  mkdir -p "$src"; git -C "$src" init -q; git -C "$src" config user.email pin@selftest; git -C "$src" config user.name pin
  git -C "$src" config commit.gpgsign false; mkdir -p "$root/nohooks"; git -C "$src" config core.hooksPath "$root/nohooks"
  printf 'x\n' >"$src/f.txt"; git -C "$src" add -A; git -C "$src" commit -qm base
  local pinsha; pinsha="$(git -C "$src" rev-parse HEAD)"
  printf 'y\n' >"$src/f.txt"; git -C "$src" add -A; git -C "$src" commit -qm head
  # The pin is NOT an ancestor of the tip — that is the whole shape of an audit worktree pin.
  git -C "$src" checkout -q -b pinside "$pinsha"; printf 'audit\n' >"$src/a.txt"
  git -C "$src" add -A; git -C "$src" commit -qm "audit pin"
  local pin; pin="$(git -C "$src" rev-parse HEAD)"
  git -C "$src" update-ref "refs/audit-pins/$pin" "$pin"; git -C "$src" checkout -q master 2>/dev/null || git -C "$src" checkout -q main
  git init -q --bare "$bare"
  git -C "$src" push -q --force "$bare" "+HEAD:refs/heads/master" "+refs/audit-pins/$pin:refs/audit-pins/$pin"
  git -C "$bare" symbolic-ref HEAD refs/heads/master
  _t "the pin is in the box's bare repo"     "$pin" "$(git -C "$bare" rev-parse "refs/audit-pins/$pin" 2>/dev/null)"
  git clone -q "$bare" "$work"; git -C "$work" remote rename origin prove
  _t "a plain clone of it does NOT have the pin" "" "$(git -C "$work" rev-parse -q --verify "refs/audit-pins/$pin" 2>/dev/null)"
  ( WORK="$work"; eval "$pinfetch" )
  _t "  ...and the setup line puts it there"  "$pin" "$(git -C "$work" rev-parse -q --verify "refs/audit-pins/$pin" 2>/dev/null)"
  _t "  ...so the checkout can read its tree" 1 "$(git -C "$work" ls-tree --name-only "$pin" 2>/dev/null | grep -c '^a.txt$' || true)"

  printf 'box-a\nbox-b\nbox-c\nbox-d\nbox-e\nbox-f\nbox-g\nbox-h\n# a comment\n' >"$root/fleet"
  # The stub answers `<proofs running>` then `<1-min load>`, which is what the probe now asks for:
  #   box-a  0 proofs, load 4.50      box-b  unprepared (prints nothing)
  #   box-c  0 proofs, load 1.00      box-d  hangs
  #   box-e  0 proofs, load 2.00      box-f  running a LANDING (BUSY)
  #   box-g  2 proofs, load 0.10  — AT THE CEILING: the lowest load on the list, and never chosen
  #   box-h  1 proof,  load 0.10  — under the ceiling, so allowed, but behind every empty box
  cat >"$root/ssh" <<'STUB'
#!/bin/sh
for a in "$@"; do case "$a" in ubuntu@*) h="${a#ubuntu@}" ;; esac; done
case "$h" in
  box-a) printf '0\n4.50\n' ;;
  box-b) exit 1 ;;
  box-c) printf '0\n1.00\n' ;;
  box-d) sleep 60 ;;
  box-e) printf '0\n2.00\n' ;;
  box-f) echo BUSY ;;
  box-g) printf '2\n0.10\n' ;;
  box-h) printf '1\n0.10\n' ;;
esac
STUB
  chmod +x "$root/ssh"
  FLEET_FILE="$root/fleet"; SSH_WRAP="$root/ssh"
  _fleet_tmo() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$@"; else shift; "$@"; fi; }
  echo "ci-remote-lib selftest: this file"
  _t "parses (bash -n)" 0 "$(bash -n "${BASH_SOURCE[0]}"; echo $?)"
  _t "the busy probe's pattern cannot match its own command line" 1 "$(grep -cE "pgrep -f ['\"]\[l\]and.run.local.sh['\"]" "${BASH_SOURCE[0]}")"
  _t "  ...and the self-matching form is gone" 0 "$(grep -cE 'pgrep -f "l(and)[.]run' "${BASH_SOURCE[0]}")"
  echo "ci-remote-lib selftest: the allocator (distinct, least loaded, prepared, never the excluded)"
  _t "three boxes, least loaded first"  "$(printf 'box-c\nbox-e\nbox-a')" "$(_fleet_tmo() { shift; [ "$1" = "$SSH_WRAP" ] && { case "$*" in *box-d*) return 1 ;; esac; }; "$@"; }; fleet_pick_hosts 3 2>/dev/null)"
  _t "the primary is never chosen"      "$(printf 'box-c\nbox-a')"        "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 2 box-e 2>/dev/null)"
  _t "a short fleet returns FEWER, not a repeat" "$(printf 'box-c\nbox-h')" "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 3 box-a box-e box-g 2>/dev/null)"
  _t "the silent box is skipped, and named" 1 "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 4 2>&1 >/dev/null | grep -c 'box-d skipped')"
  _t "a box running a landing is never chosen, and named" 1 "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 6 2>&1 >/dev/null | grep -c 'box-f skipped (a landing is running there)')"
  _t "  ...even at the lowest load" "$(printf 'box-c\nbox-e\nbox-a\nbox-h')" "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 6 2>/dev/null)"

  # ── THE PER-BOX PROOF CEILING: N SLOTS ON ONE BOX, AND THE (N+1)TH GOES SOMEWHERE ELSE ────────
  # Rail 14's standing answer was "one proof per box", which idles three quarters of a 32-vCPU box
  # while two hundred and fifty landings queue. The ceiling is what makes two safe and three
  # somebody else's problem — and it is counted, not guessed: box-g is the QUIETEST box on the list
  # and it is at the ceiling, so the only thing that can keep it out is the count.
  echo "ci-remote-lib selftest: the per-box proof ceiling (two prove here; the third goes elsewhere)"
  _t "a box at the ceiling is never chosen, and named" 1 \
     "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 8 2>&1 >/dev/null | grep -c 'box-g skipped (2 proof(s) running, ceiling 2)')"
  _t "  ...even though it is the quietest box on the list" 0 \
     "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 8 2>/dev/null | grep -c '^box-g$')"
  _t "a box UNDER the ceiling is still chosen" 1 \
     "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 8 2>/dev/null | grep -c '^box-h$')"
  # PROOFS BEFORE LOAD. box-h is the quietest box that is allowed (0.10) and it is still LAST,
  # because a proof that started forty seconds ago is not in a one-minute average yet.
  _t "one proof outranks a quiet loadavg"      "box-h" \
     "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 8 2>/dev/null | tail -1)"
  # RAISE THE CEILING AND box-g COMES BACK. The rule is the number, not a hard-coded two.
  _t "a raised ceiling admits it again"        1 \
     "$(PROVE_PER_BOX=3; _fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_hosts 8 2>/dev/null | grep -c '^box-g$')"
  # …and the single-host allocator obeys the same ceiling and the same order.
  rm -f "$root/fleet.cursor"
  _t "pick_host takes the quietest EMPTY box"  "box-c" \
     "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_host 2>/dev/null)"
  _t "  ...and never the box at the ceiling"   1 \
     "$(_fleet_tmo() { shift; case "$*" in *box-d*) return 1 ;; esac; "$@"; }; fleet_pick_host 2>&1 >/dev/null | grep -c 'box-g skipped (2 proof(s) running, ceiling 2)')"

  # ── THE SLUG: A BRANCH NAME THAT CANNOT BECOME THE SHARED TREE ────────────────────────────────
  echo "ci-remote-lib selftest: the per-branch checkout name"
  _t "a plain branch is its own slug"      "keep-land-engine-9" "$(remote_branch_slug keep-land-engine-9)"
  _t "a slash becomes a dash"              "integration-plane-extraction" "$(remote_branch_slug integration/plane-extraction)"
  _t "case is folded"                      "feat-abc" "$(remote_branch_slug FEAT/ABC)"
  _t "a sha is a slug too"                 "12bb3d265" "$(remote_branch_slug 12bb3d265)"
  # THE ONES THAT MUST NOT SILENTLY BECOME THE SHARED TREE.
  _t "no path can escape the home dir"     "etc-passwd" "$(remote_branch_slug ../../etc/passwd)"
  _t "an empty name is REFUSED"            1 "$(remote_branch_slug '' >/dev/null 2>&1; echo $?; )"
  _t "  ...as is one with nothing in it"   1 "$(remote_branch_slug '///' >/dev/null 2>&1; echo $?)"
  _t "the work dir is per-branch"          "busbar-prove-keep-land-engine-9" "$(remote_work_dir keep-land-engine-9)"
  _t "  ...and there is no unslugged one"  1 "$(remote_work_dir '' >/dev/null 2>&1; echo $?)"

  # ── TWO BRANCHES, ONE BOX, TWO TREES — the REAL box-side script against a scratch $HOME ───────
  # This is Rail 14's case, run rather than argued: the script under test is the text
  # remote_workdir_script emits, so a change to what the box runs is a change to what this proves.
  echo "ci-remote-lib selftest: two concurrent proves on one box get two checkouts"
  local H="$root/box"; mkdir -p "$H"
  ( export HOME="$H"
    git init -q --bare "$H/busbar.git"
    seed="$root/seedrepo"; mkdir -p "$seed"; git -C "$seed" init -q
    git -C "$seed" config user.email box@selftest; git -C "$seed" config user.name box
    git -C "$seed" config commit.gpgsign false; git -C "$seed" config core.hooksPath "$root/nohooks"
    printf 'x\n' >"$seed/f.txt"; git -C "$seed" add -A; git -C "$seed" commit -qm base
    git -C "$seed" push -q "$H/busbar.git" "+HEAD:refs/heads/master"
    git -C "$H/busbar.git" symbolic-ref HEAD refs/heads/master
    git clone -q "$H/busbar.git" "$H/busbar-prove"
    mkdir -p "$H/busbar-prove/target/debug"
    printf 'warm\n' >"$H/busbar-prove/target/debug/artifact"
    # TWO SLOTS, AT THE SAME TIME, exactly as two agent worktrees would.
    ( bash -s -- branch-a copy >"$root/wa.txt" 2>"$root/wa.err" ) < <(remote_workdir_script) &
    pa=$!
    ( bash -s -- branch-b copy >"$root/wb.txt" 2>"$root/wb.err" ) < <(remote_workdir_script) &
    wait $pa $! ) >/dev/null 2>&1
  _t "slot A got its own checkout"   "$H/busbar-prove-branch-a" "$(tail -1 "$root/wa.txt" 2>/dev/null)"
  _t "slot B got its own checkout"   "$H/busbar-prove-branch-b" "$(tail -1 "$root/wb.txt" 2>/dev/null)"
  _t "  ...and they are two trees"   2 "$(ls -d "$H"/busbar-prove-branch-* 2>/dev/null | wc -l | tr -d ' ')"
  _t "each is a git checkout of its own" 2 "$(ls -d "$H"/busbar-prove-branch-*/.git 2>/dev/null | wc -l | tr -d ' ')"
  # THE WARM target/ TRAVELLED. A per-branch checkout that starts cold is correct and useless: the
  # warm target dir is the whole reason a persistent box beats a container.
  _t "A's target was seeded from the shared one" "warm" "$(cat "$H/busbar-prove-branch-a/target/debug/artifact" 2>/dev/null)"
  _t "B's too"                                   "warm" "$(cat "$H/busbar-prove-branch-b/target/debug/artifact" 2>/dev/null)"
  # …AND SEEDED, NOT SHARED. `cp -al` is 98 ms against `cp -a`'s 1164 ms on a fleet box (2.8 GB,
  # 4657 files) and it is NOT the default, because a hardlinked seed is the same inode: a write in
  # A's tree would land in B's and in the box's shared tree, which is Rail 14 with extra steps.
  printf 'A-only\n' >"$H/busbar-prove-branch-a/target/debug/artifact" 2>/dev/null
  _t "a write in A does not reach B"             "warm" "$(cat "$H/busbar-prove-branch-b/target/debug/artifact" 2>/dev/null)"
  _t "  ...nor the box's shared tree"            "warm" "$(cat "$H/busbar-prove/target/debug/artifact" 2>/dev/null)"
  # AND THE SHARED TREE IS NEVER THE ANSWER. A slot that cannot name its branch does not quietly
  # get `~/busbar-prove` — that is the exact fallback Rail 14 is a record of.
  ( export HOME="$H"; bash -s -- "" copy >"$root/wc.txt" 2>"$root/wc.err" ) < <(remote_workdir_script)
  _t "an empty slug is refused by the box too" 2 "$?"
  _t "  ...and it says why"                    1 "$(grep -c 'refusing to fall back to the shared tree' "$root/wc.err")"

  # The probe the ceiling is counted with: a live pid counts, a dead one does not, and the glob
  # cannot match itself the way a pgrep can.
  echo "ci-remote-lib selftest: the proof count is a live pid, not a leftover file"
  ( export HOME="$H"
    echo $$ >"$H/busbar-prove-branch-a/.proof.pid"
    printf '999999\n' >"$H/busbar-prove-branch-b/.proof.pid"
    eval "$(_prove_count_snippet)" ) >"$root/cnt.txt" 2>&1
  _t "one live proof and one stale pid counts 1" "1" "$(tail -1 "$root/cnt.txt")"
  ( export HOME="$H"; rm -f "$H"/busbar-prove-branch-*/.proof.pid; eval "$(_prove_count_snippet)" ) >"$root/cnt0.txt" 2>&1
  _t "no pid files counts 0"                     "0" "$(tail -1 "$root/cnt0.txt")"
  echo "ci-remote-lib selftest: the request parser (a request half-understood is refused)"
  local sha; sha="$(printf '%040d' 7)"
  _t "a well-formed request parses"     0 "$(fanout_parse_request "gate=kind-isolation n=4 sha=$sha ref=shardreq-1 ceil=X=3600"; echo $?)"
  _t "  ...and yields its fields"       "kind-isolation 4 shardreq-1 3600" "$(fanout_parse_request "gate=kind-isolation n=4 sha=$sha ref=shardreq-1 ceil=X=3600"; echo "$R_gate $R_n $R_ref ${R_ceil#*=}")"
  _t "a short sha is refused"           1 "$(fanout_parse_request "gate=g n=4 sha=abc ref=r ceil=X=1"; echo $?)"
  _t "n above four is refused"          1 "$(fanout_parse_request "gate=g n=5 sha=$sha ref=r ceil=X=1"; echo $?)"
  _t "n of one is refused"              1 "$(fanout_parse_request "gate=g n=1 sha=$sha ref=r ceil=X=1"; echo $?)"
  _t "a missing gate is refused"        1 "$(fanout_parse_request "n=4 sha=$sha ref=r ceil=X=1"; echo $?)"
  _t "an unknown field is refused"      1 "$(fanout_parse_request "gate=g n=4 sha=$sha ref=r ceil=X=1 extra=1"; echo $?)"
  _t "a ceiling that is not seconds is refused" 1 "$(fanout_parse_request "gate=g n=4 sha=$sha ref=r ceil=X=soon"; echo $?)"
  rm -rf "$root"
  if [ "$fails" -eq 0 ]; then echo "ci-remote-lib selftest: GREEN (allocator, per-box proof ceiling, per-branch checkout, request parser)"; return 0; fi
  echo "ci-remote-lib selftest: RED ($fails failure(s))" >&2; return 1
}
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--selftest" ]; then _lib_selftest; exit $?; fi
