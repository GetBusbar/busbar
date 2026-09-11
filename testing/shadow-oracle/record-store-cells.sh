#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# testing/shadow-oracle/record-store-cells.sh — RECORD THE THREE SERVER-BACKED STORE CELLS ON ANY
# HOST WITH DOCKER, provision to teardown, in one command.
#
#   record-store-cells.sh [--out DIR] [--keep-services] [--no-merge]
#   record-store-cells.sh --selftest      # this file's own rules, no docker, no binary
#
# ── THE GAP THIS CLOSES ─────────────────────────────────────────────────────────────────────────
# `plugins.store-persist|store-{postgres,mysql,valkey}` are the only cells whose claim — mint,
# spend, KILL, boot again against the same store, read the money back — needs a real durable
# backend. The golden owes all three as PASS, so a recording host that cannot stand the servers up
# reports them `missing.candidate`, and the honest route from there is an accepted gap: the cells
# are owed and this host cannot produce them.
#
# That gap was never a property of the FLEET. Every busbar on-demand box has docker and has had the
# three pinned images in its local store for weeks; what was missing was a way to ASK. The only
# recording path that existed lived inside .github/workflows/oracle-record-store-cells.yml as
# twenty-odd inline steps, wired to GitHub's `services:` block — so it ran on a GitHub runner or it
# ran nowhere, and (measured on this tip) it had stopped running even there: four of its steps
# invoke `testing/shadow-oracle/{record,fetch-golden,fetch-plugin}.sh` and
# `testing/shadow-oracle/merge-recordings.py`, every one of which left this tree when the oracle was
# extracted into GetBusbar/busbar-oracle. The workflow's recording steps could not have succeeded.
#
# So the recording is a SCRIPT, and the workflow is one of its callers. A path an operator can run
# on a box is a path that gets run; a path that exists only as YAML is a path whose breakage is
# discovered by the person who needed it.
#
# ── WHY THE SERVICES ARE THIS SCRIPT'S, NOT THE CALLER'S ────────────────────────────────────────
# The oracle's answer is a COMPARISON. If the golden's store cells were recorded against Postgres 16
# and the candidate's against Postgres 17, the differ reports a divergence that is really a
# difference in how the two were run — the hardest kind of red to read, because everything about it
# looks like a busbar regression. The workflow used to re-state the three `image:` digests in YAML
# (GitHub cannot read a file into a `services:` block) and a lint, scripts/service-images-check.sh,
# made the duplication safe. A duplication made safe by a lint is still a duplication: this script
# provisions through testing/fleet-fixtures/store-services.sh, which reads
# testing/fleet-fixtures/service-images.tsv — the SAME table ci.yml's shadow-oracle job records the
# candidate side against — so there is nothing to re-state and nothing to drift.
#
# ── ADOPTION IS REFUSED, ON PURPOSE ─────────────────────────────────────────────────────────────
# An earlier shape honoured pre-set BUSBAR_TEST_POSTGRES_URL / BUSBAR_TEST_MYSQL_URL / VALKEY_URL
# and provisioned only when they were absent, so one driver could serve a runner with `services:`
# and a bare box alike. That is the failure this file exists to prevent, wearing a helpful hat: a
# caller's URL can point at ANY postgres, and the recording would then claim the pinned digest's
# name while carrying another server's behaviour. The vars are EXPORTED by this script and an
# inherited one is refused by name. There is exactly one provisioner.
#
# ── WHAT IT DOES NOT DO ─────────────────────────────────────────────────────────────────────────
# It does not write the golden. Accepting a recording into the reference is a review:
# testing/shadow-oracle/import-store-cells.sh is that step, it prints a diff, and it does not
# commit. This script records, checks, merges into a scratch part, and stops.
#
# It does not publish `raw/`. That tree is the PRE-NORMALISATION forensic view: each cell's working
# directory with its generated signing key and admin token, and the key-mint response whose `.token`
# is a live virtual key. `cells/` is post-normalisation and safe by construction. A caller that
# uploads the output must upload the part this script names, never the recording directory whole —
# and --no-merge exists for a caller that wants only the part.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/.." && pwd)"
repo="$(cd "${repo}/.." && pwd)"
services="${repo}/testing/fleet-fixtures/store-services.sh"
oracle="${repo}/bin/oracle"

# THE THREE IDS, WRITTEN ONCE. The --filter, the PASS check and the merged-count assertion all read
# this, so a fourth id cannot enter through one of them while the other two go on describing three.
STORE_CELL_IDS='plugins.store-persist|store-postgres plugins.store-persist|store-mysql plugins.store-persist|store-valkey'

# The fixture variable each cell is gated on, in the same order. `enumerate-cells.py` gates the cell
# on exactly this map and testing/shadow-oracle/scripts/store-persist.sh reads the same names, so a
# cell that ran cannot have been pointed at a backend other than the one it names.
STORE_FIXTURE_VARS='BUSBAR_TEST_POSTGRES_URL BUSBAR_TEST_MYSQL_URL VALKEY_URL'

say()  { printf '%s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }
die()  { printf 'record-store-cells: %s\n' "$*" >&2; exit 1; }

OUT=""; KEEP=0; MERGE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --keep-services) KEEP=1; shift ;;
    --no-merge) MERGE=0; shift ;;
    --selftest) shift; set -- --selftest "$@"; break ;;
    -h|--help) sed -n '5,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument '$1'" ;;
  esac
done

# ── --selftest ──────────────────────────────────────────────────────────────────────────────────
# NO DOCKER, NO BINARY, NO NETWORK. Every row below is a way this driver could go quietly wrong and
# still exit 0. Decided through the same ledger-and-verdict inversion every gate in this tree uses
# (testing/fleet-fixtures/lib.sh + verdict.sh): every check records exactly one row and NOTHING
# controls flow, so no check can mask another, an owed row that never appeared is DID NOT RUN, and
# ZERO ROWS IS RED.
if [ "${1:-}" = "--selftest" ]; then
  work="${repo}/.qa-work/record-store-cells-selftest"
  rm -rf "$work"; mkdir -p "$work"
  export LEDGER="${work}/ledger.tsv"; : >"$LEDGER"
  export GATE_NAME="store-cell recording driver"
  # shellcheck source=../fleet-fixtures/lib.sh
  source "${repo}/testing/fleet-fixtures/lib.sh"
  owed=""; owe() { owed="${owed} $1"; }

  # 1. The three ids this driver records are exactly the three cells.json declares need a backend.
  #    A driver that recorded a set the cell registry does not agree with would produce an artifact
  #    import-store-cells.sh refuses — after the twenty minutes, not before them.
  declared="$(python3 - "$repo" <<'PY'
import json, os, sys
cells = json.load(open(os.path.join(sys.argv[1], "testing/shadow-oracle/cells.json"), encoding="utf-8"))
ids = sorted(c["id"] for c in cells["cells"]
             if c["id"].startswith("plugins.store-persist|") and c.get("needs_fixture"))
print(" ".join(ids))
PY
)"
  want="$(printf '%s\n' $STORE_CELL_IDS | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
  got="$(printf '%s\n' $declared | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
  owe "record-store|ids-match-the-registry"
  if [ "$want" = "$got" ]; then
    record "record-store|ids-match-the-registry" PASS "the driver's three ids are the fixture-gated store cells cells.json declares" "$got"
  else
    record "record-store|ids-match-the-registry" FAIL "the driver records a set cells.json does not declare" "driver: ${want} | cells.json: ${got}"
  fi

  # 2. The fixture var for each id is the one store-persist.sh reads. The recorder gates the cell on
  #    the var; the driver EXPORTS it. Two lists that drifted apart would leave a cell gated on a
  #    var nothing sets — recorded as a named gap, inside a run whose whole purpose is to close it.
  drv="${repo}/testing/shadow-oracle/scripts/store-persist.sh"
  missing_var=""
  for v in $STORE_FIXTURE_VARS; do grep -q "$v" "$drv" || missing_var="${missing_var}${v} "; done
  owe "record-store|fixture-vars-are-the-drivers"
  if [ -z "$missing_var" ]; then
    record "record-store|fixture-vars-are-the-drivers" PASS "every fixture var this driver exports is read by store-persist.sh" "$STORE_FIXTURE_VARS"
  else
    record "record-store|fixture-vars-are-the-drivers" FAIL "a fixture var this driver exports is not read by store-persist.sh" "orphaned: ${missing_var}"
  fi

  # 3. RED-PROOF: an INHERITED fixture var is refused, not adopted. This is the rule the header
  #    argues for at length, and the one a future "be helpful when it's already set" edit removes.
  owe "record-store|inherited-url-refused"
  inherited_out="$(BUSBAR_TEST_POSTGRES_URL='postgres://somewhere/else' "$0" --out "$work/never" 2>&1)"
  inherited_rc=$?
  if [ "$inherited_rc" != 0 ] && printf '%s' "$inherited_out" | grep -q 'BUSBAR_TEST_POSTGRES_URL'; then
    record "record-store|inherited-url-refused" PASS "an inherited fixture URL is refused by name" \
      "$(printf '%s' "$inherited_out" | tr '\n' ' ' | cut -c1-160)"
  else
    record "record-store|inherited-url-refused" FAIL "an inherited fixture URL was ACCEPTED" \
      "a caller's URL can point at any server; the recording would carry the pinned digest's name and another server's behaviour (rc=${inherited_rc})"
  fi

  # 4. The provisioner this driver calls is the one that reads the pinned table, and its own rules
  #    hold. Running store-services.sh's self-test HERE means a table drift or a port-band collision
  #    is a red on the recording driver too, rather than a surprise twenty minutes in.
  owe "record-store|provisioner-selftest"
  if ss_out="$(bash "$services" --selftest 2>&1)"; then
    record "record-store|provisioner-selftest" PASS "store-services.sh --selftest is green" "$(printf '%s' "$ss_out" | tail -1)"
  else
    record "record-store|provisioner-selftest" FAIL "store-services.sh --selftest is red" "$(printf '%s' "$ss_out" | tr '\n' ' ' | cut -c1-200)"
  fi

  # 5. The oracle shim is present and the golden this driver records FOR is the one on disk. A
  #    driver pointed at a version the tree has no golden for records an artifact nothing can be
  #    merged into.
  owe "record-store|golden-version-present"
  gv="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' \
         "${repo}/testing/shadow-oracle/golden/1.5.5/meta.json" 2>/dev/null)"
  if [ -x "$oracle" ] && [ "$gv" = "busbar 1.5.5" ]; then
    record "record-store|golden-version-present" PASS "bin/oracle is present and the committed golden is ${gv}" ""
  else
    record "record-store|golden-version-present" FAIL "no bin/oracle, or the committed golden is not the version this driver records" "golden says: ${gv:-<unreadable>}"
  fi

  GATE_NAME="store-cell recording driver" EXPECTED_IDS="$owed" LEDGER="$LEDGER" \
    bash "${repo}/testing/fleet-fixtures/verdict.sh"
  exit $?
fi

# ── preconditions ───────────────────────────────────────────────────────────────────────────────
[ -x "$oracle" ] || die "${repo} is not a busbar checkout (no bin/oracle)"
[ -x "$services" ] || die "no ${services}"
# AN INHERITED FIXTURE URL IS REFUSED BY NAME. See the header: adopting one lets the recording claim
# the pinned digest's name while carrying some other server's behaviour, and nothing downstream can
# tell. The check is before anything expensive, and it names the variable rather than the rule.
for v in $STORE_FIXTURE_VARS; do
  [ -z "${!v:-}" ] || die "${v} is already set in this environment. This driver PROVISIONS the
backends itself, from the digests testing/fleet-fixtures/service-images.tsv pins, and exports the
three URLs; adopting an inherited one would record the pinned image's name against a server nobody
pinned. Unset ${v} and re-run."
done

command -v docker >/dev/null 2>&1 \
  || die "docker is not on PATH. There is no way to prove a store persists across a process death
without a server to persist into, and this driver will not record the three cells against anything
else. On a host without a container runtime the three cells stay a NAMED GAP (SKIP), never a pass."

OUT="${OUT:-${repo}/target/oracle/store-cells}"
mkdir -p "$OUT" || die "cannot create ${OUT}"
OUT="$(cd "$OUT" && pwd)"
part="${OUT}/part"

# TEARDOWN IS A TRAP, NOT A LAST LINE. A recording that dies in the middle of a cell leaves three
# containers holding three host ports, and the next run's readiness probe then answers from the
# PREVIOUS run's database — which is a persistence verdict from a store nobody wrote to. `--rm` plus
# `down all`'s third sweep layer means this is removable even if the trap itself never fires.
provisioned=0
teardown() {
  [ "$provisioned" = 1 ] || return 0
  if [ "$KEEP" = 1 ]; then say "  --keep-services: the three backends are still up (store-services.sh down all)"; return 0; fi
  head_ "teardown"
  bash "$services" down all
}
trap teardown EXIT

head_ "the pinned service table"
bash "$services" status

# THE KERNEL'S EPHEMERAL POOL IS NOT THE RECORDER'S TO RACE. The oracle binds a fixed 487xx/488xx
# band that sits inside Linux's default ephemeral range, so an outbound socket can be handed the port
# the next busbar is about to bind — a flake that reads as "boot 2 never came up", i.e. as a
# persistence failure. Applied and READ BACK: a silently-failed sysctl leaves the flake in place
# under a step that printed nothing. Best-effort by design — a host where this cannot be set still
# records; it just records with the race, and says so.
if [ "$(uname -s)" = Linux ]; then
  if sudo sysctl -w net.ipv4.ip_local_reserved_ports=48700-48900 >/dev/null 2>&1 \
     && sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null | grep -q '48700-48900'; then
    say "  oracle port band 48700-48900 reserved from the kernel's ephemeral pool"
  else
    say "  NOTE: could not reserve 48700-48900 from the kernel's ephemeral pool (no sudo?) — an"
    say "        outbound socket may race a recorder bind. A boot that 'never came up' on this run"
    say "        is that race before it is a product finding."
  fi
fi

head_ "provision (pinned digests, readiness proven, torn down on exit)"
bash "$services" up all || die "the backends did not come up; nothing was recorded"
provisioned=1

# EXPORTED HERE AND NOWHERE ELSE. `url` prints the DSN on stdout and logs nothing, which is why it
# can be read by command substitution at all.
export BUSBAR_TEST_POSTGRES_URL="$(bash "$services" url postgres)"
export BUSBAR_TEST_MYSQL_URL="$(bash "$services" url mysql)"
export VALKEY_URL="$(bash "$services" url valkey)"
for v in $STORE_FIXTURE_VARS; do
  [ -n "${!v:-}" ] || die "store-services.sh printed no DSN for ${v}"
done

# ── the backend versions go in the note, not just in the log ────────────────────────────────────
# A store cell's recorded bytes can carry a backend's own error text or its wire behaviour, so
# "which Postgres" is part of what the recording MEANS. The digest pins the image; this records what
# that image says it IS, read with each image's own client INSIDE the container — no client on the
# host, nothing to install, and no unpinned apt fetch on the path of a recording whose whole point
# is that everything it touches is pinned.
head_ "the backends this recording is made against"
dex() { docker exec "busbar-store-qa-$1${BUSBAR_STORE_QA_TAG:+-${BUSBAR_STORE_QA_TAG}}" "${@:2}"; }
PG_V="$(dex postgres psql -U busbar -d busbar_store_qa -tAc 'select version()' 2>/dev/null | head -1)"
MY_V="$(dex mysql mysql -ubusbar -pbusbar -N -B -e 'select version()' 2>/dev/null | head -1)"
VK_V="$(dex valkey valkey-cli INFO server 2>/dev/null \
        | tr -d '\r' | grep -E '^(valkey_version|redis_version|server_name):' \
        | sed 's/:/=/' | tr '\n' ' ' | sed 's/ $//')"
for pair in "postgres:${PG_V}" "mysql:${MY_V}" "valkey:${VK_V}"; do
  case "$pair" in
    *:) die "${pair%%:*} did not answer a version query. A recording that cannot say what it was
made against is a recording nobody can read a divergence out of." ;;
  esac
  say "  ${pair%%:*}  ${pair#*:}"
done

head_ "the published binary and the published plugins, by digest"
# fetch-golden.sh re-hashes what is on disk against golden-digests.tsv on EVERY invocation — a cache
# hit is VERIFIED, not trusted — and deletes a mismatched download rather than recording from it.
"$oracle" fetch-golden || die "could not fetch the published golden binary"
"$oracle" fetch-golden --check || die "the fetched golden binary does not hash to its pinned row"
# DERIVED from the same digest file the cells read. A hand-kept plugin list goes stale the day a
# plugin is added, and the symptom is a store cell recording against a plugin that was never fetched.
plugins="$(grep -v '^#' "${repo}/testing/shadow-oracle/plugin-digests.tsv" | cut -f1 | sort -u)"
[ -n "$plugins" ] || die "no plugins derived from plugin-digests.tsv"
for pl in $plugins; do "$oracle" fetch-plugin "$pl" >/dev/null || die "could not fetch plugin ${pl}"; done
say "  $(printf '%s\n' $plugins | wc -l | tr -d ' ') plugin tarball(s) verified against plugin-digests.tsv"
BIN="${BUSBAR_ORACLE_CACHE:-$HOME/.cache/busbar-oracle}/1.5.5/busbar"
[ -x "$BIN" ] || die "fetch-golden left no executable at ${BIN}"

head_ "record exactly the three"
# The ids carry `|` and `.`, both regex metacharacters, and one of them IS the field separator of
# every cell id in the tree. Escaped by re.escape and anchored per id, so the filter selects these
# three exactly and cannot widen into a prefix match.
re="$(STORE_CELL_IDS="$STORE_CELL_IDS" python3 -c \
  'import os,re; print("|".join("(^%s$)" % re.escape(i) for i in os.environ["STORE_CELL_IDS"].split()))')"
say "  filter: ${re}"
# A FILTERED RUN IS THE RIGHT SHAPE HERE, WHERE IT IS NOT FOR MOST CELLS. The golden's own note
# explains why a cell whose answer depends on state earlier cells left (the governance store, the
# metrics buckets) must come out of a FULL run. These three do not have that property: each is a
# script cell that boots its own busbar against its own fresh backend schema, spends, restarts and
# reads back, and the recorder gives every cell its own working tree. Their bytes are a function of
# the binary and the backend, not of what ran before them. Proven, not assumed: recorded this way on
# an on-demand fleet box, all three came out byte-identical to the committed golden's copies.
rm -rf "$part"; mkdir -p "$part"
"$oracle" record --bin "$BIN" --plane all --filter "$re" --out "$part" || die "the recorder exited non-zero"

head_ "three rows, all PASS, and no fourth"
led="${part}/ledger.tsv"
# ZERO ROWS IS RED ON ITS OWN TERMS: a recorder that ran and produced nothing must not read as three
# green cells that happened not to be written down.
[ -s "$led" ] || die "the recorder produced no ledger; nothing was recorded"
rows="$(awk -F'\t' 'NF' "$led" | wc -l | tr -d ' ')"
[ "$rows" = 3 ] || { awk -F'\t' 'NF{print "  "$1"\t"$2}' "$led" >&2; die "expected exactly 3 ledger rows, got ${rows} — the filter widened"; }
bad=0
for id in $STORE_CELL_IDS; do
  verdict="$(awk -F'\t' -v i="$id" '$1==i{print $2; exit}' "$led")"
  case "$verdict" in
    PASS) say "  PASS  $id" ;;
    # A SKIP here means the fixture gate did not see the backend this script just stood up and
    # proved ready — publishing that would offer a "recording" that re-states the gap it exists to
    # close.
    "")   printf 'record-store-cells: %s has no ledger row; the filter did not reach it\n' "$id" >&2; bad=1 ;;
    *)    printf 'record-store-cells: %s recorded %s, not PASS: %s\n' "$id" "$verdict" \
            "$(awk -F'\t' -v i="$id" '$1==i{print $3; exit}' "$led")" >&2; bad=1 ;;
  esac
done
[ "$bad" = 0 ] || die "a cell did not record PASS. A recording that did not pass is a finding to
read, not a golden to import: the cells it would install are what the product did on a bad run, and
every later replay would be measured against that."

if [ "$MERGE" = 1 ]; then
  head_ "merge into a scratch recording"
  # MERGED HERE, INTO SCRATCH, SO THE OPERATOR'S MERGE IS NOT THE FIRST ONE EVER ATTEMPTED. This
  # normalises the part into the exact layout import-store-cells.sh feeds to the golden and re-runs
  # the merger's provenance rules. A part that cannot merge with itself cannot merge with the golden
  # either, and finding that out here costs one step instead of one round trip.
  rm -rf "${OUT}/merged"
  "$oracle" merge --out "${OUT}/merged" "$part" || die "the part does not merge with itself"
  python3 - "${OUT}/merged/meta.json" <<'PY' || die "the merged recording is not three cells"
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
if m.get("recorded") != 3:
    sys.exit(f"the merged recording says recorded={m.get('recorded')}, not 3")
print(f"  merged: {m['version']}  {m['binary_sha256'][:12]}  {m['host_triple']}  harness {m['harness_rev'][:12]}")
PY
fi

head_ "provenance"
# Written INSIDE the recording the import consumes, not beside it, because the operator who reads the
# diff weeks from now is not the process that made it and will not have the directory this ran in.
# `cells/`, the ledger, the meta and this file are the normalised view; see the header on why `raw/`
# is never published.
notes_dir="$part"; [ "$MERGE" = 1 ] && notes_dir="${OUT}/merged"
cat >"${notes_dir}/merge-notes.md" <<NOTE
# store-cell recording

The three \`plugins.store-persist|*\` cells that need a live backend, recorded from the PUBLISHED
1.5.5 binary against the digest-pinned images \`testing/fleet-fixtures/service-images.tsv\` pins —
the same images every CI candidate records against, which is what makes the two sides comparable.

Recorded by \`testing/shadow-oracle/record-store-cells.sh\` on $(uname -s)/$(uname -m), host
$(hostname), at $(date -u +%Y-%m-%dT%H:%M:%SZ).

## Backends

$(bash "$services" status | sed 's/^/    /')

    postgres  ${PG_V}
    mysql     ${MY_V}
    valkey    ${VK_V}

## Verdicts

$(awk -F'\t' 'NF{printf "  - `%s` — **%s** — %s\n", $1, $2, $3}' "$led")

## What an operator does with this

    testing/shadow-oracle/import-store-cells.sh ${notes_dir}

It merges the three cells into \`testing/shadow-oracle/golden/1.5.5\`, re-stamps the provenance, and
prints the diff. It does not commit: accepting a golden is a review.

## What is deliberately NOT here

\`raw/\` is the PRE-NORMALISATION forensic tree — bodies as they came off the wire, each cell's
working directory with its generated signing key and admin token, and the key-mint responses whose
\`.token\` is a live virtual key. \`cells/\` is the post-normalisation view and is safe by
construction. The golden checks neither \`raw/\` nor this file, so an import needs only \`${notes_dir}\`.
NOTE
say "  ${notes_dir}/merge-notes.md"

head_ "done"
say "  part:   ${part}"
[ "$MERGE" = 1 ] && say "  merged: ${OUT}/merged"
say "  import: testing/shadow-oracle/import-store-cells.sh ${notes_dir}"
exit 0
