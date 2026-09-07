#!/usr/bin/env bash
# scripts/release-gate/lib.sh — the shared machinery of the release gate.
#
# WHY THE GATE'S LOGIC LIVES IN SCRIPTS AND NOT INLINE IN THE WORKFLOW.
#
# verify-deploy.yml deliberately carries its checks inline and checks nothing out: its subject is
# the LIVE deployment, and reading ./install.sh from a working copy would hide a fix that merged
# and never deployed. That reasoning is about DATA — the bytes under test must come from the wire.
# It says nothing about LOGIC. The gate's logic being inline had one concrete cost: nobody could
# run a check without pushing a commit and waiting for a runner, so "dry-run every shell block
# locally against the real published artifacts" was not a thing anyone could do, and the checks
# that mattered were never exercised against a known-broken release before being trusted.
#
# So: logic in scripts (runnable on a laptop against any published version), data still from the
# wire (every URL below is the real public endpoint a user hits; nothing is read out of the
# checkout except this file and the contract).
#
# THE LEDGER, AND WHY "did not run" IS A FIRST-CLASS STATUS.
#
# Every check appends exactly one TSV row to $LEDGER:
#
#     <id> <TAB> PASS|FAIL|SKIP <TAB> <title> <TAB> <detail> <TAB> <version>
#
# and NEVER exits on failure. Aggregation happens once, in gate.sh, against the list of ids the
# contract says MUST be reported (scripts/release-gate/expected-ids.sh). That inversion is the
# whole point:
#
#   * A check cannot mask another, because no check controls control flow. This is the six-day
#     defect: verify-deploy's (g) failed on a Cloudflare 403 and (h)(i)(j)(k)(l) never executed,
#     so a `latest` image that exited 1 on `docker run` was invisible behind a healthy website.
#   * A check that never ran is DISTINGUISHABLE from one that passed, because its id is absent
#     from the ledger and gate.sh reports it as `did not run` and goes red. A step that dies in
#     its own preamble, a runner that never came up, a matrix leg that was skipped by an `if:` —
#     all of them produce silence, and silence used to read as green.
#   * ZERO ROWS IS RED. A vacuous green (bad jq, empty contract, artifact upload that produced
#     nothing) is the exact failure mode this gate exists to eliminate, so it is checked for by
#     name rather than trusted not to happen.
#
# SKIP is counted and surfaced, never folded into PASS. gate.sh red-fails on any SKIP whose id is
# not in the explicitly-allowlisted set, and even an allowlisted SKIP prints a ::warning:: and is
# named in the summary. The allowlist exists for exactly one class: an endpoint that is healthy
# for real users but structurally unreachable from a GitHub-hosted runner (getbusbar.com sits
# behind Cloudflare, which 403s Actions' datacenter IPs). "Unreachable from CI" is not "broken",
# but it is also not "verified", and the difference has to stay visible.
set -uo pipefail

# ── Ledger ──────────────────────────────────────────────────────────────────────────────────────
: "${LEDGER:=${RUNNER_TEMP:-/tmp}/release-gate-ledger.tsv}"
export LEDGER
mkdir -p "$(dirname "$LEDGER")"
[ -f "$LEDGER" ] || : > "$LEDGER"

# record <id> <PASS|FAIL|SKIP> <title> <detail>
# Tabs and newlines are stripped from the free-text fields: the ledger is TSV and a check whose
# detail contains a tab would silently corrupt every downstream column, which is precisely the
# kind of invisible degradation this file is about.
#
# THE FIFTH COLUMN IS THE VERSION THE ROW IS ABOUT, AND IT IS NOT DECORATION.
#
# Ledgers arrive at gate.sh as downloaded workflow artifacts merged into one directory by name
# pattern. Nothing in that path binds a row to the release under test: a leg that resolved a
# different version (the `resolve` fallback picks "the current latest release" when no version is
# supplied, so a re-run with a stale input, or a matrix leg that read a different resolve output,
# reports about a DIFFERENT release), or a ledger left behind in $RUNNER_TEMP by an earlier local
# run, contributed rows that gate.sh happily counted as evidence for THIS version. Every row now
# carries the version its check was invoked for, gate.sh counts only rows that name the version it
# was asked to gate, and a row that names anything else (or nothing) is reported and is RED — a
# check that verified some other release is not a check that verified this one.
record() {
  local id="$1" status="$2" title="$3" detail="${4:-}"
  # Read at CALL time, not at source time: lib.sh is sourced before each check script assigns
  # VERSION from its own argv, and the value that matters is the one the check actually ran against.
  local ver="${VERSION:-}"
  title="$(printf '%s' "$title" | tr '\t\n' '  ')"
  detail="$(printf '%s' "$detail" | tr '\t\n' '  ')"
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$status" "$title" "$detail" "$ver" >> "$LEDGER"
  case "$status" in
    PASS) printf 'PASS  %-46s %s\n' "$id" "$title" ;;
    FAIL)
      printf 'FAIL  %-46s %s\n' "$id" "$title"
      printf '      %s\n' "$detail"
      # ::error:: so the failure is an annotation on the run, not just a line in a log nobody
      # opens. gate.sh re-states every one of these in the job summary as well.
      echo "::error title=release-gate ${id}::${title} — ${detail}"
      ;;
    SKIP)
      printf 'SKIP  %-46s %s\n' "$id" "$title"
      printf '      %s\n' "$detail"
      echo "::warning title=release-gate ${id} DID NOT VERIFY::${title} — ${detail}"
      ;;
  esac
}

# ── Retries ─────────────────────────────────────────────────────────────────────────────────────
# Bounded exponential backoff, capped. Registries, CDNs and package indexes settle at their own
# pace and a release-day race is not a defect; a permanent breakage survives every attempt, so the
# retry converts flake into latency without converting breakage into green. The cap matters: an
# unbounded retry on a genuinely-broken artifact is a hung job, which reports as neither red nor
# green until the job timeout fires.
#
#   retry <attempts> <first-delay-seconds> <command...>
retry() {
  local attempts="$1" delay="$2"; shift 2
  local i=1 rc=0
  while :; do
    "$@" && return 0
    rc=$?
    [ "$i" -ge "$attempts" ] && return "$rc"
    echo "      ...attempt ${i}/${attempts} failed (rc=${rc}); retrying in ${delay}s" >&2
    sleep "$delay"
    i=$((i + 1))
    delay=$((delay * 2)); [ "$delay" -gt 60 ] && delay=60
  done
}

# ── HTTP ────────────────────────────────────────────────────────────────────────────────────────
# EVERY outbound call carries --max-time. A TCP connection that is accepted and then never answered
# does not fail, it hangs, and a hang is the one outcome that is neither red nor green.
CURL_OPTS=(--fail --silent --show-error --location --max-time 45 --retry 0)

http_code() {  # http_code <url> [extra curl args...]
  local url="$1"; shift
  curl --silent --show-error --location --max-time 45 -o /dev/null -w '%{http_code}' "$@" "$url" 2>/dev/null || echo 000
}

fetch() {  # fetch <url> -> body on stdout, non-zero on any non-2xx
  curl "${CURL_OPTS[@]}" "$1"
}

# CLOUDFLARE, NAMED RATHER THAN GUESSED AT.
# getbusbar.com is behind Cloudflare's bot protection, which serves 403 (occasionally 503) to
# GitHub Actions' datacenter address space while serving every real visitor normally. Treating that
# as a failure is what made verify-deploy's (g) cry wolf for six days; treating it as a pass would
# be worse. This function is the ONLY place that judgement is made, so it cannot drift between
# checks: 403/503/000 from a getbusbar.com host is a SKIP, and 404 or 5xx-that-is-not-503 is a real
# failure, because those are broken for everybody.
is_cloudflare_block() {  # is_cloudflare_block <http-code>
  case "$1" in 403|503|000) return 0 ;; *) return 1 ;; esac
}

# ── Contract ────────────────────────────────────────────────────────────────────────────────────
# The single source of truth for what a release owes. Read with jq so a malformed contract is a
# hard error at the first call rather than an empty loop that reports nothing and passes.
: "${CONTRACT:=.github/release-targets.json}"
export CONTRACT

contract_jq() {  # contract_jq <jq-filter>
  jq -er "$1" "$CONTRACT"
}

# The five PUBLISHED targets — the ones that become named GitHub Release assets. Targets with
# "published": false exist in the contract because they are built (the musl binaries that go into
# the container image) but they are not assets and must not be asserted as such.
published_targets() {
  contract_jq '.targets[] | select(.published == true) | .target'
}

target_field() {  # target_field <target> <field>
  jq -er --arg t "$1" --arg f "$2" \
    '.targets[] | select(.target == $t) | .[$f] // empty' "$CONTRACT"
}

# ── THE FULL CONTRACTED ASSET LIST, IN ONE PLACE, WITH THE PLACEHOLDER SPELLED AS THE DATA SPELLS IT
#
# `contract_asset_names <tag>` prints every file name Release <tag> owes: one per published target,
# plus the metadata assets. It is the owed side of `release:no-extras`, and it was being built inline
# there with a jq that CANNOT RUN:
#
#     jq -r --arg tag "$TAG" '.metadata_assets[].name | gsub("\\{TAG\\}"; $tag)' "$CONTRACT"
#
# `.metadata_assets` is an array of STRINGS ("busbar-{tag}.cdx.json"), not of objects, so `.name`
# is `Cannot index string with string "name"` — jq exits 5, prints nothing, and because the
# substitution's status is discarded into a `$( )` the owed list simply came back two names short.
# The placeholder is lowercase `{tag}` as well; release-stage.yml's `a.replace("{tag}", tag)` reads
# it correctly, and this one was matching an uppercase spelling that does not appear in the file.
#
# The two errors pointed opposite ways and neither was visible: the metadata assets were absent from
# the OWED set (so nothing owed them) and present in the OBSERVED set (so they were reported as
# "assets the contract does not account for") on every healthy release. A permanently-red row is how
# a row gets waived, and the moment that one is waived the extras check is gone with it.
#
# A jq that fails here is a hard non-zero, never a short list: an owed set that quietly shrinks is
# the vacuous-green this gate exists to eliminate.
contract_asset_names() {  # contract_asset_names <tag>
  local tag="$1" per_target metadata
  per_target="$(contract_jq '.targets[] | select(.published == true) | "busbar-\(.target).\(.archive)"')" || {
    echo "contract_asset_names: cannot read the published targets out of ${CONTRACT}" >&2; return 1; }
  metadata="$(jq -er --arg tag "$tag" '.metadata_assets[] | gsub("\\{tag\\}"; $tag)' "$CONTRACT")" || {
    echo "contract_asset_names: cannot read .metadata_assets out of ${CONTRACT}" >&2; return 1; }
  # A floor, for the same reason every other enumeration in this gate carries one: a contract that
  # collapsed to nothing must not present as "nothing is owed".
  local n
  n="$(printf '%s\n%s\n' "$per_target" "$metadata" | awk 'NF{c++} END{print c+0}')"
  # A non-numeric count is the floor's own vacuous case: `[ "" -lt 3 ]` is a shell ERROR, not false,
  # so the `if` is simply not taken and the short list is printed with a zero exit — the floor
  # defeated by the one input it was put here to catch. Anything that is not a number counts as
  # zero, which is a refusal.
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  if [ "$n" -lt 3 ]; then
    echo "contract_asset_names: only ${n} asset name(s) derived from ${CONTRACT}; the contract collapsed" >&2
    return 1
  fi
  printf '%s\n%s\n' "$per_target" "$metadata"
}
