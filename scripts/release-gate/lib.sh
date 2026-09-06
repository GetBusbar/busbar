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
#     <id> <TAB> PASS|FAIL|SKIP <TAB> <title> <TAB> <detail> <TAB> <version> <TAB> <qa-sha>
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

# ── EVERY ROW SAYS WHICH RELEASE IT IS ABOUT ────────────────────────────────────────────────────
#
# A ledger row was `<id> PASS <title> <detail>` and nothing in it named the release. The gate then
# collected every *.tsv it found under LEDGER_DIR and diffed the union against the ids owed for the
# version on its command line. Nothing checked that the rows and the version were about the same
# thing.
#
# They can easily not be. LEDGER defaults to a path under RUNNER_TEMP and the file is opened with
# `[ -f ] || : >` — it is APPENDED TO, never truncated — so a re-run on a persisted temp dir, a
# self-hosted runner, or a workflow_dispatch of the fan-out at a second version on the same
# machine leaves the previous release's rows sitting in the file. Download-artifact merges every
# ledger it is handed into one directory, so a stale artifact does the same thing across jobs. In
# every one of those cases the gate reads a full set of green rows about a release it was not
# asked about, reports "Every one of the N contracted checks for <version> ran and passed", and is
# right about the count and wrong about the subject.
#
# So each row carries the version and the qa sha it was produced against, and gate.sh refuses a
# ledger whose rows name a different release. The two together, not just the version: the version
# is the name and the sha is the commit that name was staged from, and a re-cut of the same version
# from a different commit is exactly the confusion the record exists to prevent.
#
# Resolved AT CALL TIME, not when this file is sourced. Every check script sources lib.sh on line
# one and assigns VERSION on the line after, so reading it at source time would stamp every row in
# the fan-out with the empty string — the version column would exist, always be blank, and the
# refusal below would then reject every real ledger while a stale one is just as blank.
gate_version() {
  printf '%s' "${GATE_VERSION:-${BUSBAR_GATE_VERSION:-${VERSION:-}}}"
}

# staged_qa_sha -> the commit the record was staged from, or the empty string.
staged_qa_sha() {
  if [ -n "${STAGED_SHA:-}" ]; then printf '%s' "$STAGED_SHA"; return 0; fi
  local rec; rec="$(printf '%s' "${STAGED_RECORD:-}")"
  [ -n "$rec" ] && [ -f "$rec" ] || return 0
  jq -r '.qa_sha // empty' "$rec" 2>/dev/null
}

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
  local id="$1" status="$2" title="$3" detail="${4:-}" ver sha
  title="$(printf '%s' "$title" | tr '\t\n' '  ')"
  detail="$(printf '%s' "$detail" | tr '\t\n' '  ')"
  ver="$(gate_version | tr -d '\t\n ')"
  sha="$(staged_qa_sha | tr -d '\t\n ')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$status" "$title" "$detail" "$ver" "$sha" >> "$LEDGER"
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

# ── Staged-record digests ───────────────────────────────────────────────────────────────────────
#
# Reading a recorded digest and comparing it to an observed one. WHETHER a row is owed at all is
# decided elsewhere — expected-ids.sh emits the staged-comparison ids only when a record was
# supplied, and the checks guard on the same condition — so nothing here changes what is owed. These
# are the arithmetic, extracted so gate.sh --selftest can drive THE code rather than a copy of it.
#
# Every lookup collapses "we could not look it up" into one answer: nothing on stdout and a non-zero
# status. No record path, no such file, unparseable JSON, no entry for this name, an entry whose
# digest is "" or null — the caller reports all of them the same way, because they are the same
# fact, and the empty string is trivially "we did not check". "We could not check whether these are
# the staged bytes" must never read as "they are".

# sha256_file <path> -> the lowercase hex digest on stdout; non-zero if it cannot be computed.
# Three spellings because this runs on ubuntu, macos and windows runners: `sha256sum` is coreutils,
# `shasum` is what macOS ships, and python3 is on every GitHub-hosted image as the last resort.
sha256_file() {
  local f="$1"
  [ -f "$f" ] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print tolower($1)}'
  else
    local py=python3; command -v python3 >/dev/null 2>&1 || py=python
    "$py" -c 'import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1],"rb") as fh:
    for b in iter(lambda: fh.read(1 << 20), b""):
        h.update(b)
print(h.hexdigest())' "$f"
  fi
}

# staged_record_path -> the path to the staged record, or the empty string.
# The caller passes it in; there is no default guess. A gate that fell back to "some staged.json
# somewhere on the runner" would bind the release to whatever file happened to be lying around,
# which is a worse answer than none.
staged_record_path() { printf '%s' "${STAGED_RECORD:-}"; }

# staged_asset_sha256 <asset-name> -> the sha256 the staged record binds to that asset name.
staged_asset_sha256() {
  local name="$1" rec want
  rec="$(staged_record_path)"
  [ -n "$rec" ] || return 1
  [ -f "$rec" ] || return 1
  want="$(jq -r --arg n "$name" '(.assets // [])[] | select(.name == $n) | .sha256 // empty' "$rec" 2>/dev/null)" || return 1
  # jq prints every match; a record naming one asset twice with two digests does not have AN answer
  # for it, and picking the first would be the ledger's own first-row-wins defect in another file.
  case "$(printf '%s' "$want" | awk 'NF{n++} END{print n+0}')" in
    1) ;;
    *) return 1 ;;
  esac
  want="$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  printf '%s' "$want" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s' "$want"
}

# digest_matches <observed> <expected> -> 0 only when both are real 64-hex digests AND equal.
# A named function rather than `=` because the comparison it replaces says "equal" when both sides
# are empty, and the case that proves it is one no release can stage.
# Either side may carry the `sha256:` prefix an image digest is spelled with or omit it as an asset
# digest does; what may not be forgiven is a side that is not a digest at all.
digest_matches() {
  local got="${1:-}" want="${2:-}"
  printf '%s' "$got"  | grep -Eq '^(sha256:)?[0-9a-fA-F]{64}$' || return 1
  printf '%s' "$want" | grep -Eq '^(sha256:)?[0-9a-fA-F]{64}$' || return 1
  got="$(printf '%s'  "$got"  | tr '[:upper:]' '[:lower:]')";  got="${got#sha256:}"
  want="$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')"; want="${want#sha256:}"
  [ "$got" = "$want" ]
}

# ── Version matching ────────────────────────────────────────────────────────────────────────────
#
# ANCHORED ON BOTH SIDES, IN ONE PLACE. `grep -q "1.5.2"` matches "1.5.20", so a gate looking for
# the release it just cut passes against a page, a chart or a binary advertising a DIFFERENT one —
# and it hides until the patch number rolls into two digits, i.e. until exactly the release where it
# matters. The left anchor is equally load-bearing: "21.5.4" contains "1.5.4". `.` is escaped too,
# or "1.5.2" matches "1X5Y2".
version_re() {  # version_re <version> -> an ERE matching exactly that version, anchored both sides
  printf '(^|[^0-9.])v?%s([^0-9.]|$)' "${1//./\\.}"
}

# For use immediately after a literal left context that already supplies the left boundary
# (`busbar:`, `appVersion: `, …). Only the RIGHT anchor is added; adding the left one too would
# require a character between the prefix and the version and match nothing.
version_re_after() {  # version_re_after <version>
  printf 'v?%s([^0-9.]|$)' "${1//./\\.}"
}

_digest_from() {  # _digest_from <value> -> normalised sha256:<hex>, or non-zero
  local d="${1:-}"
  d="$(printf '%s' "$d" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  case "$d" in sha256:*) ;; *) return 1 ;; esac
  printf '%s' "${d#sha256:}" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s' "$d"
}

# The env var wins over the record so a caller can hand the digest straight across from the job that
# staged it; the record is the durable form. Either way it is a RECORDED value, never one this run
# resolved for itself.
staged_image_digest() {
  if [ -n "${STAGED_IMAGE_DIGEST:-}" ]; then _digest_from "$STAGED_IMAGE_DIGEST"; return $?; fi
  local rec; rec="$(staged_record_path)"
  [ -n "$rec" ] && [ -f "$rec" ] || return 1
  _digest_from "$(jq -r '.digest // empty' "$rec" 2>/dev/null)"
}

# The armv8.0-compat arm64 image is a first-class release artifact on its own digest, so it gets its
# own recorded anchor. A record that lost it would let the compat name be checked against the
# default image, which boots everywhere EXCEPT the boards the name exists for.
staged_compat_digest() {
  if [ -n "${STAGED_COMPAT_DIGEST:-}" ]; then _digest_from "$STAGED_COMPAT_DIGEST"; return $?; fi
  local rec; rec="$(staged_record_path)"
  [ -n "$rec" ] && [ -f "$rec" ] || return 1
  _digest_from "$(jq -r '.compat_digest // empty' "$rec" 2>/dev/null)"
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
# ── RESOLVING ONE ID's VERDICT OUT OF THE LEDGER ────────────────────────────────────────────────
#
# THE FIRST ROW USED TO WIN, SO A PASS COULD SWALLOW A LATER FAIL. gate.sh read the ledger with
# `awk -F'\t' -v i="$id" '$1==i{print; exit}'` and its comment said duplicates were "flagged below";
# nothing below flagged them — the `unexpected` scan only finds ids the contract does not know
# about. Meanwhile the ledger is opened with `[ -f "$LEDGER" ] || : > "$LEDGER"`, which does not
# truncate, so a leg that reports twice (a step re-run against a persisted RUNNER_TEMP, a retry that
# records on both attempts) leaves two rows for one id. If the PASS was written first, the FAIL was
# never read and the gate went GREEN over a check that failed.
#
# A leg that reported two DIFFERENT verdicts for one id has not told us which is true; it has told
# us the ledger is untrustworthy for that id. That is CONFLICT, and gate.sh treats it as red — not
# because the worst status is necessarily right, but because "we have two answers" is not a pass.
# Where every row agrees, the id resolves to that status, so an honest retry that reports the same
# thing twice is unremarkable.
#
# Prints one of: PASS | FAIL | SKIP | CONFLICT | (empty, meaning no row at all — "did not run").
ledger_status_for() {  # ledger_status_for <ledger-file> <id>
  awk -F'\t' -v i="$2" '
    $1 == i {
      s = $2
      if (s != "PASS" && s != "SKIP") s = "FAIL"   # anything not PASS/SKIP is a failure
      if (seen && s != last) { conflict = 1 }
      last = s; seen = 1
    }
    END {
      if (!seen) exit 0
      print (conflict ? "CONFLICT" : last)
    }' "$1"
}

# ledger_foreign_rows <ledger-file> <version>
# Prints one `id=<version-the-row-names>` per row that is NOT about <version>, including rows that
# name no version at all — a row that cannot say which release it is about cannot be counted toward
# one. Empty output means every row in the file agrees it is about this release.
#
# Column 5 and not a grep over the whole line: a version string appears in plenty of titles and
# details ("expected 1.5.4, observed 1.5.40"), and a check that reads the free text would find the
# release it wants inside a row saying the opposite.
ledger_foreign_rows() {  # ledger_foreign_rows <ledger-file> <version>
  awk -F'\t' -v want="$2" '
    NF == 0 { next }
    $5 != want { printf "%s=%s ", $1, ($5 == "" ? "<no version>" : $5) }
  ' "$1"
}

# ledger_sha_disagreements <ledger-file>
# The same fact one level down: the distinct qa shas the rows name, when there is more than one.
# One version can be staged twice from two commits, and the two stagings are different releases
# wearing one name — which is the whole reason the promote consumes a record and not a version.
ledger_sha_disagreements() {  # ledger_sha_disagreements <ledger-file>
  awk -F'\t' 'NF { if ($6 != "") seen[$6] = 1 }
    END { n = 0; for (s in seen) { n++; printf "%s ", s }
          if (n < 2) printf "" }' "$1" \
  | awk '{ if (NF > 1) print; }'
}

# The rows behind an id, for the detail line when they disagree.
ledger_rows_for() {  # ledger_rows_for <ledger-file> <id>
  awk -F'\t' -v i="$2" '$1 == i { printf "%s ", $2 }' "$1"
}

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

# ── The first-party plugin probe's expectations ─────────────────────────────────────────────────
#
# AN EMPTY EXPECTATION IS NOT AN EXPECTATION, AND grep DOES NOT SAY SO.
#
# platform-checks' plugin row — the one that functionally proves #52, i.e. that the shipped binary
# accepts a REALLY-signed first-party plugin — decided its verdict with
#
#     printf '%s' "$row" | grep -qw "$WANT_SIG" && printf '%s' "$row" | grep -qw "$WANT_STATUS"
#
# and `grep -qw ""` MATCHES ANY non-empty line: the empty pattern matches at every position, and
# the word-boundary test around a zero-width match is satisfied. So if the contract's plugin_probe
# ever lost expect_signature/expect_status — a rename, a `""`, or simply jq not being installed on
# the runner, which makes every substitution above come back empty — the strongest row in the gate
# silently degrades to "the alias appeared in the output at all" and records PASS on a binary that
# refuses every signed plugin. Nothing downstream can catch that: the ledger row says PASS and
# gate.sh sees an ordinary pass.
#
# `null` counts as absent too. `jq -er` on a key that is GONE prints the four characters `null`
# and exits 1; platform-checks runs without `set -e`, so that string becomes the expectation. It
# would not match, so the row does go red — but red reading "expected signature 'null'" blames the
# artifact when the fault is the contract, and the two have different fixes.
#
# These live here, not inline, so gate.sh --selftest can drive them with no runner, no network and
# no release: the case that matters is one the OLD code called PASS.

probe_expectation_absent() {  # probe_expectation_absent <value>  -> 0 if absent
  case "${1:-}" in "" | null) return 0 ;; *) return 1 ;; esac
}

# probe_expectations_absent <alias> <want-sig> <want-status>
# Prints the space-separated names of the contract fields that are absent (empty output = all
# present). Always exits 0; the CALLER decides, so a `set -e` caller cannot be tripped by "all
# present" and so the names can be quoted verbatim into the failure detail.
probe_expectations_absent() {
  local out=""
  probe_expectation_absent "${1:-}" && out="${out}plugin_probe.alias "
  probe_expectation_absent "${2:-}" && out="${out}plugin_probe.expect_signature "
  probe_expectation_absent "${3:-}" && out="${out}plugin_probe.expect_status "
  printf '%s' "$out"
  return 0
}

# probe_row_matches <row> <want-sig> <want-status>
# 0 only when BOTH expectations are non-empty AND both appear as whole words in the row. Refuses
# (non-zero) on an absent expectation rather than matching everything.
probe_row_matches() {
  local row="${1:-}" want_sig="${2:-}" want_status="${3:-}"
  [ -n "$row" ] || return 1
  [ -n "$(probe_expectations_absent x "$want_sig" "$want_status")" ] && return 1
  printf '%s' "$row" | grep -qw -- "$want_sig" || return 1
  printf '%s' "$row" | grep -qw -- "$want_status" || return 1
  return 0
}
