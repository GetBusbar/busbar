#!/usr/bin/env bash
# scripts/release-gate/expected-ids.sh — the list of check ids that MUST appear in the ledger.
#
# THIS FILE IS WHAT MAKES "did not run" A DETECTABLE STATE.
#
# A check that fails writes FAIL. A check that never executes writes nothing, and nothing is
# indistinguishable from "there was never a check here" unless something independent knows the
# check was owed. That is this list. gate.sh diffs it against what actually got reported and
# treats every missing id as `did not run` — RED, in its own column, distinct from PASS.
#
# It is DERIVED, never typed: the per-target ids come from .github/release-targets.json, so a
# sixth platform added to the contract automatically owes six more rows and the gate goes red
# until they are reported. A hand-maintained list would drift the moment a target was added, and
# would drift SILENTLY toward green — the failure direction that matters.
#
# Usage: scripts/release-gate/expected-ids.sh            # one id per line
#        scripts/release-gate/expected-ids.sh --describe # id <TAB> what it asserts
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

DESCRIBE=0
[ "${1:-}" = "--describe" ] && DESCRIBE=1

EMITTED=0
emit() {  # emit <id> <description>
  EMITTED=$((EMITTED + 1))
  if [ "$DESCRIBE" = 1 ]; then printf '%s\t%s\n' "$1" "$2"; else printf '%s\n' "$1"; fi
}

# ── THE FLOORS, AND WHY THIS FILE HAS THEM AT ALL ───────────────────────────────────────────────
#
# This list is what makes "did not run" detectable, so a list that comes back SHORT is the one
# failure this file cannot survive: gate.sh diffs the ledger against whatever we print, and an id
# we never printed is an id nobody is owed. Print nothing and the gate has nothing to miss.
#
# The original loop was `done < <(published_targets)`. A process substitution's exit status is not
# the loop's and is not seen by `set -e`, so a jq that failed for ANY reason — contract absent,
# malformed after an edit, `.targets[]` renamed, jq not installed — produced an empty stream, the
# loop body never ran, all 36 per-target ids vanished, and the script exited 0 with a
# perfectly-formatted 24-line answer. gate.sh (`if ! expected-ids.sh --describe`) checks only the
# exit code, so it accepted it, and every per-target check that DID report landed in `unexpected`
# (a ::warning::, not a failure) while every one that did NOT report was owed by nobody. Silent,
# green, and in the direction that matters.
#
# So: capture first and check the status explicitly, then refuse a list that is implausibly short.
# The floors are deliberately BELOW today's numbers (6 published targets, 60 ids) — they are a
# tripwire against collapse, not a second copy of the contract, and a target legitimately retired
# must not have to edit this file. Collapse to zero, or to a fraction, is what they catch.
: "${EXPECTED_IDS_TARGET_FLOOR:=5}"   # the five platforms the contract's own comment names
: "${EXPECTED_IDS_TOTAL_FLOOR:=50}"   # 6 per-target rows x 5 + the release/docker/channel rows

# ── Per-target (the matrix legs) ────────────────────────────────────────────────────────────────
# Six rows per published target, each on a NATIVE runner for that target. They are separate ids
# rather than one composite "the artifact is fine" because a composite hides which property broke,
# and because #52 broke exactly one of the six (pubkey/plugin) while the other four were perfect.

# THE TARGET LIST IS READ ONCE, AND A READ THAT FAILED IS NOT AN EMPTY LIST.
#
# `published_targets` shells out to jq. Inside a process substitution its failure is invisible: the
# exit status is not the loop's and `set -e` never sees it, so a jq that failed for ANY reason —
# contract absent, malformed after an edit, `.targets[]` renamed, jq not installed — produces an
# empty stream, the loop body never runs, every per-target id vanishes, and this script exits 0 with
# a perfectly-formatted short answer. gate.sh checks only the exit code, so it accepts it; every
# per-target check that DID report lands in `unexpected` (a warning), and every one that did NOT is
# owed by nobody. Silent, green, and in the direction that matters.
#
# So the list is captured first and a non-zero exit is fatal here, where it can still be said out
# loud, rather than inferred later from a list nobody can tell is incomplete. This decides nothing
# about WHICH ids are owed — the staged-record condition below is untouched — only that the answer
# is derived from a read that actually succeeded.
if ! TARGETS="$(published_targets)"; then
  echo "::error title=release gate::expected-ids: could not read the published targets out of ${CONTRACT} (jq exited non-zero). The per-target ids cannot be derived, so the list this script would print is SHORT and every 'did not run' verdict derived from it would be vacuous. Refusing to print a partial contract. Fix: check ${CONTRACT} parses as JSON and carries .targets[] with published==true entries, and that jq is installed." >&2
  exit 1
fi

# THE STAGED-COMPARISON IDS ARE OWED EXACTLY WHEN A RECORD WAS SUPPLIED, AND THAT IS NOT A LOOPHOLE.
#
# `sha256:<target>`, `docker:staged-digest` and `docker:staged-armv8-digest` diff the PUBLISHED
# artifacts against the record release-stage.yml wrote on qa. That record is a workflow artifact
# with a 90-day retention, so for a release older than that — or one that predates the design —
# there is nothing to diff against and demanding the rows would make the required `release gate`
# status permanently red for a reason that is not about the release. It would also be a lie in the
# other direction to let the ids quietly vanish: release-fleet.yml's `resolve` prints a ::warning::
# naming these exact ids when it cannot resolve a record, and makes it FATAL on a `release:
# published` run, which is the only trigger where the record must exist. So the ids are owed when
# they can be met, their absence is announced rather than inferred, and the one path where absence
# would matter cannot take it.
STAGED_RECORD="${STAGED_RECORD:-}"

if ! TARGETS="$(published_targets)"; then
  echo "::error title=release gate::expected-ids: could not read the published targets out of ${CONTRACT} (jq exited non-zero). The per-target ids cannot be derived, so the list this script would print is SHORT and every 'did not run' verdict derived from it would be vacuous. Refusing to print a partial contract. Fix: check ${CONTRACT} parses as JSON and carries .targets[] with published==true entries, and that jq is installed." >&2
  exit 1
fi

n_targets=0
while read -r t; do
  [ -n "$t" ] || continue
  n_targets=$((n_targets + 1))
  emit "asset:${t}"   "the named release asset exists, is plausibly sized and is really downloadable"
  [ -z "$STAGED_RECORD" ] || \
  emit "sha256:${t}"  "the published asset's sha256 IS the one qa recorded for the staged bytes"
  emit "extract:${t}" "the archive extracts to the declared executable"
  emit "version:${t}" "the shipped binary answers --version with the tagged version"
  emit "binfmt:${t}"  "the shipped binary is the declared architecture and object format"
  emit "pubkey:${t}"  "the shipped binary embeds the release public key (#52)"
  emit "plugin:${t}"  "a REAL signed first-party plugin loads as first-party/ready (#52, functionally)"
done <<< "$TARGETS"

if [ "$n_targets" -lt "$EXPECTED_IDS_TARGET_FLOOR" ]; then
  echo "::error title=release gate::expected-ids: only ${n_targets} published target(s) came out of ${CONTRACT}; the floor is ${EXPECTED_IDS_TARGET_FLOOR}. Either the contract lost platforms (a release that ships fewer platforms than it claims is the v1.5.3 defect) or the query stopped matching. Refusing to print a list that would leave those platforms owed by nobody." >&2
  exit 1
fi

# ── Release-level ───────────────────────────────────────────────────────────────────────────────
emit "release:exists"         "the GitHub Release for the tag exists and is not a draft"
emit "release:latest-pointer" "github.com/.../releases/latest redirects to this tag"
emit "release:no-extras"      "the release publishes the contracted assets and nothing unaccounted for"
emit "meta:cyclonedx"         "the CycloneDX SBOM asset is present, sized, downloadable and parses"
emit "meta:openapi"           "the OpenAPI 3.1 asset is present, sized, downloadable and parses"
emit "attest:provenance"      "the documented gh attestation verify passes on the real published bytes"

# ── Docker ──────────────────────────────────────────────────────────────────────────────────────
emit "docker:hub-version"     "registry-1.docker.io resolves getbusbar/busbar:<version>"
emit "docker:hub-latest"      "docker.io :latest is the SAME digest as :<version>"
emit "docker:ghcr-version"    "ghcr.io :<version> is the SAME digest as Docker Hub's"
emit "docker:ghcr-latest"     "ghcr.io :latest is the SAME digest as :<version>"
emit "docker:hub-armv8-pin"      "docker.io :<version>-armv8.0 (the armv8.0-compat arm64 image) resolves, own digest"
emit "docker:hub-armv8-floating" "docker.io :armv8.0 is the SAME digest as :<version>-armv8.0"
emit "docker:ghcr-armv8-pin"     "ghcr.io :<version>-armv8.0 is the SAME digest as Docker Hub's"
emit "docker:ghcr-armv8-floating" "ghcr.io :armv8.0 is the SAME digest as :<version>-armv8.0"
[ -z "$STAGED_RECORD" ] || \
emit "docker:staged-digest"   "docker.io :<version> is the DIGEST qa staged and the promote retagged"
[ -z "$STAGED_RECORD" ] || \
emit "docker:staged-armv8-digest" "docker.io :<version>-armv8.0 is the compat DIGEST qa staged"
emit "docker:label"           "the pulled image's org.opencontainers.image.version label matches"
emit "docker:boot-bare"       "the bare documented docker run boots (by digest) and answers ok on /healthz"
emit "docker:boot-ro-mount"   "the documented read-only config mount boots (by digest) and answers ok (#50)"

# ── Downstream channels ─────────────────────────────────────────────────────────────────────────
emit "helm:appversion"        "GetBusbar/helm-charts' published busbar chart appVersion == version"
emit "helm:render"            "that published chart actually renders, at the released image tag"
emit "terraform:published"    "terraform-provider-busbar is published on registry.terraform.io"
emit "brew:formula-version"   "the homebrew tap formula's version == version"
emit "brew:asset-sha256"      "every formula URL is live and its sha256 matches the real asset"
emit "install:script-live"    "getbusbar.com/install.sh is served"
emit "install:no-api-github"  "the served install.sh has no api.github.com dependency"
emit "install:e2e"            "the live install.sh installs this version with GitHub creds scrubbed"
emit "site:download-page"     "the marketing download page advertises this version"

# ── Fleet + self-consistency ────────────────────────────────────────────────────────────────────
emit "plugins:fleet-released" "every first-party plugin in plugins.yaml has a published release"
emit "contract:drift"         "release-stage.yml still derives its build matrix from the contract, and names no target the contract does not declare"

# ── The bundle image (getbusbar/busbar-headroom), rebuilt on the new busbar ─────────────────────
# The one downstream docker-checks (which verifies the ENGINE image) does not cover: the bundle that
# bakes busbar + the headroom hook, on its own version line, rebuilt by the fan-out.
emit "bundle:headroom-latest" "the getbusbar/busbar-headroom bundle :latest was (re)pushed and pulls"
emit "bundle:headroom-boot"   "the rebuilt headroom bundle actually boots and serves ok on /healthz"

# ── The total floor ─────────────────────────────────────────────────────────────────────────────
# The per-target floor above catches a collapsed contract. This catches everything else that could
# make the list short — a `set -e` abort partway down, an emit() that stopped emitting, a future
# edit that accidentally guards a whole block. Printed output is already on stdout by now; exiting
# non-zero is what matters, because gate.sh refuses a non-zero expected-ids and goes RED.
if [ "$EMITTED" -lt "$EXPECTED_IDS_TOTAL_FLOOR" ]; then
  echo "::error title=release gate::expected-ids: emitted only ${EMITTED} ids; the floor is ${EXPECTED_IDS_TOTAL_FLOOR}. A short expected list silently un-owes whole classes of check, which is how a gate goes green having verified less than it claims." >&2
  exit 1
fi
