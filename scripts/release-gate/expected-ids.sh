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

emit() {  # emit <id> <description>
  if [ "$DESCRIBE" = 1 ]; then printf '%s\t%s\n' "$1" "$2"; else printf '%s\n' "$1"; fi
}

# ── Per-target (the matrix legs) ────────────────────────────────────────────────────────────────
# Six rows per published target, each on a NATIVE runner for that target. They are separate ids
# rather than one composite "the artifact is fine" because a composite hides which property broke,
# and because #52 broke exactly one of the six (pubkey/plugin) while the other four were perfect.
while read -r t; do
  [ -n "$t" ] || continue
  emit "asset:${t}"   "the named release asset exists, is plausibly sized and is really downloadable"
  emit "extract:${t}" "the archive extracts to the declared executable"
  emit "version:${t}" "the shipped binary answers --version with the tagged version"
  emit "binfmt:${t}"  "the shipped binary is the declared architecture and object format"
  emit "pubkey:${t}"  "the shipped binary embeds the release public key (#52)"
  emit "plugin:${t}"  "a REAL signed first-party plugin loads as first-party/ready (#52, functionally)"
done < <(published_targets)

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
emit "docker:label"           "the pulled image's org.opencontainers.image.version label matches"
emit "docker:boot-bare"       "the bare documented docker run boots and answers ok on /healthz"
emit "docker:boot-ro-mount"   "the documented read-only config mount boots and answers ok (#50)"

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
emit "contract:drift"         "the contract's target list still matches release.yml's build matrix"

# ── The bundle image (getbusbar/busbar-headroom), rebuilt on the new busbar ─────────────────────
# The one downstream docker-checks (which verifies the ENGINE image) does not cover: the bundle that
# bakes busbar + the headroom hook, on its own version line, rebuilt by the fan-out.
emit "bundle:headroom-latest" "the getbusbar/busbar-headroom bundle :latest was (re)pushed and pulls"
emit "bundle:headroom-boot"   "the rebuilt headroom bundle actually boots and serves ok on /healthz"
