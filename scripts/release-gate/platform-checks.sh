#!/usr/bin/env bash
# scripts/release-gate/platform-checks.sh — everything that can only be asserted by EXECUTING the
# shipped bytes, run once per published target ON A NATIVE RUNNER FOR THAT TARGET.
#
# WHY NATIVE, AND WHY PER-TARGET AT ALL.
#
# The five release artifacts are five different binaries and they have already differed in ways
# that only running them can reveal. busbar-aarch64-unknown-linux-gnu shipped in 1.5.1, 1.5.2 and
# 1.5.3 with no embedded release public key (#52) — it downloaded fine, extracted fine, reported
# the right --version, and refused every correctly-signed first-party plugin. Four of five targets
# were perfect. A check that samples one platform, or that inspects the archive without running
# what is inside it, is green on that release; only executing the ARM binary on an ARM machine and
# handing it a real signed plugin goes red.
#
# So: six independent assertions per target, one runner per target, `fail-fast: false`, and each
# one records its own ledger row rather than exiting. A target that cannot be checked at all still
# owes six rows, and their absence is what gate.sh reports as `did not run`.
#
# Usage: scripts/release-gate/platform-checks.sh <version> <target>
#        (BUSBAR_RELEASE_PUBKEY must be in the environment for the pubkey row.)
set -uo pipefail
# `|| exit` and not a bare cd: every path below is repo-relative, so a failed cd would run the
# whole check suite against whatever directory the caller happened to be in and report confident
# nonsense. Failing here is the only honest outcome.
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

VERSION="${1:?usage: platform-checks.sh <version> <target>}"
TARGET="${2:?usage: platform-checks.sh <version> <target>}"
TAG="v${VERSION#v}"
REPO="${BUSBAR_REPO:-GetBusbar/busbar}"

ARCHIVE="$(target_field "$TARGET" archive)"
EXE="$(target_field "$TARGET" exe)"
WANT_ARCH="$(target_field "$TARGET" arch)"
WANT_FORMAT="$(target_field "$TARGET" format)"
PLUGIN_ASSET="$(target_field "$TARGET" plugin_asset)"
ASSET="busbar-${TARGET}.${ARCHIVE}"

WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/relgate-${TARGET}-XXXXXX")"
echo "── ${TARGET} — ${ASSET} @ ${TAG} (work: ${WORK})"

PY=python3; command -v python3 >/dev/null 2>&1 || PY=python

# ── asset: present BY NAME, plausibly sized, and really downloadable ────────────────────────────
# Three properties, one row, because they are one fact from a user's point of view ("the download
# link works"). All three are needed and none implies another: GitHub lists an asset the moment the
# upload row is created, so a 0-byte or truncated upload is listed identically to a good one, and a
# listed asset can still 404 from the CDN.
#
# BY NAME is the load-bearing word. v1.5.3 published five assets where seven were owed and
# release.yml's `assets | length > 0` phantom guard passed — a count cannot see which platform is
# missing.
#
# The name match is `jq --arg` equality, not grep. `busbar-x86_64-unknown-linux-gnu.tar.gz` is a
# substring of nothing else today, but "no other asset happens to contain this string" is a
# property of the current asset list, not an invariant, and a substring match that silently starts
# matching the wrong row is not a failure anyone would see.
list_assets() { gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets' 2>/dev/null; }
assets_json="$(retry 8 10 list_assets || true)"
size="$(printf '%s' "$assets_json" | jq -r --arg n "$ASSET" '.[]? | select(.name == $n) | .size' 2>/dev/null || true)"
url="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
if [ -z "${size:-}" ]; then
  record "asset:${TARGET}" FAIL "release asset ${ASSET} is MISSING from ${TAG}" \
    "Expected a release asset named exactly '${ASSET}'. It is not in the asset list. This is the 1.5.3 five-of-seven shape: that platform's build or upload never completed, and a count-based check cannot see it. Fix: re-run release.yml's ${TARGET} matrix leg."
elif [ "$size" -lt 1000000 ]; then
  record "asset:${TARGET}" FAIL "release asset ${ASSET} is implausibly small" \
    "expected >= 1000000 bytes, observed ${size}. A truncated or empty upload lists exactly like a good one and is useless to whoever downloads it. Fix: re-upload the asset on Release ${TAG}."
else
  code="$(http_code "$url" --range 0-0)"
  case "$code" in
    200|206)
      if retry 5 10 curl "${CURL_OPTS[@]}" -o "${WORK}/${ASSET}" "$url"; then
        record "asset:${TARGET}" PASS "release asset ${ASSET} present (${size} bytes) and downloadable" ""
      else
        record "asset:${TARGET}" FAIL "release asset ${ASSET} is listed but the full download failed" \
          "HEAD/range succeeded but the complete body did not transfer after retries. Fix: re-upload the asset on Release ${TAG}."
      fi
      ;;
    *)
      record "asset:${TARGET}" FAIL "release asset ${ASSET} is listed but NOT downloadable" \
        "downloading it returns HTTP ${code}. Fix: re-upload the asset on Release ${TAG}."
      ;;
  esac
fi

# ── extract: the archive really contains the declared executable ────────────────────────────────
BIN=""
if [ -s "${WORK}/${ASSET}" ]; then
  mkdir -p "${WORK}/x"
  ok=0
  case "$ARCHIVE" in
    tar.gz) tar -xzf "${WORK}/${ASSET}" -C "${WORK}/x" && ok=1 ;;
    zip)
      # python's zipfile rather than `unzip`: this same script runs on the Windows runner, where
      # `unzip` is not guaranteed to be on PATH. python3 is on every GitHub-hosted image.
      "$PY" -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
        "${WORK}/${ASSET}" "${WORK}/x" && ok=1
      ;;
  esac
  if [ "$ok" = 1 ] && [ -f "${WORK}/x/${EXE}" ]; then
    BIN="${WORK}/x/${EXE}"
    chmod +x "$BIN" 2>/dev/null || true
    record "extract:${TARGET}" PASS "${ASSET} extracts to ${EXE}" ""
  else
    record "extract:${TARGET}" FAIL "${ASSET} does not extract to ${EXE}" \
      "contents: $(find "${WORK}/x" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sed 's|.*/||' | tr '\n' ' '). The contract declares exe='${EXE}'. Fix: either the packaging step changed the layout, or .github/release-targets.json is stale."
  fi
else
  record "extract:${TARGET}" FAIL "cannot extract ${ASSET}: it was never downloaded" \
    "see asset:${TARGET} above for why. Reported as a FAIL rather than skipped because the artifact is unusable to a user either way."
fi

# ── version: the shipped binary AGREES it is the tagged version ─────────────────────────────────
# `--version` and not the filename. An asset named vX.Y.Z built from the wrong ref is a real,
# observed release failure mode and the name cannot see it.
if [ -n "$BIN" ]; then
  out="$("$BIN" --version 2>&1)"
  if printf '%s' "$out" | grep -qE "(^|[^0-9.])${VERSION//./\\.}([^0-9.]|$)"; then
    record "version:${TARGET}" PASS "shipped binary reports ${VERSION} (${out})" ""
  else
    record "version:${TARGET}" FAIL "shipped binary does NOT report ${VERSION}" \
      "\`${EXE} --version\` said '${out}'. The artifact for ${TAG} was built from the wrong ref, or the version was never bumped. Fix: re-run release.yml at ${TAG}."
  fi
else
  record "version:${TARGET}" FAIL "cannot run ${EXE}: nothing was extracted" "see extract:${TARGET}."
fi

# ── binfmt: the bytes are the architecture the NAME claims ──────────────────────────────────────
# An asset called aarch64 containing x86_64 bytes is 100% broken for everyone who downloads it and
# every other check in this file would still pass on the runner that produced it. Read from the
# object header rather than `file`/`uname`, which are not uniform across the three runner OSes.
if [ -n "$BIN" ]; then
  probe="$("$PY" scripts/release-gate/binfmt.py "$BIN" 2>&1)"
  if [ "$probe" = "${WANT_FORMAT} ${WANT_ARCH}" ]; then
    record "binfmt:${TARGET}" PASS "shipped binary is ${probe} as contracted" ""
  else
    record "binfmt:${TARGET}" FAIL "shipped binary is not the contracted architecture/format" \
      "expected '${WANT_FORMAT} ${WANT_ARCH}', observed '${probe}'. An artifact whose name promises one architecture and whose bytes are another is unusable on the platform it advertises. Fix: check release.yml's ${TARGET} leg is building for its own target triple."
  fi
else
  record "binfmt:${TARGET}" FAIL "cannot inspect ${EXE}: nothing was extracted" "see extract:${TARGET}."
fi

# ── pubkey: the shipped bytes carry the release public key (#52, statically) ────────────────────
# Reuses scripts/release-key-guard.sh — the SAME assertion release.yml makes at build time, made
# again against the PUBLISHED artifact. Deliberately not a reimplementation: two copies of one fact
# is how the fact rots. The build-time half proves the variable was set; this half proves the bytes
# a user downloads actually contain it, which is the half that would have gone red on real 1.5.3.
if [ -z "$BIN" ]; then
  record "pubkey:${TARGET}" FAIL "cannot inspect ${ASSET}: it was never downloaded" "see asset:${TARGET}."
elif ! printf '%s' "${BUSBAR_RELEASE_PUBKEY:-}" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  # NOT a skip. Without the key this row asserts nothing, and "we could not check whether the
  # release key shipped" must never read as "the release key shipped".
  record "pubkey:${TARGET}" FAIL "BUSBAR_RELEASE_PUBKEY is not available to the gate" \
    "the gate cannot look for a key it does not have, and reporting that as a pass is how #52 survived three releases. Fix: expose the org variable BUSBAR_RELEASE_PUBKEY (the PUBLIC half, 64 hex chars) to this workflow."
elif out="$(scripts/release-key-guard.sh assert-embedded "${WORK}/${ASSET}" 2>&1)"; then
  record "pubkey:${TARGET}" PASS "${ASSET} embeds the release public key" "${out}"
else
  record "pubkey:${TARGET}" FAIL "${ASSET} does NOT embed the release public key (#52)" \
    "$(printf '%s' "$out" | tr '\n' ' ' | sed 's/  */ /g'). Every correctly-signed first-party plugin will be refused on ${TARGET} with 'this build embeds no busbar release key'. This shipped in 1.5.1, 1.5.2 and 1.5.3 for aarch64-unknown-linux-gnu. Fix: the ${TARGET} build ran somewhere BUSBAR_RELEASE_PUBKEY did not reach (a cross container, a sandboxed builder) — see scripts/release-key-guard.sh."
fi

# ── plugin: a REAL signed first-party plugin actually loads (#52, functionally) ─────────────────
# The statically-grepped key above and this are not the same assertion and neither subsumes the
# other: a key can be present in the bytes and still not be wired to the verifier, and a plugin can
# fail to load for reasons that have nothing to do with the key. This is the one a user experiences.
#
# The plugin is a REAL published release of a REAL first-party repo, signed with the REAL private
# half. A locally-packed fixture signed with an ephemeral key would prove only that the signing
# code compiles, and would have been GREEN on the broken 1.5.3 ARM artifact.
PROBE_REPO="$(jq -er '.plugin_probe.repo' "$CONTRACT")"
PROBE_TAG="$(jq -er '.plugin_probe.tag' "$CONTRACT")"
PROBE_ALIAS="$(jq -er '.plugin_probe.alias' "$CONTRACT")"
WANT_SIG="$(jq -er '.plugin_probe.expect_signature' "$CONTRACT")"
WANT_STATUS="$(jq -er '.plugin_probe.expect_status' "$CONTRACT")"

if [ -z "$BIN" ]; then
  record "plugin:${TARGET}" FAIL "cannot load a plugin: ${EXE} was never extracted" "see extract:${TARGET}."
elif [ -z "$PLUGIN_ASSET" ]; then
  record "plugin:${TARGET}" FAIL "no plugin_asset declared for ${TARGET} in ${CONTRACT}" \
    "every published target owes a first-party plugin probe; a target with no probe is a target where #52 can recur unseen. Fix: add plugin_asset to this target's contract row."
else
  mkdir -p "${WORK}/plugins"
  purl="https://github.com/${PROBE_REPO}/releases/download/${PROBE_TAG}/${PLUGIN_ASSET}"
  if ! retry 5 10 curl "${CURL_OPTS[@]}" -o "${WORK}/plugins/${PLUGIN_ASSET}" "$purl"; then
    record "plugin:${TARGET}" FAIL "could not download the first-party plugin probe" \
      "GET ${purl} failed after retries. Fix: confirm ${PROBE_REPO} ${PROBE_TAG} still publishes ${PLUGIN_ASSET}, or update .github/release-targets.json's plugin_probe."
  else
    # Note the absence of `plugins.trust.allow_unsigned`. That is the whole point: the plugin must
    # verify against the key EMBEDDED in the binary, with zero configuration, exactly as an
    # operator's first install does.
    cat > "${WORK}/config.yaml" <<YAML
listen: "127.0.0.1:8080"
providers_file: "${WORK}/providers.yaml"
plugins:
  enabled: true
  dir: "${WORK}/plugins"
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
YAML
    printf 'mock:\n  protocol: anthropic\n  base_url: "https://example.invalid"\n' > "${WORK}/providers.yaml"
    # macOS quarantines anything curl downloaded; without this the runner refuses to exec it and
    # the failure looks like a busbar defect rather than a Gatekeeper attribute.
    command -v xattr >/dev/null 2>&1 && xattr -dr com.apple.quarantine "$BIN" 2>/dev/null
    out="$(BUSBAR_CONFIG="${WORK}/config.yaml" MOCK_KEY=unused "$BIN" --list-plugins 2>&1)"
    # `--list-plugins` prints one row per plugin with its signature verdict and load status, which
    # is a strictly stronger assertion than `--validate`'s "N validated" count: it names WHY.
    row="$(printf '%s\n' "$out" | awk -v a="$PROBE_ALIAS" '$3==a{print; exit}')"
    if printf '%s' "$row" | grep -qw "$WANT_SIG" && printf '%s' "$row" | grep -qw "$WANT_STATUS"; then
      record "plugin:${TARGET}" PASS "real signed first-party plugin loads: ${WANT_SIG}/${WANT_STATUS}" ""
    else
      record "plugin:${TARGET}" FAIL "the shipped ${TARGET} binary REFUSES a correctly-signed first-party plugin (#52)" \
        "expected signature '${WANT_SIG}' and status '${WANT_STATUS}' for alias '${PROBE_ALIAS}'; observed: $(printf '%s' "${row:-<no row for ${PROBE_ALIAS}>}" | sed 's/  */ /g'). Full output: $(printf '%s' "$out" | tr '\n' '|' | sed 's/  */ /g'). If the reason mentions 'embeds no busbar release key' this is #52 recurring on ${TARGET}. Fix: see pubkey:${TARGET}."
    fi
  fi
fi

echo "── ${TARGET} done; ledger: ${LEDGER}"
