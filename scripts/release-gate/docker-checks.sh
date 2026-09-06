#!/usr/bin/env bash
# scripts/release-gate/docker-checks.sh — the container half of the fan-out.
#
# THREE KINDS OF ASSERTION. The third — is this the image qa verified? — is an EXTERNAL anchor, and
# without it the other two are a closed loop: every digest they compare is fetched in this same run,
# so they establish that the four published names AGREE and can never establish what they agree ON.
# An image built from the wrong ref, or pushed by a workflow on a branch, or retagged by hand after
# the release, satisfies all of them. `docker:staged-digest` and `docker:staged-armv8-digest` diff
# the published tags against the manifest digests release-stage.yml recorded on qa before any
# user-facing name existed; the promote is a manifest retag of exactly those digests, so a
# difference means something outside the release path moved the tag. Those two rows are owed only
# when a staged record was supplied (see expected-ids.sh and release-fleet.yml's `resolve`), and the
# BOOT rows below address the image by digest rather than by the tag they used to pull.
#
# TWO KINDS OF ASSERTION, AND THE SECOND IS THE ONE THAT WAS MISSING.
#
# EXISTENCE (digests): the version tag resolves, `latest` is the SAME manifest digest as the version
# tag on BOTH registries, and the two registries agree with each other. Digests, never tag names,
# and never a local `docker run --version`: a local image cache will happily answer for a stale tag
# and report a frozen `latest` as fresh. `docker/metadata-action` does NOT imply `latest` from
# `type=semver,pattern={{version}}`, so `latest` froze wherever a human last put it and
# `docker pull getbusbar/busbar` served the previous release across at least two releases while
# every workflow involved was green.
#
# BOOT: the image actually STARTS and answers `ok` on /healthz, in BOTH documented forms. This is
# #50. v1.5.3's image exited 1 on a plain `docker run` — the FROM-scratch/USER 65532 image cannot
# write /etc/busbar, and 1.5.3 refused to boot without a writable config overlay — and it was
# `latest` in production for six days. Nothing anywhere had ever started the image before pushing
# it, and the one post-publication check that would have seen it was dark behind an unrelated
# failing check.
#
# The read-only mount form is not a variation, it is THE documented quickstart:
#   docker run ... -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" ...
# and `:ro` is the exact thing 1.5.3 refused to boot under. Both forms are asserted separately so
# the summary says which one a user's first command would have hit.
#
# Usage: scripts/release-gate/docker-checks.sh <version>
set -uo pipefail
# `|| exit` and not a bare cd: every path below is repo-relative, so a failed cd would run the
# whole check suite against whatever directory the caller happened to be in and report confident
# nonsense. Failing here is the only honest outcome.
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

VERSION="${1:?usage: docker-checks.sh <version>}"
V="${VERSION#v}"
DOCKERHUB_IMAGE="${DOCKERHUB_IMAGE:-getbusbar/busbar}"
GHCR_REPO="${GHCR_REPO:-getbusbar/busbar}"

# ── Anonymous pull-token -> HEAD manifest -> Docker-Content-Digest ──────────────────────────────
# Straight at the OCI Distribution API (registry-1.docker.io / ghcr.io), never hub.docker.com's
# tags/search index: the index can lag a real push by hours, and it is not what `docker pull` reads.
digest_of() {  # digest_of <auth-host> <registry-host> <repo> <tag> -> digest on stdout
  local auth_host="$1" reg_host="$2" repo="$3" tag="$4" token_url token
  if [ "$auth_host" = "auth.docker.io" ]; then
    token_url="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull"
  else
    token_url="https://${auth_host}/token?service=${auth_host}&scope=repository:${repo}:pull"
  fi
  token="$(curl -fsS --max-time 30 "$token_url" | jq -r '.token // .access_token' 2>/dev/null)"
  [ -n "${token:-}" ] && [ "$token" != "null" ] || return 1
  curl -fsS --max-time 30 -I \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json' \
    "https://${reg_host}/v2/${repo}/manifests/${tag}" \
  | tr -d '\r' | grep -i '^docker-content-digest:' | awk '{print $2}'
}

# ── docker:hub-version ──────────────────────────────────────────────────────────────────────────
hub_ver=""
resolve_hub_ver() { hub_ver="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" "$V")"; [ -n "$hub_ver" ]; }
if retry 6 15 resolve_hub_ver; then
  record "docker:hub-version" PASS "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V} resolves" "$hub_ver"
else
  record "docker:hub-version" FAIL "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V} does not resolve" \
    "the version-pinned image was never pushed (checked against the OCI Distribution API, not hub.docker.com's index, which can lag hours). Fix: re-run docker.yml for v${V}."
fi

# ── docker:hub-latest ───────────────────────────────────────────────────────────────────────────
hub_latest=""
resolve_hub_latest() {
  hub_latest="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" latest)"
  [ -n "$hub_latest" ] && [ "$hub_latest" = "$hub_ver" ]
}
if [ -z "$hub_ver" ]; then
  record "docker:hub-latest" FAIL "cannot compare :latest — :${V} did not resolve" "see docker:hub-version."
elif retry 6 15 resolve_hub_latest; then
  record "docker:hub-latest" PASS "${DOCKERHUB_IMAGE}:latest is the SAME digest as :${V}" "$hub_latest"
else
  record "docker:hub-latest" FAIL "${DOCKERHUB_IMAGE}:latest is NOT the ${V} image" \
    "expected ${hub_ver}, observed ${hub_latest:-<nothing>}. \`docker pull ${DOCKERHUB_IMAGE}\` — the command in the README, the docs and on the site — is serving a DIFFERENT release. docker/metadata-action does not imply \`latest\` from \`type=semver,pattern={{version}}\`. Fix: confirm docker.yml's tags: block emits an explicit \`type=raw,value=latest\` gated on a real release, then re-run it for v${V}."
fi

# ── docker:ghcr-version — byte-for-byte the same image, not merely 'an image with that tag' ─────
ghcr_ver=""
resolve_ghcr_ver() {
  ghcr_ver="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" "$V")"
  [ -n "$ghcr_ver" ] && [ "$ghcr_ver" = "$hub_ver" ]
}
if [ -z "$hub_ver" ]; then
  record "docker:ghcr-version" FAIL "cannot compare GHCR — the Docker Hub digest is unknown" "see docker:hub-version."
elif retry 6 15 resolve_ghcr_ver; then
  record "docker:ghcr-version" PASS "ghcr.io/${GHCR_REPO}:${V} digest == Docker Hub's" "$ghcr_ver"
else
  record "docker:ghcr-version" FAIL "ghcr.io/${GHCR_REPO}:${V} is not the same image as Docker Hub's" \
    "expected ${hub_ver}, observed ${ghcr_ver:-<nothing>}. The same tag resolving to different bytes on the two registries means which code a user runs depends on which registry they happened to pull from. Fix: docker.yml copies the manifest cross-registry; re-run it for v${V}."
fi

# ── docker:ghcr-latest ──────────────────────────────────────────────────────────────────────────
ghcr_latest=""
resolve_ghcr_latest() {
  ghcr_latest="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" latest)"
  [ -n "$ghcr_latest" ] && [ -n "$ghcr_ver" ] && [ "$ghcr_latest" = "$ghcr_ver" ]
}
if [ -z "$ghcr_ver" ]; then
  record "docker:ghcr-latest" FAIL "cannot compare ghcr :latest — :${V} did not resolve there" "see docker:ghcr-version."
elif retry 6 15 resolve_ghcr_latest; then
  record "docker:ghcr-latest" PASS "ghcr.io/${GHCR_REPO}:latest is the SAME digest as :${V}" "$ghcr_latest"
else
  record "docker:ghcr-latest" FAIL "ghcr.io/${GHCR_REPO}:latest is NOT the ${V} image" \
    "expected ${ghcr_ver}, observed ${ghcr_latest:-<nothing>}. Users pulling from GHCR without a tag get a different release. Same fix as the Docker Hub case."
fi

# ── docker:staged-digest — the published tag IS the digest qa verified ─────────────────────────
#
# EVERY DIGEST COMPARISON ABOVE IS BETWEEN TWO VALUES FETCHED IN THIS RUN.
# :latest == :X.Y.Z, ghcr == hub, and so on: all true of any set of tags that were pushed together,
# and all equally true of an image built from the wrong ref, or pushed by a workflow on a branch, or
# retagged by hand after the release. They prove the four names AGREE; they cannot prove what the
# names agree ON. The one external fact that can is the digest release-stage.yml recorded on qa,
# before any user-facing name existed, and which release.yml's promote merely RETAGS — the promote
# touches no compiler and builds no image, so "the published X.Y.Z is the staged digest" is a
# property the design guarantees and therefore one worth checking, because if it is false something
# outside the design moved the tag.
if [ -n "${STAGED_RECORD:-}" ]; then
  staged_digest="$(printf '%s' "$STAGED_RECORD" | jq -r '.digest // empty' 2>/dev/null || true)"
  if [ -z "$staged_digest" ]; then
    record "docker:staged-digest" FAIL "the staged record carries no image digest" \
      "a record without a digest cannot say which bytes were verified, and the promote's strongest check is a no-op against it. Fix: re-run 'Release stage' on the qa sha this release was promoted from."
  elif [ -z "$hub_ver" ]; then
    record "docker:staged-digest" FAIL "cannot compare against the staged digest — :${V} did not resolve" "see docker:hub-version."
  elif [ "$hub_ver" = "$staged_digest" ]; then
    record "docker:staged-digest" PASS "${DOCKERHUB_IMAGE}:${V} is exactly the digest qa staged" "$staged_digest"
  else
    record "docker:staged-digest" FAIL "${DOCKERHUB_IMAGE}:${V} is NOT the image qa verified" \
      "the staged record says ${staged_digest}; :${V} resolves to ${hub_ver}. The promote is a manifest RETAG of the staged digest — it builds nothing — so these cannot differ unless the version tag was moved by something other than the promote, or the release was promoted from a different staged record than the one this tag's commit was staged under. Every other docker row in this gate still passes, because they only compare the published names to each other. Fix: re-run release.yml's promote for v${V}, and find out what else pushed this tag."
  fi
fi

# ── docker:armv8 — the armv8.0-compatible arm64 variant, four names, its own digest ────────────
# The compat image (armv8.0 boards, RPi4-class) is a DIFFERENT digest from the main manifest by
# construction: a single-arch baseline image vs the two-arch (+lse arm64) index. So it gets its
# own pin/pointer agreement rows rather than joining the equality above — and an explicit
# inequality, because the failure worth catching is the fast build shipping under the compat
# name (it boots everywhere EXCEPT the boards the name exists for).
v8_pin=""
resolve_v8_pin() { v8_pin="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" "${V}-armv8.0")"; [ -n "$v8_pin" ]; }
if retry 6 15 resolve_v8_pin; then
  if [ -n "$hub_ver" ] && [ "$v8_pin" = "$hub_ver" ]; then
    record "docker:hub-armv8-pin" FAIL "${DOCKERHUB_IMAGE}:${V}-armv8.0 is the SAME digest as :${V}" \
      "the compat name must carry the armv8.0 baseline build, not the default (+lse) manifest. Fix: re-run docker.yml's promote for v${V} after confirming the staged -armv8.0 tag holds the baseline image."
  else
    record "docker:hub-armv8-pin" PASS "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V}-armv8.0 resolves (own digest)" "$v8_pin"
  fi
else
  record "docker:hub-armv8-pin" FAIL "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V}-armv8.0 does not resolve" \
    "the armv8.0-compatible arm64 image (RPi4-class boards) never got its version pin. Fix: re-run docker.yml with promote_to=${V} (idempotent)."
fi

v8_float=""
resolve_v8_float() {
  v8_float="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" armv8.0)"
  [ -n "$v8_float" ] && [ "$v8_float" = "$v8_pin" ]
}
if [ -z "$v8_pin" ]; then
  record "docker:hub-armv8-floating" FAIL "cannot compare :armv8.0 — :${V}-armv8.0 did not resolve" "see docker:hub-armv8-pin."
elif retry 6 15 resolve_v8_float; then
  record "docker:hub-armv8-floating" PASS "${DOCKERHUB_IMAGE}:armv8.0 is the SAME digest as :${V}-armv8.0" "$v8_float"
else
  record "docker:hub-armv8-floating" FAIL "${DOCKERHUB_IMAGE}:armv8.0 is NOT the ${V}-armv8.0 image" \
    "expected ${v8_pin}, observed ${v8_float:-<nothing>}. \`docker pull ${DOCKERHUB_IMAGE}:armv8.0\` — the documented tag for armv8.0 boards — serves a different release. Fix: re-run docker.yml with promote_to=${V}."
fi

ghcr_v8_pin=""
resolve_ghcr_v8_pin() {
  ghcr_v8_pin="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" "${V}-armv8.0")"
  [ -n "$ghcr_v8_pin" ] && [ "$ghcr_v8_pin" = "$v8_pin" ]
}
if [ -z "$v8_pin" ]; then
  record "docker:ghcr-armv8-pin" FAIL "cannot compare GHCR — the Docker Hub compat digest is unknown" "see docker:hub-armv8-pin."
elif retry 6 15 resolve_ghcr_v8_pin; then
  record "docker:ghcr-armv8-pin" PASS "ghcr.io/${GHCR_REPO}:${V}-armv8.0 digest == Docker Hub's" "$ghcr_v8_pin"
else
  record "docker:ghcr-armv8-pin" FAIL "ghcr.io/${GHCR_REPO}:${V}-armv8.0 is not the same image as Docker Hub's" \
    "expected ${v8_pin}, observed ${ghcr_v8_pin:-<nothing>}. Same cross-registry rule as docker:ghcr-version."
fi

ghcr_v8_float=""
resolve_ghcr_v8_float() {
  ghcr_v8_float="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" armv8.0)"
  [ -n "$ghcr_v8_float" ] && [ -n "$ghcr_v8_pin" ] && [ "$ghcr_v8_float" = "$ghcr_v8_pin" ]
}
if [ -z "$ghcr_v8_pin" ]; then
  record "docker:ghcr-armv8-floating" FAIL "cannot compare ghcr :armv8.0 — :${V}-armv8.0 did not resolve there" "see docker:ghcr-armv8-pin."
elif retry 6 15 resolve_ghcr_v8_float; then
  record "docker:ghcr-armv8-floating" PASS "ghcr.io/${GHCR_REPO}:armv8.0 is the SAME digest as :${V}-armv8.0" "$ghcr_v8_float"
else
  record "docker:ghcr-armv8-floating" FAIL "ghcr.io/${GHCR_REPO}:armv8.0 is NOT the ${V}-armv8.0 image" \
    "expected ${ghcr_v8_pin}, observed ${ghcr_v8_float:-<nothing>}. Same fix as the Docker Hub case."
fi

# The compat image is a first-class release artifact on its own digest, so it gets the same external
# anchor rather than only the four-names-agree treatment above.
if [ -n "${STAGED_RECORD:-}" ]; then
  staged_compat="$(printf '%s' "$STAGED_RECORD" | jq -r '.compat_digest // empty' 2>/dev/null || true)"
  if [ -z "$staged_compat" ]; then
    record "docker:staged-armv8-digest" FAIL "the staged record carries no armv8.0 compat digest" \
      "the compat arm64 image is promoted by the same run as the default one; a record without it means the promote had nothing to verify the compat name against. Fix: re-run 'Release stage' on the qa sha this release was promoted from."
  elif [ -z "$v8_pin" ]; then
    record "docker:staged-armv8-digest" FAIL "cannot compare against the staged compat digest — :${V}-armv8.0 did not resolve" "see docker:hub-armv8-pin."
  elif [ "$v8_pin" = "$staged_compat" ]; then
    record "docker:staged-armv8-digest" PASS "${DOCKERHUB_IMAGE}:${V}-armv8.0 is exactly the compat digest qa staged" "$staged_compat"
  else
    record "docker:staged-armv8-digest" FAIL "${DOCKERHUB_IMAGE}:${V}-armv8.0 is NOT the compat image qa verified" \
      "the staged record says ${staged_compat}; :${V}-armv8.0 resolves to ${v8_pin}. The compat name exists for armv8.0 boards that SIGILL on the default (+lse) build, so a compat tag carrying bytes nobody staged is the one failure that is invisible on every machine the gate runs on. Fix: re-run release.yml's promote for v${V}."
  fi
fi

# ── THE IMAGE THE REMAINING ROWS ACTUALLY RUN, ADDRESSED BY DIGEST ─────────────────────────────
#
# A TAG IS A MOVING POINTER, AND EVERY ROW BELOW USED ONE.
# `docker pull getbusbar/busbar:X.Y.Z` resolves the name at the instant of the pull, so the label
# row, the bare-boot row and the read-only-mount row each verified whatever that name meant when
# they happened to run — three separate resolutions, minutes apart, none of them tied to the digest
# the rows above just finished checking. That is not a hypothetical: the whole reason those rows
# exist is that `latest` once served a different release for six days while every workflow was
# green, which is precisely a name and a digest coming apart.
#
# So the boot rows address `<repo>@<digest>`. The digest is the STAGED one when a record was
# supplied — the bytes qa verified and the promote retagged, which is the strongest available
# subject — and otherwise the digest :X.Y.Z resolved to in the rows above, which is at minimum a
# pin taken once rather than three times. If neither exists there is no image to boot and the rows
# say so rather than falling back to the tag.
BOOT_DIGEST="${staged_digest:-}"
[ -n "$BOOT_DIGEST" ] || BOOT_DIGEST="$hub_ver"
BOOT_REF="${DOCKERHUB_IMAGE}@${BOOT_DIGEST}"

# ── docker:label — the image's own claim about which version it is ─────────────────────────────
# Pulled fresh, BY DIGEST, with any local copy removed first: a cached layer set for the same tag
# name would let a stale image answer for a fresh one, and a digest cannot be stale by construction.
docker rmi -f "${DOCKERHUB_IMAGE}:${V}" "$BOOT_REF" >/dev/null 2>&1
if [ -z "$BOOT_DIGEST" ]; then
  record "docker:label" FAIL "cannot read the image label: ${DOCKERHUB_IMAGE}:${V} resolves to no digest" \
    "see docker:hub-version. The label is read from an image addressed by digest rather than by tag, so with no digest there is nothing to inspect — and inspecting the tag instead would be reading whatever the name means right now, which is the failure these rows exist to catch."
elif retry 3 20 docker pull "$BOOT_REF" >/dev/null 2>&1; then
  label="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$BOOT_REF" 2>/dev/null)"
  if [ "$label" = "$V" ]; then
    record "docker:label" PASS "image label org.opencontainers.image.version == ${V}" ""
  else
    record "docker:label" FAIL "image label org.opencontainers.image.version is wrong" \
      "expected '${V}', observed '${label:-<unset>}'. The tag says one version and the image says another, so anything reading the label (SBOM tooling, admission controllers, artifacthub) reports the wrong release. Fix: check docker/metadata-action's version resolution in docker.yml."
  fi
else
  record "docker:label" FAIL "could not pull ${BOOT_REF}" \
    "\`docker pull\` failed after retries on the digest ${DOCKERHUB_IMAGE}:${V} resolves to. Fix: see docker:hub-version."
fi

# ── The two BOOT checks (#50) ───────────────────────────────────────────────────────────────────
# Syntactically-valid dummy credentials. The assertion is BOOT + /healthz, which is provider
# independent; it deliberately never spends a real provider call. BOTH env vars are required
# because the image's baked config defines an admin-tokens identity provider reading
# BUSBAR_ADMIN_TOKEN, and since 1.5.3 an unresolvable secret reference is fatal at boot — so the
# documented invocation passes both, and the check must run the form the docs tell a user to run
# rather than a reduced one that cannot fail the same way.
export ANTHROPIC_KEY=sk-ant-release-gate-dummy
export BUSBAR_ADMIN_TOKEN=release-gate-dummy-token

probe_healthz() {  # probe_healthz <port>
  local b=""
  for _ in $(seq 1 30); do
    b="$(curl -fsS -m 5 "http://127.0.0.1:${1}/healthz" 2>/dev/null || true)"
    [ "$b" = "ok" ] && return 0
    sleep 2
  done
  return 1
}
container_state() { docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' "$1" 2>/dev/null || echo unknown; }

# THE `docker run` STATUS IS NOT NOISE, AND DISCARDING IT MADE A FOREIGN LISTENER LOOK LIKE A PASS.
#
# Both boot rows were `docker run -d ... >/dev/null 2>&1` with no `||` and no captured status, and
# the verdict was `probe_healthz <host-port>`. So when `docker run` FAILED -- the commonest cause
# being "Bind for 0.0.0.0:18080 failed: port is already allocated", i.e. a leftover container from
# an earlier leg, another job on a self-hosted runner, or anything at all listening there -- the
# check went on to curl http://127.0.0.1:18080/healthz, and whatever answered `ok` PASSED the row.
# The image under test was never started. This is #50's own row: the one that exists because a
# `latest` that exited 1 on `docker run` sat in production for six days, reading green.
#
# So: the status is captured and a failed start is its own named failure; and a probe that succeeds
# is only believed once the container WE started is confirmed RUNNING, which no foreign listener on
# the host port can make true.
start_container() {  # start_container <name> <host-port> [docker run args...] <image>
  local name="$1" port="$2"; shift 2
  docker rm -f "$name" >/dev/null 2>&1
  START_ERR=""
  START_ERR="$(docker run -d --name "$name" -p "${port}:8080" \
    -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN "$@" 2>&1)" || return 1
  return 0
}

is_running() {  # is_running <name>
  [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]
}

# --- form 1: the bare `docker run` from the Dockerfile header / README, on the image's own baked
# --- /etc/busbar/config.yaml. This is the exact form that exited 1 on 1.5.3.
# The invocation is the documented one in every respect except that the image is named by digest
# instead of by tag: what a user types is `docker run getbusbar/busbar:X.Y.Z`, and what this row must
# assert is that the specific bytes the version tag stands for boot. Those are the same statement
# only while the tag resolves to that digest, which is what docker:hub-version and
# docker:staged-digest establish separately — so the rows compose instead of each re-resolving a
# name and hoping.
if [ -z "$BOOT_DIGEST" ]; then
  record "docker:boot-bare" FAIL "cannot boot ${DOCKERHUB_IMAGE}:${V}: it resolves to no digest" \
    "see docker:hub-version. Booting the tag instead would verify whatever the name means at this instant, which is the failure mode these rows exist to catch."
elif ! start_container busbar-gate-bare 18080 "$BOOT_REF"; then
  record "docker:boot-bare" FAIL "\`docker run ${BOOT_REF}\` did not START on this runner" \
    "docker said: $(printf '%s' "$START_ERR" | tr '\n' '|' | tail -c 400). NOT a pass and NOT a skip: the image under test was never launched, so nothing about it was verified. If this says 'port is already allocated', something else holds 18080 -- and the old code went on to curl that port and PASSED on whatever answered. Fix: free port 18080 on the runner, or remove a container leaked by an earlier leg."
elif probe_healthz 18080 && is_running busbar-gate-bare; then
  record "docker:boot-bare" PASS "the bare documented \`docker run\` boots and answers ok on /healthz" "${BOOT_REF}"
else
  st="$(container_state busbar-gate-bare)"
  logs="$(docker logs busbar-gate-bare 2>&1 | tail -20 | tr '\n' '|')"
  case "$st" in
    exited*) why="the container EXITED (${st}) instead of serving — this is the #50 signature exactly" ;;
    *)       why="the container is ${st} but never answered ok on /healthz" ;;
  esac
  record "docker:boot-bare" FAIL "\`docker run ${DOCKERHUB_IMAGE}:${V}\` does NOT work (#50)" \
    "${why}. Container log: ${logs}. A new user's first command fails. This shipped as v1.5.3 and was \`latest\` in production for six days. Fix: see the log above — 1.5.3's was the FROM-scratch/USER 65532 image being unable to write /etc/busbar while refusing to boot without a writable config overlay."
fi
docker rm -f busbar-gate-bare >/dev/null 2>&1

# --- form 2: the DOCUMENTED quickstart from docs/getting-started.md, verbatim, INCLUDING the
# --- read-only config mount. `:ro` is the specific thing 1.5.3 refused to boot under, so it is
# --- asserted as its own row rather than assumed to follow from form 1.
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/relgate-quickstart-XXXXXX")"
cat > "${work}/config.yaml" <<'YAML'
listen: "0.0.0.0:8080"
auth:
  chain: []
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
models:
  claude-sonnet:
    provider: anthropic
pools:
  default:
    members:
      - model: claude-sonnet
YAML
if [ -z "$BOOT_DIGEST" ]; then
  record "docker:boot-ro-mount" FAIL "cannot boot ${DOCKERHUB_IMAGE}:${V}: it resolves to no digest" \
    "see docker:hub-version."
elif ! start_container busbar-gate-ro 18081 \
     -v "${work}/config.yaml:/etc/busbar/config.yaml:ro" "$BOOT_REF"; then
  record "docker:boot-ro-mount" FAIL "the documented read-only-mount \`docker run\` did not START on this runner" \
    "docker said: $(printf '%s' "$START_ERR" | tr '\n' '|' | tail -c 400). The image under test was never launched, so this row verified nothing. See docker:boot-bare for the port-collision case."
elif probe_healthz 18081 && is_running busbar-gate-ro; then
  record "docker:boot-ro-mount" PASS "the documented read-only config mount boots and answers ok on /healthz" "${BOOT_REF}"
else
  st="$(container_state busbar-gate-ro)"
  logs="$(docker logs busbar-gate-ro 2>&1 | tail -20 | tr '\n' '|')"
  record "docker:boot-ro-mount" FAIL "the documented \`-v \"\$PWD/config.yaml:/etc/busbar/config.yaml:ro\"\` quickstart does NOT work (#50)" \
    "container ${st}. Log: ${logs}. This is the verbatim first command in docs/getting-started.md and the exact form 1.5.3 refused to boot under. Fix: the image must tolerate a read-only /etc/busbar — point config.overlay.file at a writable path in the baked config, or default to config.locked: true."
fi
docker rm -f busbar-gate-ro >/dev/null 2>&1
