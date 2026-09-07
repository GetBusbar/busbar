#!/usr/bin/env bash
# scripts/release-gate/docker-checks.sh — the container half of the fan-out.
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

# ── THE ANCHOR: WHAT WAS STAGED, NOT WHAT THIS RUN FOUND FIRST ─────────────────────────────────
#
# Every equality below used to be measured against `hub_ver` — the digest this same run had just
# resolved for `:<version>` on Docker Hub. So the family proved the four names AGREE WITH EACH
# OTHER, and four names all pointing at bytes qa never staged pass every one of them. The anchor is
# now the digest release-stage.yml RECORDED, so each name is compared to a fixed expectation.
#
# NO ANCHOR IS A FAILURE, NOT A SKIP, for the same reason the per-target sha256 row is: "we could
# not check whether these are the staged bytes" must never read as "they are". It is stated once,
# here, and every row that needs it says so in its own words.
STAGED="$(staged_image_digest || true)"
STAGED_V8="$(staged_compat_digest || true)"
NO_ANCHOR="the staged record named no image digest (STAGED_RECORD='${STAGED_RECORD:-<unset>}', STAGED_IMAGE_DIGEST='${STAGED_IMAGE_DIGEST:-<unset>}'). Without it this row can only compare registry names to each other, and four names agreeing about bytes nobody staged is a perfect pass. Fix: the caller must pass the digest release-stage.yml recorded for this release."
NO_V8_ANCHOR="the staged record named no armv8.0-compat image digest (STAGED_RECORD='${STAGED_RECORD:-<unset>}', STAGED_COMPAT_DIGEST='${STAGED_COMPAT_DIGEST:-<unset>}'). The compat arm64 image is a first-class release artifact on its own digest; without its recorded value this row cannot tell the baseline build from the default one, and the default boots everywhere EXCEPT the boards the compat name exists for."

# ── docker:hub-version ──────────────────────────────────────────────────────────────────────────
hub_ver=""
resolve_hub_ver() { hub_ver="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" "$V")"; [ -n "$hub_ver" ]; }
retry 6 15 resolve_hub_ver
if [ -z "$STAGED" ]; then
  record "docker:hub-version" FAIL "cannot bind ${DOCKERHUB_IMAGE}:${V} to the staged image" "$NO_ANCHOR"
elif [ -z "$hub_ver" ]; then
  record "docker:hub-version" FAIL "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V} does not resolve" \
    "the version-pinned image was never pushed (checked against the OCI Distribution API, not hub.docker.com's index, which can lag hours). Fix: re-run docker.yml for v${V}."
elif digest_matches "$hub_ver" "$STAGED"; then
  record "docker:hub-version" PASS "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V} is the STAGED image" "$hub_ver"
else
  record "docker:hub-version" FAIL "${DOCKERHUB_IMAGE}:${V} is not the image qa staged" \
    "the staged record names ${STAGED}; the tag resolves to ${hub_ver}. main promotes a recorded digest and touches no compiler, so a difference here means the version tag was pushed by something other than that promote — a rebuild, a manual push, a re-run of the build. Everything that soaked on qa was about the other image. Fix: re-run the promote against the staged record."
fi

# ── docker:hub-latest ───────────────────────────────────────────────────────────────────────────
hub_latest=""
resolve_hub_latest() {
  hub_latest="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" latest)"
  digest_matches "$hub_latest" "$STAGED"
}
if [ -z "$STAGED" ]; then
  record "docker:hub-latest" FAIL "cannot bind ${DOCKERHUB_IMAGE}:latest to the staged image" "$NO_ANCHOR"
elif retry 6 15 resolve_hub_latest; then
  record "docker:hub-latest" PASS "${DOCKERHUB_IMAGE}:latest is the STAGED digest" "$hub_latest"
else
  record "docker:hub-latest" FAIL "${DOCKERHUB_IMAGE}:latest is NOT the ${V} image" \
    "expected the staged ${STAGED}, observed ${hub_latest:-<nothing>}. \`docker pull ${DOCKERHUB_IMAGE}\` — the command in the README, the docs and on the site — is serving a DIFFERENT release. docker/metadata-action does not imply \`latest\` from \`type=semver,pattern={{version}}\`. Fix: confirm docker.yml's tags: block emits an explicit \`type=raw,value=latest\` gated on a real release, then re-run it for v${V}."
fi

# ── docker:ghcr-version — byte-for-byte the same image, not merely 'an image with that tag' ─────
ghcr_ver=""
resolve_ghcr_ver() {
  ghcr_ver="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" "$V")"
  digest_matches "$ghcr_ver" "$STAGED"
}
if [ -z "$STAGED" ]; then
  record "docker:ghcr-version" FAIL "cannot bind ghcr.io/${GHCR_REPO}:${V} to the staged image" "$NO_ANCHOR"
elif retry 6 15 resolve_ghcr_ver; then
  record "docker:ghcr-version" PASS "ghcr.io/${GHCR_REPO}:${V} is the STAGED digest" "$ghcr_ver"
else
  record "docker:ghcr-version" FAIL "ghcr.io/${GHCR_REPO}:${V} is not the staged image" \
    "expected the staged ${STAGED}, observed ${ghcr_ver:-<nothing>}. The same tag resolving to different bytes on the two registries means which code a user runs depends on which registry they happened to pull from. Fix: docker.yml copies the manifest cross-registry; re-run it for v${V}."
fi

# ── docker:ghcr-latest ──────────────────────────────────────────────────────────────────────────
ghcr_latest=""
resolve_ghcr_latest() {
  ghcr_latest="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" latest)"
  digest_matches "$ghcr_latest" "$STAGED"
}
if [ -z "$STAGED" ]; then
  record "docker:ghcr-latest" FAIL "cannot bind ghcr.io/${GHCR_REPO}:latest to the staged image" "$NO_ANCHOR"
elif retry 6 15 resolve_ghcr_latest; then
  record "docker:ghcr-latest" PASS "ghcr.io/${GHCR_REPO}:latest is the STAGED digest" "$ghcr_latest"
else
  record "docker:ghcr-latest" FAIL "ghcr.io/${GHCR_REPO}:latest is NOT the ${V} image" \
    "expected the staged ${STAGED}, observed ${ghcr_latest:-<nothing>}. Users pulling from GHCR without a tag get a different release. Same fix as the Docker Hub case."
fi

# ── docker:armv8 — the armv8.0-compatible arm64 variant, four names, its own digest ────────────
# The compat image (armv8.0 boards, RPi4-class) is a DIFFERENT digest from the main manifest by
# construction: a single-arch baseline image vs the two-arch (+lse arm64) index. So it gets its
# own pin/pointer agreement rows rather than joining the equality above — and an explicit
# inequality, because the failure worth catching is the fast build shipping under the compat
# name (it boots everywhere EXCEPT the boards the name exists for).
v8_pin=""
resolve_v8_pin() { v8_pin="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" "${V}-armv8.0")"; [ -n "$v8_pin" ]; }
retry 6 15 resolve_v8_pin
if [ -z "$STAGED_V8" ]; then
  record "docker:hub-armv8-pin" FAIL "cannot bind ${DOCKERHUB_IMAGE}:${V}-armv8.0 to the staged compat image" "$NO_V8_ANCHOR"
elif [ -z "$v8_pin" ]; then
  record "docker:hub-armv8-pin" FAIL "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V}-armv8.0 does not resolve" \
    "the armv8.0-compatible arm64 image (RPi4-class boards) never got its version pin. Fix: re-run docker.yml with promote_to=${V} (idempotent)."
elif ! digest_matches "$v8_pin" "$STAGED_V8"; then
  record "docker:hub-armv8-pin" FAIL "${DOCKERHUB_IMAGE}:${V}-armv8.0 is not the compat image qa staged" \
    "the staged record names ${STAGED_V8}; the tag resolves to ${v8_pin}. Fix: re-run the promote against the staged record rather than re-pushing the compat tag."
elif [ -n "$STAGED" ] && digest_matches "$v8_pin" "$STAGED"; then
  # Kept as its own verdict, and now measured between two RECORDED values rather than two names.
  # The failure worth catching is the default (+lse) manifest shipping under the compat name: it
  # boots everywhere EXCEPT the boards the name exists for, so it is invisible to every runner.
  record "docker:hub-armv8-pin" FAIL "${DOCKERHUB_IMAGE}:${V}-armv8.0 is the SAME digest as :${V}" \
    "the compat name must carry the armv8.0 baseline build, not the default (+lse) manifest, and the staged record names the same digest for both — so the staging itself, not just the tagging, collapsed the two. Fix: re-run docker.yml's promote for v${V} after confirming the staged -armv8.0 tag holds the baseline image."
else
  record "docker:hub-armv8-pin" PASS "registry-1.docker.io ${DOCKERHUB_IMAGE}:${V}-armv8.0 is the STAGED compat digest" "$v8_pin"
fi

v8_float=""
resolve_v8_float() {
  v8_float="$(digest_of auth.docker.io registry-1.docker.io "$DOCKERHUB_IMAGE" armv8.0)"
  digest_matches "$v8_float" "$STAGED_V8"
}
if [ -z "$STAGED_V8" ]; then
  record "docker:hub-armv8-floating" FAIL "cannot bind ${DOCKERHUB_IMAGE}:armv8.0 to the staged compat image" "$NO_V8_ANCHOR"
elif retry 6 15 resolve_v8_float; then
  record "docker:hub-armv8-floating" PASS "${DOCKERHUB_IMAGE}:armv8.0 is the STAGED compat digest" "$v8_float"
else
  record "docker:hub-armv8-floating" FAIL "${DOCKERHUB_IMAGE}:armv8.0 is NOT the ${V}-armv8.0 image" \
    "expected the staged ${STAGED_V8}, observed ${v8_float:-<nothing>}. \`docker pull ${DOCKERHUB_IMAGE}:armv8.0\` — the documented tag for armv8.0 boards — serves a different release. Fix: re-run docker.yml with promote_to=${V}."
fi

ghcr_v8_pin=""
resolve_ghcr_v8_pin() {
  ghcr_v8_pin="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" "${V}-armv8.0")"
  digest_matches "$ghcr_v8_pin" "$STAGED_V8"
}
if [ -z "$STAGED_V8" ]; then
  record "docker:ghcr-armv8-pin" FAIL "cannot bind ghcr.io/${GHCR_REPO}:${V}-armv8.0 to the staged compat image" "$NO_V8_ANCHOR"
elif retry 6 15 resolve_ghcr_v8_pin; then
  record "docker:ghcr-armv8-pin" PASS "ghcr.io/${GHCR_REPO}:${V}-armv8.0 is the STAGED compat digest" "$ghcr_v8_pin"
else
  record "docker:ghcr-armv8-pin" FAIL "ghcr.io/${GHCR_REPO}:${V}-armv8.0 is not the staged compat image" \
    "expected the staged ${STAGED_V8}, observed ${ghcr_v8_pin:-<nothing>}. Same cross-registry rule as docker:ghcr-version: the same name resolving to different bytes on the two registries means which code a user runs depends on where they pulled from."
fi

ghcr_v8_float=""
resolve_ghcr_v8_float() {
  ghcr_v8_float="$(digest_of ghcr.io ghcr.io "$GHCR_REPO" armv8.0)"
  digest_matches "$ghcr_v8_float" "$STAGED_V8"
}
if [ -z "$STAGED_V8" ]; then
  record "docker:ghcr-armv8-floating" FAIL "cannot bind ghcr.io/${GHCR_REPO}:armv8.0 to the staged compat image" "$NO_V8_ANCHOR"
elif retry 6 15 resolve_ghcr_v8_float; then
  record "docker:ghcr-armv8-floating" PASS "ghcr.io/${GHCR_REPO}:armv8.0 is the STAGED compat digest" "$ghcr_v8_float"
else
  record "docker:ghcr-armv8-floating" FAIL "ghcr.io/${GHCR_REPO}:armv8.0 is NOT the ${V}-armv8.0 image" \
    "expected the staged ${STAGED_V8}, observed ${ghcr_v8_float:-<nothing>}. Same fix as the Docker Hub case."
fi

# ── THE IMAGE UNDER TEST IS THE STAGED DIGEST, ADDRESSED AS ONE ────────────────────────────────
#
# The label row and both boot rows named the image `${DOCKERHUB_IMAGE}:${V}` — a TAG. "Pulled fresh
# by DIGEST-BACKED tag" is not a digest: it says the daemon resolves the tag through the registry
# rather than a stale local copy, which is a statement about caching and none at all about which
# bytes the tag points to. So a promote that rebuilt instead of retagging leaves `:<version>` on
# bytes qa never staged, and these three rows pull them, boot them, read their label and pass.
#
# The reference is now `<repo>@sha256:<digest>` from the staged record, which is the one form that
# cannot be repointed. And the label row's expectation goes with it: an image whose label disagrees
# with the version was already the failure it looked for; an image that is not the staged one is a
# failure the tag form could not see at all.
REF="${DOCKERHUB_IMAGE}@${STAGED}"
docker rmi -f "$REF" >/dev/null 2>&1
if [ -z "$STAGED" ]; then
  record "docker:label" FAIL "cannot read the staged image's label: no staged digest" "$NO_ANCHOR"
elif retry 3 20 docker pull "$REF" >/dev/null 2>&1; then
  label="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$REF" 2>/dev/null)"
  if [ "$label" = "$V" ]; then
    record "docker:label" PASS "the staged image's org.opencontainers.image.version == ${V}" "$REF"
  else
    record "docker:label" FAIL "image label org.opencontainers.image.version is wrong" \
      "expected '${V}', observed '${label:-<unset>}' on ${REF}. The release says one version and the staged image says another, so anything reading the label (SBOM tooling, admission controllers, artifacthub) reports the wrong release. Fix: check docker/metadata-action's version resolution in docker.yml."
  fi
else
  record "docker:label" FAIL "could not pull ${REF}" \
    "\`docker pull\` of the STAGED DIGEST failed after retries — the registry does not serve the bytes the record names. Fix: see docker:hub-version."
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
if [ -z "$STAGED" ]; then
  record "docker:boot-bare" FAIL "cannot boot the staged image: no staged digest" "$NO_ANCHOR"
elif ! start_container busbar-gate-bare 18080 "$REF"; then
  record "docker:boot-bare" FAIL "\`docker run ${REF}\` did not START on this runner" \
    "docker said: $(printf '%s' "$START_ERR" | tr '\n' '|' | tail -c 400). NOT a pass and NOT a skip: the image under test was never launched, so nothing about it was verified. If this says 'port is already allocated', something else holds 18080 -- and the old code went on to curl that port and PASSED on whatever answered. Fix: free port 18080 on the runner, or remove a container leaked by an earlier leg."
elif probe_healthz 18080 && is_running busbar-gate-bare; then
  record "docker:boot-bare" PASS "the bare documented \`docker run\` boots and answers ok on /healthz" ""
else
  st="$(container_state busbar-gate-bare)"
  logs="$(docker logs busbar-gate-bare 2>&1 | tail -20 | tr '\n' '|')"
  case "$st" in
    exited*) why="the container EXITED (${st}) instead of serving — this is the #50 signature exactly" ;;
    *)       why="the container is ${st} but never answered ok on /healthz" ;;
  esac
  record "docker:boot-bare" FAIL "\`docker run ${REF}\` does NOT work (#50)" \
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
if [ -z "$STAGED" ]; then
  record "docker:boot-ro-mount" FAIL "cannot boot the staged image: no staged digest" "$NO_ANCHOR"
elif ! start_container busbar-gate-ro 18081 \
     -v "${work}/config.yaml:/etc/busbar/config.yaml:ro" "$REF"; then
  record "docker:boot-ro-mount" FAIL "the documented read-only-mount \`docker run\` did not START on this runner" \
    "docker said: $(printf '%s' "$START_ERR" | tr '\n' '|' | tail -c 400). The image under test was never launched, so this row verified nothing. See docker:boot-bare for the port-collision case."
elif probe_healthz 18081 && is_running busbar-gate-ro; then
  record "docker:boot-ro-mount" PASS "the documented read-only config mount boots and answers ok on /healthz" ""
else
  st="$(container_state busbar-gate-ro)"
  logs="$(docker logs busbar-gate-ro 2>&1 | tail -20 | tr '\n' '|')"
  record "docker:boot-ro-mount" FAIL "the documented \`-v \"\$PWD/config.yaml:/etc/busbar/config.yaml:ro\"\` quickstart does NOT work (#50)" \
    "container ${st}. Log: ${logs}. This is the verbatim first command in docs/getting-started.md and the exact form 1.5.3 refused to boot under. Fix: the image must tolerate a read-only /etc/busbar — point config.overlay.file at a writable path in the baked config, or default to config.locked: true."
fi
docker rm -f busbar-gate-ro >/dev/null 2>&1
