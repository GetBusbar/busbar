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

# ── docker:label — the image's own claim about which version it is ─────────────────────────────
# Pulled fresh, by DIGEST-backed tag, with any local copy removed first: a cached layer set for the
# same tag name would let a stale image answer for a fresh one.
docker rmi -f "${DOCKERHUB_IMAGE}:${V}" >/dev/null 2>&1
if retry 3 20 docker pull "${DOCKERHUB_IMAGE}:${V}" >/dev/null 2>&1; then
  label="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "${DOCKERHUB_IMAGE}:${V}" 2>/dev/null)"
  if [ "$label" = "$V" ]; then
    record "docker:label" PASS "image label org.opencontainers.image.version == ${V}" ""
  else
    record "docker:label" FAIL "image label org.opencontainers.image.version is wrong" \
      "expected '${V}', observed '${label:-<unset>}'. The tag says one version and the image says another, so anything reading the label (SBOM tooling, admission controllers, artifacthub) reports the wrong release. Fix: check docker/metadata-action's version resolution in docker.yml."
  fi
else
  record "docker:label" FAIL "could not pull ${DOCKERHUB_IMAGE}:${V}" \
    "\`docker pull\` failed after retries. Fix: see docker:hub-version."
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

# --- form 1: the bare `docker run` from the Dockerfile header / README, on the image's own baked
# --- /etc/busbar/config.yaml. This is the exact form that exited 1 on 1.5.3.
docker rm -f busbar-gate-bare >/dev/null 2>&1
docker run -d --name busbar-gate-bare -p 18080:8080 \
  -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN "${DOCKERHUB_IMAGE}:${V}" >/dev/null 2>&1
if probe_healthz 18080; then
  record "docker:boot-bare" PASS "the bare documented \`docker run\` boots and answers ok on /healthz" ""
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
docker rm -f busbar-gate-ro >/dev/null 2>&1
docker run -d --name busbar-gate-ro -p 18081:8080 \
  -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN \
  -v "${work}/config.yaml:/etc/busbar/config.yaml:ro" \
  "${DOCKERHUB_IMAGE}:${V}" >/dev/null 2>&1
if probe_healthz 18081; then
  record "docker:boot-ro-mount" PASS "the documented read-only config mount boots and answers ok on /healthz" ""
else
  st="$(container_state busbar-gate-ro)"
  logs="$(docker logs busbar-gate-ro 2>&1 | tail -20 | tr '\n' '|')"
  record "docker:boot-ro-mount" FAIL "the documented \`-v \"\$PWD/config.yaml:/etc/busbar/config.yaml:ro\"\` quickstart does NOT work (#50)" \
    "container ${st}. Log: ${logs}. This is the verbatim first command in docs/getting-started.md and the exact form 1.5.3 refused to boot under. Fix: the image must tolerate a read-only /etc/busbar — point config.overlay.file at a writable path in the baked config, or default to config.locked: true."
fi
docker rm -f busbar-gate-ro >/dev/null 2>&1
