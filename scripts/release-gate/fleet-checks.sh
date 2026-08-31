#!/usr/bin/env bash
# scripts/release-gate/fleet-checks.sh — the one downstream the channel checks do not cover: the
# getbusbar/busbar-headroom BUNDLE image, which bakes busbar + the headroom hook and must be REBUILT
# on the new busbar and still BOOT.
#
# WHY IT IS ITS OWN CHECK AND NOT part of docker-checks.sh. docker-checks verifies getbusbar/busbar
# — the engine image. The headroom bundle is a DIFFERENT image on its OWN version line (2.x), rebuilt
# by the fan-out (release-on-upstream) when busbar releases. A bundle that silently did not rebuild
# against the new busbar, or rebuilt against a busbar that cannot boot its shipped config, is exactly
# the headroom failure plugin-consumer-verify.yml's header documents: the image built and pushed
# green while the container exited 1 on `docker run`. "It built" and "it boots" are different claims;
# only starting the container tells them apart, so that is what this does.
#
# It records ledger rows like every other check and NEVER controls flow; gate.sh aggregates. The
# bundle boot uses syntactically-valid DUMMY credentials and asserts BOOT + /healthz only — it spends
# no real provider call, exactly as docker-checks' boot rows do.
#
# Usage: scripts/release-gate/fleet-checks.sh <version>
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

VERSION="${1:?usage: fleet-checks.sh <version>}"
V="${VERSION#v}"
BUNDLE_IMAGE="${BUNDLE_IMAGE:-getbusbar/busbar-headroom}"

# ── bundle:headroom-latest — the rebuilt bundle is pushed and :latest resolves ──────────────────
# Delete any local copy first so `docker pull` cannot answer from cache and report a stale bundle as
# fresh — the same trap docker-checks.sh and plugin-consumer-verify.yml both guard.
docker rmi -f "${BUNDLE_IMAGE}:latest" >/dev/null 2>&1 || true
if retry 4 15 docker pull "${BUNDLE_IMAGE}:latest" >/dev/null 2>&1; then
  digest="$(docker image inspect "${BUNDLE_IMAGE}:latest" --format '{{index .RepoDigests 0}}' 2>/dev/null | sed 's/.*@//')"
  record "bundle:headroom-latest" PASS "${BUNDLE_IMAGE}:latest is pullable" "${digest:-<no digest>}"
else
  record "bundle:headroom-latest" FAIL "${BUNDLE_IMAGE}:latest is not pullable" \
    "the headroom bundle was not (re)pushed for the busbar ${V} release, so \`docker run ${BUNDLE_IMAGE}\` gives users a stale or absent bundle. Fix: re-run the headroom-hook release-on-upstream workflow for busbar ${V}."
  # No image to boot; boot row is a distinct fact and must still be reported (as a FAIL that points
  # at this row) rather than silently absent, which gate.sh would read as `did not run`.
  record "bundle:headroom-boot" FAIL "cannot boot the headroom bundle: it did not pull" "see bundle:headroom-latest."
  exit 0
fi

# ── bundle:headroom-boot — the bundle actually STARTS and serves, on a freshly pulled :latest ────
port=18790
export ANTHROPIC_KEY=release-gate-dummy
export BUSBAR_ADMIN_TOKEN=release-gate-dummy-token
if curl -s -m 3 -o /dev/null "http://127.0.0.1:${port}/healthz" 2>/dev/null; then
  record "bundle:headroom-boot" FAIL "port ${port} is already answering before the bundle starts" \
    "a health probe would report the wrong process; refusing a possibly-false PASS."
else
  docker rm -f busbar-headroom-gate >/dev/null 2>&1 || true
  docker run -d --name busbar-headroom-gate -p "${port}:8080" \
    -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN "${BUNDLE_IMAGE}:latest" >/dev/null 2>&1 || true
  body=""
  for _ in $(seq 1 30); do
    st="$(docker inspect -f '{{.State.Status}}' busbar-headroom-gate 2>/dev/null || echo missing)"
    { [ "$st" = "exited" ] || [ "$st" = "missing" ]; } && break
    body="$(curl -fsS -m 3 "http://127.0.0.1:${port}/healthz" 2>/dev/null || true)"
    [ "$body" = "ok" ] && break
    sleep 2
  done
  if [ "$body" = "ok" ]; then
    record "bundle:headroom-boot" PASS "the headroom bundle boots and serves ok on /healthz (rebuilt on busbar ${V})" ""
  else
    st="$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' busbar-headroom-gate 2>/dev/null || echo unknown)"
    logs="$(docker logs busbar-headroom-gate 2>&1 | tail -20 | tr '\n' '|')"
    record "bundle:headroom-boot" FAIL "the rebuilt headroom bundle does NOT boot" \
      "container ${st}. Log: ${logs}. The bundle rebuilt against busbar ${V} but its shipped config or the new engine refuses to start — the headroom failure plugin-consumer-verify documents. Fix: migrate docker/bundle/config.yaml and re-cut the bundle."
  fi
  docker rm -f busbar-headroom-gate >/dev/null 2>&1 || true
fi
