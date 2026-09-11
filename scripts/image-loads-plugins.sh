#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE IMAGE LOADS A PLUGIN, AND THE STORE OUTLIVES THE CONTAINER.
#
# Drives the container image named by $1 through the recipe the Dockerfile documents, with the
# PUBLISHED first-party tarballs, and fails loudly if any step is not what it claims. Two plugin
# KINDS are probed, not one: a store plugin and a hook plugin are both a `dlopen` of a verified
# image, so an image that loads one and not the other is an image with a kind-specific runtime,
# which is a defect. One script, run identically on a fleet box and in .github/workflows/docker.yml.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────────────────────────
# `getbusbar/busbar:1.5.5` shipped `FROM scratch` over a `static-pie` musl binary and could load NO
# plugin of any kind: musl's static libc provides `dlopen` only as a stub, and every published
# first-party plugin is a glibc cdylib (`NEEDED libc.so.6`, `ld-linux-*.so.2`). Nothing in CI ran a
# plugin against the image, so the only thing that noticed was an operator, months later. The
# sharpest part was the pre-flight: the image's own `--list-plugins` printed
# `STATUS: LOADS (store.module: sqlite)` for the very tarball the next boot refused. This script is
# the gate that makes that impossible to ship again, and it asserts BOTH halves — that the probe
# says LOADS, and that a container really boots on the plugin it named.
#
#   usage: scripts/image-loads-plugins.sh <image> [<plugin-cache-dir>]
#
# <plugin-cache-dir> defaults to ~/.cache/busbar-oracle/plugins (the oracle's cache, already
# populated on a fleet box). Tarballs are found by GLOB under it, so the exact pinned filename
# lives in testing/shadow-oracle/plugin-digests.tsv and is never restated here.
set -euo pipefail

IMAGE="${1:?usage: image-loads-plugins.sh <image> [plugin-cache-dir]}"
CACHE="${2:-$HOME/.cache/busbar-oracle/plugins}"
ADMIN="${BUSBAR_IMAGE_PROOF_ADMIN_TOKEN:-image-proof-admin}"
AP="${BUSBAR_IMAGE_PROOF_ADMIN_PORT:-48952}"
LP="${BUSBAR_IMAGE_PROOF_LISTEN_PORT:-48951}"

W="$(mktemp -d "${TMPDIR:-/tmp}/busbar-image-proof.XXXXXX")"
CN="busbar-image-proof-$$"
cleanup() { docker rm -f "$CN" >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT

die() { echo "::error::$*" >&2; echo "FAIL: $*" >&2; exit 1; }

# ── THE TARBALLS: TWO KINDS, BOTH PUBLISHED, NEITHER BUILT HERE ─────────────────────────────────
# The published artifacts are the subject. A tarball built on this runner would prove that busbar
# can load what busbar just compiled, which is not the claim an operator cares about.
mkdir -p "$W/plugins" "$W/data"
host_arch="$(uname -m)"; case "$host_arch" in aarch64|arm64) triple=aarch64-unknown-linux-gnu ;; *) triple=x86_64-unknown-linux-gnu ;; esac
store_tb="$(ls "$CACHE"/store-sqlite/*/*"${triple}".tar.gz 2>/dev/null | head -1 || true)"
hook_tb="$(ls "$CACHE"/headroom-hook/*/*"${triple}".tar.gz 2>/dev/null | head -1 || true)"
[ -n "$store_tb" ] || die "no published store-sqlite ${triple} tarball under ${CACHE} (fetch it first)"
[ -n "$hook_tb" ]  || die "no published headroom-hook ${triple} tarball under ${CACHE} (fetch it first)"
cp "$store_tb" "$hook_tb" "$W/plugins/"
chmod -R a+rX "$W/plugins"
store_alias="$(tar -xzOf "$store_tb" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["alias"])')"
hook_name="$(tar -xzOf "$hook_tb" manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
echo "store tarball: $(basename "$store_tb") (alias ${store_alias})"
echo "hook  tarball: $(basename "$hook_tb") (${hook_name})"

# THE VOLUME MUST BE WRITABLE BY THE IMAGE'S OWN UID (the Dockerfile runs `USER 65532:65532`, which
# is not this runner's uid). 0777 on a directory inside a throwaway mktemp tree is not a permission
# decision; it is the local stand-in for the `chown 65532` the docs tell an operator to do.
chmod 0777 "$W/data"

"${DOCKER:-docker}" image inspect "$IMAGE" >/dev/null 2>&1 || die "image ${IMAGE} is not present locally"

# EVERY PATH BELOW IS A CONTAINER PATH AND plugins.dir IS ABSOLUTE. A relative plugins.dir resolves
# against the process's working directory and the mounted tarball is simply not found — a failure
# indistinguishable from "busbar does not persist" until somebody reads the boot log closely.
cat >"$W/config.yaml" <<YAML
listen: "0.0.0.0:8080"
admin_listen: "0.0.0.0:8081"
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "/etc/busbar/signing.key" }
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "/etc/busbar/plugins"
store:
  module: ${store_alias}
  settings: { db_path: "/var/lib/busbar/governance.db" }
groups:
  proof:
    limits:
      - { budget: 1000000, per: day }
providers:
  openai-chat:
    api_key: { env: PROOF_UPSTREAM_KEY }
models:
  m-openai-chat:
    provider: openai-chat
YAML
cat >"$W/providers.yaml" <<'YAML'
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:9/"
YAML
docker run --rm --entrypoint /busbar "$IMAGE" --generate-signing-key >"$W/signing.key" 2>/dev/null
chmod 0644 "$W/config.yaml" "$W/providers.yaml" "$W/signing.key"

mounts=(
  -v "$W/config.yaml:/etc/busbar/config.yaml:ro"
  -v "$W/providers.yaml:/etc/busbar/providers.yaml:ro"
  -v "$W/signing.key:/etc/busbar/signing.key:ro"
  -v "$W/plugins:/etc/busbar/plugins:ro"
  -v "$W/data:/var/lib/busbar"
)

# ── 1. THE PRE-FLIGHT, AND IT MUST BE A REAL LOAD ───────────────────────────────────────────────
# `--probe-load` stages and `dlopen`s each verified tarball IN THIS IMAGE. Both rows must say LOADS
# — the store one AND the hook one. A bare `--list-plugins` is asserted too, from the other side:
# it must NOT say LOADS, because it loads nothing, and that is the 1.5.5 lie stated as a gate.
echo "== 1. pre-flight: --list-plugins --probe-load =="
probe="$(docker run --rm -e BUSBAR_ADMIN_TOKEN="$ADMIN" -e PROOF_UPSTREAM_KEY=unused "${mounts[@]}" \
  "$IMAGE" --list-plugins --probe-load 2>&1)" || die "--list-plugins --probe-load exited non-zero:
${probe}"
echo "$probe"
grep -q "${store_alias}.*LOADS" <<<"$probe" \
  || die "the STORE plugin did not probe LOADS in ${IMAGE}:
${probe}"
grep -q "${hook_name}.*LOADS" <<<"$probe" \
  || die "the HOOK plugin did not probe LOADS in ${IMAGE} — a store plugin and a hook plugin must load by identical means:
${probe}"
grep -q "CANNOT LOAD" <<<"$probe" && die "some row could not be loaded in ${IMAGE}:
${probe}"

echo "== 1b. a bare --list-plugins must claim no load =="
bare="$(docker run --rm -e BUSBAR_ADMIN_TOKEN="$ADMIN" -e PROOF_UPSTREAM_KEY=unused "${mounts[@]}" \
  "$IMAGE" --list-plugins 2>&1)" || die "--list-plugins exited non-zero: ${bare}"
grep -q 'LOADS' <<<"$bare" \
  && die "a bare --list-plugins printed a LOAD verdict without loading anything — this is the 1.5.5 defect:
${bare}"
grep -q 'VERIFIED (not loaded' <<<"$bare" \
  || die "a bare --list-plugins must say what it actually checked:
${bare}"
echo "ok: bare listing says VERIFIED (not loaded), probe says LOADS"

# ── 2. IT REALLY BOOTS ON THE PLUGIN IT NAMED ───────────────────────────────────────────────────
run_image() {
  docker run -d --name "$CN" "${mounts[@]}" \
    -p "127.0.0.1:${LP}:8080" -p "127.0.0.1:${AP}:8081" \
    -e BUSBAR_ADMIN_TOKEN="$ADMIN" -e PROOF_UPSTREAM_KEY=unused -e RUST_LOG=warn \
    "$IMAGE" >/dev/null
}
wait_healthz() {
  local i=0
  while [ $i -lt 120 ]; do
    curl -fsS -m 2 "http://127.0.0.1:${LP}/healthz" >/dev/null 2>&1 && return 0
    docker inspect -f '{{.State.Running}}' "$CN" 2>/dev/null | grep -q true || break
    sleep 0.5; i=$((i+1))
  done
  return 1
}
drop_container() { docker rm -f "$CN" >/dev/null 2>&1 || true; sleep 1; }

echo "== 2. first boot, durable sqlite store on the volume =="
run_image
wait_healthz || die "the image did not come up on the sqlite plugin (exit $(docker inspect -f '{{.State.ExitCode}}' "$CN" 2>/dev/null)):
$(docker logs "$CN" 2>&1 | tail -20)"
echo "ok: /healthz answered"

mint="$(curl -fsS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"image-proof","group":"proof"}')" || die "minting a key failed"
kid="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$mint")"
[ -n "$kid" ] || die "the mint returned no key id: ${mint}"
echo "ok: minted key ${kid}"

# ── 3. THE CONTAINER DIES AND THE MONEY DOES NOT ────────────────────────────────────────────────
# A NEW container, the same volume. This is the whole claim of the durable-store recipe.
echo "== 3. kill the container, boot a new one on the same volume, read the key back =="
drop_container
[ -s "$W/data/governance.db" ] || die "no governance.db on the volume after the first container — the store was never durable"
run_image
wait_healthz || die "the second container (same volume) did not come up:
$(docker logs "$CN" 2>&1 | tail -20)"
code="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN" \
  "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}")"
[ "$code" = 200 ] || die "the key minted before the restart reads back ${code}, not 200 — it did not survive the container"
drop_container

echo
echo "PASS: ${IMAGE} loads a store plugin AND a hook plugin, and a key minted in one container"
echo "      reads back 200 from a different container over the same /var/lib/busbar volume."
