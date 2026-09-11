#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: THE PERSISTENCE CLAIM AGAINST THE SHIPPED IMAGE, not against a binary on a
# host. Same driver shape as store-persist.sh — boot, mint, spend, KILL, boot again against the same
# store, read the money back — with `docker run` where that cell has a process.
#
#   1. `docker run` the published image with a signed store-sqlite tarball mounted at an ABSOLUTE
#      plugins.dir and a WRITABLE volume for the database
#   2. mint a key, spend through the mock, read /usage
#   3. `docker rm -f` the container, run a NEW one against the SAME volumes, read it back
#
# ── WHY THIS IS A CELL AND NOT A README EXAMPLE ─────────────────────────────────────────────────
# The Dockerfile's own header tells operators exactly this recipe — "Governance (optional) needs a
# writable volume for the SQLite file, e.g. -v busbar-data:/var/lib/busbar with
# store.settings.db_path: /var/lib/busbar/governance.db" — and adds that the image ships with ZERO
# plugins, so the operator must "drop a signed plugin tarball into /etc/busbar/plugins" themselves.
# That is four moving parts (an image that is FROM scratch and has no shell, a plugin tarball the
# loader must accept, an ABSOLUTE plugins.dir, and a volume that outlives the container) and NOTHING
# in this tree ever ran them together. The reported operator failure was exactly here: plugins not
# enabled, no tarball, and a RELATIVE plugins.dir. A recipe nobody executes is a recipe that is true
# until it is not.
#
# ── WHAT THE SUBJECT IS ─────────────────────────────────────────────────────────────────────────
# The PUBLISHED IMAGE, named by the fixture var, on both sides of the comparison — like
# documented-docker-defaults.sh, this cell's subject is the artefact busbar ships rather than the
# binary under test. So it does not move when busbar's code moves; it moves when the SHIPPED RECIPE
# stops working (a republished image, a plugin ABI that drifted, a tarball format the loader stopped
# accepting, a volume the container's uid can no longer write). That is the regression it exists to
# catch, and it is one nothing else here can see.
#
# The image is NOT invented by this harness, for the same reason store-persist.sh will not invent a
# backend URL: BUSBAR_TEST_BUSBAR_IMAGE names it, the recorder gates the cell on that var, and a
# cell that ran therefore cannot have driven an image other than the one it named.
#
# Writes $RAW/captured.json: status = 0 (all steps ran) else the failing step number; body = the
# usage view after the restart; effects = every intermediate status plus the survived/reset verdict.
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN BUSBAR_TEST_BUSBAR_IMAGE.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
IMAGE="${BUSBAR_TEST_BUSBAR_IMAGE:-}"
BOOT_BOUND="${ORACLE_BOOT_BOUND_SECS:-60}"
LP="${IMAGE_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48841}}" AP="${IMAGE_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48842}}" MP="${IMAGE_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48793}}"

# THE -1 SHAPE IS "THIS CELL COULD NOT RUN", AND IT IS NOT A PASS. record.sh reads it as a NAMED GAP.
unsupported() { jq -n --arg e "$1" '{status:-1, headers:{}, body:"", effects:{error:$e}}' >"$RAW/captured.json"; exit 0; }

[ -n "$IMAGE" ] || unsupported "BUSBAR_TEST_BUSBAR_IMAGE is unset: this cell drives a PUBLISHED image and will not invent which one"
command -v docker >/dev/null 2>&1 || unsupported "docker is not on PATH: the shipped image cannot be run here"
docker info >/dev/null 2>&1 || unsupported "docker is installed but not usable by $(id -un): the shipped image cannot be run here"

W="$RAW/image-work"; mkdir -p "$W/plugins" "$W/data"
# THE VOLUME MUST BE WRITABLE BY THE IMAGE'S OWN UID. The Dockerfile runs `USER 65532:65532`, which
# is not the recorder's uid, so a host directory left at the default mode is one the container can
# read and not write -- and sqlite's open() then fails with a message about the DATABASE rather than
# about the mount, which is the confusing shape this cell exists to keep out of an operator's day.
# 0777 on a directory inside the recorder's own throwaway work tree is not a permission decision.
chmod 0777 "$W/data"

CN="busbar-oracle-image-$$"
cleanup() { docker rm -f "$CN" >/dev/null 2>&1 || true; }
trap cleanup EXIT

tarball="$(bash "${BUSBAR_ORACLE_TOOL_DIR:-$here}/fetch-plugin.sh" store-sqlite)" \
  || unsupported "the published store-sqlite tarball could not be fetched"
cp "$tarball" "$W/plugins/"
chmod -R a+rX "$W/plugins"
alias_="$(tar -xzOf "$tarball" manifest.json | jq -r .alias)"

for p in "$LP" "$AP" "$MP"; do assert_port_free "$p" || unsupported "port $p busy"; done

python3 "${BUSBAR_ORACLE_TOOL_DIR:-$here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
wait_for_http "http://127.0.0.1:${MP}/" 5 || unsupported "mock upstream did not come up"

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
chmod 0644 "$W/signing.key"

# THE UPSTREAM IS ON THE HOST AND BUSBAR IS IN A CONTAINER. `--add-host host-gateway` is docker's own
# name for the host as seen from the container network; the alternative -- guessing the bridge's
# gateway address -- is a different guess on every daemon configuration.
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://host.docker.internal:${MP}"
YAML

# EVERY PATH IN THIS CONFIG IS A CONTAINER PATH, AND plugins.dir IS ABSOLUTE. A relative
# plugins.dir resolves against the process's working directory, which in a FROM-scratch image is
# `/` -- so the tarball an operator mounted at /etc/busbar/plugins is simply not found, the store
# silently falls back, and the governance ledger lives in RAM. That failure is indistinguishable
# from "busbar does not persist" until somebody reads the boot log closely. Absolute, always.
cat >"$W/config.yaml" <<YAML
listen: "0.0.0.0:8080"
admin_listen: "0.0.0.0:8081"
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
  module: ${alias_}
  settings: { db_path: "/var/lib/busbar/governance.db" }
groups:
  oracle:
    limits:
      - { budget: 1000000, per: day }
providers:
  openai-chat:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-openai-chat:
    provider: openai-chat
rate_card:
  m-openai-chat: { input_utok: 100000, output_utok: 200000 }
YAML
chmod 0644 "$W/config.yaml" "$W/providers.yaml"

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
# A `fail` IS THE HARNESS GIVING UP, NOT AN OUTCOME OF THE PRODUCT. `harness_error` says which of
# the two this is; record.sh refuses any cell that carries it.
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" \
  '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

# THE SAME `docker run` TWICE, WRITTEN ONCE. Two copies of this line would let the restart differ
# from the first boot in a way no reader would spot -- and "the second boot mounted a different
# volume" is precisely the mistake that makes a persistence cell say `yes` for the wrong reason.
run_image() {
  docker run -d --rm --name "$CN" \
    --add-host host.docker.internal:host-gateway \
    -p "127.0.0.1:${LP}:8080" -p "127.0.0.1:${AP}:8081" \
    -e BUSBAR_ADMIN_TOKEN="$ADMIN" -e ORACLE_UPSTREAM_KEY=unused -e RUST_LOG=warn \
    -v "$W/config.yaml:/etc/busbar/config.yaml:ro" \
    -v "$W/providers.yaml:/etc/busbar/providers.yaml:ro" \
    -v "$W/signing.key:/etc/busbar/signing.key:ro" \
    -v "$W/plugins:/etc/busbar/plugins:ro" \
    -v "$W/data:/var/lib/busbar" \
    "$IMAGE" >/dev/null 2>>"$W/run.err"
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 \
  || unsupported "the published image ${IMAGE} could not be pulled on this host"

run_image || fail 1 "docker run failed for ${IMAGE}: $(tail -c 500 "$W/run.err" 2>/dev/null)"
step boot1_started yes
if ! wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND"; then
  fail 1 "boot 1 (fresh container) did not answer /healthz within ${BOOT_BOUND}s: $(docker logs "$CN" 2>&1 | tail -c 700)"
fi
# THE PLUGIN LOAD LINE IS READ, NOT ASSUMED. A busbar that could not find the mounted tarball boots
# perfectly happily on the in-memory default and answers every request 200 -- so a cell that only
# watched HTTP statuses would record the RAM fallback as a passing persistence proof. This is the
# line that says the dlopen actually happened, and `survived` below is what says it mattered.
step plugin_loaded "$(docker logs "$CN" 2>&1 | grep -ci "plugin" | tr -d ' ')"

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"image-oracle","group":"oracle"}')"
mint_code="$(printf '%s' "$mint_raw" | tail -1)"
mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "$mint_code"

st="$(curl -sS -m 20 -o "$W/chat.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_status "$st"
sleep 0.5
u1="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_before_restart "$u1"

# THE CONTAINER IS KILLED, NOT STOPPED POLITELY, and the ports are PROVEN free before the second one
# binds them. `docker rm -f` returns as soon as the daemon has reaped the container; the published
# port can still be held for a moment, and a /healthz answered by the FIRST container still draining
# would be read as "persistence survived" for a process that never restarted.
docker rm -f "$CN" >/dev/null 2>&1
i=0
while [ $i -lt 100 ] && { ! assert_port_free "$LP" || ! assert_port_free "$AP"; }; do sleep 0.1; i=$((i+1)); done
if ! assert_port_free "$LP" || ! assert_port_free "$AP"; then
  fail 3 "port ${LP}/${AP} still answers after the first container was removed (waited 10s): the second container would bind a port the first still holds, so the persistence verdict would come from the instance that never restarted"
fi
step container_killed yes

# A NEW CONTAINER, THE SAME VOLUMES. This is the whole claim: the database outlived the process that
# wrote it, at the mount the Dockerfile's own header tells operators to use.
run_image || fail 4 "docker run failed for the restart: $(tail -c 500 "$W/run.err" 2>/dev/null)"
if ! wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND"; then
  fail 4 "boot 2 (new container, same volumes) did not answer /healthz within ${BOOT_BOUND}s: $(docker logs "$CN" 2>&1 | tail -c 700)"
fi
k2="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}")"
step key_after_restart "$k2"
u2="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_after_restart "$u2"
st2="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_after_restart "$st2"

# `survived` COMPARES TWO READS, SO IT MUST FIRST PROVE THERE WERE TWO READS. `"" = ""` is true in
# `[`, so a /usage call that came back empty on BOTH sides of the restart would read as "the money is
# exactly what it was" on the strength of having measured nothing.
u1_req="$(jq -r '.requests // empty' <<<"$u1" 2>/dev/null)"
u2_req="$(jq -r '.requests // empty' <<<"$u2" 2>/dev/null)"
[ -n "$u1_req" ] && [ -n "$u2_req" ] \
  || fail 5 "the /usage read before ($u1) or after ($u2) the restart carried no requests count, so 'survived' would compare two absences and call them equal"
step survived "$([ "$k2" = 200 ] && [ "$u2_req" = "$u1_req" ] && echo yes || echo no)"

# THE DATABASE FILE IS ON THE HOST SIDE OF THE MOUNT, or the volume was never the thing being
# written. A busbar that fell back to RAM leaves this directory empty and every status above green.
step db_file_on_the_volume "$([ -s "$W/data/governance.db" ] && echo yes || echo no)"
# Every `store error` line across BOTH containers. A store the binary cannot actually write to still
# serves 200s; this is the count that says so. A COUNT, not the text: the wording is the plugin's.
step store_errors "$(docker logs "$CN" 2>&1 | awk '/store error/{n++} END{print n+0}')"

docker rm -f "$CN" >/dev/null 2>&1
jq -n --argjson eff "$eff" --arg body "$u2" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0 out
# loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
