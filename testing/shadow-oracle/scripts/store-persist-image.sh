#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: THE PERSISTENCE CLAIM AGAINST THE SHIPPED IMAGE, not against a binary on a
# host. Same driver shape as store-persist.sh — boot, mint, spend, KILL, boot again against the same
# store, read the money back — with `docker run` where that cell has a process.
#
# ── WHY THIS IS A CELL AND NOT A README EXAMPLE ─────────────────────────────────────────────────
# The Dockerfile's own header tells operators exactly this recipe — "Governance (optional) needs a
# writable volume for the SQLite file, e.g. -v busbar-data:/var/lib/busbar with
# store.settings.db_path: /var/lib/busbar/governance.db" — and adds that the image ships with ZERO
# plugins, so the operator must "drop a signed plugin tarball into /etc/busbar/plugins" themselves.
# That is four moving parts (an image that is FROM scratch and has no shell, a plugin tarball the
# loader must accept, an ABSOLUTE plugins.dir, and a volume that outlives the container) and NOTHING
# in this tree ever ran them together. A recipe nobody executes is a recipe that is true until it
# is not.
#
# ── WHAT IT FOUND, AND WHY THE CELL IS SHAPED THE WAY IT IS ─────────────────────────────────────
# Run against the published 1.5.5 image, the recipe DOES NOT WORK, and the cell exists to pin that
# rather than to assert the happy path nobody had measured. `getbusbar/busbar:1.5.5` is FROM scratch
# (three layers: the binary, providers.yaml, config.yaml) and its busbar is a dynamically-linked ELF.
# A plugin is a cdylib and loading one is a dlopen, so:
#
#   * the memfd load path fails    — `memfd load unavailable ... dlopen failed`
#   * the private-staging fallback fails too, first for want of a /tmp at all
#     (`cannot create private plugin staging dir /tmp/...: No such file or directory`) and then,
#     given a writable /tmp, for the real reason: `dlopen failed`.
#
# So NO plugin of any kind can load in the published image, and the durable-store recipe the
# Dockerfile documents cannot be followed with it. Busbar itself behaves CORRECTLY throughout: the
# store refuses to open and the process refuses to boot, loudly, exit 1, with the reason named —
# there is no silent fall back to RAM. The defect is the image and the documentation, not the
# refusal.
#
# The sharpest part is the pre-flight: the image's OWN `--list-plugins` prints
# `STATUS: LOADS (store.module: sqlite)` for the very tarball that then fails to dlopen. An operator
# who checks before starting is told yes and then refused. `list_plugins_status` is an effect of this
# cell for exactly that reason.
#
# THE CELL THEREFORE RECORDS A TRAJECTORY, NOT A PASS. Every step is attempted and every step's
# observation is an effect; the ones that could not be reached say so in as many words rather than
# being absent. `status` is the first container's EXIT CODE — 1 today. The day the image gains what
# a dlopen needs, the container stays up, the driver takes the mint/kill/read-back path it already
# carries, and the diff on this cell is the recipe starting to work. That is the regression, in both
# directions, that nothing else here can see.
#
# TWO CONTAINERS FOR ONE OBSERVATION, ON PURPOSE. `boot1_error` is the DOCUMENTED recipe verbatim;
# `boot_error_with_tmp` is the same recipe plus a writable /tmp. Recording only the first would mean
# that adding a /tmp to the image moved this cell to green while the deeper blocker — the dlopen —
# sat exactly where it was. Two effects, two causes, and neither can hide the other.
#
# ── WHAT THE SUBJECT IS ─────────────────────────────────────────────────────────────────────────
# The PUBLISHED IMAGE, named by the fixture var, on both sides of the comparison — like
# documented-docker-defaults.sh, this cell's subject is the artefact busbar ships rather than the
# binary under test. The image is NOT invented by this harness, for the same reason store-persist.sh
# will not invent a backend URL: BUSBAR_TEST_BUSBAR_IMAGE names it, the recorder gates the cell on
# that var, and a cell that ran therefore cannot have driven an image other than the one it named.
#
# Writes $RAW/captured.json. Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN
# BUSBAR_TEST_BUSBAR_IMAGE.
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
# read and not write — and sqlite's open() then fails with a message about the DATABASE rather than
# about the mount, which is the confusing shape this cell exists to keep out of an operator's day.
# 0777 on a directory inside the recorder's own throwaway work tree is not a permission decision.
chmod 0777 "$W/data"

CN="busbar-oracle-image-$$"
cleanup() { docker rm -f "$CN" "${CN}-tmp" >/dev/null 2>&1 || true; }
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

# THE UPSTREAM IS ON THE HOST AND BUSBAR IS IN A CONTAINER, AND THE ADDRESS MUST BE A PRIVATE ONE.
# `host.docker.internal` was the obvious choice and is refused by busbar's own egress rule — "base_url
# must use https for a public host ... plaintext http is permitted only for a private/loopback
# local-model upstream" — because a name is not a private address. The bridge's gateway IS one
# (172.17.x.x), it is what the daemon itself publishes, and reading it beats guessing it.
GW="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)"
[ -n "$GW" ] || unsupported "could not read the docker bridge gateway address; the container has no route to the mock upstream"
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://${GW}:${MP}"
YAML

# EVERY PATH IN THIS CONFIG IS A CONTAINER PATH, AND plugins.dir IS ABSOLUTE. A relative plugins.dir
# resolves against the process's working directory, which in a FROM-scratch image is `/` — so the
# tarball an operator mounted at /etc/busbar/plugins is simply not found. That failure is
# indistinguishable from "busbar does not persist" until somebody reads the boot log closely.
#
# `admin_require_mtls: false` is DECLARED, not defaulted. The admin plane has to bind 0.0.0.0 to be
# reachable from outside the container at all, and busbar refuses a network-exposed admin plane
# without client certificates unless the operator says so out loud. The publish below is
# 127.0.0.1-only, so it is a token-only admin plane on the loopback of one host; saying so here is
# the honest form of that, and it keeps the refusal busbar is right to make.
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
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" \
  '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

# THE STAGING DIRECTORY'S NAME IS RANDOM PER RUN, so the error line that names it is not byte-stable
# until it is scrubbed. The scrub keeps the PATH — which is the finding, /tmp in an image that has no
# /tmp — and drops only the per-run suffix. Ports and the bridge address go the same way: they are
# this recording's, not the product's.
scrub() { sed -e 's|/tmp/busbar-plugins-[0-9]*-[0-9a-f]*|/tmp/busbar-plugins-<STAGING>|g' \
              -e "s|${GW}|<GATEWAY>|g" -e "s|:${MP}|:<PORT>|g" -e "s|${W}|<WORK>|g"; }
# The lines that decide this cell. A container that refused prints one `[error]`; a busbar that could
# not find the tarball prints nothing about a plugin at all, and that absence is itself a value.
err_lines() { docker logs "$1" 2>&1 | grep -E '^\[error\]|memfd load unavailable|plugin load failed' | scrub | tr '\n' ' ' | tail -c 400; }

# THE SAME `docker run` TWICE, WRITTEN ONCE. Two copies would let the restart differ from the first
# boot in a way no reader would spot — and "the second boot mounted a different volume" is precisely
# the mistake that makes a persistence cell say `yes` for the wrong reason. NOT `--rm`: the exit code
# of a container that refused is the finding, and `--rm` reaps it before it can be read.
run_image() {  # run_image <name> [extra docker args...]
  local name="$1"; shift
  docker run -d --name "$name" "$@" \
    -p "127.0.0.1:${LP}:8080" -p "127.0.0.1:${AP}:8081" \
    -e BUSBAR_ADMIN_TOKEN="$ADMIN" -e ORACLE_UPSTREAM_KEY=unused -e RUST_LOG=warn \
    -v "$W/config.yaml:/etc/busbar/config.yaml:ro" \
    -v "$W/providers.yaml:/etc/busbar/providers.yaml:ro" \
    -v "$W/signing.key:/etc/busbar/signing.key:ro" \
    -v "$W/plugins:/etc/busbar/plugins:ro" \
    -v "$W/data:/var/lib/busbar" \
    "$IMAGE" >/dev/null 2>>"$W/run.err"
}
exit_code_of() { docker inspect -f '{{.State.ExitCode}}' "$1" 2>/dev/null || echo "?"; }
# The ports must be PROVEN free before the next container binds them: `docker rm -f` returns as soon
# as the daemon has reaped the container, and a /healthz answered by the PREVIOUS one still draining
# would be read as "persistence survived" for a process that never restarted.
drop_container() {
  docker rm -f "$1" >/dev/null 2>&1
  local i=0
  while [ $i -lt 100 ] && { ! assert_port_free "$LP" || ! assert_port_free "$AP"; }; do sleep 0.1; i=$((i+1)); done
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 \
  || unsupported "the published image ${IMAGE} could not be pulled on this host"

# ── 0. THE PRE-FLIGHT THE OPERATOR RUNS ─────────────────────────────────────────────────────────
# The image's own verdict on the mounted tarball, in the image's own words. Measured against 1.5.5
# this prints LOADS for a plugin that then fails to dlopen, which is the difference between an
# operator who starts confidently and one who is warned.
lp_out="$(docker run --rm \
  -e BUSBAR_ADMIN_TOKEN="$ADMIN" -e ORACLE_UPSTREAM_KEY=unused \
  -v "$W/config.yaml:/etc/busbar/config.yaml:ro" -v "$W/providers.yaml:/etc/busbar/providers.yaml:ro" \
  -v "$W/signing.key:/etc/busbar/signing.key:ro" -v "$W/plugins:/etc/busbar/plugins:ro" \
  "$IMAGE" --list-plugins 2>&1 | scrub)"
step list_plugins_status "$(printf '%s' "$lp_out" | awk '/busbar-store-sqlite/{ $1=""; print }' | tr -s ' ' | tail -c 200)"

# ── 1. THE DOCUMENTED RECIPE, VERBATIM ──────────────────────────────────────────────────────────
run_image "$CN" || fail 1 "docker run failed for ${IMAGE}: $(tail -c 400 "$W/run.err" 2>/dev/null | scrub)"
if wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND"; then
  step boot1_healthz yes
  step boot1_error ""
else
  step boot1_healthz no
  step boot1_exit "$(exit_code_of "$CN")"
  step boot1_error "$(err_lines "$CN")"
fi
boot1="$(jq -r .boot1_healthz <<<"$eff")"
drop_container "$CN"

# ── 1b. THE SAME RECIPE PLUS A WRITABLE /tmp ────────────────────────────────────────────────────
# Only asked when the documented recipe did not come up, and only to separate two causes that the
# first observation alone conflates: "the image has no /tmp for the loader's staging" and "the image
# cannot dlopen at all". Adding a /tmp to the image would move `boot1_error` and leave this one
# exactly where it is; that is the point of asking twice.
if [ "$boot1" = yes ]; then
  step boot_error_with_tmp "not asked: the documented recipe came up"
else
  run_image "${CN}-tmp" --tmpfs /tmp:exec,mode=1777 \
    || fail 1 "docker run failed for the writable-/tmp variant: $(tail -c 400 "$W/run.err" 2>/dev/null | scrub)"
  if wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND"; then
    step boot_error_with_tmp "came up: the only blocker was the missing /tmp"
  else
    step boot_error_with_tmp "$(err_lines "${CN}-tmp")"
  fi
  drop_container "${CN}-tmp"
fi

# ── 2. MINT, SPEND, KILL, READ BACK ─────────────────────────────────────────────────────────────
# NOT REACHED IS A VALUE, NOT AN ABSENCE. A missing key in `effects` reads as "this cell does not
# measure that"; the literal below reads as "this cell measures it and it did not happen", which is
# the whole difference on a cell whose subject refused to start.
NR="not reached: the shipped image refused to boot"
if [ "$boot1" != yes ]; then
  for k in mint_status chat_status usage_before_restart container_killed boot2_healthz \
           key_after_restart usage_after_restart chat_after_restart; do step "$k" "$NR"; done
  step survived "no: the first container never served a request"
  step db_file_on_the_volume "$([ -s "$W/data/governance.db" ] && echo yes || echo no)"
  # THE STATUS IS THE IMAGE'S OWN EXIT CODE. Not a harness give-up: the container ran, refused, and
  # said why, and that refusal is the recorded behaviour of the shipped artefact.
  jq -n --argjson eff "$eff" --arg body "$(jq -r .boot1_error <<<"$eff")" \
     --argjson st "$(jq -r '.boot1_exit | if . == "?" then 1 else (.|tonumber) end' <<<"$eff")" \
     '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
  exit 0
fi

run_image "$CN" || fail 2 "docker run failed re-running the recipe: $(tail -c 400 "$W/run.err" 2>/dev/null | scrub)"
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" || fail 2 "the recipe came up once and not twice"

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"image-oracle","group":"oracle"}')"
mint_code="$(printf '%s' "$mint_raw" | tail -1)"
mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 3 "$mint"
step mint_status "$mint_code"

st="$(curl -sS -m 20 -o "$W/chat.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_status "$st"
sleep 0.5
u1="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_before_restart "$u1"

drop_container "$CN"
if ! assert_port_free "$LP" || ! assert_port_free "$AP"; then
  fail 4 "port ${LP}/${AP} still answers after the first container was removed (waited 10s): the second container would bind a port the first still holds, so the persistence verdict would come from the instance that never restarted"
fi
step container_killed yes

# A NEW CONTAINER, THE SAME VOLUMES. This is the whole claim: the database outlived the process that
# wrote it, at the mount the Dockerfile's own header tells operators to use.
run_image "$CN" || fail 5 "docker run failed for the restart: $(tail -c 400 "$W/run.err" 2>/dev/null | scrub)"
if wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND"; then step boot2_healthz yes; else
  step boot2_healthz no
  fail 5 "boot 2 (new container, same volumes) did not answer /healthz within ${BOOT_BOUND}s: $(err_lines "$CN")"
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
  || fail 6 "the /usage read before ($u1) or after ($u2) the restart carried no requests count, so 'survived' would compare two absences and call them equal"
step survived "$([ "$k2" = 200 ] && [ "$u2_req" = "$u1_req" ] && echo yes || echo no)"

# THE DATABASE FILE IS ON THE HOST SIDE OF THE MOUNT, or the volume was never the thing being
# written. A busbar that fell back to RAM leaves this directory empty and every status above green.
step db_file_on_the_volume "$([ -s "$W/data/governance.db" ] && echo yes || echo no)"
step store_errors "$(docker logs "$CN" 2>&1 | awk '/store error/{n++} END{print n+0}')"

drop_container "$CN"
jq -n --argjson eff "$eff" --arg body "$u2" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0 out
# loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
