#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: the NO-DATA-DIR HAZARD. A config that names no data directory and no peers —
# i.e. every config a 1.5.5 operator ever wrote — must leave a 1.6.0 binary behaving like 1.5.5:
#
#   * NOTHING new appears in the process's working directory
#   * NOTHING new appears beside config.yaml (no WAL, no keyset, no journal, no probe file)
#   * NO log line mentions a data directory, a WAL, peers or a fleet
#
# The contract is an ABSENCE, so it is recorded rather than asserted: this script boots the binary
# under test on such a config, sends ONE chat request through it, shuts it down cleanly, and reports
# the EXACT file set of both directories plus every log line carrying the hazard vocabulary. Record
# it on the published 1.5.5 FIRST — that run is what defines "exactly these files" — then on the
# candidate; the differ says whether the candidate left one byte more behind.
#
# Two modes, one per cell (the recorder passes the mode as the cell's script arg):
#   files   the two directory listings are the contract, carried as `effects.files` (a class the
#           differ compares; an effect key it does not know is invisible to it) and mirrored into
#           `body` for the readable first-diff line
#   logs    the hazard-vocabulary line set is the contract (body = those lines; golden is empty)
#
# The vocabulary and its matching follow the in-tree convention (the no-data-dir neutrality battery):
# the line is lowercased and matched against lowercase needles, and the WAL needles carry a trailing
# separator so an ordinary word that merely contains those three letters is not a false hit.
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN; args: files|logs
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
MODE="${1:?mode: files|logs}"
# The binary is launched from a DIFFERENT working directory (that directory's file set is half the
# contract), so a relative --bin path must be resolved here or the exec would miss it.
BIN="${BUSBAR_BIN:?}"; case "$BIN" in /*) ;; *) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;; esac
RAW="${RAW:?}"; mkdir -p "$RAW"; RAW="$(cd "$RAW" && pwd)"   # absolute for the same reason as BIN
ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${SCRIPT_LISTEN_PORT:-48831}" AP="${SCRIPT_ADMIN_PORT:-48832}" MP="${SCRIPT_MOCK_PORT:-48791}"

# DELIBERATELY NOT under $RAW. The recorder derives $RAW from the cell id, and this cell's id spells
# the very vocabulary the `logs` mode greps for — the binary logs the overlay path at INFO, so a
# work tree under $RAW would echo the fixture's own name back into the log and score a false hit.
# The same trap is called out in the in-tree neutrality battery, which keeps its fixture directory
# free of the tripwire words for exactly this reason. $WORK is the recorder's neutral scratch dir.
W="${WORK:?}/hz-${MODE}"
rm -rf "$W"
# `cfg` starts holding config.yaml and NOTHING else, so anything else found in it afterwards was put
# there by the binary. `run` starts EMPTY and is the process's working directory. Everything the
# fixture itself needs (providers catalog, signing key, logs) lives in `W`, outside both.
mkdir -p "$W/run" "$W/cfg"

fail() { # <status> <message>
  jq -n --argjson st "$1" --arg err "$2" \
    '{status:$st, headers:{}, body:"", effects:{error:$err}}' >"$RAW/captured.json"
  exit 0
}

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || fail -1 "port $p busy"
done

python3 "${here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
wait_for_http "http://127.0.0.1:${MP}/" 5 || fail -1 "mock upstream did not come up"

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null || fail -1 "could not generate a signing key"

cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:${MP}"
YAML

# A PURE 1.5.5-shaped config: no data directory, no peers, no keyset reference, no plane section.
# `providers_file:` points the catalog OUT of the config directory so that directory holds exactly
# one file when the binary starts.
cat >"$W/cfg/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
providers_file: "${W}/providers.yaml"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
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

# The listing the assertion is made of: names only, sorted, one per line, hidden entries included.
list_dir() { ( cd "$1" && ls -A1 2>/dev/null | LC_ALL=C sort ) | paste -sd, - ; }

before_run="$(list_dir "$W/run")"
before_cfg="$(list_dir "$W/cfg")"

# Backgrounding a shell FUNCTION would track the subshell's pid and orphan busbar on the port, so
# the subshell EXECs: the pid tracked and killed IS busbar's. The `cd` is load-bearing — the working
# directory's file set is half of what this cell records.
( cd "$W/run" && exec env \
    BUSBAR_CONFIG="$W/cfg/config.yaml" \
    ORACLE_UPSTREAM_KEY=unused \
    BUSBAR_ADMIN_TOKEN="$ADMIN" \
    RUST_LOG=info \
    "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!
track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "busbar did not come up: $(tail -c 400 "$W/busbar.log")"

mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"hazard-oracle","group":"oracle"}')"
tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$tok" ] || fail 2 "could not mint a key: $mint"

chat_status="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
  -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"

# A CLEAN shutdown, so anything the drain path would write has been written before the listing.
kill -TERM $pid 2>/dev/null
i=0; while [ $i -lt 150 ] && kill -0 $pid 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
kill -9 $pid 2>/dev/null
wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i + 1)); done

after_run="$(list_dir "$W/run")"
after_cfg="$(list_dir "$W/cfg")"

# The hazard vocabulary, matched the way the in-tree neutrality battery matches it: lowercase the
# line, then look for lowercase needles. `wal` carries a separator so `firewall` is not a hit.
needles=("data_dir" "data-dir" "data dir" "wal " "wal_" "wal:" "peers" "fleet")
hazard_lines=""
while IFS= read -r line; do
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  for n in "${needles[@]}"; do
    case "$lower" in *"$n"*) hazard_lines="${hazard_lines}${line}"$'\n'; break ;; esac
  done
done <"$W/busbar.log"
hazard_count="$(printf '%s' "$hazard_lines" | grep -c . || true)"

case "$MODE" in
  files)
    jq -n \
      --arg before_run "$before_run" --arg after_run "$after_run" \
      --arg before_cfg "$before_cfg" --arg after_cfg "$after_cfg" \
      --arg chat "$chat_status" \
      '{status:0, headers:{}, body:$after_cfg, effects:{
          files: {cwd_before: $before_run, cwd_after: $after_run,
                  config_dir_before: $before_cfg, config_dir_after: $after_cfg},
          chat_status: $chat}}' >"$RAW/captured.json"
    ;;
  logs)
    jq -n \
      --arg lines "$hazard_lines" --arg count "$hazard_count" --arg chat "$chat_status" \
      '{status:0, headers:{}, body:$lines, effects:{
          hazard_lines: $lines, hazard_line_count: $count, chat_status: $chat}}' >"$RAW/captured.json"
    ;;
  *) fail -1 "unknown mode '$MODE' (files|logs)" ;;
esac
