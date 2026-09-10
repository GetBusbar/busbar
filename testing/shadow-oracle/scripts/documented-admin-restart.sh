#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family: CHANGELOG.md:309-310 (1.5.0) — "POST
# /api/v1/admin/restart applies the settings that need a restart (listeners, TLS, store backend)
# without shell access." The admin.ops family already pins the shape of ONE restart response
# (restart_epoch, its own final epoch); this cell instead proves the DURABLE-SETTINGS half: a
# restart-scoped setting PUT through the admin API survives into the overlay file BEFORE the
# restart is even requested (so the operator never touched a shell or the binary), and a fresh
# process launched against the same config+overlay picks it up — the "without shell access" half
# of the claim, not just the 202 response shape.
#
# Each boot's stdout/stderr are captured separately (never merged with `2>&1`); the two boots' raw
# stderr are concatenated (labeled) into ONE combined `effects.stderr` — the standard path
# accepted-differences.json's D-1/D-2 transforms already reach (MULTILINE regexes, so both boots'
# lines are still individually matched inside the one blob).
#
#   documented-admin-restart.sh
#
# Writes $RAW/captured.json. Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"

# ── --selftest: A HARNESS FAILURE IS REFUSED, NEVER RECORDED (AUDIT NOTE-36) ─────────────────────
# The port guard below used to write a FABRICATED capture — `{status:-1, effects:{error:"port N
# busy"}}` — and then `exit 0`. Nothing in that capture came from busbar: the driver never reached
# the PUT, never booted, never asked the product anything. The recorder read `status:-1` as a NAMED
# GAP and filed the cell SKIP, which takes it out of the owed set entirely, so the cell stopped
# being compared and nobody was told; on an older recorder the same shape was recorded as a golden
# outright. Either way the outcome is a cell that is permanently green about nothing.
#
# THE RULE THIS SELFTEST PINS, in both halves:
#   * the DRIVER exits NON-ZERO on any harness failure and marks the capture `effects.harness_error`
#     (a give-up is not an outcome of the binary), and
#   * that capture is REFUSED — never normalized into a cell, never a row behind a golden.
# The recorder side of the refusal is the pinned tool's (record.sh's script_cell_verdict refuses a
# harness_error and a non-zero driver exit, in that order); the product side is this file's family:
# every driver under scripts/ must give up through oracle_harness_give_up / oracle_named_gap, so
# part (b) below re-audits ALL of them rather than only the one this script drives.
if [ "${1:-}" = "--selftest" ]; then
  st_bad=0
  st_ok()   { printf '  ok    %s\n' "$1"; }
  st_fail() { printf '  RED   %s\n' "$1"; st_bad=1; }
  st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/admin-restart-selftest.XXXXXX")"
  trap 'rm -rf "$st_tmp"; [ -n "${st_planted:-}" ] && kill "$st_planted" 2>/dev/null || true' EXIT

  echo "(a) a planted busy port is a harness failure: refused, never recorded"
  # Bind an ephemeral port and HOLD it for the length of the run: the driver's own guard must see it
  # busy. The port is chosen by the kernel, so this cannot collide with a real recording's ports.
  python3 - "$st_tmp/port" <<'PY' &
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
time.sleep(300)
PY
  st_planted=$!
  st_i=0; while [ "$st_i" -lt 100 ] && [ ! -s "$st_tmp/port" ]; do sleep 0.1; st_i=$((st_i + 1)); done
  st_port="$(cat "$st_tmp/port" 2>/dev/null || true)"
  if [ -z "$st_port" ]; then echo "  RED   could not plant a listener to make a port busy"; exit 1; fi
  mkdir -p "$st_tmp/raw" "$st_tmp/work"
  # BUSBAR_BIN is a stand-in on purpose: the guard fires before the binary is ever invoked, so a run
  # that reaches the binary at all has already failed the thing being proven.
  RAW="$st_tmp/raw" WORK="$st_tmp/work" BUSBAR_BIN=/usr/bin/true \
    RESTART_LISTEN_PORT="$st_port" RESTART_ADMIN_PORT="$st_port" \
    bash "$0" >"$st_tmp/run.log" 2>&1
  st_rc=$?
  kill "$st_planted" 2>/dev/null; st_planted=""

  if [ "$st_rc" -ne 0 ]; then st_ok "the driver exited ${st_rc} (non-zero) on a harness failure"
  else st_fail "the driver exited 0 on a harness failure: a run that never reached the PUT reports success"; fi

  st_cap="$st_tmp/raw/captured.json"
  if [ -s "$st_cap" ] && [ "$(jq -r 'has("effects") and (.effects | has("harness_error"))' "$st_cap" 2>/dev/null)" = true ]; then
    st_ok "the capture carries effects.harness_error ($(jq -r '.effects.harness_error' "$st_cap"))"
  else
    st_fail "the capture carries no effects.harness_error, so the recorder cannot tell a give-up from a verdict"
  fi

  # THE REFUSAL ITSELF, computed with the RECORDER'S OWN RULE and its order (record.sh's
  # script_cell_verdict): no capture -> FAIL; harness_error -> FAIL; status -1 -> SKIP (named gap);
  # non-zero driver exit -> FAIL; else PASS. FAIL is the only verdict that refuses. PASS freezes the
  # give-up in as the contract; SKIP is quieter and no better — it takes the cell out of the owed
  # set, so it is never compared, never reaches diverging.txt, and nobody is told the cell stopped
  # proving anything. A harness failure must land on FAIL.
  st_verdict=PASS
  if [ ! -s "$st_cap" ]; then st_verdict=FAIL
  elif [ "$(jq -r 'has("effects") and (.effects | has("harness_error"))' "$st_cap" 2>/dev/null)" = true ]; then st_verdict=FAIL
  elif [ "$(jq -r '.status' "$st_cap" 2>/dev/null)" = "-1" ]; then st_verdict=SKIP
  elif [ "$st_rc" -ne 0 ]; then st_verdict=FAIL
  fi
  if [ "$st_verdict" = FAIL ]; then st_ok "the recorder refuses it (FAIL): no cell file, no golden row"
  else st_fail "the recorder files it ${st_verdict}, not FAIL — a fabricated capture from a run that never reached the PUT is taken for an answer"; fi

  echo "(b) every driver under scripts/ gives up the same way (the family audit)"
  # A rule enforced in one driver is a rule fifteen siblings can break tomorrow. Every write of
  # captured.json that carries a give-up marker (`error`, `harness_error`, status -1) must NOT be
  # followed by `exit 0`, and no `fail()` may exit 0 — give-ups go through lib.sh's
  # oracle_harness_give_up (harness failure: non-zero) or oracle_named_gap (this host cannot host
  # the cell: an honest, declared SKIP).
  if python3 - "${repo}/testing/shadow-oracle/scripts" <<'PY'
import pathlib, re, sys

marker = re.compile(r'"?error"?\s*:|harness_error|"?status"?\s*:\s*-1|status\\":-1')
found = []
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.sh")):
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        # A give-up is a write of captured.json plus an exit; the exit may sit on the same line or
        # on one of the next few (a multi-line jq write ends with its own `exit`).
        if "captured.json" not in line or ">" not in line:
            continue
        window = " ".join(l for l in lines[i:i + 4] if not l.lstrip().startswith("#"))
        if not marker.search(window):
            continue
        if re.search(r"\bexit 0\b", window):
            found.append(f"{path.name}:{i + 1}: a give-up capture is written and the driver exits 0")
    # fail() is the other half: a helper that marks a harness error and then reports success is the
    # same defect wearing a function name.
    text = path.read_text()
    for m in re.finditer(r"^fail\(\)\s*\{(.*?)^\}|^fail\(\)\s*\{(.*?)\}\s*$", text, re.S | re.M):
        body = m.group(1) or m.group(2) or ""
        if re.search(r"\bexit 0\b", body):
            line_no = text[: m.start()].count("\n") + 1
            found.append(f"{path.name}:{line_no}: fail() exits 0 — the harness giving up is reported as success")
for f in found:
    print("    " + f)
sys.exit(1 if found else 0)
PY
  then st_ok "no driver records a give-up: every harness failure exits non-zero"
  else st_fail "drivers above write a give-up capture and exit 0 — those cells can be recorded vacuously"; fi

  [ "$st_bad" -eq 0 ] || { echo "documented-admin-restart.sh --selftest: RED"; exit 1; }
  echo "documented-admin-restart.sh --selftest: green"
  exit 0
fi
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${RESTART_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48931}}" AP="${RESTART_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48932}}"
W="$RAW/restart-work"; mkdir -p "$W"
# Same knob as record.sh's boot_busbar / scripts/store-persist.sh: this cell boots busbar TWICE, so
# a bound sized for an idle laptop reads a saturated host's second boot as "never restarted".
BOOT_BOUND="${ORACLE_BOOT_BOUND_SECS:-60}"

for p in "$LP" "$AP"; do
  assert_port_free "$p" || oracle_harness_give_up "port $p busy"
done

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
YAML
cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
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

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
# A `fail` IS THE HARNESS GIVING UP, NOT AN OUTCOME OF THE BINARY. It writes a captured.json like
# any other result, and the recorder used to read `status` alone — so `fail 1 "openssl produced no
# cert"` was recorded as a golden that says "this cell is exit 1", with a PASS row behind it, and
# the candidate agreed because it failed the same way. `harness_error` says which of the two this
# is; record.sh refuses any cell that carries it, and this fail() exits 70 as well — AUDIT NOTE-36:
# a give-up marked only by `status: -1` was filed SKIP, which takes the cell out of the owed set.
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 70; }

boot() {  # <stdout-file> <stderr-file>
  ( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
      ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) \
    >"$1" 2>"$2" &
  echo $!
}

pid="$(boot "$W/boot1.stdout" "$W/boot1.stderr")"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" || fail 1 "$(tail -c 800 "$W/boot1.stdout")$(tail -c 800 "$W/boot1.stderr")"
step booted "true"

# advanced.response_headers.server_timing (PB-73): RESTART-scoped, default false — the config
# plane's own example of a setting that must round-trip through a restart to take effect.
put_status="$(curl -sS -m 10 -o "$W/put.body" -w '%{http_code}' -X PUT "http://127.0.0.1:${AP}/api/v1/admin/config/settings" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"advanced":{"response_headers":{"server_timing":true}}}')"
step put_settings_status "$put_status"
step put_settings_body "$(cat "$W/put.body" 2>/dev/null | tr -d '\n')"

restart_status="$(curl -sS -m 10 -o "$W/restart.body" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/restart" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"confirm":true}')"
step restart_status "$restart_status"
step restart_body "$(cat "$W/restart.body" 2>/dev/null | tr -d '\n')"

# the restart drains and exits the process itself (no supervisor here) — wait for the port to free
i=0; while [ $i -lt 100 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done
step process_exited "$(assert_port_free "$LP" && echo true || echo false)"

# a fresh launch against the SAME config + overlay (the "supervisor" restarting it) must come back
# up clean AND now emit the Server-Timing header the pre-restart PUT staged — proving the setting
# survived the restart it required, without any shell access to the box in between.
pid2="$(boot "$W/boot2.stdout" "$W/boot2.stderr")"; track_pid "$pid2"
relaunch_ok="false"
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" && relaunch_ok="true"
step relaunch_after_restart_healthy "$relaunch_ok"
if [ "$relaunch_ok" = "true" ]; then
  hdrs="$(curl -sS -m 5 -D - -o /dev/null "http://127.0.0.1:${LP}/healthz")"
  step server_timing_header_after_relaunch "$(echo "$hdrs" | grep -qi '^server-timing:' && echo true || echo false)"
fi
kill "$pid2" 2>/dev/null; wait "$pid2" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

combined_stderr="--- boot1 ---
$(cat "$W/boot1.stderr" 2>/dev/null)
--- boot2 ---
$(cat "$W/boot2.stderr" 2>/dev/null)
"
eff="$(jq -c --arg v "$combined_stderr" '. + {stderr: $v}' <<<"$eff")"
jq -n --argjson eff "$eff" --arg body "$(jq -c 'del(.stderr)' <<<"$eff")" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0
# out loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
