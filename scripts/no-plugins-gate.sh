#!/usr/bin/env bash
# NO-PLUGINS GATE — the MECHANICAL DEFINITION of "this thing is a plugin".
#
# THE RULE. Anything busbar calls a plugin must be 100% a plugin: if it were made downloadable-only
# tomorrow, and no longer shipped preinstalled, CORE MUST STILL WORK. If core stops working, then
# core assumed it always had that module — and that module is not a plugin, it is a welded-in part of
# the engine wearing a plugin's name.
#
# WHAT "STILL WORK" MEANS HERE, and why it is not what the tree already checked. `ci.yml`'s
# `no-default-features` job builds, clippy-lints, and unit-tests the featureless binary. That proves
# the featureless binary COMPILES and that the tests which remain compiled in still pass. It never
# boots the binary and never serves a request, so it cannot see a core path that compiles fine and
# then 500s, 401s, or wedges at runtime because the module it reaches for is absent. This gate closes
# exactly that gap: it RUNS the binary and drives real HTTP through it. It does not extend the claim
# past what it executes — every assertion below is an actual request with an actual asserted response.
#
# TWO AXES, BOTH REQUIRED. A plugin can be wrongly assumed in two independent ways, and neither axis
# can see the other's failures:
#
#   AXIS 1 — COMPILED OUT.  `cargo build --no-default-features`: the built-in plugin features
#                           (`auth-admin-tokens`, `hooks-ranking`) are not in the binary at all.
#                           Catches core reaching for a Rust symbol/feature it assumed was there.
#
#   AXIS 2 — NOT INSTALLED. `cargo build` (DEFAULT features), but `plugins.dir` points at a directory
#                           with ZERO artifacts on disk. Catches core assuming some `dlopen`ed
#                           plugin — a store/auth/hook/secret tarball — is present. Axis 1 is blind
#                           to this: a compiled-in feature is not a dlopened artifact, so a binary
#                           that passes axis 1 can still hard-require a plugin that is merely absent
#                           from disk.
#
# EACH AXIS ASSERTS, against a config that references ZERO plugins:
#   A1  `--validate` exits 0                       (the boot-equivalent preflight is clean)
#   A2  the process BOOTS and stays alive
#   A3  the data plane's `/healthz` returns 200
#   A4  the ADMIN PLANE ANSWERS — not just its unauthenticated `/healthz`, but real reads
#       (`info`/`keys`/`hooks`/`config`/`audit`/`groups`) AND a real WRITE (mint a virtual key that
#       the data plane then accepts). An admin plane that 401s every call forever is "up" by any
#       liveness probe and useless by every other measure.
#   A5  a real request is PROXIED END-TO-END through a real mock upstream and comes back with the
#       mock's unique marker, byte-for-byte — on BOTH the single-model route and a POOL route
#       (`hooks: [weighted]`, the engine's inline SWRR floor, which is NOT a plugin).
#   A6  the process is STILL ALIVE after serving all of it (no crash-on-first-request)
#
# AND ONE CROSS-AXIS ASSERTION: A7 — the two axes' response-code vectors over the whole probed
# surface must be IDENTICAL. That is the rule restated mechanically: compiling every built-in plugin
# out must change NOTHING about what core serves. The one deliberate exception is `GET
# /api/v1/admin/info`'s `build` block, whose entire job is to self-report which modules ARE compiled
# in — it is read separately and asserted to DIFFER (a build block that did not change would mean the
# gate had built the same binary twice and every other assertion was vacuous).
#
# THE CONFIG IS THE BASELINE. It names `keys` (the engine's inline signed-key verifier), `weighted`
# (the inline SWRR floor), and `store.module: memory` (the one store that is not a plugin) — no
# plugin, of any kind, anywhere. That case must pass cleanly on both axes. A config that DOES name a
# plugin and then fails on a binary without it is not a violation of this rule; it is the rule
# working (see `--selftest`'s RED-A/RED-B, which use exactly that as a detector fixture).
#
# SELF-TEST. `--selftest` proves the gate cannot be lied to, in the discipline
# `scripts/settings-leak-lint.sh` established: fixtures it MUST flag, and a fixture it must stay
# silent on. Two of the REDs are the REAL featureless binary with a REAL dependency on a
# compiled-out plugin; two are stub servers that pass every EARLIER assertion and fail exactly one
# LATER one, which is how the gate proves its later assertions are load-bearing rather than
# decorative — a gate that passes vacuously is worse than no gate, because it manufactures false
# confidence. Run in CI BEFORE the verdict on the tree is trusted.
#
# DEPENDENCIES: bash 4.4+ (`${var@Q}`, exactly as scripts/release-check.sh already requires), curl,
# python3 (stdlib only — the mock upstream and the self-test stubs), and a Rust toolchain. No jq, no
# network access.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

MODE="check"
case "${1:-}" in
  ""|--check) MODE="check" ;;
  --selftest) MODE="selftest" ;;
  -h|--help)
    sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  *) echo "no-plugins-gate: unknown argument '$1' (expected --check | --selftest | --help)" >&2; exit 2 ;;
esac

# ── Output helpers ────────────────────────────────────────────────────────────────────────────────
hdr()  { printf '\n== %s ==\n' "$1"; }
ok()   { printf '  [ok] %s\n' "$1"; }
note() { printf '  [note] %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; }

# Failures are recorded globally, EXCEPT while a self-test fixture is running: a fixture that is
# SUPPOSED to fail must not poison the gate's own verdict, so `SUPPRESS=1` diverts its failures into
# a counter the fixture harness reads. (A save/restore of the array instead would be a `set -u`
# minefield on an empty array.)
FAILURES=()
SUPPRESS=0
SUPPRESSED=0
fail() {
  bad "$1"
  if [ "$SUPPRESS" = "1" ]; then SUPPRESSED=$((SUPPRESSED + 1)); else FAILURES+=("$1"); fi
}

# ── Cleanup registry ──────────────────────────────────────────────────────────────────────────────
BG_PIDS=()
TMP_DIRS=()
cleanup() {
  for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true; done
  for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && wait "$pid" >/dev/null 2>&1 || true; done
  for d in "${TMP_DIRS[@]:-}";  do [ -n "$d" ] && rm -rf "$d" || true; done
}
trap cleanup EXIT

new_tmpdir() {
  local d; d="$(mktemp -d "${TMPDIR:-/tmp}/busbar-no-plugins-gate.XXXXXX")"
  TMP_DIRS+=("$d"); echo "$d"
}

# A free TCP port, claimed by binding and releasing — the same trick the rest of the repo's harnesses
# use. Racy in principle; in a single-job runner with immediate reuse, reliable in practice.
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }

wait_for_http() {
  local url="$1" timeout_s="${2:-45}" waited=0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    waited=$((waited + 1))
    [ "$waited" -ge "$timeout_s" ] && return 1
    sleep 1
  done
}

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# ── The mock upstream — a real HTTP server, Anthropic protocol, unique marker per run ─────────────
# Same shape as scripts/release-check.sh's: any POST gets a well-formed Messages response whose text
# is a unique marker, so an assertion can prove THE SPECIFIC response came back through busbar rather
# than "some 200 from somewhere".
start_mock_upstream() {
  local port="$1" marker="$2" script
  script="$(new_tmpdir)/mock_upstream.py"
  cat >"$script" <<PYEOF
import http.server, json
MARKER = ${marker@Q}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({
            "id": "chatcmpl-no-plugins-gate", "object": "chat.completion",
            "model": "test-model",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": MARKER}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args): pass
http.server.ThreadingHTTPServer(("127.0.0.1", ${port}), Handler).serve_forever()
PYEOF
  # stdout/stderr to /dev/null at the launch site: a backgrounded serve_forever that inherits a
  # command-substitution pipe wedges the capture on EOF for the whole CI timeout (the hang
  # scripts/release-script-lint.sh exists to prevent).
  python3 "$script" >/dev/null 2>&1 &
  BG_PIDS+=("$!")
}

json_field() { python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: print(""); raise SystemExit
for k in sys.argv[1].split("."): d = d.get(k) if isinstance(d, dict) else None
print(d if d is not None else "")' "$1"; }

# ── The ZERO-PLUGIN config ────────────────────────────────────────────────────────────────────────
# Everything it names is engine-inline: `keys` (signed-key verifier), `weighted` (SWRR floor),
# `store.module: memory` (the only non-plugin store). `admin_auth: []` is the explicit open admin
# posture — the ONLY admin posture available without a plugin, since every admin auth module
# (`admin-tokens` included) is one. `plugins.enabled: true` with an EMPTY `dir` is deliberate: the
# plugin subsystem is ON and finds nothing, which is the axis-2 premise stated in config.
write_zero_plugin_config() {
  local work="$1" bin="$2" mock_port="$3" listen_port="$4" admin_port="$5" plugins_dir="$6"
  # `openai`: `anthropic` and `openai` (chat) are both EXTRACTED protocol crates as of 1.6.0's
  # dialect-extraction line — plugins by this very gate's mechanical definition — so the
  # compiled-out axis no longer speaks either BY DEFAULT (scripts/proto-deletion-gate.sh proves
  # that refusal separately, per dialect). This gate's OWN probe methodology (the mock upstream's
  # wire shape, the `/v1/chat/completions` and `/v2/chat` ingress bodies below) is still written
  # against the OpenAI dialect specifically, so `build_binaries`/`run_selftest` explicitly keep
  # `proto-openai-chat` ON for axis 1 (`--features proto-openai-chat`) — axis 1 stays "every OTHER
  # plugin-kind capability compiled out" rather than "every protocol dialect compiled out", which
  # is a distinct claim scripts/proto-deletion-gate.sh already makes per dialect. When the
  # remaining four dialects (gemini, bedrock, cohere, responses) extract, this fixture is
  # unaffected (openai chat stays linked on both axes here either way).
  cat >"${work}/providers.yaml" <<EOF
mock:
  protocol: openai
  base_url: "http://127.0.0.1:${mock_port}"
EOF
  # The `keys` verifier requires an explicit signing key (busbar no longer auto-generates one); mint
  # one through the shipping command, exactly as an operator would.
  "$bin" --generate-signing-key >"${work}/signing.key" 2>/dev/null
  [ -s "${work}/signing.key" ] || { echo "  --generate-signing-key produced no key" >&2; return 1; }
  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:${listen_port}"
admin_listen: "127.0.0.1:${admin_port}"
providers_file: "${work}/providers.yaml"
auth:
  chain: [keys]
  admin_auth: []
  signing_key: { file: "${work}/signing.key" }
plugins:
  enabled: true
  dir: "${plugins_dir}"
store:
  module: memory
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
pools:
  main:
    members:
      - model: test-model
        weight: 1
    hooks: [weighted]
EOF
}

# ── The probe set: every request the axes compare, as "<label> <code>" lines ──────────────────────
# Ordered and stable, so two axes' outputs diff cleanly.
ADMIN_READS="info keys hooks config audit groups auth admin-auth export config/versions openapi.json"

# ── run_axis <label> <busbar-bin> <plugins-dir> <outdir> ──────────────────────────────────────────
# Boots the binary against the zero-plugin config and runs A1..A6. Writes the probe vector to
# ${outdir}/probe.txt and the /info build block to ${outdir}/build.txt for A7. Returns non-zero on
# any failed assertion (and records each one in FAILURES).
run_axis() {
  local label="$1" bin="$2" plugins_dir="$3" out="$4"
  local work; work="$(new_tmpdir)"
  local marker="no-plugins-gate-${label}-$$-${RANDOM}"
  local mock_port listen_port admin_port
  mock_port="$(free_port)"; listen_port="$(free_port)"; admin_port="$(free_port)"
  local axis_failed=0
  local A="http://127.0.0.1:${admin_port}/api/v1/admin"
  local D="http://127.0.0.1:${listen_port}"

  hdr "AXIS: ${label}"
  note "binary=${bin}"
  note "plugins.dir=${plugins_dir} (artifacts on disk: $(find "$plugins_dir" -type f | wc -l | tr -d ' '))"

  # The axis-2 premise, PROVEN rather than assumed: the directory really is empty, and busbar's own
  # inventory agrees. (Asserted on both axes — it is the shared precondition of the whole gate.)
  if [ "$(find "$plugins_dir" -type f | wc -l | tr -d ' ')" != "0" ]; then
    fail "${label}: plugins.dir is NOT empty — the gate's premise is broken"; return 1
  fi

  write_zero_plugin_config "$work" "$bin" "$mock_port" "$listen_port" "$admin_port" "$plugins_dir" || {
    fail "${label}: could not build the zero-plugin config"; return 1; }

  if BUSBAR_CONFIG="${work}/config.yaml" MOCK_KEY=unused "$bin" --list-plugins 2>&1 \
       | grep -q "no plugin tarballs found"; then
    ok "${label}: busbar's own --list-plugins confirms ZERO plugin artifacts are installed"
  else
    fail "${label}: --list-plugins did not report an empty plugins dir"; axis_failed=1
  fi

  # A1 — --validate (the boot-equivalent preflight) is clean.
  if BUSBAR_CONFIG="${work}/config.yaml" MOCK_KEY=unused "$bin" --validate >"${work}/validate.out" 2>&1; then
    ok "A1 ${label}: --validate exits 0 on a config that references ZERO plugins"
  else
    fail "A1 ${label}: --validate REJECTED a zero-plugin config: $(tail -3 "${work}/validate.out" | tr '\n' ' ')"
    axis_failed=1
    return 1   # nothing downstream is meaningful if the config cannot even validate
  fi

  start_mock_upstream "$mock_port" "$marker"

  # A2 — it boots and stays alive.
  BUSBAR_CONFIG="${work}/config.yaml" MOCK_KEY=unused RUST_LOG=warn "$bin" >"${work}/busbar.log" 2>&1 &
  local pid=$!
  BG_PIDS+=("$pid")
  if ! wait_for_http "${D}/healthz" 45; then
    fail "A2/A3 ${label}: did not come up — /healthz never answered. Log: $(tail -5 "${work}/busbar.log" | tr '\n' ' ')"
    return 1
  fi
  ok "A2 ${label}: booted (pid ${pid})"

  # A3 — data-plane /healthz.
  local hz; hz="$(code "${D}/healthz")"
  if [ "$hz" = "200" ]; then ok "A3 ${label}: data-plane GET /healthz -> 200"
  else fail "A3 ${label}: data-plane GET /healthz -> ${hz}"; axis_failed=1; fi

  # A4 — the admin plane ANSWERS: liveness, real reads, and a real WRITE.
  local ahz; ahz="$(code "http://127.0.0.1:${admin_port}/healthz")"
  if [ "$ahz" = "200" ]; then ok "A4 ${label}: admin-plane GET /healthz -> 200"
  else fail "A4 ${label}: admin-plane GET /healthz -> ${ahz}"; axis_failed=1; fi

  : >"${out}/probe.txt"
  local p c
  for p in $ADMIN_READS; do
    c="$(code "${A}/${p}")"
    printf 'GET admin/%s %s\n' "$p" "$c" >>"${out}/probe.txt"
    if [ "$c" != "200" ]; then
      fail "A4 ${label}: admin read GET /api/v1/admin/${p} -> ${c} (expected 200)"; axis_failed=1
    fi
  done
  ok "A4 ${label}: admin reads all 200 (${ADMIN_READS})"

  # The admin WRITE: mint a virtual key. This is the assertion an "is it up?" probe cannot make — an
  # admin plane whose only working route is an unauthenticated /healthz would sail through A4's
  # liveness check and die here.
  local mint token key_id
  mint="$(curl -s -X POST "${A}/keys" -H 'Content-Type: application/json' -d '{"name":"no-plugins-gate"}')"
  token="$(printf '%s' "$mint" | json_field token)"
  key_id="$(printf '%s' "$mint" | json_field id)"
  if [ -n "$token" ] && [ -n "$key_id" ]; then
    ok "A4 ${label}: admin WRITE works — minted virtual key ${key_id}"
  else
    fail "A4 ${label}: admin WRITE (POST /api/v1/admin/keys) did not return a usable key: ${mint}"
    axis_failed=1
  fi

  # A5 — a real request proxied END-TO-END, on the single-model route and the pool route. Asserted on
  # the mock's unique marker, so this proves THIS response came from THAT upstream through busbar.
  local body got
  body="$(curl -s "${D}/v1/chat/completions" -H "Authorization: Bearer ${token}" \
            -H 'Content-Type: application/json' \
            -d '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}')"
  got="$(printf '%s' "$body" | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["choices"][0]["message"]["content"])
except Exception: print("")')"
  printf 'POST data/v1/chat/completions %s\n' "$(code "${D}/v1/chat/completions" -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' -d '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}')" >>"${out}/probe.txt"
  if [ "$got" = "$marker" ]; then
    ok "A5 ${label}: single-model route proxied end-to-end; body matched the upstream marker exactly"
  else
    fail "A5 ${label}: single-model proxy did not return the upstream marker (got [${got}], body: ${body})"
    axis_failed=1
  fi

  # Cohere-format ingress (engine-inline) against the openai-protocol pool: A5's pool leg stays a
  # real CROSS-PROTOCOL translation through the IR, which is what the anthropic-format leg proved
  # before that dialect became an extracted crate.
  body="$(curl -s "${D}/v2/chat" -H "Authorization: Bearer ${token}" \
            -H 'Content-Type: application/json' \
            -d '{"model":"main","messages":[{"role":"user","content":"hello"}]}')"
  got="$(printf '%s' "$body" | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["message"]["content"][0]["text"])
except Exception: print("")')"
  printf 'POST data/pool %s\n' "$(code "${D}/v2/chat" -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' -d '{"model":"main","messages":[{"role":"user","content":"hello"}]}')" >>"${out}/probe.txt"
  if [ "$got" = "$marker" ]; then
    ok "A5 ${label}: POOL route (hooks: [weighted], the inline SWRR floor) proxied end-to-end"
  else
    fail "A5 ${label}: pool proxy did not return the upstream marker (got [${got}], body: ${body})"
    axis_failed=1
  fi

  for p in stats metrics; do
    c="$(code "${D}/${p}" -H "Authorization: Bearer ${token}")"
    printf 'GET data/%s %s\n' "$p" "$c" >>"${out}/probe.txt"
  done

  # The self-report of what IS compiled in — deliberately EXCLUDED from the diffed probe vector and
  # asserted separately.
  curl -s "${A}/info" | python3 -c 'import sys,json
d = json.load(sys.stdin).get("build", {})
print(json.dumps(d, sort_keys=True))' >"${out}/build.txt"

  # A6 — still alive after serving all of that.
  if kill -0 "$pid" 2>/dev/null; then
    ok "A6 ${label}: process still alive after serving the full probe set"
  else
    fail "A6 ${label}: process DIED while serving (log: $(tail -5 "${work}/busbar.log" | tr '\n' ' '))"
    axis_failed=1
  fi

  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  return "$axis_failed"
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
# SELF-TEST — prove the gate cannot be lied to before its verdict on the tree is trusted.
# ══════════════════════════════════════════════════════════════════════════════════════════════════
#
# RED-A / RED-B are the REAL featureless binary carrying a REAL dependency on a compiled-out plugin,
# introduced in the fixture config. If the gate's A1 could not see those, its green on the tree would
# mean nothing.
#
# RED-C / RED-D are stub servers. Each passes every assertion BEFORE the one it breaks, so it proves
# the LATER assertion is load-bearing:
#   RED-C  boots, /healthz 200, admin plane fully answers — but the PROXY path 502s. This is the
#          precise shape of the hole the existing `no-default-features` job cannot see: a binary that
#          compiles, boots, and looks healthy while the request path is broken.
#   RED-D  boots, /healthz 200, proxy fine — but every /api/v1/admin/* 401s forever. An admin plane
#          bricked by an absent auth module is "up" to any liveness probe.
# GREEN is the same stub with nothing broken: the gate must be SILENT on it.

# A stub "busbar": honors --validate / --generate-signing-key / --list-plugins, parses its ports out
# of the config file, and serves the gate's whole probe surface. STUB_BREAK selects what it breaks.
write_stub_busbar() {
  local path="$1" break_mode="$2"
  cat >"${path}.py" <<PYEOF
import http.server, json, os, re, sys, threading, urllib.request
BREAK  = ${break_mode@Q}

if "--generate-signing-key" in sys.argv:
    print("0" * 64); raise SystemExit(0)
if "--validate" in sys.argv:
    print("ok: config valid (stub)"); raise SystemExit(0)
if "--list-plugins" in sys.argv:
    print("no plugin tarballs found"); raise SystemExit(0)

cfg = open(os.environ["BUSBAR_CONFIG"]).read()
def port(key):
    return int(re.search(key + r':\s*"127\.0\.0\.1:(\d+)"', cfg).group(1))
LISTEN, ADMIN = port("listen"), port("admin_listen")

# The GREEN stub is a real (if minimal) proxy: it forwards to the SAME mock upstream the gate
# started and relays the marker the gate is about to assert on. A stub that echoed a hardcoded
# string would make the marker assertion untestable, which is the assertion RED-C exists to prove.
UPSTREAM = re.search(r'base_url:\s*"([^"]+)"',
                     open(re.search(r'providers_file:\s*"([^"]+)"', cfg).group(1)).read()).group(1)

def upstream_text():
    req = urllib.request.Request(UPSTREAM + "/v1/chat/completions", data=b"{}",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)["choices"][0]["message"]["content"]

def reply(h, status, body):
    raw = json.dumps(body).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)

class Data(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            return reply(self, 500 if BREAK == "healthz" else 200, {"status": "ok"})
        reply(self, 200, {})
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if BREAK == "proxy":
            return reply(self, 502, {"error": "no upstream: ranking hook absent"})
        text = upstream_text()
        if self.path.endswith("/v2/chat"):
            return reply(self, 200, {"message": {"role": "assistant",
                                                 "content": [{"type": "text", "text": text}]}})
        reply(self, 200, {"choices": [{"message": {"content": text, "role": "assistant"}}]})
    def log_message(self, *a): pass

class Admin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            return reply(self, 200, {"status": "ok"})
        if BREAK == "admin":
            return reply(self, 401, {"error": "admin auth module not available"})
        if self.path.endswith("/info"):
            return reply(self, 200, {"build": {"auth_modules": ["keys"], "hook_plugins": []}})
        reply(self, 200, {"items": []})
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if BREAK == "admin":
            return reply(self, 401, {"error": "admin auth module not available"})
        reply(self, 200, {"id": "vk_stub", "token": "stub-token"})
    def log_message(self, *a): pass

threading.Thread(
    target=http.server.ThreadingHTTPServer(("127.0.0.1", ADMIN), Admin).serve_forever,
    daemon=True,
).start()
http.server.ThreadingHTTPServer(("127.0.0.1", LISTEN), Data).serve_forever()
PYEOF
  cat >"$path" <<PYEOF
#!/usr/bin/env bash
exec python3 ${path@Q}.py "\$@"
PYEOF
  chmod +x "$path"
}

# run_axis over a fixture, with its failures diverted from the gate's own verdict.
run_fixture() {
  local what="$1" bin="$2" plugins_dir="$3" out="$4"
  SUPPRESS=1; SUPPRESSED=0
  FIXTURE_RC=0
  run_axis "selftest-${what}" "$bin" "$plugins_dir" "$out" >"${out}/log" 2>&1 || FIXTURE_RC=$?
  FIXTURE_CAUGHT=$SUPPRESSED
  SUPPRESS=0
}

expect_red() {
  local what="$1" bin="$2" plugins_dir="$3" out; out="$(new_tmpdir)"
  run_fixture "$what" "$bin" "$plugins_dir" "$out"
  if [ "$FIXTURE_CAUGHT" -gt 0 ] || [ "$FIXTURE_RC" -ne 0 ]; then
    ok "RED ${what}: the gate CAUGHT it — $(grep -m1 '\[FAIL\]' "${out}/log" | sed 's/^ *//')"
    return 0
  fi
  fail "RED ${what}: the gate stayed SILENT on a fixture it must flag (see ${out}/log)"
  return 1
}

expect_green() {
  local what="$1" bin="$2" plugins_dir="$3" out; out="$(new_tmpdir)"
  run_fixture "$what" "$bin" "$plugins_dir" "$out"
  if [ "$FIXTURE_CAUGHT" -eq 0 ] && [ "$FIXTURE_RC" -eq 0 ]; then
    ok "GREEN ${what}: the gate stayed SILENT, as it must"
    return 0
  fi
  fail "GREEN ${what}: the gate flagged a fixture that satisfies every assertion (see ${out}/log)"
  return 1
}

build_binaries() {
  local stage="$1"
  hdr "Building both axes"
  note "axis 1 — cargo build -p busbar --no-default-features --features proto-openai-chat --locked"
  cargo build -p busbar --no-default-features --features proto-openai-chat --locked
  cp "${REPO_ROOT}/target/debug/busbar" "${stage}/busbar-no-default-features"
  note "axis 2 — cargo build -p busbar --locked (DEFAULT features)"
  cargo build -p busbar --locked
  cp "${REPO_ROOT}/target/debug/busbar" "${stage}/busbar-default-features"
  ok "staged: ${stage}/busbar-no-default-features, ${stage}/busbar-default-features"
}

run_selftest() {
  hdr "no-plugins-gate SELF-TEST (the gate cannot be lied to)"
  local stage; stage="$(new_tmpdir)"
  local empty; empty="$(new_tmpdir)"
  local rc=0

  cargo build -p busbar --no-default-features --features proto-openai-chat --locked
  cp "${REPO_ROOT}/target/debug/busbar" "${stage}/busbar-no-default-features"

  # ── RED-A / RED-B: the REAL featureless binary, with a REAL core dependency on a compiled-out
  # plugin introduced into the fixture. `write_zero_plugin_config` is wrapped so the fixture's extra
  # lines land in the same config the axis then runs.
  local orig_writer; orig_writer="$(declare -f write_zero_plugin_config)"

  eval "${orig_writer/write_zero_plugin_config/write_zero_plugin_config_orig}"

  # RED-A — the config names the `admin-tokens` ADMIN AUTH plugin, which axis 1 compiled out.
  write_zero_plugin_config() {
    write_zero_plugin_config_orig "$@" || return 1
    local work="$1"
    python3 - "$work/config.yaml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("admin_auth: []", "admin_auth: [admin-tokens]")
s += "identity-providers:\n  admin-tokens: { module: admin-tokens, token: { env: SELFTEST_ADMIN_TOKEN } }\n"
open(p, "w").write(s)
PY
  }
  SELFTEST_ADMIN_TOKEN=selftest expect_red "A (real binary, config depends on the compiled-out admin-tokens auth plugin)" \
    "${stage}/busbar-no-default-features" "$empty" || rc=1

  # RED-B — the config names a `hooks-ranking` strategy, which axis 1 compiled out.
  write_zero_plugin_config() {
    write_zero_plugin_config_orig "$@" || return 1
    local work="$1"
    python3 - "$work/config.yaml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("hooks: [weighted]", "hooks: [cheapest]")
open(p, "w").write(s)
PY
  }
  expect_red "B (real binary, config depends on the compiled-out hooks-ranking plugin)" \
    "${stage}/busbar-no-default-features" "$empty" || rc=1

  # Restore the real writer for the stub fixtures.
  unset -f write_zero_plugin_config
  eval "$orig_writer"

  # ── RED-C / RED-D / GREEN: stubs that pass every EARLIER assertion and break exactly one LATER
  # one, proving the later assertions are load-bearing.
  write_stub_busbar "${stage}/stub-proxy-broken" proxy
  write_stub_busbar "${stage}/stub-admin-broken" admin
  write_stub_busbar "${stage}/stub-green"        none

  expect_red   "C (boots + /healthz 200 + admin plane fine — but the PROXY path is broken)" \
    "${stage}/stub-proxy-broken" "$empty" || rc=1
  expect_red   "D (boots + /healthz 200 + proxy fine — but the ADMIN PLANE 401s forever)" \
    "${stage}/stub-admin-broken" "$empty" || rc=1
  expect_green "(every assertion satisfied)" "${stage}/stub-green" "$empty" || rc=1

  echo
  if [ "$rc" -eq 0 ] && [ "${#FAILURES[@]}" -eq 0 ]; then
    echo "SELF-TEST PASSED — every RED fixture was caught and the GREEN fixture was not."
  else
    echo "SELF-TEST FAILED — the gate's verdict on the tree CANNOT be trusted."
    return 1
  fi
}

run_check() {
  local stage; stage="$(new_tmpdir)"
  build_binaries "$stage"

  # ONE empty directory, shared by both axes: zero plugin artifacts on disk, everywhere.
  local empty; empty="$(new_tmpdir)"
  local out1 out2; out1="$(new_tmpdir)"; out2="$(new_tmpdir)"

  run_axis "1-compiled-out"  "${stage}/busbar-no-default-features" "$empty" "$out1" || true
  run_axis "2-not-installed" "${stage}/busbar-default-features"    "$empty" "$out2" || true

  # A7 — the cross-axis assertion.
  hdr "A7: compiling every built-in plugin OUT must change NOTHING core serves"
  if [ -s "${out1}/probe.txt" ] && [ -s "${out2}/probe.txt" ]; then
    if diff -u "${out1}/probe.txt" "${out2}/probe.txt" >/dev/null; then
      ok "A7: the two axes' response-code vectors are IDENTICAL across the whole probed surface"
    else
      fail "A7: the axes DIVERGE — core serves differently with the built-in plugins compiled out:"
      diff -u "${out1}/probe.txt" "${out2}/probe.txt" | sed 's/^/      /' || true
    fi
  else
    fail "A7: one or both axes produced no probe vector (an earlier assertion failed hard)"
  fi

  # The deliberate exception: /info's `build` block exists to self-report what IS compiled in, so it
  # MUST differ. If it did not, the gate built the same binary twice and every assertion above was
  # measuring one binary against itself — vacuous.
  if [ -s "${out1}/build.txt" ] && [ -s "${out2}/build.txt" ]; then
    if diff -q "${out1}/build.txt" "${out2}/build.txt" >/dev/null; then
      fail "A7: GET /api/v1/admin/info's build block is IDENTICAL on both axes — the two axes are the same binary, so this run proved nothing"
      note "  both reported: $(cat "${out1}/build.txt")"
    else
      ok "A7: the axes are genuinely different binaries (build self-report differs, as it must)"
      note "  axis 1 (compiled out):  $(cat "${out1}/build.txt")"
      note "  axis 2 (not installed): $(cat "${out2}/build.txt")"
    fi
  fi

  echo
  if [ "${#FAILURES[@]}" -eq 0 ]; then
    echo "NO-PLUGINS GATE PASSED — with every built-in plugin compiled out (axis 1) and with zero"
    echo "plugin artifacts on disk (axis 2), busbar boots, serves /healthz, answers its admin plane"
    echo "(reads AND a write), and proxies a real request end-to-end to a real upstream. Each of those"
    echo "is an assertion on an actual response, not an inference from a successful compile."
    return 0
  fi

  echo "NO-PLUGINS GATE FAILED — ${#FAILURES[@]} assertion(s). Core does not work without its plugins,"
  echo "which means at least one thing busbar calls a plugin is welded into the engine:"
  local f
  for f in "${FAILURES[@]}"; do echo "  - ${f}"; done
  return 1
}

case "$MODE" in
  selftest) run_selftest ;;
  check)    run_check ;;
esac
