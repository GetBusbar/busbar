#!/usr/bin/env bash
# FIXTURE-ABSENCE GATE — the `test_*` fixtures are not in a real build.
#
# THE RULE. Test fixtures exist so a suite can drive a surface that has no production caller. A
# fixture that survives into a shipped artifact is not a test any more: it is an undocumented,
# unreviewed, unauthenticated feature with a name that tells every reader to ignore it. The MCP
# plane makes this sharper than usual, because a fixture there is a TOOL — something an agent can
# discover in `tools/list` and then CALL.
#
# GOAL-1.5.5 item 24 asks for this proof on BOTH AXES, with `scripts/no-plugins-gate.sh` as the
# template. That script's structure is copied deliberately, including the reason it has two axes at
# all: a defect can reach a shipped build two independent ways and NEITHER AXIS CAN SEE THE OTHER'S.
#
#   AXIS 1 — THE ARTIFACT.  Build the binary the way a release builds it (`--release`, default
#                           features) and read the ARTIFACT: no forbidden identifier may appear in
#                           it. This is the axis that catches a fixture compiled in behind a route
#                           nobody thought to probe, or one reachable only under a config the
#                           runtime axis never sets up. It is BLIND to a name that is assembled at
#                           run time -- `format!("test_{}", x)` leaves no matchable literal.
#
#   AXIS 2 — THE WIRE.      BOOT that same binary and read what it actually SERVES: no forbidden
#                           identifier may appear on any live surface. This is the axis that
#                           catches the assembled name axis 1 cannot see, and a fixture that is
#                           registered dynamically from a config file rather than linked in. It is
#                           BLIND to a fixture that is present in the binary but not reachable from
#                           the surfaces probed here.
#
# Neither axis is a superset of the other, which is the whole reason `--run` fails if either one is
# skipped rather than reporting on whichever it managed.
#
# THE FORBIDDEN SET IS DISCOVERED, NOT ENUMERATED, and that matters more than it looks. A
# hand-written list of fixture names is an enumeration, and an enumeration stops covering whatever
# is added after it -- silently, and while still reporting green. So the set is read out of the tree
# at run time: every `test_*` string literal that appears anywhere under `crates/*/src`. A FLOOR
# then guards the degenerate case: if the discovery finds NOTHING, the gate is vacuous and says so
# rather than passing, because "no forbidden name appears in the binary" is trivially true of an
# empty forbidden set. That is the same defect `mcp-conformance.sh` refuses when the pinned suite
# lists no required scenarios.
#
# WHAT THIS GATE SAYS TODAY, honestly. busbar's MCP plane answers `404`/`-32601` to every method,
# so there are no MCP tools of any name, fixture or otherwise. The discovered set is therefore made
# up of the hook/plugin test fixtures that DO exist in the tree. That is not a weaker gate, it is
# the same gate: it is armed, it is non-vacuous, its selftest proves it bites, and the day a
# `test_echo` tool is registered on the MCP plane it is already watching for it.
#
# USAGE
#   mcp-fixture-absence-gate.sh --run        build, boot, and assert both axes
#   mcp-fixture-absence-gate.sh --selftest   prove the gate catches a planted fixture
#   mcp-fixture-absence-gate.sh --help

set -euo pipefail
cd "$(dirname "$0")/.."

# A discovery that finds fewer than this has broken, not succeeded. Kept well below what the tree
# actually carries so it fails on a collapse rather than on ordinary movement.
MIN_FORBIDDEN=2

BIN_NAME="busbar"
say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; }
die()  { fail "$*"; exit 1; }

# ── the forbidden set ─────────────────────────────────────────────────────────────────────────────
#
# Every `test_*` string LITERAL under `crates/*/src`. String literals specifically, and not Rust
# `fn test_foo` identifiers: a test FUNCTION named `test_parses_urls` is ordinary and is compiled
# out of a release build by `#[cfg(test)]` anyway. What must never ship is a fixture whose name is
# DATA -- a tool name, a metric name, a route -- because data is what crosses the wire and what a
# caller can reach for.
discover_forbidden() {
  grep -rhoE '"test_[a-z0-9_]+"' crates/*/src 2>/dev/null \
    | tr -d '"' \
    | sort -u
}

require_forbidden_set() {
  local set count
  set="$(discover_forbidden)"
  count="$(printf '%s\n' "$set" | grep -c . || true)"
  [ "$count" -ge "$MIN_FORBIDDEN" ] || die "discovery found only $count forbidden \`test_*\` \
identifier(s), below the floor of $MIN_FORBIDDEN. An empty or collapsed forbidden set makes every \
assertion below trivially true, which is a false green and not a clean tree."
  say "  discovered $count forbidden identifier(s):"
  printf '%s\n' "$set" | sed 's/^/    /'
  printf '%s\n' "$set"
}

# ── AXIS 1: the artifact ──────────────────────────────────────────────────────────────────────────
#
# `strings` rather than `grep` on the binary: `grep` on a binary answers a yes/no about the whole
# file, and a gate that cannot NAME what it found is a gate nobody can act on.
axis_artifact() {
  local bin="$1"; shift
  local -a forbidden=("$@")
  local hits=0 id
  [ -f "$bin" ] || die "axis 1: no binary at $bin. Nothing was read, and that is red, not clean."
  for id in "${forbidden[@]}"; do
    if strings -a "$bin" 2>/dev/null | grep -qxF "$id"; then
      fail "AXIS 1 (artifact): the release binary contains the fixture identifier \`$id\`."
      hits=$((hits+1))
    fi
  done
  [ "$hits" -eq 0 ] || return 1
  say "  ok: axis 1 — ${#forbidden[@]} fixture identifier(s), none present in $bin"
}

# ── AXIS 2: the wire ──────────────────────────────────────────────────────────────────────────────
#
# Boots the SAME binary axis 1 read and drives the surfaces a caller can actually reach, then reads
# everything it served. The MCP endpoint is probed by NAME even though it answers `-32601` today:
# probing it now is what makes this gate already-armed for the revision where it answers for real,
# rather than something somebody has to remember to add later.
axis_wire() {
  local bin="$1"; shift
  local -a forbidden=("$@")
  local dir port pid rc=0 id
  dir="$(mktemp -d)"
  port=18731
  admin_port=18732
  # THE CONFIG AND THE LAUNCH ARE BOTH COPIED FROM `no-plugins-gate.sh`, DELIBERATELY.
  #
  # This block previously wrote `server: { bind: ... }` and launched with `--config`. Neither
  # exists: the grammar's root keys are `listen:` / `admin_listen:`, and the config path arrives
  # through `BUSBAR_CONFIG` — there is no `--config` flag at all. So the binary exited on its
  # first argument, every run, and axis 2 has NEVER probed anything since this gate was written.
  # It surfaced only because the readiness check calls an unprobed axis RED rather than skipping
  # it; had it degraded to a skip, this would have read green forever.
  #
  # The `keys` verifier requires an explicit signing key — busbar no longer auto-generates one.
  "$bin" --generate-signing-key >"$dir/signing.key" 2>/dev/null
  [ -s "$dir/signing.key" ] || die "axis 2: --generate-signing-key produced no key"
  # A provider/model/pool set is REQUIRED by the grammar, so one is declared. It points at a port
  # nothing listens on, deliberately: this gate reads what busbar SERVES, and never routes a
  # completion, so an unreachable upstream is the honest declaration rather than a mock to maintain.
  cat >"$dir/providers.yaml" <<YAML
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:1"
YAML
  cat >"$dir/config.yaml" <<YAML
listen: "127.0.0.1:$port"
admin_listen: "127.0.0.1:$admin_port"
providers_file: "$dir/providers.yaml"
auth:
  chain: [keys]
  admin_auth: []
  signing_key: { file: "$dir/signing.key" }
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
YAML
  BUSBAR_CONFIG="$dir/config.yaml" MOCK_KEY=unused RUST_LOG=warn "$bin" >"$dir/server.log" 2>&1 &
  pid=$!
  # Readiness BY OBSERVATION, not by sleeping. Any answer proves it is listening; waiting for a 2xx
  # would make readiness depend on behaviour that is not under test here.
  local waited=0
  until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/healthz"; do
    waited=$((waited+1))
    if [ "$waited" -ge 60 ] || ! kill -0 "$pid" 2>/dev/null; then
      cat "$dir/server.log" >&2
      kill "$pid" 2>/dev/null || true
      die "axis 2: the binary never became ready. Nothing was probed, and an unprobed axis is red."
    fi
    sleep 1
  done

  : >"$dir/wire.txt"
  # `probe` hits the DATA plane; `probe_admin` hits the ADMIN plane, which listens on its own port.
  # Both are needed: the admin surface was previously probed on the data port, where it can only
  # ever 404, so its responses were never read and the identifiers could have travelled on it
  # unseen. A surface probed at the wrong address is not a probed surface.
  # `body_bytes` counts ONLY what the server actually returned, never the `--- METHOD path ---`
  # separators. That distinction is the whole point: the separators are written by `printf` before
  # curl runs, so a transcript containing nothing but separators is non-empty, and a `[ -s ]` check
  # over this file can never fail. Counting response bytes is what makes the floor below real.
  body_bytes=0
  probe_to() {
    local base="$1" method="$2" path="$3" data="${4:-}"
    printf '\n--- %s %s (%s) ---\n' "$method" "$path" "$base" >>"$dir/wire.txt"
    : >"$dir/body.tmp"
    curl -s --max-time 5 -X "$method" "$base$path" \
      -H 'content-type: application/json' ${data:+-d "$data"} >"$dir/body.tmp" 2>&1 || true
    body_bytes=$((body_bytes + $(wc -c <"$dir/body.tmp")))
    cat "$dir/body.tmp" >>"$dir/wire.txt"
  }
  probe()       { probe_to "http://127.0.0.1:$port"       "$@"; }
  probe_admin() { probe_to "http://127.0.0.1:$admin_port" "$@"; }
  probe GET  /healthz
  probe GET  /metrics
  probe_admin GET /api/v1/admin/info
  probe_admin GET /api/v1/admin/tools
  probe GET  /.well-known/oauth-protected-resource
  probe POST /mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
  probe POST /mcp '{"jsonrpc":"2.0","id":2,"method":"server/discover"}'

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  # THE PREMISE, PROVEN RATHER THAN ASSUMED. If the probes captured nothing, every assertion below
  # holds vacuously. Same reasoning as no-plugins-gate proving its plugins dir is really empty.
  #
  # A FLOOR ON RESPONSE BYTES, not `[ -s wire.txt ]`. The previous check could not fail: `probe`
  # writes its `--- METHOD path ---` separator before curl runs, so the file is non-empty even when
  # every single probe returns nothing — which is exactly the state this gate spent its whole life
  # in, since it was launching the binary with a flag that does not exist. `/healthz` and
  # `/metrics` alone answer with far more than this; the floor is set low enough to never be
  # load-bearing on response FORMAT and high enough that a wholesale probe failure is red.
  readonly MIN_WIRE_BYTES=200
  [ "$body_bytes" -ge "$MIN_WIRE_BYTES" ] || die "axis 2: the probes captured only ${body_bytes} \
response byte(s), under the ${MIN_WIRE_BYTES}-byte floor. A wire assertion over an empty \
transcript is not an assertion."

  for id in "${forbidden[@]}"; do
    if grep -qF "$id" "$dir/wire.txt"; then
      fail "AXIS 2 (wire): the running binary served the fixture identifier \`$id\`."
      rc=1
    fi
  done
  [ "$rc" -eq 0 ] || return 1
  say "  ok: axis 2 — ${#forbidden[@]} fixture identifier(s), none on any probed live surface"
}

run_gate() {
  hdr "FIXTURE-ABSENCE GATE"
  # Read with `read -r` rather than `mapfile`, which is bash 4+ and absent from the bash macOS
  # ships. A gate that only runs on the CI runner cannot be exercised by hand, and a gate nobody
  # can watch fail is a gate nobody has evidence works.
  local -a forbidden=()
  local line
  while IFS= read -r line; do
    [ -n "$line" ] && forbidden+=("$line")
  done < <(require_forbidden_set | grep -E '^test_')

  hdr "building the release artifact (default features, exactly as a release builds it)"
  cargo build --release --locked -p "$BIN_NAME" 2>&1 | tail -5
  local bin="target/release/$BIN_NAME"

  local failed=0
  hdr "AXIS 1 — THE ARTIFACT"
  axis_artifact "$bin" "${forbidden[@]}" || failed=1
  hdr "AXIS 2 — THE WIRE"
  axis_wire "$bin" "${forbidden[@]}" || failed=1

  # BOTH, never whichever ran. A gate that reports on the axis it managed is a gate that quietly
  # halves itself the first time the other axis breaks.
  [ "$failed" -eq 0 ] || die "at least one axis found a test fixture in a real build."
  say ""
  say "fixture-absence: both axes clean."
}

# ── selftest ──────────────────────────────────────────────────────────────────────────────────────
#
# Fixtures the gate MUST flag, plus ones it must stay silent on -- the discipline
# `no-plugins-gate.sh` and `settings-leak-lint.sh` established. Without this, both axes could be
# silently broken and the gate would report a confident green forever. The stand-ins are real files
# and a real process, not mocks of the assertion.
run_selftest() {
  hdr "FIXTURE-ABSENCE GATE SELF-TEST"
  local failures=0
  # NOT `local`, and not an EXIT trap on a local: an EXIT trap fires after the function's locals
  # are gone, which turned a passing self-test into `unbound variable` and an exit 1 -- a false RED,
  # which is the same disease as a false green in a different coat.
  SELFTEST_TMP="$(mktemp -d)"
  trap 'rm -rf "$SELFTEST_TMP"' EXIT
  local tmp="$SELFTEST_TMP"

  # RED 1: an artifact that CONTAINS a forbidden identifier must be caught. Written as a real file
  # read by the real `strings`-based assertion.
  printf 'harmless\ntest_planted_fixture\nmore\n' >"$tmp/dirty.bin"
  if ( axis_artifact "$tmp/dirty.bin" test_planted_fixture ) >/dev/null 2>&1; then
    say "  MISS: axis 1 accepted a binary containing a planted fixture"; failures=$((failures+1))
  else
    say "  ok: axis 1 catches a planted fixture in the artifact"
  fi

  # GREEN 1: and it must stay silent on one that does not, or RED 1 proves only that it refuses
  # everything.
  printf 'harmless\nnothing_to_see\n' >"$tmp/clean.bin"
  if ( axis_artifact "$tmp/clean.bin" test_planted_fixture ) >/dev/null 2>&1; then
    say "  ok: axis 1 passes a clean artifact"
  else
    say "  MISS: axis 1 refused a clean artifact — it refuses everything and proves nothing"
    failures=$((failures+1))
  fi

  # RED 2: a MISSING artifact must be red, not clean. "There was nothing to read" is the single
  # most common way a check like this reports success having executed nothing.
  if ( axis_artifact "$tmp/does-not-exist" test_planted_fixture ) >/dev/null 2>&1; then
    say "  MISS: axis 1 passed with no binary to read at all"; failures=$((failures+1))
  else
    say "  ok: axis 1 is RED when there is no artifact to read"
  fi

  # RED 3: the FLOOR on the discovered set. An empty forbidden set makes every assertion in this
  # file trivially true, which is a false green wearing the clothes of a clean tree.
  if ( MIN_FORBIDDEN=999999 require_forbidden_set ) >/dev/null 2>&1; then
    say "  MISS: a collapsed forbidden set was accepted"; failures=$((failures+1))
  else
    say "  ok: a forbidden set below the floor is refused"
  fi

  # GREEN 2: discovery must actually FIND the fixtures this tree carries. A floor is only a floor
  # if the real tree clears it.
  local found
  found="$(discover_forbidden | grep -c . || true)"
  if [ "$found" -ge "$MIN_FORBIDDEN" ]; then
    say "  ok: discovery finds $found forbidden identifier(s) in this tree"
  else
    say "  MISS: discovery found $found identifier(s) in a tree that has fixtures"
    failures=$((failures+1))
  fi

  # RED 4: axis 2 must be RED on an empty transcript. Proven by pointing it at a port nothing is
  # listening on, which is the shape a crashed boot leaves behind.
  if ( axis_wire /nonexistent/binary test_planted_fixture ) >/dev/null 2>&1; then
    say "  MISS: axis 2 passed without ever reaching a running binary"; failures=$((failures+1))
  else
    say "  ok: axis 2 is RED when it never reached a running binary"
  fi

  [ "$failures" -eq 0 ] || die "$failures self-test fixture(s) did not behave as declared"
  say "  self-test: 6 fixture(s) passed"
}

case "${1:---help}" in
  --run)      run_gate ;;
  --selftest) run_selftest ;;
  --help|-h)  sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown mode: $1 (try --help)" ;;
esac
