#!/usr/bin/env bash
# Response-header lint — durable CI guard for the busbar response-header consolidation.
#
# WHAT THIS GUARDS AGAINST:
#   Every response header BUSBAR ITSELF INJECTS (as opposed to one it relays/translates from an
#   upstream) must be an opt-in `advanced.response_headers` toggle, default OFF, emitted from exactly
#   ONE sanctioned site per header. Before this consolidation:
#     - `busbar;dur` (Server-Timing) WAS gated by a config flag, but the middleware that computes it
#       (`main.rs::server_timing`) unconditionally paid an `Arc<AtomicU64>` allocation, an
#       `Instant::now()`, and a task-local `.scope()` on EVERY request even with the flag off — the
#       guard was inside the function, after the cost was already paid.
#     - `x-busbar-route-policy` / `x-busbar-route-target` (`proxy/wire.rs::maybe_attach_route_policy`)
#       had NO config gate at all: they fired unconditionally whenever a non-default routing policy
#       chose the lane.
#   Both are now unified under `advanced.response_headers` (`config/mod.rs::ResponseHeadersCfg`),
#   default `false`, with `server_timing` COMPOSED out of the router entirely when disabled (not just
#   internally suppressed) and `route_policy` gated by a single process-wide check at its one emission
#   site. This script is the "can't-forget" guarantee: a NEW busbar-injected header, or a NEW
#   hand-rolled emission of an EXISTING one outside its sanctioned site, fails CI instead of silently
#   shipping unconditionally-on (or, worse, ungated and unconditionally on).
#
# WHAT IT SCANS: every literal Rust source pattern that WRITES one of these headers onto a response —
# the response-header equivalent of structure-lint.sh's choke-point registry, but standalone,
# mirroring how `release-script-lint.sh` is its own small, single-purpose sibling next to the bigger
# `structure-lint.sh`.
#
# Runs in CI (see .github/workflows/ci.yml, structure-lint job). No external deps; bash 3.2 + POSIX
# awk (macOS/Linux). `--selftest` proves the scanner still catches a real bypass before its verdict on
# the tree is trusted (same discipline as structure-lint.sh / release-script-lint.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── THE TEST-SCOPE SCANNER (verbatim from scripts/structure-lint.sh) ───────────────────────────────
# Decides which lines are `#[cfg(test)]`-gated (a test assertion that READS a response header back,
# e.g. `r.headers().get("server-timing")`, is not an injection site) or whole-line comments (prose
# that merely NAMES a header is not code). Borrowed rather than re-derived: structure-lint.sh's own
# `--selftest` already proves this scanner cannot be lied to by a doc comment or a braceless
# `#[cfg(test)]` item, and a second hand-rolled copy here would be a second place for that proof to
# rot out of sync. See structure-lint.sh's header comment for the two bugs this fixes.
TEST_SCOPE_AWK='
  function _codeof(s,   c) {
    if (s ~ /^[[:space:]]*\/\//) return ""
    c = s
    if (index(c, "\"") == 0) sub(/\/\/.*$/, "", c)
    return c
  }
  function _braces(s,   o, c) { o = gsub(/\{/, "{", s); c = gsub(/\}/, "}", s); return o - c }

  FNR==1 { in_test=0; pending=0; pend_age=0; depth=0 }
  {
    is_comment = ($0 ~ /^[[:space:]]*\/\//)
    code = _codeof($0)
    gated = 0

    if (in_test) {
      gated = 1
      depth += _braces(code)
      if (depth <= 0) { in_test = 0; depth = 0 }
    } else if (pending) {
      gated = 1
      if (code ~ /^[[:space:]]*$/ || code ~ /^[[:space:]]*#\[/) {
        pend_age++
      } else if (index(code, "{") > 0) {
        pending = 0
        depth = _braces(code)
        if (depth > 0) in_test = 1; else depth = 0
      } else if (code ~ /;[[:space:]]*$/) {
        pending = 0
      } else {
        pend_age++
      }
      if (pending && pend_age > 10) { pending = 0; pend_age = 0 }
    }

    if (!in_test && !pending && code ~ /^[[:space:]]*#\[cfg\(/ \
        && code ~ /[(,][[:space:]]*test[[:space:]]*[,)]/ \
        && code !~ /not[[:space:]]*\([[:space:]]*test[[:space:]]*\)/) {
      gated = 1
      rest = code
      sub(/^[[:space:]]*#\[cfg\(.*\)\][[:space:]]*/, "", rest)
      if (rest ~ /^[[:space:]]*$/)      { pending = 1; pend_age = 0 }
      else if (index(rest, "{") > 0)    { depth = _braces(rest); if (depth > 0) in_test = 1; else depth = 0 }
      else if (rest ~ /;[[:space:]]*$/) { }
      else                              { pending = 1; pend_age = 0 }
    }
  }
'

# One awk pass per rule: skip gated/comment lines, skip the rule'\''s allowed-exception files, flag the
# rest. `LINT_PAT`/`LINT_WHAT`/`LINT_ALLOW` arrive via the environment (not -v) so the ERE is not
# escape-processed by awk's -v handling.
scan_rule() {
  awk "$TEST_SCOPE_AWK"'
    gated || is_comment { next }
    { n = split(ENVIRON["LINT_ALLOW"], allow, ",") }
    { skip = 0; for (i = 1; i <= n; i++) if (FILENAME == allow[i]) skip = 1 }
    skip { next }
    $0 ~ ENVIRON["LINT_PAT"] { printf "%s:%d: %s\n", FILENAME, FNR, ENVIRON["LINT_WHAT"] }
  ' "$@"
}

# ── THE RULE TABLE ───────────────────────────────────────────────────────────────────────────────
# One row per busbar-injected header (or header-writing idiom). `pattern` is an ERE matched against
# CODE (comments/tests already excluded); `what` is the printed violation label; `allow` is the
# comma-separated list of the header's ONE sanctioned definition/emission file(s).
SRC_DIR="crates/busbar/src"
HDR_ROUTE_POLICY_FILE="${SRC_DIR}/proxy/mod.rs"
HDR_ROUTE_WIRE_FILE="${SRC_DIR}/proxy/wire.rs"
HDR_SERVER_TIMING_FILE="${SRC_DIR}/main.rs"

# Candidate set: every busbar .rs file except integration-test-only trees (`*/tests/*`, name-navigated
# and exempt from every choke-point rule the same way structure-lint.sh treats them).
CANDIDATES=()
while IFS= read -r f; do CANDIDATES+=("$f"); done < <(find "$SRC_DIR" -name '*.rs' -not -path '*/tests/*' | sort)

# ── SCAN FLOOR — every rule below is "for each candidate file, assert the header has ONE gated
# site", which is VACUOUSLY TRUE over zero candidates: `scan_rule` with no file arguments does not
# even scan the tree, it reads stdin (empty in CI), and every rule prints `ok`. Rename or move
# `crates/busbar/src` and this lint passes forever having opened nothing. The floor is not `> 0`
# — one surviving file is as vacuous as none — it tracks the real tree (123 files when written).
SCAN_FLOOR=100
if [ "${#CANDIDATES[@]}" -lt "$SCAN_FLOOR" ]; then
  hdr "result"
  note "response-header-lint FAILED — SCAN ROOT EMPTY OR MOVED"
  note "found ${#CANDIDATES[@]} non-test .rs files under ${SRC_DIR}, expected >= ${SCAN_FLOOR}."
  note "This lint scanned (almost) nothing, so its verdict is meaningless — it is NOT a pass."
  note "If the engine crate legitimately moved, update SRC_DIR above AND this floor together."
  exit 1
fi
# The rule table names the ONE sanctioned emission site per header. If one of those files no longer
# exists the table is stale and its `allow` column can no longer describe reality — fail loudly
# rather than let the allowlist quietly match nothing.
for _hdr_file in "$HDR_ROUTE_POLICY_FILE" "$HDR_ROUTE_WIRE_FILE" "$HDR_SERVER_TIMING_FILE"; do
  if [ ! -f "$_hdr_file" ]; then
    hdr "result"
    note "response-header-lint FAILED — sanctioned emission site missing: ${_hdr_file}"
    note "The rule table's allowlist names a file that no longer exists; update the table."
    exit 1
  fi
done
note "scan set: ${#CANDIDATES[@]} files under ${SRC_DIR} (floor ${SCAN_FLOOR})"

fail=0

check_rule() {
  local id="$1" pattern="$2" what="$3" allow="$4"
  hdr "$id"
  export LINT_PAT="$pattern" LINT_WHAT="$what" LINT_ALLOW="$allow"
  local hits
  hits=$(scan_rule "${CANDIDATES[@]}" || true)
  if [ -n "$hits" ]; then
    while IFS= read -r h; do note "UNGATED-HEADER: $h — route through ${allow}"; done <<<"$hits"
    fail=1
  else
    note "ok"
  fi
}

run_checks() {
  # Rule 1: the `x-busbar-route-policy` literal — only its `const` definition (proxy/mod.rs) may spell
  # it out; every emission site must go through the const (proxy/wire.rs owns the one emission call).
  check_rule "x-busbar-route-policy literal" \
    '"x-busbar-route-policy"' \
    'raw x-busbar-route-policy string literal outside its HDR_ROUTE_POLICY const definition' \
    "$HDR_ROUTE_POLICY_FILE"

  # Rule 2: same for the sibling header.
  check_rule "x-busbar-route-target literal" \
    '"x-busbar-route-target"' \
    'raw x-busbar-route-target string literal outside its HDR_ROUTE_TARGET const definition' \
    "$HDR_ROUTE_POLICY_FILE"

  # Rule 3: the route-policy headers may be WRITTEN (`.header(HDR_ROUTE_*, ...)`) from exactly one
  # function (`maybe_attach_route_policy` / its pure core, both in proxy/wire.rs) — the function that
  # gates them on `advanced.response_headers.route_policy`. A second write site would bypass that gate.
  check_rule "x-busbar-route-* emission site" \
    '\.header\(HDR_ROUTE_' \
    'x-busbar-route-* header write outside proxy::wire::maybe_attach_route_policy (bypasses the route_policy config gate)' \
    "$HDR_ROUTE_WIRE_FILE"

  # Rule 4: `server-timing` — the header NAME literal is only declared once (main.rs's
  # HEADER_SERVER_TIMING const, used by the ALSO-in-main.rs `server_timing` middleware it is stamped
  # from).
  check_rule "server-timing literal" \
    '"server-timing"' \
    'raw server-timing string literal outside HEADER_SERVER_TIMING (main.rs)' \
    "$HDR_SERVER_TIMING_FILE"

  # Rule 5: the `busbar;dur=` Server-Timing VALUE shape — only `server_timing` (main.rs) may format
  # it; a second formatter would be a second, ungated Server-Timing emission site.
  check_rule "busbar;dur= value shape" \
    'busbar;dur=' \
    'busbar;dur= Server-Timing value formatted outside main.rs::server_timing' \
    "$HDR_SERVER_TIMING_FILE"
}

# ── SELF-TEST — prove the scanner still catches a real bypass before trusting its verdict ──────────
run_selftest() {
  hdr "response-header-lint SELF-TEST (the UNGATED-HEADER scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 pass=0

  # RED: a hand-rolled bypass of EVERY rule in one fixture file, none in the allowlist.
  cat >"${tmp}/red.rs" <<'RED'
fn bypass(rb: axum::http::response::Builder) -> axum::http::response::Builder {
    let policy = "x-busbar-route-policy";
    let target = "x-busbar-route-target";
    let rb = rb.header(HDR_ROUTE_POLICY, "cheapest");
    let st = "server-timing";
    let v = format!("busbar;dur={}", 1.0);
    rb
}
RED
  local red_n=0
  for pat in '"x-busbar-route-policy"' '"x-busbar-route-target"' '\.header\(HDR_ROUTE_' '"server-timing"' 'busbar;dur='; do
    export LINT_PAT="$pat" LINT_WHAT=probe LINT_ALLOW="nonexistent.rs"
    hits=$(scan_rule "${tmp}/red.rs" || true)
    [ -n "$hits" ] && red_n=$((red_n+1))
  done
  if [ "$red_n" -eq 5 ]; then
    pass=$((pass+1)); note "RED: all 5 rules flagged the hand-rolled bypass file"
  else
    fail=1; note "RED FAILED: expected 5/5 rules to flag the bypass file, got ${red_n}/5"
  fi

  # GREEN: the same bypass file IS the allowlisted owner — must NOT be flagged (the sanctioned site).
  local green_n=0
  for pat in '"x-busbar-route-policy"' '"x-busbar-route-target"' '\.header\(HDR_ROUTE_' '"server-timing"' 'busbar;dur='; do
    export LINT_PAT="$pat" LINT_WHAT=probe LINT_ALLOW="${tmp}/red.rs"
    hits=$(scan_rule "${tmp}/red.rs" || true)
    [ -z "$hits" ] && green_n=$((green_n+1))
  done
  if [ "$green_n" -eq 5 ]; then
    pass=$((pass+1)); note "GREEN: all 5 rules stayed silent once the file is the allowlisted owner"
  else
    fail=1; note "GREEN FAILED: expected 5/5 rules silent once allowlisted, got ${green_n}/5"
  fi

  # GREEN: a whole-line comment merely NAMING a header, and a #[cfg(test)] body reading one back, are
  # both exempt — the same "prose/tests are not injection" contract structure-lint.sh proves.
  cat >"${tmp}/green.rs" <<'GREEN'
// The x-busbar-route-policy header names the deciding policy.
#[cfg(test)]
mod tests {
    #[test]
    fn reads_it_back() {
        let v = "x-busbar-route-policy";
        let _ = v;
    }
}
GREEN
  export LINT_PAT='"x-busbar-route-policy"' LINT_WHAT=probe LINT_ALLOW="nonexistent.rs"
  hits=$(scan_rule "${tmp}/green.rs" || true)
  if [ -z "$hits" ]; then
    pass=$((pass+1)); note "GREEN: a comment mention + a #[cfg(test)] read-back are both exempt"
  else
    fail=1; note "GREEN FAILED: comment/test exemption did not hold: $hits"
  fi

  note "self-test: ${pass}/3 fixture groups passed"
  if [ "$fail" -ne 0 ]; then
    note "response-header-lint SELF-TEST FAILED — the scanner would let a bypass through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

hdr "response-header consolidation: every busbar-injected header has ONE gated site"
run_checks

hdr "result"
if [ "$fail" -ne 0 ]; then
  note "response-header-lint FAILED"
  note "every busbar-injected response header must be emitted from its ONE sanctioned, config-gated"
  note "site (see the rule table's 'route through' hint above) — never hand-rolled elsewhere."
  exit 1
fi
note "response-header-lint passed"
