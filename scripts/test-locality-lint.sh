#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# test-locality-lint.sh -- TESTS LIVE IN THEIR OWN FILE. No inline `#[cfg(test)] mod X { ... }`
# bodies in a source file under `crates/*/src/`.
#
# THE RULE, and why it is worth a lint rather than a code-review habit.
#
# The owner's rationale is that it "keeps code file length honest and easier to compare". That is
# not an aesthetic preference; it is a correctness property of every judgement anyone makes about
# this tree from a line count, and it has ALREADY corrupted one investigation. `overlay.rs` was
# reported at 2,111 lines and reasoned about against `migrate.rs` at 2,379, concluding things about
# which file was more bloated and which deserved splitting. The real overlay figure was 607 lines of
# CODE and 919 lines of TESTS. The comparison that started that whole thread was an artifact of the
# convention violation, not a fact about the code. A `wc -l` that silently means two different
# things in two different files is a measuring instrument that lies, and every structure decision
# downstream of it inherits the lie -- including `structure-lint.sh`'s own 2,500-line ceiling, whose
# grandfather list is populated by exactly this measurement.
#
# WHAT IT FLAGS: a `#[cfg(test)]` (or `#[cfg(all(test, ...))]`) attribute whose next non-blank,
# non-attribute line opens a module BODY -- `mod NAME {`. That is the violation.
#
# WHAT IT DOES NOT FLAG, deliberately:
#   * `#[cfg(test)] #[path = "tests/foo.rs"] mod foo;` -- the DECLARATION form. This is the fix, not
#     the violation: it keeps the module a direct child so `use super::*` still resolves, while the
#     body lives in `tests/`.
#   * `#[cfg(test)]` on a fn, impl, const, use, or struct -- a test-only HELPER next to the thing it
#     helps is fine and often necessary (it may need private access the tests file cannot reach).
#   * anything already under a `tests/` directory -- that is where tests belong.
#
# THE ALLOW MARKER, same shape as `settings-leak-lint.sh` and `public-hygiene-lint.py`:
#     // test-locality-lint: allow -- <reason naming the PRIVATE ITEM that forced it>
# on the line above the `#[cfg(test)]`. An inline module can reach private items an external one
# cannot, so there is a legitimate case. The honest fixes, in order of preference, are `pub(crate)`,
# a `#[cfg(test)] pub(crate)` accessor, and only then leaving the test inline with a marker. The
# marker must NAME the private item, because "it needs private access" with no referent is how an
# allowlist becomes a rubber stamp. A marker is NOT a licence to move a whole suite inline: it
# covers the one module it sits above.
#
# GRANDFATHERED, and why that is not a blanket exemption. This lint is RED against most of the tree:
# 78 files across the workspace carry an inline body, and moving all of them in a FIX release would
# be a large, risky, zero-behaviour-change diff landing under release pressure -- the exact way a
# real regression gets introduced while chasing a lint. So pre-existing debt is ledgered below, the
# same mechanic `structure-lint.sh` already uses for its oversized-file and test-locality debt.
#
# The ledger only SHRINKS. A PR that adds an entry for NEW code is not a fix, it is evading the
# check, and `--selftest` proves the lint still goes red on a planted violation in a NON-ledgered
# file. Critically, NOTHING under `crates/busbar/src/config/` is ledgered: that directory was the
# outlier the rule was written for and it is fixed in the commit before this one. A blanket
# exemption for it would have made this lint decoration.
set -uo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }
red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }

# -- THE SCANNER ---------------------------------------------------------------------------------
# One awk pass per file, a three-state walk:
#   armed=0  nothing pending
#   armed=1  a `#[cfg(test)]`-family attribute was seen; the NEXT meaningful line decides
# While armed, further `#[...]` attribute lines (e.g. a `#[path = ...]`) and blank lines are
# TRANSPARENT -- they neither disarm nor decide -- because the declaration form legitimately puts a
# `#[path]` between the cfg and the `mod`. A `mod NAME {` while armed is the violation; a
# `mod NAME;` while armed is the sanctioned declaration; anything else disarms.
#
# `#[cfg(not(test))]` must never arm: it is the exact opposite predicate, and matching it would make
# the lint fire on production-only code.
SCAN_AWK='
  FNR==1 { armed=0; allow=0; prev_allow=0 }
  {
    line = $0
    is_comment = (line ~ /^[[:space:]]*(\/\/|\*|\/\*)/)
    # An allow marker carries forward across the comment BLOCK it starts (a reason naming a private
    # item rarely fits on one line) and is consumed by the next attribute/item it sits above.
    if (line ~ /test-locality-lint:[[:space:]]*allow/) { prev_allow = 1; next }
    if (is_comment) { next }
    if (line ~ /^[[:space:]]*$/) { next }

    # A cfg-test-family attribute ARMS. `#[cfg(not(test))]` is explicitly excluded.
    # `test` is bounded by an explicit character class rather than `\b`: macOS `awk` is POSIX and
    # silently never matches `\b`, which made an earlier draft of this scanner report ZERO hits on a
    # file full of violations. The class also keeps `#[cfg(feature = "attest")]` from arming.
    if (line ~ /^[[:space:]]*#\[cfg\(/ && line ~ /[(,[:space:]]test[),[:space:]]/ && line !~ /not[[:space:]]*\([[:space:]]*test/) {
      armed = 1; allow = prev_allow; prev_allow = 0; next
    }
    if (armed) {
      # Any other attribute is transparent while armed (the `#[path = "..."]` of the fix form).
      if (line ~ /^[[:space:]]*#\[/) { next }
      # A module BODY -- a CANDIDATE. Whether it is a violation depends on what is inside it; see
      # the collector below.
      if (line ~ /^[[:space:]]*(pub[[:space:]]*(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\{/) {
        if (!allow) {
          collecting = 1; has_test = 0; start = FNR
          # The module closes at the first line that is a lone `}` at the SAME indent as its `mod`.
          # rustfmt guarantees that shape and CI enforces `cargo fmt --check`, so this is exact
          # rather than heuristic -- and it is immune to braces inside strings and comments, which
          # naive depth counting is not.
          indent = line; sub(/[^[:space:]].*$/, "", indent)
          close_re = "^" indent "\\}"
        }
      }
      armed = 0; allow = 0; next
    }
    prev_allow = 0
  }
  # -- the collector: decide a candidate module by whether it actually CONTAINS tests -------------
  # A `#[cfg(test)] mod X { ... }` holding `#[test]` functions is a TEST SUITE and belongs in its
  # own file. A `#[cfg(test)] pub(crate) mod X { ... }` holding no tests is test-only MACHINERY --
  # `taxonomy::observed` (the witness registry), `telemetry::drain_serial` (a drain lock),
  # `hostlog::log_tap` -- referenced BY tests from production code paths. Moving those out would be
  # wrong: they are not tests, and an earlier draft of this lint flagged all three.
  collecting {
    if ($0 ~ /^[[:space:]]*#\[(tokio::)?test[]\(]/ || $0 ~ /^[[:space:]]*#\[test_case/) { has_test = 1 }
    if (FNR > start && $0 ~ close_re) {
      if (has_test) {
        printf "%s:%d: inline `#[cfg(test)] mod ... { }` test suite -- move it to tests/<name>.rs and keep a `#[cfg(test)] #[path = \"tests/<name>.rs\"] mod <name>;` declaration\n", FILENAME, start
      }
      collecting = 0
    }
  }
'
scan() { awk "$SCAN_AWK" "$@"; }

# -- THE SHRINK-ONLY LEDGER OF PRE-EXISTING DEBT --------------------------------------------------
# Every file here carried an inline test body BEFORE this lint existed. Shrinking this list is the
# only permitted edit. NOTHING under crates/busbar/src/config/ appears, on purpose.
GRANDFATHERED="
crates/api/src/auth.rs
crates/api/src/durable.rs
crates/api/src/redacted.rs
crates/api/src/signal.rs
crates/api/src/store.rs
crates/auth-admin-tokens/src/lib.rs
crates/auth-static-plugin/src/lib.rs
crates/busbar/src/admin/audit.rs
crates/busbar/src/admin/mod.rs
crates/busbar/src/admin/rate.rs
crates/busbar/src/admin/transport.rs
crates/busbar/src/admin/v1/json/handlers.rs
crates/busbar/src/admin/v1/service.rs
crates/busbar/src/admin/versions.rs
crates/busbar/src/auth/exchange.rs
crates/busbar/src/auth_cache.rs
crates/busbar/src/billing.rs
crates/busbar/src/breaker.rs
crates/busbar/src/egress_auth/bearer_token.rs
crates/busbar/src/egress_auth/jwt_bearer.rs
crates/busbar/src/egress_auth/oauth_client_credentials.rs
crates/busbar/src/endpoints.rs
crates/busbar/src/eventstream.rs
crates/busbar/src/governance/mod.rs
crates/busbar/src/governance/revocation.rs
crates/busbar/src/governance/signing.rs
crates/busbar/src/handlers/anthropic.rs
crates/busbar/src/handlers/bedrock.rs
crates/busbar/src/handlers/chat.rs
crates/busbar/src/handlers/cohere.rs
crates/busbar/src/handlers/gemini.rs
crates/busbar/src/handlers/openai.rs
crates/busbar/src/handlers/responses.rs
crates/busbar/src/health.rs
crates/busbar/src/hooks/wire.rs
crates/busbar/src/ingress/dispatch.rs
crates/busbar/src/ir/audio.rs
crates/busbar/src/ir/embeddings.rs
crates/busbar/src/ir/image.rs
crates/busbar/src/ir/moderation.rs
crates/busbar/src/ir/rerank.rs
crates/busbar/src/ir/variant.rs
crates/busbar/src/json.rs
crates/busbar/src/limits/admission.rs
crates/busbar/src/lossless.rs
crates/busbar/src/media.rs
crates/busbar/src/metrics.rs
crates/busbar/src/net_guard.rs
crates/busbar/src/observability.rs
crates/busbar/src/operation.rs
crates/busbar/src/profile.rs
crates/busbar/src/proto/detect.rs
crates/busbar/src/proto/openai_family.rs
crates/busbar/src/proto/stream.rs
crates/busbar/src/proxy/engine/mod.rs
crates/busbar/src/proxy/lazy_body.rs
crates/busbar/src/proxy/wire.rs
crates/busbar/src/sigv4.rs
crates/busbar/src/tls.rs
crates/hooks-ranking/src/lib.rs
crates/plugin-abi/src/auth.rs
crates/plugin-abi/src/export.rs
crates/plugin-abi/src/hook.rs
crates/plugin-abi/src/http_endpoint.rs
crates/plugin-abi/src/lib.rs
crates/plugin-loader/src/auth.rs
crates/plugin-loader/src/fetch.rs
crates/plugin-loader/src/hook.rs
crates/plugin-loader/src/lib.rs
crates/plugin-loader/src/registry.rs
crates/plugin-loader/src/stage.rs
crates/plugin-loader/src/tarball.rs
crates/plugin-pack/src/main.rs
crates/plugin-sdk/src/lib.rs
crates/plugin-sign/src/lib.rs
crates/plugin-testkit/src/lib.rs
crates/secret-ref/src/lib.rs
crates/store-memory/src/lib.rs
"
# Pure-shell exact-line membership, deliberately NOT the `printf '%s\n' "$LIST" | grep -qx "$1"`
# spelling its sibling lints use.
#
# THE HAZARD IN THAT SPELLING: `grep -q` exits the instant it matches. If the ledger is larger than
# the pipe buffer, `printf` still has bytes to write, takes SIGPIPE, and exits 141 -- and under
# `pipefail` the PIPELINE reports 141, i.e. "NOT grandfathered", precisely for the entries that
# matched EARLIEST. Measured, not theorised: with a 20,000-line ledger and the match on line 1, the
# grep spelling reported "not grandfathered" 200 times out of 200.
#
# It is LATENT at today's sizes -- this ledger is ~78 short lines, far under the 64KB pipe buffer,
# and an A/B of both spellings over this tree gave identical results on 12 runs each. It is written
# this way so it stays correct as the ledger grows or shrinks, because the failure mode is a gate
# that silently reports a KNOWN file as a fresh violation, which is exactly the flakiness that
# teaches people to re-run a red gate until it passes. A `case` glob has no subprocess and no pipe.
is_grandfathered() {
  case "
$GRANDFATHERED
" in
    *"
$1
"*) return 0 ;;
  esac
  return 1
}

# -- SELF-TEST: prove RED on a planted violation before any verdict is trusted --------------------
run_selftest() {
  hdr "test-locality-lint SELF-TEST (prove it goes RED on a planted violation)"
  local tmp fails=0 hits n
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # RED: every inline-body spelling, including the ones the config directory actually used.
  cat >"$tmp/red.rs" <<'RED'
#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}

#[cfg(test)]
mod version_gate_tests {
    #[test]
    fn t() {}
}

#[cfg(all(test, feature = "x"))]
mod gated_tests {
    #[test]
    fn t() {}
}

#[cfg(test)]
pub(crate) mod visible_tests {
    #[test]
    fn t() {}
}
RED
  hits=$(scan "$tmp/red.rs")
  n=$(printf '%s' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 4 ]; then
    note "PASS  RED: all 4 inline-body spellings flagged (plain, named, cfg(all(test,..)), pub(crate))"
  else
    red "  FAIL  RED: expected 4 hits, got $n"; printf '%s\n' "$hits"; fails=$((fails + 1))
  fi

  # GREEN: the fix form, test-only helpers, and the opposite cfg predicate. All must stay silent.
  cat >"$tmp/green.rs" <<'GREEN'
#[cfg(test)]
#[path = "tests/overlay_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/version_gate_tests.rs"]
mod version_gate_tests;

#[cfg(test)]
pub(crate) fn helper() -> u32 { 7 }

#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
const FIXTURE: &str = "x";

#[cfg(test)]
impl Thing {
    fn probe(&self) {}
}

#[cfg(not(test))]
mod production_only {
    pub fn f() {}
}

// Test-only MACHINERY, not a test suite: no `#[test]` inside, and production code paths reference
// it. `taxonomy::observed`, `telemetry::drain_serial` and `hostlog::log_tap` are all this shape.
#[cfg(test)]
pub(crate) mod observed {
    use std::sync::Mutex;
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
    pub(crate) fn record(s: &str) {
        SEEN.lock().unwrap().push(s.to_string());
    }
}

/// A doc comment that merely MENTIONS `#[cfg(test)] mod tests {` as prose.
fn documented() {}
GREEN
  hits=$(scan "$tmp/green.rs")
  n=$(printf '%s' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 0 ]; then
    note "PASS  GREEN: declaration form, helpers, cfg(not(test)), a test-FREE machinery module, and prose all silent"
  else
    red "  FAIL  GREEN: expected 0 hits, got $n"; printf '%s\n' "$hits"; fails=$((fails + 1))
  fi

  # The ALLOW MARKER suppresses exactly the one module it sits above, and no more.
  cat >"$tmp/allow.rs" <<'ALLOW'
// test-locality-lint: allow -- reaches the private `fn raw_cursor_bytes`, which has no
// pub(crate) accessor because exposing it would widen a parsing seam that must stay internal.
#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}

#[cfg(test)]
mod not_allowed_tests {
    #[test]
    fn t() {}
}
ALLOW
  hits=$(scan "$tmp/allow.rs")
  n=$(printf '%s' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 1 ] && printf '%s' "$hits" | grep -q 'not_allowed_tests\|:10:'; then
    note "PASS  ALLOW: the marker covers ONE module; the next one is still flagged"
  else
    red "  FAIL  ALLOW: expected exactly 1 residual hit, got $n"; printf '%s\n' "$hits"; fails=$((fails + 1))
  fi

  # The ledger must not be able to hide a NEW violation: a planted file that is NOT ledgered is red.
  if is_grandfathered "crates/busbar/src/config/overlay.rs" \
    || is_grandfathered "crates/busbar/src/config/secret.rs" \
    || is_grandfathered "crates/busbar/src/config/groups.rs" \
    || is_grandfathered "crates/busbar/src/config/patch.rs"; then
    red "  FAIL  LEDGER: a crates/busbar/src/config/ file is grandfathered -- that is the blanket"
    red "        exemption this lint exists to refuse."
    fails=$((fails + 1))
  else
    note "PASS  LEDGER: nothing under crates/busbar/src/config/ is grandfathered"
  fi

  if [ "$fails" -eq 0 ]; then
    grn "test-locality-lint self-test: ALL GREEN (RED/GREEN discipline proven)"
    return 0
  fi
  red "test-locality-lint self-test: $fails FAILED"
  return 1
}

# -- THE GATE ------------------------------------------------------------------------------------
run_lint() {
  hdr "test locality (no inline #[cfg(test)] module bodies under crates/*/src)"
  local fail=0 debt=0 f hits
  while IFS= read -r f; do
    case "$f" in */tests/*) continue ;; esac
    hits=$(scan "$f")
    [ -z "$hits" ] && continue
    if is_grandfathered "$f"; then
      debt=$((debt + 1))
      continue
    fi
    printf '%s\n' "$hits" | sed 's/^/  /'
    fail=1
  done < <(find crates -path '*/src/*' -name '*.rs' | sort)

  if [ "$debt" -gt 0 ]; then
    note "($debt file(s) carry grandfathered pre-existing debt; that ledger only shrinks)"
  fi
  if [ "$fail" -eq 0 ]; then
    grn "ok -- no NEW inline test module bodies"
    return 0
  fi
  red "test-locality-lint FAILED: move each body to tests/<name>.rs and keep a #[path] declaration."
  note "if a test genuinely needs a PRIVATE item an external module cannot reach, prefer pub(crate)"
  note "or a #[cfg(test)] pub(crate) accessor; only then leave it inline with"
  note "    // test-locality-lint: allow -- <reason naming the private item>"
  return 1
}

case "${1:-}" in
  --selftest) run_selftest ;;
  "" | --check) run_lint ;;
  -h | --help) sed -n '2,52p' "$0" ;;
  *) echo "usage: $0 [--selftest|--check]" >&2; exit 2 ;;
esac
