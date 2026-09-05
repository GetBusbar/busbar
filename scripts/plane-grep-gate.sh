#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-grep-gate.sh — THE SUBSTRING DIALECT-NAME NEUTRALITY GATE (the "Protocols as Plugins" debt meter).
#
# WHY THIS EXISTS (the gap plane-purity-lint.sh leaves):
#   scripts/plane-purity-lint.sh enforces the plane ABI with WORD-BOUNDARY rules: it bans the plane
#   KEYS (mcp / a2a / llm as whole tokens) and the six DIALECT names as whole words. That is exactly
#   right for the structural side-channel invariant it guards — but it is deliberately narrow. A token
#   like `gemini_api_version`, a path literal `"/v1/models"` that is really a Gemini/OpenAI wire fact,
#   or a field named `openai_compat` is NOT a whole-word `gemini`/`openai` hit, so plane-purity is
#   blind to it. The "Protocols as Plugins" work (owner acceptance scope F4) needs a STRICTER meter:
#   dialect names banned AS SUBSTRINGS in PRODUCTION .rs outside busbar-llm, so `gemini_api_version`,
#   `openai_style`, `cohere_rerank_v2` and friends all light up.
#
# THE ACCEPTANCE SCOPE (F4, owner-pinned):
#   Ban DIALECT NAMES in PRODUCTION Rust code outside `busbar-llm`, EXCLUDING comments/doc-strings,
#   tests, and the neutral `busbar-api` `Operation` enum (crates/api/src/operation.rs) — the generic
#   op vocabulary (chat / embedding / rerank / …) is NEUTRAL and stays. Concretely:
#
#     NEUTRAL crates (busbar-core, busbar-substrate, busbar-api): ZERO occurrences (as substrings) of
#       the six dialect names — openai gemini anthropic bedrock cohere responses — PLUS the plane keys
#       `mcp` / `a2a` / `voice` (a neutral crate must name no plane by key).
#     busbar-mcp   : may name `mcp`,   but NOT the six dialect names and NOT `a2a` / `voice`.
#     busbar-a2a   : may name `a2a`,   but NOT the six dialect names and NOT `mcp` / `voice`.
#     busbar-voice : may name `voice`, but NOT the six dialect names and NOT `mcp` / `a2a`.
#       (voice added at parity with mcp/a2a after the initial F4 pin, closing the same substring hole
#       for the busbar-voice plane crate.)
#     busbar-llm : OWNS the dialect names — not scanned.
#
#   Substring match (index, not word-boundary) is the whole point: it is a SUPERSET of plane-purity's
#   dialect rule, catching the `_api_version` / `_compat` / `/v1/…`-adjacent leakage plane-purity cannot.
#
# WHAT IS EXCLUDED (so the meter measures real debt, not comments or test scaffolding):
#   * comments + doc-comments + block comments — stripped before matching (respecting string literals,
#     so a token INSIDE a string literal is KEPT and a `//` inside a string is NOT a comment). This is
#     the same strip() the sibling plane-purity-lint.sh uses.
#   * test code — a `*/tests/*` or `*_test(s).rs` file, and a `#[cfg(test)] mod … { … }` block.
#   * TEST-SUPPORT SCAFFOLDING — the fixture surface compiled only under the `test-support` feature is
#     not production debt, so it is excluded two ways, mirroring the existing `#[cfg(test)]` handling:
#       - test-support MODULES: a brace-less `mod NAME;` whose `#[cfg(…)]` predicate NAMES `test-support`
#         (and is NOT negated with `not(…)`, and has NO production-visible sibling decl of the same name
#         in the same file — so `#[cfg(not(any(test, feature = "test-support")))] mod store;`'s partner
#         `#[cfg(any(test, feature = "test-support"))] pub mod store;` keeps `store` IN scope) causes the
#         module's whole file/subtree to be dropped from the scan (see prepass `compute_mod_excludes`).
#       - test-support ITEMS / `pub use`: an item whose own `#[cfg(…)]` predicate names `test-support`
#         (e.g. a `#[cfg(any(test, feature = "test-support"))] pub use …::{…};` re-export or a gated
#         `pub fn`) is skipped for its whole span (brace- and `;`-terminated) inside the scanner.
#   * the neutral `Operation` enum — crates/api/src/operation.rs is EXCLUDED wholesale: its variants
#     (Chat/Embeddings/Moderation/…) are the generic, protocol-neutral op vocabulary the ABI carries as
#     DATA, and are explicitly in-scope-neutral.
#   * FROZEN-WIRE ALLOWLIST — a narrow, path-scoped list (token × path-prefix × optional line) of hits
#     that are frozen CONTRACT vocabulary, not dialect leakage: the OpenAPI/MCP `responses` object key
#     under the admin/mcp/a2a wire crates, and the frozen `anthropic` protocol default / `mcp:` deploy
#     key at their pinned lines in config/mod.rs. See ALLOWLIST below — each entry is scoped, never global.
#
# REPORTING MODE (this lands NON-BLOCKING to measure the debt R3/R4/R5 will drive to 0):
#   GREP_GATE_REPORT_ONLY=1 (DEFAULT) → PRINT the violation count + the offending file:line list, EXIT 0.
#   GREP_GATE_REPORT_ONLY=0           → BLOCKING: exit 1 if any violation remains (the future hard gate).
#   Either way the full report is printed; only the exit code differs. This is the same two-mode posture
#   plane-purity used while it drained (baseline-informational → armed-check), here folded onto one env
#   flag so arming the gate is a manifest edit, not a code edit.
#
# THE SELF-TEST (--selftest, run FIRST like every sibling *-lint.sh): the scanner cannot be lied to.
#   It plants a fake `gemini_api_version` and a `busbar_a2a::Foo` in a NEUTRAL fixture and proves BOTH
#   are caught (RED), proves a per-crate symmetric case (busbar-mcp naming `a2a`/`anthropic` is caught,
#   naming `mcp` is not), and proves a CLEAN neutral fixture — plus a comment / cfg(test) block that
#   MENTION dialect names — passes with zero hits (GREEN). The tree verdict is trusted only after the
#   scanner re-proves itself on known inputs.
#
# No external deps beyond bash 3.2 + POSIX awk (macOS/Linux) — same bare-runner posture as the sibling
# gates (plane-purity-lint.sh, config-stability-gate.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# ── THE NEEDLE SETS ──────────────────────────────────────────────────────────────────────────────
# The six dialect names — banned as SUBSTRINGS everywhere outside busbar-llm.
DIALECTS="openai gemini anthropic bedrock cohere responses"

# ── THE CRATE GROUPS AND THEIR BANNED NEEDLES ────────────────────────────────────────────────────
# Each group names a crate src root and the exact set of needles that must NOT appear there. A crate
# added/removed/re-scoped is a one-line edit here, never N stale paths below.
#   neutral  : the ABI side — bans every dialect + ALL THREE plane keys (names no plane at all).
#   mcp      : may name `mcp`; bans the dialects + the OTHER plane keys `a2a` / `voice`.
#   a2a      : may name `a2a`; bans the dialects + the OTHER plane keys `mcp` / `voice`.
#   voice    : may name `voice`; bans the dialects + the OTHER plane keys `mcp` / `a2a`.
#   (busbar-llm owns the dialect names and is not scanned.)
# The plane keys are single-sourced (scripts/plane-keys.sh): the neutral crate bans EVERY protocol
# plane key, and each plane crate bans the OTHER protocol plane keys. `llm` never appears as a
# needle — busbar-llm owns the dialect names above, so it is scanned via $DIALECTS, not as a key.
# A plane added to plane-keys.sh flows into every needle set here with no edit below.
# shellcheck source=scripts/plane-keys.sh
. "$(dirname "$0")/plane-keys.sh"
NEUTRAL_ROOTS="crates/busbar-core/src crates/busbar-substrate/src crates/busbar-substrate-values/src crates/api/src"
NEUTRAL_NEEDLES="$DIALECTS $PLANE_KEYS_PROTOCOL"
# TWO ROOTS PER PLANE since the codec split: each protocol plugin kept its I/O half under the
# historical crate name and shed its pure half into a `-codec` crate a PURE kind may name. The gate
# scans sources, not manifests, so both halves are named or the moved files stop being scanned —
# which is the failure mode a split invites and the reason these are lists.
MCP_ROOT="crates/busbar-mcp/src crates/busbar-mcp-codec/src"
MCP_NEEDLES="$DIALECTS $(plane_keys_other mcp)"
A2A_ROOT="crates/busbar-a2a/src crates/busbar-a2a-codec/src"
A2A_NEEDLES="$DIALECTS $(plane_keys_other a2a)"
VOICE_ROOT="crates/busbar-voice/src crates/busbar-voice-codec/src"
VOICE_NEEDLES="$DIALECTS $(plane_keys_other voice)"

# The neutral Operation enum — generic op vocabulary, explicitly in-scope-neutral. Excluded whole.
OPERATION_EXCLUDE="crates/api/src/operation.rs"

# ── THE FROZEN-WIRE ALLOWLIST (path-scoped, never global) ──────────────────────────────────────────
# One entry per line:  NEEDLE|PATH-PREFIX|LINE   (LINE empty = every line under the prefix).
# A hit is suppressed iff its needle equals NEEDLE, its file path STARTS WITH PATH-PREFIX, and (when
# LINE is given) its line number equals LINE. This is the ONLY allowlist mechanism — inline source
# markers are NOT honoured (the gate must stay a source-read-only meter; the .rs files are frozen).
#   responses : the OpenAPI-3 response-object key + MCP `inputResponses` wire field — frozen contract
#               vocabulary, allowlisted ONLY under the admin / mcp / a2a wire crates (a stray
#               `responses` elsewhere still trips).
#   anthropic : the frozen `DEFAULT_PROTOCOL = "anthropic"` providers.yaml config-grammar default —
#               its own comment declares it frozen-wire. Pinned to its exact line in config/mod.rs.
#   mcp       : the public frozen `mcp:` deploy-config key (`mcp: McpEndpointSection` field + the
#               `deploy.mcp.0` read). Pinned to the two exact deploy-config lines in config/mod.rs —
#               the unrelated `mcp` import at the top of the file is NOT covered and still trips.
ALLOWLIST="responses|crates/busbar-core/src/admin/|
responses|crates/busbar-mcp/src/|
responses|crates/busbar-mcp-codec/src/|
responses|crates/busbar-a2a/src/|
responses|crates/busbar-a2a-codec/src/|
anthropic|crates/busbar-core/src/config/mod.rs|1291
mcp|crates/busbar-core/src/config/mod.rs|2974
mcp|crates/busbar-core/src/config/mod.rs|5017"

# ── THE TEST-SUPPORT MODULE PREPASS ────────────────────────────────────────────────────────────────
# Emits the file/subtree prefixes of every brace-less `mod NAME;` whose `#[cfg(…)]` predicate NAMES
# `test-support` (positively — not under `not(…)`) and that has NO production-visible sibling decl of
# the same name in the same file. Those modules are the crate's test-support fixture surface (compiled
# only under the feature), so their whole files are dropped from the scan. Populated into MOD_EXCLUDE.
MOD_EXCLUDE=""
compute_mod_excludes() {
  local roots="$*" decls
  # Per file: pair a pending `#[cfg(…)]` attr with the next brace-less `mod NAME;`, classify test-only
  # vs production, then keep only names that are test-only with no production sibling in that file.
  decls="$(
    for f in $(find $roots -name '*.rs' 2>/dev/null | grep -v '/tests/' | grep -Ev '_tests?\.rs$'); do
      awk -v dir="$(dirname "$f")" '
        /#\[cfg\(/ { pendcfg = $0; pend = 1 }
        {
          if (match($0, /(^|[^A-Za-z0-9_])mod[ \t]+[A-Za-z0-9_]+[ \t]*;/)) {
            name = substr($0, RSTART, RLENGTH); sub(/^.*mod[ \t]+/, "", name); sub(/[ \t]*;.*/, "", name)
            cfg = pend ? pendcfg : ""; cls = "prod"
            if (cfg != "" && index(tolower(cfg), "test-support") > 0 && index(cfg, "not(") == 0) cls = "testonly"
            print dir "/" name "\t" cls
            pend = 0; pendcfg = ""; next
          }
          if ($0 ~ /[^ \t]/ && $0 !~ /#\[cfg\(/) { pend = 0; pendcfg = "" }
        }
      ' "$f"
    done
  )"
  MOD_EXCLUDE="$(printf '%s\n' "$decls" \
    | awk -F'\t' '{ if ($2=="testonly") t[$1]=1; else p[$1]=1 }
                  END { for (k in t) if (!(k in p)) print k }' \
    | sort)"
}

# Production .rs under a set of roots, minus test files, the excluded Operation enum, and any file that
# lives under (or is) a test-support module dropped by the prepass.
prod_files() {
  local out; out="$(find $* -name '*.rs' 2>/dev/null \
    | grep -v '/tests/' \
    | grep -Ev '_tests?\.rs$' \
    | grep -vxF "$OPERATION_EXCLUDE")"
  local m
  for m in $MOD_EXCLUDE; do
    out="$(printf '%s\n' "$out" | grep -Ev "^${m}(/|\.rs$)")"
  done
  printf '%s\n' "$out" | grep -v '^$' | sort
}

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits one TSV line per violation:  NEEDLE<TAB>file:line<TAB>trimmed-source
# It strips comments/doc-comments/block-comments (respecting string literals) and excludes
# `#[cfg(test)] mod { … }` blocks, then flags any case-insensitive SUBSTRING hit of a banned needle.
scan() {
  local needles="$1"; shift
  [ "$#" -gt 0 ] || return 0
  # BSD awk forbids a literal newline in a -v value, so flatten the row-per-line ALLOWLIST to `;`-joined.
  awk -v needles="$needles" -v allow="$(printf '%s' "$ALLOWLIST" | tr '\n' ';')" '
    function strip(line,   res, i, n, c, c2, instr) {
      res = ""; n = length(line); i = 1; instr = 0
      while (i <= n) {
        c = substr(line, i, 1); c2 = substr(line, i, 2)
        if (inblk) { if (c2 == "*/") { inblk = 0; i += 2 } else { i++ } continue }
        if (instr) {
          res = res c
          if (c == "\\") { res = res substr(line, i + 1, 1); i += 2; continue }
          if (c == "\"") { instr = 0 }
          i++; continue
        }
        if (c2 == "/*") { inblk = 1; i += 2; continue }
        if (c2 == "//") { break }
        if (c == "\"") { instr = 1; res = res c; i++; continue }
        res = res c; i++
      }
      return res
    }
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function emit(needle, text) { printf "%s\t%s:%d\t%s\n", needle, FILENAME, FNR, trim(text) }
    # allowlisted(needle) — true iff a frozen-wire ALLOWLIST entry covers this needle at FILENAME:FNR.
    function allowlisted(needle,   i) {
      for (i = 1; i <= naA; i++)
        if (needle == aN[i] && index(FILENAME, aP[i]) == 1 && (aL[i] == "" || aL[i] + 0 == FNR)) return 1
      return 0
    }

    BEGIN {
      nN = split(needles, N, " ")
      # Parse the ALLOWLIST (NEEDLE|PATH-PREFIX|LINE per row).
      naA = 0; nrows = split(allow, rows, ";")
      for (r = 1; r <= nrows; r++) {
        if (rows[r] == "") continue
        nf = split(rows[r], fld, "|")
        naA++; aN[naA] = fld[1]; aP[naA] = fld[2]; aL[naA] = (nf >= 3 ? fld[3] : "")
      }
    }

    # Per-FILE reset (awk shares state across the file list).
    FNR == 1 { inblk = 0; testdepth = 0; pend = 0; pendts = 0; itemskip = 0; idepth = 0; seenbrace = 0 }

    {
      code = strip($0)
      lc   = tolower(code)
      nopen = gsub(/[{]/, "{", code); nclose = gsub(/[}]/, "}", code)

      is_cfg     = (code ~ /#\[cfg\(/)
      # names `test` as a bounded token (this also covers `"test-support"`, `test` bounded by `"`/`-`).
      is_cfgtest = (is_cfg && (tolower(" " code " ") ~ /[^a-z0-9_]test[^a-z0-9_]/))
      # names the `test-support` feature specifically (drives the ITEM/pub-use skip below).
      is_testsup = (is_cfg && index(lc, "test-support") > 0)
      has_mod    = (code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/)

      # ── skipping a test-support-gated NON-mod item span (brace- or `;`-terminated) ──
      if (itemskip) {
        if (nopen > 0) seenbrace = 1
        idepth += nopen - nclose
        if ((seenbrace && idepth <= 0) || (!seenbrace && idepth <= 0 && index(code, ";") > 0)) {
          itemskip = 0; idepth = 0; seenbrace = 0
        }
        next
      }

      # ── #[cfg(test | test-support)] mod { … } block tracking + test-support item skipping ──
      entered = 0
      if (is_cfgtest && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0; pendts = 0
      } else if (pend && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0; pendts = 0
      } else if (pendts && !is_cfg && code ~ /[^[:space:]]/) {
        # a `test-support` attr on the previous line, and THIS line is its (non-mod) item → skip its span.
        pend = 0; pendts = 0
        seenbrace = (nopen > 0); idepth = nopen - nclose
        if (!((seenbrace && idepth <= 0) || (!seenbrace && idepth <= 0 && index(code, ";") > 0))) itemskip = 1
        next
      } else if (pend && code ~ /[^[:space:]]/ && !is_cfg) {
        pend = 0; pendts = 0
      } else if (testdepth > 0) {
        testdepth += nopen - nclose; if (testdepth < 0) testdepth = 0
      }
      if (is_cfgtest && !has_mod) { pend = 1; if (is_testsup) pendts = 1 }
      if (testdepth > 0 || entered) next

      # ── substring dialect / plane-key hits (minus the frozen-wire allowlist) ──
      for (k = 1; k <= nN; k++) {
        if (index(lc, N[k]) > 0 && !allowlisted(N[k])) emit(N[k], code)
      }
    }
  ' "$@"
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-grep-gate SELF-TEST (the substring dialect scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out

  # ── RED (neutral): a planted `gemini_api_version` + a `busbar_a2a::Foo` — the substring wins that
  # plane-purity's word-boundary rule would MISS on the first. Both must be flagged.
  cat >"$tmp/neutral_red.rs" <<'RED'
pub const GEMINI_KEY: &str = "gemini_api_version";
use busbar_a2a::Foo;
use busbar_voice::Bar;
fn probe() { let url = "https://api.openai.com/v1/models"; }
RED
  out="$(scan "$NEUTRAL_NEEDLES" "$tmp/neutral_red.rs")"
  local hit_gemini hit_a2a hit_openai hit_voice
  hit_gemini="$(printf '%s\n' "$out" | awk -F'\t' '$1=="gemini"{n++} END{print n+0}')"
  hit_a2a="$(printf '%s\n' "$out"    | awk -F'\t' '$1=="a2a"{n++}    END{print n+0}')"
  hit_openai="$(printf '%s\n' "$out" | awk -F'\t' '$1=="openai"{n++} END{print n+0}')"
  hit_voice="$(printf '%s\n' "$out"  | awk -F'\t' '$1=="voice"{n++}  END{print n+0}')"
  if [ "$hit_gemini" -ge 1 ]; then note "RED neutral: caught gemini SUBSTRING in \`gemini_api_version\`"; else fail=1; note "RED neutral FAILED: gemini_api_version not flagged"; fi
  if [ "$hit_a2a"    -ge 1 ]; then note "RED neutral: caught the busbar_a2a:: plane-key reach"; else fail=1; note "RED neutral FAILED: busbar_a2a:: not flagged"; fi
  if [ "$hit_openai" -ge 1 ]; then note "RED neutral: caught openai SUBSTRING in the /v1/models url host"; else fail=1; note "RED neutral FAILED: api.openai.com not flagged"; fi
  if [ "$hit_voice"  -ge 1 ]; then note "RED neutral: caught the busbar_voice:: plane-key reach"; else fail=1; note "RED neutral FAILED: busbar_voice:: not flagged"; fi
  [ "$fail" -eq 0 ] || { note "  (scanner output was:)"; printf '%s\n' "$out" | sed 's/^/    /'; }

  # ── GREEN (neutral): the generic neutral vocabulary + a comment / cfg(test) block MENTIONING dialect
  # names — none may be flagged (executable proof of the comment/test exclusion).
  cat >"$tmp/neutral_green.rs" <<'GREEN'
pub enum Op { Chat, Embeddings, Rerank, Moderation }
// this comment names openai gemini anthropic bedrock cohere responses mcp a2a voice and must be ignored
/* block comment naming gemini_api_version and openai too — ignored */
pub fn install() { let _op = Op::Chat; let _e = Op::Embeddings; }
#[cfg(test)]
mod tests {
    fn t() { let _ = "openai gemini anthropic"; let _k = "mcp a2a voice"; }
}
GREEN
  out="$(scan "$NEUTRAL_NEEDLES" "$tmp/neutral_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN neutral: generic Op vocabulary + comment + cfg(test) fixtures flagged NONE"
  else
    fail=1; note "GREEN neutral FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── SYMMETRIC (busbar-mcp): may name `mcp`, must NOT name `a2a` or a dialect. ──
  cat >"$tmp/mcp_case.rs" <<'MCP'
use busbar_mcp::server::McpEndpoint;
fn wire() { let _ = "a2a"; let _d = "anthropic_v1"; }
MCP
  out="$(scan "$MCP_NEEDLES" "$tmp/mcp_case.rs")"
  local mcp_hit_mcp mcp_hit_a2a mcp_hit_anthropic
  mcp_hit_mcp="$(printf '%s\n' "$out"       | awk -F'\t' '$1=="mcp"{n++}       END{print n+0}')"
  mcp_hit_a2a="$(printf '%s\n' "$out"       | awk -F'\t' '$1=="a2a"{n++}       END{print n+0}')"
  mcp_hit_anthropic="$(printf '%s\n' "$out" | awk -F'\t' '$1=="anthropic"{n++} END{print n+0}')"
  # `mcp` is NOT in MCP_NEEDLES, so it must never appear as a category, and `busbar_mcp` must not trip.
  if [ "$mcp_hit_mcp" -eq 0 ];      then note "SYMMETRIC mcp: did NOT flag its own \`mcp\` name"; else fail=1; note "SYMMETRIC mcp FAILED: flagged its own \`mcp\`"; fi
  if [ "$mcp_hit_a2a" -ge 1 ];      then note "SYMMETRIC mcp: flagged the foreign \`a2a\` plane key"; else fail=1; note "SYMMETRIC mcp FAILED: foreign a2a not flagged"; fi
  if [ "$mcp_hit_anthropic" -ge 1 ]; then note "SYMMETRIC mcp: flagged \`anthropic\` SUBSTRING in anthropic_v1"; else fail=1; note "SYMMETRIC mcp FAILED: anthropic_v1 not flagged"; fi

  # ── SYMMETRIC (busbar-voice): may name `voice`, must NOT name `mcp` or `a2a`. ──
  cat >"$tmp/voice_case.rs" <<'VOICE'
use busbar_voice::runtime::Session;
fn wire() { let _ = "mcp"; let _d = "a2a_bridge"; }
VOICE
  out="$(scan "$VOICE_NEEDLES" "$tmp/voice_case.rs")"
  local voice_hit_voice voice_hit_mcp voice_hit_a2a
  voice_hit_voice="$(printf '%s\n' "$out" | awk -F'\t' '$1=="voice"{n++} END{print n+0}')"
  voice_hit_mcp="$(printf '%s\n' "$out"   | awk -F'\t' '$1=="mcp"{n++}   END{print n+0}')"
  voice_hit_a2a="$(printf '%s\n' "$out"   | awk -F'\t' '$1=="a2a"{n++}   END{print n+0}')"
  if [ "$voice_hit_voice" -eq 0 ]; then note "SYMMETRIC voice: did NOT flag its own \`voice\` name"; else fail=1; note "SYMMETRIC voice FAILED: flagged its own \`voice\`"; fi
  if [ "$voice_hit_mcp"   -ge 1 ]; then note "SYMMETRIC voice: flagged the foreign \`mcp\` plane key"; else fail=1; note "SYMMETRIC voice FAILED: foreign mcp not flagged"; fi
  if [ "$voice_hit_a2a"   -ge 1 ]; then note "SYMMETRIC voice: flagged the foreign \`a2a\` plane key SUBSTRING in a2a_bridge"; else fail=1; note "SYMMETRIC voice FAILED: foreign a2a not flagged"; fi

  if [ "$fail" -ne 0 ]; then
    red "plane-grep-gate SELF-TEST FAILED — the scanner would let a dialect substring through"
    return 1
  fi
  grn "plane-grep-gate self-test: ALL GREEN (substring RED/GREEN discipline proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
# Scans every group, prints the categorized report, and returns the total via $REPORT_TOTAL.
REPORT_TOTAL=0
run_report() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  : >"$tmp/hits"

  # Prepass: compute the test-support module subtrees to drop (across every scanned root).
  compute_mod_excludes $NEUTRAL_ROOTS $MCP_ROOT $A2A_ROOT $VOICE_ROOT

  local nf mf af vf
  nf="$(prod_files $NEUTRAL_ROOTS)"; mf="$(prod_files $MCP_ROOT)"; af="$(prod_files $A2A_ROOT)"; vf="$(prod_files $VOICE_ROOT)"
  # shellcheck disable=SC2086
  [ -n "$nf" ] && scan "$NEUTRAL_NEEDLES" $nf >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$mf" ] && scan "$MCP_NEEDLES"     $mf >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$af" ] && scan "$A2A_NEEDLES"     $af >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$vf" ] && scan "$VOICE_NEEDLES"   $vf >>"$tmp/hits"

  local total; total="$(wc -l <"$tmp/hits" | tr -d ' ')"
  REPORT_TOTAL="$total"

  hdr "PLANE-GREP report — dialect-name SUBSTRINGS outside busbar-llm (production .rs, comments/tests/Operation excluded)"
  note "neutral roots: $NEUTRAL_ROOTS   (bans: $NEUTRAL_NEEDLES)"
  note "mcp root:      $MCP_ROOT   (bans: $MCP_NEEDLES)"
  note "a2a root:      $A2A_ROOT   (bans: $A2A_NEEDLES)"
  note "voice root:    $VOICE_ROOT   (bans: $VOICE_NEEDLES)"
  note "excluded:      $OPERATION_EXCLUDE (neutral Operation enum), */tests/*, *_test(s).rs, #[cfg(test)]"

  hdr "by needle (a clean tree reports zero)"
  local d n
  for d in $DIALECTS mcp a2a voice; do
    n="$(awk -F'\t' -v c="$d" '$1==c{n++} END{print n+0}' "$tmp/hits")"
    printf '  %-12s %6d\n' "$d" "$n"
  done
  printf '  %-12s %6d\n' "TOTAL" "$total"

  hdr "top 20 files by violation count"
  awk -F'\t' '{split($2,a,":"); f[a[1]]++} END{for(k in f) printf "%6d  %s\n", f[k], k}' "$tmp/hits" \
    | sort -rn | head -20 | sed 's/^/  /'

  hdr "first 40 offending file:line"
  awk -F'\t' '{printf "  %-10s %s\n", $1, $2}' "$tmp/hits" | head -40

  cp "$tmp/hits" "${PLANE_GREP_HITS_OUT:-/dev/null}" 2>/dev/null || true
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --report | --check | "")
    run_report
    hdr "verdict"
    report_only="${GREP_GATE_REPORT_ONLY:-1}"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "plane-grep gate: PASS — no dialect-name substring outside busbar-llm"
      exit 0
    fi
    if [ "$report_only" = "0" ]; then
      red "plane-grep gate: FAIL — $REPORT_TOTAL dialect-name substring(s) outside busbar-llm (see report above)"
      note "Route each through the plane ABI / a neutral op-vocabulary constant; the dialect names belong in busbar-llm."
      exit 1
    fi
    ylw "plane-grep gate: $REPORT_TOTAL dialect-name substring(s) — REPORT-ONLY (GREP_GATE_REPORT_ONLY=1, non-blocking)."
    note "This meter is informational for now; R3/R4/R5 drive it to 0. Set GREP_GATE_REPORT_ONLY=0 to arm the hard gate."
    exit 0
    ;;
  -h | --help)
    sed -n '2,60p' "$0"
    ;;
  *)
    echo "usage: $0 [--selftest | --report | --check]   (env GREP_GATE_REPORT_ONLY=1 default report-only; =0 blocking)" >&2
    exit 2
    ;;
esac
