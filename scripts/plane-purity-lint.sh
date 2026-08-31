#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-purity-lint.sh — THE NEUTRAL-PURITY LINT: the enforcement gate for the plane ABI.
#
# WHY THIS EXISTS (docs/design/plane-extraction-design.md §1 — the honest post-mortem):
#   A protocol plane (LLM / MCP / A2A) must be a self-contained plugin merely compiled in for
#   convenience. Turn its feature off (or `git rm -r` its crate) and the NEUTRAL crates — busbar-core,
#   busbar-substrate, busbar-api — must still compile and run, serving no P protocol. That was the
#   requirement on day one; it eroded, for one reason above all: THERE WAS NO GATE. The extraction was
#   done by hand, nothing enforced completion or prevented regression, so new plane-specific code kept
#   landing in the neutral crates unchallenged. "A boundary with no instrument watching it drifts."
#   This lint is that instrument — the single most important artifact in the design.
#
# THE INVARIANT IT ENFORCES — EVERYTHING CROSSES THE ABI, NOTHING AROUND IT:
#   The plane ABI (PlaneDecl / ProtocolDecl / install_* / the opaque PlaneRecord / the plane_slots
#   type-erased runtime map / the PLANE_* diagnostics namespace) is the ONE AND ONLY surface across
#   which core and a plane communicate. Every SIDE CHANNEL is a violation to be removed, not "gated".
#   In a NEUTRAL-crate source (excluding comments, doc-strings, and test code), this lint fails RED on:
#
#     PATH-INCLUDE  (a) any `#[path = "…/busbar-{llm,mcp,a2a}/…"]` dual-compile — the witness-build
#                       side channel that reaches AROUND the ABI to compile plane source into a neutral
#                       crate. An INSTANT fail, scanned even in test scope: it must not exist at all.
#     SYMBOL        (b) any `busbar_{llm,mcp,a2a}::` symbol path — there is no legitimate one. The
#                       composition-root bin (crates/busbar) is NOT neutral and is exempt (not scanned).
#     KEY           (c1) a concrete plane key as a token: `mcp` / `a2a` / `llm`.
#     DIALECT       (c2) one of the six dialect names: openai / anthropic / gemini / bedrock / cohere /
#                        responses.
#     TYPE          (c3) a plane record type name (McpCallRecord / McpDemotionRow / TaskRow /
#                        TaskEventRow) or any plane-/dialect-prefixed CamelCase type (McpFoo, TaskRow,
#                        OpenaiFamily, …).
#
#   ALLOWED — the NEUTRAL ABI identifiers ONLY, and never flagged (the curated allow-list, made
#   executable by a GREEN self-test fixture that uses each and asserts ZERO hits):
#       PlaneRecord  PlaneDecl  ProtocolDecl  PlaneDecls  PlaneSlots  PlaneHost
#       plane_slots  plane_slot  plane_host   install_planes  install_protocols
#       install_diagnostics  install_path_ingress  BUILTIN_PLANE_DECLS  BUILTIN_DECLS
#       PLANE_*  (the neutral diagnostics namespace)
#   These are the target pattern (the acceptable neutral seams to keep). Word-boundary and
#   Plane/Protocol-prefix construction of the scanner mean none of them can match a KEY/DIALECT/TYPE
#   rule; the allow-list below is the defensive belt-and-braces and the thing the GREEN fixture proves.
#
# THE FROZEN-WIRE CARVE-OUT (the ONE documented exception — narrow, reviewable, per-line):
#   The config grammar is FROZEN, additive-only, BYTE-IDENTICAL since 1.5.3, enforced by
#   scripts/config-stability-gate.sh against the committed config-schema.snapshot.json. A handful of
#   the KEY/TYPE/DIALECT tokens above are ALSO frozen external-wire config-grammar tokens that the
#   neutral crate CANNOT stop naming without breaking that contract:
#     * the `mcp:` top-level WIRE KEY on `DeployCfg` — a 1.5.x operator's YAML carries `mcp:` and MUST
#       parse byte-identically; renaming the field (even with `#[serde(rename="mcp")]`) still leaves
#       the `mcp` token in source, and the snapshot records the wire key `mcp` verbatim.
#     * the `McpEndpointSection` TYPE name — recorded verbatim in config-schema.snapshot.json as the
#       `type` of that field. Renaming it to anything plane-neutral is a config-schema RETYPE
#       (`DeployCfg.mcp: field RETYPED …`) that the additive-only classifier fails RED and that a
#       snapshot refresh CANNOT launder (the baseline is a git ref). PROVEN, not asserted.
#     * the `anthropic` DIALECT literal in `config/mod.rs`'s `DEFAULT_PROTOCOL` — the value an
#       omitted `protocol:` on a `providers.yaml` entry defaults to. The frozen config grammar has
#       always resolved a protocol-less provider to `anthropic`; the default cannot be read off the
#       (possibly-empty) protocol registry, so it is named as a frozen-wire literal. Changing it
#       silently retargets every 1.5.x deployment whose YAML omits `protocol:`.
#   These are genuine grammar tokens, not lazily-un-extracted vocabulary — Path 1 (eliminate the token
#   while preserving the wire) is PROVABLY IMPOSSIBLE for them. So a neutral-source line may carry a
#     // plane-purity: frozen-wire <reason tied to the frozen-config contract>
#   pragma, which EXEMPTS THAT LINE from the KEY/DIALECT/TYPE vocabulary rules ONLY. It is NEVER an
#   exemption from PATH-INCLUDE or SYMBOL (a `#[path]` witness include or a `busbar_{plane}::` reach is
#   a structural side channel no config-freeze can justify), and the self-test proves a pragma does not
#   launder either. NOT a `concat!`/hex obfuscation of the token — the token stays PLAIN and greppable;
#   this is an explicit, reviewed allow, one pragma per excused line, each justifying itself in the diff.
#
# THE REVERSE EDGE ("no backwards reach", §2.1 item 2): a plane crate (busbar-{llm,mcp,a2a}) MAY name
#   the substrate ABI (busbar_substrate:: / busbar_api::) but must NOT name `busbar_core::`
#   implementation items. Core→plane and plane→core-internals are both forbidden; only plane→ABI and
#   ABI→plane(via registry) are allowed. A companion scan of the plane crates enforces this.
#
# ONE SCANNER, DRIVEN BY THE SELF-TEST (--selftest, run FIRST in CI like every sibling *-lint.sh):
#   `scan()` is the single scanner; the self-test drives THAT function, never a duplicate. It plants
#   the four side channels the design names — (i) a fake `#[path=…busbar-mcp…]`, (ii) a `busbar_a2a::`
#   reference, (iii) a `McpFoo` type, (iv) a plane-crate `busbar_core::internal::foo` backwards reach —
#   and proves the scanner flags all four (RED fixtures) AND passes clean/allow-listed/comment/test
#   fixtures (GREEN). The scanner cannot be lied to: its verdict on the tree is trusted only after it
#   re-proves itself on known inputs.
#
# ── THE TWO TREE MODES (baseline report vs. the enforcing gate) ─────────────────────────────────────
#   The neutral crates are purity-clean: zero side channels remain, and this lint now ENFORCES that.
#   It has two tree modes:
#
#     --baseline   INFORMATIONAL. Prints the full categorized violation report and ALWAYS exits 0, so
#                  the current count is visible on every push without gating on it.
#     --check      BLOCKING (fail-closed). Exits non-zero on ANY violation. This is the PERMANENT gate.
#                  It is wired into the qa/segments.toml `plane-purity` segment, now `active`: with the
#                  neutral crates drained to zero, `--check` passes green, and any regression that
#                  reintroduces a side channel fails it RED.
#
#   So: the SELF-TEST is green (it proves the scanner), the tree is clean, and `--check` is the
#   permanent hard gate that keeps it that way — with nothing to edit in this file.
#
# No external deps beyond bash 3.2 + POSIX awk (macOS/Linux) — the same bare-runner posture as the
# sibling lints (structure-lint.sh, release-script-lint.sh, response-header-lint.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# The neutral crates (the ABI side) and the plane crates (the plugin side). Derived once; a plane or
# neutral crate that appears/disappears is a one-line edit here, never N stale paths scattered below.
NEUTRAL_ROOTS="crates/busbar-core/src crates/busbar-substrate/src crates/api/src"
PLANE_ROOTS="crates/busbar-llm/src crates/busbar-mcp/src crates/busbar-a2a/src"

neutral_files() { find $NEUTRAL_ROOTS -name '*.rs' 2>/dev/null | sort; }
plane_files()   { find $PLANE_ROOTS   -name '*.rs' 2>/dev/null | sort; }

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits one TSV line per violation:  CATEGORY<TAB>file:line<TAB>trimmed-source
#   mode=forward  scan NEUTRAL sources for the side channels (a)/(b)/(c).
#   mode=reverse  scan PLANE sources for the backwards reach (busbar_core:: implementation names).
# It strips comments/doc-comments/block-comments (respecting string literals so a `//` inside a string
# is NOT a comment and a token inside a string IS kept), and — for the SYMBOL/KEY/DIALECT/TYPE rules —
# excludes test code (a `*/tests/*` or `*_test(s).rs` file, and a `#[cfg(test)] mod … { … }` block).
# The PATH-INCLUDE rule is scanned UNCONDITIONALLY, test scope included: the witness `#[path]` include
# is an instant fail wherever it lives.
scan() {
  local mode="$1"; shift
  [ "$#" -gt 0 ] || return 0
  awk -v mode="$mode" '
    # Strip comments + block-comments, respecting string literals. inblk persists across lines
    # (block comments span lines); instr is per-line (Rust string literals are overwhelmingly
    # single-line, and resetting each line guards against a raw-string/char-literal desync).
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
        if (c2 == "//") { break }                       # line comment (covers // /// //!) to EOL
        if (c == "\"") { instr = 1; res = res c; i++; continue }
        res = res c; i++
      }
      return res
    }
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    # A whole-word (identifier-boundary) case-insensitive hit of a lowercase needle. The pad makes a
    # match at line start/end boundary-clean; the class [^a-z0-9_] is the identifier boundary.
    function word_ci(lc, needle) { return (lc ~ ("[^a-z0-9_]" needle "[^a-z0-9_]")) }
    function emit(cat, text) { printf "%s\t%s:%d\t%s\n", cat, FILENAME, FNR, trim(text) }

    # Per-FILE reset (awk shares state across the file list).
    FNR == 1 { inblk = 0; testdepth = 0; pend = 0; prevfz = 0 }

    {
      code = strip($0)
      pad  = " " code " "
      lc   = tolower(pad)
      nopen = gsub(/[{]/, "{", code); nclose = gsub(/[}]/, "}", code)

      # ── FROZEN-WIRE pragma (see header + the carve-out gate below). Read on the RAW line so the
      # marker lives in a comment. A line is frozen-exempt when it carries the pragma ITSELF (a trailing
      # `// plane-purity: frozen-wire …`) OR the line directly above was a STANDALONE pragma comment —
      # the latter because rustfmt relocates a comment that trails an opening `{` onto the line above.
      # A trailing pragma (the line has code) does NOT bleed onto the next line; only a pure-comment
      # pragma line exempts the single code line that follows it. Computed here, before any early
      # `next`, so `prevfz` stays in step across test-scope and reverse-mode skips.
      curpragma = ($0 ~ /plane-purity:[[:space:]]*frozen-wire/)
      frozen    = (curpragma || prevfz)
      prevfz    = (curpragma && trim(code) == "")           # standalone pragma line ⇒ exempt next line

      istestfile = (FILENAME ~ /\/tests\// || FILENAME ~ /_tests?\.rs$/)

      # ── #[cfg(test)] mod { … } block tracking (so unit-test code is excluded from b/c) ──
      # A cfg predicate that mentions `test` (cfg(test), any(test,…), the test-support witness gate).
      is_cfgtest = (code ~ /#\[cfg\(/ && (lc ~ /[^a-z0-9_]test[^a-z0-9_]/))
      has_mod    = (code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/)
      entered = 0
      if (is_cfgtest && has_mod) {                       # attr + mod on one line
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && has_mod) {                      # the mod that a prior cfg(test) attr guarded
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && code ~ /[^[:space:]]/ && !is_cfgtest) {
        pend = 0                                          # the attr guarded a non-mod item; do not block-skip
      } else if (testdepth > 0) {
        testdepth += nopen - nclose; if (testdepth < 0) testdepth = 0
      }
      if (is_cfgtest && !has_mod) pend = 1                # remember: the guarded mod is on a later line
      intest = (istestfile || testdepth > 0 || entered)

      if (mode == "reverse") {
        # No backwards reach: a plane crate must not name busbar_core:: implementation items.
        if (!intest && code ~ /busbar_core::/) emit("BACKWARDS", code)
        next
      }

      # ── forward: neutral-crate side channels ──
      # (a) PATH-INCLUDE — unconditional, test scope included (instant fail). NEVER excusable by the
      #     frozen-wire pragma below: a witness `#[path]` include is a STRUCTURAL side channel, not a
      #     grammar token, so no config-freeze can justify it.
      if (code ~ /#\[[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]*busbar-(llm|mcp|a2a)\//) emit("PATH-INCLUDE", code)

      if (intest) next                                    # (b)/(c) exclude test code

      # (b) SYMBOL — a plane-crate symbol path. ALSO never excusable by the frozen-wire pragma: a
      #     frozen config FIELD/TYPE never requires naming `busbar_{llm,mcp,a2a}::` — that is a
      #     backwards reach into plane implementation, orthogonal to the wire grammar.
      if (code ~ /busbar_(llm|mcp|a2a)::/) emit("SYMBOL", code)

      # ── FROZEN-WIRE CARVE-OUT (the config-stability contract; see header "THE FROZEN-WIRE CARVE-OUT")
      # A neutral-source line bearing a `// plane-purity: frozen-wire <reason>` pragma is EXEMPT from
      # the VOCABULARY rules ONLY — (c1) KEY, (c2) DIALECT, (c3) TYPE. It is NEVER exempt from
      # PATH-INCLUDE or SYMBOL (checked ABOVE this gate). `frozen` is computed at the top of the block
      # (pragma on this line, or a standalone pragma comment directly above — the rustfmt-relocated
      # case). This is the narrow, reviewable escape hatch for the handful of tokens the FROZEN config
      # grammar (byte-identical since 1.5.3, guarded by config-stability-gate.sh +
      # config-schema.snapshot.json) forces a neutral crate to keep naming: the `mcp:` top-level wire
      # KEY on `DeployCfg`, and the `McpEndpointSection` TYPE name recorded verbatim in the committed
      # snapshot (renaming either is a config-schema RETYPE = RED, proven un-launderable). Every excused
      # line is one reviewable pragma in the diff, each tied by its <reason> to the frozen-config
      # contract — exactly the config-schema.waivers discipline.
      if (frozen) next

      # (c3) TYPE — the named plane record structs, plus any plane-/dialect-prefixed CamelCase type.
      #      (Checked before the bare-key rule so McpFoo reads as TYPE, not KEY.)
      if (code ~ /(^|[^A-Za-z0-9_])(McpCallRecord|McpDemotionRow|TaskRow|TaskEventRow)([^A-Za-z0-9_]|$)/ \
       || code ~ /(^|[^A-Za-z0-9_])(Mcp|A2a|A2A|Llm|Openai|Anthropic|Gemini|Bedrock|Cohere|Responses)[A-Z][A-Za-z0-9_]*/)
        emit("TYPE", code)

      # (c1) KEY — a concrete plane key as a bare token (mcp / a2a / llm). Word-boundary, so it does
      #      NOT match inside busbar_mcp / plane_mcp / MCP_RUNTIME_SLOT (underscore is not a boundary).
      if (word_ci(lc, "mcp") || word_ci(lc, "a2a") || word_ci(lc, "llm")) emit("KEY", code)

      # (c2) DIALECT — one of the six dialect names as a token.
      if (word_ci(lc, "openai") || word_ci(lc, "anthropic") || word_ci(lc, "gemini") \
       || word_ci(lc, "bedrock") || word_ci(lc, "cohere") || word_ci(lc, "responses")) emit("DIALECT", code)
    }
  ' "$@"
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-purity-lint SELF-TEST (the side-channel scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0

  # ── RED (neutral): the four side channels the design names, plus a bare key + a dialect token ──
  # (i) a fake witness #[path=…busbar-mcp…]; (ii) a busbar_a2a:: reference; (iii) a McpFoo type;
  # plus a bare `mcp` key in a string and an `anthropic` dialect token — all must be flagged.
  cat >"$tmp/neutral_red.rs" <<'RED'
#[path = "../../../busbar-mcp/src/witness.rs"]
mod mcp_witness;
use busbar_a2a::TaskThing;
pub struct McpFoo;
fn route() { let plane_key = "mcp"; let dialect = "anthropic"; }
RED
  local out cat_count
  out="$(scan forward "$tmp/neutral_red.rs")"
  cat_count() { printf '%s\n' "$out" | awk -F'\t' -v c="$1" '$1==c{n++} END{print n+0}'; }
  local need ok=1
  for need in PATH-INCLUDE SYMBOL TYPE KEY DIALECT; do
    if [ "$(cat_count "$need")" -ge 1 ]; then
      note "RED neutral: flagged $need"
    else
      ok=0; note "RED neutral FAILED: $need not flagged"; fi
  done
  [ "$ok" -eq 1 ] || { fail=1; note "  (scanner output was:)"; printf '%s\n' "$out" | sed 's/^/    /'; }

  # ── GREEN (neutral): the intentional neutral ABI, plus a comment / block-comment / cfg(test) mod
  # that MENTION plane vocabulary — none may be flagged. This is the executable proof of the
  # curated allow-list AND of the comment/test exclusion.
  cat >"$tmp/neutral_green.rs" <<'GREEN'
use busbar_substrate::plane::{PlaneDecl, PlaneRecord};
use busbar_api::store::{ProtocolDecl, PlaneSlots};
// a comment naming mcp a2a llm anthropic gemini and McpCallRecord must be ignored
/* a block comment naming TaskRow and openai and bedrock also ignored */
pub fn install(d: &PlaneDecl, r: PlaneRecord) {
    install_planes(&[d]);
    install_protocols(&[]);
    install_diagnostics(&[]);
    let _slots = plane_slots();
    let _diag = PLANE_TASK_CHAIN_VERIFY_FAILED;
    let _n = BUILTIN_PLANE_DECLS.len();
}
#[cfg(test)]
mod tests {
    fn t() { let _ = McpCallRecord::default(); let k = "mcp"; let d = "anthropic"; }
}
GREEN
  out="$(scan forward "$tmp/neutral_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN neutral: flagged none of the ABI / comment / block-comment / cfg(test) fixtures"
  else
    fail=1; note "GREEN neutral FAILED: expected 0 flags, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── FROZEN-WIRE CARVE-OUT: the pragma exempts the VOCABULARY rules (KEY/DIALECT/TYPE) on ITS line
  # ONLY, and NEVER launders a PATH-INCLUDE or SYMBOL. Three fixtures, one property each. ──
  # (1) GREEN: a frozen `mcp:` wire field + its `McpEndpointSection` snapshot type flag nothing, in
  #     BOTH pragma placements: (a) a TRAILING pragma on a line that does not end in `{`, and (b) a
  #     STANDALONE pragma comment directly ABOVE a brace-terminated line — the exact shape rustfmt
  #     produces when it relocates a comment that trailed an opening `{` (proven on this very tree).
  cat >"$tmp/frozen_green.rs" <<'FZG'
    pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire DeployCfg mcp: key + snapshot type
pub(crate) struct McpEndpointSection(Option<Box<dyn PlaneEndpointCfg>>); // plane-purity: frozen-wire snapshot type
    // plane-purity: frozen-wire reads the frozen mcp: field (rustfmt moved this off the { line below)
    if cfg.mcp.is_some() {
        errors.push("ok");
    }
FZG
  out="$(scan forward "$tmp/frozen_green.rs")"
  if [ -z "$out" ]; then
    note "frozen-wire GREEN: trailing AND standalone-above pragmas both exempt KEY/TYPE (flagged none)"
  else
    fail=1; note "frozen-wire GREEN FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi
  # (1b) BLEED CONTROL: a TRAILING pragma must NOT exempt the FOLLOWING line — only a standalone
  #      pragma comment does. The line after a trailing-pragma line still flags its own tokens.
  cat >"$tmp/frozen_bleed.rs" <<'FZB'
    pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire DeployCfg mcp: key + snapshot type
    pub(crate) other: McpDemotionRow,
FZB
  out="$(scan forward "$tmp/frozen_bleed.rs")"
  if printf '%s\n' "$out" | awk -F'\t' '$1=="TYPE" && $2 ~ /:2$/{n++} END{exit !n}'; then
    note "frozen-wire BLEED CONTROL: a trailing pragma did NOT exempt the following line"
  else
    fail=1; note "frozen-wire BLEED FAILED: trailing pragma leaked onto the next line (got: $out)"
  fi
  # (2) CONTROL: the SAME tokens WITHOUT the pragma still flag — proving the pragma, not some other
  #     quirk, is what exempts them (a green fixture that would be green anyway proves nothing).
  cat >"$tmp/frozen_control.rs" <<'FZC'
    pub(crate) mcp: McpEndpointSection,
FZC
  out="$(scan forward "$tmp/frozen_control.rs")"
  if printf '%s\n' "$out" | awk -F'\t' '$1=="KEY"{k++} $1=="TYPE"{t++} END{exit !(k&&t)}'; then
    note "frozen-wire CONTROL: the same line WITHOUT the pragma still flags KEY+TYPE"
  else
    fail=1; note "frozen-wire CONTROL FAILED: unpragma'd mcp:/McpEndpointSection must still flag (got: $out)"
  fi
  # (3) RED: the pragma must NOT launder a structural side channel. A `#[path=…busbar-mcp…]` and a
  #     `busbar_mcp::` reach, each carrying the pragma, must STILL be flagged.
  cat >"$tmp/frozen_abuse.rs" <<'FZA'
#[path = "../../../busbar-mcp/src/witness.rs"] mod w; // plane-purity: frozen-wire (abuse: must NOT excuse)
use busbar_mcp::Thing; // plane-purity: frozen-wire (abuse: must NOT excuse)
FZA
  out="$(scan forward "$tmp/frozen_abuse.rs")"
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="PATH-INCLUDE"{n++} END{print n+0}')" -ge 1 ] \
   && [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SYMBOL"{n++} END{print n+0}')" -ge 1 ]; then
    note "frozen-wire ABUSE: the pragma did NOT launder PATH-INCLUDE or SYMBOL (both still flagged)"
  else
    fail=1; note "frozen-wire ABUSE FAILED: pragma laundered a structural side channel (got: $out)"
  fi

  # ── RED (reverse): (iv) a plane crate reaching BACK into core implementation ──
  cat >"$tmp/plane_red.rs" <<'RRED'
use busbar_core::internal::foo;
fn f() { let _ = busbar_core::proto::PROTO_ANTHROPIC; }
RRED
  out="$(scan reverse "$tmp/plane_red.rs")"
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="BACKWARDS"{n++} END{print n+0}')" -ge 1 ]; then
    note "RED reverse: flagged the busbar_core:: backwards reach"
  else
    fail=1; note "RED reverse FAILED: backwards reach not flagged (got: $out)"
  fi

  # ── GREEN (reverse): a plane crate naming ONLY the substrate/api ABI is clean ──
  cat >"$tmp/plane_green.rs" <<'RGREEN'
use busbar_substrate::plane::PlaneDecl;
use busbar_api::store::PlaneRecord;
// busbar_core:: named only in a comment is not a reach
GREEN
RGREEN
  out="$(scan reverse "$tmp/plane_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN reverse: a plane crate naming only the substrate/api ABI is clean"
  else
    fail=1; note "GREEN reverse FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  if [ "$fail" -ne 0 ]; then
    red "plane-purity-lint SELF-TEST FAILED — the scanner would let a side channel through"
    return 1
  fi
  grn "plane-purity-lint self-test: ALL GREEN (scanner RED/GREEN discipline proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
# Scans the tree, prints a categorized report, and returns the total violation count via $REPORT_TOTAL.
REPORT_TOTAL=0
run_report() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local nf pf
  nf="$(neutral_files)"; pf="$(plane_files)"

  : >"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$nf" ] && scan forward $nf >>"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$pf" ] && scan reverse $pf >>"$tmp/hits"

  local total; total="$(wc -l <"$tmp/hits" | tr -d ' ')"
  REPORT_TOTAL="$total"

  hdr "NEUTRAL-PURITY report — side channels in the neutral crates + backwards reach from the planes"
  note "neutral roots: $NEUTRAL_ROOTS"
  note "plane roots:   $PLANE_ROOTS"

  hdr "by category (side channels by kind — a clean tree reports zero)"
  # Category order fixed so the report is stable; count each even when zero.
  local c n
  for c in PATH-INCLUDE SYMBOL TYPE KEY DIALECT BACKWARDS; do
    n="$(awk -F'\t' -v c="$c" '$1==c{n++} END{print n+0}' "$tmp/hits")"
    printf '  %-13s %6d\n' "$c" "$n"
  done
  printf '  %-13s %6d\n' "TOTAL" "$total"

  hdr "top 15 files by violation count"
  awk -F'\t' '{split($2,a,":"); f[a[1]]++} END{for(k in f) printf "%6d  %s\n", f[k], k}' "$tmp/hits" \
    | sort -rn | head -15 | sed 's/^/  /'

  # Keep the hit list available for callers that want the full detail.
  cp "$tmp/hits" "${PLANE_PURITY_HITS_OUT:-/dev/null}" 2>/dev/null || true
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --baseline)
    # INFORMATIONAL: surface the baseline on every push WITHOUT going red. Always exit 0.
    run_report
    hdr "verdict"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "plane-purity: the neutral crates are CLEAN (0 side channels) — the \`--check\` gate enforces this."
    else
      ylw "plane-purity: $REPORT_TOTAL side channel(s) — a regression (this baseline mode is informational)."
      note "The baseline is informational and never reddens CI; the blocking gate is \`--check\`."
      note "\`--check\` is wired as the \`plane-purity\` qa segment, now \`active\`: with the neutral crates"
      note "drained to zero it passes green, and any side channel that reappears here fails it RED."
    fi
    exit 0
    ;;
  --check | "")
    # BLOCKING (fail-closed): the PERMANENT gate. Red on ANY violation. Wired into the reserved
    # `plane-purity` qa segment; arming it (reserved→active) is a one-line flip once the tree is clean.
    run_report
    hdr "verdict"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "plane-purity gate: PASS — no side channel in the neutral crates, no backwards reach"
      exit 0
    fi
    red "plane-purity gate: FAIL — $REPORT_TOTAL side channel(s) cross AROUND the ABI (see report above)"
    note "Every one is a violation to REMOVE, not to gate. Route it through the ABI:"
    note "  PATH-INCLUDE → the plane's tests live in the plane crate; core exercises it via the registry."
    note "  SYMBOL/TYPE  → cross the ABI as an opaque PlaneRecord / a registry capability lookup."
    note "  KEY/DIALECT  → read the opaque &str key the registry supplies; the registry is the truth."
    note "  BACKWARDS    → a plane may name the substrate/api ABI, never busbar_core:: implementation."
    exit 1
    ;;
  -h | --help)
    sed -n '2,60p' "$0"
    ;;
  *)
    echo "usage: $0 [--selftest | --baseline | --check]" >&2
    exit 2
    ;;
esac
