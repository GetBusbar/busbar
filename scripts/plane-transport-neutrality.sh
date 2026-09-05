#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-transport-neutrality.sh — THE VOICE-TRANSPORT/MEDIA NEUTRALITY GATE for the neutral crates.
#
# WHY THIS EXISTS (companion to scripts/plane-purity-lint.sh):
#   plane-purity-lint bans the plane KEYS (mcp/a2a/llm/voice) and the six LLM DIALECTS as tokens in the
#   neutral crates (busbar-core / busbar-substrate / busbar-api). But Plane-4 (busbar-voice) drags in a
#   second vocabulary that plane-purity does NOT name: the duplex/live-voice TRANSPORT and MEDIA nouns
#   — `rtc` / `sdp` / `webrtc` / `twilio` / `dtmf` / `rtp` / `sideband` / `realtime` / `audio` / `mulaw`
#   / `g711` / `barge`. The voice plane owns them 100% (docs/design/plane4-duplex-session.md §7.2); a leak
#   of any of them into a NEUTRAL crate is exactly the forward-edge regression — core learning a
#   protocol's transport words — that the plane ABI exists to prevent. No BLOCKING gate covered them
#   (plane-abi-neutrality.sh scans only busbar-plugin/hot; plane-grep-gate.sh is report-only). This is
#   that gate: a fail-closed forward scan of the neutral crate sources for the transport/media nouns,
#   asserting ZERO.
#
# WHAT IT SCANS, and HOW — mirroring plane-purity-lint's scanner discipline:
#   Every non-test `.rs` under the NEUTRAL roots. Comments and doc-strings are STRIPPED (respecting
#   string literals) so a doc-comment that legitimately DISCUSSES voice transport is not a false hit;
#   only code tokens are judged. Test code (`*/tests/*`, `*_test(s).rs`, and `#[cfg(test)] mod { … }`
#   blocks) is excluded — the ban is on the neutral ABI the crates EXPORT, not their unit tests. A noun
#   is flagged when it appears as a WORD (identifier-boundary, case-insensitive: `sdp`, `SDP`) OR as a
#   CamelCase TOKEN (`SdpOffer`, `RtpStream`, `WebrtcTrack`) — the two shapes a leaked transport name
#   actually takes in Rust source. The identifier boundary is `[^a-z0-9_]` — underscore is NOT a
#   boundary, EXACTLY as plane-purity-lint's `word_ci`: an underscore-joined substring (`input_audio`)
#   is the tracked in-core-twin debt that gate scopes OUT, not a fresh transport leak, so this gate
#   scopes it out identically and stays GREEN on the current tree.
#
# ── THE TWO MODES (self-test first, then the enforcing gate) ────────────────────────────────────────
#     --selftest   Proves the scanner cannot be lied to: plants a `SdpOffer` CamelCase token and a bare
#                  `webrtc` word in a scratch tmpdir and asserts the scanner RED-flags them, and asserts
#                  a clean/allow (comment/test) fixture passes. Run FIRST in CI, like every sibling lint.
#     --check      BLOCKING (fail-closed). Exits non-zero on ANY hit in the neutral crates. The PERMANENT
#                  forward gate: the neutral crates carry ZERO transport/media nouns today, and any
#                  regression that introduces one fails it RED.
#
# No external deps beyond bash 3.2 + POSIX awk (macOS/Linux) — the same bare-runner posture as the
# sibling lints (plane-purity-lint.sh, structure-lint.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# The neutral crates (the ABI side) — single edit here if a neutral crate appears/disappears.
NEUTRAL_ROOTS="crates/busbar-core/src crates/busbar-substrate/src crates/busbar-substrate-values/src crates/api/src"

# The banned voice-transport/media nouns (Plane-4, docs/design/plane4-duplex-session.md §7.2). The
# lowercase forms drive the WORD rule; the Capitalized forms drive the CamelCase-token rule. Every one
# has ZERO hits in the neutral crates today (grep-verified) — the gate keeps it that way.
NOUNS_LC="rtc sdp webrtc twilio dtmf rtp sideband realtime audio mulaw g711 barge"
CAMEL_ALT="Rtc|Sdp|Webrtc|Twilio|Dtmf|Rtp|Sideband|Realtime|Audio|Mulaw|G711|Barge"

neutral_files() { find $NEUTRAL_ROOTS -name '*.rs' 2>/dev/null | sort; }

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits one TSV line per hit:  NOUN<TAB>file:line<TAB>trimmed-source
# Strips comments/block-comments (respecting string literals), excludes test files + `#[cfg(test)] mod`
# blocks, and flags a noun as a WORD (identifier boundary, case-insensitive) or a CamelCase TOKEN.
scan() {
  [ "$#" -gt 0 ] || return 0
  awk -v nouns_lc="$NOUNS_LC" -v camel="$CAMEL_ALT" '
    # Strip comments + block-comments, respecting string literals — identical discipline to
    # plane-purity-lint.sh: inblk persists across lines, instr resets per line.
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
    # A whole-word (identifier-boundary) case-insensitive hit of a lowercase needle. The pad makes a
    # match at line start/end boundary-clean; the class [^a-z0-9_] is the identifier boundary — EXACTLY
    # plane-purity-lint`s `word_ci`, so `_` is NOT a boundary and an underscore-joined substring
    # (`input_audio`) does not flag (that is the tracked in-core-twin debt, out of scope here too).
    function word_ci(lc, needle) { return (lc ~ ("[^a-z0-9_]" needle "[^a-z0-9_]")) }
    function emit(noun, text) { printf "%s\t%s:%d\t%s\n", noun, FILENAME, FNR, trim(text) }

    BEGIN { ncount = split(nouns_lc, N, " ") }

    # Per-FILE reset (awk shares state across the file list).
    FNR == 1 { inblk = 0; testdepth = 0; pend = 0 }

    {
      code = strip($0)
      pad  = " " code " "
      lc   = tolower(pad)
      nopen = gsub(/[{]/, "{", code); nclose = gsub(/[}]/, "}", code)

      istestfile = (FILENAME ~ /\/tests\// || FILENAME ~ /_tests?\.rs$/)

      # ── #[cfg(test)] mod { … } block tracking (unit-test code excluded), mirroring plane-purity ──
      is_cfgtest = (code ~ /#\[cfg\(/ && (lc ~ /[^a-z0-9_]test[^a-z0-9_]/))
      has_mod    = (code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/)
      entered = 0
      if (is_cfgtest && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && code ~ /[^[:space:]]/ && !is_cfgtest) {
        pend = 0
      } else if (testdepth > 0) {
        testdepth += nopen - nclose; if (testdepth < 0) testdepth = 0
      }
      if (is_cfgtest && !has_mod) pend = 1
      intest = (istestfile || testdepth > 0 || entered)
      if (intest) next

      # WORD rule — any transport noun as an identifier-boundary token (case-insensitive).
      for (i = 1; i <= ncount; i++) if (word_ci(lc, N[i])) { emit(N[i], code); }
      # CamelCase-TOKEN rule — a Capitalized noun followed by an uppercase letter, a non-identifier
      # char, or end-of-line: SdpOffer, RtpStream, WebrtcTrack, a bare `Sdp`.
      if (code ~ ("(" camel ")([A-Z]|[^A-Za-z0-9]|$)")) emit("CamelCase", code)
    }
  ' "$@"
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-transport-neutrality SELF-TEST (the transport/media scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out

  # ── RED: the two planted shapes the design names — a CamelCase `SdpOffer` (+ `RtpStream`,
  # `TwilioBridge`) and bare `webrtc` / `realtime` WORD tokens — must ALL be flagged. CamelCase-only
  # tokens are emitted under the `CamelCase` category; a bare lowercase noun under its own name. ──
  cat >"$tmp/red.rs" <<'RED'
pub struct SdpOffer { fingerprint: String }
pub struct RtpStream;
pub struct TwilioBridge;
fn negotiate() { let kind = "webrtc"; let realtime = true; }
RED
  out="$(scan "$tmp/red.rs")"
  local need ok=1
  for need in webrtc realtime CamelCase; do
    if printf '%s\n' "$out" | awk -F'\t' -v c="$need" '$1==c{n++} END{exit !(n>0)}'; then
      note "RED: flagged $need"
    else
      ok=0; note "RED FAILED: $need not flagged"; fi
  done
  # Prove the CamelCase rule caught ALL THREE CamelCase tokens (SdpOffer / RtpStream / TwilioBridge).
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="CamelCase"{n++} END{print n+0}')" -ge 3 ]; then
    note "RED: CamelCase rule flagged all 3 transport-named types"
  else
    ok=0; note "RED FAILED: CamelCase rule missed a transport-named type"; fi
  [ "$ok" -eq 1 ] || { fail=1; note "  (scanner output was:)"; printf '%s\n' "$out" | sed 's/^/    /'; }

  # ── GREEN: a comment / block-comment / cfg(test) mod that MENTION the transport nouns, and neutral
  # ABI code that names none — nothing may be flagged. Executable proof of the comment/test exclusion. ──
  cat >"$tmp/green.rs" <<'GREEN'
use busbar_substrate::plane::PlaneRecord;
// a comment naming sdp webrtc rtp twilio dtmf realtime audio mulaw and SdpOffer must be ignored
/* a block comment naming RtpStream and g711 and barge-in also ignored */
pub fn install(r: PlaneRecord) -> u64 { 0 }
#[cfg(test)]
mod tests {
    fn t() { let _ = "webrtc"; let _o = SdpOffer::default(); let _ = 0; /* rtp */ }
}
GREEN
  out="$(scan "$tmp/green.rs")"
  if [ -z "$out" ]; then
    note "GREEN: comment / block-comment / cfg(test) mentions flagged NONE"
  else
    fail=1; note "GREEN FAILED: expected 0 flags, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── CONTROL: the SAME `SdpOffer`/`webrtc` OUTSIDE a comment/test WOULD flag — so the GREEN pass is
  # the exclusion working, not the scanner being blind. ──
  cat >"$tmp/control.rs" <<'CTL'
pub struct SdpOffer;
fn f() { let _ = "webrtc"; }
CTL
  out="$(scan "$tmp/control.rs")"
  if printf '%s\n' "$out" | awk -F'\t' '$1=="webrtc"{w++} $1=="CamelCase"{c++} END{exit !(w&&c)}'; then
    note "CONTROL: the same tokens in real code DO flag (webrtc + CamelCase)"
  else
    fail=1; note "CONTROL FAILED: real-code SdpOffer/webrtc must flag (got: $out)"
  fi

  if [ "$fail" -ne 0 ]; then
    red "plane-transport-neutrality SELF-TEST FAILED — the scanner would let a transport noun through"
    return 1
  fi
  grn "plane-transport-neutrality self-test: ALL GREEN (scanner RED/GREEN discipline proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
run_check() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local nf; nf="$(neutral_files)"
  : >"$tmp/hits"
  # shellcheck disable=SC2086
  [ -n "$nf" ] && scan $nf >>"$tmp/hits"
  local total; total="$(wc -l <"$tmp/hits" | tr -d ' ')"

  hdr "VOICE-TRANSPORT/MEDIA neutrality — banned transport nouns in the neutral crates"
  note "neutral roots: $NEUTRAL_ROOTS"
  note "banned nouns:  $NOUNS_LC"

  hdr "verdict"
  if [ "$total" -eq 0 ]; then
    grn "plane-transport-neutrality gate: PASS — 0 voice-transport/media nouns in the neutral crates"
    return 0
  fi
  red "plane-transport-neutrality gate: FAIL — $total transport/media noun(s) leaked into the neutral crates:"
  sed 's/^/    /' "$tmp/hits" >&2
  note "The voice plane (busbar-voice) owns rtc/sdp/webrtc/twilio/dtmf/rtp/sideband/realtime/audio/mulaw/"
  note "g711/barge. A neutral crate must NEVER name a protocol's transport: cross the ABI as an opaque"
  note "PlaneRecord / a registry capability, never a transport noun in busbar-core/substrate/api."
  return 1
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest) run_selftest; exit $? ;;
  --check | "") run_check; exit $? ;;
  -h | --help) sed -n '2,45p' "$0" ;;
  *) echo "usage: $0 [--selftest | --check]" >&2; exit 2 ;;
esac
