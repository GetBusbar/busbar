#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# kernel-token-wire-purity-lint.sh -- the kernel never re-derives a usage token class from a raw
# provider wire pointer.
#
# The four token classes (tokens_in, tokens_out, cache_read, cache_write) are read through the
# plane's own §5.1 normalization (busbar-llm's dialect layer), never by the kernel reaching past
# that seam into a provider's raw response shape. This lint is the negative-space proof: it scans
# busbar-kernel's PRODUCTION source (comments, doc-comments and test code excluded, same
# discipline as scripts/plane-purity-lint.sh) for the raw wire field names each of the six
# dialects uses for token counts, and fails red the day one of them appears there.
#
#   anthropic/bedrock: input_tokens, output_tokens, cache_read_input_tokens,
#                       cache_creation_input_tokens
#   openai/responses:   prompt_tokens, completion_tokens, cached_tokens
#   gemini:             promptTokenCount, candidatesTokenCount, thoughtsTokenCount,
#                       cachedContentTokenCount
#   cohere:             billed_units, input_tokens (cohere's own usage shape)
#
# --check      BLOCKING: fails red on any hit outside a comment/doc-comment/test file.
# --selftest   proves the scanner: plants one fixture carrying a raw wire field name under
#              busbar-kernel/src and asserts the scan flags exactly it, then proves a clean
#              fixture and a comment-only mention both stay green.
#
# Pure grep/awk, no cargo, no network -- the bare-runner posture of the sibling *-lint.sh gates.
set -uo pipefail
cd "$(dirname "$0")/.."
repo="$(pwd)"

KERNEL_SRC="crates/busbar-kernel/src"

# The raw wire field names a dialect uses for a token count -- word-boundary matched so
# `input_tokens_total` (a plane-normalized aggregate, if one ever exists) is not a false hit but
# the bare provider field name is.
PATTERNS=(
  'input_tokens' 'output_tokens' 'cache_read_input_tokens' 'cache_creation_input_tokens'
  'prompt_tokens' 'completion_tokens' 'cached_tokens'
  'promptTokenCount' 'candidatesTokenCount' 'thoughtsTokenCount' 'cachedContentTokenCount'
  'billed_units'
)

# Strip `//` line comments and `/* */` block comments (string literals left intact), same rule the
# sibling purity lint uses, so a pattern mentioned only in prose does not false-positive.
strip_comments() {
  awk '
    BEGIN { inblk = 0 }
    {
      line = $0
      out = ""
      i = 1
      n = length(line)
      while (i <= n) {
        c = substr(line, i, 1)
        c2 = substr(line, i, 2)
        if (inblk) {
          if (c2 == "*/") { inblk = 0; i += 2; continue }
          i += 1; continue
        }
        if (c2 == "/*") { inblk = 1; i += 2; continue }
        if (c2 == "//") { break }
        out = out c
        i += 1
      }
      print out
    }
  '
}

# One (file, line, pattern) hit per line, production files only: excludes `*_tests.rs`, anything
# under a `/tests/` directory, and (approximately -- good enough for this narrow lint) a
# `#[cfg(test)]` file marked by that attribute on its own module-gate line is still scanned per
# LINE, but a hit inside an actual `#[test]` fn body is vanishingly unlikely to be a real wire
# literal rather than a fixture, and --selftest's clean-fixture case pins that a bare mention in a
# doc-comment (already stripped above) does not fire.
scan() {
  local root="$1" hits=0
  [ -d "$root" ] || return 0
  while IFS= read -r -d '' f; do
    case "$f" in
      */tests/*|*_tests.rs) continue ;;
    esac
    local stripped
    stripped="$(strip_comments <"$f")"
    for pat in "${PATTERNS[@]}"; do
      local ln
      ln="$(printf '%s\n' "$stripped" | grep -nE "\\b${pat}\\b" || true)"
      if [ -n "$ln" ]; then
        while IFS= read -r row; do
          [ -n "$row" ] || continue
          echo "${f}:${row%%:*}: raw wire field '${pat}' in kernel production source"
          hits=$((hits + 1))
        done <<<"$ln"
      fi
    done
  done < <(find "$root" -name '*.rs' -print0)
  return "$hits"
}

check() {
  local out hits
  out="$(scan "$KERNEL_SRC")"; hits=$?
  if [ "$hits" -gt 0 ]; then
    echo "kernel-token-wire-purity: RED -- ${hits} raw wire token field(s) found in busbar-kernel production source:"
    echo "$out"
    return 1
  fi
  echo "kernel-token-wire-purity: GREEN -- no raw provider wire token field reaches busbar-kernel"
  return 0
}

selftest() {
  echo "== kernel-token-wire-purity SELF-TEST =="
  local tmp fails=0 cases=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/kernel-token-wire-purity-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  say() { printf '%s  %s\n' "$1" "$2"; cases=$((cases + 1)); [ "$1" = PASS ] || fails=$((fails + 1)); }

  mkdir -p "$tmp/dirty/src" "$tmp/clean/src" "$tmp/commented/src"

  cat >"$tmp/dirty/src/lib.rs" <<'EOF'
fn class_of(v: &serde_json::Value) -> i64 {
    v["input_tokens"].as_i64().unwrap_or(0)
}
EOF
  local out hits
  out="$(scan "$tmp/dirty/src")"; hits=$?
  if [ "$hits" -eq 1 ] && printf '%s' "$out" | grep -q "input_tokens"; then
    say PASS "a raw wire field in production source is flagged, exactly once"
  else
    say FAIL "dirty fixture: hits=$hits out=$out"
  fi

  cat >"$tmp/clean/src/lib.rs" <<'EOF'
fn class_of(units: &busbar_api::ModelTokens) -> u64 {
    units.output
}
EOF
  out="$(scan "$tmp/clean/src")"; hits=$?
  [ "$hits" -eq 0 ] && say PASS "plane-normalized reads stay clean" \
    || { say FAIL "clean fixture: hits=$hits out=$out"; }

  cat >"$tmp/commented/src/lib.rs" <<'EOF'
// This crate must never read a raw `input_tokens` wire field; see PB-86.
fn class_of() -> u64 { 0 }
EOF
  out="$(scan "$tmp/commented/src")"; hits=$?
  [ "$hits" -eq 0 ] && say PASS "a comment-only mention of the vocabulary stays green" \
    || { say FAIL "commented fixture: hits=$hits out=$out"; }

  mkdir -p "$tmp/dirty/src/tests"
  echo 'fn f() { let _ = "input_tokens"; }' >"$tmp/dirty/src/tests/fixture_tests.rs"
  out="$(scan "$tmp/dirty/src")"; hits=$?
  [ "$hits" -eq 1 ] && say PASS "a hit under a /tests/ directory is excluded (still just the one lib.rs hit)" \
    || { say FAIL "tests-dir exclusion: hits=$hits out=$out"; }

  echo
  if [ "$fails" -eq 0 ]; then
    echo "kernel-token-wire-purity selftest: GREEN (${cases} cases)"; return 0
  fi
  echo "kernel-token-wire-purity selftest: RED (${fails}/${cases} cases failed)"; return 1
}

case "${1:-}" in
  --selftest) selftest ;;
  --check | "") check ;;
  *) echo "usage: $0 [--selftest | --check]" >&2; exit 2 ;;
esac
