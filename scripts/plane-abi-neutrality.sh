#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-abi-neutrality.sh — THE NEUTRALITY WITNESS for the protocol-plane ABI.
#
# The plane ABI's whole claim is that its capability surface was DERIVED from a primitive taxonomy
# (carrier / scope / egress / metering), NOT ENUMERATED from any one protocol plane. That claim rots
# silently the first time someone names a type/fn/variant after a protocol or role noun. This gate
# greps the HOT lane of the `busbar-plugin` crate (`src/hot/`) for the banned set and asserts ZERO —
# a machine check that "derived, not enumerated" STAYS true as capabilities are added. Only the HOT
# lane is scanned: the COLD lane (`src/cold/`) keeps its pre-existing store/auth/hook vocabulary and
# is deliberately exempt, and the shared crate root is neutral by construction.
#
# It ALSO covers its own token list: a self-check asserts every token the design mandates is present
# in the ban regex below (the original witness once omitted `server`/`card` and so could not catch
# its own `server-stream` leak). If a mandated token is missing from the regex, this gate FAILS.
#
# STATUS: additive/foundation. Wired here for later inclusion in the full gate; it PASSES today.

set -euo pipefail

# The directory this script lives in is `scripts/`; the crate is a sibling under `crates/`.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
crate_src="${PLANE_ABI_SRC:-$repo/crates/busbar-plugin/src/hot}"

# ── SELF-TEST ─────────────────────────────────────────────────────────────────────────────────────
# Every check below is driven for real by re-invoking THIS script with one input changed, so what is
# proven is the script that runs in CI and not a re-implementation of it. The four env hooks exist
# only for that: nothing in the repo sets them.
if [ "${1:-}" = "--selftest" ]; then
  st_tmp="$(mktemp -d)"; trap 'rm -rf "$st_tmp"' EXIT
  st_cases=0; st_fails=0
  st_say() { printf '%s  %s\n' "$1" "$2"; st_cases=$((st_cases + 1)); [ "$1" = PASS ] || st_fails=$((st_fails + 1)); }
  echo "== plane-abi-neutrality SELF-TEST =="

  # 1. THE MANDATE IS NOT A COPY OF THE ANSWER. Drop a token the design mandates from the ban list;
  #    the self-check must name it. This is the case the old `mandated=(…)` byte-copy could not fail.
  if PLANE_ABI_BANNED="llm mcp a2a tool agent sampling task card round prompt voice realtime audio" \
       bash "$0" >/dev/null 2>&1; then
    st_say FAIL "a ban list missing a design-mandated token (\`server\`) was accepted"
  else
    st_say PASS "a ban list missing a design-mandated token is refused"
  fi

  # 2. And the real ban list still satisfies the mandate, so case 1 is not a check that refuses
  #    everything.
  if bash "$0" >/dev/null 2>&1; then
    st_say PASS "the checked-in ban list satisfies the design's mandate"
  else
    st_say FAIL "the checked-in ban list does not satisfy its own mandate"
  fi

  # 3. A mandate document that is not there must be RED, never a silent fallback to the ban list
  #    itself — which is the tautology in a different coat.
  if PLANE_ABI_TAXONOMY_DOC="$st_tmp/no-such-doc.md" bash "$0" >/dev/null 2>&1; then
    st_say FAIL "a missing mandate document was accepted"
  else
    st_say PASS "a missing mandate document is refused, not defaulted to the ban list"
  fi

  # 4. A banned noun in an EXPORTED declaration is caught, and 5. a clean tree is not.
  mkdir -p "$st_tmp/dirty" "$st_tmp/clean" "$st_tmp/testpath/tests"
  printf 'pub struct McpTransport;\n' >"$st_tmp/dirty/lib.rs"
  printf 'pub struct CarrierScope;\n' >"$st_tmp/clean/lib.rs"
  if PLANE_ABI_SRC="$st_tmp/dirty" bash "$0" >/dev/null 2>&1; then
    st_say FAIL "a banned noun in an exported declaration was accepted"
  else
    st_say PASS "a banned noun in an exported declaration is refused"
  fi
  if PLANE_ABI_SRC="$st_tmp/clean" PLANE_ABI_TEST_RATCHET=0 bash "$0" >/dev/null 2>&1; then
    st_say PASS "a taxonomy-named declaration is not a finding"
  else
    st_say FAIL "a clean declaration was refused — the witness refuses everything"
  fi

  # 6. THE TEST-PATH RATCHET. A test-path declaration is reported and ratcheted, never dropped from
  #    the scan: one more than the ratchet is RED.
  printf 'fn round_trips_a_task() {}\n' >"$st_tmp/testpath/tests/a_tests.rs"
  printf 'fn prompt_helper() {}\n' >"$st_tmp/testpath/tests/b_tests.rs"
  if PLANE_ABI_SRC="$st_tmp/testpath" PLANE_ABI_TEST_RATCHET=1 bash "$0" >/dev/null 2>&1; then
    st_say FAIL "two test-path declarations passed a ratchet of one"
  else
    st_say PASS "a test-path declaration above the ratchet is RED (reported, not dropped from the scan)"
  fi
  if PLANE_ABI_SRC="$st_tmp/testpath" PLANE_ABI_TEST_RATCHET=2 bash "$0" >/dev/null 2>&1; then
    st_say PASS "and at the ratchet it passes while still printing both sites"
  else
    st_say FAIL "the ratchet refused the count it is set to"
  fi

  # 7. THE ZERO-FILE CASE. Cases 4/5 prove what the witness SEES; this proves what it does when handed
  #    nothing to look at. A hot lane that EXISTS but has been drained is the one way this gate reads
  #    its own passing answer — 0 banned nouns — off a tree it never opened.
  mkdir -p "$st_tmp/emptylane"
  if PLANE_ABI_SRC="$st_tmp/emptylane" bash "$0" >/dev/null 2>&1; then
    st_say FAIL "a hot lane holding no .rs was scanned as zero files and reported ok"
  else
    st_say PASS "a hot lane holding no .rs is refused (zero files scanned is RED, not a clean ABI)"
  fi

  echo
  [ "$st_fails" -eq 0 ] && { echo "plane-abi-neutrality selftest: GREEN (${st_cases} cases)"; exit 0; }
  echo "plane-abi-neutrality selftest: RED (${st_fails}/${st_cases} cases failed)"; exit 1
fi

# The banned protocol/role nouns (DESIGN-v5 §neutrality-witness). Matched case-insensitively as
# substrings of IDENTIFIERS on declaration lines (see the grep below).
# `voice`/`realtime`/`audio` are the Plane-4 (busbar-voice) nouns: the duplex/live-voice plane owns
# them 100% (docs/design/plane4-duplex-session.md §7.2), so a leak of any of them into the neutral
# plane ABI is exactly the regression this witness must catch BEFORE the plane lands.
banned=(llm mcp a2a tool agent sampling task server card round prompt voice realtime audio)

# ── self-check: every mandated token must appear in the ban list above ──────────────────────────
mandated=(llm mcp a2a tool agent sampling task server card round prompt voice realtime audio)
missing_tokens=()
for t in "${mandated[@]}"; do
  found=0
  for b in "${banned[@]}"; do [ "$b" = "$t" ] && found=1 && break; done
  [ "$found" -eq 0 ] && missing_tokens+=("$t")
done
if [ "${#missing_tokens[@]}" -ne 0 ]; then
  echo "FAIL plane-abi-neutrality: the ban list is missing mandated tokens: ${missing_tokens[*]}" >&2
  echo "  The witness cannot catch a leak of a token it does not list. Add them to \`banned\`." >&2
  exit 1
fi

# ── totality self-check: EVERY canonical plane key must be in the ban list ───────────────────────
# The ban list above is a curated superset (plane keys + role/media nouns); the plane KEYS it must
# never omit are single-sourced in scripts/plane-keys.sh. A plane added there whose name is not yet
# banned here is a plane whose noun this witness would wave through — fail loudly so the day a plane
# lands, this row lands with it.
# shellcheck source=scripts/plane-keys.sh
. "$here/plane-keys.sh"
missing_keys=()
for k in $PLANE_KEYS; do
  found=0
  for b in "${banned[@]}"; do [ "$b" = "$k" ] && found=1 && break; done
  [ "$found" -eq 0 ] && missing_keys+=("$k")
done
if [ "${#missing_keys[@]}" -ne 0 ]; then
  echo "FAIL plane-abi-neutrality: canonical plane key(s) not in the ban list: ${missing_keys[*]}" >&2
  echo "  scripts/plane-keys.sh names these planes; the witness cannot catch a leak of a plane" >&2
  echo "  noun it does not list. Add them to \`banned\`." >&2
  exit 1
fi

if [ ! -d "$crate_src" ]; then
  echo "FAIL plane-abi-neutrality: crate source not found at $crate_src" >&2
  exit 1
fi

# ── THE ZERO-FILE GUARD ───────────────────────────────────────────────────────────────────────────
# The check above proves the hot lane is THERE; this proves it still holds the ABI this witness is
# about. A directory that exists but carries no Rust greps clean, and 0 banned nouns over 0 files is
# the passing answer to the only ban here — indistinguishable from a genuinely derived capability
# surface. That is not hypothetical: point PLANE_ABI_SRC at an empty directory and the old code
# printed `ok … 0 banned noun(s) in exported declarations` and exited 0. Every sibling gate
# (plane-grep-gate, plane-noun-gate, plane-transport-neutrality, plane-config-noun-gate) separates the
# missing-root case from the zero-file case for exactly this reason; this one now does too.
n_files="$(find "$crate_src" -name '*.rs' | grep -c . || true)"
if [ "$n_files" -eq 0 ]; then
  echo "FAIL plane-abi-neutrality: $crate_src holds $n_files .rs file(s); zero is RED." >&2
  echo "  A scan of zero files reports zero banned nouns, which reads exactly like a neutral ABI." >&2
  echo "  If the hot lane moved, point this script at its new home in a reviewed diff that says so —" >&2
  echo "  do not let the witness go quiet by scanning a drained directory." >&2
  exit 1
fi

# Build a single alternation, e.g. (llm|mcp|a2a|...). We scan DECLARATION contexts — lines that
# introduce a Rust identifier (struct/enum/fn/type/const/trait/mod), plus enum-variant lines and
# pub field lines — so prose in doc comments (which legitimately discusses neutrality) is not
# scanned, only the names the ABI actually exports.
alt="$(IFS='|'; echo "${banned[*]}")"

# Declaration-ish lines: those containing a Rust item keyword or a `pub` field/variant. We then look
# for a banned token as a WORD within them (case-insensitive). This is deliberately conservative:
# it targets names, not comments.
# Substring (NOT word-boundary) match: a banned noun concatenated into a name — `McpTransport`,
# `server_stream` — is exactly the leak to catch, and `-w` would miss it. The declaration-line
# pre-filter keeps prose in `///`/`//` doc comments (which legitimately discuss neutrality) out of
# scope, so only names the ABI actually exports are scanned.
#
# MATCH THE CODE, NOT THE PATH: `grep -rIn` prefixes each hit with `<file>:<lineno>:`, and that
# `<file>` is an ABSOLUTE path — under a checkout dir that happens to contain a banned noun (a git
# worktree is literally named `agent-<hash>`, and `agent` is banned) a naive `grep -iE "$alt"` over
# the prefixed line matches the PATH on EVERY declaration and the witness fails everywhere,
# spuriously. So strip the `<file>:<lineno>:` prefix and test the CODE ONLY — exactly as
# `plane-purity-lint` scans the source line, never the path it lives under. The full prefixed line
# is still what we PRINT, so a real hit is still reported with its file:line.
hits="$(
  grep -rInE '^[[:space:]]*(pub[[:space:]]+)?(struct|enum|fn|type|const|trait|mod|[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[:(=,])' "$crate_src" \
    | awk -v pat="$alt" '{ code = $0; sub(/^[^:]*:[0-9]+:/, "", code); if (tolower(code) ~ tolower(pat)) print }' \
    || true
)"

if [ -n "$hits" ]; then
  echo "FAIL plane-abi-neutrality: banned protocol/role noun in a plane-ABI declaration:" >&2
  echo "$hits" | sed 's/^/    /' >&2
  echo "  The plane ABI must be DERIVED from the primitive taxonomy, never named after one protocol." >&2
  exit 1
fi

echo "ok plane-abi-neutrality: 0 banned nouns in $(basename "$crate_src")/ (ban list self-check passed)"
