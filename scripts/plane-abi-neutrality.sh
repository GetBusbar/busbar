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
crate_src="$repo/crates/busbar-plugin/src/hot"

# The banned protocol/role nouns (DESIGN-v5 §neutrality-witness). Matched case-insensitively as
# substrings of IDENTIFIERS on declaration lines (see the grep below).
banned=(llm mcp a2a tool agent sampling task server card round prompt)

# ── self-check: every mandated token must appear in the ban list above ──────────────────────────
mandated=(llm mcp a2a tool agent sampling task server card round prompt)
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

if [ ! -d "$crate_src" ]; then
  echo "FAIL plane-abi-neutrality: crate source not found at $crate_src" >&2
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
