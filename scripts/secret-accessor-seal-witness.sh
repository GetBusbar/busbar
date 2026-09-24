#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# secret-accessor-seal-witness.sh — THE DECISIONS #40 SECRET-ACCESSOR SEAL WITNESS.
#
# WHY THIS EXISTS (DECISIONS #40):
#   The two raw secret-byte accessors on the plugin-facing contract ABI are now sealed behind the
#   `busbar_contract::plugin::KernelSeal` authority token:
#       SecretValue::expose(&self, seal: &dyn KernelSeal) -> &[u8]     (Secret::resolve() output)
#       KeyMaterial::bytes(&self, seal: &dyn KernelSeal) -> &[u8]      (AuthScheme::refresh() output)
#   The only way to hold a seal is `KernelSeal::acquire_for_kernel()`, defined in busbar-contract
#   (crates/busbar-contract/src/caps/token.rs). There is NO dependency wall around it: the
#   manifest allow-list (qa/construction.toml, rule manifest-allowlist) lets every plugin-kind
#   crate name busbar-contract freely, and a manifest reads dependency NAMES -- it cannot see a
#   module path. The seal's own doc says so: "Anything that can name `busbar-contract` can still
#   call this." So nothing in the type system or the manifests stops a plugin; THIS SCAN is the
#   wall. It is the RED-provable proof that no in-tree PLUGIN crate reaches for either accessor or
#   for the seal itself. --selftest re-derives the seal's home crate and refuses if this header
#   names a crate the workspace does not have (item 467: it once cited a seal crate that never existed,
#   and a reviewer reading it would believe a wall stood where none does).
#
# THE PLUGIN BOUNDARY. A plugin is a `crate-type = ["cdylib"]` crate: the artefact the loader dlopen's.
#   That is the exact population #40's dep-wall targets, and the one that must never touch a seal.
#   (In-tree kernel-side crates — the units and the transports — legitimately hold caps and mint
#   tokens on the hot path; they are NOT cdylib and are out of scope here by construction.)
#
# FORBIDDEN in any cdylib plugin crate's source:
#   KernelSeal::acquire_for_kernel   — obtaining the seal (kernel only)
#   SecretValue::expose / .expose(   — reading a resolved secret's bytes
#   KeyMaterial::bytes  / .bytes(seal) — reading refreshed key material's bytes
#
# Mirrors the sibling gates: comment/string-stripping scan, --selftest that proves RED on a planted
# bad fixture and GREEN on a clean one. No external deps beyond bash 3.2 + POSIX awk.
#
# FOLD NOTE: when scripts/kind-isolation-dep-wall.py (the #40 gate, branch kind-isolation-gate) lands
#   in this tree, fold these three needles into its plugin-crate scan and retire this standalone.
set -uo pipefail
cd "$(dirname "$0")/.." || { echo "seal witness: FAIL — cannot cd to the repo root" >&2; exit 1; }

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# The forbidden needles (ERE alternation), matched after comment/string stripping.
# Bracket expressions ([.] / [(]) rather than backslash escapes: awk's -v assignment eats a
# backslash before it ever reaches the regex engine, so \( would arrive as a bare, unbalanced (.
NEEDLES='KernelSeal::acquire_for_kernel|SecretValue::expose|KeyMaterial::bytes|[.]expose[(]|[.]bytes[(]'

# Strip // and /* */ comments and "..." string bodies from one line (so a needle in prose/a doctest
# example or a string literal is not a violation). Shared by the real run and the self-test.
strip_awk='
function strip(line,   res,i,n,c,c2,instr) {
  res=""; n=length(line); i=1; instr=0
  while (i<=n) {
    c=substr(line,i,1); c2=substr(line,i,2)
    if (inblk) { if (c2=="*/"){inblk=0;i+=2} else {i++} continue }
    if (instr) { if (c=="\\"){i+=2;continue} if (c=="\""){instr=0} i++; continue }
    if (c2=="/*"){inblk=1;i+=2;continue}
    if (c2=="//"){break}
    if (c=="\""){instr=1;i++;continue}
    res=res c; i++
  }
  return res
}
FNR==1 { inblk=0 }
{ code=strip($0); if (code ~ needle) printf "%s:%d\t%s\n", FILENAME, FNR, code }
'

# Every crate whose Cargo.toml declares a cdylib crate-type — the plugin population.
plugin_crates() {
  grep -rl 'crate-type[^]]*cdylib' crates/*/Cargo.toml 2>/dev/null | sed 's,/Cargo.toml,,'
}

scan() { awk -v needle="$NEEDLES" "$strip_awk" "$@"; }

# The crate the header names as the seal's home, and the file that defines the seal.
SEAL_HOME_CRATE="busbar-contract"

# check_crates <crate-dir>... — the verdict over a crate list. Every named crate must contribute at
# least one .rs file under src/ (item 526): a crate the header lists as "scanned" but whose source
# the scan never read is a partial scan dressed as a full one, and a zero-file scan is RED, as in
# every sibling gate (plane-grep-gate.sh, plane-noun-gate.sh, plane-config-noun-gate.sh). Prints the
# per-crate and total file counts so a partial run and a full run are never the same output.
check_crates() {
  local c n files="" total=0 empty=""
  if [ "$#" -eq 0 ]; then red "seal witness: FAIL — no plugin crate named to scan"; return 1; fi
  note "plugin crates scanned (.rs files under src/):"
  for c in "$@"; do
    n=0
    if [ -d "$c/src" ]; then n="$(find "$c/src" -name '*.rs' -type f | wc -l | tr -d ' ')"; fi
    printf '    %s  %s file(s)\n' "$c" "$n"
    if [ "$n" -eq 0 ]; then empty="$empty $c"; continue; fi
    files="$files
$(find "$c/src" -name '*.rs' -type f)"
    total=$((total + n))
  done
  if [ -n "$empty" ]; then
    red "seal witness: FAIL — plugin crate(s) with ZERO .rs files under src/ (unscanned, not clean):$empty"
    return 1
  fi
  note "total: $total file(s) across $# crate(s)"
  local out
  # shellcheck disable=SC2086
  out="$(scan $files </dev/null)"
  if [ -z "$out" ]; then
    grn "seal witness: PASS — $total file(s) in $# cdylib plugin crate(s); none references acquire_for_kernel / SecretValue::expose / .expose( / KeyMaterial::bytes / .bytes("
    return 0
  fi
  hdr "VIOLATIONS — a plugin reached a sealed accessor (this is a #40 finding)"
  printf '%s\n' "$out" | sed 's/^/  /'
  red "seal witness: FAIL — a cdylib plugin reaches a raw secret accessor or the kernel seal"
  return 1
}

# header_crate_claims — (item 467) every `busbar-*` crate this file's own header names must be a
# crate the workspace declares, and the seal must live in SEAL_HOME_CRATE. Prints the problems.
header_crate_claims() {
  local bad="" name home
  for name in $(awk '/^set -uo pipefail/{exit} {print}' "$0" | grep -oE 'busbar-[a-z][a-z0-9-]*[a-z0-9]' | sort -u); do
    grep -qE "^name = \"$name\"" crates/*/Cargo.toml 2>/dev/null || bad="$bad
header names crate $name, which no crates/*/Cargo.toml declares"
  done
  home="$(grep -rlE 'fn acquire_for_kernel[(]' crates/*/src 2>/dev/null | head -n 1)"
  if [ -z "$home" ]; then
    bad="$bad
fn acquire_for_kernel( is defined nowhere under crates/*/src -- the seal moved; re-derive this header"
  elif ! grep -qE "^name = \"$SEAL_HOME_CRATE\"" "${home%%/src/*}/Cargo.toml" 2>/dev/null; then
    bad="$bad
the seal is defined in $home, not in crate $SEAL_HOME_CRATE as the header says"
  fi
  printf '%s' "$bad"
}

run_selftest() {
  hdr "secret-accessor-seal-witness SELF-TEST"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out

  # RED: a plugin that tries every forbidden reach.
  cat >"$tmp/bad.rs" <<'RED'
fn sneak(v: &SecretValue, seal: &Seal) {
    let _ = KernelSeal::acquire_for_kernel();
    let _ = v.expose(seal);
    let _ = SecretValue::expose(v, seal);
    let _ = km.bytes(seal);
}
RED
  out="$(scan "$tmp/bad.rs")"
  if [ -n "$out" ]; then note "RED: caught acquire_for_kernel + .expose( + SecretValue::expose + .bytes("; else fail=1; note "RED FAILED: forbidden reaches not flagged"; fi

  # GREEN: the SAME names only in a comment and a string — no violation.
  cat >"$tmp/ok.rs" <<'GREEN'
// A plugin may not call v.expose(seal) or KernelSeal::acquire_for_kernel.
fn note() { let _doc = "KeyMaterial::bytes is sealed"; }
GREEN
  out="$(scan "$tmp/ok.rs")"
  if [ -z "$out" ]; then note "GREEN: the same names in a comment + a string literal flagged NONE"; else fail=1; note "GREEN FAILED: false positive:"; printf '%s\n' "$out" | sed 's/^/    /'; fi

  # RED (item 526): a crate with no src/ and a crate whose src/ holds no .rs file are UNSCANNED,
  # not clean -- the verdict must be FAIL even though the other crate is clean.
  mkdir -p "$tmp/crates/full/src" "$tmp/crates/nosrc" "$tmp/crates/emptysrc/src"
  cp "$tmp/ok.rs" "$tmp/crates/full/src/lib.rs"
  if check_crates "$tmp/crates/full" "$tmp/crates/nosrc" "$tmp/crates/emptysrc" >/dev/null 2>&1; then
    fail=1; note "RED FAILED: crates with zero scanned files were declared a PASS"
  else note "RED: a partial scan (2 of 3 crates with no .rs files) is FAIL"; fi
  if check_crates "$tmp/crates/nosrc" >/dev/null 2>&1; then
    fail=1; note "RED FAILED: a zero-file scan was declared a PASS"
  else note "RED: a zero-file scan is FAIL"; fi
  # GREEN control: the same helper over a clean crate with source passes, and reports its count.
  out="$(check_crates "$tmp/crates/full" 2>&1)"
  if [ $? -eq 0 ] && printf '%s' "$out" | grep -q 'total: 1 file(s) across 1 crate(s)'; then
    note "GREEN: a clean crate with 1 file passes and says how many files it read"
  else fail=1; note "GREEN FAILED: clean crate not passed with a file count:"; printf '%s\n' "$out" | sed 's/^/    /'; fi
  # RED planted through the same helper: a violation inside a counted crate is FAIL.
  mkdir -p "$tmp/crates/badc/src"; cp "$tmp/bad.rs" "$tmp/crates/badc/src/lib.rs"
  if check_crates "$tmp/crates/badc" >/dev/null 2>&1; then fail=1; note "RED FAILED: planted reach passed check_crates"
  else note "RED: planted reach inside a counted crate is FAIL"; fi

  # Item 467: the header's justification names only crates that exist, and the seal lives where
  # the header says. A header citing a phantom crate reads as a wall that is not there.
  out="$(header_crate_claims)"
  if [ -z "$out" ]; then note "CLAIMS: every crate the header names exists; the seal lives in $SEAL_HOME_CRATE"
  else fail=1; note "CLAIMS FAILED:"; printf '%s\n' "$out" | sed '/^$/d; s/^/    /'; fi

  if [ "$fail" -ne 0 ]; then red "secret-accessor-seal-witness SELF-TEST FAILED"; return 1; fi
  grn "secret-accessor-seal-witness self-test: ALL GREEN (planted reach, zero/partial-file floor, header crate claims, comment/string)"
  return 0
}

run_check() {
  hdr "DECISIONS #40 secret-accessor seal — no cdylib plugin reaches a raw secret accessor or the seal"
  local crates; crates="$(plugin_crates)"
  if [ -z "$crates" ]; then red "seal witness: FAIL — found no cdylib plugin crates to scan (is the tree intact?)"; exit 1; fi
  # shellcheck disable=SC2086
  check_crates $crates; exit $?
}

case "${1:-}" in
  --selftest) run_selftest; exit $? ;;
  --check|--report|"") run_check ;;
  -h|--help) sed -n '2,45p' "$0" ;;
  *) echo "usage: $0 [--selftest | --check]" >&2; exit 2 ;;
esac
