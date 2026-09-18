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
#   A plugin cannot obtain a seal: the only way to hold one is `KernelSeal::acquire_for_kernel()` in
#   busbar-caps, and the manifest allow-list refuses a plugin crate that names busbar-caps at all.
#   The TYPE now enforces what an out-of-tree grep used to. This witness is the RED-provable proof
#   that no in-tree PLUGIN crate reaches for either accessor or for the seal itself.
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

  if [ "$fail" -ne 0 ]; then red "secret-accessor-seal-witness SELF-TEST FAILED"; return 1; fi
  grn "secret-accessor-seal-witness self-test: ALL GREEN (RED planted-reach + GREEN comment/string)"
  return 0
}

run_check() {
  hdr "DECISIONS #40 secret-accessor seal — no cdylib plugin reaches a raw secret accessor or the seal"
  local crates; crates="$(plugin_crates)"
  if [ -z "$crates" ]; then red "seal witness: FAIL — found no cdylib plugin crates to scan (is the tree intact?)"; exit 1; fi
  note "plugin crates scanned:"; printf '%s\n' "$crates" | sed 's/^/    /'

  local files out
  files="$(for c in $crates; do find "$c/src" -name '*.rs' 2>/dev/null; done)"
  [ -n "$files" ] || { grn "seal witness: PASS — plugin crates have no src to scan"; exit 0; }
  # shellcheck disable=SC2086
  out="$(scan $files)"
  if [ -z "$out" ]; then
    grn "seal witness: PASS — no cdylib plugin references acquire_for_kernel / SecretValue::expose / .expose( / KeyMaterial::bytes / .bytes("
    exit 0
  fi
  hdr "VIOLATIONS — a plugin reached a sealed accessor (this is a #40 finding)"
  printf '%s\n' "$out" | sed 's/^/  /'
  red "seal witness: FAIL — a cdylib plugin reaches a raw secret accessor or the kernel seal"
  exit 1
}

case "${1:-}" in
  --selftest) run_selftest; exit $? ;;
  --check|--report|"") run_check ;;
  -h|--help) sed -n '2,45p' "$0" ;;
  *) echo "usage: $0 [--selftest | --check]" >&2; exit 2 ;;
esac
