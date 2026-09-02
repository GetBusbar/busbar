#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# secret-hygiene-gate.sh — THE SECRET-VALUE-TYPE DEBT METER (the "secrets are a TYPE, not a String" gate).
#
# WHY THIS EXISTS (docs/design/1.6.0-secret-hygiene.md):
#   busbar's secret-hygiene guarantee is a TYPE guarantee: a value that is a secret is `Redacted<T>`
#   (busbar_api::Redacted — Debug/Display = [REDACTED], no Serialize, zeroize-on-drop), never a bare
#   `String`/`&str`/`Vec<u8>`. Its safe-to-log IDENTITY is `SecretRef`/a plain id, never the value.
#   Two ways that guarantee regresses, both caught here:
#     Check 1 — a known-secret field declared as a BARE string type instead of `Redacted<T>`, so a
#               derived Debug/Serialize could leak it.
#     Check 2 — a `.expose_secret()` call on the SAME statement as a log/audit/metric SINK, i.e. the
#               plaintext deliberately un-redacted straight into a tracing/println/audit/metric line.
#
# This mirrors scripts/plane-grep-gate.sh exactly: a comment/doc/test-stripping substring/field scanner,
# a narrow path-scoped ALLOWLIST (never inline markers — the .rs files stay frozen), a --selftest that
# proves RED on a planted bad fixture and GREEN on a good one, and a REPORT_ONLY env that defaults to
# 1 (non-blocking meter) so this lands informational and is armed (=0) later, post-pivot, once the
# Phase-2 offenders are converted — a one-flag flip, never a code edit.
#
# REPORTING MODE:
#   SECRET_GATE_REPORT_ONLY=1 (DEFAULT) → PRINT the violation count + offending file:line list, EXIT 0.
#   SECRET_GATE_REPORT_ONLY=0           → BLOCKING: exit 1 if any violation remains (the future hard gate).
#
# No external deps beyond bash 3.2 + POSIX awk (macOS/Linux) — same bare-runner posture as the sibling gates.
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# ── SCAN ROOTS ────────────────────────────────────────────────────────────────────────────────────
# Every crate's production src (tests / _test(s).rs excluded in the scanner). Substring "under crates/".
ROOTS="crates"

# ── CHECK 1 NEEDLES ──────────────────────────────────────────────────────────────────────────────
# STRONG: an unambiguously-secret field name — flagged whatever struct it sits on.
STRONG_NEEDLES="api_key api_key_plaintext client_secret private_key signing_key access_token subject_token api_secret secret_access_key password bearer credential_secret"
# CONTEXT: a generically-named field (secret / token / credential) — flagged ONLY when its enclosing
# struct name matches the secret-bearing shape below (so an unrelated `token: usize` counter is ignored).
CONTEXT_NEEDLES="secret token credential"
CONTEXT_STRUCT_RE="Key|Cred|Token|Secret|Auth|Lease|Issued|Mint"

# ── CHECK 2 SINKS ────────────────────────────────────────────────────────────────────────────────
# A log/audit/metric egress. `.expose_secret()` on the SAME statement as any of these is a leak.
SINKS="tracing:: log:: println! eprintln! print! dbg! panic! info! warn! error! debug! trace! counter! gauge! histogram! metrics_emit journal_append AuditRecord PlaneAuditLog"

# ── THE ALLOWLIST (path-scoped, never global; NEEDLE|PATH-PREFIX|FIELD) ─────────────────────────────
# A Check-1 hit is suppressed iff needle==NEEDLE, path STARTS WITH PATH-PREFIX, and the field name
# equals FIELD (empty FIELD = any). These are the design's THREE documented intentional exceptions
# (Part 3): store-ABI serde egress (CredentialSecret), the once-shown mint response (CreatedKeyView),
# and the single auth wire boundary (CompleteLoginRequest) — PLUS one type-name FALSE POSITIVE the
# doc's "*Token*-struct" rule catches by construction: `IrTokenLogprob.token` is a generated LLM
# output token's logprob entry, NOT a credential. Per the doc, false positives are silenced by the
# allowlist, never by weakening the rule.
ALLOWLIST_C1="secret|crates/api/src/store.rs|secret
credential_secret|crates/api/src/store.rs|
token|crates/busbar-core/src/admin/v1/contract/schema.rs|token
secret_access_key|crates/busbar-core/src/admin/v1/contract/schema.rs|
access_token|crates/busbar-core/src/admin/v1/contract/schema.rs|
secret|crates/busbar-core/src/admin/v1/contract/schema.rs|secret
token|crates/busbar-plugin/src/cold/auth.rs|
secret|crates/busbar-plugin/src/cold/auth.rs|
token|crates/busbar-llm/src/ir/types.rs|token"

# ── THE FIELD SCANNER (Check 1) ────────────────────────────────────────────────────────────────────
# Emits one TSV line per violation:  FIELD<TAB>file:line<TAB>trimmed-source
# Strips comments (respecting string literals), tracks a brace-depth block stack so a `name: Type` is
# only read as a FIELD when its immediately-enclosing block is a `struct` body (fn/impl params ignored),
# and flags a secret-named field whose type is bare `String`/`&str`/`Vec<u8>`/`Option<String>` and is
# NOT wrapped in `Redacted`/`Zeroizing`/`SecretRef`.
scan_fields() {
  local strong="$1" context="$2" struct_re="$3"; shift 3
  [ "$#" -gt 0 ] || return 0
  awk -v strong="$strong" -v context="$context" -v structre="$struct_re" \
      -v allow="$(printf '%s' "$ALLOWLIST_C1" | tr '\n' ';')" '
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
    function allowlisted(needle, field,   i) {
      for (i = 1; i <= naA; i++)
        if (needle == aN[i] && index(FILENAME, aP[i]) == 1 && (aF[i] == "" || aF[i] == field)) return 1
      return 0
    }
    BEGIN {
      ns = split(strong, S, " "); for (k=1;k<=ns;k++) strongset[S[k]] = 1
      nc = split(context, C, " "); for (k=1;k<=nc;k++) ctxset[C[k]] = 1
      naA = 0; nrows = split(allow, rows, ";")
      for (r=1;r<=nrows;r++) {
        if (rows[r]=="") continue
        nf = split(rows[r], fld, "|"); naA++
        aN[naA]=fld[1]; aP[naA]=fld[2]; aF[naA]=(nf>=3?fld[3]:"")
      }
    }
    FNR == 1 { inblk = 0; depth = 0; for (d in stack) delete stack[d]; for (d in sname) delete sname[d]; testmod = 0; tdepth = 0 }
    {
      code = strip($0)
      # crude #[cfg(test)] mod {…} exclusion (mirrors plane-grep): drop the block wholesale.
      no = gsub(/{/, "{", code); ncl = gsub(/}/, "}", code)
      if (testmod) { tdepth += no - ncl; if (tdepth <= 0) { testmod = 0; tdepth = 0 } next }
      if (code ~ /#\[cfg\(/ && code ~ /(^|[^a-z])test([^a-z]|$)/) { pendtest = 1 }
      else if (pendtest && code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/) { pendtest = 0; if (no > 0) { testmod = 1; tdepth = no - ncl } next }
      else if (code ~ /[^[:space:]]/ && code !~ /#\[/) { pendtest = 0 }

      # classify this line block-open type + capture struct name
      bt = "other"
      if (code ~ /(^|[^A-Za-z0-9_])struct([^A-Za-z0-9_])/) { bt = "struct"; sn = code; sub(/.*struct[ \t]+/, "", sn); sub(/[^A-Za-z0-9_].*/, "", sn); pend_sn = sn }
      else if (code ~ /(^|[^A-Za-z0-9_])enum([^A-Za-z0-9_])/) { bt = "enum" }

      # FIELD detection: only when the immediately-enclosing block is a struct body.
      if (depth >= 1 && stack[depth] == "struct") {
        line = code
        sub(/^[ \t]+/, "", line)
        sub(/^pub[ \t]*\([^)]*\)[ \t]*/, "", line)
        sub(/^pub[ \t]+/, "", line)
        if (line ~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*:/) {
          fname = line; sub(/[ \t]*:.*/, "", fname)
          ftype = line; sub(/^[A-Za-z_][A-Za-z0-9_]*[ \t]*:[ \t]*/, "", ftype)
          is_needle = 0
          if (fname in strongset) is_needle = 1
          else if ((fname in ctxset) && sname[depth] ~ structre) is_needle = 1
          if (is_needle) {
            bare = (ftype ~ /String/ || ftype ~ /&[ \t]*(\x27[a-z_]+[ \t]+)?str/ || ftype ~ /Vec[ \t]*<[ \t]*u8/)
            wrapped = (ftype ~ /Redacted/ || ftype ~ /Zeroizing/ || ftype ~ /SecretRef/)
            if (bare && !wrapped && !allowlisted(fname, fname))
              printf "%s\t%s:%d\t%s\n", fname, FILENAME, FNR, trim(code)
          }
        }
      }

      # advance the block-depth stack (net braces; struct decls carry their name onto the pushed frame)
      net = no - ncl
      if (net > 0) { for (i=0;i<net;i++) { depth++; stack[depth] = bt; if (bt == "struct") sname[depth] = pend_sn; else sname[depth] = "" } }
      else if (net < 0) { for (i=0;i<-net;i++) { if (depth>0) { delete stack[depth]; delete sname[depth]; depth-- } } }
    }
  ' "$@"
}

# ── THE SINK SCANNER (Check 2) ─────────────────────────────────────────────────────────────────────
# Emits: expose_secret<TAB>file:line<TAB>trimmed-source  for any line where `.expose_secret()` and a
# log/audit/metric sink token co-occur (same statement window == same source line, conservatively).
scan_sinks() {
  local sinks="$1"; shift
  [ "$#" -gt 0 ] || return 0
  awk -v sinks="$sinks" '
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
    BEGIN { nsk = split(sinks, SK, " ") }
    FNR == 1 { inblk = 0 }
    {
      code = strip($0)
      if (index(code, ".expose_secret()") == 0) next
      for (k = 1; k <= nsk; k++) {
        if (index(code, SK[k]) > 0) { printf "expose_secret\t%s:%d\t%s\n", FILENAME, FNR, trim(code); break }
      }
    }
  ' "$@"
}

# Production .rs under the roots, minus test files.
prod_files() {
  find $* -name '*.rs' 2>/dev/null | grep -v '/tests/' | grep -Ev '_tests?\.rs$' | grep -v '^$' | sort
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "secret-hygiene-gate SELF-TEST (the field/sink scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out

  # ── RED (Check 1): a bare `api_key: String` + a context `secret: String` on a *Key* struct. ──
  cat >"$tmp/c1_red.rs" <<'RED'
pub struct LaneConfig {
    pub api_key: String,
    pub base_url: String,
}
pub struct IssuedKey {
    pub secret: String,
    pub key_id: String,
}
RED
  out="$(scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" "$tmp/c1_red.rs")"
  local hit_api hit_secret hit_baseurl
  hit_api="$(printf '%s\n' "$out"    | awk -F'\t' '$1=="api_key"{n++} END{print n+0}')"
  hit_secret="$(printf '%s\n' "$out" | awk -F'\t' '$1=="secret"{n++}  END{print n+0}')"
  hit_baseurl="$(printf '%s\n' "$out"| awk -F'\t' '$1=="base_url"{n++}END{print n+0}')"
  if [ "$hit_api" -ge 1 ];    then note "RED c1: caught bare \`api_key: String\`"; else fail=1; note "RED c1 FAILED: api_key: String not flagged"; fi
  if [ "$hit_secret" -ge 1 ]; then note "RED c1: caught context \`secret: String\` on an *Key* struct"; else fail=1; note "RED c1 FAILED: IssuedKey.secret not flagged"; fi
  if [ "$hit_baseurl" -eq 0 ];then note "RED c1: did NOT flag the non-secret \`base_url: String\`"; else fail=1; note "RED c1 FAILED: base_url false-positive"; fi

  # ── GREEN (Check 1): the SAME fields wrapped in Redacted — zero hits. Plus a comment + a fn param. ──
  cat >"$tmp/c1_green.rs" <<'GREEN'
// api_key: String  <- a comment naming the bad shape must be ignored
pub struct LaneConfig {
    pub api_key: busbar_api::Redacted<String>,
    pub base_url: String,
}
impl LaneConfig {
    fn set(&mut self, api_key: String) { let _ = api_key; }
}
pub struct Counter { pub token: usize }
GREEN
  out="$(scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" "$tmp/c1_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN c1: Redacted-wrapped field + comment + fn-param + non-secret token:usize flagged NONE"
  else
    fail=1; note "GREEN c1 FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── RED (Check 2): `.expose_secret()` straight into a tracing sink. ──
  cat >"$tmp/c2_red.rs" <<'RED2'
fn leak(key: &Redacted<String>) {
    tracing::info!(api_key = %key.expose_secret(), "using key");
}
RED2
  out="$(scan_sinks "$SINKS" "$tmp/c2_red.rs")"
  if [ -n "$out" ]; then note "RED c2: caught \`.expose_secret()\` on a tracing:: sink line"; else fail=1; note "RED c2 FAILED: expose_secret-at-sink not flagged"; fi

  # ── GREEN (Check 2): `.expose_secret()` at a NON-sink (header injection) — no hit. ──
  cat >"$tmp/c2_green.rs" <<'GREEN2'
fn inject(key: &Redacted<String>, req: &mut Request) {
    req.header("authorization", format!("Bearer {}", key.expose_secret()));
    // tracing::info!("sent");  <- a sink in a COMMENT, on a different statement, is not a leak
}
GREEN2
  out="$(scan_sinks "$SINKS" "$tmp/c2_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN c2: expose_secret at a header-injection (non-sink) + a commented sink flagged NONE"
  else
    fail=1; note "GREEN c2 FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  if [ "$fail" -ne 0 ]; then
    red "secret-hygiene-gate SELF-TEST FAILED — the scanner would let a bare secret / a logged secret through"
    return 1
  fi
  grn "secret-hygiene-gate self-test: ALL GREEN (Check-1 field RED/GREEN + Check-2 sink RED/GREEN proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
REPORT_TOTAL=0
run_report() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  : >"$tmp/c1"; : >"$tmp/c2"
  local files; files="$(prod_files $ROOTS)"
  # shellcheck disable=SC2086
  [ -n "$files" ] && scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" $files >>"$tmp/c1"
  # shellcheck disable=SC2086
  [ -n "$files" ] && scan_sinks "$SINKS" $files >>"$tmp/c2"

  local n1 n2 total
  n1="$(awk 'END{print NR+0}' "$tmp/c1")"
  n2="$(awk 'END{print NR+0}' "$tmp/c2")"
  total=$((n1 + n2)); REPORT_TOTAL="$total"

  hdr "SECRET-HYGIENE report — bare secret VALUE types + secrets at a log/audit/metric sink (production .rs under $ROOTS)"
  note "Check 1 (bare secret field, not Redacted/Zeroizing/SecretRef): $n1"
  note "Check 2 (.expose_secret() on a log/audit/metric sink line):     $n2"

  if [ "$n1" -gt 0 ]; then
    hdr "Check 1 — bare secret fields (convert to busbar_api::Redacted<T>)"
    awk -F'\t' '{printf "  %-20s %s\n", $1, $2}' "$tmp/c1"
  fi
  if [ "$n2" -gt 0 ]; then
    hdr "Check 2 — secret exposed at a sink (log the SecretRef/id, never the value)"
    awk -F'\t' '{printf "  %-14s %s\n", $1, $2}' "$tmp/c2"
  fi

  cp "$tmp/c1" "${SECRET_GATE_C1_OUT:-/dev/null}" 2>/dev/null || true
  cp "$tmp/c2" "${SECRET_GATE_C2_OUT:-/dev/null}" 2>/dev/null || true
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --report | --check | "")
    run_report
    hdr "verdict"
    report_only="${SECRET_GATE_REPORT_ONLY:-1}"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "secret-hygiene gate: PASS — no bare secret value type, no secret at a sink"
      exit 0
    fi
    if [ "$report_only" = "0" ]; then
      red "secret-hygiene gate: FAIL — $REPORT_TOTAL secret-hygiene violation(s) (see report above)"
      note "Wrap each secret VALUE in busbar_api::Redacted<T>; log a SecretRef/id, never .expose_secret() output."
      exit 1
    fi
    ylw "secret-hygiene gate: $REPORT_TOTAL violation(s) — REPORT-ONLY (SECRET_GATE_REPORT_ONLY=1, non-blocking)."
    note "Baseline debt; Phase-2 (post-pivot) converts the remaining offenders. Set SECRET_GATE_REPORT_ONLY=0 to arm the hard gate."
    exit 0
    ;;
  -h | --help)
    sed -n '2,40p' "$0"
    ;;
  *)
    echo "usage: $0 [--selftest | --report | --check]   (env SECRET_GATE_REPORT_ONLY=1 default report-only; =0 blocking)" >&2
    exit 2
    ;;
esac
