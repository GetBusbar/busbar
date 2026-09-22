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
# There is no `set -e` here (the checks accumulate), so a failed `cd` would leave the gate scanning
# whatever directory the caller happened to be in. Refuse instead: every path below is relative.
cd "$(dirname "$0")/.." || { echo "secret-hygiene gate: FAIL — cannot cd to the repo root" >&2; exit 1; }

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# ── SCAN ROOTS ────────────────────────────────────────────────────────────────────────────────────
# Every crate's production src (tests / _test(s).rs excluded in the scanner). Substring "under crates/".
ROOTS="crates"

# ── CHECK 1 NEEDLES ──────────────────────────────────────────────────────────────────────────────
# MATCHED ON THE FIELD-NAME TAIL, NOT BY STRING EQUALITY, and that difference is the whole of this
# block's history. A needle set compared with `==` can only ever see the exact spelling somebody
# thought to write down, and Rust field names are QUALIFIED: the vendor goes on the front
# (`aws_secret_access_key`) and the role goes on the front of the generic noun (`caller_token`).
# Under equality `aws_secret_access_key != secret_access_key`, so the gate ran GREEN over the one
# field in this tree that is literally named "secret access key" — and it had an allowlist row
# pointed at that very field, which could never fire, saying so to nobody. Measured: equality saw
# 11 Check-1 fields; tail matching sees 20, and every one of the 9 it added is a real bare secret
# except one provably-constant mode label (allowlisted below, named, load-bearing).
#
# THE RULE: a field matches needle N iff `fname == N` or `fname` ends with `_N`. That is deliberately
# a TAIL match and not a SUBSTRING match, because the two were measured against this tree and the
# substring form is strictly worse:
#   substring(STRONG)          → +1 true  (aws_secret_access_key), +3 FALSE (`subject_token_type` x3,
#                                an OAuth token-TYPE URN — a constant, not a credential)
#   substring(STRONG+CONTEXT)  → +2 true, +6 FALSE (adds `token_url` x2, `upstream_credentials`)
#   tail (THIS)                → +7 true, +0 FALSE
# The qualifier in Rust field names is a PREFIX, so the secret-ness lives in the SUFFIX: `*_token` is
# a token, `token_*` is something ABOUT a token (a url, a uri, a hash, a type). Matching the tail
# encodes exactly that and nothing more.
#
# STRONG: an unambiguously-secret field name — flagged whatever struct it sits on, at any qualifier.
STRONG_NEEDLES="api_key api_key_plaintext client_secret private_key signing_key access_token subject_token api_secret secret_access_key password bearer credential_secret"
# CONTEXT: a generically-named field (secret / token / credential / credentials) — flagged ONLY when
# its enclosing struct name matches the secret-bearing shape below (so an unrelated `token: usize`
# counter is ignored). `credentials` is here because RFC 9110 spells ONE credential value plural
# (`Authorization: <scheme> <credentials>`) and that is how this tree spells it too.
#
# A QUALIFIED context needle is PROMOTED TO STRONG (struct gate skipped). The struct-name gate exists
# because a BARE `token`/`secret` is ambiguous — it could be an LLM output token or a counter. A
# QUALIFIED one is not: `caller_token` says whose token it is in the name. The gate was standing in
# for a disambiguator the field name already carries, and it was costing real coverage — all six
# `caller_token` fields sit on structs (`Walk`, `Hop`, `RouteInput`, …) that match no struct-name
# pattern and never would.
CONTEXT_NEEDLES="secret token credential credentials"
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
#
# THIS ALLOWLIST HAS NO STALE-ENTRY DETECTION, AND THAT IS HOW THESE ROTTED. A row whose PATH-PREFIX
# names a file that no longer exists suppresses nothing, reports nothing, and reads exactly like a
# row that is doing its job — the same silent-zero failure class the rest of this tree's gates arm
# `require_root` against. Two crate folds moved two of the four paths below out from under it:
#   * `crates/busbar-core/src/admin/v1/contract/schema.rs` -> `crates/busbar-kernel/src/...`
#     (W4.a core absorption, 673ecdaaa). FOUR rows pointed there. While they were dead, the design's
#     documented "once-shown mint response (CreatedKeyView)" exception was NOT excused, and its
#     three fields (`token` x2, `secret`) were counted as Check-1 debt — an intentional exception
#     silently reclassified as a violation.
#   * `crates/busbar-llm/src/ir/types.rs` -> `crates/busbar-llm-codec/src/ir/types.rs`
#     (the wire-codec split). While that row was dead, `IrTokenLogprob.token` — the type-name FALSE
#     POSITIVE this allowlist exists to silence — was reported as a real bare-secret field.
#
# AUDITED ROW BY ROW WHEN THE PATHS WERE REPOINTED, so the vacuous ones are named rather than left to
# look live. A row suppresses a hit iff `needle == NEEDLE` where `needle` IS the field name (the
# scanner calls `allowlisted(fname, fname)`), so the match is EXACT on the field name:
#   * `secret_access_key|...schema.rs|` USED TO suppress nothing and never had, at either path: that
#     struct's field is `aws_secret_access_key`, which is not EQUAL to `secret_access_key` and was in
#     neither needle set, so the scanner never raised a hit for there to be excused. The row was kept
#     as the design's written intent with the note that "a scanner change that starts matching
#     `aws_`-prefixed names would need the needle corrected, not just the path". Tail matching IS
#     that change, so the needle IS corrected: the row now reads `aws_secret_access_key|…|
#     aws_secret_access_key` and is LOAD-BEARING — it suppresses a hit the scanner really raises.
#
#     WHY THAT FIELD IS AN EXCEPTION AND NOT DEBT, which is the only thing that makes the row
#     legitimate rather than a way of making the gate quiet. `CreatedKeyView` is the design's already
#     documented "once-shown mint response" exception and its sibling `token` field is allowlisted on
#     the row directly above; excusing one and counting the other on the SAME struct for the SAME
#     reason would be incoherent. And the conversion the gate asks for is IMPOSSIBLE here, not merely
#     unperformed: `schema.rs` is compiled ONLY under `#[cfg(feature = "openapi-schema")]`, its types
#     are never instantiated (the sole reference to `CreatedKeyView` in the tree is a `typed!(…)`
#     schema registration in `busbar-core-admin/src/v1/json/handlers.rs`), and the struct derives
#     `Serialize + JsonSchema` — while `Redacted<T>` deliberately implements NEITHER (pinned by the
#     compile-time fence in `crates/busbar-contract/src/tests/redacted_no_serde.rs`). `Redacted<String>` there
#     would not compile. The field holds no value at runtime; it is a shape, not a carrier.
#
#     THE CARRIER IS SOMEWHERE THIS CHECK CANNOT LOOK, and that is the more useful thing to know.
#     The AWS secret actually travels as the 4th element of a bare tuple
#     (`GovState::mint_signed_with_aws -> StoreResult<(VirtualKey, String, String, String)>`,
#     `busbar-kernel/src/governance/state.rs`) and is written into a `json!({…})` body at
#     `busbar-core-admin/src/keys.rs:1046`. Check 1 scans STRUCT FIELDS. A tuple element has no name
#     to spell, so no needle set of any width will ever reach it. Widening the needles fixed the
#     SPELLING blind spot; it did not — and cannot — fix the SHAPE blind spot.
#   * `access_token|...schema.rs|` still suppresses nothing: `CreatedKeyView` has no access-token
#     field under any qualifier, so tail matching raises no hit there either. It is kept, unchanged,
#     as written intent — but it is dead weight, not a live exception, and the STRONG-half liveness
#     detector described below is what should eventually strike it.
#   * `upstream_credentials|crates/busbar-kernel/src/admin/v1/contract/mod.rs|upstream_credentials`
#     is the one FALSE POSITIVE tail matching introduces, and it is excused on MEASURED grounds, not
#     on the doc comment that claims it. `AuthView.upstream_credentials` is `&'static str` and is
#     assigned exactly two string literals — `"own"` / `"passthrough"` — at its single construction
#     site (`busbar-core-admin/src/v1/service.rs`, `get_auth()`), matching the published enum in
#     `busbar-plane-decision/src/meta.rs`. It names a MODE, never a credential. It cannot be renamed
#     (it is a serde field name in the frozen admin OpenAPI surface), so an allowlist row is the only
#     available disposition. It suppresses a real hit, so it is load-bearing, not dead weight.
#   * `token|crates/busbar-plugin/src/cold/auth.rs|` and `secret|...same...|` are likewise vacuous
#     today: that file's fields are `token_response` and `secret_form_field`, neither of which is an
#     exact needle. The PATH is live, so they are left exactly as written.
#   * THE TWO `crates/api/src/store.rs` ROWS WERE BOTH DEAD, FOR TWO DIFFERENT REASONS, and only
#     one of them was worth repointing. `check_allowlist_paths` passed them because the file still
#     EXISTED — a 39-line re-export shim holding ZERO occurrences of `secret` — which is the weak
#     half of staleness: it asks "does the path exist", never "did this row suppress anything".
#     - `secret|crates/api/src/store.rs|secret` is REPOINTED at `crates/busbar-contract/src/
#       records.rs`, where `CredentialSecret` actually lives (DECISIONS #83/#84). Its subject moved;
#       the finding it excused is LIVE at the new path and was being counted as fresh debt. The
#       exception is legitimate on the same MEASURED ground the `aws_secret_access_key` row above
#       stands on, and the ground is checked rather than asserted: `CredentialSecret` derives
#       `Serialize`/`Deserialize` because a plugin `RecordStore` returns it across the ABI as JSON,
#       and `Redacted<T>` deliberately implements NEITHER. Planting `pub secret: Redacted<String>`
#       there yields `the trait bound `Redacted<String>: serde::Serialize` is not satisfied` (and the
#       `Deserialize` twin). The conversion Check 1 asks for is IMPOSSIBLE here, not merely
#       unperformed. The leak surface the check protects — debug-logging — is closed at this type by
#       its own hand-written `Debug`, which prints `<redacted; present>`/`<absent>` and never the
#       value.
#     - `credential_secret|crates/api/src/store.rs|` is STRUCK. It is not a row whose subject moved:
#       `grep -rn "^\s*\(pub \)\?credential_secret\s*:" --include=*.rs crates` returns NOTHING,
#       so no struct field anywhere in the tree is spelled `credential_secret`, at the old path or
#       any other. The scanner matches EXACTLY on the field name, so this needle could never raise a
#       hit for the row to excuse. There is no path to repoint it to; it excused nothing, ever.
ALLOWLIST_C1="secret|crates/busbar-contract/src/records.rs|secret
token|crates/busbar-kernel/src/admin/v1/contract/schema.rs|token
aws_secret_access_key|crates/busbar-kernel/src/admin/v1/contract/schema.rs|aws_secret_access_key
access_token|crates/busbar-kernel/src/admin/v1/contract/schema.rs|
secret|crates/busbar-kernel/src/admin/v1/contract/schema.rs|secret
upstream_credentials|crates/busbar-kernel/src/admin/v1/contract/mod.rs|upstream_credentials
token|crates/busbar-plugin/src/cold/auth.rs|
secret|crates/busbar-plugin/src/cold/auth.rs|
token|crates/busbar-llm-codec/src/ir/types.rs|token"

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
    # `fname` IS the needle, or carries it as an `_`-delimited TAIL (`aws_` + `secret_access_key`).
    function tailmatch(f, n) { return (f == n) || qualified(f, n) }
    # The TAIL only: `fname` ends with `_N` behind at least one character of qualifier. This is what
    # promotes a qualified CONTEXT needle to STRONG, and what keeps `token_url` from matching `token`.
    function qualified(f, n) { return (length(f) > length(n) + 1 && substr(f, length(f) - length(n)) == "_" n) }
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
          # STRONG at any qualifier: `secret_access_key` AND `aws_secret_access_key`.
          for (ki = 1; ki <= ns; ki++) if (tailmatch(fname, S[ki])) is_needle = 1
          # A QUALIFIED context needle is strong on its own (`caller_token`) — no struct gate.
          if (!is_needle) for (ki = 1; ki <= nc; ki++) if (qualified(fname, C[ki])) is_needle = 1
          # A BARE context needle still needs the struct-name gate, exactly as before.
          if (!is_needle && (fname in ctxset) && sname[depth] ~ structre) is_needle = 1
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
# Emits: expose_secret<TAB>file:line<TAB>trimmed-statement  for any STATEMENT where `.expose_secret()`
# and a log/audit/metric sink token co-occur.
#
# THE STATEMENT WINDOW IS A STATEMENT, NOT A LINE. This used to read one source line at a time, which
# meant it only ever caught the leak written on a single line. rustfmt does not write it that way:
# a `tracing::info!` with more than a field or two is split across lines, so the sink token lands on
# one line and `.expose_secret()` on the next, the two never co-occur, and the gate reports zero.
#
#     tracing::info!(                      <- sink here
#         api_key = %key.expose_secret(),  <- secret here, one line later
#         "using key"
#     );
#
# That is the normal, rustfmt-produced shape of the exact leak this check exists to catch, and it
# went straight through. Lines are now accumulated into a statement buffer and flushed at a
# statement terminator (`;` `{` `}` `,`) seen at paren depth 0 — so a multi-line macro call is ONE
# window, while two adjacent single-line statements stay two, and `key.expose_secret()` handed to a
# header injection on its own line still does not join the next line's log call.
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
    function flush(   k) {
      if (stmt != "" && index(stmt, ".expose_secret()") > 0) {
        for (k = 1; k <= nsk; k++) {
          if (index(stmt, SK[k]) > 0) {
            printf "expose_secret\t%s:%d\t%s\n", stmtfile, stmtline, stmt; break
          }
        }
      }
      stmt = ""; stmtline = 0; stmtfile = ""; pdepth = 0
    }
    BEGIN { nsk = split(sinks, SK, " "); stmt = ""; pdepth = 0 }
    FNR == 1 { flush(); inblk = 0 }
    {
      code = trim(strip($0))
      if (code == "") next
      if (stmt == "") { stmt = code; stmtline = FNR; stmtfile = FILENAME }
      else { stmt = stmt " " code }
      pdepth += gsub(/\(/, "(", code) - gsub(/\)/, ")", code)
      if (pdepth < 0) pdepth = 0
      last = substr(code, length(code), 1)
      if (pdepth == 0 && (last == ";" || last == "{" || last == "}" || last == ",")) flush()
    }
    END { flush() }
  ' "$@"
}

# Production .rs under the roots, minus test files.
prod_files() {
  find "$@" -name '*.rs' 2>/dev/null | grep -v '/tests/' | grep -Ev '_tests?\.rs$' | grep -v '^$' | sort
}

# ── ALLOWLIST LIVENESS — a row that excuses nothing must be LOUD, not invisible ────────────────────
# THE FAILURE THIS EXISTS FOR. A row is `NEEDLE|PATH-PREFIX|FIELD` and suppresses a hit only when the
# violating file's path STARTS WITH PATH-PREFIX. When a crate fold moves that file, the row keeps its
# shape, keeps its place in the list, and suppresses nothing — and nothing anywhere said so. Two folds
# did exactly that here (busbar-core -> busbar-kernel, busbar-llm -> busbar-llm-codec): five rows went
# dead, four of the design's documented intentional exceptions silently became counted violations, and
# the gate's own output could not tell you. "Measured nothing" and "measured everything and it passed"
# must never be the same output, least of all in a SECURITY gate.
#
# THE RULE: every PATH-PREFIX must name something that exists on disk. That is deliberately the WEAK
# half of the question — it catches the whole moved-file class, which is the one that has actually
# bitten, and it is green on a correct tree, so it can be a HARD failure rather than another
# report-only number nobody reads. It fails INDEPENDENTLY of SECRET_GATE_REPORT_ONLY: a debt count is
# a thing to burn down, but an allowlist that cannot be trusted is a broken instrument, and a broken
# instrument is not "report-only".
#
# THE STRONG HALF IS NOT ARMED HERE, and this is the honest statement of why. "Did this row suppress
# a real hit on this run?" would also catch the four rows audited above the allowlist as vacuous for
# a different reason (an exact-match needle that matches no field at a live path). Arming it today
# would red the gate on four pre-existing rows whose owners have not yet ruled on whether to correct
# the needle or strike the row. Arm it in the commit that resolves them.
check_allowlist_paths() {
  local row prefix stale=0
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    prefix="$(printf '%s' "$row" | cut -d'|' -f2)"
    if [ -z "$prefix" ]; then
      red "secret-hygiene gate: FAIL — allowlist row \`$row\` has an EMPTY path prefix."
      note "A path-scoped allowlist with no path is a global one, which this gate does not have."
      stale=1
      continue
    fi
    if [ ! -e "$prefix" ]; then
      red "secret-hygiene gate: FAIL — allowlist row \`$row\` names a path that is not in this tree."
      note "\`$prefix\` does not exist, so this row suppresses nothing and says nothing while doing it."
      note "If the file MOVED, repoint the row. If the exception is genuinely gone, DELETE the row."
      note "Do not leave it: a stale allowlist row reads exactly like a live one."
      stale=1
    fi
  done <<EOF
$ALLOWLIST_C1
EOF
  return "$stale"
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

  # ── RED (Check 1, QUALIFIED): the prefix/suffix class the equality matcher was blind to. ──
  # THE FIELD THAT PROVED THE INSTRUMENT WAS BROKEN goes in here as a permanent fixture, so the
  # regression cannot come back quietly. `aws_secret_access_key` carries the STRONG needle
  # `secret_access_key` behind a vendor prefix; `caller_token` carries the CONTEXT needle `token`
  # behind a role prefix and sits on a struct whose NAME matches no secret-bearing pattern (which is
  # exactly how all six real ones in this tree are written). Under `==` both scored zero.
  cat >"$tmp/c1_red_qualified.rs" <<'RED1Q'
pub struct CreatedKeyView {
    pub aws_access_key_id: Option<String>,
    pub aws_secret_access_key: Option<String>,
}
pub struct Walk {
    pub caller_token: Option<String>,
    pub proto: String,
}
pub struct LaneWire {
    pub admin_password: String,
    pub shared_secret: String,
}
RED1Q
  out="$(scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" "$tmp/c1_red_qualified.rs")"
  local q
  for q in aws_secret_access_key caller_token admin_password shared_secret; do
    if printf '%s\n' "$out" | awk -F'\t' -v f="$q" '$1==f{n++} END{exit !(n+0)}'; then
      note "RED c1: caught the QUALIFIED needle \`$q\` (prefix/suffix variant)"
    else
      fail=1; note "RED c1 FAILED: qualified \`$q\` not flagged — the tail matcher regressed to =="
    fi
  done
  if printf '%s\n' "$out" | awk -F'\t' '$1=="aws_access_key_id"{n++} END{exit (n+0)}'; then
    note "RED c1: did NOT flag the sibling non-secret \`aws_access_key_id\` (an AccessKeyId is public)"
  else
    fail=1; note "RED c1 FAILED: aws_access_key_id false-positive"
  fi

  # ── GREEN (Check 1, NEAR-MISS): the head-qualified names tail matching must NOT flag. ──
  # A gate that flags everything is exactly as useless as one that flags nothing, and substring
  # matching — the obvious alternative to this tail rule — flags every one of these. `token_url` is
  # an endpoint, `token_hash` is a digest, `subject_token_type` is an OAuth URN constant,
  # `secret_form_field` names the form KEY the core fills (never the value), `plane_tokens` is a
  # counter map. They are put on a struct whose name DOES match CONTEXT_STRUCT_RE so the test proves
  # the NAME rule holds them green, not the struct gate.
  cat >"$tmp/c1_green_nearmiss.rs" <<'GREEN1N'
pub struct TokenExchangeCfg {
    pub token_url: String,
    pub token_uri: String,
    pub token_path: String,
    pub token_hash: String,
    pub admin_token_hash: String,
    pub subject_token_type: String,
    pub requested_token_type: String,
    pub secret_form_field: Option<String>,
    pub access_key_id: String,
    pub tokens_in_pointer: String,
    pub plane_tokens: String,
}
GREEN1N
  out="$(scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" "$tmp/c1_green_nearmiss.rs")"
  if [ -z "$out" ]; then
    note "GREEN c1: 11 head-qualified NEAR-MISS names (token_url/token_hash/subject_token_type/secret_form_field/…) flagged NONE"
  else
    fail=1; note "GREEN c1 FAILED: the tail matcher over-fires — expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── RED (Check 2): `.expose_secret()` straight into a tracing sink. ──
  cat >"$tmp/c2_red.rs" <<'RED2'
fn leak(key: &Redacted<String>) {
    tracing::info!(api_key = %key.expose_secret(), "using key");
}
RED2
  out="$(scan_sinks "$SINKS" "$tmp/c2_red.rs")"
  if [ -n "$out" ]; then note "RED c2: caught \`.expose_secret()\` on a tracing:: sink line"; else fail=1; note "RED c2 FAILED: expose_secret-at-sink not flagged"; fi

  # ── RED (Check 2, the shape rustfmt actually writes): the SAME leak split across lines. ──
  # The single-line fixture above is not how this leak appears in the tree: rustfmt splits any
  # tracing macro with more than a field or two, putting the sink on one line and the secret on the
  # next. A line-at-a-time scanner reports zero on this file while the secret goes to the log.
  cat >"$tmp/c2_red_multiline.rs" <<'RED3'
fn leak(key: &Redacted<String>) {
    tracing::info!(
        api_key = %key.expose_secret(),
        "using key"
    );
}
RED3
  out="$(scan_sinks "$SINKS" "$tmp/c2_red_multiline.rs")"
  if [ -n "$out" ]; then
    note "RED c2: caught the rustfmt-split \`.expose_secret()\` inside a multi-line tracing macro"
  else
    fail=1; note "RED c2 FAILED: multi-line expose_secret-at-sink not flagged"
  fi

  # ── GREEN (Check 2): `.expose_secret()` at a NON-sink (header injection) — no hit. ──
  cat >"$tmp/c2_green.rs" <<'GREEN2'
fn inject(key: &Redacted<String>, req: &mut Request) {
    req.header("authorization", format!("Bearer {}", key.expose_secret()));
    // tracing::info!("sent");  <- a sink in a COMMENT, on a different statement, is not a leak
    tracing::info!(key_id = %key.reference(), "sent");
}
GREEN2
  out="$(scan_sinks "$SINKS" "$tmp/c2_green.rs")"
  if [ -z "$out" ]; then
    note "GREEN c2: expose_secret at a header-injection, then a REAL sink on the NEXT statement — the statement window did not join them; flagged NONE"
  else
    fail=1; note "GREEN c2 FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── THE ALLOWLIST-LIVENESS DETECTOR, red then green. A detector that cannot go red is the same
  #    silent instrument it was written to replace, so it is proven on a planted stale row first and
  #    on the REAL list second — which also means every run of this self-test re-asserts that the
  #    shipped allowlist still names only live paths.
  local real_allowlist="$ALLOWLIST_C1"
  ALLOWLIST_C1="token|crates/busbar-this-crate-does-not-exist/src/x.rs|token"
  if check_allowlist_paths >/dev/null 2>&1; then
    fail=1; note "RED allowlist FAILED: a row at a path that does not exist was accepted"
  else
    note "RED allowlist: a row whose PATH-PREFIX names no path on disk is REFUSED"
  fi
  ALLOWLIST_C1="token|scripts/secret-hygiene-gate.sh|token"
  if check_allowlist_paths >/dev/null 2>&1; then
    note "GREEN allowlist: a row whose PATH-PREFIX exists is accepted"
  else
    fail=1; note "GREEN allowlist FAILED: a row at a real path was refused — the detector over-fires"
  fi
  ALLOWLIST_C1="$real_allowlist"
  if check_allowlist_paths >/dev/null 2>&1; then
    note "GREEN allowlist: every row of the SHIPPED allowlist names a path in this tree"
  else
    fail=1; note "GREEN allowlist FAILED: the shipped allowlist has a stale row (run --check to see it)"
  fi

  if [ "$fail" -ne 0 ]; then
    red "secret-hygiene-gate SELF-TEST FAILED — the scanner would let a bare secret / a logged secret through"
    return 1
  fi
  grn "secret-hygiene-gate self-test: ALL GREEN (Check-1 field RED/GREEN + Check-2 sink RED/GREEN + allowlist-liveness RED/GREEN proven)"
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
    # BEFORE the scan, never after: a stale allowlist means the numbers below are the wrong numbers,
    # and printing them first invites reading them as the verdict. Hard-fails regardless of
    # SECRET_GATE_REPORT_ONLY (see check_allowlist_paths for why).
    check_allowlist_paths || exit 1
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
