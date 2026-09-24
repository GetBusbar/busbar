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
#     Check 3 — a secret-bearing value INTERPOLATED INTO A MESSAGE that reaches a caller: a
#               `format!`/`write!`/`panic!` enclosed by an `Err(...)`/`map_err`/`ok_or_else`/
#               `push(...)`/diagnostic call. See below for why this had to be added.
#
# WHY CHECK 3 EXISTS — TWO COMMITTED LEAKS SHIPPED WITH THIS INSTRUMENT WATCHING (49d781bd1).
#   `egress/engine/mod.rs` `parse_proxy` rendered the RAW `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`
#   value with `{v:?}` on three refusal arms; those variables carry `user:password@` (RFC 3986
#   §3.2.1) and the refusal becomes a boot panic with no `catch_unwind` under it. And
#   `egress_auth/jwt_bearer.rs` `pem_to_pkcs8_der` interpolated `base64::DecodeError`'s own
#   `Display`, which names a byte OF THE KEY BODY — `InvalidLastSymbol` prints a VALID base64
#   character, i.e. six bits of the operator's RSA private key — into a string `config_validate`
#   copies verbatim into the `errors` array admin `config/validate` returns to a READ-SCOPE caller.
#
#   NEITHER WAS IN RANGE OF CHECKS 1 OR 2, structurally, and not by accident:
#     * Check 1 scans struct FIELD DECLARATIONS. Both sites are a fn PARAMETER or a third-party
#       error's `Display`. This file's own GREEN selftest case asserted that a fn param
#       `api_key: String` must NOT be flagged — true of Check 1 (a param has no derived Debug to
#       leak through) and, until Check 3, true of the whole gate. That case ENCODED THE BLIND SPOT.
#     * Check 2 needs `.expose_secret()` on the same statement as a SINK, and `format!` was not in
#       `SINKS` at all. A secret interpolated into a message that is RETURNED rather than LOGGED
#       had no rule anywhere in this file.
#   `docs/design/1.6.0-secret-hygiene.md` §1.3 said "No direct `println!(secret)` found in
#   production" — the audit looked at types, derives and sinks, and never at interpolation.
#
#   THE REMEDY CHECK 3 ASKS FOR IS REDACTION AT THE FORMATTING SITE, NEVER DELETING THE
#   DIAGNOSTIC. An error that no longer says which setting was wrong is a worse error. Both real
#   fixes keep the failing variable, the failing field and the reason; only the value goes.
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

# ── CHECK 3 NEEDLES (the MESSAGE-INTERPOLATION class) ─────────────────────────────────────────────
# THREE RULES, ONE CLASS, EACH WITH ITS OWN RED AND ITS OWN NEGATIVE CONTROL IN `--selftest`. A rule
# that flags everything satisfies a red arm exactly as well as a correct one, so every rule below is
# paired with a GREEN fixture that it must NOT fire on.
#
#   A  secret-named-binding        — the value RENDERS UNDER a secret name. Same tail-matching rule
#                                    Check 1 uses (`fname == N || fname ends with _N`), applied to
#                                    the last segment of the interpolated path, because that is what
#                                    actually reaches the string: `cred.meta.public_id` renders
#                                    `public_id`, not `cred`.
#   B  decoder-error-on-secret-    — a decoder error's `Display` interpolated, where the decoder's
#      input                         INPUT is a secret. base64 and hex name bytes OF THE INPUT on
#                                    every failure; serde/toml echo a VALUE on a data error. The
#                                    "is the input a secret" evidence is the decoded binding's NAME
#                                    (`hex_seed`) or the message's own SUBJECT (`private_key`), so
#                                    `hex::decode(&manifest.signature)` — a PUBLIC signature — and
#                                    `base64.decode(value)` on declared media stay green.
#   C  secret-subject-parameter    — the message NAMES a secret subject right where it interpolates
#                                    the enclosing fn's OWN PARAMETER. This is the `parse_proxy`
#                                    shape and the only rule that could have caught it: in that
#                                    function NOTHING is secret-named — the param is `v`, the local
#                                    is `url`, the error is `e`. The only evidence that the value is
#                                    a credential is the sentence the author wrote about it.
#
# SUBJECTS: words that make a message a statement about WHAT THE VALUE IS. `proxy` is here on
# measured grounds, not vibes: `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are RFC 3986 URLs with a
# userinfo component, which is the canonical place a corporate proxy password lives, and that is
# precisely the leak that shipped. Matched on WORD BOUNDARIES and within C3_PROXIMITY characters of
# the capture, so the `credential` inside `put_credential:` (a function name) is not a subject and a
# subject forty lines of prose away from the capture is not one either.
C3_SUBJECTS="service-account|service account|token response|proxy|password|passphrase|private_key|private key|api_key|api key|client_secret|signing key|signing_key|bearer|credential|credentials|pkcs8|passwd|userinfo|secret"
# Decoders whose error `Display` echoes its INPUT. Not a guess: `base64::DecodeError::InvalidByte`
# prints the decimal byte and offset, `InvalidLastSymbol` prints the symbol as hex AND as the
# character AND its decoded bits; `hex::FromHexError::InvalidHexCharacter { c, index }` prints the
# character; serde's `invalid type: string "…"` prints the value.
C3_DECODERS="base64:: hex::decode hex::FromHex percent_decode serde_json::from_ serde_yaml::from_ toml::from_ toml::de::"
# Secret-bearing SOURCE names beyond the Check-1 needles, for "what was being decoded". `seed` is
# what makes `hex::decode(hex_seed.trim())` — LEDGER S21's `pack.rs` companion — visible without a
# subject word in its message.
C3_SOURCE="seed pem pkcs8 privkey keypair passphrase jwk"
# The safe-to-log IDENTITY of a secret, which is what the remedy asks you to print INSTEAD of the
# value, so printing one is never the violation. Tail-matched, so `public_id`/`key_id` ride on `id`.
# `url`/`uri`/`endpoint` are in here and that is a NAMED RESIDUAL: an RFC 3986 URL can carry
# userinfo, so a credential-bearing URL bound to a `*_url` name is a shape this check waves through.
# It is here because `token_url`/`token_uri` are endpoints this tree names dozens of times and the
# measured alternative was a rule that fired on every one of them.
C3_IDENTITY="host hostname port scheme status code len count index idx offset id sub kind class name field addr method verb line column slot alias label at section module server url uri endpoint path location reference pointer selector"
# A capture whose SOURCE TEXT contains one of these is already redacted at the formatting site,
# which IS the remedy. `describe()` is this tree's own: `SecretRef::describe()` renders `env:VAR` /
# `file:/path` / `none` and never a value.
C3_REDACTORS="redact mask sanitiz fingerprint elide scrub obfusc SecretRef reference() key_id describe()"
C3_MSG="format! write! writeln! panic! unreachable! todo! assert! assert_eq! assert_ne! bail! anyhow! println! eprintln! print! .expect("
# An err/diagnostic call that must ENCLOSE the macro (see `errencloses`). `push(` is here because
# that is the exact carrier of the jwt_bearer leak: `config_validate` does `errors.push(format!(…))`
# and the `errors` array is what admin `config/validate` returns to a READ-SCOPE caller.
C3_ERRCTX="Err( map_err ok_or_else ok_or( panic! .expect( bail! anyhow! assert write! writeln! unreachable! todo! println! eprintln! print! tracing:: log:: .context( with_context push("
C3_PROXIMITY=56

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

# CHECK 3 HAS NO EXCEPTIONS AND THAT IS A MEASUREMENT, NOT AN OVERSIGHT. Every one of the findings
# Check 3 makes on this tree was read against the source and is a real member of the class (see
# docs/design/1.6.0-secret-hygiene.md Part 5 for the row-by-row disposition). The four shapes that
# LOOK like the class and are not — `SecretRef::describe()`, a public key/signature through
# `hex::decode`, declared media through base64, a `format!` building a header VALUE rather than a
# message — are held green BY THE RULES, not by rows here, which is the disposition this file
# prefers: a rule that is right needs no list. Rows use the same NEEDLE|PATH-PREFIX|FIELD shape and
# the same liveness check as Check 1, so adding one is not a code change.
ALLOWLIST_C3=""

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

# ── THE MESSAGE SCANNER (Check 3) ──────────────────────────────────────────────────────────────────
# Emits: RULE<TAB>file:line<TAB>rendered-name<TAB>trimmed-statement
scan_msgs() {
  local strong="$1" context="$2" subjects="$3" decoders="$4" source="$5" identity="$6" redactors="$7" msgs="$8" errctx="$9" prox="${10}"; shift 10
  [ "$#" -gt 0 ] || return 0
  LC_ALL=C awk -v strong="$strong" -v context="$context" -v subjects="$subjects" -v decoders="$decoders" -v source="$source" \
      -v identity="$identity" -v redactors="$redactors" -v msgs="$msgs" -v errctx="$errctx" -v prox="$prox" '
    function strip2(line,   i, n, c, c2, j, k, p, ok, ch, isb) {
      scode = ""; sblank = ""; n = length(line); i = 1
      while (i <= n) {
        c = substr(line, i, 1); c2 = substr(line, i, 2)
        if (inblk) { if (c2 == "*/") { inblk = 0; i += 2 } else { i++ } continue }
        if (inraw) {
          while (i <= n) {
            if (substr(line, i, 1) == "\"") {
              ok = 1; for (k = 1; k <= rawh; k++) if (substr(line, i + k, 1) != "#") ok = 0
              if (ok) { scode = scode "\""; sblank = sblank " "
                        for (k = 0; k < rawh; k++) { scode = scode " "; sblank = sblank " " }
                        i += 1 + rawh; inraw = 0; break }
            }
            ch = substr(line, i, 1)
            scode = scode ((ch == "\"" || ch == "\\" || ch == "{" || ch == "}") ? " " : ch); sblank = sblank " "; i++
          }
          continue
        }
        if (instr) {
          if (c == "\\") { scode = scode "  "; sblank = sblank "  "; i += 2; continue }
          scode = scode c; sblank = sblank " "
          if (c == "\"") instr = 0
          i++; continue
        }
        if (c2 == "/*") { inblk = 1; i += 2; continue }
        if (c2 == "//") break
        # RAW STRINGS, INCLUDING THE BYTE FORMS. `br#"…"#` is why this is spelled out: the first cut
        # keyed on `r` with a non-identifier char before it, so the `b` of `br#"` disqualified it,
        # the literal was read as code, its inner `"` flipped the string state, and every finding in
        # the rest of that file became untrustworthy. The lexer now says so out loud (PARSE-WARN)
        # instead of returning a quiet zero.
        isb = 0
        if (c == "b" && substr(line, i + 1, 1) == "r") { isb = 1 }
        if (c == "r" || isb) {
          j = i + 1 + isb; rawh = 0
          while (substr(line, j, 1) == "#") { rawh++; j++ }
          if (substr(line, j, 1) == "\"") {
            p = (i > 1) ? substr(line, i - 1, 1) : " "
            if (p !~ /[A-Za-z0-9_]/) {
              inraw = 1
              for (k = i; k < j; k++) { scode = scode " "; sblank = sblank " " }
              scode = scode "\""; sblank = sblank " "
              i = j + 1; continue
            }
          }
        }
        if (c == "\x27") {
          if (substr(line, i + 1, 1) == "\\" && substr(line, i + 3, 1) == "\x27") { scode = scode "    "; sblank = sblank "    "; i += 4; continue }
          if (substr(line, i + 2, 1) == "\x27") { scode = scode "   "; sblank = sblank "   "; i += 3; continue }
        }
        if (c == "\"") { instr = 1; scode = scode c; sblank = sblank " "; i++; continue }
        scode = scode c; sblank = sblank c; i++
      }
    }
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function tailmatch(f, n) { return (f == n) || qualified(f, n) }
    function qualified(f, n) { return (length(f) > length(n) + 1 && substr(f, length(f) - length(n)) == "_" n) }
    function hasany(s, arr, cnt,   k) { for (k = 1; k <= cnt; k++) if (index(s, arr[k]) > 0) return 1; return 0 }
    function isident(x) { return (x ~ /^[A-Za-z_][A-Za-z0-9_]*$/) }
    function isupperconst(s,   i, c) {
      if (s !~ /^[A-Z]/) return 0
      for (i = 1; i <= length(s); i++) { c = substr(s, i, 1); if (c >= "a" && c <= "z") return 0 }
      return 1
    }
    function isidentity(x,   k) {
      for (k = 1; k <= nid; k++) if (tailmatch(x, ID[k])) return 1
      return 0
    }
    # Every `{IDENT}`/`{IDENT:spec}` inline capture and every positional `, PATH` argument after
    # `from`. cap[] = the name the value RENDERS UNDER (the last path segment, because that is what
    # actually reaches the string), capbase[] = the root binding (what the param test asks about),
    # cappos[] = where it sits, for the proximity test.
    function captures(s, bl, from,   i, n, c, id, j, ch, seg, nseg, segs, base, start) {
      ncap = 0; n = length(s); i = from
      while (i <= n) {
        c = substr(s, i, 1)
        if (substr(bl, i, 1) == " " && c != " ") {
          if (c == "{") {
            if (substr(s, i + 1, 1) == "{") { i += 2; continue }
            j = i + 1; id = ""
            while (j <= n) { ch = substr(s, j, 1); if (ch ~ /[A-Za-z0-9_]/) { id = id ch; j++ } else break }
            ch = substr(s, j, 1)
            if (id != "" && id !~ /^[0-9]/ && (ch == "}" || ch == ":")) { ncap++; cap[ncap] = id; capbase[ncap] = id; cappos[ncap] = i; captext[ncap] = id }
            i = j; continue
          }
          i++; continue
        }
        if (c == ",") {
          j = i + 1; start = i
          while (substr(s, j, 1) == " ") j++
          while (substr(s, j, 1) ~ /[&*%?]/) { j++; while (substr(s, j, 1) == " ") j++ }
          nseg = 0; base = ""
          while (1) {
            id = ""
            while (j <= n) { ch = substr(s, j, 1); if (ch ~ /[A-Za-z0-9_]/) { id = id ch; j++ } else break }
            if (id == "") break
            if (substr(s, j, 2) == "()") { j += 2; ch = substr(s, j, 1); if (ch == ".") { j++; continue } ; break }
            nseg++; segs[nseg] = id
            if (base == "") base = id
            if (substr(s, j, 1) == ".") { j++; continue }
            break
          }
          ch = substr(s, j, 1)
          if (nseg > 0 && segs[1] !~ /^[0-9]/ && (ch == "," || ch == ")" || ch == "" || ch == " " || ch == "?")) {
            ncap++; cap[ncap] = segs[nseg]; capbase[ncap] = base; cappos[ncap] = start
            captext[ncap] = substr(s, start + 1, j - start - 1)
          }
          i++; continue
        }
        i++
      }
    }
    # Lowercased literal text with code positions blanked, index-aligned to `s`, so proximity is
    # measured in the string the reader actually sees.
    function litmap(s, bl,   i, n, res) {
      res = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        if (substr(bl, i, 1) == " " && substr(s, i, 1) != "\"" && substr(s, i, 1) != " ") res = res tolower(substr(s, i, 1))
        else res = res " "
      }
      return res
    }
    # A subject word within `prox` characters of `pos`, matched on WORD BOUNDARIES (so the
    # `credential` inside `put_credential:` is not a subject — that is a function name, not a
    # statement about what the value IS).
    function subjectnear(lm, pos,   k, lo, hi, w, seg, base, r, q, before, after) {
      lo = pos - prox; if (lo < 1) lo = 1
      hi = pos + prox; if (hi > length(lm)) hi = length(lm)
      seg = substr(lm, lo, hi - lo + 1)
      for (k = 1; k <= nsb; k++) {
        w = SB[k]; base = 0
        while (1) {
          r = index(substr(seg, base + 1), w); if (r == 0) break
          q = base + r
          before = (q == 1) ? " " : substr(seg, q - 1, 1)
          after  = substr(seg, q + length(w), 1)
          if (before !~ /[a-z0-9_]/ && after !~ /[a-z0-9_]/) return 1
          base = q
        }
      }
      return 0
    }
    function firstmsg(s,   k, p, best) {
      best = 0
      for (k = 1; k <= nms; k++) { p = index(s, MS[k]); if (p > 0 && (best == 0 || p < best)) best = p }
      return best
    }
    # The msg-macro call that lexically contains `pos`: its opening `(` in code positions.
    function enclosingmacro(bl, pos,   n, best, k, w, base, r, p, o, d, j) {
      best = 0; n = length(bl)
      for (k = 1; k <= nms; k++) {
        w = MS[k]; base = 0
        while (1) {
          r = index(substr(bl, base + 1), w); if (r == 0) break
          p = base + r; base = p
          o = p + length(w) - 1
          while (o <= n && substr(bl, o, 1) != "(") o++
          if (o > n) break
          d = 0; j = o
          for (j = o; j <= n; j++) {
            if (substr(bl, j, 1) == "(") d++
            else if (substr(bl, j, 1) == ")") { d--; if (d == 0) break }
          }
          if (o <= pos && pos <= j && o > best) best = o
        }
      }
      return best
    }
    # AN ERR/DIAGNOSTIC CALL THAT IS STILL OPEN AT `mo`. Sharing a statement is not enough: a
    # builder chain writes `.header(AUTHORIZATION, format!("Bearer {}", api_key)).map_err(|e| …)`
    # as ONE statement, and reading that as "the api_key format! is in error context" flagged a
    # header injection — the exact shape Check 2 already proves GREEN. The question the rule asks
    # is whether an err/diagnostic call ENCLOSES the macro, which is the question that means
    # "this string is going to a caller as a message".
    function errencloses(bl, mo,   n, k, w, base, r, p, o, d, j) {
      n = length(bl)
      for (k = 1; k <= nec; k++) {
        w = EC[k]; base = 0
        while (1) {
          r = index(substr(bl, base + 1), w); if (r == 0) break
          p = base + r; base = p
          o = p + length(w) - 1
          while (o <= n && substr(bl, o, 1) != "(") o++
          if (o > n) break
          if (o > mo) continue
          d = 0
          for (j = o; j <= n; j++) {
            if (substr(bl, j, 1) == "(") d++
            else if (substr(bl, j, 1) == ")") { d--; if (d == 0) break }
          }
          if (o <= mo && mo <= j) return 1
        }
      }
      return 0
    }
    # The first identifier path handed to a decoder call, for the "what was being decoded" test.
    function decodersource(s, bl,   k, p, o, n, j, id, ch, res) {
      n = length(bl); res = ""
      for (k = 1; k <= ndc; k++) {
        p = index(bl, DC[k]); if (p == 0) continue
        o = p + length(DC[k]) - 1
        while (o <= n && substr(bl, o, 1) != "(") o++
        j = o + 1
        while (substr(bl, j, 1) ~ /[ &*]/) j++
        id = ""
        while (j <= n) { ch = substr(bl, j, 1); if (ch ~ /[A-Za-z0-9_:]/ || ch == ".") { id = id ch; j++ } else break }
        if (id != "") res = res " " id
      }
      return res
    }
    # EVERY segment of the decoded path, not just the last: `hex::decode(hex_seed.trim())` hands
    # the decoder `hex_seed.trim`, and reading only the tail asks whether `trim` is a secret.
    function secretsource(src,   nn, i, mm, j, seg, k) {
      nn = split(src, SS, " ")
      for (i = 1; i <= nn; i++) {
        mm = split(SS[i], SEG, /[.:]+/)
        for (j = 1; j <= mm; j++) {
          seg = SEG[j]; if (seg == "") continue
          for (k = 1; k <= ns; k++) if (tailmatch(seg, S[k])) return 1
          for (k = 1; k <= nsr; k++) if (tailmatch(seg, SR[k])) return 1
        }
      }
      return 0
    }
    function closureparams(s, bl,   i, n, id, j, ch) {
      nclp = 0; n = length(bl); i = 1
      while (i <= n) {
        if (substr(bl, i, 1) == "|") {
          j = i + 1
          while (substr(bl, j, 1) == " ") j++
          if (substr(bl, j, 4) == "mut ") { j += 4; while (substr(bl, j, 1) == " ") j++ }
          id = ""
          while (j <= n) { ch = substr(bl, j, 1); if (ch ~ /[A-Za-z0-9_]/) { id = id ch; j++ } else break }
          while (substr(bl, j, 1) == " ") j++
          ch = substr(bl, j, 1)
          if (id != "" && (ch == "|" || ch == ":" || ch == ",")) { nclp++; clp[nclp] = id }
          i = j; continue
        }
        i++
      }
    }
    function isclosureparam(x,   k) { for (k = 1; k <= nclp; k++) if (clp[k] == x) return 1; return 0 }
    function parseparams(sig, bl,   i, n, d, j, c, ch, id, inner, bi) {
      i = 0; n = length(bl)
      for (j = 1; j <= n - 2; j++) {
        if (substr(bl, j, 3) == "fn " && (j == 1 || substr(bl, j - 1, 1) !~ /[A-Za-z0-9_]/)) {
          bi = j + 3
          while (substr(bl, bi, 1) == " ") bi++
          while (substr(bl, bi, 1) ~ /[A-Za-z0-9_]/) bi++
          if (substr(bl, bi, 1) == "<") { d = 0
            while (bi <= n) { c = substr(bl, bi, 1); if (c == "<") d++; else if (c == ">") { d--; if (d == 0) { bi++; break } } bi++ } }
          if (substr(bl, bi, 1) == "(") { i = bi; break }
        }
      }
      if (i == 0) return
      d = 0; inner = ""
      for (j = i; j <= n; j++) {
        c = substr(bl, j, 1)
        if (c == "(") { d++; if (d == 1) continue }
        if (c == ")") { d--; if (d == 0) break }
        if (d >= 1) inner = inner c
      }
      n = length(inner); j = 1; d = 0
      while (j <= n) {
        c = substr(inner, j, 1)
        if (c == "<" || c == "(" || c == "[") { d++; j++; continue }
        if (c == ">" || c == ")" || c == "]") { d--; j++; continue }
        if (d == 0 && c ~ /[A-Za-z_]/) {
          id = ""
          while (j <= n) { ch = substr(inner, j, 1); if (ch ~ /[A-Za-z0-9_]/) { id = id ch; j++ } else break }
          while (substr(inner, j, 1) == " ") j++
          if (substr(inner, j, 1) == ":" && id != "mut" && id != "self") param[id] = 1
          continue
        }
        j++
      }
    }
    function flush(   i, mpos, lm, cp, bs, k, hit, isbyte, isdoc, seen) {
      if (stmt == "") { stmt = ""; sbl = ""; stmtline = 0; pdepth = 0; return }
      mpos = firstmsg(stmt)
      if (mpos == 0) { stmt = ""; sbl = ""; stmtline = 0; pdepth = 0; return }
      captures(stmt, sbl, mpos)
      if (ncap == 0) { stmt = ""; sbl = ""; stmtline = 0; pdepth = 0; return }
      lm = litmap(stmt, sbl)
      isdec = hasany(stmt, DC, ndc)
      decsrc = isdec ? decodersource(stmt, sbl) : ""
      decsecret = isdec ? secretsource(decsrc) : 0
      closureparams(stmt, sbl)
      for (k in seen) delete seen[k]
      for (i = 1; i <= ncap; i++) {
        cp = cap[i]; bs = capbase[i]
        if (cp in seen) continue
        seen[cp] = 1
        if ((cp in redacted) || (bs in redacted)) continue
        if (isupperconst(cp)) continue
        skip = 0
        for (k = 1; k <= nrd; k++) if (index(captext[i], RD[k]) > 0) skip = 1
        if (skip) continue
        mo = enclosingmacro(sbl, cappos[i])
        if (mo == 0) continue
        if (!errencloses(sbl, mo) && errdepth < 0) continue
        hit = ""
        # A — the value RENDERS UNDER a secret name (Check 1 tail rule, on the rendered segment).
        for (k = 1; k <= ns; k++) if (tailmatch(cp, S[k])) hit = "secret-named-binding"
        if (hit == "") for (k = 1; k <= nc; k++) if (qualified(cp, C[k])) hit = "secret-named-binding"
        if (hit == "" && isidentity(cp)) { continue }
        # B — a DECODER ERROR whose Display names bytes/values OF ITS INPUT, where the input is a
        #     secret: evidenced by the decoded binding NAME or by the message own SUBJECT.
        if (hit == "" && isdec && isclosureparam(cp) && (decsecret || subjectnear(lm, cappos[i]))) hit = "decoder-error-on-secret-input"
        # C — the message NAMES a secret subject right where it interpolates the fn own parameter.
        if (hit == "" && (bs in param) && subjectnear(lm, cappos[i])) hit = "secret-subject-parameter"
        if (hit != "") printf "%s\t%s:%d\t%s\t%s\n", hit, stmtfile, stmtline, cp, substr(trim(stmt), 1, 200)
      }
      stmt = ""; sbl = ""; stmtline = 0; pdepth = 0
    }
    function newfile(f) {
      if (prevfile != "" && (instr || inraw || inblk))
        printf "PARSE-WARN\t%s:0\tlexer-unterminated\tstring/raw/comment still open at EOF — findings for this file are NOT trustworthy\n", prevfile
      prevfile = f
      stmt = ""; sbl = ""; stmtline = 0; pdepth = 0; inblk = 0; instr = 0; inraw = 0; depth = 0; errdepth = -1
      for (k in param) delete param[k]; for (k in redacted) delete redacted[k]
      insig = 0; sigbuf = ""; sigbl = ""; sigdepth = 0; testmod = 0; tdepth = 0; pendtest = 0
    }
    BEGIN {
      ns = split(strong, S, " "); nc = split(context, C, " ")
      nsb = split(subjects, SB, "|"); ndc = split(decoders, DC, " "); nsr = split(source, SR, " ")
      lastp = 0
      nid = split(identity, ID, " "); nrd = split(redactors, RD, " ")
      nms = split(msgs, MS, " "); nec = split(errctx, EC, " ")
      prevfile = ""
    }
    FNR == 1 { newfile(FILENAME) }
    {
      strip2($0)
      code = scode; bcode = sblank
      no = gsub(/{/, "{", bcode); ncl = gsub(/}/, "}", bcode)
      op = gsub(/\(/, "(", bcode); cp2 = gsub(/\)/, ")", bcode)
      if (testmod) { tdepth += no - ncl; if (tdepth <= 0) { testmod = 0; tdepth = 0 } next }
      if (code ~ /#\[cfg\(/ && code ~ /(^|[^a-z])test([^a-z]|$)/) { pendtest = 1 }
      else if (pendtest && code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/) { pendtest = 0; if (no > 0) { testmod = 1; tdepth = no - ncl } next }
      else if (code ~ /[^[:space:]]/ && code !~ /#\[/) { pendtest = 0 }

      tc = trim(code); tbl = substr(bcode, length(code) - length(tc) + 1)
      if (tc == "") next

      if (!insig && bcode ~ /(^|[^A-Za-z0-9_])fn[ \t]+[A-Za-z_]/) {
        for (k in param) delete param[k]; for (k in redacted) delete redacted[k]
        insig = 1; sigbuf = ""; sigbl = ""; sigdepth = 0
      }
      if (insig) {
        sigbuf = sigbuf " " code; sigbl = sigbl " " bcode
        sigdepth += op - cp2
        if (sigdepth <= 0 && index(sigbl, "(") > 0) { parseparams(sigbuf, sigbl); insig = 0; sigbuf = ""; sigbl = "" }
      }
      if (bcode ~ /(^|[^A-Za-z0-9_])let[ \t]+/) {
        lv = bcode; sub(/.*[^A-Za-z0-9_]let[ \t]+/, "", lv); sub(/^let[ \t]+/, "", lv); sub(/^mut[ \t]+/, "", lv)
        nm = lv; sub(/[^A-Za-z0-9_].*/, "", nm)
        if (nm != "") for (k = 1; k <= nrd; k++) if (index(code, RD[k]) > 0) redacted[nm] = 1
      }

      if (stmt == "") { stmt = tc; sbl = tbl; stmtline = FNR; stmtfile = FILENAME }
      else { stmt = stmt " " tc; sbl = sbl " " tbl }
      pdepth += op - cp2
      if (pdepth < 0) pdepth = 0
      last = substr(tc, length(tc), 1)
      willopen = (no > ncl)
      if (pdepth == 0 && (last == ";" || last == "{" || last == "}" || last == ",")) {
        pend_err = (hasany(stmt, EC, nec) && willopen)
        flush()
        if (pend_err && errdepth < 0) errdepth = depth
      }
      depth += no - ncl
      if (errdepth >= 0 && depth <= errdepth) errdepth = -1
    }
    END { flush(); if (prevfile != "" && (instr || inraw || inblk)) printf "PARSE-WARN\t%s:0\tlexer-unterminated\tstring/raw/comment still open at EOF\n", prevfile }
  ' "$@"
}

# ── SCAN FLOOR — a scan of zero files is RED, never a clean PASS ─────────────────────────────────
# THE FAILURE THIS EXISTS FOR (item 484). Every sibling gate in the plane/secret slice
# (plane-grep-gate.sh, plane-noun-gate.sh, plane-config-noun-gate.sh) refuses a zero-file scan. This
# one did not: when prod_files came back empty (a root renamed, a layout move, an exclusion that
# swallowed the tree) all three checks were skipped by their `[ -n "$files" ] &&` guards, the totals
# were 0+0+0, and the verdict printed the green PASS line. "Measured nothing" and "measured everything
# and it passed" must never be the same output. check_scan_floor ROOTS FILES returns 1 (and says why)
# when any root is not a directory or when the file listing is empty.
check_scan_floor() {
  local roots="$1" files="$2" r bad=0
  for r in $roots; do
    if [ ! -d "$r" ]; then
      red "secret-hygiene gate: FAIL — scan root \`$r\` is not a directory in this tree."
      bad=1
    fi
  done
  if [ -z "$files" ]; then
    red "secret-hygiene gate: FAIL — scanned 0 production .rs file(s) under \`$roots\`; zero is RED"
    note "A scan of zero files reports zero violations, which is indistinguishable from a clean tree."
    bad=1
  fi
  return "$bad"
}

# Production .rs under the roots, minus test files.
#
# THE TEST-FILE SHAPE (item 506, twin of the plane meters' fix). It used to be `_tests?\.rs$` — a
# literal underscore before `test` — so a module-style `tests.rs` (`#[cfg(test)] mod tests;` beside
# its parent) was scanned as PRODUCTION code, and its fixtures counted as secret-hygiene debt. The
# separator is now `/` or `_`: `foo/tests.rs`, `foo/test.rs` and `foo_tests.rs` are test code;
# `contests.rs` is not. Every `tests.rs`/`test.rs` under crates/ outside a `/tests/` dir was checked
# to be declared behind `#[cfg(test)]`.
TEST_FILE_RE='(^|[/_])tests?\.rs$'
prod_files() {
  find "$@" -name '*.rs' 2>/dev/null | grep -v '/tests/' | grep -Ev "$TEST_FILE_RE" | grep -v '^$' | sort
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
$ALLOWLIST_C3
EOF
  return "$stale"
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "secret-hygiene-gate SELF-TEST (the field/sink scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out n

  # Every Check-3 fixture below runs through the SHIPPED needles — not a copy of them — so a needle
  # edit that breaks a proof breaks this self-test rather than passing against a private duplicate.
  c3() { scan_msgs "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$C3_SUBJECTS" "$C3_DECODERS" "$C3_SOURCE" \
                   "$C3_IDENTITY" "$C3_REDACTORS" "$C3_MSG" "$C3_ERRCTX" "$C3_PROXIMITY" "$@"; }

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
  #
  # THE FN-PARAM LINE IN HERE ENCODED THE BLIND SPOT, and it is kept ONLY because the case below it
  # now closes it. As originally written this case asserted, flatly, that a fn parameter named
  # `api_key: String` must not be flagged — and for CHECK 1 that is correct and stays correct: a
  # parameter is not a field, it has no derived `Debug`/`Serialize` to leak through, and flagging it
  # here would be flagging a shape that cannot leak by the mechanism Check 1 exists for.
  #
  # But nothing else in this file looked at it either, and that is what the case was really
  # recording. Both leaks of 49d781bd1 were exactly this: a fn parameter (`parse_proxy(v: &str)`)
  # and a third-party error's `Display`, interpolated into a `format!` that becomes a returned
  # `Err`. The green line said "not a Check-1 violation"; the gate as a whole read it as "not a
  # violation". `c1_green_param_is_c3_red` immediately below takes the VERY SAME source text and
  # proves Check 3 DOES see it. The case is not deleted, because deleting it would lose the true
  # statement it makes; it is PAIRED, because on its own it was load-bearing for a false one.
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

  # ── THE PAIRING: the SAME fn param, now in a message. Check 1 green, Check 3 RED. ──
  cat >"$tmp/c1_green_param_is_c3_red.rs" <<'PAIR'
fn set(api_key: String) -> Result<(), String> {
    Err(format!("api_key {api_key} was rejected by the upstream"))
}
PAIR
  out="$(scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" "$tmp/c1_green_param_is_c3_red.rs")"
  if [ -z "$out" ]; then
    note "PAIR: Check 1 is still (correctly) silent on a fn param — a param is not a field"
  else
    fail=1; note "PAIR FAILED: Check 1 started flagging a fn param; that is not its rule"
  fi
  out="$(c3 "$tmp/c1_green_param_is_c3_red.rs")"
  if printf '%s\n' "$out" | grep -q 'secret-named-binding'; then
    note "PAIR: Check 3 FLAGS that same fn param once it reaches a message — the blind spot is closed"
  else
    fail=1; note "PAIR FAILED: the fn param the c1 GREEN case excuses is STILL invisible to the gate"
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

  # ══ CHECK 3 — the MESSAGE-INTERPOLATION class ══════════════════════════════════════════════════
  #
  # THE TWO REAL LEAKS ARE PERMANENT FIXTURES HERE, VERBATIM FROM THEIR PRE-FIX CONTENT
  # (49d781bd1^). A check written after an incident is worth exactly what it proves against that
  # incident, and "I read the rule and it looks like it would have caught it" is not a proof. These
  # are the bytes that shipped. If a future edit to the needles or the lexer stops seeing them, this
  # self-test goes red rather than the gate going quiet.

  # ── RED (Check 3, REAL LEAK #1 — egress/engine/mod.rs `tunnel::parse_proxy`, pre-49d781bd1). ──
  # Three refusal arms rendering the RAW proxy env value with `{v:?}`. `HTTPS_PROXY`/`HTTP_PROXY`/
  # `ALL_PROXY` carry `user:password@`, and this refusal is not swallowed — it becomes a boot panic
  # with no `catch_unwind` under it, so the password reached stderr, the crash report and the CI log.
  # NOTHING IN THIS FUNCTION IS SECRET-NAMED: the param is `v`, the local is `url`, the error is `e`.
  # Only rule C can see it, and only because of the sentence the author wrote about the value.
  cat >"$tmp/c3_red_proxy.rs" <<'RED3A'
pub(super) fn parse_proxy(v: &str) -> Result<ProxySpec, String> {
    let url = if v.contains("://") {
        v.to_string()
    } else {
        format!("http://{v}")
    };
    let parsed = url::Url::parse(&url)
        .map_err(|e| format!("proxy env value {v:?} is not a valid URL: {e}"))?;
    if parsed.scheme() != "http" {
        return Err(format!(
            "proxy env value {v:?} uses scheme {:?}: only plain http:// CONNECT proxies are \
             supported (an https:// proxy would need TLS-to-proxy, which this tunnel does not \
             speak)",
            parsed.scheme()
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("proxy env value {v:?} has no host"))?
        .to_string();
    Ok(ProxySpec { host })
}
RED3A
  out="$(c3 "$tmp/c3_red_proxy.rs")"
  n="$(printf '%s\n' "$out" | awk -F'\t' '$1=="secret-subject-parameter"{n++} END{print n+0}')"
  if [ "$n" -eq 3 ]; then
    note "RED c3: REAL LEAK #1 — all THREE \`parse_proxy\` refusal arms named (raw \$HTTPS_PROXY into an Err)"
  else
    fail=1; note "RED c3 FAILED: expected 3 parse_proxy arms, got $n — the shipped proxy-password leak would pass"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── RED (Check 3, REAL LEAK #2 — egress_auth/jwt_bearer.rs `pem_to_pkcs8_der`, pre-49d781bd1). ──
  # `base64::DecodeError`'s own Display names a byte OF THE KEY BODY. `InvalidLastSymbol` prints the
  # symbol as hex AND as the character AND its decoded bits — and for that variant the symbol is a
  # VALID base64 character, i.e. six bits of the operator's RSA private key. `validate_credential` ->
  # `config_validate` copies the string verbatim into the `errors` array admin `config/validate`
  # returns to a READ-SCOPE caller. A privilege boundary, not log hygiene.
  cat >"$tmp/c3_red_pem.rs" <<'RED3B'
fn pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("service-account private_key is empty or not PEM-armored".to_string());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("service-account private_key base64 is invalid: {e}"))
}
RED3B
  out="$(c3 "$tmp/c3_red_pem.rs")"
  if printf '%s\n' "$out" | grep -q 'decoder-error-on-secret-input'; then
    note "RED c3: REAL LEAK #2 — \`base64::DecodeError\`'s Display into a read-scope \`errors\` string, named"
  else
    fail=1; note "RED c3 FAILED: the shipped RSA-key-symbol leak would pass"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── RED (Check 3, LEDGER S21 companion — plugin-sdk/src/pack.rs:538, STILL LIVE). ──
  # `hex::FromHexError::InvalidHexCharacter { c, index }` prints the character AND its index, which
  # for the 32-byte ed25519 seed in $BUSBAR_SIGN_KEY is a nibble of the signing key. There is no
  # subject word in that message at all — `{SIGN_KEY_ENV}` is the env var NAME, a const — so the
  # only evidence is the decoded binding: `hex_seed`. This is the case C3_SOURCE exists for.
  cat >"$tmp/c3_red_hexseed.rs" <<'RED3C'
fn sign_it(allow_unsigned: bool) -> Result<Manifest, String> {
    let hex_seed = std::env::var(SIGN_KEY_ENV).map_err(|_| "unset".to_string())?;
    let seed = hex::decode(hex_seed.trim())
        .map_err(|e| format!("{SIGN_KEY_ENV} is not valid hex: {e}"))?;
    Ok(seed)
}
RED3C
  out="$(c3 "$tmp/c3_red_hexseed.rs")"
  if printf '%s\n' "$out" | grep -q 'decoder-error-on-secret-input'; then
    note "RED c3: LEDGER S21 companion — \$BUSBAR_SIGN_KEY's hex error (a nibble of the ed25519 seed), named"
  else
    fail=1; note "RED c3 FAILED: the pack.rs signing-seed echo would pass"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── RED (Check 3, rule A — the PLANT). A secret-NAMED binding straight into a returned Err. ──
  cat >"$tmp/c3_red_named.rs" <<'RED3D'
fn check(cfg: &Lane) -> Result<(), String> {
    if cfg.api_key.is_empty() {
        return Err(format!("upstream rejected api_key {}", cfg.api_key));
    }
    let admin_password = cfg.pw();
    if admin_password.len() < 8 {
        return Err(format!("admin_password {admin_password} is too short"));
    }
    Ok(())
}
RED3D
  out="$(c3 "$tmp/c3_red_named.rs")"
  n="$(printf '%s\n' "$out" | awk -F'\t' '$1=="secret-named-binding"{n++} END{print n+0}')"
  if [ "$n" -ge 2 ]; then
    note "RED c3: a secret-NAMED binding (api_key, admin_password) interpolated into a returned Err, named"
  else
    fail=1; note "RED c3 FAILED: expected >=2 secret-named-binding, got $n"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── GREEN (Check 3): BOTH REAL LEAKS AS THEY ARE FIXED TODAY. ──
  # The remedy is redaction AT THE FORMATTING SITE, never deleting the diagnostic. Both of these
  # still say which variable failed, which field failed, and why; neither says the value. If the
  # check cannot tell the fix from the leak it is not a check, it is a ban on error messages.
  cat >"$tmp/c3_green_fixed.rs" <<'GREEN3A'
fn redact_userinfo(v: &str) -> String {
    let (scheme, rest) = match v.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, v),
    };
    match scheme { Some(s) => format!("{s}://{rest}"), None => rest.to_string() }
}
pub(super) fn parse_proxy(v: &str) -> Result<ProxySpec, String> {
    let shown = redact_userinfo(v);
    let url = if v.contains("://") { v.to_string() } else { format!("http://{v}") };
    let parsed = url::Url::parse(&url)
        .map_err(|e| format!("proxy env value {shown:?} is not a valid URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("proxy env value {shown:?} has no host"))?
        .to_string();
    Ok(ProxySpec { host })
}
fn pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| {
            let why = match e {
                base64::DecodeError::InvalidByte(..) => "it contains a character outside the base64 alphabet",
                base64::DecodeError::InvalidLength(..) => "its final base64 group is short",
                base64::DecodeError::InvalidLastSymbol { .. } => "its final symbol carries bits decoding would discard",
                base64::DecodeError::InvalidPadding => "its `=` padding is absent or malformed",
            };
            format!("service-account private_key base64 is invalid: {why}.")
        })
}
GREEN3A
  out="$(c3 "$tmp/c3_green_fixed.rs")"
  if [ -z "$out" ]; then
    note "GREEN c3: BOTH real leaks AS FIXED flag NONE — redaction at the format site is recognised, and the diagnostic survives"
  else
    fail=1; note "GREEN c3 FAILED: the check cannot tell the fix from the leak — expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── GREEN (Check 3): THE NEGATIVE CONTROL. Without this, a rule that flags every interpolation
  #    satisfies every RED arm above and is worthless. Eight shapes that LOOK like the class:
  #      1. a plain non-secret value in an Err message
  #      2. a `format!` building a header VALUE (not a message) — sharing a statement with a
  #         trailing `.map_err` must not make it one
  #      3. `SecretRef::describe()` — the safe identity, which is what the remedy asks you to print
  #      4. the identity nouns (`host`, `port`, `location`) inside a message about a secret
  #      5. `hex::decode` of a PUBLIC key and of a signature
  #      6. base64 of declared media
  #      7. a subject word that is part of a FUNCTION name (`put_credential:`), not a claim about
  #         the value
  #      8. an ALL-CAPS const, which names an env var and is not its contents
  cat >"$tmp/c3_green_control.rs" <<'GREEN3B'
fn a(base_url: &str, retries: u32) -> Result<(), String> {
    Err(format!("upstream {base_url} refused after {retries} retries"))
}
fn b(&self) -> Result<Request, MintError> {
    http::Request::builder()
        .header(http::header::AUTHORIZATION, format!("Bearer {}", self.api_key))
        .body(Full::new(Bytes::new()))
        .map_err(|e| MintError::Provider(format!("mint request did not build: {e}")))
}
fn c(secret: &SecretRef, module: &str) -> Result<Vec<u8>, String> {
    Err(format!(
        "secret module '{module}' failed to resolve {}; a secret that cannot resolve is fatal",
        secret.describe()
    ))
}
fn d(host: &str, port: u16, location: &str) -> Result<(), String> {
    Err(format!("proxy refused CONNECT {host}:{port}; no secret is declared at {location}"))
}
fn e(s: &str, manifest: &Manifest) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("public key not valid hex: {e}"))?;
    let sig = hex::decode(&manifest.signature).map_err(|e| format!("signature not hex: {e}"))?;
    Ok(bytes)
}
fn f(at: &str, field: &str, value: &str) -> Result<(), String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("{at}: `{field}` is not valid standard base64 ({e}); it is declared media"))?;
    Ok(())
}
fn g(slot: u32, kind: &str) -> Result<(), String> {
    Err(format!("put_credential: slot {slot} for kind '{kind}' is already live"))
}
fn h() -> Result<(), String> {
    Err(format!("{SIGN_KEY_ENV} is not set; pass --allow-unsigned to package unsigned"))
}
GREEN3B
  out="$(c3 "$tmp/c3_green_control.rs")"
  if [ -z "$out" ]; then
    note "GREEN c3: NEGATIVE CONTROL — 8 non-secret/redacted/header-value/public-material shapes flagged NONE"
  else
    fail=1; note "GREEN c3 FAILED: the rule over-fires; a check that flags everything proves nothing. Got:"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── THE LEXER, RED THEN GREEN. A scanner that loses string state returns a SILENT ZERO for the
  #    rest of the file, and that is the failure mode this whole file is armed against. The first
  #    cut of Check 3 did exactly that on `br#"…"#`: the `b` disqualified the raw-string rule, the
  #    literal was read as code, its inner `"` flipped the state, and every later finding in that
  #    file became fiction. It is proven BOTH ways: the byte-raw-string must parse clean, and a
  #    genuinely unterminated literal must SAY SO rather than report zero.
  cat >"$tmp/c3_lexer_green.rs" <<'LEXG'
fn pieces() {
    for piece in [r#"{"loc"#, r#"ation":"SF"}"#] { let _ = piece; }
    let b = Bytes::from_static(br#"{"location":"S"#);
    let c = br#"["a","b"]"#;
    let d = r"a raw string with no hashes";
}
fn after(api_key: String) -> Result<(), String> {
    Err(format!("api_key {api_key} was rejected"))
}
LEXG
  out="$(c3 "$tmp/c3_lexer_green.rs")"
  if printf '%s\n' "$out" | grep -q 'PARSE-WARN'; then
    fail=1; note "LEXER FAILED: \`br#\"…\"#\` lost string state — every finding after it is fiction"
  elif printf '%s\n' "$out" | grep -q 'secret-named-binding'; then
    note "LEXER GREEN: byte/raw strings (\`br#\"…\"#\`, \`r#\"…\"#\`, \`r\"…\"\`) parse clean AND the leak AFTER them is still seen"
  else
    fail=1; note "LEXER FAILED: parsed clean but went blind — the planted leak after the raw strings was not seen"
  fi
  printf 'fn x() {\n    let s = "unterminated\n' >"$tmp/c3_lexer_red.rs"
  out="$(c3 "$tmp/c3_lexer_red.rs")"
  if printf '%s\n' "$out" | grep -q 'PARSE-WARN'; then
    note "LEXER RED: an unterminated literal is REPORTED, not silently scanned as zero findings"
  else
    fail=1; note "LEXER RED FAILED: a file the lexer could not parse produced a quiet zero"
  fi

  # ── THE ALLOWLIST-LIVENESS DETECTOR, red then green. A detector that cannot go red is the same
  #    silent instrument it was written to replace, so it is proven on a planted stale row first and
  #    on the REAL list second — which also means every run of this self-test re-asserts that the
  #    shipped allowlist still names only live paths.
  local real_allowlist="$ALLOWLIST_C1" real_allowlist3="$ALLOWLIST_C3"
  ALLOWLIST_C3=""
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
  ALLOWLIST_C1="$real_allowlist"; ALLOWLIST_C3="$real_allowlist3"
  if check_allowlist_paths >/dev/null 2>&1; then
    note "GREEN allowlist: every row of the SHIPPED allowlist names a path in this tree"
  else
    fail=1; note "GREEN allowlist FAILED: the shipped allowlist has a stale row (run --check to see it)"
  fi

  # ── SCAN FLOOR (item 484): a zero-file scan must be RED through the REAL run_report path. ──
  # RED: a root that exists but holds no production .rs (only a tests/ file, which prod_files drops).
  mkdir -p "$tmp/floor_empty/tests" "$tmp/floor_live/src"
  printf 'pub struct Clean { pub n: usize }\n' >"$tmp/floor_empty/tests/only_test.rs"
  printf 'pub struct Clean { pub n: usize }\n' >"$tmp/floor_live/src/lib.rs"
  if ( ROOTS="$tmp/floor_empty"; SCAN_BROKEN=0; run_report >/dev/null 2>&1; [ "$SCAN_BROKEN" -ne 0 ] ); then
    note "RED floor: a root holding ZERO production .rs is a broken scan, not a PASS"
  else
    fail=1; note "RED floor FAILED: a zero-file scan reported a clean 0+0+0 — the silent-zero class is back"
  fi
  # RED: a root that does not exist at all.
  if ( ROOTS="$tmp/floor_missing"; SCAN_BROKEN=0; run_report >/dev/null 2>&1; [ "$SCAN_BROKEN" -ne 0 ] ); then
    note "RED floor: a scan root that is not on disk is a broken scan, not a PASS"
  else
    fail=1; note "RED floor FAILED: a missing scan root reported a clean 0+0+0"
  fi
  # GREEN: a root with one clean production .rs scans, is not broken, and totals 0.
  if ( ROOTS="$tmp/floor_live"; SCAN_BROKEN=0; REPORT_TOTAL=x; run_report >/dev/null 2>&1; [ "$SCAN_BROKEN" -eq 0 ] && [ "$REPORT_TOTAL" = "0" ] ); then
    note "GREEN floor: a root with one clean production .rs scans and is NOT flagged broken"
  else
    fail=1; note "GREEN floor FAILED: the floor fired on a live, clean root — it over-fires"
  fi

  # ── TEST-FILE SHAPE (item 506): a module-style tests.rs is test code, not production. ──
  mkdir -p "$tmp/shape/src/sub"
  printf 'pub struct Clean { pub n: usize }\n' >"$tmp/shape/src/lib.rs"
  printf 'pub struct Clean { pub n: usize }\n' >"$tmp/shape/src/contests.rs"
  printf 'pub struct Fixture { pub api_key: String }\n' >"$tmp/shape/src/sub/tests.rs"
  printf 'pub struct Fixture { pub api_key: String }\n' >"$tmp/shape/src/test.rs"
  printf 'pub struct Fixture { pub api_key: String }\n' >"$tmp/shape/src/sub/wire_tests.rs"
  local shape; shape="$(prod_files "$tmp/shape" | sed "s|^$tmp/shape/||" | tr '\n' ' ')"
  if [ "$shape" = "src/contests.rs src/lib.rs " ]; then
    note "RED/GREEN shape: tests.rs, test.rs and *_tests.rs are excluded; lib.rs and contests.rs are scanned"
  else
    fail=1; note "SHAPE FAILED: production listing was \`$shape\` (want: src/contests.rs src/lib.rs)"
  fi

  if [ "$fail" -ne 0 ]; then
    red "secret-hygiene-gate SELF-TEST FAILED — the scanner would let a bare secret / a logged secret / a secret in a returned message through"
    return 1
  fi
  grn "secret-hygiene-gate self-test: ALL GREEN (Check-1 field RED/GREEN + Check-2 sink RED/GREEN + Check-3 message RED/GREEN incl. BOTH real leaks pre-fix and post-fix + lexer RED/GREEN + allowlist-liveness RED/GREEN + scan-floor RED/GREEN + test-file shape proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
REPORT_TOTAL=0
SCAN_BROKEN=0
run_report() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  : >"$tmp/c1"; : >"$tmp/c2"; : >"$tmp/c3"
  local files; files="$(prod_files $ROOTS)"
  # THE FLOOR, BEFORE ANY CHECK RUNS: an empty listing would otherwise skip all three checks below.
  if ! check_scan_floor "$ROOTS" "$files"; then
    SCAN_BROKEN=1
    return 0
  fi
  # shellcheck disable=SC2086
  [ -n "$files" ] && scan_fields "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$CONTEXT_STRUCT_RE" $files >>"$tmp/c1"
  # shellcheck disable=SC2086
  [ -n "$files" ] && scan_sinks "$SINKS" $files >>"$tmp/c2"
  # THE SCANNER'S OWN EXIT CODE, IN ITS OWN VARIABLE, BEFORE ANYTHING ELSE TOUCHES $?. Check 3's awk
  # bailed out mid-tree on the first run of this file — `illegal byte sequence` on an em-dash under a
  # UTF-8 locale (fixed with LC_ALL=C in the scanner) — and a bail is a PARTIAL scan that still
  # prints a number. "Measured nothing" and "measured everything and it passed" must never be the
  # same output, so a non-zero rc here is a hard FAIL, not a smaller count.
  local rc3=0
  # shellcheck disable=SC2086
  if [ -n "$files" ]; then
    scan_msgs "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$C3_SUBJECTS" "$C3_DECODERS" "$C3_SOURCE" \
              "$C3_IDENTITY" "$C3_REDACTORS" "$C3_MSG" "$C3_ERRCTX" "$C3_PROXIMITY" $files >>"$tmp/c3"
    rc3=$?
  fi
  if [ "$rc3" -ne 0 ]; then
    red "secret-hygiene gate: FAIL — the Check-3 scanner exited $rc3; its scan was PARTIAL."
    note "A scanner that bailed still prints a count, and that count is a false zero. Fix the scanner."
    SCAN_BROKEN=1
  fi
  local nwarn
  nwarn="$(awk -F'\t' '$1=="PARSE-WARN"{n++} END{print n+0}' "$tmp/c3")"
  if [ "$nwarn" -gt 0 ]; then
    red "secret-hygiene gate: FAIL — the Check-3 lexer lost string state in $nwarn file(s)."
    awk -F'\t' '$1=="PARSE-WARN"{printf "  %s  %s\n", $2, $4}' "$tmp/c3"
    note "Every finding in those files is untrustworthy — a swallowed literal reads as code and a"
    note "swallowed code region reports NOTHING. This is the silent-zero class, so it is a hard fail."
    SCAN_BROKEN=1
  fi

  local n1 n2 n3 total
  n1="$(awk 'END{print NR+0}' "$tmp/c1")"
  n2="$(awk 'END{print NR+0}' "$tmp/c2")"
  n3="$(awk -F'\t' '$1!="PARSE-WARN"{n++} END{print n+0}' "$tmp/c3")"
  total=$((n1 + n2 + n3)); REPORT_TOTAL="$total"

  hdr "SECRET-HYGIENE report — bare secret VALUE types + secrets at a sink + secrets in a MESSAGE (production .rs under $ROOTS)"
  note "Check 1 (bare secret field, not Redacted/Zeroizing/SecretRef): $n1"
  note "Check 2 (.expose_secret() on a log/audit/metric sink line):     $n2"
  note "Check 3 (secret interpolated into a message a caller receives): $n3"

  if [ "$n1" -gt 0 ]; then
    hdr "Check 1 — bare secret fields (convert to busbar_api::Redacted<T>)"
    awk -F'\t' '{printf "  %-20s %s\n", $1, $2}' "$tmp/c1"
  fi
  if [ "$n2" -gt 0 ]; then
    hdr "Check 2 — secret exposed at a sink (log the SecretRef/id, never the value)"
    awk -F'\t' '{printf "  %-14s %s\n", $1, $2}' "$tmp/c2"
  fi
  if [ "$n3" -gt 0 ]; then
    hdr "Check 3 — secret interpolated into a message a CALLER receives (redact AT the format site; never delete the diagnostic)"
    awk -F'\t' '$1!="PARSE-WARN"{printf "  %-30s %-58s %s\n", $1, $2, $3}' "$tmp/c3"
  fi

  cp "$tmp/c1" "${SECRET_GATE_C1_OUT:-/dev/null}" 2>/dev/null || true
  cp "$tmp/c2" "${SECRET_GATE_C2_OUT:-/dev/null}" 2>/dev/null || true
  cp "$tmp/c3" "${SECRET_GATE_C3_OUT:-/dev/null}" 2>/dev/null || true
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
    # A BROKEN INSTRUMENT IS NOT "REPORT-ONLY". Same posture `check_allowlist_paths` already takes:
    # a debt count is a thing to burn down, a scanner that did not finish is a thing that is lying.
    if [ "$SCAN_BROKEN" -ne 0 ]; then
      red "secret-hygiene gate: FAIL — the scan did not complete; the counts above are NOT a verdict."
      exit 1
    fi
    report_only="${SECRET_GATE_REPORT_ONLY:-1}"
    if [ "$REPORT_TOTAL" -eq 0 ]; then
      grn "secret-hygiene gate: PASS — no bare secret value type, no secret at a sink"
      exit 0
    fi
    if [ "$report_only" = "0" ]; then
      red "secret-hygiene gate: FAIL — $REPORT_TOTAL secret-hygiene violation(s) (see report above)"
      note "Wrap each secret VALUE in busbar_api::Redacted<T>; log a SecretRef/id, never .expose_secret() output."
      note "For a Check-3 hit: REDACT AT THE FORMAT SITE. Do not delete the diagnostic — an error that"
      note "no longer says which setting was wrong is a worse error than one that says too much."
      exit 1
    fi
    ylw "secret-hygiene gate: $REPORT_TOTAL violation(s) — REPORT-ONLY (SECRET_GATE_REPORT_ONLY=1, non-blocking)."
    note "Baseline debt; Phase-2 (post-pivot) converts the remaining offenders. Set SECRET_GATE_REPORT_ONLY=0 to arm the hard gate."
    exit 0
    ;;
  --scan3)
    # CHECK 3 AGAINST NAMED FILES — how the retro-proof is run, and why it is a shipped mode rather
    # than a copy of the scanner in somebody's scratch directory. "Would this check have caught the
    # leak?" is answerable ONLY against the bytes that shipped, so:
    #
    #   git show 49d781bd1^:crates/busbar-kernel/src/egress/engine/mod.rs      > /tmp/pre/a.rs
    #   git show 49d781bd1^:crates/busbar-kernel/src/egress_auth/jwt_bearer.rs > /tmp/pre/b.rs
    #   scripts/secret-hygiene-gate.sh --scan3 /tmp/pre/a.rs /tmp/pre/b.rs
    #
    # must name both. A copy of the rules run by hand proves something about the copy. This runs the
    # SHIPPED needles and the SHIPPED lexer, so it cannot drift from what CI does.
    shift
    [ "$#" -gt 0 ] || { echo "usage: $0 --scan3 <file.rs...>" >&2; exit 2; }
    scan_msgs "$STRONG_NEEDLES" "$CONTEXT_NEEDLES" "$C3_SUBJECTS" "$C3_DECODERS" "$C3_SOURCE" \
              "$C3_IDENTITY" "$C3_REDACTORS" "$C3_MSG" "$C3_ERRCTX" "$C3_PROXIMITY" "$@"
    rc=$?
    [ "$rc" -eq 0 ] || { red "secret-hygiene gate: FAIL — the Check-3 scanner exited $rc (PARTIAL scan)"; exit 1; }
    exit 0
    ;;
  -h | --help)
    sed -n '2,40p' "$0"
    ;;
  *)
    echo "usage: $0 [--selftest | --report | --check | --scan3 <file.rs...>]   (env SECRET_GATE_REPORT_ONLY=1 default report-only; =0 blocking)" >&2
    exit 2
    ;;
esac
