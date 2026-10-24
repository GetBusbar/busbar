//! `cargo xtask gate secret-hygiene` — THE SECRET-VALUE-TYPE DEBT METER (BUSBAR-1.6.0.md #53/#54).
//!
//! Ported from `scripts/secret-hygiene-gate.sh`, rule for rule. busbar's secret-hygiene guarantee is
//! a TYPE guarantee: a secret value is `Secret<T>` (Debug/Display = `[REDACTED]`, no Serialize,
//! zeroize-on-drop), never a bare `String`/`&str`/`Vec<u8>`; its safe-to-log identity is a
//! `SecretRef` or a plain id. Three ways that regresses, each a ledger row:
//!
//! * **Check 1** — a known-secret struct FIELD declared as a bare string type instead of
//!   `Secret<T>`/`Zeroizing`/`SecretRef`. Needles are matched on the field-name TAIL
//!   (`fname == N || fname ends with _N`), never as a substring.
//! * **Check 2** — `.expose(seal)` on the SAME STATEMENT as a log/audit/metric sink.
//! * **Check 3** — a secret-bearing value interpolated into a message a caller receives: a
//!   `format!`/`write!`/`panic!`/… enclosed by an `Err(..)`/`map_err`/`push(..)`/diagnostic call.
//!   Rule A (secret-named binding), B (decoder error on secret input), C (secret-subject
//!   parameter).
//!
//! THE DENOMINATOR (Law 8): every production `.rs` under `crates/` (the plane and transport pins
//! the base layer lays there included), RECONCILED against the tracked set, plus every git-pinned
//! `busbar-*` plugin crate the binary links, read from its checkout ([`pinned_sources`]).
//!
//! Plus the instrument's own rows: the scan FLOOR (zero files, a tracked file the walk did not
//! read, a read file nothing tracks, a crate that contributed nothing, or a pinned plugin crate
//! that would not resolve or read is RED), the ALLOWLIST
//! liveness (a row whose path-prefix names nothing is RED), and `scan-complete` (a lexer that lost
//! string state, or a file that would not read, is a broken instrument and not a count).
//!
//! BLOCKING BY DEFAULT — the owner-locked #53 release blocker, armed once the tree measured zero
//! violations: any Check 1/2/3 violation FAILS its row (and `cargo xtask gate secret-hygiene`
//! prints the report to stderr either way). `SECRET_GATE_REPORT_ONLY=1` is the one explicit escape,
//! kept from the script (where it was the default): the three check rows become PASS rows whose
//! detail carries the violation list. `SECRET_GATE_REPORT_ONLY=0` (the script's arming value) is
//! still accepted and simply blocks. The floor, the allowlist liveness and scan-complete rows fail
//! in BOTH modes: a broken instrument is not "report-only".
//!
//! The scanners are hand ports of the script's awk programs (byte-oriented, like `LC_ALL=C awk`),
//! quirks included: the same lexer, the same brace-depth stack, the same statement windows.

use std::collections::HashSet;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use crate::ctx::{Coverage, Ctx, Overlay, WalkError, WalkSpec};
use crate::gates::{
    prove_green, prove_red_by_configuration, prove_rows_green, prove_rows_red, Gate, Report,
};
use crate::ledger::{Row, Verdict};

pub const ROW_FLOOR: &str = "secret-hygiene:scan-floor";
pub const ROW_ALLOW: &str = "secret-hygiene:allowlist-live";
pub const ROW_SCAN: &str = "secret-hygiene:scan-complete";
pub const ROW_C1: &str = "secret-hygiene:check1-bare-field";
pub const ROW_C2: &str = "secret-hygiene:check2-sink";
pub const ROW_C3: &str = "secret-hygiene:check3-message";

// ── NEEDLES (verbatim from the script; see its history for why each is what it is) ──────────────
const STRONG_NEEDLES: &str = "api_key api_key_plaintext client_secret private_key signing_key access_token subject_token api_secret secret_access_key password bearer credential_secret";
const CONTEXT_NEEDLES: &str = "secret token credential credentials";
const CONTEXT_STRUCT_RE: &[&str] = &[
    "Key", "Cred", "Token", "Secret", "Auth", "Lease", "Issued", "Mint",
];
const SINKS: &str = "tracing:: log:: println! eprintln! print! dbg! panic! info! warn! error! debug! trace! counter! gauge! histogram! metrics_emit journal_append AuditRecord PlaneAuditLog";
const C3_SUBJECTS: &str = "service-account|service account|token response|proxy|password|passphrase|private_key|private key|api_key|api key|client_secret|signing key|signing_key|bearer|credential|credentials|pkcs8|passwd|userinfo|secret";
const C3_DECODERS: &str = "base64:: hex::decode hex::FromHex percent_decode serde_json::from_ serde_yaml::from_ toml::from_ toml::de::";
const C3_SOURCE: &str = "seed pem pkcs8 privkey keypair passphrase jwk";
const C3_IDENTITY: &str = "host hostname port scheme status code len count index idx offset id sub kind class name field addr method verb line column slot alias label at section module server url uri endpoint path location reference pointer selector";
const C3_REDACTORS: &str =
    "redact mask sanitiz fingerprint elide scrub obfusc SecretRef reference() key_id describe()";
const C3_MSG: &str = "format! write! writeln! panic! unreachable! todo! assert! assert_eq! assert_ne! bail! anyhow! println! eprintln! print! .expect(";
const C3_ERRCTX: &str = "Err( map_err ok_or_else ok_or( panic! .expect( bail! anyhow! assert write! writeln! unreachable! todo! println! eprintln! print! tracing:: log:: .context( with_context push(";
const C3_PROXIMITY: usize = 56;

/// One allowlist row: a Check-1 hit is suppressed iff `needle == field name`, the path STARTS WITH
/// `prefix`, and `field` is empty or equals the field name.
#[derive(Debug, Clone, Copy)]
pub struct Allow {
    pub needle: &'static str,
    pub prefix: &'static str,
    pub field: &'static str,
}

const fn allow(needle: &'static str, prefix: &'static str, field: &'static str) -> Allow {
    Allow {
        needle,
        prefix,
        field,
    }
}

/// THE ALLOWLIST (path-scoped, never global). The script's long audit history of each row lives in
/// git (`scripts/secret-hygiene-gate.sh` before its purge). In short: the three documented design
/// exceptions (store-ABI serde egress `CredentialSecret`, the once-shown mint response
/// `CreatedKeyView`, the auth wire boundary) plus the type-name false positives
/// (`IrTokenLogprob.token`, `AuthView.upstream_credentials`). Several rows are vacuous today (kept
/// as written intent); the LIVENESS row only asks that each path exist.
pub const ALLOWLIST_C1: &[Allow] = &[
    allow("secret", "crates/busbar-contract/src/records.rs", "secret"),
    allow(
        "token",
        "crates/busbar-core-admin/src/v1/schema.rs",
        "token",
    ),
    allow(
        "aws_secret_access_key",
        "crates/busbar-core-admin/src/v1/schema.rs",
        "aws_secret_access_key",
    ),
    allow(
        "access_token",
        "crates/busbar-core-admin/src/v1/schema.rs",
        "",
    ),
    allow(
        "secret",
        "crates/busbar-core-admin/src/v1/schema.rs",
        "secret",
    ),
    allow(
        "upstream_credentials",
        "crates/busbar-core-admin/src/v1/contract/mod.rs",
        "upstream_credentials",
    ),
    allow(
        "token",
        "crates/busbar-plane-llm/src/codec/ir/types.rs",
        "token",
    ),
];

/// One CHECK-3 1.5.5-PARITY ROW: a message whose operator-visible text busbar v1.5.5 printed with
/// the SAME detail, kept because customer-visible behaviour stays 1.5.5 (owner-locked), and whose
/// interpolated value is not secret material. Not a pattern: the row names one rule, one file and
/// one parameter, cites the 1.5.5 site it keeps and says why the value is not a secret, and it must
/// suppress EXACTLY ONE live hit — a row that suppresses none (the message moved or is gone) or
/// more than one (a second message joined it unread) is RED in both modes.
#[derive(Debug, Clone, Copy)]
pub struct Parity {
    /// The Check-3 rule the hit is reported under.
    pub rule: &'static str,
    /// The file, exactly as the scan names it (a git-pinned crate under `crates/<package>/`).
    pub path: &'static str,
    /// The interpolated binding the hit names.
    pub param: &'static str,
    /// The v1.5.5 site that printed the same detail.
    pub since: &'static str,
    /// Why the interpolated value is not secret material.
    pub why: &'static str,
}

impl Parity {
    fn matches(&self, h: &Hit) -> bool {
        h.rule == self.rule
            && h.name == self.param
            && h.loc
                .rsplit_once(':')
                .is_some_and(|(file, _)| file == self.path)
    }
    fn key(&self) -> String {
        format!("{}|{}|{}", self.rule, self.path, self.param)
    }
}

/// CHECK 3'S 1.5.5-PARITY ROWS — individually listed and counted, never a pattern (coordinator
/// ruling on #1192). Every other Check-3 finding blocks.
// qa-names: crates/busbar-auth-oidc/src/cache.rs -- xtask/src/gates/secret_hygiene.rs -- a git-pinned plugin file the scan reads from its checkout under the path the crate lived at in this tree (pinned_sources); it is never on disk here, and the parity row's own liveness (exactly one live hit) reds the day the message moves
// qa-names: crates/busbar-secret-env/src/lib.rs -- xtask/src/gates/secret_hygiene.rs -- a git-pinned plugin file the scan reads from its checkout under the path the crate lived at in this tree (pinned_sources); it is never on disk here, and the parity row's own liveness (exactly one live hit) reds the day the message moves
// qa-names: crates/busbar-secret-file/src/lib.rs -- xtask/src/gates/secret_hygiene.rs -- a git-pinned plugin file the scan reads from its checkout under the path the crate lived at in this tree (pinned_sources); it is never on disk here, and the parity row's own liveness (exactly one live hit) reds the day the message moves
pub const PARITY_C3: &[Parity] = &[
    Parity {
        rule: "secret-subject-parameter",
        path: "crates/busbar-auth-oidc/src/cache.rs",
        param: "kid",
        since: "auth-oidc v1.0.6 (shipped with busbar v1.5.5) auth-oidc/src/cache.rs:174",
        why: "a JWKS kid is the public id of a signing key, read from the token header; it is escaped, so a printable kid prints byte-for-byte as in 1.5.5",
    },
    Parity {
        rule: "decoder-error-on-secret-input",
        path: "crates/busbar-secret-env/src/lib.rs",
        param: "e",
        since: "busbar v1.5.5 crates/busbar/src/main.rs:2579",
        why: "the decoded bytes are the secret's SETTINGS (the variable name), never the resolved value",
    },
    Parity {
        rule: "decoder-error-on-secret-input",
        path: "crates/busbar-secret-file/src/lib.rs",
        param: "e",
        since: "busbar v1.5.5 crates/busbar/src/main.rs:2579",
        why: "the decoded bytes are the secret's SETTINGS (the file path), never the file's contents",
    },
];

/// The test-file shape (item 506): `(^|[/_])tests?\.rs$`.
fn is_test_file(rel: &str) -> bool {
    for suffix in ["tests.rs", "test.rs"] {
        if let Some(head) = rel.strip_suffix(suffix) {
            if head.is_empty() || head.ends_with('/') || head.ends_with('_') {
                return true;
            }
        }
    }
    false
}

// ── BYTE HELPERS (1-based, awk-style: out of range reads as 0, the awk empty string) ─────────────

fn at(s: &[u8], i: usize) -> u8 {
    if i >= 1 && i <= s.len() {
        s[i - 1]
    } else {
        0
    }
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// awk `[[:space:]]` in the C locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn trim_b(s: &[u8]) -> &[u8] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && is_space(s[a]) {
        a += 1;
    }
    while b > a && is_space(s[b - 1]) {
        b -= 1;
    }
    &s[a..b]
}

fn count(s: &[u8], ch: u8) -> i64 {
    s.iter().filter(|c| **c == ch).count() as i64
}

/// awk `index(hay, needle)`: 1-based, 0 when absent.
fn index_of(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > hay.len() {
        return 0;
    }
    hay.windows(needle.len())
        .position(|w| w == needle)
        .map_or(0, |p| p + 1)
}

/// awk `index(substr(hay, base + 1), needle)`.
fn index_from(hay: &[u8], base: usize, needle: &[u8]) -> usize {
    if base >= hay.len() {
        return 0;
    }
    index_of(&hay[base..], needle)
}

fn hasany(s: &[u8], list: &[&[u8]]) -> bool {
    list.iter().any(|w| index_of(s, w) > 0)
}

fn words(s: &'static str) -> Vec<&'static [u8]> {
    s.split_whitespace().map(str::as_bytes).collect()
}

/// `fname` carries the needle as an `_`-delimited TAIL behind at least one character of qualifier.
fn qualified(f: &[u8], n: &[u8]) -> bool {
    f.len() > n.len() + 1 && f.ends_with(n) && f[f.len() - n.len() - 1] == b'_'
}

fn tailmatch(f: &[u8], n: &[u8]) -> bool {
    f == n || qualified(f, n)
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// awk records of a file: `\n`-split, no trailing empty record.
fn records(text: &str) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = text.as_bytes().split(|b| *b == b'\n').collect();
    if v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    v
}

/// `(^|[^A-Za-z0-9_])WORD([^A-Za-z0-9_])` — a following character is REQUIRED.
fn word_followed(code: &[u8], w: &str) -> bool {
    let w = w.as_bytes();
    let n = code.len();
    let mut from = 0;
    while let Some(p) = code[from..].windows(w.len()).position(|x| x == w) {
        let at0 = from + p;
        let before_ok = at0 == 0 || !is_ident(code[at0 - 1]);
        let end = at0 + w.len();
        if before_ok && end < n && !is_ident(code[end]) {
            return true;
        }
        from = at0 + 1;
        if from >= n {
            break;
        }
    }
    false
}

/// `code ~ /#\[cfg\(/ && code ~ /(^|[^a-z])test([^a-z]|$)/`.
fn cfg_test_attr(code: &[u8]) -> bool {
    if index_of(code, b"#[cfg(") == 0 {
        return false;
    }
    let n = code.len();
    let mut from = 0;
    while let Some(p) = code[from..].windows(4).position(|x| x == b"test") {
        let a = from + p;
        let before_ok = a == 0 || !code[a - 1].is_ascii_lowercase();
        let after_ok = a + 4 >= n || !code[a + 4].is_ascii_lowercase();
        if before_ok && after_ok {
            return true;
        }
        from = a + 1;
    }
    false
}

/// One hit of any check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Check 1: the field; Check 2: `expose`; Check 3: the rule (`PARSE-WARN` for a lexer
    /// warning).
    pub rule: String,
    /// `file:line`.
    pub loc: String,
    /// Check 3: the rendered name.
    pub name: String,
    pub text: String,
}

// ── CHECK 1 ──────────────────────────────────────────────────────────────────────────────────────

/// Comment stripping that respects string literals; block-comment state carries across lines.
fn strip(line: &[u8], inblk: &mut bool) -> Vec<u8> {
    let mut res = Vec::with_capacity(line.len());
    let n = line.len();
    let mut i = 1;
    let mut instr = false;
    while i <= n {
        let c = at(line, i);
        let c1 = at(line, i + 1);
        if *inblk {
            if c == b'*' && c1 == b'/' {
                *inblk = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if instr {
            res.push(c);
            if c == b'\\' {
                if c1 != 0 {
                    res.push(c1);
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                instr = false;
            }
            i += 1;
            continue;
        }
        if c == b'/' && c1 == b'*' {
            *inblk = true;
            i += 2;
            continue;
        }
        if c == b'/' && c1 == b'/' {
            break;
        }
        if c == b'"' {
            instr = true;
            res.push(c);
            i += 1;
            continue;
        }
        res.push(c);
        i += 1;
    }
    res
}

fn skip_ws(s: &[u8], mut j: usize) -> usize {
    while matches!(at(s, j), b' ' | b'\t') {
        j += 1;
    }
    j
}

/// `ftype ~ /&[ \t]*('[a-z_]+[ \t]+)?str/`.
fn is_ref_str(t: &[u8]) -> bool {
    let blanks = |mut j: usize| {
        while matches!(t.get(j), Some(b' ' | b'\t')) {
            j += 1;
        }
        j
    };
    for (p, c) in t.iter().enumerate() {
        if *c != b'&' {
            continue;
        }
        let j = blanks(p + 1);
        if t[j..].starts_with(b"str") {
            return true;
        }
        if t.get(j) == Some(&b'\'') {
            let mut k = j + 1;
            while t
                .get(k)
                .is_some_and(|c| c.is_ascii_lowercase() || *c == b'_')
            {
                k += 1;
            }
            if k > j + 1
                && matches!(t.get(k), Some(b' ' | b'\t'))
                && t[blanks(k)..].starts_with(b"str")
            {
                return true;
            }
        }
    }
    false
}

/// `ftype ~ /Vec[ \t]*<[ \t]*u8/`.
fn is_vec_u8(t: &[u8]) -> bool {
    let blanks = |mut j: usize| {
        while matches!(t.get(j), Some(b' ' | b'\t')) {
            j += 1;
        }
        j
    };
    let mut from = 0;
    while let Some(p) = t[from..].windows(3).position(|x| x == b"Vec") {
        let a = from + p;
        let j = blanks(a + 3);
        if t.get(j) == Some(&b'<') && t[blanks(j + 1)..].starts_with(b"u8") {
            return true;
        }
        from = a + 1;
    }
    false
}

/// Type names that hold a secret's value as bare text or bytes, whatever wraps them.
const BARE_NAMES: &[&[u8]] = &[b"str", b"Bytes", b"BytesMut"];

/// The wrappers that make a secret-named field safe (Part 2 #54).
const WRAPPERS: &[&[u8]] = &[b"Secret", b"Zeroizing", b"SecretRef"];

/// The identifier tokens of `t`, in order.
fn idents(t: &[u8]) -> Vec<&[u8]> {
    t.split(|c| !is_ident(*c))
        .filter(|w| !w.is_empty())
        .collect()
}

/// A field's TYPE: `t` cut at the first `,` outside every `<>`, `()` and `[]`, so a second field
/// or a trailing attribute on the same line is never read as part of it.
fn field_type(t: &[u8]) -> &[u8] {
    let mut depth: i64 = 0;
    for (i, c) in t.iter().enumerate() {
        match *c {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth -= 1,
            b',' if depth <= 0 => return &t[..i],
            _ => {}
        }
    }
    t
}

/// `[u8; N]`, `[u8]` (behind `&`, `Box`, `Arc`, `Rc`): a byte sequence spelled as a slice or array.
fn is_u8_seq(t: &[u8]) -> bool {
    let blanks = |mut j: usize| {
        while matches!(t.get(j), Some(b' ' | b'\t')) {
            j += 1;
        }
        j
    };
    for (p, c) in t.iter().enumerate() {
        if *c != b'[' {
            continue;
        }
        let j = blanks(p + 1);
        if t[j..].starts_with(b"u8") && matches!(t.get(blanks(j + 2)), Some(b';' | b']')) {
            return true;
        }
    }
    false
}

/// THE BARE ROSTER (Part 2 #53/#54: secret material is `Secret<T>`; no bare string or byte
/// holder survives). A type is bare when it holds the value as text or bytes in ANY of the
/// spellings Rust has for that: `String` (and every type whose name carries it), `str` behind any
/// pointer (`&str`, `Arc<str>`, `Box<str>`, `Rc<str>`, `Cow<str>`), `Vec<u8>`, a `u8` array or
/// slice (`[u8; N]`, `Box<[u8]>`, `&[u8]`), and `Bytes`/`BytesMut`. The roster was String, `&str`
/// and `Vec<u8>` alone (Q128 xtask p2 #4): the other spellings read as typed.
fn is_bare(t: &[u8]) -> bool {
    index_of(t, b"String") > 0
        || is_ref_str(t)
        || is_vec_u8(t)
        || is_u8_seq(t)
        || idents(t).iter().any(|w| BARE_NAMES.contains(w))
}

/// The type is wrapped: one of its type names IS `Secret` (Part 2 #54; was `Redacted<T>`),
/// `Zeroizing` or `SecretRef`, as a whole name. A longer name that merely contains one
/// (`NotASecretString`) is not a wrapper (Q128 xtask p2 #4: this was a substring test).
fn is_wrapped(t: &[u8]) -> bool {
    idents(t).iter().any(|w| WRAPPERS.contains(w))
}

/// The identifier after the LAST `kw` followed by blanks on `code`, the awk
/// `sub(/.*kw[ \t]+/, "", sn)` then the leading identifier.
fn decl_name(code: &[u8], kw: &[u8]) -> Vec<u8> {
    let mut sn: &[u8] = code;
    let mut last = None;
    let mut from = 0;
    while let Some(p) = code[from..].windows(kw.len()).position(|x| x == kw) {
        let a = from + p;
        if matches!(at(code, a + kw.len() + 1), b' ' | b'\t') {
            last = Some(a + kw.len());
        }
        from = a + 1;
    }
    if let Some(e) = last {
        sn = &code[skip_ws(code, e + 1) - 1..];
    }
    sn.iter().copied().take_while(|c| is_ident(*c)).collect()
}

/// What a brace frame was opened by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// A `struct` body, or an enum's struct-variant body: its lines are FIELDS.
    Fields,
    /// An `enum` body: its lines are variants, and a variant that opens a brace opens a
    /// [`Frame::Fields`] (Q128 xtask p2 #4: an enum's struct-variant fields went unread).
    Enum,
    Other,
}

struct FieldScan<'a> {
    strong: Vec<&'static [u8]>,
    context: Vec<&'static [u8]>,
    allow: &'a [Allow],
    pendtest: bool,
    pend_sn: Vec<u8>,
}

impl FieldScan<'_> {
    fn allowlisted(&self, file: &str, fname: &[u8]) -> bool {
        self.allow.iter().any(|a| {
            a.needle.as_bytes() == fname
                && file.starts_with(a.prefix)
                && (a.field.is_empty() || a.field.as_bytes() == fname)
        })
    }

    fn file(&mut self, name: &str, text: &str, out: &mut Vec<Hit>) {
        let mut inblk = false;
        // Each frame: what opened it, and the declaring name (a struct's, or an enum's name joined
        // with the variant's) that the context needles are judged against.
        let mut stack: Vec<Option<Vec<u8>>> = Vec::new();
        let mut kinds: Vec<Frame> = Vec::new();
        let mut testmod = false;
        let mut tdepth: i64 = 0;
        for (idx, raw) in records(text).into_iter().enumerate() {
            let fnr = idx + 1;
            let code = strip(raw, &mut inblk);
            let no = count(&code, b'{');
            let ncl = count(&code, b'}');
            if testmod {
                tdepth += no - ncl;
                if tdepth <= 0 {
                    testmod = false;
                    tdepth = 0;
                }
                continue;
            }
            if cfg_test_attr(&code) {
                self.pendtest = true;
            } else if self.pendtest && word_followed(&code, "mod") {
                self.pendtest = false;
                if no > 0 {
                    testmod = true;
                    tdepth = no - ncl;
                }
                continue;
            } else if code.iter().any(|c| !is_space(*c)) && index_of(&code, b"#[") == 0 {
                self.pendtest = false;
            }

            let depth = stack.len();
            let opens = if word_followed(&code, "struct") {
                self.pend_sn = decl_name(&code, b"struct");
                Frame::Fields
            } else if word_followed(&code, "enum") {
                self.pend_sn = decl_name(&code, b"enum");
                Frame::Enum
            } else if depth >= 1 && kinds[depth - 1] == Frame::Enum {
                // A struct variant `Bearer {`: its body is a field frame named for the enum AND
                // the variant, so `enum Cred { Bearer { token: .. } }` reads as a *Cred* frame.
                let variant: Vec<u8> = trim_b(&code)
                    .iter()
                    .copied()
                    .take_while(|c| is_ident(*c))
                    .collect();
                let mut sn = stack[depth - 1].clone().unwrap_or_default();
                sn.extend_from_slice(&variant);
                self.pend_sn = sn;
                Frame::Fields
            } else {
                Frame::Other
            };
            if depth >= 1 && kinds[depth - 1] == Frame::Fields {
                let mut line: &[u8] = &code;
                while !line.is_empty() && matches!(line[0], b' ' | b'\t') {
                    line = &line[1..];
                }
                if line.starts_with(b"pub") {
                    let j = skip_ws(line, 4);
                    if at(line, j) == b'(' {
                        if let Some(c) = line[j..].iter().position(|c| *c == b')') {
                            line = &line[skip_ws(line, j + c + 2) - 1..];
                        }
                    }
                }
                if line.starts_with(b"pub") && matches!(at(line, 4), b' ' | b'\t') {
                    line = &line[skip_ws(line, 4) - 1..];
                }
                if matches!(at(line, 1), b'A'..=b'Z' | b'a'..=b'z' | b'_') {
                    let mut e = 1;
                    while is_ident(at(line, e + 1)) {
                        e += 1;
                    }
                    let fname = &line[..e];
                    let k = skip_ws(line, e + 1);
                    if at(line, k) == b':' {
                        // The bare test reads the rest of the line, as it always has; the
                        // wrapper must be in the field's OWN type, so a wrapper named by a second
                        // field on the line does not cover this one.
                        let ftype = &line[skip_ws(line, k + 1) - 1..];
                        let mut needle = self.strong.iter().any(|s| tailmatch(fname, s));
                        if !needle {
                            needle = self.context.iter().any(|c| qualified(fname, c));
                        }
                        if !needle && self.context.contains(&fname) {
                            let sname = stack[depth - 1].clone().unwrap_or_default();
                            needle = CONTEXT_STRUCT_RE
                                .iter()
                                .any(|r| index_of(&sname, r.as_bytes()) > 0);
                        }
                        if needle
                            && is_bare(ftype)
                            && !is_wrapped(field_type(ftype))
                            && !self.allowlisted(name, fname)
                        {
                            out.push(Hit {
                                rule: lossy(fname),
                                loc: format!("{name}:{fnr}"),
                                name: String::new(),
                                text: lossy(trim_b(&code)),
                            });
                        }
                    }
                }
            }
            let net = no - ncl;
            if net > 0 {
                for _ in 0..net {
                    stack.push(if opens == Frame::Other {
                        None
                    } else {
                        Some(self.pend_sn.clone())
                    });
                    kinds.push(opens);
                }
            } else if net < 0 {
                for _ in 0..-net {
                    if !stack.is_empty() {
                        stack.pop();
                        kinds.pop();
                    }
                }
            }
        }
    }
}

/// CHECK 1 over `(path, text)` files.
pub fn scan_fields(files: &[(String, String)], allow: &[Allow]) -> Vec<Hit> {
    let mut fs = FieldScan {
        strong: words(STRONG_NEEDLES),
        context: words(CONTEXT_NEEDLES),
        allow,
        pendtest: false,
        pend_sn: Vec::new(),
    };
    let mut out = Vec::new();
    for (n, t) in files {
        fs.file(n, t, &mut out);
    }
    out
}

// ── CHECK 2 ──────────────────────────────────────────────────────────────────────────────────────

/// CHECK 2 over `(path, text)` files: `.expose(` (the sealed accessor, Part 2 #54) and a sink on
/// one STATEMENT.
pub fn scan_sinks(files: &[(String, String)]) -> Vec<Hit> {
    let sinks = words(SINKS);
    let mut out = Vec::new();
    let mut stmt: Vec<u8> = Vec::new();
    let mut stmtline = 0usize;
    let mut stmtfile = String::new();
    let mut pdepth: i64 = 0;
    let flush = |stmt: &mut Vec<u8>,
                 stmtline: &mut usize,
                 stmtfile: &mut String,
                 pdepth: &mut i64,
                 out: &mut Vec<Hit>| {
        if !stmt.is_empty()
            && index_of(stmt, b".expose(") > 0
            && sinks.iter().any(|s| index_of(stmt, s) > 0)
        {
            out.push(Hit {
                rule: "expose".into(),
                loc: format!("{stmtfile}:{stmtline}"),
                name: String::new(),
                text: lossy(stmt),
            });
        }
        stmt.clear();
        *stmtline = 0;
        stmtfile.clear();
        *pdepth = 0;
    };
    for (name, text) in files {
        let recs = records(text);
        if recs.is_empty() {
            continue;
        }
        flush(
            &mut stmt,
            &mut stmtline,
            &mut stmtfile,
            &mut pdepth,
            &mut out,
        );
        let mut inblk = false;
        for (idx, raw) in recs.into_iter().enumerate() {
            let fnr = idx + 1;
            let stripped = strip(raw, &mut inblk);
            let code = trim_b(&stripped);
            if code.is_empty() {
                continue;
            }
            if stmt.is_empty() {
                stmt = code.to_vec();
                stmtline = fnr;
                stmtfile = name.clone();
            } else {
                stmt.push(b' ');
                stmt.extend_from_slice(code);
            }
            pdepth += count(code, b'(') - count(code, b')');
            if pdepth < 0 {
                pdepth = 0;
            }
            let last = code[code.len() - 1];
            if pdepth == 0 && matches!(last, b';' | b'{' | b'}' | b',') {
                flush(
                    &mut stmt,
                    &mut stmtline,
                    &mut stmtfile,
                    &mut pdepth,
                    &mut out,
                );
            }
        }
    }
    flush(
        &mut stmt,
        &mut stmtline,
        &mut stmtfile,
        &mut pdepth,
        &mut out,
    );
    out
}

// ── CHECK 3 ──────────────────────────────────────────────────────────────────────────────────────

struct Cap {
    cap: Vec<u8>,
    base: Vec<u8>,
    pos: usize,
    text: Vec<u8>,
}

struct Cfg {
    strong: Vec<&'static [u8]>,
    context: Vec<&'static [u8]>,
    subjects: Vec<&'static [u8]>,
    decoders: Vec<&'static [u8]>,
    source: Vec<&'static [u8]>,
    identity: Vec<&'static [u8]>,
    redactors: Vec<&'static [u8]>,
    msgs: Vec<&'static [u8]>,
    errctx: Vec<&'static [u8]>,
}

impl Cfg {
    fn new() -> Cfg {
        Cfg {
            strong: words(STRONG_NEEDLES),
            context: words(CONTEXT_NEEDLES),
            subjects: C3_SUBJECTS.split('|').map(str::as_bytes).collect(),
            decoders: words(C3_DECODERS),
            source: words(C3_SOURCE),
            identity: words(C3_IDENTITY),
            redactors: words(C3_REDACTORS),
            msgs: words(C3_MSG),
            errctx: words(C3_ERRCTX),
        }
    }
}

struct Msgs<'c> {
    cfg: &'c Cfg,
    out: Vec<Hit>,
    stmt: Vec<u8>,
    sbl: Vec<u8>,
    stmtline: usize,
    stmtfile: String,
    pdepth: i64,
    inblk: bool,
    instr: bool,
    inraw: bool,
    rawh: usize,
    depth: i64,
    errdepth: i64,
    param: HashSet<Vec<u8>>,
    redacted: HashSet<Vec<u8>>,
    insig: bool,
    sigbl: Vec<u8>,
    sigdepth: i64,
    testmod: bool,
    tdepth: i64,
    pendtest: bool,
    prevfile: Option<String>,
}

fn substr(s: &[u8], start: usize, len: usize) -> &[u8] {
    if start < 1 || start > s.len() {
        return &[];
    }
    let e = (start - 1 + len).min(s.len());
    &s[start - 1..e]
}

fn ident_at(s: &[u8], mut j: usize) -> (Vec<u8>, usize) {
    let mut id = Vec::new();
    while j <= s.len() && is_ident(at(s, j)) {
        id.push(at(s, j));
        j += 1;
    }
    (id, j)
}

/// The closing `)` index of the call opened at `o` (1-based), or `n + 1` when never closed.
fn close_paren(bl: &[u8], o: usize) -> usize {
    let n = bl.len();
    let mut d = 0;
    let mut j = o;
    while j <= n {
        if at(bl, j) == b'(' {
            d += 1;
        } else if at(bl, j) == b')' {
            d -= 1;
            if d == 0 {
                break;
            }
        }
        j += 1;
    }
    j
}

impl Msgs<'_> {
    fn reset_stmt(&mut self) {
        self.stmt.clear();
        self.sbl.clear();
        self.stmtline = 0;
        self.pdepth = 0;
    }

    /// The lexer: `(scode, sblank)` — code with string contents kept, and code with every literal
    /// and comment blanked. Raw and byte-raw strings included.
    fn lex(&mut self, line: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let n = line.len();
        let mut sc: Vec<u8> = Vec::new();
        let mut sb: Vec<u8> = Vec::new();
        let mut i = 1;
        while i <= n {
            let c = at(line, i);
            let c1 = at(line, i + 1);
            if self.inblk {
                if c == b'*' && c1 == b'/' {
                    self.inblk = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if self.inraw {
                while i <= n {
                    if at(line, i) == b'"' {
                        let ok = (1..=self.rawh).all(|k| at(line, i + k) == b'#');
                        if ok {
                            sc.push(b'"');
                            sb.push(b' ');
                            for _ in 0..self.rawh {
                                sc.push(b' ');
                                sb.push(b' ');
                            }
                            i += 1 + self.rawh;
                            self.inraw = false;
                            break;
                        }
                    }
                    let ch = at(line, i);
                    sc.push(if matches!(ch, b'"' | b'\\' | b'{' | b'}') {
                        b' '
                    } else {
                        ch
                    });
                    sb.push(b' ');
                    i += 1;
                }
                continue;
            }
            if self.instr {
                if c == b'\\' {
                    sc.extend_from_slice(b"  ");
                    sb.extend_from_slice(b"  ");
                    i += 2;
                    continue;
                }
                sc.push(c);
                sb.push(b' ');
                if c == b'"' {
                    self.instr = false;
                }
                i += 1;
                continue;
            }
            if c == b'/' && c1 == b'*' {
                self.inblk = true;
                i += 2;
                continue;
            }
            if c == b'/' && c1 == b'/' {
                break;
            }
            let isb = c == b'b' && c1 == b'r';
            if c == b'r' || isb {
                let mut j = i + 1 + usize::from(isb);
                self.rawh = 0;
                while at(line, j) == b'#' {
                    self.rawh += 1;
                    j += 1;
                }
                if at(line, j) == b'"' {
                    let p = if i > 1 { at(line, i - 1) } else { b' ' };
                    if !is_ident(p) {
                        self.inraw = true;
                        for _ in i..j {
                            sc.push(b' ');
                            sb.push(b' ');
                        }
                        sc.push(b'"');
                        sb.push(b' ');
                        i = j + 1;
                        continue;
                    }
                }
            }
            if c == b'\'' {
                if c1 == b'\\' && at(line, i + 3) == b'\'' {
                    sc.extend_from_slice(b"    ");
                    sb.extend_from_slice(b"    ");
                    i += 4;
                    continue;
                }
                if at(line, i + 2) == b'\'' {
                    sc.extend_from_slice(b"   ");
                    sb.extend_from_slice(b"   ");
                    i += 3;
                    continue;
                }
            }
            if c == b'"' {
                self.instr = true;
                sc.push(c);
                sb.push(b' ');
                i += 1;
                continue;
            }
            sc.push(c);
            sb.push(c);
            i += 1;
        }
        (sc, sb)
    }

    /// Every `{IDENT}`/`{IDENT:spec}` inline capture and every positional `, PATH` argument after
    /// `from`.
    fn captures(&self, s: &[u8], bl: &[u8], from: usize) -> Vec<Cap> {
        let mut caps = Vec::new();
        let n = s.len();
        let mut i = from;
        while i <= n {
            let c = at(s, i);
            if at(bl, i) == b' ' && c != b' ' {
                if c == b'{' {
                    if at(s, i + 1) == b'{' {
                        i += 2;
                        continue;
                    }
                    let (id, j) = ident_at(s, i + 1);
                    let ch = at(s, j);
                    if !id.is_empty() && !id[0].is_ascii_digit() && (ch == b'}' || ch == b':') {
                        caps.push(Cap {
                            cap: id.clone(),
                            base: id.clone(),
                            pos: i,
                            text: id,
                        });
                    }
                    i = j;
                    continue;
                }
                i += 1;
                continue;
            }
            if c == b',' {
                let start = i;
                let mut j = i + 1;
                while at(s, j) == b' ' {
                    j += 1;
                }
                while matches!(at(s, j), b'&' | b'*' | b'%' | b'?') {
                    j += 1;
                    while at(s, j) == b' ' {
                        j += 1;
                    }
                }
                let mut segs: Vec<Vec<u8>> = Vec::new();
                let mut base: Vec<u8> = Vec::new();
                loop {
                    let (id, nj) = ident_at(s, j);
                    j = nj;
                    if id.is_empty() {
                        break;
                    }
                    if substr(s, j, 2) == b"()" {
                        j += 2;
                        if at(s, j) == b'.' {
                            j += 1;
                            continue;
                        }
                        break;
                    }
                    if base.is_empty() {
                        base = id.clone();
                    }
                    segs.push(id);
                    if at(s, j) == b'.' {
                        j += 1;
                        continue;
                    }
                    break;
                }
                let ch = at(s, j);
                if !segs.is_empty()
                    && !segs[0][0].is_ascii_digit()
                    && matches!(ch, b',' | b')' | 0 | b' ' | b'?')
                {
                    caps.push(Cap {
                        cap: segs[segs.len() - 1].clone(),
                        base,
                        pos: start,
                        text: substr(s, start + 1, j - start - 1).to_vec(),
                    });
                }
                i += 1;
                continue;
            }
            i += 1;
        }
        caps
    }

    /// Lowercased literal text with code positions blanked, index-aligned to `s`.
    fn litmap(s: &[u8], bl: &[u8]) -> Vec<u8> {
        (1..=s.len())
            .map(|i| {
                let c = at(s, i);
                if at(bl, i) == b' ' && c != b'"' && c != b' ' {
                    c.to_ascii_lowercase()
                } else {
                    b' '
                }
            })
            .collect()
    }

    /// A subject word within `C3_PROXIMITY` characters of `pos`, on WORD BOUNDARIES.
    fn subjectnear(&self, lm: &[u8], pos: usize) -> bool {
        let lo = pos.saturating_sub(C3_PROXIMITY).max(1);
        let hi = (pos + C3_PROXIMITY).min(lm.len());
        if hi < lo {
            return false;
        }
        let seg = substr(lm, lo, hi - lo + 1);
        let word_c = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_';
        for w in &self.cfg.subjects {
            let mut base = 0;
            loop {
                let r = index_from(seg, base, w);
                if r == 0 {
                    break;
                }
                let q = base + r;
                let before = if q == 1 { b' ' } else { at(seg, q - 1) };
                let after = at(seg, q + w.len());
                if !word_c(before) && !word_c(after) {
                    return true;
                }
                base = q;
            }
        }
        false
    }

    fn firstmsg(&self, s: &[u8]) -> usize {
        let mut best = 0;
        for w in &self.cfg.msgs {
            let p = index_of(s, w);
            if p > 0 && (best == 0 || p < best) {
                best = p;
            }
        }
        best
    }

    /// The msg-macro call that lexically contains `pos`: its opening `(`.
    fn enclosingmacro(&self, bl: &[u8], pos: usize) -> usize {
        let n = bl.len();
        let mut best = 0;
        for w in &self.cfg.msgs {
            let mut base = 0;
            loop {
                let r = index_from(bl, base, w);
                if r == 0 {
                    break;
                }
                let p = base + r;
                base = p;
                let mut o = p + w.len() - 1;
                while o <= n && at(bl, o) != b'(' {
                    o += 1;
                }
                if o > n {
                    break;
                }
                let j = close_paren(bl, o);
                if o <= pos && pos <= j && o > best {
                    best = o;
                }
            }
        }
        best
    }

    /// An err/diagnostic call that is still OPEN at `mo`.
    fn errencloses(&self, bl: &[u8], mo: usize) -> bool {
        let n = bl.len();
        for w in &self.cfg.errctx {
            let mut base = 0;
            loop {
                let r = index_from(bl, base, w);
                if r == 0 {
                    break;
                }
                let p = base + r;
                base = p;
                let mut o = p + w.len() - 1;
                while o <= n && at(bl, o) != b'(' {
                    o += 1;
                }
                if o > n {
                    break;
                }
                if o > mo {
                    continue;
                }
                let j = close_paren(bl, o);
                if o <= mo && mo <= j {
                    return true;
                }
            }
        }
        false
    }

    /// The first identifier path handed to each decoder call.
    fn decodersource(&self, bl: &[u8]) -> Vec<u8> {
        let n = bl.len();
        let mut res = Vec::new();
        for d in &self.cfg.decoders {
            let p = index_of(bl, d);
            if p == 0 {
                continue;
            }
            let mut o = p + d.len() - 1;
            while o <= n && at(bl, o) != b'(' {
                o += 1;
            }
            let mut j = o + 1;
            while matches!(at(bl, j), b' ' | b'&' | b'*') {
                j += 1;
            }
            let mut id = Vec::new();
            while j <= n {
                let ch = at(bl, j);
                if is_ident(ch) || ch == b':' || ch == b'.' {
                    id.push(ch);
                    j += 1;
                } else {
                    break;
                }
            }
            if !id.is_empty() {
                res.push(b' ');
                res.extend_from_slice(&id);
            }
        }
        res
    }

    /// EVERY segment of the decoded path, not just the last.
    fn secretsource(&self, src: &[u8]) -> bool {
        for tok in src.split(|c| *c == b' ') {
            for seg in tok.split(|c| *c == b'.' || *c == b':') {
                if seg.is_empty() {
                    continue;
                }
                if self.cfg.strong.iter().any(|s| tailmatch(seg, s))
                    || self.cfg.source.iter().any(|s| tailmatch(seg, s))
                {
                    return true;
                }
            }
        }
        false
    }

    fn closureparams(bl: &[u8]) -> Vec<Vec<u8>> {
        let n = bl.len();
        let mut out = Vec::new();
        let mut i = 1;
        while i <= n {
            if at(bl, i) == b'|' {
                let mut j = i + 1;
                while at(bl, j) == b' ' {
                    j += 1;
                }
                if substr(bl, j, 4) == b"mut " {
                    j += 4;
                    while at(bl, j) == b' ' {
                        j += 1;
                    }
                }
                let (id, nj) = ident_at(bl, j);
                j = nj;
                while at(bl, j) == b' ' {
                    j += 1;
                }
                let ch = at(bl, j);
                if !id.is_empty() && matches!(ch, b'|' | b':' | b',') {
                    out.push(id);
                }
                i = j;
                continue;
            }
            i += 1;
        }
        out
    }

    fn parseparams(&mut self, bl: &[u8]) {
        let n = bl.len();
        let mut i = 0;
        if n >= 3 {
            for j in 1..=n - 2 {
                if substr(bl, j, 3) == b"fn " && (j == 1 || !is_ident(at(bl, j - 1))) {
                    let mut bi = j + 3;
                    while at(bl, bi) == b' ' {
                        bi += 1;
                    }
                    while is_ident(at(bl, bi)) {
                        bi += 1;
                    }
                    if at(bl, bi) == b'<' {
                        let mut d = 0;
                        while bi <= n {
                            let c = at(bl, bi);
                            if c == b'<' {
                                d += 1;
                            } else if c == b'>' {
                                d -= 1;
                                if d == 0 {
                                    bi += 1;
                                    break;
                                }
                            }
                            bi += 1;
                        }
                    }
                    if at(bl, bi) == b'(' {
                        i = bi;
                        break;
                    }
                }
            }
        }
        if i == 0 {
            return;
        }
        let mut d = 0;
        let mut inner: Vec<u8> = Vec::new();
        for j in i..=n {
            let c = at(bl, j);
            if c == b'(' {
                d += 1;
                if d == 1 {
                    continue;
                }
            }
            if c == b')' {
                d -= 1;
                if d == 0 {
                    break;
                }
            }
            if d >= 1 {
                inner.push(c);
            }
        }
        let n = inner.len();
        let mut j = 1;
        let mut d = 0;
        while j <= n {
            let c = at(&inner, j);
            if matches!(c, b'<' | b'(' | b'[') {
                d += 1;
                j += 1;
                continue;
            }
            if matches!(c, b'>' | b')' | b']') {
                d -= 1;
                j += 1;
                continue;
            }
            if d == 0 && (c.is_ascii_alphabetic() || c == b'_') {
                let (id, nj) = ident_at(&inner, j);
                j = nj;
                while at(&inner, j) == b' ' {
                    j += 1;
                }
                if at(&inner, j) == b':' && id != b"mut" && id != b"self" {
                    self.param.insert(id);
                }
                continue;
            }
            j += 1;
        }
    }

    fn flush(&mut self) {
        if self.stmt.is_empty() {
            self.reset_stmt();
            return;
        }
        let stmt = std::mem::take(&mut self.stmt);
        let sbl = std::mem::take(&mut self.sbl);
        let mpos = self.firstmsg(&stmt);
        if mpos == 0 {
            self.reset_stmt();
            return;
        }
        let caps = self.captures(&stmt, &sbl, mpos);
        if caps.is_empty() {
            self.reset_stmt();
            return;
        }
        let lm = Self::litmap(&stmt, &sbl);
        let isdec = hasany(&stmt, &self.cfg.decoders);
        let decsecret = if isdec {
            let src = self.decodersource(&sbl);
            self.secretsource(&src)
        } else {
            false
        };
        let clp = Self::closureparams(&sbl);
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for cp in &caps {
            let name = &cp.cap;
            let bs = &cp.base;
            if !seen.insert(name.clone()) {
                continue;
            }
            if self.redacted.contains(name) || self.redacted.contains(bs) {
                continue;
            }
            // isupperconst
            if name.first().is_some_and(u8::is_ascii_uppercase)
                && !name.iter().any(u8::is_ascii_lowercase)
            {
                continue;
            }
            if self.cfg.redactors.iter().any(|r| index_of(&cp.text, r) > 0) {
                continue;
            }
            let mo = self.enclosingmacro(&sbl, cp.pos);
            if mo == 0 {
                continue;
            }
            if !self.errencloses(&sbl, mo) && self.errdepth < 0 {
                continue;
            }
            let mut hit = "";
            if self.cfg.strong.iter().any(|s| tailmatch(name, s)) {
                hit = "secret-named-binding";
            }
            if hit.is_empty() && self.cfg.context.iter().any(|c| qualified(name, c)) {
                hit = "secret-named-binding";
            }
            if hit.is_empty() && self.cfg.identity.iter().any(|x| tailmatch(name, x)) {
                continue;
            }
            if hit.is_empty()
                && isdec
                && clp.contains(name)
                && (decsecret || self.subjectnear(&lm, cp.pos))
            {
                hit = "decoder-error-on-secret-input";
            }
            if hit.is_empty() && self.param.contains(bs) && self.subjectnear(&lm, cp.pos) {
                hit = "secret-subject-parameter";
            }
            if !hit.is_empty() {
                let t = trim_b(&stmt);
                self.out.push(Hit {
                    rule: hit.to_string(),
                    loc: format!("{}:{}", self.stmtfile, self.stmtline),
                    name: lossy(name),
                    text: lossy(&t[..t.len().min(200)]),
                });
            }
        }
        self.reset_stmt();
    }

    fn lexer_open(&self) -> bool {
        self.instr || self.inraw || self.inblk
    }

    fn newfile(&mut self, f: &str) {
        if let Some(prev) = self.prevfile.clone() {
            if self.lexer_open() {
                self.out.push(Hit {
                    rule: "PARSE-WARN".into(),
                    loc: format!("{prev}:0"),
                    name: "lexer-unterminated".into(),
                    text: "string/raw/comment still open at EOF — findings for this file are NOT trustworthy".into(),
                });
            }
        }
        self.prevfile = Some(f.to_string());
        self.reset_stmt();
        self.inblk = false;
        self.instr = false;
        self.inraw = false;
        self.depth = 0;
        self.errdepth = -1;
        self.param.clear();
        self.redacted.clear();
        self.insig = false;
        self.sigbl.clear();
        self.sigdepth = 0;
        self.testmod = false;
        self.tdepth = 0;
        self.pendtest = false;
    }

    fn line(&mut self, raw: &[u8], fnr: usize, file: &str) {
        let (code, bcode) = self.lex(raw);
        let no = count(&bcode, b'{');
        let ncl = count(&bcode, b'}');
        let op = count(&bcode, b'(');
        let cp2 = count(&bcode, b')');
        if self.testmod {
            self.tdepth += no - ncl;
            if self.tdepth <= 0 {
                self.testmod = false;
                self.tdepth = 0;
            }
            return;
        }
        if cfg_test_attr(&code) {
            self.pendtest = true;
        } else if self.pendtest && word_followed(&code, "mod") {
            self.pendtest = false;
            if no > 0 {
                self.testmod = true;
                self.tdepth = no - ncl;
            }
            return;
        } else if code.iter().any(|c| !is_space(*c)) && index_of(&code, b"#[") == 0 {
            self.pendtest = false;
        }

        let tc = trim_b(&code);
        // awk: tbl = substr(bcode, length(code) - length(tc) + 1) — the trimmed width is taken as
        // all-leading, so a line with trailing blanks shifts its blanked twin. Reproduced.
        let tbl = substr(&bcode, code.len() - tc.len() + 1, usize::MAX / 2);
        let tbl = tbl.to_vec();
        if tc.is_empty() {
            return;
        }

        if !self.insig && has_fn_sig(&bcode) {
            self.param.clear();
            self.redacted.clear();
            self.insig = true;
            self.sigbl.clear();
            self.sigdepth = 0;
        }
        if self.insig {
            self.sigbl.push(b' ');
            self.sigbl.extend_from_slice(&bcode);
            self.sigdepth += op - cp2;
            if self.sigdepth <= 0 && index_of(&self.sigbl, b"(") > 0 {
                let sbl = std::mem::take(&mut self.sigbl);
                self.parseparams(&sbl);
                self.insig = false;
            }
        }
        if let Some(nm) = let_binding(&bcode) {
            if !nm.is_empty() && self.cfg.redactors.iter().any(|r| index_of(&code, r) > 0) {
                self.redacted.insert(nm);
            }
        }

        if self.stmt.is_empty() {
            self.stmt = tc.to_vec();
            self.sbl = tbl;
            self.stmtline = fnr;
            self.stmtfile = file.to_string();
        } else {
            self.stmt.push(b' ');
            self.stmt.extend_from_slice(tc);
            self.sbl.push(b' ');
            self.sbl.extend_from_slice(&tbl);
        }
        self.pdepth += op - cp2;
        if self.pdepth < 0 {
            self.pdepth = 0;
        }
        let last = tc[tc.len() - 1];
        let willopen = no > ncl;
        if self.pdepth == 0 && matches!(last, b';' | b'{' | b'}' | b',') {
            let pend_err = hasany(&self.stmt, &self.cfg.errctx) && willopen;
            self.flush();
            if pend_err && self.errdepth < 0 {
                self.errdepth = self.depth;
            }
        }
        self.depth += no - ncl;
        if self.errdepth >= 0 && self.depth <= self.errdepth {
            self.errdepth = -1;
        }
    }
}

/// `bcode ~ /(^|[^A-Za-z0-9_])fn[ \t]+[A-Za-z_]/`.
fn has_fn_sig(b: &[u8]) -> bool {
    let n = b.len();
    let mut from = 0;
    while let Some(p) = b[from..].windows(2).position(|x| x == b"fn") {
        let a = from + p;
        if a == 0 || !is_ident(b[a - 1]) {
            let j = skip_ws(b, a + 3);
            if a + 2 < n && matches!(b[a + 2], b' ' | b'\t') {
                let c = at(b, j);
                if c.is_ascii_alphabetic() || c == b'_' {
                    return true;
                }
            }
        }
        from = a + 1;
    }
    false
}

/// The name bound by the LAST `let` on the line, per the script's two `sub`s.
fn let_binding(b: &[u8]) -> Option<Vec<u8>> {
    // bcode ~ /(^|[^A-Za-z0-9_])let[ \t]+/
    let n = b.len();
    let blank = |a: usize| matches!(at(b, a), b' ' | b'\t');
    let mut any = false;
    let mut last: Option<usize> = None; // 0-based index of the `l` of the last `.*[^id]let[ \t]+`
    let mut from = 0;
    while let Some(p) = b[from..].windows(3).position(|x| x == b"let") {
        let a = from + p;
        if blank(a + 4) {
            if a == 0 || !is_ident(b[a - 1]) {
                any = true;
            }
            if a >= 1 && !is_ident(b[a - 1]) {
                last = Some(a);
            }
        }
        from = a + 1;
        if from >= n {
            break;
        }
    }
    if !any {
        return None;
    }
    let mut lv: &[u8] = b;
    if let Some(a) = last {
        lv = &b[skip_ws(b, a + 4) - 1..];
    }
    if lv.starts_with(b"let") && matches!(at(lv, 4), b' ' | b'\t') {
        lv = &lv[skip_ws(lv, 4) - 1..];
    }
    if lv.starts_with(b"mut") && matches!(at(lv, 4), b' ' | b'\t') {
        lv = &lv[skip_ws(lv, 4) - 1..];
    }
    Some(lv.iter().copied().take_while(|c| is_ident(*c)).collect())
}

/// CHECK 3 over `(path, text)` files. `PARSE-WARN` hits are returned in the same list.
pub fn scan_msgs(files: &[(String, String)]) -> Vec<Hit> {
    let cfg = Cfg::new();
    let mut m = Msgs {
        cfg: &cfg,
        out: Vec::new(),
        stmt: Vec::new(),
        sbl: Vec::new(),
        stmtline: 0,
        stmtfile: String::new(),
        pdepth: 0,
        inblk: false,
        instr: false,
        inraw: false,
        rawh: 0,
        depth: 0,
        errdepth: -1,
        param: HashSet::new(),
        redacted: HashSet::new(),
        insig: false,
        sigbl: Vec::new(),
        sigdepth: 0,
        testmod: false,
        tdepth: 0,
        pendtest: false,
        prevfile: None,
    };
    for (name, text) in files {
        let recs = records(text);
        if recs.is_empty() {
            continue;
        }
        m.newfile(name);
        for (idx, raw) in recs.into_iter().enumerate() {
            m.line(raw, idx + 1, name);
        }
    }
    m.flush();
    if let Some(prev) = m.prevfile.clone() {
        if m.lexer_open() {
            m.out.push(Hit {
                rule: "PARSE-WARN".into(),
                loc: format!("{prev}:0"),
                name: "lexer-unterminated".into(),
                text: "string/raw/comment still open at EOF".into(),
            });
        }
    }
    m.out
}

// ── THE GIT-PINNED PLUGIN SOURCES ──────────────────────────────────────────────────────────────────

/// The pinned plugin crates the scan reads from their checkouts, and their production `.rs`.
pub struct PinnedSources {
    /// `<package> (<source>)`, one per crate read here.
    pub packages: Vec<String>,
    /// `(crates/<package>/<path in the crate>, text)`: the path the crate lived at in this tree.
    pub files: Vec<(String, String)>,
}

type PinnedResult = Arc<Result<PinnedSources, String>>;

static PINNED_MEMO: OnceLock<Mutex<BTreeMap<String, PinnedResult>>> = OnceLock::new();

/// THE GIT-PINNED PLUGIN SOURCES THAT SHIP IN THE BINARY (Part 2 #53: "a bare/unwrapped secret
/// fails the ship gate"; Law 8: the scan's denominator is the code that ships, not the code that
/// happens to sit under `crates/`).
///
/// DERIVED, NOT LISTED: every `git+` package named `busbar-*` that `cargo metadata --all-features`
/// resolves over the root manifest, read from the checkout cargo fetched for the pinned rev. A
/// crate this context already shows at `crates/<package>` (on disk, or laid by the base layer — the
/// plane and transport pins) is read by the walk and skipped here; every other one (auth, secret,
/// export, store, hook, and every `-plugin` twin) is read here, under the path it lived at.
///
/// FAILS CLOSED: `cargo metadata` that does not answer, or a pinned crate that reads no production
/// `.rs`, is an `Err` naming it — never a smaller scan. Memoised per root and planted answer.
pub fn pinned_sources(cx: &Ctx) -> PinnedResult {
    let key = format!(
        "{}\u{0}{}",
        cx.root().display(),
        cx.overlay_command("cargo-metadata:Cargo.toml")
            .unwrap_or_default()
    );
    let memo = PINNED_MEMO.get_or_init(Default::default);
    if let Some(hit) = memo.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Arc::clone(hit);
    }
    let built = Arc::new(read_pinned(cx));
    memo.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, Arc::clone(&built));
    built
}

fn read_pinned(cx: &Ctx) -> Result<PinnedSources, String> {
    let meta = cx.cargo_metadata_all_features("Cargo.toml").map_err(|e| {
        format!(
            "the git-pinned plugin sources cannot be listed: cargo metadata does not answer ({e})"
        )
    })?;
    let meta: serde_json::Value = serde_json::from_str(&meta).map_err(|e| {
        format!("the git-pinned plugin sources cannot be listed: cargo metadata is not JSON ({e})")
    })?;
    let mut out = PinnedSources {
        packages: Vec::new(),
        files: Vec::new(),
    };
    let mut seen: Vec<String> = Vec::new();
    for p in meta["packages"].as_array().into_iter().flatten() {
        let source = p["source"].as_str().unwrap_or("");
        let name = p["name"].as_str().unwrap_or("");
        if !source.starts_with("git+")
            || !name.starts_with("busbar-")
            || seen.iter().any(|n| n == name)
        {
            continue;
        }
        seen.push(name.to_string());
        let at = format!("crates/{name}");
        if cx.is_dir(&at) {
            continue;
        }
        let Some(dir) = p["manifest_path"]
            .as_str()
            .and_then(|m| Path::new(m).parent())
        else {
            return Err(format!(
                "the git-pinned plugin crate `{name}` ({source}) has no manifest path in cargo metadata"
            ));
        };
        let mut files: Vec<(String, String)> = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let rd = std::fs::read_dir(&d).map_err(|e| {
                format!(
                    "the git-pinned plugin crate `{name}`: {} would not list: {e}",
                    d.display()
                )
            })?;
            for e in rd.flatten() {
                let path = e.path();
                let leaf = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if leaf.starts_with('.') || leaf == "target" {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                let rel = path
                    .strip_prefix(dir)
                    .map(|r| r.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                let shown = format!("{at}/{rel}");
                if shown.contains("/tests/") || is_test_file(&shown) {
                    continue;
                }
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    format!(
                        "the git-pinned plugin crate `{name}`: {} would not read: {e}",
                        path.display()
                    )
                })?;
                files.push((shown, text));
            }
        }
        if files.is_empty() {
            return Err(format!(
                "the git-pinned plugin crate `{name}` ({source}) at {}: no production .rs file \
                 reads — a pinned crate scanned as zero files carries no finding",
                dir.display()
            ));
        }
        files.sort();
        out.packages.push(format!("{name} ({source})"));
        out.files.extend(files);
    }
    out.packages.sort();
    Ok(out)
}

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────

pub struct SecretHygieneGate {
    roots: &'static [&'static str],
    allow_c1: &'static [Allow],
    /// Check 3's 1.5.5-parity rows ([`PARITY_C3`]).
    allow_c3: &'static [Parity],
    /// Read the git-pinned busbar plugin sources too ([`pinned_sources`]). The shipped gate does;
    /// the self-test's sandbox twins, whose roots are fixtures, do not.
    pinned: bool,
    /// Distinguishes the self-test's mis-configured twins from the shipped gate.
    tag: &'static str,
}

impl SecretHygieneGate {
    pub const fn shipped() -> SecretHygieneGate {
        SecretHygieneGate {
            roots: &["crates"],
            allow_c1: ALLOWLIST_C1,
            allow_c3: PARITY_C3,
            pinned: true,
            tag: "",
        }
    }
}

#[derive(Default)]
struct Scan {
    /// The floor's refusal, if any.
    floor: Option<String>,
    /// The instrument could not finish (an unreadable file).
    broken: Option<String>,
    nfiles: usize,
    /// The walk reconciled against the tracked set, in one sentence ([`Coverage::census`]).
    census: String,
    /// The git-pinned plugin crates read from their checkouts, and how many files they gave.
    pinned: Vec<String>,
    npinned: usize,
    c1: Vec<Hit>,
    c2: Vec<Hit>,
    c3: Vec<Hit>,
    /// Per [`Parity`] row, in order, the live hits it suppressed.
    kept: Vec<Vec<Hit>>,
    warns: Vec<Hit>,
}

impl SecretHygieneGate {
    /// The walk, and the tracked set it is reconciled against, are both cut by this one spec.
    fn spec(&self) -> WalkSpec {
        WalkSpec::new(self.roots.iter().copied())
            .ext("rs")
            .exclude(["/tests/"])
            .allow_empty()
    }

    fn scan(&self, cx: &Ctx) -> Scan {
        let mut sc = Scan::default();
        let spec = self.spec();
        let files = match cx.walk(&spec) {
            Ok(f) => f,
            Err(WalkError::MissingRoot { root }) => {
                sc.floor = Some(format!(
                    "scan root `{root}` is not a directory in this tree"
                ));
                return sc;
            }
            Err(e) => {
                sc.broken = Some(e.to_string());
                return sc;
            }
        };
        let mut files: Vec<(String, String)> = files
            .into_iter()
            .map(|f| (f.rel_str(), f.text))
            .filter(|(rel, _)| !is_test_file(rel))
            .collect();
        if files.is_empty() {
            sc.floor = Some(format!(
                "scanned 0 production .rs file(s) under `{}`; zero is RED — a scan of zero files \
                 reports zero violations, which is indistinguishable from a clean tree",
                self.roots.join(" ")
            ));
            return sc;
        }

        // THE WALK IS RECONCILED AGAINST THE TRACKED SET (Law 8, docs/design/BUSBAR-1.6.0.md:
        // "coverage is computed as the union of those lists reconciled against the whole"). The
        // floor was "not zero", so a walk narrowed to one file certified the tree clean (Q128 xtask
        // p2 #2). A tracked file the walk did not read, or a read file nothing tracks, is refused
        // BY NAME; there is no count to re-pin.
        let whole: Vec<String> = match cx.tracked(&spec) {
            Ok(w) => w.into_iter().filter(|p| !is_test_file(p)).collect(),
            Err(e) => {
                sc.broken = Some(format!(
                    "the tracked set under `{}` would not read, so the scan cannot be reconciled: {e}",
                    self.roots.join(" ")
                ));
                return sc;
            }
        };
        let coverage = Coverage::of(files.iter().map(|(rel, _)| rel.clone()), whole);
        if !coverage.is_whole() {
            sc.floor = Some(format!(
                "the scan is not the tracked set: {} — a walk that skipped a tracked file certifies \
                 a tree it did not read (Law 8)",
                coverage.census()
            ));
            return sc;
        }
        sc.census = coverage.census();

        // A CRATE THAT CONTRIBUTED NOTHING: a manifest beside a `src/` that gave no file. The
        // reconciliation catches a file the walk went blind to; this catches a crate whose whole
        // source left the tree while its manifest stayed.
        match self.drained(cx, &files) {
            Ok(d) if d.is_empty() => {}
            Ok(d) => {
                sc.floor = Some(format!(
                    "{} — a crate scanned as zero files carries no finding",
                    d.join(" | ")
                ));
                return sc;
            }
            Err(e) => {
                sc.broken = Some(e);
                return sc;
            }
        }

        // THE GIT-PINNED PLUGIN SOURCES the binary links (Part 2 #53; Q128 xtask p2 #3): after the
        // plugin split the auth, secret and export crates that hold client secrets, bearer tokens,
        // SigV4 keys and resolved secret values live in their own repos, outside `crates/`.
        if self.pinned {
            match pinned_sources(cx).as_ref() {
                Ok(p) => {
                    sc.pinned = p.packages.clone();
                    sc.npinned = p.files.len();
                    files.extend(p.files.iter().cloned());
                }
                Err(e) => {
                    sc.floor = Some(e.clone());
                    return sc;
                }
            }
        }
        sc.nfiles = files.len() - sc.npinned;
        sc.c1 = scan_fields(&files, self.allow_c1);
        sc.c2 = scan_sinks(&files);
        let (warns, c3): (Vec<Hit>, Vec<Hit>) = scan_msgs(&files)
            .into_iter()
            .partition(|h| h.rule == "PARSE-WARN");
        sc.warns = warns;
        sc.kept = vec![Vec::new(); self.allow_c3.len()];
        for h in c3 {
            match self.allow_c3.iter().position(|p| p.matches(&h)) {
                Some(i) => sc.kept[i].push(h),
                None => sc.c3.push(h),
            }
        }
        sc
    }

    /// The crates under a root (`<root>/<name>/Cargo.toml`) with a `src/` that gave the scan no
    /// file.
    fn drained(&self, cx: &Ctx, files: &[(String, String)]) -> Result<Vec<String>, String> {
        let manifests = cx
            .walk(
                &WalkSpec::new(self.roots.iter().copied())
                    .ext("toml")
                    .allow_empty(),
            )
            .map_err(|e| format!("the crate manifests would not list: {e}"))?;
        let mut out: Vec<String> = Vec::new();
        for m in manifests {
            let rel = m.rel_str();
            let Some(dir) = rel.strip_suffix("/Cargo.toml") else {
                continue;
            };
            if !self.roots.iter().any(|r| {
                dir.strip_prefix(&format!("{r}/"))
                    .is_some_and(|n| !n.contains('/'))
            }) {
                continue;
            }
            let src = format!("{dir}/src");
            if cx.exists(&src) && !files.iter().any(|(f, _)| f.starts_with(&format!("{src}/"))) {
                out.push(format!(
                    "{dir}: has a src/ and contributed no production .rs to the scan"
                ));
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The allowlist liveness problems: an empty prefix, or a prefix that names nothing.
    fn stale_allow(&self, cx: &Ctx) -> Vec<String> {
        let mut bad = Vec::new();
        for a in self.allow_c1 {
            let row = format!("{}|{}|{}", a.needle, a.prefix, a.field);
            if a.prefix.is_empty() {
                bad.push(format!(
                    "allowlist row `{row}` has an EMPTY path prefix — a path-scoped allowlist with no path is a global one, which this gate does not have"
                ));
            } else if !cx.exists(a.prefix) {
                bad.push(format!(
                    "allowlist row `{row}` names a path that is not in this tree: `{}` does not exist, so this row suppresses nothing and says nothing while doing it. If the file MOVED, repoint the row; if the exception is gone, DELETE the row",
                    a.prefix
                ));
            }
        }
        bad
    }

    /// The parity rows that do not suppress exactly one live hit. An unmeasured scan keeps no row,
    /// so every row is refused then: a parity row is live only against a measured tree.
    fn unkept(&self, sc: &Scan, measured: bool) -> Vec<String> {
        let mut bad = Vec::new();
        for (i, p) in self.allow_c3.iter().enumerate() {
            let n = sc.kept.get(i).map_or(0, Vec::len);
            if p.path.is_empty() || p.param.is_empty() || p.rule.is_empty() {
                bad.push(format!(
                    "parity row `{}` leaves its rule, path or parameter EMPTY — a parity row names one message, never a pattern",
                    p.key()
                ));
            } else if !measured {
                bad.push(format!(
                    "parity row `{}` was not measured: the scan-floor row is red",
                    p.key()
                ));
            } else if n != 1 {
                bad.push(format!(
                    "parity row `{}` suppresses {n} live hit(s){}; a parity row keeps EXACTLY ONE 1.5.5 message. If the message moved, repoint the row; if it is gone, DELETE the row; a second message is judged on its own",
                    p.key(),
                    if n == 0 {
                        String::new()
                    } else {
                        format!(
                            " ({})",
                            sc.kept[i].iter().map(|h| h.loc.as_str()).collect::<Vec<_>>().join(", ")
                        )
                    }
                ));
            }
        }
        bad
    }

    fn print_report(&self, sc: &Scan) {
        eprintln!(
            "\n== SECRET-HYGIENE report — bare secret VALUE types + secrets at a sink + secrets in a MESSAGE (production .rs under {}) ==",
            self.roots.join(" ")
        );
        eprintln!(
            "  Check 1 (bare secret field, not Secret/Zeroizing/SecretRef): {}",
            sc.c1.len()
        );
        eprintln!(
            "  Check 2 (.expose(seal) on a log/audit/metric sink line):        {}",
            sc.c2.len()
        );
        eprintln!(
            "  Check 3 (secret interpolated into a message a caller receives): {}",
            sc.c3.len()
        );
        if !sc.c1.is_empty() {
            eprintln!(
                "\n== Check 1 — bare secret fields (convert to busbar_contract::Secret<T>) =="
            );
            for h in &sc.c1 {
                eprintln!("  {:<20} {}", h.rule, h.loc);
            }
        }
        if !sc.c2.is_empty() {
            eprintln!("\n== Check 2 — secret exposed at a sink (log the SecretRef/id, never the value) ==");
            for h in &sc.c2 {
                eprintln!("  {:<14} {}", h.rule, h.loc);
            }
        }
        if !sc.c3.is_empty() {
            eprintln!("\n== Check 3 — secret interpolated into a message a CALLER receives (redact AT the format site; never delete the diagnostic) ==");
            for h in &sc.c3 {
                eprintln!("  {:<30} {:<58} {}", h.rule, h.loc, h.name);
            }
        }
    }
}

fn check_row(id: &str, title: &str, lines: &[String], measured: bool, blocking: bool) -> Row {
    if !measured {
        return Row::fail(
            id,
            title,
            "not measured: the scan did not complete (see the scan-floor and scan-complete rows) — a broken instrument is not report-only",
        );
    }
    if lines.is_empty() {
        return Row::pass(id, title, "no violation");
    }
    if blocking {
        Row::fail(
            id,
            title,
            format!(
                "{} violation(s) (BLOCKING, #53; SECRET_GATE_REPORT_ONLY=1 is the report-only escape): {} — wrap each secret VALUE in busbar_contract::Secret<T>; log a SecretRef/id, never .expose(seal) output; for a Check-3 hit REDACT AT THE FORMAT SITE, never delete the diagnostic",
                lines.len(),
                lines.join(" | ")
            ),
        )
    } else {
        Row::pass(
            id,
            title,
            format!(
                "{} violation(s), REPORT-ONLY (SECRET_GATE_REPORT_ONLY=1; the default, blocking, makes this row FAIL): {}",
                lines.len(),
                lines.join(" | ")
            ),
        )
    }
}

impl Gate for SecretHygieneGate {
    fn name(&self) -> &'static str {
        "secret-hygiene"
    }

    fn baseline_key(&self) -> Option<String> {
        Some(format!("secret-hygiene:{}", self.tag))
    }

    fn owed(&self) -> Vec<String> {
        [ROW_FLOOR, ROW_ALLOW, ROW_SCAN, ROW_C1, ROW_C2, ROW_C3]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let sc = self.scan(cx);
        let blocking = cx.env().secret_gate_blocking;
        if cx.overlay().is_none() && self.tag.is_empty() && sc.floor.is_none() {
            self.print_report(&sc);
        }
        let mut rows = Vec::new();

        let floor_title = "the scan read exactly the tracked production .rs under every root, every crate contributed, and every git-pinned plugin crate was read";
        rows.push(match &sc.floor {
            Some(why) => Row::fail(ROW_FLOOR, floor_title, why.clone()),
            None if sc.broken.is_some() => Row::fail(
                ROW_FLOOR,
                floor_title,
                "the scan could not list its files (see scan-complete)",
            ),
            None => Row::pass(
                ROW_FLOOR,
                floor_title,
                format!(
                    "{} production .rs file(s) under `{}` ({}){}",
                    sc.nfiles,
                    self.roots.join(" "),
                    sc.census,
                    if self.pinned {
                        format!(
                            "; plus {} production .rs file(s) of {} git-pinned plugin crate(s) read from their checkouts: {}",
                            sc.npinned,
                            sc.pinned.len(),
                            sc.pinned.join(", ")
                        )
                    } else {
                        String::new()
                    }
                ),
            ),
        });

        let measured = sc.floor.is_none() && sc.broken.is_none();
        let mut stale = self.stale_allow(cx);
        stale.extend(self.unkept(&sc, measured));
        let allow_title = "every allowlist row names a path in this tree, and every Check-3 1.5.5-parity row suppresses exactly one live hit (fails in BOTH modes)";
        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_ALLOW,
                allow_title,
                format!(
                    "{} Check-1 row(s), each path-prefix exists; {} Check-3 1.5.5-parity row(s), each suppressing exactly one live hit{}",
                    self.allow_c1.len(),
                    self.allow_c3.len(),
                    self.allow_c3
                        .iter()
                        .zip(&sc.kept)
                        .map(|(p, k)| format!(
                            " | {} {} ({}) kept as {}: {}",
                            k[0].loc, p.rule, p.param, p.since, p.why
                        ))
                        .collect::<String>()
                ),
            )
        } else {
            Row::fail(ROW_ALLOW, allow_title, stale.join(" ; "))
        });

        let scan_title = "the scan completed: the Check-3 lexer kept string state in every file";
        rows.push(if let Some(why) = &sc.broken {
            Row::fail(ROW_SCAN, scan_title, why.clone())
        } else if !measured {
            Row::fail(
                ROW_SCAN,
                scan_title,
                "not measured: the scan-floor row is red",
            )
        } else if sc.warns.is_empty() {
            Row::pass(ROW_SCAN, scan_title, "no PARSE-WARN")
        } else {
            Row::fail(
                ROW_SCAN,
                scan_title,
                format!(
                    "the Check-3 lexer lost string state in {} file(s): {} — every finding in those files is untrustworthy (a swallowed literal reads as code, a swallowed code region reports NOTHING); this is the silent-zero class, so it is a hard fail",
                    sc.warns.len(),
                    sc.warns
                        .iter()
                        .map(|w| format!("{} lexer-unterminated", w.loc))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            )
        });

        let l1: Vec<String> = sc
            .c1
            .iter()
            .map(|h| format!("{} {}", h.loc, h.rule))
            .collect();
        let l2: Vec<String> = sc.c2.iter().map(|h| h.loc.clone()).collect();
        let l3: Vec<String> = sc
            .c3
            .iter()
            .map(|h| format!("{} {} ({})", h.loc, h.rule, h.name))
            .collect();
        rows.push(check_row(
            ROW_C1,
            "Check 1: no bare-string secret field (not Secret/Zeroizing/SecretRef)",
            &l1,
            measured,
            blocking,
        ));
        rows.push(check_row(
            ROW_C2,
            "Check 2: no .expose(seal) on a log/audit/metric sink statement",
            &l2,
            measured,
            blocking,
        ));
        rows.push(check_row(
            ROW_C3,
            "Check 3: no secret interpolated into a message a caller receives",
            &l3,
            measured,
            blocking,
        ));
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        selftest_battery(self, cx)
    }
}

// ── SELF-TEST ────────────────────────────────────────────────────────────────────────────────────

const SANDBOX_ROOT: &str = "selftest-sandbox";
const SANDBOX_ALLOWED: &str = "selftest-sandbox/src/allowed.rs";

static SANDBOX_ALLOW: &[Allow] = &[allow("api_key", SANDBOX_ALLOWED, "api_key")];

static SANDBOX: SecretHygieneGate = SecretHygieneGate {
    roots: &[SANDBOX_ROOT],
    allow_c1: SANDBOX_ALLOW,
    allow_c3: &[],
    pinned: false,
    tag: "sandbox",
};
static MISSING_ROOT: SecretHygieneGate = SecretHygieneGate {
    roots: &["selftest-missing-root"],
    allow_c1: ALLOWLIST_C1,
    allow_c3: PARITY_C3,
    pinned: false,
    tag: "missing-root",
};
/// A root that exists and holds only a `tests/` file, which the scan drops.
static TESTS_ONLY: SecretHygieneGate = SecretHygieneGate {
    roots: &["crates/busbar-contract/src/tests"],
    allow_c1: ALLOWLIST_C1,
    allow_c3: PARITY_C3,
    pinned: false,
    tag: "tests-only",
};
// qa-names: crates/busbar-this-crate-does-not-exist/src/x.rs -- xtask/src/gates/secret_hygiene.rs -- the self-test's PLANTED stale allowlist row; it names a path that must not exist, that is the proof the liveness row goes RED
static STALE_ALLOW: SecretHygieneGate = SecretHygieneGate {
    roots: &["selftest-missing-root"],
    allow_c1: &[allow(
        "token",
        "crates/busbar-this-crate-does-not-exist/src/x.rs",
        "token",
    )],
    allow_c3: &[],
    pinned: false,
    tag: "stale-allow",
};
static EMPTY_PREFIX_ALLOW: SecretHygieneGate = SecretHygieneGate {
    roots: &["selftest-missing-root"],
    allow_c1: &[allow("token", "", "token")],
    allow_c3: &[],
    pinned: false,
    tag: "empty-prefix-allow",
};

const PARITY_PAIR: &str = "selftest-sandbox/src/c1_pair.rs";
const fn sandbox_parity(rule: &'static str, param: &'static str) -> Parity {
    Parity {
        rule,
        path: PARITY_PAIR,
        param,
        since: "the self-test's planted 1.5.5 site",
        why: "the self-test's planted reason",
    }
}
static PARITY_ONE: SecretHygieneGate = SecretHygieneGate {
    roots: &[SANDBOX_ROOT],
    allow_c1: SANDBOX_ALLOW,
    allow_c3: &[sandbox_parity("secret-named-binding", "api_key")],
    pinned: false,
    tag: "parity-one",
};
static PARITY_WRONG_PARAM: SecretHygieneGate = SecretHygieneGate {
    roots: &[SANDBOX_ROOT],
    allow_c1: SANDBOX_ALLOW,
    allow_c3: &[sandbox_parity("secret-named-binding", "admin_password")],
    pinned: false,
    tag: "parity-wrong-param",
};
static PARITY_EMPTY: SecretHygieneGate = SecretHygieneGate {
    roots: &[SANDBOX_ROOT],
    allow_c1: SANDBOX_ALLOW,
    allow_c3: &[sandbox_parity("secret-named-binding", "")],
    pinned: false,
    tag: "parity-empty",
};

fn selftest_battery<'a>(gate: &'a SecretHygieneGate, cx: &'a Ctx) -> Report<'a> {
    let mut report = Report::new();
    let quiet = cx.clone().secret_gate_blocking(false);
    let blocking = cx.clone().secret_gate_blocking(true);

    report.push(prove_green(
        &blocking,
        gate,
        "the tree is green in the default BLOCKING mode: zero violations, every row passes (#53 armed)",
        &[ROW_FLOOR, ROW_ALLOW, ROW_SCAN, ROW_C1, ROW_C2, ROW_C3],
    ));

    // THE SANDBOX BASE: one clean production file and one allowlisted field, so a plant is judged
    // against a green tree in the default blocking mode.
    let mut base = Overlay::new();
    base.set(
        format!("{SANDBOX_ROOT}/src/lib.rs"),
        "pub struct Clean { pub n: usize }\n",
    );
    base.set(
        SANDBOX_ALLOWED,
        "pub struct Allowed { pub api_key: String }\n",
    );
    let base_cx = blocking.with_overlay(base.clone());
    let plant = |name: &str, body: &str| {
        let mut ov = Overlay::new();
        ov.set(format!("{SANDBOX_ROOT}/src/{name}.rs"), body.to_string());
        base.layered(&ov)
    };

    report.push(prove_green(
        &base_cx,
        &SANDBOX,
        "GREEN floor/allowlist: a root with one clean production .rs scans, is not flagged broken, an allowlisted bare field stays quiet and every allowlist path is live (blocking mode)",
        &[ROW_FLOOR, ROW_ALLOW, ROW_SCAN, ROW_C1, ROW_C2, ROW_C3],
    ));

    // ── Check 1 ──
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c1: a bare `api_key: String` and a context `secret: String` on an *Key* struct are caught",
        &[ROW_C1],
        plant("c1_red", fixtures::C1_RED),
        &["api_key", "secret", "c1_red.rs:2", "c1_red.rs:6"],
    ));
    // THE ESCAPE: the same plant under SECRET_GATE_REPORT_ONLY=1 is CARRIED, not failed — the row
    // passes (its detail still names every violation). The pair with the RED case above proves the
    // default is what blocks, not the plant.
    report.push(prove_rows_green(
        &quiet,
        &SANDBOX,
        "REPORT-ONLY escape (SECRET_GATE_REPORT_ONLY=1): the SAME bare fields pass the check row, carried not failed",
        &[ROW_C1],
        plant("c1_red", fixtures::C1_RED),
    ));
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "GREEN c1: Secret-wrapped fields, a comment, a fn param and a non-secret `token: usize` flag NONE",
        &[ROW_C1],
        plant("c1_green", fixtures::C1_GREEN),
    ));
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "PAIR c1: a fn parameter `api_key: String` is not a field — Check 1 stays silent on it",
        &[ROW_C1],
        plant("c1_pair", fixtures::C1_GREEN_PARAM_IS_C3_RED),
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "PAIR c3: the SAME fn parameter, once it reaches a returned message, is RED (the blind spot is closed)",
        &[ROW_C3],
        plant("c1_pair", fixtures::C1_GREEN_PARAM_IS_C3_RED),
        &["secret-named-binding", "api_key"],
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c1 QUALIFIED: aws_secret_access_key, caller_token, admin_password, shared_secret (prefix/suffix variants) are caught",
        &[ROW_C1],
        plant("c1_qualified", fixtures::C1_RED_QUALIFIED),
        &[
            "aws_secret_access_key",
            "caller_token",
            "admin_password",
            "shared_secret",
        ],
    ));
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "GREEN c1 NEAR-MISS: 11 head-qualified names (token_url, token_hash, subject_token_type, secret_form_field, ...) flag NONE",
        &[ROW_C1],
        plant("c1_nearmiss", fixtures::C1_GREEN_NEARMISS),
    ));

    // ── Check 2 ──
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c2: `.expose(seal)` on a tracing:: sink line is caught",
        &[ROW_C2],
        plant("c2_red", fixtures::C2_RED),
        &["c2_red.rs"],
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c2 MULTILINE: the rustfmt-split `.expose(seal)` inside a multi-line tracing macro is caught",
        &[ROW_C2],
        plant("c2_multiline", fixtures::C2_RED_MULTILINE),
        &["c2_multiline.rs:2"],
    ));
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "GREEN c2: expose at a header injection, then a real sink on the NEXT statement — the statement window does not join them",
        &[ROW_C2],
        plant("c2_green", fixtures::C2_GREEN),
    ));

    // ── Check 3 ──
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c3 REAL LEAK #1: the three parse_proxy refusal arms (raw $HTTPS_PROXY into an Err) are named",
        &[ROW_C3],
        plant("c3_proxy", fixtures::C3_RED_PROXY),
        &[
            "secret-subject-parameter",
            "c3_proxy.rs:7",
            "c3_proxy.rs:10",
            "c3_proxy.rs:17",
        ],
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c3 REAL LEAK #2: base64::DecodeError's Display into a read-scope errors string is named",
        &[ROW_C3],
        plant("c3_pem", fixtures::C3_RED_PEM),
        &["decoder-error-on-secret-input", "c3_pem.rs"],
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c3 LEDGER S21 companion: $BUSBAR_SIGN_KEY's hex error (a nibble of the seed) is named",
        &[ROW_C3],
        plant("c3_hexseed", fixtures::C3_RED_HEXSEED),
        &["decoder-error-on-secret-input", "c3_hexseed.rs"],
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED c3 rule A: a secret-NAMED binding (api_key, admin_password) interpolated into a returned Err is named",
        &[ROW_C3],
        plant("c3_named", fixtures::C3_RED_NAMED),
        &["secret-named-binding", "api_key", "admin_password"],
    ));
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "GREEN c3: BOTH real leaks AS FIXED (redaction at the format site) flag NONE",
        &[ROW_C3],
        plant("c3_fixed", fixtures::C3_GREEN_FIXED),
    ));
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "GREEN c3 NEGATIVE CONTROL: 8 non-secret/redacted/header-value/public-material shapes flag NONE",
        &[ROW_C3],
        plant("c3_control", fixtures::C3_GREEN_CONTROL),
    ));

    // ── The lexer ──
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "LEXER GREEN: byte/raw strings (br#\"..\"#, r#\"..\"#, r\"..\") parse clean (no PARSE-WARN)",
        &[ROW_SCAN],
        plant("lexer_green", fixtures::C3_LEXER_GREEN),
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "LEXER GREEN (blindness): the leak AFTER the raw strings is still seen",
        &[ROW_C3],
        plant("lexer_green", fixtures::C3_LEXER_GREEN),
        &["secret-named-binding", "lexer_green.rs"],
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "LEXER RED: an unterminated literal is REPORTED (scan-complete RED), not silently scanned as zero findings",
        &[ROW_SCAN],
        plant("lexer_red", "fn x() {\n    let s = \"unterminated\n"),
        &["lexer_red.rs", "lexer-unterminated"],
    ));

    // ── The allowlist liveness ──
    report.push(prove_red_by_configuration(
        &quiet,
        gate,
        &STALE_ALLOW,
        "RED allowlist: a row whose PATH-PREFIX names no path on disk is REFUSED (in report-only mode too)",
        &[ROW_ALLOW],
        &[
            "crates/busbar-this-crate-does-not-exist/src/x.rs",
            "not in this tree",
        ],
    ));
    report.push(prove_red_by_configuration(
        &quiet,
        gate,
        &EMPTY_PREFIX_ALLOW,
        "RED allowlist: a row with an EMPTY path prefix is REFUSED",
        &[ROW_ALLOW],
        &["EMPTY path prefix"],
    ));

    // ── The Check-3 1.5.5-parity rows: listed, counted, exactly one live hit each ──
    let pair_cx = blocking.with_overlay(plant("c1_pair", fixtures::C1_GREEN_PARAM_IS_C3_RED));
    let two_cx = blocking.with_overlay(plant("c1_pair", fixtures::C3_PARITY_TWO));
    report.push(prove_green(
        &pair_cx,
        &PARITY_ONE,
        "GREEN parity: a row naming the one live hit's rule, file and parameter keeps it, and every row passes",
        &[ROW_FLOOR, ROW_ALLOW, ROW_SCAN, ROW_C1, ROW_C2, ROW_C3],
    ));
    report.push(prove_red_by_configuration(
        &base_cx,
        &SANDBOX,
        &PARITY_ONE,
        "RED parity: a row whose message is gone (zero live hits) is REFUSED, not carried",
        &[ROW_ALLOW],
        &[
            "suppresses 0 live hit(s)",
            "secret-named-binding|selftest-sandbox/src/c1_pair.rs|api_key",
        ],
    ));
    report.push(prove_red_by_configuration(
        &two_cx,
        &SANDBOX,
        &PARITY_ONE,
        "RED parity: a row that would keep TWO live hits is REFUSED (a second message is judged on its own)",
        &[ROW_ALLOW],
        &["suppresses 2 live hit(s)", "c1_pair.rs:2", "c1_pair.rs:5"],
    ));
    report.push(prove_red_by_configuration(
        &pair_cx,
        &PARITY_ONE,
        &PARITY_WRONG_PARAM,
        "RED parity: a row naming another parameter keeps nothing (the live hit stays and the row is refused)",
        &[ROW_ALLOW, ROW_C3],
        &["suppresses 0 live hit(s)", "api_key"],
    ));
    report.push(prove_red_by_configuration(
        &pair_cx,
        &PARITY_ONE,
        &PARITY_EMPTY,
        "RED parity: a row with an EMPTY parameter is a pattern, and is REFUSED",
        &[ROW_ALLOW],
        &["EMPTY"],
    ));

    // ── The scan floor ──
    report.push(prove_red_by_configuration(
        &quiet,
        gate,
        &TESTS_ONLY,
        "RED floor: a root holding ZERO production .rs (only a tests/ file) is a broken scan, not a PASS",
        &[ROW_FLOOR],
        &["scanned 0 production .rs", "zero is RED"],
    ));
    report.push(prove_red_by_configuration(
        &quiet,
        gate,
        &MISSING_ROOT,
        "RED floor: a scan root that is not on disk is a broken scan, not a PASS",
        &[ROW_FLOOR],
        &["selftest-missing-root", "is not a directory"],
    ));
    // THE SCAN IS RECONCILED AGAINST THE TRACKED SET (Law 8): one tracked file hidden from the
    // walk is refused BY NAME, though every root still holds production source. "Not zero" is no
    // floor: a walk narrowed to one file must not read as a measured tree.
    match crate::gates::population::one_file_hidden(cx) {
        Ok((ov, rel)) => report.push(prove_rows_red(
            &quiet,
            gate,
            "RED floor: a tracked production .rs the walk did not read is refused by name, not certified clean",
            &[ROW_FLOOR],
            ov,
            &["NOT scanned", rel.as_str()],
        )),
        Err(e) => report.note_infra_failure(format!("secret-hygiene selftest: {e}")),
    }

    // ── The test-file shape (item 506) ──
    // Multi-line on purpose: Check 1 reads a field only when the struct body opens on an EARLIER line
    // (the script's rule), so a one-line struct would make the green arm vacuous.
    let fixture = "pub struct Fixture {\n    pub api_key: String,\n}\n";
    let mut shape = Overlay::new();
    shape.set(format!("{SANDBOX_ROOT}/src/sub/tests.rs"), fixture);
    shape.set(format!("{SANDBOX_ROOT}/src/test.rs"), fixture);
    shape.set(format!("{SANDBOX_ROOT}/src/sub/wire_tests.rs"), fixture);
    shape.set(format!("{SANDBOX_ROOT}/tests/only_test.rs"), fixture);
    report.push(prove_rows_green(
        &base_cx,
        &SANDBOX,
        "GREEN shape: tests.rs, test.rs, *_tests.rs and a tests/ file are test code, not production",
        &[ROW_C1],
        base.layered(&shape),
    ));
    report.push(prove_rows_red(
        &base_cx,
        &SANDBOX,
        "RED shape: `contests.rs` is NOT a test file — a bare secret in it is scanned",
        &[ROW_C1],
        plant("contests", fixture),
        &["api_key", "contests.rs:2"],
    ));
    report
}

/// `cargo xtask secret-hygiene-scan3 <file.rs...>` — CHECK 3 against named files, the retro-proof
/// ("would this check have caught that leak?" is answerable only against the bytes that shipped).
/// Runs the SHIPPED needles and lexer. Files are read straight from disk: they are usually
/// `git show <sha>^:<path>` dumps outside the tree.
pub fn scan3_main(files: &[String]) -> i32 {
    if files.is_empty() {
        eprintln!("usage: cargo xtask secret-hygiene-scan3 <file.rs...>");
        return 2;
    }
    let mut loaded = Vec::new();
    for f in files {
        match std::fs::read_to_string(f) {
            Ok(t) => loaded.push((f.clone(), t)),
            Err(e) => {
                eprintln!("secret-hygiene-scan3: FAIL — {f}: {e}");
                return 1;
            }
        }
    }
    for h in scan_msgs(&loaded) {
        println!("{}\t{}\t{}\t{}", h.rule, h.loc, h.name, h.text);
    }
    0
}

mod fixtures {
    pub(super) const C1_RED: &str = r#####"pub struct LaneConfig {
    pub api_key: String,
    pub base_url: String,
}
pub struct IssuedKey {
    pub secret: String,
    pub key_id: String,
}
"#####;
    pub(super) const C1_GREEN: &str = r#####"// api_key: String  <- a comment naming the bad shape must be ignored
pub struct LaneConfig {
    pub api_key: busbar_contract::Secret<String>,
    pub base_url: String,
}
impl LaneConfig {
    fn set(&mut self, api_key: String) { let _ = api_key; }
}
pub struct Counter { pub token: usize }
"#####;
    pub(super) const C1_GREEN_PARAM_IS_C3_RED: &str = r#####"fn set(api_key: String) -> Result<(), String> {
    Err(format!("api_key {api_key} was rejected by the upstream"))
}
"#####;
    pub(super) const C3_PARITY_TWO: &str = r#####"fn set(api_key: String) -> Result<(), String> {
    Err(format!("api_key {api_key} was rejected by the upstream"))
}
fn reset(api_key: String) -> Result<(), String> {
    Err(format!("api_key {api_key} was refused on reset"))
}
"#####;
    pub(super) const C1_RED_QUALIFIED: &str = r#####"pub struct CreatedKeyView {
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
"#####;
    pub(super) const C1_GREEN_NEARMISS: &str = r#####"pub struct TokenExchangeCfg {
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
"#####;
    pub(super) const C2_RED: &str = r#####"fn leak(key: &Secret<String>, seal: &Grant<Sign>) {
    tracing::info!(api_key = %key.expose(seal), "using key");
}
"#####;
    pub(super) const C2_RED_MULTILINE: &str = r#####"fn leak(key: &Secret<String>, seal: &Grant<Sign>) {
    tracing::info!(
        api_key = %key.expose(seal),
        "using key"
    );
}
"#####;
    pub(super) const C2_GREEN: &str = r#####"fn inject(key: &Secret<String>, seal: &Grant<Sign>, req: &mut Request) {
    req.header("authorization", format!("Bearer {}", key.expose(seal)));
    // tracing::info!("sent");  <- a sink in a COMMENT, on a different statement, is not a leak
    tracing::info!(key_id = %key.reference(), "sent");
}
"#####;
    pub(super) const C3_RED_PROXY: &str = r#####"pub(super) fn parse_proxy(v: &str) -> Result<ProxySpec, String> {
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
"#####;
    pub(super) const C3_RED_PEM: &str = r#####"fn pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
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
"#####;
    pub(super) const C3_RED_HEXSEED: &str = r#####"fn sign_it(allow_unsigned: bool) -> Result<Manifest, String> {
    let hex_seed = std::env::var(SIGN_KEY_ENV).map_err(|_| "unset".to_string())?;
    let seed = hex::decode(hex_seed.trim())
        .map_err(|e| format!("{SIGN_KEY_ENV} is not valid hex: {e}"))?;
    Ok(seed)
}
"#####;
    pub(super) const C3_RED_NAMED: &str = r#####"fn check(cfg: &Lane) -> Result<(), String> {
    if cfg.api_key.is_empty() {
        return Err(format!("upstream rejected api_key {}", cfg.api_key));
    }
    let admin_password = cfg.pw();
    if admin_password.len() < 8 {
        return Err(format!("admin_password {admin_password} is too short"));
    }
    Ok(())
}
"#####;
    pub(super) const C3_GREEN_FIXED: &str = r#####"fn redact_userinfo(v: &str) -> String {
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
"#####;
    pub(super) const C3_GREEN_CONTROL: &str = r#####"fn a(base_url: &str, retries: u32) -> Result<(), String> {
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
"#####;
    pub(super) const C3_LEXER_GREEN: &str = r#####"fn pieces() {
    for piece in [r#"{"loc"#, r#"ation":"SF"}"#] { let _ = piece; }
    let b = Bytes::from_static(br#"{"location":"S"#);
    let c = br#"["a","b"]"#;
    let d = r"a raw string with no hashes";
}
fn after(api_key: String) -> Result<(), String> {
    Err(format!("api_key {api_key} was rejected"))
}
"#####;
}

#[cfg(test)]
mod tests {
    use super::fixtures as f;
    use super::*;

    fn one(name: &str, text: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), text.to_string())]
    }
    fn c1(text: &str) -> Vec<Hit> {
        scan_fields(&one("t.rs", text), &[])
    }
    fn c2(text: &str) -> Vec<Hit> {
        scan_sinks(&one("t.rs", text))
    }
    fn c3(text: &str) -> Vec<Hit> {
        scan_msgs(&one("t.rs", text))
    }
    fn fields(h: &[Hit]) -> Vec<&str> {
        h.iter().map(|x| x.rule.as_str()).collect()
    }

    #[test]
    fn check1_red_and_green() {
        let h = c1(f::C1_RED);
        assert_eq!(fields(&h), ["api_key", "secret"]);
        assert!(c1(f::C1_GREEN).is_empty());
        assert!(c1(f::C1_GREEN_PARAM_IS_C3_RED).is_empty());
        let q = c1(f::C1_RED_QUALIFIED);
        assert_eq!(
            fields(&q),
            [
                "aws_secret_access_key",
                "caller_token",
                "admin_password",
                "shared_secret"
            ]
        );
        assert!(c1(f::C1_GREEN_NEARMISS).is_empty());
    }

    #[test]
    fn check1_allowlist_is_exact_and_path_scoped() {
        let text = "pub struct X {\n    pub api_key: String,\n}\n";
        let files = one("crates/a/src/x.rs", text);
        let rows = [allow("api_key", "crates/a/", "api_key")];
        assert!(scan_fields(&files, &rows).is_empty());
        let wrong_field = [allow("api_key", "crates/a/", "other")];
        assert_eq!(scan_fields(&files, &wrong_field).len(), 1);
        let wrong_path = [allow("api_key", "crates/b/", "")];
        assert_eq!(scan_fields(&files, &wrong_path).len(), 1);
    }

    #[test]
    fn check1_cfg_test_module_is_dropped() {
        let t = "#[cfg(test)]\nmod t {\n    pub struct K {\n        pub api_key: String,\n    }\n}\npub struct Real {\n    pub api_key: String,\n}\n";
        assert_eq!(c1(t).len(), 1);
        assert!(c1(t)[0].loc.ends_with(":8"));
    }

    #[test]
    fn check2_sinks() {
        assert_eq!(c2(f::C2_RED).len(), 1);
        let m = c2(f::C2_RED_MULTILINE);
        assert_eq!(m.len(), 1);
        assert!(m[0].loc.ends_with(":2"));
        assert!(c2(f::C2_GREEN).is_empty());
    }

    #[test]
    fn check3_both_real_leaks_and_the_companion() {
        let p = c3(f::C3_RED_PROXY);
        assert_eq!(
            p.iter()
                .filter(|h| h.rule == "secret-subject-parameter")
                .count(),
            3,
            "{p:?}"
        );
        assert!(c3(f::C3_RED_PEM)
            .iter()
            .any(|h| h.rule == "decoder-error-on-secret-input"));
        assert!(c3(f::C3_RED_HEXSEED)
            .iter()
            .any(|h| h.rule == "decoder-error-on-secret-input"));
        let n = c3(f::C3_RED_NAMED);
        assert!(
            n.iter()
                .filter(|h| h.rule == "secret-named-binding")
                .count()
                >= 2,
            "{n:?}"
        );
        assert!(c1(f::C1_GREEN_PARAM_IS_C3_RED).is_empty());
        assert!(c3(f::C1_GREEN_PARAM_IS_C3_RED)
            .iter()
            .any(|h| h.rule == "secret-named-binding"));
    }

    #[test]
    fn check3_green_shapes_flag_nothing() {
        assert!(
            c3(f::C3_GREEN_FIXED).is_empty(),
            "{:?}",
            c3(f::C3_GREEN_FIXED)
        );
        assert!(
            c3(f::C3_GREEN_CONTROL).is_empty(),
            "{:?}",
            c3(f::C3_GREEN_CONTROL)
        );
    }

    #[test]
    fn lexer_raw_strings_and_unterminated() {
        let h = c3(f::C3_LEXER_GREEN);
        assert!(!h.iter().any(|x| x.rule == "PARSE-WARN"), "{h:?}");
        assert!(h.iter().any(|x| x.rule == "secret-named-binding"), "{h:?}");
        let r = c3("fn x() {\n    let s = \"unterminated\n");
        assert!(r.iter().any(|x| x.rule == "PARSE-WARN"));
    }

    #[test]
    fn test_file_shape() {
        for t in ["a/tests.rs", "a/test.rs", "a/wire_tests.rs", "a/x_test.rs"] {
            assert!(is_test_file(t), "{t}");
        }
        for p in ["a/contests.rs", "a/lib.rs", "a/latest.rs"] {
            assert!(!is_test_file(p), "{p}");
        }
    }

    /// Q128 LOW: every legal spelling of a bare secret is bare — `Arc<str>`, `Box<str>`,
    /// `Rc<str>`, `Cow<str>`, a byte array, a boxed byte slice, `Bytes` — and a struct-variant
    /// body of an enum is a field frame like a struct body (Part 2 #53/#54).
    #[test]
    fn check1_reads_every_bare_spelling_and_enum_variant_fields() {
        let t = "pub struct Keys {\n    pub api_key: Arc<str>,\n    pub client_secret: Box<str>,\n    pub signing_key: [u8; 32],\n    pub private_key: Box<[u8]>,\n    pub access_token: Cow<'static, str>,\n    pub bearer: Bytes,\n    pub password: Rc<str>,\n}\npub enum Cred {\n    Bearer {\n        token: String,\n    },\n    Basic {\n        user: String,\n        password: String,\n    },\n}\n";
        assert_eq!(
            fields(&c1(t)),
            [
                "api_key",
                "client_secret",
                "signing_key",
                "private_key",
                "access_token",
                "bearer",
                "password",
                "token",
                "password"
            ]
        );
        // Still wrapped: the wrapper is a whole type name, not a substring of a longer one.
        let ok = "pub struct Keys {\n    pub api_key: Secret<Arc<str>>,\n    pub signing_key: Zeroizing<[u8; 32]>,\n}\npub enum Cred {\n    Bearer {\n        token: busbar_contract::Secret<String>,\n    },\n}\n";
        assert!(c1(ok).is_empty(), "{:?}", c1(ok));
        let fake = "pub struct Keys {\n    pub api_key: NotASecretString,\n}\n";
        assert_eq!(fields(&c1(fake)), ["api_key"]);
    }

    /// A temp tree of one crate `a` with two clean production files, a context over it, and the
    /// overlay that plants its index (a temp tree has no git index of its own) and an empty
    /// `cargo metadata` answer (no pinned package).
    fn temp_tree(tag: &str) -> (std::path::PathBuf, Ctx, Overlay) {
        let root = std::env::temp_dir().join(format!(
            "xtask-secret-hygiene-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let krate = root.join("crates").join("a");
        std::fs::create_dir_all(krate.join("src")).expect("src dir creates");
        std::fs::write(krate.join("Cargo.toml"), "[package]\nname = \"a\"\n")
            .expect("manifest write");
        std::fs::write(
            krate.join("src/lib.rs"),
            "pub struct Clean { pub n: usize }\n",
        )
        .expect("lib write");
        std::fs::write(krate.join("src/more.rs"), "pub fn f() {}\n").expect("more write");
        let mut ov = Overlay::new();
        ov.set_command(
            crate::ctx::INDEX_KEY,
            "crates/a/Cargo.toml\ncrates/a/src/lib.rs\ncrates/a/src/more.rs",
        );
        ov.set_command("cargo-metadata:Cargo.toml", r#"{"packages":[]}"#);
        let cx = Ctx::at(&root, root.join(".fix").join("xtask"))
            .expect("ctx opens over the temp root")
            .secret_gate_blocking(true);
        (root, cx, ov)
    }

    fn row<'v>(v: &'v Verdict, id: &str) -> &'v Row {
        v.rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("row {id} is in the verdict"))
    }

    /// Q128 MEDIUM (Law 8, the absent floor): a tracked file the walk did not read is refused BY
    /// NAME, though the scan still read one file. "Not zero" is no floor.
    #[test]
    fn a_tracked_file_the_scan_did_not_read_is_refused_by_name() {
        let (root, cx, mut ov) = temp_tree("hidden");
        ov.remove("crates/a/src/more.rs");
        let v = SecretHygieneGate::shipped().run(&cx.with_overlay(ov));
        let floor = row(&v, ROW_FLOOR);
        assert_eq!(floor.status, crate::ledger::Status::Fail, "{floor:?}");
        assert!(floor.detail.contains("crates/a/src/more.rs"), "{floor:?}");
        assert!(floor.detail.contains("NOT scanned"), "{floor:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other direction: a file the walk read that nothing tracks is refused by name.
    #[test]
    fn a_scanned_file_nothing_tracks_is_refused_by_name() {
        let (root, cx, mut ov) = temp_tree("extra");
        ov.set_command(
            crate::ctx::INDEX_KEY,
            "crates/a/Cargo.toml\ncrates/a/src/lib.rs",
        );
        let v = SecretHygieneGate::shipped().run(&cx.with_overlay(ov));
        let floor = row(&v, ROW_FLOOR);
        assert_eq!(floor.status, crate::ledger::Status::Fail, "{floor:?}");
        assert!(floor.detail.contains("crates/a/src/more.rs"), "{floor:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Q128 MEDIUM (Part 2 #53): a bare secret in the source of a git-pinned plugin the binary
    /// links is a Check-1 finding, named at the pinned crate's path.
    #[test]
    fn a_bare_secret_in_a_pinned_plugin_source_is_caught() {
        let (root, cx, mut ov) = temp_tree("pinned");
        let checkout = root.join("checkout").join("auth-x");
        std::fs::create_dir_all(checkout.join("src")).expect("checkout src creates");
        std::fs::write(
            checkout.join("Cargo.toml"),
            "[package]\nname = \"busbar-auth-x\"\n",
        )
        .expect("checkout manifest write");
        std::fs::write(
            checkout.join("src/lib.rs"),
            "pub struct OidcClient {\n    pub client_secret: String,\n}\n",
        )
        .expect("checkout lib write");
        let manifest = checkout.join("Cargo.toml").display().to_string();
        ov.set_command(
            "cargo-metadata:Cargo.toml",
            serde_json::json!({"packages": [{
                "name": "busbar-auth-x",
                "source": "git+https://github.com/GetBusbar/busbar-auth-x?rev=1#1",
                "manifest_path": manifest,
            }]})
            .to_string(),
        );
        let v = SecretHygieneGate::shipped().run(&cx.with_overlay(ov));
        let c1 = row(&v, ROW_C1);
        assert_eq!(c1.status, crate::ledger::Status::Fail, "{c1:?}");
        assert!(
            c1.detail
                .contains("crates/busbar-auth-x/src/lib.rs:2 client_secret"),
            "{c1:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A pinned set that cannot be resolved is a refusal, never a smaller scan.
    #[test]
    fn an_unresolvable_pinned_set_is_refused() {
        let (root, cx, mut ov) = temp_tree("nometa");
        ov.set_command("cargo-metadata:Cargo.toml", "this is not json");
        let v = SecretHygieneGate::shipped().run(&cx.with_overlay(ov));
        let floor = row(&v, ROW_FLOOR);
        assert_eq!(floor.status, crate::ledger::Status::Fail, "{floor:?}");
        assert!(floor.detail.contains("pinned"), "{floor:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ref_str_and_vec_u8() {
        assert!(is_ref_str(b"&str"));
        assert!(is_ref_str(b"& 'a str"));
        assert!(is_ref_str(b"Option<&'static str>"));
        assert!(!is_ref_str(b"&Secret<u8>"));
        assert!(is_vec_u8(b"Vec<u8>"));
        assert!(is_vec_u8(b"Vec < u8>"));
        assert!(!is_vec_u8(b"Vec<u16>x"));
    }
}
