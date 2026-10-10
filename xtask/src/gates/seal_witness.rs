// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate seal-witness` — THE W2.e SEAL WITNESS, ENFORCED.
//!
//! This is the wave-W2.e proof (arm-gate-per-wave): after the capability-proof vocabulary was
//! unified to `Pass<stage>` + `Grant<capability>` + one kernel root minter (DECISIONS #72/#73), and
//! the single-minter posture was tightened (DECISIONS #65), this gate holds both properties so they
//! cannot silently regress. It is green on the tree and run by the pipeline's turnstile on every hop, and each of its
//! failing rows is proven RED-able by its own selftest over a green baseline.
//!
//! Three rows, two claims and one census:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `seal-witness:no-surviving-proof-name` | NO code under `crates/` — test code included — names ANY of the old proof-type zoo identifiers; the unified scheme is the only one that survives (#73) |
//! | `seal-witness:single-minter` | `KernelSeal::acquire_for_kernel` — in ANY spelling: a `use … as` or grouped rename, a `type` alias, a qualified or spaced path, a split line, a fn value — is referenced, in code that compiles into a SHIPPED (lib/bin) target, only inside the kernel crate — the one root minter (#65) |
//! | `seal-witness:test-mints` | CENSUS, never a failure: every test-scope call of the minter, counted and named on every run |
//!
//! Both scans are comment-stripped (a migration note in a doc comment naming the old type is prose,
//! not a use). String literals stay INTACT, so a zoo name smuggled into a literal is still caught.
//!
//! ## WHY THE MINTER IS RESOLVED, NOT SPELLED (X5 finding 11)
//!
//! The row used to match the one string `KernelSeal::acquire_for_kernel(` on a single line, and the
//! minter is a `pub fn` of `busbar-contract`, so `type S = KernelSeal; S::acquire_for_kernel()`,
//! `use …::{KernelSeal as K}`, `<KernelSeal>::acquire_for_kernel()`, `KernelSeal :: acquire_for_kernel (`
//! or a call broken across two lines all minted with the row green. It now matches the WORD
//! `acquire_for_kernel` on the comment-stripped, line-JOINED file and resolves the path receiver
//! against `KernelSeal` and every alias the scanned tree binds to it (`use … as`, grouped or not,
//! and `type` aliases, chained, read off the literal-blanked code by the crate's one lexer in
//! `scan.rs`). An inherent associated fn cannot itself be imported in Rust, so `use
//! …::KernelSeal::acquire_for_kernel` is not a spelling that compiles — and the attempt is
//! counted anyway, since its receiver resolves.
//!
//! ## WHY `single-minter` IS SCOPED TO SHIPPED CODE (item 181, architect ruling)
//!
//! #65's subject is the shipped binary: *"every KernelSeal must be unforgeable before 1.6.0 ships …
//! a gate proves no non-kernel code can mint a seal"*, and the seal's designed enforcement is a CI
//! symbol scan over code that ships. The row used to count the NAME across every `.rs` under
//! `crates/`, test fixtures included, and was red on 135 test-file calls with ZERO production sites
//! — unsatisfiable by anything the invariant is about, blocking CI and printing THE PROOF IS
//! IMPOSSIBLE for its own selftest. BUSBAR-1.6.0.md Part 1 ("What this means for the gates"): a gate
//! that reds on something outside its subject is scoped wrong, and the fix is the gate's scope.
//!
//! So a call counts against the row only when it is CODE (not a comment) in a file that compiles
//! into a non-test target: not under a `tests/` directory (which covers `src/tests/`), not a
//! module-style test file matching `(^|[/_])tests?\.rs$`, not under `benches/` or `examples/`, and
//! not inside a `#[cfg(test)]` item. Every one of those excluded calls is still COUNTED, named and
//! printed by `seal-witness:test-mints` — the rows print, so nothing is hidden. The test-file shape
//! is a filename anchor, not a substring, so a production `attests.rs` is still scanned.
//!
//! It complements the construction gate's `token-sealed`/`seal-sites`/`kernel-seal-impls` family
//! rather than replacing it: those hold the minting SURFACE; this holds the #73 vocabulary result
//! and gives the wave a single red-before-green witness of its own.

use crate::ctx::{Ctx, Overlay, SourceFile, WalkSpec};
use crate::gates::{prove_green, prove_red, prove_rows_green, Gate, Report};
#[cfg(test)]
use crate::ledger::Status;
use crate::ledger::{Row, Verdict};
use crate::scan;
use std::collections::BTreeSet;

pub const ROW_NO_SURVIVING: &str = "seal-witness:no-surviving-proof-name";
pub const ROW_SINGLE_MINTER: &str = "seal-witness:single-minter";
pub const ROW_TEST_MINTS: &str = "seal-witness:test-mints";

/// The old capability-proof zoo (#73). None of these identifiers may survive anywhere under `crates/`.
pub const ZOO: &[&str] = &[
    "UnitToken",
    "AdmitToken",
    "TrustToken",
    "UsageToken",
    "LedgerToken",
    "DurabilityToken",
    "EgressAuthToken",
    "TransportKeyToken",
    "AdminToken",
    "RecoveryToken",
    "ExitToken",
];

/// The kernel seal's type, and the one root minter's associated fn on it (#65).
const SEAL_TYPE: &str = "KernelSeal";
const MINTER_FN: &str = "acquire_for_kernel";
/// The minter as the rows print it.
const MINTER: &str = "KernelSeal::acquire_for_kernel";

/// Where the one root minter may be spelled at all.
const KERNEL_ROOT: &str = "crates/busbar-kernel/src/";

/// Every `.rs` under `crates/`, and from 2026-09-23 that means EVERY one.
///
/// ── WHY THE FOUR TEST EXCLUSIONS ARE GONE ───────────────────────────────────────────────────────
///
/// They read `["/tests/", "/tests.rs", "_tests.rs", "/benches/", "/target/"]` and the argument
/// beside them was that a unit's own tests mint sealed tokens by calling the seal directly, "exactly
/// as the construction gate does". That mirroring is the reason to drop them, not to keep them: the
/// construction gate's `token-sealed` family stopped being production-only on the same day, because
/// #65 (`docs/design/BUSBAR-1.6.0.md:401`) binds *"a gate proves no **non-kernel code** can mint a
/// seal"* — code, not production code. Two rows holding one property from two directions is the
/// design; two rows holding it over two different populations is two different properties wearing
/// one name, and they disagreed by 135 sites.
///
/// THE EXCLUSIONS WERE ALSO WIDER THAN THE WORD "TEST". `/tests/` matches an IN-SRC directory —
/// `crates/busbar-llm/src/tests/` and `crates/busbar-kernel-identity/src/egress_auth/tests.rs` are
/// both inside a crate's own `src` and were both unscanned — and `/benches/` excluded a scope that
/// is not test code at all. The census demonstrated it: eight seal/zoo sites planted, three found,
/// with `crates/busbar-llm/tests/`, `crates/busbar-llm/benches/` and `crates/busbar-llm/src/tests/`
/// all invisible while the inline `#[cfg(test)] mod` beside them was caught — this gate's own module
/// header claimed to be "test-scoped out" and never was, so the doc and the code disagreed and only
/// one of them was enforcing anything.
///
/// MEASURED before the change: the ZOO identifiers occur ZERO times in the newly-included scope, so
/// `:no-surviving-proof-name` gains a whole population and no finding. `:single-minter` gains 135
/// sites, which is the same 135 `construction`'s `token-sealed:kernel-seal` now reports — the two
/// rows agree for the first time.
///
/// `/target/` stays: build output is not source. `xtask` is deliberately NOT added to `ROOTS`, for
/// the reason `qa/construction.toml`'s `scan_roots` note gives at length — xtask declares no product
/// dependency, so it cannot spell a real mint, and THIS FILE spells the minter's name in its own
/// constants and plants.
const ROOTS: &[&str] = &["crates"];
const EXCLUDE: &[&str] = &["/target/"];
/// The denominator floor: a walk that finds fewer files than this is broken, not clean.
///
/// ARMED AT THE MEASURED POPULATION (Law 9), not a margin below it: 2174 `.rs` files under
/// `crates/` on predev 39374ec00e (the gate prints the count in both judging rows' detail). It
/// read 200 — about a tenth of the tree — so a walk that silently dropped nine files in ten still
/// scanned "clean". It was first armed at 2181 on predev 0fd08ee75d; predev then retired the
/// kernel-identity and kernel `egress_auth` modules (24 files out, 15 in), and a floor above the
/// tree it guards refuses every walk. A tree that grows keeps this floor; a walk that comes back
/// short of it is refused.
const SCAN_FLOOR: usize = 2174;

/// Is `rel` a file that compiles only into a TEST, BENCH or EXAMPLE target — never into a shipped
/// lib/bin? A `tests/` directory anywhere on the path (which covers `src/tests/`), a `benches/` or
/// `examples/` directory, or a module-style test file whose NAME matches `(^|[/_])tests?\.rs$`
/// (`tests.rs`, `test.rs`, `foo_tests.rs`, `foo_test.rs`). The name rule is anchored at a `/` or `_`
/// boundary on purpose: `attests.rs` or `contests.rs` is production and stays scanned.
pub fn is_test_target_path(rel: &str) -> bool {
    if rel.contains("/tests/") || rel.contains("/benches/") || rel.contains("/examples/") {
        return true;
    }
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let Some(stem) = name
        .strip_suffix("tests.rs")
        .or_else(|| name.strip_suffix("test.rs"))
    else {
        return false;
    };
    stem.is_empty() || stem.ends_with('_')
}

fn word_hit(hay: &str, needle: &str) -> bool {
    let bytes = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > bytes.len() {
        return false;
    }
    let wordy = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for i in 0..=(bytes.len() - n.len()) {
        if &bytes[i..i + n.len()] != n {
            continue;
        }
        let before_ok = i == 0 || !wordy(bytes[i - 1]);
        let after_ok = i + n.len() == bytes.len() || !wordy(bytes[i + n.len()]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// One token of comment- and literal-blanked code: an identifier, a `::`, or one other char.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Path,
    Punct(char),
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Tokens of text [`scan::test_scope`] has already blanked (its `counted` field), so a literal or a
/// comment can never read as an import or an alias. A raw identifier `r#x` reads as `x`.
fn tokens(blanked: &str) -> Vec<Tok> {
    let c: Vec<char> = blanked.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == 'r'
            && c.get(i + 1) == Some(&'#')
            && c.get(i + 2).is_some_and(|x| is_ident_start(*x))
        {
            i += 2;
        } else if is_ident_start(ch) {
            let s = i;
            while i < c.len() && is_ident_char(c[i]) {
                i += 1;
            }
            out.push(Tok::Ident(c[s..i].iter().collect()));
        } else if ch == ':' && c.get(i + 1) == Some(&':') {
            out.push(Tok::Path);
            i += 2;
        } else {
            out.push(Tok::Punct(ch));
            i += 1;
        }
    }
    out
}

fn is_word(t: Option<&Tok>, w: &str) -> bool {
    matches!(t, Some(Tok::Ident(x)) if x == w)
}

/// Step over a `<…>` group starting at `t[*i] == '<'`.
fn skip_angle(t: &[Tok], i: &mut usize) {
    let mut depth = 0i32;
    while let Some(tok) = t.get(*i) {
        *i += 1;
        match tok {
            Tok::Punct('<') => depth += 1,
            Tok::Punct('>') => {
                depth -= 1;
                if depth <= 0 {
                    return;
                }
            }
            Tok::Punct(';') | Tok::Punct('{') => return,
            _ => {}
        }
    }
}

/// The last segment of the type path starting at `t[*i]` (`&`, `mut`, `dyn` and lifetimes
/// skipped): `crate::caps::KernelSeal` is `KernelSeal`. A qualified `<…>` start is not a path.
fn path_last(t: &[Tok], i: &mut usize) -> Option<String> {
    loop {
        match t.get(*i) {
            Some(Tok::Punct('&')) => *i += 1,
            Some(Tok::Punct('\'')) => *i += 2,
            Some(Tok::Ident(w)) if w == "mut" || w == "dyn" => *i += 1,
            _ => break,
        }
    }
    let mut last = None;
    loop {
        match t.get(*i) {
            Some(Tok::Path) => *i += 1,
            Some(Tok::Ident(w)) => {
                last = Some(w.clone());
                *i += 1;
                if t.get(*i) != Some(&Tok::Path) {
                    break;
                }
            }
            _ => break,
        }
    }
    last
}

/// One `use` tree (after the `use` keyword, or one member of a `{…}` group), appending
/// `(bound name, last path segment)` per leaf: `use a::KernelSeal as S` binds `S` to
/// `KernelSeal`, `use a::{KernelSeal as K, B}` binds `K` and `B`, `use a::KernelSeal::{self as S}`
/// binds `S`. Globs bind nothing new: they bring `KernelSeal` in under its own name.
fn use_tree(t: &[Tok], i: &mut usize, prefix: &[String], out: &mut Vec<(String, String)>) {
    let mut path = prefix.to_vec();
    loop {
        match t.get(*i) {
            Some(Tok::Path) => *i += 1,
            Some(Tok::Ident(w)) if w != "as" => {
                path.push(w.clone());
                *i += 1;
                if t.get(*i) != Some(&Tok::Path) {
                    break;
                }
            }
            Some(Tok::Punct('{')) => {
                *i += 1;
                loop {
                    match t.get(*i) {
                        None | Some(Tok::Punct(';')) => return,
                        Some(Tok::Punct('}')) => {
                            *i += 1;
                            return;
                        }
                        Some(Tok::Punct(',')) => *i += 1,
                        _ => {
                            let before = *i;
                            use_tree(t, i, &path, out);
                            if *i == before {
                                *i += 1;
                            }
                        }
                    }
                }
            }
            Some(Tok::Punct('*')) => {
                *i += 1;
                return;
            }
            _ => break,
        }
    }
    if path.len() == prefix.len() {
        return;
    }
    if path.last().is_some_and(|l| l == "self") {
        path.pop();
    }
    let Some(target) = path.last().cloned() else {
        return;
    };
    let mut binding = target.clone();
    if is_word(t.get(*i), "as") {
        *i += 1;
        if let Some(Tok::Ident(a)) = t.get(*i) {
            binding = a.clone();
            *i += 1;
        }
    }
    if binding != "_" {
        out.push((binding, target));
    }
}

/// Every `(new name, named type)` edge one file's blanked code introduces: `use … as` (grouped or
/// not) and `type New<…> = …Named;` (an associated `type Seal = KernelSeal;` included).
fn alias_edges(blanked: &str) -> Vec<(String, String)> {
    let t = tokens(blanked);
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if is_word(t.get(i), "use") {
            i += 1;
            let start = i;
            use_tree(&t, &mut i, &[], &mut out);
            if i == start {
                i += 1;
            }
        } else if is_word(t.get(i), "type") {
            i += 1;
            let Some(Tok::Ident(name)) = t.get(i).cloned() else {
                continue;
            };
            i += 1;
            if t.get(i) == Some(&Tok::Punct('<')) {
                skip_angle(&t, &mut i);
            }
            if t.get(i) != Some(&Tok::Punct('=')) {
                continue;
            }
            i += 1;
            if let Some(target) = path_last(&t, &mut i) {
                out.push((name, target));
            }
        } else {
            i += 1;
        }
    }
    out
}

/// `KernelSeal` and every name bound to it through any chain of edges, closed to a fixpoint. The
/// edges are the WHOLE scanned tree's, so a `pub type` or `pub use … as` in one module resolves a
/// mint spelled through it in another.
fn close_aliases(edges: &[(String, String)]) -> BTreeSet<String> {
    let mut names = BTreeSet::from([SEAL_TYPE.to_string()]);
    loop {
        let before = names.len();
        for (binding, target) in edges {
            if names.contains(target) {
                names.insert(binding.clone());
            }
        }
        if names.len() == before {
            return names;
        }
    }
}

/// Does this file implement anything on the seal type (or an alias of it)? Then `Self::` in it may
/// name the seal, and a `Self::acquire_for_kernel` there is counted.
fn impls_seal(blanked: &str, aliases: &BTreeSet<String>) -> bool {
    let t = tokens(blanked);
    let mut i = 0;
    while i < t.len() {
        if !is_word(t.get(i), "impl") {
            i += 1;
            continue;
        }
        i += 1;
        if t.get(i) == Some(&Tok::Punct('<')) {
            skip_angle(&t, &mut i);
        }
        let head = i;
        let mut depth = 0i32;
        let mut self_at = head;
        while let Some(tok) = t.get(i) {
            match tok {
                Tok::Punct('<') => depth += 1,
                Tok::Punct('>') => depth -= 1,
                Tok::Punct('{') | Tok::Punct(';') => break,
                Tok::Ident(w) if depth == 0 && w == "for" => self_at = i + 1,
                Tok::Ident(w) if depth == 0 && w == "where" => break,
                _ => {}
            }
            i += 1;
        }
        let mut j = self_at;
        if path_last(&t, &mut j).is_some_and(|n| aliases.contains(&n)) {
            return true;
        }
    }
    false
}

fn skip_ws_back(t: &[char], mut j: usize) -> usize {
    while j > 0 && t[j - 1].is_whitespace() {
        j -= 1;
    }
    j
}

/// The identifier ending at `t[j]` (exclusive), with a macro metavariable's `$` kept.
fn ident_back(t: &[char], j: usize) -> Option<String> {
    let mut s = j;
    while s > 0 && is_ident_char(t[s - 1]) {
        s -= 1;
    }
    if s == j {
        return None;
    }
    if s > 0 && t[s - 1] == '$' {
        s -= 1;
    }
    Some(t[s..j].iter().collect())
}

/// THE RECEIVER of the path segment starting at `t[s]`: the type the `::` before it hangs off,
/// across whitespace and newlines. `KernelSeal :: x` and `a::KernelSeal::\n x` give `KernelSeal`;
/// `<KernelSeal>::x` and `<KernelSeal as T>::x` give the qualified self type; `S::<T>::x` gives
/// `S`. `None` when no `::` precedes (a definition, a method call, prose in a literal).
fn receiver(t: &[char], s: usize) -> Option<String> {
    let mut j = s;
    if j >= 2 && t[j - 1] == '#' && t[j - 2] == 'r' {
        j -= 2;
    }
    j = skip_ws_back(t, j);
    if j < 2 || t[j - 1] != ':' || t[j - 2] != ':' {
        return None;
    }
    j = skip_ws_back(t, j - 2);
    if j == 0 || t[j - 1] != '>' {
        return ident_back(t, j);
    }
    let close = j - 1;
    let mut depth = 0i32;
    let mut open = None;
    let mut k = close + 1;
    while k > 0 {
        k -= 1;
        match t[k] {
            '>' => depth += 1,
            '<' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(k);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open?;
    let p = skip_ws_back(t, open);
    if p >= 2 && t[p - 1] == ':' && t[p - 2] == ':' {
        return ident_back(t, skip_ws_back(t, p - 2));
    }
    if p > 0 && is_ident_char(t[p - 1]) {
        return ident_back(t, p);
    }
    let inner: String = t[open + 1..close].iter().collect();
    let inner = inner.trim();
    if let Some(meta) = inner.strip_prefix('$') {
        let name: String = meta.chars().take_while(|c| is_ident_char(*c)).collect();
        return Some(format!("${name}"));
    }
    let toks = tokens(inner);
    let end = toks
        .iter()
        .position(|x| matches!(x, Tok::Ident(w) if w == "as"))
        .unwrap_or(toks.len());
    path_last(&toks[..end], &mut 0)
}

/// Every reference to the minter in one file's comment-stripped code (string literals intact, as
/// the old exact-string match read them): the WORD `acquire_for_kernel` whose receiver resolves —
/// to `KernelSeal` or any alias of it, to `Self` in a file that implements on the seal, or to a
/// macro metavariable (`$t::`, `<$t>::`), which no source scan can resolve and is counted rather
/// than guessed clean. The match is on the JOINED file, so a call split across lines is one
/// statement. Called or not: a minter taken as a fn value mints as surely as one called in place.
/// Returns `(0-based line, receiver as spelled)`.
fn minter_hits(code: &str, resolves: &dyn Fn(&str) -> bool) -> Vec<(usize, String)> {
    let t: Vec<char> = code.chars().collect();
    let n: Vec<char> = MINTER_FN.chars().collect();
    let mut out = Vec::new();
    let mut line = 0usize;
    let mut i = 0usize;
    while i < t.len() {
        if t[i] == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        let at_word = t[i..].starts_with(&n)
            && (i == 0
                || !is_ident_char(t[i - 1])
                || (i >= 2 && t[i - 1] == '#' && t[i - 2] == 'r'))
            && t.get(i + n.len()).is_none_or(|c| !is_ident_char(*c));
        if at_word {
            if let Some(r) = receiver(&t, i) {
                if resolves(&r) {
                    out.push((line, r));
                }
            }
            i += n.len();
            continue;
        }
        i += 1;
    }
    out
}

/// `KernelSeal` and every alias of it the scanned tree binds, chained. Only a file whose raw text
/// names something already in the set can bind a new name to it, so the edges are read off those
/// files alone, round by round, until a round reads nothing new. The blanking is the crate's one
/// lexer ([`scan::blank_code`]), carried across lines.
fn seal_aliases(files: &[SourceFile]) -> BTreeSet<String> {
    let mut names = BTreeSet::from([SEAL_TYPE.to_string()]);
    let mut read = vec![false; files.len()];
    let mut edges = Vec::new();
    loop {
        let mut grew = false;
        for (k, f) in files.iter().enumerate() {
            if read[k] || !names.iter().any(|n| f.text.contains(n.as_str())) {
                continue;
            }
            read[k] = true;
            grew = true;
            let mut st = scan::LexState::default();
            let blanked: Vec<String> = f
                .text
                .lines()
                .map(|l| scan::blank_code(l, &mut st))
                .collect();
            edges.extend(alias_edges(&blanked.join("\n")));
        }
        if !grew {
            return names;
        }
        names = close_aliases(&edges);
    }
}

struct Scan {
    files: usize,
    /// Every name the tree binds to the seal type, `KernelSeal` included.
    aliases: BTreeSet<String>,
    surviving: Vec<String>,
    minters_outside: Vec<String>,
    /// Minter calls in TEST scope (test-target path or `#[cfg(test)]`), outside the kernel crate.
    test_mints: Vec<String>,
}

fn scan_tree(cx: &Ctx) -> Result<Scan, String> {
    let spec = WalkSpec::new(ROOTS.iter().copied())
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(SCAN_FLOOR);
    let files = cx.walk(&spec).map_err(|e| format!("{e:?}"))?;

    let aliases = seal_aliases(&files);

    let mut surviving = Vec::new();
    let mut minters_outside = Vec::new();
    let mut test_mints = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        // Only a file whose raw text holds a zoo name can hold one in its code, and only a file
        // whose raw text holds the minter's name can mint: the lexers run on those alone, which is
        // what keeps a whole-tree scan per selftest plant cheap.
        if ZOO.iter().any(|z| f.text.contains(z)) {
            let mut in_block = false;
            for (i, raw) in f.text.lines().enumerate() {
                let code = scan::strip_comment_line(raw, &mut in_block);
                for name in ZOO {
                    if word_hit(&code, name) {
                        surviving.push(format!("`{name}` at {rel}:{}", i + 1));
                    }
                }
            }
        }
        if rel.starts_with(KERNEL_ROOT) || !f.text.contains(MINTER_FN) {
            continue;
        }
        let test_path = is_test_target_path(&rel);
        // THE ONE TEST-SCOPE ANSWER every scanner in this crate uses: `gated` is true inside a
        // `#[cfg(test)]` item.
        let lines = scan::test_scope(&f.text);
        let mut in_block = false;
        let code: Vec<String> = f
            .text
            .lines()
            .map(|raw| scan::strip_comment_line(raw, &mut in_block))
            .collect();
        let self_is_seal = std::cell::OnceCell::new();
        let resolves = |r: &str| match r {
            "Self" => *self_is_seal.get_or_init(|| {
                let blanked: Vec<&str> = lines.iter().map(|l| l.counted.as_str()).collect();
                impls_seal(&blanked.join("\n"), &aliases)
            }),
            _ => r.starts_with('$') || aliases.contains(r),
        };
        for (i, via) in minter_hits(&code.join("\n"), &resolves) {
            let gated = lines.get(i).is_some_and(|l| l.gated);
            let site = format!("{rel}:{}", i + 1);
            if test_path || gated {
                test_mints.push(site);
            } else if via == SEAL_TYPE {
                minters_outside.push(site);
            } else {
                minters_outside.push(format!("{site} (via `{via}`)"));
            }
        }
    }
    surviving.sort();
    minters_outside.sort();
    test_mints.sort();
    Ok(Scan {
        files: files.len(),
        aliases,
        surviving,
        minters_outside,
        test_mints,
    })
}

fn join_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

pub struct SealWitnessGate;

impl SealWitnessGate {
    fn rows(cx: &Ctx) -> Vec<Row> {
        let scan = match scan_tree(cx) {
            Ok(s) => s,
            Err(e) => {
                return vec![
                    Row::fail(
                        ROW_NO_SURVIVING,
                        "the seal-witness scan could not run",
                        e.clone(),
                    ),
                    Row::fail(
                        ROW_SINGLE_MINTER,
                        "the seal-witness scan could not run",
                        e.clone(),
                    ),
                    Row::fail(ROW_TEST_MINTS, "the seal-witness scan could not run", e),
                ];
            }
        };
        let no_surviving = if scan.surviving.is_empty() {
            Row::pass(
                ROW_NO_SURVIVING,
                "no source under crates/ names a pre-#73 proof-type zoo identifier",
                format!(
                    "{} files scanned; the capability-proof types are exactly \
                     Pass<stage> + Grant<capability> + KernelSeal",
                    scan.files
                ),
            )
        } else {
            Row::fail(
                ROW_NO_SURVIVING,
                "a pre-#73 proof-type name survived the rename",
                format!(
                    "{} surviving zoo identifier(s): {}",
                    scan.surviving.len(),
                    join_or_none(&scan.surviving)
                ),
            )
        };
        let single_minter = if scan.minters_outside.is_empty() {
            Row::pass(
                ROW_SINGLE_MINTER,
                "in shipped code, the one root minter is referenced only inside the kernel crate",
                format!(
                    "`{MINTER}` is referenced, in any spelling, in no lib/bin code outside \
                     {KERNEL_ROOT} ({} files scanned, floor {SCAN_FLOOR}; receivers resolved \
                     against {}; {} test-scope call(s) are counted by {ROW_TEST_MINTS})",
                    scan.files,
                    join_or_none(&scan.aliases.iter().cloned().collect::<Vec<_>>()),
                    scan.test_mints.len()
                ),
            )
        } else {
            Row::fail(
                ROW_SINGLE_MINTER,
                "shipped non-kernel code obtains the kernel seal",
                format!(
                    "{} production site(s) of `{MINTER}` outside {KERNEL_ROOT}: {}",
                    scan.minters_outside.len(),
                    join_or_none(&scan.minters_outside)
                ),
            )
        };
        // THE CENSUS. Never a failure: a test harness minting a seal is not the #65 breach, but it
        // is printed in full on every run so the population the minter row does not judge is never
        // a population nobody can see.
        let mut files: Vec<&str> = scan
            .test_mints
            .iter()
            .map(|s| s.rsplit_once(':').map_or(s.as_str(), |(f, _)| f))
            .collect();
        files.dedup();
        let test_mints = Row::pass(
            ROW_TEST_MINTS,
            "census: test-scope calls of the kernel minter outside the kernel crate",
            format!(
                "{} test-scope call(s) of `{MINTER}` in {} file(s) (tests/, benches/, examples/, \
                 *tests.rs, #[cfg(test)]) — informational, never red: {}",
                scan.test_mints.len(),
                files.len(),
                if files.is_empty() {
                    "none".to_string()
                } else {
                    files.join(", ")
                }
            ),
        );
        vec![no_surviving, single_minter, test_mints]
    }
}

impl Gate for SealWitnessGate {
    fn name(&self) -> &'static str {
        "seal-witness"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_NO_SURVIVING.to_string(),
            ROW_SINGLE_MINTER.to_string(),
            ROW_TEST_MINTS.to_string(),
        ]
    }

    /// The census row always passes by design; it prints, it does not judge.
    fn informational(&self) -> Vec<String> {
        vec![ROW_TEST_MINTS.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(SealWitnessGate::rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed tree carries only the unified Pass/Grant/KernelSeal scheme",
            &[ROW_NO_SURVIVING, ROW_SINGLE_MINTER, ROW_TEST_MINTS],
        ));

        // RED 1: a surviving zoo name in production is caught.
        let victim = "crates/busbar-kernel/src/teller.rs";
        let text = cx.read(victim).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            victim,
            format!("{text}\nfn __seal_witness_probe(_t: &LedgerToken) {{}}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "a resurrected `LedgerToken` in production is RED",
            &[ROW_NO_SURVIVING],
            ov,
            &["LedgerToken"],
        ));

        // RED 2: obtaining the seal outside the kernel crate is caught.
        let outsider = "crates/busbar-contract/src/lib.rs";
        let otext = cx.read(outsider).unwrap_or_default();
        let mut ov2 = Overlay::new();
        ov2.set(
            outsider,
            format!("{otext}\nfn __seal_witness_forge() {{ let _ = KernelSeal::acquire_for_kernel(); }}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "obtaining the kernel seal in a non-kernel crate's src/lib.rs is RED",
            &[ROW_SINGLE_MINTER],
            ov2,
            &["outside", outsider],
        ));

        // RED 3: a production file whose NAME merely ends in `tests.rs` is still production. The
        // test-file rule is anchored at `/` or `_`; `attests.rs` must not slip under it.
        let disguised = "crates/busbar-contract/src/attests.rs";
        let mut ov3 = Overlay::new();
        ov3.set(
            disguised,
            "pub fn __seal_witness_forge() { let _ = KernelSeal::acquire_for_kernel(); }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a mint hidden in a production file named `attests.rs` is RED",
            &[ROW_SINGLE_MINTER],
            ov3,
            &[disguised],
        ));

        // GREEN 1: a mint inside an inline `#[cfg(test)] mod` of a production file is test scope —
        // counted by the census, not by the minter row.
        let mut ov4 = Overlay::new();
        ov4.set(
            outsider,
            format!(
                "{otext}\n#[cfg(test)]\nmod __seal_witness_probe {{\n    fn f() {{\n        let _ = \
                 KernelSeal::acquire_for_kernel();\n    }}\n}}\n"
            ),
        );
        report.push(prove_rows_green(
            cx,
            self,
            "a mint inside an inline #[cfg(test)] mod is test scope, not a production minter",
            &[ROW_SINGLE_MINTER],
            ov4,
        ));

        // GREEN 2: a mint spelled in a doc comment is prose.
        let mut ov5 = Overlay::new();
        ov5.set(
            outsider,
            format!(
                "{otext}\n/// let seal = KernelSeal::acquire_for_kernel();\npub fn \
                 __seal_witness_doc() {{}}\n"
            ),
        );
        report.push(prove_rows_green(
            cx,
            self,
            "a mint in a doc comment is prose, not a production minter",
            &[ROW_SINGLE_MINTER],
            ov5,
        ));

        // RED 4..11 (X5 finding 11): THE MINT IN EVERY OTHER SPELLING. The minter row used to match
        // the one string `KernelSeal::acquire_for_kernel(` on a single line; each plant below
        // obtains the same seal from the same non-kernel `src/lib.rs` without that string.
        let spellings: [(&str, &str); 8] = [
            (
                "a mint through a `use … as` rename of KernelSeal is RED",
                "use crate::caps::KernelSeal as __SwSeal;\npub fn __seal_witness_forge() { let _ = __SwSeal::acquire_for_kernel(); }\n",
            ),
            (
                "a mint through a grouped `use {…, KernelSeal as K, …}` rename is RED",
                "use crate::caps::{Grant, KernelSeal as __SwGroup, Pass};\npub fn __seal_witness_forge() { let _ = __SwGroup::acquire_for_kernel(); }\n",
            ),
            (
                "a mint through a `type S = KernelSeal;` alias is RED",
                "type __SwType = crate::caps::KernelSeal;\npub fn __seal_witness_forge() { let _ = __SwType::acquire_for_kernel(); }\n",
            ),
            (
                "a mint whose call is split across two lines is RED",
                "pub fn __seal_witness_forge() {\n    let _ = KernelSeal::\n        acquire_for_kernel();\n}\n",
            ),
            (
                "a mint through the qualified path `<KernelSeal>::acquire_for_kernel(` is RED",
                "pub fn __seal_witness_forge() { let _ = <KernelSeal>::acquire_for_kernel(); }\n",
            ),
            (
                "a mint spelled with whitespace around `::` and before `(` is RED",
                "pub fn __seal_witness_forge() { let _ = KernelSeal :: acquire_for_kernel (); }\n",
            ),
            (
                "the minter taken as a fn value (no call parenthesis) is RED",
                "pub fn __seal_witness_forge() { let mint: fn() -> KernelSeal = KernelSeal::acquire_for_kernel; let _ = mint(); }\n",
            ),
            (
                "a mint through an alias a SIBLING module introduced is RED",
                "pub fn __seal_witness_forge() { let _ = crate::__seal_witness_alias::SwSibling::acquire_for_kernel(); }\n",
            ),
        ];
        for (name, forge) in spellings {
            let mut ov = Overlay::new();
            ov.set(outsider, format!("{otext}\n{forge}"));
            if forge.contains("__seal_witness_alias") {
                ov.set(
                    "crates/busbar-contract/src/__seal_witness_alias.rs",
                    "pub type SwSibling = crate::caps::KernelSeal;\n",
                );
            }
            report.push(prove_red(
                cx,
                self,
                name,
                &[ROW_SINGLE_MINTER],
                ov,
                &["outside", outsider],
            ));
        }

        // RED 12 (X5 finding 1): THE FLOOR IS THE MEASURED POPULATION. A walk that comes back one
        // file short of it is refused, though it still holds ten times the old floor of 200.
        let all = WalkSpec::new(ROOTS.iter().copied())
            .ext("rs")
            .exclude(EXCLUDE.iter().copied());
        match cx.list(&all) {
            Ok(rels) => {
                let keep = SCAN_FLOOR - 1;
                let mut ov7 = Overlay::new();
                for rel in rels.iter().skip(keep) {
                    ov7.remove(rel);
                }
                let found = format!("found: {keep}");
                report.push(prove_red(
                    cx,
                    self,
                    "a walk one file below the measured population (and far above 200) is refused",
                    &[ROW_NO_SURVIVING, ROW_SINGLE_MINTER],
                    ov7,
                    &["BelowFloor", found.as_str()],
                ));
            }
            Err(e) => report.note_infra_failure(format!("seal-witness selftest: {e}")),
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ITEM 181: the test-target path rule — every shape it must catch, and the production names
    /// it must not over-match.
    #[test]
    fn the_test_target_path_rule_is_anchored() {
        for t in [
            "crates/a/tests/x.rs",
            "crates/a/src/tests/mod.rs",
            "crates/a/src/tests.rs",
            "crates/a/src/test.rs",
            "crates/a/src/hold_tests.rs",
            "crates/a/src/hold_test.rs",
            "crates/a/benches/b.rs",
            "crates/a/examples/e.rs",
        ] {
            assert!(is_test_target_path(t), "{t} is test scope");
        }
        for p in [
            "crates/a/src/attests.rs",
            "crates/a/src/contests.rs",
            "crates/a/src/lib.rs",
            "crates/a/src/latest.rs",
        ] {
            assert!(!is_test_target_path(p), "{p} is production");
        }
    }

    /// ITEM 181: the real tree is green on the minter row — the #65 invariant holds in shipped
    /// code — and a production mint outside the kernel still reds it.
    #[test]
    fn single_minter_is_green_on_the_tree_and_red_on_a_production_mint() {
        let cx = Ctx::workspace().expect("workspace context");
        let rows = SealWitnessGate::rows(&cx);
        let minter = rows.iter().find(|r| r.id == ROW_SINGLE_MINTER).unwrap();
        assert_eq!(minter.status, Status::Pass, "{}", minter.detail);
        let lib = "crates/busbar-contract/src/lib.rs";
        let text = cx.read(lib).unwrap();
        let mut ov = Overlay::new();
        ov.set(
            lib,
            format!("{text}\nfn __f() {{ let _ = KernelSeal::acquire_for_kernel(); }}\n"),
        );
        let rows = SealWitnessGate::rows(&cx.with_overlay(ov));
        let minter = rows.iter().find(|r| r.id == ROW_SINGLE_MINTER).unwrap();
        assert_eq!(minter.status, Status::Fail, "{}", minter.detail);
    }

    fn hits_in(src: &str) -> Vec<(usize, String)> {
        let blanked: Vec<String> = scan::test_scope(src)
            .into_iter()
            .map(|l| l.counted)
            .collect();
        let aliases = close_aliases(&alias_edges(&blanked.join("\n")));
        let joined = blanked.join("\n");
        let resolves = |r: &str| match r {
            "Self" => impls_seal(&joined, &aliases),
            _ => r.starts_with('$') || aliases.contains(r),
        };
        minter_hits(src, &resolves)
    }

    /// X5 FINDING 11: every spelling of the mint resolves to the seal, on the line of the fn name.
    #[test]
    fn every_spelling_of_the_mint_resolves() {
        for (src, line, via) in [
            (
                "fn f() { KernelSeal::acquire_for_kernel(); }",
                0,
                "KernelSeal",
            ),
            (
                "use a::b::KernelSeal as S;\nfn f() { S::acquire_for_kernel(); }",
                1,
                "S",
            ),
            (
                "use a::{B, KernelSeal as K, c::D};\nfn f() { K::acquire_for_kernel(); }",
                1,
                "K",
            ),
            (
                "use a::{b::{KernelSeal as N}};\nfn f() { N::acquire_for_kernel(); }",
                1,
                "N",
            ),
            (
                "use a::KernelSeal::{self as Z};\nfn f() { Z::acquire_for_kernel(); }",
                1,
                "Z",
            ),
            (
                "type T<X> = crate::caps::KernelSeal;\nfn f() { T::acquire_for_kernel(); }",
                1,
                "T",
            ),
            (
                "type A = KernelSeal;\nuse m::A as B;\nfn f() { B::acquire_for_kernel(); }",
                2,
                "B",
            ),
            (
                "fn f() { <KernelSeal>::acquire_for_kernel(); }",
                0,
                "KernelSeal",
            ),
            (
                "fn f() { <KernelSeal as Tr>::acquire_for_kernel(); }",
                0,
                "KernelSeal",
            ),
            (
                "fn f() { KernelSeal :: acquire_for_kernel (); }",
                0,
                "KernelSeal",
            ),
            (
                "fn f() { KernelSeal::r#acquire_for_kernel(); }",
                0,
                "KernelSeal",
            ),
            (
                "fn f() {\n    let _ = KernelSeal::\n        acquire_for_kernel\n        ();\n}",
                2,
                "KernelSeal",
            ),
            (
                "fn f() { let m = a::KernelSeal::acquire_for_kernel; }",
                0,
                "KernelSeal",
            ),
            (
                "impl KernelSeal { fn g() -> Self { Self::acquire_for_kernel() } }",
                0,
                "Self",
            ),
            (
                "macro_rules! m { ($t:ty) => { <$t>::acquire_for_kernel() }; }",
                0,
                "$t",
            ),
        ] {
            assert_eq!(hits_in(src), vec![(line, via.to_string())], "{src}");
        }
    }

    /// ...and what is not a mint stays out: the definition, a literal naming it, a method of that
    /// name, a different type's fn, a longer identifier, and `Self` outside a seal impl.
    #[test]
    fn what_is_not_a_mint_is_not_counted() {
        for src in [
            "impl KernelSeal { pub fn acquire_for_kernel() -> Self { KernelSeal(()) } }",
            "fn f() { let _ = \"pub fn acquire_for_kernel\"; }",
            "fn f(x: X) { x.acquire_for_kernel(); }",
            "fn f() { Other::acquire_for_kernel(); }",
            "fn f() { KernelSeal::acquire_for_kernelx(); }",
            "impl Other { fn g() -> Self { Self::acquire_for_kernel() } }",
            "use a::Other as KernelSealish;\nfn f() { KernelSealish::acquire_for_kernel(); }",
        ] {
            assert!(hits_in(src).is_empty(), "{src}");
        }
    }

    /// The census is kept: an ALIASED mint in an inline `#[cfg(test)]` mod is counted there, and
    /// the same mint outside it reds the minter row naming the alias it came through.
    #[test]
    fn aliased_mints_keep_the_census_split() {
        let cx = Ctx::workspace().expect("workspace context");
        let lib = "crates/busbar-contract/src/lib.rs";
        let text = cx.read(lib).unwrap();
        let base = SealWitnessGate::rows(&cx);
        let census = |rows: &[Row]| {
            rows.iter()
                .find(|r| r.id == ROW_TEST_MINTS)
                .unwrap()
                .detail
                .clone()
        };
        let mut ov = Overlay::new();
        ov.set(
            lib,
            format!(
                "{text}\n#[cfg(test)]\nmod __p {{\n    use crate::caps::KernelSeal as S;\n    fn f() {{ \
                 let _ = S::acquire_for_kernel(); }}\n}}\n"
            ),
        );
        let rows = SealWitnessGate::rows(&cx.with_overlay(ov));
        let minter = rows.iter().find(|r| r.id == ROW_SINGLE_MINTER).unwrap();
        assert_eq!(minter.status, Status::Pass, "{}", minter.detail);
        assert_ne!(
            census(&rows),
            census(&base),
            "the aliased test mint is counted"
        );
        assert!(census(&rows).contains(lib), "{}", census(&rows));

        let mut ov = Overlay::new();
        ov.set(
            lib,
            format!("{text}\nuse crate::caps::KernelSeal as S;\nfn f() {{ let _ = S::acquire_for_kernel(); }}\n"),
        );
        let rows = SealWitnessGate::rows(&cx.with_overlay(ov));
        let minter = rows.iter().find(|r| r.id == ROW_SINGLE_MINTER).unwrap();
        assert_eq!(minter.status, Status::Fail, "{}", minter.detail);
        assert!(minter.detail.contains("(via `S`)"), "{}", minter.detail);
    }
}
