//! `cargo xtask gate abi-location` — EVERY ABI SHAPE IS DEFINED IN ONE PLACE:
//! `crates/busbar-contract/src/abi/`.
//!
//! > "edit one crate to add something to abi and all those plugin kinds then can implement it"
//! > — OWNER, 2026-09-27
//!
//! That sentence is only true while the ABI has exactly one home. A `#[repr(C)]` struct written in
//! the kernel, an `extern "C"` slot body hand-typed in the loader, a version constant minted in a
//! plugin-side crate: each one is a piece of the boundary that the next kind cannot reach by
//! editing `abi/`, because it is not there. This gate names every such piece, file by file.
//!
//! ## WHAT COUNTS AS AN ABI SHAPE
//!
//! * **`repr-c`** — a `#[repr(C …)]` struct, enum or union. `#[repr(u8)]`/`#[repr(transparent)]`
//!   alone are not counted: they fix a discriminant or a wrapper, not a C layout, and the tree uses
//!   them for on-disk frames and newtypes that never meet a plugin.
//! * **`extern-fn`** — an `extern "C"` / `extern "C-unwind"` / `extern "system"` fn DEFINITION
//!   whose signature is NOT one of the ABI's fn types: a slot signature invented outside `abi/`.
//!   A definition whose parameter and return types EQUAL an `extern "C…" fn(…)` pointer type
//!   written under `abi/` (`Op`, `DoorFn`, `WakeFn`, …) is an IMPLEMENTATION of that shape, not a
//!   shape — every plugin holds them — and is not counted (ARCHITECT ruling, M1). Types compare
//!   whitespace-free with lower-case module paths dropped (`std::os::raw::c_void` = `c_void`). The
//!   bare `extern "C" fn()` type excuses nothing: every argument-less callback would match it.
//!   `extern "C" { … }` import blocks are not definitions and are not counted.
//! * **`fn-ptr`** — an `extern "C…" fn(…)` pointer TYPE written outside `abi/`: a slot signature
//!   spelled a second time. Keyed by its ordinal in the file (`fn-ptr-1`, …), since a type has no
//!   name of its own and a line number rots.
//! * **`version-const`** — a `const`/`static` whose SCREAMING name has an `ABI` segment
//!   (`STORE_ABI`, `ABI_MINOR`, `UNIT_MAP_ABI`, …), is `POD_VERSION`, or whose type is
//!   `AbiVersion`. `CAPABILITIES`/`REACHABILITY` are not `ABI` segments and are not counted.
//!
//! ## WHERE A SHAPE MAY STILL BE WRITTEN OUTSIDE `abi/`
//!
//! Only as a TEST DOUBLE: under a `tests/` directory, under `benches/` (a bench harness is a test
//! target — it never links into a shipped artifact, and the kernel's host-vtable benches stub two
//! slots to time the real table), or inside `#[cfg(test)]` (via [`crate::scan::test_scope`], the one
//! answer to "is this line test code"). Comments and string literals never count: every match reads
//! the literal- and comment-blanked line.
//!
//! ## THE LEDGER — `qa/abi-location.toml`, DRAIN-ONLY (LAW 9)
//!
//! The gate was armed at the count it measured on the day it landed: one `[[offender]]` row per
//! shape outside `abi/`, keyed `(file, shape, item)` — never a line number. The rows are the work
//! list of the one-ABI kernel-side slot, and the ledger only ever shrinks:
//!
//! * a finding with no row is a NEW offender and reds its shape row (`abi-location:repr-c`,
//!   `:extern-fn`, `:version-const`) — the fix is to define it in `abi/`, not to add a row;
//! * a row with no finding is STALE and reds `abi-location:ledger` — a drain strikes its row in the
//!   SAME commit, so the count on record is always the count in the tree.
//!
//! `[[not_abi]]` names the rare `extern "C"` fn that is NOT a plugin/host slot (an `atexit(3)`
//! callback), each with a `why`; a stale one is red on the ledger row like any other.
//!
//! ## EXTERNAL PLUGIN CHECKOUTS
//!
//! Every plugin `plugins.yaml` registers is looked for as a local clone under `[external].root`
//! (default `..`, the sibling-checkout convention `release-check.sh` and qa-gate use), by its `repo`
//! name or that name without its `busbar-` prefix. A clone that exists is scanned by the same rules
//! (its `tests/`, `benches/`, `target/` skipped) and held to the ledger's rows that carry
//! `repo = "<repo>"`; one that does not exist is SKIPPED AND NAMED in the row's detail — never a
//! silent green. CI checks out no siblings, so there the row says exactly that.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan::{self, ScopeLine};

pub const ROW_REPR_C: &str = "abi-location:repr-c";
pub const ROW_EXTERN: &str = "abi-location:extern-fn";
pub const ROW_CONST: &str = "abi-location:version-const";
pub const ROW_LEDGER: &str = "abi-location:ledger";
pub const ROW_EXTERNAL: &str = "abi-location:external-plugins";

pub const LEDGER: &str = "qa/abi-location.toml";
/// THE ONE HOME. Everything under it is the ABI; nothing outside it may define a piece of it.
pub const ONE_HOME: &str = "crates/busbar-contract/src/abi/";

/// The workspace scan's floor: the tree holds well over a thousand Rust files, and a scan that saw
/// a fraction of them has gone blind rather than found a clean tree.
const MIN_FILES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    ReprC,
    ExternFn,
    FnPtr,
    VersionConst,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Shape::ReprC => "repr-c",
            Shape::ExternFn => "extern-fn",
            Shape::FnPtr => "fn-ptr",
            Shape::VersionConst => "version-const",
        }
    }

    fn parse(s: &str) -> Option<Shape> {
        [
            Shape::ReprC,
            Shape::ExternFn,
            Shape::FnPtr,
            Shape::VersionConst,
        ]
        .into_iter()
        .find(|k| k.label() == s)
    }

    fn row(self) -> &'static str {
        match self {
            Shape::ReprC => ROW_REPR_C,
            Shape::ExternFn | Shape::FnPtr => ROW_EXTERN,
            Shape::VersionConst => ROW_CONST,
        }
    }
}

/// One shape found outside `abi/`.
#[derive(Debug, Clone)]
struct Finding {
    /// Empty for the workspace; the `plugins.yaml` repo name for an external checkout.
    repo: String,
    file: String,
    line: usize,
    shape: Shape,
    item: String,
}

impl Finding {
    fn key(&self) -> Key {
        (
            self.repo.clone(),
            self.file.clone(),
            self.shape,
            self.item.clone(),
        )
    }

    fn describe(&self) -> String {
        let at = if self.repo.is_empty() {
            format!("{}:{}", self.file, self.line)
        } else {
            format!("{}:{}:{}", self.repo, self.file, self.line)
        };
        format!("{} {at} {}", self.shape.label(), self.item)
    }
}

type Key = (String, String, Shape, String);

fn describe_key(k: &Key) -> String {
    let at = if k.0.is_empty() {
        k.1.clone()
    } else {
        format!("{}:{}", k.0, k.1)
    };
    format!("{} {at} {}", k.2.label(), k.3)
}

// ── THE SCANNER ─────────────────────────────────────────────────────────────────────────────────

/// Is `rel` a place a test double may live? `tests/` or `benches/` anywhere in the path.
fn is_test_path(rel: &str) -> bool {
    let p = format!("/{rel}");
    p.contains("/tests/") || p.contains("/benches/")
}

/// Every ABI shape in one file's PRODUCTION lines. `sigs` are the ABI's fn types: a definition
/// with one of them implements it and is not a finding.
fn scan_file(repo: &str, rel: &str, text: &str, sigs: &BTreeSet<Sig>) -> Vec<Finding> {
    let lines = scan::test_scope(text);
    let mut out = Vec::new();
    for (idx, sl) in lines.iter().enumerate() {
        if sl.gated || sl.is_comment {
            continue;
        }
        let counted = sl.counted.as_str();
        let mut push = |shape: Shape, item: String| {
            out.push(Finding {
                repo: repo.to_string(),
                file: rel.to_string(),
                line: sl.no,
                shape,
                item,
            })
        };
        if is_repr_c(counted) {
            push(Shape::ReprC, item_after(&lines, idx));
        }
        if let Some(name) = version_const(counted) {
            push(Shape::VersionConst, name);
        }
    }
    let text = Joined::of(&lines);
    let mut fn_ptrs = 0usize;
    for item in extern_items(&text.counted, &text.raw) {
        let line = text.line_of(item.at);
        match item.name {
            Some(name) => {
                if item.sig.as_ref().is_some_and(|sig| sigs.contains(sig)) {
                    continue;
                }
                out.push(Finding {
                    repo: repo.to_string(),
                    file: rel.to_string(),
                    line,
                    shape: Shape::ExternFn,
                    item: name,
                });
            }
            None => {
                fn_ptrs += 1;
                out.push(Finding {
                    repo: repo.to_string(),
                    file: rel.to_string(),
                    line,
                    shape: Shape::FnPtr,
                    item: format!("fn-ptr-{fn_ptrs}"),
                });
            }
        }
    }
    out
}

/// A slot signature: its parameter types and its return type (`""` for none), normalised.
type Sig = (Vec<String>, String);

/// THE ABI'S FN TYPES: the signature of every `extern "C…" fn(…)` pointer type written in `texts`
/// (the files under `abi/`).
fn abi_signatures<'a>(texts: impl IntoIterator<Item = &'a str>) -> BTreeSet<Sig> {
    let mut out = BTreeSet::new();
    for text in texts {
        let lines = scan::test_scope(text);
        let joined = Joined::of(&lines);
        out.extend(
            extern_items(&joined.counted, &joined.raw)
                .into_iter()
                .filter(|i| i.name.is_none())
                .filter_map(|i| i.sig)
                // A bare `extern "C" fn()` (the `.init_array` constructor type) names no slot: it
                // would excuse every argument-less callback (an `atexit(3)` hook, a stray slot).
                .filter(|sig| !(sig.0.is_empty() && sig.1.is_empty())),
        );
    }
    out
}

/// The workspace's ABI fn types, read off `abi/`.
fn workspace_signatures(cx: &Ctx) -> Result<BTreeSet<Sig>, String> {
    let files = cx
        .walk(&WalkSpec::new([ONE_HOME]).ext("rs"))
        .map_err(|e| e.to_string())?;
    Ok(abi_signatures(files.iter().map(|f| f.text.as_str())))
}

/// A file's production text, one string: test-gated and comment lines blanked to spaces, so an
/// item spanning lines reads whole and its offset maps back to its line.
struct Joined {
    counted: Vec<char>,
    raw: Vec<char>,
    /// `(first char offset, line number)` of every line.
    starts: Vec<(usize, usize)>,
}

impl Joined {
    fn of(lines: &[ScopeLine]) -> Joined {
        let (mut counted, mut raw, mut starts) = (Vec::new(), Vec::new(), Vec::new());
        for sl in lines {
            starts.push((counted.len(), sl.no));
            let c: Vec<char> = sl.counted.chars().collect();
            if sl.gated || sl.is_comment {
                counted.extend(std::iter::repeat_n(' ', c.len()));
                raw.extend(std::iter::repeat_n(' ', c.len()));
            } else {
                let r: Vec<char> = sl.raw.chars().collect();
                // The ABI string is read back from the raw line only where the blanker kept every
                // character in place, as the line-by-line reading did.
                if r.len() == c.len() {
                    raw.extend(r);
                } else {
                    raw.extend(std::iter::repeat_n(' ', c.len()));
                }
                counted.extend(c);
            }
            counted.push('\n');
            raw.push('\n');
        }
        Joined {
            counted,
            raw,
            starts,
        }
    }

    fn line_of(&self, at: usize) -> usize {
        let i = self.starts.partition_point(|(off, _)| *off <= at);
        self.starts
            .get(i.saturating_sub(1))
            .map_or(0, |(_, no)| *no)
    }
}

/// A line that IS a `#[repr(…)]` attribute naming `C` among its representation hints.
fn is_repr_c(counted: &str) -> bool {
    let t = counted.trim_start();
    let Some(rest) = t.strip_prefix("#[repr(") else {
        return false;
    };
    let inner = rest.split(')').next().unwrap_or("");
    inner.split(',').any(|h| h.trim() == "C")
}

/// The name of the struct/enum/union a `#[repr(C)]` attribute applies to: the first
/// `struct|enum|union IDENT` in the next few lines (doc comments and further attributes between).
fn item_after(lines: &[ScopeLine], idx: usize) -> String {
    for sl in lines.iter().skip(idx).take(16) {
        let words = idents(&sl.counted);
        for w in words.windows(2) {
            if matches!(w[0].as_str(), "struct" | "enum" | "union") {
                return w[1].clone();
            }
        }
    }
    "?".to_string()
}

/// The identifier-shaped words of a line, in order.
fn idents(s: &str) -> Vec<String> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// One `extern "C…" fn`: where it starts, its name (`None` for a pointer type) and its signature.
struct ExternItem {
    at: usize,
    name: Option<String>,
    sig: Option<Sig>,
}

/// Every `extern "C…" fn` in a joined text: definitions (named) and pointer types (unnamed).
///
/// Read off the BLANKED text so a comment or a string holding the words cannot match; the ABI
/// string itself is a literal, so its contents are read back from the raw text at the same
/// position (the blanker keeps every character in place).
fn extern_items(c: &[char], r: &[char]) -> Vec<ExternItem> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 6 <= c.len() {
        if !word_at(c, i, "extern") {
            i += 1;
            continue;
        }
        let at = i;
        let mut j = skip_ws(c, i + 6);
        if c.get(j) != Some(&'"') {
            i += 6;
            continue;
        }
        let open = j;
        j += 1;
        while j < c.len() && c[j] != '"' && c[j] != '\n' {
            j += 1;
        }
        if j >= c.len() || c[j] != '"' {
            i = j;
            continue;
        }
        let abi: String = r
            .get(open + 1..j)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        let k = skip_ws(c, j + 1);
        i = j + 1;
        if !matches!(abi.as_str(), "C" | "C-unwind" | "system" | "system-unwind") {
            continue;
        }
        if !word_at(c, k, "fn") {
            // `extern "C" { … }` — an import block, not a slot.
            continue;
        }
        let n = skip_ws(c, k + 2);
        if c.get(n) == Some(&'(') {
            out.push(ExternItem {
                at,
                name: None,
                sig: signature(c, n),
            });
        } else {
            let name: String = c[n..]
                .iter()
                .take_while(|ch| ch.is_ascii_alphanumeric() || **ch == '_' || **ch == '$')
                .collect();
            let mut p = skip_ws(c, n + name.chars().count());
            if c.get(p) == Some(&'<') {
                p = skip_ws(c, close_of(c, p).map_or(c.len(), |e| e + 1));
            }
            let sig = (c.get(p) == Some(&'(')).then(|| signature(c, p)).flatten();
            out.push(ExternItem {
                at,
                name: Some(if name.is_empty() { "?".into() } else { name }),
                sig,
            });
        }
    }
    out
}

/// The index of the bracket closing the one at `open` (`(`, `[` or `<`), skipping `->`.
fn close_of(c: &[char], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open;
    while i < c.len() {
        match c[i] {
            '-' if c.get(i + 1) == Some(&'>') => i += 1,
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The signature whose parameter list opens at `open`: `(types…) -> ret`.
fn signature(c: &[char], open: usize) -> Option<Sig> {
    let close = close_of(c, open)?;
    let mut params = Vec::new();
    let (mut depth, mut from) = (0i32, open + 1);
    let mut i = open + 1;
    while i <= close {
        match c[i] {
            '-' if c.get(i + 1) == Some(&'>') => i += 1,
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' if i < close => depth -= 1,
            ',' if depth == 0 => {
                params.push(param_type(&c[from..i]));
                from = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    params.push(param_type(&c[from..close]));
    params.retain(|p| !p.is_empty());
    let mut k = skip_ws(c, close + 1);
    let mut ret = String::new();
    if c.get(k) == Some(&'-') && c.get(k + 1) == Some(&'>') {
        k += 2;
        let (mut depth, start) = (0i32, k);
        while k < c.len() {
            match c[k] {
                '-' if c.get(k + 1) == Some(&'>') => k += 1,
                '(' | '[' | '<' => depth += 1,
                ')' | ']' | '>' if depth == 0 => break,
                ')' | ']' | '>' => depth -= 1,
                '{' | ';' | ',' | '=' if depth == 0 => break,
                _ if depth == 0 && word_at(c, k, "where") => break,
                _ => {}
            }
            k += 1;
        }
        ret = normalise_type(&c[start..k.min(c.len())]);
    }
    Some((params, ret))
}

/// A parameter's type: what follows its top-level `name:` (a `::` is a path, not the colon).
fn param_type(p: &[char]) -> String {
    let mut depth = 0i32;
    for (i, ch) in p.iter().enumerate() {
        match ch {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth -= 1,
            ':' if depth == 0 && p.get(i + 1) != Some(&':') && (i == 0 || p[i - 1] != ':') => {
                return normalise_type(&p[i + 1..]);
            }
            _ => {}
        }
    }
    normalise_type(p)
}

/// A type, whitespace-free, with lower-case module path segments dropped. Segments are read
/// before the whitespace goes, so `*mut std::x` keeps its `mut`.
fn normalise_type(t: &[char]) -> String {
    let ident = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    let mut out = String::new();
    let mut i = 0;
    while i < t.len() {
        if (t[i].is_ascii_alphabetic() || t[i] == '_') && (i == 0 || !ident(t[i - 1])) {
            let end = i + t[i..].iter().take_while(|ch| ident(**ch)).count();
            let after = skip_ws(t, end);
            let is_module = t[i].is_ascii_lowercase() || t[i] == '_';
            if is_module && t.get(after) == Some(&':') && t.get(after + 1) == Some(&':') {
                i = skip_ws(t, after + 2);
                continue;
            }
            out.extend(&t[i..end]);
            i = end;
            continue;
        }
        if !t[i].is_whitespace() {
            out.push(t[i]);
        }
        i += 1;
    }
    out
}

fn skip_ws(c: &[char], mut i: usize) -> usize {
    while i < c.len() && c[i].is_whitespace() {
        i += 1;
    }
    i
}

/// `word` at `i`, bounded by non-identifier characters on both sides.
fn word_at(c: &[char], i: usize, word: &str) -> bool {
    let w: Vec<char> = word.chars().collect();
    if i + w.len() > c.len() || c[i..i + w.len()] != w[..] {
        return false;
    }
    let ident = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    let before = i == 0 || !ident(c[i - 1]);
    let after = i + w.len() == c.len() || !ident(c[i + w.len()]);
    before && after
}

/// The name of an ABI version constant declared on this line, if it declares one.
fn version_const(counted: &str) -> Option<String> {
    let c: Vec<char> = counted.chars().collect();
    let mut i = 0;
    while i < c.len() {
        let kw = if word_at(&c, i, "const") {
            5
        } else if word_at(&c, i, "static") {
            6
        } else {
            i += 1;
            continue;
        };
        let mut j = skip_ws(&c, i + kw);
        if word_at(&c, j, "mut") {
            j = skip_ws(&c, j + 3);
        }
        let name: String = c[j..]
            .iter()
            .take_while(|ch| ch.is_ascii_alphanumeric() || **ch == '_')
            .collect();
        let after = skip_ws(&c, j + name.chars().count());
        i += kw;
        if name.is_empty() || c.get(after) != Some(&':') || c.get(after + 1) == Some(&':') {
            continue;
        }
        if !name.chars().any(|ch| ch.is_ascii_uppercase())
            || name.chars().any(|ch| ch.is_ascii_lowercase())
        {
            continue;
        }
        let ty: String = c[after + 1..]
            .iter()
            .take_while(|ch| **ch != '=' && **ch != ';')
            .collect();
        let abi_segment = name.split('_').any(|seg| seg == "ABI");
        let pod = name == "POD_VERSION" || name.ends_with("_POD_VERSION");
        let typed = idents(&ty).iter().any(|w| w == "AbiVersion");
        // A VERSION IS A NUMBER. The name alone made a path prefix a version constant
        // (`CONTRACT_ABI_PREFIX: &str = "crates/busbar-contract/src/abi/"`): a `&str`, a byte
        // slice or a path cannot hold a version, so only an `AbiVersion` or a bare integer counts.
        let integer = matches!(
            ty.trim(),
            "u8" | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
        );
        if typed || ((abi_segment || pod) && integer) {
            return Some(name);
        }
    }
    None
}

// ── THE LEDGER ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Ledger {
    offenders: Vec<Key>,
    /// `(file, item)` of an `extern "C"` fn that is not a plugin/host slot.
    not_abi: Vec<(String, String)>,
    external_root: String,
    errors: Vec<String>,
}

fn load_ledger(cx: &Ctx) -> Ledger {
    let text = match cx.read(LEDGER) {
        Ok(t) => t,
        Err(e) => {
            return Ledger {
                external_root: "..".into(),
                errors: vec![format!(
                    "{LEDGER} is unreadable ({e}); every shape outside {ONE_HOME} is therefore NEW"
                )],
                ..Ledger::default()
            }
        }
    };
    let doc = crate::toml_lite::parse_text(&text);
    let mut led = Ledger {
        external_root: doc
            .table("external")
            .get_one("root")
            .unwrap_or("..")
            .to_string(),
        ..Ledger::default()
    };
    for (n, t) in doc.array_table("offender").iter().enumerate() {
        let file = t.get_one("file").unwrap_or("").to_string();
        let item = t.get_one("item").unwrap_or("").to_string();
        let repo = t.get_one("repo").unwrap_or("").to_string();
        let shape = t.get_one("shape").unwrap_or("");
        match Shape::parse(shape) {
            Some(s) if !file.is_empty() && !item.is_empty() => {
                led.offenders.push((repo, file, s, item))
            }
            _ => led.errors.push(format!(
                "[[offender]] #{}: needs file, item and a shape of repr-c|extern-fn|fn-ptr|version-const (got shape `{shape}`, file `{file}`, item `{item}`)",
                n + 1
            )),
        }
    }
    for (n, t) in doc.array_table("not_abi").iter().enumerate() {
        let file = t.get_one("file").unwrap_or("").to_string();
        let item = t.get_one("item").unwrap_or("").to_string();
        let why = t.get_one("why").unwrap_or("").trim().to_string();
        if file.is_empty() || item.is_empty() || why.is_empty() {
            led.errors.push(format!(
                "[[not_abi]] #{}: needs file, item and a `why` (an extern \"C\" fn is a slot unless a reason says otherwise)",
                n + 1
            ));
        } else {
            led.not_abi.push((file, item));
        }
    }
    led
}

/// `want` minus `have`, as multisets.
fn minus(want: &[Key], have: &[Key]) -> Vec<Key> {
    let mut left: BTreeMap<&Key, usize> = BTreeMap::new();
    for k in have {
        *left.entry(k).or_default() += 1;
    }
    let mut out = Vec::new();
    for k in want {
        match left.get_mut(k) {
            Some(n) if *n > 0 => *n -= 1,
            _ => out.push(k.clone()),
        }
    }
    out
}

// ── EXTERNAL CHECKOUTS ──────────────────────────────────────────────────────────────────────────

struct External {
    findings: Vec<Finding>,
    scanned: Vec<String>,
    absent: Vec<String>,
    errors: Vec<String>,
    root: PathBuf,
}

fn scan_external(cx: &Ctx, root_decl: &str, sigs: &BTreeSet<Sig>) -> External {
    let root = {
        let p = Path::new(root_decl);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            cx.root().join(p)
        }
    };
    let mut ext = External {
        findings: Vec::new(),
        scanned: Vec::new(),
        absent: Vec::new(),
        errors: Vec::new(),
        root: root.clone(),
    };
    let fleet = match crate::fleet::registry::load(cx) {
        Ok(f) => f,
        Err(e) => {
            ext.errors.push(format!(
                "plugins.yaml could not be read as the plugin registry: {e}"
            ));
            return ext;
        }
    };
    for p in &fleet.plugins {
        let candidates = [
            p.repo.clone(),
            p.repo
                .strip_prefix("busbar-")
                .unwrap_or(&p.repo)
                .to_string(),
        ];
        let Some(dir) = candidates
            .iter()
            .map(|c| root.join(c))
            .find(|d| d.join("Cargo.toml").is_file())
        else {
            ext.absent.push(p.repo.clone());
            continue;
        };
        let mut files = Vec::new();
        collect_rs(&dir, &dir, &mut files);
        files.sort();
        ext.scanned.push(format!(
            "{} ({} files, {})",
            p.repo,
            files.len(),
            dir.display()
        ));
        for rel in files {
            if is_test_path(&rel) {
                continue;
            }
            match std::fs::read_to_string(dir.join(&rel)) {
                Ok(text) => ext.findings.extend(scan_file(&p.repo, &rel, &text, sigs)),
                Err(e) => ext.errors.push(format!("{}:{rel}: {e}", p.repo)),
            }
        }
    }
    ext
}

/// Every `.rs` under `dir`, relative, skipping build output, VCS and hidden directories.
fn collect_rs(base: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if name == "target" || name.starts_with('.') || name == "node_modules" {
                continue;
            }
            collect_rs(base, &path, out);
        } else if name.ends_with(".rs") {
            if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

/// Where the self-test plants a plugin crate's source.
const PLUGIN_PLANT: &str = "crates/hook-test-plugin/src/planted_impl.rs";
/// A plugin's `Op` and `DoorFn` bodies: implementations of abi/'s fn types, never findings.
const PLUGIN_IMPLS: &str = "use std::os::raw::c_void;\n\
     pub extern \"C\" fn planted_op(\n    instance: *mut c_void,\n    input: *const c_void,\n    \
     out: *mut c_void,\n) -> busbar_contract::abi::mechanism::call::RawOutcome {\n    todo!()\n}\n\
     #[no_mangle]\npub extern \"C\" fn busbar_plugin_door() -> *const Door {\n    todo!()\n}\n";
/// A plugin's own shapes: a #[repr(C)] struct and a slot signature abi/ does not have.
const PLUGIN_SHAPES: &str = "#[repr(C)]\npub struct PlantedPluginPod {\n    pub a: u32,\n}\n\
     pub extern \"C\" fn planted_own_slot(x: u32) -> u32 {\n    x\n}\n";

// ── THE GATE ────────────────────────────────────────────────────────────────────────────────────

pub struct AbiLocationGate;

impl AbiLocationGate {
    fn workspace_findings(cx: &Ctx) -> Result<Vec<Finding>, String> {
        let files = cx
            .walk(
                &WalkSpec::new(["."])
                    .ext("rs")
                    .exclude(["/target/", "/.fix/", "/.git/"])
                    .min_files(MIN_FILES),
            )
            .map_err(|e| e.to_string())?;
        let rel_of = |f: &crate::ctx::SourceFile| {
            let rel = f.rel_str();
            rel.strip_prefix("./").unwrap_or(&rel).to_string()
        };
        let sigs = abi_signatures(
            files
                .iter()
                .filter(|f| rel_of(f).starts_with(ONE_HOME))
                .map(|f| f.text.as_str()),
        );
        let mut out = Vec::new();
        for f in &files {
            let rel = rel_of(f);
            if rel.starts_with(ONE_HOME) || is_test_path(&rel) {
                continue;
            }
            out.extend(scan_file("", &rel, &f.text, &sigs));
        }
        Ok(out)
    }
}

impl Gate for AbiLocationGate {
    fn name(&self) -> &'static str {
        "abi-location"
    }

    fn owed(&self) -> Vec<String> {
        [ROW_REPR_C, ROW_EXTERN, ROW_CONST, ROW_LEDGER, ROW_EXTERNAL]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let ledger = load_ledger(cx);
        let found = match Self::workspace_findings(cx) {
            Ok(f) => f,
            Err(e) => {
                let why = format!(
                    "the workspace scan did not run ({e}); an unread tree reads exactly like a clean one"
                );
                return Verdict::of(
                    self.owed()
                        .iter()
                        .map(|id| {
                            Row::fail(
                                id.clone(),
                                "the workspace could not be scanned",
                                why.clone(),
                            )
                        })
                        .collect(),
                );
            }
        };

        // The not-a-slot exclusions, each used at most once and each required to still match.
        let mut not_abi_left = ledger.not_abi.clone();
        let found: Vec<Finding> = found
            .into_iter()
            .filter(|f| {
                if f.shape != Shape::ExternFn {
                    return true;
                }
                match not_abi_left
                    .iter()
                    .position(|(file, item)| *file == f.file && *item == f.item)
                {
                    Some(i) => {
                        not_abi_left.remove(i);
                        false
                    }
                    None => true,
                }
            })
            .collect();

        let ws_ledger: Vec<Key> = ledger
            .offenders
            .iter()
            .filter(|k| k.0.is_empty())
            .cloned()
            .collect();
        let keys: Vec<Key> = found.iter().map(Finding::key).collect();
        let new_keys = minus(&keys, &ws_ledger);
        let stale = minus(&ws_ledger, &keys);

        let mut rows = Vec::new();
        for (row, shapes, what) in [
            (ROW_REPR_C, &[Shape::ReprC][..], "#[repr(C)] type"),
            (
                ROW_EXTERN,
                &[Shape::ExternFn, Shape::FnPtr][..],
                "extern \"C\" slot fn or fn-pointer type",
            ),
            (
                ROW_CONST,
                &[Shape::VersionConst][..],
                "ABI version constant",
            ),
        ] {
            let ledgered = ws_ledger.iter().filter(|k| shapes.contains(&k.2)).count();
            // New offenders, described with their line, drawn from the findings themselves.
            let mut pending = new_keys.clone();
            let mut new: Vec<String> = Vec::new();
            for f in found.iter().filter(|f| shapes.contains(&f.shape)) {
                if let Some(i) = pending.iter().position(|k| *k == f.key()) {
                    pending.remove(i);
                    new.push(f.describe());
                }
            }
            if new.is_empty() {
                rows.push(Row::pass(
                    row,
                    format!("no NEW {what} outside {ONE_HOME}"),
                    format!("{ledgered} ledgered in {LEDGER} (drain-only work list), 0 new"),
                ));
            } else {
                rows.push(Row::fail(
                    row,
                    format!("ABI shape outside {ONE_HOME}: {what}"),
                    format!(
                        "{} new: {} — define it in {ONE_HOME} (one place for every ABI shape, OWNER 2026-09-27); {ledgered} already ledgered",
                        new.len(),
                        new.join(" | ")
                    ),
                ));
            }
            debug_assert!(row == shapes[0].row());
        }

        let mut ledger_problems: Vec<String> = ledger.errors.clone();
        ledger_problems.extend(stale.iter().map(|k| {
            format!(
                "STALE row (no such shape in the tree — strike it in the draining commit): {}",
                describe_key(k)
            )
        }));
        ledger_problems.extend(not_abi_left.iter().map(|(file, item)| {
            format!("STALE [[not_abi]] {file} {item}: no such extern \"C\" fn")
        }));
        if ledger_problems.is_empty() {
            rows.push(Row::pass(
                ROW_LEDGER,
                "every ledger row names a shape still in the tree",
                format!(
                    "{} offender rows ({} workspace), {} not-a-slot exclusions; the count only drains",
                    ledger.offenders.len(),
                    ws_ledger.len(),
                    ledger.not_abi.len()
                ),
            ));
        } else {
            rows.push(Row::fail(
                ROW_LEDGER,
                format!("{LEDGER} does not match the tree"),
                ledger_problems.join(" | "),
            ));
        }

        rows.push(external_row(cx, &ledger));
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree matches its ledger: no new ABI shape outside abi/, no stale row",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // A #[repr(C)] STRUCT IN A KERNEL FILE.
        let kernel = "crates/busbar-kernel/src/lib.rs";
        let mut ov = Overlay::new();
        ov.set(
            kernel,
            format!(
                "{}\n/// planted\n#[repr(C)]\n#[derive(Clone, Copy)]\npub struct PlantedKernelPod {{\n    pub a: u32,\n}}\n",
                cx.read(kernel).unwrap_or_default()
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a #[repr(C)] struct added to a kernel file is RED",
            &[ROW_REPR_C],
            ov,
            &["PlantedKernelPod", kernel],
        ));

        // AN ABI VERSION CONSTANT IN THE PLUGIN LOADER.
        let loader = "crates/plugin-loader/src/lib.rs";
        let mut ov = Overlay::new();
        ov.set(
            loader,
            format!(
                "{}\npub const PLANTED_ABI_VERSION: u32 = 1;\n",
                cx.read(loader).unwrap_or_default()
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "an ABI version const in plugin-loader is RED",
            &[ROW_CONST],
            ov,
            &["PLANTED_ABI_VERSION"],
        ));

        // AN extern "C" SLOT BODY AND A FN-POINTER TYPE IN THE KERNEL, and in a PLUGIN CRATE a
        // #[repr(C)] struct and a slot of a signature abi/ does not have. (AN IMPLEMENTATION IS NOT
        // A SHAPE: that crate's `Op` and `DoorFn` bodies are planted beside them and must not be
        // named.)
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-kernel/src/planted_slot.rs",
            "pub extern \"C-unwind\" fn planted_slot(x: u32) -> u32 { x }\n\
             pub type PlantedPtr = Option<unsafe extern \"C\" fn(u32) -> u32>;\n",
        );
        ov.set(PLUGIN_PLANT, format!("{PLUGIN_IMPLS}{PLUGIN_SHAPES}"));
        report.push(prove_rows_red(
            cx,
            self,
            "an extern \"C\" slot body and a fn-pointer type outside abi/, and a plugin crate's \
             #[repr(C)] struct and unknown slot, are RED",
            &[ROW_EXTERN, ROW_REPR_C],
            ov,
            &[
                "extern-fn crates/busbar-kernel/src/planted_slot.rs:1 planted_slot",
                "fn-ptr-1",
                "PlantedPluginPod",
                "planted_own_slot",
            ],
        ));

        // TEST DOUBLES: under tests/, and under #[cfg(test)], and in comments/strings — all GREEN.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-kernel/tests/planted_double.rs",
            "#[repr(C)]\npub struct Double { pub a: u32 }\n\
             extern \"C-unwind\" fn double_slot() {}\npub const DOUBLE_ABI: u32 = 1;\n",
        );
        ov.set(
            "crates/busbar-kernel/src/planted_cfg_test.rs",
            "/// A `#[repr(C)]` mention and an `extern \"C\" fn x` in prose.\n\
             pub const NOTE: &str = \"#[repr(C)] extern \\\"C\\\" fn y STORE_ABI\";\n\
             #[cfg(test)]\nmod tests {\n    #[repr(C)]\n    pub struct Double { pub a: u32 }\n    \
             extern \"C\" fn double_slot() {}\n    const T_ABI: u32 = 1;\n}\n\
             #[cfg(test)]\nconst ALSO_ABI: u32 = 2;\n",
        );
        ov.set(PLUGIN_PLANT, PLUGIN_IMPLS);
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a repr(C) test double under tests/ or #[cfg(test)], ABI words in prose, and a plugin's \
             extern \"C\" Op and DoorFn bodies (implementations of abi/'s types) are GREEN",
            &[ROW_REPR_C, ROW_EXTERN, ROW_CONST],
        ));

        // THE LEDGER CANNOT OUTLIVE ITS DEBT: a row naming a shape the tree does not hold is RED.
        let ledger = cx.read(LEDGER).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            format!(
                "{ledger}\n[[offender]]\nfile = \"crates/busbar-kernel/src/lib.rs\"\nshape = \"repr-c\"\nitem = \"DrainedLongAgo\"\n"
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a ledger row whose shape was drained (and not struck) is RED",
            &[ROW_LEDGER],
            ov,
            &["DrainedLongAgo"],
        ));

        // AN EXTERNAL CHECKOUT is scanned when present: a fake clone of a registered plugin, with a
        // hand-written slot outside the SDK, under a scratch root the ledger is pointed at.
        let ext_root = cx.scratch().join("abi-location-external");
        let plugin = crate::fleet::registry::load(cx)
            .ok()
            .and_then(|f| f.plugins.first().map(|p| p.repo.clone()))
            .unwrap_or_else(|| "busbar-store-mysql".into());
        let clone = ext_root.join(&plugin);
        let planted = std::fs::create_dir_all(clone.join("src").join("tests"))
            .and_then(|()| std::fs::write(clone.join("Cargo.toml"), "[package]\nname = \"x\"\n"))
            .and_then(|()| {
                std::fs::write(
                    clone.join("src/lib.rs"),
                    "#[no_mangle]\npub extern \"C\" fn busbar_call() {}\n",
                )
            })
            .and_then(|()| {
                std::fs::write(
                    clone.join("src/tests/double.rs"),
                    "#[repr(C)]\npub struct Double { pub a: u32 }\n",
                )
            });
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            ledger.replace(
                "root = \"..\"",
                &format!("root = \"{}\"", ext_root.display()),
            ),
        );
        match planted {
            Ok(()) => report.push(prove_rows_red(
                cx,
                self,
                "a hand-written slot in a local clone of a registered plugin is RED",
                &[ROW_EXTERNAL],
                ov,
                &[&format!("{plugin}:src/lib.rs:2 busbar_call")],
            )),
            Err(e) => report.push(prove_rows_red(
                cx,
                self,
                format!(
                    "external plant could not be written under {}: {e}",
                    ext_root.display()
                ),
                &[ROW_EXTERNAL],
                ov,
                &["unplantable"],
            )),
        }

        report
    }
}

fn external_row(cx: &Ctx, ledger: &Ledger) -> Row {
    let sigs = match workspace_signatures(cx) {
        Ok(s) => s,
        Err(e) => {
            return Row::fail(
                ROW_EXTERNAL,
                "the ABI's fn types could not be read",
                format!("{ONE_HOME} did not scan ({e}); an unread ABI matches nothing"),
            )
        }
    };
    let ext = scan_external(cx, &ledger.external_root, &sigs);
    let present: Vec<&str> = ext
        .scanned
        .iter()
        .map(|s| s.split(' ').next().unwrap_or(""))
        .collect();
    let ext_ledger: Vec<Key> = ledger
        .offenders
        .iter()
        .filter(|k| !k.0.is_empty() && present.contains(&k.0.as_str()))
        .cloned()
        .collect();
    let keys: Vec<Key> = ext.findings.iter().map(Finding::key).collect();
    let new = minus(&keys, &ext_ledger);
    let stale = minus(&ext_ledger, &keys);

    let mut problems = ext.errors.clone();
    let mut pending = new.clone();
    for f in &ext.findings {
        if let Some(i) = pending.iter().position(|k| *k == f.key()) {
            pending.remove(i);
            problems.push(format!("NEW {}", f.describe()));
        }
    }
    problems.extend(
        stale
            .iter()
            .map(|k| format!("STALE row {}", describe_key(k))),
    );
    let skipped = if ext.absent.is_empty() {
        String::new()
    } else {
        format!(
            "; SKIPPED (no local clone under {}): {}",
            ext.root.display(),
            ext.absent.join(", ")
        )
    };
    if problems.is_empty() {
        Row::pass(
            ROW_EXTERNAL,
            "every locally-cloned registered plugin defines no ABI shape of its own",
            format!(
                "scanned {}: {}{skipped}",
                ext.scanned.len(),
                if ext.scanned.is_empty() {
                    "none".to_string()
                } else {
                    ext.scanned.join(", ")
                }
            ),
        )
    } else {
        Row::fail(
            ROW_EXTERNAL,
            "a registered plugin's local clone defines an ABI shape outside busbar-contract's abi/",
            format!("{}{skipped}", problems.join(" | ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(l: &str) -> Vec<(Option<String>, Option<Sig>)> {
        let c: Vec<char> = scan::blank_literals(l).chars().collect();
        let r: Vec<char> = l.chars().collect();
        extern_items(&c, &r)
            .into_iter()
            .map(|i| (i.name, i.sig))
            .collect()
    }

    fn sig(params: &[&str], ret: &str) -> Option<Sig> {
        Some((
            params.iter().map(|p| (*p).to_string()).collect(),
            ret.to_string(),
        ))
    }

    #[test]
    fn extern_items_tell_a_definition_from_a_pointer_and_an_import() {
        let l = "pub(crate) extern \"C-unwind\" fn slot(p: Option<unsafe extern \"C\" fn(u8)>) {}";
        assert_eq!(
            items(l),
            vec![
                (
                    Some("slot".to_string()),
                    sig(&["Option<unsafeextern\"\"fn(u8)>"], "")
                ),
                (None, sig(&["u8"], "")),
            ]
        );
        assert!(items("extern \"C\" { fn atexit(cb: u8); }").is_empty());
        assert!(items("extern \"Rust\" fn f() {}").is_empty());
    }

    #[test]
    fn a_signature_reads_across_lines_and_drops_module_paths() {
        let ty = "pub type Op =\n    extern \"C\" fn(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome;";
        let body = "extern \"C\" fn tick(\n    _: *mut std::os::raw::c_void,\n    input: *const c_void,\n    out: *mut c_void,\n) -> busbar_contract::abi::mechanism::call::RawOutcome {\n}";
        let want = sig(&["*mutc_void", "*constc_void", "*mutc_void"], "RawOutcome");
        assert_eq!(items(ty), vec![(None, want.clone())]);
        assert_eq!(items(body), vec![(Some("tick".into()), want)]);
        assert_eq!(
            items("pub type DoorFn = extern \"C\" fn() -> *const Door;"),
            vec![(None, sig(&[], "*constDoor"))]
        );
        assert_eq!(
            items("pub extern \"C\" fn g<T: Sync>(ctx: HostCtx, t: Ticket) where T: Send {}"),
            vec![(Some("g".into()), sig(&["HostCtx", "Ticket"], ""))]
        );
    }

    #[test]
    fn version_consts_are_abi_segments_not_substrings() {
        assert_eq!(
            version_const("pub const STORE_ABI_FLOOR: u32 = 2;"),
            Some("STORE_ABI_FLOOR".into())
        );
        assert_eq!(
            version_const("pub const TRANSPORT: super::AbiVersion = x;"),
            Some("TRANSPORT".into())
        );
        assert_eq!(
            version_const("pub const POD_VERSION: u16 = 3;"),
            Some("POD_VERSION".into())
        );
        assert_eq!(
            version_const("pub const ROW_REACHABILITY: &str = \"\";"),
            None
        );
        assert_eq!(version_const("static ALL_CAPABILITIES: u8 = 1;"), None);
        // GREEN: an ABI segment in the name does not make a string or a byte slice a version.
        assert_eq!(
            version_const("const CONTRACT_ABI_PREFIX: &str = \"crates/busbar-contract/src/abi/\";"),
            None
        );
        assert_eq!(
            version_const("pub const WIRE_ABI_MAGIC: &[u8] = b\"BB\";"),
            None
        );
        assert_eq!(version_const("const ABI_DIR: &Path = x;"), None);
        // RED: a signed integer is still a number that can carry a version.
        assert_eq!(
            version_const("pub(crate) const HOOK_ABI_MIN: i64 = 1;"),
            Some("HOOK_ABI_MIN".into())
        );
        assert_eq!(version_const("pub const fn abi() -> u32 { 1 }"), None);
    }

    #[test]
    fn repr_c_needs_the_c_hint() {
        assert!(is_repr_c("#[repr(C)]"));
        assert!(is_repr_c("  #[repr(C, u8)]"));
        assert!(!is_repr_c("#[repr(u8)]"));
        assert!(!is_repr_c("#[repr(transparent)]"));
    }
}
