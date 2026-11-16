// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-CODE SCAN (SDK-SAFE-TEST-HOST §2.1, LINT-RULES R131 `test-unsafe-outside-boundary`):
//! TST-7's enforcement. It reads source as tokens (comments and literals skipped), never as items,
//! so a token inside a `macro_rules!` body or a macro call counts like any other.
//!
//! A file is TEST-REACHABLE when it sits under a `tests/`, `benches/` or `examples/` directory, or
//! is reached from a module that exists only in test builds: `#[cfg(test)]`, a cfg that holds only
//! with `test` or `feature = "test-support"`, or the `path` a `cfg_attr(test, path = ..)` names.
//! Out-of-line `mod x;` and `#[path]` are resolved by walking the module tree from each crate root.
//!
//! In a test-reachable file R131 flags (a) every `unsafe` token, outside [`BOUNDARY`]; and (b) the
//! raw back doors the safe host replaces, outside [`BOUNDARY`] and the host ([`HOST`]): naming
//! `dispatch::Frame` (a path, a `use` group or `Frame::new`/`Frame {`), `Plugin::{call, recall,
//! call_inline}`, `LoadedDoor`, `LinkedRow::of_raw`, `rendering_of_raw`, `enter_door`, a
//! `.plugin(` call and `test_from_raw`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The one directory whose test-support code may hold `unsafe`: the SDK's reviewed boundary.
pub const BOUNDARY: &str = "busbar-contract/src/abi/sdk/test_support/";
/// The safe host, which crosses through the loader's own entries on a test's behalf.
pub const HOST: &str = "plugin-loader/src/test_host.rs";

/// Which half of R131 a finding breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// (a): an `unsafe` token.
    Unsafe,
    /// (b): a raw back door.
    BackDoor,
}

/// One R131 finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The file.
    pub file: PathBuf,
    /// Its 1-based line.
    pub line: usize,
    /// The rule.
    pub rule: Rule,
    /// What was named.
    pub what: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rule = match self.rule {
            Rule::Unsafe => "R131 (a) test-unsafe-outside-boundary",
            Rule::BackDoor => "R131 (b) test-unsafe-outside-boundary (back door)",
        };
        write!(
            f,
            "{}:{}: {rule}: {}",
            self.file.display(),
            self.line,
            self.what
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Str(String),
    Other,
}

/// `src` as tokens with their lines; comments dropped, literals kept only as strings.
fn lex(src: &str) -> Vec<(Tok, usize)> {
    let b: Vec<char> = src.chars().collect();
    let (mut i, mut line, mut out) = (0, 1, Vec::new());
    let at = |i: usize| b.get(i).copied().unwrap_or('\0');
    while i < b.len() {
        let c = b[i];
        let start = line;
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    line += usize::from(b[i] == '\n');
                    i += 1;
                }
            }
        } else if c == '"' || ((c == 'b' || c == 'c') && at(i + 1) == '"') {
            i += if c == '"' { 1 } else { 2 };
            let mut s = String::new();
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    s.push(b[i]);
                    i += 1;
                }
                line += usize::from(at(i) == '\n');
                s.push(at(i));
                i += 1;
            }
            i += 1;
            out.push((Tok::Str(s), start));
        } else if let Some(skip) = raw_string_open(&b, i) {
            let hashes = skip.1;
            i = skip.0;
            let mut s = String::new();
            while i < b.len() && !(b[i] == '"' && (1..=hashes).all(|h| at(i + h) == '#')) {
                line += usize::from(b[i] == '\n');
                s.push(b[i]);
                i += 1;
            }
            i += 1 + hashes;
            out.push((Tok::Str(s), start));
        } else if c == '\'' {
            if at(i + 1) == '\\' {
                i += 2;
                while i < b.len() && b[i] != '\'' {
                    i += 1;
                }
                i += 1;
                out.push((Tok::Other, start));
            } else if at(i + 2) == '\'' {
                i += 3;
                out.push((Tok::Other, start));
            } else {
                i += 1;
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                out.push((Tok::Other, start));
            }
        } else if c.is_alphabetic() || c == '_' {
            if c == 'r' && at(i + 1) == '#' && (at(i + 2).is_alphabetic() || at(i + 2) == '_') {
                i += 2;
            }
            let mut s = String::new();
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                s.push(b[i]);
                i += 1;
            }
            out.push((Tok::Ident(s), start));
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_' || b[i] == '.') {
                if b[i] == '.' && !at(i + 1).is_ascii_digit() {
                    break;
                }
                i += 1;
            }
            out.push((Tok::Other, start));
        } else {
            out.push((Tok::Punct(c), start));
            i += 1;
        }
    }
    out
}

/// At a raw string's opening (`r"`, `r#"`, `br#"`, `cr"`): the index past its quote and its `#`s.
fn raw_string_open(b: &[char], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if matches!(b.get(j), Some('b' | 'c')) {
        j += 1;
    }
    if b.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while b.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    (b.get(j) == Some(&'"')).then_some((j + 1, hashes))
}

/// A cfg predicate's value with `test` and `feature = "test-support"` set to `on`, every other
/// predicate true (it may hold in either build).
fn holds(toks: &[Tok], on: bool) -> bool {
    fn one(t: &[Tok], i: &mut usize, on: bool) -> bool {
        let Some(Tok::Ident(name)) = t.get(*i) else {
            *i += 1;
            return true;
        };
        *i += 1;
        if t.get(*i) == Some(&Tok::Punct('=')) {
            *i += 1;
            let v = matches!(t.get(*i), Some(Tok::Str(s)) if s == "test-support");
            *i += 1;
            return if name == "feature" && v { on } else { true };
        }
        if t.get(*i) != Some(&Tok::Punct('(')) {
            return if name == "test" { on } else { true };
        }
        *i += 1;
        let mut vals = Vec::new();
        while *i < t.len() && t.get(*i) != Some(&Tok::Punct(')')) {
            vals.push(one(t, i, on));
            if t.get(*i) == Some(&Tok::Punct(',')) {
                *i += 1;
            }
        }
        *i += 1;
        match name.as_str() {
            "not" => !vals.first().copied().unwrap_or(true),
            "all" => vals.iter().all(|v| *v),
            "any" => vals.iter().any(|v| *v),
            _ => true,
        }
    }
    let mut i = 0;
    one(toks, &mut i, on)
}

/// A predicate that holds in a test build and in no production build.
fn test_only(pred: &[Tok]) -> bool {
    holds(pred, true) && !holds(pred, false)
}

/// What one module declaration's attributes say.
#[derive(Default)]
struct Attrs {
    test: bool,
    path: Option<String>,
    test_path: Option<String>,
}

/// Reads one attribute's tokens (between `[` and `]`) into `a`.
fn attr(t: &[Tok], a: &mut Attrs) {
    let name = match t.first() {
        Some(Tok::Ident(n)) => n.as_str(),
        _ => return,
    };
    let args = || {
        let close = t.len().saturating_sub(1);
        t.get(2..close).unwrap_or(&[])
    };
    match name {
        "path" => {
            if let Some(Tok::Str(s)) = t.get(2) {
                a.path = Some(s.clone());
            }
        }
        "cfg" => a.test |= test_only(args()),
        "cfg_attr" => {
            let inner = args();
            let mut depth = 0usize;
            let comma = inner.iter().position(|x| {
                match x {
                    Tok::Punct('(') => depth += 1,
                    Tok::Punct(')') => depth = depth.saturating_sub(1),
                    _ => {}
                }
                depth == 0 && *x == Tok::Punct(',')
            });
            let Some(comma) = comma else { return };
            if !test_only(&inner[..comma]) {
                return;
            }
            let rest = &inner[comma + 1..];
            for (k, x) in rest.iter().enumerate() {
                match (x, rest.get(k + 1), rest.get(k + 2)) {
                    (Tok::Ident(p), Some(Tok::Punct('=')), Some(Tok::Str(s))) if p == "path" => {
                        a.test_path = Some(s.clone());
                    }
                    (Tok::Ident(c), Some(Tok::Punct('(')), _) if c == "cfg" => a.test = true,
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// The module tree walk: every file reached, and whether only a test build reaches it.
struct Walk {
    reached: BTreeMap<PathBuf, bool>,
}

impl Walk {
    fn file(&mut self, file: &Path, test: bool, mod_rs: bool) {
        let file = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
        if self.reached.get(&file).is_some_and(|seen| *seen || !test) {
            return;
        }
        self.reached.insert(file.clone(), test);
        let Ok(src) = std::fs::read_to_string(&file) else {
            return;
        };
        let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let base = if mod_rs {
            dir.clone()
        } else {
            dir.join(file.file_stem().unwrap_or_default())
        };
        let toks: Vec<Tok> = lex(&src).into_iter().map(|(t, _)| t).collect();
        self.items(&toks, &dir, &base, test, false);
    }

    /// The `mod` declarations in `t`, an item list whose children live under `base`.
    fn items(&mut self, t: &[Tok], dir: &Path, base: &Path, test: bool, inline: bool) {
        let mut a = Attrs::default();
        let mut i = 0;
        while i < t.len() {
            match &t[i] {
                Tok::Punct('#') => {
                    let inner = t.get(i + 1) == Some(&Tok::Punct('!'));
                    let j = i + 1 + usize::from(inner);
                    if t.get(j) == Some(&Tok::Punct('[')) {
                        let end = close(t, j);
                        // An inner attribute is the file's own, never the next module's.
                        if !inner {
                            attr(&t[j + 1..end.min(t.len())], &mut a);
                        }
                        i = end + 1;
                        continue;
                    }
                    i += 1;
                }
                Tok::Ident(k) if k == "pub" => {
                    i += 1;
                    if t.get(i) == Some(&Tok::Punct('(')) {
                        i = close(t, i) + 1;
                    }
                }
                Tok::Ident(k) if k == "mod" => {
                    let Some(Tok::Ident(name)) = t.get(i + 1) else {
                        i += 1;
                        continue;
                    };
                    let gated = test || a.test;
                    match t.get(i + 2) {
                        Some(Tok::Punct(';')) => {
                            let rel = if inline { base } else { dir };
                            if let Some(p) = &a.path {
                                self.file(&rel.join(p), gated, true);
                            } else {
                                let one = base.join(format!("{name}.rs"));
                                if one.is_file() {
                                    self.file(&one, gated, false);
                                } else {
                                    self.file(&base.join(name).join("mod.rs"), gated, true);
                                }
                            }
                            if let Some(p) = &a.test_path {
                                self.file(&rel.join(p), true, true);
                            }
                            i += 3;
                        }
                        Some(Tok::Punct('{')) => {
                            let end = close(t, i + 2);
                            let inner = base.join(a.path.as_deref().unwrap_or(name));
                            let body = t.get(i + 3..end).unwrap_or(&[]);
                            self.items(body, dir, &inner, gated, true);
                            i = end + 1;
                        }
                        _ => i += 2,
                    }
                    a = Attrs::default();
                }
                Tok::Punct('{') => {
                    i = close(t, i) + 1;
                    a = Attrs::default();
                }
                _ => {
                    if matches!(t[i], Tok::Punct(';' | '}')) {
                        a = Attrs::default();
                    }
                    i += 1;
                }
            }
        }
    }
}

/// The index of the bracket closing the one at `open`.
fn close(t: &[Tok], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, x) in t.iter().enumerate().skip(open) {
        match x {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    t.len()
}

/// Every `.rs` file under `dir`, skipping build output and VCS metadata.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if !matches!(
                name.to_str(),
                // `.cargo-home` / `.cargo`: a repository-local CARGO_HOME (CI caches it inside the
                // checkout), whose registry and git checkouts are third-party sources.
                Some("target" | ".git" | "vendor" | "node_modules" | ".cargo-home" | ".cargo")
            ) {
                sources(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn slashed(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// The test-reachable files under `root` (a repository or one crate).
#[must_use]
pub fn test_reachable(root: &Path) -> Vec<PathBuf> {
    let mut all = Vec::new();
    sources(root, &mut all);
    let mut walk = Walk {
        reached: BTreeMap::new(),
    };
    for f in &all {
        let in_src = f.parent().is_some_and(|d| d.ends_with("src"));
        let root_file = matches!(
            f.file_name().and_then(|n| n.to_str()),
            Some("lib.rs" | "main.rs")
        );
        if in_src && root_file {
            walk.file(f, false, true);
        }
    }
    let mut out: Vec<PathBuf> = walk
        .reached
        .into_iter()
        .filter_map(|(p, test)| test.then_some(p))
        .collect();
    for f in all {
        let rel = f.strip_prefix(root).unwrap_or(&f);
        let under = rel.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("tests" | "benches" | "examples")
            )
        });
        let f = f.canonicalize().unwrap_or(f);
        if under && !out.contains(&f) {
            out.push(f);
        }
    }
    out.sort();
    out
}

/// R131's findings in one file's source; `host` exempts the file from (b).
fn scan(file: &Path, src: &str, host: bool, out: &mut Vec<Finding>) {
    let t = lex(src);
    let id = |k: usize| match t.get(k) {
        Some((Tok::Ident(s), _)) => Some(s.as_str()),
        _ => None,
    };
    let p = |k: usize, c: char| matches!(t.get(k), Some((Tok::Punct(x), _)) if *x == c);
    let path = |k: usize| p(k, ':') && p(k + 1, ':');
    let mut push = |line: usize, rule: Rule, what: &str| {
        out.push(Finding {
            file: file.to_path_buf(),
            line,
            rule,
            what: what.into(),
        });
    };
    let mut group: Option<usize> = None;
    for (k, (tok, line)) in t.iter().enumerate() {
        if group.is_some_and(|end| k > end) {
            group = None;
        }
        let Tok::Ident(name) = tok else { continue };
        if name == "unsafe" {
            push(*line, Rule::Unsafe, "`unsafe`");
            continue;
        }
        if host {
            continue;
        }
        let what = match name.as_str() {
            "dispatch" if path(k + 1) && p(k + 3, '{') => {
                group = Some(close_at(&t, k + 3));
                None
            }
            "Frame"
                if (k >= 3 && path(k - 2) && id(k - 3) == Some("dispatch"))
                    || group.is_some()
                    || (path(k + 1) && id(k + 3) == Some("new"))
                    || p(k + 1, '{') =>
            {
                Some("`dispatch::Frame`")
            }
            "Plugin"
                if path(k + 1) && matches!(id(k + 3), Some("call" | "recall" | "call_inline")) =>
            {
                Some("`Plugin::call`/`recall`/`call_inline`")
            }
            "LinkedRow" if path(k + 1) && id(k + 3) == Some("of_raw") => {
                Some("`LinkedRow::of_raw`")
            }
            "LoadedDoor" | "rendering_of_raw" | "enter_door" | "test_from_raw" => {
                Some(name.as_str())
            }
            "plugin" if k >= 1 && p(k - 1, '.') && p(k + 1, '(') => Some("`.plugin(` accessor"),
            _ => None,
        };
        if let Some(what) = what {
            push(*line, Rule::BackDoor, what);
        }
    }
}

/// [`close`] over lexed tokens with lines.
fn close_at(t: &[(Tok, usize)], open: usize) -> usize {
    let toks: Vec<Tok> = t.iter().map(|(x, _)| x.clone()).collect();
    close(&toks, open)
}

/// R131 over every test-reachable file under `root`.
#[must_use]
pub fn r131(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in test_reachable(root) {
        let s = slashed(&f);
        if s.contains(BOUNDARY) {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(&f) {
            scan(&f, &src, s.ends_with(HOST), &mut out);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests;
