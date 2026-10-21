//! `cargo xtask gate door-only` — THE KERNEL REACHES A PLUGIN ONLY THROUGH ITS DOOR (M0 ABI-SPEC).
//!
//! > "compiled or dropped in is just a convenience for customer; NOTHING CHANGES about the plugin
//! > itself and how it works." — OWNER, 2026-09-27
//!
//! A compiled-in plugin is a row holding the same `door` a dropped-in one exports, and the kernel
//! calls both through the same table: it never holds a plugin crate's Rust types and never calls
//! its Rust functions. Over the WHOLE BINARY CLOSURE — every non-plugin workspace crate the `busbar`
//! binary links, the binary included, `busbar-contract` aside (its own gate is
//! `contract-stateless`):
//!
//! * **`plugin-path`** — a Rust path into a plugin crate (`busbar_plane_llm::…`) other than
//!   `<crate>::door`.
//! * **`static-seam`** — a `static` whose type holds a function pointer, a `Fn` trait or a trait
//!   object: a seam another crate installs Rust code into, bypassing every door. Exactly two are
//!   exempt, the oauth2 and admin cleanliness seams the owner ruled core
//!   ([`EXEMPT_SEAMS`]); a third is a finding.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/door-only.toml`.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_PATH: &str = "door-only:plugin-path";
pub const ROW_SEAM: &str = "door-only:static-seam";

/// The two static fn-pointer seams the owner ruled core (oauth2 and admin), and no others.
pub const EXEMPT_SEAMS: &[&str] = &[
    "crates/busbar-kernel/src/oauth_as/seam.rs",
    "crates/busbar-kernel/src/admin/seam.rs",
];

pub const SPEC: Spec = Spec {
    gate: "door-only",
    ledger: "qa/door-only.toml",
    rules: &[
        (
            ROW_PATH,
            "the binary closure names no plugin crate's Rust item but its door",
        ),
        (
            ROW_SEAM,
            "the binary closure installs no static fn-pointer seam (oauth2 and admin exempt)",
        ),
    ],
    header: "# door-only: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # The binary closure reaches a plugin only through its door, and installs no static\n\
             # fn-pointer seam but the two ruled core (oauth_as/seam.rs, admin/seam.rs). Each row\n\
             # is one the tree carries today. Strike a row in the commit that drains it; never\n\
             # add one. Regenerate with `cargo xtask gate door-only --write`.\n",
};

/// The name and declared type of a `static` item on this blanked line, if it declares one.
fn static_decl(counted: &str) -> Option<(String, String)> {
    let mut from = 0;
    while let Some(i) = counted[from..].find("static") {
        let at = from + i;
        from = at + 6;
        let before = counted[..at].chars().next_back();
        if before.is_some_and(|c| c == '\'' || c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        if !counted[at + 6..].starts_with(char::is_whitespace) {
            continue;
        }
        let rest = counted[at + 6..].trim_start();
        let rest = rest.strip_prefix("mut ").map_or(rest, str::trim_start);
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim_start();
        if name.is_empty() || !after.starts_with(':') || after.starts_with("::") {
            continue;
        }
        let ty: String = after[1..]
            .chars()
            .take_while(|c| *c != '=' && *c != ';')
            .collect();
        return Some((name, ty));
    }
    None
}

/// Does a static's declared type hold code: a fn pointer, a `Fn` trait or a trait object?
fn holds_code(ty: &str) -> bool {
    one_abi::has_word(ty, "fn")
        || one_abi::has_word(ty, "Fn")
        || one_abi::has_word(ty, "FnMut")
        || one_abi::has_word(ty, "FnOnce")
        || one_abi::has_word(ty, "dyn")
}

/// How deep an alias may name another alias before the walk stops (a cycle, or a chain no real
/// tree writes).
const ALIAS_DEPTH: usize = 8;

/// The roots a path may start at that name the crate it is written in.
const SELF_ROOTS: &[&str] = &["crate", "self", "super"];

/// THE BINARY CLOSURE'S TYPE ALIASES, so a static whose declared type holds code BEHIND AN ALIAS
/// is the finding a spelled one is. `static ROWS: OnceLock<&[Row]>` with `type Row = (&str,
/// DoorFn)` and `type DoorFn = extern "C" fn() -> *const Door` declares the same seam as spelling
/// the `fn`; reading only the words on the static's own line passes it.
///
/// An alias is resolved the way the compiler resolves the name: a path rooted at `crate`, `self`
/// or `super` in the crate it is written in, a path rooted at a workspace crate in that crate (or,
/// when that crate re-exports the alias, wherever the workspace declares it), and a bare name
/// through the file's own `use` items, else in its own crate. A path rooted anywhere else (`std`,
/// `core`, a registry crate) is not a workspace alias.
#[derive(Default)]
pub struct Aliases {
    /// crate ident -> alias name -> every declaration: (declaring file, right-hand side).
    by_crate: BTreeMap<String, BTreeMap<String, Vec<(String, String)>>>,
    /// file -> its `use` items, blanked, one string each.
    uses: BTreeMap<String, Vec<String>>,
}

impl Aliases {
    /// Read `file` (production lines only) of crate `krate`: its aliases and its `use` items.
    pub fn read(&mut self, krate: &str, file: &str, text: &str) {
        // Every crate read is a workspace crate, aliases or none: a path rooted at it is resolved
        // in it (and through its re-exports), never skipped as a registry crate's.
        self.by_crate.entry(krate.to_string()).or_default();
        let lines = one_abi::production(text);
        let mut uses = Vec::new();
        for (idx, sl) in lines.iter().enumerate() {
            let t = sl.counted.trim_start();
            let after_vis = strip_visibility(t);
            let joined = |first: &str| {
                let mut all = first.to_string();
                for more in lines.iter().skip(idx + 1).take(ALIAS_DEPTH) {
                    if all.contains(';') {
                        break;
                    }
                    all.push(' ');
                    all.push_str(more.counted.trim());
                }
                all.split(';').next().unwrap_or_default().to_string()
            };
            if let Some(rest) = after_vis.strip_prefix("use ") {
                uses.push(joined(rest));
            } else if let Some(rest) = after_vis.strip_prefix("type ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let decl = joined(rest);
                let Some((_, rhs)) = decl.split_once('=') else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                self.by_crate
                    .entry(krate.to_string())
                    .or_default()
                    .entry(name)
                    .or_default()
                    .push((file.to_string(), rhs.trim().to_string()));
            }
        }
        self.uses.insert(file.to_string(), uses);
    }

    /// Does `ty`, written in `file` of crate `krate`, hold code — spelled, or behind an alias?
    pub fn holds(&self, ty: &str, krate: &str, file: &str) -> bool {
        self.holds_at(ty, krate, file, 0)
    }

    fn holds_at(&self, ty: &str, krate: &str, file: &str, depth: usize) -> bool {
        if holds_code(ty) {
            return true;
        }
        if depth >= ALIAS_DEPTH {
            return false;
        }
        for path in paths(ty) {
            let Some(last) = path.last() else {
                continue;
            };
            let (target, name, imported) = if path.len() > 1 {
                (self.crate_of(&path[0], krate), last.clone(), true)
            } else {
                match self.imported(file, last) {
                    Some((root, name)) => (self.crate_of(&root, krate), name, true),
                    None => (Some(krate.to_string()), last.clone(), false),
                }
            };
            let Some(target) = target else {
                continue;
            };
            let here = self.by_crate.get(&target).and_then(|a| a.get(&name));
            let decls: Vec<(&str, &(String, String))> = match here {
                Some(d) => d.iter().map(|x| (target.as_str(), x)).collect(),
                // A re-export: the crate a path or a `use` names declares no such alias, so the
                // workspace's declaration of it is the one meant.
                None if imported => self
                    .by_crate
                    .iter()
                    .filter_map(|(k, a)| a.get(&name).map(|d| (k.as_str(), d)))
                    .flat_map(|(k, d)| d.iter().map(move |x| (k, x)))
                    .collect(),
                None => Vec::new(),
            };
            for (k, (f, rhs)) in decls {
                if self.holds_at(rhs, k, f, depth + 1) {
                    return true;
                }
            }
        }
        false
    }

    /// The workspace crate a path rooted at `root`, written in crate `krate`, names; `None` for a
    /// root outside the workspace.
    fn crate_of(&self, root: &str, krate: &str) -> Option<String> {
        if SELF_ROOTS.contains(&root) {
            return Some(krate.to_string());
        }
        self.by_crate.contains_key(root).then(|| root.to_string())
    }

    /// The `use` item of `file` that brings `name` into scope: the root its path starts at and the
    /// name it is declared under (`use a::B as name` declares `B`).
    fn imported(&self, file: &str, name: &str) -> Option<(String, String)> {
        let uses = self.uses.get(file)?;
        uses.iter().find_map(|u| {
            let toks = paths(u);
            if !toks.iter().any(|p| p.last().is_some_and(|l| l == name)) {
                return None;
            }
            let root = toks.first()?.first()?.clone();
            let renamed = u
                .split(',')
                .find_map(|part| {
                    let (from, to) = part.split_once(" as ")?;
                    (to.trim().trim_end_matches('}').trim() == name).then(|| {
                        from.trim()
                            .rsplit("::")
                            .next()
                            .unwrap_or_default()
                            .trim_start_matches('{')
                            .trim()
                            .to_string()
                    })
                })
                .unwrap_or_else(|| name.to_string());
            Some((root, renamed))
        })
    }
}

/// `t` without a leading `pub` or `pub(...)`.
fn strip_visibility(t: &str) -> &str {
    let Some(rest) = t.strip_prefix("pub") else {
        return t;
    };
    if rest.starts_with(char::is_whitespace) {
        return rest.trim_start();
    }
    match rest.find(')') {
        Some(close) if rest.starts_with('(') => rest[close + 1..].trim_start(),
        _ => t,
    }
}

/// The paths written in `text`, each as its segments (`a::b::C` is `[a, b, C]`). A lifetime is not
/// a path, and a keyword-rooted `dyn`/`fn` is read by [`holds_code`] before any path is.
fn paths(text: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !ident(chars[i]) || (i > 0 && (ident(chars[i - 1]) || chars[i - 1] == '\'')) {
            i += 1;
            continue;
        }
        let mut path = Vec::new();
        loop {
            let start = i;
            while i < chars.len() && ident(chars[i]) {
                i += 1;
            }
            path.push(chars[start..i].iter().collect::<String>());
            let mut j = i;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            if j + 1 < chars.len() && chars[j] == ':' && chars[j + 1] == ':' {
                let mut k = j + 2;
                while k < chars.len() && chars[k] == ' ' {
                    k += 1;
                }
                if k < chars.len() && ident(chars[k]) {
                    i = k;
                    continue;
                }
            }
            break;
        }
        if !path[0].starts_with(|c: char| c.is_ascii_digit()) {
            out.push(path);
        }
    }
    out
}

/// The two inner attributes that make a whole file test code, matched exactly: the plain test cfg
/// and the test-or-`test-support` cfg the kernel's test fixtures carry. Anything else that merely
/// mentions `test` (`any(test, fuzzing)`) is shipped by some build, so its statics are scanned.
const TEST_ONLY_FILE_ATTRS: &[&str] = &[
    "#![cfg(test)]",
    "#![cfg(any(test, feature = \"test-support\"))]",
];

/// Is this file test code as a whole: one of [`TEST_ONLY_FILE_ATTRS`], exactly, among the inner
/// attributes that lead the file, before its first item?
///
/// Read off the file's production lines (`lines`), never its raw text: a line inside a block
/// comment or a string literal is blanked in `counted`, so an attribute spelled there is no
/// attribute; and an inner attribute after the first item (`mod t {` then `#![cfg(test)]`) gates
/// that item alone, never the file.
fn test_only_file(lines: &[crate::scan::ScopeLine]) -> bool {
    for sl in lines {
        let counted = sl.counted.trim();
        if counted.is_empty() {
            continue;
        }
        if !counted.starts_with("#![") {
            return false;
        }
        if TEST_ONLY_FILE_ATTRS.contains(&sl.code.trim()) {
            return true;
        }
    }
    false
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let closure = one_abi::binary_closure(&members);
    // The closure's aliases first, `busbar-contract`'s included (the door type is declared there):
    // a static anywhere in scope may name one.
    let mut aliases = Aliases::default();
    for m in members.iter().filter(|m| closure.contains(&m.name)) {
        match one_abi::rs_files(cx, &m.dir) {
            Ok(files) => {
                let krate = m.name.replace('-', "_");
                for f in &files {
                    aliases.read(&krate, &f.rel_str(), &f.text);
                }
            }
            Err(e) => errors.push(e),
        }
    }
    let plugin_idents: Vec<String> = members
        .iter()
        .filter(|m| one_abi::is_plugin_crate(&m.name))
        .map(|m| m.name.replace('-', "_"))
        .collect();
    let scope: Vec<_> = members
        .iter()
        .filter(|m| {
            closure.contains(&m.name)
                && !one_abi::is_plugin_crate(&m.name)
                && m.name != "busbar-contract"
        })
        .collect();
    if scope.len() < 10 {
        errors.push(format!(
            "the binary closure read as {} crate(s); the scan has gone blind",
            scope.len()
        ));
    }
    for m in scope {
        let files = match one_abi::rs_files(cx, &m.dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let krate = m.name.replace('-', "_");
        for f in &files {
            let rel = f.rel_str();
            // A multi-line static's type runs onto the next lines; read up to its `=` or `;`.
            let lines = one_abi::production(&f.text);
            let test_only = test_only_file(&lines);
            for (idx, sl) in lines.iter().enumerate() {
                for p in &plugin_idents {
                    let needle = format!("{p}::");
                    let mut from = 0;
                    while let Some(i) = sl.counted[from..].find(&needle) {
                        let at = from + i;
                        from = at + needle.len();
                        let before = sl.counted[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                            continue;
                        }
                        let tail: String = sl.counted[at + needle.len()..]
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        if tail != "door" {
                            findings.push(Finding::new(ROW_PATH, &rel, p.clone(), sl.no));
                        }
                    }
                }
                if EXEMPT_SEAMS.contains(&rel.as_str()) || test_only {
                    continue;
                }
                if let Some((name, mut ty)) = static_decl(&sl.counted) {
                    for more in lines.iter().skip(idx + 1).take(6) {
                        if ty.contains('=') || sl.counted.contains('=') || sl.counted.contains(';')
                        {
                            break;
                        }
                        ty.push(' ');
                        ty.push_str(
                            &more
                                .counted
                                .chars()
                                .take_while(|c| *c != '=' && *c != ';')
                                .collect::<String>(),
                        );
                        if more.counted.contains('=') || more.counted.contains(';') {
                            break;
                        }
                    }
                    if aliases.holds(&ty, &krate, &rel) {
                        findings.push(Finding::new(ROW_SEAM, &rel, name, sl.no));
                    }
                }
            }
        }
    }
    (findings, errors)
}

pub struct DoorOnlyGate;

impl Gate for DoorOnlyGate {
    fn name(&self) -> &'static str {
        SPEC.gate
    }

    fn owed(&self) -> Vec<String> {
        SPEC.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (findings, errors) = scan(cx);
        one_abi::verdict(cx, &SPEC, findings, errors)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        // THE PLUGIN THE PLANT NAMES IS ONE THE WORKSPACE HOLDS. The plant named
        // `busbar_transport_tcp` until that transport left for its own repo (66853bf6e1); the scan
        // only knows the plugin crates that are members, so a path into a departed one is no
        // finding and the red arm proved nothing. The plugins leave this tree one by one, so the
        // plant takes whichever plugin member the census holds first.
        let plugin: &'static str = match one_abi::members(cx).map(|ms| {
            ms.into_iter()
                .find(|m| one_abi::is_plugin_crate(&m.name))
                .map(|m| m.name.replace('-', "_"))
        }) {
            Ok(Some(ident)) => Box::leak(ident.into_boxed_str()),
            Ok(None) => {
                let mut report = Report::new();
                report.note_infra_failure(
                    "door-only selftest: the workspace holds no plugin crate to plant a path into",
                );
                return report;
            }
            Err(e) => {
                let mut report = Report::new();
                report.note_infra_failure(format!("door-only selftest: {e}"));
                return report;
            }
        };
        let file = "crates/busbar-kernel/src/planted_door_only.rs";
        let mut path = Overlay::new();
        path.set(
            file,
            format!("pub fn planted() {{ {plugin}::carrier::Planted::go(); }}\n"),
        );
        // A SEAM BEHIND AN ALIAS: the function pointer is named by an alias, not spelled on the
        // static's line, so a reading of that line alone passes it.
        let mut aliased = Overlay::new();
        aliased.set(
            file,
            "pub type PlantedHook = fn() -> u8;\n\
             pub static PLANTED_ALIASED: std::sync::OnceLock<PlantedHook> = std::sync::OnceLock::new();\n",
        );
        // THE LINKED-ROW SHAPE: rows of plugin doors behind two aliases, the second the contract's
        // own door type, reached through a path into another workspace crate.
        let mut rows = Overlay::new();
        rows.set(
            file,
            "pub type PlantedRow = (&'static str, busbar_contract::abi::mechanism::door::DoorFn);\n\
             pub static PLANTED_ROWS: std::sync::OnceLock<&'static [PlantedRow]> =\n    \
             std::sync::OnceLock::new();\n",
        );
        // DATA BEHIND AN ALIAS, and a std type that shares a name with a workspace alias: neither
        // holds code, so neither is a finding.
        let mut data = Overlay::new();
        data.set(
            file,
            "pub type PlantedWords = (&'static str, u8);\n\
             pub static PLANTED_WORDS: std::sync::OnceLock<PlantedWords> = std::sync::OnceLock::new();\n\
             pub static PLANTED_CELL: std::sync::Mutex<std::cell::Cell<u8>> =\n    \
             std::sync::Mutex::new(std::cell::Cell::new(0));\n",
        );
        // NO NAME IS EXEMPT: the root's install record retyped in place to hold a fn pointer, and
        // a second fn-pointer static of the same name in an inline module of the same file, are
        // both findings.
        let preflight = "crates/busbar-kernel/src/preflight.rs";
        let real = match cx.read(preflight) {
            Ok(text) => text,
            Err(e) => {
                let mut report = Report::new();
                report.note_infra_failure(format!("door-only selftest: {preflight}: {e}"));
                return report;
            }
        };
        let declared = "static ROOT_ROWS: std::sync::OnceLock<RootInstall> =";
        if !real.contains(declared) {
            let mut report = Report::new();
            report.note_infra_failure(format!(
                "door-only selftest: {preflight} no longer declares `{declared}`"
            ));
            return report;
        }
        let mut retyped = Overlay::new();
        retyped.set(
            preflight,
            real.replace(
                declared,
                "static ROOT_ROWS: std::sync::OnceLock<fn() -> u8> =",
            ),
        );
        let mut inline = Overlay::new();
        inline.set(
            preflight,
            format!(
                "{real}\nmod planted_inline {{\n    \
                 pub static ROOT_ROWS: std::sync::OnceLock<fn() -> u8> =\n        \
                 std::sync::OnceLock::new();\n}}\n"
            ),
        );
        // THE TEST-ONLY FILE SKIP IS EXACT: a file gated `any(test, fuzzing)` ships in a fuzzing
        // build, so its fn static is a finding; one gated exactly test-or-`test-support` is not.
        let fuzzing_static =
            "pub static PLANTED_FUZZ: std::sync::OnceLock<fn() -> u8> = std::sync::OnceLock::new();\n";
        let mut fuzzing = Overlay::new();
        fuzzing.set(
            file,
            format!("#![cfg(any(test, fuzzing))]\n{fuzzing_static}"),
        );
        // DECOYS: the exact attribute where it is no file attribute — gating an inline module, in a
        // block comment, in a raw string. Each file's real fn static after the decoy is a finding.
        let mut decoy_mod = Overlay::new();
        decoy_mod.set(
            file,
            format!("mod decoy {{\n    #![cfg(test)]\n}}\n{fuzzing_static}"),
        );
        let mut decoy_comment = Overlay::new();
        decoy_comment.set(file, format!("/*\n#![cfg(test)]\n*/\n{fuzzing_static}"));
        let mut decoy_string = Overlay::new();
        decoy_string.set(
            file,
            format!(
                "pub const DECOY: &str = r#\"\n#![cfg(any(test, feature = \"test-support\"))]\n\"#;\n\
                 {fuzzing_static}"
            ),
        );
        let mut test_support = Overlay::new();
        test_support.set(
            file,
            format!("#![cfg(any(test, feature = \"test-support\"))]\n{fuzzing_static}"),
        );
        let mut seam = Overlay::new();
        seam.set(
            file,
            "pub static PLANTED_SEAM: std::sync::OnceLock<fn() -> u8> = std::sync::OnceLock::new();\n",
        );
        let mut door = Overlay::new();
        door.set(
            file,
            format!("pub const ROW: fn() = {plugin}::door;\npub static NAME: &str = \"x\";\n"),
        );
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_PATH,
                    "the kernel naming a plugin's Rust item is RED, naming the crate",
                    path,
                    vec![file, plugin],
                ),
                (
                    ROW_SEAM,
                    "a static whose fn pointer is behind an alias is RED, naming it",
                    aliased,
                    vec![file, "PLANTED_ALIASED"],
                ),
                (
                    ROW_SEAM,
                    "a static of door rows behind the contract's door alias is RED, naming it",
                    rows,
                    vec![file, "PLANTED_ROWS"],
                ),
                (
                    ROW_SEAM,
                    "the root's install record retyped to a fn pointer is RED, naming it",
                    retyped,
                    vec![preflight, "ROOT_ROWS"],
                ),
                (
                    ROW_SEAM,
                    "a fn-pointer ROOT_ROWS in an inline module of preflight.rs is RED, naming it",
                    inline,
                    vec![preflight, "ROOT_ROWS"],
                ),
                (
                    ROW_SEAM,
                    "a fn static in an `any(test, fuzzing)` file is RED, naming it",
                    fuzzing,
                    vec![file, "PLANTED_FUZZ"],
                ),
                (
                    ROW_SEAM,
                    "a test attribute gating an inline module does not hide the file's fn static",
                    decoy_mod,
                    vec![file, "PLANTED_FUZZ"],
                ),
                (
                    ROW_SEAM,
                    "a test attribute in a block comment does not hide the file's fn static",
                    decoy_comment,
                    vec![file, "PLANTED_FUZZ"],
                ),
                (
                    ROW_SEAM,
                    "a test attribute in a raw string does not hide the file's fn static",
                    decoy_string,
                    vec![file, "PLANTED_FUZZ"],
                ),
                (
                    ROW_SEAM,
                    "a static fn-pointer seam in the kernel is RED, naming it",
                    seam,
                    vec![file, "PLANTED_SEAM"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a row holding <crate>::door, and a static holding data, are not findings",
            &[ROW_PATH, ROW_SEAM],
            door,
        ));
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "data behind an alias, and std's Cell beside a workspace alias of that name, are not \
             findings",
            &[ROW_SEAM],
            data,
        ));
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a fn static in a file gated exactly test-or-`test-support` is test code, not a finding",
            &[ROW_SEAM],
            test_support,
        ));
        report
    }
}
