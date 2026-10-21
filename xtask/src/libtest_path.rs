//! THE LIBTEST NAME OF A TEST FN, READ OFF THE SOURCE.
//!
//! A ledger names a loop cell as `<repo-relative file>::<fn>`; the test harness knows it as a module
//! path (`root::serve::door_tests::agent_door::<fn>`). The two used to be bridged by a guess from
//! the file's NAME (`root/tests/serve_tests.rs` -> `root::serve_tests::tests::<fn>`), which is
//! wrong whenever a body is carried by a `#[path]` declaration under another module name or sits in
//! an inline module of its file: `serve.rs` carries `tests/serve_tests.rs` as `mod door_tests`, and
//! the cells sit in `mod agent_door { .. }` / `mod decisions_door { .. }` inside it.
//!
//! So the module tree is READ, the way rustc builds it: from the crate root (`src/main.rs`), every
//! `mod <name>;` declaration is followed to its file (a `#[path = ".."]` attribute relative to the
//! declaring file's directory, or the default `<name>.rs` / `<name>/mod.rs` beside a mod-rs file and
//! under `<stem>/` beside any other), and every inline `mod <name> { .. }` a fn sits in is part of
//! its path. Nothing is guessed: a file the tree reaches under two module paths, or a fn the file
//! defines under two module nestings, is AMBIGUOUS and refused naming both; a file the tree never
//! reaches is refused naming it.
//!
//! The reader is a token scanner, not a parser: it skips comments, string, raw-string, byte-string
//! and char literals (and tells a char literal from a lifetime), and reads only attributes
//! (`#[path = ".."]`, `#[cfg(..)]`, `#![cfg(..)]` and the attributes a `fn` carries),
//! `mod <ident> ;`, `mod <ident> {`, `fn <ident>` and brace depth. `scripts/capability-equality-summary.py`
//! carries the same algorithm for the equality ledger's own runner.
//!
//! THE CFGS ON THE WAY ARE KEPT (Law 10, status row 178). A name that resolves is a fn that EXISTS;
//! whether any build compiles it is a different question, and a module declared under a cfg no
//! build enables (`#[cfg(all(test, linked_axis_node))] mod tests;` once no linked row carried the
//! `node` axis) resolves exactly as well as one every build carries. So the tree records, for every
//! file it reaches, the `cfg` predicates of every declaration and inline module on the way to it,
//! and [`resolve_cell`] hands those back beside each fn's own attributes for a caller
//! (`crate::ci_cfg`) to judge against the build that runs it.

use std::collections::{BTreeMap, BTreeSet};

/// One token the module reader needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    Punct(char),
}

/// One `fn <name>` definition: its inline nesting, its name, the `cfg` predicates it compiles
/// under within its file (the inline modules' it sits in, outermost first, then its own), and its
/// other outer attributes as written (`test`, `tokio::test(flavor="multi_thread",worker_threads=)`,
/// `ignore`, `cfg_attr(miri,ignore)`, …; numbers are not kept).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FnItem {
    pub nest: Vec<String>,
    pub name: String,
    pub cfgs: Vec<String>,
    pub attrs: Vec<String>,
}

/// One `mod <name>;` declaration: its inline nesting, its name, its `#[path]` value if any, and the
/// `cfg` predicates it is declared under (the inline modules' it sits in, then its own).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ModDecl {
    pub nest: Vec<String>,
    pub name: String,
    pub path: Option<String>,
    pub cfgs: Vec<String>,
}

/// What a file says about modules and fns, with the inline-module nesting each one sits in.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileItems {
    /// `mod <name>;` declarations.
    pub decls: Vec<ModDecl>,
    /// `fn <name>` definitions.
    pub fns: Vec<FnItem>,
    /// The file's own inner `#![cfg(..)]` predicates, which gate everything in it.
    pub file_cfgs: Vec<String>,
}

/// An attribute's tokens as one string: idents and strings as written (a string re-quoted), puncts
/// as themselves, a single space only between two adjacent words. `cfg(all(test, linked_axis_node))`
/// reads `cfg(all(test,linked_axis_node))`; `cfg(feature = "x")` reads `cfg(feature="x")`.
fn attr_text(toks: &[Tok]) -> String {
    let mut out = String::new();
    let mut prev_word = false;
    for t in toks {
        let (s, word) = match t {
            Tok::Ident(s) => (s.clone(), true),
            Tok::Str(s) => (format!("\"{s}\""), true),
            Tok::Punct(c) => (c.to_string(), false),
        };
        if word && prev_word {
            out.push(' ');
        }
        out.push_str(&s);
        prev_word = word;
    }
    out
}

/// The predicate of a `cfg(..)` attribute's text, or `None` for any other attribute.
#[must_use]
pub fn cfg_predicate(attr: &str) -> Option<String> {
    attr.strip_prefix("cfg(")
        .and_then(|r| r.strip_suffix(')'))
        .map(str::to_string)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The tokens of `src`, comments and literal bodies skipped (a string's text is kept, for
/// `#[path = ".."]`).
fn tokens(src: &str) -> Vec<Tok> {
    let c: Vec<char> = src.chars().collect();
    let n = c.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        // Comments: `//` to end of line, `/* .. */` nested.
        if ch == '/' && i + 1 < n && c[i + 1] == '/' {
            while i < n && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && i + 1 < n && c[i + 1] == '*' {
            let mut depth = 1;
            i += 2;
            while i < n && depth > 0 {
                if c[i] == '/' && i + 1 < n && c[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && i + 1 < n && c[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // Raw strings (`r"..."`, `r#"..."#`, `br#"..."#`) and raw identifiers (`r#ident`).
        let raw_at = if ch == 'r' {
            Some(i + 1)
        } else if ch == 'b' && i + 1 < n && c[i + 1] == 'r' {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut j) = raw_at {
            let mut hashes = 0;
            while j < n && c[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < n && c[j] == '"' {
                j += 1;
                let start = j;
                loop {
                    if j >= n {
                        break;
                    }
                    if c[j] == '"' && (0..hashes).all(|k| j + 1 + k < n && c[j + 1 + k] == '#') {
                        break;
                    }
                    j += 1;
                }
                out.push(Tok::Str(c[start..j.min(n)].iter().collect()));
                i = (j + 1 + hashes).min(n);
                continue;
            }
            if ch == 'r' && hashes == 1 && j < n && is_ident_start(c[j]) {
                let start = j;
                while j < n && is_ident_char(c[j]) {
                    j += 1;
                }
                out.push(Tok::Ident(c[start..j].iter().collect()));
                i = j;
                continue;
            }
        }
        // Strings and byte strings.
        if ch == '"' || (ch == 'b' && i + 1 < n && c[i + 1] == '"') {
            let mut j = if ch == 'b' { i + 2 } else { i + 1 };
            let mut text = String::new();
            while j < n && c[j] != '"' {
                if c[j] == '\\' && j + 1 < n {
                    text.push(c[j]);
                    text.push(c[j + 1]);
                    j += 2;
                    continue;
                }
                text.push(c[j]);
                j += 1;
            }
            out.push(Tok::Str(text));
            i = (j + 1).min(n);
            continue;
        }
        // Char literals (and byte chars) versus lifetimes.
        if ch == '\'' || (ch == 'b' && i + 1 < n && c[i + 1] == '\'') {
            let q = if ch == 'b' { i + 1 } else { i };
            if q + 1 < n && c[q + 1] == '\\' {
                // `'\''`, `'\\'`, `'\u{..}'`: the escaped char is never the closing quote.
                let mut j = q + 3;
                while j < n && c[j] != '\'' {
                    j += 1;
                }
                i = (j + 1).min(n);
                continue;
            }
            if q + 2 < n && c[q + 2] == '\'' {
                i = q + 3;
                continue;
            }
            // A lifetime (`'a`): the quote alone; its name reads as an ident next.
            i = q + 1;
            continue;
        }
        if is_ident_start(ch) {
            let start = i;
            while i < n && is_ident_char(c[i]) {
                i += 1;
            }
            out.push(Tok::Ident(c[start..i].iter().collect()));
            continue;
        }
        if ch.is_ascii_digit() {
            while i < n && (is_ident_char(c[i]) || c[i] == '.') {
                i += 1;
            }
            continue;
        }
        out.push(Tok::Punct(ch));
        i += 1;
    }
    out
}

/// The name a file's DOOR-CELLS include stands under in [`FileItems::decls`]: the composition root's
/// `include!(concat!(env!("OUT_DIR"), "/door_cells.rs"))`, which its build script writes as one
/// `#[path]` module per `plane-door` row of the crate's `[package.metadata.busbar.linked]` (each a
/// door plane's own root cells, at its crate's `tests/root/mod.rs`). Not an identifier, so no real
/// module is ever mistaken for it; [`module_tree`] reads the rows off the manifest instead.
pub const DOOR_CELLS: &str = "<door-cells>";

/// The generated file the composition root includes its door planes' own root cells from.
const DOOR_CELLS_FILE: &str = "/door_cells.rs";

/// The name a file's DRIVER-PROOFS include stands under in [`FileItems::decls`]: the composition
/// root's `include!(concat!(env!("OUT_DIR"), "/driver_proofs.rs"))` (its `tests/hook_parity_driver`
/// target), which its build script writes as `#[path = ".."] pub(crate) mod proofs;` at the plane
/// crate's `tests/on_driver/mod.rs` for the one enabled `[package.metadata.busbar.driver-proofs]`
/// row. Not an identifier, so no real module is ever mistaken for it; [`module_tree`] reads the row
/// off the manifest instead ([`driver_proof_rows`]).
pub const DRIVER_PROOFS: &str = "<driver-proofs>";

/// The generated file a test target includes the driver-proofs plane's own cases from.
pub const DRIVER_PROOFS_FILE: &str = "/driver_proofs.rs";

/// The module the build script declares the driver-proofs cases under (build.rs
/// `driver_proofs_source`).
const DRIVER_PROOFS_MODULE: &str = "proofs";

/// The stand-in name of the generated module file an `include!` (its tokens after the `!`) names:
/// [`DOOR_CELLS`] or [`DRIVER_PROOFS`]; `None` for any other include.
fn generated_include(after_bang: &[Tok]) -> Option<&'static str> {
    after_bang.iter().take(14).find_map(|tok| match tok {
        Tok::Str(s) if s == DOOR_CELLS_FILE => Some(DOOR_CELLS),
        Tok::Str(s) if s == DRIVER_PROOFS_FILE => Some(DRIVER_PROOFS),
        _ => None,
    })
}

/// The module declarations and fn definitions of one file, each with its inline nesting and the
/// `cfg` predicates it sits under within the file.
#[must_use]
pub fn file_items(src: &str) -> FileItems {
    let t = tokens(src);
    let mut items = FileItems::default();
    // Inline modules open: (name, the brace depth INSIDE it, the cfg predicates it is declared under).
    let mut stack: Vec<(String, usize, Vec<String>)> = Vec::new();
    let mut depth = 0usize;
    let mut pending_path: Option<String> = None;
    // The outer attributes read since the last item boundary, as [`attr_text`] spells them.
    let mut pending_attrs: Vec<String> = Vec::new();
    let nest_of = |stack: &[(String, usize, Vec<String>)]| -> Vec<String> {
        stack.iter().map(|(m, _, _)| m.clone()).collect()
    };
    let cfgs_of = |stack: &[(String, usize, Vec<String>)], own: &[String]| -> Vec<String> {
        stack
            .iter()
            .flat_map(|(_, _, c)| c.iter().cloned())
            .chain(own.iter().filter_map(|a| cfg_predicate(a)))
            .collect()
    };
    let mut i = 0;
    while i < t.len() {
        match &t[i] {
            // An attribute: `#[..]` (outer) or `#![..]` (inner), read to its matching `]`.
            Tok::Punct('#') => {
                let inner = matches!(t.get(i + 1), Some(Tok::Punct('!')));
                let open = if inner { i + 2 } else { i + 1 };
                if matches!(t.get(open), Some(Tok::Punct('['))) {
                    let mut level = 0usize;
                    let mut k = open;
                    while k < t.len() {
                        match &t[k] {
                            Tok::Punct('[') => level += 1,
                            Tok::Punct(']') => {
                                level -= 1;
                                if level == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        k += 1;
                    }
                    let body = &t[open + 1..k.min(t.len())];
                    match body {
                        // `#[path = "..."]`
                        [Tok::Ident(p), Tok::Punct('='), Tok::Str(s)] if p == "path" && !inner => {
                            pending_path = Some(s.clone());
                        }
                        _ if inner => {
                            // `#![cfg(..)]` gates the module it sits in: the inline module open
                            // around it, or the whole file.
                            if let Some(pred) = cfg_predicate(&attr_text(body)) {
                                match stack.last_mut() {
                                    Some((_, _, c)) => c.push(pred),
                                    None => items.file_cfgs.push(pred),
                                }
                            }
                        }
                        _ => pending_attrs.push(attr_text(body)),
                    }
                    i = k + 1;
                    continue;
                }
            }
            Tok::Ident(kw) if kw == "mod" => {
                if let Some(Tok::Ident(name)) = t.get(i + 1) {
                    let nest = nest_of(&stack);
                    match t.get(i + 2) {
                        Some(Tok::Punct(';')) => {
                            items.decls.push(ModDecl {
                                nest,
                                name: name.clone(),
                                path: pending_path.take(),
                                cfgs: cfgs_of(&stack, &pending_attrs),
                            });
                            pending_attrs.clear();
                            i += 3;
                            continue;
                        }
                        Some(Tok::Punct('{')) => {
                            let own: Vec<String> = pending_attrs
                                .iter()
                                .filter_map(|a| cfg_predicate(a))
                                .collect();
                            depth += 1;
                            stack.push((name.clone(), depth, own));
                            pending_path = None;
                            pending_attrs.clear();
                            i += 3;
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            Tok::Ident(kw) if kw == "fn" => {
                if let Some(Tok::Ident(name)) = t.get(i + 1) {
                    items.fns.push(FnItem {
                        nest: nest_of(&stack),
                        name: name.clone(),
                        cfgs: cfgs_of(&stack, &pending_attrs),
                        attrs: pending_attrs
                            .iter()
                            .filter(|a| cfg_predicate(a).is_none())
                            .cloned()
                            .collect(),
                    });
                    pending_attrs.clear();
                    i += 2;
                    continue;
                }
            }
            // `include!(concat!(env!("OUT_DIR"), "/door_cells.rs"))`: the door planes' own root
            // cells, one module per manifest row ([`DOOR_CELLS`]); `.."/driver_proofs.rs"))`: the
            // driver-proofs plane's own cases ([`DRIVER_PROOFS`]).
            Tok::Ident(kw)
                if kw == "include"
                    && matches!(t.get(i + 1), Some(Tok::Punct('!')))
                    && generated_include(&t[i + 2..]).is_some() =>
            {
                items.decls.push(ModDecl {
                    nest: nest_of(&stack),
                    name: generated_include(&t[i + 2..])
                        .unwrap_or(DOOR_CELLS)
                        .to_string(),
                    path: None,
                    cfgs: cfgs_of(&stack, &pending_attrs),
                });
                pending_path = None;
                pending_attrs.clear();
            }
            Tok::Punct('{') => {
                depth += 1;
                pending_path = None;
                pending_attrs.clear();
            }
            Tok::Punct('}') => {
                while stack.last().is_some_and(|(_, d, _)| *d == depth) {
                    stack.pop();
                }
                depth = depth.saturating_sub(1);
                pending_path = None;
                pending_attrs.clear();
            }
            Tok::Punct(';') => {
                pending_path = None;
                pending_attrs.clear();
            }
            _ => {}
        }
        i += 1;
    }
    items
}

/// `a/b/../c` -> `a/c`, `a/./b` -> `a/b` (repo-relative, `/`-separated).
fn normalize(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

fn join(dir: &str, rest: &str) -> String {
    if dir.is_empty() {
        normalize(rest)
    } else {
        normalize(&format!("{dir}/{rest}"))
    }
}

fn parent(file: &str) -> String {
    file.rsplit_once('/')
        .map_or_else(String::new, |(d, _)| d.to_string())
}

/// THE MODULE TREE of one crate: every file reached from its root file, with every module path
/// that reaches it, and what each file holds.
#[derive(Debug, Default)]
pub struct ModuleTree {
    /// file -> the module paths (`::`-joined, the crate root `""`) that reach it.
    pub paths: BTreeMap<String, BTreeSet<String>>,
    /// file -> its items.
    pub items: BTreeMap<String, FileItems>,
    /// (file, module path) -> the `cfg` predicates that module is compiled under: every
    /// declaration and inline module on the way from the crate root, outermost first, then the
    /// file's own `#![cfg]`s. A door-cells module adds `feature="<row>"`, the filter its build
    /// script includes it under.
    pub chains: BTreeMap<(String, String), Vec<String>>,
}

/// The `[table]` rows of a Cargo manifest, `key = value` one per line, both sides unquoted (the
/// shape the composition root's build script reads its own metadata tables in).
fn manifest_rows(manifest: &str, table: &str) -> Vec<(String, String)> {
    let header = format!("[{table}]");
    let mut in_table = false;
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if let (true, Some((k, v))) = (in_table, code.split_once('=')) {
            rows.push((
                k.trim().trim_matches('"').to_string(),
                v.trim().trim_matches('"').to_string(),
            ));
        }
    }
    rows
}

/// The `linked-axes` word of a plane's memory-ABI door row (the build script's `PLANE_DOOR_AXIS`).
const PLANE_DOOR_AXIS: &str = "plane-door";

/// THE DOOR-CELLS MODULES of the crate whose root file is `root_file`: for every
/// `[package.metadata.busbar.linked]` row of its manifest (cargo feature -> plane crate) whose
/// `[package.metadata.busbar.linked-axes]` value names the `plane-door` axis (the rows its build
/// script mounts cells for), the module its build script names for the feature and the
/// repo-relative `tests/root/mod.rs` of the crate its `[dependencies]` row names: at the row's
/// `path` for a path dependency, and at the crate's census mount (`crates/<crate>`, a sibling of the
/// root's own directory, where the base layer lays the pinned checkout) for a PINNED one. The root's
/// build script compiles both alike (`DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`) and cites a door's cells
/// by that same mount (`DOOR_CELLS_FILES`), so a plane door that left for its own repo keeps its root
/// cells: they are read from the pin, never skipped.
pub fn door_cells(read: &dyn Fn(&str) -> Option<String>, root_file: &str) -> Vec<(String, String)> {
    door_cell_rows(read, root_file)
        .into_iter()
        .map(|(ident, file, _)| (ident, file))
        .collect()
}

/// [`door_cells`], each row with the cargo feature that keys it: `(module, file, feature)`. The
/// build script includes a row's module only when that feature is on.
pub fn door_cell_rows(
    read: &dyn Fn(&str) -> Option<String>,
    root_file: &str,
) -> Vec<(String, String, String)> {
    let crate_dir = parent(&parent(root_file));
    let Some(manifest) = read(&join(&crate_dir, "Cargo.toml")) else {
        return Vec::new();
    };
    let deps = manifest_rows(&manifest, "dependencies");
    let axes = manifest_rows(&manifest, "package.metadata.busbar.linked-axes");
    manifest_rows(&manifest, "package.metadata.busbar.linked")
        .into_iter()
        .filter(|(feature, _)| {
            axes.iter()
                .any(|(f, a)| f == feature && a.split_whitespace().any(|x| x == PLANE_DOOR_AXIS))
        })
        .filter_map(|(feature, krate)| {
            let dep = deps.iter().find(|(k, _)| *k == krate)?;
            let dir = match dep
                .1
                .split_once("path")
                .and_then(|(_, at)| at.split('"').nth(1))
            {
                Some(path) => join(&crate_dir, path),
                None => join(&parent(&crate_dir), &krate),
            };
            Some((
                feature.replace('-', "_"),
                join(&dir, "tests/root/mod.rs"),
                feature,
            ))
        })
        .collect()
}

/// [`file_items`] of `src`, read once per process for each distinct text. A gate's self-test walks
/// the same crates once per planted case, and every walk would otherwise re-tokenise every file;
/// the result depends on the text alone, so the text is the key.
fn file_items_memo(src: &str) -> FileItems {
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<FileItems>>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(Default::default);
    if let Some(hit) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(src)
    {
        return hit.as_ref().clone();
    }
    let items = file_items(src);
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(src.to_string(), std::sync::Arc::new(items.clone()));
    items
}

/// THE DRIVER-PROOFS MODULE of the crate one of whose targets is `root_file`: for every
/// `[package.metadata.busbar.driver-proofs]` row of its manifest (cargo feature -> plane crate), the
/// repo-relative `tests/on_driver/mod.rs` of the crate its `[dependencies]` row names (at the row's
/// `path`, or at the crate's census mount for a pinned one, as [`door_cell_rows`]), with the
/// feature that keys it: `(file, feature)`. The crate is the nearest directory above `root_file`
/// holding a `Cargo.toml` (a test target sits deeper than `src/main.rs`). The build script writes
/// the module only for an ENABLED row (two enabled rows are a compile error), so each row's chain
/// carries its feature.
pub fn driver_proof_rows(
    read: &dyn Fn(&str) -> Option<String>,
    root_file: &str,
) -> Vec<(String, String)> {
    let mut crate_dir = parent(root_file);
    let manifest = loop {
        if let Some(m) = read(&join(&crate_dir, "Cargo.toml")) {
            break m;
        }
        if crate_dir.is_empty() {
            return Vec::new();
        }
        crate_dir = parent(&crate_dir);
    };
    let deps = manifest_rows(&manifest, "dependencies");
    manifest_rows(&manifest, "package.metadata.busbar.driver-proofs")
        .into_iter()
        .filter_map(|(feature, krate)| {
            let dep = deps.iter().find(|(k, _)| *k == krate)?;
            let dir = match dep
                .1
                .split_once("path")
                .and_then(|(_, at)| at.split('"').nth(1))
            {
                Some(path) => join(&crate_dir, path),
                None => join(&parent(&crate_dir), &krate),
            };
            Some((join(&dir, "tests/on_driver/mod.rs"), feature))
        })
        .collect()
}

/// One file the walk still has to read: the module path it is reached under, the directory its
/// children resolve against, the non-mod-rs stem if any, and the cfg predicates of every
/// declaration on the way to it.
struct Visit {
    file: String,
    module: String,
    dir: String,
    relative: Option<String>,
    on_the_way: Vec<String>,
}

/// Walk the crate whose root file is `root_file` (repo-relative, e.g. `crates/busbar/src/main.rs`),
/// reading each file through `read` (repo-relative path -> its text, `None` when absent).
#[must_use]
pub fn module_tree(read: &dyn Fn(&str) -> Option<String>, root_file: &str) -> ModuleTree {
    let mut tree = ModuleTree::default();
    let mut work: Vec<Visit> = vec![Visit {
        file: root_file.to_string(),
        module: String::new(),
        dir: parent(root_file),
        relative: None,
        on_the_way: Vec::new(),
    }];
    while let Some(Visit {
        file,
        module,
        dir,
        relative,
        on_the_way,
    }) = work.pop()
    {
        let fresh = tree
            .paths
            .entry(file.clone())
            .or_default()
            .insert(module.clone());
        if !fresh {
            continue;
        }
        let items = match tree.items.get(&file) {
            Some(it) => it.clone(),
            None => {
                let Some(src) = read(&file) else {
                    continue;
                };
                let it = file_items_memo(&src);
                tree.items.insert(file.clone(), it.clone());
                it
            }
        };
        let chain: Vec<String> = on_the_way
            .iter()
            .chain(items.file_cfgs.iter())
            .cloned()
            .collect();
        tree.chains
            .insert((file.clone(), module.clone()), chain.clone());
        for ModDecl {
            nest,
            name,
            path: path_attr,
            cfgs: decl_cfgs,
        } in &items.decls
        {
            let child_chain: Vec<String> = chain.iter().chain(decl_cfgs.iter()).cloned().collect();
            if name == DRIVER_PROOFS {
                for (cases, feature) in driver_proof_rows(read, root_file) {
                    let child_module = std::iter::once(module.as_str())
                        .filter(|m| !m.is_empty())
                        .map(str::to_string)
                        .chain(nest.iter().cloned())
                        .chain(std::iter::once(DRIVER_PROOFS_MODULE.to_string()))
                        .collect::<Vec<_>>()
                        .join("::");
                    let cases_dir = parent(&cases);
                    let mut cases_chain = child_chain.clone();
                    cases_chain.push(format!("feature=\"{feature}\""));
                    work.push(Visit {
                        file: cases,
                        module: child_module,
                        dir: cases_dir,
                        relative: None,
                        on_the_way: cases_chain,
                    });
                }
                continue;
            }
            if name == DOOR_CELLS {
                for (ident, cells, feature) in door_cell_rows(read, root_file) {
                    let child_module = std::iter::once(module.as_str())
                        .filter(|m| !m.is_empty())
                        .map(str::to_string)
                        .chain(nest.iter().cloned())
                        .chain(std::iter::once(ident))
                        .collect::<Vec<_>>()
                        .join("::");
                    let cells_dir = parent(&cells);
                    let mut cells_chain = child_chain.clone();
                    cells_chain.push(format!("feature=\"{feature}\""));
                    work.push(Visit {
                        file: cells,
                        module: child_module,
                        dir: cells_dir,
                        relative: None,
                        on_the_way: cells_chain,
                    });
                }
                continue;
            }
            let child_module = std::iter::once(module.as_str())
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .chain(nest.iter().cloned())
                .chain(std::iter::once(name.clone()))
                .collect::<Vec<_>>()
                .join("::");
            // Inside an inline module, children resolve under the non-mod-rs stem (if any) and the
            // inline module names; at the top level a `#[path]` is relative to the file's own
            // directory and a default lookup to `<dir>/<stem>/`.
            let mut inline_dir = dir.clone();
            if !nest.is_empty() {
                if let Some(stem) = &relative {
                    inline_dir = join(&inline_dir, stem);
                }
                for m in nest {
                    inline_dir = join(&inline_dir, m);
                }
            }
            match path_attr {
                Some(p) => {
                    let child = join(&inline_dir, p);
                    let child_dir = parent(&child);
                    work.push(Visit {
                        file: child,
                        module: child_module,
                        dir: child_dir,
                        relative: None,
                        on_the_way: child_chain,
                    });
                }
                None => {
                    let base = if nest.is_empty() {
                        match &relative {
                            Some(stem) => join(&dir, stem),
                            None => dir.clone(),
                        }
                    } else {
                        inline_dir
                    };
                    let flat = join(&base, &format!("{name}.rs"));
                    let nested = join(&base, &format!("{name}/mod.rs"));
                    if read(&flat).is_some() {
                        work.push(Visit {
                            file: flat,
                            module: child_module,
                            dir: base,
                            relative: Some(name.clone()),
                            on_the_way: child_chain,
                        });
                    } else if read(&nested).is_some() {
                        let nested_dir = parent(&nested);
                        work.push(Visit {
                            file: nested,
                            module: child_module,
                            dir: nested_dir,
                            relative: None,
                            on_the_way: child_chain,
                        });
                    }
                }
            }
        }
    }
    tree
}

/// One fn a ledger cites, resolved: its libtest name, the `cfg` predicates its MODULE is compiled
/// under (from the crate root to its file, then the file's own), and each definition of that name
/// at that nesting (one, or several `cfg`-alternative bodies): its own `cfg` predicates within the
/// file and its other attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCell {
    pub path: String,
    pub chain: Vec<String>,
    pub defs: Vec<FnItem>,
}

/// The libtest name of `func` in `file`, or why there is none: the file is not reached, or the file
/// or the fn is reached two ways (ambiguity is refused, naming both, never guessed).
///
/// # Errors
/// A sentence naming the file or fn and what made it unresolvable.
pub fn resolve(tree: &ModuleTree, file: &str, func: &str) -> Result<String, String> {
    resolve_cell(tree, file, func).map(|c| c.path)
}

/// [`resolve`], with what decides whether a build compiles the fn and whether the harness runs it:
/// the cfgs on the way to its module and each definition's own cfgs and attributes.
///
/// # Errors
/// As [`resolve`].
pub fn resolve_cell(tree: &ModuleTree, file: &str, func: &str) -> Result<ResolvedCell, String> {
    let Some(paths) = tree.paths.get(file) else {
        return Err(format!(
            "{file} is reached by no `mod` declaration from the crate root, so no test in it runs"
        ));
    };
    if paths.len() > 1 {
        return Err(format!(
            "{file} is AMBIGUOUS: the crate reaches it as {}; name one",
            paths.iter().cloned().collect::<Vec<_>>().join(" and ")
        ));
    }
    let module = paths.iter().next().cloned().unwrap_or_default();
    let defs: Vec<&FnItem> = tree
        .items
        .get(file)
        .map(|it| it.fns.iter().filter(|f| f.name == func).collect())
        .unwrap_or_default();
    let nests: BTreeSet<&Vec<String>> = defs.iter().map(|f| &f.nest).collect();
    let mut nests = nests.into_iter();
    let Some(nest) = nests.next() else {
        return Err(format!("no `fn {func}` in {file}"));
    };
    if let Some(other) = nests.next() {
        return Err(format!(
            "`fn {func}` in {file} is AMBIGUOUS: it is defined under `{}` and `{}`",
            nest.join("::"),
            other.join("::")
        ));
    }
    let chain = tree
        .chains
        .get(&(file.to_string(), module.clone()))
        .cloned()
        .unwrap_or_default();
    let path = std::iter::once(module)
        .filter(|m| !m.is_empty())
        .chain(nest.iter().cloned())
        .chain(std::iter::once(func.to_string()))
        .collect::<Vec<_>>()
        .join("::");
    Ok(ResolvedCell {
        path,
        chain,
        defs: defs.into_iter().cloned().collect(),
    })
}

#[cfg(test)]
#[path = "tests/libtest_path_tests.rs"]
mod tests;
