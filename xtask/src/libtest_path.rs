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
//! and char literals (and tells a char literal from a lifetime), and reads only `#[path = ".."]`,
//! `mod <ident> ;`, `mod <ident> {`, `fn <ident>` and brace depth. `scripts/capability-equality-summary.py`
//! carries the same algorithm for the equality ledger's own runner.

use std::collections::{BTreeMap, BTreeSet};

/// One token the module reader needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    Punct(char),
}

/// What a file says about modules and fns, with the inline-module nesting each one sits in.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileItems {
    /// `mod <name>;` declarations: (inline nesting, name, `#[path]` value if any).
    pub decls: Vec<(Vec<String>, String, Option<String>)>,
    /// `fn <name>` definitions: (inline nesting, name).
    pub fns: Vec<(Vec<String>, String)>,
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

/// The module declarations and fn definitions of one file, each with its inline nesting.
#[must_use]
pub fn file_items(src: &str) -> FileItems {
    let t = tokens(src);
    let mut items = FileItems::default();
    // Inline modules open: (name, the brace depth INSIDE it).
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut depth = 0usize;
    let mut pending_path: Option<String> = None;
    let mut i = 0;
    while i < t.len() {
        match &t[i] {
            // `#[path = "..."]`
            Tok::Punct('#')
                if matches!(t.get(i + 1), Some(Tok::Punct('[')))
                    && matches!(t.get(i + 2), Some(Tok::Ident(p)) if p == "path")
                    && matches!(t.get(i + 3), Some(Tok::Punct('=')))
                    && matches!(t.get(i + 5), Some(Tok::Punct(']'))) =>
            {
                if let Some(Tok::Str(s)) = t.get(i + 4) {
                    pending_path = Some(s.clone());
                }
                i += 6;
                continue;
            }
            Tok::Ident(kw) if kw == "mod" => {
                if let Some(Tok::Ident(name)) = t.get(i + 1) {
                    let nest: Vec<String> = stack.iter().map(|(m, _)| m.clone()).collect();
                    match t.get(i + 2) {
                        Some(Tok::Punct(';')) => {
                            items.decls.push((nest, name.clone(), pending_path.take()));
                            i += 3;
                            continue;
                        }
                        Some(Tok::Punct('{')) => {
                            depth += 1;
                            stack.push((name.clone(), depth));
                            pending_path = None;
                            i += 3;
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            Tok::Ident(kw) if kw == "fn" => {
                if let Some(Tok::Ident(name)) = t.get(i + 1) {
                    let nest: Vec<String> = stack.iter().map(|(m, _)| m.clone()).collect();
                    items.fns.push((nest, name.clone()));
                    i += 2;
                    continue;
                }
            }
            Tok::Punct('{') => {
                depth += 1;
                pending_path = None;
            }
            Tok::Punct('}') => {
                while stack.last().is_some_and(|(_, d)| *d == depth) {
                    stack.pop();
                }
                depth = depth.saturating_sub(1);
                pending_path = None;
            }
            Tok::Punct(';') => pending_path = None,
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
}

/// Walk the crate whose root file is `root_file` (repo-relative, e.g. `crates/busbar/src/main.rs`),
/// reading each file through `read` (repo-relative path -> its text, `None` when absent).
#[must_use]
pub fn module_tree(read: &dyn Fn(&str) -> Option<String>, root_file: &str) -> ModuleTree {
    let mut tree = ModuleTree::default();
    // (file, module path, directory its children resolve against, the non-mod-rs stem if any)
    let mut work: Vec<(String, String, String, Option<String>)> = vec![(
        root_file.to_string(),
        String::new(),
        parent(root_file),
        None,
    )];
    while let Some((file, module, dir, relative)) = work.pop() {
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
                let it = file_items(&src);
                tree.items.insert(file.clone(), it.clone());
                it
            }
        };
        for (nest, name, path_attr) in &items.decls {
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
                    work.push((child, child_module, child_dir, None));
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
                        work.push((flat, child_module, base, Some(name.clone())));
                    } else if read(&nested).is_some() {
                        let nested_dir = parent(&nested);
                        work.push((nested, child_module, nested_dir, None));
                    }
                }
            }
        }
    }
    tree
}

/// The libtest name of `func` in `file`, or why there is none: the file is not reached, or the file
/// or the fn is reached two ways (ambiguity is refused, naming both, never guessed).
///
/// # Errors
/// A sentence naming the file or fn and what made it unresolvable.
pub fn resolve(tree: &ModuleTree, file: &str, func: &str) -> Result<String, String> {
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
    let nests: BTreeSet<&Vec<String>> = tree
        .items
        .get(file)
        .map(|it| {
            it.fns
                .iter()
                .filter(|(_, n)| n == func)
                .map(|(nest, _)| nest)
                .collect()
        })
        .unwrap_or_default();
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
    Ok(std::iter::once(module)
        .filter(|m| !m.is_empty())
        .chain(nest.iter().cloned())
        .chain(std::iter::once(func.to_string()))
        .collect::<Vec<_>>()
        .join("::"))
}

#[cfg(test)]
#[path = "tests/libtest_path_tests.rs"]
mod tests;
