//! THE RECORD CLOSURE, CLOSED (q128 section 11; Law 8: a measurement proves nothing fell outside).
//!
//! The field closure in [`super::derive_population`] resolves a field's type word through the
//! WRITER file's `use` lines and the member's crate, and steps over every word it cannot resolve.
//! So `AuditRecord.usage: Usage` reached `Usage`, whose `lines: Vec<UsageLine>` names a type
//! `busbar-kernel-audit` only RE-EXPORTS (`pub use busbar_contract::caps::UsageLine`) and the writer
//! never imports: the word resolved to nothing, was dropped, and a price on the line every audit
//! record journals passed green.
//!
//! This pass closes the population over what each member's fields name, read the way the compiler
//! reads them: a word is resolved in the file that DECLARES the field — that file's own items, its
//! `use` items (renames and globs included), the Rust prelude — and a path is followed module by
//! module, through every `pub use` re-export, to the one item it names. A type alias stands for its
//! right-hand side; a type a `macro_rules!` stamps out (`declare_id!`'s `pub struct $name(..)`) is
//! the field-less newtype the macro declares. What it reaches joins the population, and what a
//! journal writer's chain reaches is written whole, as the writer chain already reads it.
//!
//! WHAT IT CANNOT RESOLVE IS A GAP, never a word stepped over: a name with no definition, a path
//! into a module the scan cannot find, a type from a crate outside the workspace. A gap refuses
//! both record rows, as an unresolvable journal root always has.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::scan;

use super::{parse_decls, Field, Member, TypeDecl, Written};

/// The types the Rust prelude names without an import. Anything else a field names unqualified is
/// declared or imported in the field's own file, or the scan cannot vouch for it.
const PRELUDE_TYPES: &[&str] = &["Option", "Result", "Vec", "String", "Box"];

/// The standard library's crate roots: a path through one names a std type, which holds no record.
const STD_ROOTS: &[&str] = &["std", "core", "alloc"];

/// How deep a chain of re-exports and aliases is followed before the scan calls it a gap.
const MAX_DEPTH: usize = 16;

/// What one production source file declares and imports, as this pass reads it.
struct FileIndex {
    /// Its `struct`/`enum` declarations ([`parse_decls`]) and the newtypes its macros stamp out.
    decls: Vec<TypeDecl>,
    /// `type Name = rhs;`, by name: the alias stands for its right-hand side.
    aliases: BTreeMap<String, String>,
    /// Every `use` item: the name it binds (`*` for a glob) and the path it names.
    imports: Vec<(String, Vec<String>)>,
    /// The generic parameters of each declared type, which a field may name and which resolve to
    /// nothing because they are not types of the tree.
    generics: BTreeMap<String, Vec<String>>,
}

/// What a type word or path names.
enum Named {
    /// A declared `struct`/`enum` (or macro newtype), the population's unit.
    Decl(TypeDecl),
    /// A type alias: its right-hand side, read in the file that declares it.
    Alias { file: String, rhs: String },
    /// A prelude or std type: no record of the tree.
    Std,
}

struct Resolver<'a> {
    cx: &'a Ctx,
    files: BTreeMap<String, Option<FileIndex>>,
}

impl<'a> Resolver<'a> {
    fn new(cx: &'a Ctx) -> Self {
        Resolver {
            cx,
            files: BTreeMap::new(),
        }
    }

    fn index(&mut self, rel: &str) -> Option<&FileIndex> {
        if !self.files.contains_key(rel) {
            let idx = self.cx.read(rel).ok().map(|src| index_file(rel, &src));
            self.files.insert(rel.to_string(), idx);
        }
        self.files.get(rel).and_then(Option::as_ref)
    }

    fn exists(&self, rel: &str) -> bool {
        self.cx.exists(rel)
    }

    /// The crate root file (`lib.rs`, else `main.rs`) of the crate whose `src` holds `rel`.
    fn crate_root_of(&self, rel: &str) -> Option<String> {
        let src = crate_src_of(rel)?;
        self.crate_root_in(&src)
    }

    fn crate_root_in(&self, src: &str) -> Option<String> {
        ["lib.rs", "main.rs"]
            .iter()
            .map(|f| format!("{src}/{f}"))
            .find(|f| self.exists(f))
    }

    /// The file of module `seg` declared under module file `module`.
    fn child(&self, module: &str, seg: &str) -> Option<String> {
        let dir = module_dir(module);
        [format!("{dir}/{seg}.rs"), format!("{dir}/{seg}/mod.rs")]
            .into_iter()
            .find(|f| self.exists(f))
    }

    /// The file of the module that declares module file `module`.
    fn parent(&self, module: &str) -> Option<String> {
        let dir = module_dir(module);
        if dir.ends_with("/src") {
            return None;
        }
        let up = dir.rsplit_once('/')?.0;
        [
            format!("{up}.rs"),
            format!("{up}/mod.rs"),
            format!("{up}/lib.rs"),
            format!("{up}/main.rs"),
        ]
        .into_iter()
        .find(|f| f != module && self.exists(f) && module_dir(f) == up)
    }

    /// The item a word names in module file `module`: declared there, or bound by one of its `use`
    /// items. `Ok(None)` when the module neither declares nor imports it.
    fn in_module(&mut self, word: &str, module: &str, depth: usize) -> Result<Option<Named>, String> {
        if depth > MAX_DEPTH {
            return Err(format!("is re-exported or aliased deeper than {MAX_DEPTH} hops"));
        }
        let Some(idx) = self.index(module) else {
            return Err(format!("is looked up in {module}, which cannot be read"));
        };
        if let Some(d) = idx.decls.iter().find(|d| d.name == word) {
            return Ok(Some(Named::Decl(d.clone())));
        }
        if let Some(rhs) = idx.aliases.get(word) {
            return Ok(Some(Named::Alias {
                file: module.to_string(),
                rhs: rhs.clone(),
            }));
        }
        let imports = idx.imports.clone();
        if let Some((_, path)) = imports.iter().find(|(bound, _)| bound == word) {
            return self.path(path, module, depth + 1).map(Some);
        }
        for (_, path) in imports.iter().filter(|(bound, _)| bound == "*") {
            let mut through = path.clone();
            through.push(word.to_string());
            if let Ok(named) = self.path(&through, module, depth + 1) {
                return Ok(Some(named));
            }
        }
        Ok(None)
    }

    /// The item a single type word names, read from file `from`.
    fn word(&mut self, word: &str, from: &str) -> Result<Named, String> {
        if let Some(named) = self.in_module(word, from, 0)? {
            return Ok(named);
        }
        if PRELUDE_TYPES.contains(&word) {
            return Ok(Named::Std);
        }
        Err("names no definition, import or prelude type the scan can find".to_string())
    }

    /// The item a path names, read from file `from`, followed module by module.
    fn path(&mut self, path: &[String], from: &str, depth: usize) -> Result<Named, String> {
        let Some((head, rest)) = path.split_first() else {
            return Err("is an empty path".to_string());
        };
        if STD_ROOTS.contains(&head.as_str()) {
            return Ok(Named::Std);
        }
        let mut module = match head.as_str() {
            "crate" => self.crate_root_of(from),
            "self" => Some(from.to_string()),
            "super" => self.parent(from),
            krate => {
                let src = format!("crates/{}/src", krate.replace('_', "-"));
                if self.exists(&src) {
                    self.crate_root_in(&src)
                } else if let Some(child) = self.child(from, krate) {
                    Some(child)
                } else if rest.is_empty() {
                    // A one-segment path is a word of `from` itself.
                    return self.word(head, from);
                } else {
                    return Err(format!(
                        "names a type of `{krate}`, a crate outside the workspace the scan cannot read"
                    ));
                }
            }
        }
        .ok_or_else(|| format!("names a module path (`{}`) the scan cannot follow", path.join("::")))?;
        let Some((last, middle)) = rest.split_last() else {
            return Err(format!("names the module `{}`, not a type", path.join("::")));
        };
        for seg in middle {
            module = match seg.as_str() {
                "super" => self.parent(&module),
                "self" => Some(module),
                // A module re-exported under this name (`pub use inner as seg;`) is not followed:
                // it is a gap below, not a guess.
                _ => self.child(&module, seg),
            }
            .ok_or_else(|| {
                format!("names a module path (`{}`) the scan cannot follow", path.join("::"))
            })?;
        }
        match self.in_module(last, &module, depth + 1)? {
            Some(named) => Ok(named),
            None => Err(format!(
                "names `{}`, which {module} neither declares nor re-exports",
                path.join("::")
            )),
        }
    }

    /// Every declared type a field's type text reaches from file `file`, aliases followed, and a
    /// gap for every word it cannot resolve. `params` are the owner's generic parameters.
    fn reached(
        &mut self,
        file: &str,
        ty: &str,
        params: &[String],
        seen_aliases: &mut BTreeSet<(String, String)>,
    ) -> (Vec<TypeDecl>, Vec<(String, String)>) {
        let mut decls = Vec::new();
        let mut gaps = Vec::new();
        for path in type_paths(ty) {
            if path.len() == 1 {
                let w = &path[0];
                // Lower-case single words are primitives, lifetimes and keywords (`u64`, `'static`,
                // `str`, `dyn`, `mut`); a money primitive is judged by type elsewhere.
                if !w.starts_with(|c: char| c.is_ascii_uppercase()) || params.contains(w) {
                    continue;
                }
            }
            let named = if path.len() == 1 {
                self.word(&path[0], file)
            } else {
                self.path(&path, file, 0)
            };
            match named {
                Ok(Named::Decl(d)) => decls.push(d),
                Ok(Named::Std) => {}
                Ok(Named::Alias { file: at, rhs }) => {
                    if seen_aliases.insert((at.clone(), rhs.clone())) {
                        let (d, g) = self.reached(&at, &rhs, &[], seen_aliases);
                        decls.extend(d);
                        gaps.extend(g);
                    }
                }
                Err(why) => gaps.push((path.join("::"), why)),
            }
        }
        (decls, gaps)
    }

    fn generics_of(&mut self, d: &TypeDecl) -> Vec<String> {
        self.index(&d.file)
            .and_then(|i| i.generics.get(&d.name).cloned())
            .unwrap_or_default()
    }

    /// The declared type `name` in `file`, as this pass indexes it.
    fn decl_at(&mut self, file: &str, name: &str) -> Option<TypeDecl> {
        self.index(file)
            .and_then(|i| i.decls.iter().find(|d| d.name == name).cloned())
    }
}

/// CLOSE THE POPULATION. Every type a journal writer's chain reaches is written whole (its fields
/// join `written`), every type any member's field reaches joins `members`, and every field type
/// word that resolves to nothing the scan can read is a gap.
pub(super) fn close(
    cx: &Ctx,
    members: &mut Vec<Member>,
    written: &mut Vec<Written>,
    gaps: &mut Vec<String>,
) {
    let mut r = Resolver::new(cx);
    let key = |d: &TypeDecl| (d.file.clone(), d.name.clone());
    let mut known: BTreeSet<(String, String)> = members.iter().map(|m| key(&m.decl)).collect();
    let mut admit = |d: &TypeDecl, members: &mut Vec<Member>| {
        if known.insert(key(d)) {
            members.push(Member { decl: d.clone() });
        }
    };

    // THE SERIALIZATION READ, CLOSED: a type a written field names is written whole.
    let mut on_chain: BTreeSet<(String, usize, String)> = written
        .iter()
        .map(|w| (w.file.clone(), w.field.line, w.field.name.clone()))
        .collect();
    let mut chain: Vec<(TypeDecl, String)> = Vec::new();
    for w in written.iter() {
        let params = r
            .decl_at(&w.file, &w.owner)
            .map(|d| r.generics_of(&d))
            .unwrap_or_default();
        let (reached, _) = r.reached(&w.file, &w.field.ty, &params, &mut BTreeSet::new());
        chain.extend(reached.into_iter().map(|d| (d, w.writer.clone())));
    }
    let mut whole: BTreeSet<(String, String)> = BTreeSet::new();
    while let Some((d, writer)) = chain.pop() {
        if !whole.insert(key(&d)) {
            continue;
        }
        admit(&d, members);
        let params = r.generics_of(&d);
        for f in &d.fields {
            if on_chain.insert((d.file.clone(), f.line, f.name.clone())) {
                written.push(Written {
                    owner: d.name.clone(),
                    file: d.file.clone(),
                    field: f.clone(),
                    writer: writer.clone(),
                });
            }
            let (reached, _) = r.reached(&d.file, &f.ty, &params, &mut BTreeSet::new());
            chain.extend(reached.into_iter().map(|t| (t, writer.clone())));
        }
    }

    // THE MEMBER CLOSURE: every type any member's field names, and a gap for every word unread.
    let mut queue: Vec<TypeDecl> = members.iter().map(|m| m.decl.clone()).collect();
    let mut visited: BTreeSet<(String, String)> = BTreeSet::new();
    let mut gap_lines: BTreeSet<String> = BTreeSet::new();
    while let Some(d) = queue.pop() {
        if !visited.insert(key(&d)) {
            continue;
        }
        let params = r.generics_of(&d);
        for f in &d.fields {
            let (reached, unread) = r.reached(&d.file, &f.ty, &params, &mut BTreeSet::new());
            for (word, why) in unread {
                gap_lines.insert(gap(&d, f, &word, &why));
            }
            for t in reached {
                admit(&t, members);
                queue.push(t);
            }
        }
    }
    gaps.extend(gap_lines);
}

fn gap(owner: &TypeDecl, f: &Field, word: &str, why: &str) -> String {
    format!(
        "`{word}` in the type of `{}.{}` ({}:{}) {why} — the record closure cannot vouch for a \
         type it cannot read",
        owner.name, f.name, owner.file, f.line
    )
}

/// `crates/<name>/src` of a file under it.
fn crate_src_of(rel: &str) -> Option<String> {
    let rest = rel.strip_prefix("crates/")?;
    let (krate, tail) = rest.split_once('/')?;
    tail.starts_with("src/")
        .then(|| format!("crates/{krate}/src"))
}

/// The directory a module file's child modules live in: its own directory for `mod.rs`, `lib.rs`
/// and `main.rs`, else the file's path without `.rs`.
fn module_dir(module: &str) -> String {
    let (dir, base) = module.rsplit_once('/').unwrap_or(("", module));
    if matches!(base, "mod.rs" | "lib.rs" | "main.rs") {
        dir.to_string()
    } else {
        module.trim_end_matches(".rs").to_string()
    }
}

/// Every path a type's text names, as its segments: `Option<crate::recipe::Recipe>` is `Option`
/// and `crate`, `recipe`, `Recipe`; `&'static str` is `static` and `str`.
fn type_paths(ty: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut word = String::new();
    let chars: Vec<char> = ty.chars().collect();
    let mut i = 0;
    let flush_word = |word: &mut String, cur: &mut Vec<String>| {
        if !word.is_empty() {
            cur.push(std::mem::take(word));
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
            i += 1;
            continue;
        }
        if c == ':' && chars.get(i + 1) == Some(&':') {
            flush_word(&mut word, &mut cur);
            i += 2;
            continue;
        }
        flush_word(&mut word, &mut cur);
        if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        i += 1;
    }
    flush_word(&mut word, &mut cur);
    if !cur.is_empty() {
        out.push(cur);
    }
    out.retain(|p| {
        p.first()
            .is_some_and(|s| !s.starts_with(|c: char| c.is_ascii_digit()))
    });
    out
}

fn index_file(rel: &str, src: &str) -> FileIndex {
    let lines = scan::production_lines(src);
    let code: String = lines
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let mut decls = parse_decls(rel, src);
    decls.extend(macro_newtypes(rel, &code));
    FileIndex {
        generics: generics(&code),
        aliases: aliases(&code),
        imports: imports(&lines),
        decls,
    }
}

/// Strip a leading visibility (`pub`, `pub(crate)`, `pub(in …)`).
fn strip_vis(t: &str) -> &str {
    let t = t.trim_start();
    if let Some(rest) = t.strip_prefix("pub(") {
        return rest.split_once(')').map_or(t, |(_, r)| r.trim_start());
    }
    t.strip_prefix("pub ").map_or(t, str::trim_start)
}

/// Every `use` item of a file's production lines: the name it binds and the path it names.
fn imports(lines: &[(usize, String)]) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut stmt: Option<String> = None;
    for (_, code) in lines {
        let opens = strip_vis(code).starts_with("use ");
        if stmt.is_none() && !opens {
            continue;
        }
        let acc = stmt.get_or_insert_with(String::new);
        acc.push_str(code);
        acc.push(' ');
        if code.contains(';') {
            let full = stmt.take().unwrap_or_default();
            let body = strip_vis(&full)
                .strip_prefix("use ")
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("");
            expand_use(body, &[], &mut out);
        }
    }
    out
}

/// Expand one use tree (`a::b::{C, D as E, f::G, h::*}`) under `prefix`.
fn expand_use(tree: &str, prefix: &[String], out: &mut Vec<(String, Vec<String>)>) {
    let tree = tree.trim().trim_start_matches("::").trim();
    if tree.is_empty() {
        return;
    }
    if let Some(open) = tree.find('{') {
        let head = tree[..open].trim().trim_end_matches("::");
        let mut base = prefix.to_vec();
        base.extend(
            head.split("::")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
        let inner = tree[open + 1..].trim_end().trim_end_matches('}');
        let mut depth = 0i32;
        let mut part = String::new();
        for c in inner.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            if c == ',' && depth == 0 {
                expand_use(&part, &base, out);
                part.clear();
            } else {
                part.push(c);
            }
        }
        expand_use(&part, &base, out);
        return;
    }
    let (path_text, rename) = match tree.split_once(" as ") {
        Some((p, r)) => (p.trim(), Some(r.trim().to_string())),
        None => (tree, None),
    };
    let mut path = prefix.to_vec();
    path.extend(
        path_text
            .split("::")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
    if path.last().is_some_and(|l| l == "*") {
        path.pop();
        out.push(("*".to_string(), path));
        return;
    }
    if path.last().is_some_and(|l| l == "self") {
        path.pop();
    }
    let Some(bound) = rename.or_else(|| path.last().cloned()) else {
        return;
    };
    if bound != "_" {
        out.push((bound, path));
    }
}

/// `type Name<..> = rhs;` at any depth of a file's production code, by name.
fn aliases(code: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for stmt in code.split(';') {
        let line = stmt.lines().last().unwrap_or("");
        let t = strip_vis(line);
        let Some(rest) = t.strip_prefix("type ") else {
            continue;
        };
        let Some((lhs, rhs)) = rest.split_once('=') else {
            continue;
        };
        let name: String = lhs
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.entry(name).or_insert_with(|| rhs.trim().to_string());
        }
    }
    out
}

/// The generic type parameters of each `struct`/`enum` a file's code declares.
fn generics(code: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for line in code.lines() {
        let t = strip_vis(line);
        let Some(rest) = t.strip_prefix("struct ").or_else(|| t.strip_prefix("enum ")) else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim_start();
        let Some(inner) = after.strip_prefix('<') else {
            continue;
        };
        let mut depth = 1i32;
        let mut part = String::new();
        let mut params = Vec::new();
        for c in inner.chars() {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ => {}
            }
            if depth == 0 || (c == ',' && depth == 1) {
                let p = part.trim().trim_start_matches("const ").trim();
                if !p.starts_with('\'') {
                    let ident: String = p
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !ident.is_empty() {
                        params.push(ident);
                    }
                }
                part.clear();
                if depth == 0 {
                    break;
                }
            } else {
                part.push(c);
            }
        }
        out.insert(name, params);
    }
    out
}

/// The text of the brace-delimited block opening at the first `{` at or after `from`, without its
/// braces, and the offset just past it.
fn braced(code: &str, from: usize) -> Option<(&str, usize)> {
    let open = from + code[from..].find('{')?;
    let mut depth = 0i32;
    for (k, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&code[open + 1..open + k], open + k + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// THE NEWTYPES A FILE'S OWN MACROS STAMP OUT. A `macro_rules! m` whose expansion declares
/// `struct $…` declares, at each `m! { … }` invocation in the same file, one type per `Name =>`
/// entry. Its shape is the macro's: a tuple newtype with no named field ([`parse_decls`] reads a
/// tuple struct the same way).
fn macro_newtypes(rel: &str, code: &str) -> Vec<TypeDecl> {
    let mut stampers: Vec<String> = Vec::new();
    let mut at = 0;
    while let Some(k) = code[at..].find("macro_rules!") {
        let start = at + k + "macro_rules!".len();
        let name: String = code[start..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let Some((body, end)) = braced(code, start) else {
            break;
        };
        if body.contains("struct $") && !name.is_empty() {
            stampers.push(name);
        }
        at = end;
    }
    let mut out = Vec::new();
    for m in &stampers {
        let call = format!("{m}!");
        let mut at = 0;
        while let Some(k) = code[at..].find(&call) {
            let start = at + k + call.len();
            // `macro_rules! m` itself is not an invocation.
            if code[..at + k].trim_end().ends_with("macro_rules!") {
                at = start;
                continue;
            }
            let Some((body, end)) = braced(code, start) else {
                break;
            };
            for entry in body.split(';') {
                let Some((lhs, _)) = entry.split_once("=>") else {
                    continue;
                };
                let name: String = lhs
                    .trim_end()
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                    out.push(TypeDecl {
                        name,
                        file: rel.to_string(),
                        fields: Vec::new(),
                    });
                }
            }
            at = end;
        }
    }
    out
}
