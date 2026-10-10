//! `cargo xtask gate settings-leak` — AN ADMIN READ NEVER SERVES AN OPERATOR SETTINGS BAG'S VALUES.
//! The successor to `scripts/settings-leak-lint.sh`, rule for rule.
//!
//! An admin-facing PROJECTION may carry the KEY NAMES of an opaque `settings:` bag (`settings_keys`,
//! from `admin::v1::service::settings_keys`, or structurally from `service::redact_settings_bags`)
//! but never the bag itself. This defect class has been found FOUR times, in four independently
//! written projections, each accompanied by a doc comment asserting the bag was safe:
//! `NamedDefView` (an OIDC `client_secret`), `HookView` ("never a secret by contract"; a hook's bag
//! is a `SecretRef` carrier by design), `GET /hooks/{name}/status` (the hook's echo of the
//! secret-RESOLVED bag — plaintext, at READ-ONLY scope) and `GET /config/settings` (the whole
//! `RootSettings`, carrying a `store.settings.url` busbar's own docs spell with a password). A fifth
//! projection will be written the same way; this fails the build instead.
//!
//! Four rows, because the shell had four distinct ways to stop:
//!
//! * `settings-leak:plane-roots` — the mcp and a2a planes RESOLVE. 1.6.0's R-E makes them plugin
//!   crates; they are 71 of the 238 files scanned, so if they leave `busbar-core` the count falls to
//!   167, CLEARS the floor of 100, and the lint goes on printing `ok` over a tree it no longer
//!   reads. The floor catches a root that MOVED; only this catches a root that SPLIT.
//! * `settings-leak:scan-roots` — EACH root is on disk and holds a non-test `.rs`, checked ON ITS
//!   OWN before the total means anything. `find A B C` complains about a missing A to stderr, goes
//!   on listing B and C, and its status is lost to the `< <(…)` the loop read from. `$CORE` is 150
//!   of 277 files, and renaming it leaves 127 — which clears a floor of 100 and prints `passed`.
//! * `settings-leak:scan-floor` — the aggregate floor, which catches a root that moved.
//! * `settings-leak:no-raw-bag` — the finding: R1, a struct field named `settings`/`*_settings`
//!   whose TYPE is not a typed settings type (see [`TypeTree`]); R2, a hand-built `json!` member
//!   named `"settings"` — but NOT the head of an inline JSON-SCHEMA sub-schema, which describes the
//!   shape of a bag and never carries one (see [`opens_schema_fragment`] for how narrowly that is
//!   recognised, and the selftest case that proves a real bag written beside a schema fragment is
//!   still named); R3, an allow marker that carries no reason.
//!
//! R1 JUDGES THE TYPE, NOT ITS SPELLING. It used to match two spellings (`Map<` and `Value`), so
//! a `HashMap<String, Value>`, a `BTreeMap`, a `serde_yaml::Value`, a `Box<RawValue>` or an alias
//! carried the defect class back GREEN. The rule is now an ALLOWLIST of what is safe, derived from
//! the tree, so a spelling nobody thought of defaults to RED: a field named `*settings` (any case)
//! is a raw bag unless its type — through `&`/`*const`/slices/arrays, the wrappers in [`WRAPPERS`],
//! every `type X = …;` alias and single-field newtype the tree declares, and every generic wrapper
//! the tree serializes — lands on a type the scanned tree declares FIELD BY FIELD (a struct with
//! named fields, a unit struct, an enum, a union) or on one of the tree's own REDACTED wrappers (a
//! generic newtype such as `Redacted<T>` that implements no `Serialize`, so nothing can serve what
//! it holds). Any map, any JSON/YAML/TOML value, raw bytes, a string, and any type from outside the
//! tree is a bag. The fields are read from the parsed AST (`syn`), including structs a macro
//! declares, so a struct LITERAL or a function parameter named `settings` is not a declaration.
//!
//! THE ALLOWLIST is explicit, per-line and self-documenting — `// settings-leak-lint: allow —
//! <reason>` on the line or the comment block immediately above — and covers exactly the one
//! declaration it sits above. The reason follows an em dash on the marker line and is at least
//! [`MIN_REASON`] characters, the floor every written excuse in this crate is held to; a bare
//! marker, or one with a shrug for a reason, is itself a finding and covers nothing. Use it only for
//! an INBOUND request body, a response ENVELOPE whose nested bags are already redacted, or a
//! NON-PROJECTION engine type. Adding a marker with any other reason is the bug this gate exists to
//! catch, in a costume.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};

use proc_macro2::{Delimiter, Ident, Spacing, TokenStream, TokenTree};
use syn::visit::Visit;

use crate::ctx::{Ctx, Overlay, SourceFile, WalkSpec};
use crate::gates::population;
use crate::gates::{
    prove_green, prove_red, prove_rows_red_at, Gate, Report, PLANE_ROOT_MISSING_FIXTURE,
};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::PlaneRoots;

pub const ROW_PLANE_ROOTS: &str = "settings-leak:plane-roots";
pub const ROW_SCAN_ROOTS: &str = "settings-leak:scan-roots";
pub const ROW_SCAN_FLOOR: &str = "settings-leak:scan-floor";
pub const ROW_NO_RAW_BAG: &str = "settings-leak:no-raw-bag";

/// The core/bin split roots plus the LLM plane. The plane roots are FOUND, not spelled.
///
/// `busbar-core` was absorbed into `busbar-kernel` (W4.a, 673ecdaaa) — the settings/admin surface
/// this gate exists for (`settings_keys`, `RootSettings`, `HookView`, `redact_settings_bags`) now
/// lives under `crates/busbar-kernel/src` (see `config/`, `admin/`, `api.rs`). This entry is an
/// existence check only: the actual scan set is the whole `crates/` tree via
/// `population::source_population`, so repointing it does not narrow what gets scanned.
const FIXED_ROOTS: &[&str] = &[
    "crates/busbar-kernel/src",
    "crates/busbar/src",
    "crates/busbar-llm/src",
];

/// The planes whose source must be in the scan whatever crate they end up in.
const PLANE_KEYS: &[&str] = &["mcp", "a2a"];

const EXCLUDE_TESTS_DIR: &str = "/tests/";

// THE AGGREGATE FLOOR MOVED TO `gates::population`. It was 100 against a scan set of 280 — 180
// files of slack, enough to lose `busbar-core`'s 151 and still print `ok`. The floor that replaces
// it is measured against the whole tree, because the scan set now IS the whole tree.

const CLEAN: &str = "the scan cleared its floors and named nothing";

const ALLOW_MARKER: &str = "settings-leak-lint:";

/// What follows `allow` on a marker line, before its reason. The em dash every marker in the tree
/// is written with, and the module header documents.
const REASON_SEPARATOR: char = '—';

/// A marker's reason shorter than this is a shrug, not a reason: the floor every written excuse in
/// this crate is held to ([`crate::gates::Divergence::MIN_REASON`]).
pub const MIN_REASON: usize = crate::gates::Divergence::MIN_REASON;

/// The generic wrappers a settings field's type is judged THROUGH, by their first type argument:
/// holding a bag in an `Option`, a box, a shared pointer, a copy-on-write or a list is holding the
/// bag. Short on purpose: a wrapper NOT on it is not a tree-declared type either, so it is judged a
/// bag — leaving one out can only make the gate stricter.
const WRAPPERS: &[&str] = &["Option", "Box", "Arc", "Rc", "Cow", "Vec"];

/// How deep an alias chain is followed before it is refused as a bag (a cycle, or a chain no
/// reviewer would read).
const MAX_ALIAS_DEPTH: usize = 16;

fn finding_field(rel: &str, line: usize, decl: &str) -> String {
    format!(
        "{rel}:{line}: admin view field carries a RAW settings bag (`{decl}`: its type is not a \
         type this tree declares field by field) — project settings_keys \
         (admin::v1::service::settings_keys) or redact via service::redact_settings_bags"
    )
}

fn finding_marker(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: a `settings-leak-lint: allow` marker without a reason — write \
         `settings-leak-lint: allow {REASON_SEPARATOR} <why this is an inbound body, a redacted \
         envelope or a non-projection type, at least {MIN_REASON} characters>`; a marker without \
         one covers nothing"
    )
}

fn finding_unparsed(rel: &str, why: &str) -> String {
    format!(
        "{rel}: does not parse as Rust ({why}), so its fields cannot be judged — a file this gate \
         cannot read is not a clean file"
    )
}

fn finding_member(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: admin JSON body serializes a `settings` member — serve `settings_keys` \
         instead (or redact the tree with service::redact_settings_bags and allowlist the envelope)"
    )
}

fn row_no_raw_bag(offenders: &[String], census: &str) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_RAW_BAG,
            "no engine type reaching an admin read carries a raw operator settings bag",
            format!("{CLEAN}: {census}"),
        );
    }
    Row::fail(
        ROW_NO_RAW_BAG,
        "an engine type reaching an admin read carries a raw operator settings bag",
        format!(
            "{} finding(s): {} ({census})",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

/// Is this line a comment, by the shell's rule: `^[[:space:]]*(//|\*|/\*)`. A doc comment quoting
/// `"settings":` is prose, not a projection.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

/// What an allow marker on one line amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    /// No marker on the line.
    None,
    /// `settings-leak-lint: allow — <reason of at least MIN_REASON characters>`.
    Reasoned,
    /// The marker words with no separator, no reason, or a reason under [`MIN_REASON`].
    Bare,
}

/// `settings-leak-lint:`, optional whitespace, `allow`, optional whitespace, the em dash, and a
/// reason of at least [`MIN_REASON`] characters. The marker words without all of that are
/// [`Marker::Bare`] — a finding of their own, never a pass.
fn allow_marker(line: &str) -> Marker {
    let mut rest = line;
    let mut bare = false;
    while let Some(i) = rest.find(ALLOW_MARKER) {
        let after = &rest[i + ALLOW_MARKER.len()..];
        if let Some(tail) = after.trim_start().strip_prefix("allow") {
            match tail.trim_start().strip_prefix(REASON_SEPARATOR) {
                Some(reason) if reason.trim().chars().count() >= MIN_REASON => {
                    return Marker::Reasoned
                }
                _ => bare = true,
            }
        }
        rest = after;
    }
    if bare {
        Marker::Bare
    } else {
        Marker::None
    }
}

/// Is this field name one the claim covers: `settings` or anything ending in it, in any case (a
/// raw identifier's `r#` aside).
fn names_settings(ident: &str) -> bool {
    ident
        .trim_start_matches("r#")
        .to_ascii_lowercase()
        .ends_with("settings")
}

/// Could `text` declare a `*settings` field at all: an identifier ending in `settings` (any case),
/// optional whitespace, and a single `:`. Only such a file is parsed for its fields, and a file
/// without one cannot hold the declaration R1 is about. (A comment written BETWEEN a field's name
/// and its colon would slip this; rustfmt never writes one.)
fn may_declare_settings(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut from = 0;
    while let Some(i) = lower[from..].find("settings") {
        let mut j = from + i + "settings".len();
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b':' && b.get(j + 1) != Some(&b':') {
            return true;
        }
        from = from + i + 1;
    }
    false
}

/// `[pub[(…)]] <keyword> <Name>` at the head of a line, for the declaration INDEX: `struct`,
/// `enum`, `union`, `type`, `mod`. The index only says WHERE to look; what a name IS comes from
/// that file's AST, so a line the index misreads costs a parse, never a verdict, and a declaration
/// it misses leaves its name unresolved — which judges a field of that type a bag.
fn declared_on(line: &str) -> Option<(&'static str, &str)> {
    let mut t = line.trim_start();
    if let Some(rest) = t.strip_prefix("pub") {
        let rest = match rest.strip_prefix('(') {
            Some(r) => r.split_once(')')?.1,
            None => rest,
        };
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        t = rest.trim_start();
    }
    for kw in ["struct", "enum", "union", "type", "mod"] {
        if let Some(rest) = t.strip_prefix(kw) {
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            let name = rest.trim_start();
            let end = name
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(name.len());
            return (end > 0).then(|| (kw, &name[..end]));
        }
    }
    None
}

/// A type, as much of it as R1 reads, in a form that outlives its parse: an AST is tied to the
/// thread that built it, and this is memoised across a self-test's parallel plants.
#[derive(Clone, Debug)]
enum Shape {
    /// `&T`, `*const T`, `[T]`, `[T; N]`, `(T)`: judged as `T`.
    Through(Box<Shape>),
    /// `(A, B)`: a bag if any element is (and `()` is no typed settings type either).
    Tuple(Vec<Shape>),
    /// A path: whether it starts with `::`, its segments, and its LAST segment's first type
    /// argument (what a wrapper is judged by).
    Path {
        rooted: bool,
        segments: Vec<String>,
        first_arg: Option<Box<Shape>>,
    },
    /// `dyn …`, `impl …`, `fn(…)`, a macro, `_`, a qualified `<T as U>::X`: a bag.
    Opaque,
}

fn shape(ty: &syn::Type) -> Shape {
    let through = |t: &syn::Type| Shape::Through(Box::new(shape(t)));
    match ty {
        syn::Type::Reference(r) => through(&r.elem),
        syn::Type::Ptr(p) => through(&p.elem),
        syn::Type::Paren(p) => through(&p.elem),
        syn::Type::Group(g) => through(&g.elem),
        syn::Type::Slice(s) => through(&s.elem),
        syn::Type::Array(a) => through(&a.elem),
        syn::Type::Tuple(t) => Shape::Tuple(t.elems.iter().map(shape).collect()),
        syn::Type::Path(p) if p.qself.is_none() => Shape::Path {
            rooted: p.path.leading_colon.is_some(),
            segments: p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
            first_arg: p
                .path
                .segments
                .last()
                .and_then(|l| match &l.arguments {
                    syn::PathArguments::AngleBracketed(a) => a.args.iter().find_map(|g| match g {
                        syn::GenericArgument::Type(t) => Some(t),
                        _ => None,
                    }),
                    _ => None,
                })
                .map(|t| Box::new(shape(t))),
        },
        _ => Shape::Opaque,
    }
}

/// What one declaration of a name makes a settings field of that type.
#[derive(Clone, Debug)]
enum Kind {
    /// A struct with named fields, a unit struct, a multi-field tuple struct, an enum or a union: a
    /// shape the tree writes down field by field.
    Typed,
    /// `type X = …;`, or a single-field newtype over a concrete type: judged as what it stands for.
    Alias(Shape),
    /// A generic newtype over its own parameter (`Redacted<T>(T)`). If nothing in the tree
    /// serializes it, it is one of the tree's REDACTED wrappers and safe; if something does, it is
    /// as transparent as `Option` and judged by its type argument.
    GenericNewtype { derives_serialize: bool },
}

fn derives_serialize(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = a.parse_nested_meta(|m| {
            if m.path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Serialize")
            {
                found = true;
            }
            Ok(())
        });
        found
    })
}

/// One `*settings` field declaration: its line, and its type (`None` when a macro body spells it
/// in a way that does not parse as a type — judged a bag).
#[derive(Debug)]
struct FieldDecl {
    line: usize,
    ty: Option<Shape>,
}

/// What one file's AST says, memoised by the file's bytes ([`summary`]).
#[derive(Default, Debug)]
struct Summary {
    /// The parse error, when the file is not Rust.
    unparsed: Option<String>,
    /// Every named field called `*settings`: in a struct, an enum variant or a union, and in a
    /// struct a macro body declares (which the AST holds only as tokens).
    fields: Vec<FieldDecl>,
    /// Every item-level `struct`/`enum`/`union`/`type`, by name.
    decls: Vec<(String, Kind)>,
    /// Every `use` leaf: (its path's first segment, the name it binds here). A glob binds none.
    uses: Vec<(String, String)>,
}

#[derive(Default)]
struct Collect {
    summary: Summary,
}

fn use_leaves(tree: &syn::UseTree, root: Option<&str>, out: &mut Vec<(String, String)>) {
    match tree {
        syn::UseTree::Path(p) => {
            let seg = p.ident.to_string();
            use_leaves(&p.tree, Some(root.unwrap_or(&seg)), out);
        }
        syn::UseTree::Name(n) => {
            let name = n.ident.to_string();
            out.push((root.unwrap_or(&name).to_string(), name.clone()));
        }
        syn::UseTree::Rename(r) => {
            let name = r.ident.to_string();
            out.push((root.unwrap_or(&name).to_string(), r.rename.to_string()));
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(g) => {
            for t in &g.items {
                use_leaves(t, root, out);
            }
        }
    }
}

impl<'ast> Visit<'ast> for Collect {
    fn visit_field(&mut self, f: &'ast syn::Field) {
        if let Some(id) = &f.ident {
            if names_settings(&id.to_string()) {
                self.summary.fields.push(FieldDecl {
                    line: id.span().start().line,
                    ty: Some(shape(&f.ty)),
                });
            }
        }
        syn::visit::visit_field(self, f);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        macro_struct_fields(m.tokens.clone(), &mut self.summary.fields);
        syn::visit::visit_macro(self, m);
    }

    fn visit_item_struct(&mut self, it: &'ast syn::ItemStruct) {
        let kind = match &it.fields {
            syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                let ty = &f.unnamed[0].ty;
                let over_own_param = matches!(ty, syn::Type::Path(p)
                    if p.qself.is_none()
                        && it.generics.type_params().any(|g| p.path.is_ident(&g.ident)));
                if over_own_param {
                    Kind::GenericNewtype {
                        derives_serialize: derives_serialize(&it.attrs),
                    }
                } else {
                    Kind::Alias(shape(ty))
                }
            }
            _ => Kind::Typed,
        };
        self.summary.decls.push((it.ident.to_string(), kind));
        syn::visit::visit_item_struct(self, it);
    }

    fn visit_item_enum(&mut self, it: &'ast syn::ItemEnum) {
        self.summary.decls.push((it.ident.to_string(), Kind::Typed));
        syn::visit::visit_item_enum(self, it);
    }

    fn visit_item_union(&mut self, it: &'ast syn::ItemUnion) {
        self.summary.decls.push((it.ident.to_string(), Kind::Typed));
        syn::visit::visit_item_union(self, it);
    }

    fn visit_item_type(&mut self, it: &'ast syn::ItemType) {
        self.summary
            .decls
            .push((it.ident.to_string(), Kind::Alias(shape(&it.ty))));
        syn::visit::visit_item_type(self, it);
    }

    fn visit_item_use(&mut self, it: &'ast syn::ItemUse) {
        use_leaves(&it.tree, None, &mut self.summary.uses);
    }
}

fn summarize(text: &str) -> Summary {
    match syn::parse_file(text) {
        Err(e) => Summary {
            unparsed: Some(e.to_string()),
            ..Summary::default()
        },
        Ok(ast) => {
            let mut c = Collect::default();
            c.visit_file(&ast);
            c.summary
        }
    }
}

/// What a file's TEXT says without a parse: whether it may declare a `*settings` field, and the
/// names its lines declare (`struct`/`enum`/`union`/`type`) and the modules (`mod`).
#[derive(Default)]
struct TextFacts {
    may_declare: bool,
    declared: Vec<String>,
    modules: Vec<String>,
}

fn text_facts(text: &str) -> TextFacts {
    let mut facts = TextFacts {
        may_declare: may_declare_settings(text),
        ..TextFacts::default()
    };
    for line in text.lines() {
        match declared_on(line) {
            Some(("mod", name)) => facts.modules.push(name.to_string()),
            Some((_, name)) if !facts.declared.iter().any(|d| d == name) => {
                facts.declared.push(name.to_string());
            }
            Some(_) | None => {}
        }
    }
    facts
}

type MemoCell<T> = Arc<OnceLock<Arc<T>>>;
type Memo<T> = Mutex<HashMap<(usize, u64, u64), MemoCell<T>>>;

/// `f(text)`, memoised by the text itself: a self-test runs the whole gate once per plant and a
/// plant touches one file of nine hundred. Same bytes, same answer, so the memo cannot change a
/// verdict. The cell is handed out under the lock and FILLED OUTSIDE it, so concurrent cases that
/// need the same file take one parse between them.
fn memoised<T: Send + Sync + 'static>(
    memo: &'static OnceLock<Memo<T>>,
    text: &str,
    f: fn(&str) -> T,
) -> Arc<T> {
    use std::hash::{Hash, Hasher};
    let mut a = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut a);
    let mut b = std::collections::hash_map::DefaultHasher::new();
    (text.len(), text).hash(&mut b);
    0x5e7_u32.hash(&mut b);
    let key = (text.len(), a.finish(), b.finish());
    let cell = memo
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(key)
        .or_default()
        .clone();
    cell.get_or_init(|| Arc::new(f(text))).clone()
}

fn summary(text: &str) -> Arc<Summary> {
    static MEMO: OnceLock<Memo<Summary>> = OnceLock::new();
    memoised(&MEMO, text, summarize)
}

fn facts(text: &str) -> Arc<TextFacts> {
    static MEMO: OnceLock<Memo<TextFacts>> = OnceLock::new();
    memoised(&MEMO, text, text_facts)
}

/// The `[package]` and `[lib]` names of one manifest, as a path segment spells them.
fn manifest_names(toml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut section = String::new();
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.to_string();
            continue;
        }
        if section != "[package]" && section != "[lib]" {
            continue;
        }
        if let Some(v) = t.strip_prefix("name") {
            if let Some(v) = v.trim_start().strip_prefix('=') {
                out.push(v.trim().trim_matches('"').replace('-', "_"));
            }
        }
    }
    out
}

type Declared = Rc<Vec<(Kind, usize)>>;

/// THE SAFE SET, DERIVED FROM THE TREE, resolved on demand. A settings field's type is safe when
/// it lands on a declaration of this tree that is [`Kind::Typed`] or a redacted
/// [`Kind::GenericNewtype`]; it is judged THROUGH every [`Kind::Alias`] and every serialized
/// generic newtype; and a name declared more than one way is a bag if ANY of its declarations is.
/// A name the tree does not declare, or a path that starts outside it, is a bag.
///
/// Only the names a `*settings` field actually reaches are resolved, from the files the line index
/// says declare them; every parse is memoised by the file's bytes.
struct TypeTree<'f> {
    files: &'f [SourceFile],
    /// Name → the files whose lines declare it (`struct`/`enum`/`union`/`type`).
    index: HashMap<String, Vec<usize>>,
    /// First path segments that name THIS workspace: `crate`/`self`/`super`/`Self`, every crate's
    /// package and lib name, and every module the tree declares. Anything else is outside the tree.
    internal: HashSet<String>,
    summaries: RefCell<HashMap<usize, Arc<Summary>>>,
    kinds: RefCell<HashMap<String, Declared>>,
}

impl<'f> TypeTree<'f> {
    fn derive(cx: &Ctx, crates: &[String], files: &'f [SourceFile]) -> TypeTree<'f> {
        let mut internal: HashSet<String> = ["crate", "self", "super", "Self"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for c in crates {
            // A manifest that will not read leaves its crate's paths OUTSIDE the tree, which can
            // only judge more fields a bag.
            if let Ok(toml) = cx.read(format!("crates/{c}/Cargo.toml")) {
                internal.extend(manifest_names(&toml));
            }
        }
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, f) in files.iter().enumerate() {
            let facts = facts(&f.text);
            internal.extend(facts.modules.iter().cloned());
            for name in &facts.declared {
                index.entry(name.clone()).or_default().push(idx);
            }
        }
        TypeTree {
            files,
            index,
            internal,
            summaries: RefCell::default(),
            kinds: RefCell::default(),
        }
    }

    fn may_declare(&self, idx: usize) -> bool {
        facts(&self.files[idx].text).may_declare
    }

    fn declarations(&self) -> usize {
        self.index.values().map(Vec::len).sum()
    }

    fn summary(&self, idx: usize) -> Arc<Summary> {
        if let Some(s) = self.summaries.borrow().get(&idx) {
            return Arc::clone(s);
        }
        let s = summary(&self.files[idx].text);
        self.summaries.borrow_mut().insert(idx, Arc::clone(&s));
        s
    }

    fn parsed(&self) -> usize {
        self.summaries.borrow().len()
    }

    /// Does file `idx` bind `name` by a `use` whose path starts outside the tree?
    fn imported_from_outside(&self, idx: usize, name: &str) -> bool {
        self.summary(idx)
            .uses
            .iter()
            .any(|(root, bound)| bound == name && !self.internal.contains(root))
    }

    fn kinds_of(&self, name: &str) -> Declared {
        if let Some(k) = self.kinds.borrow().get(name) {
            return Rc::clone(k);
        }
        let mut out = Vec::new();
        for &idx in self.index.get(name).map(Vec::as_slice).unwrap_or(&[]) {
            let s = self.summary(idx);
            out.extend(
                s.decls
                    .iter()
                    .filter(|(n, _)| n == name)
                    .map(|(_, k)| (k.clone(), idx)),
            );
        }
        let k = Rc::new(out);
        self.kinds
            .borrow_mut()
            .insert(name.to_string(), Rc::clone(&k));
        k
    }

    /// Does any file of the tree hand-write `impl … Serialize for <name>`?
    fn serialize_impl(&self, name: &str) -> bool {
        let needle = format!("Serialize for {name}");
        self.files.iter().any(|f| {
            f.text.match_indices(&needle).any(|(i, _)| {
                f.text[i + needle.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            })
        })
    }

    /// Is `ty`, written in file `file`, a raw settings bag? `true` unless it lands on a typed or
    /// redacted declaration of this tree — see the struct note.
    fn is_bag(&self, ty: &Shape, file: usize, depth: usize) -> bool {
        if depth > MAX_ALIAS_DEPTH {
            return true;
        }
        match ty {
            Shape::Through(inner) => self.is_bag(inner, file, depth),
            Shape::Tuple(elems) => {
                elems.is_empty() || elems.iter().any(|e| self.is_bag(e, file, depth))
            }
            Shape::Opaque => true,
            Shape::Path {
                rooted,
                segments,
                first_arg,
            } => self.path_is_bag(*rooted, segments, first_arg.as_deref(), file, depth),
        }
    }

    fn path_is_bag(
        &self,
        rooted: bool,
        segments: &[String],
        first_arg: Option<&Shape>,
        file: usize,
        depth: usize,
    ) -> bool {
        let Some(name) = segments.last() else {
            return true;
        };
        let judge_arg = || first_arg.is_none_or(|t| self.is_bag(t, file, depth + 1));
        if WRAPPERS.contains(&name.as_str()) {
            return judge_arg();
        }
        let outside = rooted
            || if segments.len() > 1 {
                !self.internal.contains(&segments[0])
                    || self.imported_from_outside(file, &segments[0])
            } else {
                self.imported_from_outside(file, name)
            };
        if outside {
            return true;
        }
        let kinds = self.kinds_of(name);
        if kinds.is_empty() {
            return true;
        }
        kinds.iter().any(|(kind, at)| match kind {
            Kind::Typed => false,
            Kind::Alias(target) => self.is_bag(target, *at, depth + 1),
            Kind::GenericNewtype { derives_serialize } => {
                (*derives_serialize || self.serialize_impl(name)) && judge_arg()
            }
        })
    }
}

/// `$crate` → `crate`, so a macro body's type parses; every other token is kept.
fn unmacro(ts: TokenStream) -> TokenStream {
    let mut out = Vec::new();
    let mut it = ts.into_iter().peekable();
    while let Some(tt) = it.next() {
        match tt {
            TokenTree::Punct(p) if p.as_char() == '$' => {
                if let Some(TokenTree::Ident(id)) = it.peek() {
                    if id == "crate" {
                        out.push(TokenTree::Ident(Ident::new("crate", id.span())));
                        it.next();
                        continue;
                    }
                }
                out.push(TokenTree::Punct(p));
            }
            TokenTree::Group(g) => {
                let mut ng = proc_macro2::Group::new(g.delimiter(), unmacro(g.stream()));
                ng.set_span(g.span());
                out.push(TokenTree::Group(ng));
            }
            other => out.push(other),
        }
    }
    out.into_iter().collect()
}

/// Every `struct … { … }` / `union … { … }` in a macro body's tokens (at any depth): its
/// `*settings` fields.
fn macro_struct_fields(ts: TokenStream, out: &mut Vec<FieldDecl>) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            TokenTree::Ident(id) if id == "struct" || id == "union" => {
                let mut j = i + 1;
                while j < toks.len() {
                    match &toks[j] {
                        TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
                            body_fields(g.stream(), out);
                            break;
                        }
                        TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis => break,
                        TokenTree::Punct(p) if p.as_char() == ';' => break,
                        _ => j += 1,
                    }
                }
                i = j + 1;
            }
            TokenTree::Group(g) => {
                macro_struct_fields(g.stream(), out);
                i += 1;
            }
            _ => i += 1,
        }
    }
}

/// The named fields of one struct body, as tokens: `#[attr]* vis? name : Type ,`.
fn body_fields(ts: TokenStream, out: &mut Vec<FieldDecl>) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    for chunk in toks.split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ',')) {
        let mut k = 0;
        // attributes
        while k + 1 < chunk.len()
            && matches!(&chunk[k], TokenTree::Punct(p) if p.as_char() == '#')
            && matches!(&chunk[k + 1], TokenTree::Group(g) if g.delimiter() == Delimiter::Bracket)
        {
            k += 2;
        }
        // visibility
        if matches!(chunk.get(k), Some(TokenTree::Ident(id)) if id == "pub") {
            k += 1;
            if matches!(chunk.get(k), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
            {
                k += 1;
            }
        }
        let (Some(TokenTree::Ident(id)), Some(TokenTree::Punct(colon))) =
            (chunk.get(k), chunk.get(k + 1))
        else {
            continue;
        };
        if colon.as_char() != ':' || colon.spacing() != Spacing::Alone {
            continue;
        }
        if !names_settings(&id.to_string()) {
            continue;
        }
        let ty_tokens: TokenStream = chunk[k + 2..].iter().cloned().collect();
        out.push(FieldDecl {
            line: id.span().start().line,
            ty: syn::parse2::<syn::Type>(unmacro(ty_tokens))
                .ok()
                .map(|t| shape(&t)),
        });
    }
}

/// The JSON-Schema keywords a SUB-SCHEMA can lead with. Closed and small on purpose: this list is
/// the only thing standing between a schema fragment and the R2 rule, so it names the vocabulary
/// (draft 2020-12) rather than accepting any object.
const SCHEMA_KEYWORDS: &[&str] = &[
    "type",
    "$ref",
    "$dynamicRef",
    "properties",
    "patternProperties",
    "additionalProperties",
    "items",
    "prefixItems",
    "required",
    "oneOf",
    "anyOf",
    "allOf",
    "not",
    "const",
    "enum",
    "format",
    "pattern",
    "description",
    "title",
    "default",
    "nullable",
];

/// Is the text after a `"settings":` the start of an inline JSON-SCHEMA sub-schema, rather than a
/// value expression?
///
/// A schema fragment DESCRIBES the shape of a settings bag; it never carries one. `"settings":
/// {"type": "object"}` in [`secret_ref::oneof_schema`] is the `x-busbar-secret` field's own
/// `oneOf` — the schema busbar-ui composes a reference against — and reading it as a leak was R2
/// mistaking a description of the bag for the bag.
///
/// It is recognised as narrowly as it can be and still be recognised: the value must be an INLINE
/// object literal whose FIRST member is spelled with one of [`SCHEMA_KEYWORDS`]. Nothing else
/// qualifies — not a bare `{}`, not an identifier, not a call, not `{ "settings": settings }` —
/// so a real bag written on the same line, or on the next one, is untouched by this.
fn opens_schema_fragment(after_colon: &str) -> bool {
    let Some(inner) = after_colon.trim_start().strip_prefix('{') else {
        return false;
    };
    let inner = inner.trim_start();
    SCHEMA_KEYWORDS.iter().any(|k| {
        inner
            .strip_prefix(&format!("\"{k}\""))
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

/// R2 — a hand-built JSON response member named `settings`: `"settings"` then optional whitespace
/// then `:`, and NOT the head of a JSON-Schema sub-schema (see [`opens_schema_fragment`]).
fn is_raw_bag_member(line: &str) -> bool {
    let needle = "\"settings\"";
    let mut rest = line;
    while let Some(i) = rest.find(needle) {
        let after = &rest[i + needle.len()..];
        if let Some(value) = after.trim_start().strip_prefix(':') {
            if !opens_schema_fragment(value) {
                return true;
            }
        }
        rest = after;
    }
    false
}

/// What one file contributed: its findings, and how many fields and reasoned markers it held.
#[derive(Default)]
struct FileScan {
    findings: Vec<String>,
    fields: usize,
    markers: usize,
}

/// One file's findings. `prev_allow` carries a REASONED marker forward across the COMMENT BLOCK it
/// starts (a reason rarely fits on one line) and NO FURTHER: the first non-comment line consumes it
/// and the line after that is armed again, so a marker covers exactly one declaration. A marker
/// without a reason is a finding and covers nothing.
fn scan_file(rel: &str, text: &str, tree: &TypeTree<'_>, idx: usize) -> FileScan {
    let mut scan = FileScan::default();
    let mut covered = Vec::new();
    let mut prev_allow = false;
    for (n, line) in text.lines().enumerate() {
        let comment = is_comment(line);
        let marker = match allow_marker(line) {
            Marker::Reasoned => {
                scan.markers += 1;
                true
            }
            Marker::Bare => {
                scan.findings.push(finding_marker(rel, n + 1));
                false
            }
            Marker::None => false,
        };
        let allow = marker || prev_allow;
        prev_allow = marker || (comment && prev_allow);
        covered.push(allow);
        if comment || allow {
            continue;
        }
        if is_raw_bag_member(line) {
            scan.findings.push(finding_member(rel, n + 1));
        }
    }
    if !tree.may_declare(idx) {
        return scan;
    }
    let summary = tree.summary(idx);
    if let Some(why) = &summary.unparsed {
        scan.findings.push(finding_unparsed(rel, why));
        return scan;
    }
    let lines: Vec<&str> = text.lines().collect();
    for f in &summary.fields {
        scan.fields += 1;
        if covered.get(f.line.wrapping_sub(1)) == Some(&true) {
            continue;
        }
        if f.ty.as_ref().is_none_or(|t| tree.is_bag(t, idx, 0)) {
            let decl = lines.get(f.line.wrapping_sub(1)).map_or("", |l| l.trim());
            scan.findings.push(finding_field(rel, f.line, decl));
        }
    }
    scan
}

pub struct SettingsLeakGate;

/// The scan roots for this tree: the three fixed ones plus the resolved plane homes, relative to
/// the workspace root.
fn scan_roots(cx: &Ctx) -> Result<Vec<String>, String> {
    let roots = PlaneRoots::at(cx.abs("crates"));
    let mut out: Vec<String> = FIXED_ROOTS.iter().map(|r| (*r).to_string()).collect();
    let (ok, errs) = roots.resolve_all(PLANE_KEYS);
    if !errs.is_empty() {
        return Err(errs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | "));
    }
    for (_, dir) in ok {
        let rel = dir
            .strip_prefix(cx.root())
            .map_err(|_| format!("{} is not under the workspace root", dir.display()))?;
        out.push(rel.to_string_lossy().replace('\\', "/"));
    }
    Ok(out)
}

impl Gate for SettingsLeakGate {
    fn name(&self) -> &'static str {
        "settings-leak"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_PLANE_ROOTS.to_string(),
            ROW_SCAN_ROOTS.to_string(),
            ROW_SCAN_FLOOR.to_string(),
            ROW_NO_RAW_BAG.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let roots = match scan_roots(cx) {
            Ok(r) => r,
            Err(why) => {
                return Verdict::of(vec![
                    Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
                    Row::fail(
                        ROW_SCAN_ROOTS,
                        "the root set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the root set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_NO_RAW_BAG,
                        "the scan did not run",
                        DID_NOT_RUN.to_string(),
                    ),
                ]);
            }
        };

        // THE POPULATION IS DERIVED FROM THE TREE, not from `roots`: every non-test `.rs` under
        // `crates/`. `roots` is still resolved above, because a plane that cannot be located is its
        // own refusal — but it no longer decides what gets opened.
        let population = match population::source_population(cx) {
            Ok(p) => p,
            Err(why) => {
                return Verdict::of(vec![
                    Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                    Row::fail(ROW_SCAN_ROOTS, "the tree would not list", why),
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the scan set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_NO_RAW_BAG,
                        "the scan did not run",
                        DID_NOT_RUN.to_string(),
                    ),
                ]);
            }
        };
        let mut unusable: Vec<String> = population
            .drained
            .iter()
            .map(|c| format!("crates/{c}: has a src/ and contributed no file to the scan"))
            .collect();
        for root in &roots {
            if !cx.exists(root) {
                unusable.push(format!("{root}: not on disk"));
            }
        }
        let files = population.files.clone();
        if !unusable.is_empty() {
            return Verdict::of(vec![
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                Row::fail(
                    ROW_SCAN_ROOTS,
                    "a scan root is missing or drained",
                    format!(
                        "{} — a root that is missing or drained is scanned as ZERO files, and zero \
                         files carry no leak. If the layout moved, point the root at its new home \
                         in a reviewed diff that says so.",
                        unusable.join(" | ")
                    ),
                ),
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan set is incomplete",
                    DID_NOT_RUN.to_string(),
                ),
                Row::fail(
                    ROW_NO_RAW_BAG,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ),
            ]);
        }

        if population.below_floor() {
            return Verdict::of(vec![
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                Row::pass(
                    ROW_SCAN_ROOTS,
                    "every scan root holds production source",
                    population.census(),
                ),
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan set is below its floor",
                    format!(
                        "{}. This gate scanned (almost) nothing, so its verdict is meaningless — \
                         it is NOT a pass.",
                        population.census()
                    ),
                ),
                Row::fail(
                    ROW_NO_RAW_BAG,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ),
            ]);
        }

        let tree = TypeTree::derive(cx, &population.crates, &files);
        let mut offenders = Vec::new();
        let (mut fields, mut markers) = (0, 0);
        for (idx, f) in files.iter().enumerate() {
            let scan = scan_file(&f.rel_str(), &f.text, &tree, idx);
            offenders.extend(scan.findings);
            fields += scan.fields;
            markers += scan.markers;
        }
        offenders.sort();
        let census = format!(
            "{fields} `*settings` field(s) judged by type; {} file(s) parsed, against {} \
             declaration(s) indexed across {} file(s); {markers} allow marker(s), each with a \
             reason of at least {MIN_REASON} characters",
            tree.parsed(),
            tree.declarations(),
            files.len()
        );

        Verdict::of(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(
                ROW_SCAN_ROOTS,
                "every crate under crates/ contributed its source",
                population.census(),
            ),
            Row::pass(
                ROW_SCAN_FLOOR,
                "the scan set cleared its floor",
                population.census(),
            ),
            row_no_raw_bag(&offenders, &census),
        ])
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "no admin projection in the tree carries a raw settings bag",
            &[
                ROW_PLANE_ROOTS,
                ROW_SCAN_ROOTS,
                ROW_SCAN_FLOOR,
                ROW_NO_RAW_BAG,
            ],
        ));

        // The four historical leaks, transcribed: a Map field, an Option<Map> field, a Value field
        // and a hand-built json! member.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_views.rs",
            "#[derive(Serialize)]\npub(crate) struct HookView {\n\
             \x20   pub(crate) name: String,\n\
             \x20   pub(crate) settings: serde_json::Map<String, serde_json::Value>,\n}\n\n\
             #[derive(Serialize)]\npub(crate) struct HookReportedStatus {\n\
             \x20   pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,\n}\n\n\
             #[derive(Serialize)]\npub(crate) struct ConfigSettingsView {\n\
             \x20   pub(crate) settings: serde_json::Value,\n}\n\n\
             fn hook_status() -> Response {\n    ok_json(StatusCode::OK, &json!({\n\
             \x20       \"name\": name,\n\
             \x20       \"reported\": {\"settings\": r.settings, \"settings_version\": r.v},\n\
             \x20   }))\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "all four leak shapes are flagged (Map / Option<Map> / Value field, json! member)",
            &[ROW_NO_RAW_BAG],
            ov,
            // Named by LINE, one per shape: the Map field, the Option<Map> field, the Value field
            // and the json! member. Naming only the count would let three of the four rules be
            // deleted with this case still green.
            &[
                "4 finding(s)",
                "planted_views.rs:4",
                "planted_views.rs:9",
                "planted_views.rs:14",
                "planted_views.rs:20",
            ],
        ));

        // THE SANCTIONED FORMS stay silent: the keys projection, the redaction helper, both
        // allowlist categories, and a doc comment naming either shape.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_sanctioned.rs",
            "#[derive(Serialize)]\npub(crate) struct HookView {\n\
             \x20   pub(crate) settings_keys: Vec<String>,\n}\n\n\
             #[derive(Deserialize)]\npub(crate) struct PatchSettingsReq {\n\
             \x20   // settings-leak-lint: allow — inbound request body; never serialized back.\n\
             \x20   settings: serde_json::Map<String, serde_json::Value>,\n}\n\n\
             fn hook_status() -> Response {\n\
             \x20   crate::admin::v1::service::redact_settings_bags(&mut settings);\n\
             \x20   ok_json(StatusCode::OK, &json!({\n\
             \x20       \"desired\": {\"settings_keys\": settings_keys(&h.settings)},\n\
             \x20       // settings-leak-lint: allow — the envelope; every nested bag is redacted above.\n\
             \x20       \"settings\": settings,\n\
             \x20   }))\n}\n\n\
             // A doc comment naming a \"settings\": member, or a settings: Map<…> field, is prose.\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "keys projections, the redaction helper, both allowlist categories and prose stay silent",
            &[ROW_NO_RAW_BAG],
        ));

        // A MARKER IS NOT A BLANKET MUTE. It covers the next declaration and its own comment
        // continuation, and an unmarked leak two lines below is still caught.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_scope.rs",
            "pub(crate) struct Scoped {\n\
             \x20   // settings-leak-lint: allow — this marker (and its continuation line, since a reason\n\
             \x20   // rarely fits on one line) covers the NEXT declaration only.\n\
             \x20   pub(crate) settings: serde_json::Value,\n\
             \x20   pub(crate) other: u8,\n\
             \x20   pub(crate) hook_settings: serde_json::Map<String, serde_json::Value>,\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an allow marker covers exactly one declaration, so a later unmarked leak is flagged",
            &[ROW_NO_RAW_BAG],
            ov,
            &["1 finding(s)", "planted_scope.rs:6"],
        ));

        // A BAG IS A TYPE, NOT A SPELLING. R1 used to know two spellings (`Map<` and `Value`, with
        // an optional `Option<` and `serde_json::`), so the defect class this gate exists for came
        // back GREEN as any other map, any other JSON/YAML/TOML value, a wrapper, an alias, or a
        // struct a macro declares. One field per shape, each named by LINE: a rule that stopped
        // seeing one of them cannot hide behind the count.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_types.rs",
            "use std::collections::{BTreeMap, HashMap};\n\
             use serde_json::Value;\n\n\
             type Bag = serde_json::Map<String, Value>;\n\n\
             #[derive(Serialize)]\npub(crate) struct HookView {\n\
             \x20   pub(crate) settings: HashMap<String, Value>,\n\
             \x20   pub(crate) hook_settings: BTreeMap<String, serde_json::Value>,\n\
             \x20   pub(crate) yaml_settings: Option<serde_yaml::Value>,\n\
             \x20   pub(crate) alias_settings: Bag,\n\
             \x20   pub(crate) raw_settings: Box<RawValue>,\n\
             \x20   pub(crate) table_settings: Arc<indexmap::IndexMap<String, toml::Value>>,\n}\n\n\
             macro_rules! planted_view {\n\
             \x20   () => {\n\
             \x20       pub struct MacroView {\n\
             \x20           pub settings: HashMap<String, String>,\n\
             \x20       }\n\
             \x20   };\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a settings bag is judged by TYPE: HashMap, BTreeMap, serde_yaml::Value, an alias, \
             Box<RawValue>, a wrapped IndexMap and a macro-declared field are each flagged",
            &[ROW_NO_RAW_BAG],
            ov,
            &[
                "7 finding(s)",
                "planted_types.rs:8:",
                "planted_types.rs:9:",
                "planted_types.rs:10:",
                "planted_types.rs:11:",
                "planted_types.rs:12:",
                "planted_types.rs:13:",
                "planted_types.rs:19:",
            ],
        ));

        // A MARKER WITHOUT A REASON IS NOT AN ALLOWANCE. `carries_allow_marker` took the bare words
        // `settings-leak-lint: allow` as a pass, so a marker said nothing a reviewer could weigh.
        // A bare marker and one whose reason is a shrug are each named, and neither covers the
        // raw bag beneath it.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_marker.rs",
            "#[derive(Serialize)]\npub(crate) struct ConfigView {\n\
             \x20   // settings-leak-lint: allow\n\
             \x20   pub(crate) settings: serde_json::Value,\n\
             \x20   // settings-leak-lint: allow — ok\n\
             \x20   pub(crate) hook_settings: serde_json::Map<String, serde_json::Value>,\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an allow marker with no reason, or a reason under the floor, is flagged and covers nothing",
            &[ROW_NO_RAW_BAG],
            ov,
            &[
                "4 finding(s)",
                "planted_marker.rs:3:",
                "planted_marker.rs:4:",
                "planted_marker.rs:5:",
                "planted_marker.rs:6:",
            ],
        ));

        // A TYPED SETTINGS FIELD IS NOT A BAG. A field whose type the tree declares field by field
        // (through a wrapper, a reference, a `Vec`), the keys projection, a struct LITERAL that fills
        // a settings field, and a function parameter that reads a bag all stay silent.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_typed.rs",
            "pub(crate) struct PlantedShape {\n\
             \x20   pub(crate) url: String,\n}\n\n\
             pub(crate) struct Door<'a> {\n\
             \x20   pub(crate) settings: PlantedShape,\n\
             \x20   pub(crate) client_settings: Option<std::sync::Arc<crate::planted_typed::PlantedShape>>,\n\
             \x20   pub(crate) borrowed_settings: &'a [PlantedShape],\n\
             \x20   pub(crate) settings_keys: Vec<String>,\n}\n\n\
             fn build(settings: &serde_json::Value) -> Door<'static> {\n\
             \x20   Door {\n\
             \x20       settings: shape(settings),\n\
             \x20       client_settings: None,\n\
             \x20       borrowed_settings: &[],\n\
             \x20       settings_keys: keys(settings),\n\
             \x20   }\n}\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a typed settings field, the keys projection, a struct literal and a parameter stay silent",
            &[ROW_NO_RAW_BAG],
        ));

        // A SCHEMA FRAGMENT IS NOT A BAG, AND THE EXEMPTION IS NOT A MUTE FOR THE LINE BELOW IT.
        // R2 read `"settings": {"type": "object"}` — the `x-busbar-secret` oneOf, a DESCRIPTION of
        // a settings bag — as a leak. The exemption is scoped to an inline object literal leading
        // with a schema keyword, so a raw bag two lines down, and a bare `{}` that names no
        // keyword, are both still named. Both are planted here BESIDE the fragment: an exemption
        // proved only on a file that holds nothing else proves nothing about a real tree.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_schema.rs",
            "fn secret_schema() -> serde_json::Value {\n\
             \x20   json!({\"properties\": {\n\
             \x20       \"module\": {\"type\": \"string\"},\n\
             \x20       \"settings\": {\"type\": \"object\"},\n\
             \x20       \"either\": {\"settings\": {\"oneOf\": [{\"const\": \"none\"}]}},\n\
             \x20   }})\n}\n\n\
             fn hook_status() -> Response {\n\
             \x20   ok_json(StatusCode::OK, &json!({\n\
             \x20       \"settings\": settings,\n\
             \x20       \"also\": {\"settings\": {}},\n\
             \x20   }))\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a JSON-Schema fragment is exempt and a raw bag beside it is still named",
            &[ROW_NO_RAW_BAG],
            ov,
            &[
                "2 finding(s)",
                "planted_schema.rs:11",
                "planted_schema.rs:12",
            ],
        ));

        // THE INSTRUMENT: A ROOT THAT LEFT THE SCAN. `$CORE` is 150 of 277 files; renaming it left
        // 127, which cleared a floor of 100 and printed `passed`. Drain ONE root and the per-root
        // check must bite even though the aggregate would still clear.
        match scan_roots(cx) {
            Ok(roots) => {
                let engine = &roots[0];
                match cx.walk(
                    &WalkSpec::new([engine.clone()])
                        .ext("rs")
                        .exclude([EXCLUDE_TESTS_DIR]),
                ) {
                    Ok(files) => {
                        let mut ov = Overlay::new();
                        for f in &files {
                            ov.remove(&f.rel);
                        }
                        report.push(prove_red(
                            cx,
                            self,
                            "one drained root is refused on its own, before the total means anything",
                            &[ROW_SCAN_ROOTS],
                            ov,
                            &["missing or drained"],
                        ));
                    }
                    Err(e) => report.note_infra_failure(format!(
                        "settings-leak selftest: the engine root is unreadable ({e})"
                    )),
                }
            }
            Err(e) => report.note_infra_failure(format!(
                "settings-leak selftest: the plane roots do not resolve on this tree ({e}), so \
                 neither root plant has anything to drain"
            )),
        }

        // THE AGGREGATE FLOOR, on the run path: every root keeps a file, so the per-root check
        // passes, and the total still falls under the floor.
        match scan_roots(cx) {
            Ok(roots) => {
                let mut ov = Overlay::new();
                let mut planted_any = false;
                for root in &roots {
                    if let Ok(files) = cx.walk(
                        &WalkSpec::new([root.clone()])
                            .ext("rs")
                            .exclude([EXCLUDE_TESTS_DIR]),
                    ) {
                        for f in files.iter().skip(1) {
                            ov.remove(&f.rel);
                            planted_any = true;
                        }
                    }
                }
                if planted_any {
                    report.push(prove_red(
                        cx,
                        self,
                        "a scan set below its floor is refused even when every root still holds a file",
                        &[ROW_SCAN_FLOOR],
                        ov,
                        &["below its floor"],
                    ));
                } else {
                    report.note_infra_failure(
                        "settings-leak selftest: no root holds a second file, so the aggregate \
                         floor cannot be driven without also emptying a root"
                            .to_string(),
                    );
                }
            }
            Err(_) => { /* already reported by the case above */ }
        }

        // THE FLOOR SITS AT THE MEASURED COUNT: one file fewer than the live population is
        // refused. A floor set a margin below the count passes this tree, so the plant is red
        // exactly when the floor has slipped under the number the tree measures.
        match population::one_file_short(cx) {
            Ok(ov) => report.push(prove_red(
                cx,
                self,
                "a population one file short of the measured floor is refused",
                &[ROW_SCAN_FLOOR],
                ov,
                &["below its floor"],
            )),
            Err(e) => report.note_infra_failure(format!("settings-leak selftest: {e}")),
        }

        // THE PLANE ROOTS: the row this gate's header calls the only thing that can catch a plane
        // that split, and which had no red proof at all — a plane that left takes its projections
        // with it, and every remaining root still clears its floor. Driven THROUGH `Gate::run`
        // over a fixture tree in which no plane declares its grammar; the plane resolver reads
        // `std::fs`, so no overlay can plant this.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a plane that cannot be located is refused, not scanned as a smaller tree",
            &[ROW_PLANE_ROOTS],
            PLANE_ROOT_MISSING_FIXTURE,
            &["PLANE-ROOT-MISSING"],
        ));

        report
    }
}

const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a clean tree";

/// Read the shell gate's own output into the same four rows. Nothing here re-scans the tree.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut offenders = Vec::new();
    let mut plane_unresolved = None;
    let mut roots_unusable = None;
    let mut floor_broken = None;
    let mut ran = false;

    for raw in run.lines() {
        let t = raw.trim();
        if t.contains("PLANE ROOT UNRESOLVED") {
            plane_unresolved = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT UNUSABLE") {
            roots_unusable = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT EMPTY OR MOVED") {
            floor_broken = Some(t.to_string());
            continue;
        }
        if t.starts_with("scan set:") || t == "settings-leak-lint passed" {
            ran = true;
            continue;
        }
        if let Some(hit) = t.strip_prefix("SETTINGS-LEAK: ") {
            ran = true;
            offenders.push(hit.to_string());
        }
    }

    if plane_unresolved.is_none() && roots_unusable.is_none() && floor_broken.is_none() && !ran {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no scan-set line, no \
             verdict, no findings. Silence read as a clean tree is the exact defect this gate \
             exists for.",
            run.argv.join(" ")
        ));
    }

    if let Some(why) = plane_unresolved {
        return Ok(vec![
            Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
            Row::fail(
                ROW_SCAN_ROOTS,
                "the root set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_SCAN_FLOOR,
                "the root set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_NO_RAW_BAG,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }
    if let Some(why) = roots_unusable {
        return Ok(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::fail(ROW_SCAN_ROOTS, "a scan root is missing or drained", why),
            Row::fail(
                ROW_SCAN_FLOOR,
                "the scan set is incomplete",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_NO_RAW_BAG,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }
    if let Some(why) = floor_broken {
        return Ok(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(
                ROW_SCAN_ROOTS,
                "every scan root holds production source",
                CLEAN,
            ),
            Row::fail(ROW_SCAN_FLOOR, "the scan set is below its floor", why),
            Row::fail(
                ROW_NO_RAW_BAG,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }

    offenders.sort();
    Ok(vec![
        Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
        Row::pass(
            ROW_SCAN_ROOTS,
            "every scan root holds production source",
            CLEAN,
        ),
        Row::pass(ROW_SCAN_FLOOR, "the scan set cleared its floor", CLEAN),
        row_no_raw_bag(&offenders, "read from the legacy script's output"),
    ])
}
