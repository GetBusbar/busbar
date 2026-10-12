//! `cargo xtask gate abi-header` — THE GENERATED C HEADER, AND PROOF IT HAS NOT DRIFTED.
//!
//! BUSBAR-1.6.0.md §11.5 (line 1322) lists "a generated C header — the zero-dependency proof (#84)"
//! beside the ABI folders, and #84 (line 2237) says a third party builds a plugin from that header
//! alone. This module is the generator. It parses the Rust sources of the memory ABI with `syn` and
//! renders ONE header, `crates/busbar-contract/include/busbar_plugin.h`:
//!
//! * the sources are `abi/mechanism/`, one folder per kind (`store`, `secret`, `auth`, `hook`,
//!   `export`, `plane`, `transport`; a `tests/` folder is never read) and the three host tables a
//!   plugin calls (`abi/host/conn/connector.rs`, `abi/host/service.rs`, `abi/host/io.rs`). `abi/cold`, `abi/hot`,
//!   `abi/sdk`, `abi/host/conn/mod.rs` and `abi/mod.rs` are never read;
//! * every C-layout struct and union, every fixed-width enum and transparent newtype, every
//!   `extern "C"` function-pointer alias and every integer `pub const` becomes a C declaration. A
//!   type with no C-layout marker is Rust-only (a validator's fault enum, a contract row) and is
//!   not part of the boundary;
//! * a construct the generator cannot map FAILS the run and names the item. Nothing is skipped
//!   silently;
//! * the committed layout golden (`crates/busbar-contract/tests/golden/abi-layout.golden`) is the
//!   ONE layout pin: for every emitted struct it records, the header carries `_Static_assert`s for
//!   its size, alignment and field offsets, so a C compiler refuses a header that disagrees.
//!
//! NAMING. Each source is a kind: `mech`, `store`, `secret`, `auth`, `hook`, `export`, `plane`,
//! `transport`, `hconn` (the connector table), `hsvc` (the service table) and `hio` (the host I/O
//! table). A type is
//! `bb_<kind>_<RustName>` and a constant is `BB_<KIND>_<RUST_NAME>`, so one Rust name in two kinds
//! cannot collide. A constant inside an inline module carries the module name
//! (`BB_STORE_SLOT_RESERVE`); an enum variant is `BB_<KIND>_<Enum>_<Variant>`.
//!
//! THE COMMAND. `cargo xtask abi-header` re-renders and fails, naming the first differing line, if
//! the committed header differs. `cargo xtask abi-header --write` rewrites it. It is the one command
//! to run after any change under `abi/`.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use proc_macro2::{TokenStream, TokenTree};
use std::collections::{HashMap, HashSet};

pub const ROW_DRIFT: &str = "abi-header:drift";

/// Where the header is committed.
pub const HEADER: &str = "crates/busbar-contract/include/busbar_plugin.h";
/// The layout pin the header's static assertions come from.
pub const GOLDEN: &str = "crates/busbar-contract/tests/golden/abi-layout.golden";
/// The one command that regenerates the header.
pub const REGENERATE: &str = "cargo xtask abi-header --write";

const ABI: &str = "crates/busbar-contract/src/abi";

/// `(kind, golden alias prefix, path under abi/, is a folder)`. The order is the order of the
/// header's sections.
const SOURCES: &[(&str, &str, &str, bool)] = &[
    ("mech", "Mech", "mechanism", true),
    ("store", "Store", "store", true),
    ("secret", "Secret", "secret", true),
    ("auth", "Auth", "auth", true),
    ("hook", "Hook", "hook", true),
    ("export", "Export", "export", true),
    ("plane", "pkind::", "plane", true),
    ("transport", "tkind::", "transport", true),
    ("hconn", "hconn::", "host/conn/connector.rs", false),
    ("hsvc", "hsvc::", "host/service.rs", false),
    ("hio", "hio::", "host/io.rs", false),
];

/// One source file handed to [`render_sources`].
pub struct Src<'a> {
    pub kind: &'a str,
    pub rel: &'a str,
    pub text: &'a str,
}

// ───────────────────────────── the C type model ─────────────────────────────

#[derive(Clone, Debug)]
enum Ty {
    Void,
    Prim(&'static str),
    Named(String, String),
    Ptr(bool, Box<Ty>),
    Array(Box<Ty>, u128),
    Fn(Option<Box<Ty>>, Vec<Ty>),
}

fn cname(kind: &str, name: &str) -> String {
    format!("bb_{kind}_{name}")
}

fn prim(name: &str) -> Option<&'static str> {
    Some(match name {
        "u8" => "uint8_t",
        "u16" => "uint16_t",
        "u32" => "uint32_t",
        "u64" => "uint64_t",
        "i8" => "int8_t",
        "i16" => "int16_t",
        "i32" => "int32_t",
        "i64" => "int64_t",
        "usize" => "size_t",
        "isize" => "ptrdiff_t",
        "f32" => "float",
        "f64" => "double",
        "bool" => "bool",
        _ => return None,
    })
}

const C_KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "bool",
    "true",
    "false",
    // C++ keywords, so the header also reads as C++.
    "class",
    "new",
    "delete",
    "this",
    "template",
    "typename",
    "namespace",
    "operator",
    "private",
    "public",
    "protected",
    "virtual",
    "friend",
    "explicit",
    "export",
    "mutable",
    "using",
    "try",
    "catch",
    "throw",
    "typeid",
    "and",
    "or",
    "not",
    "xor",
];

/// A Rust identifier as the field name the layout golden records: a raw-identifier prefix dropped.
fn rust_field(ident: &syn::Ident) -> String {
    let s = ident.to_string();
    s.strip_prefix("r#").unwrap_or(&s).to_string()
}

/// A Rust field name as a C member name: a C keyword gains a trailing underscore.
fn cfield(name: &str) -> String {
    if C_KEYWORDS.contains(&name) {
        format!("{name}_")
    } else {
        name.to_string()
    }
}

fn qualified(q: bool, base: &str, inner: &str) -> String {
    let c = if q { "const " } else { "" };
    if inner.is_empty() {
        format!("{c}{base}")
    } else {
        format!("{c}{base} {inner}")
    }
}

/// The C declaration of `inner` (a name, possibly already wrapped in declarator syntax) having type
/// `ty`. `q` is whether the object of this type is const-qualified.
fn decl(ty: &Ty, inner: String, q: bool) -> String {
    match ty {
        Ty::Void => qualified(q, "void", &inner),
        Ty::Prim(p) => qualified(q, p, &inner),
        Ty::Named(k, n) => qualified(q, &cname(k, n), &inner),
        Ty::Ptr(c, to) => {
            let star = format!("*{}{}", if q { "const " } else { "" }, inner);
            let wrapped = if matches!(**to, Ty::Array(..)) {
                format!("({star})")
            } else {
                star
            };
            decl(to, wrapped, *c)
        }
        Ty::Array(el, n) => decl(el, format!("{inner}[{n}]"), q),
        Ty::Fn(ret, args) => {
            let list = if args.is_empty() {
                "void".to_string()
            } else {
                args.iter()
                    .map(|a| decl(a, String::new(), false))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let ptr = format!("(*{}{})({})", if q { "const " } else { "" }, inner, list);
            match ret {
                Some(r) => decl(r, ptr, false),
                None => qualified(false, "void", &ptr),
            }
        }
    }
}

/// Every named type `ty` mentions, with whether it is needed by value (complete) or only by name.
fn mentions(ty: &Ty, by_value: bool, out: &mut Vec<(String, String, bool)>) {
    match ty {
        Ty::Void | Ty::Prim(_) => {}
        Ty::Named(k, n) => out.push((k.clone(), n.clone(), by_value)),
        Ty::Ptr(_, to) => mentions(to, false, out),
        Ty::Array(el, _) => mentions(el, by_value, out),
        Ty::Fn(ret, args) => {
            if let Some(r) = ret {
                mentions(r, false, out);
            }
            for a in args {
                mentions(a, false, out);
            }
        }
    }
}

// ───────────────────────────── collected items ─────────────────────────────

struct FileCtx {
    kind: String,
    rel: String,
    uses: HashMap<String, Vec<String>>,
    globs: Vec<Vec<String>>,
}

enum Raw {
    Struct {
        union: bool,
        fields: Vec<(String, syn::Type)>,
    },
    Newtype(syn::Type),
    Enum {
        repr: &'static str,
        variants: Vec<(String, Option<syn::Expr>)>,
    },
    Alias(syn::Type),
}

struct RawItem {
    file: usize,
    name: String,
    doc: Option<String>,
    raw: Raw,
}

#[derive(Clone, Copy, PartialEq)]
enum ConstKind {
    Int(&'static str),
    Text,
    Bytes,
    Other,
}

struct RawConst {
    file: usize,
    scope: String,
    name: String,
    doc: Option<String>,
    kind: ConstKind,
    expr: syn::Expr,
}

#[derive(Default)]
struct Collected {
    files: Vec<FileCtx>,
    items: Vec<RawItem>,
    consts: Vec<RawConst>,
    errs: Vec<String>,
}

fn doc_line(attrs: &[syn::Attribute]) -> Option<String> {
    for a in attrs {
        if !a.path().is_ident("doc") {
            continue;
        }
        if let syn::Meta::NameValue(nv) = &a.meta {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &nv.value
            {
                let t = s.value();
                let t = t.trim();
                if !t.is_empty() {
                    return Some(t.replace("*/", "* /").replace("/*", "/ *"));
                }
            }
        }
    }
    None
}

fn has_ident(ts: TokenStream, word: &str) -> bool {
    ts.into_iter().any(|tt| match tt {
        TokenTree::Ident(i) => i == word,
        TokenTree::Group(g) => has_ident(g.stream(), word),
        _ => false,
    })
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && match &a.meta {
                syn::Meta::List(l) => has_ident(l.tokens.clone(), "test"),
                _ => false,
            }
    })
}

/// The representation hints of an item: `(c, transparent, integer)`.
fn repr_of(attrs: &[syn::Attribute]) -> Result<(bool, bool, Option<&'static str>), String> {
    let mut c = false;
    let mut transparent = false;
    let mut int = None;
    for a in attrs {
        if !a.path().is_ident("repr") {
            continue;
        }
        a.parse_nested_meta(|m| {
            let p = &m.path;
            if p.is_ident("C") {
                c = true;
            } else if p.is_ident("transparent") {
                transparent = true;
            } else if let Some(i) = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"]
                .iter()
                .find(|w| p.is_ident(w))
            {
                int = prim(i);
            } else {
                return Err(m.error("an unsupported representation hint"));
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?;
    }
    Ok((c, transparent, int))
}

fn flatten_use(tree: &syn::UseTree, prefix: &mut Vec<String>, f: &mut FileCtx) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten_use(&p.tree, prefix, f);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let id = n.ident.to_string();
            if id == "self" {
                if let Some(last) = prefix.last().cloned() {
                    f.uses.insert(last, prefix.clone());
                }
            } else {
                let mut full = prefix.clone();
                full.push(id.clone());
                f.uses.insert(id, full);
            }
        }
        syn::UseTree::Rename(r) => {
            let mut full = prefix.clone();
            full.push(r.ident.to_string());
            f.uses.insert(r.rename.to_string(), full);
        }
        syn::UseTree::Glob(_) => f.globs.push(prefix.clone()),
        syn::UseTree::Group(g) => {
            for t in &g.items {
                flatten_use(t, prefix, f);
            }
        }
    }
}

fn const_kind(t: &syn::Type) -> ConstKind {
    match t {
        syn::Type::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => {
            let id = p.path.segments[0].ident.to_string();
            match id.as_str() {
                "u8" => ConstKind::Int("u8"),
                "u16" => ConstKind::Int("u16"),
                "u32" => ConstKind::Int("u32"),
                "u64" => ConstKind::Int("u64"),
                "usize" => ConstKind::Int("usize"),
                _ => ConstKind::Other,
            }
        }
        syn::Type::Reference(r) => match &*r.elem {
            syn::Type::Path(p) if p.path.is_ident("str") => ConstKind::Text,
            syn::Type::Slice(s) => match &*s.elem {
                syn::Type::Path(p) if p.path.is_ident("u8") => ConstKind::Bytes,
                _ => ConstKind::Other,
            },
            _ => ConstKind::Other,
        },
        _ => ConstKind::Other,
    }
}

/// The glue macros whose expansion is Rust-side only: they build a contract table or an SDK marker
/// and define no C layout.
const GLUE_MACROS: &[&str] = &["kind_slots", "slot_structs", "contract", "byte_dim"];

/// The rows of a `store_slots!` invocation: `(slot number, CONST, field)`.
fn store_rows(ts: TokenStream) -> Result<Vec<(u128, String, String)>, String> {
    let mut rows = Vec::new();
    let mut cur: Vec<TokenTree> = Vec::new();
    let mut take = |cur: &mut Vec<TokenTree>| -> Result<(), String> {
        if cur.is_empty() {
            return Ok(());
        }
        let (a, b, c) = match (cur.first(), cur.get(1), cur.get(2)) {
            (Some(TokenTree::Literal(a)), Some(TokenTree::Ident(b)), Some(TokenTree::Ident(c))) => {
                (a.to_string(), b.to_string(), c.to_string())
            }
            _ => return Err("a row does not start `<slot> <CONST> <field>`".to_string()),
        };
        let k = a
            .parse::<u128>()
            .map_err(|_| format!("slot number `{a}` is not a plain integer"))?;
        rows.push((k, b, c));
        cur.clear();
        Ok(())
    };
    for tt in ts {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ';' => take(&mut cur)?,
            _ => cur.push(tt),
        }
    }
    take(&mut cur)?;
    Ok(rows)
}

fn parse_ty(s: &str) -> syn::Type {
    syn::parse_str::<syn::Type>(s).expect("a literal type parses")
}

fn collect_items(items: &[syn::Item], file: usize, scope: &mut Vec<String>, col: &mut Collected) {
    for item in items {
        let at = |col: &Collected, what: &str| format!("{} `{what}`", col.files[file].rel);
        match item {
            syn::Item::Use(u) => {
                let mut f = FileCtx {
                    kind: String::new(),
                    rel: String::new(),
                    uses: HashMap::new(),
                    globs: Vec::new(),
                };
                flatten_use(&u.tree, &mut Vec::new(), &mut f);
                col.files[file].uses.extend(f.uses);
                col.files[file].globs.extend(f.globs);
            }
            syn::Item::Mod(m) => {
                if is_cfg_test(&m.attrs) || m.ident == "tests" {
                    continue;
                }
                if let Some((_, inner)) = &m.content {
                    scope.push(m.ident.to_string());
                    collect_items(inner, file, scope, col);
                    scope.pop();
                }
            }
            syn::Item::Struct(s) => {
                if is_cfg_test(&s.attrs) {
                    continue;
                }
                let name = s.ident.to_string();
                let (c, transparent, _) = match repr_of(&s.attrs) {
                    Ok(r) => r,
                    Err(e) => {
                        col.errs.push(format!("{}: {e}", at(col, &name)));
                        continue;
                    }
                };
                if !c && !transparent {
                    continue;
                }
                if !s.generics.params.is_empty() {
                    col.errs.push(format!(
                        "{}: a generic C-layout struct cannot be mapped",
                        at(col, &name)
                    ));
                    continue;
                }
                let doc = doc_line(&s.attrs);
                match (&s.fields, transparent) {
                    (syn::Fields::Unnamed(u), true) if u.unnamed.len() == 1 => {
                        col.items.push(RawItem {
                            file,
                            name,
                            doc,
                            raw: Raw::Newtype(u.unnamed[0].ty.clone()),
                        });
                    }
                    (syn::Fields::Named(n), false) if !n.named.is_empty() => {
                        let fields = n
                            .named
                            .iter()
                            .filter_map(|f| f.ident.as_ref().map(|i| (rust_field(i), f.ty.clone())))
                            .collect();
                        col.items.push(RawItem {
                            file,
                            name,
                            doc,
                            raw: Raw::Struct {
                                union: false,
                                fields,
                            },
                        });
                    }
                    (syn::Fields::Unnamed(u), false) if !u.unnamed.is_empty() => {
                        let fields = u
                            .unnamed
                            .iter()
                            .enumerate()
                            .map(|(i, f)| (format!("f{i}"), f.ty.clone()))
                            .collect();
                        col.items.push(RawItem {
                            file,
                            name,
                            doc,
                            raw: Raw::Struct {
                                union: false,
                                fields,
                            },
                        });
                    }
                    _ => col.errs.push(format!(
                        "{}: only a named-field C-layout struct and a one-field transparent newtype map to C",
                        at(col, &name)
                    )),
                }
            }
            syn::Item::Union(u) => {
                if is_cfg_test(&u.attrs) {
                    continue;
                }
                let name = u.ident.to_string();
                match repr_of(&u.attrs) {
                    Ok((true, _, _)) => {
                        let fields = u
                            .fields
                            .named
                            .iter()
                            .filter_map(|f| f.ident.as_ref().map(|i| (rust_field(i), f.ty.clone())))
                            .collect();
                        col.items.push(RawItem {
                            file,
                            name,
                            doc: doc_line(&u.attrs),
                            raw: Raw::Struct {
                                union: true,
                                fields,
                            },
                        });
                    }
                    Ok(_) => {}
                    Err(e) => col.errs.push(format!("{}: {e}", at(col, &name))),
                }
            }
            syn::Item::Enum(e) => {
                if is_cfg_test(&e.attrs) {
                    continue;
                }
                let name = e.ident.to_string();
                let (c, _, int) = match repr_of(&e.attrs) {
                    Ok(r) => r,
                    Err(why) => {
                        col.errs.push(format!("{}: {why}", at(col, &name)));
                        continue;
                    }
                };
                let repr = match (int, c) {
                    (Some(i), _) => i,
                    (None, true) => "int32_t",
                    (None, false) => continue,
                };
                let mut variants = Vec::new();
                let mut ok = true;
                for v in &e.variants {
                    if !matches!(v.fields, syn::Fields::Unit) {
                        col.errs.push(format!(
                            "{}: variant `{}` carries data, which a C enum cannot",
                            at(col, &name),
                            v.ident
                        ));
                        ok = false;
                        continue;
                    }
                    variants.push((
                        v.ident.to_string(),
                        v.discriminant.as_ref().map(|(_, x)| x.clone()),
                    ));
                }
                if ok {
                    col.items.push(RawItem {
                        file,
                        name,
                        doc: doc_line(&e.attrs),
                        raw: Raw::Enum { repr, variants },
                    });
                }
            }
            syn::Item::Type(t) => {
                if is_cfg_test(&t.attrs) {
                    continue;
                }
                col.items.push(RawItem {
                    file,
                    name: t.ident.to_string(),
                    doc: doc_line(&t.attrs),
                    raw: Raw::Alias((*t.ty).clone()),
                });
            }
            syn::Item::Const(c) => {
                if is_cfg_test(&c.attrs) {
                    continue;
                }
                let name = c.ident.to_string();
                if name == "_" {
                    continue;
                }
                let public = matches!(c.vis, syn::Visibility::Public(_));
                let kind = const_kind(&c.ty);
                // Private constants are still evaluable, so a public one may name them.
                if !public && !matches!(kind, ConstKind::Int(_)) {
                    continue;
                }
                col.consts.push(RawConst {
                    file,
                    scope: scope.join("_"),
                    name,
                    doc: if public { doc_line(&c.attrs) } else { None },
                    kind: if public { kind } else { ConstKind::Other },
                    expr: (*c.expr).clone(),
                });
            }
            syn::Item::Macro(m) => {
                if is_cfg_test(&m.attrs) {
                    continue;
                }
                let name = m
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                let defines = m.ident.as_ref().map(ToString::to_string);
                if defines.as_deref() == Some("store_slots") {
                    // The one macro whose expansion is a C layout; its invocation is expanded below.
                    continue;
                }
                if defines.is_some() || GLUE_MACROS.contains(&name.as_str()) {
                    // A macro definition, or a glue invocation. Either one defining a C layout
                    // would be an ABI shape this generator cannot see: refuse it.
                    if has_ident(m.mac.tokens.clone(), "repr") {
                        col.errs.push(format!(
                            "{}: macro `{name}` defines a C layout the generator cannot read",
                            at(col, &name)
                        ));
                    }
                    continue;
                }
                if name == "store_slots" {
                    match store_rows(m.mac.tokens.clone()) {
                        Ok(rows) => {
                            let mut fields = vec![("head".to_string(), parse_ty("OpsHead"))];
                            for (k, konst, field) in rows {
                                fields.push((field, parse_ty("Option<Op>")));
                                col.consts.push(RawConst {
                                    file,
                                    scope: "slot".to_string(),
                                    name: konst,
                                    doc: None,
                                    kind: ConstKind::Int("u32"),
                                    expr: syn::parse_str::<syn::Expr>(&format!(
                                        "LIFECYCLE_SLOTS + {k}"
                                    ))
                                    .expect("a literal expression parses"),
                                });
                            }
                            col.items.push(RawItem {
                                file,
                                name: "Ops".to_string(),
                                doc: Some("The store kind's ops table.".to_string()),
                                raw: Raw::Struct {
                                    union: false,
                                    fields,
                                },
                            });
                        }
                        Err(why) => col
                            .errs
                            .push(format!("{}: store_slots!: {why}", at(col, "store_slots"))),
                    }
                    continue;
                }
                col.errs.push(format!(
                    "{}: item macro `{name}!` is not one the generator knows (glue or store_slots)",
                    at(col, &name)
                ));
            }
            _ => {}
        }
    }
}

// ───────────────────────────── constants ─────────────────────────────

struct ConstTable<'a> {
    map: HashMap<(String, String, String), &'a syn::Expr>,
}

impl ConstTable<'_> {
    fn eval(&self, e: &syn::Expr, kind: &str, scope: &str, depth: u32) -> Result<u128, String> {
        if depth > 32 {
            return Err("constant expression nests too deeply".to_string());
        }
        match e {
            syn::Expr::Lit(l) => match &l.lit {
                syn::Lit::Int(i) => i.base10_parse::<u128>().map_err(|e| e.to_string()),
                syn::Lit::Byte(b) => Ok(u128::from(b.value())),
                _ => Err("a literal that is not an integer".to_string()),
            },
            syn::Expr::Paren(p) => self.eval(&p.expr, kind, scope, depth + 1),
            syn::Expr::Group(g) => self.eval(&g.expr, kind, scope, depth + 1),
            syn::Expr::Cast(c) => self.eval(&c.expr, kind, scope, depth + 1),
            syn::Expr::Path(p) if p.qself.is_none() => {
                let segs: Vec<String> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if segs.len() == 2 && segs[1] == "MAX" {
                    return match segs[0].as_str() {
                        "u8" => Ok(u128::from(u8::MAX)),
                        "u16" => Ok(u128::from(u16::MAX)),
                        "u32" => Ok(u128::from(u32::MAX)),
                        "u64" => Ok(u128::from(u64::MAX)),
                        other => Err(format!("`{other}::MAX` is not a known integer bound")),
                    };
                }
                let Some(name) = segs.last() else {
                    return Err("an empty path".to_string());
                };
                for (k, s) in [(kind, scope), (kind, ""), ("mech", "")] {
                    if let Some(x) = self.map.get(&(k.to_string(), s.to_string(), name.clone())) {
                        return self.eval(x, k, s, depth + 1);
                    }
                }
                Err(format!(
                    "`{name}` is not a constant the generator can resolve"
                ))
            }
            syn::Expr::Binary(b) => {
                let l = self.eval(&b.left, kind, scope, depth + 1)?;
                let r = self.eval(&b.right, kind, scope, depth + 1)?;
                let v = match b.op {
                    syn::BinOp::Add(_) => l.checked_add(r),
                    syn::BinOp::Sub(_) => l.checked_sub(r),
                    syn::BinOp::Mul(_) => l.checked_mul(r),
                    syn::BinOp::Div(_) => l.checked_div(r),
                    syn::BinOp::Shl(_) => u32::try_from(r).ok().and_then(|s| l.checked_shl(s)),
                    syn::BinOp::Shr(_) => u32::try_from(r).ok().and_then(|s| l.checked_shr(s)),
                    syn::BinOp::BitOr(_) => Some(l | r),
                    syn::BinOp::BitAnd(_) => Some(l & r),
                    syn::BinOp::BitXor(_) => Some(l ^ r),
                    _ => return Err("an operator the generator does not evaluate".to_string()),
                };
                v.ok_or_else(|| "arithmetic that overflows or underflows".to_string())
            }
            syn::Expr::Call(c) => {
                let name = match &*c.func {
                    syn::Expr::Path(p) => p
                        .path
                        .segments
                        .last()
                        .map(|s| s.ident.to_string())
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                let bytes = match c.args.first() {
                    Some(syn::Expr::Unary(u)) if matches!(u.op, syn::UnOp::Deref(_)) => {
                        match &*u.expr {
                            syn::Expr::Lit(syn::ExprLit {
                                lit: syn::Lit::ByteStr(b),
                                ..
                            }) => Some(b.value()),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                match (name.as_str(), bytes) {
                    ("from_le_bytes", Some(b)) if b.len() <= 16 => {
                        Ok(b.iter().rev().fold(0u128, |a, x| (a << 8) | u128::from(*x)))
                    }
                    ("from_be_bytes", Some(b)) if b.len() <= 16 => {
                        Ok(b.iter().fold(0u128, |a, x| (a << 8) | u128::from(*x)))
                    }
                    _ => Err(format!(
                        "a call to `{name}` the generator does not evaluate"
                    )),
                }
            }
            _ => Err("an expression form the generator does not evaluate".to_string()),
        }
    }
}

fn c_int(v: u128, ty: &str) -> String {
    let lit = if v > 0xffff {
        format!("0x{v:x}")
    } else {
        v.to_string()
    };
    match ty {
        "u8" => format!("UINT8_C({lit})"),
        "u16" => format!("UINT16_C({lit})"),
        "u32" => format!("UINT32_C({lit})"),
        "u64" => format!("UINT64_C({lit})"),
        _ => format!("((size_t){lit})"),
    }
}

fn c_string(s: &str) -> String {
    let mut o = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if c.is_ascii_graphic() || c == ' ' => o.push(c),
            c => o.push_str(&format!("\\x{:02x}", c as u32 & 0xff)),
        }
    }
    o.push('"');
    o
}

// ───────────────────────────── type resolution ─────────────────────────────

fn kind_in(segs: &[String]) -> Option<String> {
    let start = if let Some(p) = segs.iter().position(|s| s == "abi") {
        p + 1
    } else if matches!(segs.first().map(String::as_str), Some("super" | "self")) {
        0
    } else {
        return None;
    };
    for s in &segs[start.min(segs.len())..] {
        let k = match s.as_str() {
            "mechanism" => "mech",
            "store" => "store",
            "secret" => "secret",
            "auth" => "auth",
            "hook" => "hook",
            "export" => "export",
            "plane" => "plane",
            "transport" => "transport",
            "connector" => "hconn",
            "service" => "hsvc",
            "io" => "hio",
            _ => continue,
        };
        return Some(k.to_string());
    }
    None
}

struct Resolver<'a> {
    files: &'a [FileCtx],
    defined: HashSet<(String, String)>,
    fn_aliases: HashSet<(String, String)>,
    consts: ConstTable<'a>,
}

impl Resolver<'_> {
    fn lookup(&self, ident: &str, f: &FileCtx) -> Option<(String, String)> {
        let mut cands: Vec<(String, String)> = Vec::new();
        if let Some(path) = f.uses.get(ident) {
            let name = path.last().cloned().unwrap_or_else(|| ident.to_string());
            let prefix = &path[..path.len().saturating_sub(1)];
            if let Some(k) = kind_in(prefix) {
                cands.push((k, name));
            }
        }
        cands.push((f.kind.clone(), ident.to_string()));
        for g in &f.globs {
            if let Some(k) = kind_in(g) {
                cands.push((k, ident.to_string()));
            }
        }
        for k in ["mech", "hsvc", "hconn", "hio"] {
            cands.push((k.to_string(), ident.to_string()));
        }
        cands.into_iter().find(|c| self.defined.contains(c))
    }

    fn map_type(&self, t: &syn::Type, f: &FileCtx) -> Result<Ty, String> {
        match t {
            syn::Type::Path(tp) if tp.qself.is_none() => self.map_path(&tp.path, f),
            syn::Type::Ptr(p) => Ok(Ty::Ptr(
                p.const_token.is_some(),
                Box::new(self.map_type(&p.elem, f)?),
            )),
            syn::Type::Array(a) => {
                let n = self
                    .consts
                    .eval(&a.len, &f.kind, "", 0)
                    .map_err(|e| format!("array length: {e}"))?;
                Ok(Ty::Array(Box::new(self.map_type(&a.elem, f)?), n))
            }
            syn::Type::Paren(p) => self.map_type(&p.elem, f),
            syn::Type::Group(g) => self.map_type(&g.elem, f),
            syn::Type::BareFn(b) => {
                let ok_abi = b
                    .abi
                    .as_ref()
                    .and_then(|a| a.name.as_ref())
                    .is_some_and(|n| n.value() == "C");
                if !ok_abi {
                    return Err("a function pointer that is not extern \"C\"".to_string());
                }
                if b.variadic.is_some() {
                    return Err("a variadic function pointer".to_string());
                }
                let mut args = Vec::new();
                for a in &b.inputs {
                    args.push(self.map_type(&a.ty, f)?);
                }
                let ret = match &b.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, t) => match &**t {
                        syn::Type::Tuple(u) if u.elems.is_empty() => None,
                        other => Some(Box::new(self.map_type(other, f)?)),
                    },
                };
                Ok(Ty::Fn(ret, args))
            }
            other => Err(format!("a `{}` type has no C mapping", type_form(other))),
        }
    }

    fn map_path(&self, p: &syn::Path, f: &FileCtx) -> Result<Ty, String> {
        let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
        let Some(last) = p.segments.last() else {
            return Err("an empty path".to_string());
        };
        let name = last.ident.to_string();
        if name == "Option" {
            let inner = match &last.arguments {
                syn::PathArguments::AngleBracketed(a) => match a.args.first() {
                    Some(syn::GenericArgument::Type(t)) => self.map_type(t, f)?,
                    _ => return Err("an Option with no type argument".to_string()),
                },
                _ => return Err("an Option with no type argument".to_string()),
            };
            return match &inner {
                Ty::Ptr(..) | Ty::Fn(..) => Ok(inner),
                Ty::Named(k, n) if self.fn_aliases.contains(&(k.clone(), n.clone())) => Ok(inner),
                _ => Err("an Option of something that is not a pointer".to_string()),
            };
        }
        if !matches!(last.arguments, syn::PathArguments::None) {
            return Err(format!("a generic `{name}` has no C mapping"));
        }
        if segs.len() == 1 {
            if let Some(c) = prim(&name) {
                return Ok(Ty::Prim(c));
            }
        }
        if name == "c_void" {
            return Ok(Ty::Void);
        }
        if segs.len() == 1 {
            return self
                .lookup(&name, f)
                .map(|(k, n)| Ty::Named(k, n))
                .ok_or_else(|| format!("type `{name}` is not defined in the ABI sources"));
        }
        let prefix = &segs[..segs.len() - 1];
        let kind = kind_in(prefix).unwrap_or_else(|| f.kind.clone());
        if self.defined.contains(&(kind.clone(), name.clone())) {
            Ok(Ty::Named(kind, name))
        } else {
            Err(format!(
                "type `{}` is not defined in the ABI sources",
                segs.join("::")
            ))
        }
    }
}

fn type_form(t: &syn::Type) -> &'static str {
    match t {
        syn::Type::Reference(_) => "reference",
        syn::Type::Slice(_) => "slice",
        syn::Type::Tuple(_) => "tuple",
        syn::Type::TraitObject(_) => "trait object",
        syn::Type::ImplTrait(_) => "impl trait",
        syn::Type::Never(_) => "never",
        syn::Type::Macro(_) => "macro",
        syn::Type::Infer(_) => "inferred",
        syn::Type::Path(_) => "qualified path",
        _ => "unsupported",
    }
}

// ───────────────────────────── the render ─────────────────────────────

struct CStruct {
    kind: String,
    name: String,
    union: bool,
    doc: Option<String>,
    fields: Vec<(String, Ty)>,
}

struct CTypedef {
    kind: String,
    name: String,
    doc: Option<String>,
    ty: Ty,
}

struct CEnum {
    kind: String,
    name: String,
    doc: Option<String>,
    repr: &'static str,
    variants: Vec<(String, u128)>,
}

struct CConst {
    kind: String,
    cname: String,
    doc: Option<String>,
    value: String,
}

/// The golden: `Type.field=offset`, with `__size` and `__align` per type.
fn parse_golden(text: &str) -> HashMap<String, Vec<(String, u64)>> {
    let mut out: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for line in text.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let Some((ty, field)) = key.split_once('.') else {
            continue;
        };
        if let Ok(v) = val.trim().parse::<u64>() {
            out.entry(ty.to_string())
                .or_default()
                .push((field.to_string(), v));
        }
    }
    out
}

fn comment(doc: &Option<String>) -> String {
    match doc {
        Some(d) => format!("/* {d} */\n"),
        None => String::new(),
    }
}

/// Render the header from source texts and the layout golden. The pure core of the gate.
pub fn render_sources(srcs: &[Src<'_>], golden: &str) -> Result<String, String> {
    let mut col = Collected::default();
    for s in srcs {
        if !SOURCES.iter().any(|(k, ..)| *k == s.kind) {
            return Err(format!("{}: `{}` is not an ABI kind", s.rel, s.kind));
        }
        let idx = col.files.len();
        col.files.push(FileCtx {
            kind: s.kind.to_string(),
            rel: s.rel.to_string(),
            uses: HashMap::new(),
            globs: Vec::new(),
        });
        match syn::parse_file(s.text) {
            Ok(file) => collect_items(&file.items, idx, &mut Vec::new(), &mut col),
            Err(e) => col.errs.push(format!("{}: does not parse: {e}", s.rel)),
        }
    }

    // Names, and the duplicates among them.
    let mut defined: HashSet<(String, String)> = HashSet::new();
    let mut fn_aliases: HashSet<(String, String)> = HashSet::new();
    for it in &col.items {
        let kind = col.files[it.file].kind.clone();
        if !defined.insert((kind.clone(), it.name.clone())) {
            col.errs.push(format!(
                "{}: type `{}` is defined twice in kind `{kind}`",
                col.files[it.file].rel, it.name
            ));
        }
        if let Raw::Alias(syn::Type::BareFn(_)) = &it.raw {
            fn_aliases.insert((kind, it.name.clone()));
        }
    }
    let mut table = ConstTable {
        map: HashMap::new(),
    };
    for c in &col.consts {
        table.map.insert(
            (
                col.files[c.file].kind.clone(),
                c.scope.clone(),
                c.name.clone(),
            ),
            &c.expr,
        );
    }
    let res = Resolver {
        files: &col.files,
        defined,
        fn_aliases,
        consts: table,
    };

    let mut structs: Vec<CStruct> = Vec::new();
    let mut typedefs: Vec<CTypedef> = Vec::new();
    let mut enums: Vec<CEnum> = Vec::new();
    let mut errs = std::mem::take(&mut col.errs);
    for it in &col.items {
        let f = &res.files[it.file];
        let at = format!("{}: `{}`", f.rel, it.name);
        match &it.raw {
            Raw::Struct { union, fields } => {
                let mut cf = Vec::new();
                for (fname, ty) in fields {
                    match res.map_type(ty, f) {
                        Ok(Ty::Void) => errs.push(format!("{at}: field `{fname}` is a bare void")),
                        Ok(t) => cf.push((fname.clone(), t)),
                        Err(e) => errs.push(format!("{at}: field `{fname}`: {e}")),
                    }
                }
                structs.push(CStruct {
                    kind: f.kind.clone(),
                    name: it.name.clone(),
                    union: *union,
                    doc: it.doc.clone(),
                    fields: cf,
                });
            }
            Raw::Newtype(t) | Raw::Alias(t) => match res.map_type(t, f) {
                Ok(ty) => typedefs.push(CTypedef {
                    kind: f.kind.clone(),
                    name: it.name.clone(),
                    doc: it.doc.clone(),
                    ty,
                }),
                Err(e) => errs.push(format!("{at}: {e}")),
            },
            Raw::Enum { repr, variants } => {
                let mut next = 0u128;
                let mut vs = Vec::new();
                for (vn, disc) in variants {
                    let v = match disc {
                        Some(x) => match res.consts.eval(x, &f.kind, "", 0) {
                            Ok(v) => v,
                            Err(e) => {
                                errs.push(format!("{at}: variant `{vn}`: {e}"));
                                continue;
                            }
                        },
                        None => next,
                    };
                    next = v + 1;
                    vs.push((vn.clone(), v));
                }
                enums.push(CEnum {
                    kind: f.kind.clone(),
                    name: it.name.clone(),
                    doc: it.doc.clone(),
                    repr,
                    variants: vs,
                });
            }
        }
    }

    // Constants.
    let mut consts: Vec<CConst> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for c in &col.consts {
        let f = &res.files[c.file];
        if matches!(c.kind, ConstKind::Other) {
            continue;
        }
        let scope = if c.scope.is_empty() {
            String::new()
        } else {
            format!("{}_", c.scope.to_uppercase())
        };
        let n = format!("BB_{}_{}{}", f.kind.to_uppercase(), scope, c.name);
        let at = format!("{}: const `{}`", f.rel, c.name);
        let value = match c.kind {
            ConstKind::Int(ty) => match res.consts.eval(&c.expr, &f.kind, &c.scope, 0) {
                Ok(v) => c_int(v, ty),
                Err(e) => {
                    errs.push(format!("{at}: {e}"));
                    continue;
                }
            },
            ConstKind::Text | ConstKind::Bytes => match &c.expr {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => c_string(&s.value()),
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::ByteStr(b),
                    ..
                }) => {
                    let mut bytes = b.value();
                    if bytes.last() == Some(&0) {
                        bytes.pop();
                    }
                    c_string(&String::from_utf8_lossy(&bytes))
                }
                _ => {
                    errs.push(format!("{at}: a string constant that is not a literal"));
                    continue;
                }
            },
            ConstKind::Other => continue,
        };
        if !seen.insert(n.clone()) {
            errs.push(format!("{at}: C name `{n}` is already taken"));
            continue;
        }
        consts.push(CConst {
            kind: f.kind.clone(),
            cname: n,
            doc: c.doc.clone(),
            value,
        });
    }

    // C names may not collide across types either.
    let mut cnames: HashSet<String> = HashSet::new();
    for n in structs
        .iter()
        .map(|s| cname(&s.kind, &s.name))
        .chain(typedefs.iter().map(|t| cname(&t.kind, &t.name)))
        .chain(enums.iter().map(|e| cname(&e.kind, &e.name)))
    {
        if !cnames.insert(n.clone()) {
            errs.push(format!("C type name `{n}` is defined twice"));
        }
    }

    // Order: typedefs by what they name, structs by what they hold by value.
    let td_index: HashMap<(String, String), usize> = typedefs
        .iter()
        .enumerate()
        .map(|(i, t)| ((t.kind.clone(), t.name.clone()), i))
        .collect();
    let st_index: HashMap<(String, String), usize> = structs
        .iter()
        .enumerate()
        .map(|(i, s)| ((s.kind.clone(), s.name.clone()), i))
        .collect();

    let td_order = topo(typedefs.len(), |i| {
        let mut m = Vec::new();
        mentions(&typedefs[i].ty, true, &mut m);
        m.into_iter()
            .filter_map(|(k, n, _)| td_index.get(&(k, n)).copied())
            .collect()
    });
    let st_order = topo(structs.len(), |i| {
        let mut m = Vec::new();
        for (_, t) in &structs[i].fields {
            mentions(t, true, &mut m);
        }
        m.into_iter()
            .filter(|(_, _, by_value)| *by_value)
            .filter_map(|(k, n, _)| st_index.get(&(k, n)).copied())
            .collect()
    });
    let (td_order, st_order) = match (td_order, st_order) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            if let Err(e) = a {
                errs.push(format!("typedefs: {e}"));
            }
            if let Err(e) = b {
                errs.push(format!("structs: {e}"));
            }
            (Vec::new(), Vec::new())
        }
    };

    // The golden.
    let gold = parse_golden(golden);
    let mut asserts = String::new();
    let mut pinned = 0usize;
    for s in &structs {
        let prefix = SOURCES
            .iter()
            .find(|(k, ..)| *k == s.kind)
            .map(|(_, p, ..)| *p)
            .unwrap_or("");
        let cap: String = {
            let mut c = s.kind.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        };
        let mut keys = vec![format!("{prefix}{}", s.name)];
        if s.name.starts_with(&cap) {
            keys.push(s.name.clone());
        }
        let Some((key, entries)) = keys.iter().find_map(|k| {
            gold.get(k)
                .filter(|e| e.iter().any(|(f, _)| f == "__size"))
                .map(|e| (k, e))
        }) else {
            continue;
        };
        let t = cname(&s.kind, &s.name);
        let get = |f: &str| entries.iter().find(|(n, _)| n == f).map(|(_, v)| *v);
        let (Some(size), Some(align)) = (get("__size"), get("__align")) else {
            errs.push(format!("golden `{key}` has no __size and __align"));
            continue;
        };
        pinned += 1;
        asserts.push_str(&format!(
            "BB_ASSERT(sizeof({t}) == {size}, \"{t}: size\");\nBB_ASSERT(BB_ALIGNOF({t}) == {align}, \"{t}: alignment\");\n"
        ));
        for (f, _) in &s.fields {
            if let Some(off) = get(f) {
                let cf = cfield(f);
                asserts.push_str(&format!(
                    "BB_ASSERT(offsetof({t}, {cf}) == {off}, \"{t}.{cf}: offset\");\n"
                ));
            }
        }
        for (f, _) in entries {
            if f != "__size" && f != "__align" && !s.fields.iter().any(|(n, _)| n == f) {
                errs.push(format!(
                    "golden records `{key}.{f}`, which the Rust struct `{}` does not have",
                    s.name
                ));
            }
        }
    }

    if !errs.is_empty() {
        errs.sort();
        errs.dedup();
        return Err(format!(
            "the C header cannot be generated: {} problem(s)\n  {}",
            errs.len(),
            errs.join("\n  ")
        ));
    }

    // Emit.
    let mut o = String::new();
    o.push_str(&format!(
        "/*\n * busbar_plugin.h -- the busbar plugin ABI as a C header (BUSBAR-1.6.0.md section 11.5,\n * decision 84: a third party builds a plugin from this header alone).\n *\n * GENERATED by `{REGENERATE}` from the Rust sources under\n * crates/busbar-contract/src/abi/. DO NOT EDIT. `cargo xtask abi-header` fails if this file differs\n * from what the generator renders.\n *\n * NAMING. Every type is bb_<kind>_<RustName> and every constant is BB_<KIND>_<RUST_NAME>, where\n * <kind> is one of: mech (the shared mechanism), store, secret, auth, hook, export, plane,\n * transport, hconn (the host connector table), hsvc (the host service table), hio (the host I/O\n * table). A constant in an\n * inline module carries the module name (BB_STORE_SLOT_RESERVE); an enum variant is\n * BB_<KIND>_<Enum>_<Variant>. Enums are fixed-width integer typedefs, never C enum types.\n *\n * LAYOUT. The static assertions at the end come from the layout golden\n * (crates/busbar-contract/tests/golden/abi-layout.golden) and hold on a 64-bit target.\n */\n"
    ));
    o.push_str("#ifndef BUSBAR_PLUGIN_H\n#define BUSBAR_PLUGIN_H\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");

    o.push_str("/* ---- constants ---- */\n");
    for (kind, ..) in SOURCES {
        let of_kind: Vec<&CConst> = consts.iter().filter(|c| c.kind == *kind).collect();
        if of_kind.is_empty() {
            continue;
        }
        o.push_str(&format!("\n/* {kind} */\n"));
        for c in of_kind {
            match &c.doc {
                Some(d) => o.push_str(&format!("#define {} {} /* {d} */\n", c.cname, c.value)),
                None => o.push_str(&format!("#define {} {}\n", c.cname, c.value)),
            }
        }
    }

    o.push_str("\n/* ---- enumerations ---- */\n");
    for e in &enums {
        let t = cname(&e.kind, &e.name);
        o.push_str(&comment(&e.doc));
        o.push_str(&format!("typedef {} {t};\n", e.repr));
        for (v, n) in &e.variants {
            o.push_str(&format!(
                "#define BB_{}_{}_{} (({t}){n})\n",
                e.kind.to_uppercase(),
                e.name,
                v
            ));
        }
    }

    o.push_str("\n/* ---- forward declarations ---- */\n");
    for s in &structs {
        let t = cname(&s.kind, &s.name);
        let kw = if s.union { "union" } else { "struct" };
        o.push_str(&format!("typedef {kw} {t} {t};\n"));
    }

    o.push_str("\n/* ---- scalar and function-pointer types ---- */\n");
    for i in td_order {
        let t = &typedefs[i];
        o.push_str(&comment(&t.doc));
        o.push_str(&format!(
            "typedef {};\n",
            decl(&t.ty, cname(&t.kind, &t.name), false)
        ));
    }

    o.push_str("\n/* ---- structures ---- */\n");
    for i in st_order {
        let s = &structs[i];
        let t = cname(&s.kind, &s.name);
        let kw = if s.union { "union" } else { "struct" };
        o.push('\n');
        o.push_str(&comment(&s.doc));
        o.push_str(&format!("{kw} {t} {{\n"));
        for (f, ty) in &s.fields {
            o.push_str(&format!("    {};\n", decl(ty, cfield(f), false)));
        }
        o.push_str("};\n");
    }

    o.push_str(&format!(
        "\n/* ---- layout proof: {pinned} of {} structures are pinned by the golden ---- */\n",
        structs.len()
    ));
    o.push_str("#if UINTPTR_MAX == UINT64_MAX\n#ifdef __cplusplus\n#define BB_ASSERT(c, m) static_assert(c, m)\n#define BB_ALIGNOF(t) alignof(t)\n#else\n#define BB_ASSERT(c, m) _Static_assert(c, m)\n#define BB_ALIGNOF(t) _Alignof(t)\n#endif\n\n");
    o.push_str(&asserts);
    o.push_str("#endif\n\n#ifdef __cplusplus\n}\n#endif\n\n#endif /* BUSBAR_PLUGIN_H */\n");
    Ok(o)
}

/// A depth-first order of `n` nodes in which every node follows what `deps` says it needs.
fn topo(n: usize, deps: impl Fn(usize) -> Vec<usize>) -> Result<Vec<usize>, String> {
    let mut state = vec![0u8; n];
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        visit(i, &deps, &mut state, &mut out)?;
    }
    Ok(out)
}

fn visit(
    i: usize,
    deps: &impl Fn(usize) -> Vec<usize>,
    state: &mut [u8],
    out: &mut Vec<usize>,
) -> Result<(), String> {
    match state[i] {
        2 => return Ok(()),
        1 => return Err("a type holds itself by value".to_string()),
        _ => {}
    }
    state[i] = 1;
    for d in deps(i) {
        visit(d, deps, state, out)?;
    }
    state[i] = 2;
    out.push(i);
    Ok(())
}

// ───────────────────────────── the gate ─────────────────────────────

/// Read the sources through `cx` (so an overlay can plant) and render the header.
pub fn render(cx: &Ctx) -> Result<String, String> {
    let mut texts: Vec<(String, String, String)> = Vec::new();
    for (kind, _, path, folder) in SOURCES {
        let root = format!("{ABI}/{path}");
        if *folder {
            let spec = WalkSpec::new([root.clone()]).ext("rs").exclude(["/tests/"]);
            let files = cx.list(&spec).map_err(|e| format!("{root}: {e}"))?;
            let mut rels: Vec<String> = files
                .iter()
                .map(|f| f.to_string_lossy().replace('\\', "/"))
                .collect();
            rels.sort();
            for rel in rels {
                let text = cx.read(&rel)?;
                texts.push(((*kind).to_string(), rel, text));
            }
        } else {
            let text = cx.read(&root)?;
            texts.push(((*kind).to_string(), root, text));
        }
    }
    let golden = cx.read(GOLDEN)?;
    let srcs: Vec<Src<'_>> = texts
        .iter()
        .map(|(k, r, t)| Src {
            kind: k,
            rel: r,
            text: t,
        })
        .collect();
    render_sources(&srcs, &golden)
}

/// The first line where `committed` and `rendered` differ, or `None`.
pub fn first_difference(committed: &str, rendered: &str) -> Option<String> {
    let mut a = committed.lines();
    let mut b = rendered.lines();
    let mut n = 0usize;
    loop {
        n += 1;
        match (a.next(), b.next()) {
            (None, None) => return None,
            (Some(x), Some(y)) if x == y => {}
            (x, y) => {
                return Some(format!(
                    "line {n}: committed `{}` but the sources render `{}`",
                    x.unwrap_or("<end of file>"),
                    y.unwrap_or("<end of file>")
                ))
            }
        }
    }
}

/// `--write`: regenerate the committed header.
pub fn write(cx: &Ctx) -> Result<String, String> {
    let text = render(cx)?;
    let abs = cx.abs(HEADER);
    if let Some(dir) = abs.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    cx.write_file(HEADER, &text)
        .map_err(|e| format!("{HEADER}: {e}"))?;
    Ok(format!("wrote {HEADER}: {} line(s)", text.lines().count()))
}

pub struct AbiHeaderGate;

impl Gate for AbiHeaderGate {
    fn name(&self) -> &'static str {
        "abi-header"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_DRIFT.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let desc = "the committed C header is exactly what the ABI sources render";
        let row = match render(cx) {
            Err(why) => Row::fail(ROW_DRIFT, desc, why),
            Ok(rendered) => match cx.read(HEADER) {
                Err(_) => Row::fail(
                    ROW_DRIFT,
                    desc,
                    format!("{HEADER} does not exist; run `{REGENERATE}`"),
                ),
                Ok(committed) => match first_difference(&committed, &rendered) {
                    None => Row::pass(
                        ROW_DRIFT,
                        desc,
                        format!("{HEADER}: {} line(s), no drift", rendered.lines().count()),
                    ),
                    Some(d) => Row::fail(
                        ROW_DRIFT,
                        desc,
                        format!("{HEADER} drifted at {d}; run `{REGENERATE}`"),
                    ),
                },
            },
        };
        Verdict::of(vec![row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed header is what the sources render",
            &[ROW_DRIFT],
        ));

        let committed = cx.read(HEADER).unwrap_or_default();

        // A hand edit of the header.
        let mut edited = Overlay::new();
        edited.set(
            HEADER,
            committed.replacen("#define BB_", "#define BB_PERTURBED_", 1),
        );
        report.push(prove_red(
            cx,
            self,
            "a perturbed header is RED, naming the first differing line",
            &[ROW_DRIFT],
            edited,
            &[HEADER, "drifted at line", "BB_PERTURBED_"],
        ));

        // A shape added to a kind folder without regenerating.
        let planted_rs = format!("{ABI}/store/planted_header_shape.rs");
        let mut grown = Overlay::new();
        grown.set(
            planted_rs,
            "#[repr(C)]\npub struct PlantedHeaderShape {\n    pub a: u64,\n}\n".to_string(),
        );
        report.push(prove_red(
            cx,
            self,
            "a new C-layout struct that the header lacks is RED",
            &[ROW_DRIFT],
            grown,
            &["drifted at line"],
        ));

        // A construct with no C mapping.
        let mut bad = Overlay::new();
        bad.set(
            format!("{ABI}/store/planted_unmappable.rs"),
            "#[repr(C)]\npub struct PlantedUnmappable {\n    pub s: String,\n}\n".to_string(),
        );
        report.push(prove_red(
            cx,
            self,
            "a C-layout struct with an unmappable field fails, naming the struct and the type",
            &[ROW_DRIFT],
            bad,
            &["PlantedUnmappable", "String"],
        ));

        // A golden that records a field the struct does not have.
        let golden = cx.read(GOLDEN).unwrap_or_default();
        let mut skew = Overlay::new();
        skew.set(GOLDEN, format!("{golden}StoreReserveIn.planted_field=3\n"));
        report.push(prove_red(
            cx,
            self,
            "a golden field the struct lacks is RED, naming it",
            &[ROW_DRIFT],
            skew,
            &["planted_field"],
        ));
        report
    }
}
