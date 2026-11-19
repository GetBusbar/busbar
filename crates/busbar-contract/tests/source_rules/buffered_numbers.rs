// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! No type core deserializes makes serde buffer a typed number.
//!
//! serde reads an internally or adjacently tagged enum (`#[serde(tag = ..)]`), an untagged enum or
//! variant (`#[serde(untagged)]`) and a flattened field (`#[serde(flatten)]`) by first buffering
//! the value and then replaying it through `deserialize_any`. The exact-number JSON reader
//! (`busbar_contract::json::parse`, `parse_str`, `from_value`: the store's reader) hands
//! `deserialize_any` a number as its token map, so a typed number anywhere inside the buffered part
//! (directly, or in a type it holds, however deep) is refused with "invalid type: map, expected
//! u64": the reader cannot read what the writer wrote. A stored measurement checkpoint stopped boot
//! that way.
//!
//! The rule: every production type under `crates/*/src` that derives `Deserialize` is read without
//! buffering a typed number (`u8`..`u128`, `i8`..`i128`, `usize`, `isize`, `f32`, `f64`, the
//! `NonZero` and atomic integers, std's `Duration` and `SystemTime`). A type read through a plain
//! wire struct (`#[serde(try_from = ..)]` or `from`, the `CapturedFeeWire` pattern) is not buffered
//! by serde and is not flagged; its wire struct is checked as a type of its own. A `json::Value`,
//! `Number` or `RawNumber` reads the token map itself and is not a number here. A type whose only
//! reader hands numbers as numbers is listed in [`READ_ELSEWHERE`] with that reader named.
//!
//! A field's type is followed by name through every type core defines (all of a name's
//! definitions, so a shared name can only add findings), its generic arguments, aliases and wire
//! structs. A field marked `skip` or `skip_deserializing` is not read and is not followed.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::TokenTree;
use syn::visit::Visit;

use crate::walk;

/// A type that buffers a number but is never read by the exact-number reader.
struct Allowed {
    name: &'static str,
    file: &'static str,
    reader: &'static str,
}

const READ_ELSEWHERE: &[Allowed] = &[
    Allowed {
        name: "HookPosition",
        file: "crates/busbar-core-admin/src/v1/contract/mod.rs",
        reader: "the `PUT /hooks/{name}/attachments/{target}` body, read only by `json_body` through \
                 serde_json, which hands an integer that fits a u64 as a u64 (not as its number \
                 map); give it a plain wire struct before that body moves to the exact-number reader",
    },
];

/// Number types serde reads by type, whatever path names them.
const NUMBERS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64",
];

/// std types serde reads as numbers (or as a struct of numbers), unless core defines one of that
/// name.
const STD_NUMBERS: &[&str] = &["Duration", "SystemTime"];

/// Types that read a number's token map themselves, or read nothing.
const NO_NUMBER: &[&str] = &[
    "Value",
    "Number",
    "RawNumber",
    "LazyValue",
    "OwnedLazyValue",
    "PhantomData",
];

fn is_number(name: &str) -> bool {
    NUMBERS.contains(&name)
        || name.starts_with("NonZero")
        || (name.starts_with("Atomic") && name != "AtomicBool")
}

/// One type definition core compiles outside tests.
#[derive(Clone, Copy)]
enum Def<'a> {
    Struct(&'a syn::ItemStruct),
    Enum(&'a syn::ItemEnum),
    Alias(&'a syn::ItemType),
}

impl<'a> Def<'a> {
    fn name(&self) -> String {
        match self {
            Def::Struct(s) => s.ident.to_string(),
            Def::Enum(e) => e.ident.to_string(),
            Def::Alias(t) => t.ident.to_string(),
        }
    }

    fn attrs(&self) -> &'a [syn::Attribute] {
        match *self {
            Def::Struct(s) => &s.attrs,
            Def::Enum(e) => &e.attrs,
            Def::Alias(t) => &t.attrs,
        }
    }

    fn line(&self) -> usize {
        match self {
            Def::Struct(s) => walk::line_of(&s.ident),
            Def::Enum(e) => walk::line_of(&e.ident),
            Def::Alias(t) => walk::line_of(&t.ident),
        }
    }
}

/// Every struct, enum and alias of one file, function bodies included, test code left out.
struct Defs<'a> {
    rel: &'a str,
    out: Vec<(&'a str, Def<'a>)>,
}

impl<'a> Visit<'a> for Defs<'a> {
    fn visit_item_mod(&mut self, m: &'a syn::ItemMod) {
        if !walk::is_cfg_test(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_fn(&mut self, f: &'a syn::ItemFn) {
        if !walk::is_cfg_test(&f.attrs) {
            syn::visit::visit_item_fn(self, f);
        }
    }

    fn visit_item_impl(&mut self, i: &'a syn::ItemImpl) {
        if !walk::is_cfg_test(&i.attrs) {
            syn::visit::visit_item_impl(self, i);
        }
    }

    fn visit_impl_item_fn(&mut self, f: &'a syn::ImplItemFn) {
        if !walk::is_cfg_test(&f.attrs) {
            syn::visit::visit_impl_item_fn(self, f);
        }
    }

    fn visit_item_struct(&mut self, s: &'a syn::ItemStruct) {
        if !walk::is_cfg_test(&s.attrs) {
            self.out.push((self.rel, Def::Struct(s)));
        }
    }

    fn visit_item_enum(&mut self, e: &'a syn::ItemEnum) {
        if !walk::is_cfg_test(&e.attrs) {
            self.out.push((self.rel, Def::Enum(e)));
        }
    }

    fn visit_item_type(&mut self, t: &'a syn::ItemType) {
        if !walk::is_cfg_test(&t.attrs) {
            self.out.push((self.rel, Def::Alias(t)));
        }
    }
}

/// The words inside every `#[serde(..)]` of `attrs`, `#[cfg_attr(.., serde(..))]` included.
fn serde_words(attrs: &[syn::Attribute]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for a in attrs {
        let syn::Meta::List(list) = &a.meta else {
            continue;
        };
        if a.path().is_ident("serde") {
            out.extend(walk::idents(&walk::tokens(&list.tokens)));
        } else if a.path().is_ident("cfg_attr") {
            let toks: Vec<TokenTree> = list.tokens.clone().into_iter().collect();
            for pair in toks.windows(2) {
                if let [TokenTree::Ident(i), TokenTree::Group(g)] = pair {
                    if i == "serde" {
                        out.extend(walk::idents(&walk::tokens(&g.stream())));
                    }
                }
            }
        }
    }
    out
}

/// Whether `attrs` derive `Deserialize` (directly or under `cfg_attr`).
fn derives_deserialize(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        (a.path().is_ident("derive") || a.path().is_ident("cfg_attr"))
            && matches!(&a.meta, syn::Meta::List(list)
                if walk::idents(&walk::tokens(&list.tokens)).iter().any(|i| i == "Deserialize"))
    })
}

/// The wire type a `#[serde(try_from = "W")]` or `#[serde(from = "W")]` reads through, by its last
/// path segment.
fn wire_of(attrs: &[syn::Attribute]) -> Option<String> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("serde"))
        .find_map(|a| {
            let syn::Meta::List(list) = &a.meta else {
                return None;
            };
            let toks: Vec<TokenTree> = list.tokens.clone().into_iter().collect();
            toks.windows(3).find_map(|w| match w {
                [TokenTree::Ident(key), TokenTree::Punct(eq), TokenTree::Literal(lit)]
                    if (key == "from" || key == "try_from") && eq.as_char() == '=' =>
                {
                    let text = lit.to_string();
                    text.trim_matches('"')
                        .rsplit("::")
                        .next()
                        .map(str::to_owned)
                }
                _ => None,
            })
        })
}

fn skipped(attrs: &[syn::Attribute]) -> bool {
    let words = serde_words(attrs);
    words.contains("skip") || words.contains("skip_deserializing")
}

/// One deserialized field: where it sits (`Type.field`, `Enum::Variant.0`) and whether its variant
/// is `#[serde(untagged)]`.
struct Member<'a> {
    label: String,
    field: &'a syn::Field,
    variant_untagged: bool,
}

fn push_fields<'a>(
    prefix: &str,
    fields: &'a syn::Fields,
    variant_untagged: bool,
    out: &mut Vec<Member<'a>>,
) {
    for (index, field) in fields.iter().enumerate() {
        if skipped(&field.attrs) {
            continue;
        }
        let member = field
            .ident
            .as_ref()
            .map_or_else(|| index.to_string(), ToString::to_string);
        out.push(Member {
            label: format!("{prefix}.{member}"),
            field,
            variant_untagged,
        });
    }
}

/// Every field serde reads for `def`.
fn members<'a>(name: &str, def: &Def<'a>) -> Vec<Member<'a>> {
    let mut out = Vec::new();
    match *def {
        Def::Struct(s) => push_fields(name, &s.fields, false, &mut out),
        Def::Enum(e) => {
            for v in &e.variants {
                if skipped(&v.attrs) {
                    continue;
                }
                let untagged = serde_words(&v.attrs).contains("untagged");
                push_fields(
                    &format!("{name}::{}", v.ident),
                    &v.fields,
                    untagged,
                    &mut out,
                );
            }
        }
        Def::Alias(_) => {}
    }
    out
}

/// The fields serde buffers when it reads `def`: all of them under a container `tag` (internally or
/// adjacently tagged) or `untagged`, an untagged variant's, and each flattened field.
fn buffered<'a>(name: &str, def: &Def<'a>) -> Vec<Member<'a>> {
    let words = serde_words(def.attrs());
    let whole = words.contains("tag") || words.contains("untagged");
    members(name, def)
        .into_iter()
        .filter(|m| whole || m.variant_untagged || serde_words(&m.field.attrs).contains("flatten"))
        .collect()
}

/// The search for a typed number under one buffered type.
struct Search<'d, 'a> {
    defs: &'d BTreeMap<String, Vec<Def<'a>>>,
    seen: BTreeSet<String>,
}

impl Search<'_, '_> {
    /// The first typed number `ty` holds, as the path to it (`A.f -> B.g: u64`).
    fn ty(&mut self, ty: &syn::Type, at: &str) -> Option<String> {
        match ty {
            syn::Type::Path(p) => self.path(&p.path, at),
            syn::Type::Reference(r) => self.ty(&r.elem, at),
            syn::Type::Slice(s) => self.ty(&s.elem, at),
            syn::Type::Array(a) => self.ty(&a.elem, at),
            syn::Type::Paren(p) => self.ty(&p.elem, at),
            syn::Type::Group(g) => self.ty(&g.elem, at),
            syn::Type::Tuple(t) => t.elems.iter().find_map(|e| self.ty(e, at)),
            _ => None,
        }
    }

    fn path(&mut self, path: &syn::Path, at: &str) -> Option<String> {
        let name = path.segments.last()?.ident.to_string();
        if is_number(&name)
            || (STD_NUMBERS.contains(&name.as_str()) && !self.defs.contains_key(&name))
        {
            return Some(format!("{at}: {name}"));
        }
        if NO_NUMBER.contains(&name.as_str()) {
            return None;
        }
        for segment in &path.segments {
            if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                for arg in &args.args {
                    if let syn::GenericArgument::Type(inner) = arg {
                        if let Some(hit) = self.ty(inner, at) {
                            return Some(hit);
                        }
                    }
                }
            }
        }
        self.named(&name, at)
    }

    /// Every definition core gives `name`, followed once.
    fn named(&mut self, name: &str, at: &str) -> Option<String> {
        if !self.seen.insert(name.to_owned()) {
            return None;
        }
        let defs = self.defs;
        for def in defs.get(name)? {
            if let Def::Alias(t) = def {
                if let Some(hit) = self.ty(&t.ty, at) {
                    return Some(hit);
                }
                continue;
            }
            for m in members(name, def) {
                if let Some(hit) = self.ty(&m.field.ty, &format!("{at} -> {}", m.label)) {
                    return Some(hit);
                }
            }
            if let Some(wire) = wire_of(def.attrs()) {
                if let Some(hit) = self.named(&wire, at) {
                    return Some(hit);
                }
            }
        }
        None
    }
}

/// A deserialized type that buffers a typed number.
struct Finding {
    name: String,
    rel: String,
    line: usize,
    number: String,
}

fn findings(sources: &[(&str, &syn::File)]) -> Vec<Finding> {
    let mut all = Vec::new();
    for &(rel, file) in sources {
        let mut defs = Defs {
            rel,
            out: Vec::new(),
        };
        defs.visit_file(file);
        all.extend(defs.out);
    }
    let mut by_name: BTreeMap<String, Vec<Def<'_>>> = BTreeMap::new();
    for (_, def) in &all {
        by_name.entry(def.name()).or_default().push(*def);
    }
    let mut out = Vec::new();
    for (rel, def) in &all {
        if !derives_deserialize(def.attrs()) || wire_of(def.attrs()).is_some() {
            continue;
        }
        let name = def.name();
        let mut search = Search {
            defs: &by_name,
            seen: BTreeSet::new(),
        };
        let hit = buffered(&name, def)
            .iter()
            .find_map(|m| search.ty(&m.field.ty, &m.label));
        if let Some(number) = hit {
            out.push(Finding {
                name,
                rel: (*rel).to_owned(),
                line: def.line(),
                number,
            });
        }
    }
    out
}

/// Every crate's `src`, plugins left out.
fn roots() -> Vec<String> {
    let crates = walk::repo().join("crates");
    let mut out: Vec<String> = std::fs::read_dir(&crates)
        .expect("crates/ is readable")
        .flatten()
        .filter(|e| e.path().join("src").is_dir())
        .map(|e| format!("crates/{}/src", e.file_name().to_string_lossy()))
        .filter(|root| !walk::is_plugin_crate(root))
        .collect();
    out.sort();
    out
}

#[test]
fn no_deserialized_type_buffers_a_typed_number() {
    let roots = roots();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let sources = walk::production(&roots);
    let parsed: Vec<(&str, &syn::File)> =
        sources.iter().map(|s| (s.rel.as_str(), &s.file)).collect();
    let found = findings(&parsed);
    let mut errors = Vec::new();
    for f in &found {
        if !READ_ELSEWHERE
            .iter()
            .any(|a| a.name == f.name && a.file == f.rel)
        {
            errors.push(format!(
                "{}:{}: `{}` derives Deserialize and serde buffers it (tag, untagged or flatten), \
                 yet it holds a typed number ({}); the exact-number JSON reader refuses that number \
                 as \"invalid type: map\". Read it through a plain wire struct \
                 (`#[serde(try_from = ..)]`, the CapturedFeeWire pattern), or list it in \
                 READ_ELSEWHERE naming the reader that hands it numbers",
                f.rel, f.line, f.name, f.number
            ));
        }
    }
    for a in READ_ELSEWHERE {
        assert!(!a.reader.is_empty(), "{} names its reader", a.name);
        if !found.iter().any(|f| f.name == a.name && f.rel == a.file) {
            errors.push(format!(
                "READ_ELSEWHERE lists `{}` ({}), which no longer buffers a number: delete its row",
                a.name, a.file
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn the_buffered_number_scan_sees_each_buffering_shape() {
    let file = syn::parse_file(
        r##"
        #[derive(Deserialize)] struct Basis { effective_from: u64, name: String }
        #[derive(Deserialize)] #[serde(tag = "kind")] enum Tagged { A { basis: Basis }, B }
        #[derive(Deserialize)] #[serde(untagged)] enum Words { One(String), Many(Vec<String>) }
        #[derive(Deserialize)] #[serde(untagged)] enum Position { Last(Word), Index(u32) }
        #[derive(Deserialize)] enum Word { Last }
        #[derive(Deserialize)] struct Flat { n: u64, #[serde(flatten)] rest: BTreeMap<String, Vec<String>> }
        #[derive(Deserialize)] struct FlatNumber { #[serde(flatten)] inner: Option<Inner> }
        type Inner = Windows;
        #[derive(Deserialize)] struct Windows { at: std::time::Duration }
        #[derive(Deserialize)] #[serde(tag = "kind", try_from = "Wire")] enum Read { A { n: u64 } }
        #[derive(Deserialize)] struct Wire { kind: String, n: Option<u64> }
        #[derive(Serialize)] #[serde(tag = "kind")] enum Written { A { n: u64 } }
        #[derive(Deserialize)] enum Mixed { Plain(u8), #[serde(untagged)] Loose(f64) }
        #[derive(Deserialize)] #[serde(untagged)] enum Exact { Raw(json::Value), #[serde(skip)] Never(u64) }
        #[derive(Deserialize)] #[serde(untagged)] enum Tree { Leaf(String), Node(Vec<Tree>) }
        #[derive(Deserialize)] #[serde(tag = "t", content = "c")] enum Adjacent { N(NonZeroU64) }
        #[cfg_attr(feature = "x", derive(serde::Deserialize))]
        #[cfg_attr(feature = "x", serde(untagged))]
        enum Gated { N(i64) }
        #[cfg(test)] mod tests { #[derive(Deserialize)] #[serde(untagged)] enum T { N(u64) } }
        fn f() { #[derive(Deserialize)] #[serde(untagged)] enum Inside { N(usize) } }
        "##,
    )
    .expect("planted source parses");
    let found: Vec<(String, String)> = findings(&[("planted.rs", &file)])
        .into_iter()
        .map(|f| (f.name, f.number))
        .collect();
    let expected: Vec<(String, String)> = [
        ("Tagged", "Tagged::A.basis -> Basis.effective_from: u64"),
        ("Position", "Position::Index.0: u32"),
        ("FlatNumber", "FlatNumber.inner -> Windows.at: Duration"),
        ("Mixed", "Mixed::Loose.0: f64"),
        ("Adjacent", "Adjacent::N.0: NonZeroU64"),
        ("Gated", "Gated::N.0: i64"),
        ("Inside", "Inside::N.0: usize"),
    ]
    .into_iter()
    .map(|(name, number)| (name.to_owned(), number.to_owned()))
    .collect();
    assert_eq!(found, expected);
}
