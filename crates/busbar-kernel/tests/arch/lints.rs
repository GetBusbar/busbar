// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A3, A4 and A9, THE SHAPE LINTS (CORE-ARCHITECTURE-DIET §3.1 and §5, W0).
//!
//! A3: no production trait has exactly one production impl in the workspace, outside the frozen
//! list in `arch/lints.json` (each entry is a seam W3.11 or a fold turns into a concrete type).
//! Traits under `busbar-contract/src/abi/` are the plugin ABI (A6 governs them), and traits whose
//! impls a macro writes are listed apart, because the parser cannot see inside the macro.
//! A4: `OnceLock`/`OnceCell` of `Arc`/`Box`/`Weak<dyn ..>`, `attach_*` setters (a method named
//! `attach_*` taking `&self`) and `static` `AtomicPtr` slots never grow past the frozen per-file
//! counts, each naming the MR that removes it. A9: `Pass` and `Grant` are built by struct
//! expression only at the frozen mint sites; nothing derives or implements `Clone`, `Copy` or
//! `Default` for them, and no `transmute`, `zeroed`, `MaybeUninit` or pointer cast names them.
//! A1 (hot-path purity) has no scope until W3.6/W6 create its modules; see `a1_hot_path`.
//!
//! Every list only shrinks: against the merge base no entry may be added or raised (an `admitted`
//! owner ruling covers a one-impl entry for the one merge that carries it), and an
//! entry the code no longer needs fails until it is lowered or removed. Production code only:
//! test targets and test-only regions (`cfg(test)` or the `test-support` feature) are skipped. The check parses sources; it never builds.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use serde::Deserialize;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{GenericArgument, PathArguments, Token, Type};

use super::scan::{self, Parsed};

const LINTS: &str = "crates/busbar-kernel/tests/arch/lints.json";
/// The plugin ABI: frozen, governed by A6, and implemented outside the workspace.
const ABI: &str = "crates/busbar-contract/src/abi/";
const CAPABILITIES: [&str; 2] = ["Pass", "Grant"];
const LATE_SLOTS: [&str; 2] = ["OnceLock", "OnceCell"];
const LATE_POINTERS: [&str; 3] = ["Arc", "Box", "Weak"];
const FORGERS: [&str; 4] = ["transmute", "transmute_copy", "zeroed", "uninitialized"];
const COPY_TRAITS: [&str; 3] = ["Clone", "Copy", "Default"];

#[derive(Deserialize)]
struct Lints {
    version: u32,
    a3_one_impl: OneImpl,
    /// File → its late-binding counts and the MR that removes them.
    a4_late_binding: BTreeMap<String, Late>,
    a9_capability: Minting,
    /// "<file> <trait>" → the owner ruling that admits a one-impl entry for one merge. Valid only
    /// while the merge base lacks the entry; once the entry is in the base the admission must go.
    #[serde(default)]
    admitted: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct OneImpl {
    /// Defining file → traits with exactly one production impl.
    traits: BTreeMap<String, BTreeSet<String>>,
    /// Defining file → traits a macro implements (the impl count cannot be read).
    macro_implemented: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Deserialize, Default, Clone, PartialEq, Eq)]
struct Late {
    #[serde(default)]
    once_dyn: usize,
    #[serde(default)]
    attach: usize,
    #[serde(default)]
    atomic_ptr: usize,
    #[serde(default)]
    by: String,
}

impl Late {
    fn total(&self) -> usize {
        self.once_dyn + self.attach + self.atomic_ptr
    }
    fn above(&self, other: &Late) -> bool {
        self.once_dyn > other.once_dyn
            || self.attach > other.attach
            || self.atomic_ptr > other.atomic_ptr
    }
}

#[derive(Deserialize)]
struct Minting {
    /// File → why it may build `Pass`/`Grant` by struct expression.
    mint_sites: BTreeMap<String, String>,
    /// File → the unrelated type it defines under a capability's name.
    homonyms: BTreeMap<String, String>,
}

/// What one production file holds.
#[derive(Default)]
struct Facts {
    traits: Vec<String>,
    impls: Vec<(String, usize)>,
    macro_impls: BTreeSet<String>,
    late: Late,
    capability_defs: Vec<(String, usize)>,
    mints: Vec<usize>,
    forgeries: Vec<(usize, String)>,
}

/// How a path is read as a capability in one file.
struct Names {
    /// `use .. caps::Grant as G` binds `G` to a capability.
    aliases: BTreeSet<String>,
    /// Bare names bound to an unrelated type (a homonym defined here or imported).
    bare_homonyms: BTreeSet<String>,
    /// Module names of the homonym files (`hook_child`): a path through one is not a capability.
    homonym_modules: BTreeSet<String>,
}

impl Names {
    fn path(&self, path: &syn::Path) -> bool {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let Some(last) = segments.last() else {
            return false;
        };
        if !CAPABILITIES.contains(&last.as_str()) && !self.aliases.contains(last) {
            return false;
        }
        if segments.len() == 1 {
            return !self.bare_homonyms.contains(last);
        }
        // `Phase::Grant(..)` is an enum variant: a capability lives in a module, not a type.
        let parent = &segments[segments.len() - 2];
        if parent.starts_with(|c: char| c.is_ascii_uppercase()) {
            return false;
        }
        !segments
            .iter()
            .any(|segment| self.homonym_modules.contains(segment))
    }

    fn ty(&self, ty: &Type) -> bool {
        let mut finder = TypeNames {
            names: self,
            found: false,
        };
        finder.visit_type(ty);
        finder.found
    }

    fn arguments(&self, arguments: &PathArguments) -> bool {
        match arguments {
            PathArguments::AngleBracketed(angle) => angle
                .args
                .iter()
                .any(|argument| matches!(argument, GenericArgument::Type(ty) if self.ty(ty))),
            _ => false,
        }
    }
}

struct TypeNames<'a> {
    names: &'a Names,
    found: bool,
}

impl<'ast> Visit<'ast> for TypeNames<'_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if self.names.path(path) {
            self.found = true;
        }
        visit::visit_path(self, path);
    }
}

/// Collects the file's `use` bindings of the capability names.
struct Uses<'a> {
    file: &'a Parsed,
    homonym_modules: &'a BTreeSet<String>,
    aliases: BTreeSet<String>,
    bare_homonyms: BTreeSet<String>,
}

impl Uses<'_> {
    fn tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.tree(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let ident = name.ident.to_string();
                self.bind(prefix, &ident, &ident);
            }
            syn::UseTree::Rename(rename) => {
                self.bind(
                    prefix,
                    &rename.ident.to_string(),
                    &rename.rename.to_string(),
                );
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.tree(item, prefix);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    fn bind(&mut self, prefix: &[String], original: &str, binding: &str) {
        let through_homonym = prefix
            .iter()
            .any(|segment| self.homonym_modules.contains(segment));
        if CAPABILITIES.contains(&original) && !through_homonym {
            if original != binding {
                self.aliases.insert(binding.to_string());
            }
        } else if CAPABILITIES.contains(&binding) {
            self.bare_homonyms.insert(binding.to_string());
        }
    }
}

impl<'ast> Visit<'ast> for Uses<'_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !self.file.excluded(node.use_token.span.start().line) {
            self.tree(&node.tree, &mut Vec::new());
        }
    }
}

struct Lint<'a> {
    file: &'a Parsed,
    names: &'a Names,
    /// The file defines an unrelated type under a capability's name.
    homonym: bool,
    facts: Facts,
    /// Inside `impl .. for Pass<..>`/`Grant<..>`, where `Self { .. }` builds one.
    in_capability_impl: bool,
    /// Whether the innermost typed `let` or fn return names a capability.
    typed: Vec<bool>,
}

impl Lint<'_> {
    fn live(&self, line: usize) -> bool {
        !self.file.excluded(line)
    }

    fn forged(&mut self, line: usize, what: &str) {
        if self.live(line) {
            self.facts.forgeries.push((line, what.to_string()));
        }
    }

    fn definition(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute]) {
        let name = ident.to_string();
        let line = ident.span().start().line;
        if !CAPABILITIES.contains(&name.as_str()) || !self.live(line) {
            return;
        }
        self.facts.capability_defs.push((name.clone(), line));
        if self.homonym {
            return;
        }
        for attr in attrs.iter().filter(|attr| attr.path().is_ident("derive")) {
            let Ok(derived) =
                attr.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
            else {
                continue;
            };
            for path in derived {
                let Some(last) = path.segments.last() else {
                    continue;
                };
                let derive = last.ident.to_string();
                if COPY_TRAITS.contains(&derive.as_str()) {
                    self.forged(line, &format!("derive({derive}) on {name}"));
                }
            }
        }
    }

    fn method(&mut self, sig: &syn::Signature) {
        let name = sig.ident.to_string();
        if !name.starts_with("attach_") || !self.live(sig.ident.span().start().line) {
            return;
        }
        let shared = sig.receiver().is_some_and(|receiver| {
            if receiver.colon_token.is_some() {
                !matches!(&*receiver.ty, Type::Reference(reference) if reference.mutability.is_some())
            } else {
                receiver.reference.is_some() && receiver.mutability.is_none()
            }
        });
        if shared {
            self.facts.late.attach += 1;
        }
    }

    fn returns(&self, output: &syn::ReturnType) -> bool {
        match output {
            syn::ReturnType::Type(_, ty) => self.names.ty(ty),
            syn::ReturnType::Default => false,
        }
    }
}

impl<'ast> Visit<'ast> for Lint<'_> {
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if self.live(node.ident.span().start().line) {
            self.facts.traits.push(node.ident.to_string());
        }
        visit::visit_item_trait(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let line = node.impl_token.span.start().line;
        let capability = match &*node.self_ty {
            Type::Path(path) => path.qself.is_none() && self.names.path(&path.path),
            _ => false,
        };
        if let Some((negative, path, _)) = &node.trait_ {
            if let Some(last) = path.segments.last() {
                let name = last.ident.to_string();
                if negative.is_none() && self.live(line) {
                    self.facts.impls.push((name.clone(), line));
                }
                if capability && COPY_TRAITS.contains(&name.as_str()) {
                    self.forged(line, &format!("impl {name} for a capability"));
                }
            }
        }
        let outer = std::mem::replace(&mut self.in_capability_impl, capability);
        visit::visit_item_impl(self, node);
        self.in_capability_impl = outer;
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.definition(&node.ident, &node.attrs);
        visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.definition(&node.ident, &node.attrs);
        visit::visit_item_enum(self, node);
    }

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        self.definition(&node.ident, &node.attrs);
        visit::visit_item_union(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        self.definition(&node.ident, &[]);
        visit::visit_item_type(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        let mut finder = Named {
            name: "AtomicPtr",
            found: false,
        };
        finder.visit_type(&node.ty);
        if finder.found && self.live(node.static_token.span.start().line) {
            self.facts.late.atomic_ptr += 1;
        }
        visit::visit_item_static(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let typed = self.returns(&node.sig.output);
        self.typed.push(typed);
        visit::visit_item_fn(self, node);
        self.typed.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.method(&node.sig);
        let typed = self.returns(&node.sig.output);
        self.typed.push(typed);
        visit::visit_impl_item_fn(self, node);
        self.typed.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.method(&node.sig);
        let typed = self.returns(&node.sig.output);
        self.typed.push(typed);
        visit::visit_trait_item_fn(self, node);
        self.typed.pop();
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Type(pat) = &node.pat {
            let typed = self.names.ty(&pat.ty);
            self.typed.push(typed);
            visit::visit_local(self, node);
            self.typed.pop();
        } else {
            visit::visit_local(self, node);
        }
    }

    fn visit_path_segment(&mut self, node: &'ast syn::PathSegment) {
        let ident = node.ident.to_string();
        let line = node.ident.span().start().line;
        if LATE_SLOTS.contains(&ident.as_str()) && late_dyn(&node.arguments) && self.live(line) {
            self.facts.late.once_dyn += 1;
        }
        if ident == "MaybeUninit" && self.names.arguments(&node.arguments) {
            self.forged(line, "MaybeUninit of a capability");
        }
        visit::visit_path_segment(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        let line = node.path.span().start().line;
        let own = node.path.is_ident("Self") && self.in_capability_impl;
        if node.qself.is_none() && (own || self.names.path(&node.path)) && self.live(line) {
            self.facts.mints.push(line);
        }
        visit::visit_expr_struct(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = &*node.func {
            let line = func.path.span().start().line;
            let own = func.path.is_ident("Self") && self.in_capability_impl;
            if func.qself.is_none() && (own || self.names.path(&func.path)) && self.live(line) {
                self.facts.mints.push(line);
            }
            if let Some(last) = func.path.segments.last() {
                let name = last.ident.to_string();
                if FORGERS.contains(&name.as_str())
                    && (self.names.arguments(&last.arguments)
                        || self.typed.last().copied().unwrap_or(false))
                {
                    self.forged(line, &format!("{name} of a capability"));
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
        if matches!(&*node.ty, Type::Ptr(_)) && self.names.ty(&node.ty) {
            self.forged(
                node.as_token.span.start().line,
                "pointer cast to a capability",
            );
        }
        visit::visit_expr_cast(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "cast" {
            if let Some(turbofish) = &node.turbofish {
                let names = turbofish.args.iter().any(
                    |argument| matches!(argument, GenericArgument::Type(ty) if self.names.ty(ty)),
                );
                if names {
                    self.forged(
                        node.method.span().start().line,
                        "pointer cast to a capability",
                    );
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.live(node.path.span().start().line) {
            macro_impls(node.tokens.clone(), &mut self.facts.macro_impls);
        }
        visit::visit_macro(self, node);
    }
}

/// Finds a path segment by name anywhere in a type.
struct Named {
    name: &'static str,
    found: bool,
}

impl<'ast> Visit<'ast> for Named {
    fn visit_path_segment(&mut self, node: &'ast syn::PathSegment) {
        if node.ident == self.name {
            self.found = true;
        }
        visit::visit_path_segment(self, node);
    }
}

/// `<Arc<dyn ..>>`, `<Box<dyn ..>>` or `<Weak<dyn ..>>` as the slot's argument.
fn late_dyn(arguments: &PathArguments) -> bool {
    let PathArguments::AngleBracketed(angle) = arguments else {
        return false;
    };
    let Some(GenericArgument::Type(Type::Path(pointer))) = angle.args.first() else {
        return false;
    };
    let Some(last) = pointer.path.segments.last() else {
        return false;
    };
    if !LATE_POINTERS.iter().any(|name| last.ident == *name) {
        return false;
    }
    let PathArguments::AngleBracketed(inner) = &last.arguments else {
        return false;
    };
    inner
        .args
        .iter()
        .any(|argument| matches!(argument, GenericArgument::Type(Type::TraitObject(_))))
}

/// The trait names of `impl .. Trait for ..` written inside a macro body, at any depth.
fn macro_impls(stream: TokenStream, out: &mut BTreeSet<String>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(ident) if ident == "impl" => {
                if let Some(name) = impl_trait_name(&trees[index + 1..]) {
                    out.insert(name);
                }
            }
            TokenTree::Group(group) => macro_impls(group.stream(), out),
            _ => {}
        }
    }
}

fn impl_trait_name(trees: &[TokenTree]) -> Option<String> {
    let punct = |tree: Option<&TokenTree>, c: char| matches!(tree, Some(TokenTree::Punct(punct)) if punct.as_char() == c);
    // `>` closes an angle unless it ends `->`.
    let closes = |index: usize| {
        punct(trees.get(index), '>')
            && !(index > 0
                && matches!(&trees[index - 1], TokenTree::Punct(p) if p.as_char() == '-' && p.spacing() == Spacing::Joint))
    };
    let mut index = 0;
    if punct(trees.first(), '<') {
        let mut depth = 0i32;
        while index < trees.len() {
            if punct(trees.get(index), '<') {
                depth += 1;
            } else if closes(index) {
                depth -= 1;
            }
            index += 1;
            if depth <= 0 {
                break;
            }
        }
    }
    if punct(trees.get(index), '!') {
        return None;
    }
    let mut depth = 0i32;
    let mut name = None;
    let mut stop = false;
    while index < trees.len() {
        let tree = &trees[index];
        if punct(Some(tree), '<') {
            depth += 1;
        } else if closes(index) {
            depth -= 1;
        } else if punct(Some(tree), '$') {
            index += 1;
        } else if depth == 0 {
            match tree {
                TokenTree::Punct(punct) if punct.as_char() == ';' => return None,
                TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => return None,
                TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis => {
                    stop = true;
                }
                TokenTree::Ident(ident) if ident == "where" => return None,
                TokenTree::Ident(ident) if ident == "for" => {
                    let higher_ranked = name.is_none() && punct(trees.get(index + 1), '<');
                    if !higher_ranked {
                        return name;
                    }
                }
                TokenTree::Ident(ident) if !stop && ident != "dyn" && ident != "unsafe" => {
                    name = Some(ident.to_string());
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

fn stem(file: &str) -> String {
    let path = Path::new(file);
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    if stem == "mod" {
        path.parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        stem
    }
}

#[test]
fn single_impl_traits_late_binding_and_capability_minting_stay_frozen() {
    let mut workspace = scan::load();
    let root = workspace.root.clone();
    let text = std::fs::read_to_string(root.join(LINTS)).expect(LINTS);
    let lints: Lints = sonic_rs::from_str(&text).expect(LINTS);
    assert_eq!(lints.version, 1, "{LINTS}: unknown version");
    workspace.walk(&BTreeSet::new());

    let homonym_modules: BTreeSet<String> = lints
        .a9_capability
        .homonyms
        .keys()
        .map(|file| stem(file))
        .collect();
    let mut facts: BTreeMap<String, Facts> = BTreeMap::new();
    for (path, _) in workspace
        .files
        .iter()
        .filter(|(_, reached)| reached.production)
    {
        let relative = workspace.relative(path);
        let source = std::fs::read_to_string(path).expect("read reached file");
        let Ok(syntax) = syn::parse_file(&source) else {
            continue;
        };
        let file = Parsed::new(&source);
        let homonym = lints.a9_capability.homonyms.contains_key(&relative);
        let mut uses = Uses {
            file: &file,
            homonym_modules: &homonym_modules,
            aliases: BTreeSet::new(),
            bare_homonyms: BTreeSet::new(),
        };
        uses.visit_file(&syntax);
        let mut bare_homonyms = uses.bare_homonyms;
        if homonym {
            bare_homonyms.extend(CAPABILITIES.iter().map(|name| name.to_string()));
        }
        let names = Names {
            aliases: uses.aliases,
            bare_homonyms,
            homonym_modules: homonym_modules.clone(),
        };
        let mut lint = Lint {
            file: &file,
            names: &names,
            homonym,
            facts: Facts::default(),
            in_capability_impl: false,
            typed: Vec::new(),
        };
        lint.visit_file(&syntax);
        facts.insert(relative, lint.facts);
    }

    let mut failures = Vec::new();
    let a3 = one_impl(&facts, &lints, &mut failures);
    let late = late_binding(&facts, &lints, &mut failures);
    let mints = minting(&facts, &lints, &mut failures);

    match super::base_revision(&root) {
        None => failures.push("no base revision: the frozen lists need Git history".to_string()),
        Some(base) => {
            if let Some(text) = super::file_at(&root, &base, LINTS) {
                let before: Lints = sonic_rs::from_str(&text).expect("base lints");
                shrink_only(&lints, &before, &mut failures);
            }
        }
    }

    if !failures.is_empty() {
        let (traits, macros) = a3;
        let mut report =
            String::from("measured (paste into the matching sections of lints.json):\n");
        report.push_str("a3_one_impl.traits:\n");
        for (file, names) in &traits {
            report.push_str(&format!("  \"{file}\": {},\n", json_names(names)));
        }
        report.push_str("a3_one_impl.macro_implemented:\n");
        for (file, names) in &macros {
            report.push_str(&format!("  \"{file}\": {},\n", json_names(names)));
        }
        report.push_str("a4_late_binding (once_dyn, attach, atomic_ptr):\n");
        for (file, counts) in &late {
            report.push_str(&format!(
                "  \"{file}\": {{\"once_dyn\": {}, \"attach\": {}, \"atomic_ptr\": {}}},\n",
                counts.once_dyn, counts.attach, counts.atomic_ptr
            ));
        }
        report.push_str("a9_capability struct-expression mints per file:\n");
        for (file, count) in &mints {
            report.push_str(&format!("  {file}: {count}\n"));
        }
        panic!("{report}\n{}", failures.join("\n"));
    }
}

fn json_names(names: &BTreeSet<String>) -> String {
    let quoted: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

type ByFile = BTreeMap<String, BTreeSet<String>>;

/// A3. Returns the measured single-impl and macro-implemented traits per defining file.
fn one_impl(
    facts: &BTreeMap<String, Facts>,
    lints: &Lints,
    failures: &mut Vec<String>,
) -> (ByFile, ByFile) {
    let mut impls: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut macro_impls: BTreeSet<&str> = BTreeSet::new();
    for (file, found) in facts {
        for (name, line) in &found.impls {
            impls
                .entry(name.as_str())
                .or_default()
                .push(format!("{file}:{line}"));
        }
        macro_impls.extend(found.macro_impls.iter().map(String::as_str));
    }
    let mut single = ByFile::new();
    let mut macros = ByFile::new();
    let mut sites: BTreeMap<(String, String), String> = BTreeMap::new();
    for (file, found) in facts.iter().filter(|(file, _)| !file.starts_with(ABI)) {
        for name in &found.traits {
            if macro_impls.contains(name.as_str()) {
                macros.entry(file.clone()).or_default().insert(name.clone());
                continue;
            }
            if let Some([only]) = impls.get(name.as_str()).map(Vec::as_slice) {
                single.entry(file.clone()).or_default().insert(name.clone());
                sites.insert((file.clone(), name.clone()), only.clone());
            }
        }
    }
    let frozen = &lints.a3_one_impl;
    for (file, names) in &single {
        for name in names {
            if !frozen
                .traits
                .get(file)
                .is_some_and(|listed| listed.contains(name))
            {
                failures.push(format!(
                    "one impl: the trait {name} ({file}) has exactly one production impl ({}); \
                     use the concrete type (§3.1: a trait needs two production impls or a real \
                     dynamic boundary; test doubles are no reason)",
                    sites[&(file.clone(), name.clone())]
                ));
            }
        }
    }
    for (file, names) in &frozen.traits {
        for name in names {
            if !single.get(file).is_some_and(|found| found.contains(name)) {
                failures.push(format!(
                    "one impl: {file} {name} is no longer a single-impl production trait there \
                     (deleted, moved or given another impl); remove the entry"
                ));
            }
        }
    }
    for (file, names) in &macros {
        for name in names {
            if !frozen
                .macro_implemented
                .get(file)
                .is_some_and(|listed| listed.contains(name))
            {
                failures.push(format!(
                    "one impl: the trait {name} ({file}) is implemented inside a macro, where its \
                     impls cannot be counted; write the impls out or reuse a listed trait"
                ));
            }
        }
    }
    for (file, names) in &frozen.macro_implemented {
        for name in names {
            if !macros.get(file).is_some_and(|found| found.contains(name)) {
                failures.push(format!(
                    "one impl: {file} {name} is no longer a macro-implemented production trait \
                     there; remove the entry"
                ));
            }
        }
    }
    (single, macros)
}

/// A4. Returns the measured counts per file.
fn late_binding(
    facts: &BTreeMap<String, Facts>,
    lints: &Lints,
    failures: &mut Vec<String>,
) -> BTreeMap<String, Late> {
    let measured: BTreeMap<String, Late> = facts
        .iter()
        .filter(|(_, found)| found.late.total() > 0)
        .map(|(file, found)| (file.clone(), found.late.clone()))
        .collect();
    let none = Late::default();
    for (file, counts) in &measured {
        let frozen = lints.a4_late_binding.get(file).unwrap_or(&none);
        if counts.above(frozen) {
            failures.push(format!(
                "late binding: {file} has {} OnceLock/OnceCell<Arc|Box|Weak<dyn ..>>, {} \
                 `attach_*(&self)` setters and {} static AtomicPtr slots (frozen at {}, {}, {}); \
                 boot builds the owner and passes it by value or as Arc<Concrete> (§3.1)",
                counts.once_dyn,
                counts.attach,
                counts.atomic_ptr,
                frozen.once_dyn,
                frozen.attach,
                frozen.atomic_ptr
            ));
        }
    }
    for (file, frozen) in &lints.a4_late_binding {
        let counts = measured.get(file).unwrap_or(&none);
        if counts.total() == 0 {
            failures.push(format!(
                "late binding: {file} has no late binding left; remove its entry ({})",
                frozen.by
            ));
        } else if frozen.above(counts) {
            failures.push(format!(
                "late binding: {file} is stale; lower the entry to once_dyn {}, attach {}, \
                 atomic_ptr {}",
                counts.once_dyn, counts.attach, counts.atomic_ptr
            ));
        }
        if frozen.by.is_empty() {
            failures.push(format!(
                "late binding: {file} must name the MR that removes it (`by`)"
            ));
        }
    }
    measured
}

/// A9. Returns the struct-expression mints per file.
fn minting(
    facts: &BTreeMap<String, Facts>,
    lints: &Lints,
    failures: &mut Vec<String>,
) -> BTreeMap<String, usize> {
    let frozen = &lints.a9_capability;
    let mut mints = BTreeMap::new();
    for (file, found) in facts {
        if !found.mints.is_empty() {
            mints.insert(file.clone(), found.mints.len());
            if !frozen.mint_sites.contains_key(file) {
                let lines: Vec<String> = found.mints.iter().map(usize::to_string).collect();
                failures.push(format!(
                    "capability minting: {file} builds Pass/Grant by struct expression or \
                     constructor at line(s) {}; only {:?} mints them (unit::teller after W4.3); \
                     take one from the teller instead",
                    lines.join(", "),
                    frozen.mint_sites.keys().collect::<Vec<_>>()
                ));
            }
        }
        for (line, what) in &found.forgeries {
            failures.push(format!(
                "capability minting: {file}:{line}: {what}; a capability is never copied, \
                 defaulted or forged from bytes"
            ));
        }
        for (name, line) in &found.capability_defs {
            if !frozen.mint_sites.contains_key(file) && !frozen.homonyms.contains_key(file) {
                failures.push(format!(
                    "capability minting: {file}:{line} defines a type named {name}; the name is \
                     reserved for the capability token, so rename it"
                ));
            }
        }
    }
    for file in frozen.mint_sites.keys() {
        if !mints.contains_key(file) {
            failures.push(format!(
                "capability minting: the mint site {file} no longer mints; remove the entry"
            ));
        }
    }
    for file in frozen.homonyms.keys() {
        let defines = facts
            .get(file)
            .is_some_and(|found| !found.capability_defs.is_empty());
        if !defines {
            failures.push(format!(
                "capability minting: the homonym {file} no longer defines Pass or Grant; remove \
                 the entry"
            ));
        }
    }
    mints
}

fn added(
    now: &ByFile,
    before: &ByFile,
    admitted: &BTreeMap<String, String>,
    list: &str,
    failures: &mut Vec<String>,
) {
    for (file, names) in now {
        for name in names {
            let ruled = admitted
                .get(&format!("{file} {name}"))
                .is_some_and(|ruling| !ruling.trim().is_empty());
            let moved = before.values().filter(|names| names.contains(name)).count() == 1
                && now.values().filter(|names| names.contains(name)).count() == 1
                && before.iter().any(|(old_file, names)| {
                    names.contains(name)
                        && !now.get(old_file).is_some_and(|names| names.contains(name))
                });
            if !ruled && !moved && !before.get(file).is_some_and(|old| old.contains(name)) {
                failures.push(format!(
                    "one impl: {file} {name} was added to {list}; entries can only be removed"
                ));
            }
        }
    }
}

#[test]
fn one_impl_trait_move_needs_no_admission() {
    let before = BTreeMap::from([("old/ports.rs".into(), BTreeSet::from(["AuthPort".into()]))]);
    let now = BTreeMap::from([("new/auth.rs".into(), BTreeSet::from(["AuthPort".into()]))]);
    let mut failures = Vec::new();
    added(&now, &before, &BTreeMap::new(), "traits", &mut failures);
    assert!(
        failures.is_empty(),
        "a trait move is not a new trait: {failures:?}"
    );
}

#[test]
fn one_impl_retained_trait_does_not_authorize_another_definition() {
    let before = BTreeMap::from([("old/ports.rs".into(), BTreeSet::from(["AuthPort".into()]))]);
    let now = BTreeMap::from([
        ("old/ports.rs".into(), BTreeSet::from(["AuthPort".into()])),
        ("new/auth.rs".into(), BTreeSet::from(["AuthPort".into()])),
    ]);
    let mut failures = Vec::new();
    added(&now, &before, &BTreeMap::new(), "traits", &mut failures);
    assert_eq!(failures.len(), 1);
}

fn shrink_only(now: &Lints, before: &Lints, failures: &mut Vec<String>) {
    for key in now.admitted.keys() {
        let still_new = key.split_once(' ').is_some_and(|(file, name)| {
            [
                (&now.a3_one_impl.traits, &before.a3_one_impl.traits),
                (
                    &now.a3_one_impl.macro_implemented,
                    &before.a3_one_impl.macro_implemented,
                ),
            ]
            .iter()
            .any(|(now, before)| {
                now.get(file).is_some_and(|names| names.contains(name))
                    && !before.get(file).is_some_and(|names| names.contains(name))
            })
        });
        if !still_new {
            failures.push(format!(
                "admitted: {key} is not a one-impl entry new against the merge base; remove its \
                 admission"
            ));
        }
    }
    added(
        &now.a3_one_impl.traits,
        &before.a3_one_impl.traits,
        &now.admitted,
        "a3_one_impl.traits",
        failures,
    );
    added(
        &now.a3_one_impl.macro_implemented,
        &before.a3_one_impl.macro_implemented,
        &now.admitted,
        "a3_one_impl.macro_implemented",
        failures,
    );
    let none = Late::default();
    for (file, counts) in &now.a4_late_binding {
        if counts.above(before.a4_late_binding.get(file).unwrap_or(&none)) {
            failures.push(format!(
                "late binding: the entry for {file} was added or raised; entries can only fall"
            ));
        }
    }
    for file in now.a9_capability.mint_sites.keys() {
        if !before.a9_capability.mint_sites.contains_key(file) {
            failures.push(format!(
                "capability minting: the mint site {file} was added; entries can only be removed \
                 (W4.3 moves the one site to unit::teller in the same MR that edits this list)"
            ));
        }
    }
    for file in now.a9_capability.homonyms.keys() {
        if !before.a9_capability.homonyms.contains_key(file) {
            failures.push(format!(
                "capability minting: the homonym {file} was added; rename the type instead"
            ));
        }
    }
}
