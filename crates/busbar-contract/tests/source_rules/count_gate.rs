// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CREDENTIAL CUSTODY IS NEVER ADMITTED BY A NODE-WIDE COUNT ALONE (streams-mint, lint rule 1).
//! A refusal decided by the size of a shared collection whose entries carry a principal lets one
//! principal fill it and lock every other principal out. Only a per-principal count, in the same
//! function, protects the others.
//!
//! - The receiver `R` is shared: bound from `.lock()`, `.write()` or `.borrow_mut()`, or `self`
//!   in an `impl T` whose `T` sits in a `Mutex`, `RwLock` or `RefCell` field.
//! - Its element type holds a `VirtualKey` (bare, or in `Arc`, `Box` or `Option`) as a field,
//!   directly or through one owned or `Arc` workspace struct field (depth ≤ 2).
//! - The gate is any comparison between a cap and a value derived from `R.len()` or
//!   `R.is_empty()` (through `let` bindings and `+`/`-`), guarding a refusal (`return`, `break`,
//!   `continue`, a tail `Err`, `None` or `false`) or an insert into a collection.
//! - It passes when the same function also compares a per-principal count: the `.len()` of a
//!   lookup into a map keyed by a key id.
//!
//! No exception list. Plugins hold no principal custody, so the rule reads core only.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;

use crate::walk::{self, Source};

/// Every core crate's production source root.
pub fn core_roots() -> Vec<String> {
    let crates = walk::repo().join("crates");
    let mut roots: Vec<String> = std::fs::read_dir(&crates)
        .expect("the crates directory")
        .flatten()
        .filter(|e| e.path().join("src").is_dir())
        .map(|e| format!("crates/{}/src", e.file_name().to_string_lossy()))
        .filter(|rel| !walk::is_plugin_crate(rel))
        .collect();
    roots.sort();
    roots
}

const WRAPPERS: &[&str] = &["Arc", "Rc", "Box", "Option"];
const LOCKS: &[&str] = &["Mutex", "RwLock", "RefCell"];
const SHARED_GUARDS: &[&str] = &["lock", "write", "borrow_mut"];
const SEQUENCES: &[&str] = &[
    "Vec",
    "VecDeque",
    "HashSet",
    "BTreeSet",
    "BinaryHeap",
    "IndexSet",
];
const MAPS: &[&str] = &["HashMap", "BTreeMap", "IndexMap"];
const KEY_IDS: &[&str] = &["String", "str", "KeyId", "PrincipalId"];
const INSERTS: &[&str] = &[
    "insert",
    "push",
    "push_back",
    "push_front",
    "entry",
    "extend",
    "get_or_insert_with",
];

/// The last path segment of `ty` (through references and parentheses) and its type arguments.
fn segment(ty: &syn::Type) -> Option<(String, Vec<&syn::Type>)> {
    match ty {
        syn::Type::Reference(r) => segment(&r.elem),
        syn::Type::Paren(p) => segment(&p.elem),
        syn::Type::Group(g) => segment(&g.elem),
        syn::Type::Path(p) => {
            let last = p.path.segments.last()?;
            let args = match &last.arguments {
                syn::PathArguments::AngleBracketed(a) => a
                    .args
                    .iter()
                    .filter_map(|a| match a {
                        syn::GenericArgument::Type(t) => Some(t),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            Some((last.ident.to_string(), args))
        }
        _ => None,
    }
}

/// `ty` with its `Arc`/`Rc`/`Box`/`Option` wrappers and references taken off.
fn strip(ty: &syn::Type) -> &syn::Type {
    match ty {
        syn::Type::Reference(r) => strip(&r.elem),
        syn::Type::Paren(p) => strip(&p.elem),
        syn::Type::Group(g) => strip(&g.elem),
        _ => match segment(ty) {
            Some((name, args)) if WRAPPERS.contains(&name.as_str()) && args.len() == 1 => {
                strip(args[0])
            }
            _ => ty,
        },
    }
}

fn name_of(ty: &syn::Type) -> Option<String> {
    segment(strip(ty)).map(|(n, _)| n)
}

/// The type a `Mutex`/`RwLock`/`RefCell` holds.
fn locked(ty: &syn::Type) -> Option<&syn::Type> {
    match segment(strip(ty)) {
        Some((name, args)) if LOCKS.contains(&name.as_str()) && args.len() == 1 => Some(args[0]),
        _ => None,
    }
}

/// A collection's element type: a sequence's item, a map's value.
fn element(ty: &syn::Type) -> Option<&syn::Type> {
    let (name, args) = segment(strip(ty))?;
    if SEQUENCES.contains(&name.as_str()) && args.len() == 1 {
        Some(args[0])
    } else if MAPS.contains(&name.as_str()) && args.len() >= 2 {
        Some(args[1])
    } else {
        None
    }
}

/// Whether `ty` is a map keyed by a key id.
fn keyed_by_key_id(ty: &syn::Type) -> bool {
    match segment(strip(ty)) {
        Some((name, args)) if MAPS.contains(&name.as_str()) && args.len() >= 2 => {
            name_of(args[0]).is_some_and(|k| KEY_IDS.contains(&k.as_str()))
        }
        _ => false,
    }
}

/// The workspace's structs (by name, every same-named one) and the struct names a lock holds.
#[derive(Default)]
pub struct Graph {
    structs: BTreeMap<String, Vec<Vec<(String, syn::Type)>>>,
    locked: BTreeSet<String>,
}

impl Graph {
    pub fn of(sources: &[Source]) -> Self {
        let mut graph = Self::default();
        for src in sources {
            for item in walk::items(&src.file.items) {
                let syn::Item::Struct(s) = item else { continue };
                let fields: Vec<(String, syn::Type)> = s
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        (
                            f.ident
                                .as_ref()
                                .map_or_else(|| i.to_string(), ToString::to_string),
                            f.ty.clone(),
                        )
                    })
                    .collect();
                for (_, ty) in &fields {
                    if let Some(name) = locked(ty).and_then(name_of) {
                        graph.locked.insert(name);
                    }
                }
                graph
                    .structs
                    .entry(s.ident.to_string())
                    .or_default()
                    .push(fields);
            }
        }
        graph
    }

    fn field(&self, owner: &syn::Type, member: &str) -> Option<&syn::Type> {
        let name = name_of(owner)?;
        self.structs
            .get(&name)?
            .iter()
            .flatten()
            .find(|(f, _)| f == member)
            .map(|(_, ty)| ty)
    }

    /// Whether `ty` holds a `VirtualKey`, itself or as a field at most two structs deep.
    fn carries_key(&self, ty: &syn::Type, depth: usize) -> bool {
        let ty = strip(ty);
        if let syn::Type::Tuple(t) = ty {
            return t.elems.iter().any(|e| self.carries_key(e, depth));
        }
        let Some(name) = name_of(ty) else {
            return false;
        };
        if name == "VirtualKey" {
            return true;
        }
        depth < 2
            && self.structs.get(&name).is_some_and(|all| {
                all.iter()
                    .flatten()
                    .any(|(_, f)| self.carries_key(f, depth + 1))
            })
    }
}

/// What a receiver resolved to: its type, and whether it is shared state.
struct Resolved {
    ty: syn::Type,
    shared: bool,
}

/// One function's bindings, as the rule follows them.
struct Body<'a> {
    graph: &'a Graph,
    self_ty: Option<syn::Type>,
    lets: BTreeMap<String, syn::Expr>,
    typed: BTreeMap<String, syn::Type>,
}

fn ident_of(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => {
            Some(p.path.segments[0].ident.to_string())
        }
        _ => None,
    }
}

impl Body<'_> {
    fn resolve(&self, e: &syn::Expr, depth: usize) -> Option<Resolved> {
        if depth > 16 {
            return None;
        }
        match e {
            syn::Expr::Paren(p) => self.resolve(&p.expr, depth + 1),
            syn::Expr::Group(g) => self.resolve(&g.expr, depth + 1),
            syn::Expr::Reference(r) => self.resolve(&r.expr, depth + 1),
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                self.resolve(&u.expr, depth + 1)
            }
            syn::Expr::Path(_) => {
                let name = ident_of(e)?;
                if name == "self" {
                    let ty = self.self_ty.clone()?;
                    let shared = name_of(&ty).is_some_and(|n| self.graph.locked.contains(&n));
                    return Some(Resolved { ty, shared });
                }
                if let Some(ty) = self.typed.get(&name) {
                    return Some(Resolved {
                        ty: ty.clone(),
                        shared: false,
                    });
                }
                self.resolve(self.lets.get(&name)?, depth + 1)
            }
            syn::Expr::Field(f) => {
                let syn::Member::Named(member) = &f.member else {
                    return None;
                };
                let base = self.resolve(&f.base, depth + 1)?;
                let ty = self.graph.field(&base.ty, &member.to_string())?.clone();
                Some(Resolved {
                    ty,
                    shared: base.shared,
                })
            }
            syn::Expr::MethodCall(m) => {
                let method = m.method.to_string();
                if SHARED_GUARDS.contains(&method.as_str()) {
                    let base = self.resolve(&m.receiver, depth + 1)?;
                    return Some(Resolved {
                        ty: locked(&base.ty)?.clone(),
                        shared: true,
                    });
                }
                if matches!(
                    method.as_str(),
                    "unwrap" | "expect" | "unwrap_or_else" | "unwrap_or_default"
                ) {
                    return self.resolve(&m.receiver, depth + 1);
                }
                None
            }
            _ => None,
        }
    }

    /// The receiver `R` whose `R.len()`/`R.is_empty()` the value `e` is derived from.
    fn count_receiver<'e>(&'e self, e: &'e syn::Expr, depth: usize) -> Option<&'e syn::Expr> {
        if depth > 16 {
            return None;
        }
        match e {
            syn::Expr::Paren(p) => self.count_receiver(&p.expr, depth + 1),
            syn::Expr::Group(g) => self.count_receiver(&g.expr, depth + 1),
            syn::Expr::Cast(c) => self.count_receiver(&c.expr, depth + 1),
            syn::Expr::Binary(b) if matches!(b.op, syn::BinOp::Add(_) | syn::BinOp::Sub(_)) => self
                .count_receiver(&b.left, depth + 1)
                .or_else(|| self.count_receiver(&b.right, depth + 1)),
            syn::Expr::MethodCall(m)
                if m.args.is_empty()
                    && matches!(m.method.to_string().as_str(), "len" | "is_empty") =>
            {
                Some(&m.receiver)
            }
            syn::Expr::MethodCall(m)
                if matches!(
                    m.method.to_string().as_str(),
                    "saturating_add" | "saturating_sub" | "checked_add" | "checked_sub"
                ) =>
            {
                self.count_receiver(&m.receiver, depth + 1)
            }
            syn::Expr::Path(_) => {
                let name = ident_of(e)?;
                self.count_receiver(self.lets.get(&name)?, depth + 1)
            }
            _ => None,
        }
    }

    /// Whether `e` is a gate operand: a count of shared custody whose entries carry a principal.
    fn custody_count(&self, e: &syn::Expr) -> bool {
        let Some(receiver) = self.count_receiver(e, 0) else {
            return false;
        };
        let Some(resolved) = self.resolve(receiver, 0) else {
            return false;
        };
        resolved.shared && element(&resolved.ty).is_some_and(|el| self.graph.carries_key(el, 0))
    }

    /// Whether `e` is a lookup into a map keyed by a key id (or bound from one).
    fn key_lookup(&self, e: &syn::Expr, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        match e {
            syn::Expr::Paren(p) => self.key_lookup(&p.expr, depth + 1),
            syn::Expr::Reference(r) => self.key_lookup(&r.expr, depth + 1),
            syn::Expr::MethodCall(m) => {
                let method = m.method.to_string();
                if matches!(method.as_str(), "get" | "get_mut") {
                    if let Some(r) = self.resolve(&m.receiver, 0) {
                        if keyed_by_key_id(&r.ty) {
                            return true;
                        }
                    }
                }
                self.key_lookup(&m.receiver, depth + 1)
            }
            syn::Expr::Path(_) => ident_of(e)
                .and_then(|n| self.lets.get(&n))
                .is_some_and(|init| self.key_lookup(init, depth + 1)),
            _ => false,
        }
    }

    /// Whether `e` is a per-principal count: the `.len()` of a key-id lookup.
    fn principal_count(&self, e: &syn::Expr, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        match e {
            syn::Expr::Paren(p) => self.principal_count(&p.expr, depth + 1),
            syn::Expr::Cast(c) => self.principal_count(&c.expr, depth + 1),
            syn::Expr::MethodCall(m) => {
                let method = m.method.to_string();
                let counts = method == "len"
                    || (matches!(
                        method.as_str(),
                        "map_or" | "map_or_else" | "map" | "and_then"
                    ) && m
                        .args
                        .iter()
                        .any(|a| walk::idents(&walk::tokens(a)).iter().any(|i| i == "len")));
                (counts && self.key_lookup(&m.receiver, 0))
                    || self.principal_count(&m.receiver, depth + 1)
            }
            syn::Expr::Path(_) => ident_of(e)
                .and_then(|n| self.lets.get(&n))
                .is_some_and(|init| self.principal_count(init, depth + 1)),
            _ => false,
        }
    }
}

fn is_comparison(op: &syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::Lt(_)
            | syn::BinOp::Le(_)
            | syn::BinOp::Gt(_)
            | syn::BinOp::Ge(_)
            | syn::BinOp::Eq(_)
            | syn::BinOp::Ne(_)
    )
}

/// The comparisons a condition is built of, through `&&`, `||`, `!` and parentheses.
fn comparisons<'e>(cond: &'e syn::Expr, out: &mut Vec<&'e syn::ExprBinary>) {
    match cond {
        syn::Expr::Paren(p) => comparisons(&p.expr, out),
        syn::Expr::Group(g) => comparisons(&g.expr, out),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => comparisons(&u.expr, out),
        syn::Expr::Binary(b) if matches!(b.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
            comparisons(&b.left, out);
            comparisons(&b.right, out);
        }
        syn::Expr::Binary(b) if is_comparison(&b.op) => out.push(b),
        _ => {}
    }
}

/// Whether a branch refuses (`return`, `break`, `continue`, a tail `Err`/`None`/`false`) or
/// inserts.
fn refuses_or_inserts(block: &syn::Block) -> bool {
    struct Finds(bool);
    impl<'ast> Visit<'ast> for Finds {
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.0 = true;
        }
        fn visit_expr_break(&mut self, _: &'ast syn::ExprBreak) {
            self.0 = true;
        }
        fn visit_expr_continue(&mut self, _: &'ast syn::ExprContinue) {
            self.0 = true;
        }
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if INSERTS.contains(&m.method.to_string().as_str()) {
                self.0 = true;
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut finds = Finds(false);
    finds.visit_block(block);
    if finds.0 {
        return true;
    }
    match block.stmts.last() {
        Some(syn::Stmt::Expr(tail, None)) => match tail {
            syn::Expr::Call(c) => matches!(&*c.func, syn::Expr::Path(p)
                if p.path.segments.last().is_some_and(|s| s.ident == "Err")),
            syn::Expr::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "None"),
            syn::Expr::Lit(l) => matches!(&l.lit, syn::Lit::Bool(b) if !b.value),
            _ => false,
        },
        _ => false,
    }
}

/// Gather a function's `let` bindings and typed parameters.
fn bindings(
    f: &mut Body<'_>,
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
    block: &syn::Block,
) {
    struct Lets<'f, 'g>(&'f mut Body<'g>);
    impl<'ast> Visit<'ast> for Lets<'_, '_> {
        fn visit_local(&mut self, l: &'ast syn::Local) {
            let (pat, ty) = match &l.pat {
                syn::Pat::Type(t) => (&*t.pat, Some(&*t.ty)),
                other => (other, None),
            };
            if let syn::Pat::Ident(i) = pat {
                let name = i.ident.to_string();
                if let Some(ty) = ty {
                    self.0.typed.insert(name.clone(), ty.clone());
                }
                if let Some(init) = &l.init {
                    self.0.lets.insert(name, (*init.expr).clone());
                }
            }
            syn::visit::visit_local(self, l);
        }
    }
    for input in inputs {
        if let syn::FnArg::Typed(t) = input {
            if let syn::Pat::Ident(i) = &*t.pat {
                f.typed.insert(i.ident.to_string(), (*t.ty).clone());
            }
        }
    }
    Lets(f).visit_block(block);
}

/// One function's gates and whether it also gates per principal.
fn judge(f: &Body<'_>, block: &syn::Block) -> (Vec<usize>, bool) {
    struct Ifs<'f, 'g> {
        f: &'f Body<'g>,
        gates: Vec<usize>,
        per_principal: bool,
    }
    impl<'ast> Visit<'ast> for Ifs<'_, '_> {
        fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
            if is_comparison(&b.op)
                && (self.f.principal_count(&b.left, 0) || self.f.principal_count(&b.right, 0))
            {
                self.per_principal = true;
            }
            syn::visit::visit_expr_binary(self, b);
        }
        fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
            let mut found = Vec::new();
            comparisons(&i.cond, &mut found);
            let gated = found
                .iter()
                .any(|b| self.f.custody_count(&b.left) || self.f.custody_count(&b.right));
            let guards = refuses_or_inserts(&i.then_branch)
                || matches!(&i.else_branch, Some((_, e)) if matches!(&**e, syn::Expr::Block(b) if refuses_or_inserts(&b.block)));
            if gated && guards {
                self.gates.push(walk::line_of(&i.if_token));
            }
            syn::visit::visit_expr_if(self, i);
        }
    }
    let mut ifs = Ifs {
        f,
        gates: Vec::new(),
        per_principal: false,
    };
    ifs.visit_block(block);
    (ifs.gates, ifs.per_principal)
}

/// Every node-wide custody count gate not paired with a per-principal count, as `file:line fn`.
pub fn hits(sources: &[Source]) -> Vec<String> {
    let graph = Graph::of(sources);
    let mut out = Vec::new();
    for src in sources {
        for item in walk::items(&src.file.items) {
            let mut fns: Vec<(Option<syn::Type>, &syn::Signature, &syn::Block)> = Vec::new();
            match item {
                syn::Item::Fn(f) => fns.push((None, &f.sig, &f.block)),
                syn::Item::Impl(i) if !walk::is_cfg_test(&i.attrs) => {
                    for it in &i.items {
                        if let syn::ImplItem::Fn(m) = it {
                            if !walk::is_cfg_test(&m.attrs) {
                                fns.push((Some((*i.self_ty).clone()), &m.sig, &m.block));
                            }
                        }
                    }
                }
                _ => {}
            }
            for (self_ty, sig, block) in fns {
                let mut f = Body {
                    graph: &graph,
                    self_ty,
                    lets: BTreeMap::new(),
                    typed: BTreeMap::new(),
                };
                bindings(&mut f, &sig.inputs, block);
                let (gates, per_principal) = judge(&f, block);
                if !per_principal {
                    for line in gates {
                        out.push(format!("{}:{line} {}", src.rel, sig.ident));
                    }
                }
            }
        }
    }
    out
}

#[test]
fn no_credential_custody_is_admitted_by_a_node_wide_count_alone() {
    let roots = core_roots();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let hits = hits(&walk::production(&roots));
    assert!(
        hits.is_empty(),
        "a shared collection whose entries carry a principal is gated by its size alone, so one \
         principal can fill it for all; gate on a per-principal count too:\n{}",
        hits.join("\n")
    );
}

fn planted(text: &str) -> Vec<Source> {
    vec![Source {
        rel: "planted.rs".into(),
        file: syn::parse_file(text).expect("the planted source parses"),
    }]
}

const PLANTED_TYPES: &str = r"
struct VirtualKey { id: String }
struct Source { key: Arc<VirtualKey> }
struct Entry { source: Arc<Source>, expires_at: u64 }
struct Entries {
    tickets: BTreeMap<String, Entry>,
    by_key: HashMap<Box<str>, BTreeSet<(u64, Box<str>)>>,
}
struct Custody {
    sources: Mutex<HashMap<u64, Arc<Source>>>,
    entries: Mutex<Entries>,
    plain: Mutex<Vec<u64>>,
}
";

#[test]
fn the_rule_reads_a_node_wide_count_gate_and_passes_a_per_principal_one() {
    let refused = planted(&format!(
        "{PLANTED_TYPES}
        impl Custody {{
            fn bind(&self, id: String, entry: Entry) -> Result<(), ()> {{
                let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
                if closed || entries.tickets.len() >= CAP {{
                    return Err(());
                }}
                entries.tickets.insert(id, entry);
                Ok(())
            }}
            fn register(&self, unit: u64, source: Arc<Source>) -> Option<()> {{
                let mut sources = self.sources.lock().unwrap();
                let held = sources.len() + 1;
                if CAP < held {{ None }} else {{ sources.insert(unit, source); Some(()) }}
            }}
            fn queue(&self, n: u64) -> bool {{
                let mut plain = self.plain.lock().unwrap();
                if plain.len() >= CAP {{ return false; }}
                plain.push(n);
                true
            }}
        }}"
    ));
    let hits = hits(&refused);
    assert_eq!(
        hits.len(),
        2,
        "both custody gates, not the plain queue: {hits:?}"
    );
    assert!(
        hits[0].ends_with(" bind") && hits[1].ends_with(" register"),
        "{hits:?}"
    );

    let passed = planted(&format!(
        "{PLANTED_TYPES}
        impl Entries {{
            fn admits(&self, key_id: &str, per_key: usize) -> Result<(), ()> {{
                let held = self.by_key.get(key_id);
                if held.map_or(0, BTreeSet::len) >= per_key {{
                    return Err(());
                }}
                if self.tickets.len() >= CAP {{
                    return Err(());
                }}
                Ok(())
            }}
            fn unguarded(&self) -> Result<(), ()> {{
                if self.tickets.len() >= CAP {{
                    return Err(());
                }}
                Ok(())
            }}
        }}"
    ));
    let hits = hits(&passed);
    assert!(
        hits.len() == 1 && hits[0].ends_with(" unguarded"),
        "`self` in a locked type is shared; a per-principal count passes its function only: \
         {hits:?}"
    );
}
