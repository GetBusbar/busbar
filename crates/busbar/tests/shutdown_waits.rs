// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R16 (SHUTDOWN-HANG r13 §7a, test 8.11): every wait on the shutdown path is bounded
//! by the drain owner, nothing on it is cancelled, and nothing on it blocks the control thread.
//!
//! The checker parses `root/shutdown.rs` (every item except its `#[cfg(test)]` modules) and
//! `main.rs` (`run` after the statement that creates `shutdown_tx`, plus a file-wide `.abort()`
//! ban). It is a call-graph rule with no allowlist beyond the two signal waits.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

const DRAIN_METHODS: [&str; 4] = ["bounded", "wait", "wait_requests", "bounded_requests"];
const AWAIT_MACROS: [&str; 4] = ["select", "join", "try_join", "pin"];
const BLOCKING: [&str; 12] = [
    "block_on",
    "blocking_recv",
    "blocking_send",
    "blocking_lock",
    "blocking_read",
    "blocking_write",
    "recv_timeout",
    "wait_timeout",
    "wait_timeout_while",
    "wait_while",
    "park",
    "park_timeout",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Shutdown,
    Main,
}

#[derive(Clone, PartialEq, Eq)]
enum RefCtx {
    DrainArg,
    InHelper(String),
    Other,
}

struct Scan<'a> {
    role: Role,
    file: &'a str,
    helpers: &'a BTreeSet<String>,
    drained: &'a BTreeSet<String>,
    refs: BTreeMap<String, Vec<RefCtx>>,
    found: Vec<String>,
    impl_exempt: bool,
    impl_name: Option<String>,
    signal_wait: bool,
    drain_params: Vec<String>,
    self_is_drain: bool,
    drain_arg: usize,
    blocking_ok: usize,
    helper_body: Option<String>,
    run_tail: bool,
    spawn_arg: usize,
    awaited: usize,
    finish_ok: BTreeSet<usize>,
    finish_seen: bool,
    run_seen: bool,
}

fn line(span: proc_macro2::Span) -> usize {
    span.start().line
}

fn last_ident(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

fn ends_with(path: &syn::Path, tail: &[&str]) -> bool {
    let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    names.len() >= tail.len()
        && names[names.len() - tail.len()..]
            .iter()
            .zip(tail)
            .all(|(a, b)| a == b)
}

fn strip(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Paren(p) => strip(&p.expr),
        syn::Expr::Group(g) => strip(&g.expr),
        other => other,
    }
}

fn type_is_drain(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return false;
            };
            if last.ident == "ShutdownDrain" {
                return true;
            }
            if last.ident == "Arc" {
                if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                    return args.args.iter().any(|a| match a {
                        syn::GenericArgument::Type(t) => type_is_drain(t),
                        _ => false,
                    });
                }
            }
            false
        }
        syn::Type::Reference(r) => type_is_drain(&r.elem),
        syn::Type::Paren(p) => type_is_drain(&p.elem),
        _ => false,
    }
}

fn drain_params(sig: &syn::Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pt) if type_is_drain(&pt.ty) => match &*pt.pat {
                syn::Pat::Ident(id) => Some(id.ident.to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg") && matches!(a.parse_args::<syn::Ident>(), Ok(i) if i == "test")
    })
}

fn pat_binds(pat: &syn::Pat, name: &str) -> bool {
    match pat {
        syn::Pat::Ident(id) => id.ident == name,
        syn::Pat::Tuple(t) => t.elems.iter().any(|p| pat_binds(p, name)),
        syn::Pat::Type(t) => pat_binds(&t.pat, name),
        _ => false,
    }
}

fn is_finish_call(expr: &syn::Expr) -> bool {
    match strip(expr) {
        syn::Expr::Call(c) => match strip(&c.func) {
            syn::Expr::Path(p) => ends_with(&p.path, &["shutdown", "finish"]),
            _ => false,
        },
        _ => false,
    }
}

fn is_exit_stmt(stmt: Option<&syn::Stmt>) -> bool {
    match stmt {
        Some(syn::Stmt::Expr(syn::Expr::Call(c), _)) => match strip(&c.func) {
            syn::Expr::Path(p) => {
                ends_with(&p.path, &["process", "exit"]) || ends_with(&p.path, &["exit", "exit"])
            }
            _ => false,
        },
        _ => false,
    }
}

/// A macro invocation that waits: a listed waiting macro, or any `await` in its tokens.
fn macro_await_site(mac: &syn::Macro) -> bool {
    fn has_await(tokens: &TokenStream) -> bool {
        tokens.clone().into_iter().any(|t| match t {
            TokenTree::Ident(i) => i == "await",
            TokenTree::Group(g) => has_await(&g.stream()),
            _ => false,
        })
    }
    let name = last_ident(&mac.path)
        .unwrap_or_default()
        .to_ascii_lowercase();
    AWAIT_MACROS.contains(&name.as_str()) || has_await(&mac.tokens)
}

fn is_paren(t: Option<&TokenTree>) -> Option<&proc_macro2::Group> {
    match t {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => Some(g),
        _ => None,
    }
}

fn is_punct(t: Option<&TokenTree>, c: char) -> bool {
    matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == c)
}

fn is_ident(t: Option<&TokenTree>, name: &str) -> bool {
    matches!(t, Some(TokenTree::Ident(i)) if i == name)
}

/// Blocking calls and aborts written inside a macro's tokens. At the top level of a
/// `select!`/`join!` an arm future may name `recv`/`wait` calls that produce futures.
fn macro_findings(tokens: &TokenStream, select: bool, join: bool, out: &mut Vec<&'static str>) {
    let trees: Vec<TokenTree> = tokens.clone().into_iter().collect();
    // In a select!, the tokens between an arm's `=` and `=>` are its future.
    let mut in_future = join;
    for (i, t) in trees.iter().enumerate() {
        if select && is_punct(Some(t), '=') {
            let prev = i.checked_sub(1).and_then(|p| trees.get(p));
            let compound = ['=', '!', '<', '>'].iter().any(|c| is_punct(prev, *c));
            if is_punct(trees.get(i + 1), '>') {
                // `=>` ends the arm's future.
                in_future = false;
            } else if !compound && !is_punct(trees.get(i + 1), '=') {
                in_future = true;
            }
        }
        match t {
            TokenTree::Group(g) => macro_findings(&g.stream(), false, false, out),
            TokenTree::Ident(id) => {
                let name = id.to_string();
                let group = is_paren(trees.get(i + 1));
                if name == "abort" && group.is_some() {
                    out.push("an abort() call");
                }
                if let Some(group) = group {
                    if name == "join" {
                        if group.stream().is_empty() {
                            out.push("a blocking join()");
                        }
                    } else if BLOCKING.contains(&name.as_str()) {
                        out.push("a blocking call");
                    } else if name == "sleep"
                        && i >= 3
                        && is_punct(trees.get(i - 1), ':')
                        && is_punct(trees.get(i - 2), ':')
                        && is_ident(trees.get(i - 3), "thread")
                    {
                        out.push("a blocking thread::sleep");
                    } else if name == "recv" || name == "wait" {
                        let awaited =
                            is_punct(trees.get(i + 2), '.') && is_ident(trees.get(i + 3), "await");
                        if !awaited && !in_future {
                            out.push("a blocking recv()/wait()");
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

impl<'a> Scan<'a> {
    fn new(
        role: Role,
        file: &'a str,
        helpers: &'a BTreeSet<String>,
        drained: &'a BTreeSet<String>,
    ) -> Self {
        Self {
            role,
            file,
            helpers,
            drained,
            refs: BTreeMap::new(),
            found: Vec::new(),
            impl_exempt: false,
            impl_name: None,
            signal_wait: false,
            drain_params: Vec::new(),
            self_is_drain: false,
            drain_arg: 0,
            blocking_ok: 0,
            helper_body: None,
            run_tail: false,
            spawn_arg: 0,
            awaited: 0,
            finish_ok: BTreeSet::new(),
            finish_seen: false,
            run_seen: false,
        }
    }

    fn report(&mut self, at: usize, what: impl std::fmt::Display) {
        self.found.push(format!("{}:{at}: {what}", self.file));
    }

    fn checks_blocking(&self) -> bool {
        match self.role {
            Role::Shutdown => self.blocking_ok == 0,
            Role::Main => self.run_tail && self.blocking_ok == 0,
        }
    }

    fn is_drain_call(&self, call: &syn::ExprMethodCall) -> bool {
        if !DRAIN_METHODS.contains(&call.method.to_string().as_str()) {
            return false;
        }
        match strip(&call.receiver) {
            syn::Expr::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => {
                let name = p.path.segments[0].ident.to_string();
                if name == "self" {
                    self.self_is_drain
                } else {
                    self.drain_params.contains(&name)
                }
            }
            _ => false,
        }
    }

    /// Cases 2-5 of §7a: a position where an await is bounded by its surroundings.
    fn await_allowed_here(&self) -> bool {
        self.impl_exempt
            || self.signal_wait
            || self.drain_arg > 0
            || self
                .helper_body
                .as_ref()
                .is_some_and(|h| self.drained.contains(h))
    }

    fn note_ref(&mut self, name: &str) {
        let ctx = if self.drain_arg > 0 {
            RefCtx::DrainArg
        } else if let Some(h) = &self.helper_body {
            RefCtx::InHelper(h.clone())
        } else {
            RefCtx::Other
        };
        self.refs.entry(name.to_string()).or_default().push(ctx);
    }

    fn scan_run(&mut self, block: &syn::Block) {
        self.run_seen = true;
        let mut tail = false;
        for (i, stmt) in block.stmts.iter().enumerate() {
            if tail {
                if let syn::Stmt::Local(local) = stmt {
                    if let Some(init) = &local.init {
                        if let syn::Expr::Await(aw) = strip(&init.expr) {
                            if is_finish_call(&aw.base) {
                                if is_exit_stmt(block.stmts.get(i + 1)) {
                                    self.finish_ok.insert(line(aw.span()));
                                } else {
                                    self.report(
                                        line(aw.span()),
                                        "root::shutdown::finish must be followed by the process exit",
                                    );
                                    self.finish_ok.insert(line(aw.span()));
                                }
                            }
                        }
                    }
                }
            }
            self.run_tail = tail;
            self.visit_stmt(stmt);
            if !tail {
                if let syn::Stmt::Local(local) = stmt {
                    if pat_binds(&local.pat, "shutdown_tx") {
                        tail = true;
                    }
                }
            }
        }
        self.run_tail = false;
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        if is_cfg_test(&i.attrs) {
            return;
        }
        visit::visit_item_mod(self, i);
    }

    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        let saved = (
            std::mem::replace(&mut self.drain_params, drain_params(&i.sig)),
            self.helper_body.take(),
            self.signal_wait,
            self.self_is_drain,
        );
        let name = i.sig.ident.to_string();
        if self.helpers.contains(&name) {
            self.helper_body = Some(name.clone());
        }
        self.signal_wait = name == "recv_shutdown";
        self.self_is_drain = false;
        if self.role == Role::Main && name == "run" {
            self.scan_run(&i.block);
        } else {
            visit::visit_item_fn(self, i);
        }
        self.drain_params = saved.0;
        self.helper_body = saved.1;
        self.signal_wait = saved.2;
        self.self_is_drain = saved.3;
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let name = match &*i.self_ty {
            syn::Type::Path(p) => last_ident(&p.path),
            _ => None,
        };
        let saved = (self.impl_exempt, self.impl_name.take());
        self.impl_exempt = matches!(name.as_deref(), Some("ShutdownDrain" | "DrainHandle"));
        self.impl_name = name;
        visit::visit_item_impl(self, i);
        self.impl_exempt = saved.0;
        self.impl_name = saved.1;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        let saved = (
            std::mem::replace(&mut self.drain_params, drain_params(&i.sig)),
            self.helper_body.take(),
            self.signal_wait,
            self.self_is_drain,
        );
        self.self_is_drain = self.impl_name.as_deref() == Some("ShutdownDrain");
        self.signal_wait = self.impl_name.as_deref() == Some("Signals") && i.sig.ident == "next";
        visit::visit_impl_item_fn(self, i);
        self.drain_params = saved.0;
        self.helper_body = saved.1;
        self.signal_wait = saved.2;
        self.self_is_drain = saved.3;
    }

    fn visit_expr_path(&mut self, i: &'ast syn::ExprPath) {
        if self.role == Role::Shutdown && i.qself.is_none() && i.path.segments.len() == 1 {
            let name = i.path.segments[0].ident.to_string();
            if self.helpers.contains(&name) {
                self.note_ref(&name);
            }
        }
        visit::visit_expr_path(self, i);
    }

    fn visit_expr_await(&mut self, i: &'ast syn::ExprAwait) {
        let base = strip(&i.base);
        if let syn::Expr::MethodCall(mc) = base {
            self.awaited = mc as *const syn::ExprMethodCall as usize;
        }
        let at = line(i.span());
        match self.role {
            Role::Shutdown => {
                let drain_await =
                    matches!(base, syn::Expr::MethodCall(mc) if self.is_drain_call(mc));
                if !drain_await && !self.await_allowed_here() {
                    self.report(at, "an .await that no drain call bounds");
                }
            }
            Role::Main => {
                if self.run_tail && self.spawn_arg == 0 {
                    let allowed = match base {
                        syn::Expr::Call(c) => match strip(&c.func) {
                            syn::Expr::Path(p) => {
                                if ends_with(&p.path, &["shutdown", "finish"]) {
                                    self.finish_seen = true;
                                    if !self.finish_ok.contains(&at) {
                                        self.report(
                                            at,
                                            "root::shutdown::finish must initialise a top-level let of run, followed by the process exit",
                                        );
                                    }
                                    true
                                } else {
                                    last_ident(&p.path).as_deref() == Some("bind_listener")
                                }
                            }
                            _ => false,
                        },
                        _ => false,
                    };
                    if !allowed {
                        self.report(
                            at,
                            "run awaits something other than bind_listener or root::shutdown::finish after shutdown_tx",
                        );
                    }
                }
            }
        }
        visit::visit_expr_await(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        let at = line(i.method.span());
        let method = i.method.to_string();
        let awaited = self.awaited == i as *const syn::ExprMethodCall as usize;
        let drain = self.is_drain_call(i);
        if method == "abort" {
            self.report(at, "an .abort() call");
        }
        if drain {
            let cut_ok = |e: &syn::Expr| match strip(e) {
                syn::Expr::Path(p) => {
                    p.path.segments.len() >= 2
                        && p.path.segments[p.path.segments.len() - 2].ident == "Cut"
                }
                _ => false,
            };
            match method.as_str() {
                "bounded" | "wait" => {
                    if i.args.len() != 3 || !cut_ok(&i.args[2]) {
                        self.report(
                            at,
                            format!("{method} takes (phase, future, Cut::<cut>) with the cut a Cut:: path"),
                        );
                    }
                }
                _ => {
                    if i.args.len() != 1 {
                        self.report(at, format!("{method} takes exactly one argument"));
                    }
                }
            }
        }
        if self.checks_blocking() {
            let blocking = (method == "join" && i.args.is_empty())
                || BLOCKING.contains(&method.as_str())
                || ((method == "recv" || method == "wait") && !awaited && !drain);
            if blocking {
                self.report(at, format!("a blocking .{method}() on the control thread"));
            }
        }
        self.visit_expr(&i.receiver);
        let spawns = method == "spawn" || method == "spawn_blocking";
        for arg in &i.args {
            let closure = matches!(strip(arg), syn::Expr::Closure(c) if c.asyncness.is_none());
            let exempt = closure && spawns;
            if drain {
                self.drain_arg += 1;
            }
            if exempt {
                self.blocking_ok += 1;
            }
            if method == "spawn" {
                self.spawn_arg += 1;
            }
            self.visit_expr(arg);
            if method == "spawn" {
                self.spawn_arg -= 1;
            }
            if exempt {
                self.blocking_ok -= 1;
            }
            if drain {
                self.drain_arg -= 1;
            }
        }
    }

    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        let path = match strip(&i.func) {
            syn::Expr::Path(p) => Some(p.path.clone()),
            _ => None,
        };
        let last = path.as_ref().and_then(last_ident).unwrap_or_default();
        if self.checks_blocking() {
            let at = line(i.func.span());
            if BLOCKING.contains(&last.as_str()) {
                self.report(at, format!("a blocking {last}() on the control thread"));
            }
            if path
                .as_ref()
                .is_some_and(|p| ends_with(p, &["thread", "sleep"]))
            {
                self.report(at, "a blocking thread::sleep on the control thread");
            }
        }
        let blocking_spawn = last == "spawn_blocking"
            || path
                .as_ref()
                .is_some_and(|p| ends_with(p, &["thread", "spawn"]));
        let task_spawn = last == "spawn" || last == "spawn_multithread_data";
        self.visit_expr(&i.func);
        for arg in &i.args {
            let closure = matches!(strip(arg), syn::Expr::Closure(c) if c.asyncness.is_none());
            let exempt = closure && blocking_spawn;
            if exempt {
                self.blocking_ok += 1;
            }
            if task_spawn {
                self.spawn_arg += 1;
            }
            self.visit_expr(arg);
            if task_spawn {
                self.spawn_arg -= 1;
            }
            if exempt {
                self.blocking_ok -= 1;
            }
        }
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let at = line(i.path.span());
        let name = last_ident(&i.path).unwrap_or_default().to_ascii_lowercase();
        if macro_await_site(i) {
            match self.role {
                Role::Shutdown => {
                    if !self.await_allowed_here() {
                        self.report(
                            at,
                            format!("{name}! waits on something no drain call bounds"),
                        );
                    }
                }
                Role::Main => {
                    if self.run_tail && self.spawn_arg == 0 {
                        self.report(at, format!("run waits inside {name}! after shutdown_tx"));
                    }
                }
            }
        }
        let mut findings = Vec::new();
        macro_findings(
            &i.tokens,
            name == "select",
            name == "join" || name == "try_join",
            &mut findings,
        );
        for what in findings {
            if what == "an abort() call" {
                self.report(at, format!("{what} inside {name}!"));
            } else if self.checks_blocking() {
                self.report(at, format!("{what} inside {name}! on the control thread"));
            }
        }
        if self.role == Role::Shutdown {
            fn idents(tokens: &TokenStream, out: &mut Vec<String>) {
                for t in tokens.clone() {
                    match t {
                        TokenTree::Ident(i) => out.push(i.to_string()),
                        TokenTree::Group(g) => idents(&g.stream(), out),
                        _ => {}
                    }
                }
            }
            let mut names = Vec::new();
            idents(&i.tokens, &mut names);
            for n in names {
                if self.helpers.contains(&n) {
                    self.note_ref(&n);
                }
            }
        }
        visit::visit_macro(self, i);
    }
}

fn scan(role: Role, file: &str, src: &str) -> Vec<String> {
    let parsed = match syn::parse_file(src) {
        Ok(parsed) => parsed,
        Err(error) => return vec![format!("{file}: does not parse: {error}")],
    };
    let mut helpers = BTreeSet::new();
    if role == Role::Shutdown {
        for item in &parsed.items {
            if let syn::Item::Fn(f) = item {
                if f.sig.asyncness.is_some() && matches!(f.vis, syn::Visibility::Inherited) {
                    helpers.insert(f.sig.ident.to_string());
                }
            }
        }
    }
    let none = BTreeSet::new();
    let mut first = Scan::new(role, file, &helpers, &none);
    first.visit_file(&parsed);
    // Drained helpers: the least fixpoint, so a cycle of helpers with no wrapped entry, or a
    // helper referenced once outside a drain argument, is never drained.
    let mut drained = BTreeSet::new();
    loop {
        let mut grew = false;
        for helper in &helpers {
            if drained.contains(helper) {
                continue;
            }
            let Some(refs) = first.refs.get(helper) else {
                continue;
            };
            let ok = !refs.is_empty()
                && refs.iter().all(|r| match r {
                    RefCtx::DrainArg => true,
                    RefCtx::InHelper(h) => drained.contains(h),
                    RefCtx::Other => false,
                });
            if ok {
                drained.insert(helper.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    let mut second = Scan::new(role, file, &helpers, &drained);
    second.visit_file(&parsed);
    if role == Role::Main && second.run_seen && !second.finish_seen {
        second
            .found
            .push(format!("{file}: run never awaits root::shutdown::finish"));
    }
    second.found
}

fn check_shutdown(src: &str) -> Vec<String> {
    scan(Role::Shutdown, "root/shutdown.rs", src)
}

fn check_main(src: &str) -> Vec<String> {
    scan(Role::Main, "main.rs", src)
}

#[test]
fn shutdown_waits_are_bounded() {
    let mut found = check_shutdown(include_str!("../src/root/shutdown.rs"));
    found.extend(check_main(include_str!("../src/main.rs")));
    assert!(
        found.is_empty(),
        "R16: the shutdown path must bound every wait, cancel nothing and block nothing:\n{}",
        found.join("\n")
    );
}

/// Each fixture must fail R16, naming the offending line.
#[test]
fn shutdown_wait_fixtures_that_must_fail() {
    let shutdown: &[(&str, &str)] = &[
        (
            "unwrapped await in finish",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    post.journal.flush().await;\n    0\n}\n",
        ),
        (
            "helper wrapped once and called once outside",
            "async fn helper() { store.read().await; }\npub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.bounded(Phase::Journal, DrainHandle::spawn(helper()), Cut::Seal).await;\n    let _f = helper();\n    0\n}\n",
        ),
        (
            "wrapped helper that is not private",
            "pub(crate) async fn helper() { store.read().await; }\npub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.bounded(Phase::Journal, DrainHandle::spawn(helper()), Cut::Seal).await;\n    0\n}\n",
        ),
        (
            "helper referenced as a value",
            "async fn helper() { store.read().await; }\npub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.bounded(Phase::Journal, DrainHandle::spawn(helper()), Cut::Seal).await;\n    let f = helper;\n    0\n}\n",
        ),
        (
            "two helpers calling only each other",
            "async fn a() { b().await; store.read().await; }\nasync fn b() { a().await; }\n",
        ),
        (
            "drain call through a rebinding",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let d = drain;\n    let _ = d.wait(Phase::Settle, async {}, Cut::Settle).await;\n    0\n}\n",
        ),
        (
            "abort on any receiver",
            "fn stop(h: tokio::task::JoinHandle<()>) {\n    h.abort();\n}\n",
        ),
        (
            "non-private async fn with a bare store await",
            "pub(crate) async fn note_undrained(store: &Store) {\n    store.write().await;\n}\n",
        ),
        (
            "bare select! in finish",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    tokio::select! { _ = notary_handle => {}, _ = tokio::signal::ctrl_c() => {} }\n    0\n}\n",
        ),
        (
            "await inside tracing::info!",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    tracing::info!(\"{}\", store.read().await);\n    0\n}\n",
        ),
        (
            "abort inside a select! arm",
            "impl ShutdownDrain {\n    async fn x(&self, h: Handle) {\n        tokio::select! { _ = self.clock.armed() => { h.abort(); } }\n    }\n}\n",
        ),
        (
            "abort inside a nested join! group",
            "impl ShutdownDrain {\n    async fn x(&self, h: Handle) {\n        tokio::join!(async { (h.abort()) });\n    }\n}\n",
        ),
        (
            "bounded whose cut is a variable",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let cut = Cut::Seal;\n    let _ = drain.bounded(Phase::Journal, h, cut).await;\n    0\n}\n",
        ),
        (
            "wait whose cut is a variable",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.wait(Phase::Settle, async {}, cut).await;\n    0\n}\n",
        ),
        (
            "two-argument wait",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.wait(async {}, Cut::Settle).await;\n    0\n}\n",
        ),
        (
            "bare thread join in finish",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    for h in data_handles { let _ = h.join(); }\n    0\n}\n",
        ),
        (
            "block_on in a drained helper",
            "async fn helper() { tokio::runtime::Handle::current().block_on(f); }\npub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.bounded(Phase::Journal, DrainHandle::spawn(helper()), Cut::Seal).await;\n    0\n}\n",
        ),
        (
            "block_on in a helper also called outside",
            "async fn helper() { tokio::runtime::Handle::current().block_on(f); }\npub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.bounded(Phase::Journal, DrainHandle::spawn(helper()), Cut::Seal).await;\n    let _ = helper();\n    0\n}\n",
        ),
        (
            "std recv in finish",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = rx.recv();\n    0\n}\n",
        ),
        (
            "Condvar wait in finish",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _g = cv.wait(guard);\n    0\n}\n",
        ),
        (
            "thread::sleep inside tracing::info!",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    tracing::info!(\"{:?}\", std::thread::sleep(d));\n    0\n}\n",
        ),
        (
            "join inside an async block passed to a drain call",
            "pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {\n    let _ = drain.wait(Phase::Settle, async move { let _ = h.join(); }, Cut::Settle).await;\n    0\n}\n",
        ),
    ];
    for (name, src) in shutdown {
        let found = check_shutdown(src);
        assert!(!found.is_empty(), "R16 accepted the fixture: {name}");
        assert!(
            found.iter().all(|f| f.contains(':')),
            "{name}: findings must name the line: {found:?}"
        );
    }
    let main: &[(&str, &str)] = &[
        (
            "an await in run after shutdown_tx other than finish",
            "async fn run() {\n    let (shutdown_tx, _keep) = tokio::sync::broadcast::channel::<()>(1);\n    work_recovery.await;\n    let code = root::shutdown::finish(post, &drain).await;\n    root::exit::exit(code);\n}\n",
        ),
        (
            "join! in run after shutdown_tx",
            "async fn run() {\n    let (shutdown_tx, _keep) = tokio::sync::broadcast::channel::<()>(1);\n    tokio::join!(retire_storage(a, b));\n    let code = root::shutdown::finish(post, &drain).await;\n    root::exit::exit(code);\n}\n",
        ),
        (
            "finish not followed by the exit",
            "async fn run() {\n    let (shutdown_tx, _keep) = tokio::sync::broadcast::channel::<()>(1);\n    let code = root::shutdown::finish(post, &drain).await;\n    tracing::info!(code);\n}\n",
        ),
        (
            "run never calls finish",
            "async fn run() {\n    let (shutdown_tx, _keep) = tokio::sync::broadcast::channel::<()>(1);\n}\n",
        ),
        (
            "abort anywhere in main.rs",
            "fn other(task: tokio::task::JoinHandle<()>) { task.abort(); }\n",
        ),
        (
            "bare thread join in run after shutdown_tx",
            "async fn run() {\n    let (shutdown_tx, _keep) = tokio::sync::broadcast::channel::<()>(1);\n    for h in handles { let _ = h.join(); }\n    let code = root::shutdown::finish(post, &drain).await;\n    root::exit::exit(code);\n}\n",
        ),
    ];
    for (name, src) in main {
        assert!(
            !check_main(src).is_empty(),
            "R16 accepted the main.rs fixture: {name}"
        );
    }
}

/// The designed shapes pass with no allowlist beyond the two signal waits.
#[test]
fn shutdown_wait_fixtures_that_must_pass() {
    let shutdown = r#"
pub(crate) struct ShutdownDrain { clock: Arc<DrainClock> }
impl ShutdownDrain {
    async fn limited<F: Future>(&self, cut: Cut, fut: F) -> Outcome<F::Output> {
        let mut fut = std::pin::pin!(fut);
        let mut expired = self.clock.expired_rx();
        let deadline = tokio::select! {
            biased;
            r = &mut fut => return Outcome::Done(r),
            at = self.clock.armed() => at,
        };
        let limit = self.clock.limit(deadline, cut);
        tokio::select! {
            biased;
            _ = expired.wait_for(|e| *e) => Outcome::Expired,
            _ = rx.recv() => Outcome::Cut,
            r = tokio::time::timeout_at(limit, fut) => r.map_or(Outcome::Cut, Outcome::Done),
        }
    }
    pub(crate) async fn wait<F: Future>(&self, phase: Phase, fut: F, cut: Cut) -> Outcome<F::Output> {
        self.limited(cut, fut).await
    }
    pub(crate) async fn wait_requests<F: Future>(&self, fut: F) -> Outcome<F::Output> {
        self.wait(Phase::Requests, fut, Cut::Requests).await
    }
}
impl Signals {
    pub(crate) async fn next(&mut self) { self.term.recv().await; }
}
pub(crate) async fn finish(post: PostServe, drain: &ShutdownDrain) -> i32 {
    let names = ["a", "b"].join(",");
    let path = std::path::Path::new("p").join("x");
    tracing::info!(names = %names, "phase {}", format!("{path:?}"));
    let _ = drain
        .bounded_requests(DrainHandle::spawn(tokio::task::spawn_blocking(move || {
            for h in hs {
                let _ = h.join();
            }
        })))
        .await;
    let _ = drain
        .wait(
            Phase::Settle,
            async {
                loop {
                    tokio::select! {
                        _ = passes.changed() => {}
                        _ = tokio::time::sleep(DRAIN_PASS_IDLE) => {}
                    }
                }
            },
            Cut::Settle,
        )
        .await;
    let c3 = drain.clock().limit(deadline, Cut::Seal);
    let _ = drain
        .bounded(Phase::MoneyFallback, DrainHandle::spawn(money_fallback(gov, clock, c3)), Cut::Seal)
        .await;
    let _ = drain
        .bounded(Phase::Audit, DrainHandle::spawn(drain_audit_queue()), Cut::Deadline)
        .await;
    match drain
        .bounded(Phase::Retire, DrainHandle::spawn(retire_storage(startup, book, drained)), Cut::Deadline)
        .await
    {
        Outcome::Done(Ok(())) => 0,
        _ => 75,
    }
}
async fn money_fallback(gov: Arc<GovState>, clock: Arc<DrainClock>, c3: Instant) -> Vec<String> {
    let paced = PacedHalt::new(clock, c3);
    let mut failures = Vec::new();
    match tokio::spawn(maintenance(async move { gov.flush_budgets_final().await })).await {
        Ok(flushed) => tracing::info!(flushed, "budget shutdown flush completed"),
        Err(error) => failures.push(format!("budget final driver failed: {error}")),
    }
    let _ = gov.flush_unit_checkpoints_until(&|| paced.halt()).await;
    failures
}
async fn drain_audit_queue() -> Result<(), String> {
    match tokio::spawn(flush_pending()).await {
        Ok(Ok(())) => Ok(()),
        _ => Err("x".into()),
    }
}
async fn retire_storage(startup: Startup, book: Option<NodeBook>, drained: Drained) -> Result<(), String> {
    lease.release().await?;
    startup.advance().await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    async fn anything() { x.await; h.abort(); }
}
"#;
    let found = check_shutdown(shutdown);
    assert!(found.is_empty(), "{}", found.join("\n"));
    let main = r#"
async fn run(control_work: ControlWork) {
    let prepared = prepare().await;
    let (shutdown_tx, _keep_open) = tokio::sync::broadcast::channel::<()>(1);
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            recv_shutdown(rx).await;
            let _ = tx.send(());
        });
    }
    let data = spawn_multithread_data(workers, rx, async move {
        let listener = bind_listener(&listen).await;
        serve_listener(listener).await;
    });
    let admin = bind_listener(&admin_listen).await;
    let post = PostServe { admin: Box::pin(serve_listener(admin)), data };
    let code = root::shutdown::finish(post, &drain).await;
    root::exit::exit(code);
}
async fn recv_shutdown(mut rx: Receiver<()>) {
    tokio::select! { _ = rx.recv() => {} }
}
"#;
    let found = check_main(main);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn pre_drain_propagation_wait_is_owned_by_shutdown_drain() {
    let owned = "impl ShutdownDrain { async fn coordinate(&self) { tokio::select! { _ = intent.changed() => {}, _ = tokio::time::sleep_until(deadline) => {} } } }";
    assert!(check_shutdown(owned).is_empty());
    let unmanaged = "async fn listener_delay() { tokio::time::sleep(delay).await; }";
    assert!(
        !check_shutdown(unmanaged).is_empty(),
        "a listener cannot acquire an independent shutdown timer"
    );
    let unbounded_phase = "async fn settle() { pending_write.await; }";
    assert!(
        !check_shutdown(unbounded_phase).is_empty(),
        "the pre-drain allowance does not relax settlement waits"
    );
}
