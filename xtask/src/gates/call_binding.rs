//! `cargo xtask gate call-binding` — PASS/GRANT PER-CALL BINDING (BUSBAR-1.6.0.md Part 2 #74; the
//! DoD's gate battery, l.2908, "Pass/Grant per-call binding (#74)").
//!
//! #74 (OWNER-LOCKED 2026-09-20) binds every capability proof to the call it was minted for, two
//! ways. Three rows, one per mechanism, each read as lexed code:
//!
//! | row | the claim |
//! | --- | --- |
//! | `call-binding:in-process` | the trusted half: EVERY production file of the kernel (its `impl Kernel` token vending aside) mints every `Pass`/`Grant` BOUND to the unit's call (`mint_bound`), never with the unbound `mint`, and never calls the kernel's unbound token factories (the `impl Kernel` fns that mint unbound), outside the named off-loop sites of [`OFF_LOOP`] (recovery, the sweep, the amendment journal), each of which must still mint; the loop opens the call (`next_call`), the stage compares it (`bound_to`), and the money cell refuses another call's grant (`CallMismatch`) |
//! | `call-binding:abi-handle` | the untrusted half, the context: no host entry reads a plugin's `HostCtx` as an address; every one resolves it through `handle::resolve`, whose check verifies the tag in constant time, refuses a revoked entry and (inside a crossing) another instance's, and counts a forgery |
//! | `call-binding:ticket` | the untrusted half, the ticket: a slot's generation (a worker's or an inline one) is the keyed permutation of its counter (`ticket_generation`); a wake that matches no live ticket is judged by the inverse (`ticket_count`) and a never-minted one is blamed on its supplier (`forged_ticket`), as is a wake for a worker the dispatcher does not run; a spent counter retires its slot (`next_count`) |
//!
//! Blocking from its first commit: a row that does not hold is RED, and `in-process` names every
//! unbound mint by its line.

use proc_macro2::{Delimiter, TokenStream, TokenTree};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_IN_PROCESS: &str = "call-binding:in-process";
pub const ROW_ABI_HANDLE: &str = "call-binding:abi-handle";
pub const ROW_TICKET: &str = "call-binding:ticket";

const TELLER: &str = "crates/busbar-kernel/src/teller.rs";
const PROBE: &str = "crates/busbar-kernel/src/plane_driver/probe.rs";
const INFLIGHT: &str = "crates/busbar-kernel/src/inflight.rs";
const TICK: &str = "crates/busbar-kernel/src/tick.rs";
const HOLD: &str = "crates/busbar-contract/src/caps/hold.rs";
const HANDLE: &str = "crates/plugin-loader/src/dispatch/handle.rs";
const WORKER: &str = "crates/plugin-loader/src/dispatch/worker.rs";
const INLINE: &str = "crates/plugin-loader/src/dispatch/inline.rs";

/// THE WHOLE KERNEL is read, not a hand-named roster (audit XG #5: a roster of the teller and the
/// probe left the arrival hold and the far end's own route pass unbound and green).
const KERNEL_SRC: &str = "crates/busbar-kernel/src";

/// The walk's floor: fewer production files than this is the instrument gone blind, not a clean
/// kernel. Below today's count (205) by the plane-hosting files the kernel-planes rows delete.
const KERNEL_FLOOR: usize = 100;

/// THE OFF-LOOP SITES, by file and fn: the only places in the kernel an unbound proof is minted, or
/// an unbound factory called, because no unit's call exists there. Checked both ways: a site outside
/// these is RED, and an entry that no longer mints is RED too (a stale entry would let a new mint
/// land under it unseen).
const OFF_LOOP: &[(&str, &str, &str)] = &[
    (
        "crates/busbar-kernel/src/recovery.rs",
        "materialize",
        "recovery rebuilds a hold from its durable record at boot, before any call exists",
    ),
    (
        "crates/busbar-kernel/src/recovery.rs",
        "settle",
        "recovery settles a recovered hold at boot, on no unit's call",
    ),
    (
        "crates/busbar-kernel/src/tick.rs",
        "sweep_settle",
        "the sweep settles a slot whose unit is gone, on no unit's call",
    ),
    (
        "crates/busbar-kernel/src/audit/amend.rs",
        "pass",
        "the amendment journal's access and correction records are written off the unit loop",
    ),
];

/// The host entries a plugin hands its context to.
const HOST_ENTRIES: &[&str] = &[
    "crates/plugin-loader/src/dispatch/ticket.rs",
    "crates/plugin-loader/src/dispatch/services.rs",
    "crates/plugin-loader/src/dispatch/conn_services.rs",
    "crates/plugin-loader/src/dispatch/io_slots.rs",
];

fn lex(src: &str) -> Result<TokenStream, String> {
    src.parse::<TokenStream>()
        .map_err(|e| format!("does not lex as Rust: {e}"))
}

/// `ts` flattened to `(token, line)`, each group's delimiters as tokens; the group after
/// `impl Kernel` is skipped when `skip_kernel_impl`.
fn flat(ts: TokenStream, skip_kernel_impl: bool, out: &mut Vec<(String, usize)>) {
    let trees: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        let tt = &trees[i];
        let ident =
            |t: Option<&TokenTree>, s: &str| matches!(t, Some(TokenTree::Ident(x)) if x == s);
        if skip_kernel_impl && ident(Some(tt), "impl") && ident(trees.get(i + 1), "Kernel") {
            if let Some(TokenTree::Group(g)) = trees.get(i + 2) {
                if g.delimiter() == Delimiter::Brace {
                    i += 3;
                    continue;
                }
            }
        }
        let line = tt.span().start().line;
        match tt {
            TokenTree::Group(g) => {
                let (open, close) = match g.delimiter() {
                    Delimiter::Parenthesis => ("(", ")"),
                    Delimiter::Brace => ("{", "}"),
                    Delimiter::Bracket => ("[", "]"),
                    Delimiter::None => ("", ""),
                };
                if !open.is_empty() {
                    out.push((open.to_string(), line));
                }
                flat(g.stream(), skip_kernel_impl, out);
                if !close.is_empty() {
                    out.push((close.to_string(), g.span().end().line));
                }
            }
            TokenTree::Punct(p) => out.push((p.as_char().to_string(), line)),
            TokenTree::Ident(x) => out.push((x.to_string(), line)),
            TokenTree::Literal(l) => out.push((l.to_string(), line)),
        }
        i += 1;
    }
}

fn tokens_of(src: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    flat(lex(src)?, false, &mut out);
    Ok(out.into_iter().map(|(t, _)| t).collect())
}

/// The brace group after `fn <name>` at any depth.
fn body_of(ts: &TokenStream, name: &str) -> Option<TokenStream> {
    let trees: Vec<TokenTree> = ts.clone().into_iter().collect();
    for (i, tt) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            if let Some(found) = body_of(&g.stream(), name) {
                return Some(found);
            }
        }
        let is = |t: Option<&TokenTree>, s: &str| matches!(t, Some(TokenTree::Ident(x)) if x == s);
        if is(Some(tt), "fn") && is(trees.get(i + 1), name) {
            return trees[i + 2..].iter().find_map(|t| match t {
                TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => Some(g.stream()),
                _ => None,
            });
        }
    }
    None
}

fn holds(tokens: &[String], seq: &[&str]) -> bool {
    !seq.is_empty()
        && tokens
            .windows(seq.len())
            .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
}

/// The body of `fn name` in `file`, flattened; a missing file or fn is the problem.
fn fn_tokens(cx: &Ctx, file: &str, name: &str) -> Result<Vec<String>, String> {
    let text = cx.read(file).map_err(|e| format!("{file}: {e}"))?;
    let ts = lex(&text).map_err(|e| format!("{file}: {e}"))?;
    let body = body_of(&ts, name).ok_or_else(|| format!("{file}: no `fn {name}`"))?;
    let mut out = Vec::new();
    flat(body, false, &mut out);
    Ok(out.into_iter().map(|(t, _)| t).collect())
}

fn need(cx: &Ctx, file: &str, f: &str, seq: &[&str], what: &str, bad: &mut Vec<String>) {
    match fn_tokens(cx, file, f) {
        Ok(b) if holds(&b, seq) => {}
        Ok(_) => bad.push(format!("{file}: `fn {f}` {what}")),
        Err(e) => bad.push(e),
    }
}

fn need_file(cx: &Ctx, file: &str, seq: &[&str], what: &str, bad: &mut Vec<String>) {
    match cx
        .read(file)
        .map_err(|e| e.to_string())
        .and_then(|t| tokens_of(&t))
    {
        Ok(t) if holds(&t, seq) => {}
        Ok(_) => bad.push(format!("{file}: {what}")),
        Err(e) => bad.push(format!("{file}: {e}")),
    }
}

/// A file's production code: everything above its first `#[cfg(test)]` (the loop's files keep
/// their unit tests at the foot, as `#[path]` modules).
fn production_text(text: &str) -> &str {
    &text[..text.find("#[cfg(test)]").unwrap_or(text.len())]
}

/// Every unbound `Pass::…mint(` / `Grant::…mint(` in `tokens`, by line: a `mint` call whose path is
/// `Pass`/`Grant`, with or without a turbofish.
#[cfg(test)]
fn unbound_mints(tokens: &[(String, usize)]) -> Vec<usize> {
    unbound_mint_at(tokens)
        .into_iter()
        .map(|i| tokens[i].1)
        .collect()
}

/// The token index of every `mint` that [`unbound_mints`] names.
fn unbound_mint_at(tokens: &[(String, usize)]) -> Vec<usize> {
    let t = |i: usize| tokens.get(i).map_or("", |(s, _)| s.as_str());
    let mut at = Vec::new();
    for (i, _) in tokens.iter().enumerate().skip(3) {
        if t(i) != "mint" || t(i + 1) != "(" || t(i - 1) != ":" || t(i - 2) != ":" {
            continue;
        }
        let mut head = i - 3;
        if t(head) == ">" {
            let mut depth = 0usize;
            loop {
                match t(head) {
                    ">" => depth += 1,
                    "<" => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                if head == 0 {
                    break;
                }
                head -= 1;
            }
            if head < 3 || t(head - 1) != ":" || t(head - 2) != ":" {
                continue;
            }
            head -= 3;
        }
        if matches!(t(head), "Pass" | "Grant") {
            at.push(i);
        }
    }
    at
}

/// Every unbound proof site in `tokens` with the fn it sits in: an unbound `mint(` of a pass or
/// grant, or a call (`.name(` / `::name(`) of one of `factories`.
fn unbound_sites(tokens: &[(String, usize)], factories: &[String]) -> Vec<(usize, Option<String>)> {
    let mints = unbound_mint_at(tokens);
    let t = |i: usize| tokens.get(i).map_or("", |(s, _)| s.as_str());
    let mut out = Vec::new();
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut pending: Option<String> = None;
    let mut depth = 0usize;
    for (i, (tok, line)) in tokens.iter().enumerate() {
        match tok.as_str() {
            "fn" if i + 1 < tokens.len() => pending = Some(t(i + 1).to_string()),
            ";" => pending = None,
            "{" => {
                depth += 1;
                if let Some(name) = pending.take() {
                    stack.push((name, depth));
                }
            }
            "}" => {
                if stack.last().is_some_and(|(_, d)| *d == depth) {
                    stack.pop();
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        let here = || stack.last().map(|(n, _)| n.clone());
        if mints.contains(&i) {
            out.push((*line, here()));
        }
        if factories.iter().any(|f| f == tok)
            && t(i + 1) == "("
            && (t(i.wrapping_sub(1)) == "." || t(i.wrapping_sub(1)) == ":")
            && t(i.wrapping_sub(2)) != "fn"
        {
            out.push((*line, here()));
        }
    }
    out
}

/// The kernel's UNBOUND TOKEN FACTORIES: the fns of the teller's `impl Kernel` whose body mints an
/// unbound pass or grant (`admit_token`, `admin_token`, ...), read from the code, never listed.
fn unbound_factories(teller: &str) -> Result<Vec<String>, String> {
    let ts = lex(production_text(teller))?;
    let trees: Vec<TokenTree> = ts.into_iter().collect();
    let mut names = Vec::new();
    for (i, tt) in trees.iter().enumerate() {
        let ident =
            |t: Option<&TokenTree>, s: &str| matches!(t, Some(TokenTree::Ident(x)) if x == s);
        if !(ident(Some(tt), "impl") && ident(trees.get(i + 1), "Kernel")) {
            continue;
        }
        if let Some(TokenTree::Group(g)) = trees.get(i + 2) {
            let mut tokens = Vec::new();
            flat(g.stream(), false, &mut tokens);
            for f in unbound_sites(&tokens, &[])
                .into_iter()
                .filter_map(|(_, f)| f)
            {
                if !names.contains(&f) {
                    names.push(f);
                }
            }
        }
    }
    if names.is_empty() {
        return Err(format!(
            "{TELLER}: no unbound token factory found in `impl Kernel` (the scan went blind)"
        ));
    }
    Ok(names)
}

/// A kernel file's production code as lexable text, every line at its own number: comments and
/// `#[cfg(test)]` modules dropped through the one scanner.
fn production_source(text: &str) -> String {
    let mut out = String::new();
    let mut at = 1;
    for (line, code) in crate::scan::production_lines(text) {
        while at < line {
            out.push('\n');
            at += 1;
        }
        out.push_str(&code);
        out.push('\n');
        at += 1;
    }
    out
}

/// (a) The kernel's proofs are bound to the unit's call, and compared.
fn in_process(cx: &Ctx) -> Vec<String> {
    let mut bad = Vec::new();
    let factories = match cx
        .read(TELLER)
        .map_err(|e| e.to_string())
        .and_then(|t| unbound_factories(&t))
    {
        Ok(f) => f,
        Err(e) => {
            bad.push(format!("{TELLER}: {e}"));
            Vec::new()
        }
    };
    let files = match cx.walk(
        &WalkSpec::new([KERNEL_SRC])
            .ext("rs")
            .exclude(["/tests/", "/test_support/", "_tests.rs"])
            .min_files(KERNEL_FLOOR),
    ) {
        Ok(f) => f,
        Err(e) => {
            bad.push(format!("{KERNEL_SRC}: {e}"));
            Vec::new()
        }
    };
    let mut used = vec![false; OFF_LOOP.len()];
    for file in &files {
        let rel = file.rel_str();
        let ts = match lex(&production_source(&file.text)) {
            Ok(ts) => ts,
            Err(e) => {
                bad.push(format!("{rel}: {e}"));
                continue;
            }
        };
        let mut tokens = Vec::new();
        flat(ts, true, &mut tokens);
        for (line, f) in unbound_sites(&tokens, &factories) {
            let allowed = OFF_LOOP
                .iter()
                .position(|(file, name, _)| *file == rel && f.as_deref() == Some(*name));
            match allowed {
                Some(k) => used[k] = true,
                None => bad.push(format!(
                    "{rel}:{line}: an unbound pass or grant (an unbound `mint(` or a call of the \
                     kernel's unbound factories) off the named off-loop sites: a proof no stage can \
                     tie to its call (mint_bound / admit_token_for with the unit's CallId)"
                )),
            }
        }
    }
    for ((file, name, _), seen) in OFF_LOOP.iter().zip(used) {
        if !seen && !files.is_empty() {
            bad.push(format!(
                "{file}: the off-loop entry `fn {name}` no longer mints an unbound proof: drop the \
                 stale entry"
            ));
        }
    }
    need_file(
        cx,
        TELLER,
        &[".", "next_call", "(", ")"],
        "the loop never opens a per-request call (`kernel.next_call()`)",
        &mut bad,
    );
    need_file(
        cx,
        TELLER,
        &[".", "bound_to", "("],
        "no stage compares a proof's call (`bound_to`)",
        &mut bad,
    );
    need(
        cx,
        HOLD,
        "admit",
        &["CallMismatch"],
        "admits a hold under another call's grant (no `CallMismatch`)",
        &mut bad,
    );
    bad
}

/// (b) No host entry reads a context as an address; each resolves it; the check is whole.
fn abi_handle(cx: &Ctx) -> Vec<String> {
    let mut bad = Vec::new();
    for file in HOST_ENTRIES {
        match cx
            .read(file)
            .map_err(|e| e.to_string())
            .and_then(|t| tokens_of(&t))
        {
            Ok(t) => {
                if holds(&t, &["ctx", ".", "ptr"]) {
                    bad.push(format!(
                        "{file}: a host entry reads a plugin's context as an address (`ctx.ptr`)"
                    ));
                }
                if !holds(&t, &["handle", ":", ":", "resolve", "("]) {
                    bad.push(format!(
                        "{file}: no host entry here resolves its context through `handle::resolve`"
                    ));
                }
            }
            Err(e) => bad.push(format!("{file}: {e}")),
        }
    }
    for (seq, what) in [
        (&["black_box", "("][..], "compares no tag in constant time"),
        (&["revoked", "."][..], "does not refuse a revoked entry"),
        (
            &["ptr", ":", ":", "eq", "("][..],
            "does not hold a crossing to its own instance",
        ),
        (&["count_forgery", "("][..], "counts no forgery"),
    ] {
        need(cx, HANDLE, "resolve_in", seq, what, &mut bad);
    }
    bad
}

/// (c) Ticket generations are the permutation, a mismatched wake is judged by its inverse and
/// blamed on its supplier, and a spent counter retires its slot.
fn ticket(cx: &Ctx) -> Vec<String> {
    let mut bad = Vec::new();
    let clauses: [(&str, &str, &[&str], &str); 7] = [
        (
            HANDLE,
            "ticket_generation",
            &["nonzero_permutation", "("],
            "is not the keyed permutation of the slot's counter",
        ),
        (
            WORKER,
            "mint",
            &["ticket_generation", "("],
            "mints a generation that is not `ticket_generation` of the slot's count",
        ),
        (
            WORKER,
            "ever_minted",
            &["ticket_count", "("],
            "does not judge a generation by the permutation's inverse",
        ),
        (
            WORKER,
            "judge_forgeries",
            &["forged_ticket", "("],
            "does not blame a never-minted generation on its supplier",
        ),
        (
            WORKER,
            "recycle_now",
            &["next_count", "("],
            "re-mints a slot whose counter is spent (no retirement)",
        ),
        (
            WORKER,
            "wake",
            &["forged_ticket", "("],
            "takes a wake for a worker it does not run, or a forged inline ticket, on trust",
        ),
        (
            INLINE,
            "mint",
            &["ticket_generation", "("],
            "mints an inline generation that is not the permutation of its counter",
        ),
    ];
    for (file, f, seq, what) in clauses {
        need(cx, file, f, seq, what, &mut bad);
    }
    // The inline table's own `wake` shares its name with its wakers' `Wake::wake`: read as a file.
    need_file(
        cx,
        INLINE,
        &["ticket_count", "("],
        "does not judge an inline generation by the permutation's inverse",
        &mut bad,
    );
    bad
}

fn row(id: &'static str, ok: &str, bad_title: &str, problems: Vec<String>) -> Row {
    if problems.is_empty() {
        Row::pass(id, ok, "every clause held as lexed code")
    } else {
        Row::fail(id, bad_title, problems.join(" | "))
    }
}

pub struct CallBindingGate;

impl Gate for CallBindingGate {
    fn name(&self) -> &'static str {
        "call-binding"
    }

    fn owed(&self) -> Vec<String> {
        [ROW_IN_PROCESS, ROW_ABI_HANDLE, ROW_TICKET]
            .map(str::to_string)
            .to_vec()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(vec![
            row(
                ROW_IN_PROCESS,
                "every proof the unit loop hands a stage is bound to its call and compared",
                "a proof on the unit loop is not bound to its call",
                in_process(cx),
            ),
            row(
                ROW_ABI_HANDLE,
                "every host entry resolves a plugin's context through the one check",
                "a host entry takes a plugin's context on trust",
                abi_handle(cx),
            ),
            row(
                ROW_TICKET,
                "ticket generations are permuted and a never-minted one is its supplier's forgery",
                "a ticket generation is predictable or unjudged",
                ticket(cx),
            ),
        ])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let read = |f: &str| cx.read(f).unwrap_or_default();
        let probe = read(PROBE);
        let services = read(HOST_ENTRIES[1]);
        let worker = read(WORKER);

        // (a) An unbound pass planted at the head of the probe is named by its line.
        let mut ov = Overlay::new();
        ov.set(
            PROBE,
            format!("fn planted(k: &Kernel) {{ let _ = Pass::<Route>::mint(k.seal()); }}\n{probe}"),
        );
        report.push(prove_red(
            cx,
            self,
            "an unbound pass minted on the unit loop is RED, by its line",
            &[ROW_IN_PROCESS],
            ov,
            &["plane_driver/probe.rs:1:"],
        ));

        // (a2) A call of the kernel's unbound factory in a kernel file no roster ever named (the
        // arrival hold's shape, audit XG #5) is named by its line.
        let inflight = read(INFLIGHT);
        let mut ov = Overlay::new();
        ov.set(
            INFLIGHT,
            format!(
                "fn planted(k: &Kernel) -> Grant<Admittance> {{ k.admit_token() }}\n{inflight}"
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a call of an unbound token factory anywhere in the kernel is RED, by its line",
            &[ROW_IN_PROCESS],
            ov,
            &["busbar-kernel/src/inflight.rs:1:"],
        ));

        // (a3) An off-loop entry that no longer mints is a stale entry, and RED.
        let tick = read(TICK);
        let mut ov = Overlay::new();
        ov.set(
            TICK,
            tick.replace("::mint(kernel.seal())", "::mint_bound(kernel.seal(), call)"),
        );
        report.push(prove_red(
            cx,
            self,
            "an off-loop entry whose fn mints nothing unbound any more is RED",
            &[ROW_IN_PROCESS],
            ov,
            &["`fn sweep_settle` no longer mints"],
        ));

        // (b) A host entry that reads the context as an address again.
        let mut ov = Overlay::new();
        ov.set(
            HOST_ENTRIES[1],
            format!("{services}\nfn planted(ctx: HostCtx) -> bool {{ ctx.ptr.is_null() }}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "a host entry reading a plugin's context as an address is RED",
            &[ROW_ABI_HANDLE],
            ov,
            &["ctx.ptr"],
        ));

        // (c) A wake judged without the inverse: every mismatch read as a late wake.
        let mut ov = Overlay::new();
        ov.set(
            WORKER,
            worker.replacen(
                "super::handle::ticket_count(self.key, self.index, idx, t.generation)",
                "t.generation",
                1,
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a mismatched wake judged without the permutation's inverse is RED",
            &[ROW_TICKET],
            ov,
            &["ever_minted"],
        ));
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat_of(src: &str, skip: bool) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        flat(lex(src).unwrap(), skip, &mut out);
        out
    }

    #[test]
    fn an_unbound_mint_is_found_with_or_without_a_turbofish_and_a_bound_one_is_not() {
        let src = "fn a() {\n let x = Pass::<Route>::mint(s);\n let y = Grant::mint(s);\n \
                   let z = Pass::<Route>::mint_bound(s, c);\n let w = Pass::<A<B>>::mint(s);\n}\n";
        assert_eq!(unbound_mints(&flat_of(src, false)), vec![2, 3, 5]);
    }

    #[test]
    fn the_kernels_own_token_vending_is_off_the_loop() {
        let src = "impl Kernel {\n fn t(&self) -> G { Grant::<A>::mint(&self.seal) }\n}\n\
                   fn l() { Pass::<R>::mint(s); }\n";
        assert_eq!(unbound_mints(&flat_of(src, true)), vec![4]);
        assert_eq!(unbound_mints(&flat_of(src, false)), vec![2, 4]);
    }

    #[test]
    fn a_site_is_named_with_its_fn_and_a_factory_call_counts_as_a_mint() {
        let src = "fn a() {\n if x { Pass::<R>::mint(s); }\n}\nfn b(k: &Kernel) {\n \
                   k.admit_token();\n Kernel::admit_token(k);\n k.admit_token_for(c);\n}\n\
                   fn admit_token() {}\n";
        let factories = vec!["admit_token".to_string()];
        assert_eq!(
            unbound_sites(&flat_of(src, false), &factories),
            vec![
                (2, Some("a".to_string())),
                (5, Some("b".to_string())),
                (6, Some("b".to_string())),
            ]
        );
    }

    #[test]
    fn the_factories_are_read_from_the_impl_kernel_block() {
        let src = "impl Kernel {\n fn t(&self) -> G { Grant::<A>::mint(&self.seal) }\n \
                   fn u(&self, c: C) -> G { Grant::<A>::mint_bound(&self.seal, c) }\n}\n";
        assert_eq!(unbound_factories(src).unwrap(), vec!["t".to_string()]);
    }

    #[test]
    fn production_text_stops_at_the_test_module() {
        let text = "fn a() {}\n#[cfg(test)]\nmod tests { fn b() { Pass::<X>::mint(s); } }\n";
        assert!(!production_text(text).contains("mint"));
    }
}
