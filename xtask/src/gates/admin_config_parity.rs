//! `cargo xtask gate admin-config-parity` — THE ADMIN API AND THE CONFIG FILE ARE ONE SCHEMA.
//!
//! BUSBAR-1.6.0.md Part 2 #52 (OWNER-LOCKED 2026-09-20): "Every config-file setting is ALSO
//! settable live over the admin API; the admin API and the config file are ONE schema (two front
//! doors: file at boot, admin at runtime). A RED-provable build gate fails if any config field lacks
//! a matching admin route, so the two can never drift." The DoD's gate battery (l.2905-2909) names
//! it; no gate held it, so `cargo xtask gate --all` could go green with the two doors apart.
//!
//! THE PARITY IS STRUCTURAL, AND THAT IS WHAT IS HELD. The admin door that takes a config is
//! `POST config/apply` (and its dry run `config/validate`): it carries the WHOLE document, the
//! `config.yaml` deploy block and the `providers.yaml` definitions, and parses the deploy block with
//! the very function the boot loader parses the file with. So every field the file can set, the
//! admin API can set, by construction, and a field added to the file is settable live the day it
//! lands. What could drift is the construction itself, and each way it could is a row:
//!
//! | row | the claim |
//! | --- | --- |
//! | `admin-config-parity:one-parser` | boot parses `config.yaml` through `deploy_from_yaml_str` -> `deploy_from_deserializer`, and both admin handlers (`apply_config`, `validate_config`) parse their `config` through `deploy_from_deserializer` |
//! | `admin-config-parity:whole-document` | both admin request bodies carry `config` as the raw document (`serde_json::Value`, pre-lift: never a plain-derived `DeployCfg`, which refuses every plane section) and the `providers.yaml` map (`ProviderDef`) |
//! | `admin-config-parity:routes` | the admin router mounts every whole-document door's handler, POST |
//! | `admin-config-parity:value-reaches-build` | the value the one parser returned is the value that reaches `resolve` / `build_app_from_config` (boot, `apply_config`) or the service's `validate_config` (the dry run): followed as data through `let` bindings, not matched as a spelling |
//!
//! THE DOORS ARE DERIVED, NOT NAMED: a whole-document door is every request struct of the handlers
//! file that carries both a `config` and a `providers` field, and its handler is the fn that
//! deserialises that struct. A new door is held the day it is written.
//!
//! Read as lexed code (comments and strings are never a call): a body is the brace group after
//! `fn <name>`, a field the tokens after `<name> :` up to its `,`.

use proc_macro2::{Delimiter, TokenStream, TokenTree};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_ONE_PARSER: &str = "admin-config-parity:one-parser";
pub const ROW_WHOLE_DOCUMENT: &str = "admin-config-parity:whole-document";
pub const ROW_ROUTES: &str = "admin-config-parity:routes";
pub const ROW_REACHES: &str = "admin-config-parity:value-reaches-build";

const HANDLERS: &str = "crates/busbar-core-admin/src/v1/json/handlers.rs";
const ROUTER: &str = "crates/busbar-core-admin/src/v1/json/mod.rs";
const PREPASS: &str = "crates/busbar-kernel/src/config/prepass.rs";
const BOOT: &str = "crates/busbar-kernel/src/appbuild.rs";
const BOOT_CONSUMER: &str = "crates/busbar/src/main.rs";
/// The boot loader's fn and the struct it returns the parsed deploy block in.
const BOOT_LOADER: &str = "load_config_from_disk";
const LOADED: &str = "LoadedConfig";
/// The loader call whose result the boot consumer builds from.
const BOOT_BUILD_SINKS: &[&str] = &["resolve", "build_app_from_config"];
/// The doors floor: apply and its dry run. Fewer derived doors means the derivation went blind.
const MIN_DOORS: usize = 2;

/// The one parser both doors run.
const PARSER: &str = "deploy_from_deserializer";
/// The boot loader's text entry to it.
const BOOT_ENTRY: &str = "deploy_from_yaml_str";

/// `src` lexed, or why it does not lex.
fn lex(src: &str) -> Result<TokenStream, String> {
    src.parse::<TokenStream>()
        .map_err(|e| format!("does not lex as Rust: {e}"))
}

/// Every token of `ts`, groups flattened (their delimiters as tokens).
fn flat(ts: TokenStream, out: &mut Vec<String>) {
    for tt in ts {
        match tt {
            TokenTree::Group(g) => {
                let (open, close) = match g.delimiter() {
                    Delimiter::Parenthesis => ("(", ")"),
                    Delimiter::Brace => ("{", "}"),
                    Delimiter::Bracket => ("[", "]"),
                    Delimiter::None => ("", ""),
                };
                if !open.is_empty() {
                    out.push(open.to_string());
                }
                flat(g.stream(), out);
                if !close.is_empty() {
                    out.push(close.to_string());
                }
            }
            TokenTree::Punct(p) => out.push(p.as_char().to_string()),
            TokenTree::Ident(i) => out.push(i.to_string()),
            TokenTree::Literal(l) => out.push(l.to_string()),
        }
    }
}

/// The brace group that follows `<keyword> <name>` at any depth of `ts`: a fn's body or a
/// struct's fields.
fn group_after(ts: &TokenStream, keyword: &str, name: &str) -> Option<TokenStream> {
    let trees: Vec<TokenTree> = ts.clone().into_iter().collect();
    for (i, tt) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            if let Some(found) = group_after(&g.stream(), keyword, name) {
                return Some(found);
            }
        }
        let is = |t: Option<&TokenTree>, s: &str| matches!(t, Some(TokenTree::Ident(x)) if x == s);
        if is(Some(tt), keyword) && is(trees.get(i + 1), name) {
            return trees[i + 2..].iter().find_map(|t| match t {
                TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => Some(g.stream()),
                _ => None,
            });
        }
    }
    None
}

/// The tokens of field `field` in a struct's field group: after `field :`, up to the `,` that ends
/// it (outside any generics).
fn field_tokens(fields: &TokenStream, field: &str) -> Option<Vec<String>> {
    let trees: Vec<TokenTree> = fields.clone().into_iter().collect();
    let at = trees.iter().enumerate().position(|(i, t)| {
        matches!(t, TokenTree::Ident(x) if x == field)
            && matches!(trees.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == ':')
    })?;
    let mut out = Vec::new();
    // `<` `>` are puncts, not groups: a `,` inside a type's generics is not the field's end.
    let mut angle = 0i32;
    for t in &trees[at + 2..] {
        if let TokenTree::Punct(p) = t {
            match p.as_char() {
                '<' => angle += 1,
                '>' => angle -= 1,
                ',' if angle == 0 => break,
                _ => {}
            }
        }
        flat(TokenStream::from(t.clone()), &mut out);
    }
    Some(out)
}

/// Whether `tokens` holds `seq` contiguously.
fn holds(tokens: &[String], seq: &[&str]) -> bool {
    !seq.is_empty()
        && tokens
            .windows(seq.len())
            .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
}

/// What is wrong with `fn f` in `file` when its body must hold `seq`: `None` when it does.
fn needs(cx: &Ctx, file: &str, f: &str, seq: &[&str], what: &str) -> Option<String> {
    let ts = match lexed(cx, file) {
        Ok(ts) => ts,
        Err(e) => return Some(e),
    };
    let mut all = Vec::new();
    fns(&ts, &mut all);
    match all.iter().find(|(n, _)| n == f) {
        Some((_, b)) if holds(b, seq) => None,
        Some(_) => Some(format!("{file}: `fn {f}` {what}")),
        None => Some(format!("{file}: no `fn {f}`")),
    }
}

/// The `struct`s of `ts` at any depth: `(name, field group)`.
fn structs(ts: &TokenStream, out: &mut Vec<(String, TokenStream)>) {
    let trees: Vec<TokenTree> = ts.clone().into_iter().collect();
    for (i, tt) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            structs(&g.stream(), out);
        }
        if matches!(tt, TokenTree::Ident(x) if x == "struct") {
            if let Some(TokenTree::Ident(name)) = trees.get(i + 1) {
                let fields = trees[i + 2..]
                    .iter()
                    .take_while(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ';'))
                    .find_map(|t| match t {
                        TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
                            Some(g.stream())
                        }
                        _ => None,
                    });
                if let Some(f) = fields {
                    out.push((name.to_string(), f));
                }
            }
        }
    }
}

/// Every `fn` of `ts` at any depth: `(name, flattened body)`.
fn fns(ts: &TokenStream, out: &mut Vec<(String, Vec<String>)>) {
    let trees: Vec<TokenTree> = ts.clone().into_iter().collect();
    for (i, tt) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            fns(&g.stream(), out);
        }
        if matches!(tt, TokenTree::Ident(x) if x == "fn") {
            if let Some(TokenTree::Ident(name)) = trees.get(i + 1) {
                let body = trees[i + 2..]
                    .iter()
                    .take_while(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ';'))
                    .find_map(|t| match t {
                        TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
                            Some(g.stream())
                        }
                        _ => None,
                    });
                if let Some(b) = body {
                    let mut toks = Vec::new();
                    flat(b, &mut toks);
                    out.push((name.to_string(), toks));
                }
            }
        }
    }
}

fn lexed(cx: &Ctx, file: &str) -> Result<TokenStream, String> {
    let text = cx.read(file).map_err(|e| format!("{file}: {e}"))?;
    lex(&text).map_err(|e| format!("{file}: {e}"))
}

/// One whole-document door: its request struct and the handler that deserialises it.
struct Door {
    req: String,
    handler: String,
    /// The binding the handler gives the request: `let <var>: <req> = ...`.
    var: String,
}

/// The doors, DERIVED from the handlers file: every struct carrying both `config` and `providers`.
fn doors(cx: &Ctx) -> Result<Vec<Door>, Vec<String>> {
    let ts = lexed(cx, HANDLERS).map_err(|e| vec![e])?;
    let mut all = Vec::new();
    structs(&ts, &mut all);
    let mut handlers = Vec::new();
    fns(&ts, &mut handlers);
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for (req, fields) in &all {
        if field_tokens(fields, "config").is_none() || field_tokens(fields, "providers").is_none() {
            continue;
        }
        // The handler: the fn holding `let <var> : <req> =`.
        let found = handlers.iter().find_map(|(name, toks)| {
            toks.windows(5)
                .find(|w| w[0] == "let" && w[2] == ":" && w[3] == *req && w[4] == "=")
                .map(|w| (name.clone(), w[1].clone()))
        });
        match found {
            Some((handler, var)) => out.push(Door {
                req: req.clone(),
                handler,
                var,
            }),
            None => bad.push(format!(
                "{HANDLERS}: whole-document door `{req}` is deserialised by no handler"
            )),
        }
    }
    if out.len() + bad.len() < MIN_DOORS {
        bad.push(format!(
            "{HANDLERS}: {} whole-document door(s) found, at least {MIN_DOORS} (apply and its dry \
             run) are owed: the derivation has gone blind",
            out.len() + bad.len()
        ));
    }
    if bad.is_empty() {
        Ok(out)
    } else {
        Err(bad)
    }
}

// ── DATA FLOW OVER LEXED CODE ────────────────────────────────────────────────────────────────────

/// One `let` statement: the bindings its pattern introduces and the token range of its value.
struct Let {
    binds: Vec<String>,
    expr: std::ops::Range<usize>,
}

fn lets(t: &[String]) -> Vec<Let> {
    let mut out = Vec::new();
    for (i, tok) in t.iter().enumerate() {
        if tok != "let" {
            continue;
        }
        let mut depth = 0i32;
        let mut j = i + 1;
        let mut pat_end = None;
        while j < t.len() {
            match t[j].as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => depth -= 1,
                "=" if depth == 0 => {
                    pat_end = Some(j);
                    break;
                }
                ";" if depth == 0 => break,
                _ => {}
            }
            if depth < 0 {
                break;
            }
            j += 1;
        }
        let Some(eq) = pat_end else { continue };
        // The type ascription (`: T` at depth 0) is not a binding.
        let mut d = 0i32;
        let mut cut = eq;
        for (k, tk) in t.iter().enumerate().take(eq).skip(i + 1) {
            match tk.as_str() {
                "(" | "[" | "{" => d += 1,
                ")" | "]" | "}" => d -= 1,
                ":" if d == 0 => {
                    cut = k;
                    break;
                }
                _ => {}
            }
        }
        let binds = bindings(&t[i + 1..cut]);
        // `if let P = e {` / `while let`: the value ends where the body block opens.
        let conditional = i > 0 && matches!(t[i - 1].as_str(), "if" | "while" | "&&");
        let mut depth = 0i32;
        let mut end = t.len();
        for (k, tk) in t.iter().enumerate().skip(eq + 1) {
            if conditional && depth == 0 && tk == "{" {
                end = k;
                break;
            }
            match tk.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => depth -= 1,
                ";" if depth == 0 => {
                    end = k;
                    break;
                }
                _ => {}
            }
            if depth < 0 {
                end = k;
                break;
            }
        }
        // `let (a, b) = (x, y);` binds POSITIONALLY: `a` carries `x` and nothing of `y`.
        if let (Some(ps), Some(es)) = (split_tuple(t, i + 1..cut), split_tuple(t, eq + 1..end)) {
            if ps.len() == es.len() && ps.len() > 1 {
                for (p, e) in ps.into_iter().zip(es) {
                    out.push(Let {
                        binds: bindings(&t[p]),
                        expr: e,
                    });
                }
                continue;
            }
        }
        out.push(Let {
            binds,
            expr: eq + 1..end,
        });
    }
    out
}

/// The element ranges of `t[range]` when it is exactly one parenthesised tuple `( a , b , .. )`.
fn split_tuple(t: &[String], range: std::ops::Range<usize>) -> Option<Vec<std::ops::Range<usize>>> {
    let (lo, hi) = (range.start, range.end);
    if hi <= lo + 1 || t[lo] != "(" || t[hi - 1] != ")" {
        return None;
    }
    let mut depth = 0i32;
    let mut parts = Vec::new();
    let mut from = lo + 1;
    for (k, tk) in t.iter().enumerate().take(hi).skip(lo) {
        match tk.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 && k != hi - 1 {
                    return None;
                }
            }
            "," if depth == 1 => {
                parts.push(from..k);
                from = k + 1;
            }
            _ => {}
        }
    }
    if from < hi - 1 {
        parts.push(from..hi - 1);
    }
    Some(parts)
}

/// The identifiers a pattern binds.
fn bindings(pat: &[String]) -> Vec<String> {
    pat.iter()
        .filter(|x| {
            x.chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && !matches!(x.as_str(), "mut" | "ref" | "_" | "box")
        })
        .cloned()
        .collect()
}

/// The identifiers that carry the value `seed` selects: every `let` whose value holds a seed
/// expression binds it, and every `let` whose value reads a carrier binds its names too; a closure
/// handed a carrier through `.and_then(|p| ..)` / `.map(|p| ..)` carries it in `p`.
fn carriers(t: &[String], seed: &dyn Fn(&[String]) -> bool) -> std::collections::BTreeSet<String> {
    let ls = lets(t);
    let mut set = std::collections::BTreeSet::new();
    for l in &ls {
        if seed(&t[l.expr.clone()]) {
            set.extend(l.binds.iter().cloned());
        }
    }
    loop {
        let before = set.len();
        for l in &ls {
            let e = &t[l.expr.clone()];
            if e.iter().any(|x| set.contains(x)) {
                set.extend(l.binds.iter().cloned());
                for (k, w) in e.windows(4).enumerate() {
                    let reads = e[..k].iter().any(|x| set.contains(x));
                    if reads
                        && w[0] == "."
                        && matches!(w[1].as_str(), "and_then" | "map" | "then")
                        && w[2] == "("
                        && w[3] == "|"
                    {
                        for p in e[k + 4..].iter().take_while(|x| *x != "|") {
                            if p != "mut" {
                                set.insert(p.clone());
                            }
                        }
                    }
                }
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

/// The token runs between `<name> <open>` and its match, for every occurrence of the call.
fn call_args<'a>(t: &'a [String], name: &str, open: &str) -> Vec<&'a [String]> {
    let close = if open == "(" { ")" } else { "}" };
    let mut out = Vec::new();
    for (i, w) in t.windows(2).enumerate() {
        if w[0] == name && w[1] == open {
            let mut depth = 0i32;
            for (k, tk) in t.iter().enumerate().skip(i + 1) {
                if tk == open {
                    depth += 1;
                } else if tk == close {
                    depth -= 1;
                    if depth == 0 {
                        out.push(&t[i + 2..k]);
                        break;
                    }
                }
            }
        }
    }
    out
}

/// The FIRST argument of every call to `name`: the value the call is about. A call that merely
/// shares a carrier in a later argument (the providers map beside the deploy block) is not it.
fn first_args<'a>(t: &'a [String], name: &str) -> Vec<&'a [String]> {
    call_args(t, name, "(")
        .into_iter()
        .map(|a| {
            let mut depth = 0i32;
            for (k, tk) in a.iter().enumerate() {
                match tk.as_str() {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => depth -= 1,
                    "," if depth == 0 => return &a[..k],
                    _ => {}
                }
            }
            a
        })
        .collect()
}

/// The value of field `field` in a struct literal's tokens (`field: expr,` or the shorthand
/// `field,`), as the tokens that make it.
fn literal_field(lit: &[String], field: &str) -> Option<Vec<String>> {
    let mut depth = 0i32;
    let mut k = 0;
    while k < lit.len() {
        match lit[k].as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth -= 1,
            _ => {}
        }
        if depth == 0 && lit[k] == field && (k == 0 || lit[k - 1] == ",") {
            if k + 1 >= lit.len() || lit[k + 1] == "," {
                return Some(vec![field.to_string()]);
            }
            if lit[k + 1] == ":" {
                let mut d = 0i32;
                let mut out = Vec::new();
                for tk in &lit[k + 2..] {
                    match tk.as_str() {
                        "(" | "[" | "{" => d += 1,
                        ")" | "]" | "}" => d -= 1,
                        "," if d == 0 => break,
                        _ => {}
                    }
                    out.push(tk.clone());
                }
                return Some(out);
            }
        }
        k += 1;
    }
    None
}

/// Whether `args` reads a carrier.
fn reads(args: &[String], carry: &std::collections::BTreeSet<String>) -> bool {
    args.iter().any(|x| carry.contains(x))
}

/// The seed of an admin door: `let _ = ... deploy_from_deserializer ( <var> . config ) ...`.
fn admin_seed(var: &str) -> impl Fn(&[String]) -> bool + '_ {
    move |e: &[String]| holds(e, &[PARSER, "(", var, ".", "config", ")"])
}

fn one_parser(cx: &Ctx) -> Vec<String> {
    let mut bad: Vec<String> = Vec::new();
    bad.extend(needs(
        cx,
        PREPASS,
        BOOT_ENTRY,
        &[PARSER, "("],
        "no longer parses through `deploy_from_deserializer`",
    ));
    // Boot: the loader parses the file's text through the entry, and keeps the value.
    match lexed(cx, BOOT) {
        Ok(ts) => {
            let mut f = Vec::new();
            fns(&ts, &mut f);
            match f.iter().find(|(n, _)| n == BOOT_LOADER) {
                Some((_, body)) => {
                    let seed = |e: &[String]| holds(e, &[BOOT_ENTRY, "("]);
                    if !lets(body).iter().any(|l| seed(&body[l.expr.clone()])) {
                        bad.push(format!(
                            "{BOOT}: `fn {BOOT_LOADER}` no longer binds the result of \
                             `{BOOT_ENTRY}`: boot is not parsing config.yaml through the one parser"
                        ));
                    }
                }
                None => bad.push(format!("{BOOT}: no `fn {BOOT_LOADER}`")),
            }
        }
        Err(e) => bad.push(e),
    }
    match doors(cx) {
        Err(e) => bad.extend(e),
        Ok(ds) => {
            let ts = match lexed(cx, HANDLERS) {
                Ok(ts) => ts,
                Err(e) => return vec![e],
            };
            let mut f = Vec::new();
            fns(&ts, &mut f);
            for d in &ds {
                let body = f
                    .iter()
                    .find(|(n, _)| *n == d.handler)
                    .map(|(_, b)| b.as_slice())
                    .unwrap_or(&[]);
                let seed = admin_seed(&d.var);
                if !lets(body).iter().any(|l| seed(&body[l.expr.clone()])) {
                    bad.push(format!(
                        "{HANDLERS}: `fn {}` does not bind `{PARSER}({}.config)`: the admin door \
                         does not parse the request's document with the boot loader's parser, so \
                         the door and the file are two schemas",
                        d.handler, d.var
                    ));
                }
            }
        }
    }
    bad
}

fn whole_document(cx: &Ctx) -> Vec<String> {
    let ds = match doors(cx) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let ts = match lexed(cx, HANDLERS) {
        Ok(ts) => ts,
        Err(e) => return vec![e],
    };
    let mut bad = Vec::new();
    for Door { req, .. } in &ds {
        let Some(fields) = group_after(&ts, "struct", req) else {
            bad.push(format!("{HANDLERS}: no `struct {req}`"));
            continue;
        };
        match field_tokens(&fields, "config") {
            Some(t)
                if t.last().is_some_and(|l| l == "Value")
                    && !t.iter().any(|x| x == "DeployCfg") => {}
            Some(t) => bad.push(format!(
                "{HANDLERS}: `{req}.config` is `{}`, not the raw document: a typed body refuses \
                 the sections the boot pre-pass lifts",
                t.join("")
            )),
            None => bad.push(format!("{HANDLERS}: `{req}` carries no `config`")),
        }
        match field_tokens(&fields, "providers") {
            Some(t) if t.iter().any(|x| x == "ProviderDef") => {}
            _ => bad.push(format!(
                "{HANDLERS}: `{req}` carries no `providers` map of `ProviderDef`: the \
                 providers.yaml half of the config is not settable live"
            )),
        }
    }
    bad
}

fn routes(cx: &Ctx) -> Vec<String> {
    let ds = match doors(cx) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let mut toks = Vec::new();
    match lexed(cx, ROUTER) {
        Ok(ts) => flat(ts, &mut toks),
        Err(e) => return vec![e],
    }
    let mut bad = Vec::new();
    for d in &ds {
        let mounted = toks.windows(9).any(|w| {
            w[0] == "route"
                && w[1] == "("
                && w[3] == ","
                && w[4] == "post"
                && w[5] == "("
                && w[6] == d.handler
                && w[7] == ")"
                && w[8] == ")"
        });
        if !mounted {
            bad.push(format!(
                "{ROUTER}: no `.route(<path>, post({}))`: the admin door is not mounted",
                d.handler
            ));
        }
    }
    bad
}

/// THE VALUE REACHES THE BUILD (XG#12). Token spelling proves a parser is named somewhere in a
/// handler; this follows what it returned.
fn value_reaches_build(cx: &Ctx) -> Vec<String> {
    let mut bad = Vec::new();
    // Boot, half one: the loader hands the parsed deploy block back in `LoadedConfig`.
    match lexed(cx, BOOT) {
        Ok(ts) => {
            let mut f = Vec::new();
            fns(&ts, &mut f);
            match f.iter().find(|(n, _)| n == BOOT_LOADER) {
                Some((_, body)) => {
                    let seed = |e: &[String]| holds(e, &[BOOT_ENTRY, "("]);
                    let carry = carriers(body, &seed);
                    let lits = call_args(body, LOADED, "{");
                    if lits.is_empty() {
                        bad.push(format!("{BOOT}: `fn {BOOT_LOADER}` builds no `{LOADED}`"));
                    }
                    for lit in lits {
                        let value = literal_field(lit, "deploy");
                        if !value.as_deref().is_some_and(|v| reads(v, &carry)) {
                            bad.push(format!(
                                "{BOOT}: a `{LOADED}` leaves `fn {BOOT_LOADER}` with a `deploy` that is \
                                 not the value `{BOOT_ENTRY}` parsed"
                            ));
                        }
                    }
                }
                None => bad.push(format!("{BOOT}: no `fn {BOOT_LOADER}`")),
            }
        }
        Err(e) => bad.push(e),
    }
    // Boot, half two: the consumer builds from what the loader returned.
    match lexed(cx, BOOT_CONSUMER) {
        Ok(ts) => {
            let mut f = Vec::new();
            fns(&ts, &mut f);
            let seed = |e: &[String]| holds(e, &[BOOT_LOADER, "("]);
            let mut best: Option<Vec<String>> = None;
            let mut seen = false;
            for (name, body) in &f {
                if !lets(body).iter().any(|l| seed(&body[l.expr.clone()])) {
                    continue;
                }
                seen = true;
                let carry = carriers(body, &seed);
                let missing: Vec<String> = BOOT_BUILD_SINKS
                    .iter()
                    .filter(|s| !first_args(body, s).iter().any(|a| reads(a, &carry)))
                    .map(|s| format!("{BOOT_CONSUMER}: `fn {name}` loads the config but `{s}(..)` never reads the loaded value"))
                    .collect();
                if missing.is_empty() {
                    best = None;
                    seen = true;
                    break;
                }
                best = Some(missing);
            }
            if !seen {
                bad.push(format!("{BOOT_CONSUMER}: no fn binds `{BOOT_LOADER}(..)`"));
            } else if let Some(m) = best {
                bad.extend(m);
            }
        }
        Err(e) => bad.push(e),
    }
    // The admin doors: the value the parser returned reaches the build (apply) or the dry run.
    match (doors(cx), lexed(cx, HANDLERS)) {
        (Ok(ds), Ok(ts)) => {
            let mut f = Vec::new();
            fns(&ts, &mut f);
            for d in &ds {
                let Some((_, body)) = f.iter().find(|(n, _)| *n == d.handler) else {
                    continue;
                };
                let seed = admin_seed(&d.var);
                let carry = carriers(body, &seed);
                let hit = |s: &str| first_args(body, s).iter().any(|a| reads(a, &carry));
                // A door either builds the app from the parsed value (resolve, then
                // build_app_from_config) or hands it to the service's dry run.
                let builds = BOOT_BUILD_SINKS.iter().all(|s| hit(s));
                if !(builds || hit("validate_config")) {
                    bad.push(format!(
                        "{HANDLERS}: `fn {}` parses the document but neither `resolve(..)` and \
                         `build_app_from_config(..)` nor `validate_config(..)` takes the parsed \
                         value as its subject: what the door accepts is not what it builds",
                        d.handler
                    ));
                }
            }
        }
        (Err(e), _) => bad.extend(e),
        (_, Err(e)) => bad.push(e),
    }
    bad
}

fn row(id: &'static str, ok: &str, bad_title: &str, problems: Vec<String>) -> Row {
    if problems.is_empty() {
        Row::pass(id, ok, "every clause held as lexed code".to_string())
    } else {
        Row::fail(id, bad_title, problems.join(" | "))
    }
}

pub struct AdminConfigParityGate;

impl Gate for AdminConfigParityGate {
    fn name(&self) -> &'static str {
        "admin-config-parity"
    }

    fn owed(&self) -> Vec<String> {
        [ROW_ONE_PARSER, ROW_WHOLE_DOCUMENT, ROW_ROUTES, ROW_REACHES]
            .map(str::to_string)
            .to_vec()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(vec![
            row(
                ROW_ONE_PARSER,
                "boot and both admin config doors parse with the one parser",
                "the admin config door and the config file parse two ways",
                one_parser(cx),
            ),
            row(
                ROW_WHOLE_DOCUMENT,
                "both admin config doors take the whole document, config and providers",
                "an admin config door takes less than the whole document",
                whole_document(cx),
            ),
            row(
                ROW_ROUTES,
                "the admin router mounts config/apply and config/validate",
                "an admin config door is not mounted",
                routes(cx),
            ),
            row(
                ROW_REACHES,
                "the parsed deploy block is the value boot and both admin doors build from",
                "a parsed deploy block does not reach the build it was parsed for",
                value_reaches_build(cx),
            ),
        ])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree's two config doors are one schema",
            &[ROW_ONE_PARSER, ROW_WHOLE_DOCUMENT, ROW_ROUTES, ROW_REACHES],
        ));
        let plants: [(&str, &str, &str, &str, &str, &str); 11] = [
            (
                "apply parsing a plain-derived DeployCfg instead of the boot parser is RED",
                HANDLERS,
                "busbar_kernel::config::deploy_from_deserializer(req.config)",
                "serde_json::from_value::<busbar_kernel::config::DeployCfg>(req.config)",
                ROW_ONE_PARSER,
                "apply_config",
            ),
            (
                "the boot loader leaving the shared parser is RED",
                PREPASS,
                "deploy_from_deserializer(serde_yaml::Deserializer::from_str(text))",
                "serde_yaml::from_str::<DeployCfg>(text)",
                ROW_ONE_PARSER,
                BOOT_ENTRY,
            ),
            (
                "a typed DeployCfg request body is RED",
                HANDLERS,
                "    /// The deploy config (operator-owned `config.yaml` shape), pre-lift.\n    config: serde_json::Value,",
                "    /// The deploy config (operator-owned `config.yaml` shape), pre-lift.\n    config: busbar_kernel::config::DeployCfg,",
                ROW_WHOLE_DOCUMENT,
                ".config",
            ),
            (
                "a door that drops the providers.yaml half is RED",
                HANDLERS,
                "providers: std::collections::HashMap<String, busbar_kernel::config::ProviderDef>,",
                "providers: std::collections::HashMap<String, serde_json::Value>,",
                ROW_WHOLE_DOCUMENT,
                "providers",
            ),
            (
                "an unmounted config/apply is RED",
                ROUTER,
                ".route(\"/config/apply\", post(apply_config))",
                ".route(\"/config/apply\", post(reload_config))",
                ROW_ROUTES,
                "apply_config",
            ),
            (
                "apply parsing the document and then resolving a DIFFERENT value is RED",
                HANDLERS,
                "let next = busbar_kernel::config::resolve(&deploy, &providers)",
                "let next = busbar_kernel::config::resolve(&Default::default(), &providers)",
                ROW_REACHES,
                "apply_config",
            ),
            (
                "validate parsing the document and dry-running a DIFFERENT value is RED",
                HANDLERS,
                ".validate_config(deploy, req.providers)",
                ".validate_config(Default::default(), req.providers)",
                ROW_REACHES,
                "validate_config",
            ),
            (
                "boot resolving a different value than the one it loaded is RED",
                BOOT_CONSUMER,
                "config::resolve(&deploy, &defs)",
                "config::resolve(&Default::default(), &defs)",
                ROW_REACHES,
                "resolve",
            ),
            (
                "the loader returning a deploy block other than the one it parsed is RED",
                BOOT,
                "return Ok(LoadedConfig {\n            deploy,",
                "return Ok(LoadedConfig {\n            deploy: Default::default(),",
                ROW_REACHES,
                "LoadedConfig",
            ),
            (
                "a NEW whole-document door nobody named is still held: no handler is RED",
                HANDLERS,
                "pub(crate) struct ValidateConfigReq {",
                "pub(crate) struct RoguePlantedReq {\n    config: serde_json::Value,\n    providers: std::collections::HashMap<String, busbar_kernel::config::ProviderDef>,\n}\n\n#[derive(serde::Deserialize)]\npub(crate) struct ValidateConfigReq {",
                ROW_ONE_PARSER,
                "RoguePlantedReq",
            ),
            (
                "the dry run no longer parsing the request's document with the one parser is RED",
                HANDLERS,
                "busbar_kernel::config::deploy_from_deserializer(req.config) {\n            Ok(d) => d,\n            Err(e) => {\n                return err_json(&AdminError::Validation(format!(\n                    \"malformed config body: {e}\"\n                )))\n            }\n        };\n    respond(",
                "busbar_kernel::config::deploy_from_deserializer(serde_json::Value::Null) {\n            Ok(d) => d,\n            Err(e) => {\n                return err_json(&AdminError::Validation(format!(\n                    \"malformed config body: {e}\"\n                )))\n            }\n        };\n    respond(",
                ROW_ONE_PARSER,
                "validate_config",
            ),
        ];
        for (name, file, from, to, row, naming) in plants {
            let base = cx.read(file).unwrap_or_default();
            let mut ov = Overlay::new();
            ov.set(file, base.replacen(from, to, 1));
            report.push(prove_red(cx, self, name, &[row], ov, &[naming]));
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fn_body_and_a_struct_field_are_read_as_code() {
        let src = "mod m { pub(crate) async fn apply(x: u8) -> u8 { /* parse(no) */ parse(x) } \
                   struct Req { config: serde_json::Value, providers: Map<String, ProviderDef>, x: u8 } }";
        let ts = lex(src).unwrap();
        let mut b = Vec::new();
        flat(group_after(&ts, "fn", "apply").unwrap(), &mut b);
        assert!(holds(&b, &["parse", "("]));
        let fields = group_after(&ts, "struct", "Req").unwrap();
        assert_eq!(
            field_tokens(&fields, "config")
                .unwrap()
                .last()
                .map(String::as_str),
            Some("Value")
        );
        assert!(field_tokens(&fields, "providers")
            .unwrap()
            .iter()
            .any(|t| t == "ProviderDef"));
        assert!(field_tokens(&fields, "absent").is_none());
    }
}
