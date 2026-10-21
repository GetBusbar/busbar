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
//! | `admin-config-parity:routes` | the admin router mounts `config/apply` and `config/validate` on those handlers, POST |
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

const HANDLERS: &str = "crates/busbar-core-admin/src/v1/json/handlers.rs";
const ROUTER: &str = "crates/busbar-core-admin/src/v1/json/mod.rs";
const PREPASS: &str = "crates/busbar-kernel/src/config/prepass.rs";
const BOOT: &str = "crates/busbar-kernel/src/appbuild.rs";

/// The one parser both doors run.
const PARSER: &str = "deploy_from_deserializer";
/// The boot loader's text entry to it.
const BOOT_ENTRY: &str = "deploy_from_yaml_str";

/// The admin doors that take a whole config: `(handler, its request body)`.
const DOORS: &[(&str, &str)] = &[
    ("apply_config", "ApplyConfigReq"),
    ("validate_config", "ValidateConfigReq"),
];

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

fn body(cx: &Ctx, file: &str, name: &str) -> Result<Vec<String>, String> {
    let text = cx.read(file).map_err(|e| format!("{file}: {e}"))?;
    let ts = lex(&text).map_err(|e| format!("{file}: {e}"))?;
    let g = group_after(&ts, "fn", name).ok_or_else(|| format!("{file}: no `fn {name}`"))?;
    let mut out = Vec::new();
    flat(g, &mut out);
    Ok(out)
}

/// What is wrong with `fn f` in `file` when its body must hold `seq`: `None` when it does.
fn needs(cx: &Ctx, file: &str, f: &str, seq: &[&str], what: &str) -> Option<String> {
    match body(cx, file, f) {
        Ok(b) if holds(&b, seq) => None,
        Ok(_) => Some(format!("{file}: `fn {f}` {what}")),
        Err(e) => Some(e),
    }
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
    let mut toks = Vec::new();
    match cx
        .read(BOOT)
        .map_err(|e| e.to_string())
        .and_then(|t| lex(&t))
    {
        Ok(ts) => flat(ts, &mut toks),
        Err(e) => bad.push(format!("{BOOT}: {e}")),
    }
    if !holds(&toks, &[BOOT_ENTRY, "("]) {
        bad.push(format!(
            "{BOOT}: boot no longer parses config.yaml through `{BOOT_ENTRY}`"
        ));
    }
    for (handler, _) in DOORS {
        bad.extend(needs(
            cx,
            HANDLERS,
            handler,
            &[PARSER, "("],
            "does not parse its config through the boot loader's `deploy_from_deserializer`: the \
             admin door and the file are two schemas",
        ));
    }
    bad
}

fn whole_document(cx: &Ctx) -> Vec<String> {
    let text = match cx.read(HANDLERS) {
        Ok(t) => t,
        Err(e) => return vec![format!("{HANDLERS}: {e}")],
    };
    let ts = match lex(&text) {
        Ok(ts) => ts,
        Err(e) => return vec![format!("{HANDLERS}: {e}")],
    };
    let mut bad = Vec::new();
    for (_, req) in DOORS {
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
    let mut toks = Vec::new();
    match cx
        .read(ROUTER)
        .map_err(|e| e.to_string())
        .and_then(|t| lex(&t))
    {
        Ok(ts) => flat(ts, &mut toks),
        Err(e) => return vec![format!("{ROUTER}: {e}")],
    }
    let mut bad = Vec::new();
    for (path, handler) in [
        ("\"/config/apply\"", "apply_config"),
        ("PATH_CONFIG_VALIDATE", "validate_config"),
    ] {
        if !holds(
            &toks,
            &["route", "(", path, ",", "post", "(", handler, ")", ")"],
        ) {
            bad.push(format!(
                "{ROUTER}: no `.route({path}, post({handler}))`: the admin door is not mounted"
            ));
        }
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
        [ROW_ONE_PARSER, ROW_WHOLE_DOCUMENT, ROW_ROUTES]
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
        ])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree's two config doors are one schema",
            &[ROW_ONE_PARSER, ROW_WHOLE_DOCUMENT, ROW_ROUTES],
        ));
        let handlers = cx.read(HANDLERS).unwrap_or_default();
        let router = cx.read(ROUTER).unwrap_or_default();
        let prepass = cx.read(PREPASS).unwrap_or_default();
        let plants: [(&str, &str, &str, &str, &str, &str); 5] = [
            (
                "apply parsing a plain-derived DeployCfg instead of the boot parser is RED",
                HANDLERS,
                "busbar_kernel::config::deploy_from_deserializer(req.config, handle.load().doors)",
                "serde_json::from_value::<busbar_kernel::config::DeployCfg>(req.config)",
                ROW_ONE_PARSER,
                "apply_config",
            ),
            (
                "the boot loader leaving the shared parser is RED",
                PREPASS,
                "deploy_from_deserializer(serde_yaml::Deserializer::from_str(text), doors)",
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
        ];
        for (name, file, from, to, row, naming) in plants {
            let base = match file {
                f if f == HANDLERS => &handlers,
                f if f == ROUTER => &router,
                _ => &prepass,
            };
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
