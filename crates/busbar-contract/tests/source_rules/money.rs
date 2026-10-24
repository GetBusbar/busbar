// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MONEY IS INTEGERS, A VIEW, AND SEALED BY CORE (Part 2 #44, #77). Three rules over core's
//! production source:
//!
//! - no float on the money path, outside the named places a configured decimal becomes an integer
//!   (the card build) or an integer is handed to a float-only sink (the `/metrics` gauge);
//! - the durable money records store counts, never a price, and are never keyed by a plugin;
//! - the facts line (`Posted::settle`) is sealed only by core.

use proc_macro2::TokenTree;

use crate::walk::{self, Source};

/// The money crates and directories: every production file under them is the money path.
const MONEY_DIRS: &[&str] = &[
    "crates/busbar-kernel-ledger/src",
    "crates/busbar-kernel-audit/src",
    "crates/busbar-kernel-wal/src",
    "crates/busbar-kernel/src/governance",
];

/// Money files that live beside non-money code.
const MONEY_FILES: &[&str] = &[
    "crates/busbar-kernel/src/billing.rs",
    "crates/busbar-kernel/src/cost.rs",
    "crates/busbar-kernel/src/rate_apply.rs",
    "crates/busbar-kernel/src/snapshot/money.rs",
    "crates/busbar-kernel/src/plane_driver/money.rs",
    "crates/busbar/src/root/durability/mod.rs",
    "crates/busbar/src/root/durability/replay.rs",
    "crates/busbar/src/root/durability/book.rs",
    "crates/busbar/src/root/ledger_identity.rs",
    "crates/busbar/src/root/migration.rs",
    "crates/busbar/src/root/kernel.rs",
    "crates/busbar-contract/src/count.rs",
    "crates/busbar-contract/src/records.rs",
];

/// The types a money figure is written through: a production file that names one is a money file.
const MONEY_TYPES: &[&str] = &[
    "RateNanos",
    "RateCard",
    "LedgerEntry",
    "MeteredRow",
    "Posting",
    "PostingKind",
    "PostingFlags",
    "Settling",
    "MoneyBook",
    "SharedBook",
    "AccrualMeter",
    "Posted",
];

/// The functions a float may appear in, by file: the card build's conversions of a configured
/// decimal (#44), the `/metrics` gauge sink (a float-only API, as 1.5.5), and the routing headroom
/// ratio over request/token counts (not money).
const FLOAT_ALLOWED: &[(&str, &str)] = &[
    ("crates/busbar-kernel-ledger/src/cost/rate.rs", "nano_rate"),
    (
        "crates/busbar-kernel-ledger/src/cost/rate.rs",
        "representable_nano_rate",
    ),
    (
        "crates/busbar-kernel-ledger/src/cost/rate.rs",
        "from_micro_rates",
    ),
    ("crates/busbar-kernel/src/snapshot/money.rs", "set_gauge"),
    (
        "crates/busbar-kernel/src/governance/state.rs",
        "rate_headroom",
    ),
];

/// Methods that exist on `f32`/`f64` and on no integer type.
const FLOAT_ONLY_METHODS: &[&str] = &[
    "round",
    "floor",
    "ceil",
    "trunc",
    "fract",
    "mul_add",
    "powf",
    "powi",
    "sqrt",
    "cbrt",
    "ln",
    "ln_1p",
    "log2",
    "log10",
    "exp",
    "exp2",
    "exp_m1",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "atan2",
    "sinh",
    "cosh",
    "tanh",
    "asinh",
    "acosh",
    "atanh",
    "hypot",
    "recip",
    "to_degrees",
    "to_radians",
    "copysign",
    "total_cmp",
    "round_ties_even",
    "is_nan",
    "is_infinite",
    "is_finite",
    "is_normal",
    "is_subnormal",
    "is_sign_positive",
    "is_sign_negative",
];

/// Items declared off the money path that hand their caller a float.
const FLOAT_CARRIERS: &[&str] = &["blended_per_mtok"];

fn is_float_literal(s: &str) -> bool {
    let Some(first) = s.chars().next() else {
        return false;
    };
    if !first.is_ascii_digit() {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("0x") || lower.starts_with("0o") || lower.starts_with("0b") {
        return false;
    }
    if lower.ends_with("f32") || lower.ends_with("f64") {
        return true;
    }
    let int_suffixes = [
        "usize", "isize", "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
    ];
    let digits = int_suffixes
        .iter()
        .find_map(|sfx| lower.strip_suffix(sfx))
        .unwrap_or(&lower);
    digits.contains('.') || digits.contains('e')
}

fn names_float(ident: &str) -> bool {
    ident
        .split('_')
        .any(|seg| matches!(seg.to_ascii_lowercase().as_str(), "f32" | "f64"))
}

/// The float spellings among `toks`.
fn float_hits(toks: &[TokenTree]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        match t {
            TokenTree::Ident(id) => {
                let s = id.to_string();
                let after_dot =
                    i > 0 && matches!(&toks[i - 1], TokenTree::Punct(p) if p.as_char() == '.');
                let called = matches!(toks.get(i + 1), Some(TokenTree::Group(g))
                    if g.delimiter() == proc_macro2::Delimiter::Parenthesis);
                if names_float(&s)
                    || FLOAT_CARRIERS.contains(&s.as_str())
                    || (after_dot && called && FLOAT_ONLY_METHODS.contains(&s.as_str()))
                {
                    out.push(s);
                }
            }
            TokenTree::Literal(l) => {
                let s = l.to_string();
                if is_float_literal(&s) {
                    out.push(s);
                }
            }
            _ => {}
        }
    }
    out
}

fn float_allowed(rel: &str, name: &str) -> bool {
    FLOAT_ALLOWED.iter().any(|(f, n)| *f == rel && *n == name)
}

/// The float findings in one production file, `file:line: spelling`.
fn floats_in(src: &Source) -> Vec<String> {
    let mut out = Vec::new();
    let mut report = |line: usize, hits: Vec<String>| {
        for h in hits {
            out.push(format!("{}:{line}: {h}", src.rel));
        }
    };
    for item in walk::items(&src.file.items) {
        match item {
            syn::Item::Fn(f) => {
                if !float_allowed(&src.rel, &f.sig.ident.to_string()) {
                    report(walk::line_of(&f.sig), float_hits(&walk::tokens(f)));
                }
            }
            syn::Item::Impl(imp) => {
                for ii in &imp.items {
                    if let syn::ImplItem::Fn(f) = ii {
                        if walk::is_cfg_test(&f.attrs)
                            || float_allowed(&src.rel, &f.sig.ident.to_string())
                        {
                            continue;
                        }
                        report(walk::line_of(&f.sig), float_hits(&walk::tokens(f)));
                    } else {
                        report(walk::line_of(ii), float_hits(&walk::tokens(ii)));
                    }
                }
            }
            other => report(walk::line_of(other), float_hits(&walk::tokens(other))),
        }
    }
    out
}

fn names_money_type(src: &Source) -> bool {
    walk::items(&src.file.items).iter().any(|item| {
        walk::idents(&walk::tokens(*item))
            .iter()
            .any(|i| MONEY_TYPES.contains(&i.as_str()))
    })
}

#[test]
fn no_float_on_the_money_path() {
    let mut files: Vec<Source> = walk::production(MONEY_DIRS);
    for rel in MONEY_FILES {
        files.push(walk::one(rel));
    }
    for src in walk::production(&["crates"]) {
        if src.rel.contains("/src/") && names_money_type(&src) {
            files.push(src);
        }
    }
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    files.dedup_by(|a, b| a.rel == b.rel);
    for (rel, name) in FLOAT_ALLOWED {
        let src = walk::one(rel);
        assert!(
            src.text.contains(&format!("fn {name}")),
            "{rel}: the float-allowed fn `{name}` is gone; strike it from FLOAT_ALLOWED"
        );
    }
    let findings: Vec<String> = files.iter().flat_map(floats_in).collect();
    assert!(
        findings.is_empty(),
        "a float on the money path (money is integers; Part 2 #44, #77):\n{}",
        findings.join("\n")
    );
}

#[test]
fn a_float_is_found_in_every_spelling() {
    let src = Source {
        rel: "planted.rs".into(),
        text: String::new(),
        file: syn::parse_file(
            "fn a(x: u64) -> u64 { (x as f64) as u64 }\n\
             fn b() -> u64 { 1.5 as u64 }\n\
             fn c(x: f32) -> u64 { x.round() as u64 }\n\
             fn d(v: &serde_json::Value) -> u64 { v.as_f64().unwrap_or(0) as u64 }\n\
             fn e(r: &R) -> u64 { r.blended_per_mtok() as u64 }\n\
             fn ok(x: u64) -> u64 { x.min(1_000) + 0x1e }\n",
        )
        .expect("parses"),
    };
    let found = floats_in(&src);
    for want in ["f64", "1.5", "round", "as_f64", "blended_per_mtok"] {
        assert!(found.iter().any(|f| f.ends_with(want)), "{want}: {found:?}");
    }
    assert!(!found.iter().any(|f| f.contains(":6:")), "{found:?}");
}

const RECORD_FILES: &[&str] = &[
    "crates/busbar-contract/src/records.rs",
    "crates/busbar-kernel-audit/src/record.rs",
    "crates/busbar-kernel-audit/src/amend.rs",
];

const IDENTITY_TOKENS: &[&str] = &["plugin", "plane"];
const PRICE_TOKENS: &[&str] = &[
    "spend", "price", "priced", "amount", "cents", "nanos", "micros", "dollar", "usd", "cost",
    "fee",
];
/// Pricing provenance or a count, not a stored price.
const PRICE_ALLOW: &[&str] = &["pricing_version", "priced_from_ms", "fee_count"];

/// `needle` is one of `ident`'s `_`-separated words, or anchored at a word edge.
fn token_in_ident(ident: &str, needle: &str) -> bool {
    ident.split('_').any(|seg| seg == needle)
        || ident.starts_with(&format!("{needle}_"))
        || ident.ends_with(&format!("_{needle}"))
}

fn record_findings(src: &Source) -> Vec<String> {
    let mut out = Vec::new();
    for item in walk::items(&src.file.items) {
        for (ty, field) in walk::named_fields(item) {
            let Some(name) = field.ident.as_ref().map(ToString::to_string) else {
                continue;
            };
            if IDENTITY_TOKENS.iter().any(|t| token_in_ident(&name, t)) {
                out.push(format!(
                    "{}: {ty}.{name} keys money by a plugin (#77(1))",
                    src.rel
                ));
            }
            if !PRICE_ALLOW.contains(&name.as_str())
                && PRICE_TOKENS.iter().any(|t| token_in_ident(&name, t))
            {
                out.push(format!(
                    "{}: {ty}.{name} stores a price; a price is read-time (#77(3))",
                    src.rel
                ));
            }
        }
    }
    out
}

#[test]
fn durable_money_records_store_counts_never_a_price_or_a_plugin_key() {
    let findings: Vec<String> = RECORD_FILES
        .iter()
        .flat_map(|rel| record_findings(&walk::one(rel)))
        .collect();
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

#[test]
fn a_stored_price_and_a_plugin_key_are_found() {
    let src = Source {
        rel: "planted.rs".into(),
        text: String::new(),
        file: syn::parse_file(
            "struct R { spend_cents: u64, plugin_id: u32, fee_count: u32, tokens: u64 }",
        )
        .expect("parses"),
    };
    let found = record_findings(&src);
    assert!(found.iter().any(|f| f.contains("spend_cents")), "{found:?}");
    assert!(found.iter().any(|f| f.contains("plugin_id")), "{found:?}");
    assert_eq!(found.len(), 2, "{found:?}");
}

/// Where the facts line may be sealed: core only, never a plugin.
const SEAL_ALLOWED: &[&str] = &[
    "crates/busbar-contract/",
    "crates/busbar-kernel/",
    "crates/busbar-kernel-ledger/",
    "crates/busbar/",
];

fn seals(toks: &[TokenTree]) -> bool {
    toks.windows(5).any(|w| {
        matches!(&w[0], TokenTree::Ident(i) if i == "Posted")
            && matches!(&w[1], TokenTree::Punct(p) if p.as_char() == ':')
            && matches!(&w[2], TokenTree::Punct(p) if p.as_char() == ':')
            && matches!(&w[3], TokenTree::Ident(i) if i == "settle" || i == "settle_late")
            && matches!(&w[4], TokenTree::Group(g) if g.delimiter() == proc_macro2::Delimiter::Parenthesis)
    })
}

#[test]
fn the_facts_line_is_sealed_only_by_core() {
    let mut offenders = Vec::new();
    let mut sites = 0usize;
    let mut repo_files = Vec::new();
    let crates_dir = walk::repo().join("crates");
    for entry in std::fs::read_dir(&crates_dir).expect("crates/").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().join("src").is_dir() && !walk::is_plugin_crate(&format!("crates/{name}/")) {
            repo_files.push(format!("crates/{name}/src"));
        }
    }
    let roots: Vec<&str> = repo_files.iter().map(String::as_str).collect();
    for src in walk::production(&roots) {
        let found = walk::items(&src.file.items)
            .iter()
            .any(|item| seals(&walk::tokens(*item)));
        if !found {
            continue;
        }
        sites += 1;
        if !SEAL_ALLOWED.iter().any(|root| src.rel.starts_with(root)) {
            offenders.push(src.rel.clone());
        }
    }
    assert!(sites > 0, "no `Posted::settle(` site found: the seal moved");
    assert!(
        offenders.is_empty(),
        "the facts line is sealed outside core (#77(2)): {offenders:?}"
    );
}
