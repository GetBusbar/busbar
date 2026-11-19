// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane-agnostic-auth` (owner directive ANON-PLANES, 19 Nov: "planes are not related to auth"):
//! core's auth, admission and config validation name no plane. Whatever a chain does for one plane
//! (an empty chain refused, `[anonymous]` served and narrowed by `role_bindings.anonymous`) it does
//! for every plane, because no code path there can tell the planes apart: anything a plane needs
//! from auth is a generic, plugin-declared property (its route record, its scope kinds, its
//! HANDLE), handled identically for each.
//!
//! The rule reads the production items of those modules (doc text excluded: a comment may say
//! which plane an example comes from) and refuses any identifier or string literal that names a
//! plane or a plane-only section key. The rule's own planted source shows it bites.

use proc_macro2::{Delimiter, TokenTree};
use quote::ToTokens;

use crate::walk;

/// Core's auth, admission and config-validation sources: directories, then single files.
const DIRS: &[&str] = &[
    "crates/busbar-kernel/src/auth",
    "crates/busbar-kernel/src/config_validate",
    "crates/busbar-kernel/src/inbound",
];
const FILES: &[&str] = &[
    "crates/busbar-kernel/src/inbound.rs",
    "crates/busbar/src/root/min3_auth.rs",
    "crates/busbar/src/root/min3_listener_plan.rs",
];

/// The planes and their plane-only section keys (`tools:` is MCP's, `agents:` A2A's). `pools` is
/// core's (money and routing), not a plane's, and is not listed.
const PLANE_WORDS: &[&str] = &[
    "mcp",
    "a2a",
    "llm",
    "decisions",
    "streaming",
    "tools",
    "agents",
];

/// Whether `text` has a word (split on anything that is not a letter or digit) naming a plane.
fn names_a_plane(text: &str) -> Option<&'static str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .find_map(|word| {
            let word = word.to_ascii_lowercase();
            PLANE_WORDS.iter().copied().find(|plane| *plane == word)
        })
}

/// Every identifier and string literal of `file`'s production items that names a plane, as
/// `line: word in <token>`. A `#[doc = ".."]` attribute's text is skipped.
fn violations(file: &syn::File) -> Vec<String> {
    let mut found = Vec::new();
    for item in walk::items(&file.items) {
        let line = walk::line_of(item);
        scan(item.to_token_stream(), line, &mut found);
    }
    found
}

fn scan(stream: proc_macro2::TokenStream, line: usize, found: &mut Vec<String>) {
    let toks: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            // `# [doc = ".."]` (and `#![doc ..]`): the bracket group after a `#` whose first token is `doc`.
            TokenTree::Punct(p) if p.as_char() == '#' => {
                let at = if matches!(toks.get(i + 1), Some(TokenTree::Punct(b)) if b.as_char() == '!')
                {
                    i + 2
                } else {
                    i + 1
                };
                if let Some(TokenTree::Group(g)) = toks.get(at) {
                    let is_doc = g.delimiter() == Delimiter::Bracket
                        && matches!(g.stream().into_iter().next(), Some(TokenTree::Ident(id)) if id == "doc");
                    if !is_doc {
                        scan(g.stream(), line, found);
                    }
                    i = at + 1;
                    continue;
                }
            }
            TokenTree::Group(g) => scan(g.stream(), line, found),
            TokenTree::Ident(id) => {
                let text = id.to_string();
                if let Some(word) = names_a_plane(&text) {
                    found.push(format!("{line}: `{word}` in identifier `{text}`"));
                }
            }
            TokenTree::Literal(lit) => {
                let text = lit.to_string();
                if text.contains('"') {
                    if let Some(word) = names_a_plane(&text) {
                        found.push(format!("{line}: `{word}` in literal {text}"));
                    }
                }
            }
            TokenTree::Punct(_) => {}
        }
        i += 1;
    }
}

#[test]
fn core_auth_and_config_validation_name_no_plane() {
    let mut sources = walk::production(DIRS);
    sources.extend(FILES.iter().map(|rel| walk::one(rel)));
    assert!(sources.len() > FILES.len(), "the scan lost its subject");
    let mut all = Vec::new();
    for src in &sources {
        for v in violations(&src.file) {
            all.push(format!("{}:{v}", src.rel));
        }
    }
    assert!(
        all.is_empty(),
        "plane-agnostic-auth: core's auth/admission/validation names a plane; auth is \
         plane-agnostic, so a plane's need is a generic plugin-declared property:\n{}",
        all.join("\n")
    );
}

/// The rule bites: a planted plane-specific refusal (the retired BUSBAR-3116 shape) and a branch on
/// a plane's route are found; the same decision with the plane named only in doc text is not.
#[test]
fn the_rule_finds_a_planted_plane_specific_auth_branch() {
    let planted = syn::parse_file(
        r#"
        /// Refuses the MCP plane when the chain is empty.
        fn refuse(cfg: &Cfg) -> Result<(), String> {
            if cfg.sections.contains_key("tools") && cfg.auth.chain.is_empty() {
                return Err("open to anonymous".into());
            }
            Ok(())
        }
        fn mounted(route: &Route) -> bool {
            !(route.plane == Plane::A2a && route.anonymous)
        }
        "#,
    )
    .expect("the planted source parses");
    let found = violations(&planted);
    assert!(
        found.iter().any(|v| v.contains("`tools` in literal")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v.contains("`a2a` in identifier `A2a`")),
        "{found:?}"
    );
    let clean = syn::parse_file(
        r#"
        /// A route the MCP and A2A planes declare as keeping state per caller.
        fn mounted(route: &Route) -> bool {
            route.admitted()
        }
        "#,
    )
    .expect("the clean source parses");
    assert_eq!(violations(&clean), Vec::<String>::new());
}
