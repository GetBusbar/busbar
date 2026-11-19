// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R29 `qualifier-as-plane-key` (LR-128): a door's card/lane qualifier (`""` for the
//! models plane) and a plane key are two string vocabularies; confusing them listed nothing on
//! `/v1/models` (UPG-A20). The qualifier is the `LaneQualifier` type, which neither converts to,
//! derefs to, nor compares with a `&str`; a plane key comes out of it only through
//! `LaneQualifier::plane_key`. This rule pins that the seal stays closed and that the seams use it.

use quote::ToTokens;

use crate::walk;

const DISPATCH: &str = "crates/busbar-kernel/src/plane_driver/dispatch.rs";
const ENDPOINTS: &str = "crates/busbar-kernel/src/endpoints.rs";

/// Trait impls that would let a qualifier pass for a `&str` silently.
const OPEN_DOORS: &[&str] = &[
    "Deref",
    "AsRef",
    "Borrow",
    "PartialEq",
    "PartialOrd",
    "From",
    "Into",
    "Display",
];

#[test]
fn a_lane_qualifier_is_never_a_plane_key() {
    let dispatch = walk::one(DISPATCH);
    assert!(
        dispatch.file.items.iter().any(|i| matches!(
            i,
            syn::Item::Struct(s) if s.ident == "LaneQualifier"
                && matches!(&s.fields, syn::Fields::Unnamed(f)
                    if f.unnamed.iter().all(|f| matches!(f.vis, syn::Visibility::Inherited)))
        )),
        "R29: busbar_kernel::plane_driver::dispatch::LaneQualifier is a newtype with a private field"
    );
    for src in walk::production(&["crates/busbar-kernel/src", "crates/busbar/src"]) {
        for item in walk::items(&src.file.items) {
            let syn::Item::Impl(i) = item else { continue };
            let Some((_, tr, _)) = &i.trait_ else {
                continue;
            };
            // The type itself, by whole identifier (its error type `InvalidLaneQualifier` may Display).
            let is_qualifier = |s: &str| {
                s.split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|w| w == "LaneQualifier")
            };
            let names_qualifier = |t: &syn::Type| is_qualifier(&t.to_token_stream().to_string());
            let generic_args = tr.to_token_stream().to_string();
            let on_qualifier = names_qualifier(&i.self_ty);
            let to_qualifier = is_qualifier(&generic_args);
            let Some(last) = tr.segments.last() else {
                continue;
            };
            let opens = OPEN_DOORS.iter().any(|d| last.ident == d);
            // Derived `PartialEq`/`Eq` between two qualifiers are attributes, not impls here.
            assert!(
                !(opens && (on_qualifier || to_qualifier)),
                "R29: {}:{} opens LaneQualifier to `&str` through `{}`; read the plane through \
                 `plane_key()` or the lane prefix through `lane_prefix()`",
                src.rel,
                walk::line_of(item),
                generic_args
            );
        }
    }

    let endpoints = walk::one(ENDPOINTS);
    let catalog = endpoints
        .file
        .items
        .iter()
        .find_map(|i| match i {
            syn::Item::Fn(f) if f.sig.ident == "catalog_names" => Some(f),
            _ => None,
        })
        .expect("endpoints::catalog_names");
    let third = catalog
        .sig
        .inputs
        .iter()
        .nth(2)
        .map(|a| a.to_token_stream().to_string())
        .unwrap_or_default();
    assert!(
        third.contains("LaneQualifier"),
        "R29: catalog_names takes the door's qualifier as `LaneQualifier`, found `{third}`"
    );

    // Every construction site of a `LaneQualifier` in production is found here, not listed by hand.
    let mut sites = 0;
    for src in walk::production(&["crates/busbar-kernel/src", "crates/busbar/src"]) {
        for item in walk::items(&src.file.items) {
            let (found, faults) = construction_sites(item.to_token_stream());
            sites += found;
            assert!(
                faults.is_empty(),
                "R29: {} builds a LaneQualifier from something other than the card-qualifier \
                 source or `LaneQualifier::default()`: {faults:?}",
                src.rel
            );
        }
    }
    assert!(
        sites > 0,
        "R29: no LaneQualifier construction site found in production; the scan lost its subject"
    );
}

/// Words that mark a plane key or a plane/provider/model name: a qualifier is never built from one.
const KEY_WORDS: &[&str] = &["plane", "key", "name", "fallback"];

/// The `LaneQualifier::<ctor>(..)` calls in `stream` (groups searched in place): how many there
/// are, and the ones that are not `default()` or `parse(..)` over a non-key argument.
fn construction_sites(stream: proc_macro2::TokenStream) -> (usize, Vec<String>) {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let mut found = 0;
    let mut faults = Vec::new();
    for (i, tt) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            let (n, f) = construction_sites(g.stream());
            found += n;
            faults.extend(f);
        }
        let is_path_start = matches!(tt, TokenTree::Ident(id) if id == "LaneQualifier")
            && matches!(trees.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == ':')
            && matches!(trees.get(i + 2), Some(TokenTree::Punct(p)) if p.as_char() == ':');
        if !is_path_start {
            continue;
        }
        let Some(TokenTree::Ident(ctor)) = trees.get(i + 3) else {
            continue;
        };
        found += 1;
        let args = match trees.get(i + 4) {
            Some(TokenTree::Group(g)) => g.stream(),
            _ => proc_macro2::TokenStream::new(),
        };
        let arg_idents = walk::idents(&walk::tokens(&args));
        let keyed = arg_idents.iter().any(|w| {
            let w = w.to_lowercase();
            KEY_WORDS.iter().any(|k| w.contains(k))
        });
        let ok = match ctor.to_string().as_str() {
            "default" => arg_idents.is_empty(),
            "parse" => !keyed,
            _ => false,
        };
        if !ok {
            faults.push(format!("LaneQualifier::{ctor}({args})"));
        }
    }
    (found, faults)
}

#[test]
fn a_planted_plane_key_qualifier_is_caught() {
    let scan = |src: &str| construction_sites(src.parse().expect("fixture parses"));
    let (n, bad) = scan("fn a() { let q = LaneQualifier::parse(plane_key); }");
    assert_eq!((n, bad.len()), (1, 1), "a plane key must be refused");
    let (_, bad) = scan("fn a() { let q = LaneQualifier::parse(fallback_key()); }");
    assert_eq!(bad.len(), 1, "the fallback plane key must be refused");
    let (_, bad) = scan("fn a() { x(|| { LaneQualifier::parse(decl.name) }) }");
    assert_eq!(bad.len(), 1, "a name inside nested groups must be refused");
    let (_, bad) = scan("fn a() { LaneQualifier::from(\"x\") }");
    assert_eq!(bad.len(), 1, "any other constructor must be refused");
    let (n, bad) = scan("fn a() { LaneQualifier::default(); LaneQualifier::parse(card) }");
    assert_eq!((n, bad.len()), (2, 0), "default and a card qualifier pass");
}
