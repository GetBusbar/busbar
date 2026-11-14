// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R26 `candidate-hashed-twice` (LR-125): a store candidate is validated and
//! fingerprinted once per side of the ABI, by `PreparedCandidate::new`, which carries the
//! fingerprint with the candidate. The seal is the type:
//!
//! - `Candidate::validate` is not public, so no store, SDK consumer or host code outside
//!   busbar-contract can validate a candidate a second time;
//! - the fingerprint function is private to `persistence.rs` and called only by the constructor;
//! - `control::initialization` takes the `PreparedCandidate` (proof of validation), never a bare
//!   `Candidate`, so recognising a first start does not validate again on every commit.

use quote::ToTokens;

use crate::walk;

const PERSISTENCE: &str = "crates/busbar-contract/src/persistence.rs";
const CONTROL: &str = "crates/busbar-contract/src/persistence/control.rs";

fn impl_fn<'a>(file: &'a syn::File, self_ty: &str, name: &str) -> Option<&'a syn::ImplItemFn> {
    file.items.iter().find_map(|item| {
        let syn::Item::Impl(i) = item else {
            return None;
        };
        let syn::Type::Path(p) = &*i.self_ty else {
            return None;
        };
        if p.path.segments.last()?.ident != self_ty || i.trait_.is_some() {
            return None;
        }
        i.items.iter().find_map(|it| match it {
            syn::ImplItem::Fn(f) if f.sig.ident == name => Some(f),
            _ => None,
        })
    })
}

fn free_fn<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(f) if f.sig.ident == name => Some(f),
        _ => None,
    })
}

#[test]
fn a_candidate_is_validated_and_fingerprinted_only_by_its_prepared_constructor() {
    let persistence = walk::one(PERSISTENCE);
    let validate = impl_fn(&persistence.file, "Candidate", "validate")
        .expect("Candidate::validate is defined in persistence.rs");
    assert!(
        !matches!(validate.vis, syn::Visibility::Public(_)),
        "R26: Candidate::validate is public; validation is reachable only through \
         PreparedCandidate::new, which validates once and carries the fingerprint"
    );

    let fingerprint = free_fn(&persistence.file, "candidate_fingerprint")
        .expect("the one candidate fingerprint function");
    assert!(
        matches!(fingerprint.vis, syn::Visibility::Inherited),
        "R26: candidate_fingerprint must stay private to persistence.rs"
    );
    let calls = persistence
        .file
        .to_token_stream()
        .to_string()
        .matches("candidate_fingerprint (")
        .count();
    assert_eq!(
        calls, 1,
        "R26: candidate_fingerprint is called only by PreparedCandidate::new"
    );

    let control = walk::one(CONTROL);
    let init = free_fn(&control.file, "initialization").expect("control::initialization");
    let first = init
        .sig
        .inputs
        .first()
        .map(|arg| arg.to_token_stream().to_string())
        .unwrap_or_default();
    assert!(
        first.contains("PreparedCandidate"),
        "R26: control::initialization takes `{first}`; it takes the PreparedCandidate, the proof \
         that the candidate is already validated, and never validates again"
    );
    let body = init.block.to_token_stream().to_string();
    assert!(
        !body.contains("validate ("),
        "R26: control::initialization validates the candidate a second time"
    );
}
