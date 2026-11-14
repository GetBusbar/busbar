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
const DOOR_STEPS: &str = "crates/busbar/src/root/door_steps.rs";

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
            let names_qualifier =
                |t: &syn::Type| t.to_token_stream().to_string().contains("LaneQualifier");
            let generic_args = tr.to_token_stream().to_string();
            let on_qualifier = names_qualifier(&i.self_ty);
            let to_qualifier = generic_args.contains("LaneQualifier");
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

    let door_steps = walk::one(DOOR_STEPS);
    let plane_field = door_steps
        .file
        .items
        .iter()
        .flat_map(walk::named_fields)
        .find(|(ty, f)| ty == "DoorFacts" && f.ident.as_ref().is_some_and(|i| i == "plane"))
        .map(|(_, f)| f.ty.to_token_stream().to_string())
        .unwrap_or_default();
    assert!(
        plane_field.contains("LaneQualifier"),
        "R29: DoorFacts.plane is the door's qualifier, typed `LaneQualifier`, found `{plane_field}`"
    );
}
