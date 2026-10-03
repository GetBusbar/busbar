// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROOF THAT THE TRUST VERB SURFACE IS ONE SURFACE.
//!
//! The mounted behaviour of each plane's verbs is driven over the REAL router where it lives
//! (`mcp/tests/adminverbs_tests.rs`, `a2a/tests/adminverbs_tests.rs`). What those cannot prove is
//! what this file exists for: that there is one surface above them, that its refusal and its audit
//! naming are DERIVED from the plane rather than written per plane, and that it contains no branch
//! on which plane it is serving.

use super::*;

/// EVERY PLANE KEY THIS TREE SHIPS, read off the workspace rather than written here: each
/// `crates/busbar-plane-<key>` directory is one plane (the same derivation `cargo xtask gate
/// plane-purity` uses for its vocabulary). A list typed into this file would itself name the planes
/// the ratchet exists to keep out of the shared surface — and would miss the next plane to land.
fn shipped_plane_keys() -> Vec<String> {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the kernel crate sits inside the workspace `crates/` directory");
    let mut keys: Vec<String> = std::fs::read_dir(crates_dir)
        .expect("the workspace `crates/` directory is readable")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("busbar-plane-"))
                .map(str::to_string)
        })
        .collect();
    keys.sort();
    // A derivation that found nothing would make both ratchets below pass on any source at all.
    assert!(
        keys.len() >= 2,
        "the plane roster read off `crates/busbar-plane-*` is {keys:?} — too small to be the tree"
    );
    keys
}

/// A plane key as code spells it: lowercase (`key`), Capitalised (a type or variant) and UPPERCASE
/// (a constant or acronym).
fn spellings(key: &str) -> [String; 3] {
    let mut chars = key.chars();
    let capitalised = chars
        .next()
        .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
        .unwrap_or_default();
    [key.to_string(), capitalised, key.to_ascii_uppercase()]
}

/// The shared surface's source with comment lines dropped.
fn planeverbs_code() -> String {
    include_str!("../planeverbs.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// THE RATCHET, the same one the shared sweep job and choke point F carry. This file is shared
/// because it names no plane; the moment it does, the sibling plane stops being able to
/// parameterise it and grows a copy instead.
///
/// Comments are stripped first: the header has to be able to EXPLAIN which planes it serves and how
/// their vocabularies differ, and prose that explains a boundary is not code that crosses it.
#[test]
fn the_shared_verb_surface_names_no_plane_in_its_code() {
    // The planes' own subject vocabulary, then every shipped plane key in each spelling.
    const SUBJECT_NOUNS: &[&str] = &[
        "tool", "Tool", "agent", "Agent", "skill", "Skill", "card", "Card",
    ];
    let mut banned: Vec<String> = SUBJECT_NOUNS.iter().map(|s| s.to_string()).collect();
    for key in shipped_plane_keys() {
        banned.extend(spellings(&key));
    }
    let code = planeverbs_code();
    for needle in &banned {
        assert!(
            !code.contains(needle.as_str()),
            "the shared trust verb surface names `{needle}` in its CODE. The plane's vocabulary \
             belongs in `Plane::subject_noun` / `Plane::audit_kind` and in the plane's own \
             `PlaneTrust` impl, never in the surface both planes share."
        );
    }
}

/// THE ACCEPTANCE TEST, mechanically: the plane is a type parameter and a pair of lookups, never a
/// branch. A `match` on it here would mean the handler had been re-forked inside one file, which
/// reads as unified and is not.
#[test]
fn the_plane_is_a_parameter_and_never_a_branch() {
    let code = planeverbs_code();
    let mut branches: Vec<String> = ["match plane", "match P::PLANE", "if plane =="]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // A branch on one named plane: `Plane::<Key>` for every shipped plane.
    for key in shipped_plane_keys() {
        let [_, capitalised, _] = spellings(&key);
        branches.push(format!("Plane::{capitalised}"));
    }
    for needle in &branches {
        assert!(
            !code.contains(needle.as_str()),
            "the shared trust verb surface contains `{needle}`. One handler set, parameterised by \
             plane — a branch here is one handler set per plane with extra steps."
        );
    }
}

/// A LOOKUP THAT RESOLVED IS PASSED STRAIGHT THROUGH. The shared rule decides the refusal and
/// nothing else; it never inspects, rewrites or re-validates what the plane found.
#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found =
        registered(|| Some(("entry", "cfg"))).expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}

// `the_admin_route_table_method_path_scope_is_byte_identical` stays with the kernel's admin gate
// (`busbar-kernel/tests/admin_planeverbs_cross_plane.rs`): it pins the scope matrix the gate enforces.

// THE CROSS-PLANE DERIVATIONS, moved here from the kernel's `tests/admin_planeverbs_cross_plane.rs`
// with the envelope they drive (P2 D4): driven over every linked plane with admin verbs (this crate's
// `test-linked` roster), addressed by what each declares, never by a plane key spelled here.

/// Every linked plane that mounts admin trust verbs, read back from the registry.
fn verb_planes() -> Vec<&'static busbar_kernel::plane::registry::PlaneDecl> {
    crate::ensure_seam();
    let planes: Vec<_> = busbar_kernel::plane::registry::plane_decls()
        .iter()
        .copied()
        .filter(|d| d.admin_routes.is_some())
        .collect();
    assert!(
        planes.len() >= 2,
        "the test-linked roster carries at least two planes with admin trust verbs: {:?}",
        planes.iter().map(|d| d.key).collect::<Vec<_>>()
    );
    planes
}

/// THE `404` IS DERIVED FROM THE PLANE, so the wording cannot drift apart between two planes and a
/// third plane gets the same refusal for free. Driven for EVERY linked plane with admin verbs; each
/// plane pins its own subject noun literal in its own suite (busbar-mcp `codec/tests/decl_tests.rs`,
/// busbar-a2a `a2a/tests/serve_tests.rs`).
#[test]
fn the_not_found_names_the_plane_s_own_subject() {
    // `registered` now returns the neutral, wordless `PlaneVerbError::NotFound`; the frozen wording is
    // reconstructed at the CORE boundary (`to_admin_error`) from the plane decl. That each plane gets
    // its own subject noun — and gets it for free from the one map — is what this asserts.
    for decl in verb_planes() {
        let refused = busbar_kernel::admin_verbs::registered(|| None::<()>)
            .expect_err("a lookup that resolved nothing must refuse");
        let rendered = to_admin_error(decl.key, "billing", refused).message();
        assert!(
            rendered.contains(&format!("{} `billing`", decl.subject_noun)),
            "the `{}` refusal must name the plane's own subject noun: {rendered}",
            decl.key
        );
    }
}

/// THE AUDIT ACTION AND RESOURCE are `<kind>.<verb>` on `<kind>:<name>`, with the kind coming off
/// the spine. These strings are read back by audit queries and compliance exports, so the kernel's
/// ONE recorder (`admin::planeverbs::audit`) is driven for every linked plane with admin verbs and
/// the row it writes is read back off the audit ring. Each plane pins its own published literals
/// (`<kind>`, `<kind>.connect`, `<kind>.approve`) in its own suite (busbar-mcp
/// `codec/tests/decl_tests.rs`, busbar-a2a `a2a/tests/serve_tests.rs`).
#[test]
fn the_audit_naming_is_derived_from_the_plane() {
    use crate::v1::json::audit::AUDIT;
    let principal = busbar_contract::auth::AuthPrincipal(None);
    for decl in verb_planes() {
        assert_eq!(
            busbar_kernel::plane::plane_decl(decl.key).audit_kind,
            decl.audit_kind,
            "the registry resolves `{}` to its own declaration",
            decl.key
        );
        for verb in ["connect", "approve"] {
            let name = format!("k3-audit-{}-{verb}", decl.key);
            audit(decl.key, verb, &name, "applied", &principal);
            let resource = format!("{}:{name}", decl.audit_kind);
            let rows = AUDIT.list_filtered(0, 8, None, Some(&resource));
            assert_eq!(rows.len(), 1, "one audit row on `{resource}`: {rows:?}");
            assert_eq!(
                rows[0].action,
                format!("{}.{verb}", decl.audit_kind),
                "the action word is `<kind>.<verb>` for `{}`",
                decl.key
            );
        }
    }
}
