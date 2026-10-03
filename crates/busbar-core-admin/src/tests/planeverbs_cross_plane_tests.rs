// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE ADMIN TRUST-VERB DERIVATIONS — the not-found wording and the audit action/resource
//! this crate's [`crate::planeverbs`] derives from each plane's declaration, driven for every linked
//! plane with admin verbs (the test-linked table, `[package.metadata.busbar] test-linked`) and
//! addressed by what each declares, never by a plane key spelled here. Moved with
//! `planeverbs` from the kernel's `tests/admin_planeverbs_cross_plane.rs` (1.6.0-TODO.md D4); the
//! route-table scope ratchet stays in the kernel with the scope matrix it judges. The planes' own
//! published literals are pinned in their own suites.

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
/// plane pins its own subject noun literal in its own suite.
#[test]
fn the_not_found_names_the_plane_s_own_subject() {
    // `registered` now returns the neutral, wordless `PlaneVerbError::NotFound`; the frozen wording is
    // reconstructed at the CORE boundary (`to_admin_error`) from the plane decl. That each plane gets
    // its own subject noun — and gets it for free from the one map — is what this asserts.
    for decl in verb_planes() {
        let refused = busbar_kernel::admin_verbs::registered(|| None::<()>)
            .expect_err("a lookup that resolved nothing must refuse");
        let rendered = crate::planeverbs::to_admin_error(decl.key, "billing", refused).message();
        assert!(
            rendered.contains(&format!("{} `billing`", decl.subject_noun)),
            "the `{}` refusal must name the plane's own subject noun: {rendered}",
            decl.key
        );
    }
}

/// THE AUDIT ACTION AND RESOURCE are `<kind>.<verb>` on `<kind>:<name>`, with the kind coming off
/// the spine. These strings are read back by audit queries and compliance exports, so the kernel's
/// ONE recorder (`planeverbs::audit`) is driven for every linked plane with admin verbs and
/// the row it writes is read back off the audit ring. Each plane pins its own published literals
/// (`<kind>`, `<kind>.connect`, `<kind>.approve`) in its own suite.
#[test]
fn the_audit_naming_is_derived_from_the_plane() {
    use busbar_kernel::audit_ring::AUDIT;
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
            crate::planeverbs::audit(decl.key, verb, &name, "applied", &principal);
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
