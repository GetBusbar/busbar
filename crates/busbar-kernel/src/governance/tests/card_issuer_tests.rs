// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARD-ISSUER KEY IS READ FROM THE PLANE'S DECLARATION (audit K3 #3; Law 1, BUSBAR-1.6.0.md
//! l.1877 "No plugin-instance name ever appears in core logic"): a plane that declares a
//! card-signing domain and key-id prefix gets its published issuer key whatever config section it
//! is registered under, and a plane that declares none gets none.

use super::*;
use crate::governance::signing::{TokenSigner, DEFAULT_KID};

const CARD_DOMAIN: &str = "widget-plane/card-signing/v1";

/// A plane declaring a card-signing domain under a section no core code names.
static CARD_PLANE: crate::plane::registry::PlaneDecl = crate::plane::registry::PlaneDecl {
    declaration: crate::plane::registry::PlaneDeclaration {
        key: "widget-plane",
        fallback: false,
        config_section: "widgets",
        scope_kinds: &[],
        subject_noun: "widget",
        admin_noun: "widget",
        audit_kind: "widget",
        card_signing_domain: Some(CARD_DOMAIN),
        card_kid_prefix: Some("w-"),
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    },
    wire_format_names: || &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
};

fn signer() -> TokenSigner {
    TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID)
}

#[test]
fn a_plane_declaring_a_card_domain_under_any_section_gets_its_issuer_key() {
    let _iso = busbar_kernel::plane::registry::TestRegistryIsolation::seeded(&[&CARD_PLANE]);
    let g = GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer()))
        .expect("a governance book with a signing key");
    let issuer = g
        .card_issuer(&CARD_PLANE)
        .expect("the plane's declared card-signing domain mints its issuer key");
    assert_eq!(
        (issuer.kid, issuer.issuer_spki_base64),
        (
            format!("w-{}", signer().kid()),
            signer().card_subkey_key_info_base64(CARD_DOMAIN)
        )
    );
}

#[test]
fn a_plane_declaring_no_card_domain_gets_no_issuer_key() {
    static PLAIN: crate::plane::registry::PlaneDecl = crate::plane::registry::PlaneDecl {
        declaration: crate::plane::registry::PlaneDeclaration {
            card_signing_domain: None,
            card_kid_prefix: None,
            ..CARD_PLANE.declaration
        },
        ..CARD_PLANE
    };
    let g = GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer()))
        .expect("a governance book with a signing key");
    assert!(g.card_issuer(&PLAIN).is_none());
}
