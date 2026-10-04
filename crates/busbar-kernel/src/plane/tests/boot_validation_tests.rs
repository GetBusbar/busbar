// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL JUDGES EVERY PLANE'S SECTION: a cross-plane reference, a bad pin and a bad cadence are
//! each refused by the kernel, on the boot path and on the admin write path, with the exact
//! sentence, for a plane whose own parse accepts everything.
//!
//! The plane is one busbar does not have: its section, key names and mechanism tokens are its own,
//! and its `parse_section` accepts any document. Every refusal below is therefore the kernel's.

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};

use crate::config::named_map::NamedMapSection;
use crate::plane::config::{validate_plane_entry, validate_plane_section};

const MECHANISMS: &[PinMechanismDecl] = &[
    PinMechanismDecl {
        token: "sealed_key",
        root: true,
        peer_key: false,
    },
    PinMechanismDecl {
        token: "open",
        root: false,
        peer_key: false,
    },
];

const KEYS: &[TrustKeyDecl] = &[
    TrustKeyDecl {
        key: "anchor",
        role: TrustRole::Pin,
        fingerprint: false,
        default: None,
        mechanisms: MECHANISMS,
    },
    TrustKeyDecl {
        key: "recheck_after",
        role: TrustRole::ReverifyTtl,
        fingerprint: false,
        default: Some("5s"),
        mechanisms: &[],
    },
];

/// The plane's own parse: it accepts any section, so nothing it could refuse hides the kernel's rule.
fn accept_anything(
    _: &serde_yaml::Value,
) -> Result<Box<dyn crate::plane::config::PlaneCfg>, String> {
    Ok(Box::<crate::plane::config::RawPlaneSection>::default())
}

/// A plane owning the `bays:` section and declaring two kernel trust keys.
static BAYS_PLANE: crate::plane::registry::PlaneDecl = crate::plane::registry::PlaneDecl {
    declaration: crate::plane::registry::PlaneDeclaration {
        key: "bays-plane",
        fallback: false,
        config_section: "bays",
        owned_config_sections: &["bays"],
        trust_keys: KEYS,
        ..crate::test_support::NEUTRAL_FALLBACK.declaration
    },
    parse_section: Some(accept_anything),
    ..crate::test_support::NEUTRAL_FALLBACK
};

const PIN_REFUSAL: &str = "`bays.dock`: `anchor.mechanism: sealed_key` needs `anchor.key:` — the \
     out-of-band material this registration is verified against. A pin with nothing to verify with \
     is not a pin.";
const CADENCE_REFUSAL: &str =
    "`bays.dock`: `recheck_after:` invalid duration 'soon': expected <number><s|m|h|d>";
const CROSS_PLANE_REFUSAL: &str = "`bays.dock`: `hooks:` may only name hooks from the top-level \
     `hooks:` map, by bare name. `export.siem` reaches onto the `export:` plane, and no entry on one \
     plane may reference an entry on another. Did you mean the hook `siem`?";

fn boot(section: &str) -> Result<(), String> {
    crate::config::deploy_from_yaml_str(&format!("providers: {{}}\nmodels: {{}}\nbays:\n{section}"))
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn assert_refused(got: Result<(), String>, sentence: &str) {
    let got = got.expect_err("the kernel must refuse this section");
    assert!(
        got.contains(sentence),
        "the refusal must carry the exact sentence\n  want: {sentence}\n  got:  {got}"
    );
}

#[test]
fn boot_refuses_a_cross_plane_reference_in_a_planes_section() {
    let _isolation = crate::plane::registry::TestRegistryIsolation::seeded(&[&BAYS_PLANE]);
    boot("  dock:\n    hooks: [siem]\n").expect("a bare hook name is the legal form");
    assert_refused(
        boot("  dock:\n    hooks: [export.siem]\n"),
        CROSS_PLANE_REFUSAL,
    );
}

#[test]
fn boot_refuses_a_bad_pin_in_a_planes_section() {
    let _isolation = crate::plane::registry::TestRegistryIsolation::seeded(&[&BAYS_PLANE]);
    boot("  dock:\n    anchor: { mechanism: sealed_key, key: K }\n")
        .expect("a rooted pin with material is legal");
    assert_refused(
        boot("  dock:\n    anchor: { mechanism: sealed_key }\n"),
        PIN_REFUSAL,
    );
}

#[test]
fn boot_refuses_a_bad_cadence_in_a_planes_section() {
    let _isolation = crate::plane::registry::TestRegistryIsolation::seeded(&[&BAYS_PLANE]);
    boot("  dock:\n    recheck_after: 30s\n").expect("a duration is legal");
    assert_refused(boot("  dock:\n    recheck_after: soon\n"), CADENCE_REFUSAL);
}

#[test]
fn the_admin_write_path_refuses_what_boot_refuses() {
    let _isolation = crate::plane::registry::TestRegistryIsolation::seeded(&[&BAYS_PLANE]);
    let section = NamedMapSection::Plane("bays");
    for (def, sentence) in [
        (
            serde_json::json!({ "hooks": ["export.siem"] }),
            CROSS_PLANE_REFUSAL,
        ),
        (
            serde_json::json!({ "anchor": { "mechanism": "sealed_key" } }),
            PIN_REFUSAL,
        ),
        (
            serde_json::json!({ "recheck_after": "soon" }),
            CADENCE_REFUSAL,
        ),
    ] {
        let err = section
            .parse_def("dock", &def)
            .err()
            .expect("the write path must refuse it");
        assert_eq!(err, sentence);
    }
    section
        .parse_def(
            "dock",
            &serde_json::json!({ "anchor": { "mechanism": "open" }, "hooks": ["siem"] }),
        )
        .expect("a well-formed definition is accepted");
}

/// A definition whose pin token the plane's own parse would accept but its declared `trust_keys` do
/// not spell reads, non-strictly, as NO pin: the admin write path refuses it, as boot's strict
/// reading does, instead of persisting a keyless root pin.
#[test]
fn the_admin_write_path_refuses_a_pin_token_the_declaration_does_not_spell() {
    let _isolation = crate::plane::registry::TestRegistryIsolation::seeded(&[&BAYS_PLANE]);
    let section = NamedMapSection::Plane("bays");
    let err = section
        .parse_def(
            "dock",
            &serde_json::json!({ "anchor": { "mechanism": "sealed-key" } }),
        )
        .err()
        .expect("a drifted token must be refused on the write path");
    assert_eq!(
        err,
        "`bays.dock`: `anchor.mechanism: sealed-key` is not one of `sealed_key`, `open`"
    );
}

#[test]
fn a_section_is_judged_per_registration_in_order_skipping_reserved_words() {
    let sections = ["bays", "export"];
    let value: serde_yaml::Value = serde_yaml::from_str(
        "hooks: [export.siem]\nupstream_credentials: own\n\
         a:\n  recheck_after: 1m\n\
         dock:\n  recheck_after: soon\n  hooks: [export.siem]\n",
    )
    .unwrap();
    assert_eq!(
        validate_plane_section("bays", &value, KEYS, &sections).unwrap_err(),
        CADENCE_REFUSAL,
        "the trust keys are judged before the hook list, and the reserved `hooks:` is not an entry"
    );
    let entry: serde_yaml::Value = serde_yaml::from_str("hooks: [\"a.b\"]").unwrap();
    assert_eq!(
        validate_plane_entry("bays", "dock", &entry, &[], &sections).unwrap_err(),
        "`bays.dock`: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
         `a.b` is not a bare name."
    );
}
