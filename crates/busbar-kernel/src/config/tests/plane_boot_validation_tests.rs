// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};

use super::PlaneDefinition;
use crate::config::plane_sections::{validate_plane_entry, validate_plane_section};

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

static BAYS: PlaneDefinition<'static> = PlaneDefinition {
    section: "bays",
    trust_keys: KEYS,
    caller_credential_refusal: None,
    sections: &["bays", "identity-providers", "export", "tools", "agents"],
};

const PIN_REFUSAL: &str = "`bays.dock`: `anchor.mechanism: sealed_key` needs `anchor.key:` — the \
     out-of-band material this registration is verified against. A pin with nothing to verify with \
     is not a pin.";
const NO_ROOT_KEY_REFUSAL: &str = "`bays.dock`: `anchor.mechanism: open` must not carry \
     `anchor.key:`. `open` means there is no authenticity root; key material that is never \
     verified against reads to an operator as protection that does not exist. Name the real \
     mechanism, or drop the key.";
const CADENCE_REFUSAL: &str =
    "`bays.dock`: `recheck_after:` invalid duration 'soon': expected <number><s|m|h|d>";
const CROSS_PLANE_REFUSAL: &str = "`bays.dock`: `hooks:` may only name hooks from the top-level \
     `hooks:` map, by bare name. `export.siem` reaches onto the `export:` plane, and no entry on one \
     plane may reference an entry on another. Did you mean the hook `siem`?";

fn judge_section(section: &str) -> Result<(), String> {
    let value: serde_yaml::Value = serde_yaml::from_str(section).map_err(|e| e.to_string())?;
    validate_plane_section("bays", &value, KEYS, None, BAYS.sections)
}

fn assert_refused(got: Result<(), String>, sentence: &str) {
    let got = got.expect_err("the kernel must refuse this section");
    assert!(
        got.contains(sentence),
        "the refusal must carry the exact sentence\n  want: {sentence}\n  got:  {got}"
    );
}

#[test]
fn section_policy_refuses_a_cross_plane_reference_in_a_planes_section() {
    judge_section("  dock:\n    hooks: [siem]\n").expect("a bare hook name is the legal form");
    assert_refused(
        judge_section("  dock:\n    hooks: [export.siem]\n"),
        CROSS_PLANE_REFUSAL,
    );
}

#[test]
fn section_policy_refuses_a_bad_pin_in_a_planes_section() {
    judge_section("  dock:\n    anchor: { mechanism: sealed_key, key: K }\n")
        .expect("a rooted pin with material is legal");
    assert_refused(
        judge_section("  dock:\n    anchor: { mechanism: sealed_key }\n"),
        PIN_REFUSAL,
    );
}

#[test]
fn section_policy_refuses_a_bad_cadence_in_a_planes_section() {
    judge_section("  dock:\n    recheck_after: 30s\n").expect("a duration is legal");
    assert_refused(
        judge_section("  dock:\n    recheck_after: soon\n"),
        CADENCE_REFUSAL,
    );
}

#[test]
fn section_policy_and_the_admin_write_path_judge_an_entrys_timeout() {
    judge_section("  dock:\n    timeout: 10s\n").expect("a duration is legal");
    assert_refused(
        judge_section("  dock:\n    timeout: soon\n"),
        "`bays.dock`: `timeout:` invalid duration 'soon': expected <number><s|m|h|d>",
    );
    assert_refused(
        judge_section("  dock:\n    timeout: 0s\n"),
        "`bays.dock`: `timeout: 0s` is zero, which would refuse every call to this entry before \
         it was sent.",
    );
    assert_refused(
        judge_section("  dock:\n    timeout: 10\n"),
        "`bays.dock`: `timeout:` must be a duration `<n><s|m|h|d>`, e.g. `30s`",
    );
    let entry: serde_yaml::Value = serde_yaml::from_str("timeout: 0m").expect("yaml");
    let refused = validate_plane_entry("bays", "dock", &entry, KEYS, &["bays"]).unwrap_err();
    assert!(
        refused.starts_with("`bays.dock`: `timeout: 0m` is zero"),
        "{refused}"
    );

    let models: serde_yaml::Value =
        serde_yaml::from_str("models:\n  m1: { timeout: never }\n").expect("yaml");
    let refused = validate_plane_section("bays", &models, KEYS, None, &["bays"]).unwrap_err();
    assert!(
        refused.starts_with("`bays.models.m1`: `timeout:`"),
        "{refused}"
    );
}

#[test]
fn the_admin_write_path_refuses_what_the_section_refuses() {
    let section = &BAYS;
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
            serde_json::json!({ "anchor": { "mechanism": "open", "key": "k" } }),
            NO_ROOT_KEY_REFUSAL,
        ),
        (
            serde_json::json!({ "recheck_after": "soon" }),
            CADENCE_REFUSAL,
        ),
    ] {
        let err = section
            .validate("dock", &def, || Ok(()))
            .err()
            .expect("the write path must refuse it");
        assert_eq!(err, sentence);
    }
    section
        .validate(
            "dock",
            &serde_json::json!({ "anchor": { "mechanism": "open" }, "hooks": ["siem"] }),
            || Ok(()),
        )
        .expect("a well-formed definition is accepted");
}

#[test]
fn the_admin_write_path_refuses_a_pin_token_the_declaration_does_not_spell() {
    let section = &BAYS;
    let err = section
        .validate(
            "dock",
            &serde_json::json!({ "anchor": { "mechanism": "sealed-key" } }),
            || Ok(()),
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
        validate_plane_section("bays", &value, KEYS, None, &sections).unwrap_err(),
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

const FORWARD_REFUSAL: &str = "the moorings plane never forwards a caller's credential";

static MOORINGS: PlaneDefinition<'static> = PlaneDefinition {
    section: "moorings",
    trust_keys: &[],
    caller_credential_refusal: Some(FORWARD_REFUSAL),
    sections: &[
        "bays",
        "moorings",
        "identity-providers",
        "export",
        "tools",
        "agents",
    ],
};

#[test]
fn section_policy_refuses_a_forwarded_caller_credential_in_the_planes_own_words() {
    let moorings = |default: &str| {
        let value =
            serde_yaml::from_str(&format!("upstream_credentials: {default}\nberth: {{}}\n"))
                .map_err(|e| e.to_string())?;
        validate_plane_section(
            "moorings",
            &value,
            &[],
            Some(FORWARD_REFUSAL),
            MOORINGS.sections,
        )
    };
    assert_refused(moorings("passthrough"), FORWARD_REFUSAL);
    moorings("own").expect("the plane's own credential is not refused");
    judge_section("  upstream_credentials: passthrough\n  dock: {}\n")
        .expect("a plane that states no refusal accepts a forwarded caller credential");
}

#[test]
fn the_section_default_is_judged_after_its_registrations() {
    let value: serde_yaml::Value =
        serde_yaml::from_str("upstream_credentials: passthrough\nberth: {}\n").unwrap();
    assert_eq!(
        validate_plane_section("moorings", &value, &[], Some(FORWARD_REFUSAL), &[]),
        Err(FORWARD_REFUSAL.to_string())
    );
    assert_eq!(
        validate_plane_section("moorings", &value, &[], None, &[]),
        Ok(())
    );
    let value: serde_yaml::Value =
        serde_yaml::from_str("upstream_credentials: passthrough\ndock:\n  recheck_after: soon\n")
            .unwrap();
    assert_eq!(
        validate_plane_section("bays", &value, KEYS, Some(FORWARD_REFUSAL), &[]).unwrap_err(),
        CADENCE_REFUSAL,
        "a registration's refusal comes first, as the plane's section split ordered it"
    );
}

#[test]
fn a_registrations_own_passthrough_is_refused_in_the_planes_own_words() {
    let moorings = |section: &str| {
        let value = serde_yaml::from_str(section).map_err(|e| e.to_string())?;
        validate_plane_section(
            "moorings",
            &value,
            &[],
            Some(FORWARD_REFUSAL),
            MOORINGS.sections,
        )
    };
    let refused = moorings("  berth:\n    upstream_credentials: passthrough\n")
        .expect_err("a registration's own passthrough is refused");
    assert!(
        refused.contains("`moorings.berth`") && refused.contains(FORWARD_REFUSAL),
        "the refusal names the registration, in the plane's words: {refused}"
    );
    moorings("  berth:\n    upstream_credentials: own\n")
        .expect("a registration's own credential is not refused");

    let refused = MOORINGS
        .validate(
            "berth",
            &serde_json::json!({ "upstream_credentials": "passthrough" }),
            || Ok(()),
        )
        .err()
        .expect("the admin write path refuses what boot refuses");
    assert!(
        refused.starts_with("`moorings.berth`") && refused.contains(FORWARD_REFUSAL),
        "{refused}"
    );

    judge_section("  dock:\n    upstream_credentials: passthrough\n")
        .expect("a plane that states no refusal accepts a registration's own passthrough");
}
