// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The credential positions `${VAR}` filled, and what a plane is handed over them
//! ([`super::plane_bound`]). Every test interpolates under its own section key and its own variable,
//! so the process-wide ledger other tests write into never decides one of these.

use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_ENV};
use serde_json::json;

use super::{plane_bound, plane_bound_bytes};
use crate::config::{interpolate_env_with, EnvSubst};

/// A member program's environment key (`busbar_contract::conn::PROGRAM_KEYS`).
const ENV: &str = busbar_contract::conn::PROGRAM_KEYS[2];

/// `{ env: VAR }`: the reference a plane is handed where `${VAR}` filled a whole credential value.
fn env_ref(var: &str) -> serde_json::Value {
    json!({ SECRET_MODULE_ENV: var })
}

/// Interpolate `template` with `vars` set, as boot does, and parse it.
fn interpolated(template: &str, vars: &[(&str, &str)]) -> serde_yaml::Value {
    for (k, v) in vars {
        std::env::set_var(k, v);
    }
    let text =
        interpolate_env_with(template, EnvSubst::Strict, &mut Vec::new()).expect("interpolates");
    serde_yaml::from_str(&text).expect("parses")
}

fn section(doc: &serde_yaml::Value, key: &str) -> serde_json::Value {
    serde_json::to_value(doc.get(key).expect("written")).expect("json")
}

/// A credential field `${VAR}` filled whole reaches a plane as `{ env: VAR }`; `url`, `command`,
/// `args`, `cwd` and `token_url` keep the load-time interpolation, as 1.5.5 handed them on.
#[test]
fn a_credential_field_reaches_a_plane_as_its_reference_and_every_other_field_as_interpolated() {
    const VAR: &str = "BUSBAR_FILLED_WHOLE_SECRET";
    const PLAIN: &str = "sk-filled-whole-0001";
    const HOST: &str = "BUSBAR_FILLED_WHOLE_HOST";
    let doc = interpolated(
        "filled_whole:\n  reg:\n    token: \"${BUSBAR_FILLED_WHOLE_SECRET}\"\n    \
         url: \"https://${BUSBAR_FILLED_WHOLE_HOST}/v1\"\n    \
         command: \"/opt/${BUSBAR_FILLED_WHOLE_HOST}/bin\"\n    \
         args: [\"--x\", \"${BUSBAR_FILLED_WHOLE_SECRET}\"]\n    \
         cwd: \"/srv/${BUSBAR_FILLED_WHOLE_HOST}\"\n    \
         token_url: \"https://${BUSBAR_FILLED_WHOLE_HOST}/token\"\n    \
         env:\n      API: \"${BUSBAR_FILLED_WHOLE_SECRET}\"\n    kept: literal\n",
        &[(VAR, PLAIN), (HOST, "upstream.example")],
    );
    let bound = plane_bound(&["filled_whole"], section(&doc, "filled_whole"));
    assert_eq!(
        bound,
        json!({"reg": {
            "token": env_ref(VAR),
            "url": "https://upstream.example/v1",
            "command": "/opt/upstream.example/bin",
            "args": ["--x", PLAIN],
            "cwd": "/srv/upstream.example",
            "token_url": "https://upstream.example/token",
            ENV: {"API": env_ref(VAR)},
            "kept": "literal",
        }})
    );
}

/// A credential field `${VAR}` filled only in PART reaches a plane as a TEMPLATE reference over the
/// value as written: no byte of the secret, nothing refused (no 1.5.5 narrowing), and the host
/// resolves it back to the interpolated value.
#[test]
fn a_credential_field_filled_in_part_reaches_a_plane_as_a_template_reference() {
    const VAR: &str = "BUSBAR_FILLED_PART_SECRET";
    const PLAIN: &str = "sk-filled-part-0001";
    let doc = interpolated(
        "filled_part:\n  reg:\n    env:\n      AUTH: \"Bearer ${BUSBAR_FILLED_PART_SECRET}\"\n    \
         headers: {Authorization: \"Bearer ${BUSBAR_FILLED_PART_SECRET}\"}\n",
        &[(VAR, PLAIN)],
    );
    let bound = plane_bound(&["filled_part"], section(&doc, "filled_part"));
    assert!(!bound.to_string().contains(PLAIN), "no byte: {bound}");
    let template = serde_json::to_value(SecretRef::template("Bearer ${BUSBAR_FILLED_PART_SECRET}"))
        .expect("a reference");
    assert_eq!(bound["reg"][ENV]["AUTH"], template, "{bound}");
    assert_eq!(
        bound["reg"]["headers"]["Authorization"], template,
        "{bound}"
    );
    let reference: SecretRef =
        serde_json::from_value(bound["reg"][ENV]["AUTH"].clone()).expect("a reference");
    let resolved = reference
        .resolve_template(&|r| {
            r.env_var()
                .and_then(|v| std::env::var(v).ok())
                .ok_or_else(|| "unresolved".to_string())
        })
        .expect("resolves");
    assert_eq!(resolved, format!("Bearer {PLAIN}"));
}

/// The kernel-owned `upstream_credentials` block is credential material at every depth.
#[test]
fn the_upstream_credentials_block_is_credential_material_at_every_depth() {
    const VAR: &str = "BUSBAR_FILLED_UPSTREAM_SECRET";
    let doc = interpolated(
        "filled_upstream:\n  upstream_credentials: {style: bearer, value: \"${BUSBAR_FILLED_UPSTREAM_SECRET}\"}\n",
        &[(VAR, "sk-filled-upstream-0001")],
    );
    let bound = plane_bound(&["filled_upstream"], section(&doc, "filled_upstream"));
    assert_eq!(
        bound,
        json!({"upstream_credentials": {"style": "bearer", "value": env_ref(VAR)}})
    );
}

#[test]
fn a_section_keyed_by_its_top_level_name_is_bound_at_the_root() {
    const VAR: &str = "BUSBAR_FILLED_KEYED_SECRET";
    let doc = interpolated(
        "filled_keyed:\n  api_key: ${BUSBAR_FILLED_KEYED_SECRET}\n",
        &[(VAR, "sk-filled-keyed-0001")],
    );
    let keyed = json!({"filled_keyed": section(&doc, "filled_keyed")});
    assert_eq!(
        plane_bound(&[], keyed),
        json!({"filled_keyed": {"api_key": env_ref(VAR)}})
    );
}

#[test]
fn a_number_interpolated_into_a_credential_field_is_a_position_too() {
    const VAR: &str = "BUSBAR_FILLED_NUMBER_SECRET";
    let doc = interpolated(
        "filled_number:\n  password: ${BUSBAR_FILLED_NUMBER_SECRET}\n  port: ${BUSBAR_FILLED_NUMBER_SECRET}\n",
        &[(VAR, "483920175534")],
    );
    let bytes = plane_bound_bytes(
        &["filled_number"],
        doc.get("filled_number").expect("written"),
    )
    .expect("bound");
    let bound: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        bound,
        json!({"password": env_ref(VAR), "port": 483920175534_u64})
    );
}

#[test]
fn a_literal_equal_to_the_secret_elsewhere_and_a_changed_value_are_left_as_written() {
    const VAR: &str = "BUSBAR_FILLED_LITERAL_SECRET";
    const PLAIN: &str = "sk-filled-literal-0001";
    let doc = interpolated(
        "filled_literal:\n  token: ${BUSBAR_FILLED_LITERAL_SECRET}\n  secret: sk-filled-literal-0001\n",
        &[(VAR, PLAIN)],
    );
    let bound = plane_bound(&["filled_literal"], section(&doc, "filled_literal"));
    assert_eq!(
        bound,
        json!({"token": env_ref(VAR), "secret": PLAIN}),
        "only the position"
    );
    // The same path holding a value `${VAR}` did not fill (an admin write since) is not one.
    let changed = plane_bound(
        &["filled_literal"],
        json!({"token": "written-by-the-admin-api"}),
    );
    assert_eq!(changed, json!({"token": "written-by-the-admin-api"}));
}

#[test]
fn a_section_with_nothing_interpolated_is_handed_as_written() {
    let written = json!({"reg": {"url": "http://u.invalid", "api_key": env_ref("X")}});
    assert_eq!(plane_bound(&["filled_nothing"], written.clone()), written);
}
