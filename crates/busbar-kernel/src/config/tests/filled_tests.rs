// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::door::{REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL};
use busbar_contract::secret_ref::{SecretRef, Sugars};
use serde_json::json;

use super::plane_bound_with_sources;
use crate::config::{interpolate_env_with, EnvSubst};

const ENV: &str = busbar_contract::conn::PROGRAM_KEYS[2];

fn sources() -> Sugars {
    let mut sources = Sugars::default();
    sources
        .declare(
            "fill-witness",
            &[
                (REWRITE_SUGAR, "lookup".into(), "slot".into()),
                (REWRITE_SUGAR_ROLE, "lookup".into(), SUGAR_ROLE_FILL.into()),
            ],
        )
        .unwrap();
    sources
}
fn env_ref(var: &str) -> serde_json::Value {
    serde_json::to_value(sources().reference_for_role(SUGAR_ROLE_FILL, var).unwrap()).unwrap()
}
fn plane_bound(prefix: &[&str], value: serde_json::Value) -> serde_json::Value {
    plane_bound_with_sources(prefix, value, &sources()).expect("admitted fill source")
}

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
    let template = serde_json::to_value(
        SecretRef::template("Bearer ${BUSBAR_FILLED_PART_SECRET}", &sources()).unwrap(),
    )
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
            if r == &sources().reference_for_role(SUGAR_ROLE_FILL, VAR).unwrap() {
                Ok(busbar_contract::Secret::new(PLAIN.to_owned()))
            } else {
                Err("unbound fill reference".into())
            }
        })
        .expect("resolves");
    assert_eq!(
        resolved.expose(&crate::seal::lend()),
        &format!("Bearer {PLAIN}")
    );
}

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
    let bytes = serde_json::to_vec(&plane_bound(
        &["filled_number"],
        section(&doc, "filled_number"),
    ))
    .expect("bound encoding");
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

#[test]
fn a_credential_fill_refuses_without_an_admitted_fill_owner() {
    let doc = interpolated(
        "filled_missing:\n  token: ${BUSBAR_FILLED_MISSING_OWNER}\n",
        &[("BUSBAR_FILLED_MISSING_OWNER", "unavailable-source-value")],
    );
    let error = plane_bound_with_sources(
        &["filled_missing"],
        section(&doc, "filled_missing"),
        &Sugars::default(),
    )
    .unwrap_err();
    assert!(error.contains("fill"), "{error}");
    assert!(!error.contains("unavailable-source-value"), "{error}");
}
