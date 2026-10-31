// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTINGS THE PLANE SCRIPT HANDS `open` AND `refresh` ([`handed`]), in the form the
//! composition root hands them (`busbar::root::serve::settings_of`): a plane that declares the
//! kernel-owned `pools` map, or reads any section beside its own (`SECTION_CONSUMED`), opens with
//! ONE object keyed by section; any other plane with its section bare. RED: a keyed plane handed
//! its section bare, a bare plane handed it keyed, inputs already keyed wrapped a second time.

use serde_json::{json, Value};

use super::handed;
use crate::dispatch::kinds::plane::ServedFacts;

fn facts(section: &'static str, consumed: &[&'static str]) -> ServedFacts {
    ServedFacts {
        section,
        consumed: consumed.to_vec(),
        ..ServedFacts::default()
    }
}

fn handed_as(facts: &ServedFacts, settings: &Value) -> Value {
    let bytes = handed(facts, settings.to_string().as_bytes());
    serde_json::from_slice(&bytes).expect("the handed settings are JSON")
}

#[test]
fn a_plane_reading_sections_beside_its_own_is_handed_its_section_keyed() {
    let section = json!({ "session": { "model": "m-cap" } });
    assert_eq!(
        handed_as(&facts("streams", &["providers", "models"]), &section),
        json!({ "streams": section }),
    );
}

#[test]
fn the_plane_declaring_the_pools_map_is_handed_it_keyed() {
    let section = json!({ "p": { "members": ["claude"] } });
    assert_eq!(
        handed_as(&facts("pools", &[]), &section),
        json!({ "pools": section }),
    );
}

#[test]
fn a_plane_reading_no_section_beside_its_own_is_handed_it_bare() {
    let section = json!({ "routes": { "a": 1 } });
    assert_eq!(handed_as(&facts("tools", &[]), &section), section);
}

#[test]
fn inputs_already_keyed_by_section_are_handed_as_written() {
    let keyed = json!({
        "providers": { "ant": { "protocol": "anthropic" } },
        "models": { "claude": { "provider": "ant" } },
        "pools": { "p": { "members": ["claude"] } },
    });
    let llm = facts("pools", &["providers", "models", "limits"]);
    assert_eq!(handed_as(&llm, &keyed), keyed);
}
