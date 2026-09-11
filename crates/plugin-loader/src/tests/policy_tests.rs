// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESOLVER FINDS; IT DOES NOT SAY.
//!
//! A malformed anti-downgrade floor comes back on [`super::ResolvedTrust::floor_findings`] as a
//! fact in this crate's own vocabulary — which map, which entry, which value. This cell is the red
//! half of that: at the base there was no finding to return, because the resolver announced the
//! problem itself and handed the caller nothing to act on.

use super::*;
use crate::config::PluginsCfg;

/// A well-formed floor and an omitted one are not findings; a malformed one is, and it names the
/// entry it came from rather than a rendered sentence.
#[test]
fn a_malformed_floor_comes_back_as_a_finding_naming_its_entry() {
    let mut cfg = PluginsCfg::default();
    cfg.min_versions.insert("good".to_string(), "1.2.3".into());
    cfg.min_versions
        .insert("omitted".to_string(), String::new());
    cfg.min_versions.insert("bad".to_string(), "v1.2.3".into());
    cfg.first_party_floors
        .insert("pinned".to_string(), "2.0".into());

    let resolved = trust_policy(&cfg, "1.6.0").expect("a floor is never a resolution error");

    assert_eq!(
        resolved.floor_findings,
        vec![
            FloorFinding {
                map: FloorMap::MinVersions,
                name: "bad".to_string(),
                value: "v1.2.3".to_string(),
            },
            FloorFinding {
                map: FloorMap::FirstPartyFloors,
                name: "pinned".to_string(),
                value: "2.0".to_string(),
            },
        ],
        "both maps are walked to the end, `min_versions` first, and each finding names its own \
         entry — an empty floor is an omission and a valid floor is not a finding"
    );
    // The policy still carries the operator's maps verbatim: finding a bad entry does not edit it.
    assert_eq!(resolved.policy.min_versions.len(), 3);
    assert_eq!(resolved.policy.first_party_floors.len(), 1);
}

/// A resolution ERROR (a reserved publisher name) short-circuits before the floors are read, which
/// is what the emitting resolver did too: nothing is said about a floor in a block that will not
/// resolve at all.
#[test]
fn a_resolution_error_yields_no_findings_at_all() {
    let mut cfg = PluginsCfg::default();
    cfg.min_versions.insert("bad".to_string(), "v1.2.3".into());
    cfg.trust.publishers.push(crate::config::PluginPublisher {
        name: busbar_plugin_sign::FIRST_PARTY_PUBLISHER.to_string(),
        public_key: "00".repeat(32),
    });
    assert!(trust_policy(&cfg, "1.6.0").is_err());
}
