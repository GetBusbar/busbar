// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MIGRATED-MARKER (LEGACY-KEYFILE-MARKER r2, IF r35 M-1): `$migrated` is core migration vocabulary. Core writes
//! `"$migrated": {"legacy": [..]}` into the bag of a converting open only, from the migration plan's marks
//! (`Registry::mark_legacy`), after checking each pointer against the image's D_SECRET_PATH items; it strips the
//! marker from the settled answer; and it refuses an operator bag that carries it on every other path.
use busbar_plugin_abi::fail::{refused, Fail};
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Endpoints, Open};
use busbar_plugin_abi::records::{settled, Full, Out};

mod marker_fixture {
    use super::*;
    use busbar_contract::json::{self, JsonValueMutTrait, JsonValueTrait};
    use busbar_plugin_abi::plugin::Describe;

    /// Echoes the bag it was opened with, `$migrated` included, and records the marked pointers it saw as `seen`.
    pub struct Fixture(Vec<u8>);

    impl Open for Fixture {
        async fn open(_: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let mut value = json::parse_value(&config.to_vec())
                .map_err(|_| Fail::refused(refused::R_CONFIG))?;
            let seen = value
                .get("$migrated")
                .and_then(|m| m.get("legacy"))
                .cloned();
            if let Some(seen) = seen {
                value
                    .as_object_mut()
                    .ok_or_else(|| Fail::refused(refused::R_CONFIG))?
                    .insert("seen", seen);
            }
            let echo = json::to_vec(&value).map_err(|_| Fail::refused(refused::R_CONFIG))?;
            Ok(Self(echo))
        }

        fn check(_: &Host, _: &[u8], _: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#).secret_path("/token");
        }

        fn settled(&self, out: &mut Out<'_>) -> Result<(), Full> {
            settled::config(out, &self.0)
        }
    }

    impl busbar_plugin_abi::Auth for Fixture {}
    busbar_plugin_abi::plugin!(Auth, Fixture, name: "fixture-migrated-marker");
}

const BAG: &[u8] = br#"{"token":{"module":"file","path":"/private/original"}}"#;
const SEEN: &[u8] = br#"{"token":{"module":"file","path":"/private/original"},"seen":["/token"]}"#;
const OPERATOR_MARKER: &[u8] =
    br#"{"token":{"module":"file","path":"/private/original"},"$migrated":{"legacy":["/token"]}}"#;

fn harness() -> busbar_plugin_test::suites::harness::Harness {
    busbar_plugin_test::suites::harness::Harness::admit(
        marker_fixture::PLUGIN.plugin(),
        busbar_plugin_test::FakeNeeds::new(),
    )
    .unwrap_or_else(|refusal| panic!("the fixture is admitted: {refusal:?}"))
}

fn is_config(result: &Result<(), busbar_plugin_test::suites::harness::OpenError>) -> bool {
    matches!(
        result,
        Err(busbar_plugin_test::suites::harness::OpenError::Config { code, .. }) if *code == refused::R_CONFIG
    )
}

fn json(bytes: &[u8]) -> busbar_contract::json::Value {
    busbar_contract::json::parse_value(bytes).expect("JSON")
}

#[test]
fn a_marked_converting_open_sees_the_marker_and_settles_without_it() {
    let h = harness();
    h.mark_legacy("converted", &["/token"]);
    drop(
        h.open_converting("converted", BAG)
            .expect("marked conversion"),
    );
    let settled = h.settled("converted").expect("the echo settles");
    assert_eq!(
        json(settled.config_json.as_slice()),
        json(SEEN),
        "open saw `$migrated.legacy` and the settled answer carries no `$migrated`"
    );
    assert!(settled.answered);
}

#[test]
fn the_marks_are_taken_by_one_open() {
    let h = harness();
    h.mark_legacy("converted", &["/token"]);
    drop(
        h.open_converting("converted", BAG)
            .expect("marked conversion"),
    );
    drop(h.settled("converted"));
    drop(
        h.open_converting("converted", BAG)
            .expect("unmarked conversion"),
    );
    let settled = h.settled("converted").expect("the echo settles");
    assert_eq!(json(settled.config_json.as_slice()), json(BAG));
}

#[test]
fn a_mark_off_the_image_secret_paths_is_refused_config() {
    let h = harness();
    h.mark_legacy("converted", &["/other"]);
    let result = h.open_converting("converted", BAG).map(drop);
    assert!(is_config(&result), "{result:?}");
    assert!(h.settled("converted").is_none());
}

#[test]
fn a_mark_on_a_canonical_open_is_refused_config() {
    let h = harness();
    h.mark_legacy("current", &["/token"]);
    let result = h.open("current", BAG).map(drop);
    assert!(is_config(&result), "{result:?}");
    assert!(h.settled("current").is_none());
}

#[test]
fn an_operator_bag_carrying_the_marker_is_refused_on_every_path() {
    let h = harness();
    let canonical = h.open("canonical", OPERATOR_MARKER).map(drop);
    assert!(is_config(&canonical), "canonical open: {canonical:?}");
    let converting = h.open_converting("converting", OPERATOR_MARKER).map(drop);
    assert!(is_config(&converting), "converting open: {converting:?}");
    let checked = h.check("checked", OPERATOR_MARKER);
    assert!(is_config(&checked), "DRY_RUN check: {checked:?}");
    assert!(h.settled("canonical").is_none());
    assert!(h.settled("converting").is_none());
}

#[test]
fn the_migrate_suite_runs_a_marked_conversion() {
    use busbar_plugin_test::suites::{
        harness::OpenPurpose, migrate_legacy, MigrateCase, MigrateExpect,
    };
    migrate_legacy(
        marker_fixture::PLUGIN.plugin(),
        MigrateCase {
            bag: BAG,
            purpose: OpenPurpose::ConvertUnstamped,
            limits: Default::default(),
        },
        &["/token"],
        busbar_plugin_test::FakeNeeds::new(),
        MigrateExpect::Settled {
            config: Some(SEEN),
            core_cfg: &[],
        },
    );
}
