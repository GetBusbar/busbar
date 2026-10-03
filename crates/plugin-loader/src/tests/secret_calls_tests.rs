// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SECRET AXIS OVER THE ONE DISPATCHER** (TODO step 28): [`SecretRows`] holds the kind's
//! REAL plugin (the env source, reached by KIND through `[package.metadata.busbar.both-ways]`, as
//! `secret_door_conformance_tests` reaches it) LINKED (its door) and DROPPED IN (its `cdylib`, as
//! the registry discovers it), and the kernel's calls — `answers`, `linked`, `shared`, `open`, and
//! `resolve` on what they open — answer the same through either origin.
//!
//! RED arms: a name no linked row answers has no shared instance; a dropped-in plugin is not linked
//! and has no shared instance; a dropped set replaced by an empty one answers nothing; a door of
//! another kind is refused.

use std::sync::Arc;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::ERROR_KIND_NOT_FOUND;
use busbar_contract::secret::{SecretAxis, SecretRefused};
use busbar_contract::secret_ref::SecretRef;

use super::SecretRows;
use crate::boot::{Candidate, Origin};
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};

use crate::both_ways::{secret_fixture, HOT_FIXTURES};
use crate::hook_door_conformance_tests::hook_door_plugin;
use secret_fixture::door::door;
use secret_fixture::NAME;

/// The material the hit's variable holds.
const MATERIAL: &str = "s3cr3t-secret-calls";
/// The variable the hit names (set) and the one the miss names (never set).
const HIT: &str = "BUSBAR_LOADER_SECRET_CALLS_HIT";
const MISS: &str = "BUSBAR_LOADER_SECRET_CALLS_MISS";

/// The process environment the env source reads: the hit set, the miss unset.
fn environment() {
    std::env::set_var(HIT, MATERIAL);
    std::env::remove_var(MISS);
}

fn dispatcher() -> Arc<Dispatcher> {
    static ONE: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    ONE.get_or_init(|| Arc::new(Dispatcher::new(DispatchConfig::default())))
        .clone()
}

/// The env source's module settings: it holds none, so any object opens it.
fn settings() -> serde_json::Value {
    serde_json::json!({})
}

/// A resolver no plugin reference reaches (the env source states no `secret_refs`).
fn unreached(r: &SecretRef) -> Result<Vec<u8>, String> {
    panic!("no secret reference to resolve: {}", r.describe())
}

/// Two resolves through `opened`: the hit and the miss.
fn resolves(opened: &dyn busbar_contract::secret::SecretCalls) -> Vec<String> {
    let spell = |r: Result<busbar_contract::redacted::Redacted<Vec<u8>>, SecretRefused>| match r {
        Ok(m) => format!("ok {}", String::from_utf8_lossy(m.expose_secret())),
        Err(e) => format!("refused {} {}", e.error_kind, e.text),
    };
    vec![
        spell(opened.resolve(format!(r#"{{"key":"{HIT}"}}"#).as_bytes())),
        spell(opened.resolve(format!(r#"{{"key":"{MISS}"}}"#).as_bytes())),
    ]
}

/// What `axis` answers for the plugin: its open over [`settings`] and two resolves.
fn transcript(axis: &dyn SecretAxis) -> Vec<String> {
    let opened = axis
        .open(NAME, &settings(), &unreached)
        .expect("the env source opens over its settings");
    resolves(opened.as_ref())
}

/// A linked door is answered by name, opened per module configuration through the one dispatcher,
/// and its refusal carries the plugin's own code and text.
#[test]
fn a_linked_secret_plugin_answers_and_resolves_through_the_axis() {
    environment();
    let mut rows = SecretRows::new(dispatcher, || None);
    rows.link(door).expect("the env source's door links");
    assert!(rows.answers(NAME) && rows.linked(NAME));
    assert!(!rows.answers("vault") && !rows.linked("vault"));
    let t = transcript(&rows);
    assert_eq!(t[0], format!("ok {MATERIAL}"));
    assert!(
        t[1].starts_with(&format!("refused {ERROR_KIND_NOT_FOUND} ")),
        "{}",
        t[1]
    );
    // The shared instance opens with no settings (the env source holds none) and answers as the
    // configured one does.
    let shared = rows
        .shared(NAME)
        .expect("the linked env source has a shared instance");
    assert_eq!(resolves(shared.as_ref()), t);
    // RED: a name no linked row answers has no shared instance.
    let refused = rows.shared("vault").err().expect("no row answers `vault`");
    assert_eq!(refused, "no linked secret module answers to 'vault'");
}

/// A dropped-in plugin answers as the linked one does, is not linked, and leaves with its set.
#[test]
fn a_dropped_in_secret_plugin_is_the_same_plugin_through_the_axis() {
    environment();
    let (_, logic) = HOT_FIXTURES
        .iter()
        .find(|(k, _)| *k == "secret")
        .expect("a `secret` row in Cargo.toml's [package.metadata.busbar.both-ways]");
    // The row names the repo's logic crate; the fleet's twin shape names its cdylib `<logic>_plugin`.
    let Some(path) = crate::both_ways::cdylib(&format!("{logic}_plugin")) else {
        return;
    };
    let stated = rendering_of(door).expect("the door renders its Statement");
    let bytes = std::fs::read(&path).expect("the plugin's cdylib reads");
    let candidate = Candidate::from_rendering(
        stated,
        None,
        Origin::Dropped {
            file: format!("{logic}.tar.gz").into(),
            bytes: Arc::new(bytes),
        },
    )
    .expect("the rendering reads back");
    assert_eq!(candidate.kind, KindCode::Secret);
    let rows = SecretRows::new(dispatcher, || None);
    rows.set_dropped([candidate]);
    assert!(rows.answers(NAME) && !rows.linked(NAME));
    assert!(
        rows.shared(NAME).is_err(),
        "a dropped-in plugin has no shared instance"
    );

    let mut linked = SecretRows::new(dispatcher, || None);
    linked.link(door).expect("the env source's door links");
    assert_eq!(
        transcript(&rows),
        transcript(&linked),
        "the two origins differ"
    );

    // RED: the set replaced by an empty one answers nothing.
    rows.set_dropped(std::iter::empty());
    assert!(!rows.answers(NAME));
}

/// RED: a door of another kind is refused on the secret axis.
#[test]
fn a_door_of_another_kind_is_refused() {
    let mut rows = SecretRows::new(dispatcher, || None);
    let err = rows
        .link(hook_door_plugin::conforming::door)
        .expect_err("a hook door is not a secret one");
    assert!(err.contains("not a secret one"), "{err}");
}
