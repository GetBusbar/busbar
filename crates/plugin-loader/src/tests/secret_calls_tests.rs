// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SECRET AXIS OVER THE ONE DISPATCHER** (TODO step 28): [`SecretRows`] holds the kind's
//! fixture (`secret_door_plugin`) LINKED (its door) and DROPPED IN (its example cdylib, as the
//! registry discovers it), and the kernel's calls — `answers`, `linked`, `shared`, `open`, and
//! `resolve` on what they open — answer the same through either origin.
//!
//! RED arms: a linked plugin that refuses its open answers 1.5.5's open-failure words through
//! `shared`; a dropped-in plugin is not linked and has no shared instance; a dropped set replaced
//! by an empty one answers nothing.

use std::sync::Arc;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::ERROR_KIND_NOT_FOUND;
use busbar_contract::secret::{SecretAxis, SecretRefused};
use busbar_contract::secret_ref::SecretRef;

use super::SecretRows;
use crate::boot::{Candidate, Origin};
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};

// The fixtures, as the door conformance tests already load them (one module per file).
use crate::hook_door_conformance_tests::hook_door_plugin;
use crate::secret_door_conformance_tests::secret_door_plugin::{conforming, NAME};

fn dispatcher() -> Arc<Dispatcher> {
    static ONE: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    ONE.get_or_init(|| Arc::new(Dispatcher::new(DispatchConfig::default())))
        .clone()
}

/// The fixture's module settings: one name and its material.
fn settings() -> serde_json::Value {
    serde_json::json!({"values": {"db": "fixture-material"}})
}

/// A resolver no fixture reference reaches (the fixture states no `secret_refs`).
fn unreached(r: &SecretRef) -> Result<Vec<u8>, String> {
    panic!("no secret reference to resolve: {}", r.describe())
}

/// What `axis` answers for the fixture: its open over [`settings`] and two resolves.
fn transcript(axis: &dyn SecretAxis) -> Vec<String> {
    let opened = axis
        .open(NAME, &settings(), &unreached)
        .expect("the fixture opens over its settings");
    let spell = |r: Result<busbar_contract::redacted::Redacted<Vec<u8>>, SecretRefused>| match r {
        Ok(m) => format!("ok {}", String::from_utf8_lossy(m.expose_secret())),
        Err(e) => format!("refused {} {}", e.error_kind, e.text),
    };
    vec![
        spell(opened.resolve(br#"{"name":"db"}"#)),
        spell(opened.resolve(br#"{"name":"nope"}"#)),
    ]
}

/// A linked door is answered by name, opened per module configuration through the one dispatcher,
/// and its refusal carries the plugin's own code and text.
#[test]
fn a_linked_secret_plugin_answers_and_resolves_through_the_axis() {
    let mut rows = SecretRows::new(dispatcher, || None);
    rows.link(conforming::door)
        .expect("the fixture's door links");
    assert!(rows.answers(NAME) && rows.linked(NAME));
    assert!(!rows.answers("vault") && !rows.linked("vault"));
    let t = transcript(&rows);
    assert_eq!(t[0], "ok fixture-material");
    assert!(
        t[1].starts_with(&format!("refused {ERROR_KIND_NOT_FOUND} ")),
        "{}",
        t[1]
    );
    // RED: the shared instance opens with no settings, which this fixture refuses, in 1.5.5's words.
    let refused = rows.shared(NAME).err().expect("the fixture needs settings");
    assert!(
        refused.starts_with(&format!("plugin '{NAME}' open failed: ")),
        "{refused}"
    );
    assert!(rows.shared("vault").is_err());
}

/// A dropped-in plugin answers as the linked one does, is not linked, and leaves with its set.
#[test]
fn a_dropped_in_secret_plugin_is_the_same_plugin_through_the_axis() {
    let Some(path) = crate::both_ways::example_cdylib("secret_door") else {
        return;
    };
    let stated = rendering_of(conforming::door).expect("the door renders its Statement");
    let bytes = std::fs::read(&path).expect("the example cdylib reads");
    let candidate = Candidate::from_rendering(
        stated,
        None,
        Origin::Dropped {
            file: "secret_door.tar.gz".into(),
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
    linked
        .link(conforming::door)
        .expect("the fixture's door links");
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
