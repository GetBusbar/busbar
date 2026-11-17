// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALIAS (ABI-MIN3-INTERFACE §14): `former_names` words, `NameConflict`, the plugins.yaml manifest job and
//! `module:` resolution (rounds 9, 11, 12).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_loader::refusal::RefusalCode;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::CallCx;

use crate::min3_second::{self as fx, ALIAS, ALIAS_WORDS};

fn cx(id: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: id,
        stack: CallStack::default(),
    }
}

/// L2's arm: the generic `module:` match resolves the identity and then each `former_names` word to the one
/// admitted image, an instance opens under every word, and `Registry::add` refuses `NameConflict` for a
/// newcomer whose word equals an admitted identity or word, whose identity equals an admitted word, or whose
/// identity is already admitted; a refused newcomer answers to nothing, whatever the admission order.
#[test]
fn former_names_match_and_name_conflict_at_add() {
    let h = Harness::admit(fx::alias::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("the alias image is admitted: {r:?}"));
    assert_eq!(h.identity(), ALIAS);

    for word in [ALIAS, ALIAS_WORDS[0], ALIAS_WORDS[1]] {
        assert_eq!(
            h.registry().identity_of(word).as_deref(),
            Some(ALIAS),
            "module: {word} resolves to the alias image"
        );
    }
    assert_eq!(h.registry().identity_of("alias-unknown"), None);

    for (at, word) in [ALIAS, ALIAS_WORDS[0], ALIAS_WORDS[1]]
        .into_iter()
        .enumerate()
    {
        let name = format!("alias-{at}");
        let config = format!(r#"{{"tag":"{name}"}}"#);
        let spec = h.spec_for(word, &name, config.as_bytes());
        let port = h
            .block_on(
                h.registry()
                    .open_secret(&spec, &h.needs_arc(), &h.refs_arc()),
            )
            .unwrap_or_else(|e| panic!("module: {word} opens: {e:?}"));
        let answer = h
            .block_on(port.resolve(cx(at as u64 + 1), br#"{"name":"db"}"#))
            .ok()
            .unwrap_or_else(|| panic!("the instance opened as {word} resolves"));
        assert_eq!(answer.value.as_slice(), b"db");
        assert_eq!(fx::count(&name, "built"), 1);
    }

    let conflicts = [
        (
            fx::alias_identity_word::PLUGIN.plugin(),
            "former_names",
            ALIAS,
        ),
        (
            fx::alias_shared_word::PLUGIN.plugin(),
            "former_names",
            ALIAS_WORDS[0],
        ),
        (
            fx::alias_named_word::PLUGIN.plugin(),
            "identity",
            ALIAS_WORDS[0],
        ),
        (fx::alias::PLUGIN.plugin(), "identity", ALIAS),
    ];
    for (plugin, field, word) in conflicts {
        let refused = Harness::admit_all(&[fx::alias::PLUGIN.plugin(), plugin], FakeNeeds::new())
            .err()
            .unwrap_or_else(|| panic!("a newcomer answering to {word} is refused"));
        assert_eq!(
            (refused.code, refused.field, refused.have.as_str()),
            (RefusalCode::NameConflict, field, word),
            "{refused:?}"
        );
    }
    for refused in ["fixture-alias-b", "fixture-alias-c"] {
        assert_eq!(
            h.registry().identity_of(refused),
            None,
            "{refused} was not admitted"
        );
    }
    assert_eq!(
        h.registry().identity_of(ALIAS_WORDS[0]).as_deref(),
        Some(ALIAS)
    );

    // The other order: the word's owner admitted first, the alias image is the newcomer refused.
    let first = Harness::admit(fx::alias_shared_word::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("{r:?}"));
    let refused = Harness::admit_all(
        &[
            fx::alias_shared_word::PLUGIN.plugin(),
            fx::alias::PLUGIN.plugin(),
        ],
        FakeNeeds::new(),
    )
    .err()
    .unwrap_or_else(|| panic!("the alias image shares alias-old"));
    assert_eq!(
        (refused.code, refused.field, refused.have.as_str()),
        (RefusalCode::NameConflict, "former_names", ALIAS_WORDS[0])
    );
    assert_eq!(first.registry().identity_of(ALIAS), None);
}

#[test]
#[ignore = "owner: W1-X1; blocked (re-checked on dev 2026-11-16): a busbar-ci-checks job and fixture, not a plugin-test arm; no job on dev"]
fn the_plugins_yaml_manifest_job() {
    todo!("owner: W1-X1 (C-ALIAS)")
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn every_word_resolves_module_in_old_and_current_configs() {
    todo!("owner: W1-K9 (C-ALIAS)")
}

/// Image grammar is available without a binder or an instance Needs implementation. Extending a candidate
/// cannot mutate an already-frozen generation, and duplicate admission still refuses by name.
#[test]
fn described_images_are_available_before_registry_construction() {
    use busbar_plugin_abi::host_side::HOST;
    use busbar_plugin_loader::admit::admit_linked;
    use busbar_plugin_loader::instance::{Ceilings, ImagesBuilder, SlotTable};
    use std::sync::Arc;

    let slots = Arc::new(SlotTable::new());
    let mut builder = ImagesBuilder::new(&HOST, slots, Ceilings::DEFAULT);
    builder
        .admit(admit_linked(&fx::alias::PLUGIN).expect("linked header"))
        .expect("describe");
    let images = builder.finish();
    assert_eq!(images.identity_of(ALIAS_WORDS[0]).as_deref(), Some(ALIAS));
    assert!(images.described(ALIAS).is_some());
    let mut candidate = images.extend();
    let refused = candidate
        .admit(admit_linked(&fx::alias_shared_word::PLUGIN).expect("linked header"))
        .expect_err("a conflicting candidate must refuse");
    assert_eq!(refused.code, RefusalCode::NameConflict);
    assert_eq!(images.identity_of("fixture-alias-c"), None);
    assert_eq!(images.identity_of(ALIAS_WORDS[0]).as_deref(), Some(ALIAS));
}
