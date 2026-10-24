// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND → VERB LIST (the config section of the kernel-and-plugins design): every kind's verb
//! round-trips, the six root keys are distinct, and the plane's verb is declared by each plane
//! rather than named here.

use super::*;

/// The list, as the design's config section states it — the one other spelling of it, kept to pin
/// the list.
const DESIGN: [(Kind, Verb); 7] = [
    (Kind::Store, Verb::Root("store")),
    (Kind::Secret, Verb::Root("secrets")),
    (Kind::Auth, Verb::Root("identity-providers")),
    (Kind::Hook, Verb::Root("hooks")),
    (Kind::Export, Verb::Root("export")),
    (Kind::Transport, Verb::Root("providers")),
    (Kind::Plane, Verb::Declared),
];

#[test]
fn every_kind_s_verb_is_the_design_s_and_round_trips() {
    assert_eq!(
        Kind::ALL.len(),
        DESIGN.len(),
        "every kind has exactly one line"
    );
    for (kind, verb) in DESIGN {
        assert_eq!(kind.verb(), verb, "{kind}");
        match verb {
            Verb::Root(key) => {
                assert_eq!(kind.root_key(), Some(key), "{kind}");
                assert_eq!(
                    Kind::owning_root_key(key),
                    Some(kind),
                    "`{key}` round-trips to {kind}"
                );
            }
            Verb::Declared => assert_eq!(kind.root_key(), None, "{kind}"),
        }
    }
}

#[test]
fn no_two_kinds_share_a_root_key_and_a_foreign_key_names_no_kind() {
    let keys: Vec<&str> = Kind::ALL.iter().filter_map(|k| k.root_key()).collect();
    let mut unique = keys.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), keys.len(), "{keys:?}");
    // A core-owned key and a plane's own verb are owned by no kind.
    for key in ["listen", "rate_card", "pools", "models", "tools"] {
        assert_eq!(Kind::owning_root_key(key), None, "`{key}`");
    }
}
