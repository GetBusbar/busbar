// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STATES ITS PROVIDER KEYS (row 155 B1c, ARCHITECT ruling "Option A"): the descriptor in
//! `meta::PROVIDER_KEYS` is what the door's Statement carries under the contract's one extensions
//! key, it reads in the neutral shape vocabulary, and the one loader hands it on in the plane's
//! registration, unchanged. That each form's keys are the frozen grammar's, in its order, is held
//! where the frozen grammar is reachable (the legacy engine's `provider_keys_drift_tests`). The two
//! cells that read the descriptor through the one loader (the door's Statement rendering and the
//! registration it hands on) live in `tests/conformance.rs`, the one file of a plugin crate that may
//! name the loader (kind-isolation's conformance-witness grant).

use busbar_contract::provider_keys::{decode, encode, ProviderKeys};
use busbar_plane_llm::meta::PROVIDER_KEYS;

fn declared() -> ProviderKeys {
    decode(PROVIDER_KEYS.as_bytes()).expect("the plane's provider keys are a neutral descriptor")
}

/// The descriptor reads, names every form, and round-trips through the contract's encoding.
#[test]
fn the_declared_provider_keys_are_a_neutral_descriptor() {
    let keys = declared();
    for (form, table) in [
        ("catalog", &keys.catalog),
        ("deployment", &keys.deployment),
        ("entry", &keys.entry),
    ] {
        assert!(!table.keys.is_empty(), "the {form} form states its keys");
    }
    assert_eq!(decode(&encode(&keys)), Ok(keys));
}
