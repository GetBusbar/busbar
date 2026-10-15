// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE STATES ITS PROVIDER KEYS (row 155 B1c, ARCHITECT ruling "Option A"): the descriptor in
//! `meta::PROVIDER_KEYS` is what the door's Statement carries under the contract's one extensions
//! key, it reads in the neutral shape vocabulary, and the one loader hands it on in the plane's
//! registration, unchanged. That each form's keys are the frozen grammar's, in its order, is held
//! where the frozen grammar is reachable (the legacy engine's `provider_keys_drift_tests`).

use busbar_contract::abi::mechanism::{extensions, rendering};
use busbar_contract::provider_keys::{decode, encode, ProviderKeys, EXT_PROVIDER_KEYS};
use busbar_plane_llm::meta::PROVIDER_KEYS;
use busbar_plane_llm::plane_door;
use busbar_plugin_loader::dispatch::kinds::plane::{linked_probe, registration};
use busbar_plugin_loader::dispatch::rendering_of;

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

/// The door's signed Statement rendering carries the descriptor under the one extensions key, as
/// octets, byte for byte the declared text.
#[test]
fn the_door_states_its_provider_keys_in_its_statement_extensions() {
    let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
    let read = rendering::read(&stated).expect("the rendering reads back");
    assert_eq!(
        read.extensions.fmt,
        busbar_contract::abi::mechanism::call::BLOB_OCTETS
    );
    assert_eq!(
        extensions::get(&read.extensions.bytes, EXT_PROVIDER_KEYS),
        Some(PROVIDER_KEYS.as_bytes())
    );
}

/// The one loader reads the descriptor off the bound door into the plane's registration, decoded
/// and equal to the declared one.
#[test]
fn the_loader_hands_the_provider_keys_on_in_the_registration() {
    let reg = registration(linked_probe(plane_door::door, "provider-keys-probe"))
        .expect("the linked door binds");
    assert_eq!(reg.provider_keys, Some(declared()));
}
