// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `unit`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::unit_conformance`. This file is THE SAME
//! FILE, modulo this crate's own type and step, in every sibling of the kind — so a ruling added to
//! the battery reaches all fourteen crates on their next build instead of being hand-copied
//! fourteen times and drifting, which is exactly what `kind-isolation:testkit` found.
//!
//! **Why this sibling carries fixtures the others do not.** `Verbs` is generic over its four
//! integration seams, so naming the type at all takes four concrete parameters. The stubs below are
//! inhabited-but-unreachable: every method is `unimplemented!()`, because the declaration half of
//! the battery reads associated items off the TYPE and never calls one. That also makes them an
//! honest statement — this file proves the shape, not the behaviour.
//!
//! **The answer half is OWED here.** This unit SERVES its step (it is a destination at Route), so
//! its battery arm is `assert_total` rather than `assert_answers`, and executing a verb needs a
//! live governance binding. `busbar-unit-scope` and `busbar-unit-auth` are the kind's worked
//! examples of the full battery.

use busbar_caps::{AdminToken, StepName};
use busbar_plugin_testkit::unit_conformance as conf;
use busbar_unit_verbs::governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
use busbar_unit_verbs::idempotency::ReplayEncoder;
use busbar_unit_verbs::store::{Store, StoreError};
use busbar_unit_verbs::verb::KernelVerb;
use busbar_unit_verbs::verbs::{MintedKeyOutcome, NonceSource, Verbs};

struct NoGovernance;

impl Governance for NoGovernance {
    fn group_exists(&self, _name: &str) -> bool {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn actual_parent(&self, _name: &str) -> Option<String> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn provision_group(
        &self,
        _admin: &AdminToken,
        _group: &str,
        _parent: &str,
    ) -> Result<(), GovernanceError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn mint_key(
        &self,
        _admin: &AdminToken,
        _group: Option<&str>,
    ) -> Result<MintedKey, GovernanceError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn rotate_key(&self, _admin: &AdminToken, _id: &str) -> Result<RotateOutcome, GovernanceError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn execute_new_verb(
        &self,
        _verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        unimplemented!("conformance reads the type, never calls it")
    }
}

struct NoStore;

impl Store for NoStore {
    fn chain_break(&self, _admin: &AdminToken) -> Result<(), StoreError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn store_restore(&self, _admin: &AdminToken, _backup_ref: &str) -> Result<(), StoreError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn reseal_epoch_floor(&self, _admin: &AdminToken) -> Result<(), StoreError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn replay_new_verb(&self, _key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError> {
        unimplemented!("conformance reads the type, never calls it")
    }
    fn commit_new_verb_replay(
        &self,
        _key: &(String, String),
        _response: &[u8],
    ) -> Result<(), StoreError> {
        unimplemented!("conformance reads the type, never calls it")
    }
}

struct NoNonce;

impl NonceSource for NoNonce {
    fn fill(&self, _buf: &mut [u8; 16]) {
        unimplemented!("conformance reads the type, never calls it")
    }
}

struct NoEncoder;

impl ReplayEncoder<MintedKeyOutcome> for NoEncoder {
    fn encode(&self, _value: &MintedKeyOutcome) -> Vec<u8> {
        unimplemented!("conformance reads the type, never calls it")
    }
}

#[test]
fn the_kind_has_one_entry_and_it_names_its_own_step() {
    conf::assert_owns_one_step::<Verbs<NoGovernance, NoStore, NoNonce, NoEncoder>>(StepName::Route);
}
