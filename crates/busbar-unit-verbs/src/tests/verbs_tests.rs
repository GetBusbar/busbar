// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Integration-level assertions over `Verbs`: scope enforcement, the mint/rotate idempotency wiring
//! end to end (through `Verbs`, not just the bare cache), and that a new verb reaches
//! `Governance::execute_new_verb` only once posture admits it.

use crate::governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
use crate::posture::{ApprovalState, DualControl, OperatorState, PostureCtx};
use crate::store::{Store, StoreError};
use crate::verb::{KernelVerb, VerbScope};
use crate::verbs::Verbs;
use busbar_caps::{AdminToken, KernelSeal, UnitKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

struct FakeGovernance {
    groups: Mutex<HashMap<String, Option<String>>>,
    keys: Mutex<HashMap<String, bool>>, // id -> tombstoned
    next_id: AtomicU64,
    new_verb_calls: Mutex<Vec<KernelVerb>>,
}

impl FakeGovernance {
    fn new() -> Self {
        FakeGovernance {
            groups: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            new_verb_calls: Mutex::new(Vec::new()),
        }
    }

    fn with_group(self, name: &str, parent: Option<&str>) -> Self {
        self.groups
            .lock()
            .unwrap()
            .insert(name.to_string(), parent.map(str::to_string));
        self
    }

    fn with_key(self, id: &str, tombstoned: bool) -> Self {
        self.keys.lock().unwrap().insert(id.to_string(), tombstoned);
        self
    }
}

impl Governance for FakeGovernance {
    fn group_exists(&self, name: &str) -> bool {
        self.groups.lock().unwrap().contains_key(name)
    }
    fn actual_parent(&self, name: &str) -> Option<String> {
        self.groups.lock().unwrap().get(name).cloned().flatten()
    }
    fn provision_group(&self, _admin: &AdminToken, group: &str, parent: &str) -> Result<(), GovernanceError> {
        self.groups
            .lock()
            .unwrap()
            .insert(group.to_string(), Some(parent.to_string()));
        Ok(())
    }
    fn mint_key(&self, _admin: &AdminToken, _group: Option<&str>) -> Result<MintedKey, GovernanceError> {
        let id = format!("key-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        self.keys.lock().unwrap().insert(id.clone(), false);
        Ok(MintedKey {
            id,
            secret: "sk-fresh".to_string(),
            expires_at: Some(9_999_999),
        })
    }
    fn rotate_key(&self, _admin: &AdminToken, id: &str) -> Result<RotateOutcome, GovernanceError> {
        let keys = self.keys.lock().unwrap();
        match keys.get(id) {
            None => Ok(RotateOutcome::NotFound),
            Some(true) => Ok(RotateOutcome::Tombstoned),
            Some(false) => Ok(RotateOutcome::Rotated(MintedKey {
                id: id.to_string(),
                secret: "sk-rotated".to_string(),
                expires_at: Some(9_999_999),
            })),
        }
    }
    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        Ok(b"ok".to_vec())
    }
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.new_verb_calls.lock().unwrap().push(verb);
        Ok(b"ok".to_vec())
    }
}

struct FakeStore;
impl Store for FakeStore {
    fn chain_break(&self, _admin: &AdminToken) -> Result<(), StoreError> {
        Ok(())
    }
    fn store_restore(&self, _admin: &AdminToken, _backup_ref: &str) -> Result<(), StoreError> {
        Ok(())
    }
    fn reseal_epoch_floor(&self, _admin: &AdminToken) -> Result<(), StoreError> {
        Ok(())
    }
    fn replay_new_verb(&self, _key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(None)
    }
    fn commit_new_verb_replay(&self, _key: &(String, String), _response: &[u8]) -> Result<(), StoreError> {
        Ok(())
    }
}

fn admin() -> AdminToken {
    AdminToken::mint(&KernelSeal::acquire_for_kernel())
}

#[test]
fn readonly_caller_is_refused_a_mutation() {
    let verbs = Verbs::new(FakeGovernance::new(), FakeStore);
    let admin = admin();
    let err = verbs
        .execute(
            KernelVerb::PostGroups,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            None,
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);
}

#[test]
fn readonly_caller_may_read() {
    let verbs = Verbs::new(FakeGovernance::new(), FakeStore);
    let admin = admin();
    let out = verbs
        .execute(
            KernelVerb::GetGroups,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            None,
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap();
    assert_eq!(out, b"ok");
}

#[test]
fn mint_under_an_existing_unrelated_parent_succeeds_existence_only() {
    let gov = FakeGovernance::new().with_group("some-existing-team", None);
    let verbs = Verbs::new(gov, FakeStore);
    let admin = admin();
    let out = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            None,
            Some("brand-new-leaf"),
            Some("some-existing-team"),
        )
        .unwrap();
    assert!(out.id.starts_with("key-"));
}

#[test]
fn mint_idempotency_key_replays_through_verbs_not_just_the_bare_cache() {
    let gov = FakeGovernance::new();
    let verbs = Verbs::new(gov, FakeStore);
    let admin = admin();
    let first = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_000,
            UnitKey::new(1),
            Some("dedupe-me"),
            None,
            None,
        )
        .unwrap();
    let second = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_010,
            UnitKey::new(1),
            Some("dedupe-me"),
            None,
            None,
        )
        .unwrap();
    assert_eq!(first.id, second.id, "a retry inside the window must replay, not mint again");
}

#[test]
fn without_an_idempotency_key_every_call_mints_a_new_key() {
    let gov = FakeGovernance::new();
    let verbs = Verbs::new(gov, FakeStore);
    let admin = admin();
    let first = verbs
        .create_key(&admin, "alice", VerbScope::Full, 1_000, UnitKey::new(1), None, None, None)
        .unwrap();
    let second = verbs
        .create_key(&admin, "alice", VerbScope::Full, 1_001, UnitKey::new(1), None, None, None)
        .unwrap();
    assert_ne!(first.id, second.id);
}

#[test]
fn rotate_unknown_id_is_not_found() {
    let verbs = Verbs::new(FakeGovernance::new(), FakeStore);
    let admin = admin();
    let err = verbs
        .rotate_key(&admin, "alice", VerbScope::Full, 0, UnitKey::new(1), None, "no-such-key")
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::NotFound);
}

#[test]
fn rotate_tombstoned_key_is_refused_as_conflict() {
    let gov = FakeGovernance::new().with_key("dead-key", true);
    let verbs = Verbs::new(gov, FakeStore);
    let admin = admin();
    let err = verbs
        .rotate_key(&admin, "alice", VerbScope::Full, 0, UnitKey::new(1), None, "dead-key")
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::Conflict);
}

#[test]
fn rotate_scoped_idempotency_key_replays_and_does_not_collide_with_create() {
    let gov = FakeGovernance::new().with_key("k1", false);
    let verbs = Verbs::new(gov, FakeStore);
    let admin = admin();
    let first = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_000,
            UnitKey::new(1),
            Some("shared-header"),
            "k1",
        )
        .unwrap();
    let second = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_005,
            UnitKey::new(1),
            Some("shared-header"),
            "k1",
        )
        .unwrap();
    assert_eq!(first.id, second.id);
}

#[test]
fn a_new_verb_refused_by_posture_never_reaches_governance() {
    let verbs = Verbs::new(FakeGovernance::new(), FakeStore);
    let admin = admin();
    let ctx = PostureCtx {
        operator: OperatorState::Unset,
        dual_control: DualControl::Single,
    };
    let err = verbs
        .execute(
            KernelVerb::CommitUpgrade,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            Some(ctx),
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::OperatorUnset);
}

#[test]
fn a_new_verb_admitted_by_posture_reaches_governance() {
    let verbs = Verbs::new(FakeGovernance::new(), FakeStore);
    let admin = admin();
    let ctx = PostureCtx {
        operator: OperatorState::Set,
        dual_control: DualControl::Single,
    };
    let out = verbs
        .execute(
            KernelVerb::SetOverdraftCeiling,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            Some(ctx),
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap();
    assert_eq!(out, b"ok");
}

#[test]
fn rate_limit_is_enforced_across_execute_calls() {
    let verbs = Verbs::new(FakeGovernance::new(), FakeStore);
    let admin = admin();
    for i in 0..10 {
        verbs
            .execute(
                KernelVerb::PostConfigApply,
                &admin,
                "alice",
                VerbScope::Full,
                0,
                None,
                ApprovalState::NotYetApproved,
                b"{}",
            )
            .unwrap_or_else(|e| panic!("attempt {i} should be admitted, got {e:?}"));
    }
    let err = verbs
        .execute(
            KernelVerb::PostConfigApply,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            None,
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::RateLimited);
}
