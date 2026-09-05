// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Integration-level assertions over `Verbs`: scope enforcement, the mint/rotate idempotency wiring
//! end to end (through `Verbs`, not just the bare cache), and that a new verb reaches
//! `Governance::execute_new_verb` only once posture admits it.

use crate::governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
use crate::idempotency::ReplayEncoder;
use crate::posture::{ApprovalState, DualControl, OperatorState, PostureCtx};
use crate::rate::CONFIG_CLASS_RULES;
use crate::store::{Store, StoreError};
use crate::verb::{KernelVerb, VerbScope};
use crate::verbs::{MintedKeyOutcome, NonceSource, Verbs};
use busbar_caps::{AdminToken, KernelSeal, UnitKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

/// A deterministic, test-only nonce source: fills the buffer from a counter, so two mints in the
/// same test produce different, reproducible nonces. Never used outside tests — the seam has no
/// `Default`, so a real caller must bind a real CSPRNG.
struct CountingNonceSource(AtomicU8);

impl CountingNonceSource {
    fn new() -> Self {
        CountingNonceSource(AtomicU8::new(0))
    }
}

impl NonceSource for CountingNonceSource {
    fn fill(&self, buf: &mut [u8; 16]) {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        buf.fill(0);
        buf[15] = n;
    }
}

/// A test-only encoder standing in for the admin plane's own writer: renders the minted id and
/// expiry as bytes, standing in for "the JSON body the plane was about to send".
struct FakeReplayEncoder;

impl ReplayEncoder<MintedKeyOutcome> for FakeReplayEncoder {
    fn encode(&self, outcome: &MintedKeyOutcome) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(outcome.id.as_bytes());
        out.push(0);
        out.extend_from_slice(&outcome.expires_at.unwrap_or(0).to_le_bytes());
        out
    }
}

fn make_verbs<G: Governance>(
    gov: G,
) -> Verbs<G, FakeStore, CountingNonceSource, FakeReplayEncoder> {
    Verbs::new(
        gov,
        FakeStore,
        CountingNonceSource::new(),
        FakeReplayEncoder,
        CONFIG_CLASS_RULES,
    )
}

struct FakeGovernance {
    groups: Mutex<HashMap<String, Option<String>>>,
    keys: Mutex<HashMap<String, bool>>, // id -> tombstoned
    next_id: AtomicU64,
    new_verb_calls: Mutex<Vec<KernelVerb>>,
    /// What every mutating governance call should fail with, if anything.
    ///
    /// Without this the fail-closed arm of `GovernanceError::into_refusal` is unreachable from any
    /// test: a double that can only succeed proves the happy path and nothing else, and a store that
    /// went away is the case the mapping exists for.
    fails_with: Mutex<Option<GovernanceError>>,
}

impl FakeGovernance {
    fn new() -> Self {
        FakeGovernance {
            groups: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            new_verb_calls: Mutex::new(Vec::new()),
            fails_with: Mutex::new(None),
        }
    }

    /// Every mutating call refuses with this error until it is cleared.
    fn failing_with(self, error: GovernanceError) -> Self {
        *self.fails_with.lock().unwrap() = Some(error);
        self
    }

    /// The injected failure, taken fresh for each call so a double can refuse more than once.
    fn injected(&self) -> Option<GovernanceError> {
        match *self.fails_with.lock().unwrap() {
            None => None,
            Some(GovernanceError::NotFound) => Some(GovernanceError::NotFound),
            Some(GovernanceError::Conflict) => Some(GovernanceError::Conflict),
            Some(GovernanceError::Validation) => Some(GovernanceError::Validation),
            Some(GovernanceError::Store) => Some(GovernanceError::Store),
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
    fn provision_group(
        &self,
        _admin: &AdminToken,
        group: &str,
        parent: &str,
    ) -> Result<(), GovernanceError> {
        if let Some(e) = self.injected() {
            return Err(e);
        }
        self.groups
            .lock()
            .unwrap()
            .insert(group.to_string(), Some(parent.to_string()));
        Ok(())
    }
    fn mint_key(
        &self,
        _admin: &AdminToken,
        _group: Option<&str>,
    ) -> Result<MintedKey, GovernanceError> {
        if let Some(e) = self.injected() {
            return Err(e);
        }
        let id = format!("key-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        self.keys.lock().unwrap().insert(id.clone(), false);
        Ok(MintedKey {
            id,
            secret: "sk-fresh".to_string(),
            expires_at: Some(9_999_999),
        })
    }
    fn rotate_key(&self, _admin: &AdminToken, id: &str) -> Result<RotateOutcome, GovernanceError> {
        if let Some(e) = self.injected() {
            return Err(e);
        }
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
        if let Some(e) = self.injected() {
            return Err(e);
        }
        Ok(b"ok".to_vec())
    }
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        if let Some(e) = self.injected() {
            return Err(e);
        }
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
    fn commit_new_verb_replay(
        &self,
        _key: &(String, String),
        _response: &[u8],
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

fn admin() -> AdminToken {
    AdminToken::mint(&KernelSeal::acquire_for_kernel())
}

#[test]
fn readonly_caller_is_refused_a_mutation() {
    let verbs = make_verbs(FakeGovernance::new());
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
    let verbs = make_verbs(FakeGovernance::new());
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
    let verbs = make_verbs(gov);
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
    let outcome = out
        .minted_outcome()
        .expect("first call must mint, not replay");
    assert!(outcome.id.starts_with("key-"));
}

#[test]
fn mint_idempotency_key_replays_through_verbs_not_just_the_bare_cache() {
    let gov = FakeGovernance::new();
    let verbs = make_verbs(gov);
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
    assert!(!first.is_replay());
    let first_body = first.body().to_vec();
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
    assert!(
        second.is_replay(),
        "a retry inside the window must replay, not mint again"
    );
    assert_eq!(
        second.body(),
        first_body.as_slice(),
        "CG-40: same-node replay must be byte-identical to the first response"
    );
}

#[test]
fn without_an_idempotency_key_every_call_mints_a_new_key() {
    let gov = FakeGovernance::new();
    let verbs = make_verbs(gov);
    let admin = admin();
    let first = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_000,
            UnitKey::new(1),
            None,
            None,
            None,
        )
        .unwrap();
    let second = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_001,
            UnitKey::new(1),
            None,
            None,
            None,
        )
        .unwrap();
    assert!(!first.is_replay());
    assert!(!second.is_replay());
    assert_ne!(
        first.minted_outcome().unwrap().id,
        second.minted_outcome().unwrap().id
    );
}

/// CG-40: a same-node replay is byte-identical to the first response, and a fresh mint is never
/// returned on replay — the `MintOutcome::Replayed` arm carries no `MintedKeyOutcome` at all, so
/// there is no decode step that could reconstruct (and thereby re-mint) a fresh `SecretOnce`.
#[test]
fn replay_is_byte_identical_and_never_a_fresh_mint() {
    let gov = FakeGovernance::new();
    let verbs = make_verbs(gov);
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
    let first_body = first.body().to_vec();
    assert!(first.minted_outcome().is_some(), "the first call must mint");

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
    assert!(
        second.minted_outcome().is_none(),
        "a replay must never carry a fresh MintedKeyOutcome"
    );
    assert_eq!(second.body(), first_body.as_slice());
}

/// CG-39: two mints with a real (varying) nonce source produce different nonces — the property the
/// deleted derivable placeholder (a pure function of the unit key and the secret's byte length)
/// could not guarantee.
#[test]
fn two_mints_with_a_real_nonce_source_produce_different_nonces() {
    struct RecordingNonceSource {
        seen: std::sync::Arc<Mutex<Vec<[u8; 16]>>>,
        draws: AtomicU64,
    }
    impl NonceSource for RecordingNonceSource {
        fn fill(&self, buf: &mut [u8; 16]) {
            // Stands in for the secret plugin's CSPRNG: it varies with wall-clock time, and it
            // varies with a per-source counter as well. The counter is what makes the variation a
            // property of the SOURCE rather than of the host's clock granularity — on a platform
            // whose clock ticks more coarsely than the gap between two mints, a clock-only source
            // would hand out the same nonce twice and fail this test for a reason that has nothing
            // to do with what it is proving. Neither term is a function of the unit key or the
            // secret's shape, which is the property that made the deleted placeholder predictable.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let draw = u128::from(self.draws.fetch_add(1, Ordering::SeqCst));
            *buf = (nanos ^ draw.rotate_left(64)).to_be_bytes();
            self.seen.lock().unwrap().push(*buf);
        }
    }

    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let gov = FakeGovernance::new();
    let verbs = Verbs::new(
        gov,
        FakeStore,
        RecordingNonceSource {
            seen: seen.clone(),
            draws: AtomicU64::new(0),
        },
        FakeReplayEncoder,
        CONFIG_CLASS_RULES,
    );
    let admin = admin();
    // Two calls with DISTINCT idempotency keys (or none), each therefore minting fresh, and each
    // therefore calling the nonce source exactly once.
    verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_000,
            UnitKey::new(1),
            None,
            None,
            None,
        )
        .unwrap();
    verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_001,
            UnitKey::new(1),
            None,
            None,
            None,
        )
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "each fresh mint calls the nonce source exactly once"
    );
    assert_ne!(
        seen[0], seen[1],
        "two mints with a real source must not share a nonce"
    );
}

#[test]
fn rotate_unknown_id_is_not_found() {
    let verbs = make_verbs(FakeGovernance::new());
    let admin = admin();
    let err = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            None,
            "no-such-key",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::NotFound);
}

#[test]
fn rotate_tombstoned_key_is_refused_as_conflict() {
    let gov = FakeGovernance::new().with_key("dead-key", true);
    let verbs = make_verbs(gov);
    let admin = admin();
    let err = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            None,
            "dead-key",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::Conflict);
}

#[test]
fn rotate_scoped_idempotency_key_replays_and_does_not_collide_with_create() {
    let gov = FakeGovernance::new().with_key("k1", false);
    let verbs = make_verbs(gov);
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
    assert!(!first.is_replay());
    assert!(
        second.is_replay(),
        "the second call inside the window must replay"
    );
    assert_eq!(second.body(), first.body());
}

#[test]
fn a_new_verb_refused_by_posture_never_reaches_governance() {
    let verbs = make_verbs(FakeGovernance::new());
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
    let verbs = make_verbs(FakeGovernance::new());
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

/// A governance whose mint parks inside the call, so a second caller can be observed arriving while
/// the first one's idempotency reservation is genuinely live.
///
/// The in-flight refusal is a fact about two callers overlapping, and there is no other way to hold
/// a reservation open: a single-threaded test only ever sees the reservation already committed or
/// already cleared.
struct GatedGovernance {
    inner: FakeGovernance,
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    /// How many mints actually reached governance, so a refused retry can be shown to have minted
    /// nothing.
    mints: std::sync::Arc<AtomicU64>,
    /// Only the FIRST caller parks. A second one that got this far was not refused, and it must say
    /// so with an assertion rather than by deadlocking the test.
    gate_spent: std::sync::atomic::AtomicBool,
}

impl GatedGovernance {
    fn park(&self) {
        if self
            .gate_spent
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv();
    }
}

impl Governance for GatedGovernance {
    fn group_exists(&self, name: &str) -> bool {
        self.inner.group_exists(name)
    }
    fn actual_parent(&self, name: &str) -> Option<String> {
        self.inner.actual_parent(name)
    }
    fn provision_group(
        &self,
        admin: &AdminToken,
        group: &str,
        parent: &str,
    ) -> Result<(), GovernanceError> {
        self.inner.provision_group(admin, group, parent)
    }
    fn mint_key(
        &self,
        admin: &AdminToken,
        group: Option<&str>,
    ) -> Result<MintedKey, GovernanceError> {
        self.park();
        self.mints.fetch_add(1, Ordering::SeqCst);
        self.inner.mint_key(admin, group)
    }
    fn rotate_key(&self, admin: &AdminToken, id: &str) -> Result<RotateOutcome, GovernanceError> {
        self.park();
        self.inner.rotate_key(admin, id)
    }
    fn execute_legacy(
        &self,
        verb: KernelVerb,
        admin: &AdminToken,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.inner.execute_legacy(verb, admin, request)
    }
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        admin: &AdminToken,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.inner.execute_new_verb(verb, admin, request)
    }
}

/// A retry that arrives while the first call is still running is REFUSED, not served.
///
/// The alternative is minting a second admin key for one request — a credential the client never
/// asked for and will never see. Asserted at the API level, through `Verbs`, because that is where
/// the refusal is client-visible: a regression that collapsed `Probe::InFlight` into `Probe::NoKey`
/// passes every test that only drives the bare cache.
#[test]
fn a_create_that_arrives_while_the_first_is_in_flight_is_refused_not_minted() {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let mints = std::sync::Arc::new(AtomicU64::new(0));
    let verbs = make_verbs(GatedGovernance {
        inner: FakeGovernance::new(),
        entered: entered_tx,
        release: Mutex::new(release_rx),
        mints: mints.clone(),
        gate_spent: std::sync::atomic::AtomicBool::new(false),
    });

    // Everything the run learns is collected first and asserted after the parked thread has been
    // let go: an assertion that fired inside the scope would strand the first call and hang.
    let (retry, first) = std::thread::scope(|scope| {
        let held = scope.spawn(|| {
            let admin = admin();
            verbs.create_key(
                &admin,
                "alice",
                VerbScope::Full,
                1_000,
                UnitKey::new(1),
                Some("dedupe-me"),
                None,
                None,
            )
        });

        // The first call is now inside governance with its reservation live.
        entered_rx.recv().expect("the first call reached the mint");
        let admin = admin();
        let retry = verbs.create_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_001,
            UnitKey::new(1),
            Some("dedupe-me"),
            None,
            None,
        );

        release_tx.send(()).expect("let the first call finish");
        (retry, held.join().expect("the first call did not panic"))
    });

    let err = retry.err().expect("a retry inside the first call's window is refused");
    assert_eq!(err.step, crate::refusal::RefusalStep::Admit);
    assert_eq!(
        err.reason,
        crate::refusal::ReasonCode::IdempotencyInFlight,
        "the client-visible reason for an overlapping retry"
    );

    let first = first.expect("the first call succeeds once it is let go");
    assert!(first.minted_outcome().is_some(), "exactly one key was minted");
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "the refused retry must not have reached governance at all"
    );
}

/// A rotate retry that overlaps its first call is refused the same way, on the rotate-scoped key.
#[test]
fn a_rotate_that_arrives_while_the_first_is_in_flight_is_refused() {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let verbs = make_verbs(GatedGovernance {
        inner: FakeGovernance::new().with_key("k1", false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
        mints: std::sync::Arc::new(AtomicU64::new(0)),
        gate_spent: std::sync::atomic::AtomicBool::new(false),
    });

    let (retry, first) = std::thread::scope(|scope| {
        let held = scope.spawn(|| {
            let admin = admin();
            verbs.rotate_key(
                &admin,
                "alice",
                VerbScope::Full,
                1_000,
                UnitKey::new(1),
                Some("dedupe-me"),
                "k1",
            )
        });

        entered_rx.recv().expect("the first call reached the rotate");
        let admin = admin();
        let retry = verbs.rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            1_001,
            UnitKey::new(1),
            Some("dedupe-me"),
            "k1",
        );

        release_tx.send(()).expect("let the first call finish");
        (retry, held.join().expect("the first call did not panic"))
    });

    let err = retry.err().expect("a retry inside the first call's window is refused");
    assert_eq!(err.step, crate::refusal::RefusalStep::Admit);
    assert_eq!(err.reason, crate::refusal::ReasonCode::IdempotencyInFlight);
    first.expect("the rotate succeeds once it is let go");
}

/// A store that has gone away refuses, on every governance call, with the reason the mapping names.
///
/// This is the fail-closed arm: it never echoes the cause (several of these calls carry secrets)
/// and it never proceeds as if the call had succeeded. Nothing exercised it end to end before,
/// because the only governance double in this crate could not fail.
#[test]
fn a_governance_store_failure_refuses_with_store_error_on_every_call() {
    let admin = admin();

    // Mint: the group plan is fine, the store underneath is not.
    let verbs = make_verbs(FakeGovernance::new().failing_with(GovernanceError::Store));
    let err = verbs
        .create_key(&admin, "alice", VerbScope::Full, 0, UnitKey::new(1), None, None, None)
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);
    assert_eq!(err.step, crate::refusal::RefusalStep::Verify);

    // Provisioning a leaf group on the way to a mint fails the same way.
    let verbs = make_verbs(
        FakeGovernance::new()
            .with_group("team", None)
            .failing_with(GovernanceError::Store),
    );
    let err = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            None,
            Some("leaf"),
            Some("team"),
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);

    // Rotate.
    let verbs = make_verbs(
        FakeGovernance::new()
            .with_key("k1", false)
            .failing_with(GovernanceError::Store),
    );
    let err = verbs
        .rotate_key(&admin, "alice", VerbScope::Full, 0, UnitKey::new(1), None, "k1")
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);

    // A legacy verb, through the catch-all.
    let verbs = make_verbs(FakeGovernance::new().failing_with(GovernanceError::Store));
    let err = verbs
        .execute(
            KernelVerb::PostGroups,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            None,
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);

    // And a new 1.6.0 verb, once posture has already admitted it.
    let verbs = make_verbs(FakeGovernance::new().failing_with(GovernanceError::Store));
    let err = verbs
        .execute(
            KernelVerb::SetOverdraftCeiling,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            Some(PostureCtx {
                operator: OperatorState::Set,
                dual_control: DualControl::Single,
            }),
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);
}

/// A refused mint leaves nothing behind: no key, and no idempotency entry that would make the
/// client's retry replay a failure it never got an answer for.
#[test]
fn a_store_failure_mid_mint_clears_the_reservation_rather_than_committing_it() {
    let admin = admin();
    let verbs = make_verbs(FakeGovernance::new().failing_with(GovernanceError::Store));

    let err = verbs
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
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);

    // The store comes back; the same idempotency key is a FRESH attempt, not a replayed refusal.
    let verbs = make_verbs(FakeGovernance::new());
    let out = verbs
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
        .expect("a retry after the store recovers mints");
    assert!(out.minted_outcome().is_some());
}

/// The other three governance errors map to their own reasons, so `StoreError` is not a catch-all
/// that would hide a validation mistake behind an infrastructure one.
#[test]
fn the_other_governance_errors_keep_their_own_reasons() {
    let admin = admin();
    for (error, expected) in [
        (GovernanceError::NotFound, crate::refusal::ReasonCode::NotFound),
        (GovernanceError::Conflict, crate::refusal::ReasonCode::Conflict),
        (
            GovernanceError::Validation,
            crate::refusal::ReasonCode::Validation,
        ),
    ] {
        let verbs = make_verbs(FakeGovernance::new().failing_with(error));
        let err = verbs
            .create_key(&admin, "alice", VerbScope::Full, 0, UnitKey::new(1), None, None, None)
            .unwrap_err();
        assert_eq!(err.reason, expected);
    }
}

#[test]
fn rate_limit_is_enforced_across_execute_calls() {
    let verbs = make_verbs(FakeGovernance::new());
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

// ── the five 1.6.0 ledger views ─────────────────────────────────────────────────────────────────

/// Which of the governance seam's three execution methods each verb reached.
///
/// Shared with the test rather than owned by the seam, because `Verbs` takes its governance by
/// value: the log has to outlive the executor for the test to read it. Which method a verb reaches
/// is the whole of what this crate decides about a ledger view, so it is what these tests measure.
type SeamLog = std::sync::Arc<Mutex<Vec<(KernelVerb, &'static str)>>>;

struct RoutingGovernance(SeamLog);

impl Governance for RoutingGovernance {
    fn group_exists(&self, _name: &str) -> bool {
        true
    }
    fn actual_parent(&self, _name: &str) -> Option<String> {
        None
    }
    fn provision_group(
        &self,
        _admin: &AdminToken,
        _group: &str,
        _parent: &str,
    ) -> Result<(), GovernanceError> {
        Ok(())
    }
    fn mint_key(
        &self,
        _admin: &AdminToken,
        _group: Option<&str>,
    ) -> Result<MintedKey, GovernanceError> {
        Err(GovernanceError::Validation)
    }
    fn rotate_key(&self, _admin: &AdminToken, _id: &str) -> Result<RotateOutcome, GovernanceError> {
        Err(GovernanceError::Validation)
    }
    fn execute_legacy(
        &self,
        verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "legacy"));
        Ok(b"legacy".to_vec())
    }
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "new"));
        Ok(b"new".to_vec())
    }
    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "ledger"));
        Ok(b"ledger".to_vec())
    }
}

/// A ledger view reaches the read seam, and reaches it under the posture that refuses every
/// mutation.
///
/// The posture is the part that matters. `operator: unset` with `dual_control: required` is the
/// state a fleet is in before its ceremony has run, and under it the 17 money-governance verbs are
/// refused outright. A read answers anyway — there is nothing about looking at a figure for a
/// maker-checker step to interpose on — and the control below is one of those 17 being refused on
/// the same executor, so the green is the views being exempt rather than the posture check being
/// unwired.
#[test]
fn a_ledger_view_reaches_the_read_seam_under_a_posture_that_refuses_every_mutation() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));
    let posture = Some(PostureCtx {
        operator: OperatorState::Unset,
        dual_control: DualControl::Required,
    });

    for verb in crate::verb::LEDGER_VERBS {
        let body = verbs
            .execute(
                *verb,
                &admin,
                "alice",
                VerbScope::ReadOnly,
                0,
                posture,
                ApprovalState::NotYetApproved,
                b"",
            )
            .unwrap_or_else(|e| panic!("{verb:?} was refused: {e:?}"));
        assert_eq!(body, b"ledger", "{verb:?} did not reach the read seam");
    }

    let refused = verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            posture,
            ApprovalState::NotYetApproved,
            b"",
        )
        .unwrap_err();
    assert_eq!(refused.reason, crate::refusal::ReasonCode::OperatorUnset);

    let reached = log.lock().unwrap().clone();
    assert!(
        reached.iter().all(|(_, seam)| *seam == "ledger"),
        "a ledger view reached a seam that is not the read one: {reached:?}"
    );
    assert_eq!(reached.len(), crate::verb::LEDGER_VERBS.len());
}

/// A view asks for exactly what the legacy `/usage` read asks for, and no more.
#[test]
fn a_ledger_view_requires_what_the_legacy_usage_read_requires() {
    for verb in crate::verb::LEDGER_VERBS {
        assert_eq!(
            crate::verbs::required_scope(*verb),
            crate::verbs::required_scope(KernelVerb::GetUsage),
            "{verb:?} does not require what /usage requires"
        );
        assert_eq!(crate::verbs::required_scope(*verb), VerbScope::ReadOnly);
    }
}

/// A view never spends a mutation slot.
///
/// The failure this pins is quiet and expensive: a view whose class fell through to `Crud` would
/// consume one of the mutations a minute an operator is allowed, so a dashboard polling four
/// balances would exhaust the budget the operator needed to change a config with — and the refusal
/// would name the config change, not the polling.
#[test]
fn a_ledger_view_never_spends_a_mutation_slot() {
    for verb in crate::verb::LEDGER_VERBS {
        assert_eq!(
            crate::rate::MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            crate::rate::MutationClass::Forbidden,
            "{verb:?} is classified as a mutation"
        );
    }
    // The control: a verb that IS a mutation still classifies as one, so the green above is the
    // views being excluded rather than the classifier answering `Forbidden` to everything.
    assert_ne!(
        crate::rate::MutationClass::for_verb(KernelVerb::Adjust, CONFIG_CLASS_RULES),
        crate::rate::MutationClass::Forbidden
    );
}

/// An integrator who has bound no ledger serves nothing, and says so.
///
/// The default is what makes this addition additive: a `Governance` implementation written before
/// the views existed compiles unchanged and answers `NotFound` — which is true, because it has no
/// ledger behind it — rather than inventing zeros that would read as a deployment whose books
/// balance.
#[test]
fn an_unbound_integrator_serves_no_view_rather_than_an_empty_one() {
    struct NoLedger;
    impl Governance for NoLedger {
        fn group_exists(&self, _name: &str) -> bool {
            true
        }
        fn actual_parent(&self, _name: &str) -> Option<String> {
            None
        }
        fn provision_group(
            &self,
            _admin: &AdminToken,
            _group: &str,
            _parent: &str,
        ) -> Result<(), GovernanceError> {
            Ok(())
        }
        fn mint_key(
            &self,
            _admin: &AdminToken,
            _group: Option<&str>,
        ) -> Result<MintedKey, GovernanceError> {
            Err(GovernanceError::Validation)
        }
        fn rotate_key(
            &self,
            _admin: &AdminToken,
            _id: &str,
        ) -> Result<RotateOutcome, GovernanceError> {
            Err(GovernanceError::Validation)
        }
        fn execute_legacy(
            &self,
            _verb: KernelVerb,
            _admin: &AdminToken,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            Ok(Vec::new())
        }
        fn execute_new_verb(
            &self,
            _verb: KernelVerb,
            _admin: &AdminToken,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            Ok(Vec::new())
        }
        // `execute_ledger_read` is DELIBERATELY not written here. That absence is the test.
    }

    let admin = admin();
    let verbs = make_verbs(NoLedger);
    for verb in crate::verb::LEDGER_VERBS {
        let err = verbs
            .execute(
                *verb,
                &admin,
                "alice",
                VerbScope::ReadOnly,
                0,
                None,
                ApprovalState::NotYetApproved,
                b"",
            )
            .unwrap_err();
        assert_eq!(err.reason, crate::refusal::ReasonCode::NotFound);
    }
}
