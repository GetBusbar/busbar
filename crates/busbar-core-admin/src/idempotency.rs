// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Mutex;

pub use busbar_kernel::persistence::recovery_api::IDEMPOTENCY_TTL_SECS;

enum KeyOperation<'a> {
    Create,
    Rotate(&'a str),
}

fn key_replay_key(operation: KeyOperation<'_>, header: &str) -> String {
    match operation {
        KeyOperation::Create => format!("create:{}:{}", header.len(), header),
        KeyOperation::Rotate(id) => {
            format!("rotate:{}:{}:{}:{}", id.len(), id, header.len(), header)
        }
    }
}

pub(crate) fn create_replay_key(header: &str) -> String {
    key_replay_key(KeyOperation::Create, header)
}

pub(crate) fn rotate_replay_key(id: &str, header: &str) -> String {
    key_replay_key(KeyOperation::Rotate(id), header)
}

type Slot<V> = (u64, Option<V>, Option<[u8; 32]>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingMismatch;

pub struct IdempotencyCache<V> {
    slots: Mutex<HashMap<(String, String), Slot<V>>>,
}

pub enum Probe<'a, V: Clone> {
    NoKey,

    Reserved(Reservation<'a, V>),

    Replay(V),

    InFlight,
}

impl<V: Clone> IdempotencyCache<V> {
    pub fn new() -> Self {
        IdempotencyCache {
            slots: Mutex::new(HashMap::new()),
        }
    }

    pub fn probe(&self, key: (String, String), now: u64) -> Probe<'_, V> {
        self.probe_inner(key, None, now)
            .expect("unbound replay probe")
    }

    /// Compare the exact request fingerprint before returning any cached answer.
    pub(crate) fn probe_bound(
        &self,
        key: (String, String),
        fingerprint: [u8; 32],
        now: u64,
    ) -> Result<Probe<'_, V>, BindingMismatch> {
        self.probe_inner(key, Some(fingerprint), now)
    }

    fn probe_inner(
        &self,
        key: (String, String),
        fingerprint: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Probe<'_, V>, BindingMismatch> {
        let mut guard = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        // Only completed answers age out. An in-flight sentinel is held until it resolves: a
        // dropped reservation clears itself, so a sentinel that outlives the window marks an
        // effect that may have applied, and sweeping it would admit a second mint or rotate.
        guard.retain(|_, (t, v, _)| v.is_none() || now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        if let Some((_, _, held)) = guard.get(&key) {
            if fingerprint.is_some() && held != &fingerprint {
                return Err(BindingMismatch);
            }
        }
        Ok(match guard.get(&key) {
            Some((_, Some(v), _)) => Probe::Replay(v.clone()),
            Some((_, None, _)) => Probe::InFlight,
            None => {
                guard.insert(key.clone(), (now, None, fingerprint));
                drop(guard);
                Probe::Reserved(Reservation {
                    cache: self,
                    key,
                    live: true,
                    fingerprint,
                })
            }
        })
    }
}

impl<V: Clone> Default for IdempotencyCache<V> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Reservation<'a, V: Clone> {
    cache: &'a IdempotencyCache<V>,
    key: (String, String),
    live: bool,
    fingerprint: Option<[u8; 32]>,
}

impl<'a, V: Clone> Reservation<'a, V> {
    pub fn key(&self) -> &(String, String) {
        &self.key
    }

    pub fn commit(mut self, value: V, now: u64) {
        let mut guard = self.cache.slots.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(self.key.clone(), (now, Some(value), self.fingerprint));
        self.live = false;
    }

    pub fn clear(mut self) {
        self.clear_inner();
        self.live = false;
    }

    pub fn in_flight(&mut self) {
        self.live = false;
    }

    pub fn leak(mut self) {
        self.in_flight();
    }

    fn clear_inner(&self) {
        let mut guard = self.cache.slots.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(guard.get(&self.key), Some((_, None, _))) {
            guard.remove(&self.key);
        }
    }
}

impl<'a, V: Clone> Drop for Reservation<'a, V> {
    fn drop(&mut self) {
        if self.live {
            self.clear_inner();
        }
    }
}

pub mod durable {
    use busbar_contract::Secret;
    use busbar_kernel::persistence::scoped::{
        ClaimOutcome, Expected, Mutation, Outcome, Predicate, Request, ScopedStore,
    };

    use super::{BindingMismatch, IDEMPOTENCY_TTL_SECS};

    pub(crate) const REPLAY_KIND: &str = "busbar.admin-idempotency";

    /// Bind the host-owned admin replay records and token claims to one instance.
    pub fn scoped_store(
        core: std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>,
    ) -> Result<ScopedStore, busbar_kernel::persistence::scoped::Error> {
        ScopedStore::host_private(
            core,
            "busbar.admin",
            [
                REPLAY_KIND.to_string(),
                "busbar.admin-adjust-action.v1".to_string(),
            ],
        )
    }

    const MAX_GENERATIONS: u32 = 64;

    /// Where the bounded sweep resumes: one page per settle, not the whole replay kind.
    static SWEEP_AFTER: std::sync::Mutex<Option<busbar_kernel::persistence::scoped::Cursor>> =
        std::sync::Mutex::new(None);

    const LAYOUT: u8 = 1;

    /// What a claimed key settled to.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Settled {
        /// Refused with nothing done: the next claim may run.
        Released,
        /// Ran; names what it made (e.g. `key:vk_…`). Its answer is not kept.
        Applied(String),
        /// Ran; this is its answer, replayable byte for byte.
        Answer(Vec<u8>),
        /// Sealed or possibly applied; the caller's exact receipt and answer remain in custody.
        /// This outcome never expires merely because the ordinary replay window elapsed.
        Retained(Vec<u8>),
    }

    /// Why a claim was not granted.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Refused {
        /// An earlier call with this key ran and made this; its answer cannot be replayed.
        Applied(String),
        /// An earlier call with this key ran; this is its answer.
        Answer(Vec<u8>),
        /// An earlier call sealed or may have applied; reconcile its exact retained receipt.
        Retained(Vec<u8>),
        /// An earlier call with this key has not settled.
        InFlight,
        /// The store could not answer.
        Unavailable(String),
    }

    /// A claim this caller holds, to [`settle`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Claim {
        id: String,
        generation: u32,
        held: bool,
    }

    fn record_id(key: &(String, String)) -> String {
        let framed = format!("{}:{}:{}", key.0.len(), key.0, key.1);
        busbar_contract::redacted::sha256_hex(framed.as_bytes())
    }

    fn token(id: &str, generation: u32) -> String {
        format!("{id}:{generation}")
    }

    fn held_record_id(id: &str, generation: u32) -> String {
        format!("held:{id}:{generation}")
    }

    struct HeldHead {
        generation: u32,
        bytes: Option<Secret<Vec<u8>>>,
    }

    async fn held_head(store: &ScopedStore, id: &str) -> Result<HeldHead, Refused> {
        let bytes = store
            .get(REPLAY_KIND, format!("held-head:{id}").as_bytes())
            .await
            .map_err(|e| Refused::Unavailable(format!("{e:?}")))?;
        let generation = match &bytes {
            None => 0,
            Some(value) => {
                let body = value.expose(&busbar_kernel::seal::lend());
                if body.len() != 5 || body[0] != 1 {
                    return Err(Refused::Unavailable(
                        "unreadable held idempotency cursor".into(),
                    ));
                }
                u32::from_be_bytes(body[1..].try_into().expect("length checked"))
            }
        };
        Ok(HeldHead { generation, bytes })
    }

    async fn advance_head(
        store: &ScopedStore,
        id: &str,
        head: &HeldHead,
        generation: u32,
    ) -> Result<(), Refused> {
        if generation == head.generation {
            return Ok(());
        }
        if generation < head.generation {
            return Err(Refused::Unavailable(
                "held idempotency cursor cannot regress".into(),
            ));
        }
        let key = format!("held-head:{id}").into_bytes();
        let mut body = vec![1];
        body.extend_from_slice(&generation.to_be_bytes());
        // A held class-M identity (DES-264): the Exact predicate on the head row is this
        // publication's guard, and a retry re-reads the head before publishing again.
        let op = store
            .record_op()
            .await
            .map_err(|e| Refused::Unavailable(format!("{e:?}")))?;
        let request = Request {
            op,
            predicates: vec![Predicate {
                schema: REPLAY_KIND.into(),
                key: key.clone(),
                expected: head
                    .bytes
                    .as_ref()
                    .map_or(Expected::Absent, |value| Expected::Exact(value.clone())),
            }],
            mutations: vec![Mutation::Put {
                schema: REPLAY_KIND.into(),
                key,
                value: Secret::new(body),
            }],
        };
        match store.conditional_native(&request).await {
            Ok(Outcome::Applied) => Ok(()),
            other => Err(Refused::Unavailable(format!(
                "held idempotency cursor publication was not confirmed: {other:?}"
            ))),
        }
    }

    fn encode(generation: u32, written_at: u64, settled: &Settled) -> Vec<u8> {
        let mut bytes = vec![LAYOUT];
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&written_at.to_be_bytes());
        match settled {
            Settled::Released => bytes.push(0),
            Settled::Applied(what) => {
                bytes.push(1);
                bytes.extend_from_slice(what.as_bytes());
            }
            Settled::Answer(answer) => {
                bytes.push(2);
                bytes.extend_from_slice(answer);
            }
            Settled::Retained(receipt) => {
                bytes.push(3);
                bytes.extend_from_slice(receipt);
            }
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<(u32, u64, Settled)> {
        let (&layout, rest) = bytes.split_first()?;
        if layout != LAYOUT || rest.len() < 13 {
            return None;
        }
        let generation = u32::from_be_bytes(rest[..4].try_into().ok()?);
        let written_at = u64::from_be_bytes(rest[4..12].try_into().ok()?);
        let body = &rest[13..];
        let settled = match rest[12] {
            0 => Settled::Released,
            1 => Settled::Applied(String::from_utf8(body.to_vec()).ok()?),
            2 => Settled::Answer(body.to_vec()),
            3 => Settled::Retained(body.to_vec()),
            _ => return None,
        };
        Some((generation, written_at, settled))
    }

    fn claimed(outcome: ClaimOutcome) -> Result<bool, Refused> {
        match outcome {
            ClaimOutcome::Claimed => Ok(true),
            ClaimOutcome::AlreadyClaimed => Ok(false),
            other => Err(Refused::Unavailable(format!(
                "idempotency claim was not confirmed: {other:?}"
            ))),
        }
    }

    async fn put(store: &ScopedStore, id: &str, body: Vec<u8>) -> Result<(), String> {
        match store
            .put(REPLAY_KIND, id.as_bytes(), Secret::new(body))
            .await
        {
            Ok(Outcome::Applied) => Ok(()),
            other => Err(format!("idempotency write was not confirmed: {other:?}")),
        }
    }

    async fn read_any(
        store: &ScopedStore,
        id: &str,
    ) -> Result<Option<(u32, u64, Settled)>, Refused> {
        let Some(bytes) = store
            .get(REPLAY_KIND, id.as_bytes())
            .await
            .map_err(|e| Refused::Unavailable(format!("{e:?}")))?
        else {
            return Ok(None);
        };
        let Some((generation, written_at, settled)) =
            decode(bytes.expose(&busbar_kernel::seal::lend()))
        else {
            return Err(Refused::Unavailable(format!(
                "the idempotency record `{id}` in the store is not one this build wrote"
            )));
        };
        Ok(Some((generation, written_at, settled)))
    }

    async fn held_row(
        store: &ScopedStore,
        id: &str,
        generation: u32,
    ) -> Result<Option<(u64, Settled)>, Refused> {
        let row = held_record_id(id, generation);
        let Some((held, written_at, settled)) = read_any(store, &row).await? else {
            return Ok(None);
        };
        if held != generation {
            return Err(Refused::Unavailable(format!(
                "the held idempotency record `{row}` names a different generation"
            )));
        }
        Ok(Some((written_at, settled)))
    }

    async fn read(
        store: &ScopedStore,
        id: &str,
        now: u64,
    ) -> Result<Option<(u32, Settled)>, Refused> {
        let Some((generation, written_at, settled)) = read_any(store, id).await? else {
            return Ok(None);
        };
        if !matches!(settled, Settled::Retained(_))
            && now.saturating_sub(written_at) >= IDEMPOTENCY_TTL_SECS
        {
            return Ok(None);
        }
        Ok(Some((generation, settled)))
    }

    /// Bind a credential action before effects. Only digests are persisted; never secrets.
    /// A competing claim with no binding yet remains in flight and cannot replay an answer.
    pub async fn claim_bound(
        store: &ScopedStore,
        key: &(String, String),
        fingerprint: [u8; 32],
        now: u64,
    ) -> Result<Result<Claim, Refused>, BindingMismatch> {
        let id = format!("binding:{}", record_id(key));
        let check = || async {
            match store.get(REPLAY_KIND, id.as_bytes()).await {
                Ok(Some(secret)) if secret.expose(&busbar_kernel::seal::lend()).len() == 40 => {
                    let bytes = secret.expose(&busbar_kernel::seal::lend());
                    let written =
                        u64::from_be_bytes(bytes[..8].try_into().expect("length checked"));
                    if now.saturating_sub(written) < IDEMPOTENCY_TTL_SECS
                        && bytes[8..] != fingerprint
                    {
                        return Err(BindingMismatch);
                    }
                }
                Ok(Some(_)) => {
                    return Ok(Err(Refused::Unavailable(
                        "unreadable request binding".into(),
                    )))
                }
                Err(error) => return Ok(Err(Refused::Unavailable(format!("{error:?}")))),
                Ok(None) => {}
            }
            Ok(Ok(()))
        };
        if let Err(refused) = check().await? {
            return Ok(Err(refused));
        }
        let claim = match claim(store, key, now).await {
            Ok(claim) => claim,
            Err(refused) => {
                // Another process may have installed the binding after our first read.
                if let Err(error) = check().await? {
                    return Ok(Err(error));
                }
                return Ok(Err(refused));
            }
        };
        let mut body = now.to_be_bytes().to_vec();
        body.extend_from_slice(&fingerprint);
        if let Err(error) = put(store, &id, body).await {
            return Ok(Err(Refused::Unavailable(error)));
        }
        Ok(Ok(claim))
    }

    pub async fn claim(
        store: &ScopedStore,
        key: &(String, String),
        now: u64,
    ) -> Result<Claim, Refused> {
        let id = record_id(key);
        let expires_at = now.saturating_add(IDEMPOTENCY_TTL_SECS);
        let mut generation = 0;
        while generation < MAX_GENERATIONS {
            let first = store
                .redeem(REPLAY_KIND, &token(&id, generation), expires_at)
                .await
                .map_err(|e| Refused::Unavailable(format!("{e:?}")))?;
            if claimed(first)? {
                return Ok(Claim {
                    id,
                    generation,
                    held: false,
                });
            }
            match read(store, &id, now).await? {
                Some((held, Settled::Released)) if held >= generation => {
                    generation = held.saturating_add(1)
                }
                Some((_, Settled::Applied(what))) => return Err(Refused::Applied(what)),
                Some((_, Settled::Answer(answer))) => return Err(Refused::Answer(answer)),
                Some((_, Settled::Retained(receipt))) => return Err(Refused::Retained(receipt)),
                _ => return Err(Refused::InFlight),
            }
        }
        Err(Refused::InFlight)
    }

    /// What `GET /operations/{key}` reads for one `(principal, key)`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Looked {
        /// Claimed and bound, not yet settled: the request's fingerprint and its receive time.
        InFlight {
            request_sha256: [u8; 32],
            received_at: u64,
        },
        /// Settled with an answer written at `completed_at`.
        Done { answer: Vec<u8>, completed_at: u64 },
        /// An unresolved operation's exact producer-owned intent, without a reply expiry.
        Retained { receipt: Vec<u8> },
    }

    async fn lookup_held(
        store: &ScopedStore,
        id: &str,
        now: u64,
    ) -> Result<(bool, Option<Looked>), Refused> {
        let head = held_head(store, id).await?;
        let mut observed = head.bytes.is_some();
        let mut generation = head.generation;
        for _ in 0..MAX_GENERATIONS {
            let Some((written_at, settled)) = held_row(store, id, generation).await? else {
                return Ok((observed, None));
            };
            observed = true;
            match advance_held(settled, written_at, now) {
                Err(Refused::Retained(receipt)) => {
                    return Ok((true, Some(Looked::Retained { receipt })))
                }
                Err(Refused::Answer(answer)) => {
                    return Ok((
                        true,
                        Some(Looked::Done {
                            answer,
                            completed_at: written_at,
                        }),
                    ))
                }
                Err(Refused::Applied(_)) => return Ok((true, None)),
                Err(error) => return Err(error),
                Ok(()) => {
                    generation = generation.checked_add(1).ok_or_else(|| {
                        Refused::Unavailable("held idempotency generation exhausted".into())
                    })?
                }
            }
        }
        Err(Refused::Unavailable(
            "held idempotency lookup exceeded its traversal budget".into(),
        ))
    }

    /// Reads one operation: completed answers expire, but retained intents remain visible.
    pub async fn lookup(
        store: &ScopedStore,
        key: &(String, String),
        now: u64,
    ) -> Result<Option<Looked>, String> {
        let id = record_id(key);
        let unavailable = |e: Refused| format!("{e:?}");
        let (held, looked) = lookup_held(store, &id, now).await.map_err(unavailable)?;
        if held {
            return Ok(looked);
        }
        match read_any(store, &id).await.map_err(unavailable)? {
            Some((_, written_at, Settled::Answer(answer))) => {
                if now.saturating_sub(written_at) < IDEMPOTENCY_TTL_SECS {
                    return Ok(Some(Looked::Done {
                        answer,
                        completed_at: written_at,
                    }));
                }
                return Ok(None);
            }
            // Refused with nothing done: the key is free again, there is no operation to show.
            Some((_, _, Settled::Released)) => return Ok(None),
            _ => {}
        }
        let binding = store
            .get(REPLAY_KIND, format!("binding:{id}").as_bytes())
            .await
            .map_err(|e| format!("{e:?}"))?;
        let Some(binding) = binding else {
            return Ok(None);
        };
        let bytes = binding.expose(&busbar_kernel::seal::lend());
        if bytes.len() != 40 {
            return Err("unreadable request binding".into());
        }
        let received_at = u64::from_be_bytes(bytes[..8].try_into().expect("length checked"));
        if now.saturating_sub(received_at) >= IDEMPOTENCY_TTL_SECS {
            return Ok(None);
        }
        let mut request_sha256 = [0u8; 32];
        request_sha256.copy_from_slice(&bytes[8..]);
        Ok(Some(Looked::InFlight {
            request_sha256,
            received_at,
        }))
    }

    pub async fn claim_held(
        store: &ScopedStore,
        key: &(String, String),
        now: u64,
    ) -> Result<Claim, Refused> {
        let id = record_id(key);
        let head = held_head(store, &id).await?;
        let mut generation = head.generation;
        for _ in 0..MAX_GENERATIONS {
            let row = held_record_id(&id, generation);
            if let Some((written_at, settled)) = held_row(store, &id, generation).await? {
                advance_held(settled, written_at, now)?;
                generation = generation.checked_add(1).ok_or(Refused::InFlight)?;
                continue;
            }
            advance_head(store, &id, &head, generation).await?;
            if generation == 0 {
                let legacy_generation = match read_any(store, &id).await? {
                    Some((held, written_at, settled)) => {
                        advance_held(settled, written_at, now)?;
                        held.checked_add(1).ok_or(Refused::InFlight)?
                    }
                    None => 0,
                };

                let first = store
                    .redeem(REPLAY_KIND, &token(&id, legacy_generation), u64::MAX)
                    .await
                    .map_err(|e| Refused::Unavailable(format!("{e:?}")))?;
                if !claimed(first)? {
                    return Err(Refused::InFlight);
                }
            }
            let first = store
                .redeem(REPLAY_KIND, &row, u64::MAX)
                .await
                .map_err(|e| Refused::Unavailable(format!("{e:?}")))?;
            if claimed(first)? {
                return Ok(Claim {
                    id,
                    generation,
                    held: true,
                });
            }

            // A competing claimant won. A later request can read its settled outcome;
            // this invocation neither restarts its read budget nor redeems another generation.
            return Err(Refused::InFlight);
        }
        advance_head(store, &id, &head, generation).await?;
        Err(Refused::Unavailable(
            "held idempotency claim exceeded its traversal budget".into(),
        ))
    }

    /// Settle a retained receipt terminally (TRUST-ADMIN-PRODUCER-DESIGN r3 §4.6): the held row of
    /// `key` that still retains exactly `retained` becomes `settled`, compare-and-set on its stored
    /// bytes, so a later replay (also after a restart) reads the final answer without asking the
    /// effect's owner again. `Ok(false)`: no held row of this key retains those bytes any more (a
    /// concurrent replay settled it first) or none ever did.
    pub async fn settle_retained(
        store: &ScopedStore,
        key: &(String, String),
        now: u64,
        retained: &[u8],
        settled: &Settled,
    ) -> Result<bool, String> {
        // Held generations are written in order from 0 (`claim_held`): walk them to the retained one.
        let id = record_id(key);
        let mut generation = 0;
        for _ in 0..MAX_GENERATIONS {
            let row = held_record_id(&id, generation);
            let Some(stored) = store
                .get(REPLAY_KIND, row.as_bytes())
                .await
                .map_err(|e| format!("{e:?}"))?
            else {
                return Ok(false);
            };
            let found = decode(stored.expose(&busbar_kernel::seal::lend()));
            match found {
                Some((held, _, Settled::Retained(bytes)))
                    if held == generation && bytes == retained =>
                {
                    let body = encode(generation, now, settled);
                    use busbar_kernel::persistence::scoped::{
                        Expected, Mutation, Predicate, Request,
                    };
                    // A held class-M identity (DES-264): the Exact predicate on the held row
                    // stays this settle's guard.
                    let request = Request {
                        op: store.record_op().await.map_err(|e| format!("{e:?}"))?,
                        predicates: vec![Predicate {
                            schema: REPLAY_KIND.into(),
                            key: row.clone().into_bytes(),
                            expected: Expected::Exact(stored),
                        }],
                        mutations: vec![Mutation::Put {
                            schema: REPLAY_KIND.into(),
                            key: row.into_bytes(),
                            value: Secret::new(body),
                        }],
                    };
                    return match store.conditional_native(&request).await {
                        Ok(Outcome::Applied) => Ok(true),
                        Ok(Outcome::ConditionConflict) => Ok(false),
                        other => Err(format!(
                            "the retained idempotency settlement was not confirmed: {other:?}"
                        )),
                    };
                }
                Some((held, _, _)) if held == generation => {
                    generation = generation
                        .checked_add(1)
                        .ok_or_else(|| "held idempotency generations exhausted".to_string())?;
                }
                _ => {
                    return Err(format!(
                    "the held idempotency record `{row}` in the store is not one this build wrote"
                ))
                }
            }
        }
        Ok(false)
    }

    fn advance_held(settled: Settled, written_at: u64, now: u64) -> Result<(), Refused> {
        match settled {
            Settled::Retained(receipt) => Err(Refused::Retained(receipt)),
            Settled::Answer(answer) if now.saturating_sub(written_at) < IDEMPOTENCY_TTL_SECS => {
                Err(Refused::Answer(answer))
            }
            Settled::Applied(what) if now.saturating_sub(written_at) < IDEMPOTENCY_TTL_SECS => {
                Err(Refused::Applied(what))
            }
            _ => Ok(()),
        }
    }

    pub async fn settle(
        store: &ScopedStore,
        claim: &Claim,
        now: u64,
        settled: &Settled,
    ) -> Result<(), String> {
        let body = encode(claim.generation, now, settled);
        let id = if claim.held {
            held_record_id(&claim.id, claim.generation)
        } else {
            claim.id.clone()
        };
        put(store, &id, body).await?;
        // Held and retained receipts never expire through ordinary replay cleanup. One page per
        // settle (ADMIN-API-1.6 6.3): the sweep resumes from the cursor the last settle left.
        let resume = SWEEP_AFTER.lock().unwrap_or_else(|e| e.into_inner()).take();
        {
            let page = match store.page(REPLAY_KIND, b"", resume.as_ref()).await {
                Ok(page) => page,
                Err(error) => {
                    tracing::warn!(error = ?error, "expired idempotency records were not swept; the next settle retries");
                    return Ok(());
                }
            };
            for (key, bytes) in page.rows {
                if key.starts_with(b"held:") || key.starts_with(b"held-head:") {
                    continue;
                }
                let body = bytes.expose(&busbar_kernel::seal::lend());
                let cutoff = now.saturating_sub(IDEMPOTENCY_TTL_SECS);
                let expired = if key.starts_with(b"binding:") {
                    body.len() == 40
                        && u64::from_be_bytes(body[..8].try_into().expect("length checked"))
                            < cutoff
                } else {
                    decode(body).is_some_and(|(_, written_at, outcome)| {
                        !matches!(outcome, Settled::Retained(_)) && written_at < cutoff
                    })
                };
                if expired {
                    match store.prepare_delete_exact(REPLAY_KIND, &key, bytes).await {
                        Ok(request) => match store.conditional_native(&request).await {
                            Ok(Outcome::Applied | Outcome::ConditionConflict) => {}
                            other => {
                                tracing::warn!(outcome = ?other, "expired idempotency record was not swept")
                            }
                        },
                        Err(error) => {
                            tracing::warn!(error = ?error, "expired idempotency record was not swept")
                        }
                    }
                }
            }
            *SWEEP_AFTER.lock().unwrap_or_else(|e| e.into_inner()) = page.next;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/idempotency_tests.rs"]
mod tests;
