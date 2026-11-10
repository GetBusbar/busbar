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
        guard.retain(|_, (t, _, _)| now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
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
    use busbar_kernel::persistence::scoped::{ClaimOutcome, Outcome, ScopedStore};

    use super::{BindingMismatch, IDEMPOTENCY_TTL_SECS};

    pub const REPLAY_KIND: &str = "busbar.admin-idempotency";

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

    pub async fn claim_held(
        store: &ScopedStore,
        key: &(String, String),
        now: u64,
    ) -> Result<Claim, Refused> {
        let id = record_id(key);
        let mut generation = 0;
        loop {
            let row = held_record_id(&id, generation);
            if let Some((held, written_at, settled)) = read_any(store, &row).await? {
                if held != generation {
                    return Err(Refused::Unavailable(format!(
                        "the held idempotency record `{row}` names a different generation"
                    )));
                }
                advance_held(settled, written_at, now)?;
                generation = generation.checked_add(1).ok_or(Refused::InFlight)?;
                continue;
            }
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

            if read_any(store, &row).await?.is_none() {
                return Err(Refused::InFlight);
            }
        }
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
        // Held and retained receipts never expire through ordinary replay cleanup.
        let mut cursor = None;
        loop {
            let page = match store.page(REPLAY_KIND, b"", cursor.as_ref()).await {
                Ok(page) => page,
                Err(error) => {
                    tracing::warn!(error = ?error, "expired idempotency records were not swept; the next settle retries");
                    break;
                }
            };
            for (key, bytes) in page.rows {
                if key.starts_with(b"held:") {
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
                    match store.prepare_delete_exact(REPLAY_KIND, &key, bytes) {
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
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/idempotency_tests.rs"]
mod tests;
