// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-node, in-process idempotency-replay cache — moved verbatim from
//! `busbar-core::admin::mod` (`IDEMPOTENCY_TTL_SECS`, `IdemState`, `IdemReservation`, and the
//! create/rotate call sites' cache logic). Same TTL (600 s) and the same semantics: no body hash,
//! so a retry with the same key but a DIFFERENT body still replays the first response (parity
//! clause — 1.5.5 never hashed the body either). The key is `(actor, header)` for a mint and
//! `(actor, <framed id and header>)` for a rotate; the caller builds it, and see
//! [`rotate_replay_key`] for why the rotate's two halves are length-prefixed rather than
//! joined on a separator.
//!
//! The sweep is NOT the same as 1.5.5's: it steps over the in-flight sentinel. See
//! [`IdempotencyCache::probe`].
//!
//! Generic over the cached value `V`: the served key handlers ([`crate::keys`]) cache the response
//! object they replay verbatim.
//!
//! Unlike 1.5.5 the claim also lives in the configured store ([`durable`]), so a retry after a
//! restart or on another node never runs the mutation twice: it replays, or it is refused.

use std::collections::HashMap;
use std::sync::Mutex;

// The replay window (600 s) is the store face's own constant now — pulled forward to the ONE ABI
// crate (DECISIONS #38/#40) so the loader's sealed store cache and this in-process
// cache age their slots against one number. Re-exported here so the doc links and the existing
// `crate::idempotency::IDEMPOTENCY_TTL_SECS` call sites keep resolving.
pub use busbar_contract::verb_store::IDEMPOTENCY_TTL_SECS;

/// THE REPLAY KEY FOR A ROTATE, FRAMED SO THAT NO TWO `(id, header)` PAIRS JOIN TO ONE KEY.
///
/// A rotate is scoped to the key it rotates as well as to the idempotency header, so a create and a
/// rotate sharing a header value do not replay each other. Both halves are caller-supplied free
/// text, which is exactly the condition under which a separator join stops being a function: joined
/// on a bar or a colon, `("a:b", "c")` and `("a", "b:c")` are one string, so the second rotate is
/// served the FIRST one's cached response and the key it actually named is never rotated — while
/// the caller is told it was.
///
/// So each half is length-prefixed: the decimal byte length, a colon, then exactly that many bytes.
/// A reader takes the digits up to the colon as a count and then consumes precisely that count, so
/// every boundary is fixed by a number the caller does not write. A length can contain no colon,
/// being decimal digits, so there is nothing left for a caller's bytes to move: `("a:b", "c")` is
/// `rotate:3:a:b:1:c` and `("a", "b:c")` is `rotate:1:a:3:b:c`. This is the same framing, and the
/// same reason for it, as the length-prefixed audit digest.
///
/// The lengths are BYTE lengths, not character counts: the key is compared as bytes, and a count of
/// characters would put the boundary somewhere other than where the reader would find it.
pub(crate) fn rotate_replay_key(id: &str, header: &str) -> String {
    format!("rotate:{}:{}:{}:{}", id.len(), id, header.len(), header)
}

/// One cache slot: `(inserted_at, value)`. `value: None` is the in-flight reservation sentinel
/// (1.5.5 used `serde_json::Value::Null` for the same purpose; `None` says the same thing without
/// requiring a JSON value type).
type Slot<V> = (u64, Option<V>);

/// The cache itself. `(String, String)` is `(actor, header)` for a mint or `(actor, <framed id and
/// header>)` for a rotate — the caller builds the key, this type only stores it.
///
/// It is this process's view only. What outlives the process — that a key was claimed, and what
/// the claim settled to — is the configured store's, through [`durable`].
pub struct IdempotencyCache<V> {
    slots: Mutex<HashMap<(String, String), Slot<V>>>,
}

/// The result of probing the cache before starting a mutating verb.
pub enum Probe<'a, V: Clone> {
    /// No `Idempotency-Key` header was presented; proceed and never reserve or replay for this
    /// call.
    NoKey,
    /// First time this key has been seen (or its prior reservation expired): a [`Reservation`] was
    /// inserted under the same lock hold, and the caller now owns it and must either
    /// [`Reservation::commit`] or [`Reservation::clear`]/let it drop.
    Reserved(Reservation<'a, V>),
    /// A prior call with this key already completed: replay its committed value verbatim, minting
    /// nothing new.
    Replay(V),
    /// A prior call with this key is still in flight (its reservation has not been committed or
    /// cleared yet): refuse this call rather than double-run the mutation.
    InFlight,
}

impl<V: Clone> IdempotencyCache<V> {
    /// A fresh, empty cache.
    pub fn new() -> Self {
        IdempotencyCache {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Probe (and, on a first sighting, reserve) `key` at time `now` (unix seconds). Sweeps first.
    ///
    /// THE SWEEP APPLIES TO COMMITTED VALUES ONLY. The two things stored under a key answer two
    /// different questions, and only one of them is bounded by the replay window:
    ///
    /// * A committed value answers "what did the completed call reply". That is what
    ///   [`IDEMPOTENCY_TTL_SECS`] bounds, and dropping one early costs a retry an extra run of a
    ///   mutation nobody has run yet.
    /// * A sentinel (`None`) answers "is somebody running this right now". Ten minutes is not an
    ///   upper bound on a mutation — a store gone slow, a mint blocked on an unreachable signer —
    ///   and the longer one is stuck the MORE retries arrive to be admitted. Sweeping a sentinel
    ///   tells the next retry it is the first, so two live reservations exist for one idempotency
    ///   key and two credentials are minted where the sentinel existed so that one would.
    ///
    /// So a sentinel is stepped over however old it is, and is bounded by its own [`Reservation`]
    /// instead: `commit`, `clear` and `Drop` each release it. The one path that leaves a sentinel
    /// behind is [`Reservation::leak`], which is reserved for a mutation handed to an uncancellable
    /// path — so a leaked sentinel is bounded by real work in flight, never by a header a client
    /// chooses, and this is not a way to grow the map without limit.
    ///
    /// What a restart or another node must also see is not taken here: the caller claims the key in
    /// the store ([`durable::claim`]) before its mutation becomes irreversible.
    pub fn probe(&self, key: (String, String), now: u64) -> Probe<'_, V> {
        let mut guard = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (t, v)| v.is_none() || now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        match guard.get(&key) {
            Some((_, Some(v))) => Probe::Replay(v.clone()),
            Some((_, None)) => Probe::InFlight,
            None => {
                guard.insert(key.clone(), (now, None));
                drop(guard);
                Probe::Reserved(Reservation {
                    cache: self,
                    key,
                    live: true,
                })
            }
        }
    }
}

impl<V: Clone> Default for IdempotencyCache<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// An in-flight reservation. Exactly `IdemReservation` in 1.5.5: clears the sentinel on `Drop` (a
/// parse/validation/store failure before anything irreversible happened), unless the caller
/// explicitly [`commit`](Reservation::commit)s a real value or [`clear`](Reservation::clear)s it
/// itself (a store-confirmed failure it already knows is safe to free for retry) or
/// [`leak`](Reservation::leak)s it (the mutation was handed to an uncancellable execution path —
/// 1.5.5's `spawn_blocking` — so a caller disconnect after this point must NOT clear the sentinel,
/// or a retry could double-mint against a mutation that already landed).
pub struct Reservation<'a, V: Clone> {
    cache: &'a IdempotencyCache<V>,
    key: (String, String),
    live: bool,
}

impl<'a, V: Clone> Reservation<'a, V> {
    /// The key this reservation holds, for the store claim ([`durable::claim`]).
    pub fn key(&self) -> &(String, String) {
        &self.key
    }

    /// Commit the real value, replacing the sentinel. A later replay of this key returns exactly
    /// this value.
    pub fn commit(mut self, value: V, now: u64) {
        let mut guard = self.cache.slots.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(self.key.clone(), (now, Some(value)));
        self.live = false;
    }

    /// Explicitly clear the reservation (a refusal this call already knows is safe to retry).
    /// Idempotent: clears only if the slot is still this reservation's own sentinel, never a value
    /// a concurrent commit already placed there.
    pub fn clear(mut self) {
        self.clear_inner();
        self.live = false;
    }

    /// Mark the reservation as handed to an uncancellable execution path: a subsequent `Drop`
    /// (caller cancellation) must not clear it. Mirrors 1.5.5's `IdemState::InFlight` transition.
    /// The reservation stays usable: [`commit`](Reservation::commit) and
    /// [`clear`](Reservation::clear) still release the sentinel, which is how a handler that awaits
    /// the uncancellable work finishes the claim.
    pub fn in_flight(&mut self) {
        self.live = false;
    }

    /// [`Reservation::in_flight`] for a caller that will not finish the claim itself: the sentinel
    /// is left behind for good.
    pub fn leak(mut self) {
        self.in_flight();
    }

    fn clear_inner(&self) {
        let mut guard = self.cache.slots.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(guard.get(&self.key), Some((_, None))) {
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

/// THE CLAIM THAT OUTLIVES THE PROCESS: an `Idempotency-Key` taken in the configured store, so a
/// retry after a restart, or on another node of the fleet, never runs the mutation a second time.
///
/// The cache above answers for this process. A key it has never seen is not proof that nobody ran
/// the mutation: the node may have restarted, or a sibling node may have run it. So before the
/// mutation becomes irreversible the caller [`claim`]s the key in the store, a single-use
/// test-and-set (`redeem_plane_token`) that one caller wins fleet-wide and across restarts. When
/// the mutation answers the caller [`settle`]s the claim (an upserted plane record under
/// [`REPLAY_KIND`]), and a later claimer that loses the test-and-set reads that record:
///
/// - [`Settled::Answer`]: the answer itself, which the caller replays verbatim;
/// - [`Settled::Applied`]: the mutation ran, but its answer carried a once-shown secret, which the
///   store never holds, so the caller refuses rather than run it again;
/// - [`Settled::Released`]: the mutation refused with nothing done, so the next generation of the
///   claim is open and the retry runs;
/// - nothing yet: the winner is still running, or died between claiming and settling. Refused as in
///   flight until the claim lapses with the replay window.
///
/// A store that cannot answer refuses the mutation ([`Refused::Unavailable`]): a claim nobody can
/// check is not taken on trust.
pub mod durable {
    use busbar_contract::records::{PlaneDisposition, PlaneRecordRef, RecordStore};

    use super::IDEMPOTENCY_TTL_SECS;

    /// The plane-record kind (and single-use token kind) every idempotency claim lives under.
    pub const REPLAY_KIND: &str = "busbar.admin-idempotency";

    /// The most generations one claim walks past released predecessors before it calls the key in
    /// flight. Each generation is one refused attempt inside the replay window.
    const MAX_GENERATIONS: u32 = 64;

    /// The record layout this build writes.
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
    }

    /// Why a claim was not granted.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Refused {
        /// An earlier call with this key ran and made this; its answer cannot be replayed.
        Applied(String),
        /// An earlier call with this key ran; this is its answer.
        Answer(Vec<u8>),
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
    }

    /// The record id of `key`: a digest, so neither the actor nor the client's header is stored.
    fn record_id(key: &(String, String)) -> String {
        let framed = format!("{}:{}:{}", key.0.len(), key.0, key.1);
        busbar_contract::redacted::sha256_hex(framed.as_bytes())
    }

    fn token(id: &str, generation: u32) -> String {
        format!("{id}:{generation}")
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
            _ => return None,
        };
        Some((generation, written_at, settled))
    }

    /// The settled record for `id`, if one was written inside the replay window.
    fn read(
        store: &dyn RecordStore,
        id: &str,
        now: u64,
    ) -> Result<Option<(u32, Settled)>, Refused> {
        let Some(bytes) = store
            .get_plane_record(REPLAY_KIND, id)
            .map_err(|e| Refused::Unavailable(e.to_string()))?
        else {
            return Ok(None);
        };
        let Some((generation, written_at, settled)) = decode(&bytes) else {
            return Err(Refused::Unavailable(format!(
                "the idempotency record `{id}` in the store is not one this build wrote"
            )));
        };
        if now.saturating_sub(written_at) >= IDEMPOTENCY_TTL_SECS {
            return Ok(None);
        }
        Ok(Some((generation, settled)))
    }

    /// CLAIM `key` in the store at `now`, before the mutation it guards becomes irreversible.
    ///
    /// # Errors
    ///
    /// Not granted, and why ([`Refused`]).
    pub fn claim(
        store: &dyn RecordStore,
        key: &(String, String),
        now: u64,
    ) -> Result<Claim, Refused> {
        let id = record_id(key);
        let expires_at = now.saturating_add(IDEMPOTENCY_TTL_SECS);
        let mut generation = 0;
        while generation < MAX_GENERATIONS {
            let first = store
                .redeem_plane_token(REPLAY_KIND, &token(&id, generation), expires_at, now)
                .map_err(|e| Refused::Unavailable(e.to_string()))?;
            if first {
                return Ok(Claim { id, generation });
            }
            match read(store, &id, now)? {
                Some((held, Settled::Released)) if held >= generation => {
                    generation = held.saturating_add(1)
                }
                Some((_, Settled::Applied(what))) => return Err(Refused::Applied(what)),
                Some((_, Settled::Answer(answer))) => return Err(Refused::Answer(answer)),
                _ => return Err(Refused::InFlight),
            }
        }
        Err(Refused::InFlight)
    }

    /// SETTLE a held claim: what its mutation came to, kept for the replay window. Records older
    /// than the window are swept on the way; a sweep the store refuses is logged and retried by the
    /// next settle.
    ///
    /// # Errors
    ///
    /// The store did not keep the record. The caller logs it: a later retry of this key then reads
    /// the claim as in flight until it lapses, never as free to run again.
    pub fn settle(
        store: &dyn RecordStore,
        claim: &Claim,
        now: u64,
        settled: &Settled,
    ) -> Result<(), String> {
        let body = encode(claim.generation, now, settled);
        store
            .upsert_plane_record(PlaneRecordRef {
                kind: REPLAY_KIND,
                id: &claim.id,
                parent: None,
                seq: 0,
                ts: now,
                disposition: PlaneDisposition::Terminal,
                body: &body,
            })
            .map_err(|e| e.to_string())?;
        if let Err(e) =
            store.purge_plane_records_before(REPLAY_KIND, now.saturating_sub(IDEMPOTENCY_TTL_SECS))
        {
            tracing::warn!(error = %e, "expired idempotency records were not swept; the next settle retries");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/idempotency_tests.rs"]
mod tests;
