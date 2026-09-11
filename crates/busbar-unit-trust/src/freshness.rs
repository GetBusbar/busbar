// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verify step's FRESHNESS ledger and its single-flight leadership.
//!
//! The rest of this crate answers *where may this go*. This module answers the question that has to
//! be settled before that one can be asked again: **has this subject been verified recently enough
//! to reuse the answer, and if not, who re-checks it?**
//!
//! ## Freshness only — never a cached verdict
//!
//! A [`Fresh`](Lookup::Fresh) reading says "this subject was verified within its ttl" and nothing
//! else. There is no stored verdict, no digest, no payload: a ledger that handed back a remembered
//! ANSWER would be a second place a trust decision is made, and it would keep making it after the
//! thing that produced it stopped agreeing. What is remembered is the CHECK, not its result, and
//! when the check goes stale the caller re-checks rather than re-reads.
//!
//! ## Single flight, because a stale subject is a thundering herd
//!
//! When a subject IS stale, every caller that arrives at once would otherwise re-check it at once —
//! against whatever the check talks to. So the FIRST caller to reach a stale or unseen subject is
//! told it [`Lead`](Lookup::Lead)s: it does the check and [`record`](VerifyFreshness::record)s the
//! result. Everyone behind it is told it [`Follow`](Lookup::Follow)s. Exactly one check is in
//! flight per subject.
//!
//! ## A leader that never returns must not wedge its followers
//!
//! That is the whole reason [`release`](VerifyFreshness::release) exists beside
//! [`record`](VerifyFreshness::record). Leadership is a claim held in this ledger, and a leader
//! whose work is dropped — cancelled, panicked, abandoned — would hold it forever and leave every
//! follower waiting on a check nobody is running. So the caller registers the release against
//! whatever owns the leader's lifetime and it runs when that lifetime ends; it is IDEMPOTENT with
//! `record`, which releases the same claim on the path where the leader did come back. A
//! `record`-then-`release` and a `release` alone both leave the ledger in the state the next caller
//! should read.
//!
//! ## What is deliberately NOT here
//!
//! The host-vtable's ledger also kept a lease-id -> subject map, written on every lead and erased on
//! every store and every reclaim, and NEVER READ: no code path ever asked it what a lease named. It
//! did not move, because state nothing reads is not a fact — it is per-request work and a second
//! thing to keep consistent, and the two callers that maintained it both already hold the subject
//! they are talking about.
//!
//! The subject is opaque: a scope number the caller assigns and the bytes it names, compared and
//! never interpreted. Nothing here knows what was verified, only that it was.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// A subject, as this ledger keys it: the caller's scope number and a copy of its opaque bytes.
/// Owned, so an entry outlives the borrowed range the call handed over.
type Subject = (u32, Vec<u8>);

/// What a caller is told when it asks about a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// Verified within its ttl: reuse, do not re-check.
    Fresh,
    /// Stale or unseen, and this caller is the one re-checking it. It must finish with
    /// [`record`](VerifyFreshness::record), and its lifetime owner must call
    /// [`release`](VerifyFreshness::release) whether it does or not.
    Lead,
    /// Stale, but another caller is already re-checking it. Wait for that one.
    Follow,
}

/// The freshness ledger: which subjects are verified until when, and which have a check in flight.
/// [`Default`] is its only constructor — an empty ledger — so there is no second way to build one
/// that could start from somewhere else.
///
/// One lock over both facts, because they are one fact: a subject that is fresh has no leader, and a
/// subject with a leader is not fresh. Split across two locks they could disagree, and a caller
/// would read "stale, and somebody is on it" while nobody was.
#[derive(Default)]
pub struct VerifyFreshness {
    inner: Mutex<Ledger>,
}

#[derive(Default)]
struct Ledger {
    /// Subject → the millisecond after which its verification is stale.
    fresh: HashMap<Subject, u64>,
    /// The subjects with a check IN FLIGHT right now: a second caller follows rather than re-checks.
    leading: HashSet<Subject>,
}

impl VerifyFreshness {
    /// Ask about `subject` at `now_ms`, and CLAIM leadership of its re-check if it is stale and
    /// unclaimed.
    ///
    /// This both reads and writes on purpose: "is it stale?" and "am I the one re-checking it?" have
    /// to be one step, because two callers that each read "stale" before either claimed would both
    /// lead, and the single flight this ledger exists for would be two.
    ///
    /// A [`Lead`](Lookup::Lead) answer leaves a claim in the ledger that the caller is now
    /// responsible for clearing — see [`release`](VerifyFreshness::release).
    #[must_use]
    pub fn look_up(&self, scope: u32, subject: &[u8], now_ms: u64) -> Lookup {
        let key = (scope, subject.to_vec());
        let mut led = self.lock();
        if led.fresh.get(&key).is_some_and(|&expires| now_ms < expires) {
            Lookup::Fresh
        } else if led.leading.insert(key) {
            // The first caller to reach a stale or unseen subject: it leads the re-check.
            Lookup::Lead
        } else {
            // A leader is already re-checking this subject.
            Lookup::Follow
        }
    }

    /// The leader finished: mark `subject` verified for `ttl_secs` from `now_ms` and RELEASE its
    /// leadership, so the next caller reads [`Fresh`](Lookup::Fresh) rather than leading again.
    ///
    /// `ttl_secs == 0` is strict-live: the subject is stale again immediately, which is how a caller
    /// says "check it every time" without a second switch to disagree with this one.
    pub fn record(&self, scope: u32, subject: &[u8], ttl_secs: u64, now_ms: u64) {
        let key = (scope, subject.to_vec());
        let expires = now_ms.saturating_add(ttl_secs.saturating_mul(1_000));
        let mut led = self.lock();
        led.fresh.insert(key.clone(), expires);
        led.leading.remove(&key);
    }

    /// Give up leadership of `subject` WITHOUT recording a verification — the path a leader that
    /// never came back takes.
    ///
    /// Idempotent with [`record`](VerifyFreshness::record): whichever runs second finds nothing to
    /// clear and changes nothing. Registering this against the leader's lifetime is what keeps a
    /// dropped leader from wedging every follower behind it.
    pub fn release(&self, scope: u32, subject: &[u8]) {
        self.lock().leading.remove(&(scope, subject.to_vec()));
    }

    /// Poison-recovering lock, the discipline every request-path lock takes: a panic mid-update must
    /// not wedge the ledger for every later caller.
    fn lock(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}
