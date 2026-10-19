// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT ONE UNIT'S LIVE ATTEMPT LENDS ITS MEMBER'S AUTH (THE DESIGN §6, "Auth points and guest
//! lists", item 5; the coordinator's ruling on the host auth handle: the host side resolves the
//! per-request handle, the scope extensions, the passthrough credential and the waiver FROM THE
//! UNIT, so none of them crosses the connector).
//!
//! The kernel makes NO outbound auth call. The far end records here, per attempt and before the
//! open, what the attempt's binding is to be called with; the transport's framer then calls the
//! binding's auth at its points through the host auth handle (`auth.call`), and the composition
//! root, which serves that call, reads the record of the unit the call names. The record is the
//! unit's alone: a new attempt replaces it, and the unit's far end removes it when it ends.
//!
//! The caller's credential is a SECRET held on the unit: it is recorded here as the kernel holds it
//! (`Secret`, zeroised on drop), read by the host's server under the kernel's seal, and never
//! handed to a transport.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use busbar_contract::redacted::Secret;

/// One attempt's facts for its member's auth call.
#[derive(Clone)]
pub struct AttemptAuth {
    /// The member the attempt rides (`OpenDesc::member`): the registration whose binding the
    /// framer's ref names.
    pub member: String,
    /// The binding's handle for this attempt (a refreshed binding's current one).
    pub handle: u64,
    /// The plane's per-call scope, as the call's extensions blob (empty = none).
    pub extensions: Vec<u8>,
    /// A passthrough member's lent credential: the caller's verified one, or empty when the caller
    /// presented none (nothing is presented, never the operator's key). `None` = not passthrough.
    pub caller_credential: Option<Secret<Vec<u8>>>,
    /// The plane waived its member's binding for this request: the host serves the framer's call
    /// with no auth line.
    pub waived: bool,
    /// THE UNIT'S OWN SECRET (#74): the request's kernel secret the host MACs the unit's ref
    /// under when it hands the framer the unit, and verifies a presented one against. Drawn once
    /// per unit by [`record`] from the OS random source and kept across its attempts; whatever a
    /// caller states here is replaced.
    pub secret: [u64; 2],
    /// What the binding's auth answered this attempt, when it refused the request or could not
    /// answer ([`mark`]): the attempt's failure is then the auth's, never the destination's. `None`
    /// on every new attempt; whatever a caller states here is replaced.
    pub outcome: Option<AuthOutcome>,
}

/// An auth outcome of one attempt: not the destination failing (THE DESIGN §6; 1.5.5's failover
/// parity: an auth that refuses or cannot answer moves the walk on and records nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The binding's auth refused the request.
    Refused,
    /// The binding's auth could not answer (its credential unavailable, its call failed).
    Failed,
    /// The binding's auth is still waiting (a token refreshing): an attempt whose first answer
    /// does not come meanwhile ends on the auth's wait, as 1.5.5's bounded auth wait did, never
    /// on the destination.
    Waiting,
}

impl std::fmt::Debug for AttemptAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptAuth")
            .field("member", &self.member)
            .field("handle", &self.handle)
            .field("extensions", &self.extensions.len())
            .field("passthrough", &self.caller_credential.is_some())
            .field("waived", &self.waived)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// The process's records, by unit key.
fn table() -> &'static Mutex<HashMap<u64, AttemptAuth>> {
    static TABLE: OnceLock<Mutex<HashMap<u64, AttemptAuth>>> = OnceLock::new();
    TABLE.get_or_init(Mutex::default)
}

fn lock() -> std::sync::MutexGuard<'static, HashMap<u64, AttemptAuth>> {
    table()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Record `unit`'s live attempt (replacing its last), under the unit's own secret: the one its
/// first attempt drew, or a fresh one. Unit `0` names no unit and records nothing; a unit whose
/// secret cannot be drawn records nothing either, so no framer's call for it is ever served (fail
/// closed).
pub fn record(unit: u64, mut attempt: AttemptAuth) {
    if unit == 0 {
        return;
    }
    let mut table = lock();
    let secret = match table.get(&unit) {
        Some(live) => live.secret,
        None => {
            let mut bytes = [0_u8; 16];
            if getrandom::fill(&mut bytes).is_err() {
                return;
            }
            let (a, b) = bytes.split_at(8);
            [
                u64::from_le_bytes(a.try_into().unwrap_or_default()),
                u64::from_le_bytes(b.try_into().unwrap_or_default()),
            ]
        }
    };
    attempt.secret = secret;
    attempt.outcome = None;
    table.insert(unit, attempt);
}

/// Clear `unit`'s live attempt's auth outcome: its auth answered lines after a wait.
pub fn clear(unit: u64) {
    if let Some(live) = lock().get_mut(&unit) {
        live.outcome = None;
    }
}

/// Mark `unit`'s live attempt with its auth's `outcome` (the host's server of the framer's
/// `auth.call`, once the unit verified): the attempt's failure is the auth's. A unit with no live
/// attempt marks nothing.
pub fn mark(unit: u64, outcome: AuthOutcome) {
    if let Some(live) = lock().get_mut(&unit) {
        live.outcome = Some(outcome);
    }
}

/// `unit`'s live attempt, as the host's server of the framer's `auth.call` reads it.
#[must_use]
pub fn of(unit: u64) -> Option<AttemptAuth> {
    lock().get(&unit).cloned()
}

/// Forget `unit`'s record: its far end ended.
pub fn forget(unit: u64) {
    lock().remove(&unit);
}

#[cfg(test)]
#[path = "tests/attempt_auth_tests.rs"]
mod tests;
