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
    /// The plane waived its member's binding for this request: the framer is begun with no auth.
    pub waived: bool,
}

impl std::fmt::Debug for AttemptAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptAuth")
            .field("member", &self.member)
            .field("handle", &self.handle)
            .field("extensions", &self.extensions.len())
            .field("passthrough", &self.caller_credential.is_some())
            .field("waived", &self.waived)
            .finish()
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

/// Record `unit`'s live attempt (replacing its last). Unit `0` names no unit and records nothing.
pub fn record(unit: u64, attempt: AttemptAuth) {
    if unit != 0 {
        lock().insert(unit, attempt);
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
