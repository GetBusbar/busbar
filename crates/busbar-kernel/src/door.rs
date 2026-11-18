// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{Admission, Admittance, Grant, Hold, PrincipalId, ReasonCode};
use busbar_contract::caps::{AuditFacts, OpClassId};
use busbar_contract::FinishClass;

pub fn admitted_at_zero(admit_token: &Grant<Admittance>, principal: PrincipalId) -> Admission {
    Admission::Own(Hold::open(admit_token, principal))
}

pub fn arrival_hold(principal: PrincipalId, admit_token: &Grant<Admittance>) -> Hold {
    Hold::open(admit_token, principal)
}

/// THE NODE'S ONE UNIT-KEY ALLOCATOR, from 1. A unit's identity is the kernel's to mint: a plane
/// that needs a key for a table it keeps (a served session's open calls) takes it from here.
#[derive(Debug, Default)]
pub struct UnitKeyMint(std::sync::atomic::AtomicU64);

impl UnitKeyMint {
    pub fn mint(&self) -> busbar_contract::ids::UnitKey {
        let n = next_counter(&self.0);
        busbar_contract::ids::UnitKey::new(n + 1)
    }
}

pub fn op_id() -> busbar_contract::records::OpId {
    IDS.mint()
}

#[must_use]
pub fn node() -> u64 {
    IDS.node
}

/// A unit ref's nonce: this boot's node and the next value of the `op_id` counter, so no two
/// mints in a process (and, with a fresh node per boot, across boots) share one. It needs no
/// secrecy: the MAC key is the secret.
pub(crate) fn unit_nonce() -> [u64; 2] {
    [IDS.node, next_counter(&IDS.counter)]
}

static IDS: std::sync::LazyLock<OpIds> = std::sync::LazyLock::new(|| OpIds::boot(boot_node()));

/// One boot's `op_id`s: its node half and its counter.
#[derive(Debug)]
pub(crate) struct OpIds {
    node: u64,
    counter: std::sync::atomic::AtomicU64,
}

impl OpIds {
    pub(crate) fn boot(node: u64) -> Self {
        Self {
            node,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn mint(&self) -> busbar_contract::records::OpId {
        let n = next_counter(&self.counter);
        busbar_contract::records::OpId::from_parts(self.node, n + 1)
    }
}

// Exhaustion leaves the allocator exhausted. In particular, catching a panic
// must not allow a subsequent call to reuse an identity under the same node.
fn next_counter(counter: &std::sync::atomic::AtomicU64) -> u64 {
    use std::sync::atomic::Ordering::Relaxed;
    counter
        .try_update(Relaxed, Relaxed, |current| current.checked_add(1))
        .expect("the kernel identity counter is exhausted")
}

fn boot_node() -> u64 {
    for _ in 0..8 {
        let mut b = [0u8; 8];
        if busbar_contract::crypto::fill(&mut b).is_ok() {
            let n = u64::from_le_bytes(b);
            if n != 0 {
                return n;
            }
        }
    }
    panic!("the OS entropy source answered nothing usable; a store op_id cannot be minted")
}

/// The row owns its names; the caller hands them over, so building a row copies none of them.
pub fn metering_row(
    key_id: String,
    model: String,
    provider: String,
    usage: Option<&busbar_contract::billing::TokenUsage>,
) -> busbar_contract::records::MeteringRow {
    busbar_contract::records::MeteringRow {
        pricing: None,
        scale: 0,
        usage_units: Default::default(),
        key_id,
        model,
        provider,
        tokens_input: i128::from(usage.map(|u| u.input).unwrap_or(0)),
        tokens_output: i128::from(usage.map(|u| u.output).unwrap_or(0)),
        tokens_cache_read: i128::from(usage.and_then(|u| u.cache_read).unwrap_or(0)),
        tokens_cache_write: i128::from(usage.and_then(|u| u.cache_creation).unwrap_or(0)),
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        priced_from_ms: 0,
        pricing_version: String::new(),
    }
}

/// The closed refusal set of this step: two refusals, and there is no third.
///
/// They are kept apart rather than collapsed because they are different answers to different
/// questions and they carry different statuses. A pool the caller may not reach is settled before
/// pricing is asked about at all; a name with no configured rate is a bad request, not an exhausted
/// budget. Collapsing them would make two refusals indistinguishable to anything reading the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyRefusal<'n> {
    /// The caller's key may not reach the pool it named, or a fallback pool reachable from it.
    ///
    /// One refusal for both, on purpose: a denial must be indistinguishable from outside whether it
    /// tripped on the requested pool or on a pool it would only have reached under exhaustion.
    NotAuthorized,
    /// A rate card is present and the name the caller supplied has no configured rate.
    NoRate {
        /// The name, as the caller spelled it — it appears in the message. Lent from the request:
        /// the refusal is read where it is made and copies no name.
        name: &'n str,
    },
}

impl VerifyRefusal<'_> {
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            VerifyRefusal::NotAuthorized => 403,
            VerifyRefusal::NoRate { .. } => 400,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            VerifyRefusal::NotAuthorized => busbar_contract::protocol::KIND_PERMISSION,
            VerifyRefusal::NoRate { .. } => busbar_contract::protocol::KIND_INVALID_REQUEST,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        crate::cold::host::door_refusal_message(self)
    }

    #[must_use]
    pub fn reason(&self) -> ReasonCode {
        match self {
            VerifyRefusal::NotAuthorized => ReasonCode::PoolNotPermitted,
            VerifyRefusal::NoRate { .. } => ReasonCode::NoRate,
        }
    }
}

impl std::fmt::Display for VerifyRefusal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyRefusal::NotAuthorized => {
                f.write_str("Your API key does not have permission to access this resource.")
            }
            VerifyRefusal::NoRate { name } => write!(f, "no configured rate for model '{name}'"),
        }
    }
}

pub trait PoolView {
    fn has_key(&self) -> bool;

    fn key_is_scoped(&self) -> bool;

    fn pool_allowed(&self, pool: &str) -> bool;

    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;

    fn is_configured(&self, name: &str) -> bool;

    fn is_unpriced(&self, name: &str) -> bool;
}

fn pool_authorized(view: &dyn PoolView, pool: &str) -> Option<VerifyRefusal<'static>> {
    (view.has_key() && !view.pool_allowed(pool)).then_some(VerifyRefusal::NotAuthorized)
}

fn fallback_pools_authorized(view: &dyn PoolView, pool: &str) -> Option<VerifyRefusal<'static>> {
    if !view.has_key() || !view.key_is_scoped() {
        return None;
    }
    // Walk the fallback chain from `pool`; the names the view hands back are owned, so they are
    // moved into the visited set rather than copied. `None` stands for the borrowed start.
    let mut visited = foldhash::HashSet::<String>::default();
    let mut current: Option<String> = None;
    loop {
        let next = view.on_exhausted_fallback(current.as_deref().unwrap_or(pool))?;
        if let Some(refusal) = pool_authorized(view, &next) {
            return Some(refusal);
        }
        if let Some(walked) = current.take() {
            visited.insert(walked);
        }
        if next == pool || visited.contains(&next) {
            return None;
        }
        current = Some(next);
    }
}

fn priced<'n>(view: &dyn PoolView, name: &'n str) -> Option<VerifyRefusal<'n>> {
    if !(view.has_key() && !view.is_configured(name) && view.is_unpriced(name)) {
        return None;
    }
    Some(VerifyRefusal::NoRate { name })
}

pub fn destination_guard<'n>(view: &dyn PoolView, pool: &'n str) -> Result<(), VerifyRefusal<'n>> {
    if let Some(r) = pool_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = fallback_pools_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = priced(view, pool) {
        return Err(r);
    }
    Ok(())
}

pub fn admitted_facts(
    op_class: OpClassId,
    reported: Option<FinishClass>,
    success: bool,
) -> AuditFacts {
    let finish = reported.unwrap_or(if success {
        FinishClass::Complete
    } else {
        FinishClass::Error
    });
    AuditFacts { op_class, finish }
}

pub fn refused_facts(op_class: OpClassId) -> AuditFacts {
    AuditFacts {
        op_class,
        finish: FinishClass::Error,
    }
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod door_tests;

#[cfg(test)]
#[path = "tests/door_destination_tests.rs"]
mod door_destination_tests;

#[cfg(test)]
#[path = "tests/door_op_id_tests.rs"]
mod door_op_id_tests;
