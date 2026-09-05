// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three pre-admission guards, in the one order they may run in.
//!
//! Everything here can refuse, and everything here runs before the door charges. That ordering is
//! the invariant: a refusal after a charge is a caller billed for a request that never went
//! anywhere, and no amount of refunding afterwards makes the ledger honest again.

/// What a refusal renders as, in the caller's own dialect.
///
/// The three fields are the whole wire contract: the status, the vendor-shaped kind word, and the
/// message. They are named here rather than rendered, because rendering belongs to whichever dialect
/// the caller spoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRefusal {
    /// The status.
    pub status: u16,
    /// The dialect-shaped kind word.
    pub kind: RefusalKind,
    /// The message, verbatim.
    pub message: &'static str,
}

/// The two kind words these guards can raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The caller may not reach this destination.
    Permission,
    /// The request itself is not valid.
    InvalidRequest,
}

/// The permission refusal, byte for byte.
///
/// The body carries only vendor-plausible copy: it never names the key id, the pool, or any
/// governance vocabulary, because a native vendor refusal never names an operator's key or an
/// operator's pool. The key id and pool go to the operator's own diagnostics instead.
const NOT_AUTHORIZED: GuardRefusal = GuardRefusal {
    status: 403,
    kind: RefusalKind::Permission,
    message: "Your API key does not have permission to access this resource.",
};

/// Everything the guards read about the deployment's pools and the caller's key.
pub trait PoolView {
    /// Whether the caller's key is scoped at all. `None` means it names no restriction and admits
    /// every pool; an explicit empty list is the empty SET and denies every pool, which is a
    /// different thing and is why this is an option rather than a possibly-empty slice.
    fn key_scopes(&self) -> Option<&[String]>;
    /// Whether the key may use one pool.
    fn pool_allowed(&self, pool: &str) -> bool;
    /// The pool this one falls over to when it exhausts, when its exhaustion policy names one.
    /// `None` when the policy stays inside this pool, or when the pool is not configured at all.
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;
    /// Whether the name refers to a configured pool or a configured single-lane entry.
    fn is_configured(&self, name: &str) -> bool;
    /// Whether a rate card is present at all.
    fn pricing_enabled(&self) -> bool;
    /// Whether a present card prices this name.
    fn is_unpriced(&self, name: &str) -> bool;
    /// Whether the caller presented a key at all. With no key the guards are inert.
    fn has_key(&self) -> bool;
}

/// Guard one: the requested pool's allow-list.
///
/// Inert when the caller presented no key, or when the key names no restriction.
pub fn pool_authorized(view: &dyn PoolView, pool: &str) -> Option<GuardRefusal> {
    if view.has_key() && !view.pool_allowed(pool) {
        return Some(NOT_AUTHORIZED);
    }
    None
}

/// Guard two: every fallback pool the request could reach if the requested one exhausts.
///
/// The first guard covers only the FIRST pool. Without this one, a key restricted to one pool could
/// be served by a fallback pool it may not touch, because the dispatch that far down never re-checks
/// the key — the check is an ingress concern and this is the ingress.
///
/// The chain is multi-level and may cycle, so the walk carries the same visited-set guard the
/// dispatch itself carries; the two cannot diverge because both stop for the same reason. A denial
/// is the SAME refusal the first guard raises, which is what keeps the two indistinguishable from
/// outside.
pub fn fallback_pools_authorized(view: &dyn PoolView, pool: &str) -> Option<GuardRefusal> {
    if !view.has_key() {
        return None;
    }
    // A key with no restriction admits every pool; there is nothing to walk.
    view.key_scopes()?;
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current = pool.to_string();
    loop {
        // A chain that cycles back to a pool already walked stops here.
        if !visited.insert(current.clone()) {
            return None;
        }
        let next = view.on_exhausted_fallback(&current)?;
        if let Some(refusal) = pool_authorized(view, &next) {
            return Some(refusal);
        }
        current = next;
    }
}

/// Guard three: with a rate card present, every governed request must resolve to a priced
/// destination.
///
/// A configured pool or single-lane entry is priced by construction — boot refuses a card that does
/// not cover them — so the only name that can be unpriced is an arbitrary one the caller supplied.
/// Refusing it plainly beats serving traffic that cannot be billed. Costs one boolean when no card
/// is configured.
pub fn priced(view: &dyn PoolView, name: &str, message: &'static str) -> Option<GuardRefusal> {
    if view.has_key()
        && view.pricing_enabled()
        && !view.is_configured(name)
        && view.is_unpriced(name)
    {
        return Some(GuardRefusal {
            status: 400,
            kind: RefusalKind::InvalidRequest,
            message,
        });
    }
    None
}

/// All three guards, in their fixed order.
///
/// `unpriced_message` is the caller-facing text for the third guard, which names the model the
/// caller asked for and is therefore built by the caller rather than stored here.
pub fn destination_guard(
    view: &dyn PoolView,
    pool: &str,
    unpriced_message: &'static str,
) -> Result<(), GuardRefusal> {
    if let Some(r) = pool_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = fallback_pools_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = priced(view, pool, unpriced_message) {
        return Err(r);
    }
    Ok(())
}
