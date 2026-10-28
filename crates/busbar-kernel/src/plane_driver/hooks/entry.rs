// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENTRY A UNIT'S PER-ENTRY HOOKS BIND OVER (THE DESIGN section 1: "the hook tap and gate ...
//! apply to every plane the same way"). A plane whose section names entries (`tools.servers.X`,
//! `agents.X`) carries the hooks the operator attached to each one (its per-entry `hooks:`, filed
//! under the plane's registry key by entry). A unit binds the ones attached to the entry the KERNEL
//! recorded for it at decode, never the plane's later word, guarded per route kind:
//!
//! - a DIRECT unit binds the entry its `arrive` named ([`bound_entry`]);
//! - a POOL unit binds the member its projection names, held by the recorded pool ([`bound_entry`]);
//!   the member is known only once the plane projected, so an entry-scoped plane projects before
//!   its hooks are bound;
//! - a SCOPE unit binds the one entry the kernel's Verify resolved its scope to, inside the
//!   recorded candidate list ([`scoped_entry`]).
//!
//! A projection naming any other entry refuses the unit (audit kernel-K2 leftover A4; ARCHITECT
//! 2026-10-07).

use busbar_contract::abi::plane::{ROUTE_SCOPE, ROUTE_SCOPE_LOCAL, ROUTE_SCOPE_SEPARATOR};

use super::super::{DriverSteps, FarEnd, PlaneUnits};
use super::{Projection, Stopped};

impl<S: DriverSteps, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    /// THE ENTRY THE UNIT'S PER-ENTRY HOOKS BIND OVER, read off the kernel's record of the unit and
    /// the plane's first projection `first` (module doc). `Ok(None)` binds no entry; `Err` refuses
    /// the unit (a projection naming an entry other than the recorded one).
    ///
    /// A projection the plane could not answer binds the entry the kernel recorded (a scope's unit:
    /// the one its scope resolved to), so its gates still judge the unit rather than being skipped.
    pub(crate) fn recorded_entry(
        &self,
        first: &Result<Projection, Stopped>,
    ) -> Result<Option<String>, Stopped> {
        let (recorded, route) = {
            let st = self.lock();
            (
                st.decoded.as_ref().and_then(|d| d.pool.clone()),
                st.decoded.as_ref().map_or(0, |d| d.route),
            )
        };
        // A UNIT ROUTED BY SCOPE recorded its plane's candidate list, never an entry: its entry is
        // the one the kernel's Verify resolved the scope to (`None` = none resolved yet).
        let scoped = matches!(route, ROUTE_SCOPE | ROUTE_SCOPE_LOCAL);
        let resolved = if scoped {
            self.steps.scope_entry()
        } else {
            None
        };
        let Ok(view) = first else {
            let named = if scoped {
                resolved.as_deref()
            } else {
                recorded.as_deref()
            };
            return Ok(Some(
                std::str::from_utf8(named.unwrap_or_default())
                    .unwrap_or_default()
                    .to_string(),
            ));
        };
        let holds = |pool: &[u8], member: &str| self.steps.pool_holds(pool, member);
        let bound = if scoped {
            scoped_entry(recorded.as_deref(), resolved.as_deref(), view)?
        } else {
            bound_entry(recorded.as_deref(), route, view, holds)?
        };
        Ok(bound.map(str::to_string))
    }
}

/// THE ENTRY A UNIT'S HOOKS ARE BOUND OVER: the one its `arrive` named and the kernel recorded at
/// decode (`Decoded::pool`; none named is the empty entry). The plane's `project` states an entry
/// too, and it must be the same one: a projection naming another is the plane's fault and refuses
/// the unit, so the hooks the operator attached to the routed entry can never be traded for
/// another entry's by the plane's later word (audit kernel-K2 leftover A4; ARCHITECT 2026-10-07).
/// Two units bind otherwise:
///
/// - a unit routed over a POOL (`ROUTE_POOL`, a pool named) recorded the pool, and hooks are
///   attached to its members: the entry is the member the plane's projection names, admitted only
///   when it is a member of the recorded pool (`holds`, the generation's own record of the pool's
///   members); any other entry, the empty one included, refuses the unit (THE DESIGN §1
///   l.183-187: the hook gate applies to every plane the same way);
/// - a projection that names no entry and states no body (a task's continuation, whose call was
///   screened at the unit that created the task) has nothing for a gate to screen: `None`, no entry
///   is bound.
pub(crate) fn bound_entry<'v>(
    recorded: Option<&'v [u8]>,
    route: u8,
    view: &'v Projection,
    holds: impl Fn(&[u8], &str) -> bool,
) -> Result<Option<&'v str>, Stopped> {
    if view.pool.is_empty() && view.projected.is_none() {
        return Ok(None);
    }
    let recorded = recorded.unwrap_or_default();
    if route == busbar_contract::abi::plane::ROUTE_POOL && !recorded.is_empty() {
        if view.pool.is_empty() || !holds(recorded, view.pool.as_str()) {
            return Err(Stopped::Unreadable);
        }
        return Ok(Some(&view.pool));
    }
    if recorded != view.pool.as_bytes() {
        return Err(Stopped::Unreadable);
    }
    std::str::from_utf8(recorded)
        .map(Some)
        .map_err(|_| Stopped::Unreadable)
}

/// THE ENTRY A UNIT ROUTED BY SCOPE (`ROUTE_SCOPE`, `ROUTE_SCOPE_LOCAL`) IS BOUND OVER: the ONE
/// entry the kernel's Verify resolved its scope to (`resolved`), never an entry the plane's
/// projection names. Its `arrive` recorded no entry: `candidates` is the plane's CANDIDATE LIST
/// joined by `ROUTE_SCOPE_SEPARATOR` (`None` or empty = every entry is a candidate), and the
/// plane's `project` cannot know which one the scope resolves to, so it names none. The binding
/// guarantee of [`bound_entry`] holds the same way:
///
/// - the resolved entry must be one the recorded candidate list holds (a whole member, never a
///   widening of the list); any other refuses the unit;
/// - a projection may name no entry, or the resolved one; naming any other refuses the unit, so
///   the plane's later word never trades the resolved entry's hooks for another's;
/// - a scope that resolved no entry (zero or several reach) binds none: the door refuses that unit
///   `no_destination` before anything is admitted (`abi::plane::ROUTE_SCOPE`), so no hop runs
///   ungated; a projection naming an entry for it is still refused;
/// - a projection that names no entry and states no body binds none, as for any route.
pub(crate) fn scoped_entry<'v>(
    candidates: Option<&[u8]>,
    resolved: Option<&'v [u8]>,
    view: &Projection,
) -> Result<Option<&'v str>, Stopped> {
    if view.pool.is_empty() && view.projected.is_none() {
        return Ok(None);
    }
    let Some(resolved) = resolved else {
        if view.pool.is_empty() {
            return Ok(None);
        }
        return Err(Stopped::Unreadable);
    };
    let entry = std::str::from_utf8(resolved).map_err(|_| Stopped::Unreadable)?;
    let candidates = candidates.unwrap_or_default();
    if !candidates.is_empty() {
        let candidates = std::str::from_utf8(candidates).map_err(|_| Stopped::Unreadable)?;
        if !candidates.split(ROUTE_SCOPE_SEPARATOR).any(|c| c == entry) {
            return Err(Stopped::Unreadable);
        }
    }
    if entry.is_empty() || (!view.pool.is_empty() && view.pool != entry) {
        return Err(Stopped::Unreadable);
    }
    Ok(Some(entry))
}

#[cfg(test)]
#[path = "tests/entry_tests.rs"]
mod tests;
