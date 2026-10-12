// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GATE-FIRST HOOK ORDER (spec Part 3 section 12 "Hooks": the hook stages run "in the hook
//! order 1.5.5 used for that plane (per attachment where 1.5.5 differed)"). A plane whose tail
//! states `abi::plane::TAIL_HOOKS_GATED` runs its request-stage hooks as the previous release ran
//! them for a plane that screened an invocation:
//!
//! 1. THE DECISION GATES attached to the entry the plane's `arrive` named, as the kernel recorded
//!    it at decode (its `project` must name the same entry, or the unit is refused), screen the
//!    projected body (`hooks::gate::decide_door`), the incremental scan keyed on the view's session
//!    under the operator's opt-in, fail-closed; a refusal stops the unit at the hook's own clamped
//!    status and words.
//! 2. THE REWRITE CHAIN attached to that entry runs, each rewrite handed back to the plane, which
//!    applies it and projects again.
//!
//! Both run at the unit's SCREEN, before the door admits it (`teller::RouteAwait::screen`): a
//! refusal admits nothing and is answered before any budget refusal, as 1.5.5 answered it.
//!
//! No stage tap and no route policy fires: the routed order (the rewrite chain, the request taps,
//! the route decision) is the default ([`HookOrder::Routed`]). The kernel names no plane: which
//! order a plane's units run in is the plane's own tail statement, and which hooks are attached is
//! the deployment's per-entry configuration under the plane's registry key.

use std::sync::Arc;

use busbar_contract::hook_wire::reply::{clamp_reject_status, sanitize_reject_message};
use busbar_contract::hooks::TransformOutcome;

use super::super::{FarEnd, PlaneUnits};
use super::{veto_by, HookBinder, Projection, RewriteChain, Stopped};
use crate::hooks::gate::{decide_door, DoorSubject, GateVerdict, ScanSubstrate};
use crate::hooks::ResolvedPolicy;

/// The order a plane's request-stage hooks run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HookOrder {
    /// The rewrite chain, the request taps, then the route decision (the default).
    #[default]
    Routed,
    /// The entry's decision gates over the projection, then its rewrite chain; no taps, no route
    /// policy (`TAIL_HOOKS_GATED`).
    Gated,
}

/// The incremental scan's substrate a gate-first unit is screened with: the node's session store
/// and the hook-config generation a clearance is bound to.
#[derive(Clone)]
pub struct GatedScan {
    /// The node's session store.
    pub store: Arc<crate::session::SessionStore>,
    /// The hook-config generation.
    pub generation: u64,
}

/// THE HOOKS ONE GATE-FIRST UNIT BINDS: the entry's decision gates and rewrite chain, the caller's
/// governance key and the scan substrate.
pub struct GatedHooks {
    /// The unit's correlation id: every hook payload of the unit carries it.
    pub request_id: u64,
    /// The decision gates attached to the entry, as resolved.
    pub gates: Vec<(u16, ResolvedPolicy)>,
    /// The rewrite chain attached to the entry.
    pub rewrites: RewriteChain,
    /// The caller's governance key (its `id` binds the incremental scan's clearance).
    pub key: Option<Arc<busbar_contract::records::VirtualKey>>,
    /// The incremental scan's substrate; `None` = every request is screened whole.
    pub scan: Option<GatedScan>,
}

/// The CURRENT generation's engine host, read per unit (a config apply replaces it).
pub type GenerationHost = Arc<dyn Fn() -> Arc<dyn crate::plane_host::EngineHost> + Send + Sync>;

/// A governance key lookup by the principal the kernel verified.
pub type PrincipalKeys =
    Arc<dyn Fn(&str) -> Option<Arc<busbar_contract::records::VirtualKey>> + Send + Sync>;

/// THE GATE-FIRST BINDER OVER THE DEPLOYMENT'S OWN HOOK CONFIGURATION: the hooks the deployment
/// attached to the plane `plane_key`'s entries (its per-entry `hooks:`), read off the current
/// generation, with the caller's governance key.
pub struct HostGatedHooks {
    /// The current generation's engine host.
    pub host: GenerationHost,
    /// The plane's registry key: the per-entry hooks are filed under it.
    pub plane_key: String,
    /// The caller's governance key, by the principal the kernel verified.
    pub keys: PrincipalKeys,
}

impl HookBinder for HostGatedHooks {
    fn bind(&self, _bind: &super::Bind<'_>) -> Option<super::UnitHooks> {
        None
    }

    fn order(&self) -> HookOrder {
        HookOrder::Gated
    }

    fn bind_gated(&self, container: &str, principal: Option<&str>) -> Option<GatedHooks> {
        let host = (self.host)();
        let gates = host.plane_gates_of(&self.plane_key, container);
        let rewrites = host.plane_rewrites_of(&self.plane_key, container);
        if gates.is_empty() && rewrites.is_empty() {
            return None;
        }
        Some(GatedHooks {
            request_id: host.next_request_id(),
            gates,
            rewrites,
            key: principal.and_then(|p| (self.keys)(p)),
            scan: host
                .gate_scan()
                .map(|(store, generation)| GatedScan { store, generation }),
        })
    }
}

impl<S, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    /// THE GATE-FIRST REQUEST STAGE (module doc): the entry's gates over the projection, then its
    /// rewrite chain. Nothing is bound for the entry: the unit pays nothing more.
    pub(crate) async fn gated_stage(&self, binder: &dyn HookBinder) -> Result<(), Stopped> {
        let mut view: Projection = self.project(None)?;
        let (principal, recorded, route) = {
            let st = self.lock();
            (
                st.principal.as_ref().map(|p| p.as_str().to_string()),
                st.decoded.as_ref().and_then(|d| d.pool.clone()),
                st.decoded.as_ref().map_or(0, |d| d.route),
            )
        };
        // THE ENTRY THE KERNEL RECORDED at decode, never the plane's later word: a projection naming
        // another entry is refused before any entry's gates are bound.
        let Some(entry) = bound_entry(recorded.as_deref(), route, &view)? else {
            return Ok(());
        };
        let entry = entry.to_string();
        let Some(hooks) = binder.bind_gated(&entry, principal.as_deref()) else {
            return Ok(());
        };
        let span = tracing::debug_span!("forward", request_id = tracing::field::Empty);
        span.record("request_id", hooks.request_id);

        // 1. THE DECISION GATES, over the projected invocation, keyed on the view's session.
        if !hooks.gates.is_empty() {
            let projected = view.projected.clone().unwrap_or_default();
            let now_ms = crate::store::now_ms();
            let door = DoorSubject {
                projected: &projected,
                container: &view.pool,
                dialect: &view.dialect,
                request_id: hooks.request_id,
                key: hooks.key.as_deref(),
                session: view.session.as_deref(),
                scan: hooks.scan.as_ref().map(|s| ScanSubstrate {
                    store: &s.store,
                    generation: s.generation,
                    now_ms,
                }),
            };
            if let GateVerdict::Reject {
                status,
                message,
                hook,
            } = decide_door(&hooks.gates, &door).await
            {
                tracing::info!(
                    entry = %view.pool,
                    hook = %hook,
                    status,
                    "a unit refused by a hook gate"
                );
                return Err(veto_by(status, message, hook));
            }
        }

        // 2. THE ENTRY'S REWRITE CHAIN, each rewrite applied by the plane and projected again.
        for (timeout, hook) in &hooks.rewrites {
            let req = view.request(hooks.request_id, &view.pool, true, None);
            if req.prompt.is_some() {
                crate::audit::amend::hook_read(
                    hook.name(),
                    principal.as_deref(),
                    &view.dialect,
                    false,
                );
            }
            let outcome = hook.transform(&req, *timeout).await;
            drop(req);
            match outcome {
                TransformOutcome::Rewrite(rw) => {
                    let bytes = super::rewrite_bytes(&rw);
                    let next = self.project(Some(&bytes))?;
                    // The re-projection is held to the same bound entry.
                    if next.pool != entry {
                        return Err(Stopped::Unreadable);
                    }
                    if let Some(body) = &next.rewritten {
                        self.lock().body = Some(Arc::from(body.as_slice()));
                    }
                    view = next;
                }
                TransformOutcome::Reject { status, message } => {
                    let (status, message) = rewrite_refusal(status, &message);
                    return Err(veto_by(status, message, hook.name()));
                }
                TransformOutcome::Abstain => {}
                TransformOutcome::Failed { message } => {
                    tracing::warn!(
                        hook = hook.name(),
                        entry = %view.pool,
                        error = %message,
                        "rewrite hook could not answer; proceeding with the original body"
                    );
                }
            }
        }
        Ok(())
    }
}

/// THE ENTRY A GATE-FIRST UNIT'S HOOKS ARE BOUND OVER: the one its `arrive` named and the kernel
/// recorded at decode (`Decoded::pool`; none named is the empty entry). The plane's `project`
/// states an entry too, and it must be the same one: a projection naming another is the plane's
/// fault and refuses the unit, so the gates the operator attached to the routed entry can never be
/// traded for another entry's by the plane's later word (audit kernel-K2 leftover A4; ARCHITECT
/// 2026-10-07). Two units bind otherwise:
///
/// - a unit routed over a POOL (`ROUTE_POOL`, a pool named) recorded the pool, and hooks are
///   attached to its members: the entry is the member the plane's projection names, as 1.5.5
///   bound its hooks;
/// - a projection that names no entry and states no body (a task's continuation, whose call was
///   screened at the unit that created the task) has nothing for a gate to screen: `None`, nothing
///   is bound.
fn bound_entry<'v>(
    recorded: Option<&'v [u8]>,
    route: u8,
    view: &'v Projection,
) -> Result<Option<&'v str>, Stopped> {
    if view.pool.is_empty() && view.projected.is_none() {
        return Ok(None);
    }
    let recorded = recorded.unwrap_or_default();
    if route == busbar_contract::abi::plane::ROUTE_POOL && !recorded.is_empty() {
        return Ok(Some(&view.pool));
    }
    if recorded != view.pool.as_bytes() {
        return Err(Stopped::Unreadable);
    }
    std::str::from_utf8(recorded)
        .map(Some)
        .map_err(|_| Stopped::Unreadable)
}

/// A REWRITE'S REFUSAL, as the caller is answered (SEAM-L(q), predev parity): a status the hook
/// chose is clamped to the client-error range and its words sanitized; the seam's OWN failed
/// verdict (a load-bearing hook, `on_error: reject`, that could not answer) keeps predev's
/// [`REQUIRED_HOOK_UNAVAILABLE_STATUS`] and its shared words, never clamped to a 4xx.
///
/// [`REQUIRED_HOOK_UNAVAILABLE_STATUS`]: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS
fn rewrite_refusal(status: u16, message: &str) -> (u16, String) {
    use crate::hooks::{REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS};
    if status == REQUIRED_HOOK_UNAVAILABLE_STATUS && message == REQUIRED_HOOK_UNAVAILABLE_MESSAGE {
        return (status, message.to_string());
    }
    (
        clamp_reject_status(status),
        sanitize_reject_message(message),
    )
}

#[cfg(test)]
#[path = "tests/gated_tests.rs"]
mod tests;
