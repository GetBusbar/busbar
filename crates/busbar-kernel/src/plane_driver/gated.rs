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

use busbar_contract::abi::plane::{ROUTE_SCOPE, ROUTE_SCOPE_LOCAL, ROUTE_SCOPE_SEPARATOR};
use busbar_contract::hook_wire::reply::{clamp_reject_status, sanitize_reject_message};
use busbar_contract::hooks::TransformOutcome;

use super::super::{DriverSteps, FarEnd, PlaneUnits};
use super::{rewrite_applied, veto_by, HookBinder, HookRead, Projection, RewriteChain, Stopped};
use crate::hooks::gate::{decide_door, DoorSubject, GateVerdict, ScanSubstrate};
use crate::hooks::ResolvedPolicy;
use busbar_kernel_audit::record::{HookApplied, HookHead};

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

pub struct GatedHooks {
    pub request_id: u64,

    pub gates: Vec<(u16, ResolvedPolicy)>,

    pub rewrites: RewriteChain,

    pub key: Option<Arc<busbar_contract::records::VirtualKey>>,

    pub scan: Option<GatedScan>,

    pub reads: HookRead,
}

pub type GenerationHost = Arc<dyn Fn() -> Arc<dyn crate::plane_driver::EngineHost> + Send + Sync>;

pub type PrincipalKeys =
    Arc<dyn Fn(&str) -> Option<Arc<busbar_contract::records::VirtualKey>> + Send + Sync>;

pub struct HostGatedHooks {
    pub host: GenerationHost,

    pub plane_key: String,

    pub keys: PrincipalKeys,

    pub dialects: Vec<String>,
}

impl HookBinder for HostGatedHooks {
    fn bind(&self, _bind: &super::Bind<'_>) -> Option<super::UnitHooks> {
        None
    }

    fn order(&self) -> HookOrder {
        HookOrder::Gated
    }

    fn dialect(&self, dialect: u32) -> String {
        self.dialects
            .get(dialect as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn bind_gated(&self, container: &str, principal: Option<&str>) -> Option<GatedHooks> {
        let host = (self.host)();
        let gates = host.plane_gates_of(&self.plane_key, container);
        let rewrites = host.plane_rewrites_of(&self.plane_key, container);
        if gates.is_empty() && rewrites.is_empty() {
            return None;
        }
        let scan = host
            .gate_scan()
            .map(|(store, generation)| GatedScan { store, generation });
        Some(GatedHooks {
            request_id: host.next_request_id(),
            gates,
            rewrites,
            key: principal.and_then(|p| (self.keys)(p)),
            scan,
            reads: Arc::new(
                move |hook: &str, principal: Option<&str>, op: &str, identity: bool| {
                    host.hook_read(hook, principal, op, identity);
                },
            ),
        })
    }
}

impl<S: DriverSteps, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    pub(crate) async fn gated_stage(&self, binder: &dyn HookBinder) -> Result<(), Stopped> {
        let mut ran = Vec::new();
        let stage = self.run_gated_stage(binder, &mut ran).await;
        self.report_hooks(ran);
        stage
    }

    async fn run_gated_stage(
        &self,
        binder: &dyn HookBinder,
        ran: &mut Vec<HookApplied>,
    ) -> Result<(), Stopped> {
        let first = self.project(None, false);
        let (principal, recorded, route) = {
            let st = self.lock();
            (
                st.principal.as_ref().map(|p| p.as_str().to_string()),
                st.decoded.as_ref().and_then(|d| d.pool.clone()),
                st.decoded.as_ref().map_or(0, |d| d.route),
            )
        };

        let scoped = matches!(route, ROUTE_SCOPE | ROUTE_SCOPE_LOCAL);
        let resolved = if scoped {
            self.steps.scope_entry()
        } else {
            None
        };
        let mut view: Projection = match first {
            Ok(view) => view,

            Err(Stopped::Unparseable { marked }) => {
                let named = if scoped {
                    resolved.as_deref()
                } else {
                    recorded.as_deref()
                };
                let entry = std::str::from_utf8(named.unwrap_or_default())
                    .unwrap_or_default()
                    .to_string();
                let hooks = binder.bind_gated(&entry, principal.as_deref());

                if hooks.as_ref().is_some_and(|h| !h.rewrites.is_empty()) {
                    return Err(super::fault_veto());
                }

                if !marked {
                    return Err(Stopped::Unreadable);
                }
                let Some(hooks) = hooks else {
                    return Ok(());
                };
                let null = Projection::empty(
                    entry,
                    binder.dialect(self.lock().decoded.as_ref().map_or(0, |d| d.dialect)),
                );
                return self.screen_gates(&hooks, &null, ran).await;
            }
            Err(other) => return Err(other),
        };

        let holds = |pool: &[u8], member: &str| self.steps.pool_holds(pool, member);
        let bound = if scoped {
            scoped_entry(recorded.as_deref(), resolved.as_deref(), &view)?
        } else {
            bound_entry(recorded.as_deref(), route, &view, holds)?
        };
        let Some(entry) = bound else {
            return Ok(());
        };
        let entry = entry.to_string();
        let Some(mut hooks) = binder.bind_gated(&entry, principal.as_deref()) else {
            return Ok(());
        };

        if let Some(id) = self.lock().request_id {
            hooks.request_id = id;
        }
        super::record_request_id(hooks.request_id);

        self.screen_gates(&hooks, &view, ran).await?;

        for (timeout, hook) in &hooks.rewrites {
            let req = view.request(hooks.request_id, &view.pool, true, None);
            if req.prompt.is_some() {
                (hooks.reads)(hook.name(), principal.as_deref(), &view.dialect, false);
            }
            let outcome = hook.transform(&req, *timeout).await;
            drop(req);
            ran.push(rewrite_applied(hook.name(), &outcome));
            match outcome {
                TransformOutcome::Rewrite(rw) => {
                    let bytes = super::rewrite_bytes(&rw);
                    let next = match self.project(Some(&bytes), true) {
                        Ok(next) if next.rewritten.is_some() || rw.messages.is_empty() => next,

                        Ok(next) if next.rewrite_not_applicable => {
                            if next.pool != entry && !(scoped && next.pool.is_empty()) {
                                return Err(Stopped::Unreadable);
                            }
                            rewrite_not_applicable(hook.name(), ran);
                            tracing::warn!(
                                hook = hook.name(),
                                entry = %view.pool,
                                "rewrite not applicable to this request; forwarded unmodified"
                            );
                            continue;
                        }

                        Err(fault @ Stopped::Veto(_)) => return Err(fault),

                        Ok(_) | Err(_) => {
                            let (status, message) = refused_rewrite(&**hook, &view.pool, ran);
                            return Err(veto_by(status, message, hook.name()));
                        }
                    };

                    if next.pool != entry && !(scoped && next.pool.is_empty()) {
                        return Err(Stopped::Unreadable);
                    }
                    if let Some(body) = &next.rewritten {
                        self.lock().body = Some(bytes::Bytes::copy_from_slice(body));
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

    async fn screen_gates(
        &self,
        hooks: &GatedHooks,
        view: &Projection,
        ran: &mut Vec<HookApplied>,
    ) -> Result<(), Stopped> {
        if !hooks.gates.is_empty() {
            let now_ms = crate::store::now_ms();
            let door = DoorSubject {
                projected: view.projected.as_deref(),
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
                reads: &*hooks.reads,

                plane: crate::hooks::gate::DoorShape {
                    max_tokens: view.max_tokens,
                    stream: view.stream,
                    end_user: view.end_user.as_deref(),
                },
            };
            if let GateVerdict::Reject {
                status,
                message,
                hook,
            } = decide_door(&hooks.gates, &door, ran).await
            {
                tracing::info!(
                    entry = %view.pool,
                    hook = %hook,
                    status,
                    "a unit refused by a hook gate"
                );
                return Err(veto_by(status, message, &hook));
            }
        }
        Ok(())
    }
}

fn bound_entry<'v>(
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

fn scoped_entry<'v>(
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

pub(super) fn refused_rewrite(
    hook: &dyn busbar_contract::hooks::RoutingPolicy,
    entry: &str,
    ran: &mut [HookApplied],
) -> (u16, String) {
    use crate::hooks::{REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS};
    let load_bearing = hook.refuses_failed_rewrite();
    tracing::error!(
        hook = hook.name(),
        entry = %entry,
        load_bearing,
        "a rewrite hook's rewrite could not be applied to the request; refusing the request \
         rather than forwarding the body un-rewritten"
    );
    mark_unapplied(hook.name(), ran);
    if load_bearing {
        return rewrite_refusal(
            REQUIRED_HOOK_UNAVAILABLE_STATUS,
            REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
        );
    }
    (
        busbar_contract::abi::plane::PROJECT_FAULT_STATUS,
        busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE.to_string(),
    )
}

pub(super) fn rewrite_not_applicable(hook: &str, ran: &mut [HookApplied]) {
    if let Some(last) = ran.iter_mut().rev().find(|h| h.hook == hook) {
        last.head = HookHead::Pass;
        last.failed = false;
    }
}

fn mark_unapplied(hook: &str, ran: &mut [HookApplied]) {
    if let Some(last) = ran.iter_mut().rev().find(|h| h.hook == hook) {
        last.head = HookHead::Veto;
        last.failed = true;
    }
}

pub(super) fn rewrite_refusal(status: u16, message: &str) -> (u16, String) {
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
