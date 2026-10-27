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

use super::super::{DriverSteps, FarEnd, PlaneUnits};
use super::{rewrite_applied, veto_by, HookBinder, Projection, RewriteChain, Stopped};
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
pub type GenerationHost = Arc<dyn Fn() -> Arc<dyn crate::plane_driver::EngineHost> + Send + Sync>;

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
    /// The plane's dialect names, in its tail's order: the label an in-session hook of the unit is
    /// told (its `ingress_protocol`) and the op its access amendment records, as at the screen.
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

impl<S: DriverSteps, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    /// THE GATE-FIRST REQUEST STAGE (module doc): the entry's gates over the projection, then its
    /// rewrite chain. Nothing is bound for the entry: the unit pays nothing more. The hooks it ran
    /// are reported to the driver's hook journal however it ended.
    pub(crate) async fn gated_stage(&self, binder: &dyn HookBinder) -> Result<(), Stopped> {
        let mut ran = Vec::new();
        let stage = self.run_gated_stage(binder, &mut ran).await;
        self.report_hooks(ran);
        stage
    }

    /// [`Self::gated_stage`], each hook that ran pushed onto `ran` as it answered.
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
        let mut view: Projection = match first {
            Ok(view) => view,
            // The plane answered FAULT to the unit's first `project`: where the entry the kernel
            // recorded has a rewrite hook configured, v1.5.5 materialized the document before any
            // hook ran (`proxy/engine/mod.rs:728`, `:749`) and answered the shared 500, no hook
            // invoked. Anywhere else 1.5.5's gates judged a Null body and the request proceeded
            // (`:957-961`): the entry's gates judge a view with no body, and the unit goes on.
            Err(Stopped::Unparseable { marked }) => {
                // The entry the kernel recorded at decode; a unit that recorded none, or one that
                // is not UTF-8, binds the empty entry, as `bound_entry` reads an unnamed one.
                let entry = std::str::from_utf8(recorded.as_deref().unwrap_or_default())
                    .unwrap_or_default()
                    .to_string();
                let hooks = binder.bind_gated(&entry, principal.as_deref());
                // A configured rewrite: the shared 500 for every FAULT, marked or not (v1.5.5
                // `:728`, `:749`), no hook invoked.
                if hooks.as_ref().is_some_and(|h| !h.rewrites.is_empty()) {
                    return Err(super::fault_veto());
                }
                // An unmarked FAULT is a broken plane, never 1.5.5's Null body: unreadable.
                if !marked {
                    return Err(Stopped::Unreadable);
                }
                let Some(hooks) = hooks else {
                    return Ok(());
                };
                let null = Projection {
                    pool: entry,
                    dialect: binder.dialect(self.lock().decoded.as_ref().map_or(0, |d| d.dialect)),
                    ..Projection::default()
                };
                return self.screen_gates(&hooks, &null, ran).await;
            }
            Err(other) => return Err(other),
        };
        // THE ENTRY THE KERNEL RECORDED at decode, never the plane's later word: a projection naming
        // another entry is refused before any entry's gates are bound.
        let holds = |pool: &[u8], member: &str| self.steps.pool_holds(pool, member);
        let Some(entry) = bound_entry(recorded.as_deref(), route, &view, holds)? else {
            return Ok(());
        };
        let entry = entry.to_string();
        let Some(mut hooks) = binder.bind_gated(&entry, principal.as_deref()) else {
            return Ok(());
        };
        // The unit's own correlation id, where its host minted one (status row 173).
        if let Some(id) = self.lock().request_id {
            hooks.request_id = id;
        }
        super::record_request_id(hooks.request_id);

        // 1. THE DECISION GATES, over the projected invocation, keyed on the view's session.
        self.screen_gates(&hooks, &view, ran).await?;

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
            ran.push(rewrite_applied(hook.name(), &outcome));
            match outcome {
                TransformOutcome::Rewrite(rw) => {
                    let bytes = super::rewrite_bytes(&rw);
                    let next = match self.project(Some(&bytes), true) {
                        // A rewrite naming messages the plane answered with no rewritten body:
                        // not applied, refused as a rewrite the plane refused is.
                        Ok(next) if next.rewritten.is_some() || rw.messages.is_empty() => next,
                        // A FAULT project: the shared 500, never the hook's `on_error`.
                        Err(fault @ Stopped::Veto(_)) => return Err(fault),
                        Ok(_) | Err(_) => {
                            let (status, message) = refused_rewrite(&**hook, &view.pool, ran);
                            return Err(veto_by(status, message, hook.name()));
                        }
                    };
                    // The re-projection is held to the same bound entry.
                    if next.pool != entry {
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

    /// THE ENTRY'S DECISION GATES over `view`, the projected invocation, keyed on the view's
    /// session: the first rejecting gate refuses the unit.
    async fn screen_gates(
        &self,
        hooks: &GatedHooks,
        view: &Projection,
        ran: &mut Vec<HookApplied>,
    ) -> Result<(), Stopped> {
        if !hooks.gates.is_empty() {
            let now_ms = crate::store::now_ms();
            let door = DoorSubject {
                // The plane's own body, or none: a gate granted the content never screens an
                // absent body as empty content (`decide_door`, audit Q128 p15#3).
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
                // THE DESIGN Appendix B.9 l.5436-5437: the hook view's plane-derived fields.
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

/// THE ENTRY A GATE-FIRST UNIT'S HOOKS ARE BOUND OVER: the one its `arrive` named and the kernel
/// recorded at decode (`Decoded::pool`; none named is the empty entry). The plane's `project`
/// states an entry too, and it must be the same one: a projection naming another is the plane's
/// fault and refuses the unit, so the gates the operator attached to the routed entry can never be
/// traded for another entry's by the plane's later word (audit kernel-K2 leftover A4; ARCHITECT
/// 2026-10-07). Two units bind otherwise:
///
/// - a unit routed over a POOL (`ROUTE_POOL`, a pool named) recorded the pool, and hooks are
///   attached to its members: the entry is the member the plane's projection names, as 1.5.5
///   bound its hooks, admitted only when it is a member of the recorded pool (`holds`, the
///   generation's own record of the pool's members); any other entry, the empty one included,
///   refuses the unit (THE DESIGN §1 l.183-187: the hook gate applies to every plane the same
///   way);
/// - a projection that names no entry and states no body (a task's continuation, whose call was
///   screened at the unit that created the task) has nothing for a gate to screen: `None`, nothing
///   is bound.
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

/// A REWRITE THE PLANE DID NOT APPLY (it refused the rewrite, or answered with no rewritten body:
/// one naming a model other than the routed one, a dialect with no conversation to frame it into,
/// a body the splice cannot place it in): THE REQUEST IS REFUSED, never forwarded as the caller sent
/// it. A rewrite hook rewrites to redact, compress or police; relaying the un-rewritten body
/// upstream is the fail-open the hook exists to prevent, whatever its `on_error` says (that answers
/// the hook's OWN failure to answer, not busbar's failure to apply what it answered).
///
/// A load-bearing hook (`on_error: reject`) is refused with the refusal a failed call of the same
/// hook answers, [`REQUIRED_HOOK_UNAVAILABLE_STATUS`] and its shared words; every other hook with
/// [`PROJECT_FAULT_STATUS`] and 1.5.5's own words for this case, [`PROJECT_FAULT_MESSAGE`]. The
/// refusal is logged at error naming the hook and the entry, and the hook's entry in the unit's
/// record (its "hooks applied") is rewritten to a failed veto ([`mark_unapplied`]).
///
/// [`REQUIRED_HOOK_UNAVAILABLE_STATUS`]: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS
/// [`PROJECT_FAULT_STATUS`]: busbar_contract::abi::plane::PROJECT_FAULT_STATUS
/// [`PROJECT_FAULT_MESSAGE`]: busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE
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

/// The hook's entry in the unit's record, pushed as a rewrite when it answered, rewritten to what
/// happened: a failed veto.
fn mark_unapplied(hook: &str, ran: &mut [HookApplied]) {
    if let Some(last) = ran.iter_mut().rev().find(|h| h.hook == hook) {
        last.head = HookHead::Veto;
        last.failed = true;
    }
}

/// A REWRITE'S REFUSAL, as the caller is answered (SEAM-L(q), predev parity): a status the hook
/// chose is clamped to the client-error range and its words sanitized; the seam's OWN failed
/// verdict (a load-bearing hook, `on_error: reject`, that could not answer) keeps predev's
/// [`REQUIRED_HOOK_UNAVAILABLE_STATUS`] and its shared words, never clamped to a 4xx.
///
/// [`REQUIRED_HOOK_UNAVAILABLE_STATUS`]: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS
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
